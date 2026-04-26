use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{Method, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};

use crate::monitor::{
    AggregateBucket, AggregatedBucket, HistogramHistory, HistoryDirection, HistorySample, HistoryTrafficType, SnapshotData, TrafficHistory,
};
use crate::policy::{
    add_guest_whitelist, create_scheduled_rule, delete_guest_default, delete_iface_limit, delete_scheduled_rule, get_guest_defaults,
    get_guest_whitelist, get_iface_limits, get_scheduled_rules, policy_items, remove_guest_whitelist, set_guest_default, set_iface_limit,
    update_scheduled_rule, CreateScheduledRuleRequest, GuestWhitelistEntryApi, GuestWhitelistEntryRequest, InterfaceRateLimitApi, PolicyItem,
    PolicyRuntime, ScheduledRuleApi, SetInterfaceRateLimitRequest, UpdateScheduledRuleRequest,
};
use crate::topology::TopologySnapshot;

#[derive(Clone)]
pub struct ApiState {
    pub snapshot: Arc<RwLock<SnapshotData>>,
    pub history: Arc<RwLock<TrafficHistory>>,
    pub histogram: Arc<RwLock<HistogramHistory>>,
    pub policy_runtime: Arc<RwLock<PolicyRuntime>>,
    pub topology: Arc<RwLock<TopologySnapshot>>,
}

#[derive(Debug, Deserialize, Default)]
pub struct DevicesQuery {
    pub iface: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct HistoryQuery {
    /// 内核网卡名（如 `eth0`），与 `/api/overview` 的 `ifname` 一致；服务端解析为 ifindex。
    pub iface: Option<String>,
    pub mac: Option<String>,
    pub traffic_type: Option<String>,
    pub direction: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct AggregateQuery {
    /// 内核网卡名；服务端解析为 ifindex。
    pub iface: Option<String>,
    pub mac: Option<String>,
    /// 与 `/api/trend` 相同：`all` / `ipv4` / `ipv6`；响应中另一侧字节与 bps 统计置零。
    pub traffic_type: Option<String>,
    pub start_ms: Option<u64>,
    pub end_ms: Option<u64>,
    pub bucket: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiEnvelope<T> {
    pub ok: bool,
    pub data: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn router(state: ApiState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .allow_headers(Any);

    Router::new()
        .route("/api/health", get(health))
        .route("/api/snapshot", get(snapshot))
        .route("/api/overview", get(overview))
        .route("/api/devices", get(devices))
        .route("/api/trend", get(history))
        .route("/api/histogram", get(aggregate))
        .route("/api/policy", get(policy))
        .route("/api/rate_limit/schedules", get(get_schedules).post(create_schedule))
        .route("/api/rate_limit/schedules/{id}", put(update_schedule).patch(update_schedule).delete(delete_schedule))
        .route("/api/rate_limit/iface_limits", get(get_iface_limits_handler).post(set_iface_limit_handler))
        .route("/api/rate_limit/iface_limits/{iface}", delete(delete_iface_limit_handler))
        .route("/api/rate_limit/guest_defaults", get(get_guest_defaults_handler).post(set_guest_default_handler))
        .route("/api/rate_limit/guest_defaults/{iface}", delete(delete_guest_default_handler))
        .route("/api/rate_limit/guest_whitelist", get(get_guest_whitelist_handler).post(add_guest_whitelist_handler).delete(remove_guest_whitelist_handler))
        .with_state(state)
        .layer(cors)
}

pub async fn start_server(bind_addr: &str, state: ApiState) -> anyhow::Result<()> {
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> Json<ApiEnvelope<&'static str>> {
    Json(ApiEnvelope { ok: true, data: "ok", error: None })
}

async fn snapshot(State(state): State<ApiState>) -> Json<ApiEnvelope<SnapshotData>> {
    Json(ApiEnvelope {
        ok: true,
        data: state.snapshot.read().await.clone(),
        error: None,
    })
}

async fn overview(State(state): State<ApiState>) -> Json<ApiEnvelope<Vec<crate::monitor::InterfaceOverviewItem>>> {
    Json(ApiEnvelope {
        ok: true,
        data: state.snapshot.read().await.interfaces.clone(),
        error: None,
    })
}

async fn devices(
    State(state): State<ApiState>,
    Query(q): Query<DevicesQuery>,
) -> Json<ApiEnvelope<Vec<crate::monitor::DeviceListItem>>> {
    let devices = state.snapshot.read().await.devices.clone();
    let filtered: Vec<_> = devices
        .into_iter()
        .filter(|d| {
            if let Some(ref iface) = q.iface {
                if !iface.is_empty() && d.logical_iface != *iface {
                    return false;
                }
            }
            true
        })
        .collect();
    Json(ApiEnvelope { ok: true, data: filtered, error: None })
}

async fn resolve_query_iface_to_ifindex(state: &ApiState, iface: Option<String>) -> Result<u32, String> {
    let name = iface
        .and_then(|s| {
            let t = s.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        })
        .ok_or_else(|| "iface is required".to_string())?;

    let topo = state.topology.read().await;
    if let Some(ix) = topo.ifindex_by_name(&name) {
        return Ok(ix);
    }
    drop(topo);

    let snap = state.snapshot.read().await;
    for item in &snap.interfaces {
        if item.ifname == name {
            return Ok(item.ifindex);
        }
    }

    Err(format!("unknown iface: {name}"))
}

async fn history(
    State(state): State<ApiState>,
    Query(q): Query<HistoryQuery>,
) -> Json<ApiEnvelope<Vec<HistorySample>>> {
    let ifindex = match resolve_query_iface_to_ifindex(&state, q.iface.clone()).await {
        Ok(i) => i,
        Err(e) => {
            return Json(ApiEnvelope {
                ok: false,
                data: Vec::new(),
                error: Some(e),
            });
        }
    };
    let traffic_type = parse_traffic_type(q.traffic_type.as_deref());
    let direction = parse_direction(q.direction.as_deref());
    let result = if let Some(mac) = q.mac.as_deref().filter(|s| !s.trim().is_empty()) {
        state
            .history
            .read()
            .await
            .query_device(Some(ifindex), mac, traffic_type, direction)
    } else {
        state
            .history
            .read()
            .await
            .query_iface(ifindex, traffic_type, direction)
    };
    Json(ApiEnvelope {
        ok: true,
        data: result,
        error: None,
    })
}

fn parse_traffic_type(input: Option<&str>) -> HistoryTrafficType {
    match input.unwrap_or("all").to_ascii_lowercase().as_str() {
        "ipv4" => HistoryTrafficType::Ipv4,
        "ipv6" => HistoryTrafficType::Ipv6,
        _ => HistoryTrafficType::All,
    }
}

fn parse_direction(input: Option<&str>) -> HistoryDirection {
    match input.unwrap_or("both").to_ascii_lowercase().as_str() {
        "up" => HistoryDirection::Up,
        "down" => HistoryDirection::Down,
        _ => HistoryDirection::Both,
    }
}

async fn aggregate(
    State(state): State<ApiState>,
    Query(q): Query<AggregateQuery>,
) -> Json<ApiEnvelope<Vec<AggregatedBucket>>> {
    let ifindex = match resolve_query_iface_to_ifindex(&state, q.iface.clone()).await {
        Ok(i) => i,
        Err(e) => {
            return Json(ApiEnvelope {
                ok: false,
                data: Vec::new(),
                error: Some(e),
            });
        }
    };
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let default_end = now_ms;
    let default_start = now_ms.saturating_sub(24 * 3600 * 1000);
    let start_ms = q.start_ms.unwrap_or(default_start);
    let end_ms = q.end_ms.unwrap_or(default_end);
    let bucket = match q.bucket.as_deref().unwrap_or("hourly").to_ascii_lowercase().as_str() {
        "daily" => AggregateBucket::Daily,
        _ => AggregateBucket::Hourly,
    };
    let traffic_type = parse_traffic_type(q.traffic_type.as_deref());
    let histogram = state.histogram.read().await;
    let result: Vec<AggregatedBucket> = histogram
        .query_aggregate(
            ifindex,
            q.mac.as_deref(),
            start_ms,
            end_ms,
            bucket,
        )
        .into_iter()
        .map(|b| b.with_traffic_type(traffic_type))
        .collect();
    Json(ApiEnvelope {
        ok: true,
        data: result,
        error: None,
    })
}

async fn policy(State(state): State<ApiState>) -> Json<ApiEnvelope<Vec<PolicyItem>>> {
    let data = {
        let guard = state.policy_runtime.read().await;
        policy_items(&guard)
    };
    Json(ApiEnvelope { ok: true, data, error: None })
}

async fn get_schedules(State(state): State<ApiState>) -> Json<ApiEnvelope<Vec<ScheduledRuleApi>>> {
    let data = {
        let guard = state.policy_runtime.read().await;
        get_scheduled_rules(&guard)
    };
    Json(ApiEnvelope { ok: true, data, error: None })
}

async fn create_schedule(State(state): State<ApiState>, Json(req): Json<CreateScheduledRuleRequest>) -> impl IntoResponse {
    let result = {
        let mut guard = state.policy_runtime.write().await;
        create_scheduled_rule(&mut guard, req)
    };
    match result {
        Ok(v) => Json(ApiEnvelope { ok: true, data: v, error: None }).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiEnvelope::<ScheduledRuleApi> {
                ok: false,
                data: ScheduledRuleApi {
                    id: String::new(),
                    mac: String::new(),
                    time_slot: crate::policy::TimeSlotApi { start: String::new(), end: String::new(), days: vec![] },
                    down_v4_kbps: 0,
                    down_v6_kbps: 0,
                    up_v4_kbps: 0,
                    up_v6_kbps: 0,
                },
                error: Some(e.to_string()),
            }),
        )
            .into_response(),
    }
}

async fn update_schedule(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateScheduledRuleRequest>,
) -> impl IntoResponse {
    let result = {
        let mut guard = state.policy_runtime.write().await;
        update_scheduled_rule(&mut guard, &id, req)
    };
    match result {
        Ok(v) => Json(ApiEnvelope { ok: true, data: v, error: None }).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiEnvelope::<ScheduledRuleApi> {
                ok: false,
                data: ScheduledRuleApi {
                    id: String::new(),
                    mac: String::new(),
                    time_slot: crate::policy::TimeSlotApi { start: String::new(), end: String::new(), days: vec![] },
                    down_v4_kbps: 0,
                    down_v6_kbps: 0,
                    up_v4_kbps: 0,
                    up_v6_kbps: 0,
                },
                error: Some(e.to_string()),
            }),
        )
            .into_response(),
    }
}

async fn delete_schedule(State(state): State<ApiState>, Path(id): Path<String>) -> Json<ApiEnvelope<&'static str>> {
    let result = {
        let mut guard = state.policy_runtime.write().await;
        delete_scheduled_rule(&mut guard, &id)
    };
    if let Err(e) = result {
        return Json(ApiEnvelope {
            ok: false,
            data: "error",
            error: Some(e.to_string()),
        });
    }
    Json(ApiEnvelope { ok: true, data: "ok", error: None })
}

async fn get_iface_limits_handler(State(state): State<ApiState>) -> Json<ApiEnvelope<Vec<InterfaceRateLimitApi>>> {
    let data = {
        let guard = state.policy_runtime.read().await;
        get_iface_limits(&guard)
    };
    Json(ApiEnvelope { ok: true, data, error: None })
}

async fn set_iface_limit_handler(
    State(state): State<ApiState>,
    Json(req): Json<SetInterfaceRateLimitRequest>,
) -> Json<ApiEnvelope<&'static str>> {
    let result = {
        let topology_guard = state.topology.read().await;
        let mut guard = state.policy_runtime.write().await;
        set_iface_limit(&mut guard, req, &topology_guard)
    };
    to_simple_response(result)
}

async fn delete_iface_limit_handler(
    State(state): State<ApiState>,
    Path(iface): Path<String>,
) -> Json<ApiEnvelope<&'static str>> {
    let result = {
        let mut guard = state.policy_runtime.write().await;
        delete_iface_limit(&mut guard, &iface)
    };
    to_simple_response(result)
}

async fn get_guest_defaults_handler(State(state): State<ApiState>) -> Json<ApiEnvelope<Vec<InterfaceRateLimitApi>>> {
    let data = {
        let guard = state.policy_runtime.read().await;
        get_guest_defaults(&guard)
    };
    Json(ApiEnvelope { ok: true, data, error: None })
}

async fn set_guest_default_handler(
    State(state): State<ApiState>,
    Json(req): Json<SetInterfaceRateLimitRequest>,
) -> Json<ApiEnvelope<&'static str>> {
    let result = {
        let topology_guard = state.topology.read().await;
        let mut guard = state.policy_runtime.write().await;
        set_guest_default(&mut guard, req, &topology_guard)
    };
    to_simple_response(result)
}

async fn delete_guest_default_handler(
    State(state): State<ApiState>,
    Path(iface): Path<String>,
) -> Json<ApiEnvelope<&'static str>> {
    let result = {
        let mut guard = state.policy_runtime.write().await;
        delete_guest_default(&mut guard, &iface)
    };
    to_simple_response(result)
}

async fn get_guest_whitelist_handler(State(state): State<ApiState>) -> Json<ApiEnvelope<Vec<GuestWhitelistEntryApi>>> {
    let data = {
        let guard = state.policy_runtime.read().await;
        get_guest_whitelist(&guard)
    };
    Json(ApiEnvelope { ok: true, data, error: None })
}

async fn add_guest_whitelist_handler(
    State(state): State<ApiState>,
    Json(req): Json<GuestWhitelistEntryRequest>,
) -> Json<ApiEnvelope<&'static str>> {
    let result = {
        let topology_guard = state.topology.read().await;
        let mut guard = state.policy_runtime.write().await;
        add_guest_whitelist(&mut guard, req, &topology_guard)
    };
    to_simple_response(result)
}

async fn remove_guest_whitelist_handler(
    State(state): State<ApiState>,
    Json(req): Json<GuestWhitelistEntryRequest>,
) -> Json<ApiEnvelope<&'static str>> {
    let result = {
        let mut guard = state.policy_runtime.write().await;
        remove_guest_whitelist(&mut guard, req)
    };
    to_simple_response(result)
}

fn to_simple_response(result: anyhow::Result<()>) -> Json<ApiEnvelope<&'static str>> {
    if let Err(e) = result {
        return Json(ApiEnvelope {
            ok: false,
            data: "error",
            error: Some(e.to_string()),
        });
    }
    Json(ApiEnvelope { ok: true, data: "ok", error: None })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{init_runtime, parse_policy};
    use crate::topology::{Interface, InterfaceZone, TopologySnapshot};
    use crate::utils::system_utils::InterfaceRole;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn mock_api_state() -> ApiState {
        let topo = TopologySnapshot::from_interfaces(vec![
            Interface {
                ifindex: 1,
                name: "eth0".to_string(),
                role: InterfaceRole::Ethernet,
                zone: InterfaceZone::Other,
                parent_ifindex: None,
                ipv4_cidrs: vec![],
                ipv6_cidrs: vec![],
            },
            Interface {
                ifindex: 2,
                name: "guest0".to_string(),
                role: InterfaceRole::Ethernet,
                zone: InterfaceZone::Guest,
                parent_ifindex: None,
                ipv4_cidrs: vec![],
                ipv6_cidrs: vec![],
            },
        ]);
        ApiState {
            snapshot: Arc::new(RwLock::new(SnapshotData::default())),
            history: Arc::new(RwLock::new(TrafficHistory::new(60))),
            histogram: Arc::new(RwLock::new(HistogramHistory::new())),
            policy_runtime: Arc::new(RwLock::new(init_runtime(parse_policy()))),
            topology: Arc::new(RwLock::new(topo)),
        }
    }

    #[tokio::test]
    async fn api_health() {
        let app = router(mock_api_state());
        let req = Request::get("/api/health").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let env: ApiEnvelope<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(env.ok);
    }

    #[tokio::test]
    async fn api_snapshot() {
        let app = router(mock_api_state());
        let req = Request::get("/api/snapshot").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_overview() {
        let app = router(mock_api_state());
        let req = Request::get("/api/overview").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_devices() {
        let app = router(mock_api_state());
        let req = Request::get("/api/devices").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_devices_with_iface_filter() {
        let app = router(mock_api_state());
        let req = Request::get("/api/devices?iface=eth0").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_policy() {
        let app = router(mock_api_state());
        let req = Request::get("/api/policy").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_trend_missing_iface() {
        let app = router(mock_api_state());
        let req = Request::get("/api/trend").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let env: ApiEnvelope<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(!env.ok);
        assert!(env.error.unwrap().contains("iface"));
    }

    #[tokio::test]
    async fn api_trend_by_iface() {
        let app = router(mock_api_state());
        let req = Request::get("/api/trend?iface=eth0").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let env: ApiEnvelope<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(env.ok);
    }

    #[tokio::test]
    async fn api_histogram_missing_iface() {
        let app = router(mock_api_state());
        let req = Request::get("/api/histogram").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let env: ApiEnvelope<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(!env.ok);
        assert!(env.error.unwrap().contains("iface"));
    }

    #[tokio::test]
    async fn api_histogram_by_iface_with_traffic_type() {
        let app = router(mock_api_state());
        let req = Request::get("/api/histogram?iface=eth0&traffic_type=ipv4")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let env: ApiEnvelope<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(env.ok);
    }

    #[tokio::test]
    async fn api_schedules_get() {
        let app = router(mock_api_state());
        let req = Request::get("/api/rate_limit/schedules").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_schedules_post_valid() {
        let app = router(mock_api_state());
        let body = serde_json::json!({
            "mac": "aa:bb:cc:dd:ee:ff",
            "time_slot": { "start": "09:00", "end": "18:00", "days": [1,2,3,4,5] },
            "down_v4_kbps": 100,
            "down_v6_kbps": 100,
            "up_v4_kbps": 100,
            "up_v6_kbps": 100
        });
        let req = Request::post("/api/rate_limit/schedules")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_schedules_post_invalid_time() {
        let app = router(mock_api_state());
        let body = serde_json::json!({
            "mac": "aa:bb:cc:dd:ee:ff",
            "time_slot": { "start": "99:00", "end": "18:00", "days": [1,2,3,4,5] },
            "down_v4_kbps": 100,
            "down_v6_kbps": 100,
            "up_v4_kbps": 100,
            "up_v6_kbps": 100
        });
        let req = Request::post("/api/rate_limit/schedules")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn api_schedules_delete_not_exists() {
        let app = router(mock_api_state());
        let req = Request::delete("/api/rate_limit/schedules/nonexistent-id").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let env: ApiEnvelope<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(!env.ok);
    }

    #[tokio::test]
    async fn api_iface_limits_get() {
        let app = router(mock_api_state());
        let req = Request::get("/api/rate_limit/iface_limits").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_iface_limits_post() {
        let app = router(mock_api_state());
        let body = serde_json::json!({
            "iface": "eth0",
            "down_v4_kbps": 200,
            "down_v6_kbps": 100,
            "up_v4_kbps": 160,
            "up_v6_kbps": 80
        });
        let req = Request::post("/api/rate_limit/iface_limits")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_guest_defaults_get() {
        let app = router(mock_api_state());
        let req = Request::get("/api/rate_limit/guest_defaults").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_guest_defaults_post() {
        let app = router(mock_api_state());
        let body = serde_json::json!({
            "iface": "guest0",
            "down_v4_kbps": 50,
            "down_v6_kbps": 50,
            "up_v4_kbps": 50,
            "up_v6_kbps": 50
        });
        let req = Request::post("/api/rate_limit/guest_defaults")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_guest_whitelist_get() {
        let app = router(mock_api_state());
        let req = Request::get("/api/rate_limit/guest_whitelist").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_guest_whitelist_post() {
        let app = router(mock_api_state());
        let body = serde_json::json!({
            "iface": "guest0",
            "mac": "aa:bb:cc:dd:ee:ff"
        });
        let req = Request::post("/api/rate_limit/guest_whitelist")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_guest_whitelist_delete() {
        let app = router(mock_api_state());
        let body = serde_json::json!({
            "iface": "guest0",
            "mac": "aa:bb:cc:dd:ee:ff"
        });
        let req = Request::builder()
            .method("DELETE")
            .uri("/api/rate_limit/guest_whitelist")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
}
