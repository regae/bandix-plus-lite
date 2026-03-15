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
    pub ifindex: Option<u32>,
    pub mac: Option<String>,
    pub traffic_type: Option<String>,
    pub direction: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct AggregateQuery {
    pub ifindex: Option<u32>,
    pub mac: Option<String>,
    pub start_ms: Option<u64>,
    pub end_ms: Option<u64>,
    pub bucket: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ApiEnvelope<T> {
    pub ok: bool,
    pub data: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn start_server(bind_addr: &str, state: ApiState) -> anyhow::Result<()> {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .allow_headers(Any);

    let app = Router::new()
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
        .layer(cors);

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

async fn history(
    State(state): State<ApiState>,
    Query(q): Query<HistoryQuery>,
) -> Json<ApiEnvelope<Vec<HistorySample>>> {
    let Some(ifindex) = q.ifindex else {
        return Json(ApiEnvelope {
            ok: false,
            data: Vec::new(),
            error: Some("ifindex is required".to_string()),
        });
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
    let Some(ifindex) = q.ifindex else {
        return Json(ApiEnvelope {
            ok: false,
            data: Vec::new(),
            error: Some("ifindex is required".to_string()),
        });
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
    let histogram = state.histogram.read().await;
    let result = histogram.query_aggregate(
        ifindex,
        q.mac.as_deref(),
        start_ms,
        end_ms,
        bucket,
    );
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

