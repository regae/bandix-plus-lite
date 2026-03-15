use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{Method, StatusCode};
use axum::routing::{delete, get, post, put};
use axum::response::IntoResponse;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};

use crate::monitor::{HistoryDirection, HistorySample, HistoryTrafficType, SnapshotData, TrafficHistory};
use crate::policy::{
    CreateScheduledRuleRequest, InterfaceDefaultRuleApi, PolicyItem, PolicyRuntime, ScheduledRuleApi, SetInterfaceDefaultRuleRequest,
    SetWhitelistEnabledRequest, UpdateScheduledRuleRequest, WhitelistMacRequest, WhitelistStateApi, create_scheduled_rule,
    delete_interface_default_rule, delete_scheduled_rule, get_interface_default_rules, get_scheduled_rules, get_whitelist_state,
    policy_items, set_interface_default_rule, set_whitelist_enabled, update_scheduled_rule, whitelist_add_mac, whitelist_remove_mac,
};
use crate::topology::TopologySnapshot;

#[derive(Clone)]
pub struct ApiState {
    pub snapshot: Arc<RwLock<SnapshotData>>,
    pub history: Arc<RwLock<TrafficHistory>>,
    pub policy_runtime: Arc<RwLock<PolicyRuntime>>,
    pub topology: TopologySnapshot,
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

#[derive(Debug, Serialize)]
pub struct ApiEnvelope<T> {
    pub ok: bool,
    pub data: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// 启动 HTTP API 服务，注册路由并监听指定地址
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
        .route("/api/history", get(history))
        .route("/api/policy", get(policy))
        .route("/api/rate_limit/schedules", get(get_schedules).post(create_schedule))
        .route("/api/rate_limit/schedules/{id}", put(update_schedule).delete(delete_schedule))
        .route("/api/rate_limit/whitelist", get(get_whitelist).post(add_whitelist).delete(remove_whitelist))
        .route("/api/rate_limit/whitelist/enabled", post(set_whitelist_enabled_handler))
        .route("/api/rate_limit/interface_defaults", get(get_interface_defaults).post(set_interface_default))
        .route("/api/rate_limit/interface_defaults/{iface}", delete(delete_interface_default))
        .with_state(state)
        .layer(cors);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// 健康检查端点
async fn health() -> Json<ApiEnvelope<&'static str>> {
    Json(ApiEnvelope { ok: true, data: "ok", error: None })
}

/// 返回完整流量快照（接口 + 设备）
async fn snapshot(State(state): State<ApiState>) -> Json<ApiEnvelope<SnapshotData>> {
    Json(ApiEnvelope {
        ok: true,
        data: state.snapshot.read().await.clone(),
        error: None,
    })
}

/// 返回接口级流量概览
async fn overview(State(state): State<ApiState>) -> Json<ApiEnvelope<Vec<crate::monitor::InterfaceOverviewItem>>> {
    // overview: 按命令行 --iface 的接口集合返回统计快照
    Json(ApiEnvelope {
        ok: true,
        data: state.snapshot.read().await.interfaces.clone(),
        error: None,
    })
}

/// 返回设备列表，支持按 iface 筛选
async fn devices(
    State(state): State<ApiState>,
    Query(q): Query<DevicesQuery>,
) -> Json<ApiEnvelope<Vec<crate::monitor::DeviceListItem>>> {
    // devices: 子网语义设备列表（逻辑接口），再叠加查询参数筛选
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

/// 返回接口或设备的流量历史曲线
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

/// 解析流量类型查询参数（all / ipv4 / ipv6）
fn parse_traffic_type(input: Option<&str>) -> HistoryTrafficType {
    match input.unwrap_or("all").to_ascii_lowercase().as_str() {
        "ipv4" => HistoryTrafficType::Ipv4,
        "ipv6" => HistoryTrafficType::Ipv6,
        _ => HistoryTrafficType::All,
    }
}

/// 解析方向查询参数（both / up / down）
fn parse_direction(input: Option<&str>) -> HistoryDirection {
    match input.unwrap_or("both").to_ascii_lowercase().as_str() {
        "up" => HistoryDirection::Up,
        "down" => HistoryDirection::Down,
        _ => HistoryDirection::Both,
    }
}

/// 返回当前生效的限速策略列表
async fn policy(State(state): State<ApiState>) -> Json<ApiEnvelope<Vec<PolicyItem>>> {
    let data = {
        let guard = state.policy_runtime.read().await;
        policy_items(&guard, &state.topology)
    };
    Json(ApiEnvelope { ok: true, data, error: None })
}

/// 获取所有定时限速规则
async fn get_schedules(State(state): State<ApiState>) -> Json<ApiEnvelope<Vec<ScheduledRuleApi>>> {
    let data = {
        let guard = state.policy_runtime.read().await;
        get_scheduled_rules(&guard)
    };
    Json(ApiEnvelope { ok: true, data, error: None })
}

/// 创建一条定时限速规则
async fn create_schedule(State(state): State<ApiState>, Json(req): Json<CreateScheduledRuleRequest>) -> impl IntoResponse {
    let result = {
        let mut guard = state.policy_runtime.write().await;
        create_scheduled_rule(&mut guard, req, &state.topology)
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
                    iface: None,
                    time_slot: crate::policy::TimeSlotApi { start: String::new(), end: String::new(), days: vec![] },
                    down_v4_kbps: 0,
                    down_v6_kbps: 0,
                    up_v4_kbps: 0,
                    up_v6_kbps: 0,
                    enabled: false,
                },
                error: Some(e.to_string()),
            }),
        )
            .into_response(),
    }
}

/// 更新指定 id 的定时限速规则
async fn update_schedule(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateScheduledRuleRequest>,
) -> impl IntoResponse {
    let result = {
        let mut guard = state.policy_runtime.write().await;
        update_scheduled_rule(&mut guard, &id, req, &state.topology)
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
                    iface: None,
                    time_slot: crate::policy::TimeSlotApi { start: String::new(), end: String::new(), days: vec![] },
                    down_v4_kbps: 0,
                    down_v6_kbps: 0,
                    up_v4_kbps: 0,
                    up_v6_kbps: 0,
                    enabled: false,
                },
                error: Some(e.to_string()),
            }),
        )
            .into_response(),
    }
}

/// 删除指定 id 的定时限速规则
async fn delete_schedule(State(state): State<ApiState>, Path(id): Path<String>) -> Json<ApiEnvelope<&'static str>> {
    {
        let mut guard = state.policy_runtime.write().await;
        let _ = delete_scheduled_rule(&mut guard, &id);
    }
    Json(ApiEnvelope { ok: true, data: "ok", error: None })
}

/// 获取白名单状态及其 MAC 列表
async fn get_whitelist(State(state): State<ApiState>) -> Json<ApiEnvelope<WhitelistStateApi>> {
    let data = {
        let guard = state.policy_runtime.read().await;
        get_whitelist_state(&guard)
    };
    Json(ApiEnvelope { ok: true, data, error: None })
}

/// 向白名单添加 MAC
async fn add_whitelist(State(state): State<ApiState>, Json(req): Json<WhitelistMacRequest>) -> Json<ApiEnvelope<&'static str>> {
    {
        let mut guard = state.policy_runtime.write().await;
        let _ = whitelist_add_mac(&mut guard, &req.mac);
    }
    Json(ApiEnvelope { ok: true, data: "ok", error: None })
}

/// 从白名单移除 MAC
async fn remove_whitelist(State(state): State<ApiState>, Json(req): Json<WhitelistMacRequest>) -> Json<ApiEnvelope<&'static str>> {
    {
        let mut guard = state.policy_runtime.write().await;
        let _ = whitelist_remove_mac(&mut guard, &req.mac);
    }
    Json(ApiEnvelope { ok: true, data: "ok", error: None })
}

/// 开启或关闭白名单模式
async fn set_whitelist_enabled_handler(
    State(state): State<ApiState>,
    Json(req): Json<SetWhitelistEnabledRequest>,
) -> Json<ApiEnvelope<&'static str>> {
    {
        let mut guard = state.policy_runtime.write().await;
        set_whitelist_enabled(&mut guard, req.enabled);
    }
    Json(ApiEnvelope { ok: true, data: "ok", error: None })
}

/// 获取各接口的默认限速规则
async fn get_interface_defaults(State(state): State<ApiState>) -> Json<ApiEnvelope<Vec<InterfaceDefaultRuleApi>>> {
    let data = {
        let guard = state.policy_runtime.read().await;
        get_interface_default_rules(&guard, &state.topology)
    };
    Json(ApiEnvelope { ok: true, data, error: None })
}

/// 设置指定接口的默认限速规则
async fn set_interface_default(
    State(state): State<ApiState>,
    Json(req): Json<SetInterfaceDefaultRuleRequest>,
) -> Json<ApiEnvelope<&'static str>> {
    {
        let mut guard = state.policy_runtime.write().await;
        let _ = set_interface_default_rule(&mut guard, req, &state.topology);
    }
    Json(ApiEnvelope { ok: true, data: "ok", error: None })
}

/// 删除指定接口的默认限速规则
async fn delete_interface_default(State(state): State<ApiState>, Path(iface): Path<String>) -> Json<ApiEnvelope<&'static str>> {
    {
        let mut guard = state.policy_runtime.write().await;
        let _ = delete_interface_default_rule(&mut guard, &iface, &state.topology);
    }
    Json(ApiEnvelope { ok: true, data: "ok", error: None })
}
