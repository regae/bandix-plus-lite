use axum_server::tls_rustls::RustlsConfig;
use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderValue, Method, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use chrono::{Datelike, Duration as ChronoDuration, Local, TimeZone};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;

use crate::conntrack::{ConnectionDeviceStats, ConnectionFlow, ConnectionGlobalStats, ConntrackMonitor};
use crate::dns::{DnsConfig, DnsMonitor, DnsQueriesQuery, DnsQueriesResponse, DnsStats};
use crate::monitor::{
    AggregateBucket, AggregatedBucket, HistogramHistory, HistoryDirection, HistorySample, HistoryTrafficType, KnownDevice, MonitorRuntime,
    SnapshotData, TrafficHistory,
};
use crate::persistence::PersistenceManager;
use crate::topology::TopologySnapshot;
use crate::utils::mac_utils;

#[derive(Clone)]
pub struct ApiState {
    pub snapshot: Arc<RwLock<SnapshotData>>,
    pub history: Arc<RwLock<TrafficHistory>>,
    pub histogram: Arc<RwLock<HistogramHistory>>,
    pub monitor_runtime: Arc<RwLock<MonitorRuntime>>,
    pub topology: Arc<RwLock<TopologySnapshot>>,
    pub dns_monitor: Arc<RwLock<DnsMonitor>>,
    pub connection_monitor: Arc<ConntrackMonitor>,
    pub persistence: Option<Arc<PersistenceManager>>,
}

#[derive(Clone)]
struct ApiAuth {
    bearer_token: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct DevicesQuery {
    pub iface: Option<String>,
    pub period: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct OverviewQuery {
    pub period: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SetDeviceHostnameRequest {
    pub iface: String,
    pub mac: String,
    pub hostname: String,
}

#[derive(Debug, Deserialize)]
pub struct DeleteDeviceRequest {
    pub iface: String,
    pub mac: String,
}

#[derive(Debug, Serialize)]
pub struct DeleteDeviceResult {
    pub device_state_deleted: bool,
    pub traffic_data_deleted: bool,
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

#[derive(Debug, Deserialize, Default)]
pub struct UsageRankingQuery {
    /// 内核网卡名；服务端解析为 ifindex。
    pub iface: Option<String>,
    /// 与 `/api/trend` 相同：`all` / `ipv4` / `ipv6`。
    pub traffic_type: Option<String>,
    pub start_ms: Option<u64>,
    pub end_ms: Option<u64>,
    /// 返回条目数；`0` 表示不限制。
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ConnectionFlowsQuery {
    /// Limit results to flows whose original source or reply destination is
    /// one of these comma-separated client addresses.
    pub ip: Option<String>,
    pub protocol: Option<String>,
    pub state: Option<String>,
    pub page: Option<usize>,
    pub page_size: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct ConnectionDevicesResponse {
    pub enabled: bool,
    #[serde(rename = "g")]
    pub global: ConnectionGlobalStats,
    #[serde(rename = "d")]
    pub devices: Vec<ConnectionDeviceStats>,
    #[serde(rename = "cnt")]
    pub total_devices: usize,
    #[serde(rename = "last")]
    pub last_updated: u64,
    pub total_flows: usize,
    pub event_stream_available: bool,
    pub event_loss: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ConnectionFlowsResponse {
    pub enabled: bool,
    pub items: Vec<ConnectionFlow>,
    pub total: usize,
    pub page: usize,
    pub page_size: usize,
    pub total_pages: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsageRankingItem {
    pub iface: String,
    pub mac: String,
    pub hostname: String,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub up_bytes: u64,
    pub down_bytes: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiEnvelope<T> {
    pub ok: bool,
    pub data: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn router(state: ApiState, auth: ApiAuth, cors_origin: Option<HeaderValue>) -> Router {
    let mut cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .allow_headers([AUTHORIZATION, CONTENT_TYPE])
        .max_age(std::time::Duration::from_secs(600));
    if let Some(origin) = cors_origin {
        cors = cors.allow_origin(origin);
    }

    Router::new()
        .route("/api/health", get(health))
        .route("/api/snapshot", get(snapshot))
        .route("/api/overview", get(overview))
        .route("/api/devices", get(devices).delete(delete_device_handler))
        .route("/api/devices/hostname", put(set_device_hostname_handler))
        .route("/api/trend", get(history))
        .route("/api/histogram", get(aggregate))
        .route("/api/usage_ranking", get(usage_ranking))
        .route("/api/connection/devices", get(connection_devices))
        .route("/api/connection/flows", get(connection_flows))
        .route("/api/dns/queries", get(dns_queries))
        .route("/api/dns/stats", get(dns_stats))
        .route("/api/dns/config", get(dns_config))
        .with_state(state)
        .layer(middleware::from_fn_with_state(auth, require_bearer_token))
        .layer(cors)
}

async fn require_bearer_token(State(auth): State<ApiAuth>, request: Request<axum::body::Body>, next: Next) -> Response {
    // Let CorsLayer answer preflight requests without credentials. The actual
    // request is always authenticated, including /api/health.
    if request.method() == Method::OPTIONS {
        return next.run(request).await;
    }

    let supplied = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or("");
    if !bearer_token_matches(supplied.as_bytes(), auth.bearer_token.as_bytes()) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    next.run(request).await
}

fn bearer_token_matches(supplied: &[u8], expected: &[u8]) -> bool {
    // Compare a fixed number of bytes to avoid leaking token contents through
    // early byte-by-byte string comparison. The token length is public config.
    let mut difference = (supplied.len() != expected.len()) as u8;
    for i in 0..expected.len() {
        difference |= supplied.get(i).copied().unwrap_or(0) ^ expected[i];
    }
    difference == 0
}

async fn usage_ranking(
    State(state): State<ApiState>,
    Query(q): Query<UsageRankingQuery>,
) -> Result<Json<ApiEnvelope<Vec<UsageRankingItem>>>, StatusCode> {
    let Some(iface) = q.iface.clone().filter(|s| !s.trim().is_empty()) else {
        return Err(StatusCode::BAD_REQUEST);
    };

    let tt = parse_traffic_type(q.traffic_type.as_deref());

    let now_ms = Local::now().timestamp_millis() as u64;
    let default_start = (Local::now() - ChronoDuration::days(365)).timestamp_millis() as u64;
    let start_ms = q.start_ms.unwrap_or(default_start);
    let end_ms = q.end_ms.unwrap_or(now_ms);
    if end_ms < start_ms {
        return Err(StatusCode::BAD_REQUEST);
    }

    let limit = q.limit.filter(|v| *v > 0);

    let is_all = iface == "all";
    let ifindex = if is_all {
        0
    } else {
        match resolve_query_iface_to_ifindex(&state, Some(iface.clone())).await {
            Ok(i) => i,
            Err(_) => return Err(StatusCode::BAD_REQUEST),
        }
    };

    let runtime = state.monitor_runtime.read().await;
    let histogram = state.histogram.read().await;

    let mut items: Vec<UsageRankingItem> = runtime
        .device_registry
        .entries
        .iter()
        .filter_map(|((dev_ifindex, mac), dev)| {
            if !is_all && *dev_ifindex != ifindex {
                return None;
            }

            let mac_s = mac_utils::to_string(mac);
            let buckets = histogram.query_aggregate(*dev_ifindex, Some(mac_s.as_str()), start_ms, end_ms, AggregateBucket::Daily);
            let mut up: u64 = 0;
            let mut down: u64 = 0;
            for b in buckets.into_iter().map(|b| b.with_traffic_type(tt)) {
                up = up.saturating_add(b.up_v4_bytes.saturating_add(b.up_v6_bytes));
                down = down.saturating_add(b.down_v4_bytes.saturating_add(b.down_v6_bytes));
            }
            let total = up.saturating_add(down);
            if total == 0 {
                return None;
            }

            Some(UsageRankingItem {
                iface: dev.logical_iface.clone(),
                mac: mac_s,
                hostname: dev.hostname.clone(),
                ipv4: dev.ipv4.clone(),
                ipv6: dev.ipv6.clone(),
                up_bytes: up,
                down_bytes: down,
                total_bytes: total,
            })
        })
        .collect();

    items.sort_by(|a, b| b.total_bytes.cmp(&a.total_bytes).then(a.mac.cmp(&b.mac)));
    if let Some(limit) = limit {
        items.truncate(limit);
    }

    Ok(Json(ApiEnvelope {
        ok: true,
        data: items,
        error: None,
    }))
}

pub async fn start_server(
    bind_addr: &str,
    state: ApiState,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    api_token_file: &str,
    cors_origin: Option<String>,
) -> anyhow::Result<()> {
    let config = load_tls_config(tls_cert, tls_key).await?;
    let bearer_token = std::fs::read_to_string(api_token_file)
        .map_err(|error| anyhow::anyhow!("failed to read API token file {api_token_file}: {error}"))?;
    let bearer_token = bearer_token.trim().to_string();
    anyhow::ensure!(
        bearer_token.len() >= 32,
        "API token file {api_token_file} must contain at least 32 characters"
    );
    let cors_origin = cors_origin.map(parse_cors_origin).transpose()?;
    if cors_origin.is_none() {
        warn!("API CORS is disabled; configure --cors-origin with the exact LuCI origin for browser direct fetch");
    }
    let app = router(state, ApiAuth { bearer_token }, cors_origin);
    let listener = bind_api_listener(bind_addr).await?;

    if let Some(config) = config {
        log::info!("API server listening on https://{bind_addr}");
        axum_server::from_tcp_rustls(listener, config)?
            .serve(app.into_make_service())
            .await
            .map_err(|error| anyhow::anyhow!("API server failed on {bind_addr}: {error}"))?;
    } else {
        log::info!("API server listening on http://{bind_addr}");
        axum_server::from_tcp(listener)?
            .serve(app.into_make_service())
            .await
            .map_err(|error| anyhow::anyhow!("API server failed on {bind_addr}: {error}"))?;
    }
    Ok(())
}

fn parse_cors_origin(origin: String) -> anyhow::Result<HeaderValue> {
    let authority = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
        .ok_or_else(|| anyhow::anyhow!("--cors-origin must be an http:// or https:// origin"))?;
    anyhow::ensure!(
        !authority.is_empty()
            && !authority.contains('/')
            && !authority.contains('?')
            && !authority.contains('#')
            && !authority.contains('@'),
        "--cors-origin must contain only scheme, host, and optional port (no path or credentials)"
    );
    origin
        .parse::<HeaderValue>()
        .map_err(|error| anyhow::anyhow!("invalid --cors-origin: {error}"))
}

async fn bind_api_listener(bind_addr: &str) -> anyhow::Result<std::net::TcpListener> {
    // Tokio resolves hostnames and tries each resolved address, preserving
    // the previous bind behavior for hosts such as localhost.
    Ok(tokio::net::TcpListener::bind(bind_addr)
        .await
        .map_err(|e| anyhow::anyhow!("failed to bind {bind_addr}: {e}"))?
        .into_std()?)
}

async fn load_tls_config(cert: Option<String>, key: Option<String>) -> anyhow::Result<Option<RustlsConfig>> {
    match (cert, key) {
        (Some(cert), Some(key)) => RustlsConfig::from_pem_file(cert, key)
            .await
            .map(Some)
            .map_err(|e| anyhow::anyhow!("failed to load TLS config: {e}")),
        (None, None) => Ok(None),
        _ => anyhow::bail!("--tls-cert and --tls-key must be supplied together"),
    }
}

async fn health() -> Json<ApiEnvelope<&'static str>> {
    Json(ApiEnvelope {
        ok: true,
        data: "ok",
        error: None,
    })
}

async fn dns_queries(State(state): State<ApiState>, Query(query): Query<DnsQueriesQuery>) -> Json<ApiEnvelope<DnsQueriesResponse>> {
    let response = state.dns_monitor.read().await.queries(&query, now_millis());
    Json(ApiEnvelope {
        ok: true,
        data: response,
        error: None,
    })
}

async fn dns_stats(State(state): State<ApiState>) -> Json<ApiEnvelope<DnsStats>> {
    let response = state.dns_monitor.read().await.stats(now_millis());
    Json(ApiEnvelope {
        ok: true,
        data: response,
        error: None,
    })
}

async fn dns_config(State(state): State<ApiState>) -> Json<ApiEnvelope<DnsConfig>> {
    Json(ApiEnvelope {
        ok: true,
        data: state.dns_monitor.read().await.config(),
        error: None,
    })
}

async fn connection_devices(State(state): State<ApiState>) -> Json<ApiEnvelope<ConnectionDevicesResponse>> {
    let summary = state.connection_monitor.summary().await;
    let total_devices = summary.devices.len();
    let response = ConnectionDevicesResponse {
        enabled: summary.enabled,
        global: summary.global,
        devices: summary.devices,
        total_devices,
        last_updated: summary.last_updated,
        total_flows: summary.total_flows,
        event_stream_available: summary.event_stream_available,
        event_loss: summary.event_loss,
        last_error: summary.last_error,
    };
    Json(ApiEnvelope {
        ok: true,
        data: response,
        error: None,
    })
}

async fn connection_flows(
    State(state): State<ApiState>,
    Query(query): Query<ConnectionFlowsQuery>,
) -> Json<ApiEnvelope<ConnectionFlowsResponse>> {
    let ip = query.ip.as_deref().map(str::trim).filter(|value| !value.is_empty());
    let protocol = query.protocol.as_deref().map(str::trim).filter(|value| !value.is_empty());
    let state_filter = query.state.as_deref().map(str::trim).filter(|value| !value.is_empty());
    let (enabled, flows) = state.connection_monitor.filtered_flows(ip, protocol, state_filter).await;

    let total = flows.len();
    let page_size = query.page_size.unwrap_or(100).clamp(1, 500);
    let total_pages = total.saturating_add(page_size - 1) / page_size;
    let total_pages = total_pages.max(1);
    let page = query.page.unwrap_or(1).max(1).min(total_pages);
    let start = page.saturating_sub(1).saturating_mul(page_size);
    let items = if start < total {
        flows.into_iter().skip(start).take(page_size).collect()
    } else {
        Vec::new()
    };
    Json(ApiEnvelope {
        ok: true,
        data: ConnectionFlowsResponse {
            enabled,
            items,
            total,
            page,
            page_size,
            total_pages,
        },
        error: None,
    })
}

async fn snapshot(State(state): State<ApiState>) -> Json<ApiEnvelope<SnapshotData>> {
    Json(ApiEnvelope {
        ok: true,
        data: state.snapshot.read().await.clone(),
        error: None,
    })
}

async fn overview(
    State(state): State<ApiState>,
    Query(q): Query<OverviewQuery>,
) -> Json<ApiEnvelope<Vec<crate::monitor::InterfaceOverviewItem>>> {
    let period = match parse_period_scope(q.period.as_deref()) {
        Ok(v) => v,
        Err(e) => {
            return Json(ApiEnvelope {
                ok: false,
                data: Vec::new(),
                error: Some(e),
            });
        }
    };
    let mut data = state.snapshot.read().await.interfaces.clone();
    if let Some(scope) = period {
        let (start_ms, end_ms) = period_range_ms(scope, now_millis());
        let histogram = state.histogram.read().await;
        for item in &mut data {
            let buckets = histogram.query_aggregate(item.ifindex, None, start_ms, end_ms, AggregateBucket::Hourly);
            item.cumulative = cumulative_from_buckets(&buckets);
        }
    }
    Json(ApiEnvelope {
        ok: true,
        data,
        error: None,
    })
}

async fn devices(State(state): State<ApiState>, Query(q): Query<DevicesQuery>) -> Json<ApiEnvelope<Vec<crate::monitor::DeviceListItem>>> {
    let period = match parse_period_scope(q.period.as_deref()) {
        Ok(v) => v,
        Err(e) => {
            return Json(ApiEnvelope {
                ok: false,
                data: Vec::new(),
                error: Some(e),
            });
        }
    };
    let devices = state.snapshot.read().await.devices.clone();
    let mut filtered: Vec<_> = devices
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
    if let Some(scope) = period {
        let (start_ms, end_ms) = period_range_ms(scope, now_millis());
        let histogram = state.histogram.read().await;
        for item in &mut filtered {
            let buckets = histogram.query_aggregate(item.ifindex, Some(item.mac.as_str()), start_ms, end_ms, AggregateBucket::Hourly);
            item.cumulative = cumulative_from_buckets(&buckets);
        }
    }
    Json(ApiEnvelope {
        ok: true,
        data: filtered,
        error: None,
    })
}

async fn set_device_hostname_handler(
    State(state): State<ApiState>,
    Json(req): Json<SetDeviceHostnameRequest>,
) -> Json<ApiEnvelope<&'static str>> {
    let iface = req.iface.trim();
    if iface.is_empty() {
        warn!("api PUT /api/devices/hostname rejected: iface is required");
        return Json(ApiEnvelope {
            ok: false,
            data: "error",
            error: Some("iface is required".to_string()),
        });
    }
    let mac_raw = req.mac.trim();
    if mac_raw.is_empty() {
        warn!("api PUT /api/devices/hostname rejected: mac is required iface={}", iface);
        return Json(ApiEnvelope {
            ok: false,
            data: "error",
            error: Some("mac is required".to_string()),
        });
    }
    let hostname = req.hostname.trim().to_string();
    if hostname.is_empty() {
        warn!(
            "api PUT /api/devices/hostname rejected: hostname is required iface={} mac={}",
            iface, mac_raw
        );
        return Json(ApiEnvelope {
            ok: false,
            data: "error",
            error: Some("hostname is required".to_string()),
        });
    }

    let ifindex = {
        let topo = state.topology.read().await;
        let Some(v) = topo.ifindex_by_name(iface) else {
            warn!(
                "api PUT /api/devices/hostname rejected: unknown iface={} mac={}",
                iface, mac_raw
            );
            return Json(ApiEnvelope {
                ok: false,
                data: "error",
                error: Some(format!("unknown iface: {iface}")),
            });
        };
        v
    };
    let mac = match mac_utils::from_str(mac_raw) {
        Ok(v) => v,
        Err(_) => {
            warn!(
                "api PUT /api/devices/hostname rejected: invalid mac iface={} mac_raw={}",
                iface, mac_raw
            );
            return Json(ApiEnvelope {
                ok: false,
                data: "error",
                error: Some("invalid mac format".to_string()),
            });
        }
    };

    let mac_norm = mac_utils::to_string(&mac);
    let mut snapshot_device: Option<crate::monitor::DeviceListItem> = None;
    {
        let mut snapshot = state.snapshot.write().await;
        for dev in &mut snapshot.devices {
            if dev.ifindex == ifindex && dev.mac.eq_ignore_ascii_case(&mac_norm) {
                dev.hostname = hostname.clone();
                snapshot_device = Some(dev.clone());
            }
        }
    }

    {
        let mut runtime = state.monitor_runtime.write().await;
        if let Some(known) = runtime.device_registry.entries.get_mut(&(ifindex, mac)) {
            known.hostname = hostname.clone();
        } else if let Some(dev) = snapshot_device {
            runtime.device_registry.entries.insert(
                (ifindex, mac),
                KnownDevice {
                    ifindex,
                    mac,
                    ipv4: dev.ipv4,
                    ipv6: dev.ipv6,
                    hostname: hostname.clone(),
                    logical_iface: dev.logical_iface,
                    subnet: dev.subnet,
                    last_seen_ms: now_millis(),
                },
            );
        } else {
            warn!(
                "api PUT /api/devices/hostname rejected: device not found iface={} mac={}",
                iface, mac_norm
            );
            return Json(ApiEnvelope {
                ok: false,
                data: "error",
                error: Some("device not found".to_string()),
            });
        }
    }

    if let Err(e) = persist_monitor_runtime_state(&state).await {
        warn!(
            "api PUT /api/devices/hostname failed persist iface={} mac={} hostname={} err={}",
            iface, mac_norm, hostname, e
        );
        return Json(ApiEnvelope {
            ok: false,
            data: "error",
            error: Some(format!("persist devices state failed: {}", e)),
        });
    }

    info!(
        "api PUT /api/devices/hostname ok iface={} mac={} hostname={}",
        iface, mac_norm, hostname
    );

    Json(ApiEnvelope {
        ok: true,
        data: "ok",
        error: None,
    })
}

async fn delete_device_handler(
    State(state): State<ApiState>,
    Json(req): Json<DeleteDeviceRequest>,
) -> Json<ApiEnvelope<DeleteDeviceResult>> {
    let iface = req.iface.trim();
    if iface.is_empty() {
        return delete_device_error("iface is required");
    }
    let mac = match mac_utils::from_str(req.mac.trim()) {
        Ok(value) => value,
        Err(_) => return delete_device_error("invalid mac format"),
    };
    let mac_norm = mac_utils::to_string(&mac);
    let ifindex = {
        let topology = state.topology.read().await;
        let Some(value) = topology.ifindex_by_name(iface) else {
            return delete_device_error(&format!("unknown iface: {iface}"));
        };
        value
    };

    info!("api DELETE /api/devices call iface={} mac={}", iface, mac_norm);

    let snapshot_deleted = {
        let mut snapshot = state.snapshot.write().await;
        let before = snapshot.devices.len();
        snapshot
            .devices
            .retain(|device| device.ifindex != ifindex || !device.mac.eq_ignore_ascii_case(&mac_norm));
        snapshot.devices.len() != before
    };
    let runtime_deleted = state.monitor_runtime.write().await.remove_device(ifindex, mac);
    let recent_traffic_deleted = state.history.write().await.remove_device(ifindex, &mac_norm);
    let histogram_deleted = state.histogram.write().await.remove_device(ifindex, &mac_norm);

    let disk_traffic_deleted = if let Some(persistence) = &state.persistence {
        match persistence.delete_device_traffic(iface, &mac_norm) {
            Ok(deleted) => deleted,
            Err(error) => {
                warn!(
                    "api DELETE /api/devices failed deleting traffic iface={} mac={} err={}",
                    iface, mac_norm, error
                );
                return delete_device_error(&format!("delete device traffic failed: {error}"));
            }
        }
    } else {
        false
    };

    if let Err(error) = persist_device_deletion_state(&state).await {
        warn!(
            "api DELETE /api/devices failed persist iface={} mac={} err={}",
            iface, mac_norm, error
        );
        return delete_device_error(&format!("persist device deletion failed: {error}"));
    }

    let result = DeleteDeviceResult {
        device_state_deleted: snapshot_deleted || runtime_deleted,
        traffic_data_deleted: recent_traffic_deleted || histogram_deleted || disk_traffic_deleted,
    };
    info!(
        "api DELETE /api/devices ok iface={} mac={} device_state_deleted={} traffic_data_deleted={}",
        iface, mac_norm, result.device_state_deleted, result.traffic_data_deleted
    );
    Json(ApiEnvelope {
        ok: true,
        data: result,
        error: None,
    })
}

fn delete_device_error(message: &str) -> Json<ApiEnvelope<DeleteDeviceResult>> {
    Json(ApiEnvelope {
        ok: false,
        data: DeleteDeviceResult {
            device_state_deleted: false,
            traffic_data_deleted: false,
        },
        error: Some(message.to_string()),
    })
}

#[derive(Debug, Clone, Copy)]
enum PeriodScope {
    Today,
    Week,
    Month,
    Year,
}

fn parse_period_scope(input: Option<&str>) -> Result<Option<PeriodScope>, String> {
    let Some(raw) = input else {
        return Ok(None);
    };
    let s = raw.trim();
    if s.is_empty() {
        return Ok(None);
    }
    match s.to_ascii_lowercase().as_str() {
        "all" => Ok(None),
        "today" => Ok(Some(PeriodScope::Today)),
        "week" => Ok(Some(PeriodScope::Week)),
        "month" => Ok(Some(PeriodScope::Month)),
        "year" => Ok(Some(PeriodScope::Year)),
        _ => Err("invalid period, expected one of: all, today, week, month, year".to_string()),
    }
}

fn period_range_ms(scope: PeriodScope, now_ms: u64) -> (u64, u64) {
    let now = match Local.timestamp_millis_opt(now_ms as i64) {
        chrono::LocalResult::Single(v) => v,
        _ => return (0, now_ms),
    };
    let today_start_naive = now.date_naive().and_hms_milli_opt(0, 0, 0, 0).unwrap();
    let today_start = Local.from_local_datetime(&today_start_naive).unwrap().timestamp_millis() as u64;

    let start = match scope {
        PeriodScope::Today => today_start,
        PeriodScope::Week => {
            let days = now.weekday().num_days_from_monday() as i64;
            let week_start_naive = (now.date_naive() - ChronoDuration::days(days))
                .and_hms_milli_opt(0, 0, 0, 0)
                .unwrap();
            Local.from_local_datetime(&week_start_naive).unwrap().timestamp_millis() as u64
        }
        PeriodScope::Month => {
            let month_start_naive = now.date_naive().with_day(1).unwrap().and_hms_milli_opt(0, 0, 0, 0).unwrap();
            Local.from_local_datetime(&month_start_naive).unwrap().timestamp_millis() as u64
        }
        PeriodScope::Year => {
            let year_start_naive = now
                .date_naive()
                .with_month(1)
                .unwrap()
                .with_day(1)
                .unwrap()
                .and_hms_milli_opt(0, 0, 0, 0)
                .unwrap();
            Local.from_local_datetime(&year_start_naive).unwrap().timestamp_millis() as u64
        }
    };
    (start, now_ms)
}

fn cumulative_from_buckets(buckets: &[AggregatedBucket]) -> crate::monitor::CounterQuad {
    let mut out = crate::monitor::CounterQuad::default();
    for b in buckets {
        out.up_v4_bytes = out.up_v4_bytes.saturating_add(b.up_v4_bytes);
        out.down_v4_bytes = out.down_v4_bytes.saturating_add(b.down_v4_bytes);
        out.up_v6_bytes = out.up_v6_bytes.saturating_add(b.up_v6_bytes);
        out.down_v6_bytes = out.down_v6_bytes.saturating_add(b.down_v6_bytes);
    }
    out
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

async fn resolve_query_iface_to_ifindex(state: &ApiState, iface: Option<String>) -> Result<u32, String> {
    let name = iface
        .and_then(|s| {
            let t = s.trim();
            if t.is_empty() { None } else { Some(t.to_string()) }
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

async fn history(State(state): State<ApiState>, Query(q): Query<HistoryQuery>) -> Json<ApiEnvelope<Vec<HistorySample>>> {
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
        state.history.read().await.query_iface(ifindex, traffic_type, direction)
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

async fn aggregate(State(state): State<ApiState>, Query(q): Query<AggregateQuery>) -> Json<ApiEnvelope<Vec<AggregatedBucket>>> {
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
    let mac_filter = q.mac.as_deref().filter(|s| !s.trim().is_empty());

    let result: Vec<AggregatedBucket> = if let Some(mac) = mac_filter {
        let histogram = state.histogram.read().await;
        histogram
            .query_aggregate(ifindex, Some(mac), start_ms, end_ms, bucket)
            .into_iter()
            .map(|b| b.with_traffic_type(traffic_type))
            .collect()
    } else {
        // "all devices" 口径：按设备维度聚合后再求和，避免包含无法归属到设备的流量。
        let runtime = state.monitor_runtime.read().await;
        let mut macs = Vec::new();
        for ((dev_ifindex, mac), _dev) in &runtime.device_registry.entries {
            if *dev_ifindex == ifindex {
                macs.push(mac_utils::to_string(mac));
            }
        }
        drop(runtime);

        let histogram = state.histogram.read().await;
        let mut by_window: BTreeMap<(u64, u64), AggregatedBucket> = BTreeMap::new();
        for mac in macs {
            let buckets = histogram.query_aggregate(ifindex, Some(mac.as_str()), start_ms, end_ms, bucket);
            for b in buckets {
                let key = (b.start_ts_ms, b.end_ts_ms);
                let entry = by_window.entry(key).or_insert_with(|| empty_bucket(key.0, key.1));
                accumulate_bucket(entry, &b);
            }
        }

        by_window.into_values().map(|b| b.with_traffic_type(traffic_type)).collect()
    };
    Json(ApiEnvelope {
        ok: true,
        data: result,
        error: None,
    })
}

fn empty_bucket(start_ts_ms: u64, end_ts_ms: u64) -> AggregatedBucket {
    AggregatedBucket {
        start_ts_ms,
        end_ts_ms,
        sample_count: 0,
        up_v4_bytes: 0,
        down_v4_bytes: 0,
        up_v6_bytes: 0,
        down_v6_bytes: 0,
        up_v4_bps_sum: 0,
        up_v4_bps_max: 0,
        up_v4_bps_min: 0,
        up_v4_bps_avg: 0,
        up_v4_bps_p95: 0,
        down_v4_bps_sum: 0,
        down_v4_bps_max: 0,
        down_v4_bps_min: 0,
        down_v4_bps_avg: 0,
        down_v4_bps_p95: 0,
        up_v6_bps_sum: 0,
        up_v6_bps_max: 0,
        up_v6_bps_min: 0,
        up_v6_bps_avg: 0,
        up_v6_bps_p95: 0,
        down_v6_bps_sum: 0,
        down_v6_bps_max: 0,
        down_v6_bps_min: 0,
        down_v6_bps_avg: 0,
        down_v6_bps_p95: 0,
    }
}

fn accumulate_bucket(dst: &mut AggregatedBucket, src: &AggregatedBucket) {
    dst.up_v4_bytes = dst.up_v4_bytes.saturating_add(src.up_v4_bytes);
    dst.down_v4_bytes = dst.down_v4_bytes.saturating_add(src.down_v4_bytes);
    dst.up_v6_bytes = dst.up_v6_bytes.saturating_add(src.up_v6_bytes);
    dst.down_v6_bytes = dst.down_v6_bytes.saturating_add(src.down_v6_bytes);
    dst.up_v4_bps_avg = dst.up_v4_bps_avg.saturating_add(src.up_v4_bps_avg);
    dst.up_v4_bps_max = dst.up_v4_bps_max.saturating_add(src.up_v4_bps_max);
    dst.up_v4_bps_min = dst.up_v4_bps_min.saturating_add(src.up_v4_bps_min);
    dst.up_v4_bps_p95 = dst.up_v4_bps_p95.saturating_add(src.up_v4_bps_p95);
    dst.down_v4_bps_avg = dst.down_v4_bps_avg.saturating_add(src.down_v4_bps_avg);
    dst.down_v4_bps_max = dst.down_v4_bps_max.saturating_add(src.down_v4_bps_max);
    dst.down_v4_bps_min = dst.down_v4_bps_min.saturating_add(src.down_v4_bps_min);
    dst.down_v4_bps_p95 = dst.down_v4_bps_p95.saturating_add(src.down_v4_bps_p95);
    dst.up_v6_bps_avg = dst.up_v6_bps_avg.saturating_add(src.up_v6_bps_avg);
    dst.up_v6_bps_max = dst.up_v6_bps_max.saturating_add(src.up_v6_bps_max);
    dst.up_v6_bps_min = dst.up_v6_bps_min.saturating_add(src.up_v6_bps_min);
    dst.up_v6_bps_p95 = dst.up_v6_bps_p95.saturating_add(src.up_v6_bps_p95);
    dst.down_v6_bps_avg = dst.down_v6_bps_avg.saturating_add(src.down_v6_bps_avg);
    dst.down_v6_bps_max = dst.down_v6_bps_max.saturating_add(src.down_v6_bps_max);
    dst.down_v6_bps_min = dst.down_v6_bps_min.saturating_add(src.down_v6_bps_min);
    dst.down_v6_bps_p95 = dst.down_v6_bps_p95.saturating_add(src.down_v6_bps_p95);
}

async fn persist_monitor_runtime_state(state: &ApiState) -> anyhow::Result<()> {
    if let Some(persistence) = &state.persistence {
        let runtime = state.monitor_runtime.read().await;
        let topology = state.topology.read().await;
        persistence.save_monitor_runtime(&runtime, &topology)?;
    }
    Ok(())
}

async fn persist_device_deletion_state(state: &ApiState) -> anyhow::Result<()> {
    if let Some(persistence) = &state.persistence {
        let runtime = state.monitor_runtime.read().await;
        let topology = state.topology.read().await;
        persistence.save_monitor_runtime(&runtime, &topology)?;
    }
    Ok(())
}

#[cfg(test)]
mod server_tests {
    use super::*;

    #[test]
    fn bearer_token_comparison_accepts_only_exact_value() {
        assert!(bearer_token_matches(
            b"a-long-token-value-at-least-32-chars",
            b"a-long-token-value-at-least-32-chars"
        ));
        assert!(!bearer_token_matches(
            b"a-long-token-value-at-least-32-charS",
            b"a-long-token-value-at-least-32-chars"
        ));
        assert!(!bearer_token_matches(b"short", b"a-long-token-value-at-least-32-chars"));
    }

    #[test]
    fn cors_origin_rejects_paths_and_non_http_schemes() {
        assert!(parse_cors_origin("http://192.168.1.1:80".into()).is_ok());
        assert!(parse_cors_origin("https://router.example".into()).is_ok());
        assert!(parse_cors_origin("http://router.example/luci".into()).is_err());
        assert!(parse_cors_origin("file://router.example".into()).is_err());
    }

    #[tokio::test]
    async fn listener_accepts_hostnames_and_ip_addresses() {
        // Do not require an IPv6 loopback address: IPv6 can be disabled on
        // the host running these tests. localhost still exercises resolution.
        for bind_addr in ["localhost:0", "127.0.0.1:0"] {
            let listener = bind_api_listener(bind_addr).await.unwrap();
            assert!(listener.local_addr().unwrap().ip().is_loopback());
            assert_ne!(listener.local_addr().unwrap().port(), 0);
            axum_server::from_tcp(listener).unwrap();
        }
        assert!(bind_api_listener("localhost:not-a-port").await.is_err());
    }

    #[tokio::test]
    async fn incomplete_tls_is_rejected_before_loading_files() {
        for (cert, key) in [(Some("missing.pem".into()), None), (None, Some("missing.pem".into()))] {
            let err = load_tls_config(cert, key).await.err().expect("incomplete TLS must fail");
            assert!(err.to_string().contains("must be supplied together"));
        }
        assert!(load_tls_config(None, None).await.unwrap().is_none());
        assert!(
            load_tls_config(Some("missing-cert.pem".into()), Some("missing-key.pem".into()))
                .await
                .is_err()
        );
    }
}
