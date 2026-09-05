use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{Method, StatusCode};
use axum::routing::{get, put};
use axum::{Json, Router};
use chrono::{Datelike, Duration as ChronoDuration, Local, TimeZone};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};

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
    pub persistence: Option<Arc<PersistenceManager>>,
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

pub fn router(state: ApiState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .allow_headers(Any);

    Router::new()
        .route("/api/health", get(health))
        .route("/api/snapshot", get(snapshot))
        .route("/api/overview", get(overview))
        .route("/api/devices", get(devices).delete(delete_device_handler))
        .route("/api/devices/hostname", put(set_device_hostname_handler))
        .route("/api/trend", get(history))
        .route("/api/histogram", get(aggregate))
        .route("/api/usage_ranking", get(usage_ranking))





        .with_state(state)
        .layer(cors)
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

    let ifindex = match resolve_query_iface_to_ifindex(&state, Some(iface.clone())).await {
        Ok(i) => i,
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };

    let runtime = state.monitor_runtime.read().await;
    let histogram = state.histogram.read().await;

    let mut items: Vec<UsageRankingItem> = runtime
        .device_registry
        .entries
        .iter()
        .filter_map(|((dev_ifindex, mac), dev)| {
            if *dev_ifindex != ifindex {
                return None;
            }

            let mac_s = mac_utils::to_string(mac);
            let buckets = histogram.query_aggregate(ifindex, Some(mac_s.as_str()), start_ms, end_ms, AggregateBucket::Daily);
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
                iface: iface.clone(),
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

pub async fn start_server(bind_addr: &str, state: ApiState) -> anyhow::Result<()> {
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .map_err(|error| anyhow::anyhow!("failed to bind API server to {bind_addr}: {error}"))?;
    log::info!("API server listening on {bind_addr}");
    axum::serve(listener, app)
        .await
        .map_err(|error| anyhow::anyhow!("API server failed on {bind_addr}: {error}"))?;
    Ok(())
}

async fn health() -> Json<ApiEnvelope<&'static str>> {
    Json(ApiEnvelope {
        ok: true,
        data: "ok",
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
        up_v4_bytes: 0,
        down_v4_bytes: 0,
        up_v6_bytes: 0,
        down_v6_bytes: 0,
        up_v4_bps_avg: 0,
        up_v4_bps_max: 0,
        up_v4_bps_min: 0,
        up_v4_bps_p95: 0,
        down_v4_bps_avg: 0,
        down_v4_bps_max: 0,
        down_v4_bps_min: 0,
        down_v4_bps_p95: 0,
        up_v6_bps_avg: 0,
        up_v6_bps_max: 0,
        up_v6_bps_min: 0,
        up_v6_bps_p95: 0,
        down_v6_bps_avg: 0,
        down_v6_bps_max: 0,
        down_v6_bps_min: 0,
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
