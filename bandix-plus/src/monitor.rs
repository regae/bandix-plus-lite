use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::Duration;

use aya::maps::HashMap as AyaHashMap;
use aya::Ebpf;
use bandix_plus_common::{DeviceTrafficKey, EcmTrafficKey, InterfaceTrafficKey, IpVersion, TrafficDirection, TrafficValue};
use chrono::{Local, TimeZone, Timelike};
use rustc_hash::{FxHashMap, FxHashSet};
use serde::{Deserialize, Serialize};

use crate::topology::TopologySnapshot;
use crate::utils::mac_utils;
use crate::utils::system_utils;
use crate::utils::time_utils;

fn pick_best_neighbor_state(a: &str, b: &str) -> String {
    let rank = |s: &str| match s {
        "REACHABLE" => 4,
        "STALE" => 3,
        "DELAY" => 2,
        "PROBE" => 1,
        _ => 0,
    };
    if a.is_empty() || rank(b) > rank(a) {
        b.to_string()
    } else {
        a.to_string()
    }
}

#[derive(Default)]
pub struct DeviceRegistry {
    pub entries: HashMap<(u32, [u8; 6]), KnownDevice>,
}

#[derive(Debug, Clone)]
pub struct KnownDevice {
    pub ifindex: u32,
    pub mac: [u8; 6],
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub hostname: String,
    pub logical_iface: String,
    pub subnet: String,
    #[allow(dead_code)]
    pub last_seen_ms: u64,
}

#[derive(Default)]
pub struct MonitorRuntime {
    pub buf_iface_stats: HashMap<InterfaceTrafficKey, TrafficValue>,
    pub buf_device_stats: HashMap<DeviceTrafficKey, TrafficValue>,
    pub buf_ecm_stats: HashMap<EcmTrafficKey, TrafficValue>,
    pub prev_iface_bytes: HashMap<InterfaceTrafficKey, u64>,
    pub prev_device_bytes: HashMap<DeviceTrafficKey, u64>,
    pub prev_ecm_bytes: HashMap<EcmTrafficKey, u64>,
    pub ecm_active_devices: FxHashSet<(u32, [u8; 6])>,
    pub cumulative_iface: HashMap<u32, CounterQuad>,
    pub cumulative_device: HashMap<(u32, [u8; 6]), CounterQuad>,
    pub smoothed_rates: HashMap<(u32, [u8; 6]), CounterQuad>,
    pub smoothed_iface_rates: HashMap<u32, CounterQuad>,
    pub smoothed_wan_ecm_rates: Option<CounterQuad>,
    pub smoothed_lan_ecm_rates: HashMap<u32, CounterQuad>,
    pub last_snapshot_ms: Option<u64>,
    pub last_sync_tracking_ms: u64,
    pub device_registry: DeviceRegistry,
    pub last_hostname_fetch_ms: u64,
    pub cached_hostnames: HashMap<[u8; 6], String>,
    pub last_ipv6_neigh_fetch_ms: u64,
    pub cached_ipv6_neighbors_raw: String,
    pub ecm_last_active_ms: HashMap<EcmTrafficKey, u64>,
}

impl MonitorRuntime {
    /// Remove all monitor-side state for one logical-interface/device pair.
    pub fn remove_device(&mut self, ifindex: u32, mac: [u8; 6]) -> bool {
        let mut removed = self.device_registry.entries.remove(&(ifindex, mac)).is_some();
        removed |= self.cumulative_device.remove(&(ifindex, mac)).is_some();
        removed |= self.smoothed_rates.remove(&(ifindex, mac)).is_some();

        let before = self.prev_device_bytes.len();
        self.prev_device_bytes.retain(|key, _| key.ifindex != ifindex || key.mac != mac);
        removed |= self.prev_device_bytes.len() != before;
        removed
    }
}

pub fn export_runtime_state(runtime: &MonitorRuntime, topology: &TopologySnapshot) -> MonitorRuntimeState {
    let mut known_devices = Vec::new();
    for ((ifindex, mac), dev) in &runtime.device_registry.entries {
        let logical_iface = topology
            .by_ifindex(*ifindex)
            .map(|x| x.name.clone())
            .unwrap_or_else(|| dev.logical_iface.clone());
        known_devices.push(PersistedKnownDevice {
            logical_iface,
            mac: mac_utils::to_string(mac),
            ipv4: dev.ipv4.clone(),
            ipv6: dev.ipv6.clone(),
            hostname: dev.hostname.clone(),
            subnet: dev.subnet.clone(),
            last_seen_ms: dev.last_seen_ms,
        });
    }
    known_devices.sort_by(|a, b| a.logical_iface.cmp(&b.logical_iface).then(a.mac.cmp(&b.mac)));

    MonitorRuntimeState { known_devices }
}

pub fn import_runtime_state(runtime: &mut MonitorRuntime, state: MonitorRuntimeState, topology: &TopologySnapshot) -> anyhow::Result<()> {
    runtime.device_registry.entries.clear();

    for item in state.known_devices {
        let Some(ifindex) = topology.ifindex_by_name(&item.logical_iface) else {
            continue;
        };
        let Ok(mac) = mac_utils::from_str(&item.mac) else {
            continue;
        };
        runtime.device_registry.entries.insert(
            (ifindex, mac),
            KnownDevice {
                ifindex,
                mac,
                ipv4: item.ipv4,
                ipv6: item.ipv6,
                hostname: item.hostname,
                logical_iface: item.logical_iface,
                subnet: item.subnet,
                last_seen_ms: item.last_seen_ms,
            },
        );
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct CounterQuad {
    pub up_v4_bps: u64,
    pub down_v4_bps: u64,
    pub up_v6_bps: u64,
    pub down_v6_bps: u64,
    pub up_v4_bytes: u64,
    pub down_v4_bytes: u64,
    pub up_v6_bytes: u64,
    pub down_v6_bytes: u64,
}

impl CounterQuad {
    pub fn is_empty(&self) -> bool {
        self.up_v4_bytes == 0 && self.down_v4_bytes == 0 && self.up_v6_bytes == 0 && self.down_v6_bytes == 0 &&
        self.up_v4_bps == 0 && self.down_v4_bps == 0 && self.up_v6_bps == 0 && self.down_v6_bps == 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MonitorRuntimeState {
    pub known_devices: Vec<PersistedKnownDevice>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedKnownDevice {
    pub logical_iface: String,
    pub mac: String,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub hostname: String,
    pub subnet: String,
    pub last_seen_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct InterfaceOverviewItem {
    pub ifindex: u32,
    pub ifname: String,
    pub zone: String,
    pub metrics: CounterQuad,
    pub cumulative: CounterQuad,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceListItem {
    pub ifindex: u32,
    pub logical_iface: String,
    pub subnet: String,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub mac: String,
    pub hostname: String,
    pub metrics: CounterQuad,
    pub cumulative: CounterQuad,
    pub online: bool,
    /// Last time this device was observed in a snapshot (Unix epoch ms). Online rows use the current snapshot time.
    pub last_seen_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub neighbor_state: Option<String>,
}

#[derive(Debug, Clone)]
pub enum CompletedAggregate {
    Iface {
        iface: String,
        bucket: AggregatedBucket,
    },
    Device {
        iface: String,
        mac: String,
        bucket: AggregatedBucket,
    },
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct SnapshotData {
    pub timestamp_ms: u64,
    pub interfaces: Vec<InterfaceOverviewItem>,
    pub devices: Vec<DeviceListItem>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryTrafficType {
    All,
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryDirection {
    Both,
    Up,
    Down,
}

#[derive(Debug, Clone, Copy)]
struct HistoryPoint {
    ts_ms: u64,
    metrics: CounterQuad,
    cumulative: CounterQuad,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CurrentHourState {
    pub iface: Vec<CurrentHourIfaceState>,
    pub device: Vec<CurrentHourDeviceState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentHourIfaceState {
    pub ifindex: u32,
    pub bucket: AggregatedBucket,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentHourDeviceState {
    pub ifindex: u32,
    pub mac: String,
    pub bucket: AggregatedBucket,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct DeviceSeriesKey {
    pub ifindex: u32,
    pub mac: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HistorySample {
    pub ts_ms: u64,
    pub up_v4_bps: u64,
    pub up_v6_bps: u64,
    pub down_v4_bps: u64,
    pub down_v6_bps: u64,
    pub up_v4_bytes: u64,
    pub up_v6_bytes: u64,
    pub down_v4_bytes: u64,
    pub down_v6_bytes: u64,
    pub up_v4_bytes_cumulative: u64,
    pub up_v6_bytes_cumulative: u64,
    pub down_v4_bytes_cumulative: u64,
    pub down_v6_bytes_cumulative: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggregateBucket {
    Hourly,
    Daily,
}

fn daily_bucket_local(ts_ms: u64) -> (u64, u64) {
    let dt = match Local.timestamp_millis_opt(ts_ms as i64) {
        chrono::LocalResult::Single(t) => t,
        _ => return (0, 0),
    };
    let date = dt.date_naive();
    let start_naive = date.and_hms_milli_opt(0, 0, 0, 0).unwrap();
    let end_naive = date.and_hms_milli_opt(23, 59, 59, 999).unwrap();
    let start_ts = Local.from_local_datetime(&start_naive).unwrap().timestamp_millis() as u64;
    let end_ts = Local.from_local_datetime(&end_naive).unwrap().timestamp_millis() as u64;
    (start_ts, end_ts)
}

pub fn hourly_bucket_local(ts_ms: u64) -> (u64, u64) {
    let dt = match Local.timestamp_millis_opt(ts_ms as i64) {
        chrono::LocalResult::Single(t) => t,
        _ => return (0, 0),
    };
    let date = dt.date_naive();
    let h = dt.hour();
    let start_naive = date.and_hms_milli_opt(h, 0, 0, 0).unwrap();
    let end_naive = date.and_hms_milli_opt(h, 59, 59, 999).unwrap();
    let start_ts = Local.from_local_datetime(&start_naive).unwrap().timestamp_millis() as u64;
    let end_ts = Local.from_local_datetime(&end_naive).unwrap().timestamp_millis() as u64;
    (start_ts, end_ts)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AggregatedBucket {
    pub start_ts_ms: u64,
    pub end_ts_ms: u64,
    pub sample_count: u64,
    pub up_v4_bytes: u64,
    pub down_v4_bytes: u64,
    pub up_v6_bytes: u64,
    pub down_v6_bytes: u64,
    pub up_v4_bps_sum: u64,
    pub up_v4_bps_max: u64,
    pub up_v4_bps_min: u64,
    pub down_v4_bps_sum: u64,
    pub down_v4_bps_max: u64,
    pub down_v4_bps_min: u64,
    pub up_v6_bps_sum: u64,
    pub up_v6_bps_max: u64,
    pub up_v6_bps_min: u64,
    pub down_v6_bps_sum: u64,
    pub down_v6_bps_max: u64,
    pub down_v6_bps_min: u64,
    // Computed fields for API/serialization compatibility
    #[serde(default)]
    pub up_v4_bps_avg: u64,
    #[serde(default)]
    pub up_v4_bps_p95: u64,
    #[serde(default)]
    pub down_v4_bps_avg: u64,
    #[serde(default)]
    pub down_v4_bps_p95: u64,
    #[serde(default)]
    pub up_v6_bps_avg: u64,
    #[serde(default)]
    pub up_v6_bps_p95: u64,
    #[serde(default)]
    pub down_v6_bps_avg: u64,
    #[serde(default)]
    pub down_v6_bps_p95: u64,
}

impl AggregatedBucket {
    /// 与 `HistoryQuery.traffic_type` 语义一致：仅保留选定 IP 族的字节与 bps 统计，另一侧置零。
    pub fn with_traffic_type(mut self, tt: HistoryTrafficType) -> Self {
        match tt {
            HistoryTrafficType::All => {}
            HistoryTrafficType::Ipv4 => {
                self.up_v6_bytes = 0;
                self.down_v6_bytes = 0;
                self.up_v6_bps_sum = 0;
                self.up_v6_bps_avg = 0;
                self.up_v6_bps_max = 0;
                self.up_v6_bps_min = 0;
                self.up_v6_bps_p95 = 0;
                self.down_v6_bps_sum = 0;
                self.down_v6_bps_avg = 0;
                self.down_v6_bps_max = 0;
                self.down_v6_bps_min = 0;
                self.down_v6_bps_p95 = 0;
            }
            HistoryTrafficType::Ipv6 => {
                self.up_v4_bytes = 0;
                self.down_v4_bytes = 0;
                self.up_v4_bps_sum = 0;
                self.up_v4_bps_avg = 0;
                self.up_v4_bps_max = 0;
                self.up_v4_bps_min = 0;
                self.up_v4_bps_p95 = 0;
                self.down_v4_bps_sum = 0;
                self.down_v4_bps_avg = 0;
                self.down_v4_bps_max = 0;
                self.down_v4_bps_min = 0;
                self.down_v4_bps_p95 = 0;
            }
        }
        self
    }

    /// Compute avg from sum/count before returning to API consumers.
    /// p95 is set equal to max (no sample reservoir).
    pub fn finalize(mut self) -> Self {
        if self.sample_count > 0 {
            self.up_v4_bps_avg = self.up_v4_bps_sum / self.sample_count;
            self.down_v4_bps_avg = self.down_v4_bps_sum / self.sample_count;
            self.up_v6_bps_avg = self.up_v6_bps_sum / self.sample_count;
            self.down_v6_bps_avg = self.down_v6_bps_sum / self.sample_count;
        }
        self.up_v4_bps_p95 = self.up_v4_bps_max;
        self.down_v4_bps_p95 = self.down_v4_bps_max;
        self.up_v6_bps_p95 = self.up_v6_bps_max;
        self.down_v6_bps_p95 = self.down_v6_bps_max;
        self
    }
}

const HISTOGRAM_MAX_HOURS: usize = 366 * 24;

#[derive(Debug, Default)]
pub struct HistogramHistory {
    pub current_hour_iface: HashMap<u32, AggregatedBucket>,
    pub current_hour_device: HashMap<DeviceSeriesKey, AggregatedBucket>,
    pub completed_iface: HashMap<u32, VecDeque<AggregatedBucket>>,
    pub completed_device: HashMap<DeviceSeriesKey, VecDeque<AggregatedBucket>>,
}

impl HistogramHistory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Remove current-hour and completed histogram data for one device.
    pub fn remove_device(&mut self, ifindex: u32, mac: &str) -> bool {
        let mut removed = false;
        self.current_hour_device.retain(|key, _| {
            let keep = key.ifindex != ifindex || !key.mac.eq_ignore_ascii_case(mac);
            removed |= !keep;
            keep
        });
        self.completed_device.retain(|key, _| {
            let keep = key.ifindex != ifindex || !key.mac.eq_ignore_ascii_case(mac);
            removed |= !keep;
            keep
        });
        removed
    }

    #[allow(dead_code)]
    pub fn ingest_snapshot(&mut self, snapshot: &SnapshotData) {
        let _ = self.ingest_snapshot_collect_completed(snapshot);
    }

    pub fn ingest_snapshot_collect_completed(&mut self, snapshot: &SnapshotData) -> Vec<CompletedAggregate> {
        let mut completed = Vec::new();
        for iface in &snapshot.interfaces {
            if let Some(bucket) = self.ingest_iface(iface.ifindex, snapshot.timestamp_ms, &iface.metrics) {
                completed.push(CompletedAggregate::Iface {
                    iface: iface.ifname.clone(),
                    bucket,
                });
            }
        }
        for dev in &snapshot.devices {
            if !dev.online && dev.metrics.is_empty() {
                continue;
            }
            let key = DeviceSeriesKey {
                ifindex: dev.ifindex,
                mac: dev.mac.clone(),
            };
            if let Some(bucket) = self.ingest_device(&key, snapshot.timestamp_ms, &dev.metrics) {
                completed.push(CompletedAggregate::Device {
                    iface: dev.logical_iface.clone(),
                    mac: dev.mac.clone(),
                    bucket,
                });
            }
        }
        completed
    }

    pub fn restore_iface_bucket(&mut self, ifindex: u32, bucket: AggregatedBucket) {
        self.completed_iface.entry(ifindex).or_default().push_back(bucket);
        if let Some(q) = self.completed_iface.get_mut(&ifindex) {
            trim_histogram_completed(q, HISTOGRAM_MAX_HOURS);
        }
    }

    pub fn restore_device_bucket(&mut self, ifindex: u32, mac: String, bucket: AggregatedBucket) {
        let key = DeviceSeriesKey { ifindex, mac };
        self.completed_device.entry(key.clone()).or_default().push_back(bucket);
        if let Some(q) = self.completed_device.get_mut(&key) {
            trim_histogram_completed(q, HISTOGRAM_MAX_HOURS);
        }
    }

    pub fn export_current_hour_state(&self) -> CurrentHourState {
        let mut iface = Vec::new();
        for (ifindex, bucket) in &self.current_hour_iface {
            iface.push(CurrentHourIfaceState {
                ifindex: *ifindex,
                bucket: bucket.clone(),
            });
        }
        iface.sort_by_key(|x| x.ifindex);

        let mut device = Vec::new();
        for (key, bucket) in &self.current_hour_device {
            device.push(CurrentHourDeviceState {
                ifindex: key.ifindex,
                mac: key.mac.clone(),
                bucket: bucket.clone(),
            });
        }
        device.sort_by(|a, b| a.ifindex.cmp(&b.ifindex).then(a.mac.cmp(&b.mac)));

        CurrentHourState { iface, device }
    }

    fn ingest_iface(&mut self, ifindex: u32, ts_ms: u64, metrics: &CounterQuad) -> Option<AggregatedBucket> {
        let (new_start, new_end) = hourly_bucket_local(ts_ms);
        let mut old_bucket = None;
        let entry = self.current_hour_iface.entry(ifindex).or_insert_with(|| AggregatedBucket {
            start_ts_ms: new_start,
            end_ts_ms: new_end,
            ..Default::default()
        });

        if entry.start_ts_ms != new_start {
            old_bucket = Some(entry.clone());
            self.completed_iface.entry(ifindex).or_default().push_back(entry.clone());
            trim_histogram_completed(self.completed_iface.get_mut(&ifindex).unwrap(), HISTOGRAM_MAX_HOURS);
            *entry = AggregatedBucket {
                start_ts_ms: new_start,
                end_ts_ms: new_end,
                ..Default::default()
            };
        }

        entry.up_v4_bytes = entry.up_v4_bytes.saturating_add(metrics.up_v4_bytes);
        entry.down_v4_bytes = entry.down_v4_bytes.saturating_add(metrics.down_v4_bytes);
        entry.up_v6_bytes = entry.up_v6_bytes.saturating_add(metrics.up_v6_bytes);
        entry.down_v6_bytes = entry.down_v6_bytes.saturating_add(metrics.down_v6_bytes);

        if entry.sample_count == 0 {
            entry.up_v4_bps_min = metrics.up_v4_bps;
            entry.down_v4_bps_min = metrics.down_v4_bps;
            entry.up_v6_bps_min = metrics.up_v6_bps;
            entry.down_v6_bps_min = metrics.down_v6_bps;
        } else {
            entry.up_v4_bps_min = entry.up_v4_bps_min.min(metrics.up_v4_bps);
            entry.down_v4_bps_min = entry.down_v4_bps_min.min(metrics.down_v4_bps);
            entry.up_v6_bps_min = entry.up_v6_bps_min.min(metrics.up_v6_bps);
            entry.down_v6_bps_min = entry.down_v6_bps_min.min(metrics.down_v6_bps);
        }

        entry.up_v4_bps_max = entry.up_v4_bps_max.max(metrics.up_v4_bps);
        entry.down_v4_bps_max = entry.down_v4_bps_max.max(metrics.down_v4_bps);
        entry.up_v6_bps_max = entry.up_v6_bps_max.max(metrics.up_v6_bps);
        entry.down_v6_bps_max = entry.down_v6_bps_max.max(metrics.down_v6_bps);

        entry.up_v4_bps_sum = entry.up_v4_bps_sum.saturating_add(metrics.up_v4_bps);
        entry.down_v4_bps_sum = entry.down_v4_bps_sum.saturating_add(metrics.down_v4_bps);
        entry.up_v6_bps_sum = entry.up_v6_bps_sum.saturating_add(metrics.up_v6_bps);
        entry.down_v6_bps_sum = entry.down_v6_bps_sum.saturating_add(metrics.down_v6_bps);
        entry.sample_count += 1;

        old_bucket.map(|b| b.finalize())
    }

    fn ingest_device(&mut self, key: &DeviceSeriesKey, ts_ms: u64, metrics: &CounterQuad) -> Option<AggregatedBucket> {
        let (new_start, new_end) = hourly_bucket_local(ts_ms);
        let mut old_bucket = None;
        let entry = self.current_hour_device.entry(key.clone()).or_insert_with(|| AggregatedBucket {
            start_ts_ms: new_start,
            end_ts_ms: new_end,
            ..Default::default()
        });

        if entry.start_ts_ms != new_start {
            old_bucket = Some(entry.clone());
            self.completed_device.entry(key.clone()).or_default().push_back(entry.clone());
            trim_histogram_completed(self.completed_device.get_mut(key).unwrap(), HISTOGRAM_MAX_HOURS);
            *entry = AggregatedBucket {
                start_ts_ms: new_start,
                end_ts_ms: new_end,
                ..Default::default()
            };
        }

        entry.up_v4_bytes = entry.up_v4_bytes.saturating_add(metrics.up_v4_bytes);
        entry.down_v4_bytes = entry.down_v4_bytes.saturating_add(metrics.down_v4_bytes);
        entry.up_v6_bytes = entry.up_v6_bytes.saturating_add(metrics.up_v6_bytes);
        entry.down_v6_bytes = entry.down_v6_bytes.saturating_add(metrics.down_v6_bytes);

        if entry.sample_count == 0 {
            entry.up_v4_bps_min = metrics.up_v4_bps;
            entry.down_v4_bps_min = metrics.down_v4_bps;
            entry.up_v6_bps_min = metrics.up_v6_bps;
            entry.down_v6_bps_min = metrics.down_v6_bps;
        } else {
            entry.up_v4_bps_min = entry.up_v4_bps_min.min(metrics.up_v4_bps);
            entry.down_v4_bps_min = entry.down_v4_bps_min.min(metrics.down_v4_bps);
            entry.up_v6_bps_min = entry.up_v6_bps_min.min(metrics.up_v6_bps);
            entry.down_v6_bps_min = entry.down_v6_bps_min.min(metrics.down_v6_bps);
        }

        entry.up_v4_bps_max = entry.up_v4_bps_max.max(metrics.up_v4_bps);
        entry.down_v4_bps_max = entry.down_v4_bps_max.max(metrics.down_v4_bps);
        entry.up_v6_bps_max = entry.up_v6_bps_max.max(metrics.up_v6_bps);
        entry.down_v6_bps_max = entry.down_v6_bps_max.max(metrics.down_v6_bps);

        entry.up_v4_bps_sum = entry.up_v4_bps_sum.saturating_add(metrics.up_v4_bps);
        entry.down_v4_bps_sum = entry.down_v4_bps_sum.saturating_add(metrics.down_v4_bps);
        entry.up_v6_bps_sum = entry.up_v6_bps_sum.saturating_add(metrics.up_v6_bps);
        entry.down_v6_bps_sum = entry.down_v6_bps_sum.saturating_add(metrics.down_v6_bps);
        entry.sample_count += 1;

        old_bucket.map(|b| b.finalize())
    }

    pub fn query_aggregate(
        &self,
        ifindex: u32,
        mac: Option<&str>,
        start_ms: u64,
        end_ms: u64,
        bucket: AggregateBucket,
    ) -> Vec<AggregatedBucket> {
        let hourly: Vec<AggregatedBucket> = if let Some(m) = mac.filter(|s| !s.trim().is_empty()) {
            let key = self
                .completed_device
                .keys()
                .find(|k| k.ifindex == ifindex && k.mac.eq_ignore_ascii_case(m))
                .cloned()
                .or_else(|| {
                    self.current_hour_device
                        .keys()
                        .find(|k| k.ifindex == ifindex && k.mac.eq_ignore_ascii_case(m))
                        .cloned()
                });
            if let Some(k) = key {
                self.query_device_hourly(&k, start_ms, end_ms)
            } else {
                Vec::new()
            }
        } else {
            self.query_iface_hourly(ifindex, start_ms, end_ms)
        };

        let finalized = |buckets: Vec<AggregatedBucket>| -> Vec<AggregatedBucket> {
            buckets.into_iter().map(|b| b.finalize()).collect()
        };

        match bucket {
            AggregateBucket::Hourly => finalized(hourly),
            AggregateBucket::Daily => finalized(merge_hourly_to_daily(&hourly)),
        }
    }

    fn query_iface_hourly(&self, ifindex: u32, start_ms: u64, end_ms: u64) -> Vec<AggregatedBucket> {
        let mut result = Vec::new();
        if let Some(completed) = self.completed_iface.get(&ifindex) {
            for b in completed {
                if b.start_ts_ms <= end_ms && b.end_ts_ms >= start_ms {
                    result.push(b.clone());
                }
            }
        }
        if let Some(bucket) = self.current_hour_iface.get(&ifindex) {
            if bucket.start_ts_ms <= end_ms && bucket.end_ts_ms >= start_ms {
                result.push(bucket.clone());
            }
        }
        result.sort_by_key(|b| b.start_ts_ms);
        result
    }

    fn query_device_hourly(&self, key: &DeviceSeriesKey, start_ms: u64, end_ms: u64) -> Vec<AggregatedBucket> {
        let mut result = Vec::new();
        if let Some(completed) = self.completed_device.get(&key) {
            for b in completed {
                if b.start_ts_ms <= end_ms && b.end_ts_ms >= start_ms {
                    result.push(b.clone());
                }
            }
        }
        if let Some(bucket) = self.current_hour_device.get(&key) {
            if bucket.start_ts_ms <= end_ms && bucket.end_ts_ms >= start_ms {
                result.push(bucket.clone());
            }
        }
        result.sort_by_key(|b| b.start_ts_ms);
        result
    }

    pub fn cumulative_from_completed(&self) -> (HashMap<u32, CounterQuad>, HashMap<(u32, [u8; 6]), CounterQuad>) {
        let mut iface = HashMap::new();
        for (ifindex, buckets) in &self.completed_iface {
            let mut acc = CounterQuad::default();
            for b in buckets {
                add_bucket_bytes(&mut acc, b);
            }
            iface.insert(*ifindex, acc);
        }

        let mut device = HashMap::new();
        for (k, buckets) in &self.completed_device {
            let Ok(mac) = mac_utils::from_str(&k.mac) else {
                continue;
            };
            let mut acc = CounterQuad::default();
            for b in buckets {
                add_bucket_bytes(&mut acc, b);
            }
            device.insert((k.ifindex, mac), acc);
        }

        (iface, device)
    }

    pub fn cumulative_from_all(&self) -> (HashMap<u32, CounterQuad>, HashMap<(u32, [u8; 6]), CounterQuad>) {
        let (mut iface, mut device) = self.cumulative_from_completed();

        for (ifindex, bucket) in &self.current_hour_iface {
            let acc = iface.entry(*ifindex).or_default();
            add_bucket_bytes(acc, bucket);
        }

        for (key, bucket) in &self.current_hour_device {
            let Ok(mac) = mac_utils::from_str(&key.mac) else {
                continue;
            };
            let acc = device.entry((key.ifindex, mac)).or_default();
            add_bucket_bytes(acc, bucket);
        }

        (iface, device)
    }
}

fn trim_histogram_completed(queue: &mut VecDeque<AggregatedBucket>, max_hours: usize) {
    while queue.len() > max_hours {
        let _ = queue.pop_front();
    }
}

fn merge_hourly_to_daily(hourly: &[AggregatedBucket]) -> Vec<AggregatedBucket> {
    let mut by_day: HashMap<u64, AggregatedBucket> = HashMap::new();
    for b in hourly {
        let (day_start, day_end) = daily_bucket_local(b.start_ts_ms);
        let acc = by_day.entry(day_start).or_insert_with(|| AggregatedBucket {
            start_ts_ms: day_start,
            end_ts_ms: day_end,
            ..Default::default()
        });
        acc.up_v4_bytes = acc.up_v4_bytes.saturating_add(b.up_v4_bytes);
        acc.down_v4_bytes = acc.down_v4_bytes.saturating_add(b.down_v4_bytes);
        acc.up_v6_bytes = acc.up_v6_bytes.saturating_add(b.up_v6_bytes);
        acc.down_v6_bytes = acc.down_v6_bytes.saturating_add(b.down_v6_bytes);

        acc.up_v4_bps_max = acc.up_v4_bps_max.max(b.up_v4_bps_max);
        acc.down_v4_bps_max = acc.down_v4_bps_max.max(b.down_v4_bps_max);
        acc.up_v6_bps_max = acc.up_v6_bps_max.max(b.up_v6_bps_max);
        acc.down_v6_bps_max = acc.down_v6_bps_max.max(b.down_v6_bps_max);

        if acc.up_v4_bps_min == 0 || (b.up_v4_bps_min > 0 && b.up_v4_bps_min < acc.up_v4_bps_min) {
            acc.up_v4_bps_min = b.up_v4_bps_min;
        }
        if acc.down_v4_bps_min == 0 || (b.down_v4_bps_min > 0 && b.down_v4_bps_min < acc.down_v4_bps_min) {
            acc.down_v4_bps_min = b.down_v4_bps_min;
        }
        if acc.up_v6_bps_min == 0 || (b.up_v6_bps_min > 0 && b.up_v6_bps_min < acc.up_v6_bps_min) {
            acc.up_v6_bps_min = b.up_v6_bps_min;
        }
        if acc.down_v6_bps_min == 0 || (b.down_v6_bps_min > 0 && b.down_v6_bps_min < acc.down_v6_bps_min) {
            acc.down_v6_bps_min = b.down_v6_bps_min;
        }

        acc.up_v4_bps_p95 = acc.up_v4_bps_max;
        acc.down_v4_bps_p95 = acc.down_v4_bps_max;
        acc.up_v6_bps_p95 = acc.up_v6_bps_max;
        acc.down_v6_bps_p95 = acc.down_v6_bps_max;

        acc.sample_count = acc.sample_count.saturating_add(b.sample_count);
        acc.up_v4_bps_sum = acc.up_v4_bps_sum.saturating_add(b.up_v4_bps_sum);
        acc.down_v4_bps_sum = acc.down_v4_bps_sum.saturating_add(b.down_v4_bps_sum);
        acc.up_v6_bps_sum = acc.up_v6_bps_sum.saturating_add(b.up_v6_bps_sum);
        acc.down_v6_bps_sum = acc.down_v6_bps_sum.saturating_add(b.down_v6_bps_sum);

        if acc.sample_count > 0 {
            acc.up_v4_bps_avg = acc.up_v4_bps_sum / acc.sample_count;
            acc.down_v4_bps_avg = acc.down_v4_bps_sum / acc.sample_count;
            acc.up_v6_bps_avg = acc.up_v6_bps_sum / acc.sample_count;
            acc.down_v6_bps_avg = acc.down_v6_bps_sum / acc.sample_count;
        }
    }
    let mut result: Vec<AggregatedBucket> = by_day.into_values().collect();
    result.sort_by_key(|b| b.start_ts_ms);
    result
}

#[derive(Debug, Default)]
pub struct TrafficHistory {
    window_points: usize,
    iface_series: HashMap<u32, VecDeque<HistoryPoint>>,
    device_series: HashMap<DeviceSeriesKey, VecDeque<HistoryPoint>>,
}

impl TrafficHistory {
    /// 创建流量历史记录，指定窗口内保留的采样点数量
    pub fn new(window_points: usize) -> Self {
        Self {
            window_points: window_points.max(1),
            ..Self::default()
        }
    }

    /// Remove recent sample history for one device.
    pub fn remove_device(&mut self, ifindex: u32, mac: &str) -> bool {
        let before = self.device_series.len();
        self.device_series
            .retain(|key, _| key.ifindex != ifindex || !key.mac.eq_ignore_ascii_case(mac));
        self.device_series.len() != before
    }

    /// 将一次快照数据写入历史，供后续按接口或设备查询
    pub fn ingest_snapshot(&mut self, snapshot: &SnapshotData) {
        for iface in &snapshot.interfaces {
            let queue = self.iface_series.entry(iface.ifindex).or_default();
            queue.push_back(HistoryPoint {
                ts_ms: snapshot.timestamp_ms,
                metrics: iface.metrics,
                cumulative: iface.cumulative,
            });
            trim_history_queue(queue, self.window_points);
        }

        for dev in &snapshot.devices {
            if !dev.online && dev.metrics.is_empty() {
                continue;
            }
            let key = DeviceSeriesKey {
                ifindex: dev.ifindex,
                mac: dev.mac.clone(),
            };
            let queue = self.device_series.entry(key).or_default();
            queue.push_back(HistoryPoint {
                ts_ms: snapshot.timestamp_ms,
                metrics: dev.metrics,
                cumulative: dev.cumulative,
            });
            trim_history_queue(queue, self.window_points);
        }
    }

    /// 按逻辑接口查询历史流量采样序列
    pub fn query_iface(&self, ifindex: u32, _traffic_type: HistoryTrafficType, _direction: HistoryDirection) -> Vec<HistorySample> {
        let Some(series) = self.iface_series.get(&ifindex) else {
            return Vec::new();
        };
        series_to_samples(series)
    }

    /// 按设备 MAC（可选按接口）查询历史流量，支持多接口合并
    pub fn query_device(
        &self,
        ifindex: Option<u32>,
        mac: &str,
        _traffic_type: HistoryTrafficType,
        _direction: HistoryDirection,
    ) -> Vec<HistorySample> {
        let mut merged: BTreeMap<u64, (CounterQuad, CounterQuad)> = BTreeMap::new();
        for (key, series) in &self.device_series {
            if let Some(expected_ifindex) = ifindex {
                if key.ifindex != expected_ifindex {
                    continue;
                }
            }
            if !key.mac.eq_ignore_ascii_case(mac) {
                continue;
            }
            for point in series {
                let entry = merged.entry(point.ts_ms).or_default();
                add_quad(&mut entry.0, &point.metrics);
                add_quad(&mut entry.1, &point.cumulative);
            }
        }

        merged
            .into_iter()
            .map(|(ts_ms, (metrics, cumulative))| HistorySample {
                ts_ms,
                up_v4_bps: metrics.up_v4_bps,
                up_v6_bps: metrics.up_v6_bps,
                down_v4_bps: metrics.down_v4_bps,
                down_v6_bps: metrics.down_v6_bps,
                up_v4_bytes: metrics.up_v4_bytes,
                up_v6_bytes: metrics.up_v6_bytes,
                down_v4_bytes: metrics.down_v4_bytes,
                down_v6_bytes: metrics.down_v6_bytes,
                up_v4_bytes_cumulative: cumulative.up_v4_bytes,
                up_v6_bytes_cumulative: cumulative.up_v6_bytes,
                down_v4_bytes_cumulative: cumulative.down_v4_bytes,
                down_v6_bytes_cumulative: cumulative.down_v6_bytes,
            })
            .collect()
    }
}

/// 裁剪历史队列长度不超过 max_points
fn trim_history_queue(queue: &mut VecDeque<HistoryPoint>, max_points: usize) {
    while queue.len() > max_points {
        let _ = queue.pop_front();
    }
}

fn series_to_samples(series: &VecDeque<HistoryPoint>) -> Vec<HistorySample> {
    series
        .iter()
        .map(|point| {
            let m = &point.metrics;
            let c = &point.cumulative;
            HistorySample {
                ts_ms: point.ts_ms,
                up_v4_bps: m.up_v4_bps,
                up_v6_bps: m.up_v6_bps,
                down_v4_bps: m.down_v4_bps,
                down_v6_bps: m.down_v6_bps,
                up_v4_bytes: m.up_v4_bytes,
                up_v6_bytes: m.up_v6_bytes,
                down_v4_bytes: m.down_v4_bytes,
                down_v6_bytes: m.down_v6_bytes,
                up_v4_bytes_cumulative: c.up_v4_bytes,
                up_v6_bytes_cumulative: c.up_v6_bytes,
                down_v4_bytes_cumulative: c.down_v4_bytes,
                down_v6_bytes_cumulative: c.down_v6_bytes,
            }
        })
        .collect()
}

/// 将 src 的四元组累加到 dst
fn add_quad(dst: &mut CounterQuad, src: &CounterQuad) {
    dst.up_v4_bps = dst.up_v4_bps.saturating_add(src.up_v4_bps);
    dst.down_v4_bps = dst.down_v4_bps.saturating_add(src.down_v4_bps);
    dst.up_v6_bps = dst.up_v6_bps.saturating_add(src.up_v6_bps);
    dst.down_v6_bps = dst.down_v6_bps.saturating_add(src.down_v6_bps);
    dst.up_v4_bytes = dst.up_v4_bytes.saturating_add(src.up_v4_bytes);
    dst.down_v4_bytes = dst.down_v4_bytes.saturating_add(src.down_v4_bytes);
    dst.up_v6_bytes = dst.up_v6_bytes.saturating_add(src.up_v6_bytes);
    dst.down_v6_bytes = dst.down_v6_bytes.saturating_add(src.down_v6_bytes);
}

fn add_bucket_bytes(dst: &mut CounterQuad, bucket: &AggregatedBucket) {
    dst.up_v4_bytes = dst.up_v4_bytes.saturating_add(bucket.up_v4_bytes);
    dst.down_v4_bytes = dst.down_v4_bytes.saturating_add(bucket.down_v4_bytes);
    dst.up_v6_bytes = dst.up_v6_bytes.saturating_add(bucket.up_v6_bytes);
    dst.down_v6_bytes = dst.down_v6_bytes.saturating_add(bucket.down_v6_bytes);
}

pub fn build_recovered_snapshot(runtime: &MonitorRuntime, topology: &TopologySnapshot) -> SnapshotData {
    let mut interfaces = Vec::new();
    for (ifindex, cumulative) in &runtime.cumulative_iface {
        if let Some(iface) = topology.by_ifindex(*ifindex) {
            interfaces.push(InterfaceOverviewItem {
                ifindex: *ifindex,
                ifname: iface.name.clone(),
                zone: iface.zone_name().to_string(),
                metrics: CounterQuad::default(),
                cumulative: *cumulative,
            });
        }
    }
    interfaces.sort_by_key(|x| x.ifindex);

    let mut devices = Vec::new();
    for ((ifindex, mac), known) in &runtime.device_registry.entries {
        devices.push(DeviceListItem {
            ifindex: *ifindex,
            logical_iface: known.logical_iface.clone(),
            subnet: known.subnet.clone(),
            ipv4: known.ipv4.clone(),
            ipv6: known.ipv6.clone(),
            mac: mac_utils::to_string(mac),
            hostname: known.hostname.clone(),
            metrics: CounterQuad::default(),
            cumulative: runtime.cumulative_device.get(&(*ifindex, *mac)).copied().unwrap_or_default(),
            online: false,
            last_seen_ms: known.last_seen_ms,
            neighbor_state: None,
        });
    }
    devices.sort_by(|a, b| {
        a.logical_iface
            .cmp(&b.logical_iface)
            .then(a.ipv4.cmp(&b.ipv4))
            .then(a.ipv6.cmp(&b.ipv6))
            .then(a.mac.cmp(&b.mac))
    });

    SnapshotData {
        timestamp_ms: time_utils::now_millis(),
        interfaces,
        devices,
    }
}

/// 从 eBPF 采集一次接口和设备流量快照，计算速率
pub fn collect_snapshot(
    ebpf: &mut Ebpf,
    topology: &TopologySnapshot,
    runtime: &mut MonitorRuntime,
    interval: Duration,
    monitor_ifaces: &[String],
    enable_ecm: bool,
) -> anyhow::Result<SnapshotData> {
    let now_ms = time_utils::now_millis();
    let mut iface_stats = std::mem::take(&mut runtime.buf_iface_stats);
    let mut device_stats = std::mem::take(&mut runtime.buf_device_stats);
    let mut ecm_stats = std::mem::take(&mut runtime.buf_ecm_stats);
    
    read_iface_stats(ebpf, &mut iface_stats)?;
    read_device_stats(ebpf, &mut device_stats)?;
    if enable_ecm {
        let _ = read_ecm_stats(ebpf, &mut ecm_stats);
    } else {
        // ECM is disabled: do not allow state left over from a previous
        // ECM-enabled run to affect device/interface metrics.
        ecm_stats.clear();
        runtime.prev_ecm_bytes.clear();
        runtime.ecm_last_active_ms.clear();
        runtime.ecm_active_devices.clear();
        runtime.smoothed_lan_ecm_rates.clear();
        runtime.smoothed_wan_ecm_rates = None;
    }

    let sec = if let Some(prev_ms) = runtime.last_snapshot_ms {
        ((now_ms.saturating_sub(prev_ms)) as f64 / 1000.0).max(0.001)
    } else {
        interval.as_secs_f64().max(1.0)
    };
    runtime.last_snapshot_ms = Some(now_ms);

    let monitor_set: FxHashSet<_> = monitor_ifaces.iter().map(String::as_str).collect();
    if now_ms.saturating_sub(runtime.last_sync_tracking_ms) >= 60_000 {
        if let Err(e) = sync_device_tracking(ebpf, topology, &monitor_set) {
            log::warn!("device tracking sync failed: {}", e);
        } else {
            runtime.last_sync_tracking_ms = now_ms;
        }
    }
    let ifindex_by_name: FxHashMap<_, _> = topology.interfaces().iter().map(|x| (x.name.as_str(), x.ifindex)).collect();

    let mut interfaces = Vec::new();
    let mut seen_iface_names = FxHashSet::default();
    for iface_name in monitor_ifaces {
        if !seen_iface_names.insert(iface_name.as_str()) {
            continue;
        }
        let Some(ifindex) = ifindex_by_name.get(iface_name.as_str()).copied() else {
            continue;
        };
        let mut metrics = CounterQuad::default();
        for (k, v) in &iface_stats {
            if k.ifindex != ifindex {
                continue;
            }
            let prev = runtime.prev_iface_bytes.get(k).copied().unwrap_or(0);
            let delta = delta_bytes(v.bytes, prev);
            runtime.prev_iface_bytes.insert(*k, v.bytes);
            fill_quad(k.ip_version, k.direction, &mut metrics, delta, sec);
        }
        let cum = runtime.cumulative_iface.entry(ifindex).or_default();
        add_quad(cum, &metrics);

        // Apply EWMA smoothing for interface bps (rates)
        let smoothed = runtime.smoothed_iface_rates.entry(ifindex).or_default();
        smoothed.up_v4_bps = ((0.4 * metrics.up_v4_bps as f64) + (0.6 * smoothed.up_v4_bps as f64)) as u64;
        smoothed.down_v4_bps = ((0.4 * metrics.down_v4_bps as f64) + (0.6 * smoothed.down_v4_bps as f64)) as u64;
        smoothed.up_v6_bps = ((0.4 * metrics.up_v6_bps as f64) + (0.6 * smoothed.up_v6_bps as f64)) as u64;
        smoothed.down_v6_bps = ((0.4 * metrics.down_v6_bps as f64) + (0.6 * smoothed.down_v6_bps as f64)) as u64;

        metrics.up_v4_bps = smoothed.up_v4_bps;
        metrics.down_v4_bps = smoothed.down_v4_bps;
        metrics.up_v6_bps = smoothed.up_v6_bps;
        metrics.down_v6_bps = smoothed.down_v6_bps;

        interfaces.push(InterfaceOverviewItem {
            ifindex,
            ifname: iface_name.clone(),
            zone: topology
                .by_ifindex(ifindex)
                .map(|i| i.zone_name().to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            metrics,
            cumulative: *cum,
        });
    }

    let mut subnet_map = std::collections::HashMap::new();
    for iface in topology.interfaces() {
        let mut cidrs = iface.ipv4_cidrs.clone();
        cidrs.extend(iface.ipv6_cidrs.clone());
        subnet_map.insert(iface.name.clone(), cidrs);
    }
    let filtered_neighbors = system_utils::list_neighbors_filtered(monitor_ifaces, &subnet_map, runtime, now_ms).unwrap_or_default();

    // Hostname fetch from ubus/dnsmasq is expensive. We throttle it to once per 60s.
    // Trade-off: newly connected devices will take up to 60s to have their hostnames
    // populated in the UI, which is an acceptable compromise for CPU savings.
    if now_ms.saturating_sub(runtime.last_hostname_fetch_ms) >= 60_000 {
        runtime.cached_hostnames = system_utils::list_hostname_by_mac();
        runtime.last_hostname_fetch_ms = now_ms;
    }

    let mut dev_mac_to_ips: FxHashMap<(String, [u8; 6]), (Vec<String>, Vec<String>, String)> = FxHashMap::default();
    for n in filtered_neighbors {
        let entry = dev_mac_to_ips
            .entry((n.dev, n.mac))
            .or_insert_with(|| (Vec::new(), Vec::new(), String::new()));
        if n.ip.contains(':') {
            if !entry.1.contains(&n.ip) {
                entry.1.push(n.ip);
            }
        } else {
            if !entry.0.contains(&n.ip) {
                entry.0.push(n.ip);
            }
        }
        entry.2 = pick_best_neighbor_state(entry.2.as_str(), &n.state);
    }

    let mut devices_group: FxHashMap<(u32, [u8; 6]), DeviceListItem> = FxHashMap::default();
    for ((dev, mac), (ipv4_list, ipv6_list, best_state)) in dev_mac_to_ips {
        let Some(ifindex) = ifindex_by_name.get(dev.as_str()).copied() else {
            continue;
        };
        let Some(logical_iface) = topology.by_ifindex(ifindex) else {
            continue;
        };
        if logical_iface.zone.starts_with("wan") {
            continue;
        }
        if !monitor_set.is_empty() && !monitor_set.contains(logical_iface.name.as_str()) {
            continue;
        }
        if ipv4_list.is_empty() && ipv6_list.is_empty() {
            continue;
        }
        let subnet = ipv4_list
            .first()
            .and_then(|ip| {
                logical_iface
                    .ipv4_cidrs
                    .iter()
                    .find(|cidr| system_utils::ipv4_in_cidr(ip, cidr))
                    .cloned()
            })
            .or_else(|| logical_iface.ipv4_cidrs.first().cloned())
            .or_else(|| logical_iface.ipv6_cidrs.first().cloned())
            .unwrap_or_else(|| "-".to_string());
        let ipv4: Vec<String> = ipv4_list;

        // Preserve the previous deterministic UI ordering:
        // non-link-local IPv6 first (lexicographically sorted),
        // link-local fe80:: last (also lexicographically sorted).
        //
        // Split first so the expensive comparison never has to compare
        // link-local vs non-link-local entries repeatedly.
        let mut ipv6: Vec<String> = Vec::with_capacity(ipv6_list.len());
        let mut ipv6_link_local: Vec<String> = Vec::new();
        for ip in ipv6_list {
            if ip.starts_with("fe80") {
                ipv6_link_local.push(ip);
            } else {
                ipv6.push(ip);
            }
        }

        if ipv6.len() > 1 {
            ipv6.sort_unstable();
        }
        if ipv6_link_local.len() > 1 {
            ipv6_link_local.sort_unstable();
        }

        ipv6.extend(ipv6_link_local);

        devices_group.insert(
            (ifindex, mac),
            DeviceListItem {
                ifindex,
                logical_iface: logical_iface.name.clone(),
                subnet,
                ipv4,
                ipv6,
                mac: mac_utils::to_string(&mac),
                hostname: runtime
                    .device_registry
                    .entries
                    .get(&(ifindex, mac))
                    .and_then(|known| {
                        let h = known.hostname.trim();
                        if h.is_empty() || h == "-" {
                            None
                        } else {
                            Some(known.hostname.clone())
                        }
                    })
                    .or_else(|| runtime.cached_hostnames.get(&mac).cloned())
                    .unwrap_or_else(|| "-".to_string()),
                metrics: CounterQuad::default(),
                cumulative: CounterQuad::default(),
                online: true,
                last_seen_ms: now_ms,
                neighbor_state: Some(best_state.clone()),
            },
        );
    }

    for (k, v) in &device_stats {
        if let Some(entry) = devices_group.get_mut(&(k.ifindex, k.mac)) {
            let prev = runtime.prev_device_bytes.get(k).copied().unwrap_or(0);
            let delta = delta_bytes(v.bytes, prev);
            runtime.prev_device_bytes.insert(*k, v.bytes);
            fill_quad(k.ip_version, k.direction, &mut entry.metrics, delta, sec);
        }
    }

    // --- Merge ECM (Qualcomm NSS hardware-offloaded) traffic into device metrics ---
    // ECM data is keyed by IP address. Build a reverse IP→(ifindex, mac) lookup
    // from the current neighbor table first, then fall back to the monitor's
    // historical device registry when a neighbor entry temporarily disappears.
    let mut wan_ecm_metrics = CounterQuad::default();
    let mut unresolved_ecm_metrics = CounterQuad::default();
    let mut lan_ecm_metrics: FxHashMap<u32, CounterQuad> = FxHashMap::default();
    let mac_wan = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00];
    let mac_unresolved = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    let wan_ifindex = topology.interfaces().iter().find(|i| i.zone == "wan").map(|i| i.ifindex);
    let lan_ifindex = topology.interfaces().iter().find(|i| i.zone == "lan").map(|i| i.ifindex);

    if !ecm_stats.is_empty() {
        let mut ip_to_device: FxHashMap<([u32; 4], u8), (u32, [u8; 6])> = FxHashMap::default();

        // Parse configured IPv4 CIDRs once per snapshot.
        // Hot-path ECM attribution below uses integer bit operations only.
        let mut local_v4_subnets: Vec<(u32, u32, u32)> = Vec::new();
        for iface in topology.interfaces() {
            if iface.zone == "wan" {
                continue;
            }

            for cidr in &iface.ipv4_cidrs {
                if let Some((net, mask)) = parse_cidr_to_u32(cidr) {
                    local_v4_subnets.push((iface.ifindex, net, mask));
                }
            }
        }

        // Device/neighbor-table IP lookup remains the preferred, MAC-accurate
        // attribution path.
        for ((ifindex, mac), dev) in &devices_group {
            for ip_str in &dev.ipv4 {
                if let Ok(addr) = ip_str.parse::<std::net::Ipv4Addr>() {
                    let ip_u32 = u32::from(addr);
                    ip_to_device.insert(([ip_u32, 0, 0, 0], 4), (*ifindex, *mac));
                }
            }
            for ip_str in &dev.ipv6 {
                let clean = ip_str.split('%').next().unwrap_or(ip_str);
                let clean = clean.split('/').next().unwrap_or(clean);
                if let Ok(addr) = clean.parse::<std::net::Ipv6Addr>() {
                    let segments = addr.segments();
                    let ecm_word0 = ((segments[0] as u32) << 16) | segments[1] as u32;
                    let ecm_word1 = ((segments[2] as u32) << 16) | segments[3] as u32;
                    let ecm_word2 = ((segments[4] as u32) << 16) | segments[5] as u32;
                    let ecm_word3 = ((segments[6] as u32) << 16) | segments[7] as u32;
                    ip_to_device.insert(([ecm_word0, ecm_word1, ecm_word2, ecm_word3], 6), (*ifindex, *mac));
                }
            }
        }

        // Historical fallback:
        // neighbor entries are ephemeral (ARP/ND may disappear while the
        // hardware-offloaded ECM flow is still alive). Keep recent IP→device
        // ownership so an active flow does not suddenly become WAN traffic.
        //
        // Current neighbor data always wins because it is more authoritative.
        const ECM_HISTORY_FALLBACK_MS: u64 = 10 * 60 * 1000;
        for ((ifindex, mac), dev) in &runtime.device_registry.entries {
            if now_ms.saturating_sub(dev.last_seen_ms) > ECM_HISTORY_FALLBACK_MS {
                continue;
            }

            for ip_str in &dev.ipv4 {
                if let Ok(addr) = ip_str.parse::<std::net::Ipv4Addr>() {
                    let key = ([u32::from(addr), 0, 0, 0], 4);
                    ip_to_device.entry(key).or_insert((*ifindex, *mac));
                }
            }

            for ip_str in &dev.ipv6 {
                let clean = ip_str.split('%').next().unwrap_or(ip_str);
                let clean = clean.split('/').next().unwrap_or(clean);
                if let Ok(addr) = clean.parse::<std::net::Ipv6Addr>() {
                    let segments = addr.segments();
                    let key = (
                        [
                            ((segments[0] as u32) << 16) | segments[1] as u32,
                            ((segments[2] as u32) << 16) | segments[3] as u32,
                            ((segments[4] as u32) << 16) | segments[5] as u32,
                            ((segments[6] as u32) << 16) | segments[7] as u32,
                        ],
                        6,
                    );
                    ip_to_device.entry(key).or_insert((*ifindex, *mac));
                }
            }
        }

        let mut ecm_devices: FxHashSet<(u32, [u8; 6])> = FxHashSet::default();
        let mut ecm_keys_to_prune = Vec::new();
        // Statistics entry only. This does NOT terminate the ECM flow.
        // Keep inactive stats briefly so short pauses do not cause excessive
        // delete/recreate churn.
        const ECM_IDLE_TIMEOUT_MS: u64 = 30 * 1000;

        for (ecm_key, ecm_val) in &ecm_stats {
            let lookup = (ecm_key.ip, ecm_key.ip_version);
            // A newly observed ECM key has no baseline yet. Establish the
            // baseline without counting the entire cumulative counter as
            // traffic. This is especially important after ECM is re-enabled.
            let Some(prev) = runtime.prev_ecm_bytes.get(ecm_key).copied() else {
                runtime.prev_ecm_bytes.insert(*ecm_key, ecm_val.bytes);
                continue;
            };

            let delta = delta_bytes(ecm_val.bytes, prev);
            runtime.prev_ecm_bytes.insert(*ecm_key, ecm_val.bytes);

            if delta == 0 {
                let last_active = runtime
                    .ecm_last_active_ms
                    .get(ecm_key)
                    .copied()
                    .unwrap_or(now_ms);

                if now_ms.saturating_sub(last_active) >= ECM_IDLE_TIMEOUT_MS {
                    ecm_keys_to_prune.push(*ecm_key);
                    continue;
                }
            } else {
                runtime.ecm_last_active_ms.insert(*ecm_key, now_ms);
            }

            if let Some((ifindex, mac)) = ip_to_device.get(&lookup) {
                let device_key = (*ifindex, *mac);

                // Historical IP attribution can resolve an active ECM flow
                // even when the device is temporarily absent from the current
                // neighbor snapshot. Recreate the row from the registry.
                if !devices_group.contains_key(&device_key) {
                    if let Some(known) = runtime.device_registry.entries.get(&device_key) {
                        devices_group.insert(device_key, DeviceListItem {
                            ifindex: known.ifindex,
                            logical_iface: known.logical_iface.clone(),
                            subnet: known.subnet.clone(),
                            ipv4: known.ipv4.clone(),
                            ipv6: known.ipv6.clone(),
                            mac: mac_utils::to_string(&known.mac),
                            hostname: if known.hostname.trim().is_empty() {
                                "-".to_string()
                            } else {
                                known.hostname.clone()
                            },
                            metrics: CounterQuad::default(),
                            cumulative: CounterQuad::default(),
                            online: true,
                            last_seen_ms: now_ms,
                            neighbor_state: None,
                        });
                    }
                }

                if let Some(entry) = devices_group.get_mut(&device_key) {
                    fill_quad(
                        ecm_key.ip_version,
                        ecm_key.direction,
                        &mut entry.metrics,
                        delta,
                        sec,
                    );
                    ecm_devices.insert(device_key);

                    let lan_metrics = lan_ecm_metrics.entry(*ifindex).or_default();
                    fill_quad(
                        ecm_key.ip_version,
                        ecm_key.direction,
                        lan_metrics,
                        delta,
                        sec,
                    );
                }
            } else {
                // Not in the active neighbor table. For IPv4, try to recover
                // the logical VLAN/bridge from the configured interface subnet.
                //
                // Only attribute automatically when exactly one LAN interface
                // matches; otherwise keep the traffic unresolved rather than
                // inventing an interface and corrupting per-VLAN accounting.
                if ecm_key.ip_version == 4 {
                    let ip_u32 = ecm_key.ip[0];
                    let mut matches = Vec::new();
                    for (ifindex, net, mask) in &local_v4_subnets {
                        if (ip_u32 & mask) == (*net & mask) &&
                            !matches.contains(ifindex)
                        {
                            matches.push(*ifindex);
                        }
                    }

                    if matches.len() == 1 {
                        let lan_metrics = lan_ecm_metrics.entry(matches[0]).or_default();
                        fill_quad(ecm_key.ip_version, ecm_key.direction, lan_metrics, delta, sec);
                        continue;
                    }
                }

                // Never silently turn a local/unresolved flow into WAN.
                // This aggregate is intentionally retained for observability,
                // but is not injected into a guessed VLAN interface.
                let mut is_probably_local = false;
                if ecm_key.ip_version == 6 {
                    let w0 = ecm_key.ip[0];
                    // ULA is fc00::/7, link-local is fe80::/10.
                    if (w0 & 0xFE000000) == 0xFC000000 ||
                        (w0 & 0xFFC00000) == 0xFE800000
                    {
                        is_probably_local = true;
                    }
                }

                if is_probably_local {
                    fill_quad(ecm_key.ip_version, ecm_key.direction, &mut unresolved_ecm_metrics, delta, sec);
                } else {
                    fill_quad(ecm_key.ip_version, ecm_key.direction, &mut wan_ecm_metrics, delta, sec);
                }
            }
        }

        if let Some(ifidx) = wan_ifindex {
            let entry = devices_group.entry((ifidx, mac_wan)).or_insert_with(|| DeviceListItem {
                ifindex: ifidx,
                logical_iface: topology.by_ifindex(ifidx).unwrap().name.clone(),
                subnet: String::new(),
                ipv4: vec![],
                ipv6: vec![],
                mac: mac_utils::to_string(&mac_wan),
                hostname: "WAN (External)".to_string(),
                metrics: CounterQuad::default(),
                cumulative: CounterQuad::default(),
                online: true,
                last_seen_ms: now_ms,
                neighbor_state: None,
            });
            entry.online = true;
            entry.last_seen_ms = now_ms;
            if !wan_ecm_metrics.is_empty() {
                add_quad(&mut entry.metrics, &wan_ecm_metrics);
                ecm_devices.insert((ifidx, mac_wan));
            }
        }

        if let Some(ifidx) = lan_ifindex {
            let entry = devices_group.entry((ifidx, mac_unresolved)).or_insert_with(|| DeviceListItem {
                ifindex: ifidx,
                logical_iface: topology.by_ifindex(ifidx).unwrap().name.clone(),
                subnet: String::new(),
                ipv4: vec![],
                ipv6: vec![],
                mac: mac_utils::to_string(&mac_unresolved),
                hostname: "Unresolved (LAN)".to_string(),
                metrics: CounterQuad::default(),
                cumulative: CounterQuad::default(),
                online: true,
                last_seen_ms: now_ms,
                neighbor_state: None,
            });
            entry.online = true;
            entry.last_seen_ms = now_ms;
            if !unresolved_ecm_metrics.is_empty() {
                add_quad(&mut entry.metrics, &unresolved_ecm_metrics);
                ecm_devices.insert((ifidx, mac_unresolved));
            }
        }

        // Prune idle ECM keys from kernel map to prevent permanent saturation
        if !ecm_keys_to_prune.is_empty() {
            if let Some(map) = ebpf.map_mut("ECM_TRAFFIC_STATS") {
                if let Ok(mut hash_map) = aya::maps::PerCpuHashMap::<_, EcmTrafficKey, TrafficValue>::try_from(map) {
                    for k in &ecm_keys_to_prune {
                        let _ = hash_map.remove(k);
                    }
                }
            }
            for k in &ecm_keys_to_prune {
                runtime.prev_ecm_bytes.remove(k);
                runtime.ecm_last_active_ms.remove(k);
                ecm_stats.remove(k);   // hapus juga dari snapshot lokal agar retain tidak memasukkan kembali
            }
        }

        // ECM_TRAFFIC_STATS/ECM_MAX_ENTRIES capacity is 16384; warn at >90%.
        const ECM_MAP_MAX_ENTRIES: usize = 16384;
        const ECM_MAP_WARN_THRESHOLD: usize = ECM_MAP_MAX_ENTRIES * 90 / 100;
        if ecm_stats.len() > ECM_MAP_WARN_THRESHOLD {
            log::warn!(
                "ECM_TRAFFIC_STATS/ECM_MAX_ENTRIES is dangerously full: {}/{} entries!",
                ecm_stats.len(),
                ECM_MAP_MAX_ENTRIES
            );
        }

        // Prune stale ECM keys from userspace map to prevent unbounded memory/CPU growth
        runtime.prev_ecm_bytes.retain(|k, _| ecm_stats.contains_key(k));
        runtime.ecm_last_active_ms.retain(|k, _| ecm_stats.contains_key(k));
        runtime.ecm_active_devices = ecm_devices;
    }

    for (key, dev) in devices_group.iter_mut() {
        let cum = runtime.cumulative_device.entry(*key).or_default();
        add_quad(cum, &dev.metrics);
        dev.cumulative = *cum;

        if runtime.ecm_active_devices.contains(key) {
            let smoothed = runtime.smoothed_rates.entry(*key).or_default();
            smoothed.up_v4_bps = ((0.4 * dev.metrics.up_v4_bps as f64) + (0.6 * smoothed.up_v4_bps as f64)) as u64;
            smoothed.down_v4_bps = ((0.4 * dev.metrics.down_v4_bps as f64) + (0.6 * smoothed.down_v4_bps as f64)) as u64;
            smoothed.up_v6_bps = ((0.4 * dev.metrics.up_v6_bps as f64) + (0.6 * smoothed.up_v6_bps as f64)) as u64;
            smoothed.down_v6_bps = ((0.4 * dev.metrics.down_v6_bps as f64) + (0.6 * smoothed.down_v6_bps as f64)) as u64;

            dev.metrics.up_v4_bps = smoothed.up_v4_bps;
            dev.metrics.down_v4_bps = smoothed.down_v4_bps;
            dev.metrics.up_v6_bps = smoothed.up_v6_bps;
            dev.metrics.down_v6_bps = smoothed.down_v6_bps;
        } else {
            let smoothed = runtime.smoothed_rates.entry(*key).or_default();
            *smoothed = dev.metrics.clone();
        }
    }

    for (key, dev) in &devices_group {
        runtime.device_registry.entries.insert(
            *key,
            KnownDevice {
                ifindex: dev.ifindex,
                mac: key.1,
                ipv4: dev.ipv4.clone(),
                ipv6: dev.ipv6.clone(),
                hostname: dev.hostname.clone(),
                logical_iface: dev.logical_iface.clone(),
                subnet: dev.subnet.clone(),
                last_seen_ms: now_ms,
            },
        );
    }

    let online_keys: FxHashSet<_> = devices_group.keys().cloned().collect();
    let mut devices: Vec<_> = devices_group.into_values().collect();
    for (key, known) in &runtime.device_registry.entries {
        if online_keys.contains(key) {
            continue;
        }
        if !monitor_set.is_empty() {
            if let Some(logical) = topology.by_ifindex(known.ifindex) {
                if !monitor_set.contains(logical.name.as_str()) {
                    continue;
                }
            } else {
                continue;
            }
        }
        devices.push(DeviceListItem {
            ifindex: known.ifindex,
            logical_iface: known.logical_iface.clone(),
            subnet: known.subnet.clone(),
            ipv4: known.ipv4.clone(),
            ipv6: known.ipv6.clone(),
            mac: mac_utils::to_string(&known.mac),
            hostname: known.hostname.clone(),
            metrics: CounterQuad::default(),
            cumulative: runtime.cumulative_device.get(key).copied().unwrap_or_default(),
            online: false,
            last_seen_ms: known.last_seen_ms,
            neighbor_state: None,
        });
    }

    devices.sort_by(|a, b| {
        a.logical_iface
            .cmp(&b.logical_iface)
            .then(a.ipv4.cmp(&b.ipv4))
            .then(a.ipv6.cmp(&b.ipv6))
    });

    // Everything below this point that is ECM-specific must remain inert
    // when ECM is disabled.
    // Process and smooth LAN ECM traffic for each interface
    let mut lan_ecm_smoothed: HashMap<u32, CounterQuad> = HashMap::new();

    if !enable_ecm {
        runtime.buf_iface_stats = iface_stats;
        runtime.buf_device_stats = device_stats;
        runtime.buf_ecm_stats = ecm_stats;

        return Ok(SnapshotData {
            timestamp_ms: now_ms,
            interfaces,
            devices,
        });
    }

    // Decay smoothed rates for interfaces that have no ECM traffic this tick
    let mut to_remove_lan = Vec::new();
    for (ifindex, smoothed) in runtime.smoothed_lan_ecm_rates.iter_mut() {
        if !lan_ecm_metrics.contains_key(ifindex) {
            smoothed.up_v4_bps = (0.6 * smoothed.up_v4_bps as f64) as u64;
            smoothed.down_v4_bps = (0.6 * smoothed.down_v4_bps as f64) as u64;
            smoothed.up_v6_bps = (0.6 * smoothed.up_v6_bps as f64) as u64;
            smoothed.down_v6_bps = (0.6 * smoothed.down_v6_bps as f64) as u64;
            smoothed.up_v4_bytes = 0;
            smoothed.down_v4_bytes = 0;
            smoothed.up_v6_bytes = 0;
            smoothed.down_v6_bytes = 0;
            
            if smoothed.up_v4_bps == 0 && smoothed.down_v4_bps == 0 && smoothed.up_v6_bps == 0 && smoothed.down_v6_bps == 0 {
                to_remove_lan.push(*ifindex);
            } else {
                lan_ecm_smoothed.insert(*ifindex, *smoothed);
            }
        }
    }
    for ifindex in to_remove_lan {
        runtime.smoothed_lan_ecm_rates.remove(&ifindex);
    }
    
    // Smooth incoming LAN ECM traffic
    for (ifindex, metrics) in &lan_ecm_metrics {
        let smoothed = runtime.smoothed_lan_ecm_rates.entry(*ifindex).or_default();
        smoothed.up_v4_bps = ((0.4 * metrics.up_v4_bps as f64) + (0.6 * smoothed.up_v4_bps as f64)) as u64;
        smoothed.down_v4_bps = ((0.4 * metrics.down_v4_bps as f64) + (0.6 * smoothed.down_v4_bps as f64)) as u64;
        smoothed.up_v6_bps = ((0.4 * metrics.up_v6_bps as f64) + (0.6 * smoothed.up_v6_bps as f64)) as u64;
        smoothed.down_v6_bps = ((0.4 * metrics.down_v6_bps as f64) + (0.6 * smoothed.down_v6_bps as f64)) as u64;

        smoothed.up_v4_bytes = metrics.up_v4_bytes;
        smoothed.down_v4_bytes = metrics.down_v4_bytes;
        smoothed.up_v6_bytes = metrics.up_v6_bytes;
        smoothed.down_v6_bytes = metrics.down_v6_bytes;
        
        lan_ecm_smoothed.insert(*ifindex, *smoothed);
    }

    // Add external ECM traffic to WAN interfaces
    let wan_smoothed = runtime.smoothed_wan_ecm_rates.get_or_insert(CounterQuad::default());
    if !wan_ecm_metrics.is_empty() {
        wan_smoothed.up_v4_bps = ((0.4 * wan_ecm_metrics.up_v4_bps as f64) + (0.6 * wan_smoothed.up_v4_bps as f64)) as u64;
        wan_smoothed.down_v4_bps = ((0.4 * wan_ecm_metrics.down_v4_bps as f64) + (0.6 * wan_smoothed.down_v4_bps as f64)) as u64;
        wan_smoothed.up_v6_bps = ((0.4 * wan_ecm_metrics.up_v6_bps as f64) + (0.6 * wan_smoothed.up_v6_bps as f64)) as u64;
        wan_smoothed.down_v6_bps = ((0.4 * wan_ecm_metrics.down_v6_bps as f64) + (0.6 * wan_smoothed.down_v6_bps as f64)) as u64;

        wan_smoothed.up_v4_bytes = wan_ecm_metrics.up_v4_bytes;
        wan_smoothed.down_v4_bytes = wan_ecm_metrics.down_v4_bytes;
        wan_smoothed.up_v6_bytes = wan_ecm_metrics.up_v6_bytes;
        wan_smoothed.down_v6_bytes = wan_ecm_metrics.down_v6_bytes;
    } else {
        wan_smoothed.up_v4_bps = (0.6 * wan_smoothed.up_v4_bps as f64) as u64;
        wan_smoothed.down_v4_bps = (0.6 * wan_smoothed.down_v4_bps as f64) as u64;
        wan_smoothed.up_v6_bps = (0.6 * wan_smoothed.up_v6_bps as f64) as u64;
        wan_smoothed.down_v6_bps = (0.6 * wan_smoothed.down_v6_bps as f64) as u64;

        wan_smoothed.up_v4_bytes = 0;
        wan_smoothed.down_v4_bytes = 0;
        wan_smoothed.up_v6_bytes = 0;
        wan_smoothed.down_v6_bytes = 0;
    }

    let has_wan_entry = interfaces.iter().any(|i| i.zone == "wan");
    if !has_wan_entry {
        if let Some(wan_iface) = topology.interfaces().iter().find(|i| i.zone == "wan") {
            interfaces.push(InterfaceOverviewItem {
                ifindex: wan_iface.ifindex,
                ifname: wan_iface.name.clone(),
                zone: "wan".to_string(),
                metrics: CounterQuad::default(),
                cumulative: runtime.cumulative_iface.get(&wan_iface.ifindex).copied().unwrap_or_default(),
            });
        }
    }

    let mut wan_injected = false;
    let mut unresolved_injected = false;
    for iface in &mut interfaces {
        // Inject LAN ECM traffic into LAN interfaces
        if let Some(lan_smoothed) = lan_ecm_smoothed.get(&iface.ifindex) {
            let cum = runtime.cumulative_iface.entry(iface.ifindex).or_default();
            // Need to retrieve raw bytes to accumulate
            if let Some(lan_raw) = lan_ecm_metrics.get(&iface.ifindex) {
                add_quad(cum, lan_raw);
            }
            iface.cumulative = *cum;
            add_quad(&mut iface.metrics, lan_smoothed);
        }
        let is_wan = iface.zone == "wan";

        if is_wan {
            if wan_injected {
                log::warn!(
                    "multiple interfaces with zone=='wan' detected (ifindex={}); ECM WAN traffic only injected into the first one",
                    iface.ifindex
                );
            } else {
                wan_injected = true;
                let cum = runtime.cumulative_iface.entry(iface.ifindex).or_default();
                add_quad(cum, &wan_ecm_metrics);
                iface.cumulative = *cum;

                add_quad(&mut iface.metrics, wan_smoothed);
            }
        } else if Some(iface.ifindex) == lan_ifindex && !unresolved_injected {
            unresolved_injected = true;
            let cum = runtime.cumulative_iface.entry(iface.ifindex).or_default();
            add_quad(cum, &unresolved_ecm_metrics);
            iface.cumulative = *cum;

            if let Some(smoothed) = runtime.smoothed_rates.get(&(iface.ifindex, mac_unresolved)) {
                add_quad(&mut iface.metrics, smoothed);
            }
        }
    }

    runtime.buf_iface_stats = iface_stats;
    runtime.buf_device_stats = device_stats;
    runtime.buf_ecm_stats = ecm_stats;

    Ok(SnapshotData {
        timestamp_ms: now_ms,
        interfaces,
        devices,
    })
}

/// Parse an IPv4 CIDR into `(network, mask)` in host-independent u32 form.
///
/// Examples:
///   192.168.13.0/24 -> (0xC0A80D00, 0xFFFFFF00)
///   10.0.0.1/8     -> (0x0A000000, 0xFF000000)
///   0.0.0.0/0      -> (0, 0)
fn parse_cidr_to_u32(cidr: &str) -> Option<(u32, u32)> {
    let (ip_str, prefix_str) = cidr.trim().split_once('/')?;

    let ip: std::net::Ipv4Addr = ip_str.trim().parse().ok()?;
    let prefix: u32 = prefix_str.trim().parse().ok()?;

    if prefix > 32 {
        return None;
    }

    let mask = match prefix {
        0 => 0,
        32 => u32::MAX,
        n => u32::MAX << (32 - n),
    };

    let network = u32::from(ip) & mask;
    Some((network, mask))
}

/// 计算计数器增量，兼容重置情形
fn delta_bytes(current: u64, previous: u64) -> u64 {
    if current >= previous {
        current - previous
    } else {
        // Counter may reset after map/program reload.
        current
    }
}

/// 从 eBPF map 读取接口级流量统计

fn sync_device_tracking(ebpf: &mut Ebpf, topology: &TopologySnapshot, monitor_ifaces: &FxHashSet<&str>, ) -> anyhow::Result<()> {
    let mut map: AyaHashMap<_, u32, u8> = AyaHashMap::try_from(
        ebpf.map_mut("TRACK_DEVICES")
            .ok_or_else(|| anyhow::anyhow!("TRACK_DEVICES map not found"))?,
    )?;

    // Default to tracking all interfaces unless they are explicitly WAN
    for iface in topology.interfaces() {
        if monitor_ifaces.is_empty() || monitor_ifaces.contains(iface.name.as_str()) {
            let track = if iface.zone.starts_with("wan") { 0 } else { 1 };
            let _ = map.insert(iface.ifindex, track, 0);
        }
    }
    Ok(())
}

fn read_iface_stats(ebpf: &mut Ebpf, result: &mut HashMap<InterfaceTrafficKey, TrafficValue>) -> anyhow::Result<()> {
    result.clear();
    let map = ebpf
        .map_mut("IFACE_TRAFFIC_STATS")
        .ok_or_else(|| anyhow::anyhow!("IFACE_TRAFFIC_STATS map not found"))?;
    let map: AyaHashMap<_, InterfaceTrafficKey, TrafficValue> = AyaHashMap::try_from(map)?;
    for entry in map.iter() {
        let (k, v) = entry?;
        result.insert(k, v);
    }
    Ok(())
}

/// 从 eBPF map 读取设备级流量统计
fn read_device_stats(ebpf: &mut Ebpf, result: &mut HashMap<DeviceTrafficKey, TrafficValue>) -> anyhow::Result<()> {
    result.clear();
    let map = ebpf
        .map_mut("DEVICE_TRAFFIC_STATS")
        .ok_or_else(|| anyhow::anyhow!("DEVICE_TRAFFIC_STATS map not found"))?;
    let map: AyaHashMap<_, DeviceTrafficKey, TrafficValue> = AyaHashMap::try_from(map)?;
    for entry in map.iter() {
        let (k, v) = entry?;
        result.insert(k, v);
    }
    Ok(())
}

/// 从 eBPF map 读取 ECM (Qualcomm NSS) 硬件加速流量统计 (可选)
fn read_ecm_stats(ebpf: &mut Ebpf, result: &mut HashMap<EcmTrafficKey, TrafficValue>) {
    result.clear();
    let map = match ebpf.map_mut("ECM_TRAFFIC_STATS") {
        Some(m) => m,
        None => return,
    };
    let map: aya::maps::PerCpuHashMap<_, EcmTrafficKey, TrafficValue> = match aya::maps::PerCpuHashMap::try_from(map) {
        Ok(m) => m,
        Err(e) => {
            log::error!("Failed to convert ECM map: {}", e);
            return;
        }
    };
    for entry in map.iter() {
        if let Ok((k, percpu_vals)) = entry {
            let mut sum_bytes = 0;
            let mut sum_pkts = 0;
            for val in percpu_vals.iter() {
                sum_bytes += val.bytes;
                sum_pkts += val.packets;
            }
            result.insert(
                k,
                TrafficValue {
                    bytes: sum_bytes,
                    packets: sum_pkts,
                },
            );
        }
    }
}

/// 根据 IP 版本和方向填充四元组，bytes 存增量
fn fill_quad(ip_version: u8, direction: u8, quad: &mut CounterQuad, delta_bytes: u64, sec: f64) {
    let delta_bps = ((delta_bytes as f64) * 8.0 / sec).round() as u64;
    match (ip_version, direction) {
        (x, y) if x == IpVersion::V4 as u8 && y == TrafficDirection::Ingress as u8 => {
            quad.up_v4_bps = quad.up_v4_bps.saturating_add(delta_bps);
            quad.up_v4_bytes = quad.up_v4_bytes.saturating_add(delta_bytes);
        }
        (x, y) if x == IpVersion::V4 as u8 && y == TrafficDirection::Egress as u8 => {
            quad.down_v4_bps = quad.down_v4_bps.saturating_add(delta_bps);
            quad.down_v4_bytes = quad.down_v4_bytes.saturating_add(delta_bytes);
        }
        (x, y) if x == IpVersion::V6 as u8 && y == TrafficDirection::Ingress as u8 => {
            quad.up_v6_bps = quad.up_v6_bps.saturating_add(delta_bps);
            quad.up_v6_bytes = quad.up_v6_bytes.saturating_add(delta_bytes);
        }
        (x, y) if x == IpVersion::V6 as u8 && y == TrafficDirection::Egress as u8 => {
            quad.down_v6_bps = quad.down_v6_bps.saturating_add(delta_bps);
            quad.down_v6_bytes = quad.down_v6_bytes.saturating_add(delta_bytes);
        }
        _ => {}
    }
}

#[cfg(test)]
mod aggregated_bucket_tests {
    use super::{AggregatedBucket, HistoryTrafficType};

    #[test]
    fn with_traffic_type_ipv4_clears_v6() {
        let b = AggregatedBucket {
            start_ts_ms: 0,
            end_ts_ms: 1,
            sample_count: 1,
            up_v4_bytes: 10,
            down_v4_bytes: 20,
            up_v6_bytes: 30,
            down_v6_bytes: 40,
            up_v4_bps_sum: 1,
            up_v4_bps_max: 2,
            up_v4_bps_min: 0,
            down_v4_bps_sum: 3,
            down_v4_bps_max: 4,
            down_v4_bps_min: 0,
            up_v6_bps_sum: 5,
            up_v6_bps_max: 6,
            up_v6_bps_min: 0,
            down_v6_bps_sum: 7,
            down_v6_bps_max: 8,
            down_v6_bps_min: 0,
            ..Default::default()
        }
        .with_traffic_type(HistoryTrafficType::Ipv4);
        assert_eq!(b.up_v4_bytes, 10);
        assert_eq!(b.up_v6_bytes, 0);
        assert_eq!(b.up_v6_bps_sum, 0);
    }

    #[test]
    fn with_traffic_type_ipv6_clears_v4() {
        let b = AggregatedBucket {
            start_ts_ms: 0,
            end_ts_ms: 1,
            sample_count: 1,
            up_v4_bytes: 10,
            down_v4_bytes: 20,
            up_v6_bytes: 30,
            down_v6_bytes: 40,
            up_v4_bps_sum: 1,
            up_v4_bps_max: 2,
            up_v4_bps_min: 0,
            down_v4_bps_sum: 3,
            down_v4_bps_max: 4,
            down_v4_bps_min: 0,
            up_v6_bps_sum: 5,
            up_v6_bps_max: 6,
            up_v6_bps_min: 0,
            down_v6_bps_sum: 7,
            down_v6_bps_max: 8,
            down_v6_bps_min: 0,
            ..Default::default()
        }
        .with_traffic_type(HistoryTrafficType::Ipv6);
        assert_eq!(b.up_v6_bytes, 30);
        assert_eq!(b.up_v4_bytes, 0);
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::{
        daily_bucket_local, hourly_bucket_local, AggregateBucket, AggregatedBucket, HistogramHistory,
    };
    use chrono::{Local, TimeZone};

    fn bucket(start: u64, end: u64) -> AggregatedBucket {
        AggregatedBucket {
            start_ts_ms: start,
            end_ts_ms: end,
            sample_count: 1,
            up_v4_bytes: 1,
            down_v4_bytes: 1,
            up_v6_bytes: 1,
            down_v6_bytes: 1,
            up_v4_bps_sum: 1,
            up_v4_bps_max: 1,
            up_v4_bps_min: 1,
            down_v4_bps_sum: 1,
            down_v4_bps_max: 1,
            down_v4_bps_min: 1,
            up_v6_bps_sum: 1,
            up_v6_bps_max: 1,
            up_v6_bps_min: 1,
            down_v6_bps_sum: 1,
            down_v6_bps_max: 1,
            down_v6_bps_min: 1,
            ..Default::default()
        }
    }

    #[test]
    fn hourly_bucket_uses_closed_end_235959999() {
        let ts = Local.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap().timestamp_millis() as u64;
        let (_, end) = hourly_bucket_local(ts);
        let expected = Local.with_ymd_and_hms(2024, 1, 15, 10, 59, 59).unwrap().timestamp_millis() as u64 + 999;
        assert_eq!(end, expected);
    }

    #[test]
    fn daily_bucket_uses_closed_end_235959999() {
        let ts = Local.with_ymd_and_hms(2024, 1, 15, 0, 0, 0).unwrap().timestamp_millis() as u64;
        let (_, end) = daily_bucket_local(ts);
        let expected = Local.with_ymd_and_hms(2024, 1, 15, 23, 59, 59).unwrap().timestamp_millis() as u64 + 999;
        assert_eq!(end, expected);
    }

    #[test]
    fn query_aggregate_matches_closed_boundary() {
        let mut h = HistogramHistory::new();
        let ts = Local.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap().timestamp_millis() as u64;
        let (start, end) = hourly_bucket_local(ts);
        h.restore_iface_bucket(1, bucket(start, end));

        let at_end = h.query_aggregate(1, None, end, end, AggregateBucket::Hourly);
        assert_eq!(at_end.len(), 1);

        let after_end = h.query_aggregate(1, None, end + 1, end + 1, AggregateBucket::Hourly);
        assert!(after_end.is_empty());
    }

    #[test]
    fn cumulative_from_completed_prefers_ring_bytes_as_source() {
        let mut h = HistogramHistory::new();
        let ts = Local.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap().timestamp_millis() as u64;
        let (start, end) = hourly_bucket_local(ts);

        let mut iface_bucket = bucket(start, end);
        iface_bucket.up_v4_bytes = 100;
        iface_bucket.down_v4_bytes = 200;
        iface_bucket.up_v6_bytes = 300;
        iface_bucket.down_v6_bytes = 400;
        h.restore_iface_bucket(1, iface_bucket.clone());

        let mut device_bucket = bucket(start, end);
        device_bucket.up_v4_bytes = 11;
        device_bucket.down_v4_bytes = 22;
        device_bucket.up_v6_bytes = 33;
        device_bucket.down_v6_bytes = 44;
        h.restore_device_bucket(2, "aa:bb:cc:dd:ee:ff".to_string(), device_bucket.clone());

        let (iface, device) = h.cumulative_from_completed();
        let iface_cum = iface.get(&1).unwrap();
        assert_eq!(iface_cum.up_v4_bytes, 100);
        assert_eq!(iface_cum.down_v4_bytes, 200);
        assert_eq!(iface_cum.up_v6_bytes, 300);
        assert_eq!(iface_cum.down_v6_bytes, 400);

        let dev_cum = device.get(&(2, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])).unwrap();
        assert_eq!(dev_cum.up_v4_bytes, 11);
        assert_eq!(dev_cum.down_v4_bytes, 22);
        assert_eq!(dev_cum.up_v6_bytes, 33);
        assert_eq!(dev_cum.down_v6_bytes, 44);
    }

    #[test]
    fn finalize_computes_avg_from_sum_count() {
        let b = AggregatedBucket {
            sample_count: 4,
            up_v4_bps_sum: 400,
            down_v4_bps_sum: 800,
            up_v6_bps_sum: 120,
            down_v6_bps_sum: 240,
            up_v4_bps_max: 200,
            down_v4_bps_max: 300,
            up_v6_bps_max: 60,
            down_v6_bps_max: 100,
            ..Default::default()
        }.finalize();
        assert_eq!(b.up_v4_bps_avg, 100);
        assert_eq!(b.down_v4_bps_avg, 200);
        assert_eq!(b.up_v6_bps_avg, 30);
        assert_eq!(b.down_v6_bps_avg, 60);
        // p95 == max
        assert_eq!(b.up_v4_bps_p95, 200);
        assert_eq!(b.down_v4_bps_p95, 300);
    }
}
