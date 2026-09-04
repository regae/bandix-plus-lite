use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::Duration;

use aya::maps::HashMap as AyaHashMap;
use aya::Ebpf;
use bandix_plus_common::{DeviceTrafficKey, EcmTrafficKey, InterfaceTrafficKey, IpVersion, TrafficDirection, TrafficValue};
use chrono::{Local, TimeZone, Timelike};
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
    pub prev_iface_bytes: HashMap<InterfaceTrafficKey, u64>,
    pub prev_device_bytes: HashMap<DeviceTrafficKey, u64>,
    pub prev_ecm_bytes: HashMap<EcmTrafficKey, u64>,
    pub ecm_active_devices: std::collections::HashSet<(u32, [u8; 6])>,
    pub cumulative_iface: HashMap<u32, CounterQuad>,
    pub cumulative_device: HashMap<(u32, [u8; 6]), CounterQuad>,
    pub smoothed_rates: HashMap<(u32, [u8; 6]), CounterQuad>,
    pub smoothed_iface_rates: HashMap<u32, CounterQuad>,
    pub smoothed_wan_ecm_rates: Option<CounterQuad>,
    pub last_snapshot_ms: Option<u64>,
    pub device_registry: DeviceRegistry,
    pub last_hostname_fetch_ms: u64,
    pub cached_hostnames: HashMap<[u8; 6], String>,
    pub last_ipv6_neigh_fetch_ms: u64,
    pub cached_ipv6_neighbors_raw: String,
}

impl MonitorRuntime {
    /// Remove all monitor-side state for one logical-interface/device pair.
    pub fn remove_device(&mut self, ifindex: u32, mac: [u8; 6]) -> bool {
        let mut removed = self.device_registry.entries.remove(&(ifindex, mac)).is_some();
        removed |= self.cumulative_device.remove(&(ifindex, mac)).is_some();

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

fn hourly_bucket_local(ts_ms: u64) -> (u64, u64) {
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
    pub up_v4_bytes: u64,
    pub down_v4_bytes: u64,
    pub up_v6_bytes: u64,
    pub down_v6_bytes: u64,
    pub up_v4_bps_avg: u64,
    pub up_v4_bps_max: u64,
    pub up_v4_bps_min: u64,
    pub up_v4_bps_p95: u64,
    pub down_v4_bps_avg: u64,
    pub down_v4_bps_max: u64,
    pub down_v4_bps_min: u64,
    pub down_v4_bps_p95: u64,
    pub up_v6_bps_avg: u64,
    pub up_v6_bps_max: u64,
    pub up_v6_bps_min: u64,
    pub up_v6_bps_p95: u64,
    pub down_v6_bps_avg: u64,
    pub down_v6_bps_max: u64,
    pub down_v6_bps_min: u64,
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
                self.up_v6_bps_avg = 0;
                self.up_v6_bps_max = 0;
                self.up_v6_bps_min = 0;
                self.up_v6_bps_p95 = 0;
                self.down_v6_bps_avg = 0;
                self.down_v6_bps_max = 0;
                self.down_v6_bps_min = 0;
                self.down_v6_bps_p95 = 0;
            }
            HistoryTrafficType::Ipv6 => {
                self.up_v4_bytes = 0;
                self.down_v4_bytes = 0;
                self.up_v4_bps_avg = 0;
                self.up_v4_bps_max = 0;
                self.up_v4_bps_min = 0;
                self.up_v4_bps_p95 = 0;
                self.down_v4_bps_avg = 0;
                self.down_v4_bps_max = 0;
                self.down_v4_bps_min = 0;
                self.down_v4_bps_p95 = 0;
            }
        }
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

        if entry.up_v4_bps_max == 0 && entry.up_v4_bps_avg == 0 {
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

        entry.up_v4_bps_p95 = entry.up_v4_bps_max;
        entry.down_v4_bps_p95 = entry.down_v4_bps_max;
        entry.up_v6_bps_p95 = entry.up_v6_bps_max;
        entry.down_v6_bps_p95 = entry.down_v6_bps_max;

        entry.up_v4_bps_avg = (entry.up_v4_bps_avg + metrics.up_v4_bps) / 2;
        entry.down_v4_bps_avg = (entry.down_v4_bps_avg + metrics.down_v4_bps) / 2;
        entry.up_v6_bps_avg = (entry.up_v6_bps_avg + metrics.up_v6_bps) / 2;
        entry.down_v6_bps_avg = (entry.down_v6_bps_avg + metrics.down_v6_bps) / 2;

        old_bucket
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

        if entry.up_v4_bps_max == 0 && entry.up_v4_bps_avg == 0 {
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

        entry.up_v4_bps_p95 = entry.up_v4_bps_max;
        entry.down_v4_bps_p95 = entry.down_v4_bps_max;
        entry.up_v6_bps_p95 = entry.up_v6_bps_max;
        entry.down_v6_bps_p95 = entry.down_v6_bps_max;

        entry.up_v4_bps_avg = (entry.up_v4_bps_avg + metrics.up_v4_bps) / 2;
        entry.down_v4_bps_avg = (entry.down_v4_bps_avg + metrics.down_v4_bps) / 2;
        entry.up_v6_bps_avg = (entry.up_v6_bps_avg + metrics.up_v6_bps) / 2;
        entry.down_v6_bps_avg = (entry.down_v6_bps_avg + metrics.down_v6_bps) / 2;

        old_bucket
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

        match bucket {
            AggregateBucket::Hourly => hourly,
            AggregateBucket::Daily => merge_hourly_to_daily(&hourly),
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

        acc.up_v4_bps_avg = if acc.up_v4_bps_avg == 0 {
            b.up_v4_bps_avg
        } else {
            (acc.up_v4_bps_avg + b.up_v4_bps_avg) / 2
        };
        acc.down_v4_bps_avg = if acc.down_v4_bps_avg == 0 {
            b.down_v4_bps_avg
        } else {
            (acc.down_v4_bps_avg + b.down_v4_bps_avg) / 2
        };
        acc.up_v6_bps_avg = if acc.up_v6_bps_avg == 0 {
            b.up_v6_bps_avg
        } else {
            (acc.up_v6_bps_avg + b.up_v6_bps_avg) / 2
        };
        acc.down_v6_bps_avg = if acc.down_v6_bps_avg == 0 {
            b.down_v6_bps_avg
        } else {
            (acc.down_v6_bps_avg + b.down_v6_bps_avg) / 2
        };
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
    let iface_stats = read_iface_stats(ebpf)?;
    let device_stats = read_device_stats(ebpf)?;
    let ecm_stats = if enable_ecm { read_ecm_stats(ebpf) } else { std::collections::HashMap::new() };
    let sec = if let Some(prev_ms) = runtime.last_snapshot_ms {
        ((now_ms.saturating_sub(prev_ms)) as f64 / 1000.0).max(0.001)
    } else {
        interval.as_secs_f64().max(1.0)
    };
    runtime.last_snapshot_ms = Some(now_ms);

    let monitor_set: HashSet<_> = monitor_ifaces.iter().map(String::as_str).collect();
    let iface_infos = system_utils::list_interfaces()?;
    let ifindex_by_name: HashMap<_, _> = iface_infos.iter().map(|x| (x.name.as_str(), x.ifindex)).collect();

    let mut interfaces = Vec::new();
    let mut seen_iface_names = HashSet::new();
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

    let subnet_map = system_utils::list_interface_subnets().unwrap_or_default();
    let filtered_neighbors = system_utils::list_neighbors_filtered(monitor_ifaces, &subnet_map, runtime, now_ms).unwrap_or_default();

    // Hostname fetch from ubus/dnsmasq is expensive. We throttle it to once per 60s.
    // Trade-off: newly connected devices will take up to 60s to have their hostnames
    // populated in the UI, which is an acceptable compromise for CPU savings.
    if now_ms.saturating_sub(runtime.last_hostname_fetch_ms) >= 60_000 {
        runtime.cached_hostnames = system_utils::list_hostname_by_mac();
        runtime.last_hostname_fetch_ms = now_ms;
    }

    let mut dev_mac_to_ips: HashMap<(String, [u8; 6]), (Vec<String>, Vec<String>, String)> = HashMap::new();
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

    let mut devices_group: HashMap<(u32, [u8; 6]), DeviceListItem> = HashMap::new();
    for ((dev, mac), (ipv4_list, ipv6_list, best_state)) in dev_mac_to_ips {
        let Some(ifindex) = ifindex_by_name.get(dev.as_str()).copied() else {
            continue;
        };
        let Some(logical_iface) = topology.by_ifindex(ifindex) else {
            continue;
        };
        if !monitor_set.is_empty() && !monitor_set.contains(logical_iface.name.as_str()) {
            continue;
        }
        if ipv4_list.is_empty() {
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
        let mut ipv6: Vec<String> = ipv6_list;
        ipv6.sort_by(|a, b| {
            let a_is_ll = a.starts_with("fe80");
            let b_is_ll = b.starts_with("fe80");
            match (a_is_ll, b_is_ll) {
                (true, false) => std::cmp::Ordering::Greater,
                (false, true) => std::cmp::Ordering::Less,
                _ => a.cmp(b),
            }
        });

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
    // from the devices_group that was already populated from ARP/neighbor table.
    let mut wan_ecm_metrics = CounterQuad::default();
    let mut ecm_has_external = false;

    if !ecm_stats.is_empty() {
        let mut ip_to_device: HashMap<([u32; 4], u8), (u32, [u8; 6])> = HashMap::new();
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

        let mut ecm_devices = std::collections::HashSet::new();

        for (ecm_key, ecm_val) in &ecm_stats {
            let lookup = (ecm_key.ip, ecm_key.ip_version);
            let prev = runtime.prev_ecm_bytes.get(ecm_key).copied().unwrap_or(0);
            let delta = delta_bytes(ecm_val.bytes, prev);
            runtime.prev_ecm_bytes.insert(*ecm_key, ecm_val.bytes);

            if let Some((ifindex, mac)) = ip_to_device.get(&lookup) {
                if let Some(entry) = devices_group.get_mut(&(*ifindex, *mac)) {
                    if delta > 0 {
                        fill_quad(ecm_key.ip_version, ecm_key.direction, &mut entry.metrics, delta, sec);
                        ecm_devices.insert((*ifindex, *mac));
                    }
                }
            } else {
                if delta > 0 {
                    fill_quad(ecm_key.ip_version, ecm_key.direction, &mut wan_ecm_metrics, delta, sec);
                    ecm_has_external = true;
                }
            }
        }
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

    let online_keys: HashSet<_> = devices_group.keys().cloned().collect();
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

    // Add external ECM traffic to WAN interfaces
    let wan_smoothed = runtime.smoothed_wan_ecm_rates.get_or_insert(CounterQuad::default());
    if ecm_has_external {
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

    let mut wan_injected = false;
    for iface in &mut interfaces {
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

                // Hack: Inject WAN ECM traffic into the devices (e.g. ISP modem) on this WAN interface,
                // so that the total WAN traffic appears on the "wan" device in the Web UI Device List,
                // exactly as it does when ECM is turned off (where all traffic comes from the modem's MAC).
                for dev in &mut devices {
                    if dev.ifindex == iface.ifindex {
                        add_quad(&mut dev.metrics, wan_smoothed);

                        let mut mac_arr = [0u8; 6];
                        if let Ok(m) = crate::utils::mac_utils::from_str(&dev.mac) {
                            mac_arr = m;
                        }
                        let dev_cum = runtime.cumulative_device.entry((dev.ifindex, mac_arr)).or_default();
                        add_quad(dev_cum, &wan_ecm_metrics);
                        dev.cumulative = *dev_cum;
                    }
                }
            }
        }
    }

    Ok(SnapshotData {
        timestamp_ms: now_ms,
        interfaces,
        devices,
    })
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
fn read_iface_stats(ebpf: &mut Ebpf) -> anyhow::Result<HashMap<InterfaceTrafficKey, TrafficValue>> {
    let map = ebpf
        .map_mut("IFACE_TRAFFIC_STATS")
        .ok_or_else(|| anyhow::anyhow!("IFACE_TRAFFIC_STATS map not found"))?;
    let map: AyaHashMap<_, InterfaceTrafficKey, TrafficValue> = AyaHashMap::try_from(map)?;
    let mut result = HashMap::new();
    for entry in map.iter() {
        let (k, v) = entry?;
        result.insert(k, v);
    }
    Ok(result)
}

/// 从 eBPF map 读取设备级流量统计
fn read_device_stats(ebpf: &mut Ebpf) -> anyhow::Result<HashMap<DeviceTrafficKey, TrafficValue>> {
    let map = ebpf
        .map_mut("DEVICE_TRAFFIC_STATS")
        .ok_or_else(|| anyhow::anyhow!("DEVICE_TRAFFIC_STATS map not found"))?;
    let map: AyaHashMap<_, DeviceTrafficKey, TrafficValue> = AyaHashMap::try_from(map)?;
    let mut result = HashMap::new();
    for entry in map.iter() {
        let (k, v) = entry?;
        result.insert(k, v);
    }
    Ok(result)
}

/// 从 eBPF map 读取 ECM (Qualcomm NSS) 硬件加速流量统计 (可选)
fn read_ecm_stats(ebpf: &mut Ebpf) -> HashMap<EcmTrafficKey, TrafficValue> {
    let map = match ebpf.map_mut("ECM_TRAFFIC_STATS") {
        Some(m) => m,
        None => return HashMap::new(),
    };
    let map: aya::maps::PerCpuHashMap<_, EcmTrafficKey, TrafficValue> = match aya::maps::PerCpuHashMap::try_from(map) {
        Ok(m) => m,
        Err(e) => {
            log::error!("Failed to convert ECM map: {}", e);
            return HashMap::new();
        }
    };
    let mut result = HashMap::new();
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
    result
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
            up_v4_bytes: 10,
            down_v4_bytes: 20,
            up_v6_bytes: 30,
            down_v6_bytes: 40,
            up_v4_bps_avg: 1,
            up_v4_bps_max: 2,
            up_v4_bps_min: 0,
            up_v4_bps_p95: 2,
            down_v4_bps_avg: 3,
            down_v4_bps_max: 4,
            down_v4_bps_min: 0,
            down_v4_bps_p95: 4,
            up_v6_bps_avg: 5,
            up_v6_bps_max: 6,
            up_v6_bps_min: 0,
            up_v6_bps_p95: 6,
            down_v6_bps_avg: 7,
            down_v6_bps_max: 8,
            down_v6_bps_min: 0,
            down_v6_bps_p95: 8,
        }
        .with_traffic_type(HistoryTrafficType::Ipv4);
        assert_eq!(b.up_v4_bytes, 10);
        assert_eq!(b.up_v6_bytes, 0);
        assert_eq!(b.up_v6_bps_avg, 0);
    }

    #[test]
    fn with_traffic_type_ipv6_clears_v4() {
        let b = AggregatedBucket {
            start_ts_ms: 0,
            end_ts_ms: 1,
            up_v4_bytes: 10,
            down_v4_bytes: 20,
            up_v6_bytes: 30,
            down_v6_bytes: 40,
            up_v4_bps_avg: 1,
            up_v4_bps_max: 2,
            up_v4_bps_min: 0,
            up_v4_bps_p95: 2,
            down_v4_bps_avg: 3,
            down_v4_bps_max: 4,
            down_v4_bps_min: 0,
            down_v4_bps_p95: 4,
            up_v6_bps_avg: 5,
            up_v6_bps_max: 6,
            up_v6_bps_min: 0,
            up_v6_bps_p95: 6,
            down_v6_bps_avg: 7,
            down_v6_bps_max: 8,
            down_v6_bps_min: 0,
            down_v6_bps_p95: 8,
        }
        .with_traffic_type(HistoryTrafficType::Ipv6);
        assert_eq!(b.up_v6_bytes, 30);
        assert_eq!(b.up_v4_bytes, 0);
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::{
        daily_bucket_local, hourly_bucket_local, AggregateBucket, AggregatedBucket, CounterQuad, CurrentHourPointState, HistogramHistory,
    };
    use chrono::{Local, TimeZone};

    fn bucket(start: u64, end: u64) -> AggregatedBucket {
        AggregatedBucket {
            start_ts_ms: start,
            end_ts_ms: end,
            up_v4_bytes: 1,
            down_v4_bytes: 1,
            up_v6_bytes: 1,
            down_v6_bytes: 1,
            up_v4_bps_avg: 1,
            up_v4_bps_max: 1,
            up_v4_bps_min: 1,
            up_v4_bps_p95: 1,
            down_v4_bps_avg: 1,
            down_v4_bps_max: 1,
            down_v4_bps_min: 1,
            down_v4_bps_p95: 1,
            up_v6_bps_avg: 1,
            up_v6_bps_max: 1,
            up_v6_bps_min: 1,
            up_v6_bps_p95: 1,
            down_v6_bps_avg: 1,
            down_v6_bps_max: 1,
            down_v6_bps_min: 1,
            down_v6_bps_p95: 1,
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
    fn restore_current_hour_state_hits_closed_end_boundary() {
        let mut h = HistogramHistory::new();
        let now = Local.with_ymd_and_hms(2024, 1, 15, 10, 30, 0).unwrap().timestamp_millis() as u64;
        let (start, end) = hourly_bucket_local(now);

        h.restore_current_hour_iface_state(
            3,
            start,
            vec![
                CurrentHourPointState {
                    ts_ms: start,
                    metrics: CounterQuad {
                        up_v4_bytes: 10,
                        ..CounterQuad::default()
                    },
                },
                CurrentHourPointState {
                    ts_ms: end,
                    metrics: CounterQuad {
                        up_v4_bytes: 20,
                        ..CounterQuad::default()
                    },
                },
            ],
            now,
        );

        let at_end = h.query_aggregate(3, None, end, end, AggregateBucket::Hourly);
        assert_eq!(at_end.len(), 1);
        assert_eq!(at_end[0].up_v4_bytes, 30);

        let (iface_cum, _) = h.cumulative_from_all();
        assert_eq!(iface_cum.get(&3).map(|x| x.up_v4_bytes), Some(30));
    }

    #[test]
    fn restore_current_hour_state_ignores_non_current_hour() {
        let mut h = HistogramHistory::new();
        let now = Local.with_ymd_and_hms(2024, 1, 15, 11, 5, 0).unwrap().timestamp_millis() as u64;
        let old = Local.with_ymd_and_hms(2024, 1, 15, 10, 5, 0).unwrap().timestamp_millis() as u64;
        let (old_start, old_end) = hourly_bucket_local(old);

        h.restore_current_hour_iface_state(
            7,
            old_start,
            vec![CurrentHourPointState {
                ts_ms: old_end,
                metrics: CounterQuad {
                    up_v4_bytes: 99,
                    ..CounterQuad::default()
                },
            }],
            now,
        );

        let all = h.query_aggregate(7, None, 0, u64::MAX, AggregateBucket::Hourly);
        assert!(all.is_empty());

        let (iface_cum, _) = h.cumulative_from_all();
        assert!(iface_cum.get(&7).is_none());
    }
}
