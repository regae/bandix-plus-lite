use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::Duration;

use chrono::{Local, Timelike, TimeZone};
use aya::Ebpf;
use aya::maps::HashMap as AyaHashMap;
use bandix_plus_common::{DeviceTrafficKey, InterfaceTrafficKey, IpVersion, TrafficDirection, TrafficValue};
use serde::Serialize;

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
    pub cumulative_iface: HashMap<u32, CounterQuad>,
    pub cumulative_device: HashMap<(u32, [u8; 6]), CounterQuad>,
    pub last_snapshot_ms: Option<u64>,
    pub device_registry: DeviceRegistry,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub neighbor_state: Option<String>,
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

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct DeviceSeriesKey {
    ifindex: u32,
    mac: String,
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

#[derive(Debug, Clone, Serialize)]
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
    current_hour_iface: HashMap<u32, (u64, Vec<HistoryPoint>)>,
    current_hour_device: HashMap<DeviceSeriesKey, (u64, Vec<HistoryPoint>)>,
    completed_iface: HashMap<u32, VecDeque<AggregatedBucket>>,
    completed_device: HashMap<DeviceSeriesKey, VecDeque<AggregatedBucket>>,
}

impl HistogramHistory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ingest_snapshot(&mut self, snapshot: &SnapshotData) {
        for iface in &snapshot.interfaces {
            self.ingest_iface(iface.ifindex, snapshot.timestamp_ms, &iface.metrics);
        }
        for dev in &snapshot.devices {
            let key = DeviceSeriesKey {
                ifindex: dev.ifindex,
                mac: dev.mac.clone(),
            };
            self.ingest_device(&key, snapshot.timestamp_ms, &dev.metrics);
        }
    }

    fn ingest_iface(&mut self, ifindex: u32, ts_ms: u64, metrics: &CounterQuad) {
        let (hour_start, _) = hourly_bucket_local(ts_ms);
        let entry = self.current_hour_iface.entry(ifindex).or_insert_with(|| {
            (
                hour_start,
                vec![HistoryPoint {
                    ts_ms,
                    metrics: *metrics,
                    cumulative: CounterQuad::default(),
                }],
            )
        });
        let (cur_hour, points) = entry;
        let (cur_start, _) = hourly_bucket_local(*cur_hour);
        let (new_start, _) = hourly_bucket_local(ts_ms);
        if cur_start == new_start {
            points.push(HistoryPoint {
                ts_ms,
                metrics: *metrics,
                cumulative: CounterQuad::default(),
            });
        } else {
            let bucket = points_to_bucket(cur_start, points);
            self.completed_iface
                .entry(ifindex)
                .or_default()
                .push_back(bucket);
            trim_histogram_completed(self.completed_iface.get_mut(&ifindex).unwrap(), HISTOGRAM_MAX_HOURS);
            *entry = (
                new_start,
                vec![HistoryPoint {
                    ts_ms,
                    metrics: *metrics,
                    cumulative: CounterQuad::default(),
                }],
            );
        }
    }

    fn ingest_device(&mut self, key: &DeviceSeriesKey, ts_ms: u64, metrics: &CounterQuad) {
        let (hour_start, _) = hourly_bucket_local(ts_ms);
        let entry = self.current_hour_device.entry(key.clone()).or_insert_with(|| {
            (
                hour_start,
                vec![HistoryPoint {
                    ts_ms,
                    metrics: *metrics,
                    cumulative: CounterQuad::default(),
                }],
            )
        });
        let (cur_hour, points) = entry;
        let (cur_start, _) = hourly_bucket_local(*cur_hour);
        let (new_start, _) = hourly_bucket_local(ts_ms);
        if cur_start == new_start {
            points.push(HistoryPoint {
                ts_ms,
                metrics: *metrics,
                cumulative: CounterQuad::default(),
            });
        } else {
            let bucket = points_to_bucket(cur_start, points);
            self.completed_device
                .entry(key.clone())
                .or_default()
                .push_back(bucket);
            trim_histogram_completed(
                self.completed_device.get_mut(key).unwrap(),
                HISTOGRAM_MAX_HOURS,
            );
            *entry = (
                new_start,
                vec![HistoryPoint {
                    ts_ms,
                    metrics: *metrics,
                    cumulative: CounterQuad::default(),
                }],
            );
        }
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
        if let Some((cur_start, points)) = self.current_hour_iface.get(&ifindex) {
            let (start, end) = hourly_bucket_local(*cur_start);
            if start <= end_ms && end >= start_ms && !points.is_empty() {
                result.push(points_to_bucket(start, points));
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
        if let Some((cur_start, points)) = self.current_hour_device.get(&key) {
            let (start, end) = hourly_bucket_local(*cur_start);
            if start <= end_ms && end >= start_ms && !points.is_empty() {
                result.push(points_to_bucket(start, points));
            }
        }
        result.sort_by_key(|b| b.start_ts_ms);
        result
    }
}

fn points_to_bucket(start_ms: u64, points: &[HistoryPoint]) -> AggregatedBucket {
    let (_, end_ms) = hourly_bucket_local(start_ms);
    let mut accum = BucketAccum {
        start_ts_ms: start_ms,
        end_ts_ms: end_ms,
        ..Default::default()
    };
    for p in points {
        let m = &p.metrics;
        accum.up_v4_bytes = accum.up_v4_bytes.saturating_add(m.up_v4_bytes);
        accum.down_v4_bytes = accum.down_v4_bytes.saturating_add(m.down_v4_bytes);
        accum.up_v6_bytes = accum.up_v6_bytes.saturating_add(m.up_v6_bytes);
        accum.down_v6_bytes = accum.down_v6_bytes.saturating_add(m.down_v6_bytes);
        accum.up_v4_bps.push(m.up_v4_bps);
        accum.down_v4_bps.push(m.down_v4_bps);
        accum.up_v6_bps.push(m.up_v6_bps);
        accum.down_v6_bps.push(m.down_v6_bps);
    }
    bucket_accum_to_aggregated(accum)
}

fn trim_histogram_completed(queue: &mut VecDeque<AggregatedBucket>, max_hours: usize) {
    while queue.len() > max_hours {
        let _ = queue.pop_front();
    }
}

fn merge_hourly_to_daily(hourly: &[AggregatedBucket]) -> Vec<AggregatedBucket> {
    let mut by_day: HashMap<u64, BucketAccum> = HashMap::new();
    for b in hourly {
        let (day_start, day_end) = daily_bucket_local(b.start_ts_ms);
        let acc = by_day.entry(day_start).or_insert_with(|| BucketAccum {
            start_ts_ms: day_start,
            end_ts_ms: day_end,
            ..Default::default()
        });
        acc.up_v4_bytes = acc.up_v4_bytes.saturating_add(b.up_v4_bytes);
        acc.down_v4_bytes = acc.down_v4_bytes.saturating_add(b.down_v4_bytes);
        acc.up_v6_bytes = acc.up_v6_bytes.saturating_add(b.up_v6_bytes);
        acc.down_v6_bytes = acc.down_v6_bytes.saturating_add(b.down_v6_bytes);
        acc.up_v4_bps.extend([b.up_v4_bps_avg, b.up_v4_bps_max, b.up_v4_bps_min, b.up_v4_bps_p95]);
        acc.down_v4_bps.extend([b.down_v4_bps_avg, b.down_v4_bps_max, b.down_v4_bps_min, b.down_v4_bps_p95]);
        acc.up_v6_bps.extend([b.up_v6_bps_avg, b.up_v6_bps_max, b.up_v6_bps_min, b.up_v6_bps_p95]);
        acc.down_v6_bps.extend([b.down_v6_bps_avg, b.down_v6_bps_max, b.down_v6_bps_min, b.down_v6_bps_p95]);
    }
    let mut result: Vec<AggregatedBucket> = by_day
        .into_values()
        .map(bucket_accum_to_aggregated)
        .collect();
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

#[derive(Default)]
struct BucketAccum {
    start_ts_ms: u64,
    end_ts_ms: u64,
    up_v4_bytes: u64,
    down_v4_bytes: u64,
    up_v6_bytes: u64,
    down_v6_bytes: u64,
    up_v4_bps: Vec<u64>,
    down_v4_bps: Vec<u64>,
    up_v6_bps: Vec<u64>,
    down_v6_bps: Vec<u64>,
}

fn bps_stats(v: &[u64]) -> (u64, u64, u64, u64) {
    if v.is_empty() {
        return (0, 0, 0, 0);
    }
    let mut sorted: Vec<u64> = v.to_vec();
    sorted.sort();
    let avg = (v.iter().sum::<u64>() as f64 / v.len() as f64).round() as u64;
    let min = *sorted.first().unwrap_or(&0);
    let max = *sorted.last().unwrap_or(&0);
    let p95_idx = ((sorted.len() as f64) * 0.95).floor() as usize;
    let p95 = sorted.get(p95_idx.min(sorted.len().saturating_sub(1))).copied().unwrap_or(0);
    (avg, min, max, p95)
}

fn bucket_accum_to_aggregated(a: BucketAccum) -> AggregatedBucket {
    let (up_v4_avg, up_v4_min, up_v4_max, up_v4_p95) = bps_stats(&a.up_v4_bps);
    let (down_v4_avg, down_v4_min, down_v4_max, down_v4_p95) = bps_stats(&a.down_v4_bps);
    let (up_v6_avg, up_v6_min, up_v6_max, up_v6_p95) = bps_stats(&a.up_v6_bps);
    let (down_v6_avg, down_v6_min, down_v6_max, down_v6_p95) = bps_stats(&a.down_v6_bps);
    AggregatedBucket {
        start_ts_ms: a.start_ts_ms,
        end_ts_ms: a.end_ts_ms,
        up_v4_bytes: a.up_v4_bytes,
        down_v4_bytes: a.down_v4_bytes,
        up_v6_bytes: a.up_v6_bytes,
        down_v6_bytes: a.down_v6_bytes,
        up_v4_bps_avg: up_v4_avg,
        up_v4_bps_min: up_v4_min,
        up_v4_bps_max: up_v4_max,
        up_v4_bps_p95: up_v4_p95,
        down_v4_bps_avg: down_v4_avg,
        down_v4_bps_min: down_v4_min,
        down_v4_bps_max: down_v4_max,
        down_v4_bps_p95: down_v4_p95,
        up_v6_bps_avg: up_v6_avg,
        up_v6_bps_min: up_v6_min,
        up_v6_bps_max: up_v6_max,
        up_v6_bps_p95: up_v6_p95,
        down_v6_bps_avg: down_v6_avg,
        down_v6_bps_min: down_v6_min,
        down_v6_bps_max: down_v6_max,
        down_v6_bps_p95: down_v6_p95,
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

/// 从 eBPF 采集一次接口和设备流量快照，计算速率
pub fn collect_snapshot(
    ebpf: &mut Ebpf,
    topology: &TopologySnapshot,
    runtime: &mut MonitorRuntime,
    interval: Duration,
    monitor_ifaces: &[String],
) -> anyhow::Result<SnapshotData> {
    let now_ms = time_utils::now_millis();
    let iface_stats = read_iface_stats(ebpf)?;
    let device_stats = read_device_stats(ebpf)?;
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
        let zone = topology
            .by_ifindex(ifindex)
            .map(|iface| format!("{:?}", iface.zone).to_ascii_lowercase())
            .unwrap_or_else(|| "other".to_string());
        interfaces.push(InterfaceOverviewItem {
            ifindex,
            ifname: iface_name.clone(),
            zone,
            metrics,
            cumulative: *cum,
        });
    }

    let subnet_map = system_utils::list_interface_subnets().unwrap_or_default();
    let filtered_neighbors = system_utils::list_neighbors_filtered(monitor_ifaces, &subnet_map).unwrap_or_default();
    let hostname_by_mac = system_utils::list_hostname_by_mac();

    let mut dev_mac_to_ips: HashMap<(String, [u8; 6]), (Vec<String>, Vec<String>, String)> = HashMap::new();
    for n in filtered_neighbors {
        let entry = dev_mac_to_ips.entry((n.dev, n.mac)).or_insert_with(|| (Vec::new(), Vec::new(), String::new()));
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
        let ipv6: Vec<String> = ipv6_list;

        devices_group.insert(
            (ifindex, mac),
            DeviceListItem {
                ifindex,
                logical_iface: logical_iface.name.clone(),
                subnet,
                ipv4,
                ipv6,
                mac: mac_utils::to_string(&mac),
                hostname: hostname_by_mac.get(&mac).cloned().unwrap_or_else(|| "-".to_string()),
                metrics: CounterQuad::default(),
                cumulative: CounterQuad::default(),
                online: true,
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

    for (key, dev) in devices_group.iter_mut() {
        let cum = runtime.cumulative_device.entry(*key).or_default();
        add_quad(cum, &dev.metrics);
        dev.cumulative = *cum;
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
            neighbor_state: None,
        });
    }

    devices.sort_by(|a, b| {
        a.logical_iface
            .cmp(&b.logical_iface)
            .then(a.ipv4.cmp(&b.ipv4))
            .then(a.ipv6.cmp(&b.ipv6))
    });

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
