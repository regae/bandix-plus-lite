use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::Duration;

use aya::Ebpf;
use aya::maps::HashMap as AyaHashMap;
use bandix_plus_common::{DeviceTrafficKey, InterfaceTrafficKey, IpVersion, TrafficDirection, TrafficValue};
use serde::Serialize;

use crate::topology::TopologySnapshot;
use crate::utils::mac_utils;
use crate::utils::system_utils;
use crate::utils::time_utils;

#[derive(Default)]
pub struct MonitorRuntime {
    prev_iface_bytes: HashMap<InterfaceTrafficKey, u64>,
    prev_device_bytes: HashMap<DeviceTrafficKey, u64>,
    last_snapshot_ms: Option<u64>,
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
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct DeviceSeriesKey {
    ifindex: u32,
    mac: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HistorySample {
    pub ts_ms: u64,
    pub up_bps: u64,
    pub down_bps: u64,
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
            });
            trim_history_queue(queue, self.window_points);
        }
    }

    /// 按逻辑接口查询历史流量采样序列
    pub fn query_iface(&self, ifindex: u32, traffic_type: HistoryTrafficType, direction: HistoryDirection) -> Vec<HistorySample> {
        let Some(series) = self.iface_series.get(&ifindex) else {
            return Vec::new();
        };
        series_to_samples(series, traffic_type, direction)
    }

    /// 按设备 MAC（可选按接口）查询历史流量，支持多接口合并
    pub fn query_device(
        &self,
        ifindex: Option<u32>,
        mac: &str,
        traffic_type: HistoryTrafficType,
        direction: HistoryDirection,
    ) -> Vec<HistorySample> {
        let mut merged: BTreeMap<u64, CounterQuad> = BTreeMap::new();
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
                add_quad(entry, &point.metrics);
            }
        }

        merged
            .into_iter()
            .map(|(ts_ms, metrics)| {
                let (up_bps, down_bps) = project_rates(&metrics, traffic_type, direction);
                HistorySample { ts_ms, up_bps, down_bps }
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

/// 将历史点序列转为按流量类型和方向的采样列表
fn series_to_samples(series: &VecDeque<HistoryPoint>, traffic_type: HistoryTrafficType, direction: HistoryDirection) -> Vec<HistorySample> {
    series
        .iter()
        .map(|point| {
            let (up_bps, down_bps) = project_rates(&point.metrics, traffic_type, direction);
            HistorySample {
                ts_ms: point.ts_ms,
                up_bps,
                down_bps,
            }
        })
        .collect()
}

/// 从四元组指标中提取指定流量类型和方向的上/下行速率 (bps)
fn project_rates(metrics: &CounterQuad, traffic_type: HistoryTrafficType, direction: HistoryDirection) -> (u64, u64) {
    let base_up = match traffic_type {
        HistoryTrafficType::All => metrics.up_v4_bps.saturating_add(metrics.up_v6_bps),
        HistoryTrafficType::Ipv4 => metrics.up_v4_bps,
        HistoryTrafficType::Ipv6 => metrics.up_v6_bps,
    };
    let base_down = match traffic_type {
        HistoryTrafficType::All => metrics.down_v4_bps.saturating_add(metrics.down_v6_bps),
        HistoryTrafficType::Ipv4 => metrics.down_v4_bps,
        HistoryTrafficType::Ipv6 => metrics.down_v6_bps,
    };
    match direction {
        HistoryDirection::Both => (base_up, base_down),
        HistoryDirection::Up => (base_up, 0),
        HistoryDirection::Down => (0, base_down),
    }
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
            fill_quad(k.ip_version, k.direction, &mut metrics, delta, v.bytes, sec);
        }
        let zone = topology
            .by_ifindex(ifindex)
            .map(|iface| format!("{:?}", iface.zone).to_ascii_lowercase())
            .unwrap_or_else(|| "other".to_string());
        interfaces.push(InterfaceOverviewItem {
            ifindex,
            ifname: iface_name.clone(),
            zone,
            metrics,
        });
    }

    let subnet_map = system_utils::list_interface_subnets().unwrap_or_default();
    let filtered_neighbors = system_utils::list_neighbors_filtered(monitor_ifaces, &subnet_map).unwrap_or_default();
    let hostname_by_mac = system_utils::list_hostname_by_mac();

    let mut dev_mac_to_ips: HashMap<(String, [u8; 6]), (Vec<String>, Vec<String>)> = HashMap::new();
    for n in filtered_neighbors {
        let entry = dev_mac_to_ips.entry((n.dev, n.mac)).or_default();
        if n.ip.contains(':') {
            if !entry.1.contains(&n.ip) {
                entry.1.push(n.ip);
            }
        } else {
            if !entry.0.contains(&n.ip) {
                entry.0.push(n.ip);
            }
        }
    }

    let mut devices_group: HashMap<(u32, [u8; 6]), DeviceListItem> = HashMap::new();
    for ((dev, mac), (ipv4_list, ipv6_list)) in dev_mac_to_ips {
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
            },
        );
    }

    for (k, v) in &device_stats {
        if let Some(entry) = devices_group.get_mut(&(k.ifindex, k.mac)) {
            let prev = runtime.prev_device_bytes.get(k).copied().unwrap_or(0);
            let delta = delta_bytes(v.bytes, prev);
            runtime.prev_device_bytes.insert(*k, v.bytes);
            fill_quad(k.ip_version, k.direction, &mut entry.metrics, delta, v.bytes, sec);
        }
    }

    let mut devices: Vec<_> = devices_group.into_values().collect();
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

/// 根据 IP 版本和方向填充四元组对应字段
fn fill_quad(ip_version: u8, direction: u8, quad: &mut CounterQuad, delta_bytes: u64, total_bytes: u64, sec: f64) {
    let delta_bps = ((delta_bytes as f64) * 8.0 / sec).round() as u64;
    match (ip_version, direction) {
        (x, y) if x == IpVersion::V4 as u8 && y == TrafficDirection::Ingress as u8 => {
            quad.up_v4_bps = quad.up_v4_bps.saturating_add(delta_bps);
            quad.up_v4_bytes = quad.up_v4_bytes.saturating_add(total_bytes);
        }
        (x, y) if x == IpVersion::V4 as u8 && y == TrafficDirection::Egress as u8 => {
            quad.down_v4_bps = quad.down_v4_bps.saturating_add(delta_bps);
            quad.down_v4_bytes = quad.down_v4_bytes.saturating_add(total_bytes);
        }
        (x, y) if x == IpVersion::V6 as u8 && y == TrafficDirection::Ingress as u8 => {
            quad.up_v6_bps = quad.up_v6_bps.saturating_add(delta_bps);
            quad.up_v6_bytes = quad.up_v6_bytes.saturating_add(total_bytes);
        }
        (x, y) if x == IpVersion::V6 as u8 && y == TrafficDirection::Egress as u8 => {
            quad.down_v6_bps = quad.down_v6_bps.saturating_add(delta_bps);
            quad.down_v6_bytes = quad.down_v6_bytes.saturating_add(total_bytes);
        }
        _ => {}
    }
}
