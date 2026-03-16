use std::collections::{HashMap, HashSet};

use aya::maps::HashMap as AyaHashMap;
use aya::Ebpf;
use bandix_plus_common::{
    DeviceGlobalLimitKey, DeviceIfaceLimitKey, DeviceTrafficKey, IfaceLimitKey, RateLimitValue, TrafficValue,
};
use chrono::{Datelike, Local, TimeZone, Timelike};
use serde::{Deserialize, Serialize};

use uuid::Uuid;

use crate::topology::TopologySnapshot;
use crate::utils::mac_utils;

#[derive(Debug, Clone)]
pub struct ParsedPolicy {
    pub device_static: HashMap<[u8; 6], RateLimitValue>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyItem {
    pub scope: String,
    pub iface: Option<String>,
    pub mac: Option<String>,
    pub down_v4_kbps: u64,
    pub down_v6_kbps: u64,
    pub up_v4_kbps: u64,
    pub up_v6_kbps: u64,
    pub extra: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSlotApi {
    pub start: String,
    pub end: String,
    pub days: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledRuleApi {
    pub id: String,
    pub mac: String,
    pub time_slot: TimeSlotApi,
    pub down_v4_kbps: u64,
    pub down_v6_kbps: u64,
    pub up_v4_kbps: u64,
    pub up_v6_kbps: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateScheduledRuleRequest {
    pub mac: String,
    pub time_slot: TimeSlotApi,
    pub down_v4_kbps: u64,
    pub down_v6_kbps: u64,
    pub up_v4_kbps: u64,
    pub up_v6_kbps: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateScheduledRuleRequest {
    pub mac: String,
    pub time_slot: TimeSlotApi,
    pub down_v4_kbps: u64,
    pub down_v6_kbps: u64,
    pub up_v4_kbps: u64,
    pub up_v6_kbps: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceRateLimitApi {
    pub iface: String,
    pub down_v4_kbps: u64,
    pub down_v6_kbps: u64,
    pub up_v4_kbps: u64,
    pub up_v6_kbps: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SetInterfaceRateLimitRequest {
    pub iface: String,
    pub down_v4_kbps: u64,
    pub down_v6_kbps: u64,
    pub up_v4_kbps: u64,
    pub up_v6_kbps: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuestWhitelistEntryApi {
    pub iface: String,
    pub mac: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GuestWhitelistEntryRequest {
    pub iface: String,
    pub mac: String,
}

#[derive(Debug, Clone)]
struct ScheduledRule {
    id: String,
    mac: [u8; 6],
    start_minute: u16,
    end_minute: u16,
    days_mask: u8,
    down_v4_bps: u64,
    down_v6_bps: u64,
    up_v4_bps: u64,
    up_v6_bps: u64,
}

#[derive(Debug, Clone)]
pub struct PolicyRuntime {
    pub base: ParsedPolicy,
    iface_limits: HashMap<String, RateLimitValue>,
    guest_default_limits: HashMap<String, RateLimitValue>,
    guest_whitelist: HashSet<(String, [u8; 6])>,
    scheduled_rules: Vec<ScheduledRule>,
}

pub fn parse_policy() -> ParsedPolicy {
    ParsedPolicy {
        device_static: HashMap::new(),
    }
}

pub fn init_runtime(base: ParsedPolicy) -> PolicyRuntime {
    PolicyRuntime {
        base,
        iface_limits: HashMap::new(),
        guest_default_limits: HashMap::new(),
        guest_whitelist: HashSet::new(),
        scheduled_rules: Vec::new(),
    }
}

pub fn log_policy(policy: &ParsedPolicy) {
    log::info!("policy.startup.begin");
    if policy.device_static.is_empty() {
        log::info!("policy.startup.empty");
        return;
    }
    for (mac, limit) in &policy.device_static {
        log::info!(
            "policy.startup.device mac={} down(v4/v6)_kbps={}/{} up(v4/v6)_kbps={}/{}",
            mac_utils::to_string(mac),
            bytes_to_kbps(limit.down_v4_bps),
            bytes_to_kbps(limit.down_v6_bps),
            bytes_to_kbps(limit.up_v4_bps),
            bytes_to_kbps(limit.up_v6_bps)
        );
    }
}

pub fn policy_items(runtime: &PolicyRuntime) -> Vec<PolicyItem> {
    let mut rows = Vec::new();

    for (mac, limit) in &runtime.base.device_static {
        rows.push(PolicyItem {
            scope: "device".to_string(),
            iface: None,
            mac: Some(mac_utils::to_string(mac)),
            down_v4_kbps: bytes_to_kbps(limit.down_v4_bps),
            down_v6_kbps: bytes_to_kbps(limit.down_v6_bps),
            up_v4_kbps: bytes_to_kbps(limit.up_v4_bps),
            up_v6_kbps: bytes_to_kbps(limit.up_v6_bps),
            extra: Some("static".to_string()),
        });
    }
    for rule in &runtime.scheduled_rules {
        rows.push(PolicyItem {
            scope: "device".to_string(),
            iface: None,
            mac: Some(mac_utils::to_string(&rule.mac)),
            down_v4_kbps: bytes_to_kbps(rule.down_v4_bps),
            down_v6_kbps: bytes_to_kbps(rule.down_v6_bps),
            up_v4_kbps: bytes_to_kbps(rule.up_v4_bps),
            up_v6_kbps: bytes_to_kbps(rule.up_v6_bps),
            extra: Some(format!(
                "scheduled id={} {}-{}",
                rule.id,
                minute_to_hhmm(rule.start_minute),
                minute_to_hhmm(rule.end_minute)
            )),
        });
    }
    for (iface, limit) in &runtime.iface_limits {
        rows.push(PolicyItem {
            scope: "iface".to_string(),
            iface: Some(iface.clone()),
            mac: None,
            down_v4_kbps: bytes_to_kbps(limit.down_v4_bps),
            down_v6_kbps: bytes_to_kbps(limit.down_v6_bps),
            up_v4_kbps: bytes_to_kbps(limit.up_v4_bps),
            up_v6_kbps: bytes_to_kbps(limit.up_v6_bps),
            extra: None,
        });
    }
    for (iface, limit) in &runtime.guest_default_limits {
        rows.push(PolicyItem {
            scope: "guest-default".to_string(),
            iface: Some(iface.clone()),
            mac: None,
            down_v4_kbps: bytes_to_kbps(limit.down_v4_bps),
            down_v6_kbps: bytes_to_kbps(limit.down_v6_bps),
            up_v4_kbps: bytes_to_kbps(limit.up_v4_bps),
            up_v6_kbps: bytes_to_kbps(limit.up_v6_bps),
            extra: None,
        });
    }

    rows
}

pub fn get_scheduled_rules(runtime: &PolicyRuntime) -> Vec<ScheduledRuleApi> {
    runtime.scheduled_rules.iter().map(scheduled_rule_to_api).collect()
}

pub fn create_scheduled_rule(runtime: &mut PolicyRuntime, req: CreateScheduledRuleRequest) -> anyhow::Result<ScheduledRuleApi> {
    let mac = mac_utils::from_str(&req.mac)?;
    let (start_minute, end_minute, days_mask) = parse_time_slot(&req.time_slot)?;
    let rule = ScheduledRule {
        id: Uuid::new_v4().to_string(),
        mac,
        start_minute,
        end_minute,
        days_mask,
        down_v4_bps: kbps_to_bps(req.down_v4_kbps),
        down_v6_bps: kbps_to_bps(req.down_v6_kbps),
        up_v4_bps: kbps_to_bps(req.up_v4_kbps),
        up_v6_bps: kbps_to_bps(req.up_v6_kbps),
    };
    let api = scheduled_rule_to_api(&rule);
    runtime.scheduled_rules.push(rule);
    Ok(api)
}

pub fn update_scheduled_rule(runtime: &mut PolicyRuntime, id: &str, req: UpdateScheduledRuleRequest) -> anyhow::Result<ScheduledRuleApi> {
    let mac = mac_utils::from_str(&req.mac)?;
    let (start_minute, end_minute, days_mask) = parse_time_slot(&req.time_slot)?;
    let rule = runtime
        .scheduled_rules
        .iter_mut()
        .find(|r| r.id == id)
        .ok_or_else(|| anyhow::anyhow!("scheduled rule not found: {}", id))?;
    rule.mac = mac;
    rule.start_minute = start_minute;
    rule.end_minute = end_minute;
    rule.days_mask = days_mask;
    rule.down_v4_bps = kbps_to_bps(req.down_v4_kbps);
    rule.down_v6_bps = kbps_to_bps(req.down_v6_kbps);
    rule.up_v4_bps = kbps_to_bps(req.up_v4_kbps);
    rule.up_v6_bps = kbps_to_bps(req.up_v6_kbps);
    Ok(scheduled_rule_to_api(rule))
}

pub fn delete_scheduled_rule(runtime: &mut PolicyRuntime, id: &str) -> anyhow::Result<()> {
    let before = runtime.scheduled_rules.len();
    runtime.scheduled_rules.retain(|r| r.id != id);
    if runtime.scheduled_rules.len() == before {
        anyhow::bail!("scheduled rule not found: {}", id);
    }
    Ok(())
}

pub fn get_iface_limits(runtime: &PolicyRuntime) -> Vec<InterfaceRateLimitApi> {
    let mut rows: Vec<_> = runtime
        .iface_limits
        .iter()
        .map(|(iface, limit)| InterfaceRateLimitApi {
            iface: iface.clone(),
            down_v4_kbps: bytes_to_kbps(limit.down_v4_bps),
            down_v6_kbps: bytes_to_kbps(limit.down_v6_bps),
            up_v4_kbps: bytes_to_kbps(limit.up_v4_bps),
            up_v6_kbps: bytes_to_kbps(limit.up_v6_bps),
        })
        .collect();
    rows.sort_by(|a, b| a.iface.cmp(&b.iface));
    rows
}

pub fn set_iface_limit(runtime: &mut PolicyRuntime, req: SetInterfaceRateLimitRequest, topology: &TopologySnapshot) -> anyhow::Result<()> {
    let iface = resolve_iface_name(&req.iface, topology)?;
    runtime.iface_limits.insert(
        iface,
        RateLimitValue {
            down_v4_bps: kbps_to_bps(req.down_v4_kbps),
            down_v6_bps: kbps_to_bps(req.down_v6_kbps),
            up_v4_bps: kbps_to_bps(req.up_v4_kbps),
            up_v6_bps: kbps_to_bps(req.up_v6_kbps),
        },
    );
    Ok(())
}

pub fn delete_iface_limit(runtime: &mut PolicyRuntime, iface: &str) -> anyhow::Result<()> {
    if runtime.iface_limits.remove(iface).is_none() {
        anyhow::bail!("iface limit for {} not found", iface);
    }
    Ok(())
}

pub fn get_guest_defaults(runtime: &PolicyRuntime) -> Vec<InterfaceRateLimitApi> {
    let mut rows: Vec<_> = runtime
        .guest_default_limits
        .iter()
        .map(|(iface, limit)| InterfaceRateLimitApi {
            iface: iface.clone(),
            down_v4_kbps: bytes_to_kbps(limit.down_v4_bps),
            down_v6_kbps: bytes_to_kbps(limit.down_v6_bps),
            up_v4_kbps: bytes_to_kbps(limit.up_v4_bps),
            up_v6_kbps: bytes_to_kbps(limit.up_v6_bps),
        })
        .collect();
    rows.sort_by(|a, b| a.iface.cmp(&b.iface));
    rows
}

pub fn set_guest_default(runtime: &mut PolicyRuntime, req: SetInterfaceRateLimitRequest, topology: &TopologySnapshot) -> anyhow::Result<()> {
    let iface = resolve_iface_name(&req.iface, topology)?;
    runtime.guest_default_limits.insert(
        iface,
        RateLimitValue {
            down_v4_bps: kbps_to_bps(req.down_v4_kbps),
            down_v6_bps: kbps_to_bps(req.down_v6_kbps),
            up_v4_bps: kbps_to_bps(req.up_v4_kbps),
            up_v6_bps: kbps_to_bps(req.up_v6_kbps),
        },
    );
    Ok(())
}

pub fn delete_guest_default(runtime: &mut PolicyRuntime, iface: &str) -> anyhow::Result<()> {
    if runtime.guest_default_limits.remove(iface).is_none() {
        anyhow::bail!("guest default for {} not found", iface);
    }
    runtime.guest_whitelist.retain(|(x, _)| x != iface);
    Ok(())
}

pub fn get_guest_whitelist(runtime: &PolicyRuntime) -> Vec<GuestWhitelistEntryApi> {
    let mut rows: Vec<_> = runtime
        .guest_whitelist
        .iter()
        .map(|(iface, mac)| GuestWhitelistEntryApi {
            iface: iface.clone(),
            mac: mac_utils::to_string(mac),
        })
        .collect();
    rows.sort_by(|a, b| a.iface.cmp(&b.iface).then(a.mac.cmp(&b.mac)));
    rows
}

pub fn add_guest_whitelist(runtime: &mut PolicyRuntime, req: GuestWhitelistEntryRequest, topology: &TopologySnapshot) -> anyhow::Result<()> {
    let iface = resolve_iface_name(&req.iface, topology)?;
    let mac = mac_utils::from_str(&req.mac)?;
    runtime.guest_whitelist.insert((iface, mac));
    Ok(())
}

pub fn remove_guest_whitelist(runtime: &mut PolicyRuntime, req: GuestWhitelistEntryRequest) -> anyhow::Result<()> {
    let mac = mac_utils::from_str(&req.mac)?;
    if !runtime.guest_whitelist.remove(&(req.iface, mac)) {
        anyhow::bail!("guest whitelist item not found");
    }
    Ok(())
}

pub(crate) fn compute_desired_limits(
    runtime: &PolicyRuntime,
    observed_pairs: &[(u32, [u8; 6])],
    topology: &TopologySnapshot,
    now_ms: u64,
) -> (
    HashMap<[u8; 6], RateLimitValue>,
    HashMap<(u32, [u8; 6]), RateLimitValue>,
    HashMap<u32, RateLimitValue>,
) {
    let mut desired_device = runtime.base.device_static.clone();
    let mut desired_iface_device: HashMap<(u32, [u8; 6]), RateLimitValue> = HashMap::new();
    let mut desired_iface: HashMap<u32, RateLimitValue> = HashMap::new();

    let mut ifindex_to_name: HashMap<u32, String> = HashMap::new();
    let mut iface_name_to_ifindex: HashMap<String, u32> = HashMap::new();
    for iface in topology.interfaces() {
        ifindex_to_name.insert(iface.ifindex, iface.name.clone());
        iface_name_to_ifindex.entry(iface.name.clone()).or_insert(iface.ifindex);
    }

    for (iface_name, limit) in &runtime.iface_limits {
        if let Some(ifindex) = iface_name_to_ifindex.get(iface_name) {
            merge_limit(&mut desired_iface, *ifindex, *limit);
        }
    }

    for rule in &runtime.scheduled_rules {
        if !is_rule_active(rule, now_ms) {
            continue;
        }
        let limit = RateLimitValue {
            down_v4_bps: rule.down_v4_bps,
            down_v6_bps: rule.down_v6_bps,
            up_v4_bps: rule.up_v4_bps,
            up_v6_bps: rule.up_v6_bps,
        };
        merge_limit(&mut desired_device, rule.mac, limit);
    }

    for (ifindex, mac) in observed_pairs {
        let Some(iface_name) = ifindex_to_name.get(ifindex) else {
            continue;
        };
        let Some(limit) = runtime.guest_default_limits.get(iface_name) else {
            continue;
        };
        if runtime.guest_whitelist.contains(&(iface_name.clone(), *mac)) {
            continue;
        }
        merge_limit(&mut desired_iface_device, (*ifindex, *mac), *limit);
    }

    (desired_device, desired_iface_device, desired_iface)
}

pub fn apply_runtime_policy(
    ebpf: &mut Ebpf,
    runtime: &PolicyRuntime,
    observed_pairs: &[(u32, [u8; 6])],
    topology: &TopologySnapshot,
    now_ms: u64,
) -> anyhow::Result<()> {
    let (desired_device, desired_iface_device, desired_iface) =
        compute_desired_limits(runtime, observed_pairs, topology, now_ms);

    sync_device_map(ebpf, &desired_device)?;
    sync_iface_device_map(ebpf, &desired_iface_device)?;
    sync_iface_map(ebpf, &desired_iface)?;
    Ok(())
}

pub fn collect_observed_pairs(ebpf: &mut Ebpf) -> anyhow::Result<Vec<(u32, [u8; 6])>> {
    let map = ebpf
        .map_mut("DEVICE_TRAFFIC_STATS")
        .ok_or_else(|| anyhow::anyhow!("DEVICE_TRAFFIC_STATS map not found"))?;
    let map: AyaHashMap<_, DeviceTrafficKey, TrafficValue> = AyaHashMap::try_from(map)?;
    let mut seen = HashSet::new();
    for entry in map.iter() {
        let (k, _) = entry?;
        seen.insert((k.ifindex, k.mac));
    }
    Ok(seen.into_iter().collect())
}

fn sync_device_map(ebpf: &mut Ebpf, desired: &HashMap<[u8; 6], RateLimitValue>) -> anyhow::Result<()> {
    let map = ebpf
        .map_mut("DEVICE_LIMIT_GLOBAL")
        .ok_or_else(|| anyhow::anyhow!("DEVICE_LIMIT_GLOBAL map not found"))?;
    let mut map: AyaHashMap<_, DeviceGlobalLimitKey, RateLimitValue> = AyaHashMap::try_from(map)?;
    let mut existing = HashSet::new();
    for entry in map.iter() {
        let (k, _) = entry?;
        existing.insert(k.mac);
    }
    for (mac, limit) in desired {
        let key = DeviceGlobalLimitKey { mac: *mac, _pad: [0; 2] };
        map.insert(key, *limit, 0)?;
        existing.remove(mac);
    }
    for mac in existing {
        let _ = map.remove(&DeviceGlobalLimitKey { mac, _pad: [0; 2] });
    }
    Ok(())
}

fn sync_iface_device_map(ebpf: &mut Ebpf, desired: &HashMap<(u32, [u8; 6]), RateLimitValue>) -> anyhow::Result<()> {
    let map = ebpf
        .map_mut("DEVICE_LIMIT_IFACE")
        .ok_or_else(|| anyhow::anyhow!("DEVICE_LIMIT_IFACE map not found"))?;
    let mut map: AyaHashMap<_, DeviceIfaceLimitKey, RateLimitValue> = AyaHashMap::try_from(map)?;
    let mut existing = HashSet::new();
    for entry in map.iter() {
        let (k, _) = entry?;
        existing.insert((k.ifindex, k.mac));
    }
    for ((ifindex, mac), limit) in desired {
        let key = DeviceIfaceLimitKey {
            ifindex: *ifindex,
            mac: *mac,
            _pad: [0; 2],
        };
        map.insert(key, *limit, 0)?;
        existing.remove(&(*ifindex, *mac));
    }
    for (ifindex, mac) in existing {
        let _ = map.remove(&DeviceIfaceLimitKey {
            ifindex,
            mac,
            _pad: [0; 2],
        });
    }
    Ok(())
}

fn sync_iface_map(ebpf: &mut Ebpf, desired: &HashMap<u32, RateLimitValue>) -> anyhow::Result<()> {
    let map = ebpf
        .map_mut("IFACE_LIMIT")
        .ok_or_else(|| anyhow::anyhow!("IFACE_LIMIT map not found"))?;
    let mut map: AyaHashMap<_, IfaceLimitKey, RateLimitValue> = AyaHashMap::try_from(map)?;
    let mut existing = HashSet::new();
    for entry in map.iter() {
        let (k, _) = entry?;
        existing.insert(k.ifindex);
    }
    for (ifindex, limit) in desired {
        map.insert(IfaceLimitKey { ifindex: *ifindex }, *limit, 0)?;
        existing.remove(ifindex);
    }
    for ifindex in existing {
        let _ = map.remove(&IfaceLimitKey { ifindex });
    }
    Ok(())
}

pub(crate) fn merge_limit<K: std::cmp::Eq + std::hash::Hash + Copy>(map: &mut HashMap<K, RateLimitValue>, key: K, incoming: RateLimitValue) {
    let merged = if let Some(old) = map.get(&key).copied() {
        RateLimitValue {
            down_v4_bps: stricter_limit(old.down_v4_bps, incoming.down_v4_bps),
            down_v6_bps: stricter_limit(old.down_v6_bps, incoming.down_v6_bps),
            up_v4_bps: stricter_limit(old.up_v4_bps, incoming.up_v4_bps),
            up_v6_bps: stricter_limit(old.up_v6_bps, incoming.up_v6_bps),
        }
    } else {
        incoming
    };
    map.insert(key, merged);
}

pub(crate) fn stricter_limit(a: u64, b: u64) -> u64 {
    if a == 0 {
        return b;
    }
    if b == 0 {
        return a;
    }
    a.min(b)
}

fn is_rule_active(rule: &ScheduledRule, now_ms: u64) -> bool {
    let now = match Local.timestamp_millis_opt(now_ms as i64) {
        chrono::LocalResult::Single(dt) => dt,
        _ => return false,
    };
    let minute_of_day = (now.hour() as u16) * 60 + now.minute() as u16;
    let weekday = now.weekday().num_days_from_monday() as u8 + 1;

    if rule.start_minute <= rule.end_minute {
        let day_bit = 1u8 << (weekday - 1);
        if (rule.days_mask & day_bit) == 0 {
            return false;
        }
        minute_of_day >= rule.start_minute && minute_of_day <= rule.end_minute
    } else if minute_of_day >= rule.start_minute {
        let day_bit = 1u8 << (weekday - 1);
        (rule.days_mask & day_bit) != 0
    } else if minute_of_day <= rule.end_minute {
        let prev_weekday = if weekday == 1 { 7 } else { weekday - 1 };
        let day_bit = 1u8 << (prev_weekday - 1);
        (rule.days_mask & day_bit) != 0
    } else {
        false
    }
}

fn scheduled_rule_to_api(rule: &ScheduledRule) -> ScheduledRuleApi {
    ScheduledRuleApi {
        id: rule.id.clone(),
        mac: mac_utils::to_string(&rule.mac),
        time_slot: TimeSlotApi {
            start: minute_to_hhmm(rule.start_minute),
            end: minute_to_hhmm(rule.end_minute),
            days: days_mask_to_vec(rule.days_mask),
        },
        down_v4_kbps: bytes_to_kbps(rule.down_v4_bps),
        down_v6_kbps: bytes_to_kbps(rule.down_v6_bps),
        up_v4_kbps: bytes_to_kbps(rule.up_v4_bps),
        up_v6_kbps: bytes_to_kbps(rule.up_v6_bps),
    }
}

fn parse_time_slot(slot: &TimeSlotApi) -> anyhow::Result<(u16, u16, u8)> {
    let start = parse_hhmm(&slot.start)?;
    let end = parse_hhmm(&slot.end)?;
    let mut mask = 0u8;
    for d in &slot.days {
        if *d < 1 || *d > 7 {
            anyhow::bail!("day must be 1..7");
        }
        mask |= 1u8 << (*d - 1);
    }
    if mask == 0 {
        anyhow::bail!("time_slot.days cannot be empty");
    }
    Ok((start, end, mask))
}

fn resolve_iface_name(iface: &str, topology: &TopologySnapshot) -> anyhow::Result<String> {
    let found = topology.interfaces().into_iter().find(|x| x.name == iface);
    let iface = found
        .map(|x| x.name.clone())
        .ok_or_else(|| anyhow::anyhow!("interface {} not found", iface))?;
    Ok(iface)
}

fn parse_hhmm(s: &str) -> anyhow::Result<u16> {
    let (h, m) = s
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("time format must be HH:MM"))?;
    let h = h.parse::<u16>()?;
    let m = m.parse::<u16>()?;
    if h > 23 || m > 59 {
        anyhow::bail!("invalid time {}", s);
    }
    Ok(h * 60 + m)
}

fn minute_to_hhmm(minute: u16) -> String {
    let h = minute / 60;
    let m = minute % 60;
    format!("{:02}:{:02}", h, m)
}

fn days_mask_to_vec(mask: u8) -> Vec<u8> {
    let mut out = Vec::new();
    for d in 1..=7 {
        if (mask & (1u8 << (d - 1))) != 0 {
            out.push(d);
        }
    }
    out
}

fn kbps_to_bps(kbps: u64) -> u64 {
    kbps.saturating_mul(1000) / 8
}

fn bytes_to_kbps(bytes_per_sec: u64) -> u64 {
    bytes_per_sec.saturating_mul(8) / 1000
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topology::{Interface, InterfaceZone, TopologySnapshot};
    use crate::utils::system_utils::InterfaceRole;

    fn rate_limit(down_v4: u64, down_v6: u64, up_v4: u64, up_v6: u64) -> RateLimitValue {
        RateLimitValue {
            down_v4_bps: down_v4,
            down_v6_bps: down_v6,
            up_v4_bps: up_v4,
            up_v6_bps: up_v6,
        }
    }

    #[test]
    fn stricter_limit_a_zero() {
        assert_eq!(stricter_limit(0, 100), 100);
    }

    #[test]
    fn stricter_limit_b_zero() {
        assert_eq!(stricter_limit(100, 0), 100);
    }

    #[test]
    fn stricter_limit_both_nonzero() {
        assert_eq!(stricter_limit(100, 50), 50);
        assert_eq!(stricter_limit(50, 100), 50);
    }

    #[test]
    fn merge_limit_first_insert() {
        let mut map: HashMap<[u8; 6], RateLimitValue> = HashMap::new();
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        merge_limit(&mut map, mac, rate_limit(100, 100, 100, 100));
        assert_eq!(map.get(&mac).unwrap().down_v4_bps, 100);
    }

    #[test]
    fn merge_limit_stricter_wins() {
        let mut map: HashMap<[u8; 6], RateLimitValue> = HashMap::new();
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        merge_limit(&mut map, mac, rate_limit(100, 100, 100, 100));
        merge_limit(&mut map, mac, rate_limit(50, 50, 50, 50));
        let v = map.get(&mac).unwrap();
        assert_eq!(v.down_v4_bps, 50);
        assert_eq!(v.up_v4_bps, 50);
    }

    #[test]
    fn merge_limit_unlimited_plus_limited() {
        let mut map: HashMap<[u8; 6], RateLimitValue> = HashMap::new();
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        merge_limit(&mut map, mac, rate_limit(0, 0, 0, 0));
        merge_limit(&mut map, mac, rate_limit(50, 50, 50, 50));
        let v = map.get(&mac).unwrap();
        assert_eq!(v.down_v4_bps, 50);
        assert_eq!(v.up_v4_bps, 50);
    }

    fn mock_topology() -> TopologySnapshot {
        TopologySnapshot::from_interfaces(vec![Interface {
            ifindex: 1,
            name: "eth0".to_string(),
            role: InterfaceRole::Ethernet,
            zone: InterfaceZone::Other,
            parent_ifindex: None,
            ipv4_cidrs: vec![],
            ipv6_cidrs: vec![],
        }])
    }

    fn topology_with_guest() -> TopologySnapshot {
        TopologySnapshot::from_interfaces(vec![
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
        ])
    }

    fn monday_noon_2024_ms() -> u64 {
        chrono::Local
            .with_ymd_and_hms(2024, 1, 15, 12, 0, 0)
            .unwrap()
            .timestamp_millis() as u64
    }

    #[test]
    fn compute_desired_device_static_only() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let mut base = ParsedPolicy {
            device_static: HashMap::new(),
        };
        base.device_static.insert(mac, rate_limit(12500, 6250, 10000, 5000));
        let rt = init_runtime(base);
        let (dev, iface_dev, iface) =
            compute_desired_limits(&rt, &[], &mock_topology(), monday_noon_2024_ms());
        assert_eq!(dev.get(&mac).unwrap().down_v4_bps, 12500);
        assert!(iface_dev.is_empty());
        assert!(iface.is_empty());
    }

    #[test]
    fn compute_desired_device_static_plus_scheduled_in_slot() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let mut base = ParsedPolicy {
            device_static: HashMap::new(),
        };
        base.device_static.insert(mac, rate_limit(12500, 12500, 12500, 12500));
        let mut rt = init_runtime(base);
        create_scheduled_rule(
            &mut rt,
            CreateScheduledRuleRequest {
                mac: "aa:bb:cc:dd:ee:ff".to_string(),
                time_slot: TimeSlotApi {
                    start: "00:00".to_string(),
                    end: "23:59".to_string(),
                    days: vec![1, 2, 3, 4, 5, 6, 7],
                },
                down_v4_kbps: 50,
                down_v6_kbps: 50,
                up_v4_kbps: 50,
                up_v6_kbps: 50,
            },
        )
        .unwrap();
        let (dev, _, _) = compute_desired_limits(&rt, &[], &mock_topology(), monday_noon_2024_ms());
        assert_eq!(dev.get(&mac).unwrap().down_v4_bps, 6250);
    }

    #[test]
    fn compute_desired_device_static_plus_scheduled_out_of_slot() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let mut base = ParsedPolicy {
            device_static: HashMap::new(),
        };
        base.device_static.insert(mac, rate_limit(12500, 12500, 12500, 12500));
        let mut rt = init_runtime(base);
        create_scheduled_rule(
            &mut rt,
            CreateScheduledRuleRequest {
                mac: "aa:bb:cc:dd:ee:ff".to_string(),
                time_slot: TimeSlotApi {
                    start: "09:00".to_string(),
                    end: "18:00".to_string(),
                    days: vec![1, 2, 3, 4, 5],
                },
                down_v4_kbps: 50,
                down_v6_kbps: 50,
                up_v4_kbps: 50,
                up_v6_kbps: 50,
            },
        )
        .unwrap();
        let evening_ms = chrono::Local
            .with_ymd_and_hms(2024, 1, 15, 20, 0, 0)
            .unwrap()
            .timestamp_millis() as u64;
        let (dev, _, _) = compute_desired_limits(&rt, &[], &mock_topology(), evening_ms);
        assert_eq!(dev.get(&mac).unwrap().down_v4_bps, 12500);
    }

    #[test]
    fn compute_desired_multi_limit_overlay() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let mut base = ParsedPolicy {
            device_static: HashMap::new(),
        };
        base.device_static.insert(mac, rate_limit(12500, 12500, 12500, 12500));
        let mut rt = init_runtime(base);
        create_scheduled_rule(
            &mut rt,
            CreateScheduledRuleRequest {
                mac: "aa:bb:cc:dd:ee:ff".to_string(),
                time_slot: TimeSlotApi {
                    start: "00:00".to_string(),
                    end: "23:59".to_string(),
                    days: vec![1, 2, 3, 4, 5, 6, 7],
                },
                down_v4_kbps: 60,
                down_v6_kbps: 60,
                up_v4_kbps: 60,
                up_v6_kbps: 60,
            },
        )
        .unwrap();
        let topo = topology_with_guest();
        set_guest_default(
            &mut rt,
            SetInterfaceRateLimitRequest {
                iface: "guest0".to_string(),
                down_v4_kbps: 40,
                down_v6_kbps: 40,
                up_v4_kbps: 40,
                up_v6_kbps: 40,
            },
            &topo,
        )
        .unwrap();
        let observed = [(2u32, mac)];
        let (dev, iface_dev, _) =
            compute_desired_limits(&rt, &observed, &topo, monday_noon_2024_ms());
        assert_eq!(dev.get(&mac).unwrap().down_v4_bps, 7500);
        assert_eq!(iface_dev.get(&(2, mac)).unwrap().down_v4_bps, 5000);
    }

    #[test]
    fn compute_desired_iface_limit() {
        let mut rt = init_runtime(parse_policy());
        let topo = mock_topology();
        set_iface_limit(
            &mut rt,
            SetInterfaceRateLimitRequest {
                iface: "eth0".to_string(),
                down_v4_kbps: 200,
                down_v6_kbps: 100,
                up_v4_kbps: 160,
                up_v6_kbps: 80,
            },
            &topo,
        )
        .unwrap();
        let (_, _, iface) = compute_desired_limits(&rt, &[], &topo, monday_noon_2024_ms());
        assert_eq!(iface.get(&1).unwrap().down_v4_bps, 25000);
    }

    #[test]
    fn compute_desired_guest_default() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let mut rt = init_runtime(parse_policy());
        let topo = topology_with_guest();
        set_guest_default(
            &mut rt,
            SetInterfaceRateLimitRequest {
                iface: "guest0".to_string(),
                down_v4_kbps: 50,
                down_v6_kbps: 50,
                up_v4_kbps: 50,
                up_v6_kbps: 50,
            },
            &topo,
        )
        .unwrap();
        let observed = [(2u32, mac)];
        let (_, iface_dev, _) = compute_desired_limits(&rt, &observed, &topo, monday_noon_2024_ms());
        assert_eq!(iface_dev.get(&(2, mac)).unwrap().down_v4_bps, 6250);
    }

    #[test]
    fn compute_desired_guest_whitelist_skips_limit() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let mut rt = init_runtime(parse_policy());
        let topo = topology_with_guest();
        set_guest_default(
            &mut rt,
            SetInterfaceRateLimitRequest {
                iface: "guest0".to_string(),
                down_v4_kbps: 50,
                down_v6_kbps: 50,
                up_v4_kbps: 50,
                up_v6_kbps: 50,
            },
            &topo,
        )
        .unwrap();
        add_guest_whitelist(
            &mut rt,
            GuestWhitelistEntryRequest {
                iface: "guest0".to_string(),
                mac: "aa:bb:cc:dd:ee:ff".to_string(),
            },
            &topo,
        )
        .unwrap();
        let observed = [(2u32, mac)];
        let (_, iface_dev, _) = compute_desired_limits(&rt, &observed, &topo, monday_noon_2024_ms());
        assert!(iface_dev.is_empty());
    }

    #[test]
    fn create_scheduled_rule_valid() {
        let mut rt = init_runtime(parse_policy());
        let req = CreateScheduledRuleRequest {
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            time_slot: TimeSlotApi {
                start: "09:00".to_string(),
                end: "18:00".to_string(),
                days: vec![1, 2, 3, 4, 5],
            },
            down_v4_kbps: 1000,
            down_v6_kbps: 500,
            up_v4_kbps: 800,
            up_v6_kbps: 400,
        };
        let api = create_scheduled_rule(&mut rt, req).unwrap();
        assert_eq!(api.mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(api.time_slot.start, "09:00");
        assert_eq!(api.time_slot.end, "18:00");
        assert_eq!(rt.scheduled_rules.len(), 1);
    }

    #[test]
    fn create_scheduled_rule_invalid_time() {
        let mut rt = init_runtime(parse_policy());
        let req = CreateScheduledRuleRequest {
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            time_slot: TimeSlotApi {
                start: "25:00".to_string(),
                end: "18:00".to_string(),
                days: vec![1],
            },
            down_v4_kbps: 1000,
            down_v6_kbps: 0,
            up_v4_kbps: 800,
            up_v6_kbps: 0,
        };
        assert!(create_scheduled_rule(&mut rt, req).is_err());
    }

    #[test]
    fn create_scheduled_rule_invalid_days() {
        let mut rt = init_runtime(parse_policy());
        let req = CreateScheduledRuleRequest {
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            time_slot: TimeSlotApi {
                start: "09:00".to_string(),
                end: "18:00".to_string(),
                days: vec![],
            },
            down_v4_kbps: 1000,
            down_v6_kbps: 0,
            up_v4_kbps: 800,
            up_v6_kbps: 0,
        };
        assert!(create_scheduled_rule(&mut rt, req).is_err());
    }

    #[test]
    fn delete_scheduled_rule_exists() {
        let mut rt = init_runtime(parse_policy());
        let req = CreateScheduledRuleRequest {
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            time_slot: TimeSlotApi {
                start: "09:00".to_string(),
                end: "18:00".to_string(),
                days: vec![1],
            },
            down_v4_kbps: 1000,
            down_v6_kbps: 0,
            up_v4_kbps: 800,
            up_v6_kbps: 0,
        };
        let api = create_scheduled_rule(&mut rt, req).unwrap();
        assert!(delete_scheduled_rule(&mut rt, &api.id).is_ok());
        assert!(rt.scheduled_rules.is_empty());
    }

    #[test]
    fn delete_scheduled_rule_not_exists() {
        let mut rt = init_runtime(parse_policy());
        assert!(delete_scheduled_rule(&mut rt, "nonexistent").is_err());
    }

    #[test]
    fn set_and_delete_iface_limit() {
        let mut rt = init_runtime(parse_policy());
        let topo = mock_topology();
        set_iface_limit(
            &mut rt,
            SetInterfaceRateLimitRequest {
                iface: "eth0".to_string(),
                down_v4_kbps: 100,
                down_v6_kbps: 50,
                up_v4_kbps: 80,
                up_v6_kbps: 40,
            },
            &topo,
        )
        .unwrap();
        assert_eq!(get_iface_limits(&rt).len(), 1);
        assert!(delete_iface_limit(&mut rt, "eth0").is_ok());
        assert!(delete_iface_limit(&mut rt, "eth0").is_err());
    }

    #[test]
    fn set_iface_limit_unknown_iface() {
        let mut rt = init_runtime(parse_policy());
        let topo = mock_topology();
        let err = set_iface_limit(
            &mut rt,
            SetInterfaceRateLimitRequest {
                iface: "nonexistent".to_string(),
                down_v4_kbps: 100,
                down_v6_kbps: 0,
                up_v4_kbps: 80,
                up_v6_kbps: 0,
            },
            &topo,
        );
        assert!(err.is_err());
    }

    #[test]
    fn delete_guest_default_exists() {
        let mut rt = init_runtime(parse_policy());
        let topo = mock_topology();
        set_guest_default(
            &mut rt,
            SetInterfaceRateLimitRequest {
                iface: "eth0".to_string(),
                down_v4_kbps: 100,
                down_v6_kbps: 0,
                up_v4_kbps: 80,
                up_v6_kbps: 0,
            },
            &topo,
        )
        .unwrap();
        assert!(delete_guest_default(&mut rt, "eth0").is_ok());
        assert!(delete_guest_default(&mut rt, "eth0").is_err());
    }

    #[test]
    fn policy_items_serialize() {
        let mut rt = init_runtime(parse_policy());
        let req = CreateScheduledRuleRequest {
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            time_slot: TimeSlotApi {
                start: "09:00".to_string(),
                end: "18:00".to_string(),
                days: vec![1],
            },
            down_v4_kbps: 1000,
            down_v6_kbps: 0,
            up_v4_kbps: 800,
            up_v6_kbps: 0,
        };
        create_scheduled_rule(&mut rt, req).unwrap();
        let topo = mock_topology();
        set_iface_limit(
            &mut rt,
            SetInterfaceRateLimitRequest {
                iface: "eth0".to_string(),
                down_v4_kbps: 100,
                down_v6_kbps: 0,
                up_v4_kbps: 80,
                up_v6_kbps: 0,
            },
            &topo,
        )
        .unwrap();
        let items = policy_items(&rt);
        assert!(items.iter().any(|i| i.scope == "iface" && i.iface.as_deref() == Some("eth0")));
        assert!(items.iter().any(|i| i.scope == "device" && i.extra.as_deref().map(|e| e.contains("scheduled")).unwrap_or(false)));
    }
}

