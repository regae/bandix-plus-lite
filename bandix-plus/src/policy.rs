use std::collections::{HashMap, HashSet};

use aya::Ebpf;
use aya::maps::HashMap as AyaHashMap;
use bandix_plus_common::{DeviceGlobalLimitKey, DeviceIfaceLimitKey, DeviceTrafficKey, RateLimitValue, TrafficValue};
use serde::{Deserialize, Serialize};

use crate::topology::TopologySnapshot;
use crate::utils::mac_utils;

#[derive(Debug, Clone)]
pub struct ParsedPolicy {
    pub global: HashMap<[u8; 6], RateLimitValue>,
    pub iface: HashMap<(u32, [u8; 6]), RateLimitValue>,
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
    pub iface: Option<String>,
    pub time_slot: TimeSlotApi,
    pub down_v4_kbps: u64,
    pub down_v6_kbps: u64,
    pub up_v4_kbps: u64,
    pub up_v6_kbps: u64,
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateScheduledRuleRequest {
    pub mac: String,
    pub iface: Option<String>,
    pub time_slot: TimeSlotApi,
    pub down_v4_kbps: u64,
    pub down_v6_kbps: u64,
    pub up_v4_kbps: u64,
    pub up_v6_kbps: u64,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateScheduledRuleRequest {
    pub mac: String,
    pub iface: Option<String>,
    pub time_slot: TimeSlotApi,
    pub down_v4_kbps: u64,
    pub down_v6_kbps: u64,
    pub up_v4_kbps: u64,
    pub up_v6_kbps: u64,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistStateApi {
    pub enabled: bool,
    pub macs: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SetWhitelistEnabledRequest {
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WhitelistMacRequest {
    pub mac: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceDefaultRuleApi {
    pub iface: String,
    pub down_v4_kbps: u64,
    pub down_v6_kbps: u64,
    pub up_v4_kbps: u64,
    pub up_v6_kbps: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SetInterfaceDefaultRuleRequest {
    pub iface: String,
    pub down_v4_kbps: u64,
    pub down_v6_kbps: u64,
    pub up_v4_kbps: u64,
    pub up_v6_kbps: u64,
}

#[derive(Debug, Clone)]
struct ScheduledRule {
    id: String,
    mac: [u8; 6],
    iface_ifindex: Option<u32>,
    iface_name: Option<String>,
    start_minute: u16,
    end_minute: u16,
    days_mask: u8,
    down_v4_bps: u64,
    down_v6_bps: u64,
    up_v4_bps: u64,
    up_v6_bps: u64,
    enabled: bool,
}

#[derive(Debug, Clone)]
pub struct PolicyRuntime {
    pub base: ParsedPolicy,
    whitelist_enabled: bool,
    whitelist: HashSet<[u8; 6]>,
    iface_default_limits: HashMap<u32, RateLimitValue>,
    scheduled_rules: Vec<ScheduledRule>,
    next_rule_id: u64,
}

/// 解析启动策略，当前无 CLI 规则，返回空策略。
pub fn parse_policy() -> ParsedPolicy {
    ParsedPolicy {
        global: HashMap::new(),
        iface: HashMap::new(),
    }
}

/// 用解析后的启动策略初始化运行时，包含白名单、定时规则、接口默认限速等。
pub fn init_runtime(base: ParsedPolicy) -> PolicyRuntime {
    PolicyRuntime {
        base,
        whitelist_enabled: false,
        whitelist: HashSet::new(),
        iface_default_limits: HashMap::new(),
        scheduled_rules: Vec::new(),
        next_rule_id: 1,
    }
}

/// 将启动策略以结构化日志输出。
pub fn log_policy(policy: &ParsedPolicy, topology: &TopologySnapshot) {
    log::info!("policy.startup.begin");
    if policy.global.is_empty() && policy.iface.is_empty() {
        log::info!("policy.startup.empty");
        return;
    }
    for (mac, limit) in &policy.global {
        log::info!(
            "policy.startup.global mac={} down(v4/v6)_kbps={}/{} up(v4/v6)_kbps={}/{}",
            mac_utils::to_string(mac),
            bytes_to_kbps(limit.down_v4_bps),
            bytes_to_kbps(limit.down_v6_bps),
            bytes_to_kbps(limit.up_v4_bps),
            bytes_to_kbps(limit.up_v6_bps)
        );
    }
    for ((ifindex, mac), limit) in &policy.iface {
        let ifname = topology.by_ifindex(*ifindex).map(|x| x.name.clone()).unwrap_or_else(|| format!("ifindex-{}", ifindex));
        log::info!(
            "policy.startup.iface iface={} mac={} down(v4/v6)_kbps={}/{} up(v4/v6)_kbps={}/{}",
            ifname,
            mac_utils::to_string(mac),
            bytes_to_kbps(limit.down_v4_bps),
            bytes_to_kbps(limit.down_v6_bps),
            bytes_to_kbps(limit.up_v4_bps),
            bytes_to_kbps(limit.up_v6_bps)
        );
    }
}

/// 汇总全局、接口级、定时、接口默认等限速规则，供 API 返回。
pub fn policy_items(runtime: &PolicyRuntime, topology: &TopologySnapshot) -> Vec<PolicyItem> {
    let mut rows = Vec::new();
    for (mac, limit) in &runtime.base.global {
        rows.push(PolicyItem {
            scope: "global-device".to_string(),
            iface: None,
            mac: Some(mac_utils::to_string(mac)),
            down_v4_kbps: bytes_to_kbps(limit.down_v4_bps),
            down_v6_kbps: bytes_to_kbps(limit.down_v6_bps),
            up_v4_kbps: bytes_to_kbps(limit.up_v4_bps),
            up_v6_kbps: bytes_to_kbps(limit.up_v6_bps),
            extra: None,
        });
    }
    for ((ifindex, mac), limit) in &runtime.base.iface {
        let ifname = topology.by_ifindex(*ifindex).map(|x| x.name.clone()).unwrap_or_else(|| format!("ifindex-{}", ifindex));
        rows.push(PolicyItem {
            scope: "iface-device".to_string(),
            iface: Some(ifname),
            mac: Some(mac_utils::to_string(mac)),
            down_v4_kbps: bytes_to_kbps(limit.down_v4_bps),
            down_v6_kbps: bytes_to_kbps(limit.down_v6_bps),
            up_v4_kbps: bytes_to_kbps(limit.up_v4_bps),
            up_v6_kbps: bytes_to_kbps(limit.up_v6_bps),
            extra: None,
        });
    }
    for (ifindex, limit) in &runtime.iface_default_limits {
        let ifname = topology.by_ifindex(*ifindex).map(|x| x.name.clone()).unwrap_or_else(|| format!("ifindex-{}", ifindex));
        rows.push(PolicyItem {
            scope: "iface-default".to_string(),
            iface: Some(ifname),
            mac: None,
            down_v4_kbps: bytes_to_kbps(limit.down_v4_bps),
            down_v6_kbps: bytes_to_kbps(limit.down_v6_bps),
            up_v4_kbps: bytes_to_kbps(limit.up_v4_bps),
            up_v6_kbps: bytes_to_kbps(limit.up_v6_bps),
            extra: Some(format!("whitelist_enabled={}", runtime.whitelist_enabled)),
        });
    }
    for rule in &runtime.scheduled_rules {
        rows.push(PolicyItem {
            scope: "scheduled".to_string(),
            iface: rule.iface_name.clone(),
            mac: Some(mac_utils::to_string(&rule.mac)),
            down_v4_kbps: bytes_to_kbps(rule.down_v4_bps),
            down_v6_kbps: bytes_to_kbps(rule.down_v6_bps),
            up_v4_kbps: bytes_to_kbps(rule.up_v4_bps),
            up_v6_kbps: bytes_to_kbps(rule.up_v6_bps),
            extra: Some(format!("id={} enabled={}", rule.id, rule.enabled)),
        });
    }
    rows
}

/// 获取所有定时限速规则的 API 表示。
pub fn get_scheduled_rules(runtime: &PolicyRuntime) -> Vec<ScheduledRuleApi> {
    runtime.scheduled_rules.iter().map(scheduled_rule_to_api).collect()
}

/// 创建一条定时限速规则。
pub fn create_scheduled_rule(runtime: &mut PolicyRuntime, req: CreateScheduledRuleRequest, topology: &TopologySnapshot) -> anyhow::Result<ScheduledRuleApi> {
    let mac = mac_utils::from_str(&req.mac)?;
    let (start_minute, end_minute, days_mask) = parse_time_slot(&req.time_slot)?;
    let iface_ifindex = resolve_iface_to_ifindex(req.iface.as_deref(), topology)?;
    let iface_name = req.iface;
    let rule = ScheduledRule {
        id: format!("rule-{}", runtime.next_rule_id),
        mac,
        iface_ifindex,
        iface_name,
        start_minute,
        end_minute,
        days_mask,
        down_v4_bps: kbps_to_bps(req.down_v4_kbps),
        down_v6_bps: kbps_to_bps(req.down_v6_kbps),
        up_v4_bps: kbps_to_bps(req.up_v4_kbps),
        up_v6_bps: kbps_to_bps(req.up_v6_kbps),
        enabled: req.enabled.unwrap_or(true),
    };
    runtime.next_rule_id = runtime.next_rule_id.saturating_add(1);
    let api = scheduled_rule_to_api(&rule);
    runtime.scheduled_rules.push(rule);
    Ok(api)
}

/// 更新指定 ID 的定时限速规则。
pub fn update_scheduled_rule(runtime: &mut PolicyRuntime, id: &str, req: UpdateScheduledRuleRequest, topology: &TopologySnapshot) -> anyhow::Result<ScheduledRuleApi> {
    let mac = mac_utils::from_str(&req.mac)?;
    let (start_minute, end_minute, days_mask) = parse_time_slot(&req.time_slot)?;
    let iface_ifindex = resolve_iface_to_ifindex(req.iface.as_deref(), topology)?;
    let rule = runtime
        .scheduled_rules
        .iter_mut()
        .find(|r| r.id == id)
        .ok_or_else(|| anyhow::anyhow!("scheduled rule not found: {}", id))?;
    rule.mac = mac;
    rule.iface_ifindex = iface_ifindex;
    rule.iface_name = req.iface;
    rule.start_minute = start_minute;
    rule.end_minute = end_minute;
    rule.days_mask = days_mask;
    rule.down_v4_bps = kbps_to_bps(req.down_v4_kbps);
    rule.down_v6_bps = kbps_to_bps(req.down_v6_kbps);
    rule.up_v4_bps = kbps_to_bps(req.up_v4_kbps);
    rule.up_v6_bps = kbps_to_bps(req.up_v6_kbps);
    rule.enabled = req.enabled;
    Ok(scheduled_rule_to_api(rule))
}

/// 删除指定 ID 的定时限速规则。
pub fn delete_scheduled_rule(runtime: &mut PolicyRuntime, id: &str) -> anyhow::Result<()> {
    let before = runtime.scheduled_rules.len();
    runtime.scheduled_rules.retain(|r| r.id != id);
    if runtime.scheduled_rules.len() == before {
        anyhow::bail!("scheduled rule not found: {}", id);
    }
    Ok(())
}

/// 获取白名单开关及 MAC 列表。
pub fn get_whitelist_state(runtime: &PolicyRuntime) -> WhitelistStateApi {
    let mut macs: Vec<String> = runtime.whitelist.iter().map(mac_utils::to_string).collect();
    macs.sort();
    WhitelistStateApi {
        enabled: runtime.whitelist_enabled,
        macs,
    }
}

/// 设置白名单开关。
pub fn set_whitelist_enabled(runtime: &mut PolicyRuntime, enabled: bool) {
    runtime.whitelist_enabled = enabled;
}

/// 向白名单添加 MAC。
pub fn whitelist_add_mac(runtime: &mut PolicyRuntime, mac: &str) -> anyhow::Result<()> {
    runtime.whitelist.insert(mac_utils::from_str(mac)?);
    Ok(())
}

/// 从白名单移除 MAC。
pub fn whitelist_remove_mac(runtime: &mut PolicyRuntime, mac: &str) -> anyhow::Result<()> {
    runtime.whitelist.remove(&mac_utils::from_str(mac)?);
    Ok(())
}

/// 获取各接口默认限速规则。
pub fn get_interface_default_rules(runtime: &PolicyRuntime, topology: &TopologySnapshot) -> Vec<InterfaceDefaultRuleApi> {
    let mut rows = Vec::new();
    for (ifindex, limit) in &runtime.iface_default_limits {
        let ifname = topology.by_ifindex(*ifindex).map(|x| x.name.clone()).unwrap_or_else(|| format!("ifindex-{}", ifindex));
        rows.push(InterfaceDefaultRuleApi {
            iface: ifname,
            down_v4_kbps: bytes_to_kbps(limit.down_v4_bps),
            down_v6_kbps: bytes_to_kbps(limit.down_v6_bps),
            up_v4_kbps: bytes_to_kbps(limit.up_v4_bps),
            up_v6_kbps: bytes_to_kbps(limit.up_v6_bps),
        });
    }
    rows.sort_by(|a, b| a.iface.cmp(&b.iface));
    rows
}

/// 设置指定接口的默认限速规则。
pub fn set_interface_default_rule(runtime: &mut PolicyRuntime, req: SetInterfaceDefaultRuleRequest, topology: &TopologySnapshot) -> anyhow::Result<()> {
    let ifindex = resolve_iface_to_ifindex(Some(&req.iface), topology)?
        .ok_or_else(|| anyhow::anyhow!("interface {} not found", req.iface))?;
    runtime.iface_default_limits.insert(
        ifindex,
        RateLimitValue {
            down_v4_bps: kbps_to_bps(req.down_v4_kbps),
            down_v6_bps: kbps_to_bps(req.down_v6_kbps),
            up_v4_bps: kbps_to_bps(req.up_v4_kbps),
            up_v6_bps: kbps_to_bps(req.up_v6_kbps),
        },
    );
    Ok(())
}

/// 删除指定接口的默认限速规则。
pub fn delete_interface_default_rule(runtime: &mut PolicyRuntime, iface: &str, topology: &TopologySnapshot) -> anyhow::Result<()> {
    let ifindex = resolve_iface_to_ifindex(Some(iface), topology)?
        .ok_or_else(|| anyhow::anyhow!("interface {} not found", iface))?;
    runtime.iface_default_limits.remove(&ifindex);
    Ok(())
}

/// 根据当前运行时策略、白名单、定时规则、接口默认限速，同步到 eBPF 限速 map。
pub fn apply_runtime_policy(
    ebpf: &mut Ebpf,
    runtime: &PolicyRuntime,
    observed_pairs: &[(u32, [u8; 6])],
    now_ms: u64,
) -> anyhow::Result<()> {
    let mut desired_global = runtime.base.global.clone();
    let mut desired_iface = runtime.base.iface.clone();

    if runtime.whitelist_enabled {
        for (ifindex, mac) in observed_pairs {
            if runtime.whitelist.contains(mac) {
                continue;
            }
            if let Some(default_limit) = runtime.iface_default_limits.get(ifindex) {
                merge_limit(&mut desired_iface, (*ifindex, *mac), *default_limit);
            }
        }
    }

    for rule in &runtime.scheduled_rules {
        if !rule.enabled || !is_rule_active(rule, now_ms) {
            continue;
        }
        let limit = RateLimitValue {
            down_v4_bps: rule.down_v4_bps,
            down_v6_bps: rule.down_v6_bps,
            up_v4_bps: rule.up_v4_bps,
            up_v6_bps: rule.up_v6_bps,
        };
        if let Some(ifindex) = rule.iface_ifindex {
            merge_limit(&mut desired_iface, (ifindex, rule.mac), limit);
        } else {
            merge_limit(&mut desired_global, rule.mac, limit);
        }
    }

    sync_global_map(ebpf, &desired_global)?;
    sync_iface_map(ebpf, &desired_iface)?;
    Ok(())
}

/// 从 eBPF 设备流量 map 收集已观测到的 (ifindex, mac) 对。
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

/// 将期望的全局限速同步到 eBPF DEVICE_LIMIT_GLOBAL map。
fn sync_global_map(ebpf: &mut Ebpf, desired: &HashMap<[u8; 6], RateLimitValue>) -> anyhow::Result<()> {
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
        let key = DeviceGlobalLimitKey {
            mac: *mac,
            _pad: [0; 2],
        };
        map.insert(key, *limit, 0)?;
        existing.remove(mac);
    }
    for mac in existing {
        let key = DeviceGlobalLimitKey { mac, _pad: [0; 2] };
        let _ = map.remove(&key);
    }
    Ok(())
}

/// 将期望的接口级限速同步到 eBPF DEVICE_LIMIT_IFACE map。
fn sync_iface_map(ebpf: &mut Ebpf, desired: &HashMap<(u32, [u8; 6]), RateLimitValue>) -> anyhow::Result<()> {
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
        let key = DeviceIfaceLimitKey {
            ifindex,
            mac,
            _pad: [0; 2],
        };
        let _ = map.remove(&key);
    }
    Ok(())
}

/// 合并限速：多规则时取更严格的值。
fn merge_limit<K: std::cmp::Eq + std::hash::Hash + Copy>(map: &mut HashMap<K, RateLimitValue>, key: K, incoming: RateLimitValue) {
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

/// 取两个限速中更严格者（较小且非零）。
fn stricter_limit(a: u64, b: u64) -> u64 {
    if a == 0 {
        return b;
    }
    if b == 0 {
        return a;
    }
    a.min(b)
}

/// 判断定时规则在给定时间是否处于生效时段。
fn is_rule_active(rule: &ScheduledRule, now_ms: u64) -> bool {
    let (minute_of_day, weekday) = local_minute_and_weekday(now_ms).unwrap_or_else(|| {
        // Fallback to UTC-based calculation if localtime conversion fails.
        let secs = now_ms / 1000;
        let minute = ((secs % 86_400) / 60) as u16;
        let day = (((secs / 86_400) + 3) % 7 + 1) as u8;
        (minute, day)
    });

    if rule.start_minute <= rule.end_minute {
        // Same-day window.
        let day_bit = 1u8 << (weekday - 1);
        if (rule.days_mask & day_bit) == 0 {
            return false;
        }
        minute_of_day >= rule.start_minute && minute_of_day < rule.end_minute
    } else {
        // Overnight window: [start, 24:00) belongs to current weekday,
        // [00:00, end) belongs to previous weekday.
        if minute_of_day >= rule.start_minute {
            let day_bit = 1u8 << (weekday - 1);
            (rule.days_mask & day_bit) != 0
        } else if minute_of_day < rule.end_minute {
            let prev_weekday = if weekday == 1 { 7 } else { weekday - 1 };
            let day_bit = 1u8 << (prev_weekday - 1);
            (rule.days_mask & day_bit) != 0
        } else {
            false
        }
    }
}

/// 根据毫秒时间戳计算本地分钟（0–1439）和星期（1=周一..7=周日）。
#[allow(deprecated)]
fn local_minute_and_weekday(now_ms: u64) -> Option<(u16, u8)> {
    let mut secs = (now_ms / 1000) as libc::time_t;
    let mut out = core::mem::MaybeUninit::<libc::tm>::uninit();
    let ret = unsafe { libc::localtime_r(&mut secs, out.as_mut_ptr()) };
    if ret.is_null() {
        return None;
    }
    let tm = unsafe { out.assume_init() };
    let minute_of_day = (tm.tm_hour as u16).saturating_mul(60).saturating_add(tm.tm_min as u16);
    // tm_wday: 0=Sunday..6=Saturday, convert to 1=Monday..7=Sunday
    let weekday = if tm.tm_wday == 0 { 7 } else { tm.tm_wday as u8 };
    Some((minute_of_day, weekday))
}

/// 将内部定时规则转为 API 结构。
fn scheduled_rule_to_api(rule: &ScheduledRule) -> ScheduledRuleApi {
    ScheduledRuleApi {
        id: rule.id.clone(),
        mac: mac_utils::to_string(&rule.mac),
        iface: rule.iface_name.clone(),
        time_slot: TimeSlotApi {
            start: minute_to_hhmm(rule.start_minute),
            end: minute_to_hhmm(rule.end_minute),
            days: days_mask_to_vec(rule.days_mask),
        },
        down_v4_kbps: bytes_to_kbps(rule.down_v4_bps),
        down_v6_kbps: bytes_to_kbps(rule.down_v6_bps),
        up_v4_kbps: bytes_to_kbps(rule.up_v4_bps),
        up_v6_kbps: bytes_to_kbps(rule.up_v6_bps),
        enabled: rule.enabled,
    }
}

/// 解析 API 时段为 (start_minute, end_minute, days_mask)。
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

/// 将接口名解析为逻辑接口的 ifindex。
fn resolve_iface_to_ifindex(iface: Option<&str>, topology: &TopologySnapshot) -> anyhow::Result<Option<u32>> {
    let Some(iface_name) = iface else { return Ok(None) };
    let idx = topology
        .logical_interfaces()
        .into_iter()
        .find(|x| x.name == iface_name)
        .map(|x| x.ifindex)
        .ok_or_else(|| anyhow::anyhow!("interface {} not found", iface_name))?;
    Ok(Some(idx))
}

/// 解析 HH:MM 为当日分钟数。
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

/// 将分钟数转为 HH:MM 字符串。
fn minute_to_hhmm(minute: u16) -> String {
    let h = minute / 60;
    let m = minute % 60;
    format!("{:02}:{:02}", h, m)
}

/// 将星期位掩码转为 1..7 的星期列表。
fn days_mask_to_vec(mask: u8) -> Vec<u8> {
    let mut out = Vec::new();
    for d in 1..=7 {
        if (mask & (1u8 << (d - 1))) != 0 {
            out.push(d);
        }
    }
    out
}

/// 千比特/秒转字节/秒（bps 为字节速率时除以 8）。
fn kbps_to_bps(kbps: u64) -> u64 {
    kbps.saturating_mul(1000) / 8
}

/// 字节/秒转千比特/秒。
fn bytes_to_kbps(bytes_per_sec: u64) -> u64 {
    bytes_per_sec.saturating_mul(8) / 1000
}


