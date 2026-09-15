use aya::maps::{MapData, RingBuf};
use bandix_plus_common::{DNS_PACKET_MAX_BYTES, DnsPacketHeader};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::sync::RwLock;

use crate::monitor::MonitorRuntime;
use crate::topology::TopologySnapshot;
use crate::utils::{mac_utils, time_utils};

const QUERY_DEDUP_WINDOW_NS: u64 = 500_000_000;
const RESPONSE_DEDUP_WINDOW_NS: u64 = 500_000_000;
const MAX_QUERY_MATCH_AGE_NS: u64 = 30_000_000_000;
const UNANSWERED_AFTER_MS: u64 = 5_000;
const MAX_DNS_ANSWERS: usize = 64;

fn is_blocked_answer(value: &str) -> bool {
    let answer = value.trim();
    if answer == "0.0.0.0" || answer == "::" {
        return true;
    }

    let Some((kind, data)) = answer.split_once(':') else {
        return false;
    };
    (kind.eq_ignore_ascii_case("A") && data.trim() == "0.0.0.0") || (kind.eq_ignore_ascii_case("AAAA") && data.trim() == "::")
}

fn result_matches(record: &DnsQueryRecord, needle: &str) -> bool {
    if needle == "blocked" {
        return record.response_ips.iter().any(|answer| is_blocked_answer(answer))
            || record.response_records.iter().any(|answer| is_blocked_answer(answer));
    }

    record
        .response_code
        .as_deref()
        .is_some_and(|code| code.to_ascii_lowercase().contains(needle))
        || record
            .response_ips
            .iter()
            .any(|answer| answer.to_ascii_lowercase().contains(needle))
        || record
            .response_records
            .iter()
            .any(|answer| answer.to_ascii_lowercase().contains(needle))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQueryRecord {
    pub timestamp: u64,
    pub domain: String,
    pub query_type: String,
    pub response_code: Option<String>,
    pub response_time_ms: Option<u64>,
    pub source_ip: String,
    pub destination_ip: String,
    pub source_port: u16,
    pub destination_port: u16,
    pub transaction_id: u16,
    pub is_query: bool,
    pub protocol: String,
    pub response_ips: Vec<String>,
    pub response_records: Vec<String>,
    pub device_mac: String,
    pub device_name: String,
    pub iface: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsTopItem {
    pub name: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsResponseCodeStats {
    pub code: String,
    pub count: usize,
    pub percentage: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsResponseTimePercentiles {
    pub p50: u64,
    pub p90: u64,
    pub p95: u64,
    pub p99: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsStats {
    pub total_queries: usize,
    pub total_responses: usize,
    pub queries_with_response: usize,
    pub queries_without_response: usize,
    pub success_count: usize,
    pub failure_count: usize,
    pub success_rate: f64,
    pub avg_response_time_ms: f64,
    pub min_response_time_ms: u64,
    pub max_response_time_ms: u64,
    pub latest_response_time_ms: Option<u64>,
    pub response_time_percentiles: DnsResponseTimePercentiles,
    pub response_codes: Vec<DnsResponseCodeStats>,
    pub top_domains: Vec<DnsTopItem>,
    pub top_query_types: Vec<DnsTopItem>,
    pub top_devices: Vec<DnsTopItem>,
    pub top_dns_servers: Vec<DnsTopItem>,
    pub unique_devices: usize,
    pub time_range_start: u64,
    pub time_range_end: u64,
    pub time_range_duration_minutes: u64,
    pub capture_parse_errors: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsQueriesResponse {
    pub queries: Vec<DnsQueryRecord>,
    pub total: usize,
    pub page: usize,
    pub page_size: usize,
    pub total_pages: usize,
    pub stats: DnsStats,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsConfig {
    pub enabled: bool,
    pub monitored_interfaces: Vec<String>,
    pub max_records: usize,
    pub records_in_memory: usize,
    pub persistence_enabled: bool,
}

#[derive(Debug, Deserialize, Default)]
pub struct DnsQueriesQuery {
    pub domain: Option<String>,
    pub device: Option<String>,
    pub dns_server: Option<String>,
    pub query_type: Option<String>,
    pub result: Option<String>,
    pub iface: Option<String>,
    pub protocol: Option<String>,
    pub page: Option<usize>,
    pub page_size: Option<usize>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct DnsMatchKey {
    client_ip: IpAddr,
    client_port: u16,
    transaction_id: u16,
    domain: String,
    query_type: String,
    protocol: String,
}

#[derive(Debug)]
struct TrackedQuery {
    observed_ns: u64,
    match_key: DnsMatchKey,
    record: DnsQueryRecord,
}

#[derive(Debug, Clone)]
struct ParsedDnsMessage {
    is_query: bool,
    source_ip: IpAddr,
    destination_ip: IpAddr,
    source_port: u16,
    destination_port: u16,
    transaction_id: u16,
    domain: String,
    query_type: String,
    protocol: String,
    response_code: Option<String>,
    response_ips: Vec<String>,
    response_records: Vec<String>,
}

impl ParsedDnsMessage {
    fn match_key(&self) -> DnsMatchKey {
        let (client_ip, client_port) = if self.is_query {
            (self.source_ip, self.source_port)
        } else {
            (self.destination_ip, self.destination_port)
        };
        DnsMatchKey {
            client_ip,
            client_port,
            transaction_id: self.transaction_id,
            domain: self.domain.to_ascii_lowercase(),
            query_type: self.query_type.to_ascii_uppercase(),
            protocol: self.protocol.clone(),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct DeviceIdentity {
    mac: String,
    name: String,
    iface: String,
}

pub struct DnsMonitor {
    enabled: bool,
    persistence_enabled: bool,
    monitored_interfaces: Vec<String>,
    max_records: usize,
    records: BTreeMap<u64, TrackedQuery>,
    order: VecDeque<u64>,
    pending: HashMap<DnsMatchKey, VecDeque<u64>>,
    recent_queries: HashMap<DnsMatchKey, u64>,
    recent_responses: HashMap<DnsMatchKey, u64>,
    next_id: u64,
    capture_parse_errors: u64,
}

impl DnsMonitor {
    pub fn new(enabled: bool, persistence_enabled: bool, max_records: usize, monitored_interfaces: Vec<String>) -> Self {
        Self {
            enabled,
            persistence_enabled,
            monitored_interfaces,
            max_records: max_records.max(1),
            records: BTreeMap::new(),
            order: VecDeque::new(),
            pending: HashMap::new(),
            recent_queries: HashMap::new(),
            recent_responses: HashMap::new(),
            next_id: 1,
            capture_parse_errors: 0,
        }
    }

    pub fn config(&self) -> DnsConfig {
        DnsConfig {
            enabled: self.enabled,
            monitored_interfaces: self.monitored_interfaces.clone(),
            max_records: self.max_records,
            records_in_memory: self.records.len(),
            persistence_enabled: self.persistence_enabled,
        }
    }

    fn note_parse_errors(&mut self, count: u64) {
        self.capture_parse_errors = self.capture_parse_errors.saturating_add(count);
    }

    fn ingest(&mut self, message: ParsedDnsMessage, header: DnsPacketHeader, timestamp_ms: u64, device: DeviceIdentity) {
        let key = message.match_key();
        if message.is_query {
            if self
                .recent_queries
                .get(&key)
                .is_some_and(|last| header.timestamp_ns.saturating_sub(*last) < QUERY_DEDUP_WINDOW_NS)
            {
                return;
            }
            self.recent_queries.insert(key.clone(), header.timestamp_ns);

            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1).max(1);
            let record = DnsQueryRecord {
                timestamp: timestamp_ms,
                domain: message.domain,
                query_type: message.query_type,
                response_code: None,
                response_time_ms: None,
                source_ip: message.source_ip.to_string(),
                destination_ip: message.destination_ip.to_string(),
                source_port: message.source_port,
                destination_port: message.destination_port,
                transaction_id: message.transaction_id,
                is_query: true,
                protocol: message.protocol,
                response_ips: Vec::new(),
                response_records: Vec::new(),
                device_mac: device.mac,
                device_name: device.name,
                iface: device.iface,
            };
            self.records.insert(
                id,
                TrackedQuery {
                    observed_ns: header.timestamp_ns,
                    match_key: key.clone(),
                    record,
                },
            );
            self.order.push_back(id);
            self.pending.entry(key).or_default().push_back(id);
            while self.records.len() > self.max_records {
                self.evict_oldest();
            }
        } else {
            if self
                .recent_responses
                .get(&key)
                .is_some_and(|last| header.timestamp_ns.saturating_sub(*last) < RESPONSE_DEDUP_WINDOW_NS)
            {
                return;
            }

            let mut remove_pending_key = false;
            let query_id = if let Some(queue) = self.pending.get_mut(&key) {
                while let Some(id) = queue.front().copied() {
                    let expired = self.records.get(&id).map_or(true, |query| {
                        header.timestamp_ns.saturating_sub(query.observed_ns) > MAX_QUERY_MATCH_AGE_NS
                    });
                    if expired {
                        queue.pop_front();
                    } else {
                        break;
                    }
                }
                let id = queue.pop_front();
                remove_pending_key = queue.is_empty();
                id
            } else {
                None
            };
            if remove_pending_key {
                self.pending.remove(&key);
            }

            if let Some(id) = query_id {
                if let Some(query) = self.records.get_mut(&id) {
                    let elapsed_ns = header.timestamp_ns.saturating_sub(query.observed_ns);
                    query.record.response_code = message.response_code;
                    query.record.response_time_ms = Some(elapsed_ns / 1_000_000);
                    query.record.response_ips = message.response_ips;
                    query.record.response_records = message.response_records;
                    self.recent_responses.insert(key, header.timestamp_ns);
                }
            }
        }

        let dedupe_limit = self.max_records.saturating_mul(2).max(1);
        prune_dedupe_cache(
            &mut self.recent_queries,
            header.timestamp_ns,
            QUERY_DEDUP_WINDOW_NS,
            dedupe_limit,
        );
        prune_dedupe_cache(
            &mut self.recent_responses,
            header.timestamp_ns,
            RESPONSE_DEDUP_WINDOW_NS,
            dedupe_limit,
        );
    }

    fn evict_oldest(&mut self) {
        let Some(id) = self.order.pop_front() else { return };
        let Some(query) = self.records.remove(&id) else { return };
        if query.record.response_time_ms.is_none() {
            let mut remove_key = false;
            if let Some(queue) = self.pending.get_mut(&query.match_key) {
                if queue.front() == Some(&id) {
                    queue.pop_front();
                } else {
                    queue.retain(|queued_id| *queued_id != id);
                }
                remove_key = queue.is_empty();
            }
            if remove_key {
                self.pending.remove(&query.match_key);
            }
        }
    }

    pub fn queries(&self, query: &DnsQueriesQuery, now_ms: u64) -> DnsQueriesResponse {
        let page = query.page.unwrap_or(1).max(1);
        let page_size = query.page_size.unwrap_or(20).clamp(1, 100);
        let domain = query.domain.as_deref().map(str::to_ascii_lowercase);
        let device = query.device.as_deref().map(str::to_ascii_lowercase);
        let dns_server = query.dns_server.as_deref().map(str::to_ascii_lowercase);
        let query_type = query.query_type.as_deref().map(str::to_ascii_uppercase);
        let result = query
            .result
            .as_deref()
            .map(str::trim)
            .filter(|needle| !needle.is_empty())
            .map(str::to_ascii_lowercase);
        let iface = query.iface.as_deref().map(str::to_ascii_lowercase);
        let protocol = query.protocol.as_deref().map(str::to_ascii_uppercase);
        let filtered: Vec<&DnsQueryRecord> = self
            .order
            .iter()
            .rev()
            .filter_map(|id| self.records.get(id).map(|tracked| &tracked.record))
            .filter(|record| {
                if domain
                    .as_ref()
                    .is_some_and(|needle| !record.domain.to_ascii_lowercase().contains(needle))
                {
                    return false;
                }
                if device.as_ref().is_some_and(|needle| {
                    !record.device_mac.to_ascii_lowercase().contains(needle)
                        && !record.device_name.to_ascii_lowercase().contains(needle)
                        && !record.source_ip.to_ascii_lowercase().contains(needle)
                }) {
                    return false;
                }
                if dns_server
                    .as_ref()
                    .is_some_and(|needle| !record.destination_ip.to_ascii_lowercase().contains(needle))
                {
                    return false;
                }
                if query_type
                    .as_ref()
                    .is_some_and(|wanted| !record.query_type.eq_ignore_ascii_case(wanted))
                {
                    return false;
                }
                if result.as_ref().is_some_and(|needle| !result_matches(record, needle)) {
                    return false;
                }
                if iface.as_ref().is_some_and(|wanted| !record.iface.eq_ignore_ascii_case(wanted)) {
                    return false;
                }
                if protocol
                    .as_ref()
                    .is_some_and(|wanted| !record.protocol.eq_ignore_ascii_case(wanted))
                {
                    return false;
                }
                true
            })
            .collect();
        let total = filtered.len();
        let total_pages = total.div_ceil(page_size);
        let start = page.saturating_sub(1).saturating_mul(page_size);
        let queries = filtered.into_iter().skip(start).take(page_size).cloned().collect();

        DnsQueriesResponse {
            queries,
            total,
            page,
            page_size,
            total_pages,
            stats: self.stats(now_ms),
        }
    }

    pub fn stats(&self, now_ms: u64) -> DnsStats {
        let records: Vec<&DnsQueryRecord> = self
            .order
            .iter()
            .filter_map(|id| self.records.get(id).map(|tracked| &tracked.record))
            .collect();
        let total_queries = records.len();
        let mut response_times = Vec::new();
        let mut response_codes: HashMap<String, usize> = HashMap::new();
        let mut domains: HashMap<String, usize> = HashMap::new();
        let mut query_types: HashMap<String, usize> = HashMap::new();
        let mut devices: HashMap<String, usize> = HashMap::new();
        let mut dns_servers: HashMap<String, usize> = HashMap::new();
        let mut unique_devices = HashSet::new();
        let mut time_range_start = u64::MAX;
        let mut time_range_end = 0u64;
        let mut latest_response_time_ms = None;
        let mut queries_without_response = 0usize;

        for record in &records {
            *domains.entry(record.domain.clone()).or_insert(0) += 1;
            *query_types.entry(record.query_type.clone()).or_insert(0) += 1;
            *dns_servers.entry(record.destination_ip.clone()).or_insert(0) += 1;
            let device_identity = if record.device_mac.is_empty() {
                if record.device_name.is_empty() {
                    record.source_ip.clone()
                } else {
                    record.device_name.clone()
                }
            } else {
                record.device_mac.clone()
            };
            let device_label = if record.device_name.is_empty() {
                device_identity.clone()
            } else {
                record.device_name.clone()
            };
            *devices.entry(device_label).or_insert(0) += 1;
            unique_devices.insert(device_identity);
            time_range_start = time_range_start.min(record.timestamp);
            time_range_end = time_range_end.max(record.timestamp);

            if let Some(code) = record.response_code.as_ref().filter(|code| code.as_str() != "NO_RESPONSE") {
                *response_codes.entry(code.clone()).or_insert(0) += 1;
            } else if record.timestamp.saturating_add(UNANSWERED_AFTER_MS) <= now_ms {
                queries_without_response += 1;
            }
            if let Some(response_time) = record.response_time_ms {
                response_times.push(response_time);
                latest_response_time_ms = Some(response_time);
            }
        }

        response_times.sort_unstable();
        let total_responses: usize = response_codes.values().sum();
        let success_count = *response_codes.get("NOERROR").unwrap_or(&0);
        let failure_count = total_responses.saturating_sub(success_count);
        let avg_response_time_ms = if response_times.is_empty() {
            0.0
        } else {
            response_times.iter().map(|v| *v as f64).sum::<f64>() / response_times.len() as f64
        };
        let response_time_percentiles = DnsResponseTimePercentiles {
            p50: percentile(&response_times, 50),
            p90: percentile(&response_times, 90),
            p95: percentile(&response_times, 95),
            p99: percentile(&response_times, 99),
        };
        let response_codes = sorted_top_items(response_codes, usize::MAX)
            .into_iter()
            .map(|item| DnsResponseCodeStats {
                code: item.name,
                count: item.count,
                percentage: if total_responses == 0 {
                    0.0
                } else {
                    item.count as f64 * 100.0 / total_responses as f64
                },
            })
            .collect();
        let (time_range_start, time_range_end) = if records.is_empty() { (0, 0) } else { (time_range_start, time_range_end) };

        DnsStats {
            total_queries,
            total_responses,
            queries_with_response: total_responses,
            queries_without_response,
            success_count,
            failure_count,
            success_rate: if total_responses == 0 {
                0.0
            } else {
                success_count as f64 / total_responses as f64
            },
            avg_response_time_ms,
            min_response_time_ms: response_times.first().copied().unwrap_or(0),
            max_response_time_ms: response_times.last().copied().unwrap_or(0),
            latest_response_time_ms,
            response_time_percentiles,
            response_codes,
            top_domains: sorted_top_items(domains, 10),
            top_query_types: sorted_top_items(query_types, 10),
            top_devices: sorted_top_items(devices, 10),
            top_dns_servers: sorted_top_items(dns_servers, 10),
            unique_devices: unique_devices.len(),
            time_range_start,
            time_range_end,
            time_range_duration_minutes: time_range_end.saturating_sub(time_range_start) / 60_000,
            capture_parse_errors: self.capture_parse_errors,
        }
    }

    pub fn records_for_persistence(&self) -> Vec<DnsQueryRecord> {
        self.order
            .iter()
            .filter_map(|id| self.records.get(id).map(|tracked| tracked.record.clone()))
            .collect()
    }

    pub fn restore_records(&mut self, records: Vec<DnsQueryRecord>) {
        for mut record in records
            .into_iter()
            .rev()
            .take(self.max_records)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
        {
            if record.response_time_ms.is_none() && record.response_code.is_none() {
                record.response_code = Some("NO_RESPONSE".to_string());
            }
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1).max(1);
            let client_ip = record.source_ip.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            let key = DnsMatchKey {
                client_ip,
                client_port: record.source_port,
                transaction_id: record.transaction_id,
                domain: record.domain.to_ascii_lowercase(),
                query_type: record.query_type.to_ascii_uppercase(),
                protocol: record.protocol.clone(),
            };
            self.records.insert(
                id,
                TrackedQuery {
                    observed_ns: 0,
                    match_key: key,
                    record,
                },
            );
            self.order.push_back(id);
        }
    }
}

fn prune_dedupe_cache(cache: &mut HashMap<DnsMatchKey, u64>, now_ns: u64, window_ns: u64, max_entries: usize) {
    if cache.len() <= max_entries {
        return;
    }

    let cutoff = now_ns.saturating_sub(window_ns);
    cache.retain(|_, seen_ns| *seen_ns >= cutoff);
    if cache.len() > max_entries {
        let mut retained = 0usize;
        cache.retain(|_, _| {
            retained += 1;
            retained <= max_entries
        });
    }
}

fn sorted_top_items(values: HashMap<String, usize>, limit: usize) -> Vec<DnsTopItem> {
    let mut items: Vec<DnsTopItem> = values.into_iter().map(|(name, count)| DnsTopItem { name, count }).collect();
    items.sort_by(|a, b| b.count.cmp(&a.count).then(a.name.cmp(&b.name)));
    items.truncate(limit);
    items
}

fn percentile(sorted_values: &[u64], percentile: usize) -> u64 {
    if sorted_values.is_empty() {
        return 0;
    }
    let index = (sorted_values.len() - 1).saturating_mul(percentile) / 100;
    sorted_values[index]
}

pub fn spawn_dns_reader(
    map: aya::maps::Map,
    monitor: Arc<RwLock<DnsMonitor>>,
    runtime: Arc<RwLock<MonitorRuntime>>,
    topology: Arc<RwLock<TopologySnapshot>>,
) -> anyhow::Result<()> {
    let ringbuf = RingBuf::<MapData>::try_from(map)?;
    let mut ringbuf = AsyncFd::new(ringbuf)?;
    tokio::spawn(async move {
        let clock_offset_ns = time_utils::now_millis() as i128 * 1_000_000 - monotonic_ns() as i128;
        loop {
            let mut readiness = match ringbuf.readable_mut().await {
                Ok(ready) => ready,
                Err(error) => {
                    log::error!("DNS ring buffer readiness failed: {error}");
                    return;
                }
            };
            let mut messages = Vec::new();
            let mut parse_errors = 0u64;
            loop {
                let Some(item) = readiness.get_inner_mut().next() else { break };
                let header_size = core::mem::size_of::<DnsPacketHeader>();
                if item.len() < header_size {
                    parse_errors = parse_errors.saturating_add(1);
                    continue;
                }
                let header = unsafe { core::ptr::read_unaligned(item.as_ptr() as *const DnsPacketHeader) };
                let captured_len = (header.captured_len as usize).min(DNS_PACKET_MAX_BYTES);
                if captured_len == 0 || item.len() < header_size + captured_len {
                    parse_errors = parse_errors.saturating_add(1);
                    continue;
                }
                let packet = &item[header_size..header_size + captured_len];
                match parse_dns_packet(packet, header.ip_offset as usize, header.ip_version) {
                    Some(message) => messages.push((header, message)),
                    None => parse_errors = parse_errors.saturating_add(1),
                }
            }
            readiness.clear_ready();
            drop(readiness);

            let mut processed = Vec::with_capacity(messages.len());
            for (header, message) in messages {
                let client_ip = if message.is_query { message.source_ip } else { message.destination_ip };
                let device = {
                    let runtime_guard = runtime.read().await;
                    let topology_guard = topology.read().await;
                    resolve_device(&runtime_guard, &topology_guard, header, client_ip)
                };
                let timestamp_ms = ((header.timestamp_ns as i128 + clock_offset_ns).max(0) / 1_000_000) as u64;
                processed.push((message, header, timestamp_ms, device));
            }
            if parse_errors > 0 || !processed.is_empty() {
                let mut monitor_guard = monitor.write().await;
                monitor_guard.note_parse_errors(parse_errors);
                for (message, header, timestamp_ms, device) in processed {
                    monitor_guard.ingest(message, header, timestamp_ms, device);
                }
            }
        }
    });
    Ok(())
}

fn monotonic_ns() -> u64 {
    let mut value = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) } != 0 {
        return 0;
    }
    (value.tv_sec.max(0) as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(value.tv_nsec.max(0) as u64)
}

fn resolve_device(runtime: &MonitorRuntime, topology: &TopologySnapshot, header: DnsPacketHeader, client_ip: IpAddr) -> DeviceIdentity {
    let ip_text = client_ip.to_string();
    let owns_ip =
        |known: &crate::monitor::KnownDevice| known.ipv4.iter().any(|ip| ip == &ip_text) || known.ipv6.iter().any(|ip| ip == &ip_text);
    let by_mac = (header.has_mac != 0)
        .then(|| runtime.device_registry.entries.get(&(header.ifindex, header.mac)))
        .flatten()
        .filter(|known| (known.ipv4.is_empty() && known.ipv6.is_empty()) || owns_ip(known));
    let mut ip_matches = runtime.device_registry.entries.values().filter(|known| owns_ip(known));
    let first_ip_match = ip_matches.next();
    let unique_ip_match = if ip_matches.next().is_none() { first_ip_match } else { None };
    let entry = by_mac.or(unique_ip_match);

    if let Some(known) = entry {
        return DeviceIdentity {
            mac: mac_utils::to_string(&known.mac),
            name: known.hostname.clone(),
            iface: known.logical_iface.clone(),
        };
    }

    let iface = topology
        .by_ifindex(header.ifindex)
        .map(|iface| iface.name.clone())
        .unwrap_or_default();
    let known_mac_belongs_to_another_ip = (header.has_mac != 0)
        && runtime
            .device_registry
            .entries
            .get(&(header.ifindex, header.mac))
            .is_some_and(|known| !owns_ip(known) && (!known.ipv4.is_empty() || !known.ipv6.is_empty()));
    DeviceIdentity {
        mac: if header.has_mac != 0 && !known_mac_belongs_to_another_ip {
            mac_utils::to_string(&header.mac)
        } else {
            String::new()
        },
        name: String::new(),
        iface,
    }
}

pub fn dns_queries_file(data_dir: &str) -> PathBuf {
    Path::new(data_dir).join("dns").join("queries.jsonl")
}

pub fn load_dns_records(path: &Path, max_records: usize) -> anyhow::Result<Vec<DnsQueryRecord>> {
    if max_records == 0 {
        return Ok(Vec::new());
    }
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_file() {
        anyhow::bail!("DNS history path is not a regular file: {}", path.display());
    }
    if let Some(parent) = path.parent() {
        ensure_private_dns_directory(parent)?;
    }
    use std::os::unix::fs::PermissionsExt;
    let file = std::fs::File::open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    let mut records = VecDeque::with_capacity(max_records);
    for (line_number, line) in BufReader::new(file).lines().enumerate() {
        let line = match line {
            Ok(line) => line,
            Err(error) => {
                log::warn!("DNS storage read failed at line {}: {error}", line_number + 1);
                continue;
            }
        };
        match serde_json::from_str::<DnsQueryRecord>(&line) {
            Ok(mut record) => {
                if record.response_time_ms.is_none() && record.response_code.is_none() {
                    record.response_code = Some("NO_RESPONSE".to_string());
                }
                if records.len() == max_records {
                    records.pop_front();
                }
                records.push_back(record);
            }
            Err(error) => log::warn!("DNS storage JSON parse failed at line {}: {error}", line_number + 1),
        }
    }
    Ok(records.into_iter().collect())
}

pub fn spawn_dns_persistence(monitor: Arc<RwLock<DnsMonitor>>, path: PathBuf, flush_interval: Duration) {
    tokio::spawn(async move {
        let interval = flush_interval.max(Duration::from_secs(1));
        let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
        loop {
            ticker.tick().await;
            let records = monitor.read().await.records_for_persistence();
            let output_path = path.clone();
            match tokio::task::spawn_blocking(move || save_dns_records(&output_path, &records)).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => log::error!("DNS records persistence failed: {error}"),
                Err(error) => log::error!("DNS records persistence worker failed: {error}"),
            }
        }
    });
}

fn save_dns_records(path: &Path, records: &[DnsQueryRecord]) -> anyhow::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("DNS data path has no parent directory"))?;
    std::fs::create_dir_all(parent)?;
    ensure_private_dns_directory(parent)?;
    let temp_path = path.with_extension("jsonl.tmp");
    {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp_path)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        let mut writer = BufWriter::new(file);
        for record in records {
            serde_json::to_writer(&mut writer, record)?;
            writer.write_all(b"\n")?;
        }
        writer.flush()?;
    }
    std::fs::rename(temp_path, path)?;
    Ok(())
}

fn ensure_private_dns_directory(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() {
        anyhow::bail!("DNS storage path is not a directory: {}", path.display());
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn parse_dns_packet(packet: &[u8], ip_offset: usize, ip_version: u8) -> Option<ParsedDnsMessage> {
    let (source_ip, destination_ip, protocol, transport_offset, packet_end) = match ip_version {
        4 => parse_ipv4(packet, ip_offset)?,
        6 => parse_ipv6(packet, ip_offset)?,
        _ => return None,
    };
    let (source_port, destination_port, dns_offset, dns_len) = if protocol == 17 {
        if transport_offset + 8 > packet_end {
            return None;
        }
        let source_port = read_u16(packet, transport_offset)?;
        let destination_port = read_u16(packet, transport_offset + 2)?;
        let udp_len = read_u16(packet, transport_offset + 4)? as usize;
        if udp_len < 8 + 12 || transport_offset + udp_len > packet_end {
            return None;
        }
        (source_port, destination_port, transport_offset + 8, udp_len - 8)
    } else if protocol == 6 {
        if transport_offset + 20 > packet_end {
            return None;
        }
        let source_port = read_u16(packet, transport_offset)?;
        let destination_port = read_u16(packet, transport_offset + 2)?;
        let tcp_header_len = ((packet[transport_offset + 12] >> 4) as usize) * 4;
        if tcp_header_len < 20 || transport_offset + tcp_header_len + 2 > packet_end {
            return None;
        }
        let prefix_offset = transport_offset + tcp_header_len;
        let dns_len = read_u16(packet, prefix_offset)? as usize;
        if dns_len < 12 || prefix_offset + 2 + dns_len > packet_end {
            return None;
        }
        (source_port, destination_port, prefix_offset + 2, dns_len)
    } else {
        return None;
    };

    if source_port != 53 && destination_port != 53 {
        return None;
    }
    let dns = packet.get(dns_offset..dns_offset.checked_add(dns_len)?)?;
    parse_dns_message(
        dns,
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        if protocol == 17 { "UDP" } else { "TCP" },
    )
}

fn parse_ipv4(packet: &[u8], offset: usize) -> Option<(IpAddr, IpAddr, u8, usize, usize)> {
    let header = packet.get(offset..offset.checked_add(20)?)?;
    if header[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((header[0] & 0x0f) as usize) * 4;
    if ihl < 20 {
        return None;
    }
    let total_len = read_u16(packet, offset + 2)? as usize;
    if total_len < ihl || offset.checked_add(total_len)? > packet.len() {
        return None;
    }
    let fragment = read_u16(packet, offset + 6)?;
    if fragment & 0x3fff != 0 {
        return None;
    }
    let source = IpAddr::V4(Ipv4Addr::new(header[12], header[13], header[14], header[15]));
    let destination = IpAddr::V4(Ipv4Addr::new(header[16], header[17], header[18], header[19]));
    Some((source, destination, header[9], offset + ihl, offset + total_len))
}

fn parse_ipv6(packet: &[u8], offset: usize) -> Option<(IpAddr, IpAddr, u8, usize, usize)> {
    let header = packet.get(offset..offset.checked_add(40)?)?;
    if header[0] >> 4 != 6 {
        return None;
    }
    let payload_len = read_u16(packet, offset + 4)? as usize;
    let packet_end = offset.checked_add(40)?.checked_add(payload_len)?.min(packet.len());
    let source: [u8; 16] = header[8..24].try_into().ok()?;
    let destination: [u8; 16] = header[24..40].try_into().ok()?;
    let mut next_header = header[6];
    let mut cursor = offset + 40;
    for _ in 0..8 {
        match next_header {
            0 | 43 | 60 | 135 | 139 | 140 => {
                if cursor + 2 > packet_end {
                    return None;
                }
                let next = packet[cursor];
                let extension_len = (packet[cursor + 1] as usize + 1) * 8;
                if cursor + extension_len > packet_end {
                    return None;
                }
                next_header = next;
                cursor += extension_len;
            }
            51 => {
                if cursor + 2 > packet_end {
                    return None;
                }
                let next = packet[cursor];
                let extension_len = (packet[cursor + 1] as usize + 2) * 4;
                if cursor + extension_len > packet_end {
                    return None;
                }
                next_header = next;
                cursor += extension_len;
            }
            // DNS fragments are ignored because this packet alone may not
            // contain a complete transport and DNS header.
            44 | 50 => return None,
            _ => break,
        }
    }
    Some((
        IpAddr::V6(Ipv6Addr::from(source)),
        IpAddr::V6(Ipv6Addr::from(destination)),
        next_header,
        cursor,
        packet_end,
    ))
}

fn parse_dns_message(
    dns: &[u8],
    source_ip: IpAddr,
    destination_ip: IpAddr,
    source_port: u16,
    destination_port: u16,
    protocol: &str,
) -> Option<ParsedDnsMessage> {
    if dns.len() < 12 {
        return None;
    }
    let transaction_id = read_u16(dns, 0)?;
    let flags = read_u16(dns, 2)?;
    let is_query = flags & 0x8000 == 0;
    let question_count = read_u16(dns, 4)? as usize;
    if question_count == 0 || question_count > 16 {
        return None;
    }
    let answer_count = read_u16(dns, 6)? as usize;
    let (domain, mut cursor) = read_dns_name(dns, 12)?;
    if cursor + 4 > dns.len() {
        return None;
    }
    let query_type = dns_type_name(read_u16(dns, cursor)?);
    cursor += 4;
    for _ in 1..question_count {
        let (_, next) = read_dns_name(dns, cursor)?;
        cursor = next.checked_add(4)?;
        if cursor > dns.len() {
            return None;
        }
    }

    let mut response_ips = Vec::new();
    let mut response_records = Vec::new();
    if !is_query {
        let answer_limit = answer_count.min(MAX_DNS_ANSWERS);
        for _ in 0..answer_limit {
            let (_, next) = read_dns_name(dns, cursor)?;
            cursor = next;
            if cursor + 10 > dns.len() {
                return None;
            }
            let rr_type = read_u16(dns, cursor)?;
            let data_len = read_u16(dns, cursor + 8)? as usize;
            let data_start = cursor + 10;
            let data_end = data_start.checked_add(data_len)?;
            let data = dns.get(data_start..data_end)?;
            match rr_type {
                1 if data_len == 4 => {
                    let ip = Ipv4Addr::new(data[0], data[1], data[2], data[3]).to_string();
                    response_ips.push(ip.clone());
                    response_records.push(format!("A:{ip}"));
                }
                28 if data_len == 16 => {
                    let ip = Ipv6Addr::from(<[u8; 16]>::try_from(data).ok()?).to_string();
                    response_ips.push(ip.clone());
                    response_records.push(format!("AAAA:{ip}"));
                }
                5 | 2 | 12 => {
                    if let Some((name, _)) = read_dns_name(dns, data_start) {
                        response_records.push(format!("{}:{name}", dns_type_name(rr_type)));
                    }
                }
                15 if data_len >= 3 => {
                    if let Some((exchange, _)) = read_dns_name(dns, data_start + 2) {
                        response_records.push(format!("MX:{exchange} priority={}", u16::from_be_bytes([data[0], data[1]])));
                    }
                }
                16 => {
                    let mut text_parts = Vec::new();
                    let mut pos = 0;
                    while pos < data.len() {
                        let length = data[pos] as usize;
                        pos += 1;
                        if pos + length > data.len() {
                            break;
                        }
                        text_parts.push(String::from_utf8_lossy(&data[pos..pos + length]).into_owned());
                        pos += length;
                    }
                    response_records.push(format!("TXT:{}", text_parts.join(" ")));
                }
                _ => response_records.push(format!("{}: {} bytes", dns_type_name(rr_type), data_len)),
            }
            cursor = data_end;
        }
    }

    let response_code = if is_query { None } else { Some(dns_response_code((flags & 0x0f) as u8)) };
    Some(ParsedDnsMessage {
        is_query,
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        transaction_id,
        domain: domain.to_ascii_lowercase(),
        query_type,
        protocol: protocol.to_string(),
        response_code,
        response_ips,
        response_records,
    })
}

fn read_dns_name(packet: &[u8], offset: usize) -> Option<(String, usize)> {
    let mut position = offset;
    let mut consumed_position = None;
    let mut labels = Vec::new();
    let mut jumps = 0;
    let mut expanded_len = 0usize;
    loop {
        if position >= packet.len() || jumps > 16 || labels.len() > 127 {
            return None;
        }
        let length = packet[position];
        if length & 0xc0 == 0xc0 {
            let second = *packet.get(position + 1)?;
            let pointer = (((length & 0x3f) as usize) << 8) | second as usize;
            if pointer >= packet.len() {
                return None;
            }
            consumed_position.get_or_insert(position + 2);
            position = pointer;
            jumps += 1;
            continue;
        }
        if length & 0xc0 != 0 {
            return None;
        }
        position += 1;
        if length == 0 {
            let next = consumed_position.unwrap_or(position);
            return Some((labels.join("."), next));
        }
        let end = position.checked_add(length as usize)?;
        let label = packet.get(position..end)?;
        expanded_len = expanded_len.checked_add(length as usize + 1)?;
        if expanded_len > 255 {
            return None;
        }
        labels.push(String::from_utf8_lossy(label).into_owned());
        position = end;
    }
}

fn read_u16(packet: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(packet.get(offset..offset.checked_add(2)?)?.try_into().ok()?))
}

fn dns_type_name(value: u16) -> String {
    match value {
        1 => "A".to_string(),
        2 => "NS".to_string(),
        5 => "CNAME".to_string(),
        6 => "SOA".to_string(),
        12 => "PTR".to_string(),
        15 => "MX".to_string(),
        16 => "TXT".to_string(),
        28 => "AAAA".to_string(),
        33 => "SRV".to_string(),
        64 => "SVCB".to_string(),
        65 => "HTTPS".to_string(),
        other => format!("TYPE{other}"),
    }
}

fn dns_response_code(value: u8) -> String {
    match value {
        0 => "NOERROR".to_string(),
        1 => "FORMERR".to_string(),
        2 => "SERVFAIL".to_string(),
        3 => "NXDOMAIN".to_string(),
        4 => "NOTIMP".to_string(),
        5 => "REFUSED".to_string(),
        other => format!("RCODE{other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dns_query_frame(vlan: bool) -> (Vec<u8>, usize) {
        let mut frame = vec![0u8; 12];
        if vlan {
            frame.extend_from_slice(&[0x81, 0x00, 0, 9, 0x08, 0x00]);
        } else {
            frame.extend_from_slice(&[0x08, 0x00]);
        }
        let ip_offset = frame.len();
        let dns = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'p', b'r', b'o', b'b', b'e', b'-', b'1', 0x07,
            b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let udp_len = 8 + dns.len();
        let total_len = 20 + udp_len;
        frame.extend_from_slice(&[
            0x45,
            0,
            (total_len >> 8) as u8,
            total_len as u8,
            0,
            1,
            0,
            0,
            64,
            17,
            0,
            0,
            192,
            168,
            9,
            10,
            116,
            212,
            73,
            23,
        ]);
        frame.extend_from_slice(&[0xcf, 0xdd, 0, 53, (udp_len >> 8) as u8, udp_len as u8, 0, 0]);
        frame.extend_from_slice(&dns);
        (frame, ip_offset)
    }

    fn dns_response_frame() -> (Vec<u8>, usize) {
        let (mut frame, ip_offset) = dns_query_frame(false);
        let udp_offset = ip_offset + 20;
        let dns_offset = udp_offset + 8;

        let source_ip = frame[ip_offset + 12..ip_offset + 16].to_vec();
        let destination_ip = frame[ip_offset + 16..ip_offset + 20].to_vec();
        frame[ip_offset + 12..ip_offset + 16].copy_from_slice(&destination_ip);
        frame[ip_offset + 16..ip_offset + 20].copy_from_slice(&source_ip);

        let source_port = frame[udp_offset..udp_offset + 2].to_vec();
        let destination_port = frame[udp_offset + 2..udp_offset + 4].to_vec();
        frame[udp_offset..udp_offset + 2].copy_from_slice(&destination_port);
        frame[udp_offset + 2..udp_offset + 4].copy_from_slice(&source_port);

        frame[dns_offset + 2..dns_offset + 4].copy_from_slice(&0x8180u16.to_be_bytes());
        frame[dns_offset + 6..dns_offset + 8].copy_from_slice(&1u16.to_be_bytes());
        frame.extend_from_slice(&[
            0xc0, 0x0c, // compressed owner name: question name
            0x00, 0x01, // A
            0x00, 0x01, // IN
            0x00, 0x00, 0x00, 0x3c, // TTL = 60s
            0x00, 0x04, // RDLENGTH
            93, 184, 216, 34, // 93.184.216.34
        ]);

        let total_len = u16::from_be_bytes([frame[ip_offset + 2], frame[ip_offset + 3]]) + 16;
        frame[ip_offset + 2..ip_offset + 4].copy_from_slice(&total_len.to_be_bytes());
        let udp_len = u16::from_be_bytes([frame[udp_offset + 4], frame[udp_offset + 5]]) + 16;
        frame[udp_offset + 4..udp_offset + 6].copy_from_slice(&udp_len.to_be_bytes());
        (frame, ip_offset)
    }

    fn dns_query_tcp_frame() -> (Vec<u8>, usize) {
        let (udp_frame, udp_ip_offset) = dns_query_frame(false);
        let dns = &udp_frame[udp_ip_offset + 20 + 8..];
        let ip_offset = 14;
        let tcp_dns_prefix_len = dns.len() + 2;
        let total_len = 20 + 20 + tcp_dns_prefix_len;
        let mut frame = vec![0u8; ip_offset];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

        let mut ip = [0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        ip[8] = 64;
        ip[9] = 6;
        ip[12..16].copy_from_slice(&[192, 168, 9, 10]);
        ip[16..20].copy_from_slice(&[116, 212, 73, 23]);
        frame.extend_from_slice(&ip);

        let mut tcp = [0u8; 20];
        tcp[0..2].copy_from_slice(&0xcfdd_u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&53u16.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = 0x18;
        frame.extend_from_slice(&tcp);
        frame.extend_from_slice(&(dns.len() as u16).to_be_bytes());
        frame.extend_from_slice(dns);
        (frame, ip_offset)
    }

    #[test]
    fn parses_dns_query_from_vlan_frame() {
        let (frame, ip_offset) = dns_query_frame(true);
        let parsed = parse_dns_packet(&frame, ip_offset, 4).unwrap();
        assert!(parsed.is_query);
        assert_eq!(parsed.domain, "probe-1.example.com");
        assert_eq!(parsed.query_type, "A");
        assert_eq!(parsed.source_ip, "192.168.9.10".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.destination_port, 53);
    }

    #[test]
    fn parses_dns_over_tcp_when_message_is_complete_in_one_segment() {
        let (frame, ip_offset) = dns_query_tcp_frame();
        let parsed = parse_dns_packet(&frame, ip_offset, 4).unwrap();
        assert!(parsed.is_query);
        assert_eq!(parsed.protocol, "TCP");
        assert_eq!(parsed.domain, "probe-1.example.com");
    }

    #[test]
    fn parses_dns_response_answer_records() {
        let (frame, ip_offset) = dns_response_frame();
        let parsed = parse_dns_packet(&frame, ip_offset, 4).unwrap();
        assert!(!parsed.is_query);
        assert_eq!(parsed.response_code.as_deref(), Some("NOERROR"));
        assert_eq!(parsed.response_ips, vec!["93.184.216.34"]);
        assert_eq!(parsed.response_records, vec!["A:93.184.216.34"]);
    }

    #[test]
    fn result_filter_matches_rcode_and_blocked_answers() {
        let mut record = DnsQueryRecord {
            timestamp: 0,
            domain: "example.com".into(),
            query_type: "A".into(),
            response_code: Some("NXDOMAIN".into()),
            response_time_ms: Some(1),
            source_ip: "192.168.9.10".into(),
            destination_ip: "192.168.13.121".into(),
            source_port: 53053,
            destination_port: 53,
            transaction_id: 1,
            is_query: true,
            protocol: "UDP".into(),
            response_ips: Vec::new(),
            response_records: Vec::new(),
            device_mac: String::new(),
            device_name: String::new(),
            iface: "br-vlan9".into(),
        };

        assert!(result_matches(&record, "nxdomain"));
        assert!(!result_matches(&record, "blocked"));

        record.response_code = Some("NOERROR".into());
        record.response_ips = vec!["0.0.0.0".into()];
        record.response_records = vec!["A:0.0.0.0".into()];
        assert!(result_matches(&record, "blocked"));
        assert!(result_matches(&record, "0.0.0.0"));
        assert!(!result_matches(&record, "nxdomain"));
    }

    #[test]
    fn matches_response_after_query_and_suppresses_cross_interface_duplicate() {
        let (query_frame, ip_offset) = dns_query_frame(false);
        let query = parse_dns_packet(&query_frame, ip_offset, 4).unwrap();
        let (mut response_frame, response_ip_offset) = dns_response_frame();
        response_frame[response_ip_offset + 12..response_ip_offset + 16].copy_from_slice(&[192, 168, 13, 121]);
        let response = parse_dns_packet(&response_frame, response_ip_offset, 4).unwrap();
        let mut monitor = DnsMonitor::new(true, false, 10, vec!["br-vlan9".into()]);
        let header = DnsPacketHeader {
            timestamp_ns: 1_000_000_000,
            ..DnsPacketHeader::default()
        };
        let device = DeviceIdentity {
            mac: "14:dd:a9:ec:8d:41".into(),
            name: "regis-imac-pro".into(),
            iface: "br-vlan9".into(),
        };
        monitor.ingest(query.clone(), header, 1000, device.clone());
        monitor.ingest(
            query,
            DnsPacketHeader {
                timestamp_ns: 1_100_000_000,
                ..header
            },
            1100,
            device.clone(),
        );
        monitor.ingest(
            response.clone(),
            DnsPacketHeader {
                timestamp_ns: 1_250_000_000,
                ..header
            },
            1250,
            device,
        );
        monitor.ingest(
            response,
            DnsPacketHeader {
                timestamp_ns: 1_300_000_000,
                ..header
            },
            1300,
            DeviceIdentity::default(),
        );

        let records = monitor.records_for_persistence();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].response_code.as_deref(), Some("NOERROR"));
        assert_eq!(records[0].response_time_ms, Some(250));
        assert_eq!(records[0].response_ips, vec!["93.184.216.34"]);
        let stats = monitor.stats(2000);
        assert_eq!(stats.unique_devices, 1);
        assert_eq!(stats.top_devices[0].name, "regis-imac-pro");
    }

    #[test]
    fn dns_storage_roundtrip_uses_private_permissions() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let data_dir = std::env::temp_dir().join(format!("bandix-plus-dns-{}-{unique}", std::process::id()));
        let path = dns_queries_file(data_dir.to_str().unwrap());
        let record = DnsQueryRecord {
            timestamp: 1_700_000_000_000,
            domain: "probe-1.example.com".into(),
            query_type: "A".into(),
            response_code: Some("NOERROR".into()),
            response_time_ms: Some(12),
            source_ip: "192.168.9.10".into(),
            destination_ip: "116.212.73.23".into(),
            source_port: 53053,
            destination_port: 53,
            transaction_id: 0x1234,
            is_query: true,
            protocol: "UDP".into(),
            response_ips: vec!["93.184.216.34".into()],
            response_records: vec!["A:93.184.216.34".into()],
            device_mac: "14:dd:a9:ec:8d:41".into(),
            device_name: "regis-imac-pro".into(),
            iface: "br-vlan9".into(),
        };

        save_dns_records(&path, std::slice::from_ref(&record)).unwrap();
        let restored = load_dns_records(&path, 10).unwrap();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].domain, record.domain);
        assert_eq!(restored[0].response_code.as_deref(), Some("NOERROR"));
        assert_eq!(
            std::fs::metadata(path.parent().unwrap()).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::remove_dir_all(data_dir).unwrap();
    }
}
