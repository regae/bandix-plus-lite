//! Conntrack monitoring through the kernel's ctnetlink interface.
//!
//! The monitor intentionally does not invoke the conntrack command. A
//! netlink event socket keeps the active-flow view current, while an
//! inexpensive periodic dump repairs missed events and refreshes counters
//! maintained by hardware offload implementations.

use crate::monitor::MonitorRuntime;
use crate::utils::time_utils;
use anyhow::{Context, Result, anyhow, bail};
use log::{debug, warn};
use serde::Serialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::sync::RwLock;

const NETLINK_NETFILTER: libc::c_int = 12;
const NFNL_SUBSYS_CTNETLINK: u16 = 1;
const IPCTNL_MSG_CT_NEW: u16 = 0;
const IPCTNL_MSG_CT_GET: u16 = 1;
const IPCTNL_MSG_CT_DELETE: u16 = 2;
// Netfilter group numbers are one-based and the netlink bind API takes a bit
// mask. Subscribe to NEW, UPDATE, and DESTROY so deletes do not wait for the
// periodic reconciliation dump.
const NFNLGRP_CONNTRACK_ALL: u32 = (1 << 0) | (1 << 1) | (1 << 2);
const NFNETLINK_V0: u8 = 0;
const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ROOT: u16 = 0x0100;
const NLM_F_MATCH: u16 = 0x0200;
const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;
const NLMSG_NOOP: u16 = 1;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLMSG_OVERRUN: u16 = 4;
const NLMSG_HDR_LEN: usize = 16;
const NFGENMSG_LEN: usize = 4;
const NLMSG_ALIGNTO: usize = 4;
const NLA_ALIGNTO: usize = 4;
const MAX_NETLINK_MESSAGE: usize = 1024 * 1024;
const MAX_TRACKED_FLOWS: usize = 100_000;
const DUMP_INTERVAL: Duration = Duration::from_secs(30);
const STATS_INTERVAL: Duration = Duration::from_secs(3);
// Bump this when the userspace NLA framing rules change. It is included in
// diagnostics so a deployed binary can be distinguished from an older one.
const CTNETLINK_PARSER_VERSION: &str = "nla-v2";

// ctnetlink top-level attributes.
const CTA_TUPLE_ORIG: u16 = 1;
const CTA_TUPLE_REPLY: u16 = 2;
const CTA_STATUS: u16 = 3;
const CTA_PROTOINFO: u16 = 4;
const CTA_COUNTERS_ORIG: u16 = 10;
const CTA_COUNTERS_REPLY: u16 = 11;
const CTA_ID: u16 = 13;

// Tuple attributes.
const CTA_TUPLE_IP: u16 = 1;
const CTA_TUPLE_PROTO: u16 = 2;
const CTA_IP_V4_SRC: u16 = 1;
const CTA_IP_V4_DST: u16 = 2;
const CTA_IP_V6_SRC: u16 = 3;
const CTA_IP_V6_DST: u16 = 4;
const CTA_PROTO_NUM: u16 = 1;
const CTA_PROTO_SRC_PORT: u16 = 2;
const CTA_PROTO_DST_PORT: u16 = 3;

// Protocol information attributes.
const CTA_PROTOINFO_TCP: u16 = 1;
const CTA_PROTOINFO_TCP_STATE: u16 = 1;

// Counter attributes.
const CTA_COUNTERS_PACKETS: u16 = 1;
const CTA_COUNTERS_BYTES: u16 = 2;

// IPS_* status flags from include/uapi/linux/netfilter/nf_conntrack_common.h.
const IPS_SEEN_REPLY: u32 = 1 << 1;
const IPS_ASSURED: u32 = 1 << 2;
const IPS_CONFIRMED: u32 = 1 << 3;
const IPS_SRC_NAT: u32 = 1 << 4;
const IPS_DST_NAT: u32 = 1 << 5;
const IPS_DYING: u32 = 1 << 9;
const IPS_OFFLOAD: u32 = 1 << 14;
const IPS_HW_OFFLOAD: u32 = 1 << 15;

static NETLINK_SEQUENCE: AtomicU32 = AtomicU32::new(1);

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionEndpoint {
    pub src: String,
    pub dst: String,
    pub sport: u16,
    pub dport: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionFlow {
    pub id: Option<u32>,
    pub protocol: String,
    pub state: Option<String>,
    pub orig: ConnectionEndpoint,
    #[serde(rename = "repl")]
    pub reply: ConnectionEndpoint,
    pub orig_packets: u64,
    pub orig_bytes: u64,
    #[serde(rename = "repl_packets")]
    pub reply_packets: u64,
    #[serde(rename = "repl_bytes")]
    pub reply_bytes: u64,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ConnectionGlobalStats {
    #[serde(rename = "total")]
    pub total_connections: u32,
    #[serde(rename = "tcp")]
    pub tcp_connections: u32,
    #[serde(rename = "udp")]
    pub udp_connections: u32,
    #[serde(rename = "tcp_est")]
    pub established_tcp: u32,
    #[serde(rename = "tcp_tw")]
    pub time_wait_tcp: u32,
    #[serde(rename = "tcp_cw")]
    pub close_wait_tcp: u32,
    #[serde(rename = "last")]
    pub last_updated: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionDeviceStats {
    pub mac: String,
    pub hostname: String,
    pub logical_iface: String,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    #[serde(rename = "tcp")]
    pub tcp_connections: u32,
    #[serde(rename = "udp")]
    pub udp_connections: u32,
    #[serde(rename = "tcp_est")]
    pub established_tcp: u32,
    #[serde(rename = "tcp_tw")]
    pub time_wait_tcp: u32,
    #[serde(rename = "tcp_cw")]
    pub close_wait_tcp: u32,
    #[serde(rename = "total")]
    pub total_connections: u32,
    pub last_updated: u64,
}

#[derive(Debug, Clone)]
pub struct ConnectionSummary {
    pub enabled: bool,
    pub global: ConnectionGlobalStats,
    pub devices: Vec<ConnectionDeviceStats>,
    pub total_flows: usize,
    pub last_updated: u64,
    pub event_stream_available: bool,
    pub event_loss: u64,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct EndpointKey {
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct FlowKey {
    protocol: u8,
    orig: EndpointKey,
    reply: EndpointKey,
}

#[derive(Debug, Clone)]
struct ParsedFlow {
    key: FlowKey,
    flow: ConnectionFlow,
}

#[derive(Debug, Clone)]
struct DeviceIdentity {
    mac: String,
    hostname: String,
    logical_iface: String,
    ipv4: Vec<IpAddr>,
    ipv6: Vec<IpAddr>,
}

#[derive(Default)]
struct ConntrackState {
    enabled: bool,
    flows: HashMap<FlowKey, ConnectionFlow>,
    flow_ids: HashMap<u32, FlowKey>,
    global: ConnectionGlobalStats,
    devices: Vec<ConnectionDeviceStats>,
    last_updated: u64,
    event_stream_available: bool,
    event_loss: u64,
    last_error: Option<String>,
}

pub struct ConntrackMonitor {
    state: Arc<RwLock<ConntrackState>>,
    runtime: Arc<RwLock<MonitorRuntime>>,
}

impl ConntrackMonitor {
    pub fn new(enabled: bool, runtime: Arc<RwLock<MonitorRuntime>>) -> Arc<Self> {
        Arc::new(Self {
            state: Arc::new(RwLock::new(ConntrackState {
                enabled,
                ..ConntrackState::default()
            })),
            runtime,
        })
    }

    pub fn start(self: &Arc<Self>) {
        if !self.is_enabled() {
            return;
        }

        let event_state = Arc::clone(&self.state);
        let _ = std::thread::Builder::new()
            .name("bandix-ct-events".to_string())
            .spawn(move || event_loop(event_state));

        let dump_monitor = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(DUMP_INTERVAL);
            // The first tick is immediate, so the API has data as soon as
            // ctnetlink responds instead of waiting for the first interval.
            loop {
                ticker.tick().await;
                match tokio::task::spawn_blocking(dump_conntrack).await {
                    Ok(Ok(flows)) => {
                        dump_monitor.replace_flows(flows).await;
                        debug!("conntrack dump reconciled");
                    }
                    Ok(Err(error)) => dump_monitor.note_error(error).await,
                    Err(error) => dump_monitor.note_error(anyhow!("conntrack dump task failed: {error}")).await,
                }
            }
        });

        let stats_monitor = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(STATS_INTERVAL);
            loop {
                ticker.tick().await;
                stats_monitor.refresh_stats().await;
            }
        });
    }

    fn is_enabled(&self) -> bool {
        // This is only called during startup, before the state can change.
        self.state.try_read().map(|state| state.enabled).unwrap_or(true)
    }

    async fn replace_flows(&self, flows: Vec<ParsedFlow>) {
        let mut state = self.state.write().await;
        state.flows.clear();
        state.flow_ids.clear();
        for parsed in flows.into_iter().take(MAX_TRACKED_FLOWS) {
            insert_flow(&mut state, parsed);
        }
        state.last_error = None;
    }

    async fn note_error(&self, error: anyhow::Error) {
        let message = format!("{error:#}");
        let mut state = self.state.write().await;
        if state.last_error.as_deref() != Some(message.as_str()) {
            warn!("conntrack netlink dump failed [{CTNETLINK_PARSER_VERSION}]: {message}");
        }
        state.last_error = Some(message);
    }

    async fn refresh_stats(&self) {
        let identities = {
            let runtime = self.runtime.read().await;
            device_identities(&runtime)
        };
        let mut state = self.state.write().await;
        let now = time_utils::now_millis();
        let (global, devices) = calculate_stats(state.flows.values(), &identities, now);
        state.global = global;
        state.devices = devices;
        state.last_updated = now;
    }

    pub async fn summary(&self) -> ConnectionSummary {
        let state = self.state.read().await;
        ConnectionSummary {
            enabled: state.enabled,
            global: state.global.clone(),
            devices: state.devices.clone(),
            total_flows: state.flows.len(),
            last_updated: state.last_updated,
            event_stream_available: state.event_stream_available,
            event_loss: state.event_loss,
            last_error: state.last_error.clone(),
        }
    }

    pub async fn filtered_flows(
        &self,
        ip: Option<&str>,
        protocol: Option<&str>,
        state_filter: Option<&str>,
    ) -> (bool, Vec<ConnectionFlow>) {
        let state = self.state.read().await;
        let ip_filters: Vec<&str> = ip
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .collect();
        let mut flows: Vec<_> = state
            .flows
            .values()
            .filter(|flow| {
                protocol.map(|value| flow.protocol.eq_ignore_ascii_case(value)).unwrap_or(true)
                    && state_filter
                        .map(|value| {
                            flow.state
                                .as_deref()
                                .map(|state| state.eq_ignore_ascii_case(value))
                                .unwrap_or(false)
                        })
                        .unwrap_or(true)
                    && flow_matches_ip_filters(flow, &ip_filters)
            })
            .cloned()
            .collect();
        flows.sort_by(|a, b| {
            a.orig
                .src
                .cmp(&b.orig.src)
                .then(a.orig.dst.cmp(&b.orig.dst))
                .then(a.orig.sport.cmp(&b.orig.sport))
                .then(a.orig.dport.cmp(&b.orig.dport))
        });
        (state.enabled, flows)
    }
}

fn flow_matches_ip_filters(flow: &ConnectionFlow, filters: &[&str]) -> bool {
    filters.is_empty()
        || filters
            .iter()
            .any(|value| flow.orig.src.eq_ignore_ascii_case(value) || flow.reply.dst.eq_ignore_ascii_case(value))
}

fn device_identities(runtime: &MonitorRuntime) -> Vec<DeviceIdentity> {
    runtime
        .device_registry
        .entries
        .values()
        .map(|device| DeviceIdentity {
            mac: crate::utils::mac_utils::to_string(&device.mac),
            hostname: device.hostname.clone(),
            logical_iface: device.logical_iface.clone(),
            ipv4: device.ipv4.iter().filter_map(|ip| ip.parse().ok()).collect(),
            ipv6: device.ipv6.iter().filter_map(|ip| ip.parse().ok()).collect(),
        })
        .collect()
}

/// Resolve a conntrack origin address only when exactly one registered device
/// owns it. Conntrack does not carry the ingress interface or client MAC, so
/// choosing the first match would make attribution depend on registry order
/// when an address is duplicated across interfaces/devices.
fn unique_identity_for_ip<'a>(identities: &'a [DeviceIdentity], ip: IpAddr) -> Option<&'a DeviceIdentity> {
    let mut matches = identities
        .iter()
        .filter(|device| device.ipv4.contains(&ip) || device.ipv6.contains(&ip));
    let first = matches.next();
    if matches.next().is_some() { None } else { first }
}

fn calculate_stats<'a>(
    flows: impl Iterator<Item = &'a ConnectionFlow>,
    identities: &[DeviceIdentity],
    now: u64,
) -> (ConnectionGlobalStats, Vec<ConnectionDeviceStats>) {
    let mut global = ConnectionGlobalStats {
        last_updated: now,
        ..ConnectionGlobalStats::default()
    };
    let mut devices: HashMap<&str, ConnectionDeviceStats> = HashMap::new();

    for flow in flows {
        let protocol = flow.protocol.to_ascii_lowercase();
        let counted = match protocol.as_str() {
            "tcp" => {
                global.tcp_connections = global.tcp_connections.saturating_add(1);
                classify_tcp_state(&mut global, flow.state.as_deref());
                true
            }
            "udp" => {
                global.udp_connections = global.udp_connections.saturating_add(1);
                true
            }
            _ => false,
        };
        if counted {
            global.total_connections = global.total_connections.saturating_add(1);
        }

        let Some(client_ip) = flow.orig.src.parse::<IpAddr>().ok() else {
            continue;
        };
        let Some(identity) = unique_identity_for_ip(identities, client_ip) else {
            continue;
        };
        let entry = devices.entry(identity.mac.as_str()).or_insert_with(|| ConnectionDeviceStats {
            mac: identity.mac.clone(),
            hostname: identity.hostname.clone(),
            logical_iface: identity.logical_iface.clone(),
            ipv4: identity.ipv4.iter().map(ToString::to_string).collect(),
            ipv6: identity.ipv6.iter().map(ToString::to_string).collect(),
            tcp_connections: 0,
            udp_connections: 0,
            established_tcp: 0,
            time_wait_tcp: 0,
            close_wait_tcp: 0,
            total_connections: 0,
            last_updated: now,
        });
        match protocol.as_str() {
            "tcp" => {
                entry.tcp_connections = entry.tcp_connections.saturating_add(1);
                classify_tcp_state_device(entry, flow.state.as_deref());
                entry.total_connections = entry.total_connections.saturating_add(1);
            }
            "udp" => {
                entry.udp_connections = entry.udp_connections.saturating_add(1);
                entry.total_connections = entry.total_connections.saturating_add(1);
            }
            _ => {}
        }
    }

    let mut devices: Vec<_> = devices.into_values().collect();
    devices.sort_by(|a, b| b.total_connections.cmp(&a.total_connections).then(a.mac.cmp(&b.mac)));
    (global, devices)
}

fn classify_tcp_state(global: &mut ConnectionGlobalStats, state: Option<&str>) {
    match state.unwrap_or("") {
        "ESTABLISHED" => global.established_tcp = global.established_tcp.saturating_add(1),
        "TIME_WAIT" | "FIN_WAIT" | "FIN_WAIT2" | "CLOSING" | "LAST_ACK" => global.time_wait_tcp = global.time_wait_tcp.saturating_add(1),
        "CLOSE_WAIT" => global.close_wait_tcp = global.close_wait_tcp.saturating_add(1),
        _ => {}
    }
}

fn classify_tcp_state_device(device: &mut ConnectionDeviceStats, state: Option<&str>) {
    match state.unwrap_or("") {
        "ESTABLISHED" => device.established_tcp = device.established_tcp.saturating_add(1),
        "TIME_WAIT" | "FIN_WAIT" | "FIN_WAIT2" | "CLOSING" | "LAST_ACK" => device.time_wait_tcp = device.time_wait_tcp.saturating_add(1),
        "CLOSE_WAIT" => device.close_wait_tcp = device.close_wait_tcp.saturating_add(1),
        _ => {}
    }
}

fn insert_flow(state: &mut ConntrackState, parsed: ParsedFlow) {
    if let Some(id) = parsed.flow.id {
        if let Some(old_key) = state.flow_ids.insert(id, parsed.key.clone()) {
            state.flows.remove(&old_key);
        }
    }
    if state.flows.len() >= MAX_TRACKED_FLOWS && !state.flows.contains_key(&parsed.key) {
        return;
    }
    state.flows.insert(parsed.key, parsed.flow);
}

fn remove_flow(state: &mut ConntrackState, parsed: &ParsedFlow) {
    if let Some(id) = parsed.flow.id {
        if let Some(key) = state.flow_ids.remove(&id) {
            state.flows.remove(&key);
            return;
        }
    }
    state.flows.remove(&parsed.key);
}

fn event_loop(state: Arc<RwLock<ConntrackState>>) {
    loop {
        let fd = match open_netlink(NFNLGRP_CONNTRACK_ALL) {
            Ok(fd) => fd,
            Err(error) => {
                warn!("conntrack event socket unavailable: {error:#}");
                std::thread::sleep(Duration::from_secs(5));
                continue;
            }
        };
        {
            let mut guard = state.blocking_write();
            guard.event_stream_available = true;
        }

        let mut buffer = vec![0u8; MAX_NETLINK_MESSAGE];
        loop {
            let received = unsafe { libc::recv(fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len(), 0) };
            if received < 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                if error.raw_os_error() == Some(libc::ENOBUFS) {
                    let mut guard = state.blocking_write();
                    guard.event_loss = guard.event_loss.saturating_add(1);
                    guard.last_error = Some("conntrack event socket overflowed; waiting for reconciliation dump".to_string());
                } else {
                    warn!("conntrack event socket read failed: {error}");
                }
                break;
            }
            if received == 0 {
                break;
            }
            let mut guard = state.blocking_write();
            if let Err(error) = apply_event_messages(&buffer[..received as usize], &mut guard) {
                debug!("ignored malformed conntrack event: {error:#}");
            }
        }
        unsafe { libc::close(fd) };
        state.blocking_write().event_stream_available = false;
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn apply_event_messages(buffer: &[u8], state: &mut ConntrackState) -> Result<()> {
    for message in NetlinkMessages::new(buffer) {
        let message = message?;
        match message.kind {
            NLMSG_NOOP | NLMSG_DONE => {}
            NLMSG_OVERRUN => bail!("netlink reported an overrun"),
            NLMSG_ERROR => {
                if message.payload.len() >= 4 {
                    let code = i32::from_ne_bytes(message.payload[..4].try_into().unwrap());
                    if code != 0 {
                        bail!("netlink event error: {}", std::io::Error::from_raw_os_error(-code));
                    }
                }
            }
            _ => {
                let event_type = message.kind & 0x00ff;
                if let Some(flow) = parse_flow_message(message.payload)? {
                    if event_type == IPCTNL_MSG_CT_DELETE {
                        remove_flow(state, &flow);
                    } else if event_type == IPCTNL_MSG_CT_NEW {
                        insert_flow(state, flow);
                    }
                }
            }
        }
    }
    Ok(())
}

fn dump_conntrack() -> Result<Vec<ParsedFlow>> {
    let fd = open_netlink(0)?;
    let result = dump_conntrack_on_fd(fd);
    unsafe { libc::close(fd) };
    result
}

fn dump_conntrack_on_fd(fd: RawFd) -> Result<Vec<ParsedFlow>> {
    let sequence = NETLINK_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut request = Vec::with_capacity(NLMSG_HDR_LEN + NFGENMSG_LEN);
    put_u32_native(&mut request, (NLMSG_HDR_LEN + NFGENMSG_LEN) as u32);
    put_u16_native(&mut request, (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET);
    put_u16_native(&mut request, NLM_F_REQUEST | NLM_F_DUMP);
    put_u32_native(&mut request, sequence);
    put_u32_native(&mut request, 0);
    request.extend_from_slice(&[libc::AF_UNSPEC as u8, NFNETLINK_V0, 0, 0]);

    let sent = unsafe { libc::send(fd, request.as_ptr() as *const libc::c_void, request.len(), 0) };
    if sent < 0 || sent as usize != request.len() {
        return Err(std::io::Error::last_os_error()).context("send ctnetlink dump request");
    }

    let mut flows = Vec::new();
    let mut buffer = vec![0u8; MAX_NETLINK_MESSAGE];
    loop {
        let received = unsafe { libc::recv(fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len(), 0) };
        if received < 0 {
            return Err(std::io::Error::last_os_error()).context("receive ctnetlink dump");
        }
        if received == 0 {
            bail!("ctnetlink dump socket closed before NLMSG_DONE");
        }
        let messages = NetlinkMessages::new(&buffer[..received as usize]);
        for message in messages {
            let message = message?;
            match message.kind {
                NLMSG_NOOP => {}
                NLMSG_DONE => return Ok(flows),
                NLMSG_OVERRUN => bail!("ctnetlink dump reported an overrun"),
                NLMSG_ERROR => {
                    if message.payload.len() < 4 {
                        bail!("malformed ctnetlink error response");
                    }
                    let code = i32::from_ne_bytes(message.payload[..4].try_into().unwrap());
                    if code != 0 {
                        return Err(std::io::Error::from_raw_os_error(-code)).context("ctnetlink dump rejected");
                    }
                }
                _ => {
                    if let Some(flow) = parse_flow_message(message.payload)? {
                        if flows.len() < MAX_TRACKED_FLOWS {
                            flows.push(flow);
                        }
                    }
                }
            }
        }
    }
}

fn open_netlink(groups: u32) -> Result<RawFd> {
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, NETLINK_NETFILTER) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("open NETLINK_NETFILTER socket");
    }
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as u16;
    address.nl_pid = 0;
    address.nl_groups = groups;
    let result = unsafe {
        libc::bind(
            fd,
            &address as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if result < 0 {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(error).context("bind NETLINK_NETFILTER socket");
    }
    Ok(fd)
}

fn parse_flow_message(payload: &[u8]) -> Result<Option<ParsedFlow>> {
    if payload.len() < NFGENMSG_LEN {
        bail!("ctnetlink message is shorter than nfgenmsg");
    }
    let attributes = &payload[NFGENMSG_LEN..];
    let mut orig = None;
    let mut reply = None;
    let mut status = None;
    let mut protoinfo = None;
    let mut orig_counters = (0, 0);
    let mut reply_counters = (0, 0);
    let mut id = None;
    for attribute in NetlinkAttributes::new(attributes) {
        let (kind, value) = attribute?;
        match kind {
            CTA_TUPLE_ORIG => orig = parse_tuple(value)?,
            CTA_TUPLE_REPLY => reply = parse_tuple(value)?,
            CTA_STATUS => status = read_u32_be(value),
            CTA_PROTOINFO => protoinfo = parse_tcp_state(value),
            CTA_COUNTERS_ORIG => orig_counters = parse_counters(value)?,
            CTA_COUNTERS_REPLY => reply_counters = parse_counters(value)?,
            CTA_ID => id = read_u32_be(value),
            _ => {}
        }
    }
    let Some((protocol_number, orig_key)) = orig else {
        return Ok(None);
    };
    let Some((reply_protocol, reply_key)) = reply else {
        return Ok(None);
    };
    if protocol_number != reply_protocol || (protocol_number != 6 && protocol_number != 17) {
        return Ok(None);
    }
    let protocol = if protocol_number == 6 { "tcp" } else { "udp" };
    let state = if protocol_number == 6 { protoinfo } else { None };
    let flow = ConnectionFlow {
        id,
        protocol: protocol.to_string(),
        state,
        orig: endpoint_from_key(&orig_key),
        reply: endpoint_from_key(&reply_key),
        orig_packets: orig_counters.0,
        orig_bytes: orig_counters.1,
        reply_packets: reply_counters.0,
        reply_bytes: reply_counters.1,
        flags: status.map(status_flags).unwrap_or_default(),
    };
    Ok(Some(ParsedFlow {
        key: FlowKey {
            protocol: protocol_number,
            orig: orig_key,
            reply: reply_key,
        },
        flow,
    }))
}

fn parse_tuple(value: &[u8]) -> Result<Option<(u8, EndpointKey)>> {
    let mut src = None;
    let mut dst = None;
    let mut protocol = None;
    let mut sport = None;
    let mut dport = None;
    for attribute in NetlinkAttributes::new(value) {
        let (kind, nested) = attribute?;
        match kind {
            CTA_TUPLE_IP => {
                for ip_attribute in NetlinkAttributes::new(nested) {
                    let (ip_kind, bytes) = ip_attribute?;
                    match ip_kind {
                        CTA_IP_V4_SRC if bytes.len() >= 4 => src = Some(IpAddr::from(<[u8; 4]>::try_from(&bytes[..4]).unwrap())),
                        CTA_IP_V4_DST if bytes.len() >= 4 => dst = Some(IpAddr::from(<[u8; 4]>::try_from(&bytes[..4]).unwrap())),
                        CTA_IP_V6_SRC if bytes.len() >= 16 => src = Some(IpAddr::from(<[u8; 16]>::try_from(&bytes[..16]).unwrap())),
                        CTA_IP_V6_DST if bytes.len() >= 16 => dst = Some(IpAddr::from(<[u8; 16]>::try_from(&bytes[..16]).unwrap())),
                        _ => {}
                    }
                }
            }
            CTA_TUPLE_PROTO => {
                for proto_attribute in NetlinkAttributes::new(nested) {
                    let (proto_kind, bytes) = proto_attribute?;
                    match proto_kind {
                        CTA_PROTO_NUM => protocol = bytes.first().copied(),
                        CTA_PROTO_SRC_PORT if bytes.len() >= 2 => sport = Some(u16::from_be_bytes([bytes[0], bytes[1]])),
                        CTA_PROTO_DST_PORT if bytes.len() >= 2 => dport = Some(u16::from_be_bytes([bytes[0], bytes[1]])),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    let (Some(src), Some(dst), Some(protocol), Some(sport), Some(dport)) = (src, dst, protocol, sport, dport) else {
        return Ok(None);
    };
    Ok(Some((protocol, EndpointKey { src, dst, sport, dport })))
}

fn parse_tcp_state(value: &[u8]) -> Option<String> {
    for attribute in NetlinkAttributes::new(value).flatten() {
        if attribute.0 != CTA_PROTOINFO_TCP {
            continue;
        }
        for tcp_attribute in NetlinkAttributes::new(attribute.1).flatten() {
            if tcp_attribute.0 == CTA_PROTOINFO_TCP_STATE {
                let state = tcp_attribute.1.first().copied()?;
                return Some(tcp_state_name(state).to_string());
            }
        }
    }
    None
}

fn tcp_state_name(state: u8) -> &'static str {
    match state {
        1 => "SYN_SENT",
        2 => "SYN_RECV",
        3 => "ESTABLISHED",
        4 => "FIN_WAIT",
        5 => "CLOSE_WAIT",
        6 => "LAST_ACK",
        7 => "CLOSING",
        8 => "TIME_WAIT",
        9 => "CLOSE",
        10 => "LISTEN",
        11 => "SYN_SENT2",
        _ => "NONE",
    }
}

fn parse_counters(value: &[u8]) -> Result<(u64, u64)> {
    let mut packets = 0;
    let mut bytes = 0;
    for attribute in NetlinkAttributes::new(value) {
        let (kind, data) = attribute?;
        match kind {
            CTA_COUNTERS_PACKETS if data.len() >= 8 => packets = u64::from_be_bytes(data[..8].try_into().unwrap()),
            CTA_COUNTERS_BYTES if data.len() >= 8 => bytes = u64::from_be_bytes(data[..8].try_into().unwrap()),
            _ => {}
        }
    }
    Ok((packets, bytes))
}

fn endpoint_from_key(key: &EndpointKey) -> ConnectionEndpoint {
    ConnectionEndpoint {
        src: key.src.to_string(),
        dst: key.dst.to_string(),
        sport: key.sport,
        dport: key.dport,
    }
}

fn status_flags(status: u32) -> Vec<String> {
    let mut flags = Vec::new();
    for (mask, name) in [
        (IPS_SEEN_REPLY, "SEEN_REPLY"),
        (IPS_ASSURED, "ASSURED"),
        (IPS_CONFIRMED, "CONFIRMED"),
        (IPS_SRC_NAT, "SRC_NAT"),
        (IPS_DST_NAT, "DST_NAT"),
        (IPS_DYING, "DYING"),
        (IPS_OFFLOAD, "OFFLOAD"),
        (IPS_HW_OFFLOAD, "HW_OFFLOAD"),
    ] {
        if status & mask != 0 {
            flags.push(name.to_string());
        }
    }
    flags
}

fn read_u32_be(value: &[u8]) -> Option<u32> {
    (value.len() >= 4).then(|| u32::from_be_bytes(value[..4].try_into().unwrap()))
}

fn put_u16_native(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_ne_bytes());
}

fn put_u32_native(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_ne_bytes());
}

struct NetlinkMessage<'a> {
    kind: u16,
    payload: &'a [u8],
}

struct NetlinkMessages<'a> {
    buffer: &'a [u8],
    offset: usize,
}

impl<'a> NetlinkMessages<'a> {
    fn new(buffer: &'a [u8]) -> Self {
        Self { buffer, offset: 0 }
    }
}

impl<'a> Iterator for NetlinkMessages<'a> {
    type Item = Result<NetlinkMessage<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset == self.buffer.len() {
            return None;
        }
        if self.buffer.len().saturating_sub(self.offset) < NLMSG_HDR_LEN {
            self.offset = self.buffer.len();
            return Some(Err(anyhow!("truncated netlink header")));
        }
        let base = self.offset;
        let length = u32::from_ne_bytes(self.buffer[base..base + 4].try_into().unwrap()) as usize;
        if length < NLMSG_HDR_LEN || length > self.buffer.len().saturating_sub(base) {
            self.offset = self.buffer.len();
            return Some(Err(anyhow!("invalid netlink message length {length}")));
        }
        let kind = u16::from_ne_bytes(self.buffer[base + 4..base + 6].try_into().unwrap());
        let payload = &self.buffer[base + NLMSG_HDR_LEN..base + length];
        self.offset = base + align(length, NLMSG_ALIGNTO);
        Some(Ok(NetlinkMessage { kind, payload }))
    }
}

struct NetlinkAttributes<'a> {
    buffer: &'a [u8],
    offset: usize,
}

impl<'a> NetlinkAttributes<'a> {
    fn new(buffer: &'a [u8]) -> Self {
        Self { buffer, offset: 0 }
    }
}

impl<'a> Iterator for NetlinkAttributes<'a> {
    type Item = Result<(u16, &'a [u8])>;

    fn next(&mut self) -> Option<Self::Item> {
        // The final NLA is allowed to omit its alignment bytes in a nested
        // payload. Once the aligned cursor reaches/passes the payload end,
        // there is nothing left to decode.
        if self.offset >= self.buffer.len() {
            self.offset = self.buffer.len();
            return None;
        }
        // Some ctnetlink producers include zero-filled alignment bytes after
        // the final attribute. They are outside any NLA and must not be
        // interpreted as an attribute header with nla_len == 0.
        if self.buffer[self.offset..].iter().all(|byte| *byte == 0) {
            self.offset = self.buffer.len();
            return None;
        }
        if self.buffer.len().saturating_sub(self.offset) < 4 {
            self.offset = self.buffer.len();
            return Some(Err(anyhow!("truncated netlink attribute")));
        }
        let base = self.offset;
        let length = u16::from_ne_bytes(self.buffer[base..base + 2].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(self.buffer[base + 2..base + 4].try_into().unwrap()) & 0x3fff;
        // A few vendor ctnetlink producers leave a zero-filled NLA header as
        // an end marker before the next message/padding. NLA length zero is
        // invalid for a real attribute, but treating it as the end of this
        // attribute list keeps one malformed optional tail from discarding
        // the complete conntrack dump. The all-zero remainder check above
        // handles the usual alignment-only case.
        if length == 0 {
            self.offset = self.buffer.len();
            return None;
        }
        if length < 4 || length > self.buffer.len().saturating_sub(base) {
            self.offset = self.buffer.len();
            return Some(Err(anyhow!(
                "invalid netlink attribute length {length} (kind {kind}, offset {base}, remaining {})",
                self.buffer.len().saturating_sub(base)
            )));
        }
        self.offset = base + align(length, NLA_ALIGNTO);
        Some(Ok((kind, &self.buffer[base + 4..base + length])))
    }
}

fn align(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_states_are_named_like_conntrack() {
        assert_eq!(tcp_state_name(3), "ESTABLISHED");
        assert_eq!(tcp_state_name(8), "TIME_WAIT");
        assert_eq!(tcp_state_name(99), "NONE");
    }

    #[test]
    fn status_flags_are_decoded() {
        assert_eq!(
            status_flags(IPS_ASSURED | IPS_HW_OFFLOAD),
            vec!["ASSURED".to_string(), "HW_OFFLOAD".to_string()]
        );
    }

    #[test]
    fn netlink_attribute_alignment_is_checked() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&6u16.to_ne_bytes());
        bytes.extend_from_slice(&CTA_STATUS.to_ne_bytes());
        bytes.extend_from_slice(&[1, 2]);
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        let mut attrs = NetlinkAttributes::new(&bytes);
        let (kind, value) = attrs.next().unwrap().unwrap();
        assert_eq!(kind, CTA_STATUS);
        assert_eq!(value, &[1, 2]);
        assert!(attrs.next().is_none());
    }

    #[test]
    fn zero_length_attribute_terminates_vendor_padding() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u16.to_ne_bytes());
        bytes.extend_from_slice(&CTA_STATUS.to_ne_bytes());
        // Keep non-zero bytes after the marker: this is the case that cannot
        // be identified by the all-zero trailing-padding fast path.
        bytes.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        let mut attrs = NetlinkAttributes::new(&bytes);
        assert!(attrs.next().is_none());
    }

    #[test]
    fn missing_attribute_alignment_bytes_do_not_panic() {
        let bytes = [6u8, 0, CTA_STATUS as u8, 0, 1, 2];
        let mut attrs = NetlinkAttributes::new(&bytes);
        let (kind, value) = attrs.next().unwrap().unwrap();
        assert_eq!(kind, CTA_STATUS);
        assert_eq!(value, &[1, 2]);
        assert!(attrs.next().is_none());
    }

    #[test]
    fn calculate_stats_attributes_known_client() {
        let identity = DeviceIdentity {
            mac: "00:11:22:33:44:55".to_string(),
            hostname: "client".to_string(),
            logical_iface: "br-lan".to_string(),
            ipv4: vec!["192.168.1.10".parse().unwrap()],
            ipv6: Vec::new(),
        };
        let flow = ConnectionFlow {
            id: None,
            protocol: "tcp".to_string(),
            state: Some("ESTABLISHED".to_string()),
            orig: ConnectionEndpoint {
                src: "192.168.1.10".to_string(),
                dst: "203.0.113.1".to_string(),
                sport: 1234,
                dport: 443,
            },
            reply: ConnectionEndpoint {
                src: "203.0.113.1".to_string(),
                dst: "192.168.1.10".to_string(),
                sport: 443,
                dport: 1234,
            },
            orig_packets: 1,
            orig_bytes: 2,
            reply_packets: 3,
            reply_bytes: 4,
            flags: Vec::new(),
        };
        let (global, devices) = calculate_stats([&flow].into_iter(), &[identity], 10);
        assert_eq!(global.total_connections, 1);
        assert_eq!(global.established_tcp, 1);
        assert_eq!(devices[0].total_connections, 1);
        assert!(flow_matches_ip_filters(&flow, &["192.168.1.10", "2001:db8::10"]));
        assert!(!flow_matches_ip_filters(&flow, &["2001:db8::20"]));
    }

    #[test]
    fn calculate_stats_leaves_ambiguous_client_unattributed() {
        let identity = DeviceIdentity {
            mac: "00:11:22:33:44:55".to_string(),
            hostname: "client-a".to_string(),
            logical_iface: "br-vlan9".to_string(),
            ipv4: vec!["192.168.1.10".parse().unwrap()],
            ipv6: Vec::new(),
        };
        let duplicate_ip = DeviceIdentity {
            mac: "66:77:88:99:aa:bb".to_string(),
            hostname: "client-b".to_string(),
            logical_iface: "br-vlan10".to_string(),
            ipv4: vec!["192.168.1.10".parse().unwrap()],
            ipv6: Vec::new(),
        };
        let flow = ConnectionFlow {
            id: None,
            protocol: "udp".to_string(),
            state: None,
            orig: ConnectionEndpoint {
                src: "192.168.1.10".to_string(),
                dst: "203.0.113.53".to_string(),
                sport: 5353,
                dport: 53,
            },
            reply: ConnectionEndpoint {
                src: "203.0.113.53".to_string(),
                dst: "192.168.1.10".to_string(),
                sport: 53,
                dport: 5353,
            },
            orig_packets: 1,
            orig_bytes: 2,
            reply_packets: 1,
            reply_bytes: 3,
            flags: Vec::new(),
        };

        let (global, devices) = calculate_stats([&flow].into_iter(), &[identity, duplicate_ip], 10);
        assert_eq!(global.total_connections, 1);
        assert!(devices.is_empty());
    }
}
