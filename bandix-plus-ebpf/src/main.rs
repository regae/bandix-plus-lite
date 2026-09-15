#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_UNSPEC,
    helpers::{bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{classifier, kprobe, map},
    maps::{HashMap, PerCpuHashMap, RingBuf},
    programs::{ProbeContext, TcContext},
};
use bandix_plus_common::{
    DEVICE_TRAFFIC_MAX_ENTRIES, DNS_PACKET_MAX_BYTES, DeviceTrafficKey, DnsPacketHeader, EcmTrafficKey, InterfaceTrafficKey, IpVersion,
    RouterIpKey, TrafficDirection, TrafficValue,
};

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_P_PPP_SES: u16 = 0x8864;
const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88A8;
const PPP_PROTO_IP: u16 = 0x0021;
const PPP_PROTO_IPV6: u16 = 0x0057;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const DNS_PORT: u16 = 53;
const IFACE_MAX_ENTRIES: u32 = 256;
const DEVICE_MAX_ENTRIES: u32 = DEVICE_TRAFFIC_MAX_ENTRIES;
const ECM_MAX_ENTRIES: u32 = 16384;

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct EthHdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct PppoeSessionHdr {
    ver_type: u8,
    code: u8,
    session_id: u16,
    length: u16,
    ppp_proto: u16,
}

#[derive(Clone, Copy)]
struct PacketMeta {
    ip_version: u8,
    mac: Option<[u8; 6]>,
    ip_offset: u16,
}

#[repr(C)]
struct DnsPacketEvent {
    header: DnsPacketHeader,
    packet: [u8; DNS_PACKET_MAX_BYTES],
}

#[repr(C, packed)]
struct Ipv4Hdr {
    ihl_ver: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    saddr: u32,
    daddr: u32,
}

#[repr(C, packed)]
struct VlanHdr {
    tci: u16,
    encapsulated_proto: u16,
}

#[repr(C, packed)]
struct Ipv6Hdr {
    version_flow: u32,
    payload_len: u16,
    next_header: u8,
    hop_limit: u8,
    saddr: [u32; 4],
    daddr: [u32; 4],
}

#[repr(C, packed)]
struct TcpHdr {
    source: u16,
    dest: u16,
    sequence: u32,
    acknowledgment: u32,
    offset_flags: u16,
    window: u16,
    checksum: u16,
    urgent_pointer: u16,
}

#[repr(C, packed)]
struct UdpHdr {
    source: u16,
    dest: u16,
    len: u16,
    check: u16,
}

// Patched by the userspace loader; the normal traffic path only pays for a
// small global-data read when DNS monitoring is disabled.
#[unsafe(no_mangle)]
static mut DNS_ENABLED: u8 = 0;

#[map]
static DNS_DATA: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

#[map]
static ROUTER_LOCAL_IPS: HashMap<RouterIpKey, u8> = HashMap::with_max_entries(IFACE_MAX_ENTRIES, 0);

#[map]
static MANAGEMENT_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(8, 0);

fn management_port_matches(source: u16, destination: u16, direction: u8) -> bool {
    // On ingress the router is the destination; on egress it is the source.
    // Checking only that endpoint avoids excluding outbound HTTPS traffic just
    // because its remote server listens on port 443.
    let local_port = if direction == TrafficDirection::Ingress as u8 {
        u16::from_be(destination)
    } else {
        u16::from_be(source)
    };
    unsafe { MANAGEMENT_PORTS.get(&local_port).is_some() }
}

// Exclude LuCI and Bandix Plus API control-plane packets from traffic counters.
// The caller has already decoded Ethernet/VLAN headers, keeping the hot path
// from parsing those headers twice for every packet.
fn is_management_packet(ctx: &TcContext, direction: u8, mut eth_proto: u16, mut offset: usize) -> bool {
    if eth_proto == ETH_P_PPP_SES {
        let Ok(pppoe) = ptr_at::<PppoeSessionHdr>(ctx, offset) else {
            return false;
        };
        eth_proto = u16::from_be(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*pppoe).ppp_proto)) });
        eth_proto = match eth_proto {
            PPP_PROTO_IP => ETH_P_IP,
            PPP_PROTO_IPV6 => ETH_P_IPV6,
            _ => return false,
        };
        offset += core::mem::size_of::<PppoeSessionHdr>();
    }

    if eth_proto == ETH_P_IP {
        let Ok(ip) = ptr_at::<Ipv4Hdr>(ctx, offset) else { return false };
        let ihl_ver = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip).ihl_ver)) };
        let protocol = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip).protocol)) };
        let ihl = ((ihl_ver & 0x0f) as usize) * 4;
        if protocol != 6 || ihl < core::mem::size_of::<Ipv4Hdr>() {
            return false;
        }
        let fragment_offset = u16::from_be(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip).frag_off)) });
        if fragment_offset & 0x1fff != 0 {
            return false;
        }

        let Ok(tcp) = ptr_at::<TcpHdr>(ctx, offset + ihl) else { return false };
        let source = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*tcp).source)) };
        let destination = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*tcp).dest)) };
        if !management_port_matches(source, destination, direction) {
            return false;
        }

        let saddr = u32::from_be(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip).saddr)) });
        let daddr = u32::from_be(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip).daddr)) });
        let local_ip = if direction == TrafficDirection::Ingress as u8 { daddr } else { saddr };
        let key = RouterIpKey {
            ip: [local_ip, 0, 0, 0],
            ip_version: IpVersion::V4 as u8,
            _pad: [0; 3],
        };
        return unsafe { ROUTER_LOCAL_IPS.get(&key).is_some() };
    }

    if eth_proto == ETH_P_IPV6 {
        let Ok(ip) = ptr_at::<Ipv6Hdr>(ctx, offset) else { return false };
        let next_header = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip).next_header)) };
        if next_header != 6 {
            return false;
        }

        let Ok(tcp) = ptr_at::<TcpHdr>(ctx, offset + core::mem::size_of::<Ipv6Hdr>()) else {
            return false;
        };
        let source = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*tcp).source)) };
        let destination = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*tcp).dest)) };
        if !management_port_matches(source, destination, direction) {
            return false;
        }

        let (source, destination) = unsafe {
            (
                core::ptr::read_unaligned(core::ptr::addr_of!((*ip).saddr)),
                core::ptr::read_unaligned(core::ptr::addr_of!((*ip).daddr)),
            )
        };
        let words = if direction == TrafficDirection::Ingress as u8 { destination } else { source };
        let key = RouterIpKey {
            ip: [
                u32::from_be(words[0]),
                u32::from_be(words[1]),
                u32::from_be(words[2]),
                u32::from_be(words[3]),
            ],
            ip_version: IpVersion::V6 as u8,
            _pad: [0; 3],
        };
        return unsafe { ROUTER_LOCAL_IPS.get(&key).is_some() };
    }

    false
}

#[classifier]
pub fn bandix_plus_ingress(ctx: TcContext) -> i32 {
    match try_bandix_plus(ctx, TrafficDirection::Ingress as u8) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[classifier]
pub fn bandix_plus_egress(ctx: TcContext) -> i32 {
    match try_bandix_plus(ctx, TrafficDirection::Egress as u8) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[map]
static TRACK_DEVICES: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

#[map]
static IFACE_TRAFFIC_STATS: HashMap<InterfaceTrafficKey, TrafficValue> = HashMap::with_max_entries(IFACE_MAX_ENTRIES, 0);

#[map]
static DEVICE_TRAFFIC_STATS: HashMap<DeviceTrafficKey, TrafficValue> = HashMap::with_max_entries(DEVICE_MAX_ENTRIES, 0);

#[map]
static DEVICE_TRAFFIC_INSERT_FAILURES: PerCpuHashMap<u32, u64> = PerCpuHashMap::with_max_entries(1, 0);

fn try_bandix_plus(ctx: TcContext, direction: u8) -> Result<i32, i32> {
    let ifindex = unsafe { (*ctx.skb.skb).ifindex } as u32;
    let meta = match resolve_packet_meta(&ctx, direction) {
        Some(v) => v,
        None => return Ok(TC_ACT_UNSPEC),
    };

    if unsafe { DNS_ENABLED != 0 } {
        capture_dns_packet(&ctx, ifindex, direction, &meta);
    }

    let pkt_len = unsafe { (*ctx.skb.skb).len } as u64;

    let iface_key = InterfaceTrafficKey {
        ifindex,
        ip_version: meta.ip_version,
        direction,
        _pad: [0; 2],
    };
    bump_iface_counter(&iface_key, pkt_len);

    if let Some(mac) = meta.mac {
        let track = unsafe { TRACK_DEVICES.get(&ifindex) }.copied().unwrap_or(0);
        if track == 1 {
            let device_key = DeviceTrafficKey {
                ifindex,
                mac,
                ip_version: meta.ip_version,
                direction,
            };
            bump_device_counter(&device_key, pkt_len);
        }
    }

    Ok(TC_ACT_UNSPEC)
}

fn resolve_packet_meta(ctx: &TcContext, direction: u8) -> Option<PacketMeta> {
    if let Ok(eth) = ptr_at::<EthHdr>(ctx, 0) {
        let mut eth_proto = u16::from_be(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*eth).h_proto)) });
        let mut offset = core::mem::size_of::<EthHdr>();

        for _ in 0..2 {
            if eth_proto == ETH_P_8021Q || eth_proto == ETH_P_8021AD {
                if let Ok(vlan) = ptr_at::<VlanHdr>(ctx, offset) {
                    eth_proto = u16::from_be(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*vlan).encapsulated_proto)) });
                    offset += core::mem::size_of::<VlanHdr>();
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        if let Some(ip_version) = resolve_ip_version_from_eth(ctx, eth_proto, offset) {
            if is_management_packet(ctx, direction, eth_proto, offset) {
                return None;
            }
            let h_dest = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*eth).h_dest)) };
            let mac = match direction {
                x if x == TrafficDirection::Ingress as u8 => {
                    if (h_dest[0] & 0x01) != 0 {
                        // Multicast or broadcast packet (I/G bit set in destination MAC)
                        Some(h_dest)
                    } else {
                        Some(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*eth).h_source)) })
                    }
                }
                _ => Some(h_dest),
            };
            let ip_offset = if eth_proto == ETH_P_PPP_SES {
                offset + core::mem::size_of::<PppoeSessionHdr>()
            } else {
                offset
            };
            return Some(PacketMeta {
                ip_version,
                mac,
                ip_offset: ip_offset as u16,
            });
        }
    }

    // L3-style interfaces (e.g. ppp/tun/wireguard) may have no Ethernet header.
    if let Some(ip_version) = resolve_ip_version_from_l3(ctx, 0) {
        let protocol = if ip_version == IpVersion::V4 as u8 { ETH_P_IP } else { ETH_P_IPV6 };
        if is_management_packet(ctx, direction, protocol, 0) {
            return None;
        }
        return Some(PacketMeta {
            ip_version,
            mac: None,
            ip_offset: 0,
        });
    }
    if let Some(ip_version) = resolve_ip_version_from_ppp(ctx) {
        let protocol = if ip_version == IpVersion::V4 as u8 { ETH_P_IP } else { ETH_P_IPV6 };
        if is_management_packet(ctx, direction, protocol, 2) {
            return None;
        }
        return Some(PacketMeta {
            ip_version,
            mac: None,
            ip_offset: 2,
        });
    }
    None
}

fn capture_dns_packet(ctx: &TcContext, ifindex: u32, direction: u8, meta: &PacketMeta) {
    let packet_len = ctx.len() as usize;
    // Keep the helper's dynamic length strictly nonzero. The verifier does
    // not infer this from the DNS parser's packet-bound checks.
    if packet_len == 0 || packet_len > DNS_PACKET_MAX_BYTES {
        return;
    }
    let ip_offset = meta.ip_offset as usize;
    if !is_dns_packet(ctx, ip_offset, meta.ip_version, packet_len) {
        return;
    }

    let capture_len = packet_len as u32;
    let Some(mut entry) = DNS_DATA.reserve::<DnsPacketEvent>(0) else {
        return;
    };

    let entry_ptr = entry.as_mut_ptr() as *mut u8;
    let packet_ptr = unsafe { entry_ptr.add(core::mem::size_of::<DnsPacketHeader>()) };
    // Call the helper with the already-bounded skb length. TcContext::load_bytes
    // recomputes min(skb.len(), dst.len()), which leaves zero in the verifier's
    // range and is rejected by some target kernels.
    let load_result = unsafe { aya_ebpf::helpers::generated::bpf_skb_load_bytes(ctx.skb.skb.cast(), 0, packet_ptr.cast(), capture_len) };
    if load_result != 0 {
        entry.discard(0);
        return;
    }

    let (mac, has_mac) = match meta.mac {
        Some(mac) => (mac, 1),
        None => ([0; 6], 0),
    };
    let header = DnsPacketHeader {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        ifindex,
        captured_len: capture_len,
        ip_offset: meta.ip_offset,
        ip_version: meta.ip_version,
        direction,
        mac,
        has_mac,
        _pad: 0,
    };
    unsafe { core::ptr::write_unaligned(entry_ptr as *mut DnsPacketHeader, header) };
    entry.submit(0);
}

fn is_dns_packet(ctx: &TcContext, ip_offset: usize, ip_version: u8, packet_len: usize) -> bool {
    let (protocol, transport_offset, ip_end) = if ip_version == IpVersion::V4 as u8 {
        let Ok(ip) = ptr_at::<Ipv4Hdr>(ctx, ip_offset) else { return false };
        let ihl_ver = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip).ihl_ver)) };
        let ihl = ((ihl_ver & 0x0f) as usize) * 4;
        if (ihl_ver >> 4) != 4 || ihl < core::mem::size_of::<Ipv4Hdr>() || ip_offset + ihl > packet_len {
            return false;
        }
        let total_len = u16::from_be(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip).tot_len)) }) as usize;
        if total_len < ihl || ip_offset + total_len > packet_len {
            return false;
        }
        let fragment_offset = u16::from_be(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip).frag_off)) });
        if fragment_offset & 0x3fff != 0 {
            return false;
        }
        let protocol = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip).protocol)) };
        (protocol, ip_offset + ihl, ip_offset + total_len)
    } else if ip_version == IpVersion::V6 as u8 {
        let Ok(ip) = ptr_at::<Ipv6Hdr>(ctx, ip_offset) else { return false };
        let version_flow = u32::from_be(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip).version_flow)) });
        if (version_flow >> 28) != 6 || ip_offset + core::mem::size_of::<Ipv6Hdr>() > packet_len {
            return false;
        }
        let payload_len = u16::from_be(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip).payload_len)) }) as usize;
        let ip_end = ip_offset + core::mem::size_of::<Ipv6Hdr>() + payload_len;
        if ip_end > packet_len {
            return false;
        }
        let mut protocol = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip).next_header)) };
        let mut transport_offset = ip_offset + core::mem::size_of::<Ipv6Hdr>();
        // Follow the bounded IPv6 extension-header chain so normal DNS over
        // IPv6 is not missed when options or AH headers are present.
        for _ in 0..6 {
            if protocol == IPPROTO_UDP || protocol == IPPROTO_TCP {
                break;
            }
            if protocol == 44 || protocol == 50 {
                // Fragmented or ESP packets cannot be decoded as a complete
                // DNS message from one TC skb.
                return false;
            }
            let extension_len = match protocol {
                0 | 43 | 60 | 135 | 139 | 140 => {
                    let Ok(next) = ctx.load::<u8>(transport_offset) else { return false };
                    let Ok(length) = ctx.load::<u8>(transport_offset + 1) else { return false };
                    protocol = next;
                    (length as usize + 1) * 8
                }
                51 => {
                    let Ok(next) = ctx.load::<u8>(transport_offset) else { return false };
                    let Ok(length) = ctx.load::<u8>(transport_offset + 1) else { return false };
                    protocol = next;
                    (length as usize + 2) * 4
                }
                _ => return false,
            };
            if extension_len < 8 || transport_offset + extension_len > ip_end {
                return false;
            }
            transport_offset += extension_len;
        }
        if protocol != IPPROTO_UDP && protocol != IPPROTO_TCP {
            return false;
        }
        (protocol, transport_offset, ip_end)
    } else {
        return false;
    };

    if protocol != IPPROTO_UDP && protocol != IPPROTO_TCP {
        return false;
    }

    let (dns_offset, dns_end) = if protocol == IPPROTO_UDP {
        let Ok(udp) = ptr_at::<UdpHdr>(ctx, transport_offset) else { return false };
        let source = u16::from_be(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*udp).source)) });
        let destination = u16::from_be(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*udp).dest)) });
        if source != DNS_PORT && destination != DNS_PORT {
            return false;
        }
        let udp_len = u16::from_be(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*udp).len)) }) as usize;
        if udp_len < core::mem::size_of::<UdpHdr>() + 12 || transport_offset + udp_len > ip_end {
            return false;
        }
        (transport_offset + core::mem::size_of::<UdpHdr>(), transport_offset + udp_len)
    } else {
        let Ok(tcp) = ptr_at::<TcpHdr>(ctx, transport_offset) else { return false };
        let source = u16::from_be(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*tcp).source)) });
        let destination = u16::from_be(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*tcp).dest)) });
        if source != DNS_PORT && destination != DNS_PORT {
            return false;
        }
        let offset_flags = u16::from_be(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*tcp).offset_flags)) });
        let tcp_header_len = ((offset_flags >> 12) as usize) * 4;
        let length_offset = transport_offset + tcp_header_len;
        if tcp_header_len < core::mem::size_of::<TcpHdr>() || length_offset + 2 > ip_end {
            return false;
        }
        let Some(dns_len) = packet_u16(ctx, length_offset).map(usize::from) else {
            return false;
        };
        // TCP DNS stream reassembly is not available in this TC hook. Ignore
        // messages split across skb fragments instead of forwarding partial
        // data to the userspace parser.
        if dns_len < 12 || length_offset + 2 + dns_len > ip_end {
            return false;
        }
        (length_offset + 2, length_offset + 2 + dns_len)
    };
    if dns_offset + 12 > dns_end {
        return false;
    }
    let Some(flags) = packet_u16(ctx, dns_offset + 2) else { return false };
    let Some(question_count) = packet_u16(ctx, dns_offset + 4) else {
        return false;
    };
    question_count > 0 && question_count <= 16 && ((flags >> 11) & 0x0f) <= 5
}

fn packet_u16(ctx: &TcContext, offset: usize) -> Option<u16> {
    ctx.load::<u16>(offset).ok().map(u16::from_be)
}

fn resolve_ip_version_from_eth(ctx: &TcContext, eth_proto: u16, payload_offset: usize) -> Option<u8> {
    match eth_proto {
        ETH_P_IP => Some(IpVersion::V4 as u8),
        ETH_P_IPV6 => Some(IpVersion::V6 as u8),
        ETH_P_PPP_SES => {
            let pppoe = ptr_at::<PppoeSessionHdr>(ctx, payload_offset).ok()?;
            let ppp_proto = u16::from_be(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*pppoe).ppp_proto)) });
            match ppp_proto {
                PPP_PROTO_IP => Some(IpVersion::V4 as u8),
                PPP_PROTO_IPV6 => Some(IpVersion::V6 as u8),
                _ => None,
            }
        }
        _ => None,
    }
}

fn resolve_ip_version_from_l3(ctx: &TcContext, offset: usize) -> Option<u8> {
    let first2 = ptr_at::<u16>(ctx, offset).ok()?;
    let first2 = u16::from_be(unsafe { core::ptr::read_unaligned(first2) });
    let version = (first2 >> 12) as u8;
    match version {
        4 => Some(IpVersion::V4 as u8),
        6 => Some(IpVersion::V6 as u8),
        _ => None,
    }
}

fn resolve_ip_version_from_ppp(ctx: &TcContext) -> Option<u8> {
    if let Ok(proto_ptr) = ptr_at::<u16>(ctx, 0) {
        let proto = u16::from_be(unsafe { core::ptr::read_unaligned(proto_ptr) });
        match proto {
            PPP_PROTO_IP => return Some(IpVersion::V4 as u8),
            PPP_PROTO_IPV6 => return Some(IpVersion::V6 as u8),
            _ => {}
        }
        // Protocol field + L3 payload.
        if let Some(ip_version) = resolve_ip_version_from_l3(ctx, 2) {
            return Some(ip_version);
        }
    }
    None
}

fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

fn bump_iface_counter(key: &InterfaceTrafficKey, bytes: u64) {
    unsafe {
        if let Some(value) = IFACE_TRAFFIC_STATS.get_ptr_mut(key) {
            (*value).packets = (*value).packets.saturating_add(1);
            (*value).bytes = (*value).bytes.saturating_add(bytes);
            return;
        }

        let value = TrafficValue { packets: 1, bytes };
        let _ = IFACE_TRAFFIC_STATS.insert(key, &value, 0);
    }
}

fn bump_device_counter(key: &DeviceTrafficKey, bytes: u64) {
    unsafe {
        if let Some(value) = DEVICE_TRAFFIC_STATS.get_ptr_mut(key) {
            (*value).packets = (*value).packets.saturating_add(1);
            (*value).bytes = (*value).bytes.saturating_add(bytes);
            return;
        }

        let value = TrafficValue { packets: 1, bytes };
        if DEVICE_TRAFFIC_STATS.insert(key, &value, 0).is_err() {
            bump_device_insert_failure_count();
        }
    }
}

fn bump_device_insert_failure_count() {
    let key = 0u32;
    unsafe {
        if let Some(value) = DEVICE_TRAFFIC_INSERT_FAILURES.get_ptr_mut(&key) {
            *value = (*value).saturating_add(1);
        } else {
            let initial = 1u64;
            let _ = DEVICE_TRAFFIC_INSERT_FAILURES.insert(&key, &initial, 0);
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

#[map]
static ECM_TRAFFIC_STATS: PerCpuHashMap<EcmTrafficKey, TrafficValue> = PerCpuHashMap::with_max_entries(ECM_MAX_ENTRIES, 0);

#[kprobe]
pub fn ecm_bandix_sync_hook(ctx: ProbeContext) -> u32 {
    let ip: u32 = ctx.arg(0).unwrap_or(0);
    let tx_bytes: u64 = ctx.arg(1).unwrap_or(0);
    let rx_bytes: u64 = ctx.arg(2).unwrap_or(0);
    let tx_pkts: u64 = ctx.arg(3).unwrap_or(0);
    let rx_pkts: u64 = ctx.arg(4).unwrap_or(0);

    if ip == 0 || (tx_bytes == 0 && rx_bytes == 0) {
        return 0;
    }

    if tx_bytes > 0 {
        let key = EcmTrafficKey {
            ip: [ip, 0, 0, 0],
            ip_version: 4,
            direction: TrafficDirection::Egress as u8,
            pad: [0; 2],
        };
        if let Some(val) = unsafe { ECM_TRAFFIC_STATS.get_ptr_mut(&key) } {
            unsafe {
                (*val).packets += tx_pkts;
                (*val).bytes += tx_bytes;
            }
        } else {
            let val = TrafficValue {
                packets: tx_pkts,
                bytes: tx_bytes,
            };
            let _ = unsafe { ECM_TRAFFIC_STATS.insert(&key, &val, 0) };
        }
    }

    if rx_bytes > 0 {
        let key = EcmTrafficKey {
            ip: [ip, 0, 0, 0],
            ip_version: 4,
            direction: TrafficDirection::Ingress as u8,
            pad: [0; 2],
        };
        if let Some(val) = unsafe { ECM_TRAFFIC_STATS.get_ptr_mut(&key) } {
            unsafe {
                (*val).packets += rx_pkts;
                (*val).bytes += rx_bytes;
            }
        } else {
            let val = TrafficValue {
                packets: rx_pkts,
                bytes: rx_bytes,
            };
            let _ = unsafe { ECM_TRAFFIC_STATS.insert(&key, &val, 0) };
        }
    }

    0
}

#[kprobe]
pub fn ecm_bandix_ipv6_sync_hook(ctx: ProbeContext) -> u32 {
    let ip_ptr: *const [u32; 4] = ctx.arg(0).unwrap_or(core::ptr::null());
    let tx_bytes: u64 = ctx.arg(1).unwrap_or(0);
    let rx_bytes: u64 = ctx.arg(2).unwrap_or(0);
    let tx_pkts: u64 = ctx.arg(3).unwrap_or(0);
    let rx_pkts: u64 = ctx.arg(4).unwrap_or(0);

    if ip_ptr.is_null() || (tx_bytes == 0 && rx_bytes == 0) {
        return 0;
    }

    let ip = match unsafe { bpf_probe_read_kernel(ip_ptr) } {
        Ok(val) => val,
        Err(_) => return 0,
    };
    if tx_bytes > 0 {
        let key = EcmTrafficKey {
            ip,
            ip_version: 6,
            direction: TrafficDirection::Egress as u8,
            pad: [0; 2],
        };
        if let Some(val) = unsafe { ECM_TRAFFIC_STATS.get_ptr_mut(&key) } {
            unsafe {
                (*val).packets += tx_pkts;
                (*val).bytes += tx_bytes;
            }
        } else {
            let val = TrafficValue {
                packets: tx_pkts,
                bytes: tx_bytes,
            };
            let _ = unsafe { ECM_TRAFFIC_STATS.insert(&key, &val, 0) };
        }
    }

    if rx_bytes > 0 {
        let key = EcmTrafficKey {
            ip,
            ip_version: 6,
            direction: TrafficDirection::Ingress as u8,
            pad: [0; 2],
        };
        if let Some(val) = unsafe { ECM_TRAFFIC_STATS.get_ptr_mut(&key) } {
            unsafe {
                (*val).packets += rx_pkts;
                (*val).bytes += rx_bytes;
            }
        } else {
            let val = TrafficValue {
                packets: rx_pkts,
                bytes: rx_bytes,
            };
            let _ = unsafe { ECM_TRAFFIC_STATS.insert(&key, &val, 0) };
        }
    }

    0
}
