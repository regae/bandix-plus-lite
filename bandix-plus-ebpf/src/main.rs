#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_UNSPEC},
    helpers::{bpf_probe_read_kernel},
    macros::{classifier, kprobe, map},
    maps::{HashMap, LruPerCpuHashMap},
    programs::{ProbeContext, TcContext},
};
use bandix_plus_common::{
    DeviceTrafficKey, EcmTrafficKey, 
    InterfaceTrafficKey, IpVersion, TrafficDirection, TrafficValue,
};

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_P_PPP_SES: u16 = 0x8864;
const PPP_PROTO_IP: u16 = 0x0021;
const PPP_PROTO_IPV6: u16 = 0x0057;
const MAX_ENTRIES: u32 = 8192;
const BPS_DENOM_NS: u64 = 1_000_000_000;
const BURST_WINDOW_NS: u64 = 100_000_000; // 100ms burst cap
const INIT_WINDOW_NS: u64 = 50_000_000; // 50ms initial tokens
const RATE_SAFETY_PERCENT: u64 = 95; // reduce observed overshoot

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

#[map]
static CONFIG_MAP: HashMap<u32, u32> = HashMap::with_max_entries(1, 0);

fn is_local_ipv4(ctx: &TcContext) -> bool {
    if let Ok(eth) = ptr_at::<EthHdr>(ctx, 0) {
        let mut eth_proto = u16::from_be(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*eth).h_proto)) });
        let mut offset = core::mem::size_of::<EthHdr>();

        for _ in 0..2 {
            if eth_proto == 0x8100 || eth_proto == 0x88A8 {
                if let Ok(vlan) = ptr_at::<VlanHdr>(ctx, offset) {
                    eth_proto = u16::from_be(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*vlan).encapsulated_proto)) });
                    offset += core::mem::size_of::<VlanHdr>();
                } else {
                    return false;
                }
            } else {
                break;
            }
        }

        if eth_proto == ETH_P_PPP_SES {
            offset += core::mem::size_of::<PppoeSessionHdr>();
        } else if eth_proto != ETH_P_IP {
            return false;
        }

        if let Ok(ip) = ptr_at::<Ipv4Hdr>(ctx, offset) {
            let saddr = u32::from_be(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip).saddr)) });
            let daddr = u32::from_be(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip).daddr)) });
            
            if (saddr & 0xFFFF0000) == 0xC0A80000 && (daddr & 0xFFFF0000) == 0xC0A80000 {
                return true;
            }
        }
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
#[map]
static TRACK_DEVICES: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

#[map]
static IFACE_TRAFFIC_STATS: HashMap<InterfaceTrafficKey, TrafficValue> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[map]
static DEVICE_TRAFFIC_STATS: HashMap<DeviceTrafficKey, TrafficValue> = HashMap::with_max_entries(MAX_ENTRIES, 0);






fn try_bandix_plus(ctx: TcContext, direction: u8) -> Result<i32, i32> {
    let exclude_local = unsafe { CONFIG_MAP.get(&0) }.copied().unwrap_or(0);
    if exclude_local == 1 {
        if is_local_ipv4(&ctx) {
            return Ok(TC_ACT_UNSPEC);
        }
    }

    let meta = match resolve_packet_meta(&ctx, direction) {
        Some(v) => v,
        None => return Ok(TC_ACT_UNSPEC),
    };

    let ifindex = unsafe { (*ctx.skb.skb).ifindex } as u32;
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
            if eth_proto == 0x8100 || eth_proto == 0x88A8 {
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
            let mac = match direction {
                x if x == TrafficDirection::Ingress as u8 => {
                    Some(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*eth).h_source)) })
                }
                _ => Some(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*eth).h_dest)) }),
            };
            return Some(PacketMeta { ip_version, mac });
        }
    }

    // L3-style interfaces (e.g. ppp/tun/wireguard) may have no Ethernet header.
    if let Some(ip_version) = resolve_ip_version_from_l3(ctx, 0) {
        return Some(PacketMeta { ip_version, mac: None });
    }
    if let Some(ip_version) = resolve_ip_version_from_ppp(ctx) {
        return Some(PacketMeta { ip_version, mac: None });
    }
    None
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
        let _ = DEVICE_TRAFFIC_STATS.insert(key, &value, 0);
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
static ECM_TRAFFIC_STATS: LruPerCpuHashMap<EcmTrafficKey, TrafficValue> = LruPerCpuHashMap::with_max_entries(MAX_ENTRIES, 0);

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
        let key = EcmTrafficKey { ip: [ip, 0, 0, 0], ip_version: 4, direction: TrafficDirection::Egress as u8, pad: [0; 2] };
        if let Some(val) = unsafe { ECM_TRAFFIC_STATS.get_ptr_mut(&key) } {
            unsafe { 
                (*val).packets += tx_pkts;
                (*val).bytes += tx_bytes;
            }
        } else {
            let val = TrafficValue { packets: tx_pkts, bytes: tx_bytes };
            let _ = unsafe { ECM_TRAFFIC_STATS.insert(&key, &val, 0) };
        }
    }

    if rx_bytes > 0 {
        let key = EcmTrafficKey { ip: [ip, 0, 0, 0], ip_version: 4, direction: TrafficDirection::Ingress as u8, pad: [0; 2] };
        if let Some(val) = unsafe { ECM_TRAFFIC_STATS.get_ptr_mut(&key) } {
            unsafe { 
                (*val).packets += rx_pkts;
                (*val).bytes += rx_bytes;
            }
        } else {
            let val = TrafficValue { packets: rx_pkts, bytes: rx_bytes };
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
        let key = EcmTrafficKey { ip, ip_version: 6, direction: TrafficDirection::Egress as u8, pad: [0; 2] };
        if let Some(val) = unsafe { ECM_TRAFFIC_STATS.get_ptr_mut(&key) } {
            unsafe {
                (*val).packets += tx_pkts;
                (*val).bytes += tx_bytes;
            }
        } else {
            let val = TrafficValue { packets: tx_pkts, bytes: tx_bytes };
            let _ = unsafe { ECM_TRAFFIC_STATS.insert(&key, &val, 0) };
        }
    }

    if rx_bytes > 0 {
        let key = EcmTrafficKey { ip, ip_version: 6, direction: TrafficDirection::Ingress as u8, pad: [0; 2] };
        if let Some(val) = unsafe { ECM_TRAFFIC_STATS.get_ptr_mut(&key) } {
            unsafe {
                (*val).packets += rx_pkts;
                (*val).bytes += rx_bytes;
            }
        } else {
            let val = TrafficValue { packets: rx_pkts, bytes: rx_bytes };
            let _ = unsafe { ECM_TRAFFIC_STATS.insert(&key, &val, 0) };
        }
    }
    
    0
}
