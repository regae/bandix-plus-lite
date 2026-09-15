#![no_std]

#[cfg(feature = "user")]
use aya::Pod;

pub const DEVICE_TRAFFIC_MAX_ENTRIES: u32 = 8192;

/// Maximum frame bytes copied for a DNS packet event. Normal Ethernet frames
/// fit within this bound, including two VLAN headers and IPv6 headers.
pub const DNS_PACKET_MAX_BYTES: usize = 1600;

/// Metadata shared between the TC program and the DNS userspace reader.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DnsPacketHeader {
    pub timestamp_ns: u64,
    pub ifindex: u32,
    pub captured_len: u32,
    pub ip_offset: u16,
    pub ip_version: u8,
    pub direction: u8,
    /// Client-side MAC selected from packet direction; all zero if unavailable.
    pub mac: [u8; 6],
    pub has_mac: u8,
    pub _pad: u8,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpVersion {
    V4 = 4,
    V6 = 6,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrafficDirection {
    Ingress = 1,
    Egress = 2,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InterfaceTrafficKey {
    pub ifindex: u32,
    pub ip_version: u8,
    pub direction: u8,
    pub _pad: [u8; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DeviceTrafficKey {
    pub ifindex: u32,
    pub mac: [u8; 6],
    pub ip_version: u8,
    pub direction: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TrafficValue {
    pub packets: u64,
    pub bytes: u64,
}

#[cfg(feature = "user")]
unsafe impl Pod for InterfaceTrafficKey {}
#[cfg(feature = "user")]
unsafe impl Pod for DeviceTrafficKey {}
#[cfg(feature = "user")]
unsafe impl Pod for TrafficValue {}

#[cfg(feature = "user")]
unsafe impl Pod for DnsPacketHeader {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct EcmTrafficKey {
    pub ip: [u32; 4],
    pub ip_version: u8,
    pub direction: u8,
    pub pad: [u8; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RouterIpKey {
    pub ip: [u32; 4],
    pub ip_version: u8,
    pub _pad: [u8; 3],
}

#[cfg(feature = "user")]
unsafe impl Pod for EcmTrafficKey {}
#[cfg(feature = "user")]
unsafe impl Pod for RouterIpKey {}
