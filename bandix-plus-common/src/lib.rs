#![no_std]

#[cfg(feature = "user")]
use aya::Pod;

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

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DeviceGlobalLimitKey {
    pub mac: [u8; 6],
    pub _pad: [u8; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DeviceIfaceLimitKey {
    pub ifindex: u32,
    pub mac: [u8; 6],
    pub _pad: [u8; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RateLimitValue {
    pub down_v4_bps: u64,
    pub down_v6_bps: u64,
    pub up_v4_bps: u64,
    pub up_v6_bps: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RateBucketValue {
    pub down_v4_tokens: u64,
    pub down_v6_tokens: u64,
    pub up_v4_tokens: u64,
    pub up_v6_tokens: u64,
    pub down_v4_last_refill_ns: u64,
    pub down_v6_last_refill_ns: u64,
    pub up_v4_last_refill_ns: u64,
    pub up_v6_last_refill_ns: u64,
}

#[cfg(feature = "user")]
unsafe impl Pod for InterfaceTrafficKey {}
#[cfg(feature = "user")]
unsafe impl Pod for DeviceTrafficKey {}
#[cfg(feature = "user")]
unsafe impl Pod for TrafficValue {}
#[cfg(feature = "user")]
unsafe impl Pod for DeviceGlobalLimitKey {}
#[cfg(feature = "user")]
unsafe impl Pod for DeviceIfaceLimitKey {}
#[cfg(feature = "user")]
unsafe impl Pod for RateLimitValue {}
#[cfg(feature = "user")]
unsafe impl Pod for RateBucketValue {}
