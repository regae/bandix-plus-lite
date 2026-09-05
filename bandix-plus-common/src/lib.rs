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

#[cfg(feature = "user")]
unsafe impl Pod for InterfaceTrafficKey {}
#[cfg(feature = "user")]
unsafe impl Pod for DeviceTrafficKey {}
#[cfg(feature = "user")]
unsafe impl Pod for TrafficValue {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct EcmTrafficKey {
    pub ip: [u32; 4],
    pub ip_version: u8,
    pub direction: u8,
    pub pad: [u8; 2],
}

#[cfg(feature = "user")]
unsafe impl Pod for EcmTrafficKey {}
