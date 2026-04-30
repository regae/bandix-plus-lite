use std::collections::HashMap;
use std::net::IpAddr;

use crate::utils::system_utils::{self, InterfaceInfo, InterfaceRole};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceZone {
    Lan,
    Wan,
    Guest,
    Other,
}

#[derive(Debug, Clone)]
pub struct Interface {
    pub ifindex: u32,
    pub name: String,
    pub role: InterfaceRole,
    pub zone: InterfaceZone,
    pub parent_ifindex: Option<u32>,
    pub ipv4_cidrs: Vec<String>,
    pub ipv6_cidrs: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TopologySnapshot {
    by_ifindex: HashMap<u32, Interface>,
}

impl TopologySnapshot {
    /// 扫描系统网络接口，构建拓扑快照（Lan/Wan/Guest 等区域划分）。
    pub fn discover() -> anyhow::Result<Self> {
        let interfaces = system_utils::list_interfaces()?;
        let subnet_map = system_utils::list_interface_subnets()?;
        let mut ifindex_by_name = HashMap::new();
        for iface in &interfaces {
            ifindex_by_name.insert(iface.name.clone(), iface.ifindex);
        }

        let mut by_ifindex = HashMap::new();

        for iface in interfaces {
            let node = build_interface(&iface, &subnet_map, &ifindex_by_name);
            let has_ip = !node.ipv4_cidrs.is_empty() || !node.ipv6_cidrs.is_empty();
            if !node.role.is_included_in_topology(has_ip) {
                continue;
            }
            by_ifindex.insert(node.ifindex, node.clone());
        }

        Ok(Self { by_ifindex })
    }

    /// 返回所有接口，按 ifindex 排序。
    pub fn interfaces(&self) -> Vec<&Interface> {
        let mut v: Vec<_> = self.by_ifindex.values().collect();
        v.sort_by_key(|i| i.ifindex);
        v
    }

    /// 按 ifindex 查找接口。
    pub fn by_ifindex(&self, ifindex: u32) -> Option<&Interface> {
        self.by_ifindex.get(&ifindex)
    }

    /// 按内核接口名（`Interface::name`，与 overview 的 `ifname` 一致）解析 ifindex。
    pub fn ifindex_by_name(&self, name: &str) -> Option<u32> {
        let name = name.trim();
        if name.is_empty() {
            return None;
        }
        for iface in self.by_ifindex.values() {
            if iface.name == name {
                return Some(iface.ifindex);
            }
        }
        None
    }

    #[cfg(test)]
    pub fn from_interfaces(interfaces: Vec<Interface>) -> Self {
        let by_ifindex = interfaces.into_iter().map(|i| (i.ifindex, i)).collect();
        Self { by_ifindex }
    }
}

fn build_interface(iface: &InterfaceInfo, subnet_map: &HashMap<String, Vec<String>>, ifindex_by_name: &HashMap<String, u32>) -> Interface {
    let mut ipv4_cidrs = Vec::new();
    let mut ipv6_cidrs = Vec::new();

    if let Some(subnets) = subnet_map.get(&iface.name) {
        for cidr in subnets {
            if cidr.contains(':') {
                ipv6_cidrs.push(cidr.clone());
            } else {
                ipv4_cidrs.push(cidr.clone());
            }
        }
    }

    let zone = infer_zone(&iface.name, &ipv4_cidrs, &ipv6_cidrs);
    let parent_ifindex = infer_parent_ifindex(&iface.name, ifindex_by_name);

    Interface {
        ifindex: iface.ifindex,
        name: iface.name.clone(),
        role: iface.role,
        zone,
        parent_ifindex,
        ipv4_cidrs,
        ipv6_cidrs,
    }
}

pub(crate) fn infer_zone(ifname: &str, ipv4_cidrs: &[String], ipv6_cidrs: &[String]) -> InterfaceZone {
    let lower = ifname.to_ascii_lowercase();
    if lower.contains("wan") || lower.starts_with("pppoe") || lower.starts_with("wwan") {
        return InterfaceZone::Wan;
    }
    if lower.contains("guest") {
        return InterfaceZone::Guest;
    }
    if lower.contains("lan") {
        return InterfaceZone::Lan;
    }

    infer_zone_from_ip(ipv4_cidrs, ipv6_cidrs).unwrap_or(InterfaceZone::Other)
}

fn infer_zone_from_ip(ipv4_cidrs: &[String], ipv6_cidrs: &[String]) -> Option<InterfaceZone> {
    let mut saw_internal = false;
    let mut saw_external = false;

    for cidr in ipv4_cidrs.iter().chain(ipv6_cidrs.iter()) {
        let Some(ip) = parse_ip_from_cidr(cidr) else {
            continue;
        };
        if is_internal_ip(ip) {
            saw_internal = true;
        } else if is_external_ip(ip) {
            saw_external = true;
        }
    }

    if saw_external {
        Some(InterfaceZone::Wan)
    } else if saw_internal {
        Some(InterfaceZone::Lan)
    } else {
        None
    }
}

fn parse_ip_from_cidr(cidr: &str) -> Option<IpAddr> {
    let ip = cidr.split('/').next()?.trim();
    ip.parse().ok()
}

fn is_internal_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => v6.is_unique_local(),
    }
}

fn is_external_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !v4.is_private() && !v4.is_loopback() && !v4.is_link_local() && !v4.is_unspecified(),
        IpAddr::V6(v6) => {
            !v6.is_unique_local()
                && !v6.is_loopback()
                && !v6.is_unspecified()
                && !v6.is_multicast()
                && !v6.is_unicast_link_local()
        }
    }
}

/// 解析接口名（如 br-lan.1）获取父接口的 ifindex。
pub(crate) fn infer_parent_ifindex(ifname: &str, ifindex_by_name: &HashMap<String, u32>) -> Option<u32> {
    let base = ifname.split('.').next()?;
    if base == ifname {
        return None;
    }
    ifindex_by_name.get(base).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infer_zone_eth0_other() {
        assert_eq!(infer_zone("eth0", &[], &[]), InterfaceZone::Other);
    }

    #[test]
    fn infer_zone_br_lan() {
        assert_eq!(infer_zone("br-lan", &[], &[]), InterfaceZone::Lan);
    }

    #[test]
    fn infer_zone_br_guest_name_priority_guest() {
        assert_eq!(infer_zone("br-guest", &[], &[]), InterfaceZone::Guest);
    }

    #[test]
    fn infer_zone_br_prefix_no_keyword_other() {
        assert_eq!(infer_zone("br-home", &[], &[]), InterfaceZone::Other);
    }

    #[test]
    fn infer_zone_pppoe_wan() {
        assert_eq!(infer_zone("pppoe-wan", &[], &[]), InterfaceZone::Wan);
    }

    #[test]
    fn infer_zone_guest0() {
        assert_eq!(infer_zone("guest0", &[], &[]), InterfaceZone::Guest);
    }

    #[test]
    fn infer_zone_ip_private_fallback_lan() {
        let v4 = vec!["192.168.50.1/24".to_string()];
        assert_eq!(infer_zone("eth2", &v4, &[]), InterfaceZone::Lan);
    }

    #[test]
    fn infer_zone_ip_public_fallback_wan() {
        let v4 = vec!["1.2.3.4/32".to_string()];
        assert_eq!(infer_zone("eth9", &v4, &[]), InterfaceZone::Wan);
    }

    #[test]
    fn infer_zone_name_priority_over_ip() {
        let v4 = vec!["192.168.10.1/24".to_string()];
        assert_eq!(infer_zone("wan0", &v4, &[]), InterfaceZone::Wan);
    }

    #[test]
    fn infer_parent_ifindex_with_dot() {
        let mut map = HashMap::new();
        map.insert("br-lan".to_string(), 5u32);
        assert_eq!(infer_parent_ifindex("br-lan.1", &map), Some(5));
    }

    #[test]
    fn infer_parent_ifindex_no_dot() {
        let map = HashMap::new();
        assert_eq!(infer_parent_ifindex("eth0", &map), None);
    }
}
