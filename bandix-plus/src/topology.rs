use std::collections::HashMap;

use crate::utils::system_utils::{self, InterfaceInfo, InterfaceRole};

#[derive(Debug, Clone)]
pub struct Interface {
    pub ifindex: u32,
    pub name: String,
    pub role: InterfaceRole,
    /// OpenWrt firewall 中配置的 zone 名称；未识别时为 `unknown`。
    pub zone: String,
    pub parent_ifindex: Option<u32>,
    pub ipv4_cidrs: Vec<String>,
    pub ipv6_cidrs: Vec<String>,
}

impl Interface {
    /// 返回界面和 API 使用的 zone 名称。
    pub fn zone_name(&self) -> &str {
        &self.zone
    }
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
        let firewall_zones = match system_utils::list_firewall_zones_by_device() {
            Ok(zones) => zones,
            Err(error) => {
                log::warn!("read firewall zones failed, interface zones will be unknown: {error}");
                HashMap::new()
            }
        };
        let mut ifindex_by_name = HashMap::new();
        for iface in &interfaces {
            ifindex_by_name.insert(iface.name.clone(), iface.ifindex);
        }

        let mut by_ifindex = HashMap::new();

        for iface in interfaces {
            let node = build_interface(&iface, &subnet_map, &ifindex_by_name, &firewall_zones);
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

fn build_interface(
    iface: &InterfaceInfo,
    subnet_map: &HashMap<String, Vec<String>>,
    ifindex_by_name: &HashMap<String, u32>,
    firewall_zones: &HashMap<String, String>,
) -> Interface {
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

    let parent_name = infer_parent_name(&iface.name);
    let parent_ifindex = parent_name.as_ref().and_then(|n| ifindex_by_name.get(n).copied());

    let mut zone = firewall_zones.get(&iface.name).cloned();
    if zone.is_none() {
        if let Some(pname) = &parent_name {
            zone = firewall_zones.get(pname).cloned();
        }
    }
    let zone = zone.unwrap_or_else(|| "unknown".to_string());

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


pub(crate) fn infer_parent_name(ifname: &str) -> Option<String> {
    if let Ok(master_path) = std::fs::read_link(format!("/sys/class/net/{}/master", ifname)) {
        if let Some(master_name) = master_path.file_name().and_then(|n| n.to_str()) {
            return Some(master_name.to_string());
        }
    }
    let base = ifname.split('.').next()?;
    if base != ifname {
        return Some(base.to_string());
    }
    None
}

fn resolve_zone(ifname: &str, firewall_zones: &std::collections::HashMap<String, String>) -> String {
    firewall_zones.get(ifname).cloned().unwrap_or_else(|| "unknown".to_string())
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
    fn firewall_zone_is_used_verbatim() {
        let zones = HashMap::from([("br-lan".to_string(), "wan".to_string())]);
        assert_eq!(resolve_zone("br-lan", &zones), "wan");
    }

    #[test]
    fn custom_firewall_zone_name_is_preserved() {
        let zones = HashMap::from([("br-iot".to_string(), "iot".to_string())]);
        assert_eq!(resolve_zone("br-iot", &zones), "iot");
    }

    #[test]
    fn interface_without_firewall_zone_is_unknown() {
        let zones = HashMap::new();
        assert_eq!(resolve_zone("br-lan", &zones), "unknown");
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
