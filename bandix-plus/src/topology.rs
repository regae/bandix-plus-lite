use std::collections::HashMap;

use crate::utils::system_utils::{self, InterfaceInfo};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceRole {
    Physical,
    Logical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceZone {
    Lan,
    Wan,
    Guest,
    Other,
}

#[derive(Debug, Clone)]
pub struct LogicalInterface {
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
    by_ifindex: HashMap<u32, LogicalInterface>,
}

impl TopologySnapshot {
    /// 扫描系统网络接口，构建逻辑接口拓扑快照（Lan/Wan/Guest 等区域划分）。
    pub fn discover() -> anyhow::Result<Self> {
        let interfaces = system_utils::list_interfaces()?;
        let subnet_map = system_utils::list_interface_subnets()?;
        let mut ifindex_by_name = HashMap::new();
        for iface in &interfaces {
            ifindex_by_name.insert(iface.name.clone(), iface.ifindex);
        }

        let mut by_ifindex = HashMap::new();

        for iface in interfaces {
            let node = build_logical_interface(&iface, &subnet_map, &ifindex_by_name);
            if node.role != InterfaceRole::Logical {
                continue;
            }
            by_ifindex.insert(node.ifindex, node.clone());
        }

        Ok(Self { by_ifindex })
    }

    /// 返回所有逻辑接口，按 ifindex 排序。
    pub fn logical_interfaces(&self) -> Vec<&LogicalInterface> {
        let mut v: Vec<_> = self.by_ifindex.values().collect();
        v.sort_by_key(|i| i.ifindex);
        v
    }

    /// 按 ifindex 查找逻辑接口。
    pub fn by_ifindex(&self, ifindex: u32) -> Option<&LogicalInterface> {
        self.by_ifindex.get(&ifindex)
    }
}

/// 根据物理接口信息与子网配置，构建逻辑接口节点。
fn build_logical_interface(
    iface: &InterfaceInfo,
    subnet_map: &HashMap<String, Vec<String>>,
    ifindex_by_name: &HashMap<String, u32>,
) -> LogicalInterface {
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

    let role = if iface.name != "lo" && (!ipv4_cidrs.is_empty() || !ipv6_cidrs.is_empty()) {
        InterfaceRole::Logical
    } else {
        InterfaceRole::Physical
    };

    let zone = infer_zone(&iface.name);
    let parent_ifindex = infer_parent_ifindex(&iface.name, ifindex_by_name);

    LogicalInterface {
        ifindex: iface.ifindex,
        name: iface.name.clone(),
        role,
        zone,
        parent_ifindex,
        ipv4_cidrs,
        ipv6_cidrs,
    }
}

/// 根据接口名推断所属区域（Wan/Lan/Guest/Other）。
fn infer_zone(ifname: &str) -> InterfaceZone {
    let lower = ifname.to_ascii_lowercase();
    if lower.contains("wan") || lower.starts_with("pppoe") || lower.starts_with("wwan") {
        InterfaceZone::Wan
    } else if lower.contains("guest") {
        InterfaceZone::Guest
    } else if lower.contains("lan") || lower.starts_with("br-") {
        InterfaceZone::Lan
    } else {
        InterfaceZone::Other
    }
}

/// 解析接口名（如 br-lan.1）获取父接口的 ifindex。
fn infer_parent_ifindex(ifname: &str, ifindex_by_name: &HashMap<String, u32>) -> Option<u32> {
    let base = ifname.split('.').next()?;
    if base == ifname {
        return None;
    }
    ifindex_by_name.get(base).copied()
}
