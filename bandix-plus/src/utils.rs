pub mod mac_utils {
    /// 将 6 字节 MAC 地址格式化为 xx:xx:xx:xx:xx:xx 字符串
    pub fn to_string(mac: &[u8; 6]) -> String {
        mac.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":")
    }

    /// 从 xx:xx:xx:xx:xx:xx 字符串解析出 6 字节 MAC 地址
    pub fn from_str(s: &str) -> anyhow::Result<[u8; 6]> {
        let parts: Vec<&str> = s.splitn(6, ':').collect();
        if parts.len() != 6 {
            anyhow::bail!("invalid mac format: {}", s);
        }
        let mut mac = [0u8; 6];
        for (i, p) in parts.iter().enumerate() {
            mac[i] = u8::from_str_radix(p.trim(), 16).map_err(|_| anyhow::anyhow!("invalid hex in mac: {}", p))?;
        }
        Ok(mac)
    }
}

pub mod time_utils {
    use std::time::{SystemTime, UNIX_EPOCH};

    /// 返回当前时间戳（毫秒）
    pub fn now_millis() -> u64 {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(v) => v.as_millis() as u64,
            Err(_) => 0,
        }
    }
}

pub mod system_utils {

    use std::collections::{HashMap, HashSet};
    use std::net::Ipv4Addr;
    use std::net::Ipv6Addr;
    use std::path::Path;
    use std::process::Command;

    use crate::utils::mac_utils;

    /// 从 sysfs 路径下的指定文件读取 u32 值
    fn sysfs_opt_u32(path: &std::path::Path, file: &str) -> Option<u32> {
        std::fs::read_to_string(path.join(file))
            .ok()
            .and_then(|s| s.trim().parse().ok())
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Ipv6AddrType {
        Loopback,
        LinkLocal,
        UniqueLocal,
        GlobalUnicast,
        Multicast,
        Unspecified,
        Other,
    }

    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    pub struct Ipv6AddrInfo {
        pub addr: String,
        pub addr_type: Ipv6AddrType,
    }

    /// 判断 IPv6 地址类型（环回、链路本地、单播等）
    fn ipv6_addr_type(ip: Ipv6Addr) -> Ipv6AddrType {
        let segs = ip.segments();
        if ip.is_loopback() {
            return Ipv6AddrType::Loopback;
        }
        if ip.is_unspecified() {
            return Ipv6AddrType::Unspecified;
        }
        if (segs[0] & 0xff00) == 0xff00 {
            return Ipv6AddrType::Multicast;
        }
        if (segs[0] & 0xfe00) == 0xfe80 {
            return Ipv6AddrType::LinkLocal;
        }
        if (segs[0] & 0xfe00) == 0xfc00 {
            return Ipv6AddrType::UniqueLocal;
        }
        if (segs[0] & 0xe000) == 0x2000 {
            return Ipv6AddrType::GlobalUnicast;
        }
        Ipv6AddrType::Other
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub enum InterfaceRole {
        #[default]
        Other,
        Loopback,
        Ethernet,
        Wifi,
        Bridge,
        Tun,
    }

    impl InterfaceRole {
        pub fn is_included_in_topology(self, has_ip: bool) -> bool {
            match self {
                InterfaceRole::Loopback => false,
                InterfaceRole::Other => has_ip,
                _ => true,
            }
        }
    }
    fn infer_role_from_sysfs(ifname: &str) -> InterfaceRole {
        let type_path = format!("/sys/class/net/{}/type", ifname);
        let dev_type = std::fs::read_to_string(&type_path)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .unwrap_or(0);
            
        let is_bridge = std::path::Path::new(&format!("/sys/class/net/{}/bridge", ifname)).exists();
        if is_bridge {
            return InterfaceRole::Bridge;
        }
        
        let uevent = std::fs::read_to_string(&format!("/sys/class/net/{}/uevent", ifname)).unwrap_or_default();
        if uevent.contains("DEVTYPE=wlan") {
            return InterfaceRole::Wifi;
        }
        if uevent.contains("DEVTYPE=bridge") {
            return InterfaceRole::Bridge;
        }
        
        let is_tun = std::path::Path::new(&format!("/sys/class/net/{}/tun_flags", ifname)).exists();
        
        match dev_type {
            772 => InterfaceRole::Loopback,
            1 => {
                let lower = ifname.to_ascii_lowercase();
                if lower.starts_with("wifi") || lower.starts_with("wlan") {
                    InterfaceRole::Wifi
                } else {
                    InterfaceRole::Ethernet
                }
            }
            512 => InterfaceRole::Tun,
            65534 => InterfaceRole::Tun,
            _ if is_tun => InterfaceRole::Tun,
            _ => InterfaceRole::Other,
        }
    }


    
    
    #[derive(Debug, Clone, Default)]
    #[allow(dead_code)]
    pub struct InterfaceInfo {
        pub ifindex: u32,
        pub name: String,
        pub mac: Option<String>,
        pub operstate: Option<String>,
        pub mtu: Option<u32>,
        pub flags: Option<u32>,
        pub ipv4: Vec<String>,
        pub ipv6: Vec<Ipv6AddrInfo>,
        pub role: InterfaceRole,
    }

    #[derive(Debug, Clone)]
    pub struct FilteredNeighborEntry {
        pub dev: String,
        pub mac: [u8; 6],
        pub ip: String,
        pub state: String,
    }

    pub fn is_special_mac_address(mac: &[u8; 6]) -> bool {
        if mac == &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF] {
            return true;
        }
        if (mac[0] & 0x01) == 0x01 {
            return true;
        }
        if mac == &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00] {
            return true;
        }
        false
    }

    fn extract_neighbor_state(parts: &[&str]) -> Option<&'static str> {
        fn normalize(s: &str) -> String {
            s.trim_matches(|c: char| !c.is_ascii_alphabetic()).to_ascii_uppercase()
        }
        for p in parts.iter().rev() {
            match normalize(p).as_str() {
                "REACHABLE" => return Some("REACHABLE"),
                "STALE" => return Some("STALE"),
                "DELAY" => return Some("DELAY"),
                "PROBE" => return Some("PROBE"),
                "FAILED" => return Some("FAILED"),
                "NOARP" => return Some("NOARP"),
                "INCOMPLETE" => return Some("INCOMPLETE"),
                "INVALID" => return Some("INVALID"),
                _ => {}
            }
        }
        None
    }

    pub fn list_neighbors_filtered(
        monitor_devs: &[String],
        subnet_map: &HashMap<String, Vec<String>>,
    ) -> anyhow::Result<Vec<FilteredNeighborEntry>> {
        let monitor_set: HashSet<&str> = monitor_devs.iter().map(String::as_str).collect();
        let mut entries = Vec::new();

        // 1. IPv4 via /proc/net/arp (zero overhead)
        if let Ok(arp_content) = std::fs::read_to_string("/proc/net/arp") {
            for line in arp_content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 6 {
                    continue;
                }
                let ip = parts[0].to_string();
                let flags = parts[2];
                let mac_str = parts[3];
                let dev = parts[5].to_string();

                if flags == "0x0" || flags == "0x8" || mac_str == "00:00:00:00:00:00" {
                    continue;
                }
                if !monitor_set.contains(dev.as_str()) {
                    continue;
                }
                let mac = match super::mac_utils::from_str(mac_str) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                if is_special_mac_address(&mac) {
                    continue;
                }
                if let Some(cidrs) = subnet_map.get(&dev) {
                    let in_subnet = cidrs.iter().filter(|c| !c.contains(':')).any(|cidr| ipv4_in_cidr(&ip, cidr));
                    if !in_subnet {
                        continue;
                    }
                }
                entries.push(FilteredNeighborEntry {
                    ip,
                    mac,
                    dev,
                    state: "REACHABLE".to_string(),
                });
            }
        }

        // 2. IPv6 via ip command
        if let Ok(output) = Command::new("ip").args(["-6", "neigh", "show"]).output() {
            if output.status.success() {
                let content = String::from_utf8_lossy(&output.stdout);
                for line in content.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() < 5 {
                        continue;
                    }
                    let state = match extract_neighbor_state(&parts) {
                        Some(s) => s,
                        None => continue,
                    };
                    if matches!(state, "FAILED" | "NOARP" | "INCOMPLETE" | "INVALID") {
                        continue;
                    }
                    let dev_pos = parts.iter().position(|&x| x == "dev");
                    let lladdr_pos = parts.iter().position(|&x| x == "lladdr");
                    let (Some(dev_pos), Some(lladdr_pos)) = (dev_pos, lladdr_pos) else {
                        continue;
                    };
                    if dev_pos + 1 >= parts.len() || lladdr_pos + 1 >= parts.len() {
                        continue;
                    }
                    let ip = parts[0].to_string();
                    let dev = parts[dev_pos + 1].to_string();
                    let mac_str = parts[lladdr_pos + 1];

                    if !monitor_set.contains(dev.as_str()) {
                        continue;
                    }
                    let mac = match mac_utils::from_str(mac_str) {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    if is_special_mac_address(&mac) {
                        continue;
                    }
                    entries.push(FilteredNeighborEntry {
                        dev,
                        mac,
                        ip,
                        state: state.to_string(),
                    });
                }
            }
        }

        Ok(entries)
    }

    /// 检查指定的网络接口是否都存在于系统中
    pub fn check_interface_exist(iface: &Vec<String>) -> anyhow::Result<()> {
        let all_interface = list_interfaces()?;
        let name_list: Vec<&str> = all_interface.iter().map(|i| i.name.as_str()).collect();

        for name in iface {
            if !name_list.contains(&name.as_str()) {
                anyhow::bail!("interface not found: {}", name);
            }
        }

        Ok(())
    }

    /// 从 /sys/class/net、ifaddrs 和 ip -d link 枚举所有网络接口及其信息
    pub fn list_interfaces() -> anyhow::Result<Vec<InterfaceInfo>> {
        let mut map: HashMap<u32, InterfaceInfo> = HashMap::new();
        let net_dir = std::path::Path::new("/sys/class/net");

        for entry in std::fs::read_dir(net_dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
            let ifindex: u32 = match std::fs::read_to_string(path.join("ifindex")) {
                Ok(s) => match s.trim().parse() {
                    Ok(n) => n,
                    Err(_) => continue,
                },
                Err(_) => continue,
            };
            let address_path = path.join("address");
            let mac = std::fs::read_to_string(&address_path)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .and_then(|s| mac_utils::from_str(&s).ok().map(|m| mac_utils::to_string(&m)));
            let operstate = std::fs::read_to_string(path.join("operstate"))
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            let mtu = sysfs_opt_u32(&path, "mtu");
            let role = infer_role_from_sysfs(&name);
            map.insert(
                ifindex,
                InterfaceInfo {
                    ifindex,
                    name,
                    mac,
                    operstate,
                    mtu,
                    flags: None,
                    ipv4: Vec::new(),
                    ipv6: Vec::new(),
                    role,
                },
            );
        }

        if let Ok(addrs) = nix::ifaddrs::getifaddrs() {
            for ifaddr in addrs {
                let ifindex = map
                    .values()
                    .find(|info| info.name == ifaddr.interface_name)
                    .map(|info| info.ifindex);
                let Some(ifindex) = ifindex else { continue };
                let Some(info) = map.get_mut(&ifindex) else { continue };
                if info.flags.is_none() {
                    info.flags = Some(ifaddr.flags.bits() as u32);
                }
                let Some(addr) = ifaddr.address else { continue };
                if let Some(sin) = addr.as_sockaddr_in() {
                    let ip = sin.ip().to_string();
                    if !info.ipv4.contains(&ip) {
                        info.ipv4.push(ip);
                    }
                } else if let Some(sin6) = addr.as_sockaddr_in6() {
                    let ip = sin6.ip();
                    let ip_str = ip.to_string();
                    let addr_type = ipv6_addr_type(ip);
                    if !info.ipv6.iter().any(|a| a.addr == ip_str) {
                        info.ipv6.push(Ipv6AddrInfo { addr: ip_str, addr_type });
                    }
                }
            }
        }

        let mut list: Vec<_> = map.into_values().collect();
        list.sort_by_key(|i| i.ifindex);
        Ok(list)
    }

    /// 通过 `ip addr show` 获取各接口的 IPv4/IPv6 子网 CIDR
    pub fn list_interface_subnets() -> anyhow::Result<HashMap<String, Vec<String>>> {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        if let Ok(addrs) = nix::ifaddrs::getifaddrs() {
            for ifaddr in addrs {
                let name = ifaddr.interface_name;
                if let (Some(addr), Some(mask)) = (ifaddr.address, ifaddr.netmask) {
                    if let (Some(sin), Some(min)) = (addr.as_sockaddr_in(), mask.as_sockaddr_in()) {
                        let ip = sin.ip();
                        let prefix = u32::from(min.ip()).count_ones();
                        map.entry(name.clone()).or_default().push(format!("{}/{}", ip, prefix));
                    } else if let (Some(sin6), Some(min6)) = (addr.as_sockaddr_in6(), mask.as_sockaddr_in6()) {
                        let ip = sin6.ip();
                        let prefix = u128::from_be_bytes(min6.ip().octets()).count_ones();
                        map.entry(name.clone()).or_default().push(format!("{}/{}", ip, prefix));
                    }
                }
            }
        }
        Ok(map)
    }

    /// 读取 OpenWrt firewall zone，并将逻辑网络解析到实际内核设备名。
    ///
    /// 例如 firewall zone 的 `network = lan` 会通过
    /// `network.interface dump` 解析为 `br-lan -> lan`。
    pub fn list_firewall_zones_by_device() -> anyhow::Result<HashMap<String, String>> {
        let firewall_output = Command::new("ubus")
            .args(["call", "uci", "get", r#"{"config":"firewall"}"#])
            .output()?;
        if !firewall_output.status.success() {
            anyhow::bail!("failed to read firewall configuration from ubus");
        }

        let network_output = Command::new("ubus").args(["call", "network.interface", "dump"]).output()?;
        if !network_output.status.success() {
            anyhow::bail!("failed to read network interfaces from ubus");
        }

        let firewall: serde_json::Value = serde_json::from_slice(&firewall_output.stdout)?;
        let network: serde_json::Value = serde_json::from_slice(&network_output.stdout)?;
        parse_firewall_zones_by_device(&firewall, &network)
    }

    pub(super) fn parse_firewall_zones_by_device(
        firewall: &serde_json::Value,
        network: &serde_json::Value,
    ) -> anyhow::Result<HashMap<String, String>> {
        let mut devices_by_network: HashMap<String, Vec<String>> = HashMap::new();
        let interfaces = network
            .get("interface")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("network.interface dump has no interface array"))?;

        for interface in interfaces {
            let Some(network_name) = interface.get("interface").and_then(serde_json::Value::as_str) else {
                continue;
            };
            let network_name = network_name.trim();
            if network_name.is_empty() {
                continue;
            }

            let devices = devices_by_network.entry(network_name.to_string()).or_default();
            push_unique(devices, network_name);
            for key in ["l3_device", "device"] {
                if let Some(device) = interface.get(key).and_then(serde_json::Value::as_str) {
                    push_unique(devices, device);
                }
            }
        }

        let values = firewall
            .get("values")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| anyhow::anyhow!("firewall configuration has no values object"))?;
        let mut zones_by_device = HashMap::new();

        for entry in values.values() {
            if entry.get(".type").and_then(serde_json::Value::as_str) != Some("zone") {
                continue;
            }
            let Some(zone_name) = entry.get("name").and_then(serde_json::Value::as_str) else {
                continue;
            };
            let zone_name = zone_name.trim();
            if zone_name.is_empty() {
                continue;
            }

            for network_name in json_string_values(entry.get("network")) {
                if let Some(devices) = devices_by_network.get(network_name) {
                    for device in devices {
                        zones_by_device.entry(device.clone()).or_insert_with(|| zone_name.to_string());
                    }
                } else {
                    zones_by_device
                        .entry(network_name.to_string())
                        .or_insert_with(|| zone_name.to_string());
                }
            }
            for device in json_string_values(entry.get("device")) {
                zones_by_device
                    .entry(device.to_string())
                    .or_insert_with(|| zone_name.to_string());
            }
        }

        Ok(zones_by_device)
    }

    fn json_string_values(value: Option<&serde_json::Value>) -> Vec<&str> {
        match value {
            Some(serde_json::Value::String(value)) => {
                let value = value.trim();
                if value.is_empty() {
                    Vec::new()
                } else {
                    vec![value]
                }
            }
            Some(serde_json::Value::Array(values)) => values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .collect(),
            _ => Vec::new(),
        }
    }

    fn push_unique(values: &mut Vec<String>, value: &str) {
        let value = value.trim();
        if !value.is_empty() && !values.iter().any(|item| item == value) {
            values.push(value.to_string());
        }
    }

    /// MAC -> hostname：合并 ubus uci dhcp 与 /tmp/dhcp.leases，同一 MAC 时优先 ubus
    pub fn list_hostname_by_mac() -> HashMap<[u8; 6], String> {
        let mut result = parse_dnsmasq_lease_file("/tmp/dhcp.leases").unwrap_or_default();
        if let Some(ubus_map) = parse_hostname_from_ubus_uci_dhcp() {
            for (mac, name) in ubus_map {
                result.insert(mac, name);
            }
        }
        result
    }

    fn parse_hostname_from_ubus_uci_dhcp() -> Option<HashMap<[u8; 6], String>> {
        let content = std::fs::read_to_string("/etc/config/dhcp").ok()?;
        let mut result = HashMap::new();
        
        let mut in_host = false;
        let mut current_macs = Vec::new();
        let mut current_name: Option<String> = None;

        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("config host") {
                if in_host {
                    if let Some(name) = current_name.take() {
                        for mac in current_macs.drain(..) {
                            result.insert(mac, name.clone());
                        }
                    }
                }
                in_host = true;
                current_macs.clear();
                current_name = None;
            } else if line.starts_with("config ") || line.starts_with("package ") {
                if in_host {
                    if let Some(name) = current_name.take() {
                        for mac in current_macs.drain(..) {
                            result.insert(mac, name.clone());
                        }
                    }
                }
                in_host = false;
            } else if in_host && (line.starts_with("option ") || line.starts_with("list ")) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let key = parts[1];
                    let mut val = parts[2..].join(" ");
                    if val.starts_with('\'') && val.ends_with('\'') && val.len() >= 2 {
                        val = val[1..val.len()-1].to_string();
                    } else if val.starts_with('"') && val.ends_with('"') && val.len() >= 2 {
                        val = val[1..val.len()-1].to_string();
                    }
                    if key == "mac" {
                        // Supports both space-separated "option mac" and multiple "list mac" lines
                        for mac_str in val.split_whitespace() {
                            if let Ok(mac) = mac_utils::from_str(mac_str) {
                                current_macs.push(mac);
                            }
                        }
                    } else if key == "name" {
                        current_name = Some(val);
                    }
                }
            }
        }
        
        if in_host {
            if let Some(name) = current_name.take() {
                for mac in current_macs.drain(..) {
                    result.insert(mac, name.clone());
                }
            }
        }

        Some(result)
    }

    fn parse_dnsmasq_lease_file(path: &str) -> Option<HashMap<[u8; 6], String>> {
        if !Path::new(path).exists() {
            return None;
        }
        let content = std::fs::read_to_string(path).ok()?;
        let mut result = HashMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }
            let mac = parts[1];
            let hostname = parts[3];
            if hostname.is_empty() || hostname == "*" {
                continue;
            }
            if let Ok(mac_arr) = mac_utils::from_str(mac) {
                result.insert(mac_arr, hostname.to_string());
            }
        }
        Some(result)
    }

    /// 判断 IPv4 地址是否属于指定 CIDR 子网
    pub fn ipv4_in_cidr(ip: &str, cidr: &str) -> bool {
        let (net_str, prefix_str) = match cidr.split_once('/') {
            Some(v) => v,
            None => return false,
        };
        let ip_addr = match ip.parse::<Ipv4Addr>() {
            Ok(v) => v,
            Err(_) => return false,
        };
        let net_addr = match net_str.parse::<Ipv4Addr>() {
            Ok(v) => v,
            Err(_) => return false,
        };
        let prefix = match prefix_str.parse::<u8>() {
            Ok(v) if v <= 32 => v,
            _ => return false,
        };
        let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
        (u32::from(ip_addr) & mask) == (u32::from(net_addr) & mask)
    }

    fn redact_ipv6_addr_part_keep_edge_chars(addr_part: &str) -> String {
        let chars: Vec<char> = addr_part.chars().collect();
        let n = chars.len();
        if n <= 8 {
            return chars.into_iter().map(|c| if c.is_ascii_hexdigit() { '*' } else { c }).collect();
        }
        (0..n)
            .map(|i| {
                let c = chars[i];
                if i < 4 || i >= n - 4 {
                    c
                } else if c.is_ascii_hexdigit() {
                    '*'
                } else {
                    c
                }
            })
            .collect()
    }

    /// IPv6 CIDR 脱敏后用于日志：`%` 前地址段保留前 4、后 4 个字符，中间十六进制改为 `*`；长度 ≤8 时中间无留白则整段十六进制全改 `*`。`/` 前缀与 `%` scope 原样保留。
    pub fn redact_ipv6_cidr_for_log(cidr: &str) -> String {
        let trimmed = cidr.trim();
        let (before_slash, slash_suffix) = match trimmed.split_once('/') {
            Some((a, p)) => (a, format!("/{}", p.trim())),
            None => (trimmed, String::new()),
        };
        let (addr_part, zone_suffix) = match before_slash.split_once('%') {
            Some((a, z)) => (a, format!("%{}", z)),
            None => (before_slash, String::new()),
        };
        let redacted_addr = redact_ipv6_addr_part_keep_edge_chars(addr_part);
        format!("{redacted_addr}{zone_suffix}{slash_suffix}")
    }
}

#[cfg(test)]
mod tests {
    use super::mac_utils;
    use super::system_utils;
    use super::system_utils::InterfaceRole;

    #[test]
    fn mac_to_string() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        assert_eq!(mac_utils::to_string(&mac), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn mac_from_str_valid() {
        let mac = mac_utils::from_str("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn mac_from_str_invalid() {
        assert!(mac_utils::from_str("aa:bb:cc").is_err());
        assert!(mac_utils::from_str("gg:bb:cc:dd:ee:ff").is_err());
        assert!(mac_utils::from_str("aa:bb:cc:dd:ee").is_err());
    }

    #[test]
    fn is_special_mac_address() {
        assert!(system_utils::is_special_mac_address(&[0; 6]));
        assert!(system_utils::is_special_mac_address(&[0xff; 6]));
        assert!(system_utils::is_special_mac_address(&[0x01, 0, 0, 0, 0, 0]));
        assert!(!system_utils::is_special_mac_address(&[0x02, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn ipv4_in_cidr() {
        assert!(system_utils::ipv4_in_cidr("192.168.1.100", "192.168.1.0/24"));
        assert!(!system_utils::ipv4_in_cidr("192.168.2.1", "192.168.1.0/24"));
        assert!(!system_utils::ipv4_in_cidr("192.168.1.1", "invalid"));
        assert!(!system_utils::ipv4_in_cidr("x.x.x.x", "192.168.1.0/24"));
    }

    #[test]
    fn interface_role_is_included_in_topology() {
        assert!(!InterfaceRole::Loopback.is_included_in_topology(true));
        assert!(!InterfaceRole::Loopback.is_included_in_topology(false));
        assert!(InterfaceRole::Ethernet.is_included_in_topology(true));
        assert!(!InterfaceRole::Ethernet.is_included_in_topology(false));
    }

    #[test]
    fn parse_firewall_zones_resolves_logical_networks_to_devices() {
        let firewall = serde_json::json!({
            "values": {
                "cfg_lan": { ".type": "zone", "name": "lan", "network": ["lan"] },
                "cfg_wan": { ".type": "zone", "name": "wan", "network": "wan", "device": ["eth2"] },
                "cfg_iot": { ".type": "zone", "name": "iot", "network": ["iot"] },
                "cfg_rule": { ".type": "rule", "name": "not-a-zone" }
            }
        });
        let network = serde_json::json!({
            "interface": [
                { "interface": "lan", "device": "br-lan", "l3_device": "br-lan" },
                { "interface": "wan", "device": "eth1", "l3_device": "pppoe-wan" },
                { "interface": "iot", "device": "br-iot", "l3_device": "br-iot" }
            ]
        });

        let zones = system_utils::parse_firewall_zones_by_device(&firewall, &network).unwrap();
        assert_eq!(zones.get("br-lan").map(String::as_str), Some("lan"));
        assert_eq!(zones.get("pppoe-wan").map(String::as_str), Some("wan"));
        assert_eq!(zones.get("eth1").map(String::as_str), Some("wan"));
        assert_eq!(zones.get("eth2").map(String::as_str), Some("wan"));
        assert_eq!(zones.get("br-iot").map(String::as_str), Some("iot"));
    }

    #[test]
    fn redact_ipv6_cidr_for_log_keeps_four_chars_each_end() {
        assert_eq!(
            system_utils::redact_ipv6_cidr_for_log("fe80::82af:caff:fe88:215a/64"),
            "fe80::****:****:****:215a/64"
        );
        assert_eq!(
            system_utils::redact_ipv6_cidr_for_log("2408:820c:a93a:2040::1/60"),
            "2408:****:****:***0::1/60"
        );
        assert_eq!(
            system_utils::redact_ipv6_cidr_for_log("2408:820c:a931:e11f:e9ae:4445:8d93:73bc/128"),
            "2408:****:****:****:****:****:****:73bc/128"
        );
        assert_eq!(system_utils::redact_ipv6_cidr_for_log("fe80::1%eth0"), "****::*%eth0");
    }
}
