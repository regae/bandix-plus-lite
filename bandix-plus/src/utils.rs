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

    use regex::Regex;
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

    /// 从 uevent 文件中读取 DEVTYPE 字段
    fn sysfs_uevent_devtype(path: &std::path::Path) -> Option<String> {
        let uevent = std::fs::read_to_string(path.join("uevent")).ok()?;
        for line in uevent.lines() {
            if let Some(val) = line.strip_prefix("DEVTYPE=") {
                return Some(val.trim().to_string());
            }
        }
        None
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

    #[derive(Debug, Clone, Default)]
    #[allow(dead_code)]
    pub struct InterfaceInfo {
        pub ifindex: u32,
        pub name: String,
        pub mac: Option<String>,
        pub operstate: Option<String>,
        pub mtu: Option<u32>,
        pub carrier: Option<bool>,
        pub if_type: Option<u16>,
        pub kind: Option<String>,
        pub flags: Option<u32>,
        pub ipv4: Vec<String>,
        pub ipv6: Vec<Ipv6AddrInfo>,
    }

    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    pub struct NeighborEntry {
        pub ip: String,
        pub dev: String,
        pub mac: [u8; 6],
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

        for args in [&["-4", "neigh", "show"][..], &["-6", "neigh", "show"][..]] {
            let output = Command::new("ip").args(args).output()?;
            if !output.status.success() {
                continue;
            }
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
                if !ip.contains(':') {
                    if let Some(cidrs) = subnet_map.get(&dev) {
                        let in_subnet = cidrs
                            .iter()
                            .filter(|c| !c.contains(':'))
                            .any(|cidr| ipv4_in_cidr(&ip, cidr));
                        if !in_subnet {
                            continue;
                        }
                    }
                }
                entries.push(FilteredNeighborEntry {
                    dev,
                    mac,
                    ip,
                    state: state.to_string(),
                });
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

    /// 从 /sys/class/net 和 ifaddrs 枚举所有网络接口及其信息
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
            let carrier = std::fs::read_to_string(path.join("carrier")).ok().and_then(|s| match s.trim() {
                "0" => Some(false),
                "1" => Some(true),
                _ => None,
            });
            let if_type = sysfs_opt_u32(&path, "type").map(|v| v as u16);
            let kind = sysfs_uevent_devtype(&path);
            map.insert(
                ifindex,
                InterfaceInfo {
                    ifindex,
                    name,
                    mac,
                    operstate,
                    mtu,
                    carrier,
                    if_type,
                    kind,
                    flags: None,
                    ipv4: Vec::new(),
                    ipv6: Vec::new(),
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
        let mut result: HashMap<String, Vec<String>> = HashMap::new();
        let output = Command::new("ip").args(["-o", "addr", "show"]).output()?;
        if !output.status.success() {
            anyhow::bail!("failed to run `ip -o addr show`");
        }
        let content = String::from_utf8_lossy(&output.stdout);
        let re = Regex::new(r"^\d+:\s+([^\s]+)\s+inet6?\s+([0-9a-fA-F\.:]+/\d+)\s+")?;
        for line in content.lines() {
            if let Some(caps) = re.captures(line) {
                let ifname = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
                let cidr = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
                if ifname.is_empty() || cidr.is_empty() {
                    continue;
                }
                result.entry(ifname.to_string()).or_default().push(cidr.to_string());
            }
        }
        Ok(result)
    }

    #[allow(dead_code)]
    pub fn list_neighbors() -> anyhow::Result<Vec<NeighborEntry>> {
        let output = Command::new("ip").args(["neigh", "show"]).output()?;
        if !output.status.success() {
            anyhow::bail!("failed to run `ip neigh show`");
        }
        let content = String::from_utf8_lossy(&output.stdout);
        let mut entries = Vec::new();
        let re = Regex::new(r"^([0-9a-fA-F\.:]+)\s+dev\s+([^\s]+)\s+lladdr\s+([0-9a-fA-F:]{17})\b")?;
        for line in content.lines() {
            if let Some(caps) = re.captures(line) {
                let ip = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
                let dev = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
                let mac = caps.get(3).map(|m| m.as_str()).unwrap_or_default();
                if ip.is_empty() || dev.is_empty() || mac.is_empty() {
                    continue;
                }
                if let Ok(mac) = mac_utils::from_str(mac) {
                    entries.push(NeighborEntry {
                        ip: ip.to_string(),
                        dev: dev.to_string(),
                        mac,
                    });
                }
            }
        }
        Ok(entries)
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
        let output = Command::new("ubus")
            .args(["call", "uci", "get", r#"{"config":"dhcp"}"#])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
        let values = json.get("values")?.as_object()?;
        let mut result = HashMap::new();
        for (_, entry) in values {
            let entry = entry.as_object()?;
            if entry.get(".type")?.as_str()? != "host" {
                continue;
            }
            let name = entry.get("name")?.as_str()?;
            if name.is_empty() {
                continue;
            }
            let mac_arr = entry.get("mac")?.as_array()?;
            for mac_val in mac_arr {
                let mac_str = mac_val.as_str()?;
                if let Ok(mac) = mac_utils::from_str(mac_str) {
                    result.insert(mac, name.to_string());
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
}
