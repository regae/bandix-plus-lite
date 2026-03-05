pub mod mac_utils {
    pub fn to_string(mac: &[u8; 6]) -> String {
        mac.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":")
    }

    pub fn to_string_upper(mac: &[u8; 6]) -> String {
        mac.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(":")
    }

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

pub mod system_utils {

    use regex::Regex;
    use std::collections::HashMap;
    use std::net::Ipv6Addr;
    use std::process::Command;

    use crate::utils::mac_utils;

    fn sysfs_opt_u32(path: &std::path::Path, file: &str) -> Option<u32> {
        std::fs::read_to_string(path.join(file))
            .ok()
            .and_then(|s| s.trim().parse().ok())
    }

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
    pub struct Ipv6AddrInfo {
        pub addr: String,
        pub addr_type: Ipv6AddrType,
    }

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
}
