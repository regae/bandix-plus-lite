use clap::Parser;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcOrder {
    First,
    Default,
    Last,
}

impl TcOrder {
    /// 将字符串解析为 TC 挂载顺序枚举。
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "first" => Some(Self::First),
            "default" => Some(Self::Default),
            "last" => Some(Self::Last),
            _ => None,
        }
    }
}

#[derive(Parser, Debug, Clone)]
#[command(about = "Network traffic monitoring based on eBPF for OpenWrt")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(author = "https://github.com/timsaya")]
pub struct Options {
    #[arg(short, long, help = "Network interface to monitor (can specify multiple times)")]
    pub iface: Vec<String>,

    #[arg(
        long,
        default_value = "info",
        help = "Log level: trace, debug, info, warn, error (default: info)"
    )]
    pub log_level: String,

    #[arg(long, default_value = "first", help = "TC order: first, default, last")]
    pub tc_order: String,

    #[arg(
        long,
        default_value_t = 10,
        help = "Traffic history window in minutes (default: 10)"
    )]
    pub history_window_minutes: u32,

    #[arg(long, default_value = "0.0.0.0:9911", help = "API server bind address")]
    pub api_bind: String,

    #[arg(
        long,
        default_value = "/usr/share/bandix-plus",
        help = "State directory for persisted policy/devices/traffic data"
    )]
    pub state_dir: String,
}

#[cfg(test)]
mod tests {
    use super::TcOrder;

    #[test]
    fn tc_order_parse_first() {
        assert_eq!(TcOrder::parse("first"), Some(TcOrder::First));
        assert_eq!(TcOrder::parse("FIRST"), Some(TcOrder::First));
    }

    #[test]
    fn tc_order_parse_default() {
        assert_eq!(TcOrder::parse("default"), Some(TcOrder::Default));
    }

    #[test]
    fn tc_order_parse_last() {
        assert_eq!(TcOrder::parse("last"), Some(TcOrder::Last));
    }

    #[test]
    fn tc_order_parse_invalid() {
        assert_eq!(TcOrder::parse("invalid"), None);
    }
}
