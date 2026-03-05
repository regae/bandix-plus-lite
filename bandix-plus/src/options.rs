use clap::Parser;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcOrder {
    First,
    Default,
    Last,
}

impl TcOrder {
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

    #[arg(
        long,
        default_value = "first",
        help = "TC order: first, default, last"
    )]
    pub tc_order: String,
}
