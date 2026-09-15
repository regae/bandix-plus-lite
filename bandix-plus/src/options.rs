use clap::Parser;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcOrder {
    First,
    Default,
    Last,
    Before,
    After,
}

impl TcOrder {
    /// 将字符串解析为 TC 挂载顺序枚举。
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "first" => Some(Self::First),
            "default" => Some(Self::Default),
            "last" => Some(Self::Last),
            "before" => Some(Self::Before),
            "after" => Some(Self::After),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcBackend {
    Auto,
    Tcx,
    Netlink,
}

impl TcBackend {
    /// 将字符串解析为 TC 挂载后端枚举。
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "tcx" => Some(Self::Tcx),
            "netlink" => Some(Self::Netlink),
            _ => None,
        }
    }
}

#[derive(Parser, Debug, Clone)]
#[command(about = "Network traffic monitoring based on eBPF for OpenWrt")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(author = "https://github.com/timsaya")]
pub struct Options {
    #[arg(long, help = "Enable ECM (Hardware Offload) traffic tracking")]
    pub enable_ecm: bool,

    #[arg(
        long,
        requires = "enable_ecm",
        help = "Log detailed unresolved ECM diagnostics at info level"
    )]
    pub enable_ecm_log: bool,

    #[arg(
        long,
        default_value_t = false,
        help = "Enable traffic collection and service startup (set false to exit immediately)"
    )]
    pub enable_traffic: bool,

    #[arg(
        long,
        requires = "enable_traffic",
        help = "Enable DNS monitoring (captures DNS on port 53 on configured interfaces)"
    )]
    pub enable_dns: bool,

    #[arg(
        long,
        default_value_t = 5000,
        value_parser = clap::value_parser!(u32).range(100..=50000),
        help = "Maximum DNS query records retained in memory (100-50000, default: 5000)"
    )]
    pub dns_max_records: u32,

    #[arg(
        long = "dns-enable-storage",
        default_value_t = false,
        help = "Persist the bounded DNS query history to the data directory (default: false)"
    )]
    pub dns_enable_storage: bool,

    #[arg(
        long = "dns-flush-interval",
        default_value_t = 900,
        value_parser = clap::value_parser!(u64).range(60..=86400),
        help = "DNS storage flush interval in seconds (60-86400, default: 900)"
    )]
    pub dns_flush_interval: u64,

    #[arg(
        long = "traffic_enable_storage",
        default_value_t = false,
        help = "Enable persistent storage for traffic history data (default: false)"
    )]
    pub traffic_enable_storage: bool,

    #[arg(long, default_value_t = 30, value_name = "DAYS",
        value_parser = clap::value_parser!(u32).range(1..=90),
        help = "Hourly ring capacity in days (1-90); applies to memory and persistent storage")]
    pub ring_buffer: u32,

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
        default_value = "default",
        help = "TC order: first, default, last, before, after"
    )]
    pub tc_order: String,

    #[arg(
        long,
        default_value = "auto",
        help = "TC attach backend: auto, tcx, netlink (default: auto)"
    )]
    pub tc_backend: String,

    #[arg(
        long = "netlink-priority",
        help = "Netlink priority (0..65535, 0 means default). Only used when netlink backend is active"
    )]
    pub netlink_priority: Option<u16>,

    #[arg(
        long = "tcx-anchor-ingress-id",
        help = "TCX ingress anchor program id. Used when tc-order is before/after"
    )]
    pub tcx_anchor_ingress_id: Option<u32>,

    #[arg(
        long = "tcx-anchor-egress-id",
        help = "TCX egress anchor program id. Used when tc-order is before/after"
    )]
    pub tcx_anchor_egress_id: Option<u32>,

    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..=60), help = "Traffic history window in minutes (1-60, default: 10)")]
    pub history_window_minutes: u32,

    #[arg(long, default_value = "0.0.0.0", help = "Server bind host")]
    pub host: String,

    #[arg(long, default_value_t = 8787, help = "Server bind port")]
    pub port: u16,

    #[arg(
        long,
        default_value = "/tmp/bandix-plus",
        help = "Data directory for persisted traffic history data"
    )]
    pub data_dir: String,

    #[arg(
        long,
        help = "Exact LuCI web origin allowed by API CORS (for example http://192.168.1.1)"
    )]
    pub cors_origin: Option<String>,

    #[arg(
        long,
        default_value = "/tmp/etc/bandix-plus/api-token",
        help = "Path to the API bearer token file"
    )]
    pub api_token_file: String,

    #[arg(
        long,
        requires = "tls_key",
        help = "Path to TLS certificate file (e.g. cert.pem)"
    )]
    pub tls_cert: Option<String>,

    #[arg(
        long,
        requires = "tls_cert",
        help = "Path to TLS private key file (e.g. key.pem)"
    )]
    pub tls_key: Option<String>,

    /// Automatically remove devices that haven't been seen for this many days (0 to disable)
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u32).range(0..=3650))]
    pub device_ttl_days: u32,
}

#[cfg(test)]
mod tests {
    use super::{Options, TcBackend, TcOrder};
    use clap::Parser;

    #[test]
    fn ring_buffer_days_are_validated() {
        assert_eq!(Options::try_parse_from(["bandix-plus"]).unwrap().ring_buffer, 30);
        for days in ["1", "60", "90"] {
            assert_eq!(
                Options::try_parse_from(["bandix-plus", "--ring-buffer", days])
                    .unwrap()
                    .ring_buffer,
                days.parse::<u32>().unwrap()
            );
        }
        for days in ["0", "-1", "91", "4294967295", "1.5", "abc"] {
            assert!(Options::try_parse_from(["bandix-plus", "--ring-buffer", days]).is_err());
        }
    }

    #[test]
    fn ecm_diagnostics_require_ecm() {
        assert!(Options::try_parse_from(["bandix-plus", "--enable-ecm-log"]).is_err());
        assert!(Options::try_parse_from(["bandix-plus", "--enable-ecm", "--enable-ecm-log"]).is_ok());
    }

    #[test]
    fn dns_monitoring_requires_traffic_service_and_bounds_record_count() {
        assert!(Options::try_parse_from(["bandix-plus", "--enable-dns"]).is_err());
        assert!(Options::try_parse_from(["bandix-plus", "--enable-traffic", "--enable-dns"]).is_ok());
        for records in ["99", "50001", "not-a-number"] {
            assert!(Options::try_parse_from(["bandix-plus", "--enable-traffic", "--dns-max-records", records]).is_err());
        }
        assert_eq!(
            Options::try_parse_from(["bandix-plus", "--enable-traffic", "--dns-max-records", "100"])
                .unwrap()
                .dns_max_records,
            100
        );
    }

    #[test]
    fn tls_options_require_a_pair() {
        for flag in ["--tls-cert", "--tls-key"] {
            let err = Options::try_parse_from(["bandix-plus", flag, "file.pem"]).unwrap_err();
            assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
        }
        assert!(Options::try_parse_from(["bandix-plus"]).is_ok());
        assert!(Options::try_parse_from(["bandix-plus", "--tls-cert", "cert.pem", "--tls-key", "key.pem"]).is_ok());
    }

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
    fn tc_order_parse_before() {
        assert_eq!(TcOrder::parse("before"), Some(TcOrder::Before));
    }

    #[test]
    fn tc_order_parse_after() {
        assert_eq!(TcOrder::parse("after"), Some(TcOrder::After));
    }

    #[test]
    fn tc_order_parse_invalid() {
        assert_eq!(TcOrder::parse("invalid"), None);
    }

    #[test]
    fn tc_backend_parse_auto() {
        assert_eq!(TcBackend::parse("auto"), Some(TcBackend::Auto));
        assert_eq!(TcBackend::parse("AUTO"), Some(TcBackend::Auto));
    }

    #[test]
    fn tc_backend_parse_tcx() {
        assert_eq!(TcBackend::parse("tcx"), Some(TcBackend::Tcx));
    }

    #[test]
    fn tc_backend_parse_netlink() {
        assert_eq!(TcBackend::parse("netlink"), Some(TcBackend::Netlink));
    }

    #[test]
    fn tc_backend_parse_invalid() {
        assert_eq!(TcBackend::parse("invalid"), None);
    }
}
