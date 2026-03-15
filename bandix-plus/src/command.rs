use crate::api::{ApiState, start_server};
use crate::ebpf::shared::load_ebpf_programs;
use crate::monitor::{HistogramHistory, MonitorRuntime, SnapshotData, TrafficHistory, collect_snapshot};
use crate::options::{Options, TcOrder};
use crate::policy::{apply_runtime_policy, collect_observed_pairs, init_runtime, log_policy, parse_policy};
use crate::topology::TopologySnapshot;
use crate::utils::system_utils::{self, check_interface_exist};
use crate::utils::time_utils;
use log::LevelFilter;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// 主入口：初始化日志、校验参数并启动监控服务。
pub async fn run(options: Options) -> anyhow::Result<()> {
    validate_arguments(&options)?;

    let log_level = match options.log_level.to_lowercase().as_str() {
        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        _ => {
            return Err(anyhow::anyhow!(
                "Invalid log level: {}. Valid values: trace, debug, info, warn, error",
                options.log_level
            ));
        }
    };

    env_logger::Builder::new()
        .filter(None, log_level)
        .filter_module("aya::bpf", LevelFilter::Error)
        .target(env_logger::Target::Stdout)
        .init();

    // 运行服务
    run_service(&options).await?;

    Ok(())
}

/// 加载 eBPF、拓扑与策略，启动采集循环与 API 服务。
async fn run_service(options: &Options) -> anyhow::Result<()> {
    // 解析 TC 优先级
    let tc_order = TcOrder::parse(&options.tc_order).unwrap();

    // 加载 eBPF 实例
    let ebpf = load_ebpf_programs(&options.iface, tc_order)?;
    let topology = TopologySnapshot::discover()?;
    let interfaces = system_utils::list_interfaces()?;

    log::info!("detected {} interfaces", interfaces.len());
    log::info!("logical interfaces for monitoring:");
    for iface in topology.logical_interfaces() {
        log::info!(
            "ifindex={} name={} kind={:?} zone={:?} parent_ifindex={:?} ipv4_subnets={:?} ipv6_subnets={:?}",
            iface.ifindex,
            iface.name,
            iface.kind,
            iface.zone,
            iface.parent_ifindex,
            iface.ipv4_cidrs,
            iface.ipv6_cidrs
        );
    }

    let policy = parse_policy();
    log_policy(&policy);

    let policy_runtime = Arc::new(RwLock::new(init_runtime(policy)));
    let topology_state = Arc::new(RwLock::new(topology.clone()));

    let snapshot = Arc::new(RwLock::new(SnapshotData::default()));
    let collect_interval_secs = 1_u64;
    let history_points = ((options.history_window_minutes as u64) * 60).max(1) as usize;
    let history = Arc::new(RwLock::new(TrafficHistory::new(history_points)));
    let histogram = Arc::new(RwLock::new(HistogramHistory::new()));
    let monitor_ifaces = options.iface.clone();
    let api_state = ApiState {
        snapshot: Arc::clone(&snapshot),
        history: Arc::clone(&history),
        histogram: Arc::clone(&histogram),
        policy_runtime: Arc::clone(&policy_runtime),
        topology: Arc::clone(&topology_state),
    };

    let collect_interval = Duration::from_secs(collect_interval_secs);
    let mut collector_ebpf = ebpf;
    let collector_topology = Arc::clone(&topology_state);
    let collector_snapshot = Arc::clone(&snapshot);
    let collector_history = Arc::clone(&history);
    let collector_histogram = Arc::clone(&histogram);
    let collector_policy_runtime = Arc::clone(&policy_runtime);
    let collector_monitor_ifaces = monitor_ifaces;
    tokio::spawn(async move {
        let mut runtime = MonitorRuntime::default();
        let mut ticker = tokio::time::interval(collect_interval);
        loop {
            ticker.tick().await;
            if let Ok(new_topology) = TopologySnapshot::discover() {
                let mut topology_guard = collector_topology.write().await;
                *topology_guard = new_topology;
            }
            let observed_pairs = collect_observed_pairs(&mut collector_ebpf).unwrap_or_default();
            {
                let topology_guard = collector_topology.read().await;
                let guard = collector_policy_runtime.read().await;
                if let Err(e) = apply_runtime_policy(
                    &mut collector_ebpf,
                    &guard,
                    &observed_pairs,
                    &topology_guard,
                    time_utils::now_millis(),
                ) {
                    log::error!("apply runtime policy failed: {}", e);
                }
            }
            let result = {
                let topology_guard = collector_topology.read().await;
                collect_snapshot(
                    &mut collector_ebpf,
                    &topology_guard,
                    &mut runtime,
                    collect_interval,
                    &collector_monitor_ifaces,
                )
            };
            match result {
                Ok(data) => {
                    {
                        let mut history_guard = collector_history.write().await;
                        history_guard.ingest_snapshot(&data);
                    }
                    {
                        let mut histogram_guard = collector_histogram.write().await;
                        histogram_guard.ingest_snapshot(&data);
                    }
                    let mut guard = collector_snapshot.write().await;
                    *guard = data;
                }
                Err(e) => {
                    log::error!("collector loop error: {}", e);
                }
            }
        }
    });

    log::info!("API server listening on {}", options.api_bind);
    start_server(&options.api_bind, api_state).await?;

    Ok(())
}

/// 校验 --iface 和 --tc-order 等必填与格式参数。
fn validate_arguments(options: &Options) -> anyhow::Result<()> {
    if options.iface.is_empty() {
        anyhow::bail!("at least one --iface is required");
    }

    // 检查网络接口是否存在
    check_interface_exist(&options.iface)?;

    // 检查 tc_order 参数是否合法
    TcOrder::parse(&options.tc_order)
        .ok_or_else(|| anyhow::anyhow!("Invalid tc-order: {}. Valid: first, default, last", options.tc_order))?;

    Ok(())
}
