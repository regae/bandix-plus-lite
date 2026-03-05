use crate::ebpf::shared::load_ebpf_programs;
use crate::options::{Options, TcOrder};
use crate::utils::system_utils::{self, check_interface_exist};
use log::LevelFilter;

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

async fn run_service(options: &Options) -> anyhow::Result<()> {
    // 解析 TC 优先级
    let tc_order = TcOrder::parse(&options.tc_order).unwrap();

    // 加载 eBPF 实例
    let ebpf = load_ebpf_programs(&options.iface, tc_order)?;


    let interfaces = system_utils::list_interfaces()?;

    println!("{:?}", interfaces);

    Ok(())
}

// 验证参数
fn validate_arguments(options: &Options) -> anyhow::Result<()> {
    // 检查网络接口是否存在
    check_interface_exist(&options.iface)?;

    // 检查 tc_order 参数是否合法
    TcOrder::parse(&options.tc_order)
        .ok_or_else(|| anyhow::anyhow!("Invalid tc-order: {}. Valid: first, default, last", options.tc_order))?;

    Ok(())
}
