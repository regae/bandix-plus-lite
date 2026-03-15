use aya::Ebpf;
use aya::programs::LinkOrder;
use aya::programs::tc::{self, NlOptions, SchedClassifier, TcAttachOptions, TcAttachType};
use log::{debug, warn};
use nix::sys::utsname;

use crate::options::TcOrder;

/// 判断内核版本是否大于等于指定版本号
fn kernel_at_least(major: u32, minor: u32, patch: u32) -> bool {
    let s = match utsname::uname() {
        Ok(u) => u.release().to_string_lossy().into_owned(),
        Err(_) => return false,
    };
    let mut parts = s.splitn(3, |c: char| c == '.' || c == '-');
    let (maj, min, pat): (u32, u32, u32) = (
        parts.next().and_then(|p| p.parse().ok()).unwrap_or(0),
        parts.next().unwrap_or("0").parse().unwrap_or(0),
        parts
            .next()
            .unwrap_or("0")
            .split('-')
            .next()
            .unwrap_or("0")
            .parse()
            .unwrap_or(0),
    );
    (maj, min, pat) >= (major, minor, patch)
}

/// 解除 RLIMIT_MEMLOCK 限制以便加载 eBPF 程序
fn remove_rlimit_memlock() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }
}

/// 加载 eBPF 程序并挂载到指定网络接口的 ingress/egress
pub fn load_ebpf_programs(ifaces: &Vec<String>, tc_order: TcOrder) -> anyhow::Result<Ebpf> {
    remove_rlimit_memlock();

    let mut ebpf = aya::EbpfLoader::new()
        .load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/bandix-plus")))
        .map_err(|e| anyhow::anyhow!("Failed to load eBPF program: {}", e))?;

    // 把 eBPF 在内核中的日志，拉到用户态输出
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger = tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    for iface in ifaces.iter() {
        if let Err(e) = tc::qdisc_add_clsact(&iface) {
            log::debug!("Failed to add clsact qdisc (may already exist): {}", e);
        }
    }

    {
        let ingress_program: &mut SchedClassifier = ebpf
            .program_mut("bandix_plus_ingress")
            .ok_or_else(|| anyhow::anyhow!("bandix_plus_ingress program not found in eBPF object"))?
            .try_into()
            .map_err(|e: aya::programs::ProgramError| anyhow::anyhow!("Failed to convert ingress program to SchedClassifier: {:?}", e))?;
        ingress_program.load()?;
    }

    {
        let egress_program: &mut SchedClassifier = ebpf
            .program_mut("bandix_plus_egress")
            .ok_or_else(|| anyhow::anyhow!("bandix_plus_egress program not found in eBPF object"))?
            .try_into()
            .map_err(|e: aya::programs::ProgramError| anyhow::anyhow!("Failed to convert egress program to SchedClassifier: {:?}", e))?;
        egress_program.load()?;
    }

    let use_tcx = kernel_at_least(6, 6, 0);
    let nl_priority = match tc_order {
        TcOrder::First => 1u16,
        TcOrder::Default => 0u16,
        TcOrder::Last => 65535u16,
    };

    let opts = || match use_tcx {
        true => {
            let order = match tc_order {
                TcOrder::First => LinkOrder::first(),
                TcOrder::Default => LinkOrder::default(),
                TcOrder::Last => LinkOrder::last(),
            };
            TcAttachOptions::TcxOrder(order)
        }
        false => TcAttachOptions::Netlink(NlOptions {
            priority: nl_priority,
            handle: 0,
        }),
    };

    for iface in ifaces {
        {
            let ingress_program: &mut SchedClassifier = ebpf
                .program_mut("bandix_plus_ingress")
                .ok_or_else(|| anyhow::anyhow!("bandix_plus_ingress program not found in eBPF object"))?
                .try_into()
                .map_err(|e: aya::programs::ProgramError| anyhow::anyhow!("Failed to convert ingress program to SchedClassifier: {:?}", e))?;
            ingress_program.attach_with_options(iface, TcAttachType::Ingress, opts())?;
        }
        {
            let egress_program: &mut SchedClassifier = ebpf
                .program_mut("bandix_plus_egress")
                .ok_or_else(|| anyhow::anyhow!("bandix_plus_egress program not found in eBPF object"))?
                .try_into()
                .map_err(|e: aya::programs::ProgramError| anyhow::anyhow!("Failed to convert egress program to SchedClassifier: {:?}", e))?;
            egress_program.attach_with_options(iface, TcAttachType::Egress, opts())?;
        }
    }

    let order_str = match tc_order {
        TcOrder::First => "first",
        TcOrder::Default => "default",
        TcOrder::Last => "last",
    };
    log::info!(
        "Loading shared eBPF programs for interface [{}], order: {}, backend: {}",
        ifaces.join(","),
        order_str,
        if use_tcx { "tcx" } else { "netlink" }
    );

    Ok(ebpf)
}
