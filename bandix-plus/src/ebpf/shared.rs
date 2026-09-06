use aya::Ebpf;
use aya::programs::tc::{self, NlOptions, SchedClassifier, TcAttachOptions, TcAttachType};
use aya::programs::{KProbe, LinkOrder, ProgramId};
use log::debug;
use nix::sys::utsname;

use crate::options::{TcBackend, TcOrder};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolvedBackend {
    Tcx,
    Netlink,
}

/// 加载 eBPF 程序并挂载到指定网络接口的 ingress/egress
pub fn load_ebpf_programs(
    ifaces: &Vec<String>,
    tc_backend: TcBackend,
    tc_order: TcOrder,
    netlink_priority: Option<u16>,
    tcx_anchor_ingress_id: Option<u32>,
    tcx_anchor_egress_id: Option<u32>,
    enable_ecm: bool,
    exclude_local_subnet: bool,
) -> anyhow::Result<Ebpf> {
    remove_rlimit_memlock();

    let mut ebpf = aya::EbpfLoader::new()
        .load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/bandix-plus")))
        .map_err(|e: aya::EbpfError| anyhow::anyhow!("Failed to load eBPF program: {}", e))?;

    if exclude_local_subnet {
        if let Ok(mut config_map) = aya::maps::HashMap::<_, u32, u32>::try_from(ebpf.map_mut("CONFIG_MAP").unwrap()) {
            let _ = config_map.insert(0, 1, 0);
            log::info!("Local subnet exclusion (192.168.0.0/16) is ENABLED");
        }
    }

    // 把 eBPF 在内核中的日志，拉到用户态输出
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(_e) => {
            // This can happen if you remove all log statements from your eBPF program.
            // warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            // WARNING: The original loop here caused 10-13% CPU usage because
            // it spun on readable_mut() without consuming the events properly.
            // Since we don't use eBPF logs, we just drop it or do nothing.
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

    let kernel_supports_tcx = kernel_at_least(6, 6, 0);
    let resolved_backend = match tc_backend {
        TcBackend::Auto => {
            if kernel_supports_tcx {
                ResolvedBackend::Tcx
            } else {
                ResolvedBackend::Netlink
            }
        }
        TcBackend::Tcx => {
            if !kernel_supports_tcx {
                anyhow::bail!("--tc-backend=tcx requires kernel >= 6.6.0");
            }
            ResolvedBackend::Tcx
        }
        TcBackend::Netlink => ResolvedBackend::Netlink,
    };

    if resolved_backend == ResolvedBackend::Tcx && netlink_priority.is_some() {
        anyhow::bail!("--netlink-priority is only valid for netlink backend");
    }

    if resolved_backend == ResolvedBackend::Netlink && matches!(tc_order, TcOrder::Before | TcOrder::After) {
        anyhow::bail!("--tc-order=before/after is not supported by netlink backend");
    }

    let ingress_anchor_program_id = tcx_anchor_ingress_id;
    let egress_anchor_program_id = tcx_anchor_egress_id;

    let opts = |attach_type: TcAttachType| -> anyhow::Result<TcAttachOptions> {
        match resolved_backend {
            ResolvedBackend::Tcx => {
                let anchor_program_id = match attach_type {
                    TcAttachType::Ingress => ingress_anchor_program_id,
                    TcAttachType::Egress => egress_anchor_program_id,
                    _ => None,
                };
                let order = match tc_order {
                    TcOrder::First => LinkOrder::first(),
                    TcOrder::Default => LinkOrder::default(),
                    TcOrder::Last => LinkOrder::last(),
                    TcOrder::Before => {
                        let id = anchor_program_id.ok_or_else(|| {
                            anyhow::anyhow!(
                                "anchor program id is required for {:?} when --tc-order=before; use --tcx-anchor-ingress-id/--tcx-anchor-egress-id",
                                attach_type
                            )
                        })?;
                        // SAFETY: program id validity is checked by kernel at attach time.
                        LinkOrder::before_program_id(unsafe { ProgramId::new(id) })
                    }
                    TcOrder::After => {
                        let id = anchor_program_id.ok_or_else(|| {
                            anyhow::anyhow!(
                                "anchor program id is required for {:?} when --tc-order=after; use --tcx-anchor-ingress-id/--tcx-anchor-egress-id",
                                attach_type
                            )
                        })?;
                        // SAFETY: program id validity is checked by kernel at attach time.
                        LinkOrder::after_program_id(unsafe { ProgramId::new(id) })
                    }
                };
                Ok(TcAttachOptions::TcxOrder(order))
            }
            ResolvedBackend::Netlink => {
                let nl_priority = if let Some(v) = netlink_priority {
                    v
                } else {
                    match tc_order {
                        TcOrder::First => 1u16,
                        TcOrder::Default => 0u16,
                        TcOrder::Last => 65535u16,
                        TcOrder::Before | TcOrder::After => {
                            anyhow::bail!("--tc-order=before/after is not supported by netlink backend");
                        }
                    }
                };
                Ok(TcAttachOptions::Netlink(NlOptions {
                    priority: nl_priority,
                    handle: 0,
                }))
            }
        }
    };

    for iface in ifaces {
        {
            let ingress_program: &mut SchedClassifier = ebpf
                .program_mut("bandix_plus_ingress")
                .ok_or_else(|| anyhow::anyhow!("bandix_plus_ingress program not found in eBPF object"))?
                .try_into()
                .map_err(|e: aya::programs::ProgramError| {
                    anyhow::anyhow!("Failed to convert ingress program to SchedClassifier: {:?}", e)
                })?;
            ingress_program.attach_with_options(
                iface,
                TcAttachType::Ingress,
                opts(TcAttachType::Ingress)?,
            )?;
        }
        {
            let egress_program: &mut SchedClassifier = ebpf
                .program_mut("bandix_plus_egress")
                .ok_or_else(|| anyhow::anyhow!("bandix_plus_egress program not found in eBPF object"))?
                .try_into()
                .map_err(|e: aya::programs::ProgramError| {
                    anyhow::anyhow!("Failed to convert egress program to SchedClassifier: {:?}", e)
                })?;
            egress_program.attach_with_options(
                iface,
                TcAttachType::Egress,
                opts(TcAttachType::Egress)?,
            )?;
        }
    }

    let order_str = match tc_order {
        TcOrder::First => "first",
        TcOrder::Default => "default",
        TcOrder::Last => "last",
        TcOrder::Before => "before",
        TcOrder::After => "after",
    };
    let backend_str = match resolved_backend {
        ResolvedBackend::Tcx => "tcx",
        ResolvedBackend::Netlink => "netlink",
    };
    let backend_req_str = match tc_backend {
        TcBackend::Auto => "auto",
        TcBackend::Tcx => "tcx",
        TcBackend::Netlink => "netlink",
    };
    log::info!(
        "Loading shared eBPF programs for interface [{}], order: {}, backend: {} (requested: {}), backend_options: {}",
        ifaces.join(","),
        order_str,
        backend_str,
        backend_req_str,
        match resolved_backend {
            ResolvedBackend::Tcx => format!(
                "tcx_anchor_ingress_id={},tcx_anchor_egress_id={}",
                tcx_anchor_ingress_id
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "none".to_string()),
                tcx_anchor_egress_id
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "none".to_string())
            ),
            ResolvedBackend::Netlink => format!(
                "netlink_priority={}",
                netlink_priority
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "derived_from_order".to_string())
            ),
        }
    );

    // --- ECM kprobe hooks (optional, graceful fallback) ---
    // Attach eBPF kprobes to ECM noinline stub functions.
    // If ECM kernel module is not loaded, attach will fail silently
    // and bandix-plus continues to work with TC-only monitoring.
    if enable_ecm {
    for (prog_name, kfunc) in [
        ("ecm_bandix_sync_hook", "ecm_bandix_ipv4_sync_hook"),
        ("ecm_bandix_ipv6_sync_hook", "ecm_bandix_ipv6_sync_hook"),
    ] {
        match ebpf.program_mut(prog_name) {
            Some(prog) => match TryInto::<&mut KProbe>::try_into(prog) {
                Ok(kprobe) => {
                    if let Err(e) = kprobe.load() {
                        log::info!("ECM kprobe '{}' load skipped: {}", prog_name, e);
                        continue;
                    }
                    match kprobe.attach(kfunc, 0) {
                        Ok(_) => log::info!("ECM kprobe '{}' attached to '{}' successfully", prog_name, kfunc),
                        Err(e) => log::info!("ECM kprobe '{}' attach skipped (ECM not loaded?): {}", prog_name, e),
                    }
                }
                Err(e) => log::info!("ECM kprobe '{}' type conversion skipped: {:?}", prog_name, e),
            },
            None => log::debug!("ECM kprobe '{}' not found in eBPF object, skipping", prog_name),
        }
    }
    }

    Ok(ebpf)
}
