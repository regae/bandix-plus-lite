use aya::Ebpf;
use aya::programs::tc::{self, NlOptions, SchedClassifier, TcAttachOptions, TcAttachType};
use aya::programs::{KProbe, LinkOrder, ProgramId};
use bandix_plus_common::RouterIpKey;
use log::debug;
use nix::sys::utsname;
use std::collections::HashSet;
use std::net::IpAddr;

use crate::options::{TcBackend, TcOrder};
use crate::topology::TopologySnapshot;

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
    enable_dns: bool,
    topology: &TopologySnapshot,
    api_port: u16,
) -> anyhow::Result<Ebpf> {
    remove_rlimit_memlock();

    // The DNS ring buffer stays small unless capture is enabled. This keeps
    // the default service memory footprint close to its pre-DNS baseline.
    let mut loader = aya::EbpfLoader::new();
    let dns_enabled = u8::from(enable_dns);
    loader
        .override_global("DNS_ENABLED", &dns_enabled, true)
        .map_max_entries("DNS_DATA", if enable_dns { 1024 * 1024 } else { 4096 });
    let mut ebpf = loader
        .load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/bandix-plus")))
        .map_err(|e: aya::EbpfError| anyhow::anyhow!("Failed to load eBPF program: {}", e))?;

    log::info!(
        "DNS capture enabled={} ring_buffer_bytes={}",
        enable_dns,
        if enable_dns { 1024 * 1024 } else { 4096 }
    );

    sync_traffic_filter_maps(&mut ebpf, topology, api_port)?;

    // 把 eBPF 在内核中的日志，拉到用户态输出
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(_e) => {
            // This can happen if you remove all log statements from your eBPF program.
            // warn!("failed to initialize eBPF logger: {e}");
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
            ingress_program.attach_with_options(iface, TcAttachType::Ingress, opts(TcAttachType::Ingress)?)?;
        }
        {
            let egress_program: &mut SchedClassifier = ebpf
                .program_mut("bandix_plus_egress")
                .ok_or_else(|| anyhow::anyhow!("bandix_plus_egress program not found in eBPF object"))?
                .try_into()
                .map_err(|e: aya::programs::ProgramError| {
                    anyhow::anyhow!("Failed to convert egress program to SchedClassifier: {:?}", e)
                })?;
            egress_program.attach_with_options(iface, TcAttachType::Egress, opts(TcAttachType::Egress)?)?;
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
                            Err(e) => log::info!(
                                "ECM kprobe '{}' attach skipped (ECM module may not include the Bandix hooks): {}",
                                prog_name,
                                e
                            ),
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

/// Synchronize low-cardinality traffic filters outside the per-packet hot path.
pub fn sync_traffic_filter_maps(ebpf: &mut Ebpf, topology: &TopologySnapshot, api_port: u16) -> anyhow::Result<()> {
    let mut router_ips = HashSet::new();

    for iface in topology.interfaces() {
        for cidr in iface.ipv4_cidrs.iter().chain(iface.ipv6_cidrs.iter()) {
            if let Some(address) = parse_interface_address(cidr) {
                router_ips.insert(router_ip_key(address));
            }
        }
    }

    sync_hash_map::<RouterIpKey>(ebpf, "ROUTER_LOCAL_IPS", &router_ips)?;

    let management_ports = HashSet::from([80u16, 443u16, api_port]);
    sync_hash_map::<u16>(ebpf, "MANAGEMENT_PORTS", &management_ports)?;

    log::debug!(
        "traffic filters: management_exclusion=enabled management_tcp_ports={:?}",
        management_ports
    );

    Ok(())
}

fn sync_hash_map<K>(ebpf: &mut Ebpf, map_name: &str, desired: &HashSet<K>) -> anyhow::Result<()>
where
    K: aya::Pod + Copy + Eq + std::hash::Hash,
{
    let map = ebpf
        .map_mut(map_name)
        .ok_or_else(|| anyhow::anyhow!("{map_name} map not found"))?;
    let mut map: aya::maps::HashMap<_, K, u8> = aya::maps::HashMap::try_from(map)?;
    let current: HashSet<K> = map.iter().filter_map(Result::ok).map(|(key, _)| key).collect();

    for key in &current {
        if !desired.contains(key) {
            let _ = map.remove(key);
        }
    }
    for key in desired {
        if !current.contains(key) {
            map.insert(*key, 1, 0)?;
        }
    }
    Ok(())
}

fn parse_interface_address(cidr: &str) -> Option<IpAddr> {
    let address = cidr.split('%').next()?.split('/').next()?;
    address.parse().ok()
}

fn router_ip_key(address: IpAddr) -> RouterIpKey {
    match address {
        IpAddr::V4(address) => RouterIpKey {
            ip: [u32::from(address), 0, 0, 0],
            ip_version: 4,
            _pad: [0; 3],
        },
        IpAddr::V6(address) => {
            let octets = address.octets();
            RouterIpKey {
                ip: std::array::from_fn(|index| u32::from_be_bytes(octets[index * 4..index * 4 + 4].try_into().unwrap())),
                ip_version: 6,
                _pad: [0; 3],
            }
        }
    }
}
