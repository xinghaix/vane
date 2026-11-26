//! 防火墙驱动层：本机受保护端口与环回绕过守卫、接口名严格校验、5s 异步受控执行器、
//! fw4 (nftables 单事务 + 高优先级封禁表) 与 fw3 (iptables-restore 原子提交) 串行对账与内核回滚恢复。
pub mod iptables;
pub mod nftables;

use crate::config::FirewallConfig;
use crate::logger::{self, Level};
use crate::net::dual_stack::BanKey;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

/// 路由器本机高危服务端口黑名单（拦截直接开放本机 WAN INPUT，或通过本机环回/宿主接口转发变相暴露）
pub const PROTECTED_LOCAL_INPUT_PORTS: &[u16] = &[
    21, 22, 23, 53, 67, 68, 80, 139, 443, 445, 1883, 2375, 2376, 3306, 4000, 5432, 6379, 23456,
];

const SAFE_CMD_PATH: &str = "/usr/sbin:/sbin:/usr/bin:/bin";

pub fn validate_wan_input_port(port: u16, admin_port: u16, zone: &str) -> Result<(), String> {
    validate_wan_input_ports(port, &[admin_port], zone)
}

pub fn validate_wan_input_ports(port: u16, admin_ports: &[u16], zone: &str) -> Result<(), String> {
    if zone.eq_ignore_ascii_case("wan") {
        if admin_ports.contains(&port) {
            return Err(format!("安全底线拦截：严禁在 WAN INPUT 直接放行管理后台端口 {}", port));
        }
        if PROTECTED_LOCAL_INPUT_PORTS.contains(&port) {
            return Err(format!("安全底线拦截：严禁在 WAN INPUT 放行路由器本机高危受保护端口 {}", port));
        }
    }
    Ok(())
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        other => other,
    }
}

/// 判定目标 IP 是否为禁止作为上游或转发目标的链路本地/云元数据/多播/未指定/广播/NAT64 地址
pub fn is_disallowed_upstream_or_metadata_ip(ip: IpAddr) -> bool {
    match normalize_ip(ip) {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_link_local()       // 169.254.0.0/16 (含云元数据 169.254.169.254)
                || v4.is_multicast() // 224.0.0.0/4
                || v4.is_broadcast() // 255.255.255.255
                || o[0] == 0         // 0.0.0.0/8 (含未指定 0.0.0.0)
                || o[0] >= 240       // 240.0.0.0/4 保留段与受限广播
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            let is_link_local = (s[0] & 0xffc0) == 0xfe80; // fe80::/10
            let is_site_local = (s[0] & 0xffc0) == 0xfec0; // fec0::/10 (已废弃)
            let is_nat64_well_known =
                s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0; // 64:ff9b::/96
            let is_nat64_local = s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001; // 64:ff9b:1::/48
            let is_ipv4_translated =
                s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0xffff && s[5] == 0; // ::ffff:0:0:0/96
            let is_ipv4_compatible = s[0] == 0
                && s[1] == 0
                && s[2] == 0
                && s[3] == 0
                && s[4] == 0
                && s[5] == 0
                && !v6.is_loopback(); // ::/96（排除 ::1 环回）
            v6.is_unspecified()
                || v6.is_multicast()
                || is_link_local
                || is_site_local
                || is_nat64_well_known
                || is_nat64_local
                || is_ipv4_translated
                || is_ipv4_compatible
        }
    }
}

fn collect_local_interface_ips() -> Vec<IpAddr> {
    let mut ips = Vec::new();
    for entry in crate::daemon::netlink_ip::list_interface_addresses().into_values() {
        for v4 in entry.ipv4 {
            let ip = IpAddr::V4(v4);
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
        for v6 in entry.ipv6 {
            let ip = normalize_ip(IpAddr::V6(v6));
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
    }
    ips
}

/// 严格校验端口转发/反向代理目标地址安全性：
/// - 始终拒绝链路本地/云元数据/多播/0.0.0.0/8/广播/NAT64 目标；
/// - 将 `admin_listeners` + 当前宿主机全部本地网卡 IP + 环回 + 未指定地址均视为路由器本机地址；
/// - 始终禁止转发至任意 `admin_listeners` IP:port 或本机环回受保护端口；
/// - 当非严格 LAN 绑定（`!lan_bound_only` 或 `open_wan_firewall`）时，禁止指向任何本机接口的受保护端口或管理端口。
pub fn validate_forward_target_safety_strict(
    target_ip: IpAddr,
    target_port: u16,
    open_wan_firewall: bool,
    lan_bound_only: bool,
    admin_listeners: &[SocketAddr],
) -> Result<(), String> {
    validate_forward_target_safety_strict_inner(
        target_ip,
        target_port,
        open_wan_firewall,
        lan_bound_only,
        &[],
        admin_listeners,
        &collect_local_interface_ips(),
    )
}

fn validate_forward_target_safety_strict_inner(
    target_ip: IpAddr,
    target_port: u16,
    open_wan_firewall: bool,
    lan_bound_only: bool,
    extra_admin_ports: &[u16],
    admin_listeners: &[SocketAddr],
    host_iface_ips: &[IpAddr],
) -> Result<(), String> {
    if is_disallowed_upstream_or_metadata_ip(target_ip) {
        return Err(format!(
            "安全底线拦截：禁止转发或代理至链路本地/元数据/多播/未指定/NAT64 地址 ({}:{})",
            target_ip, target_port
        ));
    }

    let ip = normalize_ip(target_ip);
    let is_loopback = ip.is_loopback();
    let is_unspecified = ip.is_unspecified();

    let mut router_host_ips: Vec<IpAddr> = host_iface_ips.iter().map(|a| normalize_ip(*a)).collect();
    for sock in admin_listeners {
        let norm = normalize_ip(sock.ip());
        if !router_host_ips.contains(&norm) {
            router_host_ips.push(norm);
        }
    }
    let is_router_host_ip = is_loopback || is_unspecified || router_host_ips.contains(&ip);

    let mut all_admin_ports: Vec<u16> = extra_admin_ports.to_vec();
    for sock in admin_listeners {
        if !all_admin_ports.contains(&sock.port()) {
            all_admin_ports.push(sock.port());
        }
    }

    // 无论是否仅限 LAN 绑定，始终禁止转发至任意管理后台监听地址
    for admin_sock in admin_listeners {
        let admin_ip = normalize_ip(admin_sock.ip());
        if admin_sock.port() == target_port
            && (admin_ip == ip || (admin_ip.is_unspecified() && is_router_host_ip))
        {
            return Err(format!(
                "安全底线拦截：禁止将转发或代理指向管理后台监听地址 ({}:{})",
                target_ip, target_port
            ));
        }
    }

    let is_protected_port =
        all_admin_ports.contains(&target_port) || PROTECTED_LOCAL_INPUT_PORTS.contains(&target_port);

    // 即使在 lan_bound_only == true 下，仍始终禁止指向本机环回受保护端口/管理端口
    if is_loopback && is_protected_port {
        return Err(format!(
            "安全底线拦截：禁止转发或代理至本机环回受保护端口或管理端口 ({}:{})",
            target_ip, target_port
        ));
    }

    // 当未严格限定 LAN 接口绑定，或显式放行 WAN 防火墙时，禁止指向任何本机接口的受保护端口或管理端口
    let effective_lan_only = lan_bound_only && !open_wan_firewall;
    if !effective_lan_only && is_router_host_ip && is_protected_port {
        return Err(format!(
            "安全底线拦截：禁止将公网或通配监听转发指向路由器本机受保护端口或管理端口 ({}:{})",
            target_ip, target_port
        ));
    }

    Ok(())
}

/// 防止通过端口转发指向 127.0.0.1 / ::1 / 0.0.0.0 或本机/管理监听地址绕过本机高危端口守卫
pub fn validate_forward_target_safety(
    target: SocketAddr,
    engine: &str,
    open_wan_firewall: bool,
    admin_port: u16,
    admin_listeners: &[String],
) -> Result<(), String> {
    validate_forward_target_safety_multi(target, engine, open_wan_firewall, &[admin_port], admin_listeners)
}

pub fn validate_forward_target_safety_multi(
    target: SocketAddr,
    engine: &str,
    open_wan_firewall: bool,
    admin_ports: &[u16],
    admin_listeners: &[String],
) -> Result<(), String> {
    let ip = normalize_ip(target.ip());
    let is_local_special = ip.is_loopback() || ip.is_unspecified();
    if engine == "kernel_dnat" && is_local_special {
        return Err(format!("安全与协议拦截：kernel_dnat 目标不能为环回或未指定地址 ({})", target));
    }
    let parsed_listeners: Vec<SocketAddr> = admin_listeners
        .iter()
        .filter_map(|l| l.parse::<SocketAddr>().ok())
        .collect();
    // _multi 无 bind_interface 上下文，按非 LAN 专属绑定（lan_bound_only = false）做严格校验
    let effective_wan = open_wan_firewall || engine == "kernel_dnat";
    validate_forward_target_safety_strict_inner(
        target.ip(),
        target.port(),
        effective_wan,
        false,
        admin_ports,
        &parsed_listeners,
        &collect_local_interface_ips(),
    )
}

pub fn validate_iface_name(iface: &str) -> Result<(), String> {
    if iface.is_empty() || iface.len() > 15 {
        return Err(format!("网卡名称长度非法: {}", iface));
    }
    if iface == "." || iface == ".." || !iface.as_bytes()[0].is_ascii_alphanumeric() {
        return Err(format!("网卡名称必须以字母或数字开头: {}", iface));
    }
    if !iface.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.') {
        return Err(format!("网卡名称包含非法字符: {}", iface));
    }
    Ok(())
}

pub fn validate_proto(proto: &str) -> Result<(), String> {
    if matches!(proto, "tcp" | "udp") {
        Ok(())
    } else {
        Err(format!("防火墙协议非法: {}", proto))
    }
}

// ---------------------------------------------------------------------------
// Lockdown 持久化标记与结构化报告 (VANE-H08)
// ---------------------------------------------------------------------------

pub fn lockdown_marker_path(data_dir: &Path) -> PathBuf {
    data_dir.join(".lockdown")
}

pub fn read_persisted_lockdown(data_dir: &Path) -> bool {
    let path = lockdown_marker_path(data_dir);
    let meta = match fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(_) => return false,
    };
    if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > 256 {
        logger::log(
            Level::Warn,
            "firewall",
            &format!("忽略非法 lockdown 标记文件（符号链接或异常大小）: {}", path.display()),
        );
        return false;
    }
    let Ok(text) = fs::read_to_string(&path) else {
        return false;
    };
    matches!(text.trim().to_ascii_lowercase().as_str(), "1" | "true" | "enabled")
}

pub fn write_persisted_lockdown(data_dir: &Path, enabled: bool) -> Result<(), String> {
    let path = lockdown_marker_path(data_dir);
    if enabled {
        crate::config::crash_safe_atomic_write_with_mode(
            &path,
            b"1\n",
            crate::config::random_nonce(),
            0o600,
            false,
        )
        .map_err(|e| format!("持久化写入 lockdown 标记失败: {}", e))?;
        Ok(())
    } else {
        match fs::symlink_metadata(&path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(format!("拒绝删除符号链接 lockdown 标记: {}", path.display()));
                }
                fs::remove_file(&path).map_err(|e| format!("移除 lockdown 标记失败: {}", e))?;
                if let Ok(dir) = fs::File::open(data_dir) {
                    let _ = dir.sync_all();
                }
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("检查 lockdown 标记失败: {}", e)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LockdownReport {
    pub active: bool,
    pub kernel_enforced: bool,
    pub conntrack_flushed: bool,
    pub warnings: Vec<String>,
}

/// CLI `vane firewall lockdown [--off]` 专用入口：
/// 原子持久化 `.lockdown` 标记并在启用时仅清空 WAN 放行链，
/// 绝不调用 `pre_start_sweep()`，绝不清空内核中的 `vane_shield` / `VANE_BAN` Fail2Ban 封禁集！
pub async fn apply_cli_lockdown_preserve_bans(
    backend_cfg: &FirewallConfig,
    data_dir: &Path,
    enabled: bool,
) -> Result<LockdownReport, String> {
    let exec: Arc<dyn FirewallExecutor> = Arc::new(SystemFirewallExecutor);
    let backend = FirewallManager::detect_backend(&backend_cfg.backend, exec.as_ref()).await;
    apply_cli_lockdown_preserve_bans_with_executor(backend, backend_cfg, data_dir, enabled, exec.as_ref()).await
}

pub async fn apply_cli_lockdown_preserve_bans_with_executor(
    backend: FirewallBackend,
    backend_cfg: &FirewallConfig,
    data_dir: &Path,
    enabled: bool,
    exec: &dyn FirewallExecutor,
) -> Result<LockdownReport, String> {
    write_persisted_lockdown(data_dir, enabled)?;
    let mut warnings = Vec::new();

    if !backend_cfg.auto_manage {
        warnings.push("firewall.auto_manage=false，已持久化 .lockdown 标记但未修改内核防火墙规则".into());
        return Ok(LockdownReport {
            active: enabled,
            kernel_enforced: false,
            conntrack_flushed: false,
            warnings,
        });
    }

    if backend == FirewallBackend::DryRun {
        warnings.push("当前防火墙后端为 DryRun（非 Linux 或未检测到 nftables/iptables），已持久化 .lockdown 标记但未生效于内核".into());
        return Ok(LockdownReport {
            active: enabled,
            kernel_enforced: false,
            conntrack_flushed: false,
            warnings,
        });
    }

    if enabled {
        match backend {
            FirewallBackend::Nftables => nftables::apply_lockdown_preserve_bans(exec).await?,
            FirewallBackend::IptablesLegacy => {
                iptables::apply_lockdown_preserve_bans(exec, "iptables-legacy", "ip6tables-legacy").await?
            }
            FirewallBackend::IptablesNft => {
                iptables::apply_lockdown_preserve_bans(exec, "iptables", "ip6tables").await?
            }
            FirewallBackend::DryRun => unreachable!(),
        }
        warnings.push(
            "CLI 已保留现有 Fail2Ban 封禁并清空内核 WAN 放行链；未按规则清理 conntrack，请通过管理端或重载运行中守护进程以同步停止用户态 WAN 监听"
                .into(),
        );
        Ok(LockdownReport {
            active: true,
            kernel_enforced: true,
            conntrack_flushed: false,
            warnings,
        })
    } else {
        warnings.push(
            "已清除持久化 .lockdown 标记（保留现有 Fail2Ban 封禁未清扫）；请重载或重启守护进程以恢复正常 WAN 规则同步"
                .into(),
        );
        Ok(LockdownReport {
            active: false,
            kernel_enforced: false,
            conntrack_flushed: false,
            warnings,
        })
    }
}

#[async_trait::async_trait]
pub trait FirewallExecutor: Send + Sync {
    async fn run(&self, program: &str, args: &[&str], stdin_data: Option<&[u8]>) -> Result<String, String>;
}

pub struct SystemFirewallExecutor;

#[async_trait::async_trait]
impl FirewallExecutor for SystemFirewallExecutor {
    async fn run(&self, program: &str, args: &[&str], stdin_data: Option<&[u8]>) -> Result<String, String> {
        if !cfg!(target_os = "linux") {
            return Err(format!("当前平台不支持宿主机内核防火墙命令: {}", program));
        }
        run_fw_cmd_with_stdin(program, args, stdin_data).await
    }
}

/// 异步非阻塞执行宿主机防火墙/conntrack 命令，5 秒硬超时 + kill_on_drop + 固定安全 PATH + 有界输出
pub async fn run_fw_cmd_async(program: &str, args: &[&str]) -> Result<String, String> {
    run_fw_cmd_with_stdin(program, args, None).await
}

pub async fn run_fw_cmd_with_stdin(
    program: &str,
    args: &[&str],
    stdin_data: Option<&[u8]>,
) -> Result<String, String> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .env("PATH", SAFE_CMD_PATH)
        .env_remove("VANE_MASTER_KEY")
        .env_remove("VANE_MASTER_KEY_FILE")
        .stdin(if stdin_data.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = cmd.spawn().map_err(|e| format!("启动 {} 失败: {}", program, e))?;
    let io_fut = async {
        if let Some(input) = stdin_data {
            if let Some(mut child_in) = child.stdin.take() {
                child_in
                    .write_all(input)
                    .await
                    .map_err(|e| format!("向 {} 写入规则脚本失败: {}", program, e))?;
                child_in
                    .shutdown()
                    .await
                    .map_err(|e| format!("关闭 {} 标准输入失败: {}", program, e))?;
            }
        }
        let mut out_buf = Vec::new();
        let mut err_buf = Vec::new();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let read_out = async {
            if let Some(s) = stdout {
                let _ = s.take(256 * 1024).read_to_end(&mut out_buf).await;
            }
        };
        let read_err = async {
            if let Some(s) = stderr {
                let _ = s.take(64 * 1024).read_to_end(&mut err_buf).await;
            }
        };
        tokio::join!(read_out, read_err);
        let status = child.wait().await.map_err(|e| format!("等待 {} 退出失败: {}", program, e))?;
        Ok::<_, String>((status, out_buf, err_buf))
    };

    match tokio::time::timeout(Duration::from_secs(5), io_fut).await {
        Ok(Ok((status, out_buf, err_buf))) if status.success() => {
            let _ = err_buf;
            Ok(String::from_utf8_lossy(&out_buf).into_owned())
        }
        Ok(Ok((status, _, err_buf))) => Err(format!(
            "{} {:?} 退出码 {:?}: {}",
            program,
            args,
            status.code(),
            String::from_utf8_lossy(&err_buf).trim()
        )),
        Ok(Err(e)) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            Err(e)
        }
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            Err(format!("执行 {} {:?} 超时 (5s)", program, args))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallBackend {
    Nftables,
    IptablesLegacy,
    IptablesNft,
    DryRun,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FirewallRule {
    /// 打开网关本机 WAN INPUT 端口
    WanInput {
        owner_module: String,
        rule_name: String,
        proto: String, // "tcp" | "udp"
        port: u16,
        ipv4: bool,
        ipv6: bool,
    },
    /// 内核 DNAT 转发（PREROUTING + FORWARD）
    KernelDnat {
        owner_module: String,
        rule_name: String,
        proto: String,
        listen_port: u16,
        target: SocketAddr,
    },
    /// 子设备精确 /128 IPv6 直连放行（FORWARD 链）
    SubDeviceIpv6Forward {
        owner_module: String,
        rule_name: String,
        device_ip: Ipv6Addr,
        tcp_ports: Vec<u16>,
        udp_ports: Vec<u16>,
    },
}

impl FirewallRule {
    pub fn owner(&self) -> &str {
        match self {
            Self::WanInput { owner_module, .. }
            | Self::KernelDnat { owner_module, .. }
            | Self::SubDeviceIpv6Forward { owner_module, .. } => owner_module,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::WanInput { rule_name, .. }
            | Self::KernelDnat { rule_name, .. }
            | Self::SubDeviceIpv6Forward { rule_name, .. } => rule_name,
        }
    }
}

pub struct FirewallManager {
    backend: FirewallBackend,
    executor: Arc<dyn FirewallExecutor>,
    op_lock: tokio::sync::Mutex<()>,
    cfg: Mutex<FirewallConfig>,
    rules: Mutex<Vec<FirewallRule>>,
    bans: Mutex<BTreeMap<BanKey, u64>>,
    lockdown: Mutex<bool>,
    degraded: AtomicBool,
    data_dir: Mutex<Option<PathBuf>>,
    admin_ports: Mutex<Vec<u16>>,
}

impl FirewallManager {
    pub async fn detect_and_init(cfg: FirewallConfig) -> Arc<Self> {
        let executor: Arc<dyn FirewallExecutor> = Arc::new(SystemFirewallExecutor);
        let backend = Self::detect_backend(&cfg.backend, executor.as_ref()).await;
        logger::log(Level::Info, "firewall", &format!("初始化防火墙后端: {:?}", backend));
        let mgr = Self::with_executor(backend, cfg, executor);
        if mgr.is_auto_manage() {
            if let Err(e) = mgr.pre_start_sweep().await {
                logger::log(Level::Warn, "firewall", &format!("启动预清扫防火墙失败: {}", e));
            }
        }
        mgr
    }

    pub async fn detect_and_init_with_data_dir(cfg: FirewallConfig, data_dir: &Path) -> Arc<Self> {
        let executor: Arc<dyn FirewallExecutor> = Arc::new(SystemFirewallExecutor);
        let backend = Self::detect_backend(&cfg.backend, executor.as_ref()).await;
        logger::log(Level::Info, "firewall", &format!("初始化防火墙后端: {:?}", backend));
        let mgr = Self::with_executor(backend, cfg, executor);
        mgr.set_data_dir(data_dir.to_path_buf());
        if mgr.init_lockdown_from_disk(data_dir) {
            logger::log(Level::Warn, "firewall", "检测到持久化 .lockdown 标记，守护进程以紧急闭锁模式启动");
        }
        if mgr.is_auto_manage() {
            if let Err(e) = mgr.pre_start_sweep().await {
                logger::log(Level::Warn, "firewall", &format!("启动预清扫防火墙失败: {}", e));
            }
        }
        mgr
    }

    pub fn with_executor(
        backend: FirewallBackend,
        cfg: FirewallConfig,
        executor: Arc<dyn FirewallExecutor>,
    ) -> Arc<Self> {
        Arc::new(Self {
            backend,
            executor,
            op_lock: tokio::sync::Mutex::new(()),
            cfg: Mutex::new(cfg),
            rules: Mutex::new(Vec::new()),
            bans: Mutex::new(BTreeMap::new()),
            lockdown: Mutex::new(false),
            degraded: AtomicBool::new(false),
            data_dir: Mutex::new(None),
            admin_ports: Mutex::new(vec![23456]),
        })
    }

    async fn detect_backend(pref: &str, exec: &dyn FirewallExecutor) -> FirewallBackend {
        if !cfg!(target_os = "linux") {
            return FirewallBackend::DryRun;
        }
        match pref {
            "nftables" => return FirewallBackend::Nftables,
            "iptables_legacy" => return FirewallBackend::IptablesLegacy,
            "iptables_nft" => return FirewallBackend::IptablesNft,
            _ => {}
        }
        if exec.run("nft", &["list", "table", "inet", "fw4"], None).await.is_ok() {
            return FirewallBackend::Nftables;
        }
        if exec.run("iptables-legacy", &["-L", "-n"], None).await.is_ok() {
            return FirewallBackend::IptablesLegacy;
        }
        if exec.run("iptables", &["-L", "-n"], None).await.is_ok() {
            return FirewallBackend::IptablesNft;
        }
        FirewallBackend::DryRun
    }

    pub fn backend(&self) -> FirewallBackend {
        self.backend
    }

    /// 若已绑定 `data_dir`，从磁盘 `.lockdown` 标记重新同步闭锁状态到内存，防止守护进程覆盖外部 CLI 闭锁
    pub fn refresh_lockdown_from_disk(&self) -> bool {
        let data_dir = self.data_dir.lock().ok().and_then(|g| g.clone());
        if let Some(dir) = data_dir {
            let active = read_persisted_lockdown(&dir);
            if let Ok(mut l) = self.lockdown.lock() {
                *l = active;
            }
            active
        } else {
            self.lockdown.lock().map(|g| *g).unwrap_or(false)
        }
    }

    pub fn is_lockdown(&self) -> bool {
        self.refresh_lockdown_from_disk()
    }

    pub fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::Acquire)
    }

    pub fn is_auto_manage(&self) -> bool {
        self.cfg.lock().map(|g| g.auto_manage).unwrap_or(true)
    }

    pub fn set_data_dir(&self, data_dir: PathBuf) {
        if let Ok(mut g) = self.data_dir.lock() {
            *g = Some(data_dir);
        }
    }

    pub fn init_lockdown_from_disk(&self, data_dir: &Path) -> bool {
        let active = read_persisted_lockdown(data_dir);
        if let Ok(mut l) = self.lockdown.lock() {
            *l = active;
        }
        active
    }

    pub fn set_protected_admin_ports(&self, ports: Vec<u16>) {
        if let Ok(mut g) = self.admin_ports.lock() {
            *g = ports;
        }
    }

    pub fn update_config(&self, new_cfg: FirewallConfig) {
        if let Ok(mut g) = self.cfg.lock() {
            *g = new_cfg;
        }
    }

    pub fn list_rules(&self) -> Vec<FirewallRule> {
        self.rules.lock().map(|g| g.clone()).unwrap_or_default()
    }

    fn snapshot_active_bans(&self, now_unix: u64) -> BTreeMap<BanKey, u64> {
        let Ok(mut map) = self.bans.lock() else { return BTreeMap::new() };
        map.retain(|_, exp| *exp > now_unix);
        map.clone()
    }

    fn validate_rule_defense_in_depth(&self, rule: &FirewallRule) -> Result<(), String> {
        let admin_ports = self.admin_ports.lock().map(|g| g.clone()).unwrap_or_else(|_| vec![23456]);
        match rule {
            FirewallRule::WanInput { proto, port, .. } => {
                validate_proto(proto)?;
                validate_wan_input_ports(*port, &admin_ports, "wan")?;
            }
            FirewallRule::KernelDnat {
                proto,
                listen_port,
                target,
                ..
            } => {
                validate_proto(proto)?;
                validate_wan_input_ports(*listen_port, &admin_ports, "wan")?;
                let ip = normalize_ip(target.ip());
                if ip.is_loopback() || ip.is_unspecified() {
                    return Err(format!("安全与协议拦截：kernel_dnat 目标不能为环回或未指定地址 ({})", target));
                }
                validate_forward_target_safety_strict_inner(
                    target.ip(),
                    target.port(),
                    true,
                    false,
                    &admin_ports,
                    &[],
                    &collect_local_interface_ips(),
                )?;
            }
            FirewallRule::SubDeviceIpv6Forward { device_ip, .. } => {
                let ip = IpAddr::V6(*device_ip);
                if ip.is_loopback() || is_disallowed_upstream_or_metadata_ip(ip) {
                    return Err(format!("安全底线拦截：子设备 IPv6 转发目标非法 ({})", device_ip));
                }
            }
        }
        Ok(())
    }

    /// 内存已回滚至旧状态后，尝试重新下发旧规则集到内核；若内核恢复亦失败则置 degraded 标志
    async fn recover_kernel_after_failure_locked(&self, context: &str) {
        if !self.is_auto_manage() || self.backend == FirewallBackend::DryRun {
            return;
        }
        match self.sync_all_locked().await {
            Ok(()) => {
                logger::log(
                    Level::Warn,
                    "firewall",
                    &format!("{} 失败后已将旧规则集重新下发内核，内存与内核状态已恢复一致", context),
                );
            }
            Err(rec_err) => {
                self.degraded.store(true, Ordering::Release);
                logger::log(
                    Level::Error,
                    "firewall",
                    &format!(
                        "{} 失败且内核回滚恢复亦失败，防火墙进入降级(degraded)状态: {}",
                        context, rec_err
                    ),
                );
            }
        }
    }

    /// 启动预清扫：清除上次进程异常退出残留的 vane 自定义子链，再重新挂载空链与当前封禁表
    pub async fn pre_start_sweep(&self) -> Result<(), String> {
        let _serial = self.op_lock.lock().await;
        if !self.is_auto_manage() || self.backend == FirewallBackend::DryRun {
            return Ok(());
        }
        let cfg = self.cfg.lock().map_err(|_| "防火墙配置锁损坏")?.clone();
        let now = logger::unix_now();
        let bans = self.snapshot_active_bans(now);
        let res = match self.backend {
            FirewallBackend::Nftables => nftables::apply_rules(self.executor.as_ref(), &cfg, &[], &bans, now).await,
            FirewallBackend::IptablesLegacy => {
                iptables::apply_rules(self.executor.as_ref(), "iptables-legacy", "ip6tables-legacy", &cfg, &[], &bans)
                    .await
            }
            FirewallBackend::IptablesNft => {
                iptables::apply_rules(self.executor.as_ref(), "iptables", "ip6tables", &cfg, &[], &bans).await
            }
            FirewallBackend::DryRun => Ok(()),
        };
        if res.is_ok() {
            self.degraded.store(false, Ordering::Release);
        } else {
            self.degraded.store(true, Ordering::Release);
        }
        res
    }

    /// 注册或更新单条规则并同步到底层防火墙；纵深防御拦截高危端口，失败则回滚内存并重发旧规则集到内核
    pub async fn upsert_rule(&self, rule: FirewallRule) -> Result<(), String> {
        self.validate_rule_defense_in_depth(&rule)?;
        let _serial = self.op_lock.lock().await;
        let prev = {
            let mut g = self.rules.lock().map_err(|_| "防火墙规则锁损坏")?;
            let prev = g.clone();
            g.retain(|r| !(r.owner() == rule.owner() && r.name() == rule.name()));
            g.push(rule);
            prev
        };
        if let Err(e) = self.sync_all_locked().await {
            if let Ok(mut g) = self.rules.lock() {
                *g = prev;
            }
            self.recover_kernel_after_failure_locked("upsert_rule").await;
            return Err(e);
        }
        Ok(())
    }

    /// 移除某个模块名下的全部防火墙放行规则（当子模块被关闭或停止时调用）并清理 conntrack；若底层失败则回滚内存并恢复内核
    pub async fn remove_module_rules(&self, owner_module: &str) -> Result<(), String> {
        let _serial = self.op_lock.lock().await;
        let (prev, removed): (Vec<FirewallRule>, Vec<FirewallRule>) = {
            let mut g = self.rules.lock().map_err(|_| "防火墙规则锁损坏")?;
            let prev = g.clone();
            let (gone, keep): (Vec<_>, Vec<_>) = g.drain(..).partition(|r| r.owner() == owner_module);
            *g = keep;
            (prev, gone)
        };
        if removed.is_empty() {
            return Ok(());
        }
        if let Err(e) = self.sync_all_locked().await {
            if let Ok(mut g) = self.rules.lock() {
                *g = prev;
            }
            self.recover_kernel_after_failure_locked("remove_module_rules").await;
            return Err(e);
        }
        for r in &removed {
            let _ = self.flush_conntrack_for_rule(r).await;
        }
        Ok(())
    }

    /// 移除指定名称的规则并断流；若底层同步失败则回滚内存并恢复内核
    pub async fn remove_rule(&self, owner_module: &str, rule_name: &str) -> Result<(), String> {
        let _serial = self.op_lock.lock().await;
        let (prev, removed): (Vec<FirewallRule>, Vec<FirewallRule>) = {
            let mut g = self.rules.lock().map_err(|_| "防火墙规则锁损坏")?;
            let prev = g.clone();
            let (gone, keep): (Vec<_>, Vec<_>) =
                g.drain(..).partition(|r| r.owner() == owner_module && r.name() == rule_name);
            *g = keep;
            (prev, gone)
        };
        if removed.is_empty() {
            return Ok(());
        }
        if let Err(e) = self.sync_all_locked().await {
            if let Ok(mut g) = self.rules.lock() {
                *g = prev;
            }
            self.recover_kernel_after_failure_locked("remove_rule").await;
            return Err(e);
        }
        for r in &removed {
            let _ = self.flush_conntrack_for_rule(r).await;
        }
        Ok(())
    }

    /// 一键紧急封锁（Lockdown）详细版：显式报告内核生效状态、conntrack 断流结果与降级告警，绝不静默掩盖失效
    pub async fn trigger_lockdown_detailed(&self, enabled: bool) -> Result<LockdownReport, String> {
        let _serial = self.op_lock.lock().await;
        let prev = self.is_lockdown();
        let data_dir = self.data_dir.lock().ok().and_then(|g| g.clone());

        if let Some(ref dir) = data_dir {
            write_persisted_lockdown(dir, enabled)?;
        }
        if let Ok(mut l) = self.lockdown.lock() {
            *l = enabled;
        }

        let rules_snapshot = self.list_rules();
        let mut warnings = Vec::new();

        if !self.is_auto_manage() {
            warnings.push(
                "firewall.auto_manage=false，未向内核防火墙下发封锁规则或清理 conntrack，仅更新内存与持久化状态"
                    .into(),
            );
            logger::log(
                Level::Warn,
                "firewall",
                &format!("紧急闭锁({})未下发内核：firewall.auto_manage=false", enabled),
            );
            return Ok(LockdownReport {
                active: enabled,
                kernel_enforced: false,
                conntrack_flushed: false,
                warnings,
            });
        }

        if self.backend == FirewallBackend::DryRun {
            warnings.push(
                "当前防火墙后端为 DryRun（非 Linux 或未检测到 nftables/iptables），未向内核下发封锁规则或清理 conntrack"
                    .into(),
            );
            logger::log(
                Level::Warn,
                "firewall",
                &format!("紧急闭锁({})未下发内核：当前处于 DryRun 后端", enabled),
            );
            return Ok(LockdownReport {
                active: enabled,
                kernel_enforced: false,
                conntrack_flushed: false,
                warnings,
            });
        }

        if let Err(e) = self.sync_all_locked().await {
            if let Ok(mut l) = self.lockdown.lock() {
                *l = prev;
            }
            if let Some(ref dir) = data_dir {
                let _ = write_persisted_lockdown(dir, prev);
            }
            self.recover_kernel_after_failure_locked("trigger_lockdown").await;
            return Err(e);
        }

        let mut conntrack_flushed = false;
        if enabled {
            let mut all_ok = true;
            for r in &rules_snapshot {
                if let Err(err) = self.flush_conntrack_for_rule(r).await {
                    all_ok = false;
                    warnings.push(format!("清理规则 {} conntrack 失败（已建立连接可能存活）: {}", r.name(), err));
                }
            }
            conntrack_flushed = all_ok;
            logger::log(
                Level::Warn,
                "firewall",
                &format!(
                    "已启用防火墙紧急闭锁模式：所有 WAN 放行规则已挂起（conntrack_flushed={}, warnings={}）",
                    conntrack_flushed,
                    warnings.len()
                ),
            );
        } else {
            logger::log(Level::Info, "firewall", "已解除防火墙紧急闭锁模式，恢复正常规则同步");
        }

        Ok(LockdownReport {
            active: enabled,
            kernel_enforced: true,
            conntrack_flushed,
            warnings,
        })
    }

    /// 一键紧急封锁（Lockdown）向后兼容入口
    pub async fn trigger_lockdown(&self, enable: bool) -> Result<(), String> {
        self.trigger_lockdown_detailed(enable).await.map(|_| ())
    }

    /// 封禁恶意源 IP 或 IPv6 /64 子网并立即切断其现有 conntrack 连接（回环/链路本地仅应用层封禁，防止内网断联）
    pub async fn ban_source_cidr(&self, cidr_or_ip: &str, duration_secs: u64) -> Result<(), String> {
        let key = BanKey::parse_cidr_or_ip(cidr_or_ip).ok_or_else(|| format!("非法封禁地址: {}", cidr_or_ip))?;
        if key.is_loopback_or_link_local() {
            return Ok(());
        }
        let dur = duration_secs.clamp(60, 86_400);
        let now = logger::unix_now();
        let _serial = self.op_lock.lock().await;
        let prev_bans = {
            let mut bans = self.bans.lock().map_err(|_| "封禁锁损坏")?;
            let prev = bans.clone();
            bans.retain(|_, exp| *exp > now);
            if bans.len() >= 1024 && !bans.contains_key(&key) {
                if let Some(oldest) = bans.iter().min_by_key(|(_, exp)| **exp).map(|(k, _)| *k) {
                    bans.remove(&oldest);
                }
            }
            bans.insert(key, now + dur);
            prev
        };
        if !self.is_auto_manage() || self.backend == FirewallBackend::DryRun {
            return Ok(());
        }
        let norm_cidr = key.display_cidr();
        let sync_res = match self.backend {
            FirewallBackend::Nftables => {
                if nftables::add_ban_cidr(self.executor.as_ref(), &norm_cidr, dur).await.is_err() {
                    self.sync_all_locked().await
                } else {
                    Ok(())
                }
            }
            FirewallBackend::IptablesLegacy | FirewallBackend::IptablesNft => self.sync_all_locked().await,
            FirewallBackend::DryRun => Ok(()),
        };
        if let Err(e) = sync_res {
            if let Ok(mut bans) = self.bans.lock() {
                *bans = prev_bans;
            }
            self.recover_kernel_after_failure_locked("ban_source_cidr").await;
            return Err(e);
        }
        let fam = match key {
            BanKey::V4(_) => "ipv4",
            BanKey::V6Prefix64(_) => "ipv6",
        };
        let _ = self.executor.run("conntrack", &["-D", "-f", fam, "-s", &norm_cidr], None).await;
        Ok(())
    }

    /// 解除源 IP / IPv6 /64 子网的内核封禁（失败回滚内存封禁表并恢复内核）
    pub async fn unban_source_cidr(&self, cidr_or_ip: &str) -> Result<bool, String> {
        let key = BanKey::parse_cidr_or_ip(cidr_or_ip).ok_or_else(|| format!("非法解封地址: {}", cidr_or_ip))?;
        let _serial = self.op_lock.lock().await;
        let (prev_bans, existed) = {
            let mut g = self.bans.lock().map_err(|_| "封禁锁损坏")?;
            let prev = g.clone();
            let ex = g.remove(&key).is_some();
            (prev, ex)
        };
        if !self.is_auto_manage() || self.backend == FirewallBackend::DryRun {
            return Ok(existed);
        }
        let norm_cidr = key.display_cidr();
        let sync_res = match self.backend {
            FirewallBackend::Nftables => {
                if nftables::remove_ban_cidr(self.executor.as_ref(), &norm_cidr).await.is_err() {
                    self.sync_all_locked().await
                } else {
                    Ok(())
                }
            }
            FirewallBackend::IptablesLegacy | FirewallBackend::IptablesNft => self.sync_all_locked().await,
            FirewallBackend::DryRun => Ok(()),
        };
        if let Err(e) = sync_res {
            if let Ok(mut g) = self.bans.lock() {
                *g = prev_bans;
            }
            self.recover_kernel_after_failure_locked("unban_source_cidr").await;
            return Err(e);
        }
        Ok(existed)
    }

    pub async fn sync_all(&self) -> Result<(), String> {
        let _serial = self.op_lock.lock().await;
        let res = self.sync_all_locked().await;
        if res.is_err() {
            self.degraded.store(true, Ordering::Release);
        }
        res
    }

    async fn sync_all_locked(&self) -> Result<(), String> {
        let locked = self.refresh_lockdown_from_disk();
        if !self.is_auto_manage() || self.backend == FirewallBackend::DryRun {
            return Ok(());
        }
        let cfg = self.cfg.lock().map_err(|_| "防火墙配置锁损坏")?.clone();
        let active_rules = if locked { Vec::new() } else { self.list_rules() };
        let now = logger::unix_now();
        let bans = self.snapshot_active_bans(now);
        let res = match self.backend {
            FirewallBackend::Nftables => {
                nftables::apply_rules(self.executor.as_ref(), &cfg, &active_rules, &bans, now).await
            }
            FirewallBackend::IptablesLegacy => {
                iptables::apply_rules(
                    self.executor.as_ref(),
                    "iptables-legacy",
                    "ip6tables-legacy",
                    &cfg,
                    &active_rules,
                    &bans,
                )
                .await
            }
            FirewallBackend::IptablesNft => {
                iptables::apply_rules(self.executor.as_ref(), "iptables", "ip6tables", &cfg, &active_rules, &bans).await
            }
            FirewallBackend::DryRun => Ok(()),
        };
        if res.is_ok() {
            self.degraded.store(false, Ordering::Release);
        }
        res
    }

    async fn run_conntrack_delete(&self, args: &[&str]) -> Result<(), String> {
        match self.executor.run("conntrack", args, None).await {
            Ok(_) => Ok(()),
            // conntrack -D 在无匹配活跃连接时会返回非零退出码并输出 "0 flow entries have been deleted"
            Err(e) if e.contains("0 flow entries") => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn flush_conntrack_for_rule(&self, rule: &FirewallRule) -> Result<(), String> {
        if !self.is_auto_manage() || self.backend == FirewallBackend::DryRun {
            return Err("未启用内核防火墙管理或处于 DryRun 模式".into());
        }
        let mut errors = Vec::new();
        match rule {
            FirewallRule::WanInput { proto, port, ipv4, ipv6, .. } => {
                let port_s = port.to_string();
                if *ipv4 {
                    if let Err(e) = self
                        .run_conntrack_delete(&["-D", "-f", "ipv4", "-p", proto, "--dport", &port_s])
                        .await
                    {
                        errors.push(e);
                    }
                }
                if *ipv6 {
                    if let Err(e) = self
                        .run_conntrack_delete(&["-D", "-f", "ipv6", "-p", proto, "--dport", &port_s])
                        .await
                    {
                        errors.push(e);
                    }
                }
            }
            FirewallRule::KernelDnat { proto, listen_port: port, target, .. } => {
                let port_s = port.to_string();
                let target_ip = target.ip().to_string();
                let fam = if target.is_ipv6() { "ipv6" } else { "ipv4" };
                if let Err(e) = self
                    .run_conntrack_delete(&["-D", "-f", fam, "-p", proto, "--dport", &port_s, "--reply-src", &target_ip])
                    .await
                {
                    errors.push(e);
                }
            }
            FirewallRule::SubDeviceIpv6Forward { device_ip, .. } => {
                let ip_s = device_ip.to_string();
                if let Err(e) = self
                    .run_conntrack_delete(&["-D", "-f", "ipv6", "-d", &ip_s])
                    .await
                {
                    errors.push(e);
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

#[cfg(test)]
#[path = "firewall_tests.rs"]
mod tests;
