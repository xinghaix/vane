//! 防火墙驱动层：本机受保护端口与环回绕过守卫、接口名严格校验、5s 异步受控执行器、
//! fw4 (nftables 单事务 + 高优先级封禁表) 与 fw3 (iptables/ip6tables) 串行对账与失败回滚。
pub mod iptables;
pub mod nftables;

use crate::config::FirewallConfig;
use crate::logger::{self, Level};
use crate::net::dual_stack::BanKey;
use serde::Serialize;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

/// 路由器本机高危服务端口黑名单（拦截直接开放本机 WAN INPUT，或通过本机环回转发变相暴露）
pub const PROTECTED_LOCAL_INPUT_PORTS: &[u16] = &[
    21, 22, 23, 53, 67, 68, 80, 139, 443, 445, 1883, 2375, 2376, 3306, 4000, 5432, 6379,
];

pub fn validate_wan_input_port(port: u16, admin_port: u16, zone: &str) -> Result<(), String> {
    if zone.eq_ignore_ascii_case("wan") {
        if port == admin_port {
            return Err(format!("安全底线拦截：严禁在 WAN INPUT 直接放行管理后台端口 {}", port));
        }
        if PROTECTED_LOCAL_INPUT_PORTS.contains(&port) {
            return Err(format!("安全底线拦截：严禁在 WAN INPUT 放行路由器本机高危受保护端口 {}", port));
        }
    }
    Ok(())
}

/// 防止通过端口转发指向 127.0.0.1 / ::1 / 0.0.0.0 或管理监听地址绕过本机高危端口守卫
pub fn validate_forward_target_safety(
    target: SocketAddr,
    engine: &str,
    open_wan_firewall: bool,
    admin_port: u16,
    admin_listeners: &[String],
) -> Result<(), String> {
    let ip = match target.ip() {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        other => other,
    };
    let is_local_special = ip.is_loopback() || ip.is_unspecified();
    if engine == "kernel_dnat" && is_local_special {
        return Err(format!("安全与协议拦截：kernel_dnat 目标不能为环回或未指定地址 ({})", target));
    }
    if open_wan_firewall || engine == "kernel_dnat" {
        if is_local_special && (target.port() == admin_port || PROTECTED_LOCAL_INPUT_PORTS.contains(&target.port())) {
            return Err(format!(
                "安全底线拦截：禁止将公网端口转发指向本机受保护端口或管理端口 ({})",
                target
            ));
        }
        for listen in admin_listeners {
            if let Ok(admin_sock) = listen.parse::<SocketAddr>() {
                if admin_sock == target || (admin_sock.ip().is_unspecified() && admin_sock.port() == target.port() && is_local_special) {
                    return Err(format!("安全底线拦截：禁止将公网端口转发指向管理后台监听地址 ({})", target));
                }
            }
        }
    }
    Ok(())
}

pub fn validate_iface_name(iface: &str) -> Result<(), String> {
    if iface.is_empty() || iface.len() > 15 {
        return Err(format!("网卡名称长度非法: {}", iface));
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

/// 异步非阻塞执行宿主机防火墙/conntrack 命令，5 秒硬超时 + kill_on_drop + 有界输出
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

    pub fn is_lockdown(&self) -> bool {
        self.lockdown.lock().map(|g| *g).unwrap_or(false)
    }

    pub fn is_auto_manage(&self) -> bool {
        self.cfg.lock().map(|g| g.auto_manage).unwrap_or(true)
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

    /// 启动预清扫：清除上次进程异常退出残留的 vane 自定义子链，再重新挂载空链与当前封禁表
    pub async fn pre_start_sweep(&self) -> Result<(), String> {
        let _serial = self.op_lock.lock().await;
        if !self.is_auto_manage() || self.backend == FirewallBackend::DryRun {
            return Ok(());
        }
        let cfg = self.cfg.lock().map_err(|_| "防火墙配置锁损坏")?.clone();
        let now = logger::unix_now();
        let bans = self.snapshot_active_bans(now);
        match self.backend {
            FirewallBackend::Nftables => nftables::apply_rules(self.executor.as_ref(), &cfg, &[], &bans, now).await,
            FirewallBackend::IptablesLegacy => {
                iptables::apply_rules(self.executor.as_ref(), "iptables-legacy", "ip6tables-legacy", &cfg, &[], &bans)
                    .await
            }
            FirewallBackend::IptablesNft => {
                iptables::apply_rules(self.executor.as_ref(), "iptables", "ip6tables", &cfg, &[], &bans).await
            }
            FirewallBackend::DryRun => Ok(()),
        }
    }

    /// 注册或更新单条规则并同步到底层防火墙；若底层下发失败则回滚内存状态（失败关闭）
    pub async fn upsert_rule(&self, rule: FirewallRule) -> Result<(), String> {
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
            return Err(e);
        }
        Ok(())
    }

    /// 移除某个模块名下的全部防火墙放行规则（当子模块被关闭或停止时调用）并清理 conntrack
    pub async fn remove_module_rules(&self, owner_module: &str) -> Result<(), String> {
        let _serial = self.op_lock.lock().await;
        let removed: Vec<FirewallRule> = {
            let mut g = self.rules.lock().map_err(|_| "防火墙规则锁损坏")?;
            let (gone, keep): (Vec<_>, Vec<_>) = g.drain(..).partition(|r| r.owner() == owner_module);
            *g = keep;
            gone
        };
        if removed.is_empty() {
            return Ok(());
        }
        self.sync_all_locked().await?;
        for r in &removed {
            self.flush_conntrack_for_rule(r).await;
        }
        Ok(())
    }

    /// 移除指定名称的规则并断流
    pub async fn remove_rule(&self, owner_module: &str, rule_name: &str) -> Result<(), String> {
        let _serial = self.op_lock.lock().await;
        let removed: Vec<FirewallRule> = {
            let mut g = self.rules.lock().map_err(|_| "防火墙规则锁损坏")?;
            let (gone, keep): (Vec<_>, Vec<_>) =
                g.drain(..).partition(|r| r.owner() == owner_module && r.name() == rule_name);
            *g = keep;
            gone
        };
        if removed.is_empty() {
            return Ok(());
        }
        self.sync_all_locked().await?;
        for r in &removed {
            self.flush_conntrack_for_rule(r).await;
        }
        Ok(())
    }

    /// 一键紧急封锁（Lockdown）：立即清空所有 WAN 放行链并切断已建立连接
    pub async fn trigger_lockdown(&self, enable: bool) -> Result<(), String> {
        let _serial = self.op_lock.lock().await;
        let prev = self.is_lockdown();
        if let Ok(mut l) = self.lockdown.lock() {
            *l = enable;
        }
        let rules_snapshot = self.list_rules();
        if let Err(e) = self.sync_all_locked().await {
            if let Ok(mut l) = self.lockdown.lock() {
                *l = prev;
            }
            return Err(e);
        }
        if enable {
            for r in &rules_snapshot {
                self.flush_conntrack_for_rule(r).await;
            }
            logger::log(
                Level::Warn,
                "firewall",
                "已启用防火墙紧急闭锁模式：所有 WAN 放行规则已挂起并清理活跃连接",
            );
        } else {
            logger::log(Level::Info, "firewall", "已解除防火墙紧急闭锁模式，恢复正常规则同步");
        }
        Ok(())
    }

    /// 封禁恶意源 IP 或 IPv6 /64 子网并立即切断其现有 conntrack 连接
    pub async fn ban_source_cidr(&self, cidr_or_ip: &str, duration_secs: u64) -> Result<(), String> {
        let key = BanKey::parse_cidr_or_ip(cidr_or_ip).ok_or_else(|| format!("非法封禁地址: {}", cidr_or_ip))?;
        let dur = duration_secs.clamp(60, 86_400);
        let now = logger::unix_now();
        let _serial = self.op_lock.lock().await;
        {
            let mut bans = self.bans.lock().map_err(|_| "封禁锁损坏")?;
            bans.retain(|_, exp| *exp > now);
            if bans.len() >= 1024 && !bans.contains_key(&key) {
                if let Some(oldest) = bans.iter().min_by_key(|(_, exp)| **exp).map(|(k, _)| *k) {
                    bans.remove(&oldest);
                }
            }
            bans.insert(key, now + dur);
        }
        if !self.is_auto_manage() || self.backend == FirewallBackend::DryRun {
            return Ok(());
        }
        let norm_cidr = key.display_cidr();
        match self.backend {
            FirewallBackend::Nftables => {
                if nftables::add_ban_cidr(self.executor.as_ref(), &norm_cidr, dur).await.is_err() {
                    self.sync_all_locked().await?;
                }
            }
            FirewallBackend::IptablesLegacy | FirewallBackend::IptablesNft => {
                self.sync_all_locked().await?;
            }
            FirewallBackend::DryRun => {}
        }
        let _ = self.executor.run("conntrack", &["-D", "-s", &norm_cidr], None).await;
        Ok(())
    }

    /// 解除源 IP / IPv6 /64 子网的内核封禁
    pub async fn unban_source_cidr(&self, cidr_or_ip: &str) -> Result<bool, String> {
        let key = BanKey::parse_cidr_or_ip(cidr_or_ip).ok_or_else(|| format!("非法解封地址: {}", cidr_or_ip))?;
        let _serial = self.op_lock.lock().await;
        let existed = self
            .bans
            .lock()
            .map_err(|_| "封禁锁损坏")?
            .remove(&key)
            .is_some();
        if !self.is_auto_manage() || self.backend == FirewallBackend::DryRun {
            return Ok(existed);
        }
        let norm_cidr = key.display_cidr();
        match self.backend {
            FirewallBackend::Nftables => {
                if nftables::remove_ban_cidr(self.executor.as_ref(), &norm_cidr).await.is_err() {
                    self.sync_all_locked().await?;
                }
            }
            FirewallBackend::IptablesLegacy | FirewallBackend::IptablesNft => {
                self.sync_all_locked().await?;
            }
            FirewallBackend::DryRun => {}
        }
        Ok(existed)
    }

    pub async fn sync_all(&self) -> Result<(), String> {
        let _serial = self.op_lock.lock().await;
        self.sync_all_locked().await
    }

    async fn sync_all_locked(&self) -> Result<(), String> {
        if !self.is_auto_manage() || self.backend == FirewallBackend::DryRun {
            return Ok(());
        }
        let cfg = self.cfg.lock().map_err(|_| "防火墙配置锁损坏")?.clone();
        let active_rules = if self.is_lockdown() { Vec::new() } else { self.list_rules() };
        let now = logger::unix_now();
        let bans = self.snapshot_active_bans(now);
        match self.backend {
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
        }
    }

    async fn flush_conntrack_for_rule(&self, rule: &FirewallRule) {
        if !self.is_auto_manage() || self.backend == FirewallBackend::DryRun {
            return;
        }
        match rule {
            FirewallRule::WanInput { proto, port, .. }
            | FirewallRule::KernelDnat { proto, listen_port: port, .. } => {
                let port_s = port.to_string();
                let _ = self
                    .executor
                    .run("conntrack", &["-D", "-p", proto, "--dport", &port_s], None)
                    .await;
            }
            FirewallRule::SubDeviceIpv6Forward { device_ip, .. } => {
                let ip_s = device_ip.to_string();
                let _ = self.executor.run("conntrack", &["-D", "-d", &ip_s], None).await;
            }
        }
    }
}

#[cfg(test)]
#[path = "firewall_tests.rs"]
mod tests;
