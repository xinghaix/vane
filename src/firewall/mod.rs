//! 防火墙驱动层：本机受保护端口守卫、接口名严格校验、5s 异步超时命令执行器、
//! fw4 (nftables) 与 fw3 (iptables/ip6tables) 自动探测与规则同步。
pub mod iptables;
pub mod nftables;

use crate::config::FirewallConfig;
use crate::logger::{self, Level};
use serde::Serialize;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::process::Command;

/// 路由器本机高危服务端口黑名单（仅针对打开路由器本机 WAN INPUT 链生效；转发至内网不同 IP 的 DNAT 不受影响）
pub const PROTECTED_LOCAL_INPUT_PORTS: &[u16] = &[
    21, 22, 23, 53, 67, 68, 80, 139, 443, 445, 1883, 2375, 2376, 3306, 5432, 6379,
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

pub fn validate_iface_name(iface: &str) -> Result<(), String> {
    if iface.is_empty() || iface.len() > 15 {
        return Err(format!("网卡名称长度非法: {}", iface));
    }
    if !iface.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.') {
        return Err(format!("网卡名称包含非法字符: {}", iface));
    }
    Ok(())
}

/// 异步非阻塞执行宿主机防火墙/conntrack 命令，5 秒硬超时 + kill_on_drop
pub async fn run_fw_cmd_async(program: &str, args: &[&str]) -> Result<String, String> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let fut = cmd.output();
    match tokio::time::timeout(Duration::from_secs(5), fut).await {
        Ok(Ok(out)) if out.status.success() => Ok(String::from_utf8_lossy(&out.stdout).into_owned()),
        Ok(Ok(out)) => Err(format!(
            "{} {:?} 退出码 {:?}: {}",
            program,
            args,
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        )),
        Ok(Err(e)) => Err(format!("启动 {} 失败: {}", program, e)),
        Err(_) => Err(format!("执行 {} {:?} 超时 (5s)", program, args)),
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
    cfg: Mutex<FirewallConfig>,
    rules: Mutex<Vec<FirewallRule>>,
    lockdown: Mutex<bool>,
}

impl FirewallManager {
    pub async fn detect_and_init(cfg: FirewallConfig) -> Arc<Self> {
        let backend = Self::detect_backend(&cfg.backend).await;
        logger::log(Level::Info, "firewall", &format!("初始化防火墙后端: {:?}", backend));
        let mgr = Arc::new(Self {
            backend,
            cfg: Mutex::new(cfg),
            rules: Mutex::new(Vec::new()),
            lockdown: Mutex::new(false),
        });
        if mgr.is_auto_manage() {
            let _ = mgr.pre_start_sweep().await;
        }
        mgr
    }

    async fn detect_backend(pref: &str) -> FirewallBackend {
        match pref {
            "nftables" => return FirewallBackend::Nftables,
            "iptables_legacy" => return FirewallBackend::IptablesLegacy,
            "iptables_nft" => return FirewallBackend::IptablesNft,
            _ => {}
        }
        if cfg!(target_os = "linux") {
            if run_fw_cmd_async("nft", &["list", "table", "inet", "fw4"]).await.is_ok() {
                return FirewallBackend::Nftables;
            }
            if run_fw_cmd_async("iptables-legacy", &["-L", "-n"]).await.is_ok() {
                return FirewallBackend::IptablesLegacy;
            }
            if run_fw_cmd_async("iptables", &["-L", "-n"]).await.is_ok() {
                return FirewallBackend::IptablesNft;
            }
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

    /// 启动预清扫：清除上次进程异常退出残留的 vane 自定义子链，再重新挂载空链
    pub async fn pre_start_sweep(&self) -> Result<(), String> {
        let cfg = self.cfg.lock().map_err(|_| "lock poisoned")?.clone();
        match self.backend {
            FirewallBackend::Nftables => nftables::reset_chains(&cfg).await,
            FirewallBackend::IptablesLegacy => iptables::reset_chains("iptables-legacy", "ip6tables-legacy", &cfg).await,
            FirewallBackend::IptablesNft => iptables::reset_chains("iptables", "ip6tables", &cfg).await,
            FirewallBackend::DryRun => Ok(()),
        }
    }

    /// 注册或更新单条规则并同步到底层防火墙
    pub async fn upsert_rule(&self, rule: FirewallRule) -> Result<(), String> {
        {
            let mut g = self.rules.lock().map_err(|_| "lock poisoned")?;
            g.retain(|r| !(r.owner() == rule.owner() && r.name() == rule.name()));
            g.push(rule);
        }
        self.sync_all().await
    }

    /// 移除某个模块名下的全部防火墙放行规则（当子模块被关闭或停止时调用）并清理 conntrack
    pub async fn remove_module_rules(&self, owner_module: &str) -> Result<(), String> {
        let removed: Vec<FirewallRule> = {
            let mut g = self.rules.lock().map_err(|_| "lock poisoned")?;
            let ( gone, keep ): (Vec<_>, Vec<_>) = g.drain(..).partition(|r| r.owner() == owner_module);
            *g = keep;
            gone
        };
        self.sync_all().await?;
        for r in removed {
            self.flush_conntrack_for_rule(&r).await;
        }
        Ok(())
    }

    /// 移除指定名称的规则并断流
    pub async fn remove_rule(&self, owner_module: &str, rule_name: &str) -> Result<(), String> {
        let removed: Vec<FirewallRule> = {
            let mut g = self.rules.lock().map_err(|_| "lock poisoned")?;
            let (gone, keep): (Vec<_>, Vec<_>) =
                g.drain(..).partition(|r| r.owner() == owner_module && r.name() == rule_name);
            *g = keep;
            gone
        };
        self.sync_all().await?;
        for r in removed {
            self.flush_conntrack_for_rule(&r).await;
        }
        Ok(())
    }

    /// 一键紧急封锁（Lockdown）：立即清空所有 WAN 放行链并切断已建立连接
    pub async fn trigger_lockdown(&self, enable: bool) -> Result<(), String> {
        if let Ok(mut l) = self.lockdown.lock() {
            *l = enable;
        }
        let rules_snapshot = self.list_rules();
        self.sync_all().await?;
        if enable {
            for r in &rules_snapshot {
                self.flush_conntrack_for_rule(r).await;
            }
            logger::log(Level::Warn, "firewall", "已启用防火墙紧急闭锁模式：所有 WAN 放行规则已挂起并清理活跃连接");
        } else {
            logger::log(Level::Info, "firewall", "已解除防火墙紧急闭锁模式，恢复正常规则同步");
        }
        Ok(())
    }

    /// 封禁恶意源 IP 或 IPv6 /64 子网并立即切断其现有 conntrack 连接
    pub async fn ban_source_cidr(&self, cidr: &str, duration_secs: u64) -> Result<(), String> {
        match self.backend {
            FirewallBackend::Nftables => nftables::add_ban_cidr(cidr, duration_secs).await?,
            FirewallBackend::IptablesLegacy => iptables::add_ban_cidr("iptables-legacy", "ip6tables-legacy", cidr).await?,
            FirewallBackend::IptablesNft => iptables::add_ban_cidr("iptables", "ip6tables", cidr).await?,
            FirewallBackend::DryRun => {}
        }
        if let Some(ip_part) = cidr.split('/').next() {
            if let Ok(ip) = ip_part.parse::<IpAddr>() {
                let _ = run_fw_cmd_async("conntrack", &["-D", "-s", &ip.to_string()]).await;
            }
        }
        Ok(())
    }

    pub async fn sync_all(&self) -> Result<(), String> {
        if !self.is_auto_manage() {
            return Ok(());
        }
        let cfg = self.cfg.lock().map_err(|_| "lock poisoned")?.clone();
        let active_rules = if self.is_lockdown() {
            Vec::new()
        } else {
            self.list_rules()
        };
        match self.backend {
            FirewallBackend::Nftables => nftables::apply_rules(&cfg, &active_rules).await,
            FirewallBackend::IptablesLegacy => {
                iptables::apply_rules("iptables-legacy", "ip6tables-legacy", &cfg, &active_rules).await
            }
            FirewallBackend::IptablesNft => iptables::apply_rules("iptables", "ip6tables", &cfg, &active_rules).await,
            FirewallBackend::DryRun => Ok(()),
        }
    }

    async fn flush_conntrack_for_rule(&self, rule: &FirewallRule) {
        if self.backend == FirewallBackend::DryRun {
            return;
        }
        match rule {
            FirewallRule::WanInput { proto, port, .. } | FirewallRule::KernelDnat { proto, listen_port: port, .. } => {
                let port_s = port.to_string();
                let _ = run_fw_cmd_async("conntrack", &["-D", "-p", proto, "--dport", &port_s]).await;
            }
            FirewallRule::SubDeviceIpv6Forward { device_ip, .. } => {
                let ip_s = device_ip.to_string();
                let _ = run_fw_cmd_async("conntrack", &["-D", "-d", &ip_s]).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_ports_and_iface_validation() {
        assert!(validate_wan_input_port(22, 23456, "wan").is_err());
        assert!(validate_wan_input_port(23456, 23456, "wan").is_err());
        assert!(validate_wan_input_port(8443, 23456, "wan").is_ok());
        assert!(validate_iface_name("pppoe-wan").is_ok());
        assert!(validate_iface_name("br-lan.10").is_ok());
        assert!(validate_iface_name("wan;rm -rf").is_err());
    }
}
