//! 全量配置结构、默认值、校验逻辑与掉电安全原子落盘。
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const SECRET_PATH_PLACEHOLDER: &str = "/_vane_init_change_me";
pub const UNCHANGED_SENTINEL: &str = "__UNCHANGED__";

// ---------------------------------------------------------------------------
// 顶层配置
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Config {
    pub system: SystemConfig,
    pub modules: ModulesConfig,
    pub admin: AdminConfig,
    pub web_terminal: WebTerminalConfig,
    pub security: SecurityConfig,
    pub firewall: FirewallConfig,
    pub monitor: MonitorConfig,
    pub docker: DockerConfig,
    pub dns_providers: BTreeMap<String, DnsProviderConfig>,
    pub ddns: Vec<DdnsConfig>,
    pub acme: Vec<AcmeConfig>,
    pub reverse_proxy: Vec<ReverseProxyConfig>,
    pub port_forwards: Vec<PortForwardConfig>,
    pub stun: Vec<StunConfig>,
    pub cron: Vec<CronConfig>,
    pub notifications: Vec<NotificationConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            system: SystemConfig::default(),
            modules: ModulesConfig::default(),
            admin: AdminConfig::default(),
            web_terminal: WebTerminalConfig::default(),
            security: SecurityConfig::default(),
            firewall: FirewallConfig::default(),
            monitor: MonitorConfig::default(),
            docker: DockerConfig::default(),
            dns_providers: BTreeMap::new(),
            ddns: Vec::new(),
            acme: Vec::new(),
            reverse_proxy: Vec::new(),
            port_forwards: Vec::new(),
            stun: Vec::new(),
            cron: Vec::new(),
            notifications: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct SystemConfig {
    pub timezone_offset: String,
    pub worker_threads: u8,
    pub log_ring_capacity: usize,
    pub global_max_conns: usize,
}

impl Default for SystemConfig {
    fn default() -> Self {
        Self { timezone_offset: "UTC".into(), worker_threads: 2, log_ring_capacity: 300, global_max_conns: 512 }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ModulesConfig {
    pub reverse_proxy: bool,
    pub port_forward: bool,
    pub ddns: bool,
    pub acme: bool,
    pub stun: bool,
    pub web_terminal: bool,
    pub cron: bool,
    pub docker: bool,
}

impl Default for ModulesConfig {
    fn default() -> Self {
        Self {
            reverse_proxy: true,
            port_forward: true,
            ddns: true,
            acme: true,
            stun: false,
            web_terminal: false,
            cron: false,
            docker: true,
        }
    }
}

pub const MODULE_NAMES: &[&str] =
    &["reverse_proxy", "port_forward", "ddns", "acme", "stun", "web_terminal", "cron", "docker"];

impl ModulesConfig {
    pub fn get(&self, name: &str) -> Option<bool> {
        Some(match name {
            "reverse_proxy" => self.reverse_proxy,
            "port_forward" => self.port_forward,
            "ddns" => self.ddns,
            "acme" => self.acme,
            "stun" => self.stun,
            "web_terminal" => self.web_terminal,
            "cron" => self.cron,
            "docker" => self.docker,
            _ => return None,
        })
    }

    pub fn set(&mut self, name: &str, v: bool) -> bool {
        let slot = match name {
            "reverse_proxy" => &mut self.reverse_proxy,
            "port_forward" => &mut self.port_forward,
            "ddns" => &mut self.ddns,
            "acme" => &mut self.acme,
            "stun" => &mut self.stun,
            "web_terminal" => &mut self.web_terminal,
            "cron" => &mut self.cron,
            "docker" => &mut self.docker,
            _ => return false,
        };
        *slot = v;
        true
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ed25519KeyEntry {
    pub id: String,
    pub pubkey: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AdminConfig {
    pub listen_lan: Vec<String>,
    pub canonical_origin: String,
    pub secret_path: String,
    pub username: String,
    pub must_change_password: bool,
    pub password_login_enabled: bool,
    pub password_hash: String,
    pub totp_enabled: bool,
    pub totp_secret: String,
    /// TOTP 已接受的最大时间步长（单调水位线，持久化防重启后重放）
    pub totp_last_step: u64,
    pub totp_recovery_hashes: Vec<String>,
    pub authorized_ed25519_keys: Vec<Ed25519KeyEntry>,
    pub session_ttl_secs: u64,
    pub docker_socket: String,
    /// 额外受信 Origin（例如本地开发时前端 dev server），默认空
    pub extra_allowed_origins: Vec<String>,
    /// 可选：自定义管理面板证书路径（留空则自动生成本地自签 ECDSA 证书或复用 ACME 证书）
    pub tls_cert_path: String,
    pub tls_key_path: String,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            listen_lan: vec!["192.168.1.1:23456".into()],
            canonical_origin: "https://192.168.1.1:23456".into(),
            secret_path: SECRET_PATH_PLACEHOLDER.into(),
            username: "admin".into(),
            must_change_password: true,
            password_login_enabled: true,
            password_hash: String::new(),
            totp_enabled: false,
            totp_secret: String::new(),
            totp_last_step: 0,
            totp_recovery_hashes: Vec::new(),
            authorized_ed25519_keys: Vec::new(),
            session_ttl_secs: 3600,
            docker_socket: "/var/run/docker.sock".into(),
            extra_allowed_origins: Vec::new(),
            tls_cert_path: String::new(),
            tls_key_path: String::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct WebTerminalConfig {
    pub shell: String,
    pub default_cwd: String,
    pub idle_timeout_secs: u64,
    pub max_sessions: usize,
    pub require_reauth: bool,
}

impl Default for WebTerminalConfig {
    fn default() -> Self {
        Self {
            shell: "auto".into(),
            default_cwd: "/root".into(),
            idle_timeout_secs: 900,
            max_sessions: 2,
            require_reauth: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct SecurityConfig {
    pub tls_handshake_timeout_secs: u64,
    pub http_header_timeout_secs: u64,
    pub max_login_failures: u32,
    pub ban_duration_secs: u64,
    pub kernel_ban_offload: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            tls_handshake_timeout_secs: 5,
            http_header_timeout_secs: 10,
            max_login_failures: 5,
            ban_duration_secs: 1800,
            kernel_ban_offload: true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct FirewallConfig {
    pub auto_manage: bool,
    pub backend: String,
    pub wan_interfaces: Vec<String>,
    pub lan_interfaces: Vec<String>,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            auto_manage: true,
            backend: "auto".into(),
            wan_interfaces: vec!["pppoe-wan".into()],
            lan_interfaces: vec!["br-lan".into()],
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct MonitorConfig {
    pub interfaces: Vec<String>,
    pub thermal_path: String,
    pub temp_alert_celsius: u8,
    pub mem_low_mb: u64,
    pub alert_cooldown_secs: u64,
    pub sample_interval_secs: u64,
    pub top_processes: usize,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            interfaces: vec!["pppoe-wan".into(), "br-lan".into()],
            thermal_path: String::new(),
            temp_alert_celsius: 85,
            mem_low_mb: 32,
            alert_cooldown_secs: 1800,
            sample_interval_secs: 2,
            top_processes: 10,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct DockerConfig {
    pub protected_containers: Vec<String>,
    pub log_tail_default: u32,
    pub log_timestamps: bool,
}

impl Default for DockerConfig {
    fn default() -> Self {
        Self { protected_containers: vec!["vane".into()], log_tail_default: 200, log_timestamps: false }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct DnsProviderConfig {
    pub provider: String,
    /// Cloudflare API Token / 阿里云 AccessKeyId / DNSPod SecretId
    pub api_token: String,
    /// 阿里云 AccessKeySecret / DNSPod SecretKey（Cloudflare 无需）
    pub secret_key: String,
    pub happy_eyeballs_delay_ms: u64,
}

impl Default for DnsProviderConfig {
    fn default() -> Self {
        Self { provider: "cloudflare".into(), api_token: String::new(), secret_key: String::new(), happy_eyeballs_delay_ms: 250 }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DdnsSource {
    Interface {
        name: String,
        #[serde(default)]
        preferred_subnet: String,
        #[serde(default)]
        index: usize,
    },
    PrefixAndIid {
        prefix_iface: String,
        iid: String,
    },
    NeighborMac {
        prefix_iface: String,
        mac: String,
    },
    ExternalUrl {
        #[serde(default)]
        url_v4: String,
        #[serde(default)]
        url_v6: String,
    },
    CustomHttpExtract {
        url: String,
    },
}

impl Default for DdnsSource {
    fn default() -> Self {
        DdnsSource::Interface { name: "pppoe-wan".into(), preferred_subnet: String::new(), index: 0 }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct CustomHttpTemplate {
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: String,
    pub success_keyword: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct DdnsConfig {
    pub name: String,
    pub enabled: bool,
    /// dns_providers 中的账号 id，或 "custom_http"
    pub provider: String,
    pub domain: String,
    pub records: Vec<String>,
    pub source: DdnsSource,
    pub on_missing_public_ip: String,
    pub ttl: u32,
    pub proxied: bool,
    pub line: String,
    pub comment: String,
    pub split_dns_lan_ips: Vec<String>,
    pub firewall_allow_tcp_ports: Vec<u16>,
    pub firewall_allow_udp_ports: Vec<u16>,
    pub custom_http: CustomHttpTemplate,
    /// custom_http 模板变量 {{token}}
    pub token: String,
    pub reconcile_interval_secs: u64,
}

impl Default for DdnsConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            enabled: true,
            provider: String::new(),
            domain: String::new(),
            records: vec!["A".into(), "AAAA".into()],
            source: DdnsSource::default(),
            on_missing_public_ip: "keep_existing".into(),
            ttl: 600,
            proxied: false,
            line: "default".into(),
            comment: String::new(),
            split_dns_lan_ips: Vec::new(),
            firewall_allow_tcp_ports: Vec::new(),
            firewall_allow_udp_ports: Vec::new(),
            custom_http: CustomHttpTemplate::default(),
            token: String::new(),
            reconcile_interval_secs: 900,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeployHook {
    CopyToDir {
        dir: String,
    },
    Webhook {
        url: String,
        #[serde(default)]
        include_private_key: bool,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AcmeConfig {
    pub enabled: bool,
    pub domain: String,
    pub extra_domains: Vec<String>,
    pub email: String,
    pub dns_provider: String,
    pub cert_dir: String,
    pub renew_before_days: u32,
    /// letsencrypt | letsencrypt_staging | zerossl | buypass | google | https://自定义 Directory URL
    pub directory_url: String,
    pub eab_kid: String,
    pub eab_hmac_key: String,
    pub challenge_alias_domain: String,
    pub propagation_timeout_secs: u64,
    pub deploy_hooks: Vec<DeployHook>,
    /// 签发后是否同时作为管理面板证书
    pub use_for_admin: bool,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            domain: String::new(),
            extra_domains: Vec::new(),
            email: String::new(),
            dns_provider: String::new(),
            cert_dir: "/data/vane/certs".into(),
            renew_before_days: 30,
            directory_url: "letsencrypt".into(),
            eab_kid: String::new(),
            eab_hmac_key: String::new(),
            challenge_alias_domain: String::new(),
            propagation_timeout_secs: 180,
            deploy_hooks: Vec::new(),
            use_for_admin: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ReverseProxyRule {
    pub enabled: bool,
    pub host: String,
    pub path_prefix: String,
    pub strip_prefix: bool,
    /// proxy | redirect | static
    pub mode: String,
    pub upstream: String,
    pub websocket: bool,
    /// strict | pinned_sha256 | insecure_skip_verify
    pub upstream_tls_mode: String,
    pub upstream_cert_sha256: String,
    pub upstream_sni: String,
    pub upstream_host_header: String,
    pub sanitize_forwarded_headers: bool,
    pub request_headers_set: BTreeMap<String, String>,
    pub request_headers_remove: Vec<String>,
    pub response_headers_set: BTreeMap<String, String>,
    pub response_headers_remove: Vec<String>,
    pub auth_gate: bool,
    pub allowed_cidrs: Vec<String>,
    pub denied_cidrs: Vec<String>,
    pub max_body_mb: u64,
    pub read_timeout_secs: u64,
    pub redirect_url: String,
    pub redirect_code: u16,
    pub static_status: u16,
    pub static_content_type: String,
    pub static_body: String,
}

impl Default for ReverseProxyRule {
    fn default() -> Self {
        Self {
            enabled: true,
            host: String::new(),
            path_prefix: "/".into(),
            strip_prefix: false,
            mode: "proxy".into(),
            upstream: String::new(),
            websocket: true,
            upstream_tls_mode: "strict".into(),
            upstream_cert_sha256: String::new(),
            upstream_sni: String::new(),
            upstream_host_header: String::new(),
            sanitize_forwarded_headers: true,
            request_headers_set: BTreeMap::new(),
            request_headers_remove: Vec::new(),
            response_headers_set: BTreeMap::new(),
            response_headers_remove: Vec::new(),
            auth_gate: false,
            allowed_cidrs: Vec::new(),
            denied_cidrs: Vec::new(),
            max_body_mb: 0,
            read_timeout_secs: 120,
            redirect_url: String::new(),
            redirect_code: 302,
            static_status: 200,
            static_content_type: "text/plain; charset=utf-8".into(),
            static_body: String::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ReverseProxyConfig {
    pub name: String,
    pub enabled: bool,
    pub stack: String,
    pub listen_port: u16,
    pub strict_sni: bool,
    pub open_wan_firewall: bool,
    pub max_concurrent_conns: usize,
    pub rules: Vec<ReverseProxyRule>,
}

impl Default for ReverseProxyConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            enabled: true,
            stack: "dual".into(),
            listen_port: 8443,
            strict_sni: true,
            open_wan_firewall: true,
            max_concurrent_conns: 256,
            rules: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct PortForwardConfig {
    pub name: String,
    pub enabled: bool,
    /// tcp | udp | tcp_udp
    pub proto: String,
    pub stack: String,
    /// userspace_splice | kernel_dnat
    pub engine: String,
    pub listen_port: u16,
    pub bind_interface: String,
    pub source_ip: String,
    pub target: String,
    pub targets: Vec<String>,
    /// failover | round_robin
    pub load_balance: String,
    /// none | v1 | v2
    pub send_proxy_protocol: String,
    pub open_wan_firewall: bool,
    pub max_concurrent_conns: usize,
    pub allowed_cidrs: Vec<String>,
    pub allowed_time_window: String,
    /// 一键临时开门租约到期时间（0 表示不限期）
    pub expire_at_unix: u64,
    pub udp_session_timeout_secs: u64,
    pub tcp_idle_timeout_secs: u64,
    pub health_check_interval_secs: u64,
}

impl Default for PortForwardConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            enabled: true,
            proto: "tcp".into(),
            stack: "dual".into(),
            engine: "userspace_splice".into(),
            listen_port: 0,
            bind_interface: String::new(),
            source_ip: String::new(),
            target: String::new(),
            targets: Vec::new(),
            load_balance: "failover".into(),
            send_proxy_protocol: "none".into(),
            open_wan_firewall: true,
            max_concurrent_conns: 64,
            allowed_cidrs: Vec::new(),
            allowed_time_window: String::new(),
            expire_at_unix: 0,
            udp_session_timeout_secs: 60,
            tcp_idle_timeout_secs: 3600,
            health_check_interval_secs: 10,
        }
    }
}

impl PortForwardConfig {
    pub fn effective_targets(&self) -> Vec<String> {
        if !self.targets.is_empty() {
            self.targets.clone()
        } else if !self.target.is_empty() {
            vec![self.target.clone()]
        } else {
            Vec::new()
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct CloudflareRedirectConfig {
    pub zone_id: String,
    pub ruleset_id: String,
    pub rule_id: String,
    pub api_token: String,
    /// 固定入口域名，例如 go.home.example.com
    pub source_host: String,
    /// 跳转目标模板，支持 {{ip}} {{port}} {{public_addr}}
    pub target_template: String,
    pub status_code: u16,
}

impl Default for CloudflareRedirectConfig {
    fn default() -> Self {
        Self {
            zone_id: String::new(),
            ruleset_id: String::new(),
            rule_id: String::new(),
            api_token: String::new(),
            source_host: String::new(),
            target_template: "https://{{public_addr}}".into(),
            status_code: 302,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct StunConfig {
    pub name: String,
    pub enabled: bool,
    pub proto: String,
    pub local_port: u16,
    pub stun_server: String,
    pub stun_servers: Vec<String>,
    pub keepalive_secs: u64,
    pub webhook_url: String,
    pub bind_rule: String,
    pub on_change_cloudflare_redirect: Option<CloudflareRedirectConfig>,
}

impl Default for StunConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            enabled: true,
            proto: "udp".into(),
            local_port: 0,
            stun_server: String::new(),
            stun_servers: Vec::new(),
            keepalive_secs: 25,
            webhook_url: String::new(),
            bind_rule: String::new(),
            on_change_cloudflare_redirect: None,
        }
    }
}

impl StunConfig {
    pub fn servers(&self) -> Vec<String> {
        let mut v = Vec::new();
        if !self.stun_server.is_empty() {
            v.push(self.stun_server.clone());
        }
        for s in &self.stun_servers {
            if !v.contains(s) {
                v.push(s.clone());
            }
        }
        v
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CronAction {
    DockerPruneImages {
        #[serde(default = "default_true")]
        dangling_only: bool,
    },
    DockerRestartContainer {
        container: String,
    },
    RuleToggle {
        /// port_forward | reverse_proxy
        target_kind: String,
        rule: String,
        enable: bool,
    },
    HttpRequest {
        #[serde(default = "default_get")]
        method: String,
        url: String,
        #[serde(default)]
        headers: BTreeMap<String, String>,
        #[serde(default)]
        body: String,
    },
    Exec {
        program: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        cwd: String,
    },
}

fn default_true() -> bool {
    true
}
fn default_get() -> String {
    "GET".into()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct CronConfig {
    pub name: String,
    pub enabled: bool,
    pub schedule: String,
    pub timeout_secs: u64,
    pub action: CronAction,
    pub notify_on_failure: bool,
}

impl Default for CronConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            enabled: true,
            schedule: "0 0 4 * * *".into(),
            timeout_secs: 60,
            action: CronAction::DockerPruneImages { dangling_only: true },
            notify_on_failure: true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct NotificationConfig {
    pub name: String,
    pub enabled: bool,
    /// webhook | bark | telegram | wecom | feishu | dingtalk | ntfy | gotify
    pub provider: String,
    /// 订阅事件，空表示全部
    pub events: Vec<String>,
    /// Webhook / 机器人地址 / Bark 或 Ntfy 或 Gotify 服务器地址（含密钥时加密保存）
    pub url: String,
    /// Telegram Bot Token / Bark Device Key / Gotify App Token
    pub token: String,
    pub chat_id: String,
    /// 钉钉 / 飞书加签密钥
    pub secret: String,
    pub method: String,
    pub headers: BTreeMap<String, String>,
    pub body_template: String,
    pub min_severity: String,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            enabled: true,
            provider: "webhook".into(),
            events: Vec::new(),
            url: String::new(),
            token: String::new(),
            chat_id: String::new(),
            secret: String::new(),
            method: "POST".into(),
            headers: BTreeMap::new(),
            body_template: String::new(),
            min_severity: "info".into(),
        }
    }
}

// ---------------------------------------------------------------------------
// 敏感字段枚举（Vault 自动加封 / 脱敏 / 保留未修改密文）
// ---------------------------------------------------------------------------

impl Config {
    /// 遍历全部 L2 运行时可逆机密字段，回调参数为 (字段路径 AAD, 字段值)
    pub fn for_each_secret_mut(&mut self, mut f: impl FnMut(&str, &mut String)) {
        f("admin.totp_secret", &mut self.admin.totp_secret);
        for (id, p) in self.dns_providers.iter_mut() {
            f(&format!("dns_providers.{}.api_token", id), &mut p.api_token);
            f(&format!("dns_providers.{}.secret_key", id), &mut p.secret_key);
        }
        for d in self.ddns.iter_mut() {
            f(&format!("ddns.{}.token", d.name), &mut d.token);
        }
        for a in self.acme.iter_mut() {
            f(&format!("acme.{}.eab_hmac_key", a.domain), &mut a.eab_hmac_key);
            for (i, h) in a.deploy_hooks.iter_mut().enumerate() {
                if let DeployHook::Webhook { url, .. } = h {
                    f(&format!("acme.{}.deploy_hooks.{}.url", a.domain, i), url);
                }
            }
        }
        for s in self.stun.iter_mut() {
            f(&format!("stun.{}.webhook_url", s.name), &mut s.webhook_url);
            if let Some(cf) = s.on_change_cloudflare_redirect.as_mut() {
                f(&format!("stun.{}.on_change_cloudflare_redirect.api_token", s.name), &mut cf.api_token);
            }
        }
        for n in self.notifications.iter_mut() {
            f(&format!("notifications.{}.url", n.name), &mut n.url);
            f(&format!("notifications.{}.token", n.name), &mut n.token);
            f(&format!("notifications.{}.secret", n.name), &mut n.secret);
        }
    }

    pub fn secret_map(&self) -> BTreeMap<String, String> {
        let mut c = self.clone();
        let mut m = BTreeMap::new();
        c.for_each_secret_mut(|p, v| {
            m.insert(p.to_string(), v.clone());
        });
        m
    }

    pub fn timezone_offset_secs(&self) -> i64 {
        parse_tz_offset(&self.system.timezone_offset).unwrap_or(0)
    }

    pub fn admin_listen_addrs(&self) -> Vec<SocketAddr> {
        self.admin.listen_lan.iter().filter_map(|s| s.parse().ok()).collect()
    }

    pub fn admin_port(&self) -> u16 {
        self.admin_listen_addrs().first().map(|a| a.port()).unwrap_or(23456)
    }

    // -----------------------------------------------------------------------
    // 校验
    // -----------------------------------------------------------------------

    pub fn validate(&self) -> Result<(), String> {
        let s = &self.system;
        if parse_tz_offset(&s.timezone_offset).is_none() {
            return Err(format!("system.timezone_offset 非法: {}", s.timezone_offset));
        }
        range("system.worker_threads", s.worker_threads as u64, 1, 8)?;
        range("system.log_ring_capacity", s.log_ring_capacity as u64, 50, 1000)?;
        range("system.global_max_conns", s.global_max_conns as u64, 64, 4096)?;

        let a = &self.admin;
        if a.listen_lan.is_empty() {
            return Err("admin.listen_lan 不能为空".into());
        }
        for l in &a.listen_lan {
            let addr: SocketAddr = l.parse().map_err(|_| format!("admin.listen_lan 非法地址: {}", l))?;
            if addr.ip().is_unspecified() {
                return Err("admin.listen_lan 禁止使用 0.0.0.0 或 [::]，请绑定局域网地址".into());
            }
            if addr.port() == 0 {
                return Err("admin.listen_lan 禁止使用 0 端口".into());
            }
        }
        if !(a.canonical_origin.starts_with("https://") || a.canonical_origin.starts_with("http://")) {
            return Err("admin.canonical_origin 必须以 https:// 开头".into());
        }
        if a.secret_path != "/" {
            if !a.secret_path.starts_with('/') || a.secret_path.len() < 9 {
                return Err("admin.secret_path 必须以 / 开头且长度 >= 8（或设为 \"/\"）".into());
            }
            if !a.secret_path[1..].bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
                return Err("admin.secret_path 仅允许字母、数字、下划线与连字符".into());
            }
        }
        validate_username(&a.username)?;
        range("admin.session_ttl_secs", a.session_ttl_secs, 300, 86_400)?;
        if !a.password_login_enabled {
            if a.must_change_password {
                return Err("完成首次改密前不允许关闭密码登录".into());
            }
            if a.authorized_ed25519_keys.is_empty() {
                return Err("至少绑定 1 把 Ed25519 公钥后才允许关闭密码登录".into());
            }
        }
        let mut key_ids = Vec::new();
        for k in &a.authorized_ed25519_keys {
            validate_name("authorized_ed25519_keys.id", &k.id)?;
            if key_ids.contains(&&k.id) {
                return Err(format!("Ed25519 公钥 id 重复: {}", k.id));
            }
            key_ids.push(&k.id);
            if crate::security::auth::parse_openssh_ed25519(&k.pubkey).is_none() {
                return Err(format!("Ed25519 公钥 {} 格式非法（需 ssh-ed25519 AAAA...）", k.id));
            }
        }

        let w = &self.web_terminal;
        range("web_terminal.idle_timeout_secs", w.idle_timeout_secs, 60, 3600)?;
        range("web_terminal.max_sessions", w.max_sessions as u64, 1, 4)?;
        if w.shell != "auto" && !w.shell.starts_with('/') {
            return Err("web_terminal.shell 必须为 auto 或绝对路径".into());
        }

        let sec = &self.security;
        range("security.tls_handshake_timeout_secs", sec.tls_handshake_timeout_secs, 2, 30)?;
        range("security.http_header_timeout_secs", sec.http_header_timeout_secs, 3, 60)?;
        range("security.max_login_failures", sec.max_login_failures as u64, 3, 20)?;
        range("security.ban_duration_secs", sec.ban_duration_secs, 60, 86_400)?;

        let fw = &self.firewall;
        if !matches!(fw.backend.as_str(), "auto" | "nftables" | "iptables_legacy" | "iptables_nft") {
            return Err(format!("firewall.backend 非法: {}", fw.backend));
        }
        for i in fw.wan_interfaces.iter().chain(fw.lan_interfaces.iter()) {
            crate::firewall::validate_iface_name(i)?;
        }

        let m = &self.monitor;
        range("monitor.sample_interval_secs", m.sample_interval_secs, 1, 60)?;
        range("monitor.temp_alert_celsius", m.temp_alert_celsius as u64, 40, 125)?;
        range("monitor.top_processes", m.top_processes as u64, 1, 50)?;

        for (id, p) in &self.dns_providers {
            validate_name("dns_providers.<id>", id)?;
            if !matches!(p.provider.as_str(), "cloudflare" | "aliyun" | "dnspod") {
                return Err(format!("dns_providers.{}.provider 不支持: {}", id, p.provider));
            }
            range("happy_eyeballs_delay_ms", p.happy_eyeballs_delay_ms, 100, 2000)?;
        }

        let mut names = Vec::new();
        for d in &self.ddns {
            validate_name("ddns.name", &d.name)?;
            unique(&mut names, "ddns", &d.name)?;
            validate_domain(&d.domain)?;
            if d.provider != "custom_http" && !self.dns_providers.contains_key(&d.provider) {
                return Err(format!("ddns.{} 引用了不存在的 DNS 服务商账号 {}", d.name, d.provider));
            }
            if d.provider == "custom_http" && !d.custom_http.url.starts_with("http") {
                return Err(format!("ddns.{} custom_http.url 非法", d.name));
            }
            if d.records.is_empty() || !d.records.iter().all(|r| r == "A" || r == "AAAA") {
                return Err(format!("ddns.{}.records 仅支持 A / AAAA", d.name));
            }
            if !matches!(d.on_missing_public_ip.as_str(), "keep_existing" | "delete_record") {
                return Err(format!("ddns.{}.on_missing_public_ip 非法", d.name));
            }
            if !matches!(d.line.as_str(), "default" | "telecom" | "unicom" | "mobile" | "oversea") {
                return Err(format!("ddns.{}.line 非法", d.name));
            }
            match &d.source {
                DdnsSource::Interface { name, preferred_subnet, .. } => {
                    crate::firewall::validate_iface_name(name)?;
                    if !preferred_subnet.is_empty() {
                        parse_cidr(preferred_subnet)?;
                    }
                }
                DdnsSource::PrefixAndIid { prefix_iface, iid } => {
                    crate::firewall::validate_iface_name(prefix_iface)?;
                    iid.parse::<std::net::Ipv6Addr>().map_err(|_| format!("ddns.{} iid 非法", d.name))?;
                }
                DdnsSource::NeighborMac { prefix_iface, mac } => {
                    crate::firewall::validate_iface_name(prefix_iface)?;
                    parse_mac(mac).ok_or_else(|| format!("ddns.{} mac 非法", d.name))?;
                }
                DdnsSource::ExternalUrl { url_v4, url_v6 } => {
                    if url_v4.is_empty() && url_v6.is_empty() {
                        return Err(format!("ddns.{} external_url 至少配置一个地址", d.name));
                    }
                }
                DdnsSource::CustomHttpExtract { url } => {
                    if !url.starts_with("http") {
                        return Err(format!("ddns.{} custom_http_extract.url 非法", d.name));
                    }
                }
            }
            for ip in &d.split_dns_lan_ips {
                ip.parse::<IpAddr>().map_err(|_| format!("ddns.{} split_dns_lan_ips 非法 {}", d.name, ip))?;
            }
        }

        let mut names = Vec::new();
        for a in &self.acme {
            validate_domain(&a.domain)?;
            unique(&mut names, "acme", &a.domain)?;
            for e in &a.extra_domains {
                validate_domain(e)?;
            }
            if !self.dns_providers.contains_key(&a.dns_provider) {
                return Err(format!("acme.{} 引用了不存在的 DNS 服务商账号 {}", a.domain, a.dns_provider));
            }
            range("acme.renew_before_days", a.renew_before_days as u64, 7, 60)?;
            if crate::daemon::acme::resolve_directory(&a.directory_url).is_none() {
                return Err(format!("acme.{}.directory_url 非法", a.domain));
            }
            if !a.challenge_alias_domain.is_empty() {
                validate_domain(&a.challenge_alias_domain)?;
            }
            if !a.cert_dir.starts_with('/') {
                return Err("acme.cert_dir 必须为绝对路径".into());
            }
        }

        let admin_port = self.admin_port();
        let mut names = Vec::new();
        let mut used_ports: Vec<(u16, &'static str)> = Vec::new();
        for r in &self.reverse_proxy {
            validate_name("reverse_proxy.name", &r.name)?;
            unique(&mut names, "reverse_proxy", &r.name)?;
            validate_stack(&r.stack)?;
            if r.listen_port == 0 {
                return Err(format!("reverse_proxy.{} 禁止使用 0 端口", r.name));
            }
            if r.open_wan_firewall {
                crate::firewall::validate_wan_input_port(r.listen_port, admin_port, "wan")?;
            }
            range("reverse_proxy.max_concurrent_conns", r.max_concurrent_conns as u64, 1, 4096)?;
            if used_ports.iter().any(|(p, k)| *p == r.listen_port && *k == "tcp") {
                return Err(format!("端口冲突: {}", r.listen_port));
            }
            used_ports.push((r.listen_port, "tcp"));
            for rule in &r.rules {
                validate_rule(rule).map_err(|e| format!("reverse_proxy.{} 规则 {}: {}", r.name, rule.host, e))?;
            }
        }

        let mut names = Vec::new();
        for p in &self.port_forwards {
            validate_name("port_forwards.name", &p.name)?;
            unique(&mut names, "port_forwards", &p.name)?;
            validate_stack(&p.stack)?;
            if !matches!(p.proto.as_str(), "tcp" | "udp" | "tcp_udp") {
                return Err(format!("port_forwards.{}.proto 非法", p.name));
            }
            if !matches!(p.engine.as_str(), "userspace_splice" | "kernel_dnat") {
                return Err(format!("port_forwards.{}.engine 非法", p.name));
            }
            if p.listen_port == 0 {
                return Err(format!("port_forwards.{} 禁止使用 0 端口", p.name));
            }
            if !matches!(p.load_balance.as_str(), "failover" | "round_robin") {
                return Err(format!("port_forwards.{}.load_balance 非法", p.name));
            }
            if !matches!(p.send_proxy_protocol.as_str(), "none" | "v1" | "v2") {
                return Err(format!("port_forwards.{}.send_proxy_protocol 非法", p.name));
            }
            let targets = p.effective_targets();
            if targets.is_empty() {
                return Err(format!("port_forwards.{} 至少需要一个目标地址", p.name));
            }
            let mut parsed = Vec::new();
            for t in &targets {
                let a: SocketAddr = t.parse().map_err(|_| format!("port_forwards.{} 目标地址非法 {}", p.name, t))?;
                if a.port() == 0 {
                    return Err(format!("port_forwards.{} 目标端口不能为 0", p.name));
                }
                parsed.push(a);
            }
            if p.engine == "kernel_dnat" {
                if p.send_proxy_protocol != "none" || !p.allowed_cidrs.is_empty() || targets.len() > 1 {
                    return Err(format!(
                        "port_forwards.{}: kernel_dnat 仅支持单目标、无 Proxy Protocol / CIDR 策略的同栈纯转发",
                        p.name
                    ));
                }
                let t = parsed[0];
                if (p.stack == "ipv4_only" && !t.is_ipv4()) || (p.stack == "ipv6_only" && !t.is_ipv6()) || p.stack == "dual" {
                    return Err(format!("port_forwards.{}: kernel_dnat 需要 stack 与目标地址同协议族（不支持 dual 跨栈）", p.name));
                }
            }
            // 用户态引擎监听本机端口 -> 走 WAN INPUT，需要受保护端口校验
            if p.engine == "userspace_splice" && p.open_wan_firewall {
                crate::firewall::validate_wan_input_port(p.listen_port, admin_port, "wan")?;
            }
            if !p.bind_interface.is_empty() {
                crate::firewall::validate_iface_name(&p.bind_interface)?;
            }
            if !p.source_ip.is_empty() {
                p.source_ip.parse::<IpAddr>().map_err(|_| format!("port_forwards.{}.source_ip 非法", p.name))?;
            }
            for c in &p.allowed_cidrs {
                parse_cidr(c)?;
            }
            if !p.allowed_time_window.is_empty() {
                parse_time_window(&p.allowed_time_window)?;
            }
            range("port_forwards.udp_session_timeout_secs", p.udp_session_timeout_secs, 10, 600)?;
            range("port_forwards.max_concurrent_conns", p.max_concurrent_conns as u64, 1, 4096)?;
            for kind in proto_kinds(&p.proto) {
                if used_ports.iter().any(|(port, k)| *port == p.listen_port && *k == kind) {
                    return Err(format!("端口冲突: {}/{}", p.listen_port, kind));
                }
                used_ports.push((p.listen_port, kind));
            }
        }

        let mut names = Vec::new();
        for s in &self.stun {
            validate_name("stun.name", &s.name)?;
            unique(&mut names, "stun", &s.name)?;
            if !matches!(s.proto.as_str(), "udp" | "tcp") {
                return Err(format!("stun.{}.proto 非法", s.name));
            }
            if s.servers().is_empty() {
                return Err(format!("stun.{} 至少配置一个 STUN 服务器", s.name));
            }
            range("stun.keepalive_secs", s.keepalive_secs, 5, 3600)?;
        }

        let mut names = Vec::new();
        for c in &self.cron {
            validate_name("cron.name", &c.name)?;
            unique(&mut names, "cron", &c.name)?;
            crate::daemon::cron::CronSchedule::parse(&c.schedule).map_err(|e| format!("cron.{}: {}", c.name, e))?;
            range("cron.timeout_secs", c.timeout_secs, 1, 86_400)?;
            match &c.action {
                CronAction::Exec { program, .. } => {
                    if !program.starts_with('/') {
                        return Err(format!("cron.{}: exec.program 必须为绝对路径", c.name));
                    }
                }
                CronAction::RuleToggle { target_kind, .. } => {
                    if !matches!(target_kind.as_str(), "port_forward" | "reverse_proxy") {
                        return Err(format!("cron.{}: rule_toggle.target_kind 非法", c.name));
                    }
                }
                CronAction::HttpRequest { url, .. } => {
                    if !url.starts_with("http://") && !url.starts_with("https://") {
                        return Err(format!("cron.{}: http_request.url 非法", c.name));
                    }
                }
                _ => {}
            }
        }

        let mut names = Vec::new();
        for n in &self.notifications {
            validate_name("notifications.name", &n.name)?;
            unique(&mut names, "notifications", &n.name)?;
            if !matches!(
                n.provider.as_str(),
                "webhook" | "bark" | "telegram" | "wecom" | "feishu" | "dingtalk" | "ntfy" | "gotify"
            ) {
                return Err(format!("notifications.{}.provider 不支持: {}", n.name, n.provider));
            }
        }
        Ok(())
    }
}

fn proto_kinds(p: &str) -> Vec<&'static str> {
    match p {
        "tcp" => vec!["tcp"],
        "udp" => vec!["udp"],
        _ => vec!["tcp", "udp"],
    }
}

fn validate_rule(r: &ReverseProxyRule) -> Result<(), String> {
    validate_domain(&r.host)?;
    if !r.path_prefix.starts_with('/') {
        return Err("path_prefix 必须以 / 开头".into());
    }
    match r.mode.as_str() {
        "proxy" => {
            if !(r.upstream.starts_with("http://") || r.upstream.starts_with("https://")) {
                return Err("upstream 必须为 http:// 或 https:// 地址".into());
            }
        }
        "redirect" => {
            if r.redirect_url.is_empty() {
                return Err("redirect 模式需要 redirect_url".into());
            }
            if !matches!(r.redirect_code, 301 | 302 | 307 | 308) {
                return Err("redirect_code 仅支持 301/302/307/308".into());
            }
        }
        "static" => {
            if !(100..=599).contains(&r.static_status) {
                return Err("static_status 非法".into());
            }
        }
        _ => return Err(format!("mode 非法: {}", r.mode)),
    }
    if !matches!(r.upstream_tls_mode.as_str(), "strict" | "pinned_sha256" | "insecure_skip_verify") {
        return Err("upstream_tls_mode 非法".into());
    }
    if r.upstream_tls_mode == "pinned_sha256" {
        let hex = r.upstream_cert_sha256.replace(':', "");
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("upstream_cert_sha256 需要 64 位十六进制 SHA-256 指纹".into());
        }
    }
    for c in r.allowed_cidrs.iter().chain(r.denied_cidrs.iter()) {
        parse_cidr(c)?;
    }
    for (k, v) in r.request_headers_set.iter().chain(r.response_headers_set.iter()) {
        http::HeaderName::from_bytes(k.as_bytes()).map_err(|_| format!("Header 名非法: {}", k))?;
        http::HeaderValue::from_str(v).map_err(|_| format!("Header 值非法: {}", k))?;
    }
    if r.read_timeout_secs == 0 || r.read_timeout_secs > 86_400 {
        return Err("read_timeout_secs 范围 1 ~ 86400".into());
    }
    Ok(())
}

fn range(name: &str, v: u64, lo: u64, hi: u64) -> Result<(), String> {
    if v < lo || v > hi {
        Err(format!("{} = {} 超出允许范围 {} ~ {}", name, v, lo, hi))
    } else {
        Ok(())
    }
}

fn unique<'a>(names: &mut Vec<&'a str>, kind: &str, n: &'a str) -> Result<(), String> {
    if names.contains(&n) {
        return Err(format!("{} 名称重复: {}", kind, n));
    }
    names.push(n);
    Ok(())
}

pub fn validate_stack(s: &str) -> Result<(), String> {
    match s {
        "dual" | "ipv4_only" | "ipv6_only" => Ok(()),
        _ => Err(format!("stack 非法: {}（仅支持 dual / ipv4_only / ipv6_only）", s)),
    }
}

pub fn validate_name(field: &str, n: &str) -> Result<(), String> {
    if n.is_empty() || n.len() > 64 || !n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.') {
        return Err(format!("{} 非法: \"{}\"（仅允许 1~64 位字母/数字/_-.）", field, n));
    }
    Ok(())
}

pub fn validate_username(n: &str) -> Result<(), String> {
    if n.len() < 3 || n.len() > 32 || !n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.') {
        return Err("用户名需为 3~32 位字母、数字或 _-.".into());
    }
    Ok(())
}

pub fn validate_domain(d: &str) -> Result<(), String> {
    let body = d.strip_prefix("*.").unwrap_or(d);
    if body.is_empty() || body.len() > 253 {
        return Err(format!("域名非法: {}", d));
    }
    for label in body.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(format!("域名非法: {}", d));
        }
    }
    Ok(())
}

/// 解析 CIDR（不带前缀长度时视为单地址）
pub fn parse_cidr(s: &str) -> Result<(IpAddr, u8), String> {
    let (ip_s, len_s) = match s.split_once('/') {
        Some((a, b)) => (a, Some(b)),
        None => (s, None),
    };
    let ip: IpAddr = ip_s.trim().parse().map_err(|_| format!("CIDR 非法: {}", s))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let len = match len_s {
        Some(l) => l.trim().parse::<u8>().map_err(|_| format!("CIDR 非法: {}", s))?,
        None => max,
    };
    if len > max {
        return Err(format!("CIDR 前缀长度非法: {}", s));
    }
    Ok((ip, len))
}

pub fn cidr_contains(cidr: &(IpAddr, u8), ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    };
    match (cidr.0, ip) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            let len = cidr.1 as u32;
            if len == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - len);
            (u32::from(n) & mask) == (u32::from(a) & mask)
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            let len = cidr.1 as u32;
            if len == 0 {
                return true;
            }
            let mask = u128::MAX << (128 - len);
            (u128::from(n) & mask) == (u128::from(a) & mask)
        }
        _ => false,
    }
}

pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(|c| c == ':' || c == '-').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(out)
}

/// 解析 "HH:MM-HH:MM" 时间窗，返回 (起始分钟, 结束分钟)，支持跨午夜
pub fn parse_time_window(s: &str) -> Result<(u32, u32), String> {
    let (a, b) = s.split_once('-').ok_or_else(|| format!("时间窗格式非法: {}", s))?;
    let p = |x: &str| -> Result<u32, String> {
        let (h, m) = x.trim().split_once(':').ok_or_else(|| format!("时间格式非法: {}", x))?;
        let h: u32 = h.parse().map_err(|_| format!("时间格式非法: {}", x))?;
        let m: u32 = m.parse().map_err(|_| format!("时间格式非法: {}", x))?;
        if h > 23 || m > 59 {
            return Err(format!("时间越界: {}", x));
        }
        Ok(h * 60 + m)
    };
    Ok((p(a)?, p(b)?))
}

pub fn time_window_contains(window: (u32, u32), minute_of_day: u32) -> bool {
    let (s, e) = window;
    if s <= e {
        minute_of_day >= s && minute_of_day < e
    } else {
        minute_of_day >= s || minute_of_day < e
    }
}

/// 解析时区偏移："UTC" / "Z" / "+08:00" / "-0530" / "auto"
pub fn parse_tz_offset(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.eq_ignore_ascii_case("utc") || s == "Z" || s.is_empty() {
        return Some(0);
    }
    if s.eq_ignore_ascii_case("auto") {
        return Some(detect_system_tz_offset());
    }
    let (sign, rest) = match s.as_bytes().first()? {
        b'+' => (1, &s[1..]),
        b'-' => (-1, &s[1..]),
        _ => return None,
    };
    let (h, m) = if let Some((h, m)) = rest.split_once(':') {
        (h, m)
    } else if rest.len() == 4 {
        (&rest[..2], &rest[2..])
    } else {
        (rest, "0")
    };
    let h: i64 = h.parse().ok()?;
    let m: i64 = m.parse().ok()?;
    if h > 14 || m > 59 {
        return None;
    }
    Some(sign * (h * 3600 + m * 60))
}

/// 读取 /etc/TZ（OpenWrt POSIX TZ，例如 "CST-8"）解析偏移，失败回退 UTC
fn detect_system_tz_offset() -> i64 {
    if let Ok(tz) = fs::read_to_string("/etc/TZ") {
        if let Some(off) = parse_posix_tz(tz.trim()) {
            return off;
        }
    }
    0
}

/// POSIX TZ 偏移符号与 UTC 相反："CST-8" => +8h
pub fn parse_posix_tz(tz: &str) -> Option<i64> {
    let start = tz.find(|c: char| c == '+' || c == '-' || c.is_ascii_digit())?;
    let rest = &tz[start..];
    let (sign, rest) = match rest.as_bytes()[0] {
        b'-' => (1i64, &rest[1..]),
        b'+' => (-1i64, &rest[1..]),
        _ => (-1i64, rest),
    };
    let end = rest.find(|c: char| !(c.is_ascii_digit() || c == ':')).unwrap_or(rest.len());
    let num = &rest[..end];
    let (h, m) = num.split_once(':').unwrap_or((num, "0"));
    let h: i64 = h.parse().ok()?;
    let m: i64 = m.parse().ok()?;
    Some(sign * (h * 3600 + m * 60))
}

// ---------------------------------------------------------------------------
// 掉电安全原子落盘
// ---------------------------------------------------------------------------

/// 掉电安全原子写：0600 临时文件 (O_CREAT|O_EXCL) -> sync_all -> .bak 备份 -> rename -> 父目录 sync_all
pub fn crash_safe_atomic_write(target: &Path, data: &[u8], pid_nonce: u64) -> std::io::Result<()> {
    let parent = match target.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    if !parent.exists() {
        fs::create_dir_all(&parent)?;
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))?;
    }
    let file_name = target.file_name().and_then(|s| s.to_str()).unwrap_or("config.toml");
    let tmp_path = parent.join(format!(".{}.{}.{:016x}.tmp", file_name, std::process::id(), pid_nonce));
    let mut bak_name = target.as_os_str().to_owned();
    bak_name.push(".bak");
    let bak_path = PathBuf::from(bak_name);

    let write_res = (|| -> std::io::Result<()> {
        let mut tmp_file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp_path)?;
        tmp_file.write_all(data)?;
        tmp_file.sync_all()?; // 1. 刷入文件内容与 inode
        Ok(())
    })();
    if let Err(e) = write_res {
        // ENOSPC / EROFS 等：立即中止并保留旧有效状态
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }

    if target.exists() {
        if let Ok(old) = fs::read(target) {
            let bak_tmp = parent.join(format!(".{}.{:016x}.baktmp", file_name, pid_nonce));
            let ok = (|| -> std::io::Result<()> {
                let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&bak_tmp)?;
                f.write_all(&old)?;
                f.sync_all()?;
                fs::rename(&bak_tmp, &bak_path)
            })();
            if ok.is_err() {
                let _ = fs::remove_file(&bak_tmp);
            }
        }
    }

    if let Err(e) = fs::rename(&tmp_path, target) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    fs::set_permissions(target, fs::Permissions::from_mode(0o600))?;

    // 3. 对父目录执行 fsync，确保 rename 后的目录项持久写入闪存
    if let Ok(dir_fd) = File::open(&parent) {
        let _ = dir_fd.sync_all();
    }
    Ok(())
}

pub fn random_nonce() -> u64 {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 8];
    let _ = ring::rand::SystemRandom::new().fill(&mut b);
    u64::from_le_bytes(b)
}

pub fn random_alnum(len: usize) -> String {
    use ring::rand::SecureRandom;
    const CHARS: &[u8] = b"abcdefghijkmnpqrstuvwxyz23456789";
    let mut buf = vec![0u8; len];
    let _ = ring::rand::SystemRandom::new().fill(&mut buf);
    buf.iter().map(|b| CHARS[(*b as usize) % CHARS.len()] as char).collect()
}

/// 序列化并原子写入配置
pub fn save_config(path: &Path, cfg: &Config) -> Result<(), String> {
    let text = toml::to_string_pretty(cfg).map_err(|e| format!("序列化配置失败: {}", e))?;
    crash_safe_atomic_write(path, text.as_bytes(), random_nonce()).map_err(|e| format!("原子写入配置失败: {}", e))
}

pub fn parse_config(text: &str) -> Result<Config, String> {
    toml::from_str::<Config>(text).map_err(|e| format!("配置解析失败: {}", e))
}

/// 加载结果：配置 + 是否需要回写（初始化密码哈希、随机安全路径等）
pub struct LoadOutcome {
    pub config: Config,
    pub dirty: bool,
    pub created: bool,
}

/// 加载配置文件；不存在时生成默认配置。会补齐初始密码哈希与随机安全路径。
pub fn load_or_init(path: &Path) -> Result<LoadOutcome, String> {
    let (mut cfg, created) = if path.exists() {
        let meta = fs::metadata(path).map_err(|e| format!("读取配置失败: {}", e))?;
        if meta.permissions().mode() & 0o077 != 0 {
            crate::log_warn!("config", "配置文件权限过宽（{:o}），将收紧为 0600", meta.permissions().mode() & 0o777);
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
        let text = fs::read_to_string(path).map_err(|e| format!("读取配置失败: {}", e))?;
        (parse_config(&text)?, false)
    } else {
        (Config::default(), true)
    };
    let mut dirty = created;
    if crate::security::auth::PasswordHash::parse(&cfg.admin.password_hash).is_none() {
        cfg.admin.password_hash = crate::security::auth::PasswordHash::create(crate::security::auth::DEFAULT_INITIAL_PASSWORD)
            .map_err(|e| e.to_string())?
            .encode();
        cfg.admin.must_change_password = true;
        dirty = true;
    }
    if cfg.admin.secret_path == SECRET_PATH_PLACEHOLDER {
        cfg.admin.secret_path = format!("/_vane_{}", random_alnum(16));
        dirty = true;
    }
    Ok(LoadOutcome { config: cfg, dirty, created })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vane-test-{}-{}", tag, random_alnum(8)));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn atomic_write_creates_0600_and_backup() {
        let d = tmpdir("aw");
        let target = d.join("config.toml");
        crash_safe_atomic_write(&target, b"first", 1).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"first");
        assert_eq!(fs::metadata(&target).unwrap().permissions().mode() & 0o777, 0o600);
        crash_safe_atomic_write(&target, b"second", 2).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"second");
        let bak = d.join("config.toml.bak");
        assert_eq!(fs::read(&bak).unwrap(), b"first");
        assert_eq!(fs::metadata(&bak).unwrap().permissions().mode() & 0o777, 0o600);
        // 不残留临时文件
        let leftovers: Vec<_> = fs::read_dir(&d)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn atomic_write_fails_cleanly_when_tmp_exists() {
        let d = tmpdir("aw2");
        let target = d.join("c.toml");
        crash_safe_atomic_write(&target, b"ok", 7).unwrap();
        // 预先占用同名临时文件，O_EXCL 必须失败且目标保持原值
        let tmp = d.join(format!(".c.toml.{}.{:016x}.tmp", std::process::id(), 9u64));
        fs::write(&tmp, b"x").unwrap();
        assert!(crash_safe_atomic_write(&target, b"bad", 9).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"ok");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn default_config_is_valid_and_has_expected_defaults() {
        let c = Config::default();
        c.validate().unwrap();
        assert_eq!(c.admin.listen_lan, vec!["192.168.1.1:23456".to_string()]);
        assert_eq!(c.admin.username, "admin");
        assert!(c.admin.must_change_password);
        assert_eq!(c.admin.session_ttl_secs, 3600);
        assert!(!c.modules.web_terminal);
        assert!(!c.modules.stun);
        assert!(!c.modules.cron);
    }

    #[test]
    fn validation_rejects_bad_values() {
        let mut c = Config::default();
        c.admin.session_ttl_secs = 86_401;
        assert!(c.validate().is_err());
        c.admin.session_ttl_secs = 299;
        assert!(c.validate().is_err());
        c.admin.session_ttl_secs = 86_400;
        c.validate().unwrap();

        let mut c = Config::default();
        c.admin.listen_lan = vec!["0.0.0.0:23456".into()];
        assert!(c.validate().is_err());

        let mut c = Config::default();
        c.port_forwards.push(PortForwardConfig {
            name: "ssh".into(),
            listen_port: 22,
            target: "192.168.1.10:22".into(),
            ..Default::default()
        });
        assert!(c.validate().unwrap_err().contains("受保护端口"));
        c.port_forwards[0].listen_port = 2222;
        c.validate().unwrap();
        // 内核 DNAT 跨栈被拒绝
        c.port_forwards[0].engine = "kernel_dnat".into();
        assert!(c.validate().is_err());
        c.port_forwards[0].stack = "ipv4_only".into();
        c.validate().unwrap();
    }

    #[test]
    fn example_config_parses_and_validates() {
        let text = include_str!("../config.example.toml");
        let c = parse_config(text).unwrap();
        c.validate().unwrap();
        assert_eq!(c.ddns.len(), 2);
        assert!(matches!(c.ddns[1].source, DdnsSource::PrefixAndIid { .. }));
    }

    #[test]
    fn cidr_and_window_helpers() {
        let c = parse_cidr("192.168.1.0/24").unwrap();
        assert!(cidr_contains(&c, "192.168.1.77".parse().unwrap()));
        assert!(cidr_contains(&c, "::ffff:192.168.1.5".parse().unwrap()));
        assert!(!cidr_contains(&c, "192.168.2.1".parse().unwrap()));
        let c6 = parse_cidr("2001:db8::/32").unwrap();
        assert!(cidr_contains(&c6, "2001:db8:1::1".parse().unwrap()));
        let w = parse_time_window("23:00-06:30").unwrap();
        assert!(time_window_contains(w, 23 * 60 + 5));
        assert!(time_window_contains(w, 60));
        assert!(!time_window_contains(w, 12 * 60));
        assert_eq!(parse_tz_offset("+08:00"), Some(28_800));
        assert_eq!(parse_tz_offset("-0530"), Some(-19_800));
        assert_eq!(parse_posix_tz("CST-8"), Some(28_800));
    }

    #[test]
    fn load_or_init_bootstraps_default_password() {
        let d = tmpdir("load");
        let p = d.join("config.toml");
        let out = load_or_init(&p).unwrap();
        assert!(out.created && out.dirty);
        assert!(out.config.admin.must_change_password);
        assert_ne!(out.config.admin.secret_path, SECRET_PATH_PLACEHOLDER);
        let h = crate::security::auth::PasswordHash::parse(&out.config.admin.password_hash).unwrap();
        assert!(h.verify(b"admin321"));
        save_config(&p, &out.config).unwrap();
        let again = load_or_init(&p).unwrap();
        assert!(!again.dirty);
        fs::remove_dir_all(&d).unwrap();
    }
}
