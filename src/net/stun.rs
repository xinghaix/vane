//! RFC 5389 / 8489 STUN 双栈穿透探测与持久保活状态机：
//! 支持同端口 SO_REUSEPORT 持续持有映射、UDP/TCP 流式帧解析、IPv4/IPv6 双栈服务器，
//! 并在映射地址变化时真实触发 Webhook、Cloudflare Redirect Ruleset API 与多渠道通知。
use crate::config::{CloudflareRedirectConfig, Config, StunConfig};
use crate::daemon::notify::dispatch_notification;
use crate::logger::{self, Level};
use crate::net::dual_stack::{bind_reusable_udp, connect_tcp_with_options};
use crate::net::http_client::{shared as http_shared, HttpRequest};
use crate::security::vault::Vault;
use arc_swap::ArcSwap;
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::watch;

pub const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_RESPONSE_SUCCESS: u16 = 0x0101;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const CF_API_BASE_DEFAULT: &str = "https://api.cloudflare.com/client/v4";

#[derive(Clone, Debug, Default, Serialize)]
pub struct StunStatus {
    pub name: String,
    pub enabled: bool,
    pub proto: String,
    pub local_addr: String,
    pub public_addr: String,
    pub server: String,
    pub status: String,
    pub last_probe_unix: u64,
    pub last_change_unix: u64,
    pub error: String,
}

pub type StunRuntime = Arc<RwLock<BTreeMap<String, StunStatus>>>;

pub fn new_stun_runtime() -> StunRuntime {
    Arc::new(RwLock::new(BTreeMap::new()))
}

pub fn build_binding_request() -> ([u8; 20], [u8; 12]) {
    let mut tx_id = [0u8; 12];
    let _ = SystemRandom::new().fill(&mut tx_id);
    let mut pkt = [0u8; 20];
    pkt[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    pkt[2..4].copy_from_slice(&0u16.to_be_bytes());
    pkt[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    pkt[8..20].copy_from_slice(&tx_id);
    (pkt, tx_id)
}

pub fn parse_binding_response(pkt: &[u8], expected_tx_id: &[u8; 12]) -> Result<SocketAddr, &'static str> {
    if pkt.len() < 20 {
        return Err("STUN 报文不足 20 字节");
    }
    let msg_type = u16::from_be_bytes([pkt[0], pkt[1]]);
    let msg_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    let cookie = u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
    if msg_type != BINDING_RESPONSE_SUCCESS || cookie != STUN_MAGIC_COOKIE {
        return Err("STUN Magic Cookie 或响应类型不匹配");
    }
    if &pkt[8..20] != expected_tx_id {
        return Err("STUN Transaction ID 不匹配");
    }
    if pkt.len() < 20 + msg_len {
        return Err("STUN 属性负载被截断");
    }

    let mut pos = 20;
    let end = 20 + msg_len;
    let mut fallback_mapped = None;

    while pos + 4 <= end {
        let attr_type = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
        let attr_len = u16::from_be_bytes([pkt[pos + 2], pkt[pos + 3]]) as usize;
        pos += 4;
        if pos + attr_len > end {
            return Err("STUN 属性长度越界");
        }
        let val = &pkt[pos..pos + attr_len];
        if attr_type == ATTR_XOR_MAPPED_ADDRESS {
            if let Some(addr) = parse_xor_mapped(val, expected_tx_id) {
                return Ok(addr);
            }
        } else if attr_type == ATTR_MAPPED_ADDRESS && fallback_mapped.is_none() {
            fallback_mapped = parse_plain_mapped(val);
        }
        let pad = (4 - (attr_len % 4)) % 4;
        pos = pos.saturating_add(attr_len).saturating_add(pad);
    }

    fallback_mapped.ok_or("未找到有效的 MAPPED-ADDRESS 属性")
}

fn parse_xor_mapped(val: &[u8], tx_id: &[u8; 12]) -> Option<SocketAddr> {
    if val.len() < 8 {
        return None;
    }
    let family = val[1];
    let xport = u16::from_be_bytes([val[2], val[3]]);
    let port = xport ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
    let cookie_bytes = STUN_MAGIC_COOKIE.to_be_bytes();

    match family {
        0x01 if val.len() >= 8 => {
            let ip = Ipv4Addr::new(
                val[4] ^ cookie_bytes[0],
                val[5] ^ cookie_bytes[1],
                val[6] ^ cookie_bytes[2],
                val[7] ^ cookie_bytes[3],
            );
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x02 if val.len() >= 20 => {
            let mut oct = [0u8; 16];
            for i in 0..4 {
                oct[i] = val[4 + i] ^ cookie_bytes[i];
            }
            for i in 0..12 {
                oct[4 + i] = val[8 + i] ^ tx_id[i];
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(oct)), port))
        }
        _ => None,
    }
}

fn parse_plain_mapped(val: &[u8]) -> Option<SocketAddr> {
    if val.len() < 8 {
        return None;
    }
    let family = val[1];
    let port = u16::from_be_bytes([val[2], val[3]]);
    match family {
        0x01 if val.len() >= 8 => {
            let ip = Ipv4Addr::new(val[4], val[5], val[6], val[7]);
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x02 if val.len() >= 20 => {
            let mut oct = [0u8; 16];
            oct.copy_from_slice(&val[4..20]);
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(oct)), port))
        }
        _ => None,
    }
}

pub fn format_public_endpoint(addr: SocketAddr) -> String {
    addr.to_string()
}

pub fn effective_local_port(entry: &StunConfig, cfg: Option<&Config>) -> u16 {
    if entry.local_port != 0 {
        return entry.local_port;
    }
    let Some(cfg) = cfg else { return 0 };
    if entry.bind_rule.is_empty() {
        return 0;
    }
    if let Some(pf) = cfg.port_forwards.iter().find(|p| p.name == entry.bind_rule) {
        return pf.listen_port;
    }
    if let Some(rp) = cfg.reverse_proxy.iter().find(|r| r.name == entry.bind_rule) {
        return rp.listen_port;
    }
    0
}

#[derive(Clone, Debug)]
pub struct ProbeOutcome {
    pub mapped: SocketAddr,
    pub local_addr: SocketAddr,
    pub server_used: String,
}

struct PersistentUdpSockets {
    v4: Option<UdpSocket>,
    v6: Option<UdpSocket>,
    bound_port: u16,
}

impl PersistentUdpSockets {
    fn new(bound_port: u16) -> Self {
        Self { v4: None, v6: None, bound_port }
    }

    fn socket_for(&mut self, ipv6: bool) -> Result<&UdpSocket, String> {
        if ipv6 {
            if self.v6.is_none() {
                let bind = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), self.bound_port);
                let s = bind_reusable_udp(bind, "").map_err(|e| format!("绑定 IPv6 STUN UDP 端口失败: {}", e))?;
                self.v6 = Some(s);
            }
            Ok(self.v6.as_ref().unwrap())
        } else {
            if self.v4.is_none() {
                let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), self.bound_port);
                let s = bind_reusable_udp(bind, "").map_err(|e| format!("绑定 IPv4 STUN UDP 端口失败: {}", e))?;
                self.v4 = Some(s);
            }
            Ok(self.v4.as_ref().unwrap())
        }
    }

    fn reset(&mut self, ipv6: bool) {
        if ipv6 {
            self.v6 = None;
        } else {
            self.v4 = None;
        }
    }
}

async fn resolve_server_addrs(server: &str) -> Result<Vec<SocketAddr>, String> {
    if let Ok(sock) = server.parse::<SocketAddr>() {
        return Ok(vec![sock]);
    }
    let addrs: Vec<SocketAddr> = tokio::time::timeout(Duration::from_secs(4), tokio::net::lookup_host(server))
        .await
        .map_err(|_| format!("解析 STUN 服务器 {} 超时", server))?
        .map_err(|e| format!("解析 STUN 服务器 {} 失败: {}", server, e))?
        .take(8)
        .collect();
    if addrs.is_empty() {
        return Err(format!("STUN 服务器 {} 无可用地址", server));
    }
    Ok(addrs)
}

async fn probe_udp_on_socket(sock: &UdpSocket, target: SocketAddr) -> Result<SocketAddr, String> {
    let (req, tx_id) = build_binding_request();
    sock.send_to(&req, target).await.map_err(|e| format!("UDP 发送失败: {}", e))?;
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut buf = [0u8; 1024];
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err("STUN UDP 响应超时".into());
        }
        let (n, _) = tokio::time::timeout(deadline - now, sock.recv_from(&mut buf))
            .await
            .map_err(|_| "STUN UDP 响应超时".to_string())?
            .map_err(|e| format!("UDP 接收失败: {}", e))?;
        if n >= 20 && &buf[8..20] != &tx_id {
            // 忽略共享端口或残留重传的非本事务报文，继续等待匹配的 tx_id
            continue;
        }
        return parse_binding_response(&buf[..n], &tx_id).map_err(str::to_string);
    }
}

async fn read_stun_tcp_response(stream: &mut TcpStream, tx_id: &[u8; 12]) -> Result<SocketAddr, String> {
    let mut hdr = [0u8; 20];
    tokio::time::timeout(Duration::from_secs(4), stream.read_exact(&mut hdr))
        .await
        .map_err(|_| "STUN TCP 读取帧头超时".to_string())?
        .map_err(|e| format!("STUN TCP 读取帧头失败: {}", e))?;
    let msg_len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
    if msg_len > 1024 {
        return Err(format!("STUN TCP 响应负载超限: {}", msg_len));
    }
    let mut full = Vec::with_capacity(20 + msg_len);
    full.extend_from_slice(&hdr);
    full.resize(20 + msg_len, 0);
    if msg_len > 0 {
        tokio::time::timeout(Duration::from_secs(4), stream.read_exact(&mut full[20..]))
            .await
            .map_err(|_| "STUN TCP 读取属性超时".to_string())?
            .map_err(|e| format!("STUN TCP 读取属性失败: {}", e))?;
    }
    parse_binding_response(&full, tx_id).map_err(str::to_string)
}

async fn probe_tcp_target(target: SocketAddr, local_port: u16, persistent: &mut Option<TcpStream>) -> Result<(SocketAddr, SocketAddr), String> {
    if let Some(ref mut existing) = persistent {
        let (req, tx_id) = build_binding_request();
        if existing.write_all(&req).await.is_ok() {
            if let Ok(mapped) = read_stun_tcp_response(existing, &tx_id).await {
                let local = existing.local_addr().unwrap_or_else(|_| SocketAddr::new(target.ip(), local_port));
                return Ok((mapped, local));
            }
        }
        *persistent = None;
    }

    let mut stream = tokio::time::timeout(
        Duration::from_secs(4),
        connect_tcp_with_options(target, None, local_port, "", local_port != 0),
    )
    .await
    .map_err(|_| "STUN TCP 连接超时".to_string())?
    .map_err(|e| format!("STUN TCP 连接失败: {}", e))?;

    let local = stream
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::new(target.ip(), local_port));
    let (req, tx_id) = build_binding_request();
    stream
        .write_all(&req)
        .await
        .map_err(|e| format!("STUN TCP 发送失败: {}", e))?;
    let mapped = read_stun_tcp_response(&mut stream, &tx_id).await?;
    *persistent = Some(stream);
    Ok((mapped, local))
}

async fn probe_with_session(
    entry: &StunConfig,
    local_port: u16,
    udp_socks: &mut PersistentUdpSockets,
    tcp_conn: &mut Option<TcpStream>,
) -> Result<ProbeOutcome, String> {
    let servers = entry.servers();
    if servers.is_empty() {
        return Err("未配置 STUN 服务器".into());
    }
    let mut last_err = String::new();
    for srv in servers {
        let candidates = match resolve_server_addrs(&srv).await {
            Ok(c) => c,
            Err(e) => {
                last_err = e;
                continue;
            }
        };
        for target in candidates {
            let attempt = if entry.proto == "tcp" {
                probe_tcp_target(target, local_port, tcp_conn).await
            } else {
                match udp_socks.socket_for(target.is_ipv6()) {
                    Ok(sock) => match probe_udp_on_socket(sock, target).await {
                        Ok(mapped) => {
                            let local = sock.local_addr().unwrap_or(target);
                            Ok((mapped, local))
                        }
                        Err(e) => {
                            udp_socks.reset(target.is_ipv6());
                            Err(e)
                        }
                    },
                    Err(e) => Err(e),
                }
            };
            match attempt {
                Ok((mapped, local_addr)) => {
                    return Ok(ProbeOutcome {
                        mapped,
                        local_addr,
                        server_used: srv,
                    });
                }
                Err(e) => last_err = format!("{} ({}): {}", srv, target, e),
            }
        }
    }
    Err(last_err)
}

/// 单次即时探测（用于 CLI / 测试或无状态调用）
pub async fn probe_stun_once(cfg: &StunConfig) -> Result<SocketAddr, String> {
    let mut udp_socks = PersistentUdpSockets::new(cfg.local_port);
    let mut tcp_conn = None;
    let out = probe_with_session(cfg, cfg.local_port, &mut udp_socks, &mut tcp_conn).await?;
    logger::log(
        Level::Info,
        "stun",
        &format!(
            "STUN 规则 {} 通过 {} 探测到公网映射: {}",
            cfg.name,
            out.server_used,
            format_public_endpoint(out.mapped)
        ),
    );
    Ok(out.mapped)
}

pub fn build_cloudflare_redirect_payload(
    source_host: &str,
    target_template: &str,
    mapped: SocketAddr,
    status_code: u16,
) -> String {
    let public_addr = format_public_endpoint(mapped);
    let target_url = target_template
        .replace("{{public_addr}}", &public_addr)
        .replace("{{ip}}", &mapped.ip().to_string())
        .replace("{{port}}", &mapped.port().to_string());
    let mut map = BTreeMap::new();
    map.insert("action", json!("redirect"));
    map.insert("expression", json!(format!(r#"(http.host eq "{}")"#, source_host)));
    map.insert(
        "action_parameters",
        json!({
            "from_value": {
                "status_code": status_code,
                "target_url": { "value": target_url },
                "preserve_query_string": true
            }
        }),
    );
    serde_json::to_string(&map).unwrap_or_default()
}

pub async fn push_cloudflare_redirect_with_base(
    api_base: &str,
    rule_name: &str,
    cf: &CloudflareRedirectConfig,
    vault: &Vault,
    mapped: SocketAddr,
) -> Result<(), String> {
    let token = vault.reveal_string(
        &format!("stun.{}.on_change_cloudflare_redirect.api_token", rule_name),
        &cf.api_token,
    )?;
    if token.is_empty() {
        return Err("Cloudflare Redirect API Token 为空".into());
    }
    let url = format!(
        "{}/zones/{}/rulesets/{}/rules/{}",
        api_base.trim_end_matches('/'),
        cf.zone_id,
        cf.ruleset_id,
        cf.rule_id
    );
    let body_str = build_cloudflare_redirect_payload(&cf.source_host, &cf.target_template, mapped, cf.status_code);
    let mut req = HttpRequest::new("PATCH", &url);
    req.headers.insert("authorization".into(), format!("Bearer {}", token));
    req.headers.insert("content-type".into(), "application/json".into());
    req.body = body_str.into_bytes();
    req.response_limit = 64 * 1024;
    let resp = http_shared().execute(req).await?;
    resp.ensure_success()?;
    let val: Value = resp.json()?;
    if val.get("success").and_then(Value::as_bool) != Some(true) {
        return Err("Cloudflare Redirect Ruleset API 返回业务失败 (success != true)".into());
    }
    Ok(())
}

async fn run_change_hooks(
    entry: &StunConfig,
    cfg: &Config,
    vault: &Vault,
    mapped: SocketAddr,
    previous_addr: &str,
    cf_api_base: &str,
) -> Result<(), String> {
    let public_addr = format_public_endpoint(mapped);
    let mut errors = Vec::new();

    if !entry.webhook_url.is_empty() {
        match vault.reveal_string(&format!("stun.{}.webhook_url", entry.name), &entry.webhook_url) {
            Ok(url) if !url.is_empty() => {
                let payload = json!({
                    "event": "stun_change",
                    "name": entry.name,
                    "proto": entry.proto,
                    "public_addr": public_addr,
                    "ip": mapped.ip().to_string(),
                    "port": mapped.port(),
                    "previous_addr": previous_addr,
                    "timestamp": logger::unix_now(),
                });
                let mut req = HttpRequest::new("POST", &url).json(&payload);
                req.response_limit = 32 * 1024;
                match http_shared().execute(req).await.and_then(|r| r.ensure_success().map(|_| ())) {
                    Ok(()) => logger::log(Level::Info, "stun", &format!("STUN {} 已推送 Webhook 回调", entry.name)),
                    Err(e) => errors.push(format!("Webhook 回调失败: {}", e)),
                }
            }
            Ok(_) => {}
            Err(e) => errors.push(format!("解密 Webhook URL 失败: {}", e)),
        }
    }

    if let Some(ref cf) = entry.on_change_cloudflare_redirect {
        match push_cloudflare_redirect_with_base(cf_api_base, &entry.name, cf, vault, mapped).await {
            Ok(()) => logger::log(
                Level::Info,
                "stun",
                &format!("STUN {} 已更新 Cloudflare Redirect 规则 -> {}", entry.name, public_addr),
            ),
            Err(e) => errors.push(format!("Cloudflare Redirect 更新失败: {}", e)),
        }
    }

    let title = format!("STUN 映射变更: {}", entry.name);
    let msg = if previous_addr.is_empty() {
        format!("规则 {} 建立新公网映射: {}", entry.name, public_addr)
    } else {
        format!("规则 {} 公网映射由 {} 变更为 {}", entry.name, previous_addr, public_addr)
    };
    for n in cfg.notifications.iter().filter(|n| n.enabled) {
        if let Err(e) = dispatch_notification(n, vault, "stun_change", &title, &msg, "info").await {
            logger::log(Level::Warn, "stun", &format!("通知渠道 {} 投递 STUN 变更失败: {}", n.name, e));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn update_status(runtime: &StunRuntime, st: StunStatus) {
    if let Ok(mut guard) = runtime.write() {
        guard.insert(st.name.clone(), st);
    }
}

/// 管理面板手动探测入口：执行真实 STUN 探测，并在地址变化或首次未同步时触发联动钩子
pub async fn probe_and_sync_stun_entry(
    entry: &StunConfig,
    cfg: &Config,
    vault: &Vault,
    stun_addrs: &ArcSwap<BTreeMap<String, String>>,
    runtime: &StunRuntime,
) -> Result<StunStatus, String> {
    probe_and_sync_stun_with_cf_base(entry, cfg, vault, stun_addrs, runtime, CF_API_BASE_DEFAULT).await
}

pub async fn probe_and_sync_stun_with_cf_base(
    entry: &StunConfig,
    cfg: &Config,
    vault: &Vault,
    stun_addrs: &ArcSwap<BTreeMap<String, String>>,
    runtime: &StunRuntime,
    cf_api_base: &str,
) -> Result<StunStatus, String> {
    let local_port = effective_local_port(entry, Some(cfg));
    let mut udp_socks = PersistentUdpSockets::new(local_port);
    let mut tcp_conn = None;
    let now = logger::unix_now();

    match probe_with_session(entry, local_port, &mut udp_socks, &mut tcp_conn).await {
        Ok(out) => {
            let pub_str = format_public_endpoint(out.mapped);
            let prev = stun_addrs.load().get(&entry.name).cloned().unwrap_or_default();
            let prev_last_change = runtime
                .read()
                .ok()
                .and_then(|g| g.get(&entry.name).map(|s| s.last_change_unix))
                .unwrap_or(0);
            let changed = prev != pub_str;
            if changed {
                let mut next = (**stun_addrs.load()).clone();
                next.insert(entry.name.clone(), pub_str.clone());
                stun_addrs.store(Arc::new(next));
            }
            let hook_err = if changed {
                run_change_hooks(entry, cfg, vault, out.mapped, &prev, cf_api_base)
                    .await
                    .err()
                    .unwrap_or_default()
            } else {
                String::new()
            };
            let st = StunStatus {
                name: entry.name.clone(),
                enabled: entry.enabled,
                proto: entry.proto.clone(),
                local_addr: out.local_addr.to_string(),
                public_addr: pub_str,
                server: out.server_used,
                status: if hook_err.is_empty() { "active".into() } else { "degraded".into() },
                last_probe_unix: now,
                last_change_unix: if changed { now } else { prev_last_change.max(now) },
                error: hook_err,
            };
            update_status(runtime, st.clone());
            Ok(st)
        }
        Err(e) => {
            let prev = runtime.read().ok().and_then(|g| g.get(&entry.name).cloned());
            let st = StunStatus {
                name: entry.name.clone(),
                enabled: entry.enabled,
                proto: entry.proto.clone(),
                local_addr: prev.as_ref().map(|p| p.local_addr.clone()).unwrap_or_default(),
                public_addr: prev.as_ref().map(|p| p.public_addr.clone()).unwrap_or_default(),
                server: String::new(),
                status: "error".into(),
                last_probe_unix: now,
                last_change_unix: prev.as_ref().map(|p| p.last_change_unix).unwrap_or(0),
                error: e.clone(),
            };
            update_status(runtime, st);
            Err(e)
        }
    }
}

/// 长期监督运行的单规则 STUN 保活会话（持续持有同一本地 Socket 端口防止 NAT 映射老化关闭）
pub async fn run_stun_rule(
    entry: StunConfig,
    cfg: Arc<Config>,
    vault: Arc<Vault>,
    stun_addrs: Arc<ArcSwap<BTreeMap<String, String>>>,
    runtime: StunRuntime,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), String> {
    let local_port = effective_local_port(&entry, Some(&cfg));
    let mut udp_socks = PersistentUdpSockets::new(local_port);
    let mut tcp_conn = None;
    let keepalive = Duration::from_secs(entry.keepalive_secs.clamp(5, 3600));
    let mut last_hook_synced_addr = String::new();

    loop {
        if *shutdown_rx.borrow() {
            break;
        }
        let now = logger::unix_now();
        match probe_with_session(&entry, local_port, &mut udp_socks, &mut tcp_conn).await {
            Ok(out) => {
                let pub_str = format_public_endpoint(out.mapped);
                let prev_in_map = stun_addrs.load().get(&entry.name).cloned().unwrap_or_default();
                let addr_changed = prev_in_map != pub_str;
                if addr_changed {
                    logger::log(
                        Level::Info,
                        "stun",
                        &format!("STUN {} 公网映射更新: {} (local={})", entry.name, pub_str, out.local_addr),
                    );
                    let mut next = (**stun_addrs.load()).clone();
                    next.insert(entry.name.clone(), pub_str.clone());
                    stun_addrs.store(Arc::new(next));
                }

                let mut hook_err = String::new();
                if last_hook_synced_addr != pub_str {
                    match run_change_hooks(&entry, &cfg, &vault, out.mapped, &prev_in_map, CF_API_BASE_DEFAULT).await {
                        Ok(()) => last_hook_synced_addr = pub_str.clone(),
                        Err(e) => {
                            logger::log(Level::Warn, "stun", &format!("STUN {} 联动回调异常: {}", entry.name, e));
                            hook_err = e;
                        }
                    }
                }

                let prev_change = runtime
                    .read()
                    .ok()
                    .and_then(|g| g.get(&entry.name).map(|s| s.last_change_unix))
                    .unwrap_or(0);
                update_status(
                    &runtime,
                    StunStatus {
                        name: entry.name.clone(),
                        enabled: entry.enabled,
                        proto: entry.proto.clone(),
                        local_addr: out.local_addr.to_string(),
                        public_addr: pub_str,
                        server: out.server_used,
                        status: if hook_err.is_empty() { "active".into() } else { "degraded".into() },
                        last_probe_unix: now,
                        last_change_unix: if addr_changed || prev_change == 0 { now } else { prev_change },
                        error: hook_err,
                    },
                );
            }
            Err(e) => {
                let prev = runtime.read().ok().and_then(|g| g.get(&entry.name).cloned());
                update_status(
                    &runtime,
                    StunStatus {
                        name: entry.name.clone(),
                        enabled: entry.enabled,
                        proto: entry.proto.clone(),
                        local_addr: prev.as_ref().map(|p| p.local_addr.clone()).unwrap_or_default(),
                        public_addr: prev.as_ref().map(|p| p.public_addr.clone()).unwrap_or_default(),
                        server: String::new(),
                        status: "error".into(),
                        last_probe_unix: now,
                        last_change_unix: prev.as_ref().map(|p| p.last_change_unix).unwrap_or(0),
                        error: e.clone(),
                    },
                );
                return Err(e);
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(keepalive) => {}
            _ = shutdown_rx.changed() => break,
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "stun_tests.rs"]
mod protocol_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stun_xor_mapped_parse_v4_and_v6() {
        let (_, tx_id) = build_binding_request();
        let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
        let ip = [198, 51, 100, 42];
        let port: u16 = 12345;
        let xport = port ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
        let mut resp = Vec::new();
        resp.extend_from_slice(&BINDING_RESPONSE_SUCCESS.to_be_bytes());
        resp.extend_from_slice(&12u16.to_be_bytes());
        resp.extend_from_slice(&cookie);
        resp.extend_from_slice(&tx_id);
        resp.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        resp.extend_from_slice(&8u16.to_be_bytes());
        resp.push(0);
        resp.push(0x01);
        resp.extend_from_slice(&xport.to_be_bytes());
        for i in 0..4 {
            resp.push(ip[i] ^ cookie[i]);
        }

        let parsed = parse_binding_response(&resp, &tx_id).unwrap();
        assert_eq!(parsed, "198.51.100.42:12345".parse().unwrap());
        assert_eq!(format_public_endpoint(parsed), "198.51.100.42:12345");
    }
}
