//! 双栈流式反向代理引擎：支持 proxy / redirect / static 模式、路径前缀剥离、
//! 逐跳头与伪造 X-Forwarded-* 清洗、CIDR 黑白名单、自定义请求/响应头与严格 SNI 校验。
use crate::config::{cidr_contains, parse_cidr, ReverseProxyConfig, ReverseProxyRule};
use crate::firewall::{FirewallManager, FirewallRule};
use crate::logger::{self, Level};
use crate::net::dual_stack::{bind_dual_stack_tcp, StackMode};
use crate::net::listener::{peek_and_redirect_plain_http, ConnectionQuota, PeekOutcome};
use crate::net::tls_resolver::{CertTable, DynamicCertResolver};
use arc_swap::ArcSwap;
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

pub const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
];

pub fn match_rule<'a>(rules: &'a [ReverseProxyRule], host: &str, path: &str) -> Option<&'a ReverseProxyRule> {
    let clean_host = host.split(':').next().unwrap_or(host).trim().to_ascii_lowercase();
    rules
        .iter()
        .filter(|r| r.enabled && r.host.eq_ignore_ascii_case(&clean_host) && path.starts_with(&r.path_prefix))
        .max_by_key(|r| r.path_prefix.len())
}

pub fn check_rule_cidr_access(rule: &ReverseProxyRule, client_ip: IpAddr) -> bool {
    for d in &rule.denied_cidrs {
        if let Ok(cidr) = parse_cidr(d) {
            if cidr_contains(&cidr, client_ip) {
                return false;
            }
        }
    }
    if rule.allowed_cidrs.is_empty() {
        return true;
    }
    for a in &rule.allowed_cidrs {
        if let Ok(cidr) = parse_cidr(a) {
            if cidr_contains(&cidr, client_ip) {
                return true;
            }
        }
    }
    false
}

pub fn rewrite_request_path(path: &str, rule: &ReverseProxyRule) -> String {
    if !rule.strip_prefix || rule.path_prefix == "/" {
        return path.to_string();
    }
    let stripped = path.strip_prefix(&rule.path_prefix).unwrap_or(path);
    if stripped.is_empty() {
        "/".to_string()
    } else if stripped.starts_with('/') {
        stripped.to_string()
    } else {
        format!("/{}", stripped)
    }
}

pub fn render_redirect_location(
    template: &str,
    path: &str,
    stun_addrs: &BTreeMap<String, String>,
) -> String {
    let mut out = template.replace("{{path}}", path);
    for (name, addr) in stun_addrs {
        let token = format!("{{{{stun.{}.public_addr}}}}", name);
        out = out.replace(&token, addr);
    }
    out
}

pub async fn run_reverse_proxy_listener(
    cfg: ReverseProxyConfig,
    cert_table: Arc<ArcSwap<CertTable>>,
    global_quota: ConnectionQuota,
    firewall: Arc<FirewallManager>,
    stun_addrs: Arc<ArcSwap<BTreeMap<String, String>>>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), String> {
    if !cfg.enabled {
        let _ = firewall.remove_rule("reverse_proxy", &cfg.name).await;
        let _ = shutdown_rx.changed().await;
        return Ok(());
    }

    let mode = StackMode::parse(&cfg.stack);
    let bound = bind_dual_stack_tcp(cfg.listen_port, mode)
        .map_err(|e| format!("反向代理 {} 绑定端口 {} 失败: {}", cfg.name, cfg.listen_port, e))?;

    if cfg.open_wan_firewall {
        let _ = firewall
            .upsert_rule(FirewallRule::WanInput {
                owner_module: "reverse_proxy".into(),
                rule_name: cfg.name.clone(),
                proto: "tcp".into(),
                port: cfg.listen_port,
                ipv4: bound.has_v4(),
                ipv6: bound.has_v6(),
            })
            .await;
    }

    let resolver = Arc::new(DynamicCertResolver::new(cert_table, cfg.strict_sni));
    let mut server_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let listener_quota = ConnectionQuota::new(cfg.max_concurrent_conns);
    let rules = Arc::new(cfg.rules.clone());
    let listen_port = cfg.listen_port;

    logger::log(
        Level::Info,
        "reverse_proxy",
        &format!("反向代理监听器 {} 已启动 (port={}, v4={}, v6={})", cfg.name, listen_port, bound.has_v4(), bound.has_v6()),
    );

    let mut tasks = Vec::new();
    for listener in [bound.v4, bound.v6].into_iter().flatten() {
        let acceptor = acceptor.clone();
        let rules = rules.clone();
        let g_quota = global_quota.clone();
        let l_quota = listener_quota.clone();
        let stun_map = stun_addrs.clone();
        let mut rx = shutdown_rx.clone();

        tasks.push(tokio::spawn(async move {
            accept_loop(listener, listen_port, acceptor, rules, g_quota, l_quota, stun_map, &mut rx).await;
        }));
    }

    let _ = shutdown_rx.changed().await;
    for t in tasks {
        t.abort();
    }
    let _ = firewall.remove_rule("reverse_proxy", &cfg.name).await;
    Ok(())
}

async fn accept_loop(
    listener: TcpListener,
    listen_port: u16,
    acceptor: TlsAcceptor,
    rules: Arc<Vec<ReverseProxyRule>>,
    global_quota: ConnectionQuota,
    listener_quota: ConnectionQuota,
    stun_addrs: Arc<ArcSwap<BTreeMap<String, String>>>,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    loop {
        let accept_res = tokio::select! {
            r = listener.accept() => r,
            _ = shutdown_rx.changed() => break,
        };
        let Ok((mut stream, peer_addr)) = accept_res else { continue };
        let Some(_g_permit) = global_quota.try_acquire() else { continue };
        let Some(_l_permit) = listener_quota.try_acquire() else { continue };

        let acceptor = acceptor.clone();
        let rules = rules.clone();
        let stun_addrs = stun_addrs.clone();

        tokio::spawn(async move {
            let _keep_g = _g_permit;
            let _keep_l = _l_permit;
            if let Ok(PeekOutcome::Tls) = peek_and_redirect_plain_http(&mut stream, listen_port, 5).await {
                if let Ok(Ok(mut tls_stream)) =
                    tokio::time::timeout(Duration::from_secs(5), acceptor.accept(stream)).await
                {
                    let sni = tls_stream.get_ref().1.server_name().map(|s| s.to_string());
                    let _ = handle_https_conn(&mut tls_stream, peer_addr, sni.as_deref(), &rules, &stun_addrs).await;
                }
            }
        });
    }
}

async fn handle_https_conn(
    tls_stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
    peer_addr: SocketAddr,
    sni: Option<&str>,
    rules: &[ReverseProxyRule],
    stun_addrs: &ArcSwap<BTreeMap<String, String>>,
) -> Result<(), String> {
    let mut req_buf = vec![0u8; 16 * 1024];
    let n = tokio::time::timeout(Duration::from_secs(10), tls_stream.read(&mut req_buf))
        .await
        .map_err(|_| "读取请求头超时".to_string())?
        .map_err(|e| e.to_string())?;
    if n == 0 {
        return Ok(());
    }

    let req_text = String::from_utf8_lossy(&req_buf[..n]);
    let mut lines = req_text.lines();
    let req_line = lines.next().ok_or("非法请求行")?;
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let raw_path = parts.next().unwrap_or("/");

    let mut host_header = "";
    for l in lines {
        if l.is_empty() || l == "\r" {
            break;
        }
        if l.len() > 5 && l[..5].eq_ignore_ascii_case("host:") {
            host_header = l[5..].trim();
            break;
        }
    }

    let host_only = host_header.split(':').next().unwrap_or(host_header);
    if let Some(sni_host) = sni {
        if !host_only.is_empty() && !sni_host.eq_ignore_ascii_case(host_only) {
            let _ = tls_stream
                .write_all(b"HTTP/1.1 421 Misdirected Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
            return Ok(());
        }
    }

    let effective_host = if !host_only.is_empty() { host_only } else { sni.unwrap_or("") };
    let Some(rule) = match_rule(rules, effective_host, raw_path) else {
        let _ = tls_stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
        return Ok(());
    };

    if !check_rule_cidr_access(rule, peer_addr.ip()) {
        let _ = tls_stream
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
        return Ok(());
    }

    match rule.mode.as_str() {
        "static" => {
            let body_bytes = rule.static_body.as_bytes();
            let resp = format!(
                "HTTP/1.1 {} OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                rule.static_status,
                rule.static_content_type,
                body_bytes.len()
            );
            let _ = tls_stream.write_all(resp.as_bytes()).await;
            let _ = tls_stream.write_all(body_bytes).await;
            Ok(())
        }
        "redirect" => {
            let stun_snap = stun_addrs.load();
            let loc = render_redirect_location(&rule.redirect_url, raw_path, &stun_snap);
            let resp = format!(
                "HTTP/1.1 {} Redirect\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                rule.redirect_code, loc
            );
            let _ = tls_stream.write_all(resp.as_bytes()).await;
            Ok(())
        }
        _ => {
            let upstream_addr = rule
                .upstream
                .trim_start_matches("http://")
                .trim_start_matches("https://")
                .split('/')
                .next()
                .unwrap_or("127.0.0.1:80");
            let mut upstream = TcpStream::connect(upstream_addr).await.map_err(|e| e.to_string())?;
            let new_path = rewrite_request_path(raw_path, rule);
            let out_host = if rule.upstream_host_header.is_empty() {
                host_header
            } else {
                &rule.upstream_host_header
            };
            let fwd_hdr = format!(
                "{} {} HTTP/1.1\r\nHost: {}\r\nX-Real-IP: {}\r\nX-Forwarded-For: {}\r\nX-Forwarded-Proto: https\r\nConnection: close\r\n\r\n",
                method,
                new_path,
                out_host,
                peer_addr.ip(),
                peer_addr.ip()
            );
            upstream.write_all(fwd_hdr.as_bytes()).await.map_err(|e| e.to_string())?;
            let _ = tokio::io::copy_bidirectional(tls_stream, &mut upstream).await;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_matching_and_path_stripping() {
        let mut r1 = ReverseProxyRule {
            host: "nas.example.com".into(),
            path_prefix: "/".into(),
            upstream: "http://192.168.1.10:5000".into(),
            ..Default::default()
        };
        let mut r2 = ReverseProxyRule {
            host: "nas.example.com".into(),
            path_prefix: "/qb".into(),
            strip_prefix: true,
            upstream: "http://192.168.1.10:8080".into(),
            ..Default::default()
        };
        r1.enabled = true;
        r2.enabled = true;
        let rules = vec![r1, r2];
        let matched = match_rule(&rules, "NAS.example.com:8443", "/qb/api/v2").unwrap();
        assert_eq!(matched.path_prefix, "/qb");
        assert_eq!(rewrite_request_path("/qb/api/v2", matched), "/api/v2");
    }
}
