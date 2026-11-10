//! 4x4 全矩阵双引擎端口转发：支持 TCP (Linux splice / 跨平台回退)、UDP 会话代理、
//! HAProxy Proxy Protocol v1/v2 真实源 IP 注入、多目标主备/轮询、每日时间窗与一键临时开门租约。
use crate::config::{cidr_contains, parse_cidr, parse_time_window, time_window_contains, PortForwardConfig};
use crate::firewall::{FirewallManager, FirewallRule};
use crate::logger::{self, Level};
use crate::net::dual_stack::{bind_dual_stack_tcp, bind_dual_stack_udp, StackMode};
use crate::net::listener::ConnectionQuota;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{watch, Mutex};

pub fn encode_proxy_protocol_v1(client: SocketAddr, local: SocketAddr) -> Vec<u8> {
    match (client.ip(), local.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            format!("PROXY TCP4 {} {} {} {}\r\n", src, dst, client.port(), local.port()).into_bytes()
        }
        _ => {
            let src6 = match client.ip() {
                IpAddr::V6(v6) => v6,
                IpAddr::V4(v4) => v4.to_ipv6_mapped(),
            };
            let dst6 = match local.ip() {
                IpAddr::V6(v6) => v6,
                IpAddr::V4(v4) => v4.to_ipv6_mapped(),
            };
            format!("PROXY TCP6 {} {} {} {}\r\n", src6, dst6, client.port(), local.port()).into_bytes()
        }
    }
}

pub fn encode_proxy_protocol_v2(client: SocketAddr, local: SocketAddr) -> Vec<u8> {
    const SIG: [u8; 12] = [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A];
    let mut out = Vec::with_capacity(52);
    out.extend_from_slice(&SIG);
    out.push(0x21);
    match (client.ip(), local.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            out.push(0x11);
            out.extend_from_slice(&12u16.to_be_bytes());
            out.extend_from_slice(&src.octets());
            out.extend_from_slice(&dst.octets());
            out.extend_from_slice(&client.port().to_be_bytes());
            out.extend_from_slice(&local.port().to_be_bytes());
        }
        _ => {
            let src6 = match client.ip() {
                IpAddr::V6(v6) => v6,
                IpAddr::V4(v4) => v4.to_ipv6_mapped(),
            };
            let dst6 = match local.ip() {
                IpAddr::V6(v6) => v6,
                IpAddr::V4(v4) => v4.to_ipv6_mapped(),
            };
            out.push(0x21);
            out.extend_from_slice(&36u16.to_be_bytes());
            out.extend_from_slice(&src6.octets());
            out.extend_from_slice(&dst6.octets());
            out.extend_from_slice(&client.port().to_be_bytes());
            out.extend_from_slice(&local.port().to_be_bytes());
        }
    }
    out
}

pub fn is_rule_active_now(cfg: &PortForwardConfig, unix_now: u64, tz_offset_secs: i64) -> bool {
    if !cfg.enabled {
        return false;
    }
    if cfg.expire_at_unix > 0 && unix_now >= cfg.expire_at_unix {
        return false;
    }
    if !cfg.allowed_time_window.is_empty() {
        if let Ok(win) = parse_time_window(&cfg.allowed_time_window) {
            let parts = crate::logger::breakdown(unix_now as i64, tz_offset_secs);
            let minute_of_day = parts.hour as u32 * 60 + parts.minute as u32;
            if !time_window_contains(win, minute_of_day) {
                return false;
            }
        }
    }
    true
}

pub fn check_forward_cidr(cfg: &PortForwardConfig, peer_ip: IpAddr) -> bool {
    if cfg.allowed_cidrs.is_empty() {
        return true;
    }
    for c in &cfg.allowed_cidrs {
        if let Ok(parsed) = parse_cidr(c) {
            if cidr_contains(&parsed, peer_ip) {
                return true;
            }
        }
    }
    false
}

pub async fn run_port_forward_rule(
    cfg: PortForwardConfig,
    tz_offset_secs: i64,
    global_quota: ConnectionQuota,
    firewall: Arc<FirewallManager>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), String> {
    let now = logger::unix_now();
    if !is_rule_active_now(&cfg, now, tz_offset_secs) {
        let _ = firewall.remove_rule("port_forward", &cfg.name).await;
        let _ = shutdown_rx.changed().await;
        return Ok(());
    }

    let targets: Vec<SocketAddr> = cfg
        .effective_targets()
        .iter()
        .filter_map(|t| t.parse().ok())
        .collect();
    if targets.is_empty() {
        return Err(format!("端口转发 {} 无有效目标地址", cfg.name));
    }

    if cfg.engine == "kernel_dnat" {
        for proto in ["tcp", "udp"] {
            if cfg.proto == proto || cfg.proto == "tcp_udp" {
                firewall
                    .upsert_rule(FirewallRule::KernelDnat {
                        owner_module: "port_forward".into(),
                        rule_name: format!("{}_{}", cfg.name, proto),
                        proto: proto.into(),
                        listen_port: cfg.listen_port,
                        target: targets[0],
                    })
                    .await?;
            }
        }
        let _ = shutdown_rx.changed().await;
        let _ = firewall.remove_rule("port_forward", &format!("{}_tcp", cfg.name)).await;
        let _ = firewall.remove_rule("port_forward", &format!("{}_udp", cfg.name)).await;
        return Ok(());
    }

    let mode = StackMode::parse(&cfg.stack);
    let rule_quota = ConnectionQuota::new(cfg.max_concurrent_conns);
    let rr_counter = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();

    if cfg.proto == "tcp" || cfg.proto == "tcp_udp" {
        let bound = bind_dual_stack_tcp(cfg.listen_port, mode)
            .map_err(|e| format!("转发规则 {} 绑定 TCP {} 失败: {}", cfg.name, cfg.listen_port, e))?;
        if cfg.open_wan_firewall {
            let _ = firewall
                .upsert_rule(FirewallRule::WanInput {
                    owner_module: "port_forward".into(),
                    rule_name: format!("{}_tcp", cfg.name),
                    proto: "tcp".into(),
                    port: cfg.listen_port,
                    ipv4: bound.has_v4(),
                    ipv6: bound.has_v6(),
                })
                .await;
        }
        for listener in [bound.v4, bound.v6].into_iter().flatten() {
            let cfg_c = cfg.clone();
            let targets_c = targets.clone();
            let g_q = global_quota.clone();
            let r_q = rule_quota.clone();
            let rr = rr_counter.clone();
            let mut rx = shutdown_rx.clone();
            handles.push(tokio::spawn(async move {
                loop {
                    let res = tokio::select! {
                        r = listener.accept() => r,
                        _ = rx.changed() => break,
                    };
                    let Ok((mut inbound, peer)) = res else { continue };
                    if !is_rule_active_now(&cfg_c, logger::unix_now(), tz_offset_secs)
                        || !check_forward_cidr(&cfg_c, peer.ip())
                    {
                        continue;
                    }
                    let Some(_gp) = g_q.try_acquire() else { continue };
                    let Some(_rp) = r_q.try_acquire() else { continue };
                    let targets_inner = targets_c.clone();
                    let lb = cfg_c.load_balance.clone();
                    let pp = cfg_c.send_proxy_protocol.clone();
                    let idx = rr.fetch_add(1, Ordering::Relaxed);
                    tokio::spawn(async move {
                        let _g = _gp;
                        let _r = _rp;
                        let local_addr = inbound.local_addr().unwrap_or(peer);
                        if let Some(mut outbound) = connect_target(&targets_inner, &lb, idx).await {
                            match pp.as_str() {
                                "v1" => {
                                    let _ = outbound.write_all(&encode_proxy_protocol_v1(peer, local_addr)).await;
                                }
                                "v2" => {
                                    let _ = outbound.write_all(&encode_proxy_protocol_v2(peer, local_addr)).await;
                                }
                                _ => {}
                            }
                            let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                        }
                    });
                }
            }));
        }
    }

    if cfg.proto == "udp" || cfg.proto == "tcp_udp" {
        let bound = bind_dual_stack_udp(cfg.listen_port, mode)
            .map_err(|e| format!("转发规则 {} 绑定 UDP {} 失败: {}", cfg.name, cfg.listen_port, e))?;
        if cfg.open_wan_firewall {
            let _ = firewall
                .upsert_rule(FirewallRule::WanInput {
                    owner_module: "port_forward".into(),
                    rule_name: format!("{}_udp", cfg.name),
                    proto: "udp".into(),
                    port: cfg.listen_port,
                    ipv4: bound.v4.is_some(),
                    ipv6: bound.v6.is_some(),
                })
                .await;
        }
        for sock in [bound.v4, bound.v6].into_iter().flatten() {
            let sock = Arc::new(sock);
            let cfg_c = cfg.clone();
            let target = targets[0];
            let mut rx = shutdown_rx.clone();
            handles.push(tokio::spawn(async move {
                run_udp_proxy(sock, target, cfg_c, tz_offset_secs, &mut rx).await;
            }));
        }
    }

    logger::log(Level::Info, "port_forward", &format!("端口转发规则 {} 已启动 (port={})", cfg.name, cfg.listen_port));
    let _ = shutdown_rx.changed().await;
    for h in handles {
        h.abort();
    }
    let _ = firewall.remove_rule("port_forward", &format!("{}_tcp", cfg.name)).await;
    let _ = firewall.remove_rule("port_forward", &format!("{}_udp", cfg.name)).await;
    Ok(())
}

async fn connect_target(targets: &[SocketAddr], lb: &str, rr_idx: usize) -> Option<TcpStream> {
    if targets.is_empty() {
        return None;
    }
    if lb == "round_robin" {
        let start = rr_idx % targets.len();
        for offset in 0..targets.len() {
            let t = targets[(start + offset) % targets.len()];
            if let Ok(Ok(s)) = tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(t)).await {
                return Some(s);
            }
        }
        None
    } else {
        for t in targets {
            if let Ok(Ok(s)) = tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(*t)).await {
                return Some(s);
            }
        }
        None
    }
}

async fn run_udp_proxy(
    inbound: Arc<UdpSocket>,
    target: SocketAddr,
    cfg: PortForwardConfig,
    tz_offset_secs: i64,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    let sessions: Arc<Mutex<HashMap<SocketAddr, (Arc<UdpSocket>, Instant)>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let mut buf = vec![0u8; 4096];
    let idle = Duration::from_secs(cfg.udp_session_timeout_secs.clamp(10, 600));

    loop {
        let recv_res = tokio::select! {
            r = inbound.recv_from(&mut buf) => r,
            _ = shutdown_rx.changed() => break,
        };
        let Ok((n, peer)) = recv_res else { continue };
        if !is_rule_active_now(&cfg, logger::unix_now(), tz_offset_secs) || !check_forward_cidr(&cfg, peer.ip()) {
            continue;
        }

        let upstream_sock = {
            let mut map = sessions.lock().await;
            map.retain(|_, (_, last)| last.elapsed() < idle);
            if let Some((s, last)) = map.get_mut(&peer) {
                *last = Instant::now();
                s.clone()
            } else {
                if map.len() >= cfg.max_concurrent_conns {
                    continue;
                }
                let bind_any = if target.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
                let Ok(s) = UdpSocket::bind(bind_any).await else { continue };
                if s.connect(target).await.is_err() {
                    continue;
                }
                let s = Arc::new(s);
                map.insert(peer, (s.clone(), Instant::now()));

                let s_clone = s.clone();
                let in_clone = inbound.clone();
                let sessions_clone = sessions.clone();
                tokio::spawn(async move {
                    let mut rbuf = vec![0u8; 4096];
                    while let Ok(Ok(rn)) = tokio::time::timeout(idle, s_clone.recv(&mut rbuf)).await {
                        let _ = in_clone.send_to(&rbuf[..rn], peer).await;
                    }
                    sessions_clone.lock().await.remove(&peer);
                });
                s
            }
        };

        let _ = upstream_sock.send(&buf[..n]).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_protocol_headers_are_valid() {
        let c: SocketAddr = "198.51.100.7:54321".parse().unwrap();
        let l: SocketAddr = "192.168.1.1:2222".parse().unwrap();
        let v1 = encode_proxy_protocol_v1(c, l);
        assert_eq!(v1, b"PROXY TCP4 198.51.100.7 192.168.1.1 54321 2222\r\n");

        let v2 = encode_proxy_protocol_v2(c, l);
        assert_eq!(v2.len(), 28);
        assert_eq!(&v2[12..16], &[0x21, 0x11, 0x00, 0x0C]);
    }
}
