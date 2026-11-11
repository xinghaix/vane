//! 4x4 全矩阵双引擎端口转发：支持 TCP (Linux 受限管道 splice 零拷贝 / TimedIo 回退)、
//! 64 KiB UDP 会话代理（Linux IP_PKTINFO/IPV6_PKTINFO 源地址一致回包）、Proxy Protocol v1/v2、
//! 网卡与源 IP 绑定、多目标健康检查与主备/轮询、每日时间窗与临时开门租约实时启停回收。
use crate::config::{cidr_contains, parse_cidr, parse_time_window, time_window_contains, PortForwardConfig};
use crate::firewall::{FirewallManager, FirewallRule};
use crate::logger::{self, Level};
use crate::net::dual_stack::{
    bind_dual_stack_tcp_on, bind_dual_stack_udp_on, connect_tcp_with_options, connect_udp_with_options, StackMode,
};
use crate::net::listener::ConnectionQuota;
use tokio::sync::OwnedSemaphorePermit;

struct DualPermit {
    _global: OwnedSemaphorePermit,
    _local: OwnedSemaphorePermit,
}
use crate::net::proxy_io::TimedIo;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{watch, Mutex};
use tokio_util::sync::CancellationToken;

const MAX_UDP_PACKET: usize = 65_535;
const RELAY_BUF_SIZE: usize = 16_384;

struct CancelOnDrop(CancellationToken);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

pub fn encode_proxy_protocol_v1(client: SocketAddr, local: SocketAddr) -> Vec<u8> {
    match (client.ip(), local.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            format!("PROXY TCP4 {} {} {} {}
", src, dst, client.port(), local.port()).into_bytes()
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
            format!("PROXY TCP6 {} {} {} {}
", src6, dst6, client.port(), local.port()).into_bytes()
        }
    }
}

pub fn encode_proxy_protocol_v2(client: SocketAddr, local: SocketAddr) -> Vec<u8> {
    const SIG: [u8; 12] = [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A];
    let mut out = Vec::with_capacity(52);
    out.extend_from_slice(&SIG);
    out.push(0x21); // version 2 + PROXY command
    match (client.ip(), local.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            out.push(0x11); // AF_INET + STREAM
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
            out.push(0x21); // AF_INET6 + STREAM
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

/// 计算距离下一次租约到期或时间窗边界切换的精确等待时长（上限 30s 以容忍系统时钟跳变）
pub fn next_transition_delay(cfg: &PortForwardConfig, unix_now: u64, tz_offset_secs: i64) -> Option<Duration> {
    let mut best_secs: Option<u64> = None;
    if cfg.expire_at_unix > 0 {
        if unix_now >= cfg.expire_at_unix {
            return None;
        }
        best_secs = Some(cfg.expire_at_unix - unix_now);
    }
    if !cfg.allowed_time_window.is_empty() {
        if let Ok((start_m, end_m)) = parse_time_window(&cfg.allowed_time_window) {
            if start_m != end_m {
                let parts = crate::logger::breakdown(unix_now as i64, tz_offset_secs);
                let cur_sec_of_day = parts.hour as u32 * 3600 + parts.minute as u32 * 60 + parts.second as u32;
                let active = time_window_contains((start_m, end_m), parts.hour as u32 * 60 + parts.minute as u32);
                let target_m = if active { end_m } else { start_m };
                let target_sec = target_m * 60;
                let delta = if target_sec > cur_sec_of_day {
                    (target_sec - cur_sec_of_day) as u64
                } else {
                    (86_400 + target_sec - cur_sec_of_day) as u64
                };
                best_secs = Some(best_secs.map_or(delta, |b| b.min(delta)));
            }
        }
    }
    best_secs.map(|s| Duration::from_secs(s.clamp(1, 30)))
}

pub fn check_forward_cidr(cfg: &PortForwardConfig, peer_ip: IpAddr) -> bool {
    let clean_ip = match peer_ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        other => other,
    };
    if cfg.allowed_cidrs.is_empty() {
        return true;
    }
    for c in &cfg.allowed_cidrs {
        if let Ok(parsed) = parse_cidr(c) {
            if cidr_contains(&parsed, clean_ip) {
                return true;
            }
        }
    }
    false
}

struct TargetPool {
    targets: Vec<SocketAddr>,
    load_balance: String,
    source_ip: Option<IpAddr>,
    bind_interface: String,
    cooldown: Duration,
    rr_counter: AtomicUsize,
    unhealthy_until: StdMutex<Vec<Option<Instant>>>,
}

impl TargetPool {
    fn new(cfg: &PortForwardConfig, targets: Vec<SocketAddr>) -> Result<Arc<Self>, String> {
        let source_ip = if cfg.source_ip.is_empty() {
            None
        } else {
            Some(
                cfg.source_ip
                    .parse::<IpAddr>()
                    .map_err(|_| format!("端口转发 {} source_ip 非法: {}", cfg.name, cfg.source_ip))?,
            )
        };
        let cooldown = if cfg.health_check_interval_secs == 0 {
            Duration::from_secs(10)
        } else {
            Duration::from_secs(cfg.health_check_interval_secs.clamp(3, 300))
        };
        let n = targets.len();
        Ok(Arc::new(Self {
            targets,
            load_balance: cfg.load_balance.clone(),
            source_ip,
            bind_interface: cfg.bind_interface.clone(),
            cooldown,
            rr_counter: AtomicUsize::new(0),
            unhealthy_until: StdMutex::new(vec![None; n]),
        }))
    }

    fn ordered_indices(&self) -> Vec<usize> {
        let n = self.targets.len();
        let start = if self.load_balance == "round_robin" {
            self.rr_counter.fetch_add(1, Ordering::Relaxed) % n
        } else {
            0
        };
        let now = Instant::now();
        let mut healthy = Vec::with_capacity(n);
        let mut fallback = Vec::with_capacity(n);
        let guard = self.unhealthy_until.lock().ok();
        for offset in 0..n {
            let idx = (start + offset) % n;
            let is_down = guard
                .as_ref()
                .and_then(|g| g.get(idx).copied().flatten())
                .is_some_and(|until| now < until);
            if is_down {
                fallback.push(idx);
            } else {
                healthy.push(idx);
            }
        }
        healthy.extend(fallback);
        healthy
    }

    fn mark_healthy(&self, idx: usize) {
        if let Ok(mut g) = self.unhealthy_until.lock() {
            if let Some(slot) = g.get_mut(idx) {
                *slot = None;
            }
        }
    }

    fn mark_unhealthy(&self, idx: usize) {
        if self.targets.len() <= 1 {
            return;
        }
        if let Ok(mut g) = self.unhealthy_until.lock() {
            if let Some(slot) = g.get_mut(idx) {
                *slot = Some(Instant::now() + self.cooldown);
            }
        }
    }

    async fn connect_tcp(&self) -> Option<TcpStream> {
        for idx in self.ordered_indices() {
            let target = self.targets[idx];
            match tokio::time::timeout(
                Duration::from_secs(3),
                connect_tcp_with_options(target, self.source_ip, 0, &self.bind_interface, false),
            )
            .await
            {
                Ok(Ok(s)) => {
                    self.mark_healthy(idx);
                    return Some(s);
                }
                _ => self.mark_unhealthy(idx),
            }
        }
        None
    }

    async fn connect_udp(&self) -> Option<UdpSocket> {
        for idx in self.ordered_indices() {
            let target = self.targets[idx];
            if let Ok(s) = connect_udp_with_options(target, self.source_ip, &self.bind_interface).await {
                return Some(s);
            }
        }
        None
    }
}

async fn cleanup_rule_firewall(firewall: &FirewallManager, name: &str) -> Result<(), String> {
    let r1 = firewall.remove_rule("port_forward", &format!("{}_tcp", name)).await;
    let r2 = firewall.remove_rule("port_forward", &format!("{}_udp", name)).await;
    r1.and(r2)
}

/// 运行单条端口转发规则的完整生命周期（含时间窗/租约实时切换、子任务收敛与防火墙幂等撤销）
pub async fn run_port_forward_rule(
    cfg: PortForwardConfig,
    tz_offset_secs: i64,
    global_quota: ConnectionQuota,
    firewall: Arc<FirewallManager>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), String> {
    if !cfg.enabled {
        return cleanup_rule_firewall(&firewall, &cfg.name).await;
    }

    let targets: Vec<SocketAddr> = cfg
        .effective_targets()
        .iter()
        .filter_map(|t| t.parse().ok())
        .collect();
    if targets.is_empty() {
        return Err(format!("端口转发 {} 无有效目标地址", cfg.name));
    }

    loop {
        if *shutdown_rx.borrow() {
            break;
        }
        let now = logger::unix_now();
        if !is_rule_active_now(&cfg, now, tz_offset_secs) {
            let _ = cleanup_rule_firewall(&firewall, &cfg.name).await;
            if cfg.expire_at_unix > 0 && now >= cfg.expire_at_unix {
                // 一次性临时租约已到期，保持关闭直到配置重载或网关退出
                let _ = shutdown_rx.changed().await;
                break;
            }
            let wait = next_transition_delay(&cfg, now, tz_offset_secs).unwrap_or(Duration::from_secs(15));
            tokio::select! {
                _ = tokio::time::sleep(wait) => continue,
                _ = shutdown_rx.changed() => break,
            }
        }

        let res = run_active_window(
            &cfg,
            &targets,
            tz_offset_secs,
            global_quota.clone(),
            firewall.clone(),
            &mut shutdown_rx,
        )
        .await;
        let cleanup = cleanup_rule_firewall(&firewall, &cfg.name).await;
        res?;
        cleanup?;
    }

    cleanup_rule_firewall(&firewall, &cfg.name).await
}

async fn run_active_window(
    cfg: &PortForwardConfig,
    targets: &[SocketAddr],
    tz_offset_secs: i64,
    global_quota: ConnectionQuota,
    firewall: Arc<FirewallManager>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Result<(), String> {
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
        return wait_until_inactive_or_shutdown(cfg, tz_offset_secs, shutdown_rx).await;
    }

    let mode = StackMode::parse(&cfg.stack);
    let rule_quota = ConnectionQuota::new(cfg.max_concurrent_conns);
    let pool = TargetPool::new(cfg, targets.to_vec())?;
    let cancel = CancellationToken::new();
    let _cancel_guard = CancelOnDrop(cancel.clone());
    let mut workers = tokio::task::JoinSet::new();

    if targets.len() > 1 && cfg.health_check_interval_secs > 0 && (cfg.proto == "tcp" || cfg.proto == "tcp_udp") {
        let pool_hc = pool.clone();
        let interval = Duration::from_secs(cfg.health_check_interval_secs.clamp(5, 3600));
        let hc_cancel = cancel.child_token();
        workers.spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = hc_cancel.cancelled() => break,
                    _ = ticker.tick() => {
                        for (idx, target) in pool_hc.targets.iter().copied().enumerate() {
                            let ok = tokio::time::timeout(
                                Duration::from_secs(2),
                                connect_tcp_with_options(target, pool_hc.source_ip, 0, &pool_hc.bind_interface, false),
                            )
                            .await
                            .is_ok_and(|r| r.is_ok());
                            if ok {
                                pool_hc.mark_healthy(idx);
                            } else {
                                pool_hc.mark_unhealthy(idx);
                            }
                        }
                    }
                }
            }
            Ok::<(), String>(())
        });
    }

    if cfg.proto == "tcp" || cfg.proto == "tcp_udp" {
        let bound = bind_dual_stack_tcp_on(cfg.listen_port, mode, &cfg.bind_interface)
            .map_err(|e| format!("转发规则 {} 绑定 TCP {} 失败: {}", cfg.name, cfg.listen_port, e))?;
        if cfg.open_wan_firewall {
            firewall
                .upsert_rule(FirewallRule::WanInput {
                    owner_module: "port_forward".into(),
                    rule_name: format!("{}_tcp", cfg.name),
                    proto: "tcp".into(),
                    port: cfg.listen_port,
                    ipv4: bound.has_v4(),
                    ipv6: bound.has_v6(),
                })
                .await?;
        }
        for listener in [bound.v4, bound.v6].into_iter().flatten() {
            workers.spawn(run_tcp_listener(
                listener,
                Arc::new(cfg.clone()),
                pool.clone(),
                tz_offset_secs,
                global_quota.clone(),
                rule_quota.clone(),
                cancel.child_token(),
            ));
        }
    }

    if cfg.proto == "udp" || cfg.proto == "tcp_udp" {
        let bound = bind_dual_stack_udp_on(cfg.listen_port, mode, &cfg.bind_interface, true)
            .map_err(|e| format!("转发规则 {} 绑定 UDP {} 失败: {}", cfg.name, cfg.listen_port, e))?;
        if cfg.open_wan_firewall {
            firewall
                .upsert_rule(FirewallRule::WanInput {
                    owner_module: "port_forward".into(),
                    rule_name: format!("{}_udp", cfg.name),
                    proto: "udp".into(),
                    port: cfg.listen_port,
                    ipv4: bound.v4.is_some(),
                    ipv6: bound.v6.is_some(),
                })
                .await?;
        }
        for sock in [bound.v4, bound.v6].into_iter().flatten() {
            workers.spawn(run_udp_proxy(
                Arc::new(sock),
                Arc::new(cfg.clone()),
                pool.clone(),
                tz_offset_secs,
                global_quota.clone(),
                rule_quota.clone(),
                cancel.child_token(),
            ));
        }
    }

    logger::log(
        Level::Info,
        "port_forward",
        &format!("端口转发规则 {} 已启动 (port={}, proto={})", cfg.name, cfg.listen_port, cfg.proto),
    );

    let wait_res = tokio::select! {
        r = wait_until_inactive_or_shutdown(cfg, tz_offset_secs, shutdown_rx) => r,
        joined = workers.join_next() => match joined {
            Some(Ok(Err(e))) => Err(e),
            _ => Ok(()),
        }
    };

    cancel.cancel();
    while workers.join_next().await.is_some() {}
    wait_res
}

async fn wait_until_inactive_or_shutdown(
    cfg: &PortForwardConfig,
    tz_offset_secs: i64,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Result<(), String> {
    loop {
        if *shutdown_rx.borrow() {
            return Ok(());
        }
        let now = logger::unix_now();
        if !is_rule_active_now(cfg, now, tz_offset_secs) {
            logger::log(
                Level::Info,
                "port_forward",
                &format!("端口转发规则 {} 租约或时间窗已结束，正在关闭监听并回收连接", cfg.name),
            );
            return Ok(());
        }
        match next_transition_delay(cfg, now, tz_offset_secs) {
            Some(delay) => {
                tokio::select! {
                    _ = tokio::time::sleep(delay) => continue,
                    _ = shutdown_rx.changed() => return Ok(()),
                }
            }
            None => {
                let _ = shutdown_rx.changed().await;
                return Ok(());
            }
        }
    }
}

async fn run_tcp_listener(
    listener: TcpListener,
    cfg: Arc<PortForwardConfig>,
    pool: Arc<TargetPool>,
    tz_offset_secs: i64,
    global_quota: ConnectionQuota,
    rule_quota: ConnectionQuota,
    cancel: CancellationToken,
) -> Result<(), String> {
    let mut conns = tokio::task::JoinSet::new();
    let idle_timeout = Duration::from_secs(cfg.tcp_idle_timeout_secs.clamp(5, 86_400));

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = conns.join_next(), if !conns.is_empty() => {},
            res = listener.accept() => {
                let Ok((inbound, peer)) = res else { continue };
                if !is_rule_active_now(&cfg, logger::unix_now(), tz_offset_secs)
                    || !check_forward_cidr(&cfg, peer.ip())
                {
                    continue;
                }
                let Some(gp) = global_quota.try_acquire() else { continue };
                let Some(rp) = rule_quota.try_acquire() else { continue };
                let permit = DualPermit { _global: gp, _local: rp };
                let pool_c = pool.clone();
                let pp = cfg.send_proxy_protocol.clone();
                let conn_cancel = cancel.child_token();
                conns.spawn(async move {
                    let _permit = permit;
                    let _ = inbound.set_nodelay(true);
                    let local_addr = inbound.local_addr().unwrap_or(peer);
                    let connect_fut = pool_c.connect_tcp();
                    let Some(mut outbound) = (tokio::select! {
                        _ = conn_cancel.cancelled() => None,
                        s = connect_fut => s,
                    }) else { return };

                    let hdr = match pp.as_str() {
                        "v1" => Some(encode_proxy_protocol_v1(peer, local_addr)),
                        "v2" => Some(encode_proxy_protocol_v2(peer, local_addr)),
                        _ => None,
                    };
                    if let Some(bytes) = hdr {
                        if tokio::time::timeout(Duration::from_secs(5), outbound.write_all(&bytes)).await.is_err() {
                            return;
                        }
                    }

                    tokio::select! {
                        _ = conn_cancel.cancelled() => {}
                        _ = relay_tcp_streams(inbound, outbound, idle_timeout) => {}
                    }
                });
            }
        }
    }

    while conns.join_next().await.is_some() {}
    Ok(())
}

async fn relay_tcp_streams(inbound: TcpStream, outbound: TcpStream, idle_timeout: Duration) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        match splice_bidirectional(&inbound, &outbound, idle_timeout).await {
            Ok(()) => return Ok(()),
            Err(e) if matches!(e.raw_os_error(), Some(libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP)) => {}
            Err(e) => return Err(e),
        }
    }
    let mut a = TimedIo::new(inbound, idle_timeout);
    let mut b = TimedIo::new(outbound, idle_timeout);
    tokio::io::copy_bidirectional_with_sizes(&mut a, &mut b, RELAY_BUF_SIZE, RELAY_BUF_SIZE)
        .await
        .map(|_| ())
}

#[cfg(target_os = "linux")]
struct OwnedPipe {
    r: libc::c_int,
    w: libc::c_int,
}

#[cfg(target_os = "linux")]
impl OwnedPipe {
    fn create_bounded() -> io::Result<Self> {
        let mut fds = [0 as libc::c_int; 2];
        let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        let pipe = Self { r: fds[0], w: fds[1] };
        let _ = unsafe { libc::fcntl(pipe.w, libc::F_SETPIPE_SZ, RELAY_BUF_SIZE as libc::c_int) };
        Ok(pipe)
    }
}

#[cfg(target_os = "linux")]
impl Drop for OwnedPipe {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.r);
            libc::close(self.w);
        }
    }
}

#[cfg(target_os = "linux")]
async fn splice_one_way(src: &TcpStream, dst: &TcpStream, idle: Duration) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    use tokio::io::Interest;

    let pipe = OwnedPipe::create_bounded()?;
    let mut in_pipe = 0usize;
    let mut eof = false;

    while !eof || in_pipe > 0 {
        if !eof && in_pipe < RELAY_BUF_SIZE {
            let read_step = src.async_io(Interest::READABLE, || {
                let n = unsafe {
                    libc::splice(
                        src.as_raw_fd(),
                        std::ptr::null_mut(),
                        pipe.w,
                        std::ptr::null_mut(),
                        RELAY_BUF_SIZE - in_pipe,
                        libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            let n = tokio::time::timeout(idle, read_step)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP splice 读取空闲超时"))??;
            if n == 0 {
                eof = true;
            } else {
                in_pipe += n;
            }
        }

        while in_pipe > 0 {
            let write_step = dst.async_io(Interest::WRITABLE, || {
                let n = unsafe {
                    libc::splice(
                        pipe.r,
                        std::ptr::null_mut(),
                        dst.as_raw_fd(),
                        std::ptr::null_mut(),
                        in_pipe,
                        libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            let n = tokio::time::timeout(idle, write_step)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP splice 写入空闲超时"))??;
            in_pipe -= n;
        }
    }

    let _ = unsafe { libc::shutdown(dst.as_raw_fd(), libc::SHUT_WR) };
    Ok(())
}

#[cfg(target_os = "linux")]
async fn splice_bidirectional(a: &TcpStream, b: &TcpStream, idle: Duration) -> io::Result<()> {
    tokio::try_join!(splice_one_way(a, b, idle), splice_one_way(b, a, idle)).map(|_| ())
}

struct UdpSessionEntry {
    sock: Arc<UdpSocket>,
    last_active: Instant,
}

async fn run_udp_proxy(
    inbound: Arc<UdpSocket>,
    cfg: Arc<PortForwardConfig>,
    pool: Arc<TargetPool>,
    tz_offset_secs: i64,
    global_quota: ConnectionQuota,
    rule_quota: ConnectionQuota,
    cancel: CancellationToken,
) -> Result<(), String> {
    let sessions: Arc<Mutex<HashMap<(SocketAddr, Option<IpAddr>), UdpSessionEntry>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let mut session_tasks = tokio::task::JoinSet::new();
    let mut buf = vec![0u8; MAX_UDP_PACKET];
    let idle = Duration::from_secs(cfg.udp_session_timeout_secs.clamp(10, 600));

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = session_tasks.join_next(), if !session_tasks.is_empty() => {},
            recv_res = recv_udp_pkt(&inbound, &mut buf) => {
                let Ok((n, peer, local_dst_ip)) = recv_res else { continue };
                if !is_rule_active_now(&cfg, logger::unix_now(), tz_offset_secs)
                    || !check_forward_cidr(&cfg, peer.ip())
                {
                    continue;
                }

                let key = (peer, local_dst_ip);
                let existing = {
                    let mut map = sessions.lock().await;
                    map.retain(|_, entry| entry.last_active.elapsed() < idle);
                    if let Some(entry) = map.get_mut(&key) {
                        entry.last_active = Instant::now();
                        Some(entry.sock.clone())
                    } else {
                        None
                    }
                };

                let upstream_sock = if let Some(s) = existing {
                    s
                } else {
                    let Some(gp) = global_quota.try_acquire() else { continue };
                    let Some(rp) = rule_quota.try_acquire() else { continue };
                    let permit = DualPermit { _global: gp, _local: rp };
                    let Some(s) = pool.connect_udp().await else { continue };
                    let s = Arc::new(s);
                    {
                        let mut map = sessions.lock().await;
                        if map.len() >= cfg.max_concurrent_conns {
                            continue;
                        }
                        map.insert(key, UdpSessionEntry { sock: s.clone(), last_active: Instant::now() });
                    }

                    let s_clone = s.clone();
                    let in_clone = inbound.clone();
                    let sessions_clone = sessions.clone();
                    let sess_cancel = cancel.child_token();
                    session_tasks.spawn(async move {
                        let _permit = permit;
                        let mut rbuf = vec![0u8; MAX_UDP_PACKET];
                        loop {
                            let recv_fut = tokio::time::timeout(idle, s_clone.recv(&mut rbuf));
                            let res = tokio::select! {
                                _ = sess_cancel.cancelled() => break,
                                r = recv_fut => r,
                            };
                            let Ok(Ok(rn)) = res else { break };
                            let _ = send_udp_pkt(&in_clone, &rbuf[..rn], peer, local_dst_ip).await;
                            if let Some(entry) = sessions_clone.lock().await.get_mut(&key) {
                                entry.last_active = Instant::now();
                            }
                        }
                        sessions_clone.lock().await.remove(&key);
                    });
                    s
                };

                let _ = upstream_sock.send(&buf[..n]).await;
            }
        }
    }

    while session_tasks.join_next().await.is_some() {}
    Ok(())
}

#[cfg(target_os = "linux")]
async fn recv_udp_pkt(sock: &UdpSocket, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, Option<IpAddr>)> {
    use std::os::fd::AsRawFd;
    use tokio::io::Interest;

    sock.async_io(Interest::READABLE, || {
        let mut peer_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut cmsg_buf = [0u8; 128];
        let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
        hdr.msg_name = (&mut peer_storage as *mut libc::sockaddr_storage).cast();
        hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        hdr.msg_iov = &mut iov;
        hdr.msg_iovlen = 1;
        hdr.msg_control = cmsg_buf.as_mut_ptr().cast();
        hdr.msg_controllen = cmsg_buf.len() as _;

        let n = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut hdr, 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let (_, peer_sock) = unsafe { socket2::SockAddr::try_init(|st, len| {
            *st = peer_storage;
            *len = hdr.msg_namelen;
            Ok(())
        }) }?;
        let peer = peer_sock
            .as_socket()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "UDP 对端地址无效"))?;

        let mut local_ip = None;
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&hdr);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == libc::IPPROTO_IP && (*cmsg).cmsg_type == libc::IP_PKTINFO {
                    let info: libc::in_pktinfo = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast());
                    local_ip = Some(IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(info.ipi_addr.s_addr))));
                    break;
                } else if (*cmsg).cmsg_level == libc::IPPROTO_IPV6 && (*cmsg).cmsg_type == libc::IPV6_PKTINFO {
                    let info: libc::in6_pktinfo = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast());
                    local_ip = Some(IpAddr::V6(std::net::Ipv6Addr::from(info.ipi6_addr.s6_addr)));
                    break;
                }
                cmsg = libc::CMSG_NXTHDR(&hdr, cmsg);
            }
        }
        Ok((n as usize, peer, local_ip))
    })
    .await
}

#[cfg(not(target_os = "linux"))]
async fn recv_udp_pkt(sock: &UdpSocket, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, Option<IpAddr>)> {
    let (n, peer) = sock.recv_from(buf).await?;
    Ok((n, peer, None))
}

#[cfg(target_os = "linux")]
async fn send_udp_pkt(
    sock: &UdpSocket,
    buf: &[u8],
    peer: SocketAddr,
    local_src: Option<IpAddr>,
) -> io::Result<usize> {
    use std::os::fd::AsRawFd;
    use tokio::io::Interest;

    let Some(src_ip) = local_src else {
        return sock.send_to(buf, peer).await;
    };
    let dst_sa = socket2::SockAddr::from(peer);
    sock.async_io(Interest::WRITABLE, || {
        let mut iov = libc::iovec {
            iov_base: buf.as_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut cmsg_space = [0u8; 128];
        let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
        hdr.msg_name = dst_sa.as_ptr() as *mut libc::c_void;
        hdr.msg_namelen = dst_sa.len();
        hdr.msg_iov = &mut iov;
        hdr.msg_iovlen = 1;

        unsafe {
            match src_ip {
                IpAddr::V4(v4) => {
                    let space = libc::CMSG_SPACE(std::mem::size_of::<libc::in_pktinfo>() as u32) as usize;
                    hdr.msg_control = cmsg_space.as_mut_ptr().cast();
                    hdr.msg_controllen = space as _;
                    let cmsg = libc::CMSG_FIRSTHDR(&hdr);
                    (*cmsg).cmsg_level = libc::IPPROTO_IP;
                    (*cmsg).cmsg_type = libc::IP_PKTINFO;
                    (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::in_pktinfo>() as u32) as _;
                    let info = libc::in_pktinfo {
                        ipi_ifindex: 0,
                        ipi_spec_dst: libc::in_addr { s_addr: u32::from(v4).to_be() },
                        ipi_addr: libc::in_addr { s_addr: 0 },
                    };
                    std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast(), info);
                }
                IpAddr::V6(v6) => {
                    let space = libc::CMSG_SPACE(std::mem::size_of::<libc::in6_pktinfo>() as u32) as usize;
                    hdr.msg_control = cmsg_space.as_mut_ptr().cast();
                    hdr.msg_controllen = space as _;
                    let cmsg = libc::CMSG_FIRSTHDR(&hdr);
                    (*cmsg).cmsg_level = libc::IPPROTO_IPV6;
                    (*cmsg).cmsg_type = libc::IPV6_PKTINFO;
                    (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::in6_pktinfo>() as u32) as _;
                    let info = libc::in6_pktinfo {
                        ipi6_addr: libc::in6_addr { s6_addr: v6.octets() },
                        ipi6_ifindex: 0,
                    };
                    std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast(), info);
                }
            }
            let n = libc::sendmsg(sock.as_raw_fd(), &hdr, 0);
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }
    })
    .await
}

#[cfg(not(target_os = "linux"))]
async fn send_udp_pkt(
    sock: &UdpSocket,
    buf: &[u8],
    peer: SocketAddr,
    _local_src: Option<IpAddr>,
) -> io::Result<usize> {
    sock.send_to(buf, peer).await
}

#[cfg(test)]
#[path = "port_forward_tests.rs"]
mod protocol_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_protocol_headers_are_valid() {
        let c: SocketAddr = "198.51.100.7:54321".parse().unwrap();
        let l: SocketAddr = "192.168.1.1:2222".parse().unwrap();
        let v1 = encode_proxy_protocol_v1(c, l);
        assert_eq!(v1, b"PROXY TCP4 198.51.100.7 192.168.1.1 54321 2222
");

        let v2 = encode_proxy_protocol_v2(c, l);
        assert_eq!(v2.len(), 28);
        assert_eq!(&v2[12..16], &[0x21, 0x11, 0x00, 0x0C]);
    }
}
