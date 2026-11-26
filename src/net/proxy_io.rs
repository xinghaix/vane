//! 流式传输空闲超时、HTTP 请求活跃度跟踪与上游安全解析/TLS 策略，跳过 PKI 时仍验证 TLS 握手签名。
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};
use std::{
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
pub type BoxStream = Box<dyn Stream>;

/// 跟踪单条 HTTP/1.1 或 HTTP/2 连接的请求/流进展活跃度（不被 H2 PING 帧重置）
pub(crate) struct HttpActivity {
    start: Instant,
    last_activity_ms: AtomicU64,
    active_requests: AtomicUsize,
    total_requests: AtomicU64,
    notify: tokio::sync::Notify,
}

impl HttpActivity {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            start: Instant::now(),
            last_activity_ms: AtomicU64::new(0),
            active_requests: AtomicUsize::new(0),
            total_requests: AtomicU64::new(0),
            notify: tokio::sync::Notify::new(),
        })
    }

    pub(crate) fn touch(&self) {
        let ms = self.start.elapsed().as_millis().min(u64::MAX as u128) as u64;
        self.last_activity_ms.store(ms, Ordering::Release);
    }

    pub(crate) fn begin_request(self: &Arc<Self>) -> ActiveRequestGuard {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.active_requests.fetch_add(1, Ordering::AcqRel);
        self.touch();
        self.notify.notify_waiters();
        ActiveRequestGuard {
            activity: self.clone(),
        }
    }

    pub(crate) fn active_requests(&self) -> usize {
        self.active_requests.load(Ordering::Acquire)
    }

    pub(crate) fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    pub(crate) fn idle_elapsed(&self) -> Duration {
        let now_ms = self.start.elapsed().as_millis().min(u64::MAX as u128) as u64;
        let last_ms = self.last_activity_ms.load(Ordering::Acquire);
        Duration::from_millis(now_ms.saturating_sub(last_ms))
    }

    pub(crate) async fn wait_idle_timeout(&self, first_request_timeout: Duration, keep_alive_timeout: Duration) {
        loop {
            if self.active_requests() > 0 {
                self.notify.notified().await;
                continue;
            }
            let limit = if self.total_requests() == 0 {
                first_request_timeout
            } else {
                keep_alive_timeout
            };
            let elapsed = self.idle_elapsed();
            if elapsed >= limit {
                return;
            }
            let remaining = limit.saturating_sub(elapsed);
            tokio::select! {
                _ = tokio::time::sleep(remaining) => {},
                _ = self.notify.notified() => {},
            }
        }
    }
}

pub(crate) struct ActiveRequestGuard {
    activity: Arc<HttpActivity>,
}

impl ActiveRequestGuard {
    pub(crate) fn touch(&self) {
        self.activity.touch();
    }
}

impl Drop for ActiveRequestGuard {
    fn drop(&mut self) {
        self.activity.touch();
        self.activity.active_requests.fetch_sub(1, Ordering::AcqRel);
        self.activity.notify.notify_waiters();
    }
}

pub struct TimedIo<T> {
    inner: T,
    read: Pin<Box<tokio::time::Sleep>>,
    write: Pin<Box<tokio::time::Sleep>>,
    timeout: Duration,
    read_deadline: bool,
}

impl<T> TimedIo<T> {
    pub fn new(inner: T, timeout: Duration) -> Self {
        Self {
            inner,
            read: Box::pin(tokio::time::sleep(timeout)),
            write: Box::pin(tokio::time::sleep(timeout)),
            timeout,
            read_deadline: true,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for TimedIo<T> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let timeout = self.timeout;
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(result) => {
                if result.is_ok() && buf.filled().len() > before {
                    let next = tokio::time::Instant::now() + timeout;
                    self.read.as_mut().reset(next);
                }
                Poll::Ready(result)
            }
            Poll::Pending => {
                if self.read_deadline && self.read.as_mut().poll(cx).is_ready() {
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, "读取空闲超时")))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for TimedIo<T> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let timeout = self.timeout;
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(result) => {
                if result.as_ref().is_ok_and(|n| *n > 0) {
                    let next = tokio::time::Instant::now() + timeout;
                    self.write.as_mut().reset(next);
                }
                Poll::Ready(result)
            }
            Poll::Pending => {
                if self.write.as_mut().poll(cx).is_ready() {
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, "写入空闲超时")))
                } else {
                    Poll::Pending
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let timeout = self.timeout;
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(result) => {
                if result.is_ok() {
                    let next = tokio::time::Instant::now() + timeout;
                    self.write.as_mut().reset(next);
                }
                Poll::Ready(result)
            }
            Poll::Pending => {
                if self.write.as_mut().poll(cx).is_ready() {
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, "刷新写入超时")))
                } else {
                    Poll::Pending
                }
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_shutdown(cx) {
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => {
                if self.write.as_mut().poll(cx).is_ready() {
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, "关闭写入超时")))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

#[derive(Debug)]
struct CertificatePolicy {
    fingerprint: Option<Vec<u8>>,
}

impl ServerCertVerifier for CertificatePolicy {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Some(expected) = &self.fingerprint {
            let actual = ring::digest::digest(&ring::digest::SHA256, cert.as_ref());
            if actual.as_ref() != expected {
                return Err(rustls::Error::General("上游证书指纹不匹配".into()));
            }
            let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref())
                .map_err(|_| rustls::Error::General("上游证书无效".into()))?;
            let now = now.as_secs() as i64;
            if now < parsed.validity().not_before.timestamp() || now >= parsed.validity().not_after.timestamp() {
                return Err(rustls::Error::General("上游固定证书不在有效期内".into()));
            }
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        sig: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            sig,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        sig: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            sig,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn normalize_upstream_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        other => other,
    }
}

fn is_disallowed_upstream_ip(ip: IpAddr) -> bool {
    match normalize_upstream_ip(ip) {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 0
                || v4.is_unspecified()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            let is_nat64_wk = segs[0] == 0x0064
                && segs[1] == 0xff9b
                && segs[2] == 0
                && segs[3] == 0
                && segs[4] == 0
                && segs[5] == 0;
            let is_nat64_local = segs[0] == 0x0064 && segs[1] == 0xff9b && segs[2] == 0x0001;
            v6.is_unspecified()
                || v6.is_unicast_link_local()
                || v6.is_multicast()
                || is_nat64_wk
                || is_nat64_local
        }
    }
}

/// 对解析出的上游 SocketAddr 执行 Post-DNS 安全底线校验（覆盖链路本地/元数据/NAT64/本机接口/管理面/受保护端口）
pub(crate) fn validate_upstream_addr(addr: SocketAddr, admin_listeners: &[SocketAddr]) -> Result<(), String> {
    let port = addr.port();
    if port == 0 {
        return Err("上游目标端口不能为 0".into());
    }
    let ip = normalize_upstream_ip(addr.ip());
    if is_disallowed_upstream_ip(ip) {
        return Err(format!("安全底线拦截：禁止反代连接链路本地/未指定/多播/NAT64 上游地址 ({})", addr));
    }

    let mut admin_ports: Vec<u16> = vec![23456];
    let mut admin_listener_strs: Vec<String> = Vec::with_capacity(admin_listeners.len());
    for listener in admin_listeners {
        if !admin_ports.contains(&listener.port()) {
            admin_ports.push(listener.port());
        }
        admin_listener_strs.push(listener.to_string());
    }

    let norm_addr = SocketAddr::new(ip, port);
    crate::firewall::validate_forward_target_safety_multi(
        norm_addr,
        "userspace_splice",
        true,
        &admin_ports,
        &admin_listener_strs,
    )?;

    // 纵深防线：枚举全部本机接口 IP 并比对默认管理端口 23456、实时管理监听与受保护本机高危端口
    let mut is_router_host_ip = ip.is_loopback() || ip.is_unspecified();
    if !is_router_host_ip
        && admin_listeners
            .iter()
            .any(|l| normalize_upstream_ip(l.ip()) == ip)
    {
        is_router_host_ip = true;
    }
    if !is_router_host_ip {
        let ifaces = crate::daemon::netlink_ip::list_interface_addresses();
        'iface_scan: for iface in ifaces.values() {
            match ip {
                IpAddr::V4(v4) => {
                    if iface.ipv4.contains(&v4) {
                        is_router_host_ip = true;
                        break 'iface_scan;
                    }
                }
                IpAddr::V6(v6) => {
                    if iface.ipv6.contains(&v6) {
                        is_router_host_ip = true;
                        break 'iface_scan;
                    }
                }
            }
        }
    }

    if is_router_host_ip
        && (admin_ports.contains(&port)
            || crate::firewall::PROTECTED_LOCAL_INPUT_PORTS.contains(&port))
    {
        return Err(format!(
            "安全底线拦截：禁止将反向代理上游指向本机受保护端口或管理端口 ({})",
            addr
        ));
    }
    for listener in admin_listeners {
        let admin_ip = normalize_upstream_ip(listener.ip());
        if listener.port() == port
            && (admin_ip == ip || (admin_ip.is_unspecified() && is_router_host_ip))
        {
            return Err(format!(
                "安全底线拦截：禁止将反向代理上游指向管理后台监听地址 ({})",
                addr
            ));
        }
    }

    Ok(())
}

#[allow(dead_code)]
pub async fn upstream(rule: &crate::config::ReverseProxyRule, uri: &http::Uri) -> Result<BoxStream, String> {
    upstream_with_admin_listeners(rule, uri, &[]).await
}

pub async fn upstream_with_admin_listeners(
    rule: &crate::config::ReverseProxyRule,
    uri: &http::Uri,
    admin_listeners: &[SocketAddr],
) -> Result<BoxStream, String> {
    let scheme = uri.scheme_str().ok_or("上游 URL 缺少协议")?;
    if !matches!(scheme, "http" | "https") || uri.authority().is_none_or(|a| a.as_str().contains('@')) {
        return Err("上游 URL 非法".into());
    }
    let host = uri.host().ok_or("上游主机缺失")?.trim_matches(['[', ']']);
    let port = uri.port_u16().unwrap_or(if scheme == "https" { 443 } else { 80 });
    if port == 0 {
        return Err("上游端口不能为 0".into());
    }

    // 单次 DNS 解析 -> 全量 Post-DNS 安全校验 -> 仅连接已校验候选地址（消除 DNS Rebinding TOCTOU）
    let resolved: Vec<SocketAddr> = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host((host, port)),
    )
    .await
    .map_err(|_| "上游 DNS 解析超时")?
    .map_err(|_| "上游 DNS 解析失败")?
    .take(32)
    .collect();
    if resolved.is_empty() {
        return Err("上游 DNS 解析无可用地址".into());
    }
    for addr in &resolved {
        validate_upstream_addr(*addr, admin_listeners)?;
    }

    let (v6, v4): (Vec<_>, Vec<_>) = resolved.into_iter().partition(SocketAddr::is_ipv6);
    let mut ordered = Vec::with_capacity(v6.len() + v4.len());
    for idx in 0..v6.len().max(v4.len()) {
        if let Some(a) = v6.get(idx) {
            ordered.push(*a);
        }
        if let Some(a) = v4.get(idx) {
            ordered.push(*a);
        }
    }

    let socket = super::dual_stack::connect_candidates(&ordered, 250)
        .await
        .map_err(|_| "上游连接失败")?;
    if scheme == "http" {
        return Ok(Box::new(socket));
    }
    let mut tls = (*super::http_client::shared().tls_config()).clone();
    match rule.upstream_tls_mode.as_str() {
        "strict" => {}
        "pinned_sha256" => {
            let hex = rule.upstream_cert_sha256.replace(':', "");
            if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("上游指纹格式非法".into());
            }
            let fingerprint = (0..64)
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            tls.dangerous()
                .set_certificate_verifier(Arc::new(CertificatePolicy { fingerprint: Some(fingerprint) }));
        }
        "insecure_skip_verify" => {
            tls.dangerous()
                .set_certificate_verifier(Arc::new(CertificatePolicy { fingerprint: None }));
        }
        _ => return Err("上游 TLS 策略非法".into()),
    }
    let sni = if rule.upstream_sni.is_empty() { host } else { &rule.upstream_sni };
    let name = ServerName::try_from(sni.to_string()).map_err(|_| "上游 SNI 非法")?;
    let stream = tokio_rustls::TlsConnector::from(Arc::new(tls))
        .connect(name, socket)
        .await
        .map_err(|_| "上游 TLS 验证或握手失败")?;
    Ok(Box::new(stream))
}
