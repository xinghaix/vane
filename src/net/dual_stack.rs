//! 双向容错双栈绑定器（0.0.0.0 + IPV6_V6ONLY=1 [::]）、接口/源地址绑定、BanKey 归一化与 Happy Eyeballs 连接器。
use serde::Serialize;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StackMode {
    Dual,
    Ipv4Only,
    Ipv6Only,
}

impl StackMode {
    pub fn parse(s: &str) -> Self {
        match s {
            "ipv4_only" => Self::Ipv4Only,
            "ipv6_only" => Self::Ipv6Only,
            _ => Self::Dual,
        }
    }
}

pub struct BoundTcpListeners {
    pub v4: Option<TcpListener>,
    pub v6: Option<TcpListener>,
}

impl BoundTcpListeners {
    pub fn has_v4(&self) -> bool {
        self.v4.is_some()
    }
    pub fn has_v6(&self) -> bool {
        self.v6.is_some()
    }
}

/// 将底层 Socket 绑定到指定网卡（Linux 使用 SO_BINDTODEVICE，macOS 使用 IP_BOUND_IF / IPV6_BOUND_IF）
pub fn bind_socket_to_interface(socket: &Socket, domain: Domain, iface: &str) -> io::Result<()> {
    if iface.is_empty() {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        let _ = domain;
        socket.bind_device(Some(iface.as_bytes()))
    }
    #[cfg(target_os = "macos")]
    {
        let c_name = std::ffi::CString::new(iface)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "网卡名称含空字节"))?;
        let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        let Some(nz) = std::num::NonZeroU32::new(idx) else {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("网卡接口不存在: {}", iface)));
        };
        if domain == Domain::IPV6 {
            socket.bind_device_by_index_v6(Some(nz))
        } else {
            socket.bind_device_by_index_v4(Some(nz))
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (socket, domain);
        Err(io::Error::new(io::ErrorKind::Unsupported, "当前平台不支持按网卡绑定 Socket"))
    }
}

/// 绑定双栈 TCP 监听器：IPv4 与 IPV6_V6ONLY=1 的 IPv6 彼此独立，单一协议栈失败不短路另一协议栈
pub fn bind_dual_stack_tcp(port: u16, mode: StackMode) -> io::Result<BoundTcpListeners> {
    bind_dual_stack_tcp_on(port, mode, "")
}

pub fn bind_dual_stack_tcp_on(port: u16, mode: StackMode, iface: &str) -> io::Result<BoundTcpListeners> {
    let mut v4_listener = None;
    let mut v6_listener = None;
    let mut last_err = None;

    if matches!(mode, StackMode::Dual | StackMode::Ipv4Only) {
        match bind_single_tcp(Domain::IPV4, SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port), false, iface) {
            Ok(l) => v4_listener = Some(l),
            Err(e) => last_err = Some(e),
        }
    }

    if matches!(mode, StackMode::Dual | StackMode::Ipv6Only) {
        match bind_single_tcp(Domain::IPV6, SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port), true, iface) {
            Ok(l) => v6_listener = Some(l),
            Err(e) => last_err = Some(e),
        }
    }

    if v4_listener.is_none() && v6_listener.is_none() {
        return Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "未绑定任何协议栈")));
    }

    Ok(BoundTcpListeners { v4: v4_listener, v6: v6_listener })
}

fn bind_single_tcp(domain: Domain, addr: SocketAddr, v6_only: bool, iface: &str) -> io::Result<TcpListener> {
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    if v6_only {
        socket.set_only_v6(true)?;
    }
    bind_socket_to_interface(&socket, domain, iface)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(256)?;
    TcpListener::from_std(socket.into())
}

pub struct BoundUdpSockets {
    pub v4: Option<UdpSocket>,
    pub v6: Option<UdpSocket>,
}

pub fn bind_dual_stack_udp(port: u16, mode: StackMode) -> io::Result<BoundUdpSockets> {
    bind_dual_stack_udp_on(port, mode, "", false)
}

pub fn bind_dual_stack_udp_on(
    port: u16,
    mode: StackMode,
    iface: &str,
    enable_pktinfo: bool,
) -> io::Result<BoundUdpSockets> {
    let mut v4_sock = None;
    let mut v6_sock = None;
    let mut last_err = None;

    if matches!(mode, StackMode::Dual | StackMode::Ipv4Only) {
        match bind_single_udp(
            Domain::IPV4,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
            false,
            iface,
            enable_pktinfo,
            false,
        ) {
            Ok(s) => v4_sock = Some(s),
            Err(e) => last_err = Some(e),
        }
    }

    if matches!(mode, StackMode::Dual | StackMode::Ipv6Only) {
        match bind_single_udp(
            Domain::IPV6,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
            true,
            iface,
            enable_pktinfo,
            false,
        ) {
            Ok(s) => v6_sock = Some(s),
            Err(e) => last_err = Some(e),
        }
    }

    if v4_sock.is_none() && v6_sock.is_none() {
        return Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "未绑定任何 UDP 协议栈")));
    }

    Ok(BoundUdpSockets { v4: v4_sock, v6: v6_sock })
}

pub fn bind_reusable_udp(addr: SocketAddr, iface: &str) -> io::Result<UdpSocket> {
    let domain = if addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    bind_single_udp(domain, addr, addr.is_ipv6(), iface, false, addr.port() != 0)
}

fn bind_single_udp(
    domain: Domain,
    addr: SocketAddr,
    v6_only: bool,
    iface: &str,
    enable_pktinfo: bool,
    reuse_port: bool,
) -> io::Result<UdpSocket> {
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    if reuse_port {
        socket.set_reuse_port(true)?;
    }
    #[cfg(not(unix))]
    let _ = reuse_port;
    if v6_only {
        socket.set_only_v6(true)?;
    }
    #[cfg(target_os = "linux")]
    if enable_pktinfo {
        use std::os::fd::AsRawFd;
        let one: libc::c_int = 1;
        let rc = unsafe {
            if domain == Domain::IPV6 {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::IPPROTO_IPV6,
                    libc::IPV6_RECVPKTINFO,
                    (&one as *const libc::c_int).cast(),
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            } else {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::IPPROTO_IP,
                    libc::IP_PKTINFO,
                    (&one as *const libc::c_int).cast(),
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            }
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = enable_pktinfo;
    bind_socket_to_interface(&socket, domain, iface)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    UdpSocket::from_std(socket.into())
}

/// 支持可选源 IP、网卡绑定与端口复用的异步出站 TCP 连接器
pub async fn connect_tcp_with_options(
    target: SocketAddr,
    source_ip: Option<IpAddr>,
    local_port: u16,
    iface: &str,
    reuse_port: bool,
) -> io::Result<TcpStream> {
    let domain = if target.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    if let Some(src) = source_ip {
        if src.is_ipv6() != target.is_ipv6() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("source_ip ({}) 与目标地址 ({}) 协议族不一致", src, target),
            ));
        }
    }
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    if domain == Domain::IPV6 {
        socket.set_only_v6(true)?;
    }
    if local_port != 0 || reuse_port {
        socket.set_reuse_address(true)?;
        #[cfg(unix)]
        if reuse_port {
            socket.set_reuse_port(true)?;
        }
    }
    bind_socket_to_interface(&socket, domain, iface)?;
    if source_ip.is_some() || local_port != 0 {
        let bind_ip = source_ip.unwrap_or_else(|| {
            if target.is_ipv6() {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            } else {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            }
        });
        socket.bind(&SocketAddr::new(bind_ip, local_port).into())?;
    }
    socket.set_nonblocking(true)?;
    let tcp_sock = TcpSocket::from_std_stream(socket.into());
    let stream = tcp_sock.connect(target).await?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// 支持可选源 IP 与网卡绑定的出站 UDP Socket
pub async fn connect_udp_with_options(
    target: SocketAddr,
    source_ip: Option<IpAddr>,
    iface: &str,
) -> io::Result<UdpSocket> {
    let domain = if target.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    if let Some(src) = source_ip {
        if src.is_ipv6() != target.is_ipv6() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("source_ip ({}) 与目标地址 ({}) 协议族不一致", src, target),
            ));
        }
    }
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if domain == Domain::IPV6 {
        socket.set_only_v6(true)?;
    }
    bind_socket_to_interface(&socket, domain, iface)?;
    let bind_ip = source_ip.unwrap_or_else(|| {
        if target.is_ipv6() {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        }
    });
    socket.set_nonblocking(true)?;
    socket.bind(&SocketAddr::new(bind_ip, 0).into())?;
    let udp = UdpSocket::from_std(socket.into())?;
    udp.connect(target).await?;
    Ok(udp)
}

/// 源地址封禁与限速键：IPv4 按 /32，IPv6 按 /64 前缀归一化（自动解包 ::ffff:a.b.c.d）
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub enum BanKey {
    V4(Ipv4Addr),
    V6Prefix64(u64),
}

impl BanKey {
    pub fn from_peer(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self::V4(v4),
            IpAddr::V6(v6) => {
                if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                    return Self::V4(mapped_v4);
                }
                let octets = v6.octets();
                let prefix64 = u64::from_be_bytes([
                    octets[0], octets[1], octets[2], octets[3], octets[4], octets[5], octets[6], octets[7],
                ]);
                Self::V6Prefix64(prefix64)
            }
        }
    }

    pub fn display_cidr(&self) -> String {
        match self {
            Self::V4(v4) => format!("{}/32", v4),
            Self::V6Prefix64(p) => {
                let b = p.to_be_bytes();
                let v6 = Ipv6Addr::from([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], 0, 0, 0, 0, 0, 0, 0, 0]);
                format!("{}/64", v6)
            }
        }
    }

    pub fn parse_cidr_or_ip(s: &str) -> Option<Self> {
        let base = s.split('/').next()?.trim();
        let ip: IpAddr = base.parse().ok()?;
        Some(Self::from_peer(ip))
    }
}

/// RFC 8305 Happy Eyeballs 双栈 TCP 连接竞速器
pub async fn connect_happy_eyeballs(host_port: &str, delay_ms: u64) -> io::Result<TcpStream> {
    let addrs: Vec<SocketAddr> = tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host(host_port))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS 解析超时"))??
        .take(32)
        .collect();
    if addrs.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "DNS 解析无结果"));
    }

    let mut v6_addrs = Vec::new();
    let mut v4_addrs = Vec::new();
    for a in addrs {
        if a.is_ipv6() {
            v6_addrs.push(a);
        } else {
            v4_addrs.push(a);
        }
    }

    let mut ordered = Vec::new();
    let max_len = v6_addrs.len().max(v4_addrs.len());
    for i in 0..max_len {
        if let Some(a6) = v6_addrs.get(i) {
            ordered.push(*a6);
        }
        if let Some(a4) = v4_addrs.get(i) {
            ordered.push(*a4);
        }
    }

    if ordered.len() == 1 {
        return tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(ordered[0]))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "连接超时"))?;
    }

    connect_candidates(&ordered, delay_ms).await
}

/// 首个连接失败不能取消其他地址族；成功后 JoinSet 自动回收剩余竞速任务。
pub async fn connect_candidates(addresses: &[SocketAddr], delay_ms: u64) -> io::Result<TcpStream> {
    let mut attempts = tokio::task::JoinSet::new();
    let delay = Duration::from_millis(delay_ms.clamp(10, 2000));
    for (index, address) in addresses.iter().copied().take(32).enumerate() {
        attempts.spawn(async move {
            if index > 0 {
                tokio::time::sleep(delay * index as u32).await;
            }
            TcpStream::connect(address).await
        });
    }
    tokio::time::timeout(Duration::from_secs(8), async {
        let mut last_error = io::Error::new(io::ErrorKind::NotFound, "没有可连接的地址");
        while let Some(result) = attempts.join_next().await {
            match result {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(error)) => last_error = error,
                Err(_) => {}
            }
        }
        Err(last_error)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "双栈连接超时"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ban_key_normalizes_ipv4_and_ipv6_prefix64() {
        let k1 = BanKey::from_peer("2001:db8:abcd:1234::1".parse().unwrap());
        let k2 = BanKey::from_peer("2001:db8:abcd:1234:ffff:ffff:ffff:ffff".parse().unwrap());
        assert_eq!(k1, k2);
        assert_eq!(k1.display_cidr(), "2001:db8:abcd:1234::/64");

        let mapped = BanKey::from_peer("::ffff:192.0.2.10".parse().unwrap());
        let pure_v4 = BanKey::from_peer("192.0.2.10".parse().unwrap());
        assert_eq!(mapped, pure_v4);
        assert_eq!(pure_v4.display_cidr(), "192.0.2.10/32");
    }

    #[tokio::test]
    async fn nonexistent_interface_is_rejected_honestly() {
        let err = bind_dual_stack_tcp_on(0, StackMode::Ipv4Only, "vane_nonexist9").err().unwrap();
        assert!(matches!(
            err.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied | io::ErrorKind::InvalidInput | io::ErrorKind::Other
        ));
    }
}
