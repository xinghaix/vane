//! 双向容错双栈绑定器（0.0.0.0 + IPV6_V6ONLY=1 [::]）、BanKey 归一化与 RFC 8305 Happy Eyeballs 连接器。
use serde::Serialize;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

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

/// 绑定双栈 TCP 监听器：IPv4 与 IPV6_V6ONLY=1 的 IPv6 彼此独立，单一协议栈失败不短路另一协议栈
pub fn bind_dual_stack_tcp(port: u16, mode: StackMode) -> io::Result<BoundTcpListeners> {
    let mut v4_listener = None;
    let mut v6_listener = None;
    let mut last_err = None;

    if matches!(mode, StackMode::Dual | StackMode::Ipv4Only) {
        match bind_single_tcp(Domain::IPV4, SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port), false) {
            Ok(l) => v4_listener = Some(l),
            Err(e) => last_err = Some(e),
        }
    }

    if matches!(mode, StackMode::Dual | StackMode::Ipv6Only) {
        match bind_single_tcp(Domain::IPV6, SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port), true) {
            Ok(l) => v6_listener = Some(l),
            Err(e) => last_err = Some(e),
        }
    }

    if v4_listener.is_none() && v6_listener.is_none() {
        return Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "未绑定任何协议栈")));
    }

    Ok(BoundTcpListeners { v4: v4_listener, v6: v6_listener })
}

fn bind_single_tcp(domain: Domain, addr: SocketAddr, v6_only: bool) -> io::Result<TcpListener> {
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    if v6_only {
        socket.set_only_v6(true)?;
    }
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
    let mut v4_sock = None;
    let mut v6_sock = None;
    let mut last_err = None;

    if matches!(mode, StackMode::Dual | StackMode::Ipv4Only) {
        match bind_single_udp(Domain::IPV4, SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port), false) {
            Ok(s) => v4_sock = Some(s),
            Err(e) => last_err = Some(e),
        }
    }

    if matches!(mode, StackMode::Dual | StackMode::Ipv6Only) {
        match bind_single_udp(Domain::IPV6, SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port), true) {
            Ok(s) => v6_sock = Some(s),
            Err(e) => last_err = Some(e),
        }
    }

    if v4_sock.is_none() && v6_sock.is_none() {
        return Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "未绑定任何 UDP 协议栈")));
    }

    Ok(BoundUdpSockets { v4: v4_sock, v6: v6_sock })
}

fn bind_single_udp(domain: Domain, addr: SocketAddr, v6_only: bool) -> io::Result<UdpSocket> {
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    if v6_only {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    UdpSocket::from_std(socket.into())
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
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(host_port).await?.collect();
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

    // 交错排列 IPv6 与 IPv4 地址
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

    let first = ordered[0];
    let second = ordered[1];
    let delay = Duration::from_millis(delay_ms.clamp(50, 2000));

    tokio::select! {
        res1 = TcpStream::connect(first) => {
            if let Ok(s) = res1 {
                return Ok(s);
            }
            TcpStream::connect(second).await
        }
        _ = tokio::time::sleep(delay) => {
            tokio::select! {
                res1 = TcpStream::connect(first) => res1,
                res2 = TcpStream::connect(second) => res2,
            }
        }
    }
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
}
