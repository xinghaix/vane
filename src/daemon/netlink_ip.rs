//! 双栈公网地址感知与筛选器：剔除 RFC1918 / CGNAT (100.64.0.0/10) IPv4 与
//! Link-Local / ULA / Deprecated IPv6，支持子设备 /128 IPv6 地址精确合成。
use serde::Serialize;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug, Default, Serialize)]
pub struct InterfaceAddresses {
    pub name: String,
    pub ipv4: Vec<Ipv4Addr>,
    pub ipv6: Vec<Ipv6Addr>,
}

/// 判断 IPv4 是否为真实全球单播公网地址（剔除私网、环回、链路本地、CGNAT 100.64.0.0/10、文档与广播地址）
pub fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    if ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_broadcast() || ip.is_documentation() || ip.is_unspecified() {
        return false;
    }
    // CGNAT 100.64.0.0/10
    if o[0] == 100 && (o[1] & 0xC0) == 64 {
        return false;
    }
    // 192.0.0.0/24, 198.18.0.0/15, 224.0.0.0/3
    if (o[0] == 192 && o[1] == 0 && o[2] == 0) || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) || o[0] >= 224 {
        return false;
    }
    true
}

/// 判断 IPv6 是否为全球单播公网地址（2000::/3，剔除 fe80::/10 链路本地、fc00::/7 ULA、2001:db8::/32 文档地址）
pub fn is_public_gua_ipv6(ip: Ipv6Addr) -> bool {
    let segs = ip.segments();
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    // 2001:db8::/32 文档地址
    if segs[0] == 0x2001 && segs[1] == 0x0db8 {
        return false;
    }
    // 2000::/3 全球单播前缀 (0x2000 ..= 0x3fff)
    (segs[0] & 0xE000) == 0x2000
}

/// 结合接口当前 64 位全球单播前缀与子设备固定 64 位接口标识符 (IID) 合成精确的 /128 IPv6 地址
pub fn synthesize_subdevice_ipv6(prefix_addr: Ipv6Addr, iid_addr: Ipv6Addr) -> Ipv6Addr {
    let p = prefix_addr.segments();
    let s = iid_addr.segments();
    Ipv6Addr::new(p[0], p[1], p[2], p[3], s[4], s[5], s[6], s[7])
}

/// 根据子设备的 6 字节 MAC 地址计算标准 EUI-64 接口标识符并合成精确 /128 IPv6 地址
pub fn synthesize_eui64_ipv6(prefix_addr: Ipv6Addr, mac: [u8; 6]) -> Ipv6Addr {
    let p = prefix_addr.octets();
    Ipv6Addr::from([
        p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
        mac[0] ^ 0x02, mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5],
    ])
}

/// 枚举本机所有网络接口及其 IPv4/IPv6 地址（使用 getifaddrs 跨 Linux/macOS 零外部命令依赖）
pub fn list_interface_addresses() -> BTreeMap<String, InterfaceAddresses> {
    let mut map: BTreeMap<String, InterfaceAddresses> = BTreeMap::new();
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 || ifap.is_null() {
            return map;
        }
        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_name.is_null() && !ifa.ifa_addr.is_null() {
                let name = std::ffi::CStr::from_ptr(ifa.ifa_name).to_string_lossy().into_owned();
                let fam = (*ifa.ifa_addr).sa_family as i32;
                let entry = map.entry(name.clone()).or_insert_with(|| InterfaceAddresses {
                    name,
                    ipv4: Vec::new(),
                    ipv6: Vec::new(),
                });
                if fam == libc::AF_INET {
                    let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                    if !entry.ipv4.contains(&ip) {
                        entry.ipv4.push(ip);
                    }
                } else if fam == libc::AF_INET6 {
                    let sin6 = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                    let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                    if !entry.ipv6.contains(&ip) {
                        entry.ipv6.push(ip);
                    }
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    map
}

/// 从文本响应中提取第一个合法 IPv4 或 IPv6 地址
pub fn extract_ip_from_text(text: &str, want_v6: bool) -> Option<IpAddr> {
    for token in text.split(|c: char| !c.is_ascii_hexdigit() && c != '.' && c != ':') {
        if token.is_empty() {
            continue;
        }
        if let Ok(ip) = token.parse::<IpAddr>() {
            if want_v6 && ip.is_ipv6() {
                return Some(ip);
            } else if !want_v6 && ip.is_ipv4() {
                return Some(ip);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_cgnat_and_synthesizes_subdevice_v6() {
        assert!(!is_public_ipv4("100.64.10.1".parse().unwrap()));
        assert!(!is_public_ipv4("192.168.1.1".parse().unwrap()));
        assert!(is_public_ipv4("1.1.1.1".parse().unwrap()));

        assert!(!is_public_gua_ipv6("fe80::1".parse().unwrap()));
        assert!(!is_public_gua_ipv6("fd00::1".parse().unwrap()));
        assert!(is_public_gua_ipv6("240e:3b0:1234:5678::1".parse().unwrap()));

        let p: Ipv6Addr = "240e:3b0:1234:5678::1".parse().unwrap();
        let iid: Ipv6Addr = "::200:5eff:fe00:5301".parse().unwrap();
        assert_eq!(
            synthesize_subdevice_ipv6(p, iid),
            "240e:3b0:1234:5678:200:5eff:fe00:5301".parse::<Ipv6Addr>().unwrap()
        );
    }
}
