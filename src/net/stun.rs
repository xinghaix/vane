//! RFC 5389 / 8489 STUN 穿透映射探测状态机（完整校验 20B Header + Magic Cookie + Transaction ID）。
use crate::config::StunConfig;
use crate::logger::{self, Level};
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

pub const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_RESPONSE_SUCCESS: u16 = 0x0101;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

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
            break;
        }
        let val = &pkt[pos..pos + attr_len];
        if attr_type == ATTR_XOR_MAPPED_ADDRESS {
            if let Some(addr) = parse_xor_mapped(val, expected_tx_id) {
                return Ok(addr);
            }
        } else if attr_type == ATTR_MAPPED_ADDRESS {
            fallback_mapped = parse_plain_mapped(val);
        }
        let pad = (4 - (attr_len % 4)) % 4;
        pos += attr_len + pad;
    }

    fallback_mapped.ok_or("未找到 XOR-MAPPED-ADDRESS 属性")
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
        _ => None,
    }
}

pub fn format_public_endpoint(addr: SocketAddr) -> String {
    addr.to_string()
}

pub async fn probe_stun_once(cfg: &StunConfig) -> Result<SocketAddr, String> {
    let servers = cfg.servers();
    if servers.is_empty() {
        return Err("未配置 STUN 服务器".into());
    }
    let mut last_err = String::new();
    for srv in servers {
        let res = if cfg.proto == "tcp" {
            probe_tcp(&srv, cfg.local_port).await
        } else {
            probe_udp(&srv, cfg.local_port).await
        };
        match res {
            Ok(addr) => {
                logger::log(
                    Level::Info,
                    "stun",
                    &format!("STUN 规则 {} 通过 {} 探测到映射地址: {}", cfg.name, srv, format_public_endpoint(addr)),
                );
                return Ok(addr);
            }
            Err(e) => last_err = format!("{}: {}", srv, e),
        }
    }
    Err(last_err)
}

async fn probe_udp(server: &str, local_port: u16) -> Result<SocketAddr, String> {
    let target: SocketAddr = tokio::net::lookup_host(server)
        .await
        .map_err(|e| e.to_string())?
        .find(|a| a.is_ipv4())
        .ok_or_else(|| "STUN DNS 解析无 IPv4 地址".to_string())?;
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), local_port);
    let sock = UdpSocket::bind(bind_addr).await.map_err(|e| e.to_string())?;
    let (req, tx_id) = build_binding_request();
    sock.send_to(&req, target).await.map_err(|e| e.to_string())?;
    let mut buf = [0u8; 512];
    let (n, _) = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
        .await
        .map_err(|_| "STUN UDP 响应超时".to_string())?
        .map_err(|e| e.to_string())?;
    parse_binding_response(&buf[..n], &tx_id).map_err(|e| e.to_string())
}

async fn probe_tcp(server: &str, _local_port: u16) -> Result<SocketAddr, String> {
    let mut stream = tokio::time::timeout(Duration::from_secs(4), TcpStream::connect(server))
        .await
        .map_err(|_| "STUN TCP 连接超时".to_string())?
        .map_err(|e| e.to_string())?;
    let (req, tx_id) = build_binding_request();
    stream.write_all(&req).await.map_err(|e| e.to_string())?;
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(4), stream.read(&mut buf))
        .await
        .map_err(|_| "STUN TCP 读取超时".to_string())?
        .map_err(|e| e.to_string())?;
    parse_binding_response(&buf[..n], &tx_id).map_err(|e| e.to_string())
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
    map.insert("action", serde_json::json!("redirect"));
    map.insert("expression", serde_json::json!(format!("(http.host eq \"{}\")", source_host)));
    map.insert(
        "action_parameters",
        serde_json::json!({
            "from_value": {
                "status_code": status_code,
                "target_url": { "value": target_url },
                "preserve_query_string": true
            }
        }),
    );
    serde_json::to_string(&map).unwrap_or_default()
}

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
