use super::*;
use crate::config::{CloudflareRedirectConfig, Config, StunConfig};
use axum::{
    extract::Request,
    routing::{patch, post},
    Json, Router,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

struct TempDir(PathBuf);
impl TempDir {
    fn create(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("vane_{}_{}", tag, crate::config::random_nonce()));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn encode_xor_response(tx_id: &[u8; 12], mapped: SocketAddr) -> Vec<u8> {
    let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
    let xport = mapped.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
    let mut attr = Vec::new();
    match mapped.ip() {
        IpAddr::V4(v4) => {
            attr.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
            attr.extend_from_slice(&8u16.to_be_bytes());
            attr.push(0);
            attr.push(0x01);
            attr.extend_from_slice(&xport.to_be_bytes());
            let oct = v4.octets();
            for i in 0..4 {
                attr.push(oct[i] ^ cookie[i]);
            }
        }
        IpAddr::V6(v6) => {
            attr.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
            attr.extend_from_slice(&20u16.to_be_bytes());
            attr.push(0);
            attr.push(0x02);
            attr.extend_from_slice(&xport.to_be_bytes());
            let oct = v6.octets();
            for i in 0..4 {
                attr.push(oct[i] ^ cookie[i]);
            }
            for i in 0..12 {
                attr.push(oct[4 + i] ^ tx_id[i]);
            }
        }
    }
    let mut pkt = Vec::with_capacity(20 + attr.len());
    pkt.extend_from_slice(&BINDING_RESPONSE_SUCCESS.to_be_bytes());
    pkt.extend_from_slice(&(attr.len() as u16).to_be_bytes());
    pkt.extend_from_slice(&cookie);
    pkt.extend_from_slice(tx_id);
    pkt.extend_from_slice(&attr);
    pkt
}

#[tokio::test]
async fn persistent_udp_session_retains_local_port_and_re_probes() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let srv_addr = server.local_addr().unwrap();
    let seen_client_port = Arc::new(AtomicU16::new(0));
    let seen_count = Arc::new(AtomicUsize::new(0));
    let port_rec = seen_client_port.clone();
    let cnt_rec = seen_count.clone();

    tokio::spawn(async move {
        let mut buf = [0u8; 256];
        while let Ok((n, peer)) = server.recv_from(&mut buf).await {
            if n < 20 {
                continue;
            }
            let prev = port_rec.swap(peer.port(), Ordering::SeqCst);
            if prev != 0 {
                assert_eq!(prev, peer.port());
            }
            cnt_rec.fetch_add(1, Ordering::SeqCst);
            let mut tx = [0u8; 12];
            tx.copy_from_slice(&buf[8..20]);
            let resp = encode_xor_response(&tx, SocketAddr::new("203.0.113.88".parse().unwrap(), peer.port()));
            let _ = server.send_to(&resp, peer).await;
        }
    });

    let mut entry = StunConfig::default();
    entry.name = "nat_udp".into();
    entry.proto = "udp".into();
    entry.local_port = 0;
    entry.stun_server = srv_addr.to_string();

    let mut udp_socks = PersistentUdpSockets::new(0);
    let mut tcp_conn = None;
    let first = probe_with_session(&entry, 0, &mut udp_socks, &mut tcp_conn).await.unwrap();
    let second = probe_with_session(&entry, 0, &mut udp_socks, &mut tcp_conn).await.unwrap();
    assert_eq!(first.local_addr.port(), second.local_addr.port());
    assert_eq!(first.mapped, second.mapped);
    assert_eq!(seen_count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn ipv6_tcp_stun_and_webhook_plus_cloudflare_redirect_hooks_execute_for_real() {
    let Ok(stun_tcp) = TcpListener::bind("[::1]:0").await else { return };
    let stun_srv_addr = stun_tcp.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = stun_tcp.accept().await {
            let mut req = [0u8; 20];
            s.read_exact(&mut req).await.unwrap();
            let mut tx = [0u8; 12];
            tx.copy_from_slice(&req[8..20]);
            let mapped: SocketAddr = "[2001:db8:8888::1]:45678".parse().unwrap();
            let resp = encode_xor_response(&tx, mapped);
            s.write_all(&resp[..10]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(15)).await;
            s.write_all(&resp[10..]).await.unwrap();
        }
    });

    let webhook_hits = Arc::new(AtomicUsize::new(0));
    let cf_hits = Arc::new(AtomicUsize::new(0));
    let wh_c = webhook_hits.clone();
    let cf_c = cf_hits.clone();

    let app = Router::new()
        .route(
            "/hook",
            post(move |Json(body): Json<Value>| {
                let wh_c = wh_c.clone();
                async move {
                    assert_eq!(body["public_addr"], "[2001:db8:8888::1]:45678");
                    wh_c.fetch_add(1, Ordering::SeqCst);
                    Json(json!({ "ok": true }))
                }
            }),
        )
        .route(
            "/zones/{zone}/rulesets/{rs}/rules/{rule}",
            patch(move |req: Request| {
                let cf_c = cf_c.clone();
                async move {
                    let auth = req
                        .headers()
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    assert_eq!(auth, "Bearer cf-secret-token-123");
                    let bytes = axum::body::to_bytes(req.into_body(), 16_384).await.unwrap();
                    let body: Value = serde_json::from_slice(&bytes).unwrap();
                    assert_eq!(
                        body["action_parameters"]["from_value"]["target_url"]["value"],
                        "https://[2001:db8:8888::1]:45678"
                    );
                    cf_c.fetch_add(1, Ordering::SeqCst);
                    Json(json!({ "success": true, "result": {} }))
                }
            }),
        );

    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(http_listener, app).await;
    });

    let dir = TempDir::create("stun_test");
    let vault = Vault::load_or_create(&dir.0).unwrap();
    let mut cfg = Config::default();
    let mut entry = StunConfig::default();
    entry.name = "v6_tcp".into();
    entry.proto = "tcp".into();
    entry.stun_server = stun_srv_addr.to_string();
    entry.webhook_url = format!("http://{}/hook", http_addr);
    entry.on_change_cloudflare_redirect = Some(CloudflareRedirectConfig {
        zone_id: "zone1".into(),
        ruleset_id: "rs1".into(),
        rule_id: "rule1".into(),
        api_token: "cf-secret-token-123".into(),
        source_host: "go.example.com".into(),
        target_template: "https://{{public_addr}}".into(),
        status_code: 302,
    });
    cfg.stun.push(entry);
    vault.auto_seal(&mut cfg).unwrap();

    let stun_addrs = ArcSwap::from_pointee(BTreeMap::new());
    let runtime = new_stun_runtime();
    let cf_base = format!("http://{}", http_addr);

    let status = probe_and_sync_stun_with_cf_base(
        &cfg.stun[0],
        &cfg,
        &vault,
        &stun_addrs,
        &runtime,
        &cf_base,
    )
    .await
    .unwrap();

    assert_eq!(status.status, "active");
    assert_eq!(status.public_addr, "[2001:db8:8888::1]:45678");
    assert_eq!(webhook_hits.load(Ordering::SeqCst), 1);
    assert_eq!(cf_hits.load(Ordering::SeqCst), 1);
}
