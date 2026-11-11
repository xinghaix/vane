use super::*;
use axum::routing::get;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn exercise_listener(bind_addr: &str) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let listener = match bind(bind_addr.parse().unwrap()) {
        Ok(listener) => listener,
        Err(e) if bind_addr.starts_with('[') && matches!(e.kind(), io::ErrorKind::AddrNotAvailable | io::ErrorKind::Unsupported) => return,
        Err(e) => panic!("绑定测试监听器失败: {e}"),
    };
    let addr = listener.local_addr().unwrap();
    let (_, _, key) = crate::net::tls_resolver::generate_self_signed_cert(&[
        "[2001:db8::1234]:23456".into(), "127.0.0.1:23456".into()
    ]).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(key.cert[0].clone()).unwrap();
    let client = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    let app = Router::new().route("/", get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move { peer.ip().to_string() }));
    let quota = Arc::new(Semaphore::new(16));
    let task = tokio::spawn(serve(listener, app, Arc::new(tls_config(key)), "https://router.example:23456".into(), quota,
        Duration::from_secs(1), Duration::from_secs(1)));
    let mut plain = tokio::net::TcpStream::connect(addr).await.unwrap();
    plain.write_all(b"GET / HTTP/1.1\r\nHost: attacker.example\r\n\r\n").await.unwrap();
    let mut buf = [0; 512];
    let n = tokio::time::timeout(Duration::from_secs(2), plain.read(&mut buf)).await.unwrap().unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.starts_with("HTTP/1.1 308"));
    assert!(response.contains("Location: https://router.example:23456/"));
    assert!(!response.contains("attacker.example"));

    // 通过 IPv4 或 IPv6 socket 连接，并用显式 IPv6 SAN 验证证书。
    let socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
    let name = rustls::pki_types::ServerName::IpAddress("2001:db8::1234".parse::<std::net::IpAddr>().unwrap().into());
    let mut secure = connector.connect(name, socket).await.unwrap();
    secure.write_all(b"GET / HTTP/1.1\r\nHost: router.example:23456\r\nConnection: close\r\nX-Real-IP: 198.51.100.4\r\n\r\n").await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), secure.read_to_end(&mut response)).await.unwrap().unwrap();
    let response = String::from_utf8_lossy(&response);
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.ends_with(&addr.ip().to_string()));
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn https_ipv4_and_fixed_plaintext_redirect() { exercise_listener("127.0.0.1:0").await; }

#[tokio::test]
async fn https_ipv6_and_fixed_plaintext_redirect() { exercise_listener("[::1]:0").await; }
