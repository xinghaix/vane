use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn fixture(response: &'static [u8]) -> (String, tokio::task::JoinHandle<String>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/test", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = vec![0; 4096];
        let count = stream.read(&mut bytes).await.unwrap();
        stream.write_all(response).await.unwrap();
        String::from_utf8_lossy(&bytes[..count]).to_string()
    });
    (url, task)
}

#[tokio::test]
async fn chunked_body_and_non_success_status() {
    let (url, task) = fixture(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n").await;
    let response = shared().execute(HttpRequest::new("GET", &url)).await.unwrap();
    assert_eq!(response.body, b"hello");
    assert!(task.await.unwrap().starts_with("GET /test HTTP/1.1"));
    let (url, task) = fixture(b"HTTP/1.1 302 Found\r\nLocation: http://invalid.example/\r\nContent-Length: 0\r\n\r\n").await;
    assert!(shared().execute(HttpRequest::new("GET", &url)).await.unwrap().ensure_success().is_err());
    task.await.unwrap();
}

#[tokio::test]
async fn enforces_body_limits_and_deadlines() {
    let (url, task) = fixture(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n").await;
    let mut request = HttpRequest::new("GET", &url);
    request.response_limit = 3;
    assert!(shared().execute(request).await.err().unwrap().contains("大小限制"));
    task.await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut request = HttpRequest::new("GET", &format!("http://{}", listener.local_addr().unwrap()));
    request.timeout = Duration::from_millis(50);
    let task = tokio::spawn(async move { let (_stream, _) = listener.accept().await.unwrap(); std::future::pending::<()>().await; });
    assert!(shared().execute(request).await.err().unwrap().contains("超时"));
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn tls_requires_trusted_certificate_and_verifies_ip_san() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (_, _, key) = crate::net::tls_resolver::generate_self_signed_cert(&["127.0.0.1:23456".into()]).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(key.cert[0].clone()).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://{}/", listener.local_addr().unwrap());
    let server = tokio_rustls::TlsAcceptor::from(Arc::new(crate::web::server::tls_config(key)));
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        assert!(server.accept(socket).await.is_err());
        let (socket, _) = listener.accept().await.unwrap();
        let mut stream = server.accept(socket).await.unwrap();
        let mut buffer = [0; 1024];
        assert!(stream.read(&mut buffer).await.unwrap() > 0);
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await.unwrap();
    });
    let error = shared().execute(HttpRequest::new("GET", &url)).await.err().unwrap();
    assert!(error.contains("TLS"));
    let trusted = HttpClient { tls: Arc::new(rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth()), slots: Arc::new(Semaphore::new(1)) };
    assert_eq!(trusted.execute(HttpRequest::new("GET", &url)).await.unwrap().body, b"ok");
    task.await.unwrap();
}

#[tokio::test]
async fn rejects_injected_headers_before_connecting() {
    let mut request = HttpRequest::new("GET", "http://127.0.0.1:1");
    request.headers.insert("authorization".into(), "secret\r\ninjected: true".into());
    let error = shared().execute(request).await.err().unwrap();
    assert!(!error.contains("secret"));
    assert!(error.contains("请求头"));
}

#[tokio::test]
async fn failed_candidate_does_not_cancel_successful_candidate() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unavailable = closed.local_addr().unwrap();
    drop(closed);
    let connected = super::super::dual_stack::connect_candidates(&[unavailable, listener.local_addr().unwrap()], 10).await.unwrap();
    assert_eq!(connected.peer_addr().unwrap(), listener.local_addr().unwrap());
}

#[tokio::test]
async fn ssrf_policy_blocks_loopback_and_link_local_metadata() {
    let mut req = HttpRequest::new("GET", "http://127.0.0.1:8080/secret");
    req.ssrf_policy = SsrfPolicy::BlockLoopbackAndLinkLocal;
    let err = shared().execute(req).await.err().unwrap();
    assert!(err.contains("SSRF"));

    let mut meta = HttpRequest::new("GET", "http://169.254.169.254/latest/meta-data/");
    meta.ssrf_policy = SsrfPolicy::BlockLoopbackAndLinkLocal;
    let err2 = shared().execute(meta).await.err().unwrap();
    assert!(err2.contains("SSRF"));
}

#[test]
fn ssrf_ip_filter_blocks_special_reserved_and_nat64_ranges() {
    let parse = |s: &str| s.parse::<std::net::IpAddr>().unwrap();

    // 始终拦截的特殊/保留地址段（包含 0.0.0.0/8, 广播, 240/4, 192.0.0/24, 198.18/15, fec0::/10, 100::/64, ::/96, ::ffff:0:0:0/96）
    for blocked in [
        "0.0.0.0",
        "0.1.2.3",
        "169.254.169.254",
        "192.0.0.1",
        "198.18.0.1",
        "198.19.255.254",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "::",
        "::127.0.0.1",
        "::169.254.169.254",
        "::ffff:0:127.0.0.1",
        "::ffff:0:1.1.1.1",
        "fe80::1",
        "fec0::1",
        "100::1",
        "ff02::1",
        "64:ff9b::169.254.169.254",
        "64:ff9b::0.1.2.3",
        "64:ff9b::240.0.0.1",
        "64:ff9b:1::127.0.0.1",
        "64:ff9b:1::169.254.169.254",
        "64:ff9b:1::1.1.1.1",
    ] {
        let ip = parse(blocked);
        assert!(!is_ip_allowed(ip, SsrfPolicy::BlockLoopbackAndLinkLocal), "expected blocked (default): {blocked}");
        assert!(!is_ip_allowed(ip, SsrfPolicy::PublicOnly), "expected blocked (public): {blocked}");
        assert!(!is_ip_allowed(ip, SsrfPolicy::AllowLoopback), "expected blocked (allow_loopback): {blocked}");
    }

    // NAT64 Well-Known Prefix (64:ff9b::/96) 递归校验内嵌 IPv4
    assert!(!is_ip_allowed(parse("64:ff9b::127.0.0.1"), SsrfPolicy::BlockLoopbackAndLinkLocal));
    assert!(!is_ip_allowed(parse("64:ff9b::127.0.0.1"), SsrfPolicy::PublicOnly));
    assert!(!is_ip_allowed(parse("64:ff9b::10.0.0.1"), SsrfPolicy::PublicOnly));
    assert!(!is_ip_allowed(parse("64:ff9b::192.168.1.1"), SsrfPolicy::PublicOnly));
    assert!(!is_ip_allowed(parse("64:ff9b::100.64.0.1"), SsrfPolicy::PublicOnly));
    assert!(is_ip_allowed(parse("64:ff9b::1.1.1.1"), SsrfPolicy::PublicOnly));
    assert!(is_ip_allowed(parse("64:ff9b::1.1.1.1"), SsrfPolicy::BlockLoopbackAndLinkLocal));

    // PublicOnly 与 netlink_ip 保持一致（拒绝私网/ULA/CGNAT/文档地址，放行真实公网 IP）
    for non_public in ["127.0.0.1", "::1", "10.0.0.1", "192.168.1.1", "100.64.1.1", "203.0.113.1", "fc00::1", "2001:db8::1"] {
        assert!(!is_ip_allowed(parse(non_public), SsrfPolicy::PublicOnly), "expected blocked (public): {non_public}");
    }
    assert!(is_ip_allowed(parse("1.1.1.1"), SsrfPolicy::PublicOnly));
    assert!(is_ip_allowed(parse("2606:4700:4700::1111"), SsrfPolicy::PublicOnly));
    // AllowLoopback 允许本地测试回环地址
    assert!(is_ip_allowed(parse("127.0.0.1"), SsrfPolicy::AllowLoopback));
    assert!(is_ip_allowed(parse("::1"), SsrfPolicy::AllowLoopback));
}
