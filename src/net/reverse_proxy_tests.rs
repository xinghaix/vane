//! 在真实 TCP/TLS 边界验证反代，不对内部转发函数做模拟。
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn proxy_preserves_binary_post_body_headers_and_response() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let app = axum::Router::new().fallback(axum::routing::any(
        |request: axum::extract::Request| async move {
            assert_eq!(request.headers().get("x-test").unwrap(), "original");
            let bytes = axum::body::to_bytes(request.into_body(), 1024 * 1024)
                .await
                .unwrap();
            ([("x-upstream", "present")], bytes)
        },
    ));
    let upstream_task = tokio::spawn(async move { axum::serve(upstream, app).await.unwrap() });
    let reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = reservation.local_addr().unwrap().port();
    drop(reservation);
    let (_, _, key) =
        crate::net::tls_resolver::generate_self_signed_cert(&["proxy.example.com".into()]).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(key.cert[0].clone()).unwrap();
    let mut table = CertTable::default();
    table.exact.insert("proxy.example.com".into(), key);
    let cfg = ReverseProxyConfig {
        name: "test".into(),
        listen_port: port,
        stack: "ipv4_only".into(),
        open_wan_firewall: false,
        rules: vec![ReverseProxyRule {
            host: "proxy.example.com".into(),
            upstream: format!("http://{upstream_address}"),
            ..Default::default()
        }],
        ..Default::default()
    };
    let firewall = FirewallManager::detect_and_init(crate::config::FirewallConfig {
        auto_manage: false,
        ..Default::default()
    })
    .await;
    let (stop, rx) = watch::channel(false);
    let server = tokio::spawn(run_reverse_proxy_listener(
        cfg,
        Arc::new(ArcSwap::from_pointee(table)),
        ConnectionQuota::new(32),
        firewall,
        Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
        rx,
    ));
    let socket = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(socket) = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).await {
                break socket;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let client = tokio_rustls::TlsConnector::from(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));
    let mut socket = client
        .connect(
            rustls::pki_types::ServerName::try_from("proxy.example.com").unwrap(),
            socket,
        )
        .await
        .unwrap();
    let payload = b"binary\x00body\xffpayload";
    let request=format!("POST /upload HTTP/1.1\r\nHost: proxy.example.com\r\nX-Test: original\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",payload.len());
    let mut bytes = request.into_bytes();
    bytes.extend_from_slice(payload);
    socket.write_all(&bytes).await.unwrap();
    socket.shutdown().await.unwrap();
    let mut response = Vec::new();
    let result =
        tokio::time::timeout(Duration::from_secs(3), socket.read_to_end(&mut response)).await;
    stop.send(true).unwrap();
    server.await.unwrap().unwrap();
    upstream_task.abort();
    let _ = upstream_task.await;
    result.unwrap().unwrap();
    assert!(
        response
            .windows(payload.len())
            .any(|window| window == payload),
        "反代没有原样传递二进制正文"
    );
    assert!(String::from_utf8_lossy(&response).contains("x-upstream: present"));
}

struct TestProxy {
    port: u16,
    ipv6: bool,
    roots: rustls::RootCertStore,
    stop: watch::Sender<bool>,
    server: tokio::task::JoinHandle<Result<(), String>>,
    quota: ConnectionQuota,
}
impl TestProxy {
    async fn start(rules: Vec<ReverseProxyRule>, auth: Arc<dyn ProxyAuthorization>) -> Self {
        Self::start_stack(rules, auth, false).await
    }
    async fn start_stack(
        rules: Vec<ReverseProxyRule>,
        auth: Arc<dyn ProxyAuthorization>,
        ipv6: bool,
    ) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let reserved = TcpListener::bind(if ipv6 { "[::1]:0" } else { "127.0.0.1:0" })
            .await
            .unwrap();
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);
        let (_, _, key) =
            crate::net::tls_resolver::generate_self_signed_cert(&["proxy.example.com".into()])
                .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(key.cert[0].clone()).unwrap();
        let mut table = CertTable::default();
        table.exact.insert("proxy.example.com".into(), key);
        let cfg = ReverseProxyConfig {
            name: "test".into(),
            listen_port: port,
            stack: if ipv6 { "ipv6_only" } else { "ipv4_only" }.into(),
            open_wan_firewall: false,
            rules,
            ..Default::default()
        };
        let firewall = FirewallManager::detect_and_init(crate::config::FirewallConfig {
            auto_manage: false,
            ..Default::default()
        })
        .await;
        let (stop, rx) = watch::channel(false);
        let quota = ConnectionQuota::new(16);
        let server = tokio::spawn(run_reverse_proxy_authorized(
            cfg,
            Arc::new(ArcSwap::from_pointee(table)),
            quota.clone(),
            firewall,
            Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            rx,
            auth,
        ));
        Self {
            port,
            ipv6,
            roots,
            stop,
            server,
            quota,
        }
    }
    async fn socket(&self) -> TcpStream {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(socket) = TcpStream::connect((
                    if self.ipv6 {
                        IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
                    } else {
                        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                    },
                    self.port,
                ))
                .await
                {
                    break socket;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap()
    }
    async fn tls(&self, h2: bool) -> tokio_rustls::client::TlsStream<TcpStream> {
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(self.roots.clone())
            .with_no_client_auth();
        config.alpn_protocols = vec![if h2 {
            b"h2".to_vec()
        } else {
            b"http/1.1".to_vec()
        }];
        tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(
                rustls::pki_types::ServerName::try_from("proxy.example.com").unwrap(),
                self.socket().await,
            )
            .await
            .unwrap()
    }
    async fn raw(&self, request: &[u8], fragment: bool) -> Vec<u8> {
        let mut stream = self.tls(false).await;
        if fragment {
            for chunk in request.chunks(3) {
                stream.write_all(chunk).await.unwrap();
            }
        } else {
            stream.write_all(request).await.unwrap();
        }
        stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        response
    }
    async fn shutdown(self) {
        self.stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(3), self.server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(self.quota.active_connections(), 0);
    }
}
#[tokio::test]
async fn upstream_tls_strict_pin_and_explicit_insecure_modes_are_distinct() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (_, _, key) =
        crate::net::tls_resolver::generate_self_signed_cert(&["backend.example.com".into()])
            .unwrap();
    let fingerprint: String = ring::digest::digest(&ring::digest::SHA256, key.cert[0].as_ref())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(crate::web::server::tls_config(key)));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            if let Ok(mut tls) = acceptor.accept(socket).await {
                assert_eq!(tls.get_ref().1.server_name(), Some("backend.example.com"));
                let mut bytes = [0; 4096];
                tls.read(&mut bytes).await.unwrap();
                tls.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                )
                .await
                .unwrap();
            }
        }
    });
    for (mode, pin, expected) in [
        ("strict", fingerprint.clone(), 502),
        ("pinned_sha256", "00".repeat(32), 502),
        ("pinned_sha256", fingerprint, 200),
        ("insecure_skip_verify", String::new(), 200),
    ] {
        let mut cfg = rule(&format!("https://{address}"));
        cfg.upstream_tls_mode = mode.into();
        cfg.upstream_cert_sha256 = pin;
        cfg.upstream_sni = "backend.example.com".into();
        let proxy = TestProxy::start(vec![cfg], Arc::new(NoAuthorization)).await;
        let response = proxy
            .raw(
                b"GET / HTTP/1.1\r\nHost: proxy.example.com\r\nConnection: close\r\n\r\n",
                false,
            )
            .await;
        assert!(
            String::from_utf8_lossy(&response).starts_with(&format!("HTTP/1.1 {expected}")),
            "TLS 模式 {mode} 的响应不符"
        );
        proxy.shutdown().await;
    }
    task.abort();
    let _ = task.await;
}

struct TestAuthorization {
    tickets: crate::security::tickets::SessionTickets,
    alive: AtomicBool,
}
impl ProxyAuthorization for TestAuthorization {
    fn session(&self, _: &HeaderMap, _: IpAddr) -> Option<[u8; 32]> {
        None
    }
    fn websocket_ticket(&self, ticket: &str, target: &str, peer: IpAddr) -> Option<[u8; 32]> {
        self.tickets.consume(
            ticket,
            target,
            crate::net::dual_stack::BanKey::from_peer(peer),
        )
    }
    fn session_alive(&self, _: &[u8; 32]) -> bool {
        self.alive.load(Ordering::Relaxed)
    }
}
async fn response_head(stream: &mut tokio_rustls::client::TlsStream<TcpStream>) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).await.unwrap();
            header.push(byte[0]);
            assert!(header.len() < 8192);
        }
        header
    })
    .await
    .unwrap()
}
#[tokio::test]
async fn websocket_requires_origin_ticket_and_closes_after_session_revocation() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = axum::Router::new().route(
        "/ws",
        axum::routing::get(|request: axum::extract::ws::WebSocketUpgrade| async move {
            request.on_upgrade(|mut socket| async move {
                while let Some(Ok(message)) = socket.recv().await {
                    if socket.send(message).await.is_err() {
                        break;
                    }
                }
            })
        }),
    );
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let auth = Arc::new(TestAuthorization {
        tickets: Default::default(),
        alive: AtomicBool::new(true),
    });
    let mut guarded = rule(&format!("http://{address}"));
    guarded.auth_gate = true;
    let proxy = TestProxy::start(vec![guarded], auth.clone()).await;
    let target = format!("proxy.example.com:{}/ws", proxy.port);
    let ticket = auth
        .tickets
        .issue(
            "session",
            target,
            crate::net::dual_stack::BanKey::from_peer("127.0.0.1".parse().unwrap()),
        )
        .unwrap();
    let request=format!("GET /ws?vane_ticket={ticket} HTTP/1.1\r\nHost: proxy.example.com:{}\r\nOrigin: https://proxy.example.com:{}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",proxy.port,proxy.port);
    let bad_origin = request.replace(
        &format!("Origin: https://proxy.example.com:{}", proxy.port),
        "Origin: https://evil.example",
    );
    let mut rejected = proxy.tls(false).await;
    rejected.write_all(bad_origin.as_bytes()).await.unwrap();
    assert!(response_head(&mut rejected)
        .await
        .starts_with(b"HTTP/1.1 403"));
    drop(rejected);
    let mut socket = proxy.tls(false).await;
    socket.write_all(request.as_bytes()).await.unwrap();
    let response = response_head(&mut socket).await;
    assert!(response.starts_with(b"HTTP/1.1 101"));
    socket
        .write_all(&[0x81, 0x82, 1, 2, 3, 4, b'h' ^ 1, b'i' ^ 2])
        .await
        .unwrap();
    let mut echo = [0; 4];
    tokio::time::timeout(Duration::from_secs(2), socket.read_exact(&mut echo))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(echo, [0x81, 2, b'h', b'i']);
    let mut replay = proxy.tls(false).await;
    replay.write_all(request.as_bytes()).await.unwrap();
    assert!(response_head(&mut replay)
        .await
        .starts_with(b"HTTP/1.1 401"));
    drop(replay);
    auth.alive.store(false, Ordering::Relaxed);
    let mut byte = [0];
    let closed = tokio::time::timeout(Duration::from_secs(3), socket.read(&mut byte))
        .await
        .unwrap();
    assert!(closed.is_err() || closed.unwrap() == 0);
    drop(socket);
    proxy.shutdown().await;
    task.abort();
    let _ = task.await;
}

fn rule(upstream: &str) -> ReverseProxyRule {
    ReverseProxyRule {
        host: "proxy.example.com".into(),
        upstream: upstream.into(),
        ..Default::default()
    }
}

#[tokio::test]
async fn ipv6_listener_proxies_ipv6_backend_and_enforces_real_peer_cidr() {
    let listener = match TcpListener::bind("[::1]:0").await {
        Ok(listener) => listener,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::Unsupported
            ) =>
        {
            return
        }
        Err(error) => panic!("{error}"),
    };
    let address = listener.local_addr().unwrap();
    let app = axum::Router::new().fallback(axum::routing::any(|| async { "ipv6 backend" }));
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    for (allow, expected) in [("::1/128", 200), ("127.0.0.1/32", 403)] {
        let mut cfg = rule(&format!("http://{address}"));
        cfg.allowed_cidrs = vec![allow.into()];
        let proxy = TestProxy::start_stack(vec![cfg], Arc::new(NoAuthorization), true).await;
        let response=proxy.raw(b"GET / HTTP/1.1\r\nHost: proxy.example.com\r\nX-Real-IP: 127.0.0.1\r\nConnection: close\r\n\r\n",false).await;
        assert!(String::from_utf8_lossy(&response).starts_with(&format!("HTTP/1.1 {expected}")));
        if expected == 200 {
            assert!(String::from_utf8_lossy(&response).contains("ipv6 backend"));
        }
        proxy.shutdown().await;
    }
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn unknown_length_upload_is_limited_and_spoofed_authority_is_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = axum::Router::new().fallback(axum::routing::any(
        |request: axum::extract::Request| async move {
            let _ = axum::body::to_bytes(request.into_body(), 4 * 1024 * 1024).await;
            "done"
        },
    ));
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut cfg = rule(&format!("http://{address}"));
    cfg.max_body_mb = 1;
    let proxy = TestProxy::start(vec![cfg], Arc::new(NoAuthorization)).await;
    let (mut sender, driver) =
        hyper::client::conn::http1::handshake(TokioIo::new(proxy.tls(false).await))
            .await
            .unwrap();
    let driver = tokio::spawn(driver);
    let chunks = futures_util::stream::iter(
        (0..17).map(|_| Ok::<_, std::io::Error>(bytes::Bytes::from(vec![0u8; 65536]))),
    );
    let request = Request::builder()
        .method("POST")
        .uri("/upload")
        .header("host", "proxy.example.com")
        .body(Body::from_stream(chunks))
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    drop(response);
    drop(sender);
    driver.abort();
    let _ = driver.await;
    let response = proxy
        .raw(
            b"GET / HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n",
            false,
        )
        .await;
    assert!(response.starts_with(b"HTTP/1.1 421"));
    proxy.shutdown().await;
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn shutdown_cancels_an_active_upstream_and_returns_all_connection_permits() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = Arc::new(tokio::sync::Notify::new());
    let ready = accepted.clone();
    let upstream = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = [0; 4096];
        socket.read(&mut bytes).await.unwrap();
        ready.notify_one();
        let mut byte = [0];
        assert_eq!(socket.read(&mut byte).await.unwrap(), 0);
    });
    let proxy = TestProxy::start(
        vec![rule(&format!("http://{address}"))],
        Arc::new(NoAuthorization),
    )
    .await;
    let mut client = proxy.tls(false).await;
    client
        .write_all(b"GET /pending HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n")
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), accepted.notified())
        .await
        .unwrap();
    proxy.shutdown().await;
    tokio::time::timeout(Duration::from_secs(2), upstream)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn plaintext_redirect_preserves_path_only_for_configured_hosts() {
    let proxy = TestProxy::start(vec![rule("http://127.0.0.1:1")], Arc::new(NoAuthorization)).await;
    for (host, status, path) in [
        ("proxy.example.com", 308, true),
        ("evil.example", 404, false),
    ] {
        let mut socket = proxy.socket().await;
        socket
            .write_all(
                format!("GET /safe?q=1 HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(3), socket.read_to_end(&mut response))
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with(&format!("HTTP/1.1 {status}")));
        if path {
            assert!(text.contains(&format!(
                "https://proxy.example.com:{}/safe?q=1",
                proxy.port
            )));
        } else {
            assert!(!text.contains("Location:"));
        }
    }
    proxy.shutdown().await;
}

#[tokio::test]
async fn fragmented_chunked_request_and_hop_headers_are_handled_correctly() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = axum::Router::new().fallback(axum::routing::any(
        |request: axum::extract::Request| async move {
            assert_eq!(request.uri(), "/base/path?q=1");
            assert!(request.headers().get("x-remove").is_none());
            assert!(request.headers().get("forwarded").is_none());
            assert!(request.headers().get("x-forwarded-secret").is_none());
            assert_eq!(request.headers()["x-real-ip"], "127.0.0.1");
            assert_eq!(request.headers()["x-forwarded-for"], "127.0.0.1");
            assert_eq!(request.headers()["cookie"], "backend=keep");
            let bytes = axum::body::to_bytes(request.into_body(), 1024)
                .await
                .unwrap();
            assert_eq!(&bytes[..], b"hello world");
            Response::builder()
                .header("connection", "x-remove-response")
                .header("x-remove-response", "hidden")
                .header("set-cookie", "vane_session=evil")
                .header("set-cookie", "backend=ok")
                .body(Body::from("ok"))
                .unwrap()
        },
    ));
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut cfg = rule(&format!("http://{address}/base"));
    cfg.path_prefix = "/api".into();
    cfg.strip_prefix = true;
    cfg.response_headers_set
        .insert("x-added".into(), "configured".into());
    let proxy = TestProxy::start(vec![cfg], Arc::new(NoAuthorization)).await;
    let request=b"POST /api/path?q=1 HTTP/1.1\r\nHost: proxy.example.com\r\nTransfer-Encoding: chunked\r\nForwarded: for=evil\r\nX-Forwarded-Secret: evil\r\nX-Real-IP: evil\r\nCookie: vane_session=secret; backend=keep\r\nConnection: close, X-Remove\r\nX-Remove: hidden\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    let response = proxy.raw(request, true).await;
    let text = String::from_utf8_lossy(&response);
    assert!(text.starts_with("HTTP/1.1 200"));
    assert!(text.contains("x-added: configured"));
    assert!(text.contains("backend=ok"));
    assert!(!text.contains("vane_session"));
    assert!(!text.contains("hidden"));
    proxy.shutdown().await;
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn http2_authority_routes_and_streams_a_binary_response() {
    use http_body_util::BodyExt;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = axum::Router::new().fallback(axum::routing::any(|| async { vec![0u8, 1, 255, 2] }));
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let proxy = TestProxy::start(
        vec![rule(&format!("http://{address}"))],
        Arc::new(NoAuthorization),
    )
    .await;
    let socket = proxy.tls(true).await;
    assert_eq!(socket.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let (mut sender, driver) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        TokioIo::new(socket),
    )
    .await
    .unwrap();
    let driver = tokio::spawn(driver);
    let request = Request::builder()
        .uri("https://proxy.example.com/resource")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], &[0, 1, 255, 2]);
    drop(sender);
    driver.abort();
    let _ = driver.await;
    proxy.shutdown().await;
    task.abort();
    let _ = task.await;
}
