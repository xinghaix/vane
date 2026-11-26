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
                assert!(tls.read(&mut bytes).await.unwrap() > 0);
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
        assert!(socket.read(&mut bytes).await.unwrap() > 0);
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

#[tokio::test]
async fn websocket_works_without_ticket_when_auth_gate_disabled() {
    use axum::extract::ws::WebSocketUpgrade;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = axum::Router::new().route(
        "/ws",
        axum::routing::get(|ws: WebSocketUpgrade| async move {
            ws.on_upgrade(|mut socket| async move {
                if let Some(Ok(msg)) = socket.recv().await {
                    let _ = socket.send(msg).await;
                }
            })
        }),
    );
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut normal = rule(&format!("http://{address}"));
    normal.auth_gate = false;
    normal.websocket = true;
    let proxy = TestProxy::start(vec![normal], Arc::new(NoAuthorization)).await;
    let request = format!(
        "GET /ws HTTP/1.1\r\nHost: proxy.example.com:{}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        proxy.port
    );
    let mut socket = proxy.tls(false).await;
    socket.write_all(request.as_bytes()).await.unwrap();
    let response = response_head(&mut socket).await;
    assert!(response.starts_with(b"HTTP/1.1 101"), "unexpected response: {}", String::from_utf8_lossy(&response));
    socket
        .write_all(&[0x81, 0x82, 1, 2, 3, 4, b'o' ^ 1, b'k' ^ 2])
        .await
        .unwrap();
    let mut echo = [0; 4];
    tokio::time::timeout(Duration::from_secs(2), socket.read_exact(&mut echo))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(echo, [0x81, 2, b'o', b'k']);
    drop(socket);
    proxy.shutdown().await;
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn security_regressions_upgrade_bypass_traversal_template_and_cookies_blocked() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = axum::Router::new().fallback(axum::routing::any(|req: axum::extract::Request| async move {
        let has_entry_cookie = req
            .headers()
            .get(header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|c| c.contains("vane_entry"));
        assert!(!has_entry_cookie, "vane_entry cookie leaked to upstream!");
        let resp = axum::response::Response::builder()
            .header(header::SET_COOKIE, "vane_session =hijack; Path=/")
            .header(header::SET_COOKIE, "vane_entry=hijack2; Path=/")
            .header(header::SET_COOKIE, "app=ok; Path=/")
            .body(axum::body::Body::from(format!("path={}", req.uri().path())))
            .unwrap();
        resp
    }));
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let mut static_rule = rule(&format!("http://{address}"));
    static_rule.path_prefix = "/secret".into();
    static_rule.mode = "static".into();
    static_rule.auth_gate = true;
    static_rule.static_body = "top-secret".into();

    let mut redirect_rule = rule(&format!("http://{address}"));
    redirect_rule.path_prefix = "/redir".into();
    redirect_rule.mode = "redirect".into();
    redirect_rule.auth_gate = false;
    redirect_rule.redirect_url = "https://target.example/{{path}}".into();

    let mut admin_sub = rule(&format!("http://{address}"));
    admin_sub.path_prefix = "/admin".into();
    admin_sub.auth_gate = true;

    let mut root_open = rule(&format!("http://{address}"));
    root_open.path_prefix = "/".into();
    root_open.auth_gate = false;

    let proxy = TestProxy::start(
        vec![static_rule, redirect_rule, admin_sub, root_open],
        Arc::new(NoAuthorization),
    )
    .await;

    // 1. Upgrade: websocket 不能绕过 static 规则的 auth_gate
    let mut upg_sock = proxy.tls(false).await;
    upg_sock
        .write_all(b"GET /secret HTTP/1.1\r\nHost: proxy.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
        .await
        .unwrap();
    assert!(response_head(&mut upg_sock).await.starts_with(b"HTTP/1.1 400"));
    drop(upg_sock);

    // 2. 非规范路径（/x/../admin、%2f、/%61dmin/panel）不能穿透到公开兜底规则
    for (bad_path, expect_prefix) in [
        ("/x/../admin", "HTTP/1.1 400"),
        ("/%2fadmin", "HTTP/1.1 400"),
        ("/%61dmin/panel", "HTTP/1.1 401"),
    ] {
        let req = format!("GET {bad_path} HTTP/1.1\r\nHost: proxy.example.com\r\nConnection: close\r\n\r\n");
        let resp = proxy.raw(req.as_bytes(), false).await;
        let head = String::from_utf8_lossy(&resp);
        assert!(head.starts_with(expect_prefix), "{bad_path} -> {head}");
    }

    // 3. redirect {{path}} 中包含 {{stun.hidden.public_addr}} 时不可触发 STUN 模板展开
    let stun_map = [("hidden".to_string(), "203.0.113.10:51820".to_string())]
        .into_iter()
        .collect();
    let rendered = render_redirect_location_safe(
        "https://target.example{{path}}",
        "/?q={{stun.hidden.public_addr}}",
        &stun_map,
    )
    .unwrap();
    assert!(!rendered.contains("203.0.113.10"));

    // 4. vane_entry 不透传到上游，且带空格的 Set-Cookie: vane_session =hijack 被过滤
    let resp = proxy
        .raw(
            b"GET /public HTTP/1.1\r\nHost: proxy.example.com\r\nCookie: vane_entry=secret; app_c=1\r\nConnection: close\r\n\r\n",
            false,
        )
        .await;
    let text = String::from_utf8_lossy(&resp);
    assert!(text.starts_with("HTTP/1.1 200"));
    assert!(!text.contains("hijack"));
    assert!(text.contains("app=ok"));

    proxy.shutdown().await;
    task.abort();
    let _ = task.await;
}

struct IsolatedGateTestAuth {
    store: crate::security::proxy_gate::ProxyGateStore,
    users: std::sync::Mutex<std::collections::HashMap<String, (String, bool)>>,
}

impl ProxyAuthorization for IsolatedGateTestAuth {
    fn session(&self, _: &HeaderMap, _: IpAddr) -> Option<[u8; 32]> {
        None
    }
    fn websocket_ticket(&self, _: &str, _: &str, _: IpAddr) -> Option<[u8; 32]> {
        None
    }
    fn gate_portal_enabled(&self) -> bool {
        true
    }
    fn gate_session(
        &self,
        headers: &HeaderMap,
        host: &str,
        allowed_users: &[String],
        _: IpAddr,
    ) -> Option<[u8; 32]> {
        let users = self.users.lock().unwrap();
        self.store
            .validate_request(headers, host, allowed_users, |u| users.get(u).is_some_and(|(_, en)| *en))
    }
    fn session_alive(&self, digest: &[u8; 32]) -> bool {
        let users = self.users.lock().unwrap();
        self.store
            .session_alive(digest, |u| users.get(u).is_some_and(|(_, en)| *en))
    }
    fn gate_login<'a>(
        &'a self,
        host: String,
        allowed_users: Vec<String>,
        username: String,
        password: String,
        peer: IpAddr,
    ) -> GateLoginFuture<'a> {
        Box::pin(async move {
            let ok = {
                let users = self.users.lock().unwrap();
                allowed_users.iter().any(|u| u == &username)
                    && users
                        .get(&username)
                        .is_some_and(|(pw, en)| *en && pw == &password)
            };
            if !ok {
                return Err((StatusCode::UNAUTHORIZED, "账号或密码错误".to_string()));
            }
            let tok = self
                .store
                .issue(
                    &username,
                    &host,
                    crate::net::dual_stack::BanKey::from_peer(peer),
                    Duration::from_secs(3600),
                )
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            Ok((tok, 3600))
        })
    }
    fn gate_logout(&self, headers: &HeaderMap) {
        self.store.revoke_headers(headers);
    }
}

#[tokio::test]
async fn isolated_auth_gate_portal_login_redirect_cookie_scrub_ws_and_logout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = axum::Router::new()
        .route(
            "/ws",
            axum::routing::get(|ws: axum::extract::ws::WebSocketUpgrade| async move {
                ws.on_upgrade(|mut socket| async move {
                    while let Some(Ok(msg)) = socket.recv().await {
                        if socket.send(msg).await.is_err() {
                            break;
                        }
                    }
                })
            }),
        )
        .fallback(axum::routing::any(|req: axum::extract::Request| async move {
            let ck = req
                .headers()
                .get(header::COOKIE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            assert!(
                !ck.contains("vane_gate_session"),
                "vane_gate_session must never leak to upstream!"
            );
            axum::response::Response::builder()
                .header(header::SET_COOKIE, "vane_gate_session=forged; Path=/")
                .header(header::SET_COOKIE, "app_sid=ok; Path=/")
                .body(axum::body::Body::from(format!("ok:{}", req.uri())))
                .unwrap()
        }));
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let mut users = std::collections::HashMap::new();
    users.insert("alice".to_string(), ("AlicePass#1".to_string(), true));
    users.insert("bob".to_string(), ("BobPass#1".to_string(), true));
    let auth = Arc::new(IsolatedGateTestAuth {
        store: crate::security::proxy_gate::ProxyGateStore::new(),
        users: std::sync::Mutex::new(users),
    });

    let mut r_app = rule(&format!("http://{address}"));
    r_app.auth_gate = true;
    r_app.auth_gate_users = vec!["alice".into()];

    let mut r_other = rule(&format!("http://{address}"));
    r_other.path_prefix = "/bob-only".into();
    r_other.auth_gate = true;
    r_other.auth_gate_users = vec!["bob".into()];

    let proxy = TestProxy::start(vec![r_app, r_other], auth.clone()).await;

    // 1. 浏览器 HTML 访问未登录 -> 302 跳转到 /_vane_auth/login?next=...
    let browser_req = format!(
        "GET /files?page=2 HTTP/1.1\r\nHost: proxy.example.com:{}\r\nAccept: text/html\r\nSec-Fetch-Mode: navigate\r\nConnection: close\r\n\r\n",
        proxy.port
    );
    let resp = String::from_utf8_lossy(&proxy.raw(browser_req.as_bytes(), false).await).into_owned();
    assert!(resp.starts_with("HTTP/1.1 302"), "expected 302 redirect: {resp}");
    assert!(
        resp.contains("location: /_vane_auth/login?next=%2Ffiles%3Fpage%3D2")
            || resp.contains("Location: /_vane_auth/login?next=%2Ffiles%3Fpage%3D2"),
        "missing next redirect: {resp}"
    );

    // 2. API/非 HTML 请求或携带伪造管理员 vane_session -> 401
    let api_req = format!(
        "GET /files HTTP/1.1\r\nHost: proxy.example.com:{}\r\nAccept: application/json\r\nCookie: vane_session=fake_admin\r\nConnection: close\r\n\r\n",
        proxy.port
    );
    let resp = String::from_utf8_lossy(&proxy.raw(api_req.as_bytes(), false).await).into_owned();
    assert!(resp.starts_with("HTTP/1.1 401"), "expected 401: {resp}");

    // 3. GET /_vane_auth/login 返回独立登录页面 HTML + 严格 CSP
    let login_page_req = format!(
        "GET /_vane_auth/login?next=%2Ffiles%3Fpage%3D2 HTTP/1.1\r\nHost: proxy.example.com:{}\r\nConnection: close\r\n\r\n",
        proxy.port
    );
    let resp = String::from_utf8_lossy(&proxy.raw(login_page_req.as_bytes(), false).await).into_owned();
    assert!(resp.starts_with("HTTP/1.1 200"), "login page failed: {resp}");
    assert!(resp.contains("访问身份验证") && resp.contains("content-security-policy: default-src 'none'"));

    // 4. POST /_vane_auth/login 无授权用户 bob 登录 /files -> 401；授权用户 alice 登录 -> 303 + Set-Cookie
    let bob_body = "username=bob&password=BobPass%231&next=%2Ffiles%3Fpage%3D2";
    let bob_post = format!(
        "POST /_vane_auth/login HTTP/1.1\r\nHost: proxy.example.com:{}\r\nOrigin: https://proxy.example.com:{}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        proxy.port, proxy.port, bob_body.len(), bob_body
    );
    let resp = String::from_utf8_lossy(&proxy.raw(bob_post.as_bytes(), false).await).into_owned();
    assert!(resp.starts_with("HTTP/1.1 401"), "unauthorized user bob must fail: {resp}");

    let alice_body = "username=alice&password=AlicePass%231&next=%2Ffiles%3Fpage%3D2";
    let alice_post = format!(
        "POST /_vane_auth/login HTTP/1.1\r\nHost: proxy.example.com:{}\r\nOrigin: https://proxy.example.com:{}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        proxy.port, proxy.port, alice_body.len(), alice_body
    );
    let resp = String::from_utf8_lossy(&proxy.raw(alice_post.as_bytes(), false).await).into_owned();
    assert!(resp.starts_with("HTTP/1.1 303"), "alice login should redirect 303: {resp}");
    let cookie_pair = resp
        .lines()
        .find_map(|line| {
            let low = line.to_ascii_lowercase();
            if low.starts_with("set-cookie:") {
                let val = line.split_once(':')?.1.trim();
                val.split(';').next().map(str::to_string)
            } else {
                None
            }
        })
        .expect("missing vane_gate_session Set-Cookie");
    assert!(cookie_pair.starts_with("vane_gate_session="));

    // 5. 持 alice 门禁 Cookie 访问 /files -> 200，且不透传 vane_gate_session 给上游、过滤上游伪造 Set-Cookie
    let ok_req = format!(
        "GET /files?page=2 HTTP/1.1\r\nHost: proxy.example.com:{}\r\nCookie: {}; other=1\r\nConnection: close\r\n\r\n",
        proxy.port, cookie_pair
    );
    let resp = String::from_utf8_lossy(&proxy.raw(ok_req.as_bytes(), false).await).into_owned();
    assert!(resp.starts_with("HTTP/1.1 200"), "authenticated request failed: {resp}");
    assert!(resp.contains("ok:/files?page=2"));
    assert!(resp.contains("app_sid=ok"));
    assert!(!resp.contains("vane_gate_session=forged"));

    // 6. 跨规则隔离：alice 的 Cookie 不能访问仅授权给 bob 的 /bob-only
    let cross_req = format!(
        "GET /bob-only HTTP/1.1\r\nHost: proxy.example.com:{}\r\nCookie: {}\r\nConnection: close\r\n\r\n",
        proxy.port, cookie_pair
    );
    let resp = String::from_utf8_lossy(&proxy.raw(cross_req.as_bytes(), false).await).into_owned();
    assert!(resp.starts_with("HTTP/1.1 401"), "alice must not access bob-only rule: {resp}");

    // 7. 同域 WebSocket 直接复用 vane_gate_session Cookie（无需管理态 ticket），且在撤销后自动断开
    let ws_req = format!(
        "GET /ws HTTP/1.1\r\nHost: proxy.example.com:{}\r\nOrigin: https://proxy.example.com:{}\r\nCookie: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        proxy.port, proxy.port, cookie_pair
    );
    let mut socket = proxy.tls(false).await;
    socket.write_all(ws_req.as_bytes()).await.unwrap();
    let ws_head = response_head(&mut socket).await;
    assert!(ws_head.starts_with(b"HTTP/1.1 101"), "WS with gate cookie failed: {}", String::from_utf8_lossy(&ws_head));
    socket
        .write_all(&[0x81, 0x82, 1, 2, 3, 4, b'g' ^ 1, b'o' ^ 2])
        .await
        .unwrap();
    let mut echo = [0; 4];
    tokio::time::timeout(Duration::from_secs(2), socket.read_exact(&mut echo))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(echo, [0x81, 2, b'g', b'o']);

    // 8. POST /_vane_auth/logout 注销会话 -> 清除 Cookie 且已有 WS 连接 3 秒内自动断开
    let logout_req = format!(
        "POST /_vane_auth/logout HTTP/1.1\r\nHost: proxy.example.com:{}\r\nOrigin: https://proxy.example.com:{}\r\nCookie: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        proxy.port, proxy.port, cookie_pair
    );
    let resp = String::from_utf8_lossy(&proxy.raw(logout_req.as_bytes(), false).await).into_owned();
    assert!(resp.starts_with("HTTP/1.1 303"), "logout should redirect 303: {resp}");
    assert!(resp.contains("Max-Age=0"));

    let mut byte = [0];
    let closed = tokio::time::timeout(Duration::from_secs(3), socket.read(&mut byte))
        .await
        .unwrap();
    assert!(closed.is_err() || closed.unwrap() == 0, "WS should close after gate logout");
    drop(socket);

    // 注销后旧 Cookie 失效
    let after_logout = String::from_utf8_lossy(&proxy.raw(ok_req.as_bytes(), false).await).into_owned();
    assert!(after_logout.starts_with("HTTP/1.1 401"));

    proxy.shutdown().await;
    task.abort();
    let _ = task.await;
}

#[test]
fn path_canonicalization_case_insensitive_gate_and_strip_prefix_security() {
    // VANE-H02: 拒绝分号矩阵参数、%3b/%3B 以及 ..;
    for bad in [
        "/admin;jsessionid=1",
        "/admin%3bfoo",
        "/admin%3Bfoo",
        "/x/..;/admin",
        "/..;/admin",
        "/public/%3b/admin",
    ] {
        assert!(!is_canonical_request_path(bad), "expected non-canonical: {bad}");
    }
    assert!(is_canonical_request_path("/api/v2/items"));
    assert!(is_canonical_request_path("/%61pi/v2"));

    // VANE-H02: auth_gate / CIDR 规则大小写不敏感匹配，防止 /Admin 穿透到公开规则 /
    let mut r_root = rule("http://192.168.1.10:8080");
    r_root.path_prefix = "/".into();
    r_root.auth_gate = false;

    let mut r_admin = rule("http://192.168.1.10:8081");
    r_admin.path_prefix = "/admin".into();
    r_admin.auth_gate = true;
    r_admin.strip_prefix = true;

    let mut r_cidr = rule("http://192.168.1.10:8082");
    r_cidr.path_prefix = "/internal".into();
    r_cidr.allowed_cidrs = vec!["192.168.1.0/24".into()];
    r_cidr.strip_prefix = true;

    let mut r_api = rule("http://192.168.1.10:8083");
    r_api.path_prefix = "/api".into();
    r_api.strip_prefix = true;

    let rules = vec![r_root, r_admin.clone(), r_cidr.clone(), r_api.clone()];
    for path in ["/Admin", "/Admin/panel", "/ADMIN/settings", "/%41dmin/panel", "/%61dmin/x"] {
        let matched = match_rule(&rules, "proxy.example.com", path).unwrap();
        assert_eq!(matched.path_prefix, "/admin", "path={path}");
    }
    let matched_cidr = match_rule(&rules, "proxy.example.com", "/Internal/metrics").unwrap();
    assert_eq!(matched_cidr.path_prefix, "/internal");

    // VANE-H02: rewrite_request_path 先分离查询串、归一化路径后再 strip_prefix，并保留原始查询串
    assert_eq!(rewrite_request_path("/%61pi/v2?k=%61&x=1", &r_api), "/v2?k=%61&x=1");
    assert_eq!(rewrite_request_path("/%61pi?foo=bar", &r_api), "/?foo=bar");
    assert_eq!(rewrite_request_path("/Admin/panel?tab=%61", &r_admin), "/panel?tab=%61");
    assert_eq!(rewrite_request_path("/Admin", &r_admin), "/");

    // VANE-L09: 防止相对重定向模板 /{{path}} 遇到 /evil.com 产生 //evil.com 协议相对开放重定向
    let empty_stun = BTreeMap::new();
    let loc = render_redirect_location_safe("/{{path}}", "/evil.com", &empty_stun).unwrap();
    assert!(!loc.starts_with("//"), "protocol-relative open redirect: {loc}");
    assert_eq!(loc, "/evil.com");
    assert!(render_redirect_location_safe("//evil.com{{path}}", "/a", &empty_stun).is_none());
    assert!(render_redirect_location_safe("/{{path}}", "/\\evil.com", &empty_stun).is_none());
}

#[test]
fn upstream_post_dns_safety_blocks_metadata_nat64_and_admin_listeners() {
    let admin: Vec<SocketAddr> = vec!["192.168.50.1:8443".parse().unwrap()];
    for bad in [
        "169.254.169.254:80",
        "[fe80::1]:80",
        "0.0.0.0:8080",
        "0.1.2.3:8080",
        "255.255.255.255:8080",
        "224.0.0.1:8080",
        "[64:ff9b::169.254.169.254]:80",
        "[64:ff9b:1::1]:80",
        "127.0.0.1:22",
        "127.0.0.1:23456",
        "[::1]:23456",
        "192.168.50.1:8443",
        "192.168.50.1:22",
    ] {
        let addr: SocketAddr = bad.parse().unwrap();
        assert!(
            crate::net::proxy_io::validate_upstream_addr(addr, &admin).is_err(),
            "expected upstream blocked: {bad}"
        );
    }
    assert!(crate::net::proxy_io::validate_upstream_addr("192.168.50.2:8080".parse().unwrap(), &admin).is_ok());
    assert!(crate::net::proxy_io::validate_upstream_addr("127.0.0.1:54321".parse().unwrap(), &admin).is_ok());
}

#[tokio::test]
async fn h02_h03_semicolon_case_gate_connection_close_fail2ban_and_h2_idle_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = axum::Router::new().fallback(axum::routing::any(|req: axum::extract::Request| async move {
        format!("uri={}", req.uri())
    }));
    let backend_task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let mut admin_rule = rule(&format!("http://{address}"));
    admin_rule.path_prefix = "/admin".into();
    admin_rule.auth_gate = true;

    let mut api_rule = rule(&format!("http://{address}"));
    api_rule.path_prefix = "/api".into();
    api_rule.strip_prefix = true;

    let mut blocked_rule = rule(&format!("http://{address}"));
    blocked_rule.path_prefix = "/denied".into();
    blocked_rule.denied_cidrs = vec!["127.0.0.1/32".into()];

    let mut root_rule = rule(&format!("http://{address}"));
    root_rule.path_prefix = "/".into();

    // 使用带 Fail2Ban 与短 H2 请求空闲超时的 runtime options
    let _ = rustls::crypto::ring::default_provider().install_default();
    let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = reserved.local_addr().unwrap().port();
    drop(reserved);
    let (_, _, key) = crate::net::tls_resolver::generate_self_signed_cert(&["proxy.example.com".into()]).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(key.cert[0].clone()).unwrap();
    let mut table = CertTable::default();
    table.exact.insert("proxy.example.com".into(), key);

    let cfg = ReverseProxyConfig {
        name: "h02_h03".into(),
        listen_port: port,
        stack: "ipv4_only".into(),
        open_wan_firewall: false,
        rules: vec![admin_rule, api_rule, blocked_rule, root_rule],
        ..Default::default()
    };
    let firewall = FirewallManager::detect_and_init(crate::config::FirewallConfig {
        auto_manage: false,
        ..Default::default()
    })
    .await;
    let f2b = Arc::new(crate::security::fail2ban::Fail2Ban::new());
    let (stop, rx) = watch::channel(false);
    let quota = ConnectionQuota::new(16);
    let opts = ReverseProxyRuntimeOptions::default()
        .with_fail2ban(Some(f2b.clone()))
        .with_h2_idle_timeout(Duration::from_millis(350))
        .with_max_conns_per_peer(4);

    let server = tokio::spawn(run_reverse_proxy_with_runtime_options(
        cfg,
        Arc::new(ArcSwap::from_pointee(table)),
        quota.clone(),
        firewall,
        Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
        rx,
        Arc::new(NoAuthorization),
        opts,
    ));
    let proxy = TestProxy {
        port,
        ipv6: false,
        roots,
        stop,
        server,
        quota,
    };

    // 1. /; /%3b /..; 返回 400，/Admin 命中 auth_gate 返回 401
    for (p, expect) in [
        ("/admin;x", "HTTP/1.1 400"),
        ("/admin%3bx", "HTTP/1.1 400"),
        ("/x/..;/admin", "HTTP/1.1 400"),
        ("/Admin/panel", "HTTP/1.1 401"),
    ] {
        let req = format!("GET {p} HTTP/1.1\r\nHost: proxy.example.com\r\nConnection: close\r\n\r\n");
        let resp = String::from_utf8_lossy(&proxy.raw(req.as_bytes(), false).await).into_owned();
        assert!(resp.starts_with(expect), "{p} -> {resp}");
    }

    // 2. /%61pi/items?q=%61 剥离前缀并转发规范化路径 + 原始查询串
    let resp = String::from_utf8_lossy(
        &proxy
            .raw(
                b"GET /%61pi/items?q=%61 HTTP/1.1\r\nHost: proxy.example.com\r\nConnection: close\r\n\r\n",
                false,
            )
            .await,
    )
    .into_owned();
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(resp.contains("uri=/items?q=%61"), "{resp}");

    // 3. 403 / 421 主动返回 Connection: close 并断开连接（即使客户端未发 Connection: close）
    for (req_raw, expected_code) in [
        (b"GET /denied HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n".as_slice(), "HTTP/1.1 403"),
        (b"GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n".as_slice(), "HTTP/1.1 421"),
    ] {
        let mut s = proxy.tls(false).await;
        s.write_all(req_raw).await.unwrap();
        let mut out = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut out))
            .await
            .unwrap()
            .unwrap();
        let text = String::from_utf8_lossy(&out).to_ascii_lowercase();
        assert!(text.starts_with(&expected_code.to_ascii_lowercase()), "{text}");
        assert!(text.contains("connection: close"), "missing connection: close in {text}");
    }

    // 4. 空闲 H2 连接即使持续发送/应答 PING 也会在请求活跃超时后自动关闭并释放许可
    {
        let socket = proxy.tls(true).await;
        let (mut sender, mut driver) = hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
            .timer(TokioTimer::new())
            .keep_alive_interval(Some(Duration::from_millis(80)))
            .keep_alive_timeout(Duration::from_secs(2))
            .keep_alive_while_idle(true)
            .handshake::<_, http_body_util::Empty<bytes::Bytes>>(TokioIo::new(socket))
            .await
            .unwrap();
        let req = Request::builder()
            .uri("https://proxy.example.com/ok")
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
        let res = tokio::select! {
            r = sender.send_request(req) => r.unwrap(),
            _ = &mut driver => panic!("driver exited before response"),
        };
        assert_eq!(res.status(), StatusCode::OK);
        let _ = res.into_body().collect().await.unwrap();
        // 不再发送任何 HTTP 请求，等待 H2 空闲请求超时触发 GOAWAY / 断链
        let closed = tokio::time::timeout(Duration::from_secs(3), driver).await;
        assert!(closed.is_ok(), "idle H2 connection was not closed despite active PINGs");
    }

    // 5. Fail2Ban 封禁来源在 accept 阶段直接断开，不进入 TLS/HTTP
    let key_v4 = BanKey::from_peer("127.0.0.1".parse().unwrap());
    for _ in 0..3 {
        f2b.record_failure(key_v4, 3, 600, "test_ban");
    }
    assert!(f2b.is_key_banned(key_v4));
    let mut banned_sock = proxy.socket().await;
    let mut probe = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(2), banned_sock.read(&mut probe))
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(n, 0, "banned peer should be closed immediately at accept");

    proxy.shutdown().await;
    backend_task.abort();
    let _ = backend_task.await;
}
