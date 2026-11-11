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
        let mut buffer = [0;1024];
        stream.read(&mut buffer).await.unwrap();
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
