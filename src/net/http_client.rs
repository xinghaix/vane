//! 后台 HTTP 底座：双栈成功优先、严格 TLS、有限正文、全程超时，不自动跟随重定向。
use bytes::Bytes;
use http::{header, HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use std::{collections::BTreeMap, net::SocketAddr, sync::{Arc, OnceLock}, time::Duration};
use tokio::{io::{AsyncRead, AsyncWrite}, sync::Semaphore};

#[derive(Clone, Copy, Default)]
pub enum AddressFamily { #[default] Any, Ipv4, Ipv6 }

#[derive(Clone)]
pub struct HttpClient { tls: Arc<rustls::ClientConfig>, slots: Arc<Semaphore> }

pub struct HttpResponse { pub status: StatusCode, pub headers: HeaderMap, pub body: Vec<u8> }
impl HttpResponse {
    pub fn ensure_success(&self) -> Result<(), String> {
        if self.status.is_success() { Ok(()) } else { Err(format!("远端 HTTP 状态码 {}", self.status.as_u16())) }
    }
    pub fn json(&self) -> Result<serde_json::Value, String> {
        self.ensure_success()?;
        serde_json::from_slice(&self.body).map_err(|_| "远端返回了无效 JSON".into())
    }
}

pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub family: AddressFamily,
    pub timeout: Duration,
    pub response_limit: usize,
    pub happy_eyeballs_delay_ms: u64,
}
impl HttpRequest {
    pub fn new(method: &str, url: &str) -> Self {
        Self { method: method.into(), url: url.into(), headers: BTreeMap::new(), body: Vec::new(),
            family: AddressFamily::Any, timeout: Duration::from_secs(20), response_limit: 1024 * 1024,
            happy_eyeballs_delay_ms: 250 }
    }
    pub fn json(mut self, value: &serde_json::Value) -> Self {
        self.headers.insert("content-type".into(), "application/json".into());
        self.body = value.to_string().into_bytes();
        self
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let native = rustls_native_certs::load_native_certs();
        for cert in native.certs { let _ = roots.add(cert); }
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions().expect("TLS 协议版本")
            .with_root_certificates(roots).with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Self { tls: Arc::new(tls), slots: Arc::new(Semaphore::new(8)) }
    }
}

pub fn shared() -> &'static HttpClient {
    static CLIENT: OnceLock<HttpClient> = OnceLock::new();
    CLIENT.get_or_init(HttpClient::default)
}

impl HttpClient {
    pub(crate) fn tls_config(&self) -> Arc<rustls::ClientConfig> { self.tls.clone() }

    pub async fn execute(&self, spec: HttpRequest) -> Result<HttpResponse, String> {
        let timeout = spec.timeout.clamp(Duration::from_millis(1), Duration::from_secs(300));
        tokio::time::timeout(timeout, self.execute_inner(spec)).await.map_err(|_| "HTTP 请求超时".to_string())?
    }

    async fn execute_inner(&self, spec: HttpRequest) -> Result<HttpResponse, String> {
        let _slot = self.slots.acquire().await.map_err(|_| "HTTP 客户端已关闭")?;
        if spec.url.len() > 8192 || spec.url.contains('#') || spec.body.len() > 1024 * 1024 {
            return Err("请求 URL 或正文超过限制".into());
        }
        let uri: Uri = spec.url.parse().map_err(|_| "非法 HTTP URL")?;
        let scheme = uri.scheme_str().ok_or("URL 缺少协议")?;
        if !matches!(scheme, "http" | "https") { return Err("仅支持 HTTP/HTTPS".into()); }
        let authority = uri.authority().ok_or("URL 缺少主机")?;
        if authority.as_str().contains('@') { return Err("禁止在 URL 用户信息中传递凭据".into()); }
        let host = uri.host().ok_or("URL 缺少主机")?.trim_matches(['[', ']']);
        let port = uri.port_u16().unwrap_or(if scheme == "https" { 443 } else { 80 });
        if port == 0 { return Err("目标端口不能为 0".into()); }
        let method = Method::from_bytes(spec.method.as_bytes()).map_err(|_| "非法 HTTP 方法")?;
        if method == Method::CONNECT { return Err("后台 HTTP 不允许 CONNECT".into()); }
        let mut request = Request::builder().method(method).uri(uri.path_and_query().map(|p| p.as_str()).unwrap_or("/"));
        request = request.header(header::HOST, authority.as_str()).header(header::CONNECTION, "close")
            .header(header::USER_AGENT, concat!("vane/", env!("CARGO_PKG_VERSION")));
        for (name, value) in &spec.headers {
            let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| "非法 HTTP 请求头名称")?;
            if matches!(name.as_str(), "host" | "content-length" | "transfer-encoding" | "connection" | "upgrade" | "proxy-authorization") {
                return Err("禁止覆盖 HTTP 传输控制头".into());
            }
            let value = HeaderValue::from_str(value).map_err(|_| "非法 HTTP 请求头值")?;
            request = request.header(name, value);
        }
        let request = request.body(Full::new(Bytes::from(spec.body))).map_err(|_| "构造 HTTP 请求失败")?;
        let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await.map_err(|_| "DNS 解析失败")?
            .filter(|addr| match spec.family { AddressFamily::Any => true, AddressFamily::Ipv4 => addr.is_ipv4(), AddressFamily::Ipv6 => addr.is_ipv6() })
            .take(32).collect();
        // 交错排列地址族，避免一个地址族的长列表阻塞另一个地址族。
        let (v6, v4): (Vec<_>, Vec<_>) = addresses.into_iter().partition(SocketAddr::is_ipv6);
        let mut ordered = Vec::new();
        for index in 0..v6.len().max(v4.len()) {
            if let Some(addr) = v6.get(index) { ordered.push(*addr); }
            if let Some(addr) = v4.get(index) { ordered.push(*addr); }
        }
        let stream = super::dual_stack::connect_candidates(&ordered, spec.happy_eyeballs_delay_ms).await.map_err(|_| "连接目标服务器失败")?;
        let limit = spec.response_limit.clamp(1, 8 * 1024 * 1024);
        if scheme == "https" {
            let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|_| "非法 TLS 服务器名称")?;
            let stream = tokio_rustls::TlsConnector::from(self.tls.clone()).connect(name, stream).await.map_err(|_| "TLS 握手或证书验证失败")?;
            send(stream, request, limit).await
        } else { send(stream, request, limit).await }
    }
}

// 超时或调用方取消时同步中止连接驱动，不能留下游离后台任务。
struct ConnectionTask(tokio::task::JoinHandle<()>);
impl Drop for ConnectionTask { fn drop(&mut self) { self.0.abort(); } }

async fn send<I>(stream: I, request: Request<Full<Bytes>>, limit: usize) -> Result<HttpResponse, String>
where I: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.map_err(|_| "HTTP 握手失败")?;
    let _connection = ConnectionTask(tokio::spawn(async move { let _ = connection.await; }));
    let response = sender.send_request(request).await.map_err(|_| "HTTP 请求发送或响应头读取失败")?;
    let (parts, mut incoming) = response.into_parts();
    if parts.headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok()).is_some_and(|n| n > limit as u64) {
        return Err("HTTP 响应超过大小限制".into());
    }
    let mut body = Vec::new();
    while let Some(frame) = incoming.frame().await {
        let frame = frame.map_err(|_| "HTTP 响应正文读取失败")?;
        if let Some(data) = frame.data_ref() {
            if data.len() > limit.saturating_sub(body.len()) { return Err("HTTP 响应超过大小限制".into()); }
            body.extend_from_slice(data);
        }
    }
    Ok(HttpResponse { status: parts.status, headers: parts.headers, body })
}

#[cfg(test)]
#[path = "http_client_tests.rs"]
mod tests;
