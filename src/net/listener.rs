//! 单端口多协议嗅探器（首字节 0x16 识别 TLS Handshake，明文 HTTP 自动返回 308 跳转 HTTPS）与全局连接配额。
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone)]
pub struct ConnectionQuota {
    sem: Arc<Semaphore>,
    cap: usize,
}

impl ConnectionQuota {
    pub fn new(max_conns: usize) -> Self {
        let cap = max_conns.clamp(16, 8192);
        Self { sem: Arc::new(Semaphore::new(cap)), cap }
    }

    pub fn try_acquire(&self) -> Option<OwnedSemaphorePermit> {
        self.sem.clone().try_acquire_owned().ok()
    }

    pub fn active_connections(&self) -> usize {
        self.cap.saturating_sub(self.sem.available_permits())
    }

    pub fn capacity(&self) -> usize {
        self.cap
    }
}

pub enum PeekOutcome {
    Tls,
    PlainHttpRedirected,
}

pub async fn peek_and_redirect_plain_http(
    stream: &mut TcpStream,
    default_https_port: u16,
    header_timeout_secs: u64,
) -> io::Result<PeekOutcome> {
    let mut first = [0u8; 1];
    let n = tokio::time::timeout(
        Duration::from_secs(header_timeout_secs.clamp(2, 30)),
        stream.peek(&mut first),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "首字节读取超时"))??;

    if n == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "空连接"));
    }

    if first[0] == 0x16 {
        return Ok(PeekOutcome::Tls);
    }

    let mut buf = [0u8; 4096];
    let read_n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .unwrap_or(Ok(0))
        .unwrap_or(0);
    let req_str = String::from_utf8_lossy(&buf[..read_n]);
    let mut lines = req_str.lines();
    let path = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .filter(|p| p.starts_with('/'))
        .unwrap_or("/");
    let mut host = lines
        .find(|l| l.len() > 5 && l[..5].eq_ignore_ascii_case("host:"))
        .map(|l| l[5..].trim())
        .unwrap_or("localhost");

    if host.starts_with('[') {
        if let Some(end) = host.find(']') {
            host = &host[..=end];
        }
    } else if let Some((h, _)) = host.split_once(':') {
        host = h;
    }

    let location = if default_https_port == 443 {
        format!("https://{}{}", host, path)
    } else {
        format!("https://{}:{}{}", host, default_https_port, path)
    };

    let resp = format!(
        "HTTP/1.1 308 Permanent Redirect\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        location
    );
    let _ = stream.write_all(resp.as_bytes()).await;
    let _ = stream.shutdown().await;
    Ok(PeekOutcome::PlainHttpRedirected)
}
