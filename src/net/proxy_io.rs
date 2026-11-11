//! 流式传输空闲超时与上游 TLS 策略，跳过 PKI 时仍验证 TLS 握手签名。
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
pub type BoxStream = Box<dyn Stream>;

pub struct TimedIo<T> {
    inner: T,
    read: Pin<Box<tokio::time::Sleep>>,
    write: Pin<Box<tokio::time::Sleep>>,
    timeout: Duration,
    read_deadline: bool,
}

impl<T> TimedIo<T> {
    pub fn new(inner: T, timeout: Duration) -> Self {
        Self {
            inner,
            read: Box::pin(tokio::time::sleep(timeout)),
            write: Box::pin(tokio::time::sleep(timeout)),
            timeout,
            read_deadline: true,
        }
    }

    pub fn without_read_deadline(mut self) -> Self {
        self.read_deadline = false;
        self
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for TimedIo<T> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let timeout = self.timeout;
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(result) => {
                if result.is_ok() && buf.filled().len() > before {
                    self.read.as_mut().reset(tokio::time::Instant::now() + timeout);
                }
                Poll::Ready(result)
            }
            Poll::Pending => {
                if self.read_deadline && self.read.as_mut().poll(cx).is_ready() {
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, "读取空闲超时")))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for TimedIo<T> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let timeout = self.timeout;
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(result) => {
                if result.as_ref().is_ok_and(|n| *n > 0) {
                    self.write.as_mut().reset(tokio::time::Instant::now() + timeout);
                }
                Poll::Ready(result)
            }
            Poll::Pending => {
                if self.write.as_mut().poll(cx).is_ready() {
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, "写入空闲超时")))
                } else {
                    Poll::Pending
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => {
                if self.write.as_mut().poll(cx).is_ready() {
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, "刷新写入超时")))
                } else {
                    Poll::Pending
                }
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_shutdown(cx) {
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => {
                if self.write.as_mut().poll(cx).is_ready() {
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, "关闭写入超时")))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

#[derive(Debug)]
struct CertificatePolicy {
    fingerprint: Option<Vec<u8>>,
}

impl ServerCertVerifier for CertificatePolicy {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Some(expected) = &self.fingerprint {
            let actual = ring::digest::digest(&ring::digest::SHA256, cert.as_ref());
            if actual.as_ref() != expected {
                return Err(rustls::Error::General("上游证书指纹不匹配".into()));
            }
            let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref())
                .map_err(|_| rustls::Error::General("上游证书无效".into()))?;
            let now = now.as_secs() as i64;
            if now < parsed.validity().not_before.timestamp() || now >= parsed.validity().not_after.timestamp() {
                return Err(rustls::Error::General("上游固定证书不在有效期内".into()));
            }
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        sig: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            sig,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        sig: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            sig,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub async fn upstream(rule: &crate::config::ReverseProxyRule, uri: &http::Uri) -> Result<BoxStream, String> {
    let scheme = uri.scheme_str().ok_or("上游 URL 缺少协议")?;
    if !matches!(scheme, "http" | "https") || uri.authority().is_none_or(|a| a.as_str().contains('@')) {
        return Err("上游 URL 非法".into());
    }
    let host = uri.host().ok_or("上游主机缺失")?.trim_matches(['[', ']']);
    let port = uri.port_u16().unwrap_or(if scheme == "https" { 443 } else { 80 });
    let target = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let socket = super::dual_stack::connect_happy_eyeballs(&target, 250)
        .await
        .map_err(|_| "上游连接失败")?;
    if scheme == "http" {
        return Ok(Box::new(socket));
    }
    let mut tls = (*super::http_client::shared().tls_config()).clone();
    match rule.upstream_tls_mode.as_str() {
        "strict" => {}
        "pinned_sha256" => {
            let hex = rule.upstream_cert_sha256.replace(':', "");
            if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("上游指纹格式非法".into());
            }
            let fingerprint = (0..64)
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            tls.dangerous()
                .set_certificate_verifier(Arc::new(CertificatePolicy { fingerprint: Some(fingerprint) }));
        }
        "insecure_skip_verify" => {
            tls.dangerous()
                .set_certificate_verifier(Arc::new(CertificatePolicy { fingerprint: None }));
        }
        _ => return Err("上游 TLS 策略非法".into()),
    }
    let sni = if rule.upstream_sni.is_empty() { host } else { &rule.upstream_sni };
    let name = ServerName::try_from(sni.to_string()).map_err(|_| "上游 SNI 非法")?;
    let stream = tokio_rustls::TlsConnector::from(Arc::new(tls))
        .connect(name, socket)
        .await
        .map_err(|_| "上游 TLS 验证或握手失败")?;
    Ok(Box::new(stream))
}
