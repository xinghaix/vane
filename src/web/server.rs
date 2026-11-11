//! 独立管理面 HTTPS 服务：连接配额覆盖嗅探、握手与 WebSocket 生命周期。
use axum::{extract::ConnectInfo, Router};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::{server::{ClientHello, ResolvesServerCert}, sign::CertifiedKey};
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{io::AsyncWriteExt, net::TcpListener, sync::Semaphore, task::JoinSet};
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;

#[derive(Debug)]
struct AdminCertificate(Arc<arc_swap::ArcSwap<CertifiedKey>>);
impl ResolvesServerCert for AdminCertificate {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> { Some(self.0.load_full()) }
}

pub fn tls_config(cert: Arc<CertifiedKey>) -> rustls::ServerConfig {
    tls_config_dynamic(Arc::new(arc_swap::ArcSwap::from(cert)))
}

pub fn tls_config_dynamic(cert: Arc<arc_swap::ArcSwap<CertifiedKey>>) -> rustls::ServerConfig {
    // 管理证书独立于数据面证书池，避免反代更新影响管理面。
    let mut cfg = rustls::ServerConfig::builder().with_no_client_auth()
        .with_cert_resolver(Arc::new(AdminCertificate(cert)));
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    cfg
}

pub fn bind(addr: SocketAddr) -> io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    if addr.is_ipv6() { socket.set_only_v6(true)?; }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    TcpListener::from_std(socket.into())
}

pub async fn serve(listener: TcpListener, app: Router, tls: Arc<rustls::ServerConfig>,
    canonical_origin: String, quota: Arc<Semaphore>, handshake_timeout: Duration,
    header_timeout: Duration) -> io::Result<()> {
    let acceptor = TlsAcceptor::from(tls);
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            Some(_) = connections.join_next(), if !connections.is_empty() => {},
            incoming = listener.accept() => {
                let (mut stream, peer) = incoming?;
                let Ok(permit) = quota.clone().try_acquire_owned() else { continue };
                let acceptor = acceptor.clone();
                let app = app.clone();
                let redirect = format!("HTTP/1.1 308 Permanent Redirect\r\nLocation: {}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", canonical_origin.trim_end_matches('/'));
                connections.spawn(async move {
                    // Arc 克隆交给升级请求，WebSocket 断开之前不释放连接配额。
                    let permit = Arc::new(permit);
                    let mut first = [0u8; 1];
                    if !matches!(tokio::time::timeout(handshake_timeout, stream.peek(&mut first)).await, Ok(Ok(1))) { return; }
                    if first[0] != 0x16 {
                        if matches!(first[0], b'G' | b'H') {
                            let _ = tokio::time::timeout(header_timeout, stream.write_all(redirect.as_bytes())).await;
                        }
                        return;
                    }
                    let Ok(Ok(tls_stream)) = tokio::time::timeout(handshake_timeout, acceptor.accept(stream)).await else { return };
                    let service = service_fn(move |mut req: hyper::Request<Incoming>| {
                        req.extensions_mut().insert(ConnectInfo(peer));
                        req.extensions_mut().insert(permit.clone());
                        app.clone().oneshot(req)
                    });
                    let mut builder = hyper::server::conn::http1::Builder::new();
                    builder.timer(TokioTimer::new()).header_read_timeout(header_timeout).max_buf_size(32 * 1024);
                    let _ = builder.serve_connection(TokioIo::new(tls_stream), service).with_upgrades().await;
                });
            }
        }
    }
}
