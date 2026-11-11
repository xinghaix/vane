//! 将 instant-acme 协议请求接入共享有界 HTTP 客户端，不启用另一套 TLS 信任策略。
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use instant_acme::{BodyWrapper, BytesResponse, Error, HttpClient};
use std::{future::Future, pin::Pin};

pub struct AcmeTransport;
impl HttpClient for AcmeTransport {
    fn request(
        &self,
        request: http::Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, Error>> + Send>> {
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            if parts.uri.scheme_str() != Some("https") {
                #[cfg(not(test))]
                return Err(Error::Str("ACME endpoints must use HTTPS"));
                #[cfg(test)]
                if !matches!(parts.uri.host(), Some("127.0.0.1") | Some("[::1]")) {
                    return Err(Error::Str("test ACME endpoint is not loopback"));
                }
            }
            let mut spec = crate::net::http_client::HttpRequest::new(
                parts.method.as_str(),
                &parts.uri.to_string(),
            );
            for (key, value) in &parts.headers {
                if matches!(
                    key.as_str(),
                    "host" | "content-length" | "connection" | "user-agent"
                ) {
                    continue;
                }
                spec.headers.insert(
                    key.to_string(),
                    value
                        .to_str()
                        .map_err(|_| Error::Str("invalid ACME header"))?
                        .into(),
                );
            }
            spec.body = body
                .collect()
                .await
                .map_err(|_| Error::Str("invalid ACME body"))?
                .to_bytes()
                .to_vec();
            let response = crate::net::http_client::shared()
                .execute(spec)
                .await
                .map_err(|error| Error::Other(Box::new(std::io::Error::other(error))))?;
            let mut result = http::Response::new(Full::new(Bytes::from(response.body)));
            *result.status_mut() = response.status;
            *result.headers_mut() = response.headers;
            Ok(BytesResponse::from(result))
        })
    }
}
