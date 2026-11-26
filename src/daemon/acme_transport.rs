//! 将 instant-acme 协议请求接入共享有界 HTTP 客户端，不启用另一套 TLS 信任策略。
use crate::net::http_client::SsrfPolicy;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use instant_acme::{BodyWrapper, BytesResponse, Error, HttpClient};
use std::{future::Future, pin::Pin};

/// 判断 ACME CA 目录别名或 URL 是否属于内置公共 CA（启用严格 PublicOnly SSRF 策略）
pub fn is_builtin_public_acme_ca(directory: &str) -> bool {
    let trimmed = directory.trim();
    if matches!(
        trimmed,
        "letsencrypt" | "letsencrypt_staging" | "zerossl" | "buypass" | "google"
    ) {
        return true;
    }
    let Ok(uri) = trimmed.parse::<http::Uri>() else {
        return false;
    };
    let Some(host) = uri.host() else {
        return false;
    };
    let host_lc = host.trim_matches(['[', ']']).to_ascii_lowercase();
    matches!(
        host_lc.as_str(),
        "acme-v02.api.letsencrypt.org"
            | "acme-staging-v02.api.letsencrypt.org"
            | "acme.zerossl.com"
            | "api.buypass.com"
            | "dv.acme-v02.api.pki.goog"
    )
}

#[derive(Default)]
pub struct AcmeTransport {
    ssrf_policy: SsrfPolicy,
}

impl AcmeTransport {
    #[allow(dead_code)]
    pub fn new(ssrf_policy: SsrfPolicy) -> Self {
        Self { ssrf_policy }
    }

    pub fn for_directory(directory: &str) -> Self {
        let ssrf_policy = if is_builtin_public_acme_ca(directory) {
            SsrfPolicy::PublicOnly
        } else {
            SsrfPolicy::default()
        };
        Self { ssrf_policy }
    }

    #[allow(dead_code)]
    pub fn ssrf_policy(&self) -> SsrfPolicy {
        self.ssrf_policy
    }
}

impl HttpClient for AcmeTransport {
    fn request(
        &self,
        request: http::Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, Error>> + Send>> {
        let ssrf_policy = self.ssrf_policy;
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
            spec.ssrf_policy = ssrf_policy;
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
