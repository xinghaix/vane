//! 管理请求的可信来源、安全入口路径 (`secret_path`) 与模块边界；不信任代理转发头。
use super::AppState;
use crate::config::{Config, SECRET_PATH_PLACEHOLDER};
use axum::{
    extract::{Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::hmac;
use std::sync::Arc;

pub const ENTRY_COOKIE_NAME: &str = "vane_entry";

/// 固定 HTTPS Origin，拒绝用户信息、查询参数和路径前缀。
pub fn origin_authority(value: &str) -> Option<String> {
    let uri: Uri = value.parse().ok()?;
    let authority = uri.authority()?;
    if uri.scheme_str() != Some("https")
        || authority.as_str().contains('@')
        || uri.query().is_some()
        || !matches!(uri.path(), "" | "/")
    {
        return None;
    }
    if authority.host().is_empty()
        || authority.port_u16() == Some(0)
        || (authority.as_str().contains(':')
            && authority.port_u16().is_none()
            && !authority.as_str().ends_with(']'))
    {
        return None;
    }
    Some(format!(
        "{}:{}",
        authority.host().to_ascii_lowercase(),
        authority.port_u16().unwrap_or(443)
    ))
}

pub fn trusted_authority(authority: &str, cfg: &Config) -> bool {
    let Some(normalized) = origin_authority(&format!("https://{authority}")) else {
        return false;
    };
    origin_authority(&cfg.admin.canonical_origin).as_ref() == Some(&normalized)
        || cfg
            .admin
            .listen_lan
            .iter()
            .any(|address| origin_authority(&format!("https://{address}")).as_ref() == Some(&normalized))
}

pub fn trusted_origin_authority(authority: &str, cfg: &Config) -> bool {
    trusted_authority(authority, cfg)
        || cfg
            .admin
            .extra_allowed_origins
            .iter()
            .any(|origin| origin_authority(origin).as_deref() == Some(authority))
}

pub fn active_secret_path(cfg: &Config) -> Option<&str> {
    let sp = cfg.admin.secret_path.trim();
    if sp.is_empty() || sp == "/" || sp == SECRET_PATH_PLACEHOLDER {
        None
    } else {
        Some(sp)
    }
}

pub fn compute_entry_token(mac_key: &[u8; 32], secret_path: &str) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, mac_key);
    let mut msg = Vec::with_capacity(16 + secret_path.len());
    msg.extend_from_slice(b"vane-entry-v1:");
    msg.extend_from_slice(secret_path.as_bytes());
    let sig = hmac::sign(&key, &msg);
    URL_SAFE_NO_PAD.encode(sig.as_ref())
}

pub fn build_entry_set_cookie(mac_key: &[u8; 32], secret_path: &str) -> Option<HeaderValue> {
    let tok = compute_entry_token(mac_key, secret_path);
    let raw = format!(
        "{}={}; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Strict",
        ENTRY_COOKIE_NAME, tok
    );
    HeaderValue::from_str(&raw).ok()
}

pub fn has_valid_entry_cookie(headers: &HeaderMap, mac_key: &[u8; 32], secret_path: &str) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, mac_key);
    let mut msg = Vec::with_capacity(16 + secret_path.len());
    msg.extend_from_slice(b"vane-entry-v1:");
    msg.extend_from_slice(secret_path.as_bytes());
    for val in headers.get_all(header::COOKIE) {
        let Ok(s) = val.to_str() else { continue };
        for pair in s.split(';') {
            let pair = pair.trim();
            if let Some(tok) = pair.strip_prefix(&format!("{}=", ENTRY_COOKIE_NAME)) {
                if let Ok(raw_tag) = URL_SAFE_NO_PAD.decode(tok.as_bytes()) {
                    if hmac::verify(&key, &msg, &raw_tag).is_ok() {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn reject(code: &'static str) -> Response {
    (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": code}))).into_response()
}

pub async fn guard(State(state): State<Arc<AppState>>, request: Request, next: Next) -> Response {
    let cfg = state.config.load_full();
    let headers = request.headers();
    let host = headers.get(header::HOST).and_then(|h| h.to_str().ok());
    let authority = request.uri().authority().map(|a| a.as_str());
    if headers.get_all(header::HOST).iter().count() > 1
        || host.is_none() && authority.is_none()
        || host.is_some_and(|h| !trusted_authority(h, &cfg))
        || authority.is_some_and(|h| !trusted_authority(h, &cfg))
    {
        return reject("UNTRUSTED_HOST");
    }

    let path = request.uri().path().to_string();
    let unsafe_method = !matches!(*request.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    let websocket = path == "/api/pty/ws";
    let origin = headers.get(header::ORIGIN);
    // 浏览器写请求与 WebSocket 必须携带受信 Origin；命令行调用也需显式提供。
    if headers.get_all(header::ORIGIN).iter().count() > 1
        || (unsafe_method || websocket) && origin.is_none()
        || origin.is_some_and(|o| {
            o.to_str()
                .ok()
                .and_then(origin_authority)
                .is_none_or(|a| !trusted_origin_authority(&a, &cfg))
        })
    {
        return reject("UNTRUSTED_ORIGIN");
    }
    if (unsafe_method || websocket) && headers.get("sec-fetch-site").is_some_and(|v| v == "cross-site") {
        return reject("CROSS_SITE_REQUEST");
    }

    // 安全入口路径守卫：启用非 "/" 的 secret_path 时，未命中入口路径且无有效入口/会话凭据的请求统一返回 404
    let mut issue_entry_cookie: Option<HeaderValue> = None;
    if let Some(sp) = active_secret_path(&cfg) {
        let hit_secret_path = path == sp
            || path
                .strip_prefix(sp)
                .is_some_and(|rest| rest == "/" || rest.starts_with('/'));
        if hit_secret_path {
            issue_entry_cookie = build_entry_set_cookie(state.vault.mac_key(), sp);
        } else {
            let authorized = has_valid_entry_cookie(headers, state.vault.mac_key(), sp)
                || super::current_session_scope(&state, headers).is_some();
            if !authorized {
                return StatusCode::NOT_FOUND.into_response();
            }
        }
    }

    let module = [
        ("/api/proxy/", "reverse_proxy"),
        ("/api/port-forwards/", "port_forward"),
        ("/api/ddns/", "ddns"),
        ("/api/acme/", "acme"),
        ("/api/stun/", "stun"),
        ("/api/cron/", "cron"),
        ("/api/docker/", "docker"),
        ("/api/pty/", "web_terminal"),
    ]
    .into_iter()
    .find(|(prefix, _)| path.starts_with(prefix))
    .map(|(_, name)| name);
    if module.is_some_and(|name| cfg.modules.get(name) != Some(true)) {
        return reject("MODULE_DISABLED");
    }

    let is_api = path.starts_with("/api/");
    let mut response = next.run(request).await;
    let resp_headers = response.headers_mut();
    if let Some(cookie) = issue_entry_cookie {
        resp_headers.append(header::SET_COOKIE, cookie);
    }
    resp_headers.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    resp_headers.insert(header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    resp_headers.insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    if is_api {
        resp_headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_is_strict_https_and_handles_both_ip_families_and_extra_origins() {
        for input in [
            "http://localhost:23456",
            "https://user@host",
            "https://host/path",
            "https://host?query",
            "https://host:0",
            "https://host:65536",
            "null",
        ] {
            assert!(origin_authority(input).is_none(), "{input}");
        }
        assert_eq!(origin_authority("https://[::1]:23456").as_deref(), Some("[::1]:23456"));
        assert_eq!(origin_authority("https://EXAMPLE.com/").as_deref(), Some("example.com:443"));
        let mut cfg = Config::default();
        cfg.admin.listen_lan.push("[::1]:23456".into());
        cfg.admin.extra_allowed_origins.push("https://dev.router.local:5173".into());
        assert!(trusted_authority("[::1]:23456", &cfg));
        assert!(!trusted_authority("dev.router.local:5173", &cfg));
        assert!(trusted_origin_authority("dev.router.local:5173", &cfg));
        assert!(!trusted_authority("192.168.1.1:23457", &cfg));
        assert!(!trusted_authority("192.168.1.1.evil.example:23456", &cfg));
        cfg.admin.canonical_origin = "http://192.168.1.1:23456".into();
        assert!(cfg.validate().is_err());
    }
}
