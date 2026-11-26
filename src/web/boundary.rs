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

fn apply_security_headers(resp: &mut Response, is_api: bool) {
    let headers = resp.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' wss:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
            .parse()
            .unwrap(),
    );
    headers.insert(
        header::HeaderName::from_static("permissions-policy"),
        "camera=(), microphone=(), geolocation=()".parse().unwrap(),
    );
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        "max-age=31536000".parse().unwrap(),
    );
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    headers.insert(header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    headers.insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    if is_api {
        headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    }
}

fn reject(code: &'static str, is_api: bool) -> Response {
    let mut resp = (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": code}))).into_response();
    apply_security_headers(&mut resp, is_api);
    resp
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SecretPathGateDecision {
    Allow { issue_entry_cookie: bool },
    RejectTooManyRequests,
    RejectNotFound { newly_banned: bool },
}

fn evaluate_secret_path_gate(
    path: &str,
    secret_path: &str,
    authorized: bool,
    peer_ban_key: Option<crate::net::dual_stack::BanKey>,
    fail2ban: &crate::security::fail2ban::Fail2Ban,
    max_probe_failures: u32,
    ban_duration_secs: u64,
) -> SecretPathGateDecision {
    let hit_secret_path = path == secret_path
        || path
            .strip_prefix(secret_path)
            .is_some_and(|rest| rest == "/" || rest.starts_with('/'));
    if !authorized {
        if let Some(ban_key) = peer_ban_key {
            // 先执行 Fail2Ban（含表满 Fail-Closed）拦截，再判定是否命中 secret_path，消除路径探测预言机。
            if fail2ban.is_key_blocked(ban_key) {
                return SecretPathGateDecision::RejectTooManyRequests;
            }
            if !hit_secret_path {
                return match fail2ban.record_failure_checked(
                    ban_key,
                    max_probe_failures,
                    ban_duration_secs,
                    "secret_path_probe",
                ) {
                    crate::security::fail2ban::FailureOutcome::NewlyBanned => {
                        SecretPathGateDecision::RejectNotFound { newly_banned: true }
                    }
                    crate::security::fail2ban::FailureOutcome::SaturatedFailClosed => {
                        SecretPathGateDecision::RejectTooManyRequests
                    }
                    crate::security::fail2ban::FailureOutcome::Tracked => {
                        SecretPathGateDecision::RejectNotFound { newly_banned: false }
                    }
                };
            }
        } else if !hit_secret_path {
            return SecretPathGateDecision::RejectNotFound { newly_banned: false };
        }
    }
    SecretPathGateDecision::Allow {
        issue_entry_cookie: hit_secret_path,
    }
}

pub async fn guard(State(state): State<Arc<AppState>>, request: Request, next: Next) -> Response {
    let cfg = state.config.load_full();
    let path = request.uri().path().to_string();
    let is_api = path.starts_with("/api/");
    let headers = request.headers();
    let host = headers.get(header::HOST).and_then(|h| h.to_str().ok());
    let authority = request.uri().authority().map(|a| a.as_str());
    if headers.get_all(header::HOST).iter().count() > 1
        || host.is_none() && authority.is_none()
        || host.is_some_and(|h| !trusted_authority(h, &cfg))
        || authority.is_some_and(|h| !trusted_authority(h, &cfg))
    {
        return reject("UNTRUSTED_HOST", is_api);
    }

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
        return reject("UNTRUSTED_ORIGIN", is_api);
    }
    if (unsafe_method || websocket) && headers.get("sec-fetch-site").is_some_and(|v| v == "cross-site") {
        return reject("CROSS_SITE_REQUEST", is_api);
    }

    let session_scope = super::current_session_scope(&state, headers);

    // 安全入口路径守卫：启用非 "/" 的 secret_path 时，未授权来源先校验 Fail2Ban 返回 429，再核验入口路径，防止封禁态探测与绕过
    let mut issue_entry_cookie: Option<HeaderValue> = None;
    if let Some(sp) = active_secret_path(&cfg) {
        let authorized =
            has_valid_entry_cookie(headers, state.vault.mac_key(), sp) || session_scope.is_some();
        let peer_ban_key = request
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|axum::extract::ConnectInfo(peer)| crate::net::dual_stack::BanKey::from_peer(peer.ip()));
        match evaluate_secret_path_gate(
            &path,
            sp,
            authorized,
            peer_ban_key,
            &state.fail2ban,
            cfg.security.max_login_failures.saturating_mul(2),
            cfg.security.ban_duration_secs,
        ) {
            SecretPathGateDecision::Allow {
                issue_entry_cookie: should_issue,
            } => {
                if should_issue {
                    issue_entry_cookie = build_entry_set_cookie(state.vault.mac_key(), sp);
                }
            }
            SecretPathGateDecision::RejectTooManyRequests => {
                let mut resp = StatusCode::TOO_MANY_REQUESTS.into_response();
                apply_security_headers(&mut resp, is_api);
                return resp;
            }
            SecretPathGateDecision::RejectNotFound { newly_banned } => {
                if newly_banned && cfg.security.kernel_ban_offload {
                    if let Some(ban_key) = peer_ban_key {
                        let kernel_capable = !ban_key.is_loopback_or_link_local()
                            && state.firewall.is_auto_manage()
                            && state.firewall.backend() != crate::firewall::FirewallBackend::DryRun;
                        if state
                            .firewall
                            .ban_source_cidr(&ban_key.display_cidr(), cfg.security.ban_duration_secs)
                            .await
                            .is_ok()
                            && kernel_capable
                        {
                            state.fail2ban.mark_kernel_offloaded(ban_key);
                        }
                    }
                }
                let mut resp = StatusCode::NOT_FOUND.into_response();
                apply_security_headers(&mut resp, is_api);
                return resp;
            }
        }
    }

    // 仅在已建立有效会话后检查模块启用状态与按模块二次验证门禁，防止未认证调用者探测已启用子模块
    if let Some((ref session_token, _)) = session_scope {
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
        if let Some(name) = module {
            if cfg.modules.get(name) != Some(true) {
                return reject("MODULE_DISABLED", is_api);
            }
            // /api/pty/ws 走一次性绑定 ticket；/api/pty/ticket 支持单次 reauth_token 或会话解锁（在 handler 内核验）
            let exempt_pty_auth = path == "/api/pty/ws" || path == "/api/pty/ticket";
            if !exempt_pty_auth && cfg.module_requires_reauth(name) {
                let unlocked = state
                    .auth
                    .lock()
                    .map(|a| a.sessions.is_module_unlocked(session_token, name))
                    .unwrap_or(false);
                if !unlocked {
                    let mut resp = (
                        StatusCode::FORBIDDEN,
                        Json(serde_json::json!({
                            "error": "MODULE_REAUTH_REQUIRED",
                            "module": name,
                            "message": "访问该子模块前需要完成二次身份验证"
                        })),
                    )
                        .into_response();
                    apply_security_headers(&mut resp, is_api);
                    return resp;
                }
            }
        }
    }

    let mut response = next.run(request).await;
    if let Some(cookie) = issue_entry_cookie {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    apply_security_headers(&mut response, is_api);
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

    #[test]
    fn secret_path_gate_blocks_banned_and_saturated_peers_before_path_match() {
        use crate::net::dual_stack::BanKey;
        use crate::security::fail2ban::{Fail2Ban, MAX_TRACKED_KEYS};
        use std::net::{IpAddr, Ipv4Addr};

        let f2b = Fail2Ban::new();
        let sp = "/_vane_secret1234";
        let attacker = BanKey::from_peer(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)));

        // 未封禁前命中真实 secret_path 可放行并签发入口 Cookie
        assert_eq!(
            evaluate_secret_path_gate(sp, sp, false, Some(attacker), &f2b, 3, 600),
            SecretPathGateDecision::Allow { issue_entry_cookie: true }
        );

        // 连续 3 次探测错误路径触发封禁
        assert_eq!(
            evaluate_secret_path_gate("/wrong1", sp, false, Some(attacker), &f2b, 3, 600),
            SecretPathGateDecision::RejectNotFound { newly_banned: false }
        );
        assert_eq!(
            evaluate_secret_path_gate("/wrong2", sp, false, Some(attacker), &f2b, 3, 600),
            SecretPathGateDecision::RejectNotFound { newly_banned: false }
        );
        assert_eq!(
            evaluate_secret_path_gate("/wrong3", sp, false, Some(attacker), &f2b, 3, 600),
            SecretPathGateDecision::RejectNotFound { newly_banned: true }
        );

        // 封禁后即使猜中真实 secret_path，也必须在路径判定前返回 429，消除探测预言机
        assert_eq!(
            evaluate_secret_path_gate(sp, sp, false, Some(attacker), &f2b, 3, 600),
            SecretPathGateDecision::RejectTooManyRequests
        );
        assert_eq!(
            evaluate_secret_path_gate("/wrong4", sp, false, Some(attacker), &f2b, 3, 600),
            SecretPathGateDecision::RejectTooManyRequests
        );

        // 表满（1024 条活跃未卸载封禁）时，新的未授权来源即使命中 secret_path 也 Fail-Closed 返回 429
        let saturated_f2b = Fail2Ban::new();
        for i in 0..MAX_TRACKED_KEYS {
            let k = BanKey::from_peer(IpAddr::V4(Ipv4Addr::new(10, 9, ((i >> 8) & 0xff) as u8, (i & 0xff) as u8)));
            for _ in 0..3 {
                saturated_f2b.record_failure(k, 3, 600, "flood");
            }
        }
        let newcomer = BanKey::from_peer(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 88)));
        assert_eq!(
            evaluate_secret_path_gate(sp, sp, false, Some(newcomer), &saturated_f2b, 3, 600),
            SecretPathGateDecision::RejectTooManyRequests
        );
        // 已持有有效会话或入口 Cookie 的管理员不受表满影响
        assert_eq!(
            evaluate_secret_path_gate("/api/dashboard", sp, true, Some(newcomer), &saturated_f2b, 3, 600),
            SecretPathGateDecision::Allow { issue_entry_cookie: false }
        );
    }
}
