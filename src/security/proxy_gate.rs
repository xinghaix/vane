//! 反向代理独立访问门禁（完全隔离于 Vane 管理员账号、密码与会话池）。
//! 即使某条反代规则的访问门禁凭据泄露，也绝不会影响 Vane 路由器管理权限或其他未授权反代规则。

use crate::net::dual_stack::BanKey;
use crate::security::auth::SessionStore;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use http::{header, HeaderMap};
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const PROXY_GATE_COOKIE_NAME: &str = "vane_gate_session";
pub const GATE_PORTAL_PREFIX: &str = "/_vane_auth";
pub const GATE_LOGIN_PATH: &str = "/_vane_auth/login";
pub const GATE_LOGOUT_PATH: &str = "/_vane_auth/logout";

const MAX_GATE_SESSIONS: usize = 512;

#[derive(Clone, Debug)]
struct GateSession {
    username: String,
    host: String,
    #[allow(dead_code)]
    peer: BanKey,
    expires_at: Instant,
}

#[derive(Default)]
pub struct ProxyGateStore {
    sessions: Mutex<HashMap<[u8; 32], GateSession>>,
}

impl ProxyGateStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn extract_cookie(headers: &HeaderMap) -> Option<String> {
        for val in headers.get_all(header::COOKIE) {
            let Ok(s) = val.to_str() else { continue };
            for pair in s.split(';') {
                let pair = pair.trim();
                if let Some(tok) = pair.strip_prefix(&format!("{PROXY_GATE_COOKIE_NAME}=")) {
                    let clean = tok.trim();
                    if !clean.is_empty() && clean.len() <= 256 {
                        return Some(clean.to_string());
                    }
                }
            }
        }
        None
    }

    pub fn issue(
        &self,
        username: &str,
        host: &str,
        peer: BanKey,
        ttl: Duration,
    ) -> Result<String, &'static str> {
        let mut raw = [0u8; 32];
        SystemRandom::new()
            .fill(&mut raw)
            .map_err(|_| "生成门禁会话令牌失败")?;
        let token = URL_SAFE_NO_PAD.encode(raw);
        let digest = SessionStore::token_digest(&token);
        let now = Instant::now();
        let ttl = ttl.clamp(Duration::from_secs(300), Duration::from_secs(604_800));
        let mut guard = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        guard.retain(|_, s| s.expires_at > now);
        if guard.len() >= MAX_GATE_SESSIONS {
            if let Some(oldest_key) = guard
                .iter()
                .min_by_key(|(_, s)| s.expires_at)
                .map(|(k, _)| *k)
            {
                guard.remove(&oldest_key);
            }
        }
        guard.insert(
            digest,
            GateSession {
                username: username.to_string(),
                host: host.to_ascii_lowercase(),
                peer,
                expires_at: now + ttl,
            },
        );
        Ok(token)
    }

    /// 严格校验门禁会话：仅当令牌有效、未过期、绑定主机名匹配、用户属于当前规则授权列表且账号仍处于启用态时返回会话摘要。
    pub fn validate_request<F>(
        &self,
        headers: &HeaderMap,
        host: &str,
        allowed_users: &[String],
        is_user_enabled: F,
    ) -> Option<[u8; 32]>
    where
        F: Fn(&str) -> bool,
    {
        if allowed_users.is_empty() {
            return None;
        }
        let token = Self::extract_cookie(headers)?;
        let digest = SessionStore::token_digest(&token);
        let host_low = host.to_ascii_lowercase();
        let now = Instant::now();
        let mut guard = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let sess = guard.get(&digest)?;
        if sess.expires_at <= now {
            guard.remove(&digest);
            return None;
        }
        if sess.host != host_low {
            return None;
        }
        if !allowed_users.iter().any(|u| u == &sess.username) {
            return None;
        }
        if !is_user_enabled(&sess.username) {
            guard.remove(&digest);
            return None;
        }
        Some(digest)
    }

    pub fn session_alive<F>(&self, digest: &[u8; 32], is_user_enabled: F) -> bool
    where
        F: Fn(&str) -> bool,
    {
        let now = Instant::now();
        let mut guard = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let Some(sess) = guard.get(digest) else {
            return false;
        };
        if sess.expires_at <= now || !is_user_enabled(&sess.username) {
            guard.remove(digest);
            return false;
        }
        true
    }

    pub fn revoke_headers(&self, headers: &HeaderMap) {
        if let Some(tok) = Self::extract_cookie(headers) {
            let digest = SessionStore::token_digest(&tok);
            if let Ok(mut guard) = self.sessions.lock() {
                guard.remove(&digest);
            }
        }
    }

    pub fn revoke_user(&self, username: &str) -> usize {
        let Ok(mut guard) = self.sessions.lock() else {
            return 0;
        };
        let before = guard.len();
        guard.retain(|_, s| s.username != username);
        before.saturating_sub(guard.len())
    }

    pub fn revoke_all(&self) {
        if let Ok(mut guard) = self.sessions.lock() {
            guard.clear();
        }
    }

    pub fn active_counts_by_user(&self) -> BTreeMap<String, usize> {
        let now = Instant::now();
        let mut out = BTreeMap::new();
        if let Ok(mut guard) = self.sessions.lock() {
            guard.retain(|_, s| s.expires_at > now);
            for sess in guard.values() {
                *out.entry(sess.username.clone()).or_insert(0) += 1;
            }
        }
        out
    }
}

/// 严格收敛登录成功后的跳转路径，杜绝 Open Redirect 与 /_vane_auth 死循环。
pub fn sanitize_next_path(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || !trimmed.starts_with('/')
        || trimmed.starts_with("//")
        || trimmed.starts_with("/\\")
        || trimmed.contains('\\')
        || trimmed.bytes().any(|b| b < 0x20 || b == 0x7f)
        || trimmed.len() > 2048
    {
        return "/".to_string();
    }
    let path_only = trimmed.split(['?', '#']).next().unwrap_or("/");
    if path_only == GATE_PORTAL_PREFIX || path_only.starts_with(&format!("{GATE_PORTAL_PREFIX}/")) {
        return "/".to_string();
    }
    trimmed.to_string()
}

pub fn percent_encode_query(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            ) {
                out.push(((hi << 4) | lo) as u8);
                i += 3;
                continue;
            }
            out.push(bytes[i]);
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn parse_query_pairs(query: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        if let Some((k, v)) = pair.split_once('=') {
            map.insert(percent_decode(k), percent_decode(v));
        }
    }
    map
}

fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// 渲染独立反代访问门禁登录页（零外部资源、严格 CSP、自适应深浅色、无需 JS 即可提交）。
pub fn render_gate_login_html(host: &str, next: &str, error_msg: Option<&str>) -> String {
    let safe_host = escape_html(host);
    let safe_next = escape_html(&sanitize_next_path(next));
    let err_html = match error_msg {
        Some(msg) if !msg.is_empty() => format!(
            r#"<div class="err" role="alert">{}</div>"#,
            escape_html(msg)
        ),
        _ => String::new(),
    };
    format!(
        r#"<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover" />
<meta name="robots" content="noindex,nofollow" />
<title>访问验证 · {safe_host}</title>
<style>
:root{{color-scheme:light dark;--bg:#f4f4f6;--card:#ffffff;--text:#18181b;--sub:#52525b;--muted:#71717a;--in-bg:#f8f8fa;--in-bd:rgba(0,0,0,.16);--bd:rgba(0,0,0,.08);--ac:#059669;--ac-h:#047857;--ac-s:rgba(5,150,105,.12);--er:#dc2626;--er-s:rgba(220,38,38,.1);--sh:0 20px 50px -16px rgba(15,23,42,.18)}}
@media(prefers-color-scheme:dark){{:root{{--bg:#09090b;--card:#16161a;--text:#f4f4f5;--sub:#a1a1aa;--muted:#71717a;--in-bg:#1e1e24;--in-bd:rgba(255,255,255,.16);--bd:rgba(255,255,255,.09);--ac:#10b981;--ac-h:#059669;--ac-s:rgba(16,185,129,.16);--er:#f87171;--er-s:rgba(248,113,113,.14);--sh:0 20px 50px -12px rgba(0,0,0,.68)}}}}
*{{box-sizing:border-box}}
body{{margin:0;min-height:100dvh;display:grid;place-items:center;padding:20px;background:radial-gradient(circle at 50% 0%,var(--ac-s),transparent 52%),var(--bg);color:var(--text);font:14px/1.5 -apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",system-ui,sans-serif}}
.card{{width:100%;max-width:400px;background:var(--card);border:1px solid var(--bd);border-radius:22px;padding:28px 24px;box-shadow:var(--sh)}}
.head{{display:flex;align-items:center;gap:12px;margin-bottom:18px}}
.ico{{width:40px;height:40px;border-radius:12px;background:var(--ac-s);color:var(--ac);display:grid;place-items:center;flex-shrink:0}}
h1{{margin:0;font-size:17px;font-weight:700}}
.host{{font-size:12px;color:var(--sub);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all;margin-top:2px}}
.note{{font-size:12px;color:var(--sub);margin:0 0 16px;line-height:1.55}}
.err{{background:var(--er-s);color:var(--er);border:1px solid var(--er);border-radius:12px;padding:9px 12px;font-size:12.5px;margin-bottom:14px}}
label{{display:block;font-size:12.5px;font-weight:600;color:var(--sub);margin-bottom:6px}}
.f{{margin-bottom:14px}}
input{{width:100%;min-height:40px;padding:8px 13px;border-radius:12px;border:1px solid var(--in-bd);background:var(--in-bg);color:var(--text);font:inherit;outline:none;transition:border-color .15s,box-shadow .15s}}
input:focus{{border-color:var(--ac);box-shadow:0 0 0 3px var(--ac-s)}}
button{{width:100%;min-height:42px;margin-top:4px;border:none;border-radius:999px;background:var(--ac);color:#fff;font:600 14px/1 inherit;cursor:pointer;transition:background .15s}}
button:hover{{background:var(--ac-h)}}
.foot{{margin-top:14px;text-align:center;font-size:11.5px;color:var(--muted)}}
</style>
</head>
<body>
<main class="card">
  <div class="head">
    <div class="ico" aria-hidden="true">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
    </div>
    <div>
      <h1>访问身份验证</h1>
      <div class="host">{safe_host}</div>
    </div>
  </div>
  <p class="note">此服务受独立访问门禁保护，请使用分配给该服务的专属访问账号登录（与网关管理后台账号完全隔离）。</p>
  {err_html}
  <form method="post" action="{GATE_LOGIN_PATH}">
    <input type="hidden" name="next" value="{safe_next}" />
    <div class="f">
      <label for="u">访问账号</label>
      <input id="u" name="username" type="text" autocomplete="username" required autofocus />
    </div>
    <div class="f">
      <label for="p">访问密码</label>
      <input id="p" name="password" type="password" autocomplete="current-password" required />
    </div>
    <button type="submit">验证并进入</button>
  </form>
  <div class="foot">Protected by Vane Access Gate</div>
</main>
</body>
</html>"#
    )
}

/// 渲染退出确认页（GET 访问 /_vane_auth/logout 时展示，通过同源 POST 完成会话注销，防范跨站注销 CSRF）。
pub fn render_gate_logout_html(host: &str) -> String {
    let safe_host = escape_html(host);
    format!(
        r#"<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover" />
<meta name="robots" content="noindex,nofollow" />
<title>退出登录 · {safe_host}</title>
<style>
:root{{color-scheme:light dark;--bg:#f4f4f6;--card:#ffffff;--text:#18181b;--sub:#52525b;--bd:rgba(0,0,0,.08);--ac:#059669;--er:#dc2626;--er-h:#b91c1c;--sh:0 20px 50px -16px rgba(15,23,42,.18)}}
@media(prefers-color-scheme:dark){{:root{{--bg:#09090b;--card:#16161a;--text:#f4f4f5;--sub:#a1a1aa;--bd:rgba(255,255,255,.09);--ac:#10b981;--er:#ef4444;--er-h:#dc2626;--sh:0 20px 50px -12px rgba(0,0,0,.68)}}}}
*{{box-sizing:border-box}}
body{{margin:0;min-height:100dvh;display:grid;place-items:center;padding:20px;background:var(--bg);color:var(--text);font:14px/1.5 -apple-system,BlinkMacSystemFont,"PingFang SC",system-ui,sans-serif}}
.card{{width:100%;max-width:380px;background:var(--card);border:1px solid var(--bd);border-radius:22px;padding:26px 22px;box-shadow:var(--sh);text-align:center}}
h1{{margin:0 0 6px;font-size:17px}}
.host{{font-size:12px;color:var(--sub);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;margin-bottom:14px;word-break:break-all}}
p{{margin:0 0 18px;font-size:13px;color:var(--sub)}}
button{{width:100%;min-height:40px;border:none;border-radius:999px;background:var(--er);color:#fff;font:600 14px/1 inherit;cursor:pointer;margin-bottom:10px}}
button:hover{{background:var(--er-h)}}
a{{display:inline-block;font-size:13px;color:var(--ac);text-decoration:none;font-weight:600}}
</style>
</head>
<body>
<main class="card">
  <h1>退出访问门禁登录</h1>
  <div class="host">{safe_host}</div>
  <p>退出后将清除本域名下的独立门禁会话，下次访问需重新验证。</p>
  <form method="post" action="{GATE_LOGOUT_PATH}">
    <button type="submit">确认退出登录</button>
  </form>
  <a href="/">返回服务</a>
</main>
</body>
</html>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_next_path_blocks_open_redirects_and_portal_loops() {
        assert_eq!(sanitize_next_path("/files?a=1&b=2"), "/files?a=1&b=2");
        assert_eq!(sanitize_next_path(""), "/");
        assert_eq!(sanitize_next_path("https://evil.com/x"), "/");
        assert_eq!(sanitize_next_path("//evil.com/x"), "/");
        assert_eq!(sanitize_next_path("/\\evil.com"), "/");
        assert_eq!(sanitize_next_path("/_vane_auth/login?next=/"), "/");
        assert_eq!(sanitize_next_path("/_vane_auth/logout"), "/");
        assert_eq!(sanitize_next_path("/ok\r\nSet-Cookie: a=1"), "/");
    }

    #[test]
    fn gate_session_is_host_and_user_isolated_and_revocable() {
        let store = ProxyGateStore::new();
        let peer = BanKey::from_peer("127.0.0.1".parse().unwrap());
        let tok = store
            .issue("family", "photos.example.com", peer, Duration::from_secs(3600))
            .unwrap();
        let mut hdrs = HeaderMap::new();
        hdrs.insert(
            header::COOKIE,
            format!("{PROXY_GATE_COOKIE_NAME}={tok}").parse().unwrap(),
        );

        // 同域名 + 规则已授权该用户 => 通过
        let allowed = vec!["family".to_string()];
        let digest = store
            .validate_request(&hdrs, "photos.example.com", &allowed, |_| true)
            .expect("authorized host & user should pass");
        assert!(store.session_alive(&digest, |_| true));

        // 跨域名（即使同一账号）=> 拒绝
        assert!(store
            .validate_request(&hdrs, "nas.example.com", &allowed, |_| true)
            .is_none());

        // 同域名但当前规则仅授权了别的账号 => 拒绝
        let other = vec!["devops".to_string()];
        assert!(store
            .validate_request(&hdrs, "photos.example.com", &other, |_| true)
            .is_none());

        // 规则未授权任何账号 => 严格 fail-closed 拒绝
        assert!(store
            .validate_request(&hdrs, "photos.example.com", &[], |_| true)
            .is_none());

        // 账号被禁用 => 拒绝并失效
        assert!(!store.session_alive(&digest, |_| false));

        // 吊销指定用户全部会话
        let tok2 = store
            .issue("family", "photos.example.com", peer, Duration::from_secs(3600))
            .unwrap();
        let d2 = SessionStore::token_digest(&tok2);
        assert!(store.session_alive(&d2, |_| true));
        assert_eq!(store.revoke_user("family"), 1);
        assert!(!store.session_alive(&d2, |_| true));
    }
}
