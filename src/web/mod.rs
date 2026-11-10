//! Web 管理后台：全程 HTTPS / 局域网监听、单管理员三合一认证、强制首次修改初始密码硬门禁、
//! 敏感配置自动脱敏与 AEAD 加密落盘、.br/.gz 预压缩静态直出与 PWA 支持。
pub mod ws_pty;

use crate::config::{save_config, Config, Ed25519KeyEntry, ModulesConfig};
use crate::daemon::acme::{issue_or_renew_cert, CertStatus};
use crate::daemon::cron::execute_cron_job;
use crate::daemon::ddns::{sync_ddns_entry, DdnsStatusMap};
use crate::daemon::notify::dispatch_notification;
use crate::docker::unix_client::{container_action, container_logs, list_containers, prune_dangling_images};
use crate::firewall::FirewallManager;
use crate::logger::{self, Level};
use crate::monitor::procfs::collect_snapshot;
use crate::net::dual_stack::BanKey;
use crate::net::listener::ConnectionQuota;
use crate::net::stun::{format_public_endpoint, probe_stun_once};
use crate::net::tls_resolver::CertTable;
use crate::security::auth::{
    base32_decode, base32_encode, generate_recovery_codes, generate_totp_secret, normalize_ed25519_pubkey,
    normalize_recovery_code, otpauth_uri, parse_openssh_ed25519, AuthEngine, AuthState, HashGate, PasswordHash,
    SessionScope,
};
use crate::security::fail2ban::Fail2Ban;
use crate::security::vault::Vault;
use crate::supervisor::HealthRegistry;
use crate::web::ws_pty::{handle_pty_websocket, PtyManager};
use arc_swap::ArcSwap;
use axum::body::Body;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{header, HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rust_embed::RustEmbed;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::sync::Notify;

#[derive(RustEmbed)]
#[folder = "web-ui/dist/"]
struct WebAssets;

pub const SESSION_COOKIE_NAME: &str = "vane_session";

pub struct AppState {
    pub config_path: PathBuf,
    pub config: Arc<ArcSwap<Config>>,
    pub vault: Arc<Vault>,
    pub auth: Mutex<AuthState>,
    pub hash_gate: Arc<HashGate>,
    pub fail2ban: Arc<Fail2Ban>,
    pub firewall: Arc<FirewallManager>,
    pub health_registry: HealthRegistry,
    pub ddns_status: DdnsStatusMap,
    pub cert_table: Arc<ArcSwap<CertTable>>,
    pub cert_status: RwLock<BTreeMap<String, CertStatus>>,
    pub stun_addrs: Arc<ArcSwap<BTreeMap<String, String>>>,
    pub global_quota: ConnectionQuota,
    pub pty_mgr: Arc<PtyManager>,
    pub reload_notify: Arc<Notify>,
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/auth/status", get(api_auth_status))
        .route("/api/auth/login", post(api_auth_login))
        .route("/api/auth/logout", post(api_auth_logout))
        .route("/api/auth/change-password", post(api_auth_change_password))
        .route("/api/auth/challenge", post(api_auth_challenge))
        .route("/api/auth/login-ed25519", post(api_auth_login_ed25519))
        .route("/api/auth/totp/setup", post(api_totp_setup))
        .route("/api/auth/totp/enable", post(api_totp_enable))
        .route("/api/auth/totp/disable", post(api_totp_disable))
        .route("/api/auth/ed25519/keys", post(api_add_ed25519_key))
        .route("/api/auth/ed25519/keys/{id}", delete(api_delete_ed25519_key))
        .route("/api/dashboard", get(api_dashboard))
        .route("/api/logs", get(api_get_logs).delete(api_clear_logs))
        .route("/api/settings", get(api_get_settings).put(api_put_settings))
        .route("/api/modules", put(api_put_modules))
        .route("/api/port-forwards/{name}/lease", post(api_port_forward_lease))
        .route("/api/ddns/{name}/sync", post(api_ddns_sync))
        .route("/api/acme/{domain}/issue", post(api_acme_issue))
        .route("/api/stun/{name}/probe", post(api_stun_probe))
        .route("/api/cron/{name}/run", post(api_cron_run))
        .route("/api/notifications/{name}/test", post(api_notification_test))
        .route("/api/docker/containers", get(api_docker_containers))
        .route("/api/docker/containers/{id}/logs", get(api_docker_logs))
        .route("/api/docker/containers/{id}/{action}", post(api_docker_action))
        .route("/api/docker/prune", post(api_docker_prune))
        .route("/api/security/bans", get(api_list_bans))
        .route("/api/security/bans/{ip}", delete(api_unban_ip))
        .route("/api/firewall/lockdown", post(api_firewall_lockdown))
        .route("/api/backup/export", post(api_backup_export))
        .route("/api/backup/import", post(api_backup_import))
        .route("/api/pty/ticket", post(api_pty_ticket))
        .route("/api/pty/ws", get(api_pty_ws))
        .route("/manifest.webmanifest", get(serve_manifest))
        .route("/sw.js", get(serve_sw))
        .fallback(serve_static_or_spa)
        .with_state(state)
}

fn extract_session_token(headers: &HeaderMap) -> Option<String> {
    for val in headers.get_all(header::COOKIE) {
        let Ok(s) = val.to_str() else { continue };
        for pair in s.split(';') {
            let pair = pair.trim();
            if let Some(tok) = pair.strip_prefix(&format!("{}=", SESSION_COOKIE_NAME)) {
                if !tok.is_empty() {
                    return Some(tok.to_string());
                }
            }
        }
    }
    None
}

fn current_session_scope(state: &AppState, headers: &HeaderMap) -> Option<(String, SessionScope)> {
    let token = extract_session_token(headers)?;
    let cfg = state.config.load();
    let ttl = Duration::from_secs(cfg.admin.session_ttl_secs.clamp(300, 86_400));
    let mut auth = state.auth.lock().ok()?;
    let sess = auth.sessions.validate(&token, ttl)?;
    // 双重硬校验：即使会话曾经是 FullAdmin，若配置被重置为 must_change_password 或密码仍是 admin321，立即降级为 MustChangePassword
    let effective_scope = if let Some(ph) = PasswordHash::parse(&cfg.admin.password_hash) {
        let resolved = AuthEngine::resolve_session_scope(cfg.admin.must_change_password, &ph.salt, &ph.hash, ph.iters);
        if resolved == SessionScope::MustChangePassword {
            SessionScope::MustChangePassword
        } else {
            sess.scope
        }
    } else {
        SessionScope::MustChangePassword
    };
    Some((token, effective_scope))
}

/// 校验 FullAdmin 权限：未登录返回 401；处于 MustChangePassword 硬步骤改密状态返回 403 MUST_CHANGE_INITIAL_PASSWORD
fn require_full_admin(state: &AppState, headers: &HeaderMap) -> Result<String, Response> {
    match current_session_scope(state, headers) {
        Some((tok, SessionScope::FullAdmin)) => Ok(tok),
        Some((_, SessionScope::MustChangePassword)) => Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "MUST_CHANGE_INITIAL_PASSWORD",
                "message": "初次登录必须先修改默认密码 (admin321)，禁止跳过进入管理页面"
            })),
        )
            .into_response()),
        None => Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "UNAUTHORIZED", "message": "登录态已过期，请重新登录" })),
        )
            .into_response()),
    }
}

fn require_any_session(state: &AppState, headers: &HeaderMap) -> Result<(String, SessionScope), Response> {
    current_session_scope(state, headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "UNAUTHORIZED", "message": "请先登录" })),
        )
            .into_response()
    })
}

fn peer_ip(headers: &HeaderMap) -> IpAddr {
    headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<IpAddr>().ok())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

async fn api_auth_status(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let cfg = state.config.load();
    let session = current_session_scope(&state, &headers);
    let authenticated = session.is_some();
    let must_change_password = match session {
        Some((_, scope)) => scope == SessionScope::MustChangePassword,
        None => cfg.admin.must_change_password,
    };
    Json(serde_json::json!({
        "authenticated": authenticated,
        "username": cfg.admin.username,
        "must_change_password": must_change_password,
        "password_login_enabled": cfg.admin.password_login_enabled,
        "totp_enabled": cfg.admin.totp_enabled,
        "has_ed25519_keys": !cfg.admin.authorized_ed25519_keys.is_empty(),
        "ed25519_key_ids": cfg.admin.authorized_ed25519_keys.iter().map(|k| &k.id).collect::<Vec<_>>(),
        "session_ttl_secs": cfg.admin.session_ttl_secs,
        "modules": cfg.modules,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
    #[serde(default)]
    totp_code: String,
}

async fn api_auth_login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Response {
    let ip = peer_ip(&headers);
    let ban_key = BanKey::from_peer(ip);
    if state.fail2ban.is_key_banned(ban_key) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({ "error": "IP_BANNED", "message": "认证失败次数过多，该网络已被临时封禁" })),
        )
            .into_response();
    }

    let cfg = state.config.load();
    if !cfg.admin.password_login_enabled {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "PASSWORD_LOGIN_DISABLED", "message": "当前已配置为仅允许 Ed25519 密钥登录" })),
        )
            .into_response();
    }
    if req.username.trim() != cfg.admin.username {
        on_login_failed(&state, ban_key).await;
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "INVALID_CREDENTIALS", "message": "用户名或密码错误" })),
        )
            .into_response();
    }

    let Some(ph) = PasswordHash::parse(&cfg.admin.password_hash) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "密码哈希未初始化" }))).into_response();
    };
    let pw_bytes = req.password.into_bytes();
    let ph_clone = ph.clone();
    let must_change_flag = cfg.admin.must_change_password;
    let Ok((pw_ok, scope)) = state
        .hash_gate
        .run(move || {
            let ok = ph_clone.verify(&pw_bytes);
            let sc = AuthEngine::resolve_session_scope(must_change_flag, &ph_clone.salt, &ph_clone.hash, ph_clone.iters);
            (ok, sc)
        })
        .await
    else {
        return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({ "error": "认证繁忙" }))).into_response();
    };

    if !pw_ok {
        on_login_failed(&state, ban_key).await;
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "INVALID_CREDENTIALS", "message": "用户名或密码错误" })),
        )
            .into_response();
    }

    // 若启用了 TOTP，在同一互斥锁内校验防回退重放
    if cfg.admin.totp_enabled {
        let Ok(totp_plain) = state.vault.reveal_string("admin.totp_secret", &cfg.admin.totp_secret) else {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "TOTP 密钥解密失败" }))).into_response();
        };
        let secret_bytes = base32_decode(&totp_plain).unwrap_or_default();
        let code_trim = req.totp_code.trim();
        let totp_ok = if let Ok(code_num) = code_trim.parse::<u32>() {
            let mut auth = state.auth.lock().unwrap();
            auth.engine.verify_totp(&secret_bytes, code_num, logger::unix_now())
        } else {
            // 检查是否为一次性恢复码
            let norm = normalize_recovery_code(code_trim);
            cfg.admin.totp_recovery_hashes.iter().any(|h| PasswordHash::parse(h).is_some_and(|p| p.verify(norm.as_bytes())))
        };
        if !totp_ok {
            on_login_failed(&state, ban_key).await;
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "INVALID_TOTP", "message": "TOTP 动态验证码错误或已重放使用" })),
            )
                .into_response();
        }
    }

    state.fail2ban.record_success(ban_key);
    let ttl = Duration::from_secs(cfg.admin.session_ttl_secs.clamp(300, 86_400));
    let token = {
        let mut auth = state.auth.lock().unwrap();
        match auth.sessions.issue(scope, ban_key, ttl) {
            Ok(t) => t,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response(),
        }
    };

    logger::log(Level::Info, "auth", &format!("管理员登录成功 (ip={}, must_change_password={})", ip, scope == SessionScope::MustChangePassword));
    build_session_response(&token, ttl.as_secs(), scope == SessionScope::MustChangePassword, &cfg)
}

fn build_session_response(token: &str, ttl_secs: u64, must_change: bool, cfg: &Config) -> Response {
    let cookie = format!(
        "{}={}; Path=/; Max-Age={}; HttpOnly; SameSite=Strict",
        SESSION_COOKIE_NAME, token, ttl_secs
    );
    let body = serde_json::json!({
        "authenticated": true,
        "username": cfg.admin.username,
        "must_change_password": must_change,
        "totp_enabled": cfg.admin.totp_enabled,
        "session_ttl_secs": cfg.admin.session_ttl_secs,
        "modules": cfg.modules,
    });
    let mut resp = Json(body).into_response();
    if let Ok(hv) = header::HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    resp
}

async fn on_login_failed(state: &AppState, ban_key: BanKey) {
    let cfg = state.config.load();
    if state.fail2ban.record_failure(ban_key, cfg.security.max_login_failures, cfg.security.ban_duration_secs, "login_failed") {
        let cidr = ban_key.display_cidr();
        logger::log(Level::Warn, "fail2ban", &format!("源网络 {} 连续认证失败，已封禁 {}s", cidr, cfg.security.ban_duration_secs));
        if cfg.security.kernel_ban_offload {
            let _ = state.firewall.ban_source_cidr(&cidr, cfg.security.ban_duration_secs).await;
        }
    }
}

async fn api_auth_logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(tok) = extract_session_token(&headers) {
        if let Ok(mut auth) = state.auth.lock() {
            auth.sessions.revoke(&tok);
        }
    }
    let mut resp = Json(serde_json::json!({ "ok": true })).into_response();
    if let Ok(hv) = header::HeaderValue::from_str(&format!("{}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict", SESSION_COOKIE_NAME)) {
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    resp
}

#[derive(Deserialize)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
    #[serde(default)]
    new_username: String,
}

async fn api_auth_change_password(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ChangePasswordRequest>,
) -> Response {
    let (_old_tok, _) = match require_any_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let cfg_snap = state.config.load();
    let Some(ph) = PasswordHash::parse(&cfg_snap.admin.password_hash) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "密码未初始化" }))).into_response();
    };

    let target_username = if req.new_username.trim().is_empty() {
        cfg_snap.admin.username.clone()
    } else {
        req.new_username.trim().to_string()
    };
    if let Err(e) = crate::config::validate_username(&target_username) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e, "message": e }))).into_response();
    }

    let cur_pw = req.current_password.into_bytes();
    let new_pw = req.new_password.into_bytes();
    let uname_bytes = target_username.clone().into_bytes();
    let ph_clone = ph.clone();

    let res = state
        .hash_gate
        .run(move || -> Result<PasswordHash, &'static str> {
            if !ph_clone.verify(&cur_pw) {
                return Err("原密码错误");
            }
            AuthEngine::validate_new_password(&new_pw, &uname_bytes, &ph_clone.salt, &ph_clone.hash, ph_clone.iters)?;
            PasswordHash::create(&new_pw)
        })
        .await;

    let new_hash = match res {
        Ok(Ok(h)) => h,
        Ok(Err(msg)) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "INVALID_PASSWORD", "message": msg }))).into_response();
        }
        Err(msg) => {
            return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({ "error": msg, "message": msg }))).into_response();
        }
    };

    let mut next_cfg = (**cfg_snap).clone();
    next_cfg.admin.username = target_username;
    next_cfg.admin.password_hash = new_hash.encode();
    next_cfg.admin.must_change_password = false;
    if let Err(e) = save_config(&state.config_path, &next_cfg) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e, "message": e }))).into_response();
    }
    state.config.store(Arc::new(next_cfg.clone()));

    // 密码变更后清空所有旧会话并签发全新 FullAdmin 会话
    let ban_key = BanKey::from_peer(peer_ip(&headers));
    let ttl = Duration::from_secs(next_cfg.admin.session_ttl_secs.clamp(300, 86_400));
    let new_token = {
        let mut auth = state.auth.lock().unwrap();
        auth.sessions.revoke_all();
        auth.sessions.issue(SessionScope::FullAdmin, ban_key, ttl).unwrap_or_default()
    };
    logger::log(Level::Info, "auth", "管理员密码已成功修改并完成原子落盘，已解锁完整管理权限");
    build_session_response(&new_token, ttl.as_secs(), false, &next_cfg)
}

#[derive(Deserialize)]
struct ChallengeReq {
    key_id: String,
}

async fn api_auth_challenge(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ChallengeReq>,
) -> Response {
    let cfg = state.config.load();
    if !cfg.admin.authorized_ed25519_keys.iter().any(|k| k.id == req.key_id) {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "未找到指定的公钥 ID" }))).into_response();
    }
    let client_key = BanKey::from_peer(peer_ip(&headers));
    let rng = ring::rand::SystemRandom::new();
    let mut auth = state.auth.lock().unwrap();
    match auth.engine.issue_challenge(&rng, req.key_id, client_key) {
        Ok(nonce) => Json(serde_json::json!({
            "nonce_b64": B64.encode(nonce),
            "canonical_origin": auth.engine.canonical_origin(),
        }))
        .into_response(),
        Err(e) => (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({ "error": e }))).into_response(),
    }
}

#[derive(Deserialize)]
struct Ed25519LoginReq {
    key_id: String,
    nonce_b64: String,
    signature_b64: String,
}

async fn api_auth_login_ed25519(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<Ed25519LoginReq>,
) -> Response {
    let ip = peer_ip(&headers);
    let client_key = BanKey::from_peer(ip);
    if state.fail2ban.is_key_banned(client_key) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({ "error": "IP_BANNED" }))).into_response();
    }
    let cfg = state.config.load();
    let Some(entry) = cfg.admin.authorized_ed25519_keys.iter().find(|k| k.id == req.key_id) else {
        on_login_failed(&state, client_key).await;
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "公钥不存在" }))).into_response();
    };
    let Some(raw_pk) = parse_openssh_ed25519(&entry.pubkey) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "公钥格式错误" }))).into_response();
    };
    let Ok(nonce_vec) = B64.decode(req.nonce_b64.trim()) else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "nonce 编码错误" }))).into_response();
    };
    let Ok(nonce): Result<[u8; 32], _> = nonce_vec.try_into() else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "nonce 长度错误" }))).into_response();
    };
    let Ok(sig) = B64.decode(req.signature_b64.trim()) else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "签名编码错误" }))).into_response();
    };

    let verified = {
        let mut auth = state.auth.lock().unwrap();
        auth.engine.verify_ed25519_challenge(&nonce, &req.key_id, client_key, &sig, &raw_pk)
    };
    if !verified {
        on_login_failed(&state, client_key).await;
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "Ed25519 挑战签名验证失败" }))).into_response();
    }

    state.fail2ban.record_success(client_key);
    let scope = if cfg.admin.must_change_password {
        SessionScope::MustChangePassword
    } else {
        SessionScope::FullAdmin
    };
    let ttl = Duration::from_secs(cfg.admin.session_ttl_secs.clamp(300, 86_400));
    let token = {
        let mut auth = state.auth.lock().unwrap();
        auth.sessions.issue(scope, client_key, ttl).unwrap_or_default()
    };
    build_session_response(&token, ttl.as_secs(), scope == SessionScope::MustChangePassword, &cfg)
}

async fn api_totp_setup(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let Ok(secret) = generate_totp_secret() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "生成密钥失败" }))).into_response();
    };
    let b32 = base32_encode(&secret);
    let cfg = state.config.load();
    let uri = otpauth_uri(&b32, &cfg.admin.username, "Vane Gateway");
    if let Ok(mut auth) = state.auth.lock() {
        auth.pending_totp_secret = Some((secret, std::time::Instant::now()));
    }
    Json(serde_json::json!({ "secret_base32": b32, "otpauth_uri": uri })).into_response()
}

#[derive(Deserialize)]
struct TotpEnableReq {
    code: String,
}

async fn api_totp_enable(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<TotpEnableReq>,
) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let Ok(code_num) = req.code.trim().parse::<u32>() else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "请输入 6 位数字验证码" }))).into_response();
    };
    let secret_opt = {
        let mut auth = state.auth.lock().unwrap();
        if let Some((sec, _)) = auth.pending_totp_secret.clone() {
            if auth.engine.verify_totp(&sec, code_num, logger::unix_now()) {
                auth.pending_totp_secret = None;
                Some(sec)
            } else {
                None
            }
        } else {
            None
        }
    };
    let Some(secret) = secret_opt else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "TOTP 验证码错误或已过期" }))).into_response();
    };
    let recovery_codes = generate_recovery_codes(6).unwrap_or_default();
    let recovery_hashes: Vec<String> = recovery_codes
        .iter()
        .filter_map(|c| PasswordHash::create_with_iters(normalize_recovery_code(c).as_bytes(), 100_000).ok().map(|h| h.encode()))
        .collect();

    let mut next_cfg = (**state.config.load()).clone();
    next_cfg.admin.totp_enabled = true;
    next_cfg.admin.totp_secret = state
        .vault
        .seal("admin.totp_secret", base32_encode(&secret).as_bytes())
        .unwrap_or_default();
    next_cfg.admin.totp_recovery_hashes = recovery_hashes;
    if let Err(e) = save_config(&state.config_path, &next_cfg) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response();
    }
    state.config.store(Arc::new(next_cfg));
    Json(serde_json::json!({ "enabled": true, "recovery_codes": recovery_codes })).into_response()
}

async fn api_totp_disable(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let mut next_cfg = (**state.config.load()).clone();
    next_cfg.admin.totp_enabled = false;
    next_cfg.admin.totp_secret.clear();
    next_cfg.admin.totp_recovery_hashes.clear();
    let _ = save_config(&state.config_path, &next_cfg);
    state.config.store(Arc::new(next_cfg));
    Json(serde_json::json!({ "enabled": false })).into_response()
}

async fn api_add_ed25519_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(entry): Json<Ed25519KeyEntry>,
) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let Some((norm_pub, _)) = normalize_ed25519_pubkey(&entry.pubkey, &entry.id) else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "公钥格式非法（需 ssh-ed25519 AAAA...）" }))).into_response();
    };
    let mut next_cfg = (**state.config.load()).clone();
    next_cfg.admin.authorized_ed25519_keys.retain(|k| k.id != entry.id);
    next_cfg.admin.authorized_ed25519_keys.push(Ed25519KeyEntry { id: entry.id, pubkey: norm_pub });
    if let Err(e) = next_cfg.validate().and_then(|_| save_config(&state.config_path, &next_cfg)) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response();
    }
    state.config.store(Arc::new(next_cfg.clone()));
    Json(serde_json::json!({ "keys": next_cfg.admin.authorized_ed25519_keys })).into_response()
}

async fn api_delete_ed25519_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let mut next_cfg = (**state.config.load()).clone();
    next_cfg.admin.authorized_ed25519_keys.retain(|k| k.id != id);
    if next_cfg.admin.authorized_ed25519_keys.is_empty() {
        next_cfg.admin.password_login_enabled = true;
    }
    let _ = save_config(&state.config_path, &next_cfg);
    state.config.store(Arc::new(next_cfg.clone()));
    Json(serde_json::json!({ "keys": next_cfg.admin.authorized_ed25519_keys })).into_response()
}

async fn api_dashboard(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let cfg = state.config.load();
    let sys = collect_snapshot(&cfg.monitor);
    let health = state.health_registry.read().map(|g| g.clone()).unwrap_or_default();
    let ddns = state.ddns_status.read().map(|g| g.values().cloned().collect::<Vec<_>>()).unwrap_or_default();
    let certs = state.cert_status.read().map(|g| g.values().cloned().collect::<Vec<_>>()).unwrap_or_default();
    let stun = (**state.stun_addrs.load()).clone();
    let fw_rules = state.firewall.list_rules();
    let bans = state.fail2ban.list_active_bans();

    Json(serde_json::json!({
        "system": sys,
        "modules": cfg.modules,
        "module_health": health,
        "active_connections": state.global_quota.active_connections(),
        "max_connections": state.global_quota.capacity(),
        "firewall": {
            "backend": state.firewall.backend(),
            "lockdown": state.firewall.is_lockdown(),
            "rules": fw_rules,
        },
        "ddns": ddns,
        "certs": certs,
        "stun_public_addrs": stun,
        "bans": bans,
    }))
    .into_response()
}

async fn api_get_logs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let min_level = q.get("level").and_then(|s| Level::parse(s));
    let module = q.get("module").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let entries = logger::global().query(min_level, module, 500, 0);
    Json(serde_json::json!({ "entries": entries })).into_response()
}

async fn api_clear_logs(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    logger::global().clear();
    Json(serde_json::json!({ "ok": true })).into_response()
}

async fn api_get_settings(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let cfg = state.config.load();
    Json(state.vault.masked_config_json(&cfg)).into_response()
}

async fn api_put_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(mut incoming_json): Json<serde_json::Value>,
) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    crate::security::vault::normalize_masked_input(&mut incoming_json);
    let current_cfg = state.config.load();
    let mut next_cfg: Config = match serde_json::from_value(incoming_json) {
        Ok(c) => c,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": format!("配置格式错误: {}", e) }))).into_response(),
    };
    // 保持 password_hash 与 totp 状态不被普通设置表单清空
    next_cfg.admin.password_hash = current_cfg.admin.password_hash.clone();
    next_cfg.admin.must_change_password = current_cfg.admin.must_change_password;
    next_cfg.admin.totp_last_step = current_cfg.admin.totp_last_step;
    next_cfg.admin.totp_recovery_hashes = current_cfg.admin.totp_recovery_hashes.clone();

    if let Err(e) = state.vault.merge_secrets(&mut next_cfg, &current_cfg, None) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response();
    }
    if let Err(e) = next_cfg.validate() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response();
    }
    if let Err(e) = save_config(&state.config_path, &next_cfg) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response();
    }
    logger::global().set_capacity(next_cfg.system.log_ring_capacity);
    state.firewall.update_config(next_cfg.firewall.clone());
    state.config.store(Arc::new(next_cfg.clone()));
    state.reload_notify.notify_waiters();
    logger::log(Level::Info, "config", "配置已在 Web 设置页更新并热生效");
    Json(state.vault.masked_config_json(&next_cfg)).into_response()
}

async fn api_put_modules(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(modules): Json<ModulesConfig>,
) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let mut next_cfg = (**state.config.load()).clone();
    let prev_modules = next_cfg.modules.clone();
    next_cfg.modules = modules.clone();
    if let Err(e) = save_config(&state.config_path, &next_cfg) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response();
    }
    // 对被关闭的模块立即撤销其关联的防火墙规则
    if prev_modules.reverse_proxy && !modules.reverse_proxy {
        let _ = state.firewall.remove_module_rules("reverse_proxy").await;
    }
    if prev_modules.port_forward && !modules.port_forward {
        let _ = state.firewall.remove_module_rules("port_forward").await;
    }
    if prev_modules.ddns && !modules.ddns {
        let _ = state.firewall.remove_module_rules("ddns").await;
    }
    state.config.store(Arc::new(next_cfg));
    state.reload_notify.notify_waiters();
    logger::log(Level::Info, "modules", &format!("子功能模块开关已更新: {:?}", modules));
    Json(serde_json::json!({ "modules": modules })).into_response()
}

#[derive(Deserialize)]
struct LeaseReq {
    minutes: u64,
}

async fn api_port_forward_lease(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(name): AxumPath<String>,
    Json(req): Json<LeaseReq>,
) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let mut next_cfg = (**state.config.load()).clone();
    let Some(pf) = next_cfg.port_forwards.iter_mut().find(|p| p.name == name) else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "转发规则不存在" }))).into_response();
    };
    if req.minutes == 0 {
        pf.expire_at_unix = 0;
    } else {
        pf.enabled = true;
        pf.expire_at_unix = logger::unix_now() + req.minutes.clamp(1, 1440) * 60;
    }
    let exp = pf.expire_at_unix;
    let _ = save_config(&state.config_path, &next_cfg);
    state.config.store(Arc::new(next_cfg));
    state.reload_notify.notify_waiters();
    Json(serde_json::json!({ "name": name, "expire_at_unix": exp })).into_response()
}

async fn api_ddns_sync(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(name): AxumPath<String>,
) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let cfg = state.config.load();
    let Some(entry) = cfg.ddns.iter().find(|d| d.name == name) else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "DDNS 规则不存在" }))).into_response();
    };
    match sync_ddns_entry(entry, &state.firewall, &state.ddns_status).await {
        Ok(st) => Json(st).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response(),
    }
}

async fn api_acme_issue(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(domain): AxumPath<String>,
) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let cfg = state.config.load();
    let Some(entry) = cfg.acme.iter().find(|a| a.domain == domain) else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "ACME 域名配置不存在" }))).into_response();
    };
    match issue_or_renew_cert(entry, &state.cert_table) {
        Ok(st) => {
            if let Ok(mut g) = state.cert_status.write() {
                g.insert(st.domain.clone(), st.clone());
            }
            Json(st).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response(),
    }
}

async fn api_stun_probe(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(name): AxumPath<String>,
) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let cfg = state.config.load();
    let Some(entry) = cfg.stun.iter().find(|s| s.name == name) else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "STUN 规则不存在" }))).into_response();
    };
    match probe_stun_once(entry).await {
        Ok(addr) => {
            let pub_s = format_public_endpoint(addr);
            let mut next = (**state.stun_addrs.load()).clone();
            next.insert(name.clone(), pub_s.clone());
            state.stun_addrs.store(Arc::new(next));
            Json(serde_json::json!({ "name": name, "public_addr": pub_s })).into_response()
        }
        Err(e) => (StatusCode::BAD_GATEWAY, Json(serde_json::json!({ "error": e }))).into_response(),
    }
}

async fn api_cron_run(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(name): AxumPath<String>,
) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let cfg = state.config.load();
    let Some(job) = cfg.cron.iter().find(|c| c.name == name) else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "Cron 任务不存在" }))).into_response();
    };
    match execute_cron_job(job).await {
        Ok(out) => Json(serde_json::json!({ "ok": true, "output": out })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response(),
    }
}

async fn api_notification_test(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(name): AxumPath<String>,
) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let cfg = state.config.load();
    let Some(n) = cfg.notifications.iter().find(|x| x.name == name) else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "通知渠道不存在" }))).into_response();
    };
    match dispatch_notification(n, "test", "Vane 通知测试", "这是一条来自 Vane 网关管理面板的测试消息", "info").await {
        Ok(()) => Json(serde_json::json!({ "ok": true })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response(),
    }
}

async fn api_docker_containers(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let cfg = state.config.load();
    if !cfg.modules.docker {
        return Json(serde_json::json!({ "enabled": false, "containers": [] })).into_response();
    }
    match list_containers(&cfg.admin.docker_socket, &cfg.docker).await {
        Ok(list) => Json(serde_json::json!({ "enabled": true, "containers": list })).into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, Json(serde_json::json!({ "error": e }))).into_response(),
    }
}

async fn api_docker_action(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath((id, action)): AxumPath<(String, String)>,
) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let cfg = state.config.load();
    if !cfg.modules.docker {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "Docker 模块已关闭" }))).into_response();
    }
    match container_action(&cfg.admin.docker_socket, &cfg.docker, &id, &action).await {
        Ok(()) => Json(serde_json::json!({ "ok": true })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response(),
    }
}

async fn api_docker_logs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let cfg = state.config.load();
    let tail = q.get("tail").and_then(|s| s.parse::<u32>().ok());
    match container_logs(&cfg.admin.docker_socket, &cfg.docker, &id, tail).await {
        Ok(logs) => Json(serde_json::json!({ "logs": logs })).into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, Json(serde_json::json!({ "error": e }))).into_response(),
    }
}

async fn api_docker_prune(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let cfg = state.config.load();
    match prune_dangling_images(&cfg.admin.docker_socket).await {
        Ok(res) => Json(serde_json::json!({ "ok": true, "result": res })).into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, Json(serde_json::json!({ "error": e }))).into_response(),
    }
}

async fn api_list_bans(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    Json(serde_json::json!({ "bans": state.fail2ban.list_active_bans() })).into_response()
}

async fn api_unban_ip(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(ip): AxumPath<String>,
) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let removed = state.fail2ban.unban(&ip);
    Json(serde_json::json!({ "unbanned": removed })).into_response()
}

#[derive(Deserialize)]
struct LockdownReq {
    enable: bool,
}

async fn api_firewall_lockdown(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<LockdownReq>,
) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    match state.firewall.trigger_lockdown(req.enable).await {
        Ok(()) => Json(serde_json::json!({ "lockdown": req.enable })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response(),
    }
}

#[derive(Deserialize)]
struct BackupExportReq {
    password: String,
}

async fn api_backup_export(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<BackupExportReq>,
) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let cfg = state.config.load();
    let ph_gate = state.hash_gate.clone();
    let vault = state.vault.clone();
    let pw = req.password.into_bytes();
    let Ok(res) = ph_gate.run(move || vault.export_backup(&cfg, &pw, BTreeMap::new())).await else {
        return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({ "error": "繁忙" }))).into_response();
    };
    match res {
        Ok(bytes) => Json(serde_json::json!({ "backup_blob": B64.encode(bytes) })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response(),
    }
}

#[derive(Deserialize)]
struct BackupImportReq {
    backup_blob: String,
    password: String,
}

async fn api_backup_import(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<BackupImportReq>,
) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let ph_gate = state.hash_gate.clone();
    let vault = state.vault.clone();
    let Ok(raw_bytes) = B64.decode(req.backup_blob.trim()) else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "备份文件 Base64 编码错误" }))).into_response();
    };
    let pw = req.password.into_bytes();
    let Ok(res) = ph_gate.run(move || vault.import_backup(&raw_bytes, &pw)).await else {
        return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({ "error": "繁忙" }))).into_response();
    };
    let (restored_cfg, _) = match res {
        Ok(c) => c,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response(),
    };
    if let Err(e) = save_config(&state.config_path, &restored_cfg) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response();
    }
    state.config.store(Arc::new(restored_cfg));
    state.reload_notify.notify_waiters();
    Json(serde_json::json!({ "ok": true })).into_response()
}

async fn api_pty_ticket(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let cfg = state.config.load();
    if !cfg.modules.web_terminal {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "WEB_TERMINAL_DISABLED", "message": "Web 终端功能默认关闭，请先在「系统设置 -> 功能模块管理」中打开" })),
        )
            .into_response();
    }
    match state.pty_mgr.issue_ticket(cfg.web_terminal.max_sessions) {
        Ok(ticket) => Json(serde_json::json!({ "ticket": ticket })).into_response(),
        Err(e) => (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({ "error": e }))).into_response(),
    }
}

async fn api_pty_ws(
    State(state): State<Arc<AppState>>,
    ws: WebSocketUpgrade,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let cfg = state.config.load();
    if !cfg.modules.web_terminal {
        return (StatusCode::FORBIDDEN, "Web 终端已关闭").into_response();
    }
    let Some(ticket) = q.get("ticket") else {
        return (StatusCode::UNAUTHORIZED, "缺少终端 Ticket").into_response();
    };
    if !state.pty_mgr.consume_ticket(ticket) {
        return (StatusCode::UNAUTHORIZED, "无效或已过期的终端 Ticket").into_response();
    }
    let target = q.get("target").cloned().unwrap_or_else(|| "host".into());
    let pty_mgr = state.pty_mgr.clone();
    let term_cfg = cfg.web_terminal.clone();
    ws.on_upgrade(move |socket| async move {
        handle_pty_websocket(socket, &pty_mgr, term_cfg, target).await;
    })
}

async fn serve_manifest(State(state): State<Arc<AppState>>) -> Response {
    let cfg = state.config.load();
    let start_url = if cfg.admin.secret_path.is_empty() {
        "/".to_string()
    } else {
        cfg.admin.secret_path.clone()
    };
    let manifest = serde_json::json!({
        "name": "Vane Gateway Console",
        "short_name": "Vane",
        "description": "高安全双栈路由器全能网关控制台",
        "start_url": start_url,
        "scope": "/",
        "display": "standalone",
        "background_color": "#090b0f",
        "theme_color": "#090b0f",
        "icons": [
            { "src": "/icon.svg", "sizes": "any", "type": "image/svg+xml", "purpose": "any maskable" }
        ]
    });
    (
        [(header::CONTENT_TYPE, "application/manifest+json; charset=utf-8")],
        manifest.to_string(),
    )
        .into_response()
}

async fn serve_sw() -> Response {
    let sw_code = r#"
const CACHE_NAME = 'vane-shell-v1';
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))));
  self.clients.claim();
});
self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (url.pathname.startsWith('/api/')) return;
  if (e.request.method !== 'GET') return;
  e.respondWith(fetch(e.request).catch(() => caches.match(e.request)));
});
"#;
    ([(header::CONTENT_TYPE, "application/javascript; charset=utf-8")], sw_code).into_response()
}

async fn serve_static_or_spa(uri: Uri, method: Method, headers: HeaderMap) -> Response {
    if method != Method::GET && method != Method::HEAD {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let raw_path = uri.path().trim_start_matches('/');
    let path = if raw_path.is_empty() || !raw_path.contains('.') {
        "index.html"
    } else {
        raw_path
    };
    let accept_enc = headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let mime = content_type_for(path);

    // 优先检查 Brotli (.br) 与 Gzip (.gz) 预压缩切片
    if accept_enc.contains("br") {
        let br_name = format!("{}.br", path);
        if let Some(f) = load_asset(&br_name) {
            return ([(header::CONTENT_TYPE, mime), (header::CONTENT_ENCODING, "br")], Body::from(f)).into_response();
        }
    }
    if accept_enc.contains("gzip") {
        let gz_name = format!("{}.gz", path);
        if let Some(f) = load_asset(&gz_name) {
            return ([(header::CONTENT_TYPE, mime), (header::CONTENT_ENCODING, "gzip")], Body::from(f)).into_response();
        }
    }
    if let Some(f) = load_asset(path) {
        return ([(header::CONTENT_TYPE, mime)], Body::from(f)).into_response();
    }
    if let Some(f) = load_asset("index.html") {
        return ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], Body::from(f)).into_response();
    }
    StatusCode::NOT_FOUND.into_response()
}

fn load_asset(rel_path: &str) -> Option<Vec<u8>> {
    let disk_path = PathBuf::from("web-ui/dist").join(rel_path);
    if disk_path.is_file() {
        if let Ok(bytes) = std::fs::read(&disk_path) {
            return Some(bytes);
        }
    }
    WebAssets::get(rel_path).map(|f| f.data.into_owned())
}

fn content_type_for(path: &str) -> &'static str {
    if path.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if path.ends_with(".js") || path.ends_with(".mjs") {
        "application/javascript; charset=utf-8"
    } else if path.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if path.ends_with(".svg") {
        "image/svg+xml"
    } else if path.ends_with(".json") || path.ends_with(".webmanifest") {
        "application/json; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::Request;
    use tower::ServiceExt;

    async fn make_test_app(tmp_dir: &std::path::Path) -> Router {
        let cfg_path = tmp_dir.join("config.toml");
        let outcome = crate::config::load_or_init(&cfg_path).unwrap();
        let vault = Arc::new(Vault::load_or_create(tmp_dir).unwrap());
        let firewall = FirewallManager::detect_and_init(outcome.config.firewall.clone()).await;
        let state = Arc::new(AppState {
            config_path: cfg_path,
            config: Arc::new(ArcSwap::from_pointee(outcome.config.clone())),
            vault,
            auth: Mutex::new(AuthState::new(outcome.config.admin.canonical_origin.clone(), 0)),
            hash_gate: Arc::new(HashGate::new()),
            fail2ban: Arc::new(Fail2Ban::new()),
            firewall,
            health_registry: crate::supervisor::new_health_registry(),
            ddns_status: Arc::new(RwLock::new(BTreeMap::new())),
            cert_table: Arc::new(ArcSwap::from_pointee(CertTable::default())),
            cert_status: RwLock::new(BTreeMap::new()),
            stun_addrs: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            global_quota: ConnectionQuota::new(128),
            pty_mgr: Arc::new(PtyManager::new()),
            reload_notify: Arc::new(Notify::new()),
        });
        build_router(state)
    }

    #[tokio::test]
    async fn end_to_end_mandatory_password_change_and_module_switches() {
        let tmp = std::env::temp_dir().join(format!("vane_web_test_{}", crate::config::random_nonce()));
        let _ = std::fs::create_dir_all(&tmp);
        let app = make_test_app(&tmp).await;

        // 1. 使用初始密码 admin / admin321 登录 -> 必须返回 must_change_password = true
        let login_req = Request::builder()
            .method("POST")
            .uri("/api/auth/login")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"username":"admin","password":"admin321"}"#))
            .unwrap();
        let login_resp = app.clone().oneshot(login_req).await.unwrap();
        assert_eq!(login_resp.status(), StatusCode::OK);
        let cookie_hdr = login_resp
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let login_json: serde_json::Value =
            serde_json::from_slice(&to_bytes(login_resp.into_body(), 65536).await.unwrap()).unwrap();
        assert_eq!(login_json["must_change_password"], true);

        // 2. 未修改初始密码前访问 /api/dashboard 与 /api/settings -> 被后端硬门禁拒绝 403 MUST_CHANGE_INITIAL_PASSWORD
        let dash_req = Request::builder()
            .method("GET")
            .uri("/api/dashboard")
            .header(header::COOKIE, &cookie_hdr)
            .body(Body::empty())
            .unwrap();
        let dash_resp = app.clone().oneshot(dash_req).await.unwrap();
        assert_eq!(dash_resp.status(), StatusCode::FORBIDDEN);
        let err_json: serde_json::Value =
            serde_json::from_slice(&to_bytes(dash_resp.into_body(), 65536).await.unwrap()).unwrap();
        assert_eq!(err_json["error"], "MUST_CHANGE_INITIAL_PASSWORD");

        // 3. 尝试将密码仍改为 admin321 或弱密码 -> 拒绝 400 BAD_REQUEST
        let bad_pw_req = Request::builder()
            .method("POST")
            .uri("/api/auth/change-password")
            .header(header::COOKIE, &cookie_hdr)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"current_password":"admin321","new_password":"admin321"}"#))
            .unwrap();
        let bad_pw_resp = app.clone().oneshot(bad_pw_req).await.unwrap();
        assert_eq!(bad_pw_resp.status(), StatusCode::BAD_REQUEST);

        // 4. 修改为合规强密码 Vane#2026Strong -> 签发新会话并解除硬门禁
        let ok_pw_req = Request::builder()
            .method("POST")
            .uri("/api/auth/change-password")
            .header(header::COOKIE, &cookie_hdr)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"current_password":"admin321","new_password":"Vane#2026Strong"}"#))
            .unwrap();
        let ok_pw_resp = app.clone().oneshot(ok_pw_req).await.unwrap();
        assert_eq!(ok_pw_resp.status(), StatusCode::OK);
        let new_cookie = ok_pw_resp
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();

        // 5. 使用新会话访问 /api/dashboard -> 200 OK
        let dash_ok = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/dashboard")
                    .header(header::COOKIE, &new_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dash_ok.status(), StatusCode::OK);

        // 6. Web 终端默认关闭 (modules.web_terminal = false) -> 申请 Ticket 返回 403
        let pty_disabled = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/pty/ticket")
                    .header(header::COOKIE, &new_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pty_disabled.status(), StatusCode::FORBIDDEN);

        // 7. 静态资源预压缩协商 (Accept-Encoding: br) -> Content-Encoding: br
        let static_req = Request::builder()
            .method("GET")
            .uri("/")
            .header(header::ACCEPT_ENCODING, "br, gzip")
            .body(Body::empty())
            .unwrap();
        let static_resp = app.oneshot(static_req).await.unwrap();
        assert_eq!(static_resp.status(), StatusCode::OK);
        assert_eq!(static_resp.headers().get(header::CONTENT_ENCODING).unwrap(), "br");

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
