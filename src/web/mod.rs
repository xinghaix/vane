//! Web 管理后台：全程 HTTPS / 局域网监听、单管理员三合一认证、强制首次修改初始密码硬门禁、
//! 安全入口路径 (`secret_path`)、并发安全配置更新、敏感配置脱敏与 AEAD 加密落盘、
//! `.rodata` 零拷贝 `.br/.gz` 预压缩静态直出与 PWA 支持。
pub mod boundary;
pub mod server;
pub mod ws_pty;

use crate::config::{save_config, Config, Ed25519KeyEntry, ModulesConfig};
use crate::daemon::acme::{issue_or_renew_cert, AcmeRuntime};
use crate::daemon::cron::{execute_cron_job_with_ctx, CronExecutionContext, CronRuntime, CronSchedule};
use crate::daemon::ddns::{sync_ddns_entry, DdnsStatusMap};
use crate::daemon::notify::{broadcast_event, send_test_notification};
use crate::docker::unix_client::{container_action, container_logs, list_containers, prune_dangling_images};
use crate::firewall::FirewallManager;
use crate::logger::{self, Level};
use crate::monitor::alerts::{evaluate_and_notify_alerts, AlertState};
use crate::monitor::procfs::MonitorSampler;
use crate::net::dual_stack::BanKey;
use crate::net::listener::ConnectionQuota;
use crate::net::{snapshot_rule_statuses, RuleStatusMap};
use crate::net::stun::{probe_and_sync_stun_entry, StunRuntime};
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
use axum::body::{Body, Bytes};
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path as AxumPath, Query, State};
use axum::http::{header, HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rust_embed::RustEmbed;
use serde::Deserialize;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;

#[derive(RustEmbed)]
#[folder = "web-ui/dist/"]
struct WebAssets;

pub const SESSION_COOKIE_NAME: &str = "vane_session";
const PENDING_TOTP_TTL: Duration = Duration::from_secs(600);

pub struct AppState {
    pub config_path: PathBuf,
    pub config: Arc<ArcSwap<Config>>,
    pub config_lock: tokio::sync::Mutex<()>,
    pub vault: Arc<Vault>,
    pub auth: Mutex<AuthState>,
    pub hash_gate: Arc<HashGate>,
    pub fail2ban: Arc<Fail2Ban>,
    pub firewall: Arc<FirewallManager>,
    pub health_registry: HealthRegistry,
    pub ddns_status: DdnsStatusMap,
    pub cert_table: Arc<ArcSwap<CertTable>>,
    pub cert_status: Arc<AcmeRuntime>,
    pub admin_cert: Arc<ArcSwap<rustls::sign::CertifiedKey>>,
    pub stun_addrs: Arc<ArcSwap<BTreeMap<String, String>>>,
    pub stun_status: StunRuntime,
    pub reverse_proxy_status: RuleStatusMap,
    pub port_forward_status: RuleStatusMap,
    pub cron_status: Arc<CronRuntime>,
    pub monitor_sampler: MonitorSampler,
    pub alert_state: AlertState,
    pub global_quota: ConnectionQuota,
    pub pty_mgr: Arc<PtyManager>,
    pub proxy_tickets: crate::security::tickets::SessionTickets,
    pub reload_notify: Arc<Notify>,
}

impl AppState {
    pub async fn apply_runtime_settings(&self, next_cfg: &Config) {
        logger::global().set_capacity(next_cfg.system.log_ring_capacity);
        logger::global().set_tz_offset(next_cfg.timezone_offset_secs());
        if self.firewall.is_auto_manage() && !next_cfg.firewall.auto_manage {
            let _ = self.firewall.pre_start_sweep().await;
        }
        self.firewall.update_config(next_cfg.firewall.clone());
        self.global_quota.set_capacity(next_cfg.system.global_max_conns);
        if let Ok(mut auth) = self.auth.lock() {
            auth.engine
                .set_canonical_origin(next_cfg.admin.canonical_origin.clone());
        }
        if !next_cfg.modules.web_terminal {
            self.pty_mgr.notify_revoke();
        }
    }

    pub fn build_cron_context(self: &Arc<Self>, cfg: Arc<Config>) -> CronExecutionContext {
        let st = self.clone();
        let toggler = Arc::new(move |target_kind: String, rule_name: String, enable: bool| {
            let st = st.clone();
            Box::pin(async move {
                let _guard = st.config_lock.lock().await;
                let mut next = (**st.config.load()).clone();
                let mut found = false;
                match target_kind.as_str() {
                    "port_forward" => {
                        for p in next.port_forwards.iter_mut() {
                            if p.name == rule_name {
                                p.enabled = enable;
                                found = true;
                            }
                        }
                        if found && !enable {
                            let _ = st
                                .firewall
                                .remove_rule("port_forward", &format!("{}_tcp", rule_name))
                                .await;
                            let _ = st
                                .firewall
                                .remove_rule("port_forward", &format!("{}_udp", rule_name))
                                .await;
                        }
                    }
                    "reverse_proxy" => {
                        for r in next.reverse_proxy.iter_mut() {
                            if r.name == rule_name {
                                r.enabled = enable;
                                found = true;
                            }
                        }
                        if found && !enable {
                            let _ = st.firewall.remove_rule("reverse_proxy", &rule_name).await;
                        }
                    }
                    other => return Err(format!("不支持的规则类型: {}", other)),
                }
                if !found {
                    return Err(format!("未找到目标规则 {}.{}", target_kind, rule_name));
                }
                next.validate_with_vault(Some(&st.vault))?;
                save_config(&st.config_path, &next)?;
                st.config.store(Arc::new(next));
                st.reload_notify.notify_one();
                Ok(format!("已将 {}.{} 设为 enabled={}", target_kind, rule_name, enable))
            }) as std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send>>
        });

        CronExecutionContext {
            config: cfg,
            vault: self.vault.clone(),
            runtime: self.cron_status.clone(),
            rule_toggler: Some(toggler),
        }
    }
}

impl crate::net::reverse_proxy::ProxyAuthorization for AppState {
    fn session(&self, headers: &HeaderMap, _peer: std::net::IpAddr) -> Option<[u8; 32]> {
        current_session_scope(self, headers)
            .filter(|(_, scope)| *scope == SessionScope::FullAdmin)
            .map(|(token, _)| crate::security::auth::SessionStore::token_digest(&token))
    }
    fn websocket_ticket(&self, ticket: &str, target: &str, peer: std::net::IpAddr) -> Option<[u8; 32]> {
        let session = self.proxy_tickets.consume(ticket, target, BanKey::from_peer(peer))?;
        self.session_alive(&session).then_some(session)
    }
    fn session_alive(&self, session: &[u8; 32]) -> bool {
        let cfg = self.config.load();
        let Ok(mut auth) = self.auth.lock() else { return false };
        let Some(sess) = auth
            .sessions
            .validate_digest(session, Duration::from_secs(cfg.admin.session_ttl_secs), false)
        else {
            return false;
        };
        auth.effective_scope(&cfg.admin, sess.scope) == SessionScope::FullAdmin
    }
    fn trusted_origin(&self, origin: &str, authority: &str) -> bool {
        let Some(origin_auth) = boundary::origin_authority(origin) else {
            return false;
        };
        let cfg = self.config.load();
        boundary::origin_authority(&format!("https://{authority}")).as_ref() == Some(&origin_auth)
            || boundary::trusted_origin_authority(&origin_auth, &cfg)
    }
}

#[derive(Deserialize)]
struct ProxyTicketRequest {
    listener: String,
    authority: String,
    path: String,
}

async fn api_proxy_ticket(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<ProxyTicketRequest>,
) -> Response {
    let token = match require_full_admin(&state, &headers) {
        Ok(token) => token,
        Err(response) => return response,
    };
    let cfg = state.config.load();
    let Some(listener) = cfg
        .reverse_proxy
        .iter()
        .find(|entry| entry.enabled && entry.name == body.listener)
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "LISTENER_NOT_FOUND", "message": "未找到已启用的目标反代监听器" })),
        )
            .into_response();
    };
    let uri: http::Uri = match format!("https://{}{}", body.authority, body.path).parse() {
        Ok(uri) => uri,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "INVALID_PROXY_TARGET", "message": "目标 Authority 或路径格式非法" })),
            )
                .into_response();
        }
    };
    let authority: http::uri::Authority = match body.authority.parse() {
        Ok(authority) => authority,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "INVALID_PROXY_TARGET", "message": "目标 Authority 格式非法" })),
            )
                .into_response();
        }
    };
    if !body.path.starts_with('/')
        || body.path.starts_with("//")
        || body.path.contains("vane_ticket=")
        || body.path.contains('#')
        || boundary::origin_authority(&format!("https://{}", body.authority)).is_none()
        || authority.port_u16().unwrap_or(443) != listener.listen_port
        || crate::net::reverse_proxy::match_rule(&listener.rules, authority.host(), uri.path())
            .is_none_or(|rule| !rule.websocket)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "INVALID_PROXY_TARGET", "message": "目标端口或路径未匹配到允许 WebSocket 的启用规则" })),
        )
            .into_response();
    }
    match state
        .proxy_tickets
        .issue(&token, format!("{}{}", body.authority, body.path), BanKey::from_peer(peer.ip()))
    {
        Ok(ticket) => Json(serde_json::json!({"ticket": ticket, "expires_in": 30})).into_response(),
        Err(msg) => (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({ "error": "TICKET_BUSY", "message": msg })),
        )
            .into_response(),
    }
}

async fn request_timeout_guard(request: axum::extract::Request, next: axum::middleware::Next) -> Response {
    if request.uri().path() == "/api/pty/ws" {
        return next.run(request).await;
    }
    match tokio::time::timeout(Duration::from_secs(60), next.run(request)).await {
        Ok(resp) => resp,
        Err(_) => (
            StatusCode::REQUEST_TIMEOUT,
            Json(serde_json::json!({ "error": "REQUEST_TIMEOUT", "message": "请求处理超时" })),
        )
            .into_response(),
    }
}

pub fn build_router(state: Arc<AppState>) -> Router {
    let auth_routes = Router::new()
        .route("/api/auth/status", get(api_auth_status))
        .route("/api/auth/login", post(api_auth_login))
        .route("/api/auth/logout", post(api_auth_logout))
        .route("/api/auth/change-password", post(api_auth_change_password))
        .route("/api/auth/challenge", post(api_auth_challenge))
        .route("/api/auth/login-ed25519", post(api_auth_login_ed25519))
        .route("/api/auth/totp/setup", post(api_totp_setup))
        .route("/api/auth/totp/enable", post(api_totp_enable))
        .route("/api/auth/totp/disable", post(api_totp_disable))
        .route("/api/auth/totp/recovery-codes", post(api_totp_regenerate_recovery))
        .route("/api/auth/ed25519/keys", post(api_add_ed25519_key))
        .route("/api/auth/ed25519/keys/{id}", delete(api_delete_ed25519_key))
        .route("/api/auth/ca-cert", get(api_export_admin_cert))
        .layer(DefaultBodyLimit::max(8 * 1024));

    Router::new()
        .merge(auth_routes)
        .route("/api/dashboard", get(api_dashboard))
        .route("/api/system/network-info", get(api_system_network_info))
        .route("/api/logs", get(api_get_logs).delete(api_clear_logs))
        .route("/api/settings", get(api_get_settings).put(api_put_settings))
        .route("/api/modules", put(api_put_modules))
        .route("/api/port-forwards/{name}/lease", post(api_port_forward_lease))
        .route("/api/ddns/{name}/sync", post(api_ddns_sync))
        .route("/api/acme/{domain}/issue", post(api_acme_issue))
        .route("/api/stun/{name}/probe", post(api_stun_probe))
        .route("/api/cron/preview", get(api_cron_preview))
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
        .route(
            "/api/backup/import",
            post(api_backup_import).layer(DefaultBodyLimit::max(24 * 1024 * 1024)),
        )
        .route("/api/backup/sanitized", post(api_backup_sanitized))
        .route("/api/proxy/ticket", post(api_proxy_ticket))
        .route("/api/pty/ticket", post(api_pty_ticket))
        .route("/api/pty/ws", get(api_pty_ws))
        .route("/manifest.webmanifest", get(serve_manifest))
        .route("/sw.js", get(serve_sw))
        .fallback(serve_static_or_spa)
        .layer(axum::middleware::from_fn(request_timeout_guard))
        .layer(axum::middleware::from_fn_with_state(state.clone(), boundary::guard))
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

pub(crate) fn current_session_scope(state: &AppState, headers: &HeaderMap) -> Option<(String, SessionScope)> {
    let token = extract_session_token(headers)?;
    let cfg = state.config.load();
    let ttl = Duration::from_secs(cfg.admin.session_ttl_secs.clamp(300, 86_400));
    let mut auth = state.auth.lock().ok()?;
    let sess = auth.sessions.validate(&token, ttl)?;
    // 双重硬校验：即使会话曾经是 FullAdmin，若配置被重置为 must_change_password 或密码仍是 admin321，立即降级为 MustChangePassword
    let effective_scope = auth.effective_scope(&cfg.admin, sess.scope);
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

async fn api_auth_status(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let cfg = state.config.load();
    let session = current_session_scope(&state, &headers);
    let key_ids: Vec<&String> = cfg.admin.authorized_ed25519_keys.iter().map(|k| &k.id).collect();
    if let Some((_, scope)) = session {
        Json(serde_json::json!({
            "authenticated": true,
            "username": cfg.admin.username,
            "must_change_password": scope == SessionScope::MustChangePassword,
            "password_login_enabled": cfg.admin.password_login_enabled,
            "totp_enabled": cfg.admin.totp_enabled,
            "totp_recovery_remaining": cfg.admin.totp_recovery_hashes.len(),
            "has_ed25519_keys": !key_ids.is_empty(),
            "ed25519_key_ids": key_ids,
            "session_ttl_secs": cfg.admin.session_ttl_secs,
            "language": cfg.system.language,
            "modules": cfg.modules,
        }))
        .into_response()
    } else {
        Json(serde_json::json!({
            "authenticated": false,
            "password_login_enabled": cfg.admin.password_login_enabled,
            "totp_enabled": cfg.admin.totp_enabled,
            "has_ed25519_keys": !key_ids.is_empty(),
            "ed25519_key_ids": key_ids,
            "language": cfg.system.language,
        }))
        .into_response()
    }
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
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<LoginRequest>,
) -> Response {
    let ip = peer.ip();
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
        let pw_bytes = req.password.into_bytes();
        let dummy_iters = PasswordHash::parse(&cfg.admin.password_hash)
            .map(|p| p.iters)
            .unwrap_or(crate::security::auth::PBKDF2_ITERS);
        let Ok(()) = state
            .hash_gate
            .run(move || AuthEngine::verify_dummy_password(&pw_bytes, dummy_iters))
            .await
        else {
            return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({ "error": "认证繁忙" }))).into_response();
        };
        on_login_failed(&state, ban_key).await;
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "INVALID_CREDENTIALS", "message": "用户名或密码错误" })),
        )
            .into_response();
    }

    let Some(ph) = PasswordHash::parse(&cfg.admin.password_hash) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "密码哈希未初始化" })),
        )
            .into_response();
    };
    let pw_bytes = req.password.into_bytes();
    let ph_clone = ph.clone();
    let must_change_flag = cfg.admin.must_change_password;
    let Ok((pw_ok, scope)) = state
        .hash_gate
        .run(move || {
            let ok = ph_clone.verify(&pw_bytes);
            let sc = if ok {
                AuthEngine::resolve_session_scope(must_change_flag, &ph_clone.salt, &ph_clone.hash, ph_clone.iters)
            } else {
                SessionScope::MustChangePassword
            };
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

    // 若启用了 TOTP：防回退单调水位校验并落盘，或一次性核销恢复码（在 spawn_blocking 中执行）
    if cfg.admin.totp_enabled {
        let Ok(totp_plain) = state.vault.reveal_string("admin.totp_secret", &cfg.admin.totp_secret) else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "TOTP 密钥解密失败" })),
            )
                .into_response();
        };
        let Some(secret_bytes) = base32_decode(&totp_plain).filter(|b| b.len() >= 16) else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "TOTP 密钥无效，请核对配置后重试" })),
            )
                .into_response();
        };
        let code_trim = req.totp_code.trim().to_string();
        if code_trim.is_empty() {
            on_login_failed(&state, ban_key).await;
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "TOTP_REQUIRED", "message": "请输入 6 位 TOTP 验证码或一次性恢复码" })),
            )
                .into_response();
        }

        if code_trim.len() == 6 && code_trim.bytes().all(|b| b.is_ascii_digit()) {
            let code_num = code_trim.parse::<u32>().unwrap_or(u32::MAX);
            let accepted_step = {
                let mut auth = state.auth.lock().unwrap_or_else(|e| e.into_inner());
                if auth.engine.verify_totp(&secret_bytes, code_num, logger::unix_now()) {
                    Some(auth.engine.totp_watermark())
                } else {
                    None
                }
            };
            let Some(new_step) = accepted_step else {
                on_login_failed(&state, ban_key).await;
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "error": "INVALID_TOTP", "message": "TOTP 动态验证码错误或已重放使用" })),
                )
                    .into_response();
            };
            // 水位线原子落盘防进程重启后重放
            let _cfg_guard = state.config_lock.lock().await;
            let mut next_cfg = (**state.config.load()).clone();
            if new_step > next_cfg.admin.totp_last_step {
                next_cfg.admin.totp_last_step = new_step;
                if let Err(e) = save_config(&state.config_path, &next_cfg) {
                    logger::log(Level::Error, "auth", &format!("持久化 TOTP 水位线失败: {}", e));
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({ "error": "持久化安全状态失败" })),
                    )
                        .into_response();
                }
                state.config.store(Arc::new(next_cfg));
            }
        } else {
            // 一次性恢复码校验（放入 HashGate 防止阻塞异步线程）并原子消费移除
            let _cfg_guard = state.config_lock.lock().await;
            let cur_cfg = state.config.load();
            let hashes = cur_cfg.admin.totp_recovery_hashes.clone();
            let norm = normalize_recovery_code(&code_trim);
            let Ok(matched_hash) = state
                .hash_gate
                .run(move || {
                    hashes
                        .into_iter()
                        .find(|h| PasswordHash::parse(h).is_some_and(|p| p.verify(norm.as_bytes())))
                })
                .await
            else {
                return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({ "error": "认证繁忙" }))).into_response();
            };
            let Some(used_hash) = matched_hash else {
                on_login_failed(&state, ban_key).await;
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "error": "INVALID_TOTP", "message": "TOTP 动态验证码或一次性恢复码无效" })),
                )
                    .into_response();
            };
            let mut next_cfg = (**cur_cfg).clone();
            if let Some(pos) = next_cfg.admin.totp_recovery_hashes.iter().position(|h| h == &used_hash) {
                next_cfg.admin.totp_recovery_hashes.remove(pos);
            }
            if let Err(e) = save_config(&state.config_path, &next_cfg) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": format!("核销恢复码落盘失败: {}", e) })),
                )
                    .into_response();
            }
            let left = next_cfg.admin.totp_recovery_hashes.len();
            state.config.store(Arc::new(next_cfg));
            logger::log(
                Level::Warn,
                "auth",
                &format!("管理员使用一次性 TOTP 恢复码登录成功，剩余可用恢复码: {}", left),
            );
        }
    }

    let latest_cfg = state.config.load();
    state.fail2ban.record_success(ban_key);
    let ttl = Duration::from_secs(latest_cfg.admin.session_ttl_secs.clamp(300, 86_400));
    let token = {
        let mut auth = state.auth.lock().unwrap_or_else(|e| e.into_inner());
        match auth.sessions.issue(scope, ban_key, ttl) {
            Ok(t) => t,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response(),
        }
    };

    logger::log(
        Level::Info,
        "auth",
        &format!("管理员登录成功 (ip={}, must_change_password={})", ip, scope == SessionScope::MustChangePassword),
    );
    build_session_response(&token, ttl.as_secs(), scope == SessionScope::MustChangePassword, &latest_cfg, &state.vault)
}

fn build_session_response(token: &str, ttl_secs: u64, must_change: bool, cfg: &Config, vault: &Vault) -> Response {
    let cookie = format!(
        "{}={}; Path=/; Max-Age={}; HttpOnly; Secure; SameSite=Strict",
        SESSION_COOKIE_NAME, token, ttl_secs
    );
    let body = serde_json::json!({
        "authenticated": true,
        "username": cfg.admin.username,
        "must_change_password": must_change,
        "password_login_enabled": cfg.admin.password_login_enabled,
        "totp_enabled": cfg.admin.totp_enabled,
        "totp_recovery_remaining": cfg.admin.totp_recovery_hashes.len(),
        "has_ed25519_keys": !cfg.admin.authorized_ed25519_keys.is_empty(),
        "ed25519_key_ids": cfg.admin.authorized_ed25519_keys.iter().map(|k| &k.id).collect::<Vec<_>>(),
        "session_ttl_secs": cfg.admin.session_ttl_secs,
        "language": cfg.system.language,
        "modules": cfg.modules,
    });
    let mut resp = Json(body).into_response();
    if let Ok(hv) = header::HeaderValue::from_str(&cookie) {
        resp.headers_mut().append(header::SET_COOKIE, hv);
    }
    if let Some(sp) = boundary::active_secret_path(cfg) {
        if let Some(entry_hv) = boundary::build_entry_set_cookie(vault.mac_key(), sp) {
            resp.headers_mut().append(header::SET_COOKIE, entry_hv);
        }
    }
    resp
}

async fn on_login_failed(state: &AppState, ban_key: BanKey) {
    let cfg = state.config.load();
    if state
        .fail2ban
        .record_failure(ban_key, cfg.security.max_login_failures, cfg.security.ban_duration_secs, "login_failed")
    {
        let cidr = ban_key.display_cidr();
        let msg = format!(
            "源网络 {} 连续认证失败已达阈值，已临时封禁 {}s",
            cidr, cfg.security.ban_duration_secs
        );
        logger::log(Level::Warn, "fail2ban", &msg);
        if cfg.security.kernel_ban_offload {
            let _ = state.firewall.ban_source_cidr(&cidr, cfg.security.ban_duration_secs).await;
        }
        broadcast_event(&cfg, &state.vault, "ip_banned", "Vane 防爆破自动封禁告警", &msg, "warning").await;
    }
}

async fn api_auth_logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(tok) = extract_session_token(&headers) {
        if let Ok(mut auth) = state.auth.lock() {
            auth.sessions.revoke(&tok);
        }
        state.pty_mgr.notify_revoke();
    }
    let mut resp = Json(serde_json::json!({ "ok": true })).into_response();
    if let Ok(hv) = header::HeaderValue::from_str(&format!(
        "{}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict",
        SESSION_COOKIE_NAME
    )) {
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
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<ChangePasswordRequest>,
) -> Response {
    let (_old_tok, _) = match require_any_session(&state, &headers) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let ban_key = BanKey::from_peer(peer.ip());
    if state.fail2ban.is_key_banned(ban_key) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({ "error": "IP_BANNED", "message": "认证失败次数过多，该网络已被临时封禁" })),
        )
            .into_response();
    }
    let cfg_snap_pre = state.config.load();
    let Some(ph_pre) = PasswordHash::parse(&cfg_snap_pre.admin.password_hash) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "密码未初始化" })),
        )
            .into_response();
    };

    let target_username = if req.new_username.trim().is_empty() {
        cfg_snap_pre.admin.username.clone()
    } else {
        req.new_username.trim().to_string()
    };
    if let Err(e) = crate::config::validate_username(&target_username) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e, "message": e }))).into_response();
    }

    let cur_pw = req.current_password.into_bytes();
    let new_pw = req.new_password.into_bytes();
    let uname_bytes = target_username.clone().into_bytes();
    let ph_clone = ph_pre.clone();

    // 在持有 config_lock 之前执行 PBKDF2，避免阻塞其他配置写请求
    let res = state
        .hash_gate
        .run(move || -> Result<(bool, PasswordHash), &'static str> {
            if !ph_clone.verify(&cur_pw) {
                return Ok((false, ph_clone));
            }
            AuthEngine::validate_new_password(&new_pw, &uname_bytes, &ph_clone.salt, &ph_clone.hash, ph_clone.iters)?;
            Ok((true, PasswordHash::create(&new_pw)?))
        })
        .await;

    let new_hash = match res {
        Ok(Ok((false, _))) => {
            on_login_failed(&state, ban_key).await;
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "INVALID_PASSWORD", "message": "原密码错误" })),
            )
                .into_response();
        }
        Ok(Ok((true, h))) => h,
        Ok(Err(msg)) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "INVALID_PASSWORD", "message": msg })),
            )
                .into_response();
        }
        Err(msg) => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": msg, "message": msg })),
            )
                .into_response();
        }
    };

    let _cfg_guard = state.config_lock.lock().await;
    let cfg_snap = state.config.load();
    if cfg_snap.admin.password_hash != cfg_snap_pre.admin.password_hash {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": "认证状态已并发变更，请重新输入" })),
        )
            .into_response();
    }
    let mut next_cfg = (**cfg_snap).clone();
    next_cfg.admin.username = target_username;
    next_cfg.admin.password_hash = new_hash.encode();
    next_cfg.admin.must_change_password = false;
    if let Err(e) = save_config(&state.config_path, &next_cfg) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e, "message": e })),
        )
            .into_response();
    }
    state.config.store(Arc::new(next_cfg.clone()));
    state.fail2ban.record_success(ban_key);

    // 密码变更后清空所有旧会话、终止遗留 PTY 终端并签发全新 FullAdmin 会话
    let ttl = Duration::from_secs(next_cfg.admin.session_ttl_secs.clamp(300, 86_400));
    let new_token = {
        let mut auth = state.auth.lock().unwrap_or_else(|e| e.into_inner());
        auth.sessions.revoke_all();
        match auth.sessions.issue(SessionScope::FullAdmin, ban_key, ttl) {
            Ok(t) => t,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response(),
        }
    };
    state.pty_mgr.notify_revoke();
    logger::log(Level::Info, "auth", "管理员密码已成功修改并完成原子落盘，已解锁完整管理权限");
    build_session_response(&new_token, ttl.as_secs(), false, &next_cfg, &state.vault)
}

#[derive(Deserialize)]
struct ChallengeReq {
    key_id: String,
}

async fn api_auth_challenge(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<ChallengeReq>,
) -> Response {
    let client_key = BanKey::from_peer(peer.ip());
    if state.fail2ban.is_key_banned(client_key) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({ "error": "IP_BANNED", "message": "认证失败次数过多，该网络已被临时封禁" })),
        )
            .into_response();
    }
    let cfg = state.config.load();
    if !cfg.admin.authorized_ed25519_keys.iter().any(|k| k.id == req.key_id) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "未找到指定的公钥 ID" })),
        )
            .into_response();
    }
    let rng = ring::rand::SystemRandom::new();
    let mut auth = state.auth.lock().unwrap_or_else(|e| e.into_inner());
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
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<Ed25519LoginReq>,
) -> Response {
    let ip = peer.ip();
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
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "公钥格式错误" })),
        )
            .into_response();
    };
    if req.nonce_b64.trim().len() > 256 || req.signature_b64.trim().len() > 256 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "挑战参数长度超限" }))).into_response();
    }
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
        let mut auth = state.auth.lock().unwrap_or_else(|e| e.into_inner());
        auth.engine
            .verify_ed25519_challenge(&nonce, &req.key_id, client_key, &sig, &raw_pk)
    };
    if !verified {
        on_login_failed(&state, client_key).await;
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Ed25519 挑战签名验证失败" })),
        )
            .into_response();
    }

    state.fail2ban.record_success(client_key);
    let ttl = Duration::from_secs(cfg.admin.session_ttl_secs.clamp(300, 86_400));
    let (token, scope) = {
        let mut auth = state.auth.lock().unwrap_or_else(|e| e.into_inner());
        let sc = auth.effective_scope(&cfg.admin, SessionScope::FullAdmin);
        let tok = match auth.sessions.issue(sc, client_key, ttl) {
            Ok(t) => t,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response(),
        };
        (tok, sc)
    };
    logger::log(Level::Info, "auth", &format!("管理员通过 Ed25519 密钥 {} 登录成功", req.key_id));
    build_session_response(&token, ttl.as_secs(), scope == SessionScope::MustChangePassword, &cfg, &state.vault)
}

async fn api_totp_setup(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let Ok(secret) = generate_totp_secret() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "生成密钥失败" })),
        )
            .into_response();
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

async fn hash_recovery_codes_blocking(gate: &HashGate) -> Result<(Vec<String>, Vec<String>), Response> {
    let recovery_codes = generate_recovery_codes(6).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response()
    })?;
    let codes_for_hash = recovery_codes.clone();
    let Ok(hashes) = gate
        .run(move || {
            codes_for_hash
                .iter()
                .filter_map(|c| {
                    PasswordHash::create_with_iters(normalize_recovery_code(c).as_bytes(), 100_000)
                        .ok()
                        .map(|h| h.encode())
                })
                .collect::<Vec<String>>()
        })
        .await
    else {
        return Err((StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({ "error": "繁忙" }))).into_response());
    };
    Ok((recovery_codes, hashes))
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
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "请输入 6 位数字验证码" })),
        )
            .into_response();
    };
    let _cfg_guard = state.config_lock.lock().await;
    if state.config.load().admin.totp_enabled {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "TOTP 已启用，请先关闭后再重新配置" })),
        )
            .into_response();
    }
    let verified_opt = {
        let mut auth = state.auth.lock().unwrap_or_else(|e| e.into_inner());
        match auth.pending_totp_secret.clone() {
            Some((sec, issued_at)) if issued_at.elapsed() <= PENDING_TOTP_TTL => {
                let mut probe = AuthEngine::new(String::new());
                if probe.verify_totp(&sec, code_num, logger::unix_now()) {
                    let wm = probe.totp_watermark();
                    auth.pending_totp_secret = None;
                    auth.engine.reset_totp_watermark();
                    auth.engine.restore_totp_watermark(wm);
                    Some((sec, wm))
                } else {
                    None
                }
            }
            Some(_) => {
                auth.pending_totp_secret = None;
                None
            }
            None => None,
        }
    };
    let Some((secret, watermark)) = verified_opt else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "TOTP 验证码错误或引导密钥已超时过期，请重新生成" })),
        )
            .into_response();
    };

    let (recovery_codes, recovery_hashes) = match hash_recovery_codes_blocking(&state.hash_gate).await {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };

    let mut next_cfg = (**state.config.load()).clone();
    next_cfg.admin.totp_enabled = true;
    next_cfg.admin.totp_last_step = watermark;
    next_cfg.admin.totp_secret = match state.vault.seal("admin.totp_secret", base32_encode(&secret).as_bytes()) {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response(),
    };
    next_cfg.admin.totp_recovery_hashes = recovery_hashes;
    if let Err(e) = save_config(&state.config_path, &next_cfg) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response();
    }
    state.config.store(Arc::new(next_cfg));
    logger::log(Level::Info, "auth", "已启用管理员 TOTP 双因素认证并生成一次性恢复码");
    Json(serde_json::json!({ "enabled": true, "recovery_codes": recovery_codes })).into_response()
}

async fn api_totp_regenerate_recovery(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let _cfg_guard = state.config_lock.lock().await;
    if !state.config.load().admin.totp_enabled {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "请先启用 TOTP 二步验证" })),
        )
            .into_response();
    }
    let (recovery_codes, recovery_hashes) = match hash_recovery_codes_blocking(&state.hash_gate).await {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };
    let mut next_cfg = (**state.config.load()).clone();
    next_cfg.admin.totp_recovery_hashes = recovery_hashes;
    if let Err(e) = save_config(&state.config_path, &next_cfg) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response();
    }
    state.config.store(Arc::new(next_cfg));
    logger::log(Level::Info, "auth", "已重新生成一次性 TOTP 恢复码（旧恢复码已作废）");
    Json(serde_json::json!({ "recovery_codes": recovery_codes })).into_response()
}

async fn api_totp_disable(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let _cfg_guard = state.config_lock.lock().await;
    let mut next_cfg = (**state.config.load()).clone();
    next_cfg.admin.totp_enabled = false;
    next_cfg.admin.totp_secret.clear();
    next_cfg.admin.totp_last_step = 0;
    next_cfg.admin.totp_recovery_hashes.clear();
    if let Err(e) = save_config(&state.config_path, &next_cfg) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response();
    }
    if let Ok(mut auth) = state.auth.lock() {
        auth.engine.reset_totp_watermark();
        auth.pending_totp_secret = None;
    }
    state.config.store(Arc::new(next_cfg));
    logger::log(Level::Warn, "auth", "管理员已关闭 TOTP 双因素认证");
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
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "公钥格式非法（需 ssh-ed25519 AAAA...）" })),
        )
            .into_response();
    };
    let _cfg_guard = state.config_lock.lock().await;
    let mut next_cfg = (**state.config.load()).clone();
    next_cfg.admin.authorized_ed25519_keys.retain(|k| k.id != entry.id);
    next_cfg
        .admin
        .authorized_ed25519_keys
        .push(Ed25519KeyEntry { id: entry.id, pubkey: norm_pub });
    if let Err(e) = next_cfg
        .validate_with_vault(Some(&state.vault))
        .and_then(|_| save_config(&state.config_path, &next_cfg))
    {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response();
    }
    state.config.store(Arc::new(next_cfg.clone()));
    Json(serde_json::json!({ "keys": next_cfg.admin.authorized_ed25519_keys })).into_response()
}

async fn api_delete_ed25519_key(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    let cur_tok = match require_full_admin(&state, &headers) {
        Ok(tok) => tok,
        Err(resp) => return resp,
    };
    let _cfg_guard = state.config_lock.lock().await;
    let mut next_cfg = (**state.config.load()).clone();
    let before = next_cfg.admin.authorized_ed25519_keys.len();
    next_cfg.admin.authorized_ed25519_keys.retain(|k| k.id != id);
    if next_cfg.admin.authorized_ed25519_keys.is_empty() {
        next_cfg.admin.password_login_enabled = true;
    }
    if let Err(e) = save_config(&state.config_path, &next_cfg) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response();
    }
    state.config.store(Arc::new(next_cfg.clone()));
    let mut resp = Json(serde_json::json!({ "keys": next_cfg.admin.authorized_ed25519_keys })).into_response();
    if next_cfg.admin.authorized_ed25519_keys.len() != before {
        let ttl = Duration::from_secs(next_cfg.admin.session_ttl_secs.clamp(300, 86_400));
        let peer_key = BanKey::from_peer(peer.ip());
        if let Ok(mut auth) = state.auth.lock() {
            if let Ok(fresh) = auth.sessions.revoke_all_and_reissue(&cur_tok, peer_key, SessionScope::FullAdmin, ttl) {
                let cookie = format!("{SESSION_COOKIE_NAME}={fresh}; Path=/; Max-Age={}; HttpOnly; Secure; SameSite=Strict", ttl.as_secs());
                if let Ok(hv) = header::HeaderValue::from_str(&cookie) {
                    resp.headers_mut().append(header::SET_COOKIE, hv);
                }
            }
        }
        state.pty_mgr.notify_revoke();
    }
    resp
}

async fn api_export_admin_cert(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let ck = state.admin_cert.load_full();
    let mut pem = String::new();
    for der in &ck.cert {
        pem.push_str("-----BEGIN CERTIFICATE-----\n");
        for chunk in B64.encode(der.as_ref()).as_bytes().chunks(64) {
            pem.push_str(&String::from_utf8_lossy(chunk));
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
    }
    (
        [
            (header::CONTENT_TYPE, "application/x-x509-ca-cert"),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"vane-admin.crt\""),
        ],
        pem,
    )
        .into_response()
}

async fn api_dashboard(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let cfg = state.config.load_full();
    let sampler = state.monitor_sampler.clone();
    let mcfg = cfg.monitor.clone();
    let sys = match tokio::task::spawn_blocking(move || sampler.sample(&mcfg)).await {
        Ok(s) => s,
        Err(_) => state.monitor_sampler.sample(&cfg.monitor),
    };

    // 若配置了启用中的通知渠道，异步执行低内存 / 高温告警阈值评估与冷却投递
    if cfg.notifications.iter().any(|n| n.enabled) {
        let st = state.clone();
        let cfg_clone = cfg.clone();
        let sys_clone = sys.clone();
        tokio::spawn(async move {
            evaluate_and_notify_alerts(&st.alert_state, &cfg_clone, &st.vault, &sys_clone).await;
        });
    }

    let health = state.health_registry.read().map(|g| g.clone()).unwrap_or_default();
    let ddns = state
        .ddns_status
        .read()
        .map(|g| g.values().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let certs = state
        .cert_status
        .read()
        .map(|g| g.values().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let stun_addrs = (**state.stun_addrs.load()).clone();
    let stun_list = state
        .stun_status
        .read()
        .map(|g| g.values().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let rp_list = snapshot_rule_statuses(&state.reverse_proxy_status);
    let pf_list = snapshot_rule_statuses(&state.port_forward_status);
    let cron_list = state.cron_status.snapshot();
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
        "stun": stun_list,
        "stun_public_addrs": stun_addrs,
        "reverse_proxy_status": rp_list,
        "port_forward_status": pf_list,
        "cron": cron_list,
        "bans": bans,
    }))
    .into_response()
}

#[derive(serde::Serialize)]
struct NeighborInfo {
    iface: String,
    ip: String,
    mac: String,
    state: String,
}

async fn discover_neighbors() -> Vec<NeighborInfo> {
    #[cfg(target_os = "linux")]
    {
        use tokio::io::AsyncReadExt;
        async fn run_ip(args: &[&str]) -> Option<Vec<u8>> {
            let mut child = tokio::process::Command::new("ip")
                .args(args)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .ok()?;
            let stdout = child.stdout.take()?;
            let mut buf = Vec::new();
            let ok = tokio::time::timeout(Duration::from_secs(2), async {
                stdout.take(256 * 1024).read_to_end(&mut buf).await.ok()?;
                let st = child.wait().await.ok()?;
                st.success().then_some(())
            })
            .await;
            match ok {
                Ok(Some(())) => Some(buf),
                _ => {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    None
                }
            }
        }
        let mut out = Vec::new();
        if let Some(bytes) = run_ip(&["-j", "-6", "neigh", "show"]).await {
            if let Ok(serde_json::Value::Array(items)) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                for e in items {
                    let dst = e.get("dst").and_then(|v| v.as_str()).unwrap_or("");
                    let lladdr = e.get("lladdr").and_then(|v| v.as_str()).unwrap_or("");
                    let dev = e.get("dev").and_then(|v| v.as_str()).unwrap_or("");
                    let st = e.get("state").map(|v| v.to_string()).unwrap_or_default();
                    let upper = st.to_ascii_uppercase();
                    if upper.contains("FAILED") || upper.contains("INCOMPLETE") || lladdr.is_empty() {
                        continue;
                    }
                    if let Ok(ip) = dst.parse::<std::net::Ipv6Addr>() {
                        if !ip.is_unicast_link_local() && !ip.is_loopback() {
                            out.push(NeighborInfo { iface: dev.into(), ip: ip.to_string(), mac: lladdr.into(), state: st });
                        }
                    }
                }
                return out;
            }
        }
        if let Some(bytes) = run_ip(&["-6", "neigh", "show"]).await {
            let text = String::from_utf8_lossy(&bytes);
            for line in text.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                let Some(ip_s) = parts.first() else { continue };
                let Ok(ip) = ip_s.parse::<std::net::Ipv6Addr>() else { continue };
                if ip.is_unicast_link_local() || ip.is_loopback() { continue; }
                let upper = line.to_ascii_uppercase();
                if upper.contains("FAILED") || upper.contains("INCOMPLETE") { continue; }
                let dev = parts.windows(2).find(|w| w[0] == "dev").map(|w| w[1]).unwrap_or("");
                let mac = parts.windows(2).find(|w| w[0] == "lladdr").map(|w| w[1]).unwrap_or("");
                if !mac.is_empty() {
                    out.push(NeighborInfo { iface: dev.into(), ip: ip.to_string(), mac: mac.into(), state: parts.last().copied().unwrap_or("").into() });
                }
            }
        }
        out
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

async fn api_system_network_info(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let ifaces = tokio::task::spawn_blocking(|| {
        crate::daemon::netlink_ip::list_interface_addresses()
            .into_iter()
            .map(|(iface, entry)| {
                serde_json::json!({
                    "iface": iface,
                    "ipv4": entry.ipv4.into_iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
                    "ipv6": entry.ipv6.into_iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
                })
            })
            .collect::<Vec<_>>()
    })
    .await
    .unwrap_or_default();
    let neighbors = discover_neighbors().await;
    let split_dns_path = state
        .config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("split-dns.hosts")
        .to_string_lossy()
        .into_owned();
    Json(serde_json::json!({
        "interfaces": ifaces,
        "neighbors": neighbors,
        "split_dns_path": split_dns_path,
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
    let cfg = state.config.load();
    let min_level = q.get("level").and_then(|s| Level::parse(s));
    let module = q.get("module").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let kw = q.get("q").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let limit = q
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(cfg.system.log_ring_capacity)
        .clamp(1, 1000);
    let after_seq = q.get("after_seq").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    let entries = logger::global().query_filtered(min_level, module, kw, limit, after_seq);
    let modules = logger::global().modules();
    Json(serde_json::json!({
        "entries": entries,
        "modules": modules,
        "capacity": cfg.system.log_ring_capacity,
    }))
    .into_response()
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
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(mut incoming_json): Json<serde_json::Value>,
) -> Response {
    let cur_tok = match require_full_admin(&state, &headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let _cfg_guard = state.config_lock.lock().await;
    let mut renames: Vec<(String, String)> = Vec::new();
    if let Some(obj) = incoming_json.as_object_mut() {
        if let Some(arr) = obj.remove("_renames").and_then(|v| v.as_array().cloned()) {
            for item in arr {
                if let (Some(from), Some(to)) = (
                    item.get("from").and_then(|v| v.as_str()),
                    item.get("to").and_then(|v| v.as_str()),
                ) {
                    renames.push((from.to_string(), to.to_string()));
                }
            }
        }
    }
    crate::security::vault::normalize_masked_input(&mut incoming_json);
    // 剥离 masked_config_json 注入的只读摘要字段（如 totp_recovery_hashes: { remaining: N }），防止反序列化类型冲突
    if let Some(admin_obj) = incoming_json.get_mut("admin").and_then(|v| v.as_object_mut()) {
        admin_obj.remove("password_hash");
        admin_obj.remove("totp_last_step");
        admin_obj.remove("totp_recovery_hashes");
    }

    let current_cfg = state.config.load();
    let mut next_cfg: Config = match serde_json::from_value(incoming_json) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("配置格式错误: {}", e) })),
            )
                .into_response()
        }
    };
    // L1 认证凭据与 TOTP 状态由专属接口受控修改，设置保存一律沿用当前受保护状态
    next_cfg.admin.password_hash = current_cfg.admin.password_hash.clone();
    next_cfg.admin.must_change_password = current_cfg.admin.must_change_password;
    next_cfg.admin.totp_enabled = current_cfg.admin.totp_enabled;
    next_cfg.admin.totp_secret = current_cfg.admin.totp_secret.clone();
    next_cfg.admin.totp_last_step = current_cfg.admin.totp_last_step;
    next_cfg.admin.totp_recovery_hashes = current_cfg.admin.totp_recovery_hashes.clone();

    if let Err(e) = state.vault.merge_secrets_many(&mut next_cfg, &current_cfg, &renames) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response();
    }
    if let Err(e) = next_cfg.validate_with_vault(Some(&state.vault)) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response();
    }
    if let Err(e) = save_config(&state.config_path, &next_cfg) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response();
    }
    let security_identity_changed = next_cfg.admin.username != current_cfg.admin.username
        || next_cfg.admin.secret_path != current_cfg.admin.secret_path
        || next_cfg.admin.authorized_ed25519_keys != current_cfg.admin.authorized_ed25519_keys;
    let mut restart_fields: Vec<&'static str> = Vec::new();
    if next_cfg.admin.listen_lan != current_cfg.admin.listen_lan {
        restart_fields.push("admin.listen_lan");
    }
    if next_cfg.admin.canonical_origin != current_cfg.admin.canonical_origin {
        restart_fields.push("admin.canonical_origin");
    }
    if next_cfg.admin.tls_cert_path != current_cfg.admin.tls_cert_path
        || next_cfg.admin.tls_key_path != current_cfg.admin.tls_key_path
    {
        restart_fields.push("admin.tls_cert_path");
    }
    if next_cfg.system.worker_threads != current_cfg.system.worker_threads {
        restart_fields.push("system.worker_threads");
    }
    if next_cfg.firewall.backend != current_cfg.firewall.backend {
        restart_fields.push("firewall.backend");
    }

    state.apply_runtime_settings(&next_cfg).await;
    state.config.store(Arc::new(next_cfg.clone()));
    state.reload_notify.notify_one();
    logger::log(Level::Info, "config", "配置已在 Web 设置页更新并热生效");

    let mut resp = Json(state.vault.masked_config_json(&next_cfg)).into_response();
    if security_identity_changed {
        let ttl = Duration::from_secs(next_cfg.admin.session_ttl_secs.clamp(300, 86_400));
        let peer_key = BanKey::from_peer(peer.ip());
        if let Ok(mut auth) = state.auth.lock() {
            if let Ok(fresh) = auth.sessions.revoke_all_and_reissue(&cur_tok, peer_key, SessionScope::FullAdmin, ttl) {
                let cookie = format!("{SESSION_COOKIE_NAME}={fresh}; Path=/; Max-Age={}; HttpOnly; Secure; SameSite=Strict", ttl.as_secs());
                if let Ok(hv) = header::HeaderValue::from_str(&cookie) {
                    resp.headers_mut().append(header::SET_COOKIE, hv);
                }
            }
        }
        state.pty_mgr.notify_revoke();
    }
    if !restart_fields.is_empty() {
        if let Ok(hv) = header::HeaderValue::from_str(&restart_fields.join(",")) {
            resp.headers_mut()
                .insert(header::HeaderName::from_static("x-vane-restart-required"), hv);
        }
    }
    if let Some(sp) = boundary::active_secret_path(&next_cfg) {
        if let Some(entry_hv) = boundary::build_entry_set_cookie(state.vault.mac_key(), sp) {
            resp.headers_mut().append(header::SET_COOKIE, entry_hv);
        }
    }
    resp
}

async fn api_put_modules(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(modules): Json<ModulesConfig>,
) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let _cfg_guard = state.config_lock.lock().await;
    let mut next_cfg = (**state.config.load()).clone();
    let prev_modules = next_cfg.modules.clone();
    next_cfg.modules = modules.clone();
    if let Err(e) = save_config(&state.config_path, &next_cfg) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response();
    }
    // 对被关闭的模块立即撤销其关联的防火墙规则与活跃终端会话
    if prev_modules.reverse_proxy && !modules.reverse_proxy {
        let _ = state.firewall.remove_module_rules("reverse_proxy").await;
    }
    if prev_modules.port_forward && !modules.port_forward {
        let _ = state.firewall.remove_module_rules("port_forward").await;
    }
    if prev_modules.ddns && !modules.ddns {
        let _ = state.firewall.remove_module_rules("ddns").await;
    }
    if prev_modules.web_terminal && !modules.web_terminal {
        state.pty_mgr.notify_revoke();
    }
    state.config.store(Arc::new(next_cfg));
    state.reload_notify.notify_one();
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
    let _cfg_guard = state.config_lock.lock().await;
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
    if let Err(e) = next_cfg.validate_with_vault(Some(&state.vault)) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response();
    }
    if let Err(e) = save_config(&state.config_path, &next_cfg) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response();
    }
    state.config.store(Arc::new(next_cfg));
    state.reload_notify.notify_one();
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
    match sync_ddns_entry(entry, &cfg, &state.vault, &state.firewall, &state.ddns_status).await {
        Ok(st) => {
            let has_err = st.status == "failed"
                || st.ipv4.error.is_some()
                || st.ipv6.error.is_some()
                || st.firewall_error.is_some();
            if has_err {
                let mut val = serde_json::to_value(&st).unwrap_or_default();
                let msgs: Vec<&str> = [
                    st.ipv4.error.as_deref(),
                    st.ipv6.error.as_deref(),
                    st.firewall_error.as_deref(),
                ]
                .into_iter()
                .flatten()
                .collect();
                let summary = if msgs.is_empty() { st.status.clone() } else { msgs.join("; ") };
                val["message"] = serde_json::json!(summary);
                (StatusCode::BAD_GATEWAY, Json(val)).into_response()
            } else {
                (StatusCode::OK, Json(st)).into_response()
            }
        }
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
    match issue_or_renew_cert(
        entry,
        &cfg,
        &state.vault,
        &state.cert_table,
        &state.cert_status,
        &state.admin_cert,
        true,
    )
    .await
    {
        Ok(st) => {
            if st.status == "active" {
                (StatusCode::OK, Json(st)).into_response()
            } else {
                let mut val = serde_json::to_value(&st).unwrap_or_default();
                val["message"] = serde_json::json!(st.last_error.clone().unwrap_or_else(|| st.status.clone()));
                (StatusCode::BAD_GATEWAY, Json(val)).into_response()
            }
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
    match probe_and_sync_stun_entry(entry, &cfg, &state.vault, &state.stun_addrs, &state.stun_status).await {
        Ok(st) => Json(st).into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, Json(serde_json::json!({ "error": e }))).into_response(),
    }
}

async fn api_cron_preview(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let expr = q.get("expr").map(String::as_str).unwrap_or("");
    let cfg = state.config.load();
    let tz = cfg.timezone_offset_secs();
    match CronSchedule::parse(expr) {
        Ok(sched) => {
            let runs = sched.next_runs(logger::unix_now(), tz, 3);
            let formatted: Vec<String> = runs.iter().map(|ts| logger::format_rfc3339(*ts, tz)).collect();
            Json(serde_json::json!({ "valid": true, "next_runs": runs, "formatted": formatted })).into_response()
        }
        Err(e) => Json(serde_json::json!({ "valid": false, "error": e })).into_response(),
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
    let cfg = state.config.load_full();
    let Some(job) = cfg.cron.iter().find(|c| c.name == name).cloned() else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "Cron 任务不存在" }))).into_response();
    };
    let ctx = state.build_cron_context(cfg);
    match execute_cron_job_with_ctx(&job, Some(&ctx)).await {
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
    match send_test_notification(
        n,
        &state.vault,
        "Vane 通知测试",
        "这是一条来自 Vane 网关管理面板的测试消息",
    )
    .await
    {
        Ok(outcome) => Json(serde_json::json!({ "outcome": outcome })).into_response(),
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
    let fw_removed = state.firewall.unban_source_cidr(&ip).await.unwrap_or(false);
    Json(serde_json::json!({ "unbanned": removed || fw_removed })).into_response()
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

fn read_file_bounded(path: &std::path::Path, limit: usize) -> Result<Option<Vec<u8>>, String> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_file() {
                return Ok(None);
            }
            if meta.len() as usize > limit {
                return Err(format!("文件 {} 超过备份大小上限", path.display()));
            }
            std::fs::read(path)
                .map(Some)
                .map_err(|e| format!("读取 {} 失败: {}", path.display(), e))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("读取 {} 元数据失败: {}", path.display(), e)),
    }
}

fn collect_backup_files(
    data_dir: &std::path::Path,
    cfg: &Config,
    vault: &Vault,
) -> Result<(BTreeMap<String, Vec<u8>>, serde_json::Value), String> {
    let mut files = BTreeMap::new();
    let mut admin_tls = false;
    let crt_path = data_dir.join("certs").join("admin.crt");
    let key_path = data_dir.join("certs").join("admin.key");
    if let (Ok(Some(crt)), Ok(Some(key))) = (
        read_file_bounded(&crt_path, 256 * 1024),
        read_file_bounded(&key_path, 256 * 1024),
    ) {
        files.insert("certs/admin.crt".into(), crt);
        files.insert("certs/admin.key".into(), key);
        admin_tls = true;
    }

    let mut acme_accounts = 0usize;
    let acc_dir = data_dir.join("acme-accounts");
    if let Ok(entries) = std::fs::read_dir(&acc_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(id) = name.strip_suffix(".json") else { continue };
            if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            if let Some(raw) = read_file_bounded(&entry.path(), 128 * 1024)? {
                let encoded = std::str::from_utf8(&raw).map_err(|_| "ACME 账户文件编码错误")?;
                let plain = vault.reveal_string(&format!("acme.account.{id}"), encoded.trim())?;
                files.insert(format!("acme-accounts/{id}.json"), plain.into_bytes());
                acme_accounts += 1;
            }
        }
    }

    let mut acme_challenges = 0usize;
    let chal_dir = data_dir.join("acme-challenges");
    if let Ok(entries) = std::fs::read_dir(&chal_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let key = format!("acme-challenges/{name}");
            if !crate::security::vault::validate_backup_file_key(&key) {
                continue;
            }
            if let Some(raw) = read_file_bounded(&entry.path(), 128 * 1024)? {
                files.insert(key, raw);
                acme_challenges += 1;
            }
        }
    }

    let mut acme_certs = 0usize;
    let mut seen_domains = std::collections::BTreeSet::new();
    for a in &cfg.acme {
        let safe = crate::daemon::acme_store::safe_name(&a.domain);
        if !seen_domains.insert(safe.clone()) {
            continue;
        }
        let bpath = crate::daemon::acme_store::bundle_path(std::path::Path::new(&a.cert_dir), &a.domain);
        let key = format!("acme-certs/{safe}/bundle.json");
        if crate::security::vault::validate_backup_file_key(&key) {
            if let Some(raw) = read_file_bounded(&bpath, 256 * 1024)? {
                files.insert(key, raw);
                acme_certs += 1;
            }
        }
    }

    let summary = serde_json::json!({
        "admin_tls": admin_tls,
        "acme_accounts": acme_accounts,
        "acme_certs": acme_certs,
        "acme_challenges": acme_challenges,
    });
    Ok((files, summary))
}

async fn restore_backup_files(
    data_dir: &std::path::Path,
    cfg: &Config,
    files: &BTreeMap<String, Vec<u8>>,
    vault: &Vault,
    cert_table: &Arc<ArcSwap<CertTable>>,
    admin_cert: &Arc<ArcSwap<rustls::sign::CertifiedKey>>,
) -> Result<serde_json::Value, String> {
    let mut admin_tls = false;
    let mut acme_accounts = 0usize;
    let mut acme_certs = 0usize;
    let mut acme_challenges = 0usize;

    if let (Some(crt), Some(key)) = (files.get("certs/admin.crt"), files.get("certs/admin.key")) {
        let ck = crate::net::tls_resolver::certified_key_from_pem(crt, key)?;
        let certs_dir = data_dir.join("certs");
        let crt_dst = certs_dir.join("admin.crt");
        let key_dst = certs_dir.join("admin.key");
        let crt_bytes = crt.clone();
        let key_bytes = key.clone();
        tokio::task::spawn_blocking(move || {
            std::fs::create_dir_all(&certs_dir).map_err(|e| format!("创建证书目录失败: {e}"))?;
            let _ = std::fs::set_permissions(&certs_dir, std::os::unix::fs::PermissionsExt::from_mode(0o700));
            crate::config::crash_safe_atomic_write(&crt_dst, &crt_bytes, crate::config::random_nonce())
                .map_err(|e| format!("写入管理证书失败: {e}"))?;
            crate::config::crash_safe_atomic_write(&key_dst, &key_bytes, crate::config::random_nonce())
                .map_err(|e| format!("写入管理私钥失败: {e}"))?;
            Ok::<(), String>(())
        })
        .await
        .map_err(|_| "恢复管理证书任务失败")??;
        admin_cert.store(ck);
        admin_tls = true;
    }

    for (key, raw) in files {
        if let Some(id_file) = key.strip_prefix("acme-accounts/") {
            let id = id_file.strip_suffix(".json").unwrap_or("");
            if serde_json::from_slice::<serde_json::Value>(raw).is_err() {
                return Err(format!("备份内 ACME 账户 {} JSON 非法", id));
            }
            let sealed = vault.seal(&format!("acme.account.{id}"), raw)?;
            let dst = data_dir.join("acme-accounts").join(id_file);
            crate::daemon::acme_store::atomic(dst, sealed.into_bytes()).await?;
            acme_accounts += 1;
        } else if let Some(chal_file) = key.strip_prefix("acme-challenges/") {
            if serde_json::from_slice::<serde_json::Value>(raw).is_err() {
                return Err(format!("备份内挑战日志 {} JSON 非法", chal_file));
            }
            let dst = data_dir.join("acme-challenges").join(chal_file);
            crate::daemon::acme_store::atomic(dst, raw.clone()).await?;
            acme_challenges += 1;
        } else if let Some(rest) = key.strip_prefix("acme-certs/") {
            let safe_dir = rest.strip_suffix("/bundle.json").unwrap_or("");
            let bundle: crate::daemon::acme_store::Bundle =
                serde_json::from_slice(raw).map_err(|_| format!("备份内证书包 {} 格式非法", safe_dir))?;
            let verified = crate::daemon::acme_store::verify(&bundle)?;
            let now = logger::unix_now();
            if verified.expires <= now || verified.issued > now + 300 {
                logger::log(Level::Warn, "backup", &format!("备份证书 {} 已过期或未生效，跳过恢复", safe_dir));
                continue;
            }
            let matching_acme = cfg
                .acme
                .iter()
                .find(|a| crate::daemon::acme_store::safe_name(&a.domain) == safe_dir);
            let target_dir = matching_acme
                .map(|a| PathBuf::from(&a.cert_dir))
                .unwrap_or_else(|| data_dir.join("certs"));
            let target_domain = matching_acme
                .map(|a| a.domain.as_str())
                .or_else(|| bundle.domains.first().map(String::as_str))
                .unwrap_or(safe_dir);
            crate::daemon::acme_store::store(&target_dir, target_domain, &bundle).await?;
            cert_table.rcu(|current| {
                let mut next = CertTable {
                    exact: current.exact.clone(),
                    wildcard: current.wildcard.clone(),
                    fallback: current.fallback.clone(),
                };
                for name in &bundle.domains {
                    if let Some(suffix) = name.strip_prefix('*') {
                        next.wildcard.insert(suffix.to_ascii_lowercase(), verified.key.clone());
                    } else {
                        next.exact.insert(name.to_ascii_lowercase(), verified.key.clone());
                    }
                }
                Arc::new(next)
            });
            acme_certs += 1;
        }
    }

    Ok(serde_json::json!({
        "admin_tls": admin_tls,
        "acme_accounts": acme_accounts,
        "acme_certs": acme_certs,
        "acme_challenges": acme_challenges,
    }))
}

async fn api_backup_export(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<BackupExportReq>,
) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let cfg = state.config.load_full();
    let data_dir = state
        .config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."))
        .to_path_buf();
    let vault = state.vault.clone();
    let cfg_read = cfg.clone();
    let collect_res = tokio::task::spawn_blocking(move || collect_backup_files(&data_dir, &cfg_read, &vault))
        .await
        .map_err(|_| "收集备份文件任务失败".to_string())
        .and_then(|r| r);
    let (files, summary) = match collect_res {
        Ok(pair) => pair,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response(),
    };

    let ph_gate = state.hash_gate.clone();
    let vault = state.vault.clone();
    let pw = req.password.into_bytes();
    let Ok(res) = ph_gate
        .run(move || vault.export_backup(&cfg, &pw, files))
        .await
    else {
        return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({ "error": "繁忙" }))).into_response();
    };
    match res {
        Ok(bytes) => Json(serde_json::json!({
            "backup_blob": B64.encode(bytes),
            "summary": summary,
        }))
        .into_response(),
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
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<BackupImportReq>,
) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let Ok(raw_bytes) = B64.decode(req.backup_blob.trim()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "备份文件 Base64 编码错误" })),
        )
            .into_response();
    };
    let ph_gate = state.hash_gate.clone();
    let vault = state.vault.clone();
    let pw = req.password.into_bytes();
    let Ok(res) = ph_gate.run(move || vault.import_backup(&raw_bytes, &pw)).await else {
        return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({ "error": "繁忙" }))).into_response();
    };
    let (restored_cfg, files) = match res {
        Ok(c) => c,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response(),
    };
    if let Err(e) = restored_cfg.validate_with_vault(Some(&state.vault)) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response();
    }
    if restored_cfg.admin.password_login_enabled && PasswordHash::parse(&restored_cfg.admin.password_hash).is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "备份内管理员密码哈希无效，拒绝导入以防锁死" })),
        )
            .into_response();
    }

    let _cfg_guard = state.config_lock.lock().await;
    let current_cfg = state.config.load();
    let data_dir = state
        .config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."))
        .to_path_buf();
    let restored_summary = match restore_backup_files(
        &data_dir,
        &restored_cfg,
        &files,
        &state.vault,
        &state.cert_table,
        &state.admin_cert,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response(),
    };

    if let Err(e) = save_config(&state.config_path, &restored_cfg) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response();
    }
    let mut restart_fields: Vec<&'static str> = Vec::new();
    if restored_cfg.admin.listen_lan != current_cfg.admin.listen_lan {
        restart_fields.push("admin.listen_lan");
    }
    if restored_cfg.admin.canonical_origin != current_cfg.admin.canonical_origin {
        restart_fields.push("admin.canonical_origin");
    }
    if restored_cfg.admin.tls_cert_path != current_cfg.admin.tls_cert_path
        || restored_cfg.admin.tls_key_path != current_cfg.admin.tls_key_path
    {
        restart_fields.push("admin.tls_cert_path");
    }
    if restored_cfg.system.worker_threads != current_cfg.system.worker_threads {
        restart_fields.push("system.worker_threads");
    }
    if restored_cfg.firewall.backend != current_cfg.firewall.backend {
        restart_fields.push("firewall.backend");
    }

    state.apply_runtime_settings(&restored_cfg).await;
    let ban_key = BanKey::from_peer(peer.ip());
    let ttl = Duration::from_secs(restored_cfg.admin.session_ttl_secs.clamp(300, 86_400));
    let scope = match PasswordHash::parse(&restored_cfg.admin.password_hash) {
        Some(ph) => AuthEngine::resolve_session_scope(
            restored_cfg.admin.must_change_password,
            &ph.salt,
            &ph.hash,
            ph.iters,
        ),
        None => SessionScope::MustChangePassword,
    };
    let new_token = {
        let mut auth = state.auth.lock().unwrap_or_else(|e| e.into_inner());
        auth.engine.reset_totp_watermark();
        auth.engine.restore_totp_watermark(restored_cfg.admin.totp_last_step);
        auth.pending_totp_secret = None;
        auth.sessions.revoke_all();
        match auth.sessions.issue(scope, ban_key, ttl) {
            Ok(t) => t,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response(),
        }
    };
    state.pty_mgr.notify_revoke();
    state.config.store(Arc::new(restored_cfg.clone()));
    state.reload_notify.notify_one();
    logger::log(Level::Info, "backup", "加密备份已成功导入并热重载生效");

    let cookie = format!(
        "{}={}; Path=/; Max-Age={}; HttpOnly; Secure; SameSite=Strict",
        SESSION_COOKIE_NAME,
        new_token,
        ttl.as_secs()
    );
    let body = serde_json::json!({
        "authenticated": true,
        "username": restored_cfg.admin.username,
        "must_change_password": scope == SessionScope::MustChangePassword,
        "password_login_enabled": restored_cfg.admin.password_login_enabled,
        "totp_enabled": restored_cfg.admin.totp_enabled,
        "totp_recovery_remaining": restored_cfg.admin.totp_recovery_hashes.len(),
        "has_ed25519_keys": !restored_cfg.admin.authorized_ed25519_keys.is_empty(),
        "ed25519_key_ids": restored_cfg.admin.authorized_ed25519_keys.iter().map(|k| &k.id).collect::<Vec<_>>(),
        "session_ttl_secs": restored_cfg.admin.session_ttl_secs,
        "language": restored_cfg.system.language,
        "modules": restored_cfg.modules,
        "secret_path": boundary::active_secret_path(&restored_cfg).unwrap_or("/"),
        "restored_summary": restored_summary,
        "restart_required": restart_fields,
    });
    let mut resp = Json(body).into_response();
    if let Ok(hv) = header::HeaderValue::from_str(&cookie) {
        resp.headers_mut().append(header::SET_COOKIE, hv);
    }
    if let Some(sp) = boundary::active_secret_path(&restored_cfg) {
        if let Some(entry_hv) = boundary::build_entry_set_cookie(state.vault.mac_key(), sp) {
            resp.headers_mut().append(header::SET_COOKIE, entry_hv);
        }
    }
    if !restart_fields.is_empty() {
        if let Ok(hv) = header::HeaderValue::from_str(&restart_fields.join(",")) {
            resp.headers_mut()
                .insert(header::HeaderName::from_static("x-vane-restart-required"), hv);
        }
    }
    resp
}

async fn api_backup_sanitized(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return resp;
    }
    let cfg = state.config.load();
    match crate::security::vault::sanitized_export(&cfg) {
        Ok(toml_text) => Json(serde_json::json!({ "toml": toml_text })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response(),
    }
}

#[derive(Deserialize, Default)]
struct PtyTicketReq {
    #[serde(default)]
    target: String,
    #[serde(default)]
    reauth_password: String,
}

async fn api_pty_ticket(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Response {
    let session_token = match require_full_admin(&state, &headers) {
        Ok(tok) => tok,
        Err(resp) => return resp,
    };
    let cfg = state.config.load();
    if !cfg.modules.web_terminal {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "WEB_TERMINAL_DISABLED",
                "message": "Web 终端功能默认关闭，请先在「系统设置 -> 功能模块管理」中打开"
            })),
        )
            .into_response();
    }
    let req: PtyTicketReq = if raw_body.is_empty() {
        PtyTicketReq::default()
    } else {
        match serde_json::from_slice(&raw_body) {
            Ok(v) => v,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "终端票据请求格式错误" })),
                )
                    .into_response()
            }
        }
    };
    let target = if req.target.trim().is_empty() {
        "host".to_string()
    } else {
        req.target.trim().to_string()
    };
    if target.starts_with("container:") && !cfg.modules.docker {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "MODULE_DISABLED", "message": "Docker 模块已关闭" })),
        )
            .into_response();
    }

    // 若开启打开终端二次认证，校验管理员密码（使用 403 防止前端误判为会话过期登出）
    if cfg.web_terminal.require_reauth {
        let ban_key = BanKey::from_peer(peer.ip());
        if state.fail2ban.is_key_banned(ban_key) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "IP_BANNED", "message": "认证失败次数过多，该网络已被临时封禁" })),
            )
                .into_response();
        }
        if req.reauth_password.is_empty() {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "REAUTH_REQUIRED",
                    "message": "打开 Web 终端前需要二次验证管理员密码"
                })),
            )
                .into_response();
        }
        let Some(ph) = PasswordHash::parse(&cfg.admin.password_hash) else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "密码未初始化" })),
            )
                .into_response();
        };
        let pw = req.reauth_password.into_bytes();
        let Ok(ok) = state.hash_gate.run(move || ph.verify(&pw)).await else {
            return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({ "error": "认证繁忙" }))).into_response();
        };
        if !ok {
            on_login_failed(&state, ban_key).await;
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "error": "INVALID_REAUTH_PASSWORD", "message": "二次验证密码错误" })),
            )
                .into_response();
        }
    }

    match state.pty_mgr.issue_bound_ticket(
        &session_token,
        &target,
        BanKey::from_peer(peer.ip()),
        cfg.web_terminal.max_sessions,
    ) {
        Ok(ticket) => Json(serde_json::json!({ "ticket": ticket, "target": target, "expires_in": 30 })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response(),
    }
}

async fn api_pty_ws(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    ws: WebSocketUpgrade,
    axum::Extension(permit): axum::Extension<Arc<tokio::sync::OwnedSemaphorePermit>>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let cfg = state.config.load();
    if !cfg.modules.web_terminal {
        return (StatusCode::FORBIDDEN, "Web 终端已关闭").into_response();
    }
    let Some(ticket) = q.get("ticket") else {
        return (StatusCode::UNAUTHORIZED, "缺少终端 Ticket").into_response();
    };
    let target = q.get("target").cloned().unwrap_or_else(|| "host".into());
    let Some(session_digest) = state
        .pty_mgr
        .consume_bound_ticket(ticket, &target, BanKey::from_peer(peer.ip()))
    else {
        return (StatusCode::UNAUTHORIZED, "无效、已过期或目标不匹配的终端 Ticket").into_response();
    };
    if !crate::net::reverse_proxy::ProxyAuthorization::session_alive(state.as_ref(), &session_digest) {
        return (StatusCode::UNAUTHORIZED, "关联登录会话已失效").into_response();
    }
    let cols = q
        .get("cols")
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(100);
    let rows = q
        .get("rows")
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(28);
    let pty_mgr = state.pty_mgr.clone();
    let term_cfg = cfg.web_terminal.clone();
    let docker_sock = cfg.admin.docker_socket.clone();
    let docker_cfg = cfg.docker.clone();
    let st_check = state.clone();
    ws.max_message_size(64 * 1024)
        .max_frame_size(64 * 1024)
        .on_upgrade(move |socket| async move {
        let _permit = permit;
        handle_pty_websocket(
            socket,
            &pty_mgr,
            term_cfg,
            docker_sock,
            docker_cfg,
            target,
            cols,
            rows,
            move || {
                st_check.config.load().modules.web_terminal
                    && crate::net::reverse_proxy::ProxyAuthorization::session_alive(
                        st_check.as_ref(),
                        &session_digest,
                    )
            },
        )
        .await;
    })
}

async fn serve_manifest(State(state): State<Arc<AppState>>) -> Response {
    let cfg = state.config.load();
    let start_url = boundary::active_secret_path(&cfg).unwrap_or("/").to_string();
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
        [
            (header::CONTENT_TYPE, "application/manifest+json; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        manifest.to_string(),
    )
        .into_response()
}

async fn serve_sw() -> Response {
    let sw_code = format!(
        r#"const CACHE_NAME = 'vane-shell-{}';
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => {{
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))));
  self.clients.claim();
}});
self.addEventListener('fetch', (e) => {{
  if (e.request.method !== 'GET') return;
  const url = new URL(e.request.url);
  if (url.origin !== self.location.origin || url.pathname.startsWith('/api/')) return;
  if (url.pathname === '/icon.svg') {{
    e.respondWith(
      fetch(e.request).then(async (resp) => {{
        if (resp && resp.status === 200 && resp.type === 'basic') {{
          const cache = await caches.open(CACHE_NAME);
          cache.put(e.request, resp.clone()).catch(() => {{}});
        }}
        return resp;
      }}).catch(() => caches.match(e.request))
    );
    return;
  }}
  if (!url.pathname.startsWith('/assets/')) return;
  e.respondWith(
    caches.open(CACHE_NAME).then(async (cache) => {{
      const cached = await cache.match(e.request);
      if (cached) return cached;
      const resp = await fetch(e.request);
      if (resp && resp.status === 200 && resp.type === 'basic') cache.put(e.request, resp.clone()).catch(() => {{}});
      return resp;
    }})
  );
}});
"#,
        env!("CARGO_PKG_VERSION")
    );
    (
        [
            (header::CONTENT_TYPE, "application/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        sw_code,
    )
        .into_response()
}

async fn serve_static_or_spa(uri: Uri, method: Method, headers: HeaderMap) -> Response {
    if method != Method::GET && method != Method::HEAD {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    if uri.path().starts_with("/api/") {
        return StatusCode::NOT_FOUND.into_response();
    }
    let raw_path = uri.path().trim_start_matches('/');
    if raw_path.contains(['%', '\\']) || raw_path.split('/').any(|p| p.starts_with('.')) {
        return StatusCode::NOT_FOUND.into_response();
    }
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
    let cache_ctrl = if path.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };

    let is_head = method == Method::HEAD;

    // 优先检查 Brotli (.br) 与 Gzip (.gz) 预压缩切片，直接零拷贝返回 ELF .rodata Bytes
    if accept_enc.contains("br") {
        let br_name = format!("{}.br", path);
        if let Some(f) = load_asset(&br_name) {
            let len = f.len().to_string();
            return (
                [
                    (header::CONTENT_TYPE, mime),
                    (header::CONTENT_ENCODING, "br"),
                    (header::CACHE_CONTROL, cache_ctrl),
                    (header::VARY, "Accept-Encoding"),
                    (header::CONTENT_LENGTH, len.as_str()),
                ],
                if is_head { Body::empty() } else { Body::from(f) },
            )
                .into_response();
        }
    }
    if accept_enc.contains("gzip") {
        let gz_name = format!("{}.gz", path);
        if let Some(f) = load_asset(&gz_name) {
            let len = f.len().to_string();
            return (
                [
                    (header::CONTENT_TYPE, mime),
                    (header::CONTENT_ENCODING, "gzip"),
                    (header::CACHE_CONTROL, cache_ctrl),
                    (header::VARY, "Accept-Encoding"),
                    (header::CONTENT_LENGTH, len.as_str()),
                ],
                if is_head { Body::empty() } else { Body::from(f) },
            )
                .into_response();
        }
    }
    if let Some(f) = load_asset(path) {
        let len = f.len().to_string();
        return (
            [
                (header::CONTENT_TYPE, mime),
                (header::CACHE_CONTROL, cache_ctrl),
                (header::CONTENT_LENGTH, len.as_str()),
            ],
            if is_head { Body::empty() } else { Body::from(f) },
        )
            .into_response();
    }
    StatusCode::NOT_FOUND.into_response()
}

fn load_asset(rel_path: &str) -> Option<Bytes> {
    if rel_path.is_empty()
        || rel_path.starts_with('/')
        || rel_path.contains(['\\', '%'])
        || rel_path.split('/').any(|part| part.is_empty() || part.starts_with('.'))
    {
        return None;
    }
    WebAssets::get(rel_path).map(|f| match f.data {
        Cow::Borrowed(static_slice) => Bytes::from_static(static_slice),
        Cow::Owned(vec) => Bytes::from(vec),
    })
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

    fn trusted_request() -> axum::http::request::Builder {
        Request::builder()
            .header(header::HOST, "192.168.1.1:23456")
            .header(header::ORIGIN, "https://192.168.1.1:23456")
            .extension(ConnectInfo("192.168.1.2:12345".parse::<SocketAddr>().unwrap()))
    }

    async fn make_test_app_with_secret_path(tmp_dir: &std::path::Path, secret_path: &str) -> (Router, Arc<AppState>) {
        let cfg_path = tmp_dir.join("config.toml");
        let mut outcome = crate::config::load_or_init(&cfg_path).unwrap();
        outcome.config.admin.secret_path = secret_path.to_string();
        save_config(&cfg_path, &outcome.config).unwrap();
        let vault = Arc::new(Vault::load_or_create(tmp_dir).unwrap());
        let mut firewall_cfg = outcome.config.firewall.clone();
        firewall_cfg.auto_manage = false;
        let firewall = FirewallManager::detect_and_init(firewall_cfg).await;
        let state = Arc::new(AppState {
            config_path: cfg_path,
            config: Arc::new(ArcSwap::from_pointee(outcome.config.clone())),
            config_lock: tokio::sync::Mutex::new(()),
            vault,
            auth: Mutex::new(AuthState::new(outcome.config.admin.canonical_origin.clone(), 0)),
            hash_gate: Arc::new(HashGate::new()),
            fail2ban: Arc::new(Fail2Ban::new()),
            firewall,
            health_registry: crate::supervisor::new_health_registry(),
            ddns_status: Arc::new(crate::daemon::ddns::DdnsRuntime::default()),
            cert_table: Arc::new(ArcSwap::from_pointee(CertTable::default())),
            cert_status: Arc::new(AcmeRuntime::new(tmp_dir.to_path_buf())),
            admin_cert: Arc::new(ArcSwap::from(crate::net::tls_resolver::generate_self_signed_cert(&[]).unwrap().2)),
            stun_addrs: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            stun_status: crate::net::stun::new_stun_runtime(),
            reverse_proxy_status: crate::net::new_rule_status_map(),
            port_forward_status: crate::net::new_rule_status_map(),
            cron_status: CronRuntime::new(),
            monitor_sampler: MonitorSampler::new(),
            alert_state: AlertState::default(),
            global_quota: ConnectionQuota::new(128),
            pty_mgr: Arc::new(PtyManager::new()),
            proxy_tickets: crate::security::tickets::SessionTickets::default(),
            reload_notify: Arc::new(Notify::new()),
        });
        (build_router(state.clone()), state)
    }

    async fn make_test_app(tmp_dir: &std::path::Path) -> Router {
        make_test_app_with_secret_path(tmp_dir, "/").await.0
    }

    #[tokio::test]
    async fn rejects_missing_origin_and_disabled_module_endpoints() {
        let tmp = std::env::temp_dir().join(format!("vane_guard_test_{}", crate::config::random_nonce()));
        std::fs::create_dir_all(&tmp).unwrap();
        let app = make_test_app(&tmp).await;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/logout")
                    .header(header::HOST, "192.168.1.1:23456")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        // 未登录访问关闭模块的接口返回 401，防止未认证枚举已启用子模块
        for path in ["/api/cron/missing/run", "/api/stun/missing/probe", "/api/pty/ticket"] {
            let response = app
                .clone()
                .oneshot(trusted_request().method("POST").uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        // 登录完整管理员后访问关闭模块，由边界守卫返回 403 MODULE_DISABLED
        let login_r = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"username":"admin","password":"admin321"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let init_ck = login_r
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let ch_r = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/change-password")
                    .header(header::COOKIE, &init_ck)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"current_password":"admin321","new_password":"Vane#GuardPass1"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let admin_ck = ch_r
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        for path in ["/api/cron/missing/run", "/api/stun/missing/probe", "/api/pty/ticket"] {
            let response = app
                .clone()
                .oneshot(
                    trusted_request()
                        .method("POST")
                        .uri(path)
                        .header(header::COOKIE, &admin_ck)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            let body = to_bytes(response.into_body(), 1024).await.unwrap();
            assert!(String::from_utf8_lossy(&body).contains("MODULE_DISABLED"));
        }
        for path in ["/api/not-found", "/../../Cargo.toml", "/%2e%2e/package.json", "/missing.js"] {
            let response = app
                .clone()
                .oneshot(trusted_request().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
        std::fs::remove_dir_all(tmp).unwrap();
    }

    #[tokio::test]
    async fn secret_path_gate_blocks_uninvited_requests_and_grants_entry_cookie() {
        let tmp = std::env::temp_dir().join(format!("vane_secpath_test_{}", crate::config::random_nonce()));
        std::fs::create_dir_all(&tmp).unwrap();
        let (app, _) = make_test_app_with_secret_path(&tmp, "/_vane_gate123456").await;

        // 未携带入口 Cookie 直接访问 / 或 /api/auth/status 一律返回 404
        for uri in ["/", "/api/auth/status"] {
            let r = app
                .clone()
                .oneshot(trusted_request().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::NOT_FOUND, "uri={uri}");
        }

        // 访问正确的 secret_path 获得 index.html 与 vane_entry Cookie
        let entry_resp = app
            .clone()
            .oneshot(trusted_request().uri("/_vane_gate123456").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(entry_resp.status(), StatusCode::OK);
        let entry_cookie = entry_resp
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        assert!(entry_cookie.starts_with("vane_entry="));

        // 携带 vane_entry Cookie 后可正常访问 /api/auth/status
        let st_resp = app
            .oneshot(
                trusted_request()
                    .uri("/api/auth/status")
                    .header(header::COOKIE, &entry_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(st_resp.status(), StatusCode::OK);
        std::fs::remove_dir_all(tmp).unwrap();
    }

    #[tokio::test]
    async fn settings_get_then_put_roundtrip_and_totp_recovery_code_single_use() {
        let tmp = std::env::temp_dir().join(format!("vane_roundtrip_test_{}", crate::config::random_nonce()));
        std::fs::create_dir_all(&tmp).unwrap();
        let (app, state) = make_test_app_with_secret_path(&tmp, "/").await;

        // 登录并完成初始改密
        let login = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"username":"admin","password":"admin321"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let c0 = login.headers()[header::SET_COOKIE].to_str().unwrap().split(';').next().unwrap().to_string();
        let pw_resp = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/change-password")
                    .header(header::COOKIE, &c0)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"current_password":"admin321","new_password":"Vane#2026Strong"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pw_resp.status(), StatusCode::OK);
        let admin_cookie = pw_resp.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();

        // GET /api/settings -> 修改 global_max_conns -> PUT /api/settings 必须 200 OK（不因 totp_recovery_hashes 脱敏结构失败）
        let get_res = app
            .clone()
            .oneshot(
                trusted_request()
                    .uri("/api/settings")
                    .header(header::COOKIE, &admin_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get_res.status(), StatusCode::OK);
        let mut settings_val: serde_json::Value =
            serde_json::from_slice(&to_bytes(get_res.into_body(), 131_072).await.unwrap()).unwrap();
        settings_val["system"]["global_max_conns"] = serde_json::json!(256);

        let put_res = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("PUT")
                    .uri("/api/settings")
                    .header(header::COOKIE, &admin_cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(settings_val.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put_res.status(), StatusCode::OK);
        assert_eq!(state.global_quota.capacity(), 256);

        // 绑定 TOTP 并验证：1) 水位线持久化落盘；2) 一次性恢复码用过即焚不可重用
        let setup_res = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/totp/setup")
                    .header(header::COOKIE, &admin_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let setup_json: serde_json::Value =
            serde_json::from_slice(&to_bytes(setup_res.into_body(), 8192).await.unwrap()).unwrap();
        let secret_b32 = setup_json["secret_base32"].as_str().unwrap();
        let secret_raw = base32_decode(secret_b32).unwrap();
        let code = crate::security::auth::totp_code(&secret_raw, logger::unix_now() / 30);

        let enable_res = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/totp/enable")
                    .header(header::COOKIE, &admin_cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::json!({ "code": format!("{:06}", code) }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(enable_res.status(), StatusCode::OK);
        let enable_json: serde_json::Value =
            serde_json::from_slice(&to_bytes(enable_res.into_body(), 8192).await.unwrap()).unwrap();
        let recovery_code = enable_json["recovery_codes"][0].as_str().unwrap().to_string();

        // 水位线已写入磁盘配置
        let on_disk = crate::config::load_or_init(&state.config_path).unwrap().config;
        assert!(on_disk.admin.totp_last_step > 0);
        assert_eq!(on_disk.admin.totp_recovery_hashes.len(), 6);

        // 首次使用恢复码登录成功，剩余恢复码减为 5
        let rec_login_1 = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "username": "admin",
                            "password": "Vane#2026Strong",
                            "totp_code": recovery_code,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rec_login_1.status(), StatusCode::OK);
        assert_eq!(state.config.load().admin.totp_recovery_hashes.len(), 5);

        // 重放同一个恢复码必须被拒绝 401
        let rec_login_2 = app
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "username": "admin",
                            "password": "Vane#2026Strong",
                            "totp_code": recovery_code,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rec_login_2.status(), StatusCode::UNAUTHORIZED);
        std::fs::remove_dir_all(tmp).unwrap();
    }

    #[tokio::test]
    async fn forged_forwarding_headers_do_not_evade_login_ban() {
        let tmp = std::env::temp_dir().join(format!("vane_peer_test_{}", crate::config::random_nonce()));
        std::fs::create_dir_all(&tmp).unwrap();
        let app = make_test_app(&tmp).await;
        let attempts = Config::default().security.max_login_failures;
        for attempt in 0..=attempts {
            let request = trusted_request()
                .method("POST")
                .uri("/api/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-real-ip", format!("198.51.100.{}", attempt + 1))
                .header("x-forwarded-for", format!("2001:db8::{}", attempt + 1))
                .body(Body::from(r#"{"username":"unknown","password":"wrong"}"#))
                .unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                if attempt < attempts { StatusCode::UNAUTHORIZED } else { StatusCode::TOO_MANY_REQUESTS }
            );
        }
        std::fs::remove_dir_all(tmp).unwrap();
    }

    #[test]
    fn admin_cookie_requires_secure_transport() {
        let vault = Vault::from_master(&[1u8; 32]);
        let response = build_session_response("test-token", 3600, true, &Config::default(), &vault);
        assert!(response.headers()[header::SET_COOKIE].to_str().unwrap().contains("; Secure;"));
    }

    #[test]
    fn assets_cannot_escape_embedded_root() {
        assert!(load_asset("../../Cargo.toml").is_none());
        assert!(load_asset("../package.json").is_none());
    }

    #[tokio::test]
    async fn rejects_untrusted_host_and_cross_origin_logout() {
        let tmp = std::env::temp_dir().join(format!("vane_boundary_test_{}", crate::config::random_nonce()));
        std::fs::create_dir_all(&tmp).unwrap();
        let app = make_test_app(&tmp).await;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/auth/status")
                    .header(header::HOST, "evil.example:23456")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/logout")
                    .header(header::HOST, "192.168.1.1:23456")
                    .header(header::ORIGIN, "https://evil.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[tokio::test]
    async fn end_to_end_mandatory_password_change_and_module_switches() {
        let tmp = std::env::temp_dir().join(format!("vane_web_test_{}", crate::config::random_nonce()));
        let _ = std::fs::create_dir_all(&tmp);
        let app = make_test_app(&tmp).await;

        let login_req = trusted_request()
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

        let dash_req = trusted_request()
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

        let bad_pw_req = trusted_request()
            .method("POST")
            .uri("/api/auth/change-password")
            .header(header::COOKIE, &cookie_hdr)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"current_password":"admin321","new_password":"admin321"}"#))
            .unwrap();
        let bad_pw_resp = app.clone().oneshot(bad_pw_req).await.unwrap();
        assert_eq!(bad_pw_resp.status(), StatusCode::BAD_REQUEST);

        let ok_pw_req = trusted_request()
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

        let dash_ok = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("GET")
                    .uri("/api/dashboard")
                    .header(header::COOKIE, &new_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dash_ok.status(), StatusCode::OK);

        let pty_disabled = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/pty/ticket")
                    .header(header::COOKIE, &new_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pty_disabled.status(), StatusCode::FORBIDDEN);

        let static_req = trusted_request()
            .method("GET")
            .uri("/")
            .header(header::ACCEPT_ENCODING, "br, gzip")
            .body(Body::empty())
            .unwrap();
        let static_resp = app.clone().oneshot(static_req).await.unwrap();
        assert_eq!(static_resp.status(), StatusCode::OK);
        assert_eq!(static_resp.headers().get(header::CONTENT_ENCODING).unwrap(), "br");

        // HEAD 请求必须返回 Content-Length 但空响应体
        let head_resp = app
            .clone()
            .oneshot(trusted_request().method("HEAD").uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(head_resp.status(), StatusCode::OK);
        assert!(head_resp.headers().contains_key(header::CONTENT_LENGTH));
        assert!(to_bytes(head_resp.into_body(), 1024).await.unwrap().is_empty());

        // 添加 DNS 服务商并用 _renames 重命名，Vault 机密必须保留而非被清空
        let get_s = app
            .clone()
            .oneshot(trusted_request().uri("/api/settings").header(header::COOKIE, &new_cookie).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let mut cfg_val: serde_json::Value = serde_json::from_slice(&to_bytes(get_s.into_body(), 131_072).await.unwrap()).unwrap();
        cfg_val["dns_providers"]["cf_a"] = serde_json::json!({
            "provider": "cloudflare",
            "api_token": "super-secret-cf-tok-999",
            "secret_key": "",
            "happy_eyeballs_delay_ms": 250,
            "zone_name": "example.com",
            "zone_id": ""
        });
        let put1 = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("PUT")
                    .uri("/api/settings")
                    .header(header::COOKIE, &new_cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(cfg_val.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put1.status(), StatusCode::OK);
        let mut cfg_renamed: serde_json::Value = serde_json::from_slice(&to_bytes(put1.into_body(), 131_072).await.unwrap()).unwrap();
        let prov_val = cfg_renamed["dns_providers"].as_object_mut().unwrap().remove("cf_a").unwrap();
        cfg_renamed["dns_providers"]["cf_b"] = prov_val;
        cfg_renamed["_renames"] = serde_json::json!([{ "from": "dns_providers.cf_a", "to": "dns_providers.cf_b" }]);
        let put2 = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("PUT")
                    .uri("/api/settings")
                    .header(header::COOKIE, &new_cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(cfg_renamed.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put2.status(), StatusCode::OK);
        let after_rename: serde_json::Value = serde_json::from_slice(&to_bytes(put2.into_body(), 131_072).await.unwrap()).unwrap();
        assert_eq!(after_rename["dns_providers"]["cf_b"]["api_token"]["configured"], true);

        // 开启 web_terminal + require_reauth 后，错误的二次密码必须返回 403 而非 401
        let mut cfg_pty = after_rename;
        cfg_pty["modules"]["web_terminal"] = serde_json::json!(true);
        cfg_pty["web_terminal"]["require_reauth"] = serde_json::json!(true);
        let put3 = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("PUT")
                    .uri("/api/settings")
                    .header(header::COOKIE, &new_cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(cfg_pty.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put3.status(), StatusCode::OK);
        let bad_reauth = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/pty/ticket")
                    .header(header::COOKIE, &new_cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"target":"host","reauth_password":"wrong"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad_reauth.status(), StatusCode::FORBIDDEN);

        // 验证 /api/system/network-info 与 /api/logs 增强参数与 /api/dashboard 运行态字段
        let net_info = app
            .clone()
            .oneshot(trusted_request().uri("/api/system/network-info").header(header::COOKIE, &new_cookie).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(net_info.status(), StatusCode::OK);
        let net_json: serde_json::Value = serde_json::from_slice(&to_bytes(net_info.into_body(), 65536).await.unwrap()).unwrap();
        assert!(net_json["interfaces"].is_array());
        assert!(net_json["neighbors"].is_array());
        assert!(net_json["split_dns_path"].as_str().unwrap().ends_with("split-dns.hosts"));

        let logs_res = app
            .clone()
            .oneshot(trusted_request().uri("/api/logs?limit=10").header(header::COOKIE, &new_cookie).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(logs_res.status(), StatusCode::OK);
        let logs_json: serde_json::Value = serde_json::from_slice(&to_bytes(logs_res.into_body(), 65536).await.unwrap()).unwrap();
        assert!(logs_json["entries"].is_array());
        assert!(logs_json["modules"].is_array());
        assert!(logs_json["capacity"].as_u64().unwrap() >= 50);

        let dash2 = app
            .clone()
            .oneshot(trusted_request().uri("/api/dashboard").header(header::COOKIE, &new_cookie).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(dash2.status(), StatusCode::OK);
        let dash_json: serde_json::Value = serde_json::from_slice(&to_bytes(dash2.into_body(), 131_072).await.unwrap()).unwrap();
        assert!(dash_json["reverse_proxy_status"].is_array());
        assert!(dash_json["port_forward_status"].is_array());

        // 修改重启生效字段时必须返回 X-Vane-Restart-Required 响应头
        let mut cfg_restart = cfg_pty;
        cfg_restart["system"]["worker_threads"] = serde_json::json!(4);
        let put_restart = app
            .oneshot(
                trusted_request()
                    .method("PUT")
                    .uri("/api/settings")
                    .header(header::COOKIE, &new_cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(cfg_restart.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put_restart.status(), StatusCode::OK);
        let restart_hdr = put_restart
            .headers()
            .get("x-vane-restart-required")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(restart_hdr.contains("system.worker_threads"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn cross_machine_backup_exports_and_restores_acme_accounts_certs_and_admin_tls() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir_a = std::env::temp_dir().join(format!("vane_bak_a_{}", crate::config::random_nonce()));
        let dir_b = std::env::temp_dir().join(format!("vane_bak_b_{}", crate::config::random_nonce()));
        std::fs::create_dir_all(&dir_a).unwrap();
        std::fs::create_dir_all(&dir_b).unwrap();

        let (app_a, state_a) = make_test_app_with_secret_path(&dir_a, "/").await;
        // 完成机器 A 登录与改密
        let login_resp = app_a
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"username":"admin","password":"admin321"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let init_cookie = login_resp
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let ch_resp = app_a
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/change-password")
                    .header(header::COOKIE, &init_cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"current_password":"admin321","new_password":"Vane#BackupPass1"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let cookie_a = ch_resp
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();

        // 在机器 A 写入管理证书、ACME 账户密文、挑战日志以及由测试 CA 签发的有效代际证书
        let _ = crate::net::tls_resolver::load_or_create_admin_cert(&dir_a, &["192.168.1.1:23456".into()]).unwrap();
        let cert_dir_b = dir_b.join("acme-certs");
        let acc_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let sealed_acc = state_a
            .vault
            .seal(&format!("acme.account.{acc_id}"), br#"{"id":"https://ca/acct/1"}"#)
            .unwrap();
        crate::daemon::acme_store::atomic(
            dir_a.join("acme-accounts").join(format!("{acc_id}.json")),
            sealed_acc.into_bytes(),
        )
        .await
        .unwrap();
        crate::daemon::acme_store::atomic(
            dir_a.join("acme-challenges").join("app.example.com.json"),
            br#"{"provider":"cf","leases":[]}"#.to_vec(),
        )
        .await
        .unwrap();

        // 构造机器 A 上带有 ACME + 反代加密头的配置，并写入有效代际证书
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_kp = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_kp).unwrap();
        let issuer = rcgen::Issuer::from_params(&ca_params, &ca_kp);
        let mut leaf_params = rcgen::CertificateParams::new(vec!["app.example.com".into()]).unwrap();
        leaf_params.distinguished_name.push(rcgen::DnType::CommonName, "app.example.com");
        let leaf_kp = rcgen::KeyPair::generate().unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_kp, &issuer).unwrap();
        let bundle = crate::daemon::acme_store::Bundle {
            directory: "letsencrypt_staging".into(),
            domains: vec!["app.example.com".into()],
            certificate: format!("{}{}", leaf_cert.pem(), ca_cert.pem()),
            private_key: leaf_kp.serialize_pem(),
        };
        let cert_dir_a = dir_a.join("acme-certs");
        crate::daemon::acme_store::store(&cert_dir_a, "app.example.com", &bundle)
            .await
            .unwrap();

        let mut cfg_a = (**state_a.config.load()).clone();
        cfg_a.dns_providers.insert(
            "cf".into(),
            crate::config::DnsProviderConfig {
                provider: "cloudflare".into(),
                api_token: state_a.vault.seal("dns_providers.cf.api_token", b"cf-secret").unwrap(),
                ..Default::default()
            },
        );
        cfg_a.acme.push(crate::config::AcmeConfig {
            domain: "app.example.com".into(),
            dns_provider: "cf".into(),
            cert_dir: cert_dir_a.to_string_lossy().into_owned(),
            ..Default::default()
        });
        cfg_a.reverse_proxy.push(crate::config::ReverseProxyConfig {
            name: "rp".into(),
            listen_port: 8443,
            rules: vec![crate::config::ReverseProxyRule {
                host: "app.example.com".into(),
                upstream: "http://192.168.1.50:8080".into(),
                request_headers_set: [(
                    "Authorization".into(),
                    state_a
                        .vault
                        .seal("reverse_proxy.rp.rules.0.request_headers_set.Authorization", b"Bearer upstream-tok")
                        .unwrap(),
                )]
                .into_iter()
                .collect(),
                ..Default::default()
            }],
            ..Default::default()
        });
        state_a.config.store(Arc::new(cfg_a.clone()));
        save_config(&state_a.config_path, &cfg_a).unwrap();

        // 机器 A 导出全量加密备份
        let exp_resp = app_a
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/backup/export")
                    .header(header::COOKIE, &cookie_a)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"password":"migrate-pass-99"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(exp_resp.status(), StatusCode::OK);
        let exp_json: serde_json::Value =
            serde_json::from_slice(&to_bytes(exp_resp.into_body(), 1024 * 1024).await.unwrap()).unwrap();
        assert_eq!(exp_json["summary"]["admin_tls"], true);
        assert_eq!(exp_json["summary"]["acme_accounts"], 1);
        assert_eq!(exp_json["summary"]["acme_certs"], 1);
        assert_eq!(exp_json["summary"]["acme_challenges"], 1);
        let blob = exp_json["backup_blob"].as_str().unwrap().to_string();

        // 机器 B（拥有完全不同的主密钥）登录并导入备份
        let (app_b, state_b) = make_test_app_with_secret_path(&dir_b, "/").await;
        let login_b = app_b
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"username":"admin","password":"admin321"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let init_cookie_b = login_b
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let ch_b = app_b
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/change-password")
                    .header(header::COOKIE, &init_cookie_b)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"current_password":"admin321","new_password":"Vane#TempPassB1"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let cookie_b = ch_b
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();

        // 避免 dir_a 被清理前写回覆盖，测试导出后再删 dir_a，并验证机器 B 可导入
        let _ = cert_dir_b;
        let imp_resp = app_b
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/backup/import")
                    .header(header::COOKIE, &cookie_b)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "backup_blob": blob, "password": "migrate-pass-99" }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(imp_resp.status(), StatusCode::OK);
        let imp_json: serde_json::Value =
            serde_json::from_slice(&to_bytes(imp_resp.into_body(), 131_072).await.unwrap()).unwrap();
        assert_eq!(imp_json["restored_summary"]["admin_tls"], true);
        assert_eq!(imp_json["restored_summary"]["acme_accounts"], 1);
        assert_eq!(imp_json["restored_summary"]["acme_certs"], 1);
        assert_eq!(imp_json["restored_summary"]["acme_challenges"], 1);

        // 验证机器 B 用自己的 Vault 成功重加密了 ACME 账户且 CertTable 已热加载该域名证书
        let sealed_on_b = std::fs::read_to_string(dir_b.join("acme-accounts").join(format!("{acc_id}.json"))).unwrap();
        assert_eq!(
            state_b
                .vault
                .reveal_string(&format!("acme.account.{acc_id}"), &sealed_on_b)
                .unwrap(),
            r#"{"id":"https://ca/acct/1"}"#
        );
        assert!(state_b.cert_table.load().exact.contains_key("app.example.com"));
        let rp_hdr = &state_b.config.load().reverse_proxy[0].rules[0].request_headers_set["Authorization"];
        assert_eq!(
            state_b
                .vault
                .reveal_string("reverse_proxy.rp.rules.0.request_headers_set.Authorization", rp_hdr)
                .unwrap(),
            "Bearer upstream-tok"
        );

        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
    }
}
