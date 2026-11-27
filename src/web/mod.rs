//! Web 管理后台：全程 HTTPS / 局域网监听、单管理员三合一认证、强制首次修改初始密码硬门禁、
//! 安全入口路径 (`secret_path`)、并发安全配置更新、敏感配置脱敏与 AEAD 加密落盘、
//! `.rodata` 零拷贝 `.br/.gz` 预压缩静态直出与 PWA 支持。
pub mod boundary;
pub mod server;
pub mod ws_pty;

use crate::config::{save_config, Config, ModulesConfig};
use crate::daemon::acme::{issue_or_renew_cert, AcmeRuntime};
use crate::daemon::cron::{CronExecutionContext, CronRuntime, CronSchedule};
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
    base32_decode, base32_encode, generate_recovery_codes, generate_totp_secret, normalize_recovery_code,
    otpauth_uri, AuthEngine, AuthState, HashGate, PasswordHash, SessionScope,
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
    pub proxy_gate_fail2ban: crate::security::fail2ban::SharedScopedFail2Ban,
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
    pub inbox: Arc<crate::daemon::inbox::NotificationInbox>,
    pub updater: Arc<crate::daemon::updater::UpdateRuntime>,
    pub global_quota: ConnectionQuota,
    pub pty_mgr: Arc<PtyManager>,
    pub proxy_gate: Arc<crate::security::proxy_gate::ProxyGateStore>,
    pub reauth_tickets: crate::security::tickets::SessionTickets,
    pub reload_notify: Arc<Notify>,
    pub live_admin_listeners: Arc<Vec<SocketAddr>>,
    pub shutdown_flag: Arc<std::sync::atomic::AtomicBool>,
}

impl AppState {
    pub fn admin_session_alive(&self, session: &[u8; 32]) -> bool {
        let cfg = self.config.load();
        let Ok(mut auth) = self.auth.lock() else { return false };
        let Some(sess) = auth.sessions.validate_digest(
            session,
            Duration::from_secs(cfg.admin.session_ttl_secs.clamp(300, 86_400)),
            false,
        ) else {
            return false;
        };
        auth.effective_scope(&cfg.admin, sess.scope) == SessionScope::FullAdmin
    }

    pub fn pty_session_alive(&self, session: &[u8; 32], is_container: bool) -> bool {
        if self.shutdown_flag.load(std::sync::atomic::Ordering::Acquire) {
            return false;
        }
        let cfg = self.config.load();
        if !cfg.modules.web_terminal {
            return false;
        }
        if is_container && !cfg.modules.docker {
            return false;
        }
        let Ok(mut auth) = self.auth.lock() else { return false };
        let Some(sess) = auth.sessions.validate_digest(
            session,
            Duration::from_secs(cfg.admin.session_ttl_secs.clamp(300, 86_400)),
            false,
        ) else {
            return false;
        };
        if auth.effective_scope(&cfg.admin, sess.scope) != SessionScope::FullAdmin {
            return false;
        }
        if cfg.module_requires_reauth("web_terminal")
            && !auth.sessions.is_module_unlocked_digest(session, "web_terminal")
        {
            return false;
        }
        if is_container
            && cfg.module_requires_reauth("docker")
            && !auth.sessions.is_module_unlocked_digest(session, "docker")
        {
            return false;
        }
        true
    }

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
        if !next_cfg.modules.web_terminal || !next_cfg.modules.docker {
            self.pty_mgr.notify_revoke();
        }
        if !next_cfg.modules.reverse_proxy {
            self.proxy_gate.revoke_all();
        }
        if !next_cfg.modules.cron {
            self.cron_status.cancel_all();
        }
    }

    pub fn build_cron_context(self: &Arc<Self>, cfg: Arc<Config>) -> CronExecutionContext {
        let st = self.clone();
        let toggler = Arc::new(move |target_kind: String, rule_name: String, enable: bool| {
            let st = st.clone();
            Box::pin(async move {
                let _guard = st.config_lock.lock().await;
                let mut next = (**st.config.load()).clone();
                if !next.modules.cron {
                    return Err("计划任务模块已禁用，拒绝执行规则切换".into());
                }
                let mut found = false;
                match target_kind.as_str() {
                    "port_forward" => {
                        if !next.modules.port_forward {
                            return Err("端口转发模块已禁用，拒绝修改规则".into());
                        }
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
                        if !next.modules.reverse_proxy {
                            return Err("反向代理模块已禁用，拒绝修改规则".into());
                        }
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
                next.validate_with_vault_and_listeners(Some(&st.vault), &st.live_admin_listeners)?;
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
        .with_live_config(self.config.clone())
    }
}

impl crate::net::reverse_proxy::ProxyAuthorization for AppState {
    /// 严禁复用 Vane 管理员会话 Cookie：反向代理门禁必须完全隔离于管理后台权限。
    fn session(&self, _headers: &HeaderMap, _peer: std::net::IpAddr) -> Option<[u8; 32]> {
        None
    }
    fn websocket_ticket(&self, _ticket: &str, _target: &str, _peer: std::net::IpAddr) -> Option<[u8; 32]> {
        None
    }
    fn gate_portal_enabled(&self) -> bool {
        true
    }
    fn gate_session(
        &self,
        headers: &HeaderMap,
        host: &str,
        allowed_users: &[String],
        _peer: std::net::IpAddr,
    ) -> Option<[u8; 32]> {
        let cfg = self.config.load();
        self.proxy_gate.validate_request(headers, host, allowed_users, |uname| {
            cfg.proxy_auth_users
                .iter()
                .any(|u| u.enabled && u.username == uname)
        })
    }
    fn session_alive(&self, session: &[u8; 32]) -> bool {
        let cfg = self.config.load();
        self.proxy_gate.session_alive(session, |uname| {
            cfg.proxy_auth_users
                .iter()
                .any(|u| u.enabled && u.username == uname)
        })
    }
    fn gate_login<'a>(
        &'a self,
        host: String,
        allowed_users: Vec<String>,
        username: String,
        password: String,
        peer: std::net::IpAddr,
    ) -> crate::net::reverse_proxy::GateLoginFuture<'a> {
        Box::pin(async move {
            let ban_key = BanKey::from_peer(peer);
            if self.proxy_gate_fail2ban.is_key_blocked(&host, ban_key) {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    "认证失败次数过多，该网络已被临时封禁，请稍后再试".to_string(),
                ));
            }
            let uname = username.trim().to_string();
            let cfg = self.config.load();
            if !cfg.modules.reverse_proxy {
                return Err((StatusCode::FORBIDDEN, "反向代理模块已关闭".to_string()));
            }
            let account = cfg
                .proxy_auth_users
                .iter()
                .find(|u| u.enabled && u.username == uname)
                .cloned();
            let allowed = !uname.is_empty() && allowed_users.iter().any(|u| u == &uname);
            // 始终执行一次均衡 PBKDF2 校验，消除用户名探测计时侧信道
            let dummy_hash = cfg.admin.password_hash.clone();
            let hash_str = account
                .as_ref()
                .map(|a| a.password_hash.clone())
                .unwrap_or(dummy_hash);
            let pw_bytes = password.into_bytes();
            let verify_res = self
                .hash_gate
                .run(move || PasswordHash::parse(&hash_str).is_some_and(|ph| ph.verify(&pw_bytes)))
                .await;
            let verified = match verify_res {
                Ok(v) => v,
                Err(_) => {
                    return Err((
                        StatusCode::TOO_MANY_REQUESTS,
                        "当前认证请求较多，请稍后再试".to_string(),
                    ));
                }
            };
            let Some(acc) = account.filter(|_| allowed && verified) else {
                let outcome = on_proxy_gate_login_failed(self, &host, ban_key).await;
                logger::log(
                    Level::Warn,
                    "proxy_gate",
                    &format!("反代门禁认证失败 (host={}, user={}, ip={})", host, uname, peer),
                );
                if outcome == crate::security::fail2ban::FailureOutcome::SaturatedFailClosed {
                    return Err((
                        StatusCode::TOO_MANY_REQUESTS,
                        "认证限流表已饱和，请稍后再试".to_string(),
                    ));
                }
                return Err((
                    StatusCode::UNAUTHORIZED,
                    "访问账号或密码错误，或无权访问此服务".to_string(),
                ));
            };
            // VANE-L01：PBKDF2 完成后重检最新配置快照，避免并发改密/禁用账号或停用模块 TOCTOU
            let cfg_after = self.config.load();
            let still_valid = cfg_after.modules.reverse_proxy
                && cfg_after.proxy_auth_users.iter().any(|u| {
                    u.enabled && u.username == acc.username && u.password_hash == acc.password_hash
                });
            if !still_valid {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    "门禁账号状态已变更，请重新登录".to_string(),
                ));
            }
            // VANE-H04：仅清除当前反代 host 作用域计数，绝不影响管理面与其他规则的 Fail2Ban
            self.proxy_gate_fail2ban.record_success(&host, ban_key);
            let ttl = Duration::from_secs(acc.session_ttl_secs.clamp(300, 604_800));
            let token = self
                .proxy_gate
                .issue(&acc.username, &host, ban_key, ttl)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            logger::log(
                Level::Info,
                "proxy_gate",
                &format!("反代门禁登录成功 (host={}, user={}, ip={})", host, acc.username, peer),
            );
            Ok((token, ttl.as_secs()))
        })
    }
    fn gate_logout(&self, headers: &HeaderMap) {
        self.proxy_gate.revoke_headers(headers);
    }
}

fn validate_proxy_gate_password(username: &str, pw: &str) -> Result<(), String> {
    if pw.len() < 8 || pw.len() > 128 {
        return Err("门禁密码长度需为 8 ~ 128 位".into());
    }
    if pw.eq_ignore_ascii_case(username) || pw == "admin321" {
        return Err("门禁密码不能与用户名相同或使用弱默认密码".into());
    }
    let has_alpha = pw.bytes().any(|b| b.is_ascii_alphabetic());
    let has_num_or_sym = pw.bytes().any(|b| b.is_ascii_digit() || b.is_ascii_punctuation());
    if !(has_alpha && has_num_or_sym) {
        return Err("门禁密码至少需同时包含字母与数字（或符号）".into());
    }
    Ok(())
}

fn serialize_proxy_auth_users(state: &AppState, cfg: &Config) -> serde_json::Value {
    let counts = state.proxy_gate.active_counts_by_user();
    let users: Vec<serde_json::Value> = cfg
        .proxy_auth_users
        .iter()
        .map(|u| {
            let bound_rules = cfg
                .reverse_proxy
                .iter()
                .flat_map(|l| l.rules.iter())
                .filter(|r| r.auth_gate && r.auth_gate_users.iter().any(|x| x == &u.username))
                .count();
            serde_json::json!({
                "username": u.username,
                "enabled": u.enabled,
                "session_ttl_secs": u.session_ttl_secs,
                "note": u.note,
                "active_sessions": counts.get(&u.username).copied().unwrap_or(0),
                "bound_rules": bound_rules,
            })
        })
        .collect();
    serde_json::json!({ "users": users })
}

#[derive(Deserialize)]
struct CreateProxyAuthUserRequest {
    username: String,
    password: String,
    #[serde(default = "default_true_bool")]
    enabled: bool,
    #[serde(default = "default_gate_ttl")]
    session_ttl_secs: u64,
    #[serde(default)]
    note: String,
}

fn default_true_bool() -> bool {
    true
}
fn default_gate_ttl() -> u64 {
    43_200
}

#[derive(Deserialize)]
struct UpdateProxyAuthUserRequest {
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    session_ttl_secs: Option<u64>,
    #[serde(default)]
    note: Option<String>,
}

async fn api_proxy_auth_users_list(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return *resp;
    }
    let cfg = state.config.load();
    Json(serialize_proxy_auth_users(&state, &cfg)).into_response()
}

async fn api_proxy_auth_user_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreateProxyAuthUserRequest>,
) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return *resp;
    }
    let username = req.username.trim().to_string();
    if let Err(e) = crate::config::validate_username(&username) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response();
    }
    if let Err(e) = validate_proxy_gate_password(&username, &req.password) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response();
    }
    if !(300..=604_800).contains(&req.session_ttl_secs) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "登录有效期范围需在 300 ~ 604800 秒之间" })),
        )
            .into_response();
    }
    let note = req.note.trim().to_string();
    if note.chars().count() > 128 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "备注长度不能超过 128 字符" })),
        )
            .into_response();
    }
    let pw = req.password;
    let hash = match state
        .hash_gate
        .run(move || PasswordHash::create(pw.as_bytes()))
        .await
    {
        Ok(Ok(h)) => h.encode(),
        Ok(Err(e)) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response()
        }
        Err(_) => {
            return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({ "error": "系统繁忙，请稍后再试" })))
                .into_response()
        }
    };

    let _cfg_guard = state.config_lock.lock().await;
    let mut next_cfg = (**state.config.load()).clone();
    if next_cfg.proxy_auth_users.len() >= 64 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "独立门禁账号数量已达 64 个上限" })),
        )
            .into_response();
    }
    if next_cfg.proxy_auth_users.iter().any(|u| u.username == username) {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": format!("门禁账号 \"{}\" 已存在", username) })),
        )
            .into_response();
    }
    next_cfg.proxy_auth_users.push(crate::config::ProxyAuthUser {
        username: username.clone(),
        password_hash: hash,
        enabled: req.enabled,
        session_ttl_secs: req.session_ttl_secs,
        note,
    });
    if let Err(e) = next_cfg.validate_with_vault_and_listeners(Some(&state.vault), &state.live_admin_listeners) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response();
    }
    if let Err(e) = save_config(&state.config_path, &next_cfg) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response();
    }
    let out = serialize_proxy_auth_users(&state, &next_cfg);
    state.config.store(Arc::new(next_cfg));
    logger::log(Level::Info, "proxy_gate", &format!("已创建反代独立门禁账号: {}", username));
    Json(serde_json::json!({ "ok": true, "users": out["users"] })).into_response()
}

async fn api_proxy_auth_user_update(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(username): AxumPath<String>,
    Json(req): Json<UpdateProxyAuthUserRequest>,
) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return *resp;
    }
    if let Some(ttl) = req.session_ttl_secs {
        if !(300..=604_800).contains(&ttl) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "登录有效期范围需在 300 ~ 604800 秒之间" })),
            )
                .into_response();
        }
    }
    if let Some(ref note) = req.note {
        if note.trim().chars().count() > 128 {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "备注长度不能超过 128 字符" })),
            )
                .into_response();
        }
    }
    let new_hash = match req.password.as_deref() {
        Some(pw) if !pw.is_empty() => {
            if let Err(e) = validate_proxy_gate_password(&username, pw) {
                return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response();
            }
            let pw_owned = pw.to_string();
            match state
                .hash_gate
                .run(move || PasswordHash::create(pw_owned.as_bytes()))
                .await
            {
                Ok(Ok(h)) => Some(h.encode()),
                Ok(Err(e)) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e })))
                        .into_response()
                }
                Err(_) => {
                    return (
                        StatusCode::TOO_MANY_REQUESTS,
                        Json(serde_json::json!({ "error": "系统繁忙，请稍后再试" })),
                    )
                        .into_response()
                }
            }
        }
        _ => None,
    };

    let _cfg_guard = state.config_lock.lock().await;
    let mut next_cfg = (**state.config.load()).clone();
    let Some(user) = next_cfg.proxy_auth_users.iter_mut().find(|u| u.username == username) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "未找到该独立门禁账号" })),
        )
            .into_response();
    };
    let mut should_revoke = false;
    if let Some(h) = new_hash {
        user.password_hash = h;
        should_revoke = true;
    }
    if let Some(en) = req.enabled {
        if !en {
            should_revoke = true;
        }
        user.enabled = en;
    }
    if let Some(ttl) = req.session_ttl_secs {
        user.session_ttl_secs = ttl;
    }
    if let Some(note) = req.note {
        user.note = note.trim().to_string();
    }
    if let Err(e) = next_cfg.validate_with_vault_and_listeners(Some(&state.vault), &state.live_admin_listeners) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response();
    }
    if let Err(e) = save_config(&state.config_path, &next_cfg) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response();
    }
    state.config.store(Arc::new(next_cfg.clone()));
    if should_revoke {
        state.proxy_gate.revoke_user(&username);
    }
    let out = serialize_proxy_auth_users(&state, &next_cfg);
    logger::log(Level::Info, "proxy_gate", &format!("已更新反代独立门禁账号: {}", username));
    Json(serde_json::json!({ "ok": true, "users": out["users"] })).into_response()
}

async fn api_proxy_auth_user_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(username): AxumPath<String>,
) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return *resp;
    }
    let _cfg_guard = state.config_lock.lock().await;
    let mut next_cfg = (**state.config.load()).clone();
    let before = next_cfg.proxy_auth_users.len();
    next_cfg.proxy_auth_users.retain(|u| u.username != username);
    if next_cfg.proxy_auth_users.len() == before {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "未找到该独立门禁账号" })),
        )
            .into_response();
    }
    let mut rules_changed = false;
    for listener in next_cfg.reverse_proxy.iter_mut() {
        for rule in listener.rules.iter_mut() {
            let len_before = rule.auth_gate_users.len();
            rule.auth_gate_users.retain(|u| u != &username);
            if rule.auth_gate_users.len() != len_before {
                rules_changed = true;
            }
        }
    }
    if let Err(e) = next_cfg.validate_with_vault_and_listeners(Some(&state.vault), &state.live_admin_listeners) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response();
    }
    if let Err(e) = save_config(&state.config_path, &next_cfg) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response();
    }
    state.proxy_gate.revoke_user(&username);
    state.config.store(Arc::new(next_cfg.clone()));
    if rules_changed {
        state.reload_notify.notify_one();
    }
    let out = serialize_proxy_auth_users(&state, &next_cfg);
    logger::log(Level::Info, "proxy_gate", &format!("已删除反代独立门禁账号并清理授权引用: {}", username));
    Json(serde_json::json!({ "ok": true, "users": out["users"] })).into_response()
}

async fn api_proxy_auth_user_revoke(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(username): AxumPath<String>,
) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return *resp;
    }
    let cfg = state.config.load();
    if !cfg.proxy_auth_users.iter().any(|u| u.username == username) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "未找到该独立门禁账号" })),
        )
            .into_response();
    }
    let revoked = state.proxy_gate.revoke_user(&username);
    logger::log(
        Level::Info,
        "proxy_gate",
        &format!("已强制下线反代门禁账号 {} 的 {} 个活跃会话", username, revoked),
    );
    let out = serialize_proxy_auth_users(&state, &cfg);
    Json(serde_json::json!({ "ok": true, "revoked": revoked, "users": out["users"] })).into_response()
}

async fn request_timeout_guard(request: axum::extract::Request, next: axum::middleware::Next) -> Response {
    if request.uri().path() == "/api/pty/ws" {
        return next.run(request).await;
    }
    let timeout = if request.uri().path() == "/api/update/upload" {
        Duration::from_secs(300)
    } else {
        Duration::from_secs(60)
    };
    match tokio::time::timeout(timeout, next.run(request)).await {
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
        .route("/api/auth/totp/setup", post(api_totp_setup))
        .route("/api/auth/totp/enable", post(api_totp_enable))
        .route("/api/auth/totp/disable", post(api_totp_disable))
        .route("/api/auth/totp/recovery-codes", post(api_totp_regenerate_recovery))
        .route("/api/auth/passkey/register/options", post(api_passkey_register_options))
        .route("/api/auth/passkey/register/verify", post(api_passkey_register_verify))
        .route("/api/auth/passkey/toggle", post(api_passkey_toggle))
        .route("/api/auth/passkey/{id}", delete(api_passkey_delete))
        .route("/api/auth/passkey/login/options", post(api_passkey_login_options))
        .route("/api/auth/passkey/login/verify", post(api_passkey_login_verify))
        .route("/api/auth/reauth/options", post(api_reauth_options))
        .route("/api/auth/reauth/verify", post(api_reauth_verify))
        .route("/api/auth/module-lock", post(api_auth_module_lock))
        .layer(DefaultBodyLimit::max(8 * 1024));

    Router::new()
        .merge(auth_routes)
        .route("/api/dashboard", get(api_dashboard))
        .route("/api/system/network-info", get(api_system_network_info))
        .route("/api/logs", get(api_get_logs).delete(api_clear_logs))
        .route("/api/settings", get(api_get_settings).put(api_put_settings))
        .route("/api/modules", put(api_put_modules))
        .route("/api/modules/reauth", put(api_put_module_reauth))
        .route("/api/port-forwards/{name}/lease", post(api_port_forward_lease))
        .route("/api/ddns/{name}/sync", post(api_ddns_sync))
        .route("/api/acme/{domain}/issue", post(api_acme_issue))
        .route("/api/stun/{name}/probe", post(api_stun_probe))
        .route("/api/cron/preview", get(api_cron_preview))
        .route("/api/cron/{name}/run", post(api_cron_run))
        .route("/api/notifications/inbox", get(api_inbox_list).delete(api_inbox_clear))
        .route("/api/notifications/inbox/read", post(api_inbox_mark_read))
        .route("/api/notifications/inbox/{id}", delete(api_inbox_delete))
        .route("/api/notifications/{name}/test", post(api_notification_test))
        .route("/api/update/status", get(api_update_status))
        .route("/api/update/check", post(api_update_check))
        .route(
            "/api/update/upload",
            post(api_update_upload).layer(DefaultBodyLimit::max(50 * 1024 * 1024)),
        )
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
            post(api_backup_import).layer(DefaultBodyLimit::max(8 * 1024 * 1024)),
        )
        .route("/api/backup/sanitized", post(api_backup_sanitized))
        .route("/api/proxy/auth-users", get(api_proxy_auth_users_list).post(api_proxy_auth_user_create))
        .route(
            "/api/proxy/auth-users/{username}",
            put(api_proxy_auth_user_update).delete(api_proxy_auth_user_delete),
        )
        .route("/api/proxy/auth-users/{username}/revoke", post(api_proxy_auth_user_revoke))
        .route("/api/pty/shells", get(api_pty_shells))
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
fn require_full_admin(state: &AppState, headers: &HeaderMap) -> Result<String, Box<Response>> {
    match current_session_scope(state, headers) {
        Some((tok, SessionScope::FullAdmin)) => Ok(tok),
        Some((_, SessionScope::MustChangePassword)) => Err(Box::new(
            (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "MUST_CHANGE_INITIAL_PASSWORD",
                    "message": "初次登录必须先修改默认密码 (admin321)，禁止跳过进入管理页面"
                })),
            )
                .into_response(),
        )),
        None => Err(Box::new(
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "UNAUTHORIZED", "message": "登录态已过期，请重新登录" })),
            )
                .into_response(),
        )),
    }
}

fn require_any_session(state: &AppState, headers: &HeaderMap) -> Result<(String, SessionScope), Box<Response>> {
    current_session_scope(state, headers).ok_or_else(|| {
        Box::new(
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "UNAUTHORIZED", "message": "请先登录" })),
            )
                .into_response(),
        )
    })
}

async fn api_auth_status(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let cfg = state.config.load();
    let session = current_session_scope(&state, &headers);
    if let Some((token, scope)) = session {
        let unlocked_modules = state
            .auth
            .lock()
            .map(|a| a.sessions.unlocked_modules_remaining(&token))
            .unwrap_or_default();
        let mut eff_reauth = cfg.module_reauth.clone();
        if cfg.web_terminal.require_reauth {
            eff_reauth.web_terminal = true;
        }
        Json(serde_json::json!({
            "authenticated": true,
            "initial_setup": cfg.admin.must_change_password,
            "username": cfg.admin.username,
            "must_change_password": scope == SessionScope::MustChangePassword,
            "password_login_enabled": cfg.admin.password_login_enabled,
            "totp_enabled": cfg.admin.totp_enabled,
            "totp_recovery_remaining": cfg.admin.totp_recovery_hashes.len(),
            "passkey_enabled": cfg.admin.passkey_enabled,
            "has_passkeys": !cfg.admin.passkeys.is_empty(),
            "passkeys_count": cfg.admin.passkeys.len(),
            "session_ttl_secs": cfg.admin.session_ttl_secs,
            "language": cfg.system.language,
            "modules": cfg.modules,
            "module_reauth": eff_reauth,
            "unlocked_modules": unlocked_modules,
            "unread_notifications": state.inbox.unread_count(),
        }))
        .into_response()
    } else {
        Json(serde_json::json!({
            "authenticated": false,
            "initial_setup": cfg.admin.must_change_password,
            "password_login_enabled": cfg.admin.password_login_enabled,
            "totp_enabled": cfg.admin.totp_enabled,
            "passkey_enabled": cfg.admin.passkey_enabled,
            "has_passkeys": !cfg.admin.passkeys.is_empty(),
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
    if state.fail2ban.is_key_blocked(ban_key) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({ "error": "IP_BANNED", "message": "认证失败次数过多或限流已饱和，请稍后再试" })),
        )
            .into_response();
    }

    let cfg = state.config.load();
    if !cfg.admin.password_login_enabled {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "PASSWORD_LOGIN_DISABLED", "message": "当前已配置为仅允许通行密钥免密登录" })),
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
        if on_login_failed(&state, ban_key).await == crate::security::fail2ban::FailureOutcome::SaturatedFailClosed {
            return saturated_fail_closed_response();
        }
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "INVALID_CREDENTIALS", "message": "用户名或密码错误" })),
        )
            .into_response();
    }

    let pre_username = cfg.admin.username.clone();
    let pre_password_hash = cfg.admin.password_hash.clone();
    let Some(ph) = PasswordHash::parse(&pre_password_hash) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "密码哈希未初始化" })),
        )
            .into_response();
    };
    let pw_bytes = req.password.into_bytes();
    let ph_clone = ph.clone();
    let must_change_flag = cfg.admin.must_change_password;
    let Ok((pw_ok, mut scope)) = state
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
        if on_login_failed(&state, ban_key).await == crate::security::fail2ban::FailureOutcome::SaturatedFailClosed {
            return saturated_fail_closed_response();
        }
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "INVALID_CREDENTIALS", "message": "用户名或密码错误" })),
        )
            .into_response();
    }

    // VANE-L01：PBKDF2 校验完成后重读最新配置快照，避免并发关闭密码登录、改密或启用 TOTP 的 TOCTOU
    let cfg_after_pw = state.config.load();
    if !cfg_after_pw.admin.password_login_enabled
        || cfg_after_pw.admin.username != pre_username
        || cfg_after_pw.admin.password_hash != pre_password_hash
    {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": "AUTH_STATE_CHANGED", "message": "认证配置已并发变更，请重新登录" })),
        )
            .into_response();
    }
    if cfg_after_pw.admin.must_change_password {
        scope = SessionScope::MustChangePassword;
    }

    // 若启用了 TOTP：防回退单调水位校验并落盘，或一次性核销恢复码（PBKDF2 绝不持有 config_lock）
    if cfg_after_pw.admin.totp_enabled {
        let Ok(totp_plain) = state
            .vault
            .reveal_string("admin.totp_secret", &cfg_after_pw.admin.totp_secret)
        else {
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
            if on_login_failed(&state, ban_key).await == crate::security::fail2ban::FailureOutcome::SaturatedFailClosed {
                return saturated_fail_closed_response();
            }
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
                if on_login_failed(&state, ban_key).await == crate::security::fail2ban::FailureOutcome::SaturatedFailClosed {
                    return saturated_fail_closed_response();
                }
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
            // VANE-I01：先在锁外执行 HashGate PBKDF2 匹配，再加 config_lock 二次核验并原子移除消费
            let hashes = cfg_after_pw.admin.totp_recovery_hashes.clone();
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
                if on_login_failed(&state, ban_key).await == crate::security::fail2ban::FailureOutcome::SaturatedFailClosed {
                    return saturated_fail_closed_response();
                }
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "error": "INVALID_TOTP", "message": "TOTP 动态验证码或一次性恢复码无效" })),
                )
                    .into_response();
            };
            let consumed_left = {
                let _cfg_guard = state.config_lock.lock().await;
                let cur_cfg = state.config.load();
                if !cur_cfg.admin.totp_enabled {
                    None
                } else if let Some(pos) = cur_cfg
                    .admin
                    .totp_recovery_hashes
                    .iter()
                    .position(|h| h == &used_hash)
                {
                    let mut next_cfg = (**cur_cfg).clone();
                    next_cfg.admin.totp_recovery_hashes.remove(pos);
                    if let Err(e) = save_config(&state.config_path, &next_cfg) {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({ "error": format!("核销恢复码落盘失败: {}", e) })),
                        )
                            .into_response();
                    }
                    let left = next_cfg.admin.totp_recovery_hashes.len();
                    state.config.store(Arc::new(next_cfg));
                    Some(left)
                } else {
                    None
                }
            };
            let Some(left) = consumed_left else {
                if on_login_failed(&state, ban_key).await == crate::security::fail2ban::FailureOutcome::SaturatedFailClosed {
                    return saturated_fail_closed_response();
                }
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "error": "INVALID_TOTP", "message": "一次性恢复码已被并发消费或已失效" })),
                )
                    .into_response();
            };
            logger::log(
                Level::Warn,
                "auth",
                &format!("管理员使用一次性 TOTP 恢复码登录成功，剩余可用恢复码: {}", left),
            );
        }
    }

    let latest_cfg = state.config.load();
    if !latest_cfg.admin.password_login_enabled
        || latest_cfg.admin.username != pre_username
        || latest_cfg.admin.password_hash != pre_password_hash
        || (!cfg_after_pw.admin.totp_enabled && latest_cfg.admin.totp_enabled)
    {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": "AUTH_STATE_CHANGED", "message": "认证配置已并发变更，请重新登录" })),
        )
            .into_response();
    }
    if latest_cfg.admin.must_change_password {
        scope = SessionScope::MustChangePassword;
    }

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
    let mut eff_reauth = cfg.module_reauth.clone();
    if cfg.web_terminal.require_reauth {
        eff_reauth.web_terminal = true;
    }
    let body = serde_json::json!({
        "authenticated": true,
        "username": cfg.admin.username,
        "must_change_password": must_change,
        "password_login_enabled": cfg.admin.password_login_enabled,
        "totp_enabled": cfg.admin.totp_enabled,
        "totp_recovery_remaining": cfg.admin.totp_recovery_hashes.len(),
        "passkey_enabled": cfg.admin.passkey_enabled,
        "has_passkeys": !cfg.admin.passkeys.is_empty(),
        "passkeys_count": cfg.admin.passkeys.len(),
        "session_ttl_secs": cfg.admin.session_ttl_secs,
        "language": cfg.system.language,
        "modules": cfg.modules,
        "module_reauth": eff_reauth,
        "unlocked_modules": {},
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

fn saturated_fail_closed_response() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(serde_json::json!({
            "error": "RATE_LIMIT_SATURATED",
            "message": "认证防爆破追踪表已饱和，请稍后再试"
        })),
    )
        .into_response()
}

fn should_emit_ban_notification(scope: &str, ban_key: BanKey) -> bool {
    use std::sync::OnceLock;
    use std::time::Instant;
    const PER_KEY_COOLDOWN: Duration = Duration::from_secs(60);
    const MAX_TRACKED_NOTIFS: usize = 256;
    static STATE: OnceLock<Mutex<HashMap<(String, BanKey), Instant>>> = OnceLock::new();
    let map_mutex = STATE.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(mut map) = map_mutex.lock() else {
        return false;
    };
    let now = Instant::now();
    map.retain(|_, ts| now.duration_since(*ts) < PER_KEY_COOLDOWN);
    let key = (scope.to_string(), ban_key);
    if map.contains_key(&key) || map.len() >= MAX_TRACKED_NOTIFS {
        return false;
    }
    map.insert(key, now);
    true
}

fn spawn_ban_notification(state: &AppState, cfg: Arc<Config>, scope: &str, ban_key: BanKey, msg: String) {
    if !should_emit_ban_notification(scope, ban_key) {
        return;
    }
    let vault = state.vault.clone();
    tokio::spawn(async move {
        broadcast_event(&cfg, &vault, "ip_banned", "Vane 防爆破自动封禁告警", &msg, "warning").await;
    });
}

async fn on_login_failed(state: &AppState, ban_key: BanKey) -> crate::security::fail2ban::FailureOutcome {
    let cfg = state.config.load_full();
    let outcome = state.fail2ban.record_failure_checked(
        ban_key,
        cfg.security.max_login_failures,
        cfg.security.ban_duration_secs,
        "login_failed",
    );
    if outcome == crate::security::fail2ban::FailureOutcome::NewlyBanned {
        let cidr = ban_key.display_cidr();
        let msg = format!(
            "源网络 {} 连续管理认证失败已达阈值，已临时封禁 {}s",
            cidr, cfg.security.ban_duration_secs
        );
        logger::log(Level::Warn, "fail2ban", &msg);
        if cfg.security.kernel_ban_offload {
            let kernel_capable = !ban_key.is_loopback_or_link_local()
                && state.firewall.is_auto_manage()
                && state.firewall.backend() != crate::firewall::FirewallBackend::DryRun;
            if state
                .firewall
                .ban_source_cidr(&cidr, cfg.security.ban_duration_secs)
                .await
                .is_ok()
                && kernel_capable
            {
                state.fail2ban.mark_kernel_offloaded(ban_key);
            }
        }
        spawn_ban_notification(state, cfg, "admin", ban_key, msg);
    }
    outcome
}

async fn on_proxy_gate_login_failed(
    state: &AppState,
    host: &str,
    ban_key: BanKey,
) -> crate::security::fail2ban::FailureOutcome {
    let cfg = state.config.load_full();
    let outcome = state.proxy_gate_fail2ban.record_failure_checked(
        host,
        ban_key,
        cfg.security.max_login_failures,
        cfg.security.ban_duration_secs,
        "proxy_gate_failed",
    );
    if outcome == crate::security::fail2ban::FailureOutcome::NewlyBanned {
        let cidr = ban_key.display_cidr();
        let msg = format!(
            "源网络 {} 连续反代门禁认证失败 (host={}) 已达阈值，已临时封禁 {}s",
            cidr, host, cfg.security.ban_duration_secs
        );
        logger::log(Level::Warn, "fail2ban", &msg);
        if cfg.security.kernel_ban_offload {
            let kernel_capable = !ban_key.is_loopback_or_link_local()
                && state.firewall.is_auto_manage()
                && state.firewall.backend() != crate::firewall::FirewallBackend::DryRun;
            if state
                .firewall
                .ban_source_cidr(&cidr, cfg.security.ban_duration_secs)
                .await
                .is_ok()
                && kernel_capable
            {
                state.proxy_gate_fail2ban.mark_kernel_offloaded(host, ban_key);
            }
        }
        spawn_ban_notification(state, cfg, host, ban_key, msg);
    }
    outcome
}

fn collect_all_active_bans(state: &AppState) -> Vec<crate::security::fail2ban::ScopedBanRecord> {
    let mut out: Vec<crate::security::fail2ban::ScopedBanRecord> = state
        .fail2ban
        .list_active_bans()
        .into_iter()
        .map(|record| crate::security::fail2ban::ScopedBanRecord {
            scope: "admin".to_string(),
            record,
        })
        .collect();
    out.extend(state.proxy_gate_fail2ban.list_all_bans());
    out.sort_by(|a, b| {
        b.record
            .banned_at_unix
            .cmp(&a.record.banned_at_unix)
            .then_with(|| a.scope.cmp(&b.scope))
    });
    out
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
        Err(resp) => return *resp,
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
            if on_login_failed(&state, ban_key).await == crate::security::fail2ban::FailureOutcome::SaturatedFailClosed {
                return saturated_fail_closed_response();
            }
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

#[derive(Deserialize, Default)]
struct ReauthTokenBody {
    #[serde(default)]
    reauth_token: String,
}

fn parse_optional_reauth_body(raw_body: &Bytes) -> Option<String> {
    if raw_body.is_empty() {
        return None;
    }
    serde_json::from_slice::<ReauthTokenBody>(raw_body)
        .ok()
        .map(|b| b.reauth_token)
        .filter(|s| !s.trim().is_empty())
}

fn extract_reauth_token<'a>(headers: &'a HeaderMap, body_token: Option<&'a str>) -> Option<&'a str> {
    body_token
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            headers
                .get("x-vane-reauth-token")
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|s| !s.is_empty())
        })
}

fn consume_reauth_token_checked(
    state: &AppState,
    session_token: &str,
    headers: &HeaderMap,
    body_token: Option<&str>,
    peer_ip: std::net::IpAddr,
    require_mfa: bool,
) -> Result<(), crate::security::auth::ReauthConsumeError> {
    let Some(tok) = extract_reauth_token(headers, body_token) else {
        return Err(crate::security::auth::ReauthConsumeError::InvalidOrExpired);
    };
    state
        .reauth_tickets
        .consume_reauth_token_ex(session_token, tok, peer_ip, require_mfa)
}

fn reauth_error_response(
    err: crate::security::auth::ReauthConsumeError,
    require_mfa: bool,
    message: &str,
) -> Response {
    match err {
        crate::security::auth::ReauthConsumeError::MfaRequired => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "MFA_REAUTH_REQUIRED",
                "code": "MFA_REAUTH_REQUIRED",
                "mfa_required": true,
                "message": format!("{}（已启用双因素认证，请使用 TOTP 或通行密钥完成二次验证）", message),
            })),
        )
            .into_response(),
        crate::security::auth::ReauthConsumeError::InvalidOrExpired => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "REAUTH_REQUIRED",
                "code": "REAUTH_REQUIRED",
                "mfa_required": require_mfa,
                "message": message,
            })),
        )
            .into_response(),
    }
}

async fn api_totp_setup(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Response {
    let cur_tok = match require_full_admin(&state, &headers) {
        Ok(tok) => tok,
        Err(resp) => return *resp,
    };
    let cfg = state.config.load();
    if cfg.admin.totp_enabled {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "TOTP_ALREADY_ENABLED",
                "message": "同一管理员账号最多绑定 1 个 TOTP，请先关闭现有 TOTP 后再重新配置"
            })),
        )
            .into_response();
    }
    let require_mfa = crate::security::auth::admin_has_mfa_enabled(&cfg.admin);
    let body_tok = parse_optional_reauth_body(&raw_body);
    if let Err(err) = consume_reauth_token_checked(
        &state,
        &cur_tok,
        &headers,
        body_tok.as_deref(),
        peer.ip(),
        require_mfa,
    ) {
        return reauth_error_response(err, require_mfa, "配置 TOTP 双因素认证前需要完成二次身份验证");
    }
    let Ok(secret) = generate_totp_secret() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "生成密钥失败" })),
        )
            .into_response();
    };
    let b32 = base32_encode(&secret);
    let uri = otpauth_uri(&b32, &cfg.admin.username, "Vane Gateway");
    if let Ok(mut auth) = state.auth.lock() {
        auth.pending_totp_secret = Some((secret, std::time::Instant::now()));
    }
    Json(serde_json::json!({ "secret_base32": b32, "otpauth_uri": uri })).into_response()
}

#[derive(Deserialize)]
struct TotpEnableReq {
    code: String,
    #[serde(default)]
    reauth_token: String,
}

async fn hash_recovery_codes_blocking(gate: &HashGate) -> Result<(Vec<String>, Vec<String>), Box<Response>> {
    let recovery_codes = generate_recovery_codes(6).map_err(|e| {
        Box::new((StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response())
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
        return Err(Box::new(
            (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({ "error": "繁忙" }))).into_response(),
        ));
    };
    Ok((recovery_codes, hashes))
}

async fn api_totp_enable(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<TotpEnableReq>,
) -> Response {
    let cur_tok = match require_full_admin(&state, &headers) {
        Ok(tok) => tok,
        Err(resp) => return *resp,
    };
    let Ok(code_num) = req.code.trim().parse::<u32>() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "请输入 6 位数字验证码" })),
        )
            .into_response();
    };
    let cfg_pre = state.config.load();
    if cfg_pre.admin.totp_enabled {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "TOTP 已启用，请先关闭后再重新配置" })),
        )
            .into_response();
    }
    let require_mfa = crate::security::auth::admin_has_mfa_enabled(&cfg_pre.admin);
    if let Err(err) = consume_reauth_token_checked(
        &state,
        &cur_tok,
        &headers,
        Some(&req.reauth_token),
        peer.ip(),
        require_mfa,
    ) {
        return reauth_error_response(err, require_mfa, "启用 TOTP 双因素认证前需要完成二次身份验证");
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

    // VANE-I01：在 config_lock 之外生成并哈希 6 个一次性恢复码，避免长时间阻塞配置写锁
    let (recovery_codes, recovery_hashes) = match hash_recovery_codes_blocking(&state.hash_gate).await {
        Ok(pair) => pair,
        Err(resp) => return *resp,
    };

    let _cfg_guard = state.config_lock.lock().await;
    if state.config.load().admin.totp_enabled {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "TOTP 已启用，请先关闭后再重新配置" })),
        )
            .into_response();
    }
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

async fn api_totp_regenerate_recovery(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Response {
    let cur_tok = match require_full_admin(&state, &headers) {
        Ok(tok) => tok,
        Err(resp) => return *resp,
    };
    let cfg_pre = state.config.load();
    if !cfg_pre.admin.totp_enabled {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "请先启用 TOTP 二步验证" })),
        )
            .into_response();
    }
    let require_mfa = crate::security::auth::admin_has_mfa_enabled(&cfg_pre.admin);
    let body_tok = parse_optional_reauth_body(&raw_body);
    if let Err(err) = consume_reauth_token_checked(
        &state,
        &cur_tok,
        &headers,
        body_tok.as_deref(),
        peer.ip(),
        require_mfa,
    ) {
        return reauth_error_response(err, require_mfa, "重新生成 TOTP 一次性恢复码前需要完成二次身份验证");
    }
    // VANE-I01：在 config_lock 之外执行恢复码 PBKDF2 计算
    let (recovery_codes, recovery_hashes) = match hash_recovery_codes_blocking(&state.hash_gate).await {
        Ok(pair) => pair,
        Err(resp) => return *resp,
    };
    let _cfg_guard = state.config_lock.lock().await;
    if !state.config.load().admin.totp_enabled {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "请先启用 TOTP 二步验证" })),
        )
            .into_response();
    }
    let mut next_cfg = (**state.config.load()).clone();
    next_cfg.admin.totp_recovery_hashes = recovery_hashes;
    if let Err(e) = save_config(&state.config_path, &next_cfg) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response();
    }
    state.config.store(Arc::new(next_cfg));
    logger::log(Level::Info, "auth", "已重新生成一次性 TOTP 恢复码（旧恢复码已作废）");
    Json(serde_json::json!({ "recovery_codes": recovery_codes })).into_response()
}

async fn api_totp_disable(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Response {
    let cur_tok = match require_full_admin(&state, &headers) {
        Ok(tok) => tok,
        Err(resp) => return *resp,
    };
    let _cfg_guard = state.config_lock.lock().await;
    let mut next_cfg = (**state.config.load()).clone();
    let was_enabled = next_cfg.admin.totp_enabled;
    if was_enabled {
        let require_mfa = crate::security::auth::admin_has_mfa_enabled(&next_cfg.admin);
        let body_tok = parse_optional_reauth_body(&raw_body);
        if let Err(err) = consume_reauth_token_checked(
            &state,
            &cur_tok,
            &headers,
            body_tok.as_deref(),
            peer.ip(),
            require_mfa,
        ) {
            return reauth_error_response(err, require_mfa, "关闭已启用的 TOTP 双因素认证前需要完成二次身份验证");
        }
    }
    next_cfg.admin.totp_enabled = false;
    next_cfg.admin.totp_secret.clear();
    next_cfg.admin.totp_last_step = 0;
    next_cfg.admin.totp_recovery_hashes.clear();
    if let Err(e) = save_config(&state.config_path, &next_cfg) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response();
    }
    let mut resp = Json(serde_json::json!({ "enabled": false })).into_response();
    if let Ok(mut auth) = state.auth.lock() {
        auth.engine.reset_totp_watermark();
        auth.pending_totp_secret = None;
        if was_enabled {
            let ttl = Duration::from_secs(next_cfg.admin.session_ttl_secs.clamp(300, 86_400));
            let peer_key = BanKey::from_peer(peer.ip());
            if let Ok(fresh) = auth.sessions.revoke_all_and_reissue(&cur_tok, peer_key, SessionScope::FullAdmin, ttl) {
                let cookie = format!(
                    "{SESSION_COOKIE_NAME}={fresh}; Path=/; Max-Age={}; HttpOnly; Secure; SameSite=Strict",
                    ttl.as_secs()
                );
                if let Ok(hv) = header::HeaderValue::from_str(&cookie) {
                    resp.headers_mut().append(header::SET_COOKIE, hv);
                }
            }
        }
    }
    state.config.store(Arc::new(next_cfg));
    if was_enabled {
        state.pty_mgr.notify_revoke();
    }
    logger::log(Level::Warn, "auth", "管理员已关闭 TOTP 双因素认证并彻底清空已保存密钥与恢复码");
    resp
}

// ---------------------------------------------------------------------------
// WebAuthn / Passkey 通行密钥（注册 / 登录 / 开关 / 删除）与全局多因素二次验证
// ---------------------------------------------------------------------------

fn resolve_verified_webauthn_origin_rp(headers: &HeaderMap, cfg: &Config) -> Result<(String, String), String> {
    let raw_origin = headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "缺少受信 Origin 请求头".to_string())?;
    let Some(auth) = boundary::origin_authority(raw_origin) else {
        return Err("Origin 必须为合法 HTTPS 地址".into());
    };
    if !boundary::trusted_origin_authority(&auth, cfg) {
        return Err("请求来源 Origin 不受信任".into());
    }
    let rp_id = crate::security::webauthn::extract_rp_id_from_origin(raw_origin)?;
    Ok((raw_origin.trim_end_matches('/').to_string(), rp_id))
}

async fn api_passkey_register_options(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Response {
    let session_token = match require_full_admin(&state, &headers) {
        Ok(tok) => tok,
        Err(resp) => return *resp,
    };
    let cfg = state.config.load();
    if cfg.admin.passkeys.len() >= 16 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "PASSKEY_LIMIT", "message": "最多绑定 16 把通行密钥" })),
        )
            .into_response();
    }
    let (origin, rp_id) = match resolve_verified_webauthn_origin_rp(&headers, &cfg) {
        Ok(v) => v,
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "PASSKEY_RP_INVALID", "message": msg })),
            )
                .into_response()
        }
    };
    let require_mfa = crate::security::auth::admin_has_mfa_enabled(&cfg.admin);
    let body_tok = parse_optional_reauth_body(&raw_body);
    if let Err(err) = consume_reauth_token_checked(
        &state,
        &session_token,
        &headers,
        body_tok.as_deref(),
        peer.ip(),
        require_mfa,
    ) {
        return reauth_error_response(err, require_mfa, "注册新通行密钥前需要完成二次身份验证");
    }
    let ban_key = BanKey::from_peer(peer.ip());
    let session_digest = crate::security::auth::SessionStore::token_digest(&session_token);
    let challenge = {
        let mut auth = state.auth.lock().unwrap_or_else(|e| e.into_inner());
        match auth
            .webauthn
            .create_session_registration_challenge_with_reauth(
                origin,
                rp_id.clone(),
                ban_key,
                session_digest,
                true,
            )
        {
            Ok(c) => c,
            Err(e) => return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({ "error": e }))).into_response(),
        }
    };
    let user_id_hash = ring::digest::digest(&ring::digest::SHA256, format!("vane-admin:{}", cfg.admin.username).as_bytes());
    let user_id_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(user_id_hash.as_ref());
    let exclude: Vec<serde_json::Value> = cfg
        .admin
        .passkeys
        .iter()
        .map(|p| serde_json::json!({ "type": "public-key", "id": p.id }))
        .collect();
    Json(serde_json::json!({
        "challenge": challenge,
        "rp": { "name": "Vane Gateway", "id": rp_id },
        "user": {
            "id": user_id_b64,
            "name": cfg.admin.username,
            "displayName": cfg.admin.username
        },
        "pubKeyCredParams": [
            { "type": "public-key", "alg": crate::security::webauthn::COSE_ALG_ES256 },
            { "type": "public-key", "alg": crate::security::webauthn::COSE_ALG_EDDSA }
        ],
        "timeout": 60000,
        "attestation": "none",
        "excludeCredentials": exclude,
        "authenticatorSelection": {
            "residentKey": "preferred",
            "userVerification": "required"
        }
    }))
    .into_response()
}

#[derive(Deserialize)]
struct PasskeyRegisterVerifyReq {
    #[serde(default)]
    name: String,
    challenge: String,
    client_data_json: String,
    attestation_object: String,
}

async fn api_passkey_register_verify(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<PasskeyRegisterVerifyReq>,
) -> Response {
    let session_token = match require_full_admin(&state, &headers) {
        Ok(tok) => tok,
        Err(resp) => return *resp,
    };
    let cfg_pre = state.config.load();
    let (origin, rp_id) = match resolve_verified_webauthn_origin_rp(&headers, &cfg_pre) {
        Ok(v) => v,
        Err(msg) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": msg }))).into_response(),
    };
    let ban_key = BanKey::from_peer(peer.ip());
    let session_digest = crate::security::auth::SessionStore::token_digest(&session_token);
    let consumed = {
        let mut auth = state.auth.lock().unwrap_or_else(|e| e.into_inner());
        auth.webauthn.consume_for_session(
            &req.challenge,
            &crate::security::webauthn::WebAuthnPurpose::Register,
            &origin,
            &rp_id,
            ban_key,
            session_digest,
        )
    };
    let Some(challenge) = consumed else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "PASSKEY_CHALLENGE_INVALID", "message": "通行密钥注册挑战已过期或无效，请重试" })),
        )
            .into_response();
    };
    if !challenge.reauth_verified {
        let require_mfa = crate::security::auth::admin_has_mfa_enabled(&cfg_pre.admin);
        return reauth_error_response(
            crate::security::auth::ReauthConsumeError::InvalidOrExpired,
            require_mfa,
            "注册通行密钥前必须完成二次身份验证",
        );
    }
    let eff_name = if req.name.trim().is_empty() {
        "Passkey"
    } else {
        req.name.trim()
    };
    let entry = match crate::security::webauthn::verify_registration(
        &req.challenge,
        &origin,
        &rp_id,
        &req.client_data_json,
        &req.attestation_object,
        eff_name,
        logger::unix_now(),
    ) {
        Ok(e) => e,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response(),
    };

    let _cfg_guard = state.config_lock.lock().await;
    let mut next_cfg = (**state.config.load()).clone();
    if next_cfg.admin.passkeys.len() >= 16 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "通行密钥数量已达上限 (16)" }))).into_response();
    }
    if next_cfg.admin.passkeys.iter().any(|p| p.id == entry.id) {
        return (StatusCode::CONFLICT, Json(serde_json::json!({ "error": "该通行密钥已绑定，请勿重复添加" }))).into_response();
    }
    let added_name = entry.name.clone();
    next_cfg.admin.passkeys.push(entry);
    next_cfg.admin.passkey_enabled = true;
    if let Err(e) = next_cfg
        .validate_with_vault_and_listeners(Some(&state.vault), &state.live_admin_listeners)
        .and_then(|_| save_config(&state.config_path, &next_cfg))
    {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response();
    }
    state.config.store(Arc::new(next_cfg.clone()));
    logger::log(Level::Info, "auth", &format!("管理员已绑定新的通行密钥: {}", added_name));
    Json(serde_json::json!({
        "passkey_enabled": next_cfg.admin.passkey_enabled,
        "passkeys": next_cfg.admin.passkeys
    }))
    .into_response()
}

#[derive(Deserialize)]
struct PasskeyToggleReq {
    enabled: bool,
    #[serde(default)]
    reauth_token: String,
}

async fn api_passkey_toggle(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<PasskeyToggleReq>,
) -> Response {
    let cur_tok = match require_full_admin(&state, &headers) {
        Ok(tok) => tok,
        Err(resp) => return *resp,
    };
    let _cfg_guard = state.config_lock.lock().await;
    let mut next_cfg = (**state.config.load()).clone();
    let was_enabled = next_cfg.admin.passkey_enabled;
    if req.enabled {
        if next_cfg.admin.passkeys.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "PASSKEY_REQUIRED",
                    "message": "请先绑定至少 1 把通行密钥，绑定成功后将自动启用"
                })),
            )
                .into_response();
        }
        let require_mfa = crate::security::auth::admin_has_mfa_enabled(&next_cfg.admin);
        if let Err(err) = consume_reauth_token_checked(
            &state,
            &cur_tok,
            &headers,
            Some(&req.reauth_token),
            peer.ip(),
            require_mfa,
        ) {
            return reauth_error_response(
                err,
                require_mfa,
                "启用通行密钥前需要完成二次身份验证",
            );
        }
        next_cfg.admin.passkey_enabled = true;
    } else {
        if !next_cfg.admin.password_login_enabled {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "LAST_AUTH_METHOD",
                    "message": "当前已关闭密码登录，不能关闭或清空全部通行密钥；请先重新开启密码登录，防止账号锁死"
                })),
            )
                .into_response();
        }
        if was_enabled || !next_cfg.admin.passkeys.is_empty() {
            let require_mfa = crate::security::auth::admin_has_mfa_enabled(&next_cfg.admin);
            if let Err(err) = consume_reauth_token_checked(
                &state,
                &cur_tok,
                &headers,
                Some(&req.reauth_token),
                peer.ip(),
                require_mfa,
            ) {
                return reauth_error_response(
                    err,
                    require_mfa,
                    "关闭通行密钥并清空已保存密钥前需要完成二次身份验证",
                );
            }
        }
        next_cfg.admin.passkey_enabled = false;
        next_cfg.admin.passkeys.clear();
    }
    if let Err(e) = next_cfg
        .validate_with_vault_and_listeners(Some(&state.vault), &state.live_admin_listeners)
        .and_then(|_| save_config(&state.config_path, &next_cfg))
    {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response();
    }
    state.config.store(Arc::new(next_cfg.clone()));
    let mut resp = Json(serde_json::json!({
        "passkey_enabled": next_cfg.admin.passkey_enabled,
        "passkeys": next_cfg.admin.passkeys
    }))
    .into_response();
    if was_enabled && !next_cfg.admin.passkey_enabled {
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
        logger::log(Level::Warn, "auth", "管理员已关闭通行密钥并彻底清空全部已保存通行密钥");
    } else {
        logger::log(Level::Info, "auth", &format!("通行密钥开关已更新为 enabled={}", next_cfg.admin.passkey_enabled));
    }
    resp
}

async fn api_passkey_delete(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    let cur_tok = match require_full_admin(&state, &headers) {
        Ok(tok) => tok,
        Err(resp) => return *resp,
    };
    let _cfg_guard = state.config_lock.lock().await;
    let mut next_cfg = (**state.config.load()).clone();
    if !next_cfg.admin.passkeys.iter().any(|p| p.id == id) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "PASSKEY_NOT_FOUND", "message": "目标通行密钥不存在" })),
        )
            .into_response();
    }
    if next_cfg.admin.passkeys.len() <= 1 && !next_cfg.admin.password_login_enabled {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "LAST_AUTH_METHOD",
                "message": "当前已关闭密码登录，不能删除最后一把通行密钥；请先重新开启密码登录，防止账号锁死"
            })),
        )
            .into_response();
    }
    let require_mfa = crate::security::auth::admin_has_mfa_enabled(&next_cfg.admin);
    if let Err(err) = consume_reauth_token_checked(&state, &cur_tok, &headers, None, peer.ip(), require_mfa) {
        return reauth_error_response(err, require_mfa, "删除已绑定的通行密钥前需要完成二次身份验证");
    }
    let before = next_cfg.admin.passkeys.len();
    next_cfg.admin.passkeys.retain(|p| p.id != id);
    if next_cfg.admin.passkeys.is_empty() {
        next_cfg.admin.passkey_enabled = false;
    }
    if let Err(e) = next_cfg
        .validate_with_vault_and_listeners(Some(&state.vault), &state.live_admin_listeners)
        .and_then(|_| save_config(&state.config_path, &next_cfg))
    {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response();
    }
    state.config.store(Arc::new(next_cfg.clone()));
    let mut resp = Json(serde_json::json!({
        "passkey_enabled": next_cfg.admin.passkey_enabled,
        "passkeys": next_cfg.admin.passkeys
    }))
    .into_response();
    if next_cfg.admin.passkeys.len() != before {
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
        logger::log(Level::Warn, "auth", "管理员已移除一把通行密钥并轮换全部登录会话");
    }
    resp
}

async fn api_passkey_login_options(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let ban_key = BanKey::from_peer(peer.ip());
    if state.fail2ban.is_key_blocked(ban_key) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({ "error": "IP_BANNED", "message": "认证失败次数过多或限流已饱和，请稍后再试" })),
        )
            .into_response();
    }
    let cfg = state.config.load();
    if cfg.admin.must_change_password {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "MUST_CHANGE_INITIAL_PASSWORD", "message": "请先使用初始密码登录并完成强制改密" })),
        )
            .into_response();
    }
    if !cfg.admin.passkey_enabled || cfg.admin.passkeys.is_empty() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "PASSKEY_DISABLED", "message": "未启用或未绑定通行密钥" })),
        )
            .into_response();
    }
    let (origin, rp_id) = match resolve_verified_webauthn_origin_rp(&headers, &cfg) {
        Ok(v) => v,
        Err(msg) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "PASSKEY_RP_INVALID", "message": msg }))).into_response(),
    };
    let allow: Vec<serde_json::Value> = cfg
        .admin
        .passkeys
        .iter()
        .filter(|p| p.rp_id == rp_id)
        .map(|p| serde_json::json!({ "type": "public-key", "id": p.id }))
        .collect();
    if allow.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "PASSKEY_RP_MISMATCH",
                "message": format!("当前域名 ({}) 下尚未绑定通行密钥，请使用原注册域名或密码登录", rp_id)
            })),
        )
            .into_response();
    }
    let challenge = {
        let mut auth = state.auth.lock().unwrap_or_else(|e| e.into_inner());
        match auth
            .webauthn
            .issue(crate::security::webauthn::WebAuthnPurpose::Login, origin, rp_id.clone(), ban_key)
        {
            Ok(c) => c,
            Err(e) => return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({ "error": e }))).into_response(),
        }
    };
    Json(serde_json::json!({
        "challenge": challenge,
        "rpId": rp_id,
        "timeout": 60000,
        "userVerification": "required",
        "allowCredentials": allow
    }))
    .into_response()
}

#[derive(Deserialize)]
struct PasskeyAssertionReq {
    challenge: String,
    credential_id: String,
    client_data_json: String,
    authenticator_data: String,
    signature: String,
}

async fn api_passkey_login_verify(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<PasskeyAssertionReq>,
) -> Response {
    let ip = peer.ip();
    let ban_key = BanKey::from_peer(ip);
    if state.fail2ban.is_key_blocked(ban_key) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({ "error": "IP_BANNED", "message": "认证失败次数过多或限流已饱和，请稍后再试" })),
        )
            .into_response();
    }
    let cfg_pre = state.config.load();
    if cfg_pre.admin.must_change_password || !cfg_pre.admin.passkey_enabled || cfg_pre.admin.passkeys.is_empty() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "PASSKEY_DISABLED" }))).into_response();
    }
    let (origin, rp_id) = match resolve_verified_webauthn_origin_rp(&headers, &cfg_pre) {
        Ok(v) => v,
        Err(msg) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": msg }))).into_response(),
    };
    let consumed = {
        let mut auth = state.auth.lock().unwrap_or_else(|e| e.into_inner());
        auth.webauthn.consume(
            &req.challenge,
            &crate::security::webauthn::WebAuthnPurpose::Login,
            &origin,
            &rp_id,
            ban_key,
        )
    };
    if consumed.is_none() {
        if on_login_failed(&state, ban_key).await == crate::security::fail2ban::FailureOutcome::SaturatedFailClosed {
            return saturated_fail_closed_response();
        }
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "PASSKEY_CHALLENGE_INVALID", "message": "通行密钥挑战已过期或无效" })),
        )
            .into_response();
    }

    let _cfg_guard = state.config_lock.lock().await;
    let cur_cfg = state.config.load();
    // VANE-L01：在 config_lock 下重新核验强制改密状态与通行密钥开关，消除并发配置变更 TOCTOU
    if cur_cfg.admin.must_change_password || !cur_cfg.admin.passkey_enabled || cur_cfg.admin.passkeys.is_empty() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "PASSKEY_DISABLED", "message": "通行密钥登录状态已变更" })),
        )
            .into_response();
    }
    let (idx, new_count) = match crate::security::webauthn::verify_assertion(
        &req.challenge,
        &origin,
        &rp_id,
        &cur_cfg.admin.passkeys,
        &req.credential_id,
        &req.client_data_json,
        &req.authenticator_data,
        &req.signature,
    ) {
        Ok(res) => res,
        Err(e) => {
            if on_login_failed(&state, ban_key).await == crate::security::fail2ban::FailureOutcome::SaturatedFailClosed {
                return saturated_fail_closed_response();
            }
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "PASSKEY_VERIFY_FAILED", "message": e }))).into_response();
        }
    };

    let mut next_cfg = (**cur_cfg).clone();
    let key_name = next_cfg.admin.passkeys[idx].name.clone();
    next_cfg.admin.passkeys[idx].sign_count = new_count;
    next_cfg.admin.passkeys[idx].last_used_at = logger::unix_now();
    if let Err(e) = save_config(&state.config_path, &next_cfg) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response();
    }
    state.config.store(Arc::new(next_cfg.clone()));

    state.fail2ban.record_success(ban_key);
    let ttl = Duration::from_secs(next_cfg.admin.session_ttl_secs.clamp(300, 86_400));
    let token = {
        let mut auth = state.auth.lock().unwrap_or_else(|e| e.into_inner());
        match auth.sessions.issue(SessionScope::FullAdmin, ban_key, ttl) {
            Ok(t) => t,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response(),
        }
    };
    logger::log(Level::Info, "auth", &format!("管理员通过通行密钥 ({}) 登录成功 (ip={})", key_name, ip));
    build_session_response(&token, ttl.as_secs(), false, &next_cfg, &state.vault)
}

async fn api_reauth_options(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let session_token = match require_full_admin(&state, &headers) {
        Ok(tok) => tok,
        Err(resp) => return *resp,
    };
    let cfg = state.config.load();
    let ban_key = BanKey::from_peer(peer.ip());
    let mut passkey_opts: Option<serde_json::Value> = None;
    let mut passkey_reason = String::new();
    if cfg.admin.passkey_enabled && !cfg.admin.passkeys.is_empty() {
        match resolve_verified_webauthn_origin_rp(&headers, &cfg) {
            Ok((origin, rp_id)) => {
                let allow: Vec<serde_json::Value> = cfg
                    .admin
                    .passkeys
                    .iter()
                    .filter(|p| p.rp_id == rp_id)
                    .map(|p| serde_json::json!({ "type": "public-key", "id": p.id }))
                    .collect();
                if !allow.is_empty() {
                    let digest = crate::security::auth::SessionStore::token_digest(&session_token);
                    let ch = {
                        let mut auth = state.auth.lock().unwrap_or_else(|e| e.into_inner());
                        auth.webauthn.issue(
                            crate::security::webauthn::WebAuthnPurpose::Reauth(digest),
                            origin,
                            rp_id.clone(),
                            ban_key,
                        )
                    };
                    if let Ok(challenge) = ch {
                        passkey_opts = Some(serde_json::json!({
                            "challenge": challenge,
                            "rpId": rp_id,
                            "timeout": 60000,
                            "userVerification": "required",
                            "allowCredentials": allow
                        }));
                    }
                } else {
                    passkey_reason = format!("当前域名 ({rp_id}) 下无已绑定通行密钥");
                }
            }
            Err(msg) => passkey_reason = msg,
        }
    }
    Json(serde_json::json!({
        "mfa_enabled": crate::security::auth::admin_has_mfa_enabled(&cfg.admin),
        "methods": {
            "password": cfg.admin.password_login_enabled,
            "totp": cfg.admin.totp_enabled,
            "passkey": passkey_opts.is_some()
        },
        "passkey_options": passkey_opts,
        "passkey_unavailable_reason": passkey_reason
    }))
    .into_response()
}

#[derive(Deserialize)]
struct ReauthVerifyReq {
    method: String, // "password" | "totp" | "passkey"
    #[serde(default)]
    unlock_module: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    totp_code: String,
    #[serde(default)]
    challenge: String,
    #[serde(default)]
    credential_id: String,
    #[serde(default)]
    client_data_json: String,
    #[serde(default)]
    authenticator_data: String,
    #[serde(default)]
    signature: String,
}

async fn api_reauth_verify(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<ReauthVerifyReq>,
) -> Response {
    let session_token = match require_full_admin(&state, &headers) {
        Ok(tok) => tok,
        Err(resp) => return *resp,
    };
    let ban_key = BanKey::from_peer(peer.ip());
    if state.fail2ban.is_key_banned(ban_key) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({ "error": "IP_BANNED", "message": "认证失败次数过多，该网络已被临时封禁" })),
        )
            .into_response();
    }

    let verified_with_mfa = match req.method.as_str() {
        "password" => {
            let cfg = state.config.load();
            if !cfg.admin.password_login_enabled {
                return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "PASSWORD_LOGIN_DISABLED" }))).into_response();
            }
            if req.password.is_empty() {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({ "error": "INVALID_REAUTH_PASSWORD", "message": "请输入管理员密码" })),
                )
                    .into_response();
            }
            let pre_hash = cfg.admin.password_hash.clone();
            let Some(ph) = PasswordHash::parse(&pre_hash) else {
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "密码未初始化" }))).into_response();
            };
            let pw = req.password.into_bytes();
            let Ok(ok) = state.hash_gate.run(move || ph.verify(&pw)).await else {
                return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({ "error": "认证繁忙" }))).into_response();
            };
            if !ok {
                if on_login_failed(&state, ban_key).await == crate::security::fail2ban::FailureOutcome::SaturatedFailClosed {
                    return saturated_fail_closed_response();
                }
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({ "error": "INVALID_REAUTH_PASSWORD", "message": "二次验证密码错误" })),
                )
                    .into_response();
            }
            // VANE-L01：HashGate 返回后重检密码配置是否并发变更
            let cfg_after = state.config.load();
            if !cfg_after.admin.password_login_enabled || cfg_after.admin.password_hash != pre_hash {
                return (
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({ "error": "AUTH_STATE_CHANGED", "message": "认证状态已并发变更，请重新验证" })),
                )
                    .into_response();
            }
            false
        }
        "totp" => {
            let _cfg_guard = state.config_lock.lock().await;
            let cfg = state.config.load();
            if !cfg.admin.totp_enabled {
                return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "TOTP 未开启" }))).into_response();
            }
            let Ok(totp_plain) = state.vault.reveal_string("admin.totp_secret", &cfg.admin.totp_secret) else {
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "TOTP 密钥解密失败" }))).into_response();
            };
            let Some(secret_bytes) = base32_decode(&totp_plain).filter(|b| b.len() >= 16) else {
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "TOTP 密钥配置无效" }))).into_response();
            };
            let code_str = req.totp_code.trim();
            let Some(num) = (code_str.len() == 6).then(|| code_str.parse::<u32>().ok()).flatten() else {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({ "error": "INVALID_TOTP", "message": "请输入 6 位 TOTP 验证码" })),
                )
                    .into_response();
            };
            let (ok, new_watermark) = {
                let mut auth = state.auth.lock().unwrap_or_else(|e| e.into_inner());
                let passed = auth.engine.verify_totp(&secret_bytes, num, logger::unix_now());
                (passed, auth.engine.totp_watermark())
            };
            if !ok {
                if on_login_failed(&state, ban_key).await == crate::security::fail2ban::FailureOutcome::SaturatedFailClosed {
                    return saturated_fail_closed_response();
                }
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({ "error": "INVALID_TOTP", "message": "TOTP 验证码无效或已重放" })),
                )
                    .into_response();
            }
            if new_watermark > cfg.admin.totp_last_step {
                let mut next_cfg = (**cfg).clone();
                next_cfg.admin.totp_last_step = new_watermark;
                if let Err(e) = save_config(&state.config_path, &next_cfg) {
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response();
                }
                state.config.store(Arc::new(next_cfg));
            }
            true
        }
        "passkey" => {
            let cfg_pre = state.config.load();
            if !cfg_pre.admin.passkey_enabled || cfg_pre.admin.passkeys.is_empty() {
                return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "PASSKEY_DISABLED" }))).into_response();
            }
            let (origin, rp_id) = match resolve_verified_webauthn_origin_rp(&headers, &cfg_pre) {
                Ok(v) => v,
                Err(msg) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": msg }))).into_response(),
            };
            let digest = crate::security::auth::SessionStore::token_digest(&session_token);
            let consumed = {
                let mut auth = state.auth.lock().unwrap_or_else(|e| e.into_inner());
                auth.webauthn.consume(
                    &req.challenge,
                    &crate::security::webauthn::WebAuthnPurpose::Reauth(digest),
                    &origin,
                    &rp_id,
                    ban_key,
                )
            };
            if consumed.is_none() {
                if on_login_failed(&state, ban_key).await == crate::security::fail2ban::FailureOutcome::SaturatedFailClosed {
                    return saturated_fail_closed_response();
                }
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({ "error": "PASSKEY_CHALLENGE_INVALID", "message": "通行密钥验证挑战已过期或无效" })),
                )
                    .into_response();
            }
            let _cfg_guard = state.config_lock.lock().await;
            let cur_cfg = state.config.load();
            if !cur_cfg.admin.passkey_enabled || cur_cfg.admin.passkeys.is_empty() {
                return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "PASSKEY_DISABLED" }))).into_response();
            }
            let (idx, new_count) = match crate::security::webauthn::verify_assertion(
                &req.challenge,
                &origin,
                &rp_id,
                &cur_cfg.admin.passkeys,
                &req.credential_id,
                &req.client_data_json,
                &req.authenticator_data,
                &req.signature,
            ) {
                Ok(r) => r,
                Err(e) => {
                    if on_login_failed(&state, ban_key).await == crate::security::fail2ban::FailureOutcome::SaturatedFailClosed {
                        return saturated_fail_closed_response();
                    }
                    return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "PASSKEY_VERIFY_FAILED", "message": e }))).into_response();
                }
            };
            let mut next_cfg = (**cur_cfg).clone();
            next_cfg.admin.passkeys[idx].sign_count = new_count;
            next_cfg.admin.passkeys[idx].last_used_at = logger::unix_now();
            if let Err(e) = save_config(&state.config_path, &next_cfg) {
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response();
            }
            state.config.store(Arc::new(next_cfg));
            true
        }
        _ => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "不支持的二次验证方式" }))).into_response();
        }
    };

    let mut unlocked_modules = std::collections::BTreeMap::new();
    let req_mod = req.unlock_module.trim();
    if !req_mod.is_empty() && crate::config::MODULE_NAMES.contains(&req_mod) {
        if let Ok(mut auth) = state.auth.lock() {
            auth.sessions.unlock_module(&session_token, req_mod);
            unlocked_modules = auth.sessions.unlocked_modules_remaining(&session_token);
        }
    } else if let Ok(auth) = state.auth.lock() {
        unlocked_modules = auth.sessions.unlocked_modules_remaining(&session_token);
    }

    match state
        .reauth_tickets
        .issue_reauth_token_ex(&session_token, peer.ip(), verified_with_mfa)
    {
        Ok(reauth_token) => Json(serde_json::json!({
            "reauth_token": reauth_token,
            "verified_with_mfa": verified_with_mfa,
            "expires_in": 30,
            "unlocked_modules": unlocked_modules,
            "unlock_ttl_secs": crate::security::auth::MODULE_UNLOCK_TTL.as_secs(),
        }))
        .into_response(),
        Err(msg) => (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({ "error": "TICKET_BUSY", "message": msg }))).into_response(),
    }
}

#[derive(Deserialize)]
struct ModuleLockReq {
    module: String,
}

async fn api_auth_module_lock(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ModuleLockReq>,
) -> Response {
    let session_token = match require_full_admin(&state, &headers) {
        Ok(tok) => tok,
        Err(resp) => return *resp,
    };
    let target_mod = req.module.trim();
    let unlocked_modules = if let Ok(mut auth) = state.auth.lock() {
        auth.sessions.lock_module(&session_token, target_mod);
        auth.sessions.unlocked_modules_remaining(&session_token)
    } else {
        std::collections::BTreeMap::new()
    };
    if matches!(target_mod, "web_terminal" | "docker") {
        state.pty_mgr.notify_revoke();
    }
    Json(serde_json::json!({
        "ok": true,
        "unlocked_modules": unlocked_modules
    }))
    .into_response()
}

async fn api_dashboard(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return *resp;
    }
    let cfg = state.config.load_full();
    let sampler = state.monitor_sampler.clone();
    let mcfg = cfg.monitor.clone();
    let sys = match tokio::task::spawn_blocking(move || sampler.sample(&mcfg)).await {
        Ok(s) => s,
        Err(_) => state.monitor_sampler.sample(&cfg.monitor),
    };

    // 异步执行低内存 / 高温告警阈值评估（始终写入站内消息通知，并按需投递外部通知渠道）
    {
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
    let bans = collect_all_active_bans(&state);

    Json(serde_json::json!({
        "system": sys,
        "modules": cfg.modules,
        "module_health": health,
        "active_connections": state.global_quota.active_connections(),
        "max_connections": state.global_quota.capacity(),
        "firewall": {
            "backend": state.firewall.backend(),
            "lockdown": state.firewall.is_lockdown(),
            "degraded": state.firewall.is_degraded(),
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
        "unread_notifications": state.inbox.unread_count(),
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
                .env_remove("VANE_MASTER_KEY")
                .env_remove("VANE_MASTER_KEY_FILE")
                .env("PATH", "/usr/sbin:/sbin:/usr/bin:/bin")
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
        return *resp;
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
        return *resp;
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
        return *resp;
    }
    logger::global().clear();
    Json(serde_json::json!({ "ok": true })).into_response()
}

async fn api_get_settings(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return *resp;
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
        Err(resp) => return *resp,
    };
    let _cfg_guard = state.config_lock.lock().await;
    let mut renames: Vec<(String, String)> = Vec::new();
    let mut body_reauth_token: Option<String> = None;
    if let Some(obj) = incoming_json.as_object_mut() {
        body_reauth_token = obj
            .remove("reauth_token")
            .and_then(|v| v.as_str().map(str::to_string))
            .filter(|s| !s.trim().is_empty());
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
    // 独立反代门禁账号仅通过 /api/proxy/auth-users* 受控管理，避免 PUT /api/settings 意外覆盖哈希
    if let Some(root_obj) = incoming_json.as_object_mut() {
        root_obj.remove("proxy_auth_users");
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
    // L1 认证凭据、TOTP、通行密钥、反代独立门禁账号与仅配置文件可控的安全边界字段，一律沿用当前受保护状态
    next_cfg.admin.password_hash = current_cfg.admin.password_hash.clone();
    next_cfg.admin.must_change_password = current_cfg.admin.must_change_password;
    next_cfg.admin.totp_enabled = current_cfg.admin.totp_enabled;
    next_cfg.admin.totp_secret = current_cfg.admin.totp_secret.clone();
    next_cfg.admin.totp_last_step = current_cfg.admin.totp_last_step;
    next_cfg.admin.totp_recovery_hashes = current_cfg.admin.totp_recovery_hashes.clone();
    next_cfg.admin.passkey_enabled = current_cfg.admin.passkey_enabled;
    next_cfg.admin.passkeys = current_cfg.admin.passkeys.clone();
    next_cfg.proxy_auth_users = current_cfg.proxy_auth_users.clone();
    // VANE-M07 / VANE-H07 / VANE-M06：以下宿主执行与二进制更新边界字段仅允许通过本地 config.toml 修改
    next_cfg.admin.docker_socket = current_cfg.admin.docker_socket.clone();
    next_cfg.admin.allow_manual_update_upload = current_cfg.admin.allow_manual_update_upload;
    next_cfg.admin.update_signing_public_key = current_cfg.admin.update_signing_public_key.clone();
    next_cfg.admin.allow_cron_exec = current_cfg.admin.allow_cron_exec;

    // VANE-M03：修改管理面安全边界字段（含双向 password_login_enabled、secret_path、Origin/监听/用户名/TLS 路径）前强制二次验证
    let sensitive_admin_changed = next_cfg.admin.password_login_enabled != current_cfg.admin.password_login_enabled
        || next_cfg.admin.secret_path != current_cfg.admin.secret_path
        || next_cfg.admin.extra_allowed_origins != current_cfg.admin.extra_allowed_origins
        || next_cfg.admin.canonical_origin != current_cfg.admin.canonical_origin
        || next_cfg.admin.listen_lan != current_cfg.admin.listen_lan
        || next_cfg.admin.username != current_cfg.admin.username
        || next_cfg.admin.tls_cert_path != current_cfg.admin.tls_cert_path
        || next_cfg.admin.tls_key_path != current_cfg.admin.tls_key_path;
    if sensitive_admin_changed {
        let require_mfa = crate::security::auth::admin_has_mfa_enabled(&current_cfg.admin);
        if let Err(err) = consume_reauth_token_checked(
            &state,
            &cur_tok,
            &headers,
            body_reauth_token.as_deref(),
            peer.ip(),
            require_mfa,
        ) {
            return reauth_error_response(
                err,
                require_mfa,
                "修改管理员认证、入口路径、受信 Origin 或监听/证书等敏感安全设置前需要完成二次身份验证",
            );
        }
    }

    if let Err(e) = state.vault.merge_secrets_many(&mut next_cfg, &current_cfg, &renames) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response();
    }

    // module_reauth 由专属接口 PUT /api/modules/reauth 受控管理（关闭必须二次验证），普通设置保存一律沿用受保护状态
    // 同时兼容旧版调用方通过 PUT /api/settings 将 web_terminal.require_reauth 从 false 置为 true
    let legacy_enable_pty =
        !current_cfg.module_requires_reauth("web_terminal") && next_cfg.web_terminal.require_reauth;
    next_cfg.module_reauth = current_cfg.module_reauth.clone();
    if legacy_enable_pty {
        next_cfg.module_reauth.web_terminal = true;
    }
    next_cfg.web_terminal.require_reauth = next_cfg.module_reauth.web_terminal;

    // 1) 若某子模块当前处于禁用状态，后台静默保留其原有专属配置，禁止绕过前端修改
    if !current_cfg.modules.reverse_proxy {
        next_cfg.reverse_proxy = current_cfg.reverse_proxy.clone();
    }
    if !current_cfg.modules.port_forward {
        next_cfg.port_forwards = current_cfg.port_forwards.clone();
    }
    if !current_cfg.modules.ddns {
        next_cfg.ddns = current_cfg.ddns.clone();
    }
    if !current_cfg.modules.acme {
        next_cfg.acme = current_cfg.acme.clone();
    }
    if !current_cfg.modules.stun {
        next_cfg.stun = current_cfg.stun.clone();
    }
    if !current_cfg.modules.cron {
        next_cfg.cron = current_cfg.cron.clone();
    }
    if !current_cfg.modules.web_terminal {
        next_cfg.web_terminal.shell = current_cfg.web_terminal.shell.clone();
        next_cfg.web_terminal.default_cwd = current_cfg.web_terminal.default_cwd.clone();
        next_cfg.web_terminal.idle_timeout_secs = current_cfg.web_terminal.idle_timeout_secs;
        next_cfg.web_terminal.max_sessions = current_cfg.web_terminal.max_sessions;
    }
    if !current_cfg.modules.docker {
        next_cfg.docker = current_cfg.docker.clone();
    }
    // 共用 DNS 服务商账号池由动态 DDNS 与 ACME 证书共同依赖；当两者均禁用时静默保留原配置
    if !current_cfg.modules.ddns && !current_cfg.modules.acme {
        next_cfg.dns_providers = current_cfg.dns_providers.clone();
    }

    // 2) 若修改了已开启二次验证的子模块规则/参数，或停用受保护子模块，校验当前会话已解锁对应子模块
    let mut changed_modules: Vec<&'static str> = Vec::new();
    for m in crate::config::MODULE_NAMES {
        if current_cfg.modules.get(m) == Some(true) && next_cfg.modules.get(m) == Some(false) {
            changed_modules.push(m);
        }
    }
    if next_cfg.reverse_proxy != current_cfg.reverse_proxy && !changed_modules.contains(&"reverse_proxy") {
        changed_modules.push("reverse_proxy");
    }
    if next_cfg.port_forwards != current_cfg.port_forwards && !changed_modules.contains(&"port_forward") {
        changed_modules.push("port_forward");
    }
    if next_cfg.ddns != current_cfg.ddns && !changed_modules.contains(&"ddns") {
        changed_modules.push("ddns");
    }
    if next_cfg.acme != current_cfg.acme && !changed_modules.contains(&"acme") {
        changed_modules.push("acme");
    }
    // VANE-M03：dns_providers 变动必须同步纳入已启用的 ddns / acme 模块二次认证范围
    if next_cfg.dns_providers != current_cfg.dns_providers {
        if current_cfg.modules.ddns && !changed_modules.contains(&"ddns") {
            changed_modules.push("ddns");
        }
        if current_cfg.modules.acme && !changed_modules.contains(&"acme") {
            changed_modules.push("acme");
        }
    }
    if next_cfg.stun != current_cfg.stun && !changed_modules.contains(&"stun") {
        changed_modules.push("stun");
    }
    if next_cfg.cron != current_cfg.cron && !changed_modules.contains(&"cron") {
        changed_modules.push("cron");
    }
    if next_cfg.docker != current_cfg.docker && !changed_modules.contains(&"docker") {
        changed_modules.push("docker");
    }
    if (next_cfg.web_terminal.shell != current_cfg.web_terminal.shell
        || next_cfg.web_terminal.default_cwd != current_cfg.web_terminal.default_cwd
        || next_cfg.web_terminal.idle_timeout_secs != current_cfg.web_terminal.idle_timeout_secs
        || next_cfg.web_terminal.max_sessions != current_cfg.web_terminal.max_sessions)
        && !changed_modules.contains(&"web_terminal")
    {
        changed_modules.push("web_terminal");
    }
    for m in changed_modules {
        if current_cfg.module_requires_reauth(m) {
            let unlocked = state
                .auth
                .lock()
                .map(|a| a.sessions.is_module_unlocked(&cur_tok, m))
                .unwrap_or(false);
            if !unlocked {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "error": "MODULE_REAUTH_REQUIRED",
                        "code": "MODULE_REAUTH_REQUIRED",
                        "module": m,
                        "message": "修改该受保护子模块的配置前需要完成二次身份验证"
                    })),
                )
                    .into_response();
            }
        }
    }

    if let Err(e) = next_cfg.validate_with_vault_and_listeners(Some(&state.vault), &state.live_admin_listeners) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response();
    }
    if let Err(e) = save_config(&state.config_path, &next_cfg) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response();
    }
    // 对新启用二次验证或刚被停用的模块立即锁定所有活跃会话中的解锁状态
    let mut revoke_pty = false;
    if let Ok(mut auth) = state.auth.lock() {
        for m in crate::config::MODULE_NAMES {
            let newly_protected = !current_cfg.module_requires_reauth(m) && next_cfg.module_requires_reauth(m);
            let newly_disabled = current_cfg.modules.get(m) == Some(true) && next_cfg.modules.get(m) == Some(false);
            if newly_protected || newly_disabled {
                auth.sessions.lock_module_all_sessions(m);
                if matches!(*m, "web_terminal" | "docker") {
                    revoke_pty = true;
                }
            }
        }
    }
    let security_identity_changed = next_cfg.admin.username != current_cfg.admin.username
        || next_cfg.admin.secret_path != current_cfg.admin.secret_path
        || (current_cfg.admin.passkey_enabled && !next_cfg.admin.passkey_enabled);
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

    // VANE-M04：务必先原子更新 state.config，再触发 apply_runtime_settings 与 pty_mgr.notify_revoke()
    state.config.store(Arc::new(next_cfg.clone()));
    state.apply_runtime_settings(&next_cfg).await;
    if revoke_pty {
        state.pty_mgr.notify_revoke();
    }
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

#[derive(Deserialize)]
struct ModulesUpdateReq {
    #[serde(flatten)]
    modules: ModulesConfig,
    #[serde(default)]
    reauth_token: String,
}

async fn api_put_modules(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<ModulesUpdateReq>,
) -> Response {
    let cur_tok = match require_full_admin(&state, &headers) {
        Ok(tok) => tok,
        Err(resp) => return *resp,
    };
    let modules = req.modules;
    let _cfg_guard = state.config_lock.lock().await;
    let mut next_cfg = (**state.config.load()).clone();
    let prev_modules = next_cfg.modules.clone();

    // 停用已开启二次验证保护的子模块前，需当前会话已解锁该模块或提供一次性 reauth_token
    let mut locked_to_disable: Vec<&'static str> = Vec::new();
    for m in crate::config::MODULE_NAMES {
        if prev_modules.get(m) == Some(true)
            && modules.get(m) == Some(false)
            && next_cfg.module_requires_reauth(m)
        {
            let unlocked = state
                .auth
                .lock()
                .map(|a| a.sessions.is_module_unlocked(&cur_tok, m))
                .unwrap_or(false);
            if !unlocked {
                locked_to_disable.push(m);
            }
        }
    }
    if !locked_to_disable.is_empty()
        && consume_reauth_token_checked(&state, &cur_tok, &headers, Some(&req.reauth_token), peer.ip(), false).is_err()
    {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "MODULE_REAUTH_REQUIRED",
                "code": "MODULE_REAUTH_REQUIRED",
                "module": locked_to_disable[0],
                "message": "停用已开启二次验证保护的子模块前需要完成二次身份验证"
            })),
        )
            .into_response();
    }

    next_cfg.modules = modules.clone();
    if let Err(e) = save_config(&state.config_path, &next_cfg) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response();
    }
    // VANE-M04 / VANE-M05：先原子发布新配置与会话锁状态，再触发 PTY 撤销、反代门禁撤权、Cron 取消与防火墙清理
    let unlocked_modules = if let Ok(mut auth) = state.auth.lock() {
        for m in crate::config::MODULE_NAMES {
            if prev_modules.get(m) == Some(true) && modules.get(m) == Some(false) {
                auth.sessions.lock_module_all_sessions(m);
            }
        }
        auth.sessions.unlocked_modules_remaining(&cur_tok)
    } else {
        std::collections::BTreeMap::new()
    };
    state.config.store(Arc::new(next_cfg));
    if prev_modules.reverse_proxy && !modules.reverse_proxy {
        state.proxy_gate.revoke_all();
        let _ = state.firewall.remove_module_rules("reverse_proxy").await;
    }
    if prev_modules.port_forward && !modules.port_forward {
        let _ = state.firewall.remove_module_rules("port_forward").await;
    }
    if prev_modules.ddns && !modules.ddns {
        let _ = state.firewall.remove_module_rules("ddns").await;
    }
    if prev_modules.cron && !modules.cron {
        state.cron_status.cancel_all();
    }
    if (prev_modules.web_terminal && !modules.web_terminal) || (prev_modules.docker && !modules.docker) {
        state.pty_mgr.notify_revoke();
    }
    state.reload_notify.notify_one();
    logger::log(Level::Info, "modules", &format!("子功能模块开关已更新: {:?}", modules));
    Json(serde_json::json!({ "modules": modules, "unlocked_modules": unlocked_modules })).into_response()
}

#[derive(Deserialize)]
struct ModuleReauthToggleReq {
    module: String,
    require_reauth: bool,
    #[serde(default)]
    reauth_token: String,
}

async fn api_put_module_reauth(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<ModuleReauthToggleReq>,
) -> Response {
    let session_token = match require_full_admin(&state, &headers) {
        Ok(tok) => tok,
        Err(resp) => return *resp,
    };
    let module = req.module.trim();
    if !crate::config::MODULE_NAMES.contains(&module) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "不支持的子功能模块名称" })),
        )
            .into_response();
    }

    let _cfg_guard = state.config_lock.lock().await;
    let mut next_cfg = (**state.config.load()).clone();
    if next_cfg.modules.get(module) != Some(true) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "MODULE_DISABLED",
                "message": "该子模块当前处于禁用状态，请先开启模块后再调整其二次验证保护"
            })),
        )
            .into_response();
    }
    let was_on = next_cfg.module_requires_reauth(module);

    // 关闭已启用的二次验证保护前，必须完成二次身份验证（若启用 MFA 则强制 MFA 验证）
    if was_on && !req.require_reauth {
        let require_mfa = crate::security::auth::admin_has_mfa_enabled(&next_cfg.admin);
        if let Err(err) = consume_reauth_token_checked(
            &state,
            &session_token,
            &headers,
            Some(&req.reauth_token),
            peer.ip(),
            require_mfa,
        ) {
            return reauth_error_response(err, require_mfa, "关闭子模块二次验证前需要完成二次身份验证");
        }
    }

    next_cfg.module_reauth.set(module, req.require_reauth);
    if module == "web_terminal" {
        next_cfg.web_terminal.require_reauth = req.require_reauth;
    }
    if let Err(e) = save_config(&state.config_path, &next_cfg) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response();
    }

    let unlocked_modules = if let Ok(mut auth) = state.auth.lock() {
        if req.require_reauth {
            auth.sessions.lock_module_all_sessions(module);
        }
        auth.sessions.unlocked_modules_remaining(&session_token)
    } else {
        std::collections::BTreeMap::new()
    };

    let reauth_snapshot = next_cfg.module_reauth.clone();
    state.config.store(Arc::new(next_cfg));
    if req.require_reauth && matches!(module, "web_terminal" | "docker") {
        state.pty_mgr.notify_revoke();
    }
    logger::log(
        Level::Info,
        "security",
        &format!("子模块 {} 二次验证保护已设为 {}", module, req.require_reauth),
    );
    Json(serde_json::json!({
        "module_reauth": reauth_snapshot,
        "unlocked_modules": unlocked_modules
    }))
    .into_response()
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
        return *resp;
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
    if let Err(e) = next_cfg.validate_with_vault_and_listeners(Some(&state.vault), &state.live_admin_listeners) {
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
        return *resp;
    }
    let cfg = state.config.load();
    if !cfg.modules.ddns {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "MODULE_DISABLED", "message": "DDNS 模块已禁用" })),
        )
            .into_response();
    }
    let Some(entry) = cfg.ddns.iter().find(|d| d.name == name) else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "DDNS 规则不存在" }))).into_response();
    };
    // VANE-M05：调用前二次核验实时 modules.ddns，并在同步完成后在 config_lock 下核验避免在途同步向已停用模块回写防火墙规则
    if !state.config.load().modules.ddns {
        let _ = state.firewall.remove_module_rules("ddns").await;
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "MODULE_DISABLED", "message": "DDNS 模块已禁用" })),
        )
            .into_response();
    }
    let sync_res = sync_ddns_entry(entry, &cfg, &state.vault, &state.firewall, &state.ddns_status).await;
    {
        let _cfg_guard = state.config_lock.lock().await;
        let live_cfg = state.config.load();
        if !live_cfg.modules.ddns {
            let _ = state.firewall.remove_module_rules("ddns").await;
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "MODULE_DISABLED",
                    "message": "DDNS 模块已在同步期间停用，已立即撤销残留防火墙放行规则"
                })),
            )
                .into_response();
        }
        let rule_still_enabled = live_cfg.ddns.iter().any(|d| d.name == name && d.enabled);
        if !rule_still_enabled {
            let _ = state.firewall.remove_rule("ddns", &name).await;
        }
    }
    match sync_res {
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
        return *resp;
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
        return *resp;
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
        return *resp;
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
        return *resp;
    }
    let cfg = state.config.load_full();
    if !cfg.modules.cron {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "MODULE_DISABLED", "message": "计划任务模块已禁用" })),
        )
            .into_response();
    }
    let Some(job) = cfg.cron.iter().find(|c| c.name == name).cloned() else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "Cron 任务不存在" }))).into_response();
    };
    if !job.enabled {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "CRON_JOB_DISABLED",
                "message": "该计划任务当前处于禁用状态，拒绝执行"
            })),
        )
            .into_response();
    }
    if matches!(job.action, crate::config::CronAction::Exec { .. }) && !cfg.admin.allow_cron_exec {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "CRON_EXEC_DISABLED",
                "message": "宿主机命令计划任务 (Exec) 默认关闭，请在 config.toml 中设置 admin.allow_cron_exec = true 后重启启用"
            })),
        )
            .into_response();
    }
    let ctx = state.build_cron_context(cfg);
    let cancel = state.cron_status.cancel_token();
    match crate::daemon::cron::execute_cron_job_cancellable(&job, Some(&ctx), Some(cancel)).await {
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
        return *resp;
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

async fn api_inbox_list(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return *resp;
    }
    let (items, unread_count, storage_bytes) = state.inbox.snapshot();
    Json(serde_json::json!({
        "items": items,
        "unread_count": unread_count,
        "capacity": crate::daemon::inbox::MAX_INBOX_ITEMS,
        "storage_bytes": storage_bytes,
        "max_storage_bytes": crate::daemon::inbox::MAX_INBOX_BYTES,
    }))
    .into_response()
}

#[derive(Deserialize, Default)]
struct InboxReadReq {
    #[serde(default)]
    id: Option<u64>,
}

async fn api_inbox_mark_read(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return *resp;
    }
    let req: InboxReadReq = if raw_body.is_empty() {
        InboxReadReq::default()
    } else {
        match serde_json::from_slice(&raw_body) {
            Ok(v) => v,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "请求格式非法" })),
                )
                    .into_response()
            }
        }
    };
    let unread_count = state.inbox.mark_read(req.id);
    Json(serde_json::json!({ "ok": true, "unread_count": unread_count })).into_response()
}

async fn api_inbox_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<u64>,
) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return *resp;
    }
    let (removed, unread_count) = state.inbox.delete(id);
    Json(serde_json::json!({ "ok": true, "removed": removed, "unread_count": unread_count })).into_response()
}

async fn api_inbox_clear(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return *resp;
    }
    state.inbox.clear();
    Json(serde_json::json!({ "ok": true, "unread_count": 0 })).into_response()
}

fn update_signing_key_status(cfg: &Config) -> (bool, &'static str, String) {
    match crate::daemon::updater::resolve_effective_signing_public_key(&cfg.admin.update_signing_public_key) {
        Ok(Some(resolved)) => (true, resolved.source.as_str(), resolved.fingerprint),
        Ok(None) | Err(_) => (false, crate::daemon::updater::UpdateSigningKeySource::None.as_str(), String::new()),
    }
}

async fn api_update_status(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return *resp;
    }
    let cfg = state.config.load();
    let snap = state.updater.snapshot();
    let (key_ready, key_source, key_fingerprint) = update_signing_key_status(&cfg);
    Json(serde_json::json!({
        "status": snap,
        "config": cfg.update,
        "allow_manual_update_upload": cfg.admin.allow_manual_update_upload,
        "update_signing_key_configured": key_ready,
        "update_signing_key_source": key_source,
        "update_signing_key_fingerprint": key_fingerprint,
        "manual_upload_ready": cfg.admin.allow_manual_update_upload && key_ready,
        "limits": {
            "max_upload_mb": crate::daemon::updater::MAX_UPLOAD_ARCHIVE_BYTES / (1024 * 1024),
            "max_uncompressed_mb": crate::daemon::updater::MAX_UNCOMPRESSED_TAR_BYTES / (1024 * 1024),
            "max_entries": crate::daemon::updater::MAX_TAR_ENTRIES,
        }
    }))
    .into_response()
}

async fn api_update_check(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return *resp;
    }
    let cfg = state.config.load_full();
    let res = crate::daemon::updater::check_github_release(&cfg.update.repo).await;
    let err_msg = res.as_ref().err().cloned();
    let info_opt = res.as_ref().ok().cloned();
    let should_notify = state.updater.record_check_result(res);
    if should_notify {
        if let Some(ref rel) = info_opt {
            let title = format!("发现 Vane 新版本 {}", rel.tag_name);
            let msg = format!(
                "当前运行版本 v{}，GitHub Release 已发布 {}（{}）。请前往「系统设置 → 系统更新」查看更新说明并手动上传更新包。",
                crate::daemon::updater::current_version(),
                rel.tag_name,
                rel.html_url
            );
            broadcast_event(&cfg, &state.vault, "system_update", &title, &msg, "info").await;
        }
    }
    let snap = state.updater.snapshot();
    let (key_ready, key_source, key_fingerprint) = update_signing_key_status(&cfg);
    if let Some(err) = err_msg {
        return (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({
                "error": err,
                "status": snap,
                "config": cfg.update,
                "allow_manual_update_upload": cfg.admin.allow_manual_update_upload,
                "update_signing_key_configured": key_ready,
                "update_signing_key_source": key_source,
                "update_signing_key_fingerprint": key_fingerprint,
                "manual_upload_ready": cfg.admin.allow_manual_update_upload && key_ready,
            })),
        )
            .into_response();
    }
    Json(serde_json::json!({
        "status": snap,
        "config": cfg.update,
        "allow_manual_update_upload": cfg.admin.allow_manual_update_upload,
        "update_signing_key_configured": key_ready,
        "update_signing_key_source": key_source,
        "update_signing_key_fingerprint": key_fingerprint,
        "manual_upload_ready": cfg.admin.allow_manual_update_upload && key_ready,
    }))
    .into_response()
}

fn update_worker_semaphore(updater: &Arc<crate::daemon::updater::UpdateRuntime>) -> Arc<tokio::sync::Semaphore> {
    use std::sync::{OnceLock, Weak};
    static SEMS: OnceLock<Mutex<HashMap<usize, Weak<tokio::sync::Semaphore>>>> = OnceLock::new();
    let map_lock = SEMS.get_or_init(|| Mutex::new(HashMap::new()));
    let key = Arc::as_ptr(updater) as usize;
    let Ok(mut map) = map_lock.lock() else {
        return Arc::new(tokio::sync::Semaphore::new(1));
    };
    map.retain(|_, w| w.strong_count() > 0);
    if let Some(existing) = map.get(&key).and_then(Weak::upgrade) {
        return existing;
    }
    let sem = Arc::new(tokio::sync::Semaphore::new(1));
    map.insert(key, Arc::downgrade(&sem));
    sem
}

async fn api_update_upload(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    mut body: Body,
) -> Response {
    use http_body_util::BodyExt;
    use tokio::io::AsyncWriteExt;

    let session_token = match require_full_admin(&state, &headers) {
        Ok(tok) => tok,
        Err(resp) => return *resp,
    };
    let cfg = state.config.load_full();
    // VANE-H07：允许仅在存在可信 Ed25519 公钥（config.toml 自定义覆盖 > 二进制内置官方公钥）且未显式禁用时上传
    if !cfg.admin.allow_manual_update_upload {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "MANUAL_UPDATE_DISABLED",
                "code": "MANUAL_UPDATE_DISABLED",
                "message": "手动二进制上传更新已在 config.toml 中关闭，如需启用请将 admin.allow_manual_update_upload 设为 true（或删除该项）并重启 Vane"
            })),
        )
            .into_response();
    }
    let resolved_signing_key = match crate::daemon::updater::resolve_effective_signing_public_key(
        &cfg.admin.update_signing_public_key,
    ) {
        Ok(Some(k)) => k,
        Ok(None) => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "MANUAL_UPDATE_SIGNING_KEY_MISSING",
                    "code": "MANUAL_UPDATE_SIGNING_KEY_MISSING",
                    "message": "当前构建未内置官方 Ed25519 发布公钥且 config.toml 未配置 admin.update_signing_public_key，已拒绝未签名更新上传"
                })),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("安全拦截：{}，拒绝未签名更新包", e) })),
            )
                .into_response();
        }
    };
    let ban_key = BanKey::from_peer(peer.ip());
    if state.fail2ban.is_key_banned(ban_key) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({ "error": "IP_BANNED", "message": "认证失败次数过多，该网络已被临时封禁" })),
        )
            .into_response();
    }

    // VANE-H05 / VANE-H07：强制二次身份验证（若启用了 TOTP/Passkey 则必须通过 MFA 强因子验证）
    let require_mfa = crate::security::auth::admin_has_mfa_enabled(&cfg.admin);
    if let Err(err) = consume_reauth_token_checked(&state, &session_token, &headers, None, peer.ip(), require_mfa) {
        return reauth_error_response(err, require_mfa, "上传并应用系统更新前需要完成二次身份验证");
    }

    let Ok(_apply_guard) = state.updater.apply_lock.try_lock() else {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": "已有系统更新任务正在进行，请稍候" })),
        )
            .into_response();
    };
    let worker_sem = update_worker_semaphore(&state.updater);
    let Ok(worker_permit) = worker_sem.try_acquire_owned() else {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": "已有系统更新后台验证线程正在运行，请稍候" })),
        )
            .into_response();
    };

    if let Some(cl) = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
    {
        if cl > crate::daemon::updater::MAX_UPLOAD_ARCHIVE_BYTES {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(serde_json::json!({
                    "error": format!(
                        "上传压缩包超过 {} MiB 限制",
                        crate::daemon::updater::MAX_UPLOAD_ARCHIVE_BYTES / (1024 * 1024)
                    )
                })),
            )
                .into_response();
        }
    }

    let filename_hint = headers
        .get("x-vane-filename")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.len() <= 160)
        .map(str::to_string);

    let expected_signature_b64 = headers
        .get("x-vane-update-signature")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| {
            q.get("signature")
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        });

    // 在落盘前先行校验请求签名格式，避免无效未签名上传浪费路由器闪存 I/O（信任公钥已在入口完成解析）
    match expected_signature_b64.as_deref() {
        Some(sig) => {
            if let Err(e) = crate::daemon::updater::parse_ed25519_signature(sig) {
                return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response();
            }
        }
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "安全拦截：缺少独立 Ed25519 签名（请通过 x-vane-update-signature 请求头或 signature 参数提供），拒绝未签名更新包"
                })),
            )
                .into_response();
        }
    }

    let expected_sha_raw = if let Some(b64) = headers
        .get("x-vane-expected-sha256-b64")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        match B64.decode(b64.as_bytes()).ok().and_then(|b| String::from_utf8(b).ok()) {
            Some(s) => s,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "预期 SHA-256 请求头编码非法" })),
                )
                    .into_response()
            }
        }
    } else if let Some(h) = headers
        .get("x-vane-expected-sha256")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        h.to_string()
    } else {
        q.get("expected_sha256")
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    };

    let expected_sha256 = match crate::daemon::updater::parse_expected_sha256(
        &expected_sha_raw,
        filename_hint.as_deref(),
    ) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response(),
    };

    let sandbox = match crate::daemon::updater::TempSandboxDir::create("vane-upload") {
        Ok(s) => s,
        Err(e) => {
            return (StatusCode::INSUFFICIENT_STORAGE, Json(serde_json::json!({ "error": e }))).into_response()
        }
    };
    let archive_path = sandbox.path().join("upload.tar.gz");

    // 流式直写临时目录并边写边算 SHA-256，绝不将整个压缩包缓存在路由器内存中
    let mut out_file = match tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&archive_path)
        .await
    {
        Ok(f) => f,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("创建临时上传文件失败: {e}") })),
            )
                .into_response()
        }
    };

    let mut total_bytes = 0u64;
    let mut hasher = ring::digest::Context::new(&ring::digest::SHA256);
    while let Some(frame_res) = body.frame().await {
        let frame = match frame_res {
            Ok(f) => f,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": format!("接收上传数据流失败: {e}") })),
                )
                    .into_response()
            }
        };
        if let Ok(chunk) = frame.into_data() {
            if chunk.is_empty() {
                continue;
            }
            total_bytes = total_bytes.saturating_add(chunk.len() as u64);
            if total_bytes > crate::daemon::updater::MAX_UPLOAD_ARCHIVE_BYTES {
                return (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    Json(serde_json::json!({
                        "error": format!(
                            "上传压缩包超过 {} MiB 安全上限",
                            crate::daemon::updater::MAX_UPLOAD_ARCHIVE_BYTES / (1024 * 1024)
                        )
                    })),
                )
                    .into_response();
            }
            hasher.update(&chunk);
            if let Err(e) = out_file.write_all(&chunk).await {
                return (
                    StatusCode::INSUFFICIENT_STORAGE,
                    Json(serde_json::json!({ "error": format!("写入临时目录失败（磁盘可能已满）: {e}") })),
                )
                    .into_response();
            }
        }
    }
    if total_bytes == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "上传文件为空，请选择有效的 .tar.gz 发布压缩包" })),
        )
            .into_response();
    }
    if let Err(e) = out_file.flush().await.and(out_file.sync_all().await) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("同步临时上传文件失败: {e}") })),
        )
            .into_response();
    }
    drop(out_file);

    let archive_sha256 = crate::daemon::updater::hex_encode(hasher.finish().as_ref());
    let target_exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("无法定位当前运行程序路径: {e}") })),
            )
                .into_response()
        }
    };
    let config_path = state.config_path.clone();
    let signing_public_key = resolved_signing_key.public_key_hex;

    // VANE-L11：使用受并发上限 1 保护的独立 OS 线程 + oneshot 执行耗时更新校验，避免阻塞全局 Tokio blocking 线程池
    let (tx, rx) = tokio::sync::oneshot::channel();
    let spawn_res = std::thread::Builder::new()
        .name("vane-update-worker".into())
        .spawn(move || {
            let _worker_permit = worker_permit;
            let _sandbox_guard = sandbox;
            let res = crate::daemon::updater::verify_and_install_uploaded_archive_signed(
                &_sandbox_guard,
                &archive_path,
                &archive_sha256,
                expected_sha256.as_deref(),
                expected_signature_b64.as_deref(),
                &signing_public_key,
                &config_path,
                &target_exe,
            );
            let _ = tx.send(res);
        });
    if let Err(e) = spawn_res {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("启动更新验证工作线程失败: {e}") })),
        )
            .into_response();
    }
    let result = rx.await;

    match result {
        Ok(Ok(applied)) => {
            let msg = format!(
                "已通过 Ed25519 验签与安全沙箱校验并原子替换主程序：v{} → v{} ({}/{})，旧版已备份至 {}，重启服务后生效。",
                applied.previous_version,
                applied.new_version,
                applied.os,
                applied.arch,
                applied.backup_path
            );
            logger::log(Level::Info, "update", &msg);
            state.inbox.push(
                "system_update",
                "info",
                &format!("系统程序已更新至 v{}", applied.new_version),
                &msg,
                Some("settings/update"),
            );
            Json(serde_json::json!({
                "ok": true,
                "result": applied,
            }))
            .into_response()
        }
        Ok(Err(err)) => {
            logger::log(Level::Warn, "update", &format!("手动更新包校验未通过: {}", err));
            (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": err }))).into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "更新沙箱执行任务异常中止" })),
        )
            .into_response(),
    }
}

async fn api_docker_containers(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return *resp;
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
        return *resp;
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
        return *resp;
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
        return *resp;
    }
    let cfg = state.config.load();
    match prune_dangling_images(&cfg.admin.docker_socket).await {
        Ok(res) => Json(serde_json::json!({ "ok": true, "result": res })).into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, Json(serde_json::json!({ "error": e }))).into_response(),
    }
}

async fn api_list_bans(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return *resp;
    }
    let all_bans = collect_all_active_bans(&state);
    let proxy_gate_bans = state.proxy_gate_fail2ban.list_all_bans();
    Json(serde_json::json!({
        "bans": all_bans,
        "proxy_gate_bans": proxy_gate_bans,
    }))
    .into_response()
}

async fn api_unban_ip(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(ip): AxumPath<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return *resp;
    }
    let scope_opt = q
        .get("scope")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());
    let (removed_admin, removed_proxy) = match scope_opt {
        Some("admin") => (state.fail2ban.unban(&ip), false),
        Some(host) => (false, state.proxy_gate_fail2ban.unban_scope(host, &ip)),
        None => (
            state.fail2ban.unban(&ip),
            state.proxy_gate_fail2ban.unban_cidr_all_scopes(&ip),
        ),
    };
    let still_banned_anywhere = BanKey::parse_cidr_or_ip(&ip).is_some_and(|k| {
        state.fail2ban.is_key_banned(k) || state.proxy_gate_fail2ban.is_key_banned_any_scope(k)
    });
    let fw_removed = if still_banned_anywhere {
        false
    } else {
        state.firewall.unban_source_cidr(&ip).await.unwrap_or(false)
    };
    Json(serde_json::json!({
        "unbanned": removed_admin || removed_proxy || fw_removed,
        "admin_unbanned": removed_admin,
        "proxy_gate_unbanned": removed_proxy,
        "firewall_unbanned": fw_removed,
    }))
    .into_response()
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
        return *resp;
    }
    match state.firewall.trigger_lockdown_detailed(req.enable).await {
        Ok(report) => {
            // VANE-H08：触发编排器立即停止或恢复用户态 WAN 监听（reverse_proxy / port_forward）
            state.reload_notify.notify_one();
            Json(serde_json::json!({
                "lockdown": report.active,
                "active": report.active,
                "kernel_enforced": report.kernel_enforced,
                "conntrack_flushed": report.conntrack_flushed,
                "warnings": report.warnings,
            }))
            .into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response(),
    }
}

#[derive(Deserialize)]
struct BackupExportReq {
    password: String,
    #[serde(default)]
    reauth_token: String,
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
    // VANE-L05：统一经 read_admin_cert_pair 读取代际或兼容路径管理证书对，拒绝符号链接并验证权限
    if let Some((crt, key)) = crate::net::tls_resolver::read_admin_cert_pair(&data_dir.join("certs"))? {
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
                // VANE-L03：ACME 账户文件始终密文落盘，强制使用 vault.open 校验 AEAD 完整性，禁止明文回退
                let plain = vault.open(&format!("acme.account.{id}"), encoded.trim())?;
                files.insert(format!("acme-accounts/{id}.json"), plain.expose().to_vec());
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
        let Ok(safe) = crate::daemon::acme_store::try_safe_name(&a.domain) else {
            continue;
        };
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

struct PreparedAdminTls {
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    certified_key: Arc<rustls::sign::CertifiedKey>,
}

struct PreparedAcmeCert {
    target_dir: PathBuf,
    target_domain: String,
    bundle: crate::daemon::acme_store::Bundle,
    verified_key: Arc<rustls::sign::CertifiedKey>,
    allowed_domains: Vec<String>,
}

struct PreparedBackupRestore {
    admin_tls: Option<PreparedAdminTls>,
    acme_accounts: Vec<(String, String)>,
    acme_challenges: Vec<(String, Vec<u8>)>,
    acme_certs: Vec<PreparedAcmeCert>,
}

/// VANE-M13：在触碰任何磁盘文件或修改内存态（admin_cert / cert_table）前，全量预校验所有备份条目
fn prepare_backup_files_for_restore(
    cfg: &Config,
    files: &BTreeMap<String, Vec<u8>>,
    vault: &Vault,
) -> Result<PreparedBackupRestore, String> {
    for key in files.keys() {
        if !crate::security::vault::validate_backup_file_key(key) {
            return Err(format!("备份包含非法文件路径键: {}", key));
        }
    }

    let admin_tls = match (files.get("certs/admin.crt"), files.get("certs/admin.key")) {
        (Some(crt), Some(key)) => {
            let ck = crate::net::tls_resolver::certified_key_from_pem(crt, key)?;
            Some(PreparedAdminTls {
                cert_pem: crt.clone(),
                key_pem: key.clone(),
                certified_key: ck,
            })
        }
        (None, None) => None,
        _ => return Err("备份内管理证书 (certs/admin.crt) 与私钥 (certs/admin.key) 不完整".into()),
    };

    let mut acme_accounts = Vec::new();
    let mut acme_challenges = Vec::new();
    let mut acme_certs = Vec::new();
    let now = logger::unix_now();

    for (key, raw) in files {
        if key == "certs/admin.crt" || key == "certs/admin.key" {
            continue;
        }
        if let Some(id_file) = key.strip_prefix("acme-accounts/") {
            let Some(id) = id_file.strip_suffix(".json") else {
                return Err(format!("备份内 ACME 账户文件名非法: {}", id_file));
            };
            if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(format!("备份内 ACME 账户 ID 非法: {}", id));
            }
            if serde_json::from_slice::<serde_json::Value>(raw).is_err() {
                return Err(format!("备份内 ACME 账户 {} JSON 非法", id));
            }
            let sealed = vault.seal(&format!("acme.account.{id}"), raw)?;
            acme_accounts.push((id_file.to_string(), sealed));
        } else if let Some(chal_file) = key.strip_prefix("acme-challenges/") {
            if serde_json::from_slice::<serde_json::Value>(raw).is_err() {
                return Err(format!("备份内挑战日志 {} JSON 非法", chal_file));
            }
            acme_challenges.push((chal_file.to_string(), raw.clone()));
        } else if let Some(rest) = key.strip_prefix("acme-certs/") {
            let Some(safe_dir) = rest.strip_suffix("/bundle.json") else {
                return Err(format!("备份内 ACME 证书路径非法: {}", key));
            };
            let normalized = crate::daemon::acme_store::try_safe_name(safe_dir)?;
            if normalized != safe_dir {
                return Err(format!("备份内 ACME 证书目录名未规范化: {}", safe_dir));
            }
            let bundle: crate::daemon::acme_store::Bundle =
                serde_json::from_slice(raw).map_err(|_| format!("备份内证书包 {} 格式非法", safe_dir))?;
            let verified = crate::daemon::acme_store::verify(&bundle)?;
            if verified.expires <= now || verified.issued > now + 300 {
                logger::log(Level::Warn, "backup", &format!("备份证书 {} 已过期或未生效，跳过恢复", safe_dir));
                continue;
            }
            if !cfg.modules.acme {
                logger::log(Level::Warn, "backup", &format!("恢复配置已禁用 ACME 模块，跳过备份证书 {}", safe_dir));
                continue;
            }
            let Some(matching_acme) = cfg.acme.iter().find(|a| {
                a.enabled
                    && crate::daemon::acme_store::try_safe_name(&a.domain)
                        .is_ok_and(|s| s == safe_dir)
            }) else {
                logger::log(
                    Level::Warn,
                    "backup",
                    &format!("备份证书 {} 未匹配任何已启用的 ACME 规则，跳过恢复防证书注入", safe_dir),
                );
                continue;
            };
            let configured: std::collections::BTreeSet<String> = std::iter::once(&matching_acme.domain)
                .chain(matching_acme.extra_domains.iter())
                .map(|d| d.to_ascii_lowercase())
                .collect();
            let allowed_domains: Vec<String> = bundle
                .domains
                .iter()
                .filter(|d| configured.contains(&d.to_ascii_lowercase()))
                .cloned()
                .collect();
            if allowed_domains.is_empty() {
                logger::log(
                    Level::Warn,
                    "backup",
                    &format!("备份证书 {} 域名列表与已配置 ACME 规则无交集，跳过恢复", safe_dir),
                );
                continue;
            }
            acme_certs.push(PreparedAcmeCert {
                target_dir: PathBuf::from(&matching_acme.cert_dir),
                target_domain: matching_acme.domain.clone(),
                bundle,
                verified_key: verified.key,
                allowed_domains,
            });
        }
    }

    Ok(PreparedBackupRestore {
        admin_tls,
        acme_accounts,
        acme_challenges,
        acme_certs,
    })
}

async fn write_prepared_backup_files_to_disk(
    data_dir: &std::path::Path,
    prepared: &PreparedBackupRestore,
) -> Result<(), String> {
    if let Some(ref tls) = prepared.admin_tls {
        let certs_dir = data_dir.join("certs");
        let crt_bytes = tls.cert_pem.clone();
        let key_bytes = tls.key_pem.clone();
        tokio::task::spawn_blocking(move || {
            crate::net::tls_resolver::save_admin_cert_pair_atomic(&certs_dir, &crt_bytes, &key_bytes)
        })
        .await
        .map_err(|_| "恢复管理证书任务失败")??;
    }

    for (id_file, sealed) in &prepared.acme_accounts {
        let dst = data_dir.join("acme-accounts").join(id_file);
        crate::daemon::acme_store::atomic(dst, sealed.as_bytes().to_vec()).await?;
    }
    for (chal_file, raw) in &prepared.acme_challenges {
        let dst = data_dir.join("acme-challenges").join(chal_file);
        crate::daemon::acme_store::atomic(dst, raw.clone()).await?;
    }
    for cert in &prepared.acme_certs {
        crate::daemon::acme_store::store(&cert.target_dir, &cert.target_domain, &cert.bundle).await?;
    }
    Ok(())
}

fn commit_prepared_backup_memory(
    cfg: &Config,
    prepared: PreparedBackupRestore,
    cert_table: &Arc<ArcSwap<CertTable>>,
    admin_cert: &Arc<ArcSwap<rustls::sign::CertifiedKey>>,
) -> serde_json::Value {
    let admin_tls = if let Some(tls) = prepared.admin_tls {
        admin_cert.store(tls.certified_key);
        true
    } else {
        false
    };
    let acme_accounts = prepared.acme_accounts.len();
    let acme_challenges = prepared.acme_challenges.len();
    let acme_certs = prepared.acme_certs.len();

    if !prepared.acme_certs.is_empty() {
        cert_table.rcu(|current| {
            let mut next = CertTable {
                exact: current.exact.clone(),
                wildcard: current.wildcard.clone(),
                fallback: current.fallback.clone(),
            };
            for cert in &prepared.acme_certs {
                for name in &cert.allowed_domains {
                    if let Some(suffix) = name.strip_prefix('*') {
                        next.wildcard.insert(suffix.to_ascii_lowercase(), cert.verified_key.clone());
                    } else {
                        next.exact.insert(name.to_ascii_lowercase(), cert.verified_key.clone());
                    }
                }
            }
            Arc::new(next)
        });
    }
    // VANE-M13：导入后始终按恢复后的配置裁剪 cert_table，清除残留或已禁用的域名证书
    crate::daemon::acme::prune_cert_table(cfg, cert_table);

    serde_json::json!({
        "admin_tls": admin_tls,
        "acme_accounts": acme_accounts,
        "acme_certs": acme_certs,
        "acme_challenges": acme_challenges,
    })
}

fn detect_backup_security_downgrades(current: &Config, restored: &Config) -> Vec<String> {
    let mut downgrades = Vec::new();
    if current.admin.totp_enabled && !restored.admin.totp_enabled {
        downgrades.push("disable_totp".to_string());
    }
    if (current.admin.passkey_enabled && !current.admin.passkeys.is_empty())
        && (!restored.admin.passkey_enabled || restored.admin.passkeys.is_empty())
    {
        downgrades.push("disable_passkey".to_string());
    }
    for m in crate::config::MODULE_NAMES {
        if current.module_requires_reauth(m) && !restored.module_requires_reauth(m) {
            downgrades.push(format!("disable_module_reauth:{m}"));
        }
    }
    if !current.modules.web_terminal && restored.modules.web_terminal {
        downgrades.push("enable_web_terminal".to_string());
    }
    if !current.admin.allow_cron_exec && restored.admin.allow_cron_exec {
        downgrades.push("enable_allow_cron_exec".to_string());
    }
    if !current.admin.allow_manual_update_upload && restored.admin.allow_manual_update_upload {
        downgrades.push("enable_allow_manual_update_upload".to_string());
    }
    if current.admin.update_signing_public_key.trim() != restored.admin.update_signing_public_key.trim() {
        downgrades.push("change_update_signing_public_key".to_string());
    }
    downgrades
}

async fn api_backup_export(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<BackupExportReq>,
) -> Response {
    let cur_tok = match require_full_admin(&state, &headers) {
        Ok(tok) => tok,
        Err(resp) => return *resp,
    };
    let cfg = state.config.load_full();
    // VANE-H05：加密备份导出包含全部 Vault 明文与证书私钥，必须通过二次认证（启用 MFA 时要求强因子）
    let require_mfa = crate::security::auth::admin_has_mfa_enabled(&cfg.admin);
    if let Err(err) = consume_reauth_token_checked(
        &state,
        &cur_tok,
        &headers,
        Some(&req.reauth_token),
        peer.ip(),
        require_mfa,
    ) {
        return reauth_error_response(err, require_mfa, "导出全量加密备份前需要完成二次身份验证");
    }
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
    #[serde(default)]
    reauth_token: String,
    #[serde(default)]
    allow_security_downgrade: bool,
}

async fn api_backup_import(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<BackupImportReq>,
) -> Response {
    let cur_tok = match require_full_admin(&state, &headers) {
        Ok(tok) => tok,
        Err(resp) => return *resp,
    };
    // VANE-H05：备份导入可覆盖全部认证与模块配置，强制二次认证（启用 MFA 时要求强因子）
    let cur_cfg_pre = state.config.load();
    let require_mfa = crate::security::auth::admin_has_mfa_enabled(&cur_cfg_pre.admin);
    if let Err(err) = consume_reauth_token_checked(
        &state,
        &cur_tok,
        &headers,
        Some(&req.reauth_token),
        peer.ip(),
        require_mfa,
    ) {
        return reauth_error_response(err, require_mfa, "导入加密备份前需要完成二次身份验证");
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
    if let Err(e) = restored_cfg.validate_with_vault_and_listeners(Some(&state.vault), &state.live_admin_listeners) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response();
    }

    // VANE-L02：拒绝仍处于强制改密态或使用默认初始密码 (admin321) 的备份，并兼容合法纯 Passkey 配置
    if restored_cfg.admin.must_change_password {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "BACKUP_DEFAULT_PASSWORD_REJECTED",
                "message": "拒绝导入仍处于强制初始改密状态 (must_change_password=true) 的备份"
            })),
        )
            .into_response();
    }
    let hash_trimmed = restored_cfg.admin.password_hash.trim();
    if hash_trimmed.is_empty() {
        if !restored_cfg.admin.is_passkey_only() {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "备份内管理员密码哈希为空且非纯通行密钥配置，拒绝导入以防锁死" })),
            )
                .into_response();
        }
    } else {
        let Some(ph) = PasswordHash::parse(hash_trimmed) else {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "备份内管理员密码哈希无效，拒绝导入以防锁死" })),
            )
                .into_response();
        };
        let Ok(is_default_pw) = state
            .hash_gate
            .run(move || ph.verify(crate::security::auth::DEFAULT_INITIAL_PASSWORD))
            .await
        else {
            return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({ "error": "繁忙" }))).into_response();
        };
        if is_default_pw {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "BACKUP_DEFAULT_PASSWORD_REJECTED",
                    "message": "拒绝导入仍使用默认初始密码 (admin321) 的备份"
                })),
            )
                .into_response();
        }
    }

    let _cfg_guard = state.config_lock.lock().await;
    let current_cfg = state.config.load_full();

    // VANE-H05：检测安全防护基线降级，未显式传入 allow_security_downgrade=true 时拒绝
    let downgrades = detect_backup_security_downgrades(&current_cfg, &restored_cfg);
    if !downgrades.is_empty() && !req.allow_security_downgrade {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "SECURITY_DOWNGRADE_CONFIRM_REQUIRED",
                "code": "SECURITY_DOWNGRADE_CONFIRM_REQUIRED",
                "downgrades": downgrades,
                "message": "导入该备份将降低当前安全防护基线（关闭双因素/模块保护或开启高危执行开关），请显式确认 allow_security_downgrade=true 后重试"
            })),
        )
            .into_response();
    }

    // VANE-M13：在触碰任何磁盘文件与内存态前，全量预校验所有备份文件条目
    let prepared = match prepare_backup_files_for_restore(&restored_cfg, &files, &state.vault) {
        Ok(p) => p,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response(),
    };

    let data_dir = state
        .config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."))
        .to_path_buf();

    // VANE-M13：先原子保存 config.toml，再写入已验证的备份文件；若落盘失败则回滚 config.toml 且不污染运行态
    if let Err(e) = save_config(&state.config_path, &restored_cfg) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))).into_response();
    }
    if let Err(e) = write_prepared_backup_files_to_disk(&data_dir, &prepared).await {
        let _ = save_config(&state.config_path, &current_cfg);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("恢复备份文件失败（已回滚配置）: {}", e) })),
        )
            .into_response();
    }

    let restored_summary =
        commit_prepared_backup_memory(&restored_cfg, prepared, &state.cert_table, &state.admin_cert);

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

    // VANE-L02：合法纯 Passkey 备份保持 FullAdmin 会话作用域，避免导入后锁死
    let ban_key = BanKey::from_peer(peer.ip());
    let ttl = Duration::from_secs(restored_cfg.admin.session_ttl_secs.clamp(300, 86_400));
    let scope = if restored_cfg.admin.is_passkey_only() && restored_cfg.admin.password_hash.trim().is_empty() {
        SessionScope::FullAdmin
    } else {
        match PasswordHash::parse(&restored_cfg.admin.password_hash) {
            Some(ph) => AuthEngine::resolve_session_scope(
                restored_cfg.admin.must_change_password,
                &ph.salt,
                &ph.hash,
                ph.iters,
            ),
            None => SessionScope::MustChangePassword,
        }
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
    // VANE-M04 / VANE-M05：先原子发布新配置，再触发 PTY 撤销、反代门禁撤权与计划任务取消
    state.config.store(Arc::new(restored_cfg.clone()));
    state.apply_runtime_settings(&restored_cfg).await;
    state.pty_mgr.notify_revoke();
    state.proxy_gate.revoke_all();
    state.cron_status.cancel_all();
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
        "passkey_enabled": restored_cfg.admin.passkey_enabled,
        "has_passkeys": !restored_cfg.admin.passkeys.is_empty(),
        "passkeys_count": restored_cfg.admin.passkeys.len(),
        "session_ttl_secs": restored_cfg.admin.session_ttl_secs,
        "language": restored_cfg.system.language,
        "modules": restored_cfg.modules,
        "module_reauth": restored_cfg.module_reauth,
        "unlocked_modules": {},
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
        return *resp;
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
    shell: String,
    #[serde(default)]
    reauth_password: String,
    #[serde(default)]
    reauth_token: String,
}

async fn api_pty_shells(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_full_admin(&state, &headers) {
        return *resp;
    }
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
    let available = crate::web::ws_pty::detect_available_shells();
    let default = crate::web::ws_pty::default_shell_id(&cfg.web_terminal.shell, &available);
    Json(serde_json::json!({
        "available": available,
        "default": default,
        "configured": cfg.web_terminal.shell,
    }))
    .into_response()
}

async fn api_pty_ticket(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Response {
    let session_token = match require_full_admin(&state, &headers) {
        Ok(tok) => tok,
        Err(resp) => return *resp,
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
    let is_container = target.starts_with("container:");
    if is_container && !cfg.modules.docker {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "MODULE_DISABLED", "message": "Docker 模块已关闭" })),
        )
            .into_response();
    }

    // VANE-M04：打开容器终端前，若 Docker 模块开启了二次验证，必须先解锁 docker 模块
    if is_container && cfg.module_requires_reauth("docker") {
        let docker_unlocked = state
            .auth
            .lock()
            .map(|a| a.sessions.is_module_unlocked(&session_token, "docker"))
            .unwrap_or(false);
        if !docker_unlocked {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "MODULE_REAUTH_REQUIRED",
                    "code": "MODULE_REAUTH_REQUIRED",
                    "module": "docker",
                    "message": "打开容器终端前需要完成 Docker 模块二次身份验证"
                })),
            )
                .into_response();
        }
    }

    // 若开启 Web 终端二次认证：支持已解锁的 web_terminal 会话、一次性 reauth_token 或兼容直传密码
    if cfg.module_requires_reauth("web_terminal") {
        let ban_key = BanKey::from_peer(peer.ip());
        if state.fail2ban.is_key_banned(ban_key) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "IP_BANNED", "message": "认证失败次数过多，该网络已被临时封禁" })),
            )
                .into_response();
        }
        let raw_reauth_tok = extract_reauth_token(&headers, Some(&req.reauth_token));
        if let Some(tok) = raw_reauth_tok {
            if state
                .reauth_tickets
                .consume_reauth_token_ex(&session_token, tok, peer.ip(), false)
                .is_err()
            {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "error": "REAUTH_REQUIRED",
                        "code": "REAUTH_REQUIRED",
                        "mfa_required": false,
                        "message": "二次验证凭据无效或已过期，请重新验证"
                    })),
                )
                    .into_response();
            }
            // VANE-M04：票据期二次验证通过后同步标记本会话 web_terminal 解锁态，确保随后建立的 WS 保持存活直至显式加锁/过期
            if let Ok(mut auth) = state.auth.lock() {
                auth.sessions.unlock_module(&session_token, "web_terminal");
            }
        } else if !req.reauth_password.is_empty() {
            if !cfg.admin.password_login_enabled {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "error": "REAUTH_REQUIRED",
                        "code": "REAUTH_REQUIRED",
                        "mfa_required": false,
                        "message": "请使用已启用的二次验证方式"
                    })),
                )
                    .into_response();
            }
            let pre_hash = cfg.admin.password_hash.clone();
            let Some(ph) = PasswordHash::parse(&pre_hash) else {
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
                if on_login_failed(&state, ban_key).await == crate::security::fail2ban::FailureOutcome::SaturatedFailClosed {
                    return saturated_fail_closed_response();
                }
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({ "error": "INVALID_REAUTH_PASSWORD", "message": "二次验证密码错误" })),
                )
                    .into_response();
            }
            // VANE-L01：HashGate 后重检配置状态
            let cfg_after = state.config.load();
            if !cfg_after.modules.web_terminal
                || !cfg_after.admin.password_login_enabled
                || cfg_after.admin.password_hash != pre_hash
            {
                return (
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({ "error": "AUTH_STATE_CHANGED", "message": "认证或模块状态已变更，请重试" })),
                )
                    .into_response();
            }
            if let Ok(mut auth) = state.auth.lock() {
                auth.sessions.unlock_module(&session_token, "web_terminal");
            }
        } else {
            let session_unlocked = state
                .auth
                .lock()
                .map(|a| a.sessions.is_module_unlocked(&session_token, "web_terminal"))
                .unwrap_or(false);
            if !session_unlocked {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "error": "MODULE_REAUTH_REQUIRED",
                        "code": "MODULE_REAUTH_REQUIRED",
                        "module": "web_terminal",
                        "message": "打开 Web 终端前需要完成二次身份验证"
                    })),
                )
                    .into_response();
            }
        }
    }

    let shell = match crate::web::ws_pty::validate_shell_choice(&req.shell) {
        Ok(s) => s,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response(),
    };
    match state.pty_mgr.issue_bound_ticket_with_shell(
        &session_token,
        &target,
        &shell,
        BanKey::from_peer(peer.ip()),
        cfg.web_terminal.max_sessions,
    ) {
        Ok(ticket) => Json(serde_json::json!({
            "ticket": ticket,
            "target": target,
            "shell": shell,
            "expires_in": 30
        }))
        .into_response(),
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
    if state.shutdown_flag.load(std::sync::atomic::Ordering::Acquire) {
        return (StatusCode::SERVICE_UNAVAILABLE, "服务正在关闭").into_response();
    }
    let cfg = state.config.load();
    if !cfg.modules.web_terminal {
        return (StatusCode::FORBIDDEN, "Web 终端已关闭").into_response();
    }
    let Some(ticket) = q.get("ticket") else {
        return (StatusCode::UNAUTHORIZED, "缺少终端 Ticket").into_response();
    };
    let target = q.get("target").cloned().unwrap_or_else(|| "host".into());
    let is_container = target.starts_with("container:");
    if is_container && !cfg.modules.docker {
        return (StatusCode::FORBIDDEN, "Docker 模块已关闭").into_response();
    }
    let shell_choice = q.get("shell").cloned().unwrap_or_else(|| "auto".into());
    let Some(session_digest) = state
        .pty_mgr
        .consume_bound_ticket_with_shell(ticket, &target, &shell_choice, BanKey::from_peer(peer.ip()))
    else {
        return (StatusCode::UNAUTHORIZED, "无效、已过期或目标不匹配的终端 Ticket").into_response();
    };
    if !state.admin_session_alive(&session_digest) {
        return (StatusCode::UNAUTHORIZED, "关联登录会话已失效").into_response();
    }
    if !state.pty_session_alive(&session_digest, is_container) {
        return (StatusCode::FORBIDDEN, "终端或容器模块未解锁或已关闭").into_response();
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
            shell_choice,
            cols,
            rows,
            move || st_check.pty_session_alive(&session_digest, is_container),
        )
        .await;
    })
}

fn sw_asset_fingerprint() -> &'static str {
    static FP: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    FP.get_or_init(|| {
        let mut names: Vec<String> = WebAssets::iter().map(|s| s.into_owned()).collect();
        names.sort();
        let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
        ctx.update(env!("CARGO_PKG_VERSION").as_bytes());
        for name in names {
            ctx.update(b"\n");
            ctx.update(name.as_bytes());
        }
        let d = ctx.finish();
        d.as_ref()[..6].iter().map(|b| format!("{b:02x}")).collect()
    })
}

async fn serve_manifest(State(state): State<Arc<AppState>>) -> Response {
    let cfg = state.config.load();
    let start_url = boundary::active_secret_path(&cfg).unwrap_or("/").to_string();
    let manifest = serde_json::json!({
        "id": "/",
        "name": "Vane Gateway",
        "short_name": "Vane",
        "description": "高安全双栈路由器全能网关控制台",
        "start_url": start_url,
        "scope": "/",
        "display": "standalone",
        "display_override": ["window-controls-overlay", "standalone"],
        "orientation": "any",
        "background_color": "#09090b",
        "theme_color": "#09090b",
        "icons": [
            { "src": "/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any" },
            { "src": "/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any" },
            { "src": "/icon-maskable-512.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable" },
            { "src": "/icon.svg", "sizes": "any", "type": "image/svg+xml", "purpose": "any" }
        ],
        "shortcuts": [
            { "name": "仪表盘", "short_name": "Dashboard", "url": format!("{start_url}#dashboard"), "icons": [{ "src": "/icon-192.png", "sizes": "192x192", "type": "image/png" }] },
            { "name": "运行日志", "short_name": "Logs", "url": format!("{start_url}#logs"), "icons": [{ "src": "/icon-192.png", "sizes": "192x192", "type": "image/png" }] },
            { "name": "系统设置", "short_name": "Settings", "url": format!("{start_url}#settings"), "icons": [{ "src": "/icon-192.png", "sizes": "192x192", "type": "image/png" }] }
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
        r#"const CACHE_NAME = 'vane-shell-{}-{}';
const ICON_PATHS = new Set(['/icon.svg', '/icon-192.png', '/icon-512.png', '/icon-maskable-512.png', '/apple-touch-icon.png']);
const OFFLINE_HTML = '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><title>Vane Gateway</title><style>body{{margin:0;min-height:100dvh;display:grid;place-items:center;background:#09090b;color:#f4f4f5;font:14px/1.6 system-ui,-apple-system,sans-serif;padding:24px;text-align:center}}.box{{max-width:340px;padding:26px 22px;border-radius:20px;background:#16161a;border:1px solid rgba(255,255,255,.1)}}h1{{margin:0 0 8px;font-size:17px}}p{{margin:0 0 18px;color:#a1a1aa;font-size:13px}}a{{display:inline-block;padding:8px 18px;border-radius:999px;background:#10b981;color:#fff;text-decoration:none;font-weight:600}}</style></head><body><div class="box"><h1>无法连接到 Vane 网关</h1><p>当前网络离线或路由器正在重启，请确认连接后重试。</p><a href="">重新连接</a></div></body></html>';

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => {{
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))));
  self.clients.claim();
}});
self.addEventListener('message', (e) => {{
  if (e.data && e.data.type === 'SKIP_WAITING') self.skipWaiting();
}});
self.addEventListener('fetch', (e) => {{
  if (e.request.method !== 'GET') return;
  const url = new URL(e.request.url);
  if (url.origin !== self.location.origin || url.pathname.startsWith('/api/')) return;
  if (e.request.mode === 'navigate') {{
    e.respondWith(
      fetch(e.request).catch(() => new Response(OFFLINE_HTML, {{
        status: 503,
        headers: {{ 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }}
      }}))
    );
    return;
  }}
  if (ICON_PATHS.has(url.pathname)) {{
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
        env!("CARGO_PKG_VERSION"),
        sw_asset_fingerprint()
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
    if uri.path().starts_with("/api/") {
        return StatusCode::NOT_FOUND.into_response();
    }
    if method != Method::GET && method != Method::HEAD {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
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
    } else if path.ends_with(".png") || path.ends_with(".svg") || path.ends_with(".ico") {
        "public, max-age=86400"
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
    } else if path.ends_with(".png") {
        "image/png"
    } else if path.ends_with(".ico") {
        "image/x-icon"
    } else if path.ends_with(".webp") {
        "image/webp"
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
        firewall.set_data_dir(tmp_dir.to_path_buf());
        let live_listeners: Vec<SocketAddr> = outcome
            .config
            .admin
            .listen_lan
            .iter()
            .filter_map(|s| s.parse::<SocketAddr>().ok())
            .collect();
        let state = Arc::new(AppState {
            config_path: cfg_path,
            config: Arc::new(ArcSwap::from_pointee(outcome.config.clone())),
            config_lock: tokio::sync::Mutex::new(()),
            vault,
            auth: Mutex::new(AuthState::new(outcome.config.admin.canonical_origin.clone(), 0)),
            hash_gate: Arc::new(HashGate::new()),
            fail2ban: Arc::new(Fail2Ban::new()),
            proxy_gate_fail2ban: Arc::new(crate::security::fail2ban::ScopedFail2Ban::new()),
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
            inbox: crate::daemon::inbox::NotificationInbox::load_or_new(tmp_dir),
            updater: Arc::new(crate::daemon::updater::UpdateRuntime::new()),
            global_quota: ConnectionQuota::new(128),
            pty_mgr: Arc::new(PtyManager::new()),
            proxy_gate: Arc::new(crate::security::proxy_gate::ProxyGateStore::new()),
            reauth_tickets: crate::security::tickets::SessionTickets::default(),
            reload_notify: Arc::new(Notify::new()),
            live_admin_listeners: Arc::new(live_listeners),
            shutdown_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
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

        // 绑定 TOTP 并验证：0) 无 reauth 被 403 拒绝；1) 水位线持久化落盘；2) 一次性恢复码用过即焚不可重用
        let setup_no_reauth = app
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
        assert_eq!(setup_no_reauth.status(), StatusCode::FORBIDDEN);

        let reauth_setup = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/reauth/verify")
                    .header(header::COOKIE, &admin_cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"method":"password","password":"Vane#2026Strong"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let tok_setup = serde_json::from_slice::<serde_json::Value>(&to_bytes(reauth_setup.into_body(), 4096).await.unwrap())
            .unwrap()["reauth_token"]
            .as_str()
            .unwrap()
            .to_string();

        let setup_res = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/totp/setup")
                    .header(header::COOKIE, &admin_cookie)
                    .header("x-vane-reauth-token", &tok_setup)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(setup_res.status(), StatusCode::OK);
        let setup_json: serde_json::Value =
            serde_json::from_slice(&to_bytes(setup_res.into_body(), 8192).await.unwrap()).unwrap();
        let secret_b32 = setup_json["secret_base32"].as_str().unwrap();
        let secret_raw = base32_decode(secret_b32).unwrap();
        let code = crate::security::auth::totp_code(&secret_raw, logger::unix_now() / 30);

        let reauth_enable = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/reauth/verify")
                    .header(header::COOKIE, &admin_cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"method":"password","password":"Vane#2026Strong"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let tok_enable = serde_json::from_slice::<serde_json::Value>(&to_bytes(reauth_enable.into_body(), 4096).await.unwrap())
            .unwrap()["reauth_token"]
            .as_str()
            .unwrap()
            .to_string();

        let enable_res = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/totp/enable")
                    .header(header::COOKIE, &admin_cookie)
                    .header("x-vane-reauth-token", &tok_enable)
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

        // 机器 A 导出全量加密备份：未带 reauth 必须被 403 拒绝，携带有效 reauth 后成功导出
        let exp_no_reauth = app_a
            .clone()
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
        assert_eq!(exp_no_reauth.status(), StatusCode::FORBIDDEN);

        let reauth_a = app_a
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/reauth/verify")
                    .header(header::COOKIE, &cookie_a)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"method":"password","password":"Vane#BackupPass1"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let tok_a = serde_json::from_slice::<serde_json::Value>(&to_bytes(reauth_a.into_body(), 4096).await.unwrap())
            .unwrap()["reauth_token"]
            .as_str()
            .unwrap()
            .to_string();

        let exp_resp = app_a
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/backup/export")
                    .header(header::COOKIE, &cookie_a)
                    .header("x-vane-reauth-token", &tok_a)
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
        let imp_no_reauth = app_b
            .clone()
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
        assert_eq!(imp_no_reauth.status(), StatusCode::FORBIDDEN);

        let reauth_b = app_b
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/reauth/verify")
                    .header(header::COOKIE, &cookie_b)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"method":"password","password":"Vane#TempPassB1"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let tok_b = serde_json::from_slice::<serde_json::Value>(&to_bytes(reauth_b.into_body(), 4096).await.unwrap())
            .unwrap()["reauth_token"]
            .as_str()
            .unwrap()
            .to_string();

        let imp_resp = app_b
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/backup/import")
                    .header(header::COOKIE, &cookie_b)
                    .header("x-vane-reauth-token", &tok_b)
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

    #[tokio::test]
    async fn unified_reauth_token_supports_password_totp_and_single_use_pty_ticket() {
        let dir = std::env::temp_dir().join(format!("vane_reauth_e2e_{}", crate::config::random_nonce()));
        let (app, state) = make_test_app_with_secret_path(&dir, "/").await;

        // 1) 登录并修改初始密码
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
        let init_cookie = login
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let ch = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/change-password")
                    .header(header::COOKIE, &init_cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"current_password":"admin321","new_password":"Vane#Reauth99"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ch.status(), StatusCode::OK);
        let cookie = ch
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();

        // 2) 开启 web_terminal + require_reauth 与 TOTP
        let totp_secret = b"0123456789ABCDEF0123";
        {
            let mut next = (**state.config.load()).clone();
            next.modules.web_terminal = true;
            next.web_terminal.require_reauth = true;
            next.admin.totp_enabled = true;
            next.admin.totp_secret = state
                .vault
                .seal("admin.totp_secret", base32_encode(totp_secret).as_bytes())
                .unwrap();
            save_config(&state.config_path, &next).unwrap();
            state.config.store(Arc::new(next));
        }

        // 3) 查询可用二次验证方式
        let opts_resp = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/reauth/options")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(opts_resp.status(), StatusCode::OK);
        let opts_json: serde_json::Value =
            serde_json::from_slice(&to_bytes(opts_resp.into_body(), 16_384).await.unwrap()).unwrap();
        assert_eq!(opts_json["methods"]["password"], true);
        assert_eq!(opts_json["methods"]["totp"], true);

        // 4) 通过密码获取一次性 reauth_token，验证 PTY ticket 仅允许消费一次
        let pw_reauth = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/reauth/verify")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"method":"password","password":"Vane#Reauth99"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pw_reauth.status(), StatusCode::OK);
        let pw_json: serde_json::Value =
            serde_json::from_slice(&to_bytes(pw_reauth.into_body(), 16_384).await.unwrap()).unwrap();
        let token1 = pw_json["reauth_token"].as_str().unwrap().to_string();

        let pty_ok = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/pty/ticket")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "target": "host", "shell": "sh", "reauth_token": token1 }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pty_ok.status(), StatusCode::OK);

        // 重放同一 reauth_token 必须被拒绝
        let pty_replay = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/pty/ticket")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "target": "host", "shell": "sh", "reauth_token": token1 }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pty_replay.status(), StatusCode::FORBIDDEN);

        // 5) 通过 TOTP 二次验证获取 reauth_token 并验证单调防重放
        let step = logger::unix_now() / 30;
        let code = format!("{:06}", crate::security::auth::totp_code(totp_secret, step));
        let totp_reauth = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/reauth/verify")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "method": "totp", "totp_code": code }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(totp_reauth.status(), StatusCode::OK);
        let totp_replay = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/reauth/verify")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "method": "totp", "totp_code": code }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(totp_replay.status(), StatusCode::FORBIDDEN);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn inbox_crud_and_update_status_and_upload_reauth_gate() {
        let dir = std::env::temp_dir().join(format!("vane_inbox_upd_http_{}", crate::config::random_nonce()));
        std::fs::create_dir_all(&dir).unwrap();
        let (app, state) = make_test_app_with_secret_path(&dir, "/").await;

        // 登录并改密
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
        let init_ck = login.headers()[header::SET_COOKIE].to_str().unwrap().split(';').next().unwrap().to_string();
        let ch = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/change-password")
                    .header(header::COOKIE, &init_ck)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"current_password":"admin321","new_password":"Vane#UpdatePass1"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let cookie = ch.headers()[header::SET_COOKIE].to_str().unwrap().split(';').next().unwrap().to_string();

        // 写入 2 条站内通知并通过 HTTP 接口查询 / 标记已读 / 删除 / 清空
        let m1 = state.inbox.push("ddns_failed", "error", "DDNS 失败", "域名同步超时", None);
        let m2 = state.inbox.push("system_update", "info", "发现新版本", "v0.2.0 可用", None);
        assert_eq!(m1.module, "ddns");
        assert_eq!(m2.module, "settings/update");

        let list_r = app
            .clone()
            .oneshot(trusted_request().uri("/api/notifications/inbox").header(header::COOKIE, &cookie).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(list_r.status(), StatusCode::OK);
        let list_j: serde_json::Value = serde_json::from_slice(&to_bytes(list_r.into_body(), 32_768).await.unwrap()).unwrap();
        assert_eq!(list_j["unread_count"], 2);
        assert_eq!(list_j["items"].as_array().unwrap().len(), 2);

        let read_one = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/notifications/inbox/read")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::json!({ "id": m1.id }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(read_one.status(), StatusCode::OK);
        let read_j: serde_json::Value = serde_json::from_slice(&to_bytes(read_one.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(read_j["unread_count"], 1);

        let del_r = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("DELETE")
                    .uri(format!("/api/notifications/inbox/{}", m2.id))
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(del_r.status(), StatusCode::OK);
        let del_j: serde_json::Value = serde_json::from_slice(&to_bytes(del_r.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(del_j["unread_count"], 0);

        // 查询系统更新状态：默认关闭自动检查，allow_manual_update_upload 默认开启（依赖可信 Ed25519 公钥）
        let has_builtin_key = crate::daemon::updater::builtin_update_signing_public_key().is_some();
        let upd_r = app
            .clone()
            .oneshot(trusted_request().uri("/api/update/status").header(header::COOKIE, &cookie).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(upd_r.status(), StatusCode::OK);
        let upd_j: serde_json::Value = serde_json::from_slice(&to_bytes(upd_r.into_body(), 16_384).await.unwrap()).unwrap();
        assert_eq!(upd_j["config"]["auto_check"], false);
        assert_eq!(upd_j["allow_manual_update_upload"], true);
        assert_eq!(upd_j["update_signing_key_configured"], has_builtin_key);
        assert_eq!(upd_j["manual_upload_ready"], has_builtin_key);
        assert_eq!(upd_j["status"]["current_version"], env!("CARGO_PKG_VERSION"));

        // 未内置公钥且未配置 config 公钥时，上传必须 fail-closed 返回 403 MANUAL_UPDATE_SIGNING_KEY_MISSING
        if !has_builtin_key {
            let missing_key_up = app
                .clone()
                .oneshot(
                    trusted_request()
                        .method("POST")
                        .uri("/api/update/upload")
                        .header(header::COOKIE, &cookie)
                        .body(Body::from(b"not-a-gzip".to_vec()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(missing_key_up.status(), StatusCode::FORBIDDEN);
            assert!(String::from_utf8_lossy(&to_bytes(missing_key_up.into_body(), 4096).await.unwrap())
                .contains("MANUAL_UPDATE_SIGNING_KEY_MISSING"));
        }

        // 在 config.toml 中显式设置 allow_manual_update_upload = false 时，即使配置了公钥也必须返回 403 MANUAL_UPDATE_DISABLED
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        {
            use ring::signature::KeyPair;
            let mut next = (**state.config.load()).clone();
            next.admin.allow_manual_update_upload = false;
            next.admin.update_signing_public_key = B64.encode(kp.public_key().as_ref());
            state.config.store(Arc::new(next));
        }
        let disabled_up = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/update/upload")
                    .header(header::COOKIE, &cookie)
                    .body(Body::from(b"not-a-gzip".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(disabled_up.status(), StatusCode::FORBIDDEN);
        assert!(String::from_utf8_lossy(&to_bytes(disabled_up.into_body(), 4096).await.unwrap())
            .contains("MANUAL_UPDATE_DISABLED"));

        // 恢复默认 allow_manual_update_upload = true，仅靠 Ed25519 验签公钥即可进入上传流程
        {
            let mut next = (**state.config.load()).clone();
            next.admin.allow_manual_update_upload = true;
            state.config.store(Arc::new(next));
        }

        // 未携带二次验证令牌上传压缩包必须被 403 REAUTH_REQUIRED 拦截
        let no_reauth = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/update/upload")
                    .header(header::COOKIE, &cookie)
                    .body(Body::from(b"not-a-gzip".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(no_reauth.status(), StatusCode::FORBIDDEN);
        let no_reauth_body = to_bytes(no_reauth.into_body(), 4096).await.unwrap();
        assert!(String::from_utf8_lossy(&no_reauth_body).contains("REAUTH_REQUIRED"));

        // 携带有效 reauth_token 与 Ed25519 签名上传非法非 gzip 文件应通过验签后被沙箱 400 拦截
        let reauth_r = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/reauth/verify")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"method":"password","password":"Vane#UpdatePass1"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reauth_r.status(), StatusCode::OK);
        let reauth_j: serde_json::Value = serde_json::from_slice(&to_bytes(reauth_r.into_body(), 4096).await.unwrap()).unwrap();
        let tok = reauth_j["reauth_token"].as_str().unwrap();
        let payload = b"#!/bin/sh\necho bad\n".to_vec();
        let sig_b64 = B64.encode(kp.sign(&payload).as_ref());

        let bad_upload = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/update/upload")
                    .header(header::COOKIE, &cookie)
                    .header("x-vane-reauth-token", tok)
                    .header("x-vane-update-signature", sig_b64)
                    .body(Body::from(payload))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad_upload.status(), StatusCode::BAD_REQUEST);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn per_module_reauth_enforces_isolation_and_removed_endpoints_404() {
        let dir = std::env::temp_dir().join(format!("vane_mod_reauth_http_{}", crate::config::random_nonce()));
        std::fs::create_dir_all(&dir).unwrap();
        let (app, _) = make_test_app_with_secret_path(&dir, "/").await;

        // 登录并改密
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
        let init_ck = login.headers()[header::SET_COOKIE].to_str().unwrap().split(';').next().unwrap().to_string();
        let ch = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/change-password")
                    .header(header::COOKIE, &init_ck)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"current_password":"admin321","new_password":"Vane#ModReauth1"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let cookie = ch.headers()[header::SET_COOKIE].to_str().unwrap().split(';').next().unwrap().to_string();

        // 已移除的接口返回 404
        for (method, path) in [
            ("GET", "/api/auth/ca-cert"),
            ("POST", "/api/auth/challenge"),
            ("POST", "/api/auth/login-ed25519"),
            ("POST", "/api/auth/ed25519/keys"),
        ] {
            let r = app
                .clone()
                .oneshot(trusted_request().method(method).uri(path).header(header::COOKIE, &cookie).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::NOT_FOUND, "expected 404 for {method} {path}");
        }

        // 开启 ddns 与 docker 的模块二次验证
        for m in ["ddns", "docker"] {
            let r = app
                .clone()
                .oneshot(
                    trusted_request()
                        .method("PUT")
                        .uri("/api/modules/reauth")
                        .header(header::COOKIE, &cookie)
                        .header("content-type", "application/json")
                        .body(Body::from(serde_json::json!({ "module": m, "require_reauth": true }).to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::OK);
        }

        // 未解锁时：dashboard 不受影响（200 OK），但 ddns / docker 接口被 403 MODULE_REAUTH_REQUIRED 拦截
        let dash = app
            .clone()
            .oneshot(trusted_request().uri("/api/dashboard").header(header::COOKIE, &cookie).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(dash.status(), StatusCode::OK);

        let ddns_blocked = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/ddns/missing/sync")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ddns_blocked.status(), StatusCode::FORBIDDEN);
        let b = to_bytes(ddns_blocked.into_body(), 4096).await.unwrap();
        assert!(String::from_utf8_lossy(&b).contains("MODULE_REAUTH_REQUIRED"));

        // 解锁 ddns 后，ddns 接口放行（返回 404 规则不存在），而 docker 仍保持 403 锁定隔离
        let unlock_ddns = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/reauth/verify")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"method":"password","password":"Vane#ModReauth1","unlock_module":"ddns"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unlock_ddns.status(), StatusCode::OK);

        let ddns_allowed = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/ddns/missing/sync")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ddns_allowed.status(), StatusCode::NOT_FOUND);

        let docker_still_blocked = app
            .clone()
            .oneshot(
                trusted_request()
                    .uri("/api/docker/containers")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(docker_still_blocked.status(), StatusCode::FORBIDDEN);

        // 不带二次验证令牌关闭 ddns 二次验证保护必须被 403 拒绝
        let disarm_no_tok = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("PUT")
                    .uri("/api/modules/reauth")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"module":"ddns","require_reauth":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(disarm_no_tok.status(), StatusCode::FORBIDDEN);

        // 携带一次性 reauth_token 成功关闭保护
        let reauth_r = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/reauth/verify")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"method":"password","password":"Vane#ModReauth1"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let rj: serde_json::Value = serde_json::from_slice(&to_bytes(reauth_r.into_body(), 4096).await.unwrap()).unwrap();
        let tok = rj["reauth_token"].as_str().unwrap();

        let disarm_ok = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("PUT")
                    .uri("/api/modules/reauth")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::json!({ "module": "ddns", "require_reauth": false, "reauth_token": tok }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(disarm_ok.status(), StatusCode::OK);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn totp_passkey_disable_reauth_and_locked_disabled_module_settings_guard() {
        let dir = std::env::temp_dir().join(format!("vane_sec_guard_http_{}", crate::config::random_nonce()));
        std::fs::create_dir_all(&dir).unwrap();
        let (app, state) = make_test_app_with_secret_path(&dir, "/").await;

        // 登录并改密
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
        let init_ck = login.headers()[header::SET_COOKIE].to_str().unwrap().split(';').next().unwrap().to_string();
        let ch = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/change-password")
                    .header(header::COOKIE, &init_ck)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"current_password":"admin321","new_password":"Vane#SecGuard1"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let mut cookie = ch.headers()[header::SET_COOKIE].to_str().unwrap().split(';').next().unwrap().to_string();

        // 1) 未绑定任何通行密钥时，禁止空开 passkey_enabled=true（400 PASSKEY_REQUIRED）
        let empty_enable = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/passkey/toggle")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"enabled":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(empty_enable.status(), StatusCode::BAD_REQUEST);
        assert!(String::from_utf8_lossy(&to_bytes(empty_enable.into_body(), 4096).await.unwrap()).contains("PASSKEY_REQUIRED"));

        // 2) 模拟已开启 TOTP：重复 setup 被 400 拦截；无 reauth_token 关闭被 403 拦截；有 reauth_token 关闭并彻底清空密钥
        {
            let mut next = (**state.config.load()).clone();
            next.admin.totp_enabled = true;
            next.admin.totp_secret = state.vault.seal("admin.totp_secret", b"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP").unwrap();
            next.admin.totp_recovery_hashes = vec!["dummy-hash".into()];
            state.config.store(Arc::new(next));
        }
        let dup_setup = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/totp/setup")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dup_setup.status(), StatusCode::BAD_REQUEST);

        let totp_dis_no_tok = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/totp/disable")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(totp_dis_no_tok.status(), StatusCode::FORBIDDEN);

        // 启用 TOTP 时：仅密码签发的 reauth_token 必须被 403 MFA_REAUTH_REQUIRED 拒绝；通过 TOTP 签发的令牌才能关闭 TOTP
        let reauth_pw_only = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/reauth/verify")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"method":"password","password":"Vane#SecGuard1"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let tok_pw = serde_json::from_slice::<serde_json::Value>(&to_bytes(reauth_pw_only.into_body(), 4096).await.unwrap())
            .unwrap()["reauth_token"]
            .as_str()
            .unwrap()
            .to_string();
        let totp_dis_pw_denied = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/totp/disable")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::json!({ "reauth_token": tok_pw }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(totp_dis_pw_denied.status(), StatusCode::FORBIDDEN);
        let denied_body = String::from_utf8_lossy(&to_bytes(totp_dis_pw_denied.into_body(), 4096).await.unwrap()).into_owned();
        assert!(denied_body.contains("MFA_REAUTH_REQUIRED"), "got: {denied_body}");

        let totp_raw = base32_decode("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP").unwrap();
        let totp_code = format!("{:06}", crate::security::auth::totp_code(&totp_raw, logger::unix_now() / 30));
        let reauth1 = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/reauth/verify")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::json!({ "method": "totp", "totp_code": totp_code }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reauth1.status(), StatusCode::OK);
        let tok1 = serde_json::from_slice::<serde_json::Value>(&to_bytes(reauth1.into_body(), 4096).await.unwrap())
            .unwrap()["reauth_token"]
            .as_str()
            .unwrap()
            .to_string();

        let totp_dis_ok = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/totp/disable")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::json!({ "reauth_token": tok1 }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(totp_dis_ok.status(), StatusCode::OK);
        if let Some(sc) = totp_dis_ok.headers().get(header::SET_COOKIE).and_then(|v| v.to_str().ok()) {
            cookie = sc.split(';').next().unwrap().to_string();
        }
        {
            let cfg = state.config.load();
            assert!(!cfg.admin.totp_enabled);
            assert!(cfg.admin.totp_secret.is_empty());
            assert!(cfg.admin.totp_recovery_hashes.is_empty());
        }

        // 3) 模拟已启用且含 1 把真实 Ed25519 Passkey：无 reauth_token 关闭被 403 拦截；关闭密码登录时禁止关闭/清空最后一把 Passkey（防死锁）；
        //    恢复密码登录后，仅密码签发的令牌被 MFA_REAUTH_REQUIRED 拦截，经真实 Passkey 签发的 MFA 令牌关闭通行密钥并清空列表！
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pk_kp = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pk_cred_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x5au8; 24]);
        {
            use ring::signature::KeyPair;
            let mut next = (**state.config.load()).clone();
            next.admin.extra_allowed_origins.push("https://localhost:23456".into());
            next.admin.passkey_enabled = true;
            next.admin.password_login_enabled = false;
            next.admin.passkeys.push(crate::config::PasskeyEntry {
                id: pk_cred_id.clone(),
                name: "MacBook · Chrome".into(),
                rp_id: "localhost".into(),
                alg: crate::security::webauthn::COSE_ALG_EDDSA,
                pubkey_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pk_kp.public_key().as_ref()),
                sign_count: 1,
                created_at: 1_700_000_000,
                last_used_at: 0,
            });
            state.config.store(Arc::new(next));
        }
        let pk_lockout = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/passkey/toggle")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"enabled":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pk_lockout.status(), StatusCode::BAD_REQUEST);
        assert!(String::from_utf8_lossy(&to_bytes(pk_lockout.into_body(), 4096).await.unwrap()).contains("LAST_AUTH_METHOD"));

        {
            let mut next = (**state.config.load()).clone();
            next.admin.password_login_enabled = true;
            state.config.store(Arc::new(next));
        }
        let pk_no_reauth = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/passkey/toggle")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"enabled":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pk_no_reauth.status(), StatusCode::FORBIDDEN);

        // 密码令牌无法关闭已启用的 Passkey（必须 MFA）
        let reauth_pw2 = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/reauth/verify")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"method":"password","password":"Vane#SecGuard1"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let tok_pw2 = serde_json::from_slice::<serde_json::Value>(&to_bytes(reauth_pw2.into_body(), 4096).await.unwrap())
            .unwrap()["reauth_token"]
            .as_str()
            .unwrap()
            .to_string();
        let pk_dis_pw_denied = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/passkey/toggle")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::json!({ "enabled": false, "reauth_token": tok_pw2 }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pk_dis_pw_denied.status(), StatusCode::FORBIDDEN);
        assert!(String::from_utf8_lossy(&to_bytes(pk_dis_pw_denied.into_body(), 4096).await.unwrap())
            .contains("MFA_REAUTH_REQUIRED"));

        // 经真实 Passkey 断言获取 MFA reauth_token 并关闭 Passkey
        let pk_opts_r = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/reauth/options")
                    .header(header::HOST, "192.168.1.1:23456")
                    .header(header::ORIGIN, "https://localhost:23456")
                    .header(header::COOKIE, &cookie)
                    .extension(ConnectInfo("192.168.1.2:12345".parse::<SocketAddr>().unwrap()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pk_opts_r.status(), StatusCode::OK);
        let pk_opts_j: serde_json::Value =
            serde_json::from_slice(&to_bytes(pk_opts_r.into_body(), 8192).await.unwrap()).unwrap();
        let pk_ch = pk_opts_j["passkey_options"]["challenge"].as_str().unwrap().to_string();
        let cd_json = serde_json::json!({
            "type": "webauthn.get",
            "challenge": pk_ch,
            "origin": "https://localhost:23456",
            "crossOrigin": false
        })
        .to_string();
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(ring::digest::digest(&ring::digest::SHA256, b"localhost").as_ref());
        auth_data.push(0x05); // UP | UV
        auth_data.extend_from_slice(&2u32.to_be_bytes());
        let mut signed = auth_data.clone();
        signed.extend_from_slice(ring::digest::digest(&ring::digest::SHA256, cd_json.as_bytes()).as_ref());
        let pk_sig = pk_kp.sign(&signed);
        let reauth2 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/reauth/verify")
                    .header(header::HOST, "192.168.1.1:23456")
                    .header(header::ORIGIN, "https://localhost:23456")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .extension(ConnectInfo("192.168.1.2:12345".parse::<SocketAddr>().unwrap()))
                    .body(Body::from(
                        serde_json::json!({
                            "method": "passkey",
                            "challenge": pk_ch,
                            "credential_id": pk_cred_id,
                            "client_data_json": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cd_json.as_bytes()),
                            "authenticator_data": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&auth_data),
                            "signature": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pk_sig.as_ref()),
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reauth2.status(), StatusCode::OK);
        let tok2 = serde_json::from_slice::<serde_json::Value>(&to_bytes(reauth2.into_body(), 4096).await.unwrap())
            .unwrap()["reauth_token"]
            .as_str()
            .unwrap()
            .to_string();
        let pk_dis_ok = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/auth/passkey/toggle")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::json!({ "enabled": false, "reauth_token": tok2 }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pk_dis_ok.status(), StatusCode::OK);
        if let Some(sc) = pk_dis_ok.headers().get(header::SET_COOKIE).and_then(|v| v.to_str().ok()) {
            cookie = sc.split(';').next().unwrap().to_string();
        }
        {
            let cfg = state.config.load();
            assert!(!cfg.admin.passkey_enabled);
            assert!(cfg.admin.passkeys.is_empty());
        }

        // 4) 开启 docker 二次验证锁，同时保持 web_terminal 禁用：
        //    - 未解锁时修改 docker.log_tail_default 必须被 403 MODULE_REAUTH_REQUIRED 拦截
        //    - 仅配置文件可控的 admin.docker_socket 尝试通过 Web 修改会被静默保留原值
        //    - 未解锁时停用 docker 模块（PUT /api/modules）必须被 403 MODULE_REAUTH_REQUIRED 拦截
        //    - 修改已禁用模块 web_terminal 的 default_cwd 时，后台必须 200 OK 且静默保留原值不落盘变更
        //    - 对已禁用模块 web_terminal 调用 PUT /api/modules/reauth 必须 403 MODULE_DISABLED
        let lock_dk = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("PUT")
                    .uri("/api/modules/reauth")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"module":"docker","require_reauth":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(lock_dk.status(), StatusCode::OK);

        let reauth_disabled_wt = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("PUT")
                    .uri("/api/modules/reauth")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"module":"web_terminal","require_reauth":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reauth_disabled_wt.status(), StatusCode::FORBIDDEN);

        let get_s = app
            .clone()
            .oneshot(trusted_request().uri("/api/settings").header(header::COOKIE, &cookie).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let base_settings: serde_json::Value = serde_json::from_slice(&to_bytes(get_s.into_body(), 131_072).await.unwrap()).unwrap();

        let mut mod_dk = base_settings.clone();
        mod_dk["docker"]["log_tail_default"] = serde_json::json!(500);
        let dk_blocked = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("PUT")
                    .uri("/api/settings")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(mod_dk.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dk_blocked.status(), StatusCode::FORBIDDEN);
        assert!(String::from_utf8_lossy(&to_bytes(dk_blocked.into_body(), 4096).await.unwrap()).contains("MODULE_REAUTH_REQUIRED"));

        // VANE-M07：admin.docker_socket 仅允许在本地 config.toml 修改，Web 提交修改被静默保留原值
        let orig_sock = state.config.load().admin.docker_socket.clone();
        let mut mod_sock = base_settings.clone();
        mod_sock["admin"]["docker_socket"] = serde_json::json!("/tmp/custom-docker.sock");
        let sock_ignored = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("PUT")
                    .uri("/api/settings")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(mod_sock.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(sock_ignored.status(), StatusCode::OK);
        assert_eq!(state.config.load().admin.docker_socket, orig_sock);

        let mut mods_off = base_settings["modules"].clone();
        mods_off["docker"] = serde_json::json!(false);
        let disable_dk_blocked = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("PUT")
                    .uri("/api/modules")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(mods_off.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(disable_dk_blocked.status(), StatusCode::FORBIDDEN);

        // 已禁用模块 web_terminal 的修改被静默忽略，同时全局字段 global_max_conns 正常保存
        let orig_cwd = state.config.load().web_terminal.default_cwd.clone();
        let mut mod_disabled_wt = base_settings.clone();
        mod_disabled_wt["web_terminal"]["default_cwd"] = serde_json::json!("/tmp/should-be-ignored");
        mod_disabled_wt["system"]["global_max_conns"] = serde_json::json!(777);
        let wt_silent = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("PUT")
                    .uri("/api/settings")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(mod_disabled_wt.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wt_silent.status(), StatusCode::OK);
        {
            let cfg = state.config.load();
            assert_eq!(cfg.system.global_max_conns, 777);
            assert_eq!(cfg.web_terminal.default_cwd, orig_cwd);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn pwa_manifest_service_worker_and_png_icons_are_valid() {
        let dir = std::env::temp_dir().join(format!("vane_pwa_http_{}", crate::config::random_nonce()));
        std::fs::create_dir_all(&dir).unwrap();
        let (app, _) = make_test_app_with_secret_path(&dir, "/").await;

        let mf = app
            .clone()
            .oneshot(trusted_request().uri("/manifest.webmanifest").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(mf.status(), StatusCode::OK);
        assert!(mf.headers()[header::CONTENT_TYPE].to_str().unwrap().contains("application/manifest+json"));
        let mj: serde_json::Value = serde_json::from_slice(&to_bytes(mf.into_body(), 16_384).await.unwrap()).unwrap();
        assert_eq!(mj["display"], "standalone");
        assert_eq!(mj["start_url"], "/");
        let icons = mj["icons"].as_array().unwrap();
        assert!(icons.iter().any(|i| i["src"] == "/icon-192.png" && i["type"] == "image/png"));
        assert!(icons.iter().any(|i| i["src"] == "/icon-512.png" && i["type"] == "image/png"));
        assert!(icons.iter().any(|i| i["src"] == "/icon-maskable-512.png" && i["purpose"] == "maskable"));

        let sw = app
            .clone()
            .oneshot(trusted_request().uri("/sw.js").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(sw.status(), StatusCode::OK);
        assert!(sw.headers()[header::CONTENT_TYPE].to_str().unwrap().contains("javascript"));
        let sw_txt = String::from_utf8(to_bytes(sw.into_body(), 32_768).await.unwrap().to_vec()).unwrap();
        assert!(sw_txt.contains("/api/"));
        assert!(sw_txt.contains("apple-touch-icon.png"));
        assert!(sw_txt.contains("OFFLINE_HTML"));

        for icon_path in ["/icon-192.png", "/icon-512.png", "/icon-maskable-512.png", "/apple-touch-icon.png"] {
            let r = app
                .clone()
                .oneshot(trusted_request().uri(icon_path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::OK, "missing icon {icon_path}");
            assert_eq!(r.headers()[header::CONTENT_TYPE], "image/png");
            let bytes = to_bytes(r.into_body(), 65_536).await.unwrap();
            assert!(bytes.starts_with(b"\x89PNG\r\n\x1a\n"), "invalid PNG magic for {icon_path}");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn proxy_auth_users_crud_isolation_and_module_lock() {
        let dir = std::env::temp_dir().join(format!("vane_gate_api_{}", crate::config::random_nonce()));
        std::fs::create_dir_all(&dir).unwrap();
        let (app, state) = make_test_app_with_secret_path(&dir, "/").await;

        // 管理员登录并完成首次改密
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
        let init_ck = login_r.headers()[header::SET_COOKIE]
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
                    .body(Body::from(r#"{"current_password":"admin321","new_password":"Admin#Strong99"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ch_r.status(), StatusCode::OK);
        let admin_ck = ch_r.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();

        // 1. 强隔离校验：管理员 cookie 不能通过 ProxyAuthorization::session / gate_session
        let mut admin_headers = HeaderMap::new();
        admin_headers.insert(header::COOKIE, header::HeaderValue::from_str(&admin_ck).unwrap());
        assert!(
            crate::net::reverse_proxy::ProxyAuthorization::session(
                state.as_ref(),
                &admin_headers,
                "192.168.1.2".parse().unwrap(),
            )
            .is_none(),
            "Vane 管理员 cookie 绝不能用于反代门禁"
        );
        assert!(
            crate::net::reverse_proxy::ProxyAuthorization::gate_session(
                state.as_ref(),
                &admin_headers,
                "nas.example.com",
                &["admin".to_string()],
                "192.168.1.2".parse().unwrap(),
            )
            .is_none(),
            "Vane 管理员 cookie 绝不能通过 gate_session"
        );

        // 2. 创建独立门禁账号（弱密码被拒，强密码成功）
        let weak_r = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/proxy/auth-users")
                    .header(header::COOKIE, &admin_ck)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"username":"nas_guest","password":"123"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(weak_r.status(), StatusCode::BAD_REQUEST);

        let create_r = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/proxy/auth-users")
                    .header(header::COOKIE, &admin_ck)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"username":"nas_guest","password":"GateUser#2026","session_ttl_secs":3600,"note":"NAS 访客"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_r.status(), StatusCode::OK);
        let created_json: serde_json::Value =
            serde_json::from_slice(&to_bytes(create_r.into_body(), 16_384).await.unwrap()).unwrap();
        assert_eq!(created_json["users"].as_array().unwrap().len(), 1);
        assert!(created_json["users"][0].get("password_hash").is_none());

        // 3. GET /api/settings 不泄露 password_hash，且 PUT /api/settings 不可篡改 proxy_auth_users
        let get_s = app
            .clone()
            .oneshot(trusted_request().uri("/api/settings").header(header::COOKIE, &admin_ck).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let mut settings_v: serde_json::Value =
            serde_json::from_slice(&to_bytes(get_s.into_body(), 131_072).await.unwrap()).unwrap();
        assert!(settings_v["proxy_auth_users"][0].get("password_hash").is_none());
        assert_eq!(settings_v["proxy_auth_users"][0]["password_configured"], true);
        let orig_hash = state.config.load().proxy_auth_users[0].password_hash.clone();
        settings_v["proxy_auth_users"] = serde_json::json!([]);
        let put_s = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("PUT")
                    .uri("/api/settings")
                    .header(header::COOKIE, &admin_ck)
                    .header("content-type", "application/json")
                    .body(Body::from(settings_v.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put_s.status(), StatusCode::OK);
        assert_eq!(state.config.load().proxy_auth_users.len(), 1);
        assert_eq!(state.config.load().proxy_auth_users[0].password_hash, orig_hash);

        // 4. 独立门禁登录：未授权规则被拒，已授权规则成功签发 vane_gate_session，且不能登录 Vane 管理后台
        let deny_login = crate::net::reverse_proxy::ProxyAuthorization::gate_login(
            state.as_ref(),
            "nas.example.com".into(),
            vec!["other_user".into()],
            "nas_guest".into(),
            "GateUser#2026".into(),
            "192.168.1.9".parse().unwrap(),
        )
        .await;
        assert!(deny_login.is_err());

        let (gate_tok, ttl) = crate::net::reverse_proxy::ProxyAuthorization::gate_login(
            state.as_ref(),
            "nas.example.com".into(),
            vec!["nas_guest".into()],
            "nas_guest".into(),
            "GateUser#2026".into(),
            "192.168.1.9".parse().unwrap(),
        )
        .await
        .expect("authorized gate user should succeed");
        assert_eq!(ttl, 3600);

        // 门禁 Cookie 不能访问管理后台 /api/settings
        let try_admin = app
            .clone()
            .oneshot(
                trusted_request()
                    .uri("/api/settings")
                    .header(header::COOKIE, format!("vane_gate_session={gate_tok}; vane_session={gate_tok}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(try_admin.status(), StatusCode::UNAUTHORIZED);

        // 5. 强制下线 & 更新禁用 & 删除账号
        let rev_r = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("POST")
                    .uri("/api/proxy/auth-users/nas_guest/revoke")
                    .header(header::COOKIE, &admin_ck)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rev_r.status(), StatusCode::OK);
        let rev_v: serde_json::Value =
            serde_json::from_slice(&to_bytes(rev_r.into_body(), 16_384).await.unwrap()).unwrap();
        assert_eq!(rev_v["revoked"], 1);

        // 6. 模块级二次验证开启后，/api/proxy/auth-users 自动受 MODULE_REAUTH_REQUIRED 拦截
        let lock_r = app
            .clone()
            .oneshot(
                trusted_request()
                    .method("PUT")
                    .uri("/api/modules/reauth")
                    .header(header::COOKIE, &admin_ck)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"module":"reverse_proxy","require_reauth":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(lock_r.status(), StatusCode::OK);
        let blocked_list = app
            .clone()
            .oneshot(
                trusted_request()
                    .uri("/api/proxy/auth-users")
                    .header(header::COOKIE, &admin_ck)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(blocked_list.status(), StatusCode::FORBIDDEN);
        assert!(String::from_utf8_lossy(&to_bytes(blocked_list.into_body(), 4096).await.unwrap())
            .contains("MODULE_REAUTH_REQUIRED"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
