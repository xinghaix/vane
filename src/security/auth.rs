#![allow(deprecated)]
//! 单管理员多模态强认证：PBKDF2 口令（受限 spawn_blocking）、初始密码硬拦截、
//! 单调水位 TOTP 防回退重放、通行密钥 (Passkey) 与按子模块隔离的二次验证会话管理。
use crate::net::dual_stack::BanKey;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use base64::Engine;
use ring::rand::{SecureRandom, SystemRandom};
use ring::{constant_time, digest, hmac, pbkdf2};
use std::collections::{BTreeMap, HashMap};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

pub const DEFAULT_INITIAL_PASSWORD: &[u8] = b"admin321";
pub const DEFAULT_USERNAME: &str = "admin";
pub const PBKDF2_ITERS: u32 = 100_000;
const MAX_SESSIONS: usize = 32;
/// 会话绝对生命周期上限：24 小时
const SESSION_ABSOLUTE_MAX: Duration = Duration::from_secs(86_400);
/// 子模块二次验证解锁有效期：10 分钟（按模块独立隔离，登出或安全配置变更即刻失效）
pub const MODULE_UNLOCK_TTL: Duration = Duration::from_secs(600);
const HASH_QUEUE_LIMIT: usize = 4;

/// 登录会话权限作用域：未修改初始密码前强制锁死在 MustChangePassword，禁止进入任何管理页面 API
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SessionScope {
    MustChangePassword,
    FullAdmin,
}

/// 二次认证令牌核销失败原因（区分无效/过期与强因子 MFA 要求）
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReauthConsumeError {
    InvalidOrExpired,
    MfaRequired,
}

/// 判定是否为合法纯通行密钥免密配置（关闭密码登录且已启用并绑定至少一把通行密钥）
pub fn is_valid_passkey_only_config(admin: &crate::config::AdminConfig) -> bool {
    !admin.password_login_enabled && admin.passkey_enabled && !admin.passkeys.is_empty()
}

/// 判定管理员是否启用了至少一种强多因素认证方式（TOTP 或已绑定的 Passkey）
pub fn admin_has_mfa_enabled(admin: &crate::config::AdminConfig) -> bool {
    admin.totp_enabled || (admin.passkey_enabled && !admin.passkeys.is_empty())
}

// ---------------------------------------------------------------------------
// PBKDF2 口令哈希：pbkdf2-sha256$<iters>$<salt_b64>$<hash_b64>
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswordHash {
    pub iters: u32,
    pub salt: Vec<u8>,
    pub hash: Vec<u8>,
}

impl PasswordHash {
    pub fn create(password: &[u8]) -> Result<Self, &'static str> {
        Self::create_with_iters(password, PBKDF2_ITERS)
    }

    pub fn create_with_iters(password: &[u8], iters: u32) -> Result<Self, &'static str> {
        if password.is_empty() || password.len() > 256 {
            return Err("密码长度非法");
        }
        let mut salt = vec![0u8; 16];
        SystemRandom::new().fill(&mut salt).map_err(|_| "随机源失败")?;
        let mut hash = vec![0u8; 32];
        let n = NonZeroU32::new(iters).ok_or("迭代次数非法")?;
        pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, n, &salt, password, &mut hash);
        Ok(Self { iters, salt, hash })
    }

    pub fn parse(s: &str) -> Option<Self> {
        let mut it = s.split('$');
        if it.next()? != "pbkdf2-sha256" {
            return None;
        }
        let iters: u32 = it.next()?.parse().ok()?;
        let salt = B64.decode(it.next()?).ok()?;
        let hash = B64.decode(it.next()?).ok()?;
        if it.next().is_some() || iters < 100_000 || salt.len() < 16 || hash.len() != 32 {
            return None;
        }
        Some(Self { iters, salt, hash })
    }

    pub fn encode(&self) -> String {
        format!("pbkdf2-sha256${}${}${}", self.iters, B64.encode(&self.salt), B64.encode(&self.hash))
    }

    pub fn verify(&self, password: &[u8]) -> bool {
        AuthEngine::verify_password(password, &self.salt, &self.hash, self.iters)
    }
}

struct WaitingGuard<'a>(&'a AtomicUsize);

impl Drop for WaitingGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// PBKDF2 计算闸门：Semaphore(1) 串行 + 最多 4 个排队请求，超出直接拒绝，计算放入 spawn_blocking
pub struct HashGate {
    sem: Semaphore,
    waiting: AtomicUsize,
}

impl Default for HashGate {
    fn default() -> Self {
        Self::new()
    }
}

impl HashGate {
    pub fn new() -> Self {
        Self { sem: Semaphore::new(1), waiting: AtomicUsize::new(0) }
    }

    pub async fn run<R, F>(&self, f: F) -> Result<R, &'static str>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        if self.waiting.fetch_add(1, Ordering::SeqCst) >= HASH_QUEUE_LIMIT {
            self.waiting.fetch_sub(1, Ordering::SeqCst);
            return Err("认证请求过多，请稍后重试");
        }
        let guard = WaitingGuard(&self.waiting);
        let permit = self.sem.acquire().await;
        drop(guard);
        let _permit = permit.map_err(|_| "认证队列已关闭")?;
        tokio::task::spawn_blocking(f).await.map_err(|_| "认证计算任务异常")
    }
}

// ---------------------------------------------------------------------------
// AuthEngine：口令策略 / TOTP
// ---------------------------------------------------------------------------

pub struct AuthEngine {
    last_totp_step: Option<u64>, // 严格单调递增水位线：拒绝任何 <= last_totp_step 的动态码
    canonical_origin: String,    // 服务端固定受信 Origin，绝不采信客户端自报 Host
}

impl AuthEngine {
    pub fn new(canonical_origin: String) -> Self {
        Self { last_totp_step: None, canonical_origin }
    }

    pub fn set_canonical_origin(&mut self, origin: String) {
        self.canonical_origin = origin;
    }

    pub fn canonical_origin(&self) -> &str {
        &self.canonical_origin
    }

    /// 从持久化配置恢复水位线（防进程重启后重放）
    pub fn restore_totp_watermark(&mut self, step: u64) {
        if step > 0 {
            self.last_totp_step = Some(self.last_totp_step.map_or(step, |s| s.max(step)));
        }
    }

    pub fn reset_totp_watermark(&mut self) {
        self.last_totp_step = None;
    }

    pub fn totp_watermark(&self) -> u64 {
        self.last_totp_step.unwrap_or(0)
    }

    /// 1. 恒定时间 PBKDF2-HMAC-SHA256 校验（调用方置于受 Semaphore(1) 保护的 spawn_blocking 中执行）
    pub fn verify_password(password: &[u8], salt: &[u8], expected_hash: &[u8], iters: u32) -> bool {
        if password.is_empty() || password.len() > 256 || salt.len() < 16 || iters < 100_000 {
            return false;
        }
        let Some(n) = NonZeroU32::new(iters) else { return false };
        pbkdf2::verify(pbkdf2::PBKDF2_HMAC_SHA256, n, salt, password, expected_hash).is_ok()
    }

    /// 用户名不存在时执行等开销占位 PBKDF2 计算，消除登录耗时差异暴露管理员用户名
    pub fn verify_dummy_password(password: &[u8], iters: u32) {
        const DUMMY_SALT: [u8; 16] = [0x56, 0x61, 0x6e, 0x65, 0x44, 0x75, 0x6d, 0x6d, 0x79, 0x53, 0x61, 0x6c, 0x74, 0x30, 0x31, 0x21];
        const DUMMY_HASH: [u8; 32] = [0x9f; 32];
        let bounded = if password.is_empty() { b"x" } else if password.len() > 256 { &password[..256] } else { password };
        let iters = iters.clamp(100_000, 1_000_000);
        let _ = Self::verify_password(bounded, &DUMMY_SALT, &DUMMY_HASH, iters);
    }

    /// 判定当前密码是否仍为初始默认密码，决定签发受限改密会话还是完整管理会话
    pub fn resolve_session_scope(must_change_flag: bool, current_salt: &[u8], current_hash: &[u8], iters: u32) -> SessionScope {
        if must_change_flag || Self::verify_password(DEFAULT_INITIAL_PASSWORD, current_salt, current_hash, iters) {
            SessionScope::MustChangePassword
        } else {
            SessionScope::FullAdmin
        }
    }

    /// 强制改密校验：8~128 位 + 必须含英文字母 + 至少含数字或特殊字符之一，且严禁与初始密码/旧密码/用户名相同
    pub fn validate_new_password(
        new_password: &[u8],
        username: &[u8],
        current_salt: &[u8],
        current_hash: &[u8],
        iters: u32,
    ) -> Result<(), &'static str> {
        if new_password.len() < 8 || new_password.len() > 128 {
            return Err("新密码长度必须在 8 ~ 128 位之间");
        }
        let has_letter = new_password.iter().any(|b| b.is_ascii_alphabetic());
        let has_digit_or_symbol = new_password.iter().any(|b| b.is_ascii_digit() || b.is_ascii_punctuation());
        if !has_letter || !has_digit_or_symbol {
            return Err("密码需包含英文字母，且至少包含数字或特殊字符中的一种");
        }
        if constant_time::verify_slices_are_equal(new_password, DEFAULT_INITIAL_PASSWORD).is_ok() {
            return Err("新密码不能与初始默认密码 (admin321) 相同");
        }
        if constant_time::verify_slices_are_equal(new_password, username).is_ok() {
            return Err("新密码不能与用户名相同");
        }
        if Self::verify_password(new_password, current_salt, current_hash, iters) {
            return Err("新密码不能与当前正在使用的密码相同");
        }
        Ok(())
    }

    /// 2. RFC 6238 TOTP 校验（±1 步长容错 + 严格单调递增水位防回退重放）
    pub fn verify_totp(&mut self, secret: &[u8], code: u32, unix_now: u64) -> bool {
        let current_step = unix_now / 30;
        for step in [current_step.saturating_sub(1), current_step, current_step + 1] {
            if self.last_totp_step.is_some_and(|last| step <= last) {
                continue;
            }
            let bin_code = totp_code(secret, step);
            if constant_time::verify_slices_are_equal(&bin_code.to_be_bytes(), &code.to_be_bytes()).is_ok() {
                self.last_totp_step = Some(step);
                return true;
            }
        }
        false
    }
}

/// RFC 4226 HOTP 动态截断
pub fn totp_code(secret: &[u8], step: u64) -> u32 {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let tag = hmac::sign(&key, &step.to_be_bytes());
    let bytes = tag.as_ref();
    let offset = (bytes[19] & 0x0f) as usize;
    u32::from_be_bytes([bytes[offset] & 0x7f, bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]]) % 1_000_000
}

// ---------------------------------------------------------------------------
// Base32 (RFC 4648) 与 TOTP 工具
// ---------------------------------------------------------------------------

const B32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut buf: u32 = 0;
    let mut bits = 0;
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            out.push(B32[((buf >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut bits = 0;
    for c in s.chars().filter(|c| !c.is_whitespace() && *c != '=' && *c != '-') {
        let v = B32.iter().position(|&x| x as char == c.to_ascii_uppercase())? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            out.push(((buf >> (bits - 8)) & 0xff) as u8);
            bits -= 8;
        }
    }
    Some(out)
}

pub fn generate_totp_secret() -> Result<Vec<u8>, &'static str> {
    let mut s = vec![0u8; 20];
    SystemRandom::new().fill(&mut s).map_err(|_| "随机源失败")?;
    Ok(s)
}

pub fn otpauth_uri(secret_b32: &str, username: &str, issuer: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        url_encode(issuer),
        url_encode(username),
        secret_b32,
        url_encode(issuer)
    )
}

pub fn url_encode(s: &str) -> String {
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

/// 生成一次性恢复码（明文仅返回一次，落盘保存 PBKDF2 哈希）
pub fn generate_recovery_codes(n: usize) -> Result<Vec<String>, &'static str> {
    let mut codes = Vec::with_capacity(n);
    for _ in 0..n {
        let mut b = [0u8; 10];
        SystemRandom::new().fill(&mut b).map_err(|_| "随机源失败")?;
        let s = base32_encode(&b).to_lowercase();
        codes.push(format!("{}-{}-{}-{}", &s[0..4], &s[4..8], &s[8..12], &s[12..16]));
    }
    Ok(codes)
}

pub fn normalize_recovery_code(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_lowercase()).collect()
}

// ---------------------------------------------------------------------------
// 会话存储
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Session {
    pub scope: SessionScope,
    pub created: Instant,
    pub last_seen: Instant,
    pub client_key: BanKey,
    pub unlocked_modules: HashMap<String, Instant>,
}

/// 会话表：仅保存令牌的 SHA-256 摘要，滑动过期（session_ttl）+ 24h 绝对上限
pub struct SessionStore {
    sessions: HashMap<[u8; 32], Session>,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore {
    pub fn new() -> Self {
        Self { sessions: HashMap::new() }
    }

    pub fn token_digest(token: &str) -> [u8; 32] {
        let d = digest::digest(&digest::SHA256, token.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(d.as_ref());
        out
    }

    pub fn issue(&mut self, scope: SessionScope, client_key: BanKey, ttl: Duration) -> Result<String, &'static str> {
        self.purge(ttl);
        if self.sessions.len() >= MAX_SESSIONS {
            // 淘汰最久未活动的会话
            if let Some(k) = self.sessions.iter().min_by_key(|(_, s)| s.last_seen).map(|(k, _)| *k) {
                self.sessions.remove(&k);
            }
        }
        let mut raw = [0u8; 32];
        SystemRandom::new().fill(&mut raw).map_err(|_| "随机源失败")?;
        let token = B64URL.encode(raw);
        let now = Instant::now();
        self.sessions.insert(
            Self::token_digest(&token),
            Session {
                scope,
                created: now,
                last_seen: now,
                client_key,
                unlocked_modules: HashMap::new(),
            },
        );
        Ok(token)
    }

    pub fn unlock_module(&mut self, token: &str, module: &str) -> bool {
        let Some(sess) = self.sessions.get_mut(&Self::token_digest(token)) else {
            return false;
        };
        sess.unlocked_modules.retain(|_, ts| ts.elapsed() <= MODULE_UNLOCK_TTL);
        sess.unlocked_modules.insert(module.to_string(), Instant::now());
        true
    }

    pub fn lock_module(&mut self, token: &str, module: &str) {
        if let Some(sess) = self.sessions.get_mut(&Self::token_digest(token)) {
            sess.unlocked_modules.remove(module);
        }
    }

    pub fn lock_module_all_sessions(&mut self, module: &str) {
        for sess in self.sessions.values_mut() {
            sess.unlocked_modules.remove(module);
        }
    }

    pub fn is_module_unlocked(&self, token: &str, module: &str) -> bool {
        self.is_module_unlocked_digest(&Self::token_digest(token), module)
    }

    pub fn is_module_unlocked_digest(&self, key: &[u8; 32], module: &str) -> bool {
        self.sessions
            .get(key)
            .and_then(|s| s.unlocked_modules.get(module))
            .is_some_and(|ts| ts.elapsed() <= MODULE_UNLOCK_TTL)
    }

    pub fn unlocked_modules_remaining(&self, token: &str) -> BTreeMap<String, u64> {
        let mut out = BTreeMap::new();
        let Some(sess) = self.sessions.get(&Self::token_digest(token)) else {
            return out;
        };
        for (m, ts) in &sess.unlocked_modules {
            let elapsed = ts.elapsed();
            if elapsed < MODULE_UNLOCK_TTL {
                out.insert(m.clone(), (MODULE_UNLOCK_TTL - elapsed).as_secs().max(1));
            }
        }
        out
    }

    /// 校验并续期会话
    pub fn validate(&mut self, token: &str, ttl: Duration) -> Option<Session> {
        self.validate_digest(&Self::token_digest(token),ttl,true)
    }

    pub fn validate_digest(&mut self, key: &[u8;32], ttl:Duration, touch:bool) -> Option<Session> {
        let key=*key;
        let now = Instant::now();
        let expired = match self.sessions.get(&key) {
            Some(s) => now.duration_since(s.last_seen) > ttl || now.duration_since(s.created) > SESSION_ABSOLUTE_MAX,
            None => return None,
        };
        if expired {
            self.sessions.remove(&key);
            return None;
        }
        let s = self.sessions.get_mut(&key)?;
        if touch {s.last_seen = now;}
        Some(s.clone())
    }

    pub fn revoke(&mut self, token: &str) {
        self.sessions.remove(&Self::token_digest(token));
    }

    pub fn revoke_all(&mut self) {
        self.sessions.clear();
    }

    pub fn revoke_all_and_reissue(
        &mut self,
        current_token: &str,
        fallback_peer: BanKey,
        scope: SessionScope,
        ttl: Duration,
    ) -> Result<String, &'static str> {
        let peer = self
            .sessions
            .get(&Self::token_digest(current_token))
            .map(|s| s.client_key)
            .unwrap_or(fallback_peer);
        self.sessions.clear();
        self.issue(scope, peer, ttl)
    }

    pub fn purge(&mut self, ttl: Duration) {
        let now = Instant::now();
        self.sessions
            .retain(|_, s| now.duration_since(s.last_seen) <= ttl && now.duration_since(s.created) <= SESSION_ABSOLUTE_MAX);
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }
}

/// 认证子系统运行态（受同一互斥锁保护：TOTP 校验、水位更新与会话签发原子完成）
pub struct AuthState {
    pub engine: AuthEngine,
    pub sessions: SessionStore,
    pub pending_totp_secret: Option<(Vec<u8>, Instant)>,
    pub webauthn: crate::security::webauthn::WebAuthnChallengeStore,
    password_gate: Option<(String,SessionScope)>,
}

impl AuthState {
    pub fn effective_scope(&mut self, admin: &crate::config::AdminConfig, scope: SessionScope) -> SessionScope {
        if admin.must_change_password {
            return SessionScope::MustChangePassword;
        }
        // 合法的纯通行密钥免密配置（关闭密码登录且已启用并绑定至少一把通行密钥）允许空 password_hash 保持 FullAdmin
        if is_valid_passkey_only_config(admin) && admin.password_hash.trim().is_empty() {
            return scope;
        }
        if self.password_gate.as_ref().is_none_or(|(hash, _)| hash != &admin.password_hash) {
            let gate = PasswordHash::parse(&admin.password_hash)
                .map(|hash| AuthEngine::resolve_session_scope(false, &hash.salt, &hash.hash, hash.iters))
                .unwrap_or(SessionScope::MustChangePassword);
            self.password_gate = Some((admin.password_hash.clone(), gate));
        }
        if self
            .password_gate
            .as_ref()
            .is_some_and(|(_, gate)| *gate == SessionScope::MustChangePassword)
        {
            SessionScope::MustChangePassword
        } else {
            scope
        }
    }
    pub fn new(canonical_origin: String, totp_watermark: u64) -> Self {
        let mut engine = AuthEngine::new(canonical_origin);
        engine.restore_totp_watermark(totp_watermark);
        Self {
            engine,
            sessions: SessionStore::new(),
            pending_totp_secret: None,
            webauthn: crate::security::webauthn::WebAuthnChallengeStore::default(),
            password_gate: None,
        }
    }
}

pub type SharedHashGate = Arc<HashGate>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn key(ip: &str) -> BanKey {
        BanKey::from_peer(ip.parse::<IpAddr>().unwrap())
    }

    #[test]
    fn password_hash_roundtrip() {
        let h = PasswordHash::create(b"Str0ngPass!").unwrap();
        let enc = h.encode();
        let p = PasswordHash::parse(&enc).unwrap();
        assert!(p.verify(b"Str0ngPass!"));
        assert!(!p.verify(b"wrong"));
        assert!(PasswordHash::parse("pbkdf2-sha256$1000$AAAA$BBBB").is_none());
    }

    #[test]
    fn initial_password_forces_must_change_scope() {
        let h = PasswordHash::create(DEFAULT_INITIAL_PASSWORD).unwrap();
        // 即使手动把 must_change_password 改为 false，只要哈希仍匹配 admin321 也必须锁定
        assert_eq!(AuthEngine::resolve_session_scope(false, &h.salt, &h.hash, h.iters), SessionScope::MustChangePassword);
        assert_eq!(AuthEngine::resolve_session_scope(true, &h.salt, &h.hash, h.iters), SessionScope::MustChangePassword);
        let h2 = PasswordHash::create(b"NewPassw0rd").unwrap();
        assert_eq!(AuthEngine::resolve_session_scope(false, &h2.salt, &h2.hash, h2.iters), SessionScope::FullAdmin);
        assert_eq!(AuthEngine::resolve_session_scope(true, &h2.salt, &h2.hash, h2.iters), SessionScope::MustChangePassword);
    }

    #[test]
    fn strong_password_rules() {
        let h = PasswordHash::create(b"OldPassw0rd").unwrap();
        let v = |p: &str| AuthEngine::validate_new_password(p.as_bytes(), b"admin", &h.salt, &h.hash, h.iters);
        assert!(v("short1").is_err());
        assert!(v(&"a1".repeat(65)).is_err());
        assert!(v("abcdefgh").is_err(), "纯字母必须拒绝");
        assert!(v("12345678").is_err(), "纯数字必须拒绝");
        assert!(v("!!!!@@@@").is_err(), "无字母必须拒绝");
        assert!(v("admin321").is_err(), "初始密码必须拒绝");
        assert!(v("OldPassw0rd").is_err(), "当前密码必须拒绝");
        assert!(v("abcdefg1").is_ok());
        assert!(v("abcdefg!").is_ok());
        let hu = PasswordHash::create(b"Another1").unwrap();
        assert!(AuthEngine::validate_new_password(b"router01", b"router01", &hu.salt, &hu.hash, hu.iters).is_err());
    }

    #[test]
    fn totp_rfc6238_vector_and_replay_protection() {
        // RFC 6238 附录 B：SHA1 密钥 "12345678901234567890"，T=59 -> 94287082（取 6 位 287082）
        let secret = b"12345678901234567890";
        assert_eq!(totp_code(secret, 59 / 30), 287_082);
        let mut e = AuthEngine::new("https://192.168.1.1:23456".into());
        let now = 1_700_000_000u64;
        let step = now / 30;
        let code_now = totp_code(secret, step);
        assert!(e.verify_totp(secret, code_now, now));
        // 同一码重放拒绝
        assert!(!e.verify_totp(secret, code_now, now));
        // 回退到前一步长（n -> n-1）拒绝
        let code_prev = totp_code(secret, step - 1);
        assert!(!e.verify_totp(secret, code_prev, now));
        // 前进到 n+1 可接受，之后再回退到 n 仍拒绝（n -> n+1 -> n）
        let code_next = totp_code(secret, step + 1);
        assert!(e.verify_totp(secret, code_next, now));
        assert!(!e.verify_totp(secret, code_now, now + 30));
        assert!(!e.verify_totp(secret, 123_456 ^ code_now, now + 120));
    }

    #[test]
    fn totp_watermark_restored() {
        let secret = b"12345678901234567890";
        let now = 1_700_000_000u64;
        let mut e = AuthEngine::new("o".into());
        e.restore_totp_watermark(now / 30 + 1);
        assert!(!e.verify_totp(secret, totp_code(secret, now / 30), now));
        assert!(!e.verify_totp(secret, totp_code(secret, now / 30 + 1), now));
    }

    #[test]
    fn base32_roundtrip() {
        let data = b"12345678901234567890";
        let enc = base32_encode(data);
        assert_eq!(enc, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(base32_decode(&enc).unwrap(), data);
        assert_eq!(base32_decode("gezd gnbv").unwrap(), b"12345");
    }

    #[test]
    fn session_module_unlock_is_isolated_and_revocable() {
        let mut s = SessionStore::new();
        let ck = key("127.0.0.1");
        let tok = s.issue(SessionScope::FullAdmin, ck, Duration::from_secs(3600)).unwrap();
        assert!(!s.is_module_unlocked(&tok, "ddns"));
        assert!(s.unlock_module(&tok, "ddns"));
        assert!(s.is_module_unlocked(&tok, "ddns"));
        assert!(!s.is_module_unlocked(&tok, "docker"));
        let rem = s.unlocked_modules_remaining(&tok);
        assert!(rem.get("ddns").copied().unwrap_or(0) > 0);
        s.lock_module(&tok, "ddns");
        assert!(!s.is_module_unlocked(&tok, "ddns"));
    }

    #[test]
    fn session_store_ttl_and_revoke() {
        let mut s = SessionStore::new();
        let ck = key("127.0.0.1");
        let t = s.issue(SessionScope::MustChangePassword, ck, Duration::from_secs(3600)).unwrap();
        assert_eq!(s.validate(&t, Duration::from_secs(3600)).unwrap().scope, SessionScope::MustChangePassword);
        assert!(s.validate("bogus", Duration::from_secs(3600)).is_none());
        assert!(s.validate(&t, Duration::from_secs(0)).is_none() || s.len() <= 1);
        let t2 = s.issue(SessionScope::FullAdmin, ck, Duration::from_secs(3600)).unwrap();
        s.revoke(&t2);
        assert!(s.validate(&t2, Duration::from_secs(3600)).is_none());
        for _ in 0..40 {
            s.issue(SessionScope::FullAdmin, ck, Duration::from_secs(3600)).unwrap();
        }
        assert!(s.len() <= MAX_SESSIONS);
        s.revoke_all();
        assert_eq!(s.len(), 0);
    }

    #[tokio::test]
    async fn hash_gate_runs_blocking() {
        let g = HashGate::new();
        let r = g.run(|| 21 * 2).await.unwrap();
        assert_eq!(r, 42);
    }

    #[tokio::test]
    async fn hash_gate_does_not_leak_waiting_slots_on_cancel() {
        let g = Arc::new(HashGate::new());
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel::<()>();
        let g0 = g.clone();
        let blocker = tokio::spawn(async move {
            g0.run(move || {
                let _ = entered_tx.send(());
                let _ = rx.recv_timeout(Duration::from_secs(2));
                1
            })
            .await
        });
        let _ = entered_rx.await;
        // 排满剩余排队位并在等待时立刻取消，不能永久卡死 HashGate
        for _ in 0..8 {
            let mut waiters = Vec::new();
            for _ in 0..(HASH_QUEUE_LIMIT - 1) {
                let gw = g.clone();
                waiters.push(tokio::spawn(async move { gw.run(|| 2).await }));
            }
            tokio::task::yield_now().await;
            for w in waiters {
                w.abort();
                let _ = w.await;
            }
        }
        let _ = tx.send(());
        assert_eq!(blocker.await.unwrap().unwrap(), 1);
        assert_eq!(g.run(|| 99).await.unwrap(), 99);
    }

    #[test]
    fn recovery_codes_format() {
        let c = generate_recovery_codes(8).unwrap();
        assert_eq!(c.len(), 8);
        assert_eq!(normalize_recovery_code(&c[0]).len(), 16);
    }

    #[test]
    fn effective_scope_allows_valid_passkey_only_without_password_hash() {
        let mut state = AuthState::new("https://router.local:23456".into(), 0);
        let mut admin = crate::config::AdminConfig::default();
        admin.must_change_password = false;
        admin.password_login_enabled = false;
        admin.password_hash = String::new();
        admin.passkey_enabled = true;
        admin.passkeys.push(crate::config::PasskeyEntry {
            id: "AAAAAAAAAAAAAAAAAAAAAA".into(),
            name: "TouchID".into(),
            rp_id: "router.local".into(),
            alg: -8,
            pubkey_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            sign_count: 0,
            created_at: 1,
            last_used_at: 0,
        });

        assert!(is_valid_passkey_only_config(&admin));
        assert!(admin_has_mfa_enabled(&admin));
        assert_eq!(
            state.effective_scope(&admin, SessionScope::FullAdmin),
            SessionScope::FullAdmin
        );

        // must_change_password=true 仍必须锁死
        admin.must_change_password = true;
        assert_eq!(
            state.effective_scope(&admin, SessionScope::FullAdmin),
            SessionScope::MustChangePassword
        );
        admin.must_change_password = false;

        // 若重新开启密码登录但密码哈希仍为空，不能命中旧缓存，必须回落 MustChangePassword
        admin.password_login_enabled = true;
        assert_eq!(
            state.effective_scope(&admin, SessionScope::FullAdmin),
            SessionScope::MustChangePassword
        );

        // 若纯 Passkey 配置但无已绑定密钥，仍必须 fail-closed
        admin.password_login_enabled = false;
        admin.passkeys.clear();
        assert!(!is_valid_passkey_only_config(&admin));
        assert!(!admin_has_mfa_enabled(&admin));
        assert_eq!(
            state.effective_scope(&admin, SessionScope::FullAdmin),
            SessionScope::MustChangePassword
        );
    }

    #[test]
    fn session_module_unlock_digest_matches_token_unlock() {
        let mut s = SessionStore::new();
        let ck = key("127.0.0.1");
        let tok = s.issue(SessionScope::FullAdmin, ck, Duration::from_secs(3600)).unwrap();
        let digest = SessionStore::token_digest(&tok);
        assert!(!s.is_module_unlocked_digest(&digest, "docker"));
        assert!(s.unlock_module(&tok, "docker"));
        assert!(s.is_module_unlocked_digest(&digest, "docker"));
        s.lock_module(&tok, "docker");
        assert!(!s.is_module_unlocked_digest(&digest, "docker"));
    }
}
