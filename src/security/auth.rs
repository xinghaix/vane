#![allow(deprecated)]
//! 单管理员多模态强认证：PBKDF2 口令（受限 spawn_blocking）、初始密码硬拦截、
//! 单调水位 TOTP 防回退重放、OpenSSH Ed25519 绑定挑战验签与会话管理。
use crate::net::dual_stack::BanKey;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use base64::Engine;
use ring::rand::{SecureRandom, SystemRandom};
use ring::{constant_time, digest, hmac, pbkdf2, signature};
use std::collections::{HashMap, VecDeque};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

pub const DEFAULT_INITIAL_PASSWORD: &[u8] = b"admin321";
pub const DEFAULT_USERNAME: &str = "admin";
pub const PBKDF2_ITERS: u32 = 100_000;
const CHALLENGE_POOL_CAP: usize = 64;
const CHALLENGE_TTL: Duration = Duration::from_secs(60);
const MAX_SESSIONS: usize = 32;
/// 会话绝对生命周期上限：24 小时
const SESSION_ABSOLUTE_MAX: Duration = Duration::from_secs(86_400);
const HASH_QUEUE_LIMIT: usize = 4;

/// 登录会话权限作用域：未修改初始密码前强制锁死在 MustChangePassword，禁止进入任何管理页面 API
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SessionScope {
    MustChangePassword,
    FullAdmin,
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
        let permit = self.sem.acquire().await;
        self.waiting.fetch_sub(1, Ordering::SeqCst);
        let _permit = permit.map_err(|_| "认证队列已关闭")?;
        tokio::task::spawn_blocking(f).await.map_err(|_| "认证计算任务异常")
    }
}

// ---------------------------------------------------------------------------
// AuthEngine：口令策略 / TOTP / Ed25519 挑战
// ---------------------------------------------------------------------------

pub struct PendingChallenge {
    pub nonce: [u8; 32],
    pub key_id: String,
    pub client_key: BanKey,
    pub issued_at: Instant,
}

pub struct AuthEngine {
    challenges: VecDeque<PendingChallenge>,
    last_totp_step: Option<u64>, // 严格单调递增水位线：拒绝任何 <= last_totp_step 的动态码
    canonical_origin: String,    // 服务端固定受信 Origin，绝不采信客户端自报 Host
}

impl AuthEngine {
    pub fn new(canonical_origin: String) -> Self {
        Self { challenges: VecDeque::with_capacity(CHALLENGE_POOL_CAP), last_totp_step: None, canonical_origin }
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

    /// 3. 签发绑定上下文的一次性挑战（单管理员模型，按源 IP 限速，不驱逐未过期挑战）
    pub fn issue_challenge(&mut self, rng: &dyn SecureRandom, key_id: String, client_key: BanKey) -> Result<[u8; 32], &'static str> {
        while self.challenges.front().is_some_and(|c| c.issued_at.elapsed() > CHALLENGE_TTL) {
            self.challenges.pop_front();
        }
        if self.challenges.len() >= CHALLENGE_POOL_CAP {
            return Err("当前并发挑战过多，请稍后重试");
        }
        if self.challenges.iter().filter(|c| c.client_key == client_key).count() >= 3 {
            return Err("同一网络请求过于频繁");
        }
        let mut nonce = [0u8; 32];
        rng.fill(&mut nonce).map_err(|_| "硬件随机源生成失败")?;
        self.challenges.push_back(PendingChallenge { nonce, key_id, client_key, issued_at: Instant::now() });
        Ok(nonce)
    }

    /// 构造签名原文：vane-ed25519-auth-v1|<nonce>|<key_id>|<canonical_origin>
    pub fn challenge_message(&self, nonce: &[u8; 32], key_id: &str) -> Vec<u8> {
        let mut msg = Vec::with_capacity(128);
        msg.extend_from_slice(b"vane-ed25519-auth-v1|");
        msg.extend_from_slice(nonce);
        msg.push(b'|');
        msg.extend_from_slice(key_id.as_bytes());
        msg.push(b'|');
        msg.extend_from_slice(self.canonical_origin.as_bytes());
        msg
    }

    /// 4. 原子消费挑战并校验 Ed25519 签名（强制绑定 KeyID、源网络与服务端 Origin）
    pub fn verify_ed25519_challenge(
        &mut self,
        nonce: &[u8; 32],
        key_id: &str,
        client_key: BanKey,
        sig: &[u8],
        raw_ed25519_pubkey: &[u8; 32],
    ) -> bool {
        let Some(pos) = self.challenges.iter().position(|c| {
            c.issued_at.elapsed() <= CHALLENGE_TTL
                && c.client_key == client_key
                && c.key_id == key_id
                && constant_time::verify_slices_are_equal(&c.nonce, nonce).is_ok()
        }) else {
            return false;
        };
        self.challenges.remove(pos);
        let msg = self.challenge_message(nonce, key_id);
        let pk = signature::UnparsedPublicKey::new(&signature::ED25519, raw_ed25519_pubkey);
        pk.verify(&msg, sig).is_ok()
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

/// 从 OpenSSH ssh-ed25519 公钥 Wire Format 解码字节中提取精确的 32B 原始公钥
pub fn extract_ed25519_from_ssh_wire(wire_bytes: &[u8]) -> Option<[u8; 32]> {
    const PREFIX: &[u8] = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20";
    if wire_bytes.len() == 51 && wire_bytes.starts_with(PREFIX) {
        let mut out = [0u8; 32];
        out.copy_from_slice(&wire_bytes[19..51]);
        Some(out)
    } else {
        None
    }
}

/// 解析 "ssh-ed25519 AAAAC3... comment" 文本
pub fn parse_openssh_ed25519(text: &str) -> Option<[u8; 32]> {
    let mut parts = text.split_whitespace();
    if parts.next()? != "ssh-ed25519" {
        return None;
    }
    let wire = B64.decode(parts.next()?).ok()?;
    extract_ed25519_from_ssh_wire(&wire)
}

/// 将 32B 原始公钥编码为 OpenSSH 文本
pub fn encode_openssh_ed25519(raw: &[u8; 32], comment: &str) -> String {
    let mut wire = Vec::with_capacity(51);
    wire.extend_from_slice(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20");
    wire.extend_from_slice(raw);
    let mut s = format!("ssh-ed25519 {}", B64.encode(wire));
    if !comment.is_empty() {
        s.push(' ');
        s.push_str(comment);
    }
    s
}

/// 接受 OpenSSH 文本或 base64 原始 32B 公钥，统一规范化为 OpenSSH 文本
pub fn normalize_ed25519_pubkey(input: &str, comment: &str) -> Option<(String, [u8; 32])> {
    let t = input.trim();
    if let Some(raw) = parse_openssh_ed25519(t) {
        return Some((t.split_whitespace().take(3).collect::<Vec<_>>().join(" "), raw));
    }
    let bytes = B64.decode(t).or_else(|_| B64URL.decode(t)).ok()?;
    if bytes.len() == 32 {
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&bytes);
        return Some((encode_openssh_ed25519(&raw, comment), raw));
    }
    None
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
        self.sessions.insert(Self::token_digest(&token), Session { scope, created: now, last_seen: now, client_key });
        Ok(token)
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
    password_gate: Option<(String,SessionScope)>,
}

impl AuthState {
    pub fn effective_scope(&mut self,admin:&crate::config::AdminConfig,scope:SessionScope)->SessionScope {
        if admin.must_change_password{return SessionScope::MustChangePassword;}
        if self.password_gate.as_ref().is_none_or(|(hash,_)|hash!=&admin.password_hash){
            let gate=PasswordHash::parse(&admin.password_hash).map(|hash|AuthEngine::resolve_session_scope(false,&hash.salt,&hash.hash,hash.iters)).unwrap_or(SessionScope::MustChangePassword);
            self.password_gate=Some((admin.password_hash.clone(),gate));
        }
        if self.password_gate.as_ref().is_some_and(|(_,gate)|*gate==SessionScope::MustChangePassword){SessionScope::MustChangePassword}else{scope}
    }
    pub fn new(canonical_origin: String, totp_watermark: u64) -> Self {
        let mut engine = AuthEngine::new(canonical_origin);
        engine.restore_totp_watermark(totp_watermark);
        Self { engine, sessions: SessionStore::new(), pending_totp_secret: None, password_gate: None }
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
    fn ssh_wire_format_parsing() {
        let raw = [0x42u8; 32];
        let text = encode_openssh_ed25519(&raw, "admin@example");
        assert_eq!(parse_openssh_ed25519(&text), Some(raw));
        let wire = B64.decode(text.split_whitespace().nth(1).unwrap()).unwrap();
        assert_eq!(wire.len(), 51);
        assert_eq!(extract_ed25519_from_ssh_wire(&wire), Some(raw));
        let mut bad = wire.clone();
        bad[4] = b'x';
        assert!(extract_ed25519_from_ssh_wire(&bad).is_none());
        assert!(extract_ed25519_from_ssh_wire(&wire[..50]).is_none());
        assert!(parse_openssh_ed25519("ssh-rsa AAAAB3Nza").is_none());
        let (norm, r) = normalize_ed25519_pubkey(&B64.encode(raw), "k1").unwrap();
        assert_eq!(r, raw);
        assert!(norm.starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5"));
    }

    #[test]
    fn ed25519_challenge_binding() {
        let rng = SystemRandom::new();
        let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        use ring::signature::KeyPair;
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(kp.public_key().as_ref());

        let mut e = AuthEngine::new("https://192.168.1.1:23456".into());
        let client = key("192.168.1.20");
        let nonce = e.issue_challenge(&rng, "k1".into(), client).unwrap();
        let sig = kp.sign(&e.challenge_message(&nonce, "k1"));

        // 错误源网络 / 错误 key_id 均拒绝，且不消费挑战
        assert!(!e.verify_ed25519_challenge(&nonce, "k1", key("192.168.1.21"), sig.as_ref(), &pubkey));
        assert!(!e.verify_ed25519_challenge(&nonce, "k2", client, sig.as_ref(), &pubkey));
        // 正确验签成功并一次性消费
        assert!(e.verify_ed25519_challenge(&nonce, "k1", client, sig.as_ref(), &pubkey));
        assert!(!e.verify_ed25519_challenge(&nonce, "k1", client, sig.as_ref(), &pubkey));

        // 绑定 canonical_origin：针对其他 Origin 的签名无效
        let nonce2 = e.issue_challenge(&rng, "k1".into(), client).unwrap();
        let mut other = AuthEngine::new("https://evil.example".into());
        let bad_sig = kp.sign(&other.challenge_message(&nonce2, "k1"));
        let _ = other.issue_challenge(&rng, "k1".into(), client);
        assert!(!e.verify_ed25519_challenge(&nonce2, "k1", client, bad_sig.as_ref(), &pubkey));

        // 同源限速：每个源网络最多 3 个未完成挑战
        let mut e2 = AuthEngine::new("o".into());
        for _ in 0..3 {
            e2.issue_challenge(&rng, "k".into(), client).unwrap();
        }
        assert!(e2.issue_challenge(&rng, "k".into(), client).is_err());
        assert!(e2.issue_challenge(&rng, "k".into(), key("2001:db8::1")).is_ok());
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

    #[test]
    fn recovery_codes_format() {
        let c = generate_recovery_codes(8).unwrap();
        assert_eq!(c.len(), 8);
        assert_eq!(normalize_recovery_code(&c[0]).len(), 16);
    }
}
