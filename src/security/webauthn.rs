//! 纯 Rust W3C WebAuthn (Passkey / FIDO2) 注册与认证验签引擎：
//! 零外部新增依赖，基于 `ring` 实现 ES256 (ECDSA P-256) 与 EdDSA (Ed25519) 验签、
//! 严格有界 CBOR 解码、RP ID Hash 核验、UP+UV 用户验证标志、单调 signCount 克隆检测
//! 以及绑定 Origin/RP ID/用途/源网段的 60 秒一次性挑战池。
use crate::config::PasskeyEntry;
use crate::net::dual_stack::BanKey;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use ring::rand::{SecureRandom, SystemRandom};
#[allow(deprecated)]
use ring::constant_time;
use ring::{digest, signature};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[allow(deprecated)]
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    constant_time::verify_slices_are_equal(a, b).is_ok()
}

const CHALLENGE_POOL_CAP: usize = 64;
const CHALLENGE_PER_PEER_CAP: usize = 4;
const CHALLENGE_TTL: Duration = Duration::from_secs(60);
const MAX_CBOR_BYTES: usize = 16 * 1024;
const MAX_CBOR_DEPTH: usize = 6;
pub const COSE_ALG_ES256: i32 = -7;
pub const COSE_ALG_EDDSA: i32 = -8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WebAuthnPurpose {
    Register,
    Login,
    Reauth([u8; 32]),
}

pub struct PendingWebAuthnChallenge {
    pub challenge_b64: String,
    pub purpose: WebAuthnPurpose,
    pub origin: String,
    pub rp_id: String,
    pub peer: BanKey,
    pub issued_at: Instant,
    /// 标记签发该挑战前是否已完成二次身份验证（用于将 Reauth 状态绑定至 60s 通行密钥注册挑战）
    pub reauth_verified: bool,
    /// 可选绑定的管理员会话摘要（防同网段其他会话窃取注册挑战）
    pub bound_session: Option<[u8; 32]>,
}

#[derive(Default)]
pub struct WebAuthnChallengeStore {
    entries: VecDeque<PendingWebAuthnChallenge>,
}

impl WebAuthnChallengeStore {
    pub fn issue(
        &mut self,
        purpose: WebAuthnPurpose,
        origin: String,
        rp_id: String,
        peer: BanKey,
    ) -> Result<String, &'static str> {
        self.issue_with_reauth(purpose, origin, rp_id, peer, false, None)
    }

    pub fn issue_with_reauth(
        &mut self,
        purpose: WebAuthnPurpose,
        origin: String,
        rp_id: String,
        peer: BanKey,
        reauth_verified: bool,
        bound_session: Option<[u8; 32]>,
    ) -> Result<String, &'static str> {
        let now = Instant::now();
        while self
            .entries
            .front()
            .is_some_and(|e| now.duration_since(e.issued_at) > CHALLENGE_TTL)
        {
            self.entries.pop_front();
        }
        if self.entries.len() >= CHALLENGE_POOL_CAP {
            return Err("当前通行密钥认证请求过多，请稍后重试");
        }
        if self.entries.iter().filter(|e| e.peer == peer).count() >= CHALLENGE_PER_PEER_CAP {
            return Err("同一网络通行密钥请求过于频繁");
        }
        let mut raw = [0u8; 32];
        SystemRandom::new()
            .fill(&mut raw)
            .map_err(|_| "硬件随机源生成挑战失败")?;
        let challenge_b64 = B64URL.encode(raw);
        self.entries.push_back(PendingWebAuthnChallenge {
            challenge_b64: challenge_b64.clone(),
            purpose,
            origin,
            rp_id,
            peer,
            issued_at: now,
            reauth_verified,
            bound_session,
        });
        Ok(challenge_b64)
    }

    /// 签发绑定二次验证状态的 60 秒 Passkey 注册挑战。
    pub fn create_registration_challenge_with_reauth(
        &mut self,
        origin: String,
        rp_id: String,
        peer: BanKey,
        reauth_verified: bool,
    ) -> Result<String, &'static str> {
        self.issue_with_reauth(
            WebAuthnPurpose::Register,
            origin,
            rp_id,
            peer,
            reauth_verified,
            None,
        )
    }

    /// 签发同时绑定管理员会话摘要与二次验证状态的 60 秒 Passkey 注册挑战。
    pub fn create_session_registration_challenge_with_reauth(
        &mut self,
        origin: String,
        rp_id: String,
        peer: BanKey,
        session_digest: [u8; 32],
        reauth_verified: bool,
    ) -> Result<String, &'static str> {
        self.issue_with_reauth(
            WebAuthnPurpose::Register,
            origin,
            rp_id,
            peer,
            reauth_verified,
            Some(session_digest),
        )
    }

    /// 一次性核销匹配挑战（按用途、Origin、RP ID、源网段四重绑定；拒绝未校验会话的会话绑定挑战）。
    pub fn consume(
        &mut self,
        challenge_b64: &str,
        purpose: &WebAuthnPurpose,
        origin: &str,
        rp_id: &str,
        peer: BanKey,
    ) -> Option<PendingWebAuthnChallenge> {
        let now = Instant::now();
        self.entries
            .retain(|e| now.duration_since(e.issued_at) <= CHALLENGE_TTL);
        let idx = self.entries.iter().position(|e| {
            e.bound_session.is_none()
                && e.purpose == *purpose
                && e.origin == origin
                && e.rp_id == rp_id
                && e.peer == peer
                && ct_eq(e.challenge_b64.as_bytes(), challenge_b64.as_bytes())
        })?;
        self.entries.remove(idx)
    }

    /// 一次性核销绑定会话摘要的挑战（按用途、Origin、RP ID、源网段与会话摘要五重绑定）。
    pub fn consume_for_session(
        &mut self,
        challenge_b64: &str,
        purpose: &WebAuthnPurpose,
        origin: &str,
        rp_id: &str,
        peer: BanKey,
        session_digest: [u8; 32],
    ) -> Option<PendingWebAuthnChallenge> {
        let now = Instant::now();
        self.entries
            .retain(|e| now.duration_since(e.issued_at) <= CHALLENGE_TTL);
        let idx = self.entries.iter().position(|e| {
            e.bound_session
                .is_some_and(|bound| ct_eq(&bound, &session_digest))
                && e.purpose == *purpose
                && e.origin == origin
                && e.rp_id == rp_id
                && e.peer == peer
                && ct_eq(e.challenge_b64.as_bytes(), challenge_b64.as_bytes())
        })?;
        self.entries.remove(idx)
    }
}

/// 从已通过可信边界校验的 HTTPS Origin 提取合法 WebAuthn RP ID（拒绝纯 IPv4/IPv6 地址）。
pub fn extract_rp_id_from_origin(origin: &str) -> Result<String, String> {
    let uri: http::Uri = origin
        .trim()
        .parse()
        .map_err(|_| "Origin 格式非法".to_string())?;
    if uri.scheme_str() != Some("https") {
        return Err("通行密钥要求通过 HTTPS 访问".into());
    }
    let host = uri
        .host()
        .ok_or_else(|| "Origin 缺少主机名".to_string())?
        .trim_matches(['[', ']'])
        .to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 {
        return Err("通行密钥域名长度非法".into());
    }
    if host.parse::<IpAddr>().is_ok() {
        return Err(
            "浏览器 WebAuthn 规范不支持纯 IP 地址，请改用域名访问（如 https://localhost:23456 或已配置域名）"
                .into(),
        );
    }
    if !host
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        || host.starts_with('.')
        || host.ends_with('.')
        || host.contains("..")
    {
        return Err("通行密钥 RP ID 主机名非法".into());
    }
    Ok(host)
}

pub fn decode_b64url_flexible(s: &str) -> Result<Vec<u8>, String> {
    let trimmed = s.trim().trim_end_matches('=');
    B64URL
        .decode(trimmed)
        .map_err(|_| "Base64URL 解码失败".to_string())
}

pub fn validate_passkey_entry(entry: &PasskeyEntry) -> Result<(), String> {
    if entry.name.trim().is_empty() || entry.name.len() > 64 {
        return Err("passkeys.name 长度需在 1 ~ 64 之间".into());
    }
    let id_bytes = decode_b64url_flexible(&entry.id).map_err(|_| "passkeys.id 非法 Base64URL")?;
    if id_bytes.len() < 16 || id_bytes.len() > 1024 {
        return Err("passkeys.id 长度非法（需 16 ~ 1024 字节）".into());
    }
    let rp_ok = !entry.rp_id.is_empty()
        && entry.rp_id.len() <= 253
        && entry.rp_id.parse::<IpAddr>().is_err()
        && entry
            .rp_id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.');
    if !rp_ok {
        return Err(format!("passkeys.rp_id 非法: {}", entry.rp_id));
    }
    let pk = decode_b64url_flexible(&entry.pubkey_b64).map_err(|_| "passkeys.pubkey_b64 非法")?;
    match entry.alg {
        COSE_ALG_ES256 => {
            if pk.len() != 65 || pk[0] != 0x04 {
                return Err("ES256 通行密钥公钥必须是 65 字节非压缩 P-256 点".into());
            }
        }
        COSE_ALG_EDDSA => {
            if pk.len() != 32 {
                return Err("EdDSA 通行密钥公钥必须是 32 字节 Ed25519 公钥".into());
            }
        }
        other => return Err(format!("不支持的通行密钥 COSE 算法: {}", other)),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 严格有界 CBOR 解码器（仅用于解析 WebAuthn attestationObject 与 COSE_Key）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum CborVal {
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CborVal>),
    Map(Vec<(CborVal, CborVal)>),
    Bool(bool),
    Null,
}

impl CborVal {
    fn as_map(&self) -> Option<&[(CborVal, CborVal)]> {
        match self {
            CborVal::Map(m) => Some(m),
            _ => None,
        }
    }

    fn map_get_text(&self, key: &str) -> Option<&CborVal> {
        self.as_map()?
            .iter()
            .find(|(k, _)| matches!(k, CborVal::Text(t) if t == key))
            .map(|(_, v)| v)
    }

    fn map_get_int(&self, key: i64) -> Option<&CborVal> {
        self.as_map()?
            .iter()
            .find(|(k, _)| matches!(k, CborVal::Int(i) if *i == key))
            .map(|(_, v)| v)
    }

    fn as_int(&self) -> Option<i64> {
        match self {
            CborVal::Int(v) => Some(*v),
            _ => None,
        }
    }

    fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            CborVal::Bytes(b) => Some(b),
            _ => None,
        }
    }
}

fn read_cbor_u64(data: &[u8], pos: &mut usize, ai: u8) -> Result<u64, String> {
    match ai {
        0..=23 => Ok(ai as u64),
        24 => {
            if *pos >= data.len() {
                return Err("CBOR 截断".into());
            }
            let v = data[*pos] as u64;
            *pos += 1;
            Ok(v)
        }
        25 => {
            if *pos + 2 > data.len() {
                return Err("CBOR 截断".into());
            }
            let v = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as u64;
            *pos += 2;
            Ok(v)
        }
        26 => {
            if *pos + 4 > data.len() {
                return Err("CBOR 截断".into());
            }
            let v = u32::from_be_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]) as u64;
            *pos += 4;
            Ok(v)
        }
        27 => {
            if *pos + 8 > data.len() {
                return Err("CBOR 截断".into());
            }
            let mut b = [0u8; 8];
            b.copy_from_slice(&data[*pos..*pos + 8]);
            *pos += 8;
            Ok(u64::from_be_bytes(b))
        }
        _ => Err("不支持的不定长或非法 CBOR 编码".into()),
    }
}

fn decode_cbor_item(data: &[u8], pos: &mut usize, depth: usize) -> Result<CborVal, String> {
    if depth > MAX_CBOR_DEPTH {
        return Err("CBOR 嵌套深度超限".into());
    }
    if *pos >= data.len() {
        return Err("CBOR 数据意外结束".into());
    }
    let first = data[*pos];
    *pos += 1;
    let major = first >> 5;
    let ai = first & 0x1f;
    match major {
        0 => {
            let n = read_cbor_u64(data, pos, ai)?;
            let i = i64::try_from(n).map_err(|_| "CBOR 正整数溢出".to_string())?;
            Ok(CborVal::Int(i))
        }
        1 => {
            let n = read_cbor_u64(data, pos, ai)?;
            let i = i64::try_from(n).map_err(|_| "CBOR 负整数溢出".to_string())?;
            let neg = (-1i64).checked_sub(i).ok_or_else(|| "CBOR 负整数下溢".to_string())?;
            Ok(CborVal::Int(neg))
        }
        2 => {
            let len = usize::try_from(read_cbor_u64(data, pos, ai)?).map_err(|_| "CBOR 字节串过长")?;
            if len > MAX_CBOR_BYTES || *pos + len > data.len() {
                return Err("CBOR 字节串越界".into());
            }
            let out = data[*pos..*pos + len].to_vec();
            *pos += len;
            Ok(CborVal::Bytes(out))
        }
        3 => {
            let len = usize::try_from(read_cbor_u64(data, pos, ai)?).map_err(|_| "CBOR 文本过长")?;
            if len > MAX_CBOR_BYTES || *pos + len > data.len() {
                return Err("CBOR 文本越界".into());
            }
            let s = std::str::from_utf8(&data[*pos..*pos + len])
                .map_err(|_| "CBOR 文本 UTF-8 非法")?
                .to_string();
            *pos += len;
            Ok(CborVal::Text(s))
        }
        4 => {
            let count = usize::try_from(read_cbor_u64(data, pos, ai)?).map_err(|_| "CBOR 数组过大")?;
            if count > 256 {
                return Err("CBOR 数组元素数超限".into());
            }
            let mut arr = Vec::with_capacity(count);
            for _ in 0..count {
                arr.push(decode_cbor_item(data, pos, depth + 1)?);
            }
            Ok(CborVal::Array(arr))
        }
        5 => {
            let count = usize::try_from(read_cbor_u64(data, pos, ai)?).map_err(|_| "CBOR Map 过大")?;
            if count > 128 {
                return Err("CBOR Map 键数超限".into());
            }
            let mut entries = Vec::with_capacity(count);
            for _ in 0..count {
                let k = decode_cbor_item(data, pos, depth + 1)?;
                let v = decode_cbor_item(data, pos, depth + 1)?;
                entries.push((k, v));
            }
            Ok(CborVal::Map(entries))
        }
        6 => {
            // CBOR Tag：跳过 tag 编号，递归解析内容
            let _ = read_cbor_u64(data, pos, ai)?;
            decode_cbor_item(data, pos, depth + 1)
        }
        7 => match ai {
            20 => Ok(CborVal::Bool(false)),
            21 => Ok(CborVal::Bool(true)),
            22 | 23 => Ok(CborVal::Null),
            _ => Err("不支持的 CBOR 简单值或浮点类型".into()),
        },
        _ => Err("未知 CBOR 主类型".into()),
    }
}

fn decode_cbor_exact(data: &[u8]) -> Result<CborVal, String> {
    if data.len() > MAX_CBOR_BYTES {
        return Err("CBOR 负载超过大小上限".into());
    }
    let mut pos = 0;
    let val = decode_cbor_item(data, &mut pos, 0)?;
    if pos != data.len() {
        return Err("CBOR 末尾存在非法尾随字节".into());
    }
    Ok(val)
}

fn decode_cbor_prefix(data: &[u8]) -> Result<(CborVal, usize), String> {
    if data.len() > MAX_CBOR_BYTES {
        return Err("CBOR 负载超过大小上限".into());
    }
    let mut pos = 0;
    let val = decode_cbor_item(data, &mut pos, 0)?;
    Ok((val, pos))
}

// ---------------------------------------------------------------------------
// clientDataJSON / authData / COSE_Key 校验
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: Option<bool>,
}

fn verify_client_data(
    client_data_bytes: &[u8],
    expected_type: &str,
    expected_challenge: &str,
    expected_origin: &str,
) -> Result<(), String> {
    if client_data_bytes.len() > 4096 {
        return Err("clientDataJSON 过长".into());
    }
    let cd: ClientData = serde_json::from_slice(client_data_bytes)
        .map_err(|_| "clientDataJSON 解析失败".to_string())?;
    if cd.kind != expected_type {
        return Err(format!("WebAuthn 类型不匹配: {}", cd.kind));
    }
    if !ct_eq(
        cd.challenge.trim_end_matches('=').as_bytes(),
        expected_challenge.trim_end_matches('=').as_bytes(),
    ) {
        return Err("WebAuthn 挑战值不匹配".into());
    }
    if cd.origin != expected_origin {
        return Err("WebAuthn Origin 不匹配".into());
    }
    if cd.cross_origin == Some(true) {
        return Err("拒绝跨站 iframe 通行密钥请求".into());
    }
    Ok(())
}

fn verify_rp_id_hash(auth_data: &[u8], rp_id: &str) -> Result<(), String> {
    if auth_data.len() < 37 {
        return Err("authenticatorData 长度不足 37 字节".into());
    }
    let expected = digest::digest(&digest::SHA256, rp_id.as_bytes());
    if !ct_eq(&auth_data[..32], expected.as_ref()) {
        return Err("RP ID 哈希校验失败（防跨站钓鱼）".into());
    }
    Ok(())
}

fn parse_cose_public_key(cose: &CborVal) -> Result<(i32, Vec<u8>), String> {
    let kty = cose.map_get_int(1).and_then(CborVal::as_int).ok_or("COSE_Key 缺少 kty")?;
    let alg = cose.map_get_int(3).and_then(CborVal::as_int).ok_or("COSE_Key 缺少 alg")?;
    let crv = cose.map_get_int(-1).and_then(CborVal::as_int).ok_or("COSE_Key 缺少 crv")?;

    if kty == 2 && alg == COSE_ALG_ES256 as i64 && crv == 1 {
        let x = cose.map_get_int(-2).and_then(CborVal::as_bytes).ok_or("ES256 公钥缺少 X 坐标")?;
        let y = cose.map_get_int(-3).and_then(CborVal::as_bytes).ok_or("ES256 公钥缺少 Y 坐标")?;
        if x.len() != 32 || y.len() != 32 {
            return Err("ES256 公钥坐标长度必须为 32 字节".into());
        }
        let mut sec1 = Vec::with_capacity(65);
        sec1.push(0x04);
        sec1.extend_from_slice(x);
        sec1.extend_from_slice(y);
        Ok((COSE_ALG_ES256, sec1))
    } else if kty == 1 && alg == COSE_ALG_EDDSA as i64 && crv == 6 {
        let x = cose.map_get_int(-2).and_then(CborVal::as_bytes).ok_or("Ed25519 公钥缺少 X")?;
        if x.len() != 32 {
            return Err("Ed25519 公钥长度必须为 32 字节".into());
        }
        Ok((COSE_ALG_EDDSA, x.to_vec()))
    } else {
        Err(format!("不支持的通行密钥算法 (kty={kty}, alg={alg}, crv={crv})，仅支持 ES256(P-256) 与 Ed25519"))
    }
}

/// 校验浏览器 `navigator.credentials.create` 返回的注册凭据并生成 `PasskeyEntry`。
pub fn verify_registration(
    expected_challenge: &str,
    expected_origin: &str,
    expected_rp_id: &str,
    client_data_b64: &str,
    attestation_object_b64: &str,
    name: &str,
    now_unix: u64,
) -> Result<PasskeyEntry, String> {
    let clean_name = name.trim();
    if clean_name.is_empty() || clean_name.len() > 64 {
        return Err("通行密钥名称长度需在 1 ~ 64 之间".into());
    }
    let client_data = decode_b64url_flexible(client_data_b64)?;
    verify_client_data(&client_data, "webauthn.create", expected_challenge, expected_origin)?;

    let att_bytes = decode_b64url_flexible(attestation_object_b64)?;
    let att_cbor = decode_cbor_exact(&att_bytes)?;
    let auth_data = att_cbor
        .map_get_text("authData")
        .and_then(CborVal::as_bytes)
        .ok_or("attestationObject 缺少 authData")?;

    verify_rp_id_hash(auth_data, expected_rp_id)?;
    let flags = auth_data[32];
    let up = (flags & 0x01) != 0;
    let uv = (flags & 0x04) != 0;
    let at = (flags & 0x40) != 0;
    if !up || !uv {
        return Err("通行密钥注册需要完成用户本地验证（生物识别/设备锁/密码器确认）".into());
    }
    if !at || auth_data.len() < 55 {
        return Err("attestation 缺少认证凭据数据".into());
    }

    let sign_count = u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
    let cred_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    if !(16..=1024).contains(&cred_len) || 55 + cred_len >= auth_data.len() {
        return Err("通行密钥 Credential ID 长度非法".into());
    }
    let cred_id = &auth_data[55..55 + cred_len];
    let cose_slice = &auth_data[55 + cred_len..];
    let (cose_val, _consumed) = decode_cbor_prefix(cose_slice)?;
    let (alg, pubkey_raw) = parse_cose_public_key(&cose_val)?;

    let entry = PasskeyEntry {
        id: B64URL.encode(cred_id),
        name: clean_name.to_string(),
        rp_id: expected_rp_id.to_string(),
        alg,
        pubkey_b64: B64URL.encode(&pubkey_raw),
        sign_count,
        created_at: now_unix,
        last_used_at: 0,
    };
    validate_passkey_entry(&entry)?;
    Ok(entry)
}

/// 校验浏览器 `navigator.credentials.get` 返回的断言签名（用于登录与敏感操作二次验证）。
/// 返回 `(匹配条目索引, 新 sign_count)`。
pub fn verify_assertion(
    expected_challenge: &str,
    expected_origin: &str,
    expected_rp_id: &str,
    passkeys: &[PasskeyEntry],
    credential_id_b64: &str,
    client_data_b64: &str,
    authenticator_data_b64: &str,
    signature_b64: &str,
) -> Result<(usize, u32), String> {
    let client_data = decode_b64url_flexible(client_data_b64)?;
    verify_client_data(&client_data, "webauthn.get", expected_challenge, expected_origin)?;

    let cred_id_norm = credential_id_b64.trim().trim_end_matches('=');
    let (idx, entry) = passkeys
        .iter()
        .enumerate()
        .find(|(_, p)| p.id.trim_end_matches('=') == cred_id_norm)
        .ok_or_else(|| "未找到匹配的已注册通行密钥".to_string())?;
    if entry.rp_id != expected_rp_id {
        return Err("通行密钥所属域名 (RP ID) 与当前访问地址不匹配".into());
    }

    let auth_data = decode_b64url_flexible(authenticator_data_b64)?;
    verify_rp_id_hash(&auth_data, &entry.rp_id)?;
    let flags = auth_data[32];
    let up = (flags & 0x01) != 0;
    let uv = (flags & 0x04) != 0;
    if !up || !uv {
        return Err("通行密钥未完成用户本地身份核验 (UP/UV)".into());
    }

    let new_sign_count = u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
    // 按 W3C WebAuthn §7.2 检测验证器克隆：非零计数器必须严格递增；同步通行密钥双方均为 0 时允许通过。
    if (entry.sign_count > 0 || new_sign_count > 0) && new_sign_count <= entry.sign_count {
        return Err("通行密钥签名计数器未递增，疑似重放或克隆设备，已拒绝".into());
    }

    let sig_bytes = decode_b64url_flexible(signature_b64)?;
    if sig_bytes.is_empty() || sig_bytes.len() > 256 {
        return Err("通行密钥签名长度非法".into());
    }
    let pubkey_bytes = decode_b64url_flexible(&entry.pubkey_b64)?;

    let client_hash = digest::digest(&digest::SHA256, &client_data);
    let mut signed_payload = Vec::with_capacity(auth_data.len() + 32);
    signed_payload.extend_from_slice(&auth_data);
    signed_payload.extend_from_slice(client_hash.as_ref());

    match entry.alg {
        COSE_ALG_ES256 => {
            let pk = signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, &pubkey_bytes);
            pk.verify(&signed_payload, &sig_bytes)
                .map_err(|_| "ES256 通行密钥签名验证失败".to_string())?;
        }
        COSE_ALG_EDDSA => {
            let pk = signature::UnparsedPublicKey::new(&signature::ED25519, &pubkey_bytes);
            pk.verify(&signed_payload, &sig_bytes)
                .map_err(|_| "Ed25519 通行密钥签名验证失败".to_string())?;
        }
        other => return Err(format!("不支持的通行密钥算法: {}", other)),
    }

    Ok((idx, new_sign_count))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair};

    fn cbor_uint(major: u8, n: u64, out: &mut Vec<u8>) {
        let prefix = major << 5;
        if n <= 23 {
            out.push(prefix | (n as u8));
        } else if n <= 0xff {
            out.push(prefix | 24);
            out.push(n as u8);
        } else if n <= 0xffff {
            out.push(prefix | 25);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        } else {
            out.push(prefix | 26);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
    }

    fn cbor_int(v: i64, out: &mut Vec<u8>) {
        if v >= 0 {
            cbor_uint(0, v as u64, out);
        } else {
            cbor_uint(1, (-1 - v) as u64, out);
        }
    }

    fn cbor_bytes(b: &[u8], out: &mut Vec<u8>) {
        cbor_uint(2, b.len() as u64, out);
        out.extend_from_slice(b);
    }

    fn cbor_text(s: &str, out: &mut Vec<u8>) {
        cbor_uint(3, s.len() as u64, out);
        out.extend_from_slice(s.as_bytes());
    }

    fn build_attestation_object(rp_id: &str, flags: u8, sign_count: u32, cred_id: &[u8], cose_key: &[u8]) -> Vec<u8> {
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(digest::digest(&digest::SHA256, rp_id.as_bytes()).as_ref());
        auth_data.push(flags);
        auth_data.extend_from_slice(&sign_count.to_be_bytes());
        auth_data.extend_from_slice(&[0u8; 16]); // AAGUID
        auth_data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(cred_id);
        auth_data.extend_from_slice(cose_key);

        let mut obj = Vec::new();
        cbor_uint(5, 3, &mut obj);
        cbor_text("fmt", &mut obj);
        cbor_text("none", &mut obj);
        cbor_text("attStmt", &mut obj);
        cbor_uint(5, 0, &mut obj);
        cbor_text("authData", &mut obj);
        cbor_bytes(&auth_data, &mut obj);
        obj
    }

    #[test]
    fn es256_and_ed25519_passkey_register_and_verify_with_clone_and_origin_protection() {
        let rng = SystemRandom::new();
        let origin = "https://localhost:23456";
        let rp_id = extract_rp_id_from_origin(origin).unwrap();
        assert_eq!(rp_id, "localhost");
        assert!(extract_rp_id_from_origin("https://192.168.1.1:23456").is_err());
        assert!(extract_rp_id_from_origin("http://localhost:23456").is_err());

        // 1) ES256 (P-256) 注册 + 登录验证
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        let pub_bytes = kp.public_key().as_ref();
        assert_eq!(pub_bytes.len(), 65);
        assert_eq!(pub_bytes[0], 0x04);

        let mut cose = Vec::new();
        cbor_uint(5, 5, &mut cose);
        cbor_int(1, &mut cose); cbor_int(2, &mut cose);   // kty: EC2
        cbor_int(3, &mut cose); cbor_int(-7, &mut cose);  // alg: ES256
        cbor_int(-1, &mut cose); cbor_int(1, &mut cose);  // crv: P-256
        cbor_int(-2, &mut cose); cbor_bytes(&pub_bytes[1..33], &mut cose);
        cbor_int(-3, &mut cose); cbor_bytes(&pub_bytes[33..65], &mut cose);

        let cred_id = [0x42u8; 32];
        let challenge = B64URL.encode([0x11u8; 32]);
        let cd_create = serde_json::json!({
            "type": "webauthn.create",
            "challenge": challenge,
            "origin": origin,
            "crossOrigin": false
        })
        .to_string();
        let att_obj = build_attestation_object(&rp_id, 0x45, 1, &cred_id, &cose); // UP|UV|AT
        let mut entry = verify_registration(
            &challenge,
            origin,
            &rp_id,
            &B64URL.encode(cd_create.as_bytes()),
            &B64URL.encode(&att_obj),
            "MacBook Touch ID",
            1_700_000_000,
        )
        .unwrap();
        assert_eq!(entry.alg, COSE_ALG_ES256);
        assert_eq!(entry.sign_count, 1);

        // 构造真实断言签名（sign_count = 2）
        let login_ch = B64URL.encode([0x22u8; 32]);
        let cd_get = serde_json::json!({
            "type": "webauthn.get",
            "challenge": login_ch,
            "origin": origin,
            "crossOrigin": false
        })
        .to_string();
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(digest::digest(&digest::SHA256, rp_id.as_bytes()).as_ref());
        auth_data.push(0x05); // UP | UV
        auth_data.extend_from_slice(&2u32.to_be_bytes());
        let mut payload = auth_data.clone();
        payload.extend_from_slice(digest::digest(&digest::SHA256, cd_get.as_bytes()).as_ref());
        let sig = kp.sign(&rng, &payload).unwrap();

        let (idx, new_cnt) = verify_assertion(
            &login_ch,
            origin,
            &rp_id,
            &[entry.clone()],
            &entry.id,
            &B64URL.encode(cd_get.as_bytes()),
            &B64URL.encode(&auth_data),
            &B64URL.encode(sig.as_ref()),
        )
        .unwrap();
        assert_eq!(idx, 0);
        assert_eq!(new_cnt, 2);

        // 克隆/重放检测：sign_count 未递增必须拒绝
        entry.sign_count = 2;
        assert!(verify_assertion(
            &login_ch,
            origin,
            &rp_id,
            &[entry.clone()],
            &entry.id,
            &B64URL.encode(cd_get.as_bytes()),
            &B64URL.encode(&auth_data),
            &B64URL.encode(sig.as_ref()),
        )
        .is_err());

        // 2) Ed25519 (-8) 注册与断言校验（含 synced passkey sign_count=0）
        let ed_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let ed_kp = Ed25519KeyPair::from_pkcs8(ed_pkcs8.as_ref()).unwrap();
        let mut ed_cose = Vec::new();
        cbor_uint(5, 4, &mut ed_cose);
        cbor_int(1, &mut ed_cose); cbor_int(1, &mut ed_cose);   // kty: OKP
        cbor_int(3, &mut ed_cose); cbor_int(-8, &mut ed_cose);  // alg: EdDSA
        cbor_int(-1, &mut ed_cose); cbor_int(6, &mut ed_cose);  // crv: Ed25519
        cbor_int(-2, &mut ed_cose); cbor_bytes(ed_kp.public_key().as_ref(), &mut ed_cose);

        let ed_att = build_attestation_object(&rp_id, 0x45, 0, &[0x99u8; 24], &ed_cose);
        let ed_entry = verify_registration(
            &challenge,
            origin,
            &rp_id,
            &B64URL.encode(cd_create.as_bytes()),
            &B64URL.encode(&ed_att),
            "1Password",
            1_700_000_000,
        )
        .unwrap();
        assert_eq!(ed_entry.alg, COSE_ALG_EDDSA);

        let mut ed_auth = Vec::new();
        ed_auth.extend_from_slice(digest::digest(&digest::SHA256, rp_id.as_bytes()).as_ref());
        ed_auth.push(0x05);
        ed_auth.extend_from_slice(&0u32.to_be_bytes());
        let mut ed_payload = ed_auth.clone();
        ed_payload.extend_from_slice(digest::digest(&digest::SHA256, cd_get.as_bytes()).as_ref());
        let ed_sig = ed_kp.sign(&ed_payload);
        assert!(verify_assertion(
            &login_ch,
            origin,
            &rp_id,
            &[ed_entry.clone()],
            &ed_entry.id,
            &B64URL.encode(cd_get.as_bytes()),
            &B64URL.encode(&ed_auth),
            &B64URL.encode(ed_sig.as_ref()),
        )
        .is_ok());

        // 缺少 UV 标志 (仅 UP=0x01) 必须拒绝
        ed_auth[32] = 0x01;
        let mut no_uv_payload = ed_auth.clone();
        no_uv_payload.extend_from_slice(digest::digest(&digest::SHA256, cd_get.as_bytes()).as_ref());
        let no_uv_sig = ed_kp.sign(&no_uv_payload);
        assert!(verify_assertion(
            &login_ch,
            origin,
            &rp_id,
            &[ed_entry],
            &B64URL.encode([0x99u8; 24]),
            &B64URL.encode(cd_get.as_bytes()),
            &B64URL.encode(&ed_auth),
            &B64URL.encode(no_uv_sig.as_ref()),
        )
        .is_err());
    }

    #[test]
    fn registration_challenge_binds_reauth_and_optional_session() {
        let mut store = WebAuthnChallengeStore::default();
        let peer = BanKey::from_peer("192.0.2.55".parse().unwrap());
        let origin = "https://router.local:23456".to_string();
        let rp_id = "router.local".to_string();

        // 默认 issue 签发的挑战 reauth_verified 为 false
        let ch_plain = store
            .issue(WebAuthnPurpose::Register, origin.clone(), rp_id.clone(), peer)
            .unwrap();
        let consumed_plain = store
            .consume(&ch_plain, &WebAuthnPurpose::Register, &origin, &rp_id, peer)
            .unwrap();
        assert!(!consumed_plain.reauth_verified);
        assert!(consumed_plain.bound_session.is_none());

        // create_registration_challenge_with_reauth 正确绑定 reauth_verified=true 且一次性核销
        let ch_reauth = store
            .create_registration_challenge_with_reauth(origin.clone(), rp_id.clone(), peer, true)
            .unwrap();
        let consumed_reauth = store
            .consume(&ch_reauth, &WebAuthnPurpose::Register, &origin, &rp_id, peer)
            .unwrap();
        assert!(consumed_reauth.reauth_verified);
        assert!(store
            .consume(&ch_reauth, &WebAuthnPurpose::Register, &origin, &rp_id, peer)
            .is_none());

        // 会话绑定的注册挑战不能被普通 consume 或其他会话消费
        let sess_a = [0xAAu8; 32];
        let sess_b = [0xBBu8; 32];
        let ch_sess = store
            .create_session_registration_challenge_with_reauth(
                origin.clone(),
                rp_id.clone(),
                peer,
                sess_a,
                true,
            )
            .unwrap();
        assert!(store
            .consume(&ch_sess, &WebAuthnPurpose::Register, &origin, &rp_id, peer)
            .is_none());
        assert!(store
            .consume_for_session(&ch_sess, &WebAuthnPurpose::Register, &origin, &rp_id, peer, sess_b)
            .is_none());
        let consumed_sess = store
            .consume_for_session(&ch_sess, &WebAuthnPurpose::Register, &origin, &rp_id, peer, sess_a)
            .unwrap();
        assert!(consumed_sess.reauth_verified);
        assert_eq!(consumed_sess.bound_session, Some(sess_a));
    }
}
