//! 敏感字段信封加密（ChaCha20-Poly1305 + HKDF，字段路径作为 AAD）、自动加封、API 脱敏与跨机加密备份。
use crate::config::{encode_secret_segment, Config, UNCHANGED_SENTINEL};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use ring::{hkdf, pbkdf2};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{Read, Write};
use std::num::NonZeroU32;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub const ENC_PREFIX: &str = "enc:v1:";
pub const ENC_PREFIX_V2: &str = "enc:v2:";
const MASTER_KEY_FILE: &str = ".master.key";
const MAX_MASTER_KEY_FILE_BYTES: u64 = 4096;
const BACKUP_MAGIC: &[u8; 8] = b"VANEBAK1";
const BACKUP_MAGIC_V2: &[u8; 8] = b"VANEBAK2";
const BACKUP_PBKDF2_ITERS: u32 = 600_000;
const BACKUP_MAX_ITERS: u32 = 1_000_000;
const MAX_BACKUP_BYTES: usize = 16 * 1024 * 1024;
const MAX_BACKUP_FILES: usize = 256;
const MASK_MARKER: &str = "\u{0}__VANE_SECRET__:";

pub fn is_sealed_value(value: &str) -> bool {
    value.starts_with(ENC_PREFIX_V2) || value.starts_with(ENC_PREFIX)
}

fn v2_aad(field_path: &str) -> String {
    format!("v2:{}", field_path)
}

pub fn validate_backup_passphrase(password: &[u8]) -> Result<(), String> {
    if password.len() < 8 || password.len() > 128 {
        return Err("备份密码长度必须在 8 ~ 128 位之间".into());
    }
    let has_letter = password.iter().any(|b| b.is_ascii_alphabetic());
    let has_digit_or_symbol = password
        .iter()
        .any(|b| b.is_ascii_digit() || b.is_ascii_punctuation());
    if !has_letter || !has_digit_or_symbol {
        return Err("备份密码需包含英文字母，且至少包含数字或特殊字符中的一种".into());
    }
    Ok(())
}

fn zeroize_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: b 指向切片内有效可写字节
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

fn zeroize_string(s: &mut String) {
    // SAFETY: 清零底层缓冲区后立刻 clear()，不会在有效 UTF-8 之外暴露半截字符
    unsafe { zeroize_bytes(s.as_bytes_mut()) };
    s.clear();
}

/// 解密后的明文机密：Drop 时 write_volatile 逐字节清零，禁止 Debug/Display 打印明文
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(v: Vec<u8>) -> Self {
        Self(v)
    }
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
    pub fn expose_str(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap_or("")
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.0);
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(****)")
    }
}

/// 字段级 ChaCha20-Poly1305 信封加密：绑定字段路径作为 AAD 防止跨字段密文替换攻击
pub fn seal_field(dek: &[u8; 32], field_path: &str, plaintext: &[u8], rng: &dyn SecureRandom) -> Result<Vec<u8>, &'static str> {
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes).map_err(|_| "Nonce 生成失败")?;
    let unbound = UnboundKey::new(&aead::CHACHA20_POLY1305, dek).map_err(|_| "无效密钥")?;
    let key = LessSafeKey::new(unbound);
    let mut out = Vec::with_capacity(12 + plaintext.len() + 16);
    out.extend_from_slice(&nonce_bytes);
    let mut body = plaintext.to_vec();
    if key
        .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce_bytes), Aad::from(field_path.as_bytes()), &mut body)
        .is_err()
    {
        zeroize_bytes(&mut body);
        return Err("AEAD 加密失败");
    }
    out.extend_from_slice(&body);
    zeroize_bytes(&mut body);
    Ok(out)
}

pub fn open_field(dek: &[u8; 32], field_path: &str, sealed_nonce_and_cipher: &[u8]) -> Result<Vec<u8>, &'static str> {
    if sealed_nonce_and_cipher.len() < 12 + 16 {
        return Err("密文长度不足");
    }
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&sealed_nonce_and_cipher[..12]);
    let mut buf = sealed_nonce_and_cipher[12..].to_vec();
    let unbound = UnboundKey::new(&aead::CHACHA20_POLY1305, dek).map_err(|_| "无效密钥")?;
    let key = LessSafeKey::new(unbound);
    let plain_len = match key.open_in_place(
        Nonce::assume_unique_for_key(nonce_bytes),
        Aad::from(field_path.as_bytes()),
        &mut buf,
    ) {
        Ok(plain) => plain.len(),
        Err(_) => {
            zeroize_bytes(&mut buf);
            return Err("AEAD 解密或 AAD 字段路径校验失败");
        }
    };
    zeroize_bytes(&mut buf[plain_len..]);
    buf.truncate(plain_len);
    Ok(buf)
}

struct HkdfLen(usize);
impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// 由 32B 根密钥经 HKDF-SHA256 派生用途隔离的子密钥
pub fn hkdf_derive(root: &[u8], info: &[u8]) -> [u8; 32] {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"vane-hkdf-salt-v1");
    let prk = salt.extract(root);
    let info_arr = [info];
    let okm = prk.expand(&info_arr, HkdfLen(32)).expect("HKDF 输出长度合法");
    let mut out = [0u8; 32];
    okm.fill(&mut out).expect("HKDF 填充");
    out
}

pub struct Vault {
    dek: [u8; 32],
    /// 用于会话 Cookie / 入口 Cookie 等 HMAC 的派生密钥
    mac_key: [u8; 32],
    rng: SystemRandom,
}

impl Drop for Vault {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.dek);
        zeroize_bytes(&mut self.mac_key);
    }
}

fn read_master_key_file(path: &Path, tighten_to_0400: bool) -> Result<Vec<u8>, String> {
    let lmeta = fs::symlink_metadata(path).map_err(|e| format!("读取主密钥元数据失败: {}", e))?;
    if lmeta.file_type().is_symlink() {
        return Err(format!("拒绝读取符号链接主密钥文件: {}", path.display()));
    }
    if !lmeta.file_type().is_file() {
        return Err(format!("主密钥路径不是普通文件: {}", path.display()));
    }
    if lmeta.len() > MAX_MASTER_KEY_FILE_BYTES {
        return Err(format!("主密钥文件超过 {} 字节大小上限", MAX_MASTER_KEY_FILE_BYTES));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| format!("打开主密钥文件失败: {}", e))?;
    let fmeta = file.metadata().map_err(|e| format!("读取主密钥文件状态失败: {}", e))?;
    if !fmeta.is_file() {
        return Err(format!("主密钥路径不是普通文件: {}", path.display()));
    }
    if fmeta.len() > MAX_MASTER_KEY_FILE_BYTES {
        return Err(format!("主密钥文件超过 {} 字节大小上限", MAX_MASTER_KEY_FILE_BYTES));
    }
    let mode = fmeta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        if tighten_to_0400 {
            crate::log_warn!(
                "vault",
                "主密钥文件 {} 权限过宽（{:o}），将收紧为 0400",
                path.display(),
                mode
            );
            file.set_permissions(fs::Permissions::from_mode(0o400))
                .map_err(|e| format!("收紧主密钥文件权限失败: {}", e))?;
        } else {
            crate::log_warn!(
                "vault",
                "VANE_MASTER_KEY_FILE {} 权限过宽（{:o}），尝试收紧组与其他用户权限",
                path.display(),
                mode
            );
            let target_mode = (mode & 0o700).max(0o400);
            if file.set_permissions(fs::Permissions::from_mode(target_mode)).is_err() && (mode & 0o007 != 0) {
                return Err(format!(
                    "VANE_MASTER_KEY_FILE 权限对其他用户可见（{:o}）且无法收紧",
                    mode
                ));
            }
        }
    }
    let mut raw = Vec::new();
    file.take(MAX_MASTER_KEY_FILE_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|e| format!("读取主密钥失败: {}", e))?;
    if raw.len() as u64 > MAX_MASTER_KEY_FILE_BYTES {
        zeroize_bytes(&mut raw);
        return Err(format!("主密钥文件超过 {} 字节大小上限", MAX_MASTER_KEY_FILE_BYTES));
    }
    Ok(raw)
}

impl Vault {
    pub fn from_master(master: &[u8; 32]) -> Self {
        Self {
            dek: hkdf_derive(master, b"vane-config-dek-v1"),
            mac_key: hkdf_derive(master, b"vane-mac-key-v1"),
            rng: SystemRandom::new(),
        }
    }

    /// 加载或生成主密钥：优先环境变量 VANE_MASTER_KEY（base64/hex 32B），否则 <data_dir>/.master.key（0400）
    pub fn load_or_create(data_dir: &Path) -> Result<Self, String> {
        if let Ok(mut v) = std::env::var("VANE_MASTER_KEY") {
            let key_res = decode_key_text(v.trim()).ok_or_else(|| "VANE_MASTER_KEY 必须为 32 字节的 base64 或 hex 编码".to_string());
            zeroize_string(&mut v);
            let mut key = key_res?;
            let vault = Self::from_master(&key);
            zeroize_bytes(&mut key);
            return Ok(vault);
        }
        if let Ok(file) = std::env::var("VANE_MASTER_KEY_FILE") {
            let mut raw = read_master_key_file(Path::new(&file), false)?;
            let key_res = if raw.len() == 32 {
                let mut k = [0u8; 32];
                k.copy_from_slice(&raw);
                Ok(k)
            } else {
                let mut text = String::from_utf8(raw.clone()).map_err(|_| "VANE_MASTER_KEY_FILE 内容非法".to_string());
                let decoded = text
                    .as_deref()
                    .ok()
                    .and_then(|t| decode_key_text(t.trim()))
                    .ok_or_else(|| "VANE_MASTER_KEY_FILE 内容非法".to_string());
                if let Ok(ref mut t) = text {
                    zeroize_string(t);
                }
                decoded
            };
            zeroize_bytes(&mut raw);
            let mut key = key_res?;
            let vault = Self::from_master(&key);
            zeroize_bytes(&mut key);
            return Ok(vault);
        }
        let path = data_dir.join(MASTER_KEY_FILE);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                let mut raw = read_master_key_file(&path, true)?;
                let key_res = if raw.len() == 32 {
                    let mut k = [0u8; 32];
                    k.copy_from_slice(&raw);
                    Ok(k)
                } else {
                    let mut text = String::from_utf8(raw.clone()).map_err(|_| "主密钥文件内容非法".to_string());
                    let decoded = text
                        .as_deref()
                        .ok()
                        .and_then(|t| decode_key_text(t.trim()))
                        .ok_or_else(|| "主密钥文件内容非法".to_string());
                    if let Ok(ref mut t) = text {
                        zeroize_string(t);
                    }
                    decoded
                };
                zeroize_bytes(&mut raw);
                let mut key = key_res?;
                let vault = Self::from_master(&key);
                zeroize_bytes(&mut key);
                return Ok(vault);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("读取主密钥元数据失败: {}", e)),
        }
        let mut key = [0u8; 32];
        SystemRandom::new().fill(&mut key).map_err(|_| "硬件随机源生成主密钥失败")?;
        if !data_dir.exists() {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(data_dir)
                .map_err(|e| {
                    zeroize_bytes(&mut key);
                    format!("创建数据目录失败: {}", e)
                })?;
            let _ = fs::set_permissions(data_dir, fs::Permissions::from_mode(0o700));
        }
        let mut encoded = B64.encode(key);
        let write_res = (|| -> std::io::Result<()> {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o400)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&path)?;
            f.write_all(encoded.as_bytes())?;
            f.set_permissions(fs::Permissions::from_mode(0o400))?;
            f.sync_all()?;
            if let Ok(dir_fd) = fs::File::open(data_dir) {
                let _ = dir_fd.sync_all();
            }
            Ok(())
        })();
        zeroize_string(&mut encoded);
        if let Err(e) = write_res {
            let _ = fs::remove_file(&path);
            zeroize_bytes(&mut key);
            return Err(format!("写入主密钥失败: {}", e));
        }
        crate::log_info!("vault", "已生成新的主密钥 {}", path.display());
        let vault = Self::from_master(&key);
        zeroize_bytes(&mut key);
        Ok(vault)
    }

    pub fn rng(&self) -> &SystemRandom {
        &self.rng
    }

    pub fn mac_key(&self) -> &[u8; 32] {
        &self.mac_key
    }

    /// 使用无歧义 AAD（v2 域分离）加密为 enc:v2: 密文
    pub fn seal(&self, field_path: &str, plaintext: &[u8]) -> Result<String, String> {
        let aad = v2_aad(field_path);
        let sealed = seal_field(&self.dek, &aad, plaintext, &self.rng).map_err(|e| e.to_string())?;
        Ok(format!("{}{}", ENC_PREFIX_V2, B64.encode(sealed)))
    }

    /// 解密 enc:v2: 或历史 enc:v1: 密文
    pub fn open(&self, field_path: &str, value: &str) -> Result<SecretBytes, String> {
        self.open_with_legacy(field_path, None, value)
    }

    /// 解密密文：enc:v2: 仅验证规范路径 AAD；历史 enc:v1: 允许回退校验旧版未转义路径 AAD
    pub fn open_with_legacy(
        &self,
        field_path: &str,
        legacy_field_path: Option<&str>,
        value: &str,
    ) -> Result<SecretBytes, String> {
        if let Some(b64) = value.strip_prefix(ENC_PREFIX_V2) {
            let raw = B64.decode(b64.trim()).map_err(|_| "密文 base64 非法".to_string())?;
            let aad = v2_aad(field_path);
            return open_field(&self.dek, &aad, &raw)
                .map(SecretBytes::new)
                .map_err(|e| e.to_string());
        }
        if let Some(b64) = value.strip_prefix(ENC_PREFIX) {
            let raw = B64.decode(b64.trim()).map_err(|_| "密文 base64 非法".to_string())?;
            if let Ok(plain) = open_field(&self.dek, field_path, &raw) {
                return Ok(SecretBytes::new(plain));
            }
            if let Some(legacy) = legacy_field_path.filter(|l| *l != field_path) {
                return open_field(&self.dek, legacy, &raw)
                    .map(SecretBytes::new)
                    .map_err(|e| e.to_string());
            }
            return Err("AEAD 解密或 AAD 字段路径校验失败".into());
        }
        Err("不是有效的 enc:v2: 或 enc:v1: 密文".into())
    }

    /// 取得字段明文：enc:v2:/enc:v1: 则解密，否则视为尚未加封的明文
    pub fn reveal(&self, field_path: &str, value: &str) -> Result<SecretBytes, String> {
        self.reveal_with_legacy(field_path, None, value)
    }

    pub fn reveal_with_legacy(
        &self,
        field_path: &str,
        legacy_field_path: Option<&str>,
        value: &str,
    ) -> Result<SecretBytes, String> {
        if is_sealed_value(value) {
            self.open_with_legacy(field_path, legacy_field_path, value)
        } else {
            Ok(SecretBytes::new(value.as_bytes().to_vec()))
        }
    }

    pub fn reveal_string(&self, field_path: &str, value: &str) -> Result<String, String> {
        self.reveal(field_path, value).map(|s| s.expose_str().to_string())
    }

    pub fn reveal_string_with_legacy(
        &self,
        field_path: &str,
        legacy_field_path: Option<&str>,
        value: &str,
    ) -> Result<String, String> {
        self.reveal_with_legacy(field_path, legacy_field_path, value)
            .map(|s| s.expose_str().to_string())
    }

    /// 自动加封：将所有明文机密字段加密为 enc:v2:，并将旧版 enc:v1: 透明升级为 enc:v2:，返回是否发生变化
    pub fn auto_seal(&self, cfg: &mut Config) -> Result<bool, String> {
        let mut changed = false;
        let mut err = None;
        cfg.for_each_secret_with_legacy_mut(|path, legacy_path, v| {
            if v.is_empty() || v.starts_with(ENC_PREFIX_V2) || err.is_some() {
                return;
            }
            if v.starts_with(ENC_PREFIX) {
                match self
                    .open_with_legacy(path, Some(legacy_path), v)
                    .and_then(|plain| self.seal(path, plain.expose()))
                {
                    Ok(s) => {
                        *v = s;
                        changed = true;
                    }
                    Err(e) => err = Some(e),
                }
                return;
            }
            match self.seal(path, v.as_bytes()) {
                Ok(s) => {
                    zeroize_string(v);
                    *v = s;
                    changed = true;
                }
                Err(e) => err = Some(e),
            }
        });
        match err {
            Some(e) => Err(e),
            None => Ok(changed),
        }
    }

    /// 校验所有密文可被当前主密钥解开（启动时检测主密钥不匹配）
    pub fn verify_all(&self, cfg: &Config) -> Vec<String> {
        let mut bad = Vec::new();
        let mut clone = cfg.clone();
        clone.for_each_secret_with_legacy_mut(|path, legacy_path, v| {
            if is_sealed_value(v) && self.open_with_legacy(path, Some(legacy_path), v).is_err() {
                bad.push(path.to_string());
            }
        });
        bad
    }

    /// 合并写回：新配置中值为 __UNCHANGED__ 的字段保留旧密文；新明文重新加封。
    /// rename 用于规则改名时将旧路径前缀映射到新路径前缀（解密后按新路径重新加封）。
    pub fn merge_secrets(&self, new_cfg: &mut Config, old_cfg: &Config, rename: Option<(&str, &str)>) -> Result<(), String> {
        let pairs: Vec<(String, String)> = rename
            .into_iter()
            .map(|(f, t)| (f.to_string(), t.to_string()))
            .collect();
        self.merge_secrets_many(new_cfg, old_cfg, &pairs)
    }

    /// 支持多条改名映射的密钥合并写回（先匹配具体重命名，禁止跨集合或 admin.* 重映射）。
    pub fn merge_secrets_many(
        &self,
        new_cfg: &mut Config,
        old_cfg: &Config,
        renames: &[(String, String)],
    ) -> Result<(), String> {
        let mut validated: Vec<(String, String)> = Vec::with_capacity(renames.len());
        for (from, to) in renames {
            let from_base = from.trim().trim_end_matches('.');
            let to_base = to.trim().trim_end_matches('.');
            let (canon_from, canon_to) = validate_and_canonicalize_rename_pair(from_base, to_base)?;
            validated.push((canon_from, canon_to));
        }
        // 最长（最具体）前缀优先，防止外层规则改名吞掉内层 deploy_hooks/rules 索引移动
        validated.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

        let old = old_cfg.secret_map_with_legacy();
        let mut err: Option<String> = None;
        new_cfg.for_each_secret_with_legacy_mut(|path, legacy_path, v| {
            if err.is_some() {
                return;
            }
            if v == UNCHANGED_SENTINEL {
                if !path.starts_with("admin.") {
                    for (from_base, to_base) in &validated {
                        if let Some(rest) = path.strip_prefix(to_base.as_str()) {
                            if rest.is_empty() || rest.starts_with('.') {
                                let old_path = format!("{}{}", from_base, rest);
                                if let Some((old_legacy, o)) = old.get(&old_path) {
                                    match self
                                        .reveal_with_legacy(&old_path, Some(old_legacy.as_str()), o)
                                        .and_then(|p| {
                                            if p.is_empty() {
                                                Ok(String::new())
                                            } else {
                                                self.seal(path, p.expose())
                                            }
                                        }) {
                                        Ok(s) => *v = s,
                                        Err(e) => err = Some(e),
                                    }
                                } else {
                                    *v = String::new();
                                }
                                return;
                            }
                        }
                    }
                }
                if let Some((old_legacy, o)) = old.get(path) {
                    if o.starts_with(ENC_PREFIX) {
                        match self
                            .open_with_legacy(path, Some(old_legacy.as_str()), o)
                            .and_then(|p| self.seal(path, p.expose()))
                        {
                            Ok(s) => *v = s,
                            Err(e) => err = Some(e),
                        }
                    } else {
                        *v = o.clone();
                    }
                    return;
                }
                *v = String::new();
                return;
            }
            if !v.is_empty() && !is_sealed_value(v) {
                match self.seal(path, v.as_bytes()) {
                    Ok(s) => {
                        zeroize_string(v);
                        *v = s;
                    }
                    Err(e) => err = Some(e),
                }
            } else if v.starts_with(ENC_PREFIX_V2) {
                if self.open(path, v).is_err() {
                    // 拒绝客户端注入无法以本字段路径解开的外来密文（防跨字段剪贴）
                    err = Some(format!("字段 {} 的密文无法通过校验", path));
                }
            } else if v.starts_with(ENC_PREFIX) {
                match self
                    .open_with_legacy(path, Some(legacy_path), v)
                    .and_then(|p| self.seal(path, p.expose()))
                {
                    Ok(s) => *v = s,
                    Err(_) => err = Some(format!("字段 {} 的密文无法通过校验", path)),
                }
            }
        });
        match err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn mask_value(&self, path: &str, legacy_path: &str, v: &str) -> serde_json::Value {
        if v.is_empty() {
            return serde_json::json!({ "configured": false, "masked": "" });
        }
        if path == "admin.totp_secret" {
            return serde_json::json!({ "configured": true, "masked": "****" });
        }
        let masked = match self.reveal_with_legacy(path, Some(legacy_path), v) {
            Ok(p) => mask_plain(p.expose_str()),
            Err(_) => "****(主密钥不匹配)".to_string(),
        };
        serde_json::json!({ "configured": true, "masked": masked })
    }

    /// API 读取脱敏：所有机密字段转换为 { configured, masked }，并移除密码哈希等 L1 认证材料
    pub fn masked_config_json(&self, cfg: &Config) -> serde_json::Value {
        let mut clone = cfg.clone();
        let mut originals: BTreeMap<String, (String, String, String)> = BTreeMap::new();
        let mut idx = 0usize;
        clone.for_each_secret_with_legacy_mut(|path, legacy_path, v| {
            let id = format!("{}{}", MASK_MARKER, idx);
            idx += 1;
            originals.insert(
                id.clone(),
                (path.to_string(), legacy_path.to_string(), std::mem::replace(v, id)),
            );
        });
        let mut json = serde_json::to_value(&clone).unwrap_or(serde_json::Value::Null);
        replace_markers(&mut json, &mut |s| {
            originals
                .get(s)
                .map(|(p, lp, v)| self.mask_value(p, lp, v))
        });
        if let Some(admin) = json.get_mut("admin").and_then(|a| a.as_object_mut()) {
            admin.remove("password_hash");
            admin.remove("totp_last_step");
            let n = cfg.admin.totp_recovery_hashes.len();
            admin.insert("totp_recovery_hashes".into(), serde_json::json!({ "remaining": n }));
        }
        if let Some(users) = json.get_mut("proxy_auth_users").and_then(|v| v.as_array_mut()) {
            for (u_val, u_cfg) in users.iter_mut().zip(cfg.proxy_auth_users.iter()) {
                if let Some(obj) = u_val.as_object_mut() {
                    obj.remove("password_hash");
                    obj.insert(
                        "password_configured".into(),
                        serde_json::json!(!u_cfg.password_hash.is_empty()),
                    );
                }
            }
        }
        json
    }

    // -----------------------------------------------------------------------
    // 跨设备加密备份 (.vane.bak)
    // -----------------------------------------------------------------------

    /// 模式 A：全量加密备份。机密字段以明文形式进入归档，再以备份密码派生密钥整包 AEAD 加密（VANEBAK2 + 完整 40B 头 AAD）
    pub fn export_backup(&self, cfg: &Config, password: &[u8], mut files: BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>, String> {
        validate_backup_passphrase(password)?;
        let mut plain_cfg = cfg.clone();
        let mut err = None;
        plain_cfg.for_each_secret_with_legacy_mut(|path, legacy_path, v| {
            if err.is_some() {
                return;
            }
            if is_sealed_value(v) {
                match self.open_with_legacy(path, Some(legacy_path), v) {
                    Ok(p) => *v = p.expose_str().to_string(),
                    Err(e) => err = Some(format!("{}: {}", path, e)),
                }
            }
        });
        if let Some(e) = err {
            plain_cfg.for_each_secret_mut(|_, v| zeroize_string(v));
            for raw in files.values_mut() {
                zeroize_bytes(raw);
            }
            return Err(format!("解密机密字段失败: {}", e));
        }
        let mut config_toml = match toml::to_string_pretty(&plain_cfg) {
            Ok(t) => t,
            Err(e) => {
                plain_cfg.for_each_secret_mut(|_, v| zeroize_string(v));
                for raw in files.values_mut() {
                    zeroize_bytes(raw);
                }
                return Err(e.to_string());
            }
        };
        // 清理临时明文副本
        plain_cfg.for_each_secret_mut(|_, v| zeroize_string(v));
        let encoded_files: BTreeMap<String, String> = files
            .iter_mut()
            .map(|(k, v)| {
                let b64 = B64.encode(&*v);
                zeroize_bytes(v);
                (k.clone(), b64)
            })
            .collect();
        files.clear();
        let payload = BackupPayload {
            version: 1,
            created_at: crate::logger::unix_now(),
            config_toml: std::mem::take(&mut config_toml),
            files: encoded_files,
        };
        let mut body = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
        drop(payload);
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        if self.rng.fill(&mut salt).is_err() || self.rng.fill(&mut nonce).is_err() {
            zeroize_bytes(&mut body);
            return Err("随机源失败".into());
        }
        let mut header = [0u8; 40];
        header[..8].copy_from_slice(BACKUP_MAGIC_V2);
        header[8..24].copy_from_slice(&salt);
        header[24..28].copy_from_slice(&BACKUP_PBKDF2_ITERS.to_be_bytes());
        header[28..40].copy_from_slice(&nonce);
        let mut key = derive_backup_key(password, &salt, BACKUP_PBKDF2_ITERS);
        let seal_res = (|| -> Result<(), String> {
            let unbound = UnboundKey::new(&aead::CHACHA20_POLY1305, &key).map_err(|_| "无效密钥")?;
            LessSafeKey::new(unbound)
                .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(&header[..]), &mut body)
                .map_err(|_| "备份加密失败".into())
        })();
        zeroize_bytes(&mut key);
        if let Err(e) = seal_res {
            zeroize_bytes(&mut body);
            return Err(e);
        }
        let mut out = Vec::with_capacity(header.len() + body.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&body);
        zeroize_bytes(&mut body);
        Ok(out)
    }

    /// 导入：校验备份密码与 AEAD 标签后，用当前机器主密钥重新加封全部机密
    pub fn import_backup(&self, data: &[u8], password: &[u8]) -> Result<(Config, BTreeMap<String, Vec<u8>>), String> {
        let mut payload = decrypt_backup(data, password)?;
        let mut cfg = crate::config::parse_config(&payload.config_toml)?;
        zeroize_string(&mut payload.config_toml);
        if let Err(e) = self.auto_seal(&mut cfg) {
            cfg.for_each_secret_mut(|_, v| zeroize_string(v));
            return Err(e);
        }
        if payload.files.len() > MAX_BACKUP_FILES {
            return Err("备份内文件数量超过上限".into());
        }
        let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut total_decoded = 0usize;
        while let Some((k, mut v)) = payload.files.pop_first() {
            if !validate_backup_file_key(&k) {
                zeroize_string(&mut v);
                for buf in files.values_mut() {
                    zeroize_bytes(buf);
                }
                return Err(format!("备份内文件名非法: {}", k));
            }
            let decode_res = B64.decode(&v).map_err(|_| "备份内文件编码非法".to_string());
            zeroize_string(&mut v);
            let mut raw = match decode_res {
                Ok(r) => r,
                Err(e) => {
                    for buf in files.values_mut() {
                        zeroize_bytes(buf);
                    }
                    return Err(e);
                }
            };
            match total_decoded.checked_add(raw.len()).filter(|&n| n <= MAX_BACKUP_BYTES) {
                Some(n) => total_decoded = n,
                None => {
                    zeroize_bytes(&mut raw);
                    for buf in files.values_mut() {
                        zeroize_bytes(buf);
                    }
                    return Err("备份内附加文件总大小超过 16 MiB 上限".to_string());
                }
            }
            files.insert(k, raw);
        }
        Ok((cfg, files))
    }
}

/// 模式 B：脱敏排障导出，剔除全部 Token、哈希与私钥
pub fn sanitized_export(cfg: &Config) -> Result<String, String> {
    let mut c = cfg.clone();
    c.for_each_secret_mut(|_, v| {
        if !v.is_empty() {
            *v = "<redacted>".into();
        }
    });
    for a in c.acme.iter_mut() {
        if !a.eab_kid.is_empty() {
            a.eab_kid = "<redacted>".into();
        }
    }
    c.admin.password_hash = "<redacted>".into();
    c.admin.totp_recovery_hashes.clear();
    c.admin.totp_last_step = 0;
    c.admin.secret_path = "/<redacted>".into();
    for u in c.proxy_auth_users.iter_mut() {
        if !u.password_hash.is_empty() {
            u.password_hash = "<redacted>".into();
        }
    }
    toml::to_string_pretty(&c).map_err(|e| e.to_string())
}

fn is_already_canonical_segment(seg: &str) -> bool {
    if seg.contains('.') {
        return false;
    }
    let bytes = seg.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if matches!(bytes.get(i + 1..i + 3), Some(b"25" | b"2E")) {
                i += 3;
                continue;
            }
            return false;
        }
        i += 1;
    }
    true
}

fn canonicalize_dynamic_segment_for_rename(seg: &str) -> String {
    if is_already_canonical_segment(seg) {
        seg.to_string()
    } else {
        encode_secret_segment(seg)
    }
}

fn validate_and_canonicalize_rename_pair(from_base: &str, to_base: &str) -> Result<(String, String), String> {
    const ALLOWED_ROOTS: &[&str] = &[
        "dns_providers",
        "ddns",
        "acme",
        "stun",
        "cron",
        "notifications",
        "reverse_proxy",
    ];
    let Some((root, from_rest)) = from_base.split_once('.') else {
        return Err("无效的密钥重命名路径".into());
    };
    let Some((to_root, to_rest)) = to_base.split_once('.') else {
        return Err("无效的密钥重命名路径".into());
    };
    if root != to_root || !ALLOWED_ROOTS.contains(&root) {
        return Err(format!("禁止跨类别或受保护区域的密钥重映射: {} -> {}", from_base, to_base));
    }
    if from_rest.is_empty()
        || to_rest.is_empty()
        || from_rest.starts_with('.')
        || from_rest.ends_with('.')
        || to_rest.starts_with('.')
        || to_rest.ends_with('.')
        || from_rest.contains("..")
        || to_rest.contains("..")
    {
        return Err("无效的密钥重命名路径".into());
    }

    let is_digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());

    // 1) ACME deploy_hooks 索引移动/重命名：acme.<domain>.deploy_hooks.<idx>.url
    if root == "acme" && (from_rest.contains(".deploy_hooks.") || to_rest.contains(".deploy_hooks.")) {
        let parse_hook = |rest: &str| -> Option<String> {
            let (dom, tail) = rest.rsplit_once(".deploy_hooks.")?;
            let idx = tail.strip_suffix(".url")?;
            if dom.is_empty() || !is_digits(idx) {
                return None;
            }
            Some(format!(
                "acme.{}.deploy_hooks.{}.url",
                canonicalize_dynamic_segment_for_rename(dom),
                idx
            ))
        };
        if let (Some(cf), Some(ct)) = (parse_hook(from_rest), parse_hook(to_rest)) {
            return Ok((cf, ct));
        }
        return Err(format!("不支持的密钥重映射层级: {} -> {}", from_base, to_base));
    }

    // 2) 反向代理规则级/请求头级：reverse_proxy.<rp>.rules.<idx>[.request_headers_set.<header>]
    if root == "reverse_proxy" && (from_rest.contains(".rules.") || to_rest.contains(".rules.")) {
        let parse_rule = |rest: &str| -> Option<(u8, String)> {
            let (rp, tail) = rest.rsplit_once(".rules.")?;
            if rp.is_empty() {
                return None;
            }
            let enc_rp = canonicalize_dynamic_segment_for_rename(rp);
            if is_digits(tail) {
                return Some((1, format!("reverse_proxy.{}.rules.{}", enc_rp, tail)));
            }
            let (idx, hdr) = tail.split_once(".request_headers_set.")?;
            if is_digits(idx) && !hdr.is_empty() {
                let enc_hdr = canonicalize_dynamic_segment_for_rename(hdr);
                return Some((
                    2,
                    format!("reverse_proxy.{}.rules.{}.request_headers_set.{}", enc_rp, idx, enc_hdr),
                ));
            }
            None
        };
        if let (Some((a, cf)), Some((b, ct))) = (parse_rule(from_rest), parse_rule(to_rest)) {
            if a == b {
                return Ok((cf, ct));
            }
        }
        return Err(format!("不支持的密钥重映射层级: {} -> {}", from_base, to_base));
    }

    // 3) 顶层规则项整项重命名：<collection>.<name_or_domain>（支持域名/规则名内含 '.'，但禁止携带敏感子字段路径防跨字段重映射）
    const FORBIDDEN_SUBFIELDS: &[&str] = &[
        ".api_token",
        ".secret_key",
        ".token",
        ".custom_http.",
        ".source.",
        ".eab_hmac_key",
        ".deploy_hooks.",
        ".webhook_url",
        ".on_change_cloudflare_redirect.",
        ".action.",
        ".url",
        ".secret",
        ".body_template",
        ".headers.",
        ".rules.",
    ];
    let has_subfield = |rest: &str| {
        FORBIDDEN_SUBFIELDS
            .iter()
            .any(|m| rest.contains(m) || rest.ends_with(m.trim_end_matches('.')))
    };
    if has_subfield(from_rest) || has_subfield(to_rest) {
        return Err(format!("不支持的密钥重映射层级: {} -> {}", from_base, to_base));
    }
    Ok((
        format!("{}.{}", root, canonicalize_dynamic_segment_for_rename(from_rest)),
        format!("{}.{}", to_root, canonicalize_dynamic_segment_for_rename(to_rest)),
    ))
}

pub fn validate_backup_file_key(k: &str) -> bool {
    if k.is_empty() || k.len() > 256 || k.contains('\\') || k.contains('\0') || k.starts_with('/') {
        return false;
    }
    let segs: Vec<&str> = k.split('/').collect();
    if segs.iter().any(|s| s.is_empty() || *s == "." || *s == ".." || s.starts_with('.')) {
        return false;
    }
    let is_safe_seg = |s: &str| {
        s.len() <= 128
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    };
    match segs.as_slice() {
        [single] => is_safe_seg(single),
        ["certs", name] => matches!(*name, "admin.crt" | "admin.key"),
        ["acme-accounts", name] => {
            name.strip_suffix(".json")
                .is_some_and(|id| id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()))
        }
        ["acme-challenges", name] => name.ends_with(".json") && is_safe_seg(name),
        ["acme-certs", dir_name, file_name] => *file_name == "bundle.json" && is_safe_seg(dir_name),
        _ => false,
    }
}

#[derive(Serialize, Deserialize)]
struct BackupPayload {
    version: u32,
    created_at: u64,
    config_toml: String,
    files: BTreeMap<String, String>,
}

impl Drop for BackupPayload {
    fn drop(&mut self) {
        zeroize_string(&mut self.config_toml);
        for v in self.files.values_mut() {
            zeroize_string(v);
        }
    }
}

fn derive_backup_key(password: &[u8], salt: &[u8], iters: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    let n = NonZeroU32::new(iters.max(1)).unwrap_or(NonZeroU32::MIN);
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, n, salt, password, &mut key);
    key
}

fn decrypt_backup(data: &[u8], password: &[u8]) -> Result<BackupPayload, String> {
    if data.len() > MAX_BACKUP_BYTES {
        return Err("备份文件超过 16 MiB 大小上限".into());
    }
    if data.len() < 8 + 16 + 4 + 12 + 16 {
        return Err("不是有效的 .vane.bak 备份文件".into());
    }
    let magic = &data[..8];
    let aad: &[u8] = if magic == BACKUP_MAGIC_V2 {
        &data[..40]
    } else if magic == BACKUP_MAGIC {
        BACKUP_MAGIC
    } else {
        return Err("不是有效的 .vane.bak 备份文件".into());
    };
    let salt = &data[8..24];
    let iters = u32::from_be_bytes([data[24], data[25], data[26], data[27]]);
    if !(100_000..=BACKUP_MAX_ITERS).contains(&iters) {
        return Err("备份文件迭代参数非法".into());
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&data[28..40]);
    let mut body = data[40..].to_vec();
    let mut key = derive_backup_key(password, salt, iters);
    let parsed = (|| -> Result<BackupPayload, String> {
        let unbound = UnboundKey::new(&aead::CHACHA20_POLY1305, &key).map_err(|_| "无效密钥")?;
        let plain = LessSafeKey::new(unbound)
            .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(aad), &mut body)
            .map_err(|_| "备份密码错误或文件已损坏")?;
        let payload: BackupPayload =
            serde_json::from_slice(plain).map_err(|e| format!("备份内容解析失败: {}", e))?;
        if payload.version != 1 {
            return Err(format!("不支持的备份格式版本: {}", payload.version));
        }
        Ok(payload)
    })();
    zeroize_bytes(&mut key);
    zeroize_bytes(&mut body);
    parsed
}

fn replace_markers(v: &mut serde_json::Value, f: &mut dyn FnMut(&str) -> Option<serde_json::Value>) {
    match v {
        serde_json::Value::String(s) if s.starts_with(MASK_MARKER) => {
            if let Some(n) = f(s) {
                *v = n;
            }
        }
        serde_json::Value::Array(a) => a.iter_mut().for_each(|x| replace_markers(x, f)),
        serde_json::Value::Object(o) => o.values_mut().for_each(|x| replace_markers(x, f)),
        _ => {}
    }
}

/// 将前端回传的脱敏对象 { configured, masked } 统一替换为 __UNCHANGED__ 占位符
pub fn normalize_masked_input(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(o) if o.contains_key("configured") && o.contains_key("masked") && o.len() <= 3 => {
            *v = serde_json::Value::String(UNCHANGED_SENTINEL.into());
        }
        serde_json::Value::Array(a) => a.iter_mut().for_each(normalize_masked_input),
        serde_json::Value::Object(o) => o.values_mut().for_each(normalize_masked_input),
        _ => {}
    }
}

/// 脱敏展示："cf_live_abcdef1234" -> "cf_****...1234"
pub fn mask_plain(p: &str) -> String {
    let chars: Vec<char> = p.chars().collect();
    if chars.len() >= 12 {
        let head: String = chars[..3].iter().collect();
        let tail: String = chars[chars.len() - 4..].iter().collect();
        format!("{}****...{}", head, tail)
    } else {
        "****".into()
    }
}

fn decode_key_text(t: &str) -> Option<[u8; 32]> {
    let mut bytes = if t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()) {
        (0..32).map(|i| u8::from_str_radix(&t[i * 2..i * 2 + 2], 16).ok()).collect::<Option<Vec<u8>>>()?
    } else {
        B64.decode(t).ok()?
    };
    if bytes.len() != 32 {
        zeroize_bytes(&mut bytes);
        return None;
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&bytes);
    zeroize_bytes(&mut bytes);
    Some(k)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DnsProviderConfig, NotificationConfig};

    fn vault() -> Vault {
        Vault::from_master(&[7u8; 32])
    }

    fn seal_legacy_v1(v: &Vault, field_path: &str, plaintext: &[u8]) -> String {
        let sealed = seal_field(&v.dek, field_path, plaintext, &v.rng).unwrap();
        format!("{}{}", ENC_PREFIX, B64.encode(sealed))
    }

    #[test]
    fn seal_open_roundtrip() {
        let v = vault();
        let s = v.seal("dns_providers.cf.api_token", b"cf_live_secret_value").unwrap();
        assert!(s.starts_with(ENC_PREFIX_V2));
        let p = v.open("dns_providers.cf.api_token", &s).unwrap();
        assert_eq!(p.expose(), b"cf_live_secret_value");
        // 同明文两次加密 nonce 不同
        let s2 = v.seal("dns_providers.cf.api_token", b"cf_live_secret_value").unwrap();
        assert_ne!(s, s2);
    }

    #[test]
    fn aad_binding_blocks_cross_field_swap() {
        let v = vault();
        let s = v.seal("admin.totp_secret", b"JBSWY3DPEHPK3PXP").unwrap();
        assert!(v.open("notifications.alert.url", &s).is_err());
        assert!(v.open("admin.totp_secret", &s).is_ok());
    }

    #[test]
    fn tamper_and_wrong_key_rejected() {
        let v = vault();
        let s = v.seal("a.b", b"hello world").unwrap();
        let mut raw = B64.decode(s.strip_prefix(ENC_PREFIX_V2).unwrap()).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        let tampered = format!("{}{}", ENC_PREFIX_V2, B64.encode(&raw));
        assert!(v.open("a.b", &tampered).is_err());
        let other = Vault::from_master(&[8u8; 32]);
        assert!(other.open("a.b", &s).is_err());
        assert!(open_field(&[0u8; 32], "x", &[0u8; 10]).is_err());
    }

    fn sample_cfg() -> Config {
        let mut c = Config::default();
        c.dns_providers.insert(
            "cf_home".into(),
            DnsProviderConfig { api_token: "cf_live_abcdefghijk1234".into(), ..Default::default() },
        );
        c.notifications.push(NotificationConfig {
            name: "tg".into(),
            provider: "telegram".into(),
            token: "123456:ABCDEFGHIJKLMN".into(),
            chat_id: "1".into(),
            ..Default::default()
        });
        c
    }

    #[test]
    fn auto_seal_mask_and_merge_unchanged() {
        let v = vault();
        let mut c = sample_cfg();
        c.admin.totp_secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".into();
        assert!(v.auto_seal(&mut c).unwrap());
        assert!(!v.auto_seal(&mut c).unwrap());
        let tok = c.dns_providers["cf_home"].api_token.clone();
        assert!(tok.starts_with(ENC_PREFIX_V2));

        let masked = v.masked_config_json(&c);
        let m = &masked["dns_providers"]["cf_home"]["api_token"];
        assert_eq!(m["configured"], true);
        assert_eq!(m["masked"], "cf_****...1234");
        // VANE-L07: admin.totp_secret must unconditionally mask to "****"
        assert_eq!(masked["admin"]["totp_secret"]["configured"], true);
        assert_eq!(masked["admin"]["totp_secret"]["masked"], "****");
        assert!(masked["admin"].get("password_hash").is_none());
        let text = masked.to_string();
        assert!(!text.contains("enc:v1:"));
        assert!(!text.contains("enc:v2:"));
        assert!(!text.contains("abcdefghijk"));
        assert!(!text.contains("JBSWY3DPE"));

        // 前端回传脱敏对象 -> 归一化为 __UNCHANGED__ -> 保留原密文
        let mut back = masked.clone();
        normalize_masked_input(&mut back);
        back["admin"]["totp_recovery_hashes"] = serde_json::json!([]);
        back["admin"]["password_hash"] = serde_json::json!("");
        let mut new_cfg: Config = serde_json::from_value(back).unwrap();
        v.merge_secrets(&mut new_cfg, &c, None).unwrap();
        assert_eq!(new_cfg.dns_providers["cf_home"].api_token, tok);

        // 新明文被重新加封
        new_cfg.notifications[0].token = "999:NEWTOKENVALUE".into();
        v.merge_secrets(&mut new_cfg.clone(), &c, None).unwrap();
        let mut n2 = new_cfg.clone();
        v.merge_secrets(&mut n2, &c, None).unwrap();
        assert!(n2.notifications[0].token.starts_with(ENC_PREFIX_V2));
        assert_eq!(v.reveal_string("notifications.tg.token", &n2.notifications[0].token).unwrap(), "999:NEWTOKENVALUE");

        // 外来密文（跨字段剪贴）被拒绝
        let mut evil = c.clone();
        evil.notifications[0].url = tok.clone();
        assert!(v.merge_secrets(&mut evil, &c, None).is_err());
    }

    #[test]
    fn merge_with_rename_reseals() {
        let v = vault();
        let mut c = sample_cfg();
        v.auto_seal(&mut c).unwrap();
        let mut n = c.clone();
        n.notifications[0].name = "tg2".into();
        n.notifications[0].token = UNCHANGED_SENTINEL.into();
        v.merge_secrets(&mut n, &c, Some(("notifications.tg.", "notifications.tg2."))).unwrap();
        assert_eq!(v.reveal_string("notifications.tg2.token", &n.notifications[0].token).unwrap(), "123456:ABCDEFGHIJKLMN");
    }

    #[test]
    fn backup_roundtrip_across_machines() {
        let a = vault();
        let mut c = sample_cfg();
        a.auto_seal(&mut c).unwrap();
        let mut files = BTreeMap::new();
        files.insert("admin.crt".to_string(), b"CERTDATA".to_vec());

        // VANE-L04: weak passphrases rejected
        assert!(a.export_backup(&c, b"12345678", files.clone()).is_err());
        assert!(a.export_backup(&c, b"password", files.clone()).is_err());
        assert!(a.export_backup(&c, b"short1!", files.clone()).is_err());

        let bak = a.export_backup(&c, b"backup-pass-1", files).unwrap();
        assert!(bak.starts_with(BACKUP_MAGIC_V2));
        assert!(!String::from_utf8_lossy(&bak).contains("cf_live"));

        // Tampering with header bytes (iters or salt) must fail V2 full-header AAD check
        let mut tampered_header = bak.clone();
        tampered_header[27] ^= 1;
        let b = Vault::from_master(&[9u8; 32]);
        assert!(b.import_backup(&tampered_header, b"backup-pass-1").is_err());

        assert!(b.import_backup(&bak, b"wrong-pass-1").is_err());
        let (restored, files) = b.import_backup(&bak, b"backup-pass-1").unwrap();
        let t = &restored.dns_providers["cf_home"].api_token;
        assert!(t.starts_with(ENC_PREFIX_V2));
        assert_eq!(b.reveal_string("dns_providers.cf_home.api_token", t).unwrap(), "cf_live_abcdefghijk1234");
        assert!(a.open("dns_providers.cf_home.api_token", t).is_err());
        assert_eq!(files["admin.crt"], b"CERTDATA");

        let s = sanitized_export(&c).unwrap();
        assert!(!s.contains("enc:v1:"));
        assert!(!s.contains("enc:v2:"));
    }

    #[test]
    fn backup_reads_legacy_v1_and_rejects_bad_payload_version() {
        let v = vault();
        let cfg = sample_cfg();
        let payload = BackupPayload {
            version: 1,
            created_at: 1,
            config_toml: toml::to_string_pretty(&cfg).unwrap(),
            files: BTreeMap::new(),
        };
        let make_v1 = |pl: &BackupPayload| -> Vec<u8> {
            let mut body = serde_json::to_vec(pl).unwrap();
            let salt = [3u8; 16];
            let nonce = [4u8; 12];
            let iters: u32 = 100_000;
            let key = derive_backup_key(b"Legacy-Pass1", &salt, iters);
            let unbound = UnboundKey::new(&aead::CHACHA20_POLY1305, &key).unwrap();
            LessSafeKey::new(unbound)
                .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(BACKUP_MAGIC), &mut body)
                .unwrap();
            let mut out = Vec::new();
            out.extend_from_slice(BACKUP_MAGIC);
            out.extend_from_slice(&salt);
            out.extend_from_slice(&iters.to_be_bytes());
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&body);
            out
        };
        let legacy_bak = make_v1(&payload);
        let (restored, _) = v.import_backup(&legacy_bak, b"Legacy-Pass1").unwrap();
        assert!(restored.dns_providers["cf_home"].api_token.starts_with(ENC_PREFIX_V2));

        let bad_ver_payload = BackupPayload {
            version: 2,
            created_at: 1,
            config_toml: toml::to_string_pretty(&cfg).unwrap(),
            files: BTreeMap::new(),
        };
        let bad_bak = make_v1(&bad_ver_payload);
        assert!(v.import_backup(&bad_bak, b"Legacy-Pass1").is_err());
    }

    #[test]
    fn v2_canonical_aad_blocks_dot_collision_and_upgrades_v1() {
        let v = vault();
        let mut old_cfg = Config::default();
        let mut hdrs = BTreeMap::new();
        hdrs.insert("token".into(), "TOP_SECRET_HEADER".into());
        old_cfg.notifications.push(NotificationConfig {
            name: "ops".into(),
            provider: "webhook".into(),
            headers: hdrs,
            ..Default::default()
        });
        v.auto_seal(&mut old_cfg).unwrap();

        // Attacker adds a colliding rule named "ops.headers" with token = __UNCHANGED__
        let mut next_cfg = old_cfg.clone();
        next_cfg.notifications.push(NotificationConfig {
            name: "ops.headers".into(),
            provider: "telegram".into(),
            token: UNCHANGED_SENTINEL.into(),
            ..Default::default()
        });
        v.merge_secrets_many(&mut next_cfg, &old_cfg, &[]).unwrap();
        // Must NOT inherit rule "ops"'s header "token"
        assert!(next_cfg.notifications[1].token.is_empty());

        // Legacy enc:v1: with dots in ACME domain transparently decrypts and upgrades to enc:v2:
        let mut legacy_cfg = Config::default();
        legacy_cfg.acme.push(crate::config::AcmeConfig {
            domain: "example.com".into(),
            dns_provider: "cf".into(),
            eab_hmac_key: seal_legacy_v1(&v, "acme.example.com.eab_hmac_key", b"legacy-eab-secret"),
            ..Default::default()
        });
        assert!(v.verify_all(&legacy_cfg).is_empty());
        assert!(v.auto_seal(&mut legacy_cfg).unwrap());
        assert!(legacy_cfg.acme[0].eab_hmac_key.starts_with(ENC_PREFIX_V2));
        let canon = format!("acme.{}.eab_hmac_key", encode_secret_segment("example.com"));
        assert_eq!(
            v.open(&canon, &legacy_cfg.acme[0].eab_hmac_key).unwrap().expose_str(),
            "legacy-eab-secret"
        );
    }

    #[test]
    fn load_or_create_atomic_0400_and_rejects_symlink() {
        let dir = std::env::temp_dir().join(format!("vane-vault-test-{}", crate::config::random_alnum(8)));
        fs::create_dir_all(&dir).unwrap();
        let v1 = Vault::load_or_create(&dir).unwrap();
        let key_path = dir.join(MASTER_KEY_FILE);
        assert_eq!(fs::symlink_metadata(&key_path).unwrap().permissions().mode() & 0o777, 0o400);
        assert!(!dir.join(".master.key.bak").exists());
        let ct = v1.seal("a.b", b"hello").unwrap();
        let v2 = Vault::load_or_create(&dir).unwrap();
        assert_eq!(v2.open("a.b", &ct).unwrap().expose(), b"hello");

        // Symlink .master.key must be rejected
        let dir_sym = std::env::temp_dir().join(format!("vane-vault-sym-{}", crate::config::random_alnum(8)));
        fs::create_dir_all(&dir_sym).unwrap();
        std::os::unix::fs::symlink(&key_path, dir_sym.join(MASTER_KEY_FILE)).unwrap();
        assert!(Vault::load_or_create(&dir_sym).is_err());

        let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&dir_sym);
    }

    #[test]
    fn secret_bytes_debug_is_redacted() {
        let s = SecretBytes::new(b"topsecret".to_vec());
        assert_eq!(format!("{:?}", s), "SecretBytes(****)");
        assert_eq!(mask_plain("short"), "****");
    }

    #[test]
    fn merge_secrets_blocks_cross_field_rename_and_preserves_hook_shift() {
        use crate::config::{AcmeConfig, DeployHook};
        let v = vault();
        let mut old_cfg = sample_cfg();
        old_cfg.admin.totp_secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".into();
        old_cfg.acme.push(AcmeConfig {
            domain: "example.com".into(),
            dns_provider: "cf_home".into(),
            deploy_hooks: vec![
                DeployHook::Webhook {
                    url: "https://deleted.example/hook0".into(),
                    include_private_key: false,
                },
                DeployHook::Webhook {
                    url: "https://keep-secret.example/hook1".into(),
                    include_private_key: true,
                },
            ],
            ..Default::default()
        });
        v.auto_seal(&mut old_cfg).unwrap();

        // 1) 攻击者企图通过 _renames 把 admin.totp_secret 跨字段复制到通知请求头 -> 必须被拒绝
        let mut exfil = old_cfg.clone();
        exfil.notifications[0].headers.insert("x-leak".into(), UNCHANGED_SENTINEL.into());
        assert!(v
            .merge_secrets_many(
                &mut exfil,
                &old_cfg,
                &[("admin.totp_secret".into(), "notifications.tg.headers.x-leak".into())]
            )
            .is_err());

        // 2) 删除 deploy_hooks[0]，deploy_hooks[1] 前移为 [0]；必须继承原 hook1 URL，而非已删除的 hook0 URL
        let mut shifted = old_cfg.clone();
        shifted.acme[0].deploy_hooks = vec![DeployHook::Webhook {
            url: UNCHANGED_SENTINEL.into(),
            include_private_key: true,
        }];
        v.merge_secrets_many(
            &mut shifted,
            &old_cfg,
            &[(
                "acme.example.com.deploy_hooks.1.url".into(),
                "acme.example.com.deploy_hooks.0.url".into(),
            )],
        )
        .unwrap();
        let DeployHook::Webhook { ref url, .. } = shifted.acme[0].deploy_hooks[0] else {
            panic!("expected webhook");
        };
        let hook_path = format!("acme.{}.deploy_hooks.0.url", encode_secret_segment("example.com"));
        assert_eq!(
            v.reveal_string(&hook_path, url).unwrap(),
            "https://keep-secret.example/hook1"
        );
    }
}
