//! 敏感字段信封加密（ChaCha20-Poly1305 + HKDF，字段路径作为 AAD）、自动加封、API 脱敏与跨机加密备份。
use crate::config::{Config, UNCHANGED_SENTINEL};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use ring::{hkdf, pbkdf2};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::num::NonZeroU32;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub const ENC_PREFIX: &str = "enc:v1:";
const MASTER_KEY_FILE: &str = ".master.key";
const BACKUP_MAGIC: &[u8; 8] = b"VANEBAK1";
const BACKUP_PBKDF2_ITERS: u32 = 200_000;
const BACKUP_MAX_ITERS: u32 = 600_000;
const MAX_BACKUP_BYTES: usize = 16 * 1024 * 1024;
const MAX_BACKUP_FILES: usize = 256;
const MASK_MARKER: &str = "\u{0}__VANE_SECRET__:";

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
        for b in self.0.iter_mut() {
            // SAFETY: b 是指向本 Vec 内有效、对齐的 u8 引用
            unsafe { std::ptr::write_volatile(b, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
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
    key.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce_bytes), Aad::from(field_path.as_bytes()), &mut body)
        .map_err(|_| "AEAD 加密失败")?;
    out.extend_from_slice(&body);
    for b in body.iter_mut() {
        *b = 0;
    }
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
    let plain = key
        .open_in_place(Nonce::assume_unique_for_key(nonce_bytes), Aad::from(field_path.as_bytes()), &mut buf)
        .map_err(|_| "AEAD 解密或 AAD 字段路径校验失败")?;
    let plain_len = plain.len();
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
        for b in self.dek.iter_mut().chain(self.mac_key.iter_mut()) {
            // SAFETY: 指向自身数组元素
            unsafe { std::ptr::write_volatile(b, 0) };
        }
    }
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
        if let Ok(v) = std::env::var("VANE_MASTER_KEY") {
            let key = decode_key_text(v.trim()).ok_or("VANE_MASTER_KEY 必须为 32 字节的 base64 或 hex 编码")?;
            return Ok(Self::from_master(&key));
        }
        if let Ok(file) = std::env::var("VANE_MASTER_KEY_FILE") {
            let text = fs::read_to_string(&file).map_err(|e| format!("读取 VANE_MASTER_KEY_FILE 失败: {}", e))?;
            let key = decode_key_text(text.trim()).ok_or("VANE_MASTER_KEY_FILE 内容非法")?;
            return Ok(Self::from_master(&key));
        }
        let path = data_dir.join(MASTER_KEY_FILE);
        if path.exists() {
            let raw = fs::read(&path).map_err(|e| format!("读取主密钥失败: {}", e))?;
            let key = if raw.len() == 32 {
                let mut k = [0u8; 32];
                k.copy_from_slice(&raw);
                k
            } else {
                decode_key_text(String::from_utf8_lossy(&raw).trim()).ok_or("主密钥文件内容非法")?
            };
            return Ok(Self::from_master(&key));
        }
        let mut key = [0u8; 32];
        SystemRandom::new().fill(&mut key).map_err(|_| "硬件随机源生成主密钥失败")?;
        if !data_dir.exists() {
            fs::create_dir_all(data_dir).map_err(|e| format!("创建数据目录失败: {}", e))?;
            let _ = fs::set_permissions(data_dir, fs::Permissions::from_mode(0o700));
        }
        crate::config::crash_safe_atomic_write(&path, B64.encode(key).as_bytes(), crate::config::random_nonce())
            .map_err(|e| format!("写入主密钥失败: {}", e))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).map_err(|e| format!("设置主密钥权限失败: {}", e))?;
        crate::log_info!("vault", "已生成新的主密钥 {}", path.display());
        Ok(Self::from_master(&key))
    }

    pub fn rng(&self) -> &SystemRandom {
        &self.rng
    }

    pub fn mac_key(&self) -> &[u8; 32] {
        &self.mac_key
    }

    pub fn seal(&self, field_path: &str, plaintext: &[u8]) -> Result<String, String> {
        let sealed = seal_field(&self.dek, field_path, plaintext, &self.rng).map_err(|e| e.to_string())?;
        Ok(format!("{}{}", ENC_PREFIX, B64.encode(sealed)))
    }

    pub fn open(&self, field_path: &str, value: &str) -> Result<SecretBytes, String> {
        let b64 = value.strip_prefix(ENC_PREFIX).ok_or("不是 enc:v1: 密文")?;
        let raw = B64.decode(b64.trim()).map_err(|_| "密文 base64 非法".to_string())?;
        open_field(&self.dek, field_path, &raw).map(SecretBytes::new).map_err(|e| e.to_string())
    }

    /// 取得字段明文：enc:v1: 则解密，否则视为尚未加封的明文
    pub fn reveal(&self, field_path: &str, value: &str) -> Result<SecretBytes, String> {
        if value.starts_with(ENC_PREFIX) {
            self.open(field_path, value)
        } else {
            Ok(SecretBytes::new(value.as_bytes().to_vec()))
        }
    }

    pub fn reveal_string(&self, field_path: &str, value: &str) -> Result<String, String> {
        self.reveal(field_path, value).map(|s| s.expose_str().to_string())
    }

    /// 自动加封：将所有明文机密字段加密为 enc:v1:，返回是否发生变化
    pub fn auto_seal(&self, cfg: &mut Config) -> Result<bool, String> {
        let mut changed = false;
        let mut err = None;
        cfg.for_each_secret_mut(|path, v| {
            if v.is_empty() || v.starts_with(ENC_PREFIX) || err.is_some() {
                return;
            }
            match self.seal(path, v.as_bytes()) {
                Ok(s) => {
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
        for (path, v) in cfg.secret_map() {
            if v.starts_with(ENC_PREFIX) && self.open(&path, &v).is_err() {
                bad.push(path);
            }
        }
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
            validate_rename_pair(from_base, to_base)?;
            validated.push((from_base.to_string(), to_base.to_string()));
        }
        // 最长（最具体）前缀优先，防止外层规则改名吞掉内层 deploy_hooks/rules 索引移动
        validated.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

        let old = old_cfg.secret_map();
        let mut err: Option<String> = None;
        new_cfg.for_each_secret_mut(|path, v| {
            if err.is_some() {
                return;
            }
            if v == UNCHANGED_SENTINEL {
                if !path.starts_with("admin.") {
                    for (from_base, to_base) in &validated {
                        if let Some(rest) = path.strip_prefix(to_base.as_str()) {
                            if rest.is_empty() || rest.starts_with('.') {
                                let old_path = format!("{}{}", from_base, rest);
                                if let Some(o) = old.get(&old_path) {
                                    match self.reveal(&old_path, o).and_then(|p| {
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
                if let Some(o) = old.get(path) {
                    *v = o.clone();
                    return;
                }
                *v = String::new();
                return;
            }
            if !v.is_empty() && !v.starts_with(ENC_PREFIX) {
                match self.seal(path, v.as_bytes()) {
                    Ok(s) => *v = s,
                    Err(e) => err = Some(e),
                }
            } else if v.starts_with(ENC_PREFIX) && self.open(path, v).is_err() {
                // 拒绝客户端注入无法以本字段路径解开的外来密文（防跨字段剪贴）
                err = Some(format!("字段 {} 的密文无法通过校验", path));
            }
        });
        match err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn mask_value(&self, path: &str, v: &str) -> serde_json::Value {
        if v.is_empty() {
            return serde_json::json!({ "configured": false, "masked": "" });
        }
        let masked = match self.reveal(path, v) {
            Ok(p) => mask_plain(p.expose_str()),
            Err(_) => "****(主密钥不匹配)".to_string(),
        };
        serde_json::json!({ "configured": true, "masked": masked })
    }

    /// API 读取脱敏：所有机密字段转换为 { configured, masked }，并移除密码哈希等 L1 认证材料
    pub fn masked_config_json(&self, cfg: &Config) -> serde_json::Value {
        let mut clone = cfg.clone();
        let mut originals: BTreeMap<String, (String, String)> = BTreeMap::new();
        let mut idx = 0usize;
        clone.for_each_secret_mut(|path, v| {
            let id = format!("{}{}", MASK_MARKER, idx);
            idx += 1;
            originals.insert(id.clone(), (path.to_string(), std::mem::replace(v, id)));
        });
        let mut json = serde_json::to_value(&clone).unwrap_or(serde_json::Value::Null);
        replace_markers(&mut json, &mut |s| originals.get(s).map(|(p, v)| self.mask_value(p, v)));
        if let Some(admin) = json.get_mut("admin").and_then(|a| a.as_object_mut()) {
            admin.remove("password_hash");
            admin.remove("totp_last_step");
            let n = cfg.admin.totp_recovery_hashes.len();
            admin.insert("totp_recovery_hashes".into(), serde_json::json!({ "remaining": n }));
        }
        json
    }

    // -----------------------------------------------------------------------
    // 跨设备加密备份 (.vane.bak)
    // -----------------------------------------------------------------------

    /// 模式 A：全量加密备份。机密字段以明文形式进入归档，再以备份密码派生密钥整包 AEAD 加密
    pub fn export_backup(&self, cfg: &Config, password: &[u8], files: BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>, String> {
        if password.len() < 8 {
            return Err("备份密码至少 8 位".into());
        }
        let mut plain_cfg = cfg.clone();
        let mut err = None;
        plain_cfg.for_each_secret_mut(|path, v| {
            if v.starts_with(ENC_PREFIX) {
                match self.open(path, v) {
                    Ok(p) => *v = p.expose_str().to_string(),
                    Err(e) => err = Some(format!("{}: {}", path, e)),
                }
            }
        });
        if let Some(e) = err {
            return Err(format!("解密机密字段失败: {}", e));
        }
        let mut config_toml = toml::to_string_pretty(&plain_cfg).map_err(|e| e.to_string())?;
        // 清理临时明文副本
        plain_cfg.for_each_secret_mut(|_, v| zeroize_string(v));
        let payload = BackupPayload {
            version: 1,
            created_at: crate::logger::unix_now(),
            config_toml: std::mem::take(&mut config_toml),
            files: files.into_iter().map(|(k, v)| (k, B64.encode(v))).collect(),
        };
        let mut body = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
        drop(payload);
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        self.rng.fill(&mut salt).map_err(|_| "随机源失败")?;
        self.rng.fill(&mut nonce).map_err(|_| "随机源失败")?;
        let mut key = derive_backup_key(password, &salt, BACKUP_PBKDF2_ITERS);
        let seal_res = (|| -> Result<(), String> {
            let unbound = UnboundKey::new(&aead::CHACHA20_POLY1305, &key).map_err(|_| "无效密钥")?;
            LessSafeKey::new(unbound)
                .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(BACKUP_MAGIC), &mut body)
                .map_err(|_| "备份加密失败".into())
        })();
        zeroize_bytes(&mut key);
        if let Err(e) = seal_res {
            zeroize_bytes(&mut body);
            return Err(e);
        }
        let mut out = Vec::with_capacity(8 + 16 + 4 + 12 + body.len());
        out.extend_from_slice(BACKUP_MAGIC);
        out.extend_from_slice(&salt);
        out.extend_from_slice(&BACKUP_PBKDF2_ITERS.to_be_bytes());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&body);
        zeroize_bytes(&mut body);
        Ok(out)
    }

    /// 导入：校验备份密码与 AEAD 标签后，用当前机器主密钥重新加封全部机密
    pub fn import_backup(&self, data: &[u8], password: &[u8]) -> Result<(Config, BTreeMap<String, Vec<u8>>), String> {
        let mut payload = decrypt_backup(data, password)?;
        let mut cfg = crate::config::parse_config(&payload.config_toml)?;
        zeroize_string(&mut payload.config_toml);
        self.auto_seal(&mut cfg)?;
        if payload.files.len() > MAX_BACKUP_FILES {
            return Err("备份内文件数量超过上限".into());
        }
        let mut files = BTreeMap::new();
        let mut total_decoded = 0usize;
        for (k, v) in payload.files {
            if !validate_backup_file_key(&k) {
                return Err(format!("备份内文件名非法: {}", k));
            }
            let raw = B64.decode(v).map_err(|_| "备份内文件编码非法")?;
            total_decoded = total_decoded
                .checked_add(raw.len())
                .filter(|&n| n <= MAX_BACKUP_BYTES)
                .ok_or_else(|| "备份内附加文件总大小超过 16 MiB 上限".to_string())?;
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
    for k in c.admin.authorized_ed25519_keys.iter_mut() {
        k.pubkey = "<redacted>".into();
    }
    toml::to_string_pretty(&c).map_err(|e| e.to_string())
}

fn validate_rename_pair(from_base: &str, to_base: &str) -> Result<(), String> {
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
        let valid_hook = |rest: &str| {
            rest.rsplit_once(".deploy_hooks.").is_some_and(|(dom, tail)| {
                !dom.is_empty()
                    && tail.strip_suffix(".url").is_some_and(is_digits)
            })
        };
        if valid_hook(from_rest) && valid_hook(to_rest) {
            return Ok(());
        }
        return Err(format!("不支持的密钥重映射层级: {} -> {}", from_base, to_base));
    }

    // 2) 反向代理规则级/请求头级：reverse_proxy.<rp>.rules.<idx>[.request_headers_set.<header>]
    if root == "reverse_proxy" && (from_rest.contains(".rules.") || to_rest.contains(".rules.")) {
        let rule_shape = |rest: &str| -> Option<u8> {
            let (rp, tail) = rest.rsplit_once(".rules.")?;
            if rp.is_empty() {
                return None;
            }
            if is_digits(tail) {
                return Some(1);
            }
            let (idx, hdr) = tail.split_once(".request_headers_set.")?;
            if is_digits(idx) && !hdr.is_empty() && !hdr.contains('.') {
                return Some(2);
            }
            None
        };
        if let (Some(a), Some(b)) = (rule_shape(from_rest), rule_shape(to_rest)) {
            if a == b {
                return Ok(());
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
    Ok(())
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
    if data.len() < 8 + 16 + 4 + 12 + 16 || &data[..8] != BACKUP_MAGIC {
        return Err("不是有效的 .vane.bak 备份文件".into());
    }
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
            .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(BACKUP_MAGIC), &mut body)
            .map_err(|_| "备份密码错误或文件已损坏")?;
        serde_json::from_slice(plain).map_err(|e| format!("备份内容解析失败: {}", e))
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
    let bytes = if t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()) {
        (0..32).map(|i| u8::from_str_radix(&t[i * 2..i * 2 + 2], 16).ok()).collect::<Option<Vec<u8>>>()?
    } else {
        B64.decode(t).ok()?
    };
    if bytes.len() != 32 {
        return None;
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&bytes);
    Some(k)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DnsProviderConfig, NotificationConfig};

    fn vault() -> Vault {
        Vault::from_master(&[7u8; 32])
    }

    #[test]
    fn seal_open_roundtrip() {
        let v = vault();
        let s = v.seal("dns_providers.cf.api_token", b"cf_live_secret_value").unwrap();
        assert!(s.starts_with(ENC_PREFIX));
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
        let mut raw = B64.decode(s.strip_prefix(ENC_PREFIX).unwrap()).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        let tampered = format!("{}{}", ENC_PREFIX, B64.encode(&raw));
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
        assert!(v.auto_seal(&mut c).unwrap());
        assert!(!v.auto_seal(&mut c).unwrap());
        let tok = c.dns_providers["cf_home"].api_token.clone();
        assert!(tok.starts_with(ENC_PREFIX));

        let masked = v.masked_config_json(&c);
        let m = &masked["dns_providers"]["cf_home"]["api_token"];
        assert_eq!(m["configured"], true);
        assert_eq!(m["masked"], "cf_****...1234");
        assert!(masked["admin"].get("password_hash").is_none());
        let text = masked.to_string();
        assert!(!text.contains("enc:v1:"));
        assert!(!text.contains("abcdefghijk"));

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
        assert!(n2.notifications[0].token.starts_with(ENC_PREFIX));
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
        let bak = a.export_backup(&c, b"backup-pass-1", files).unwrap();
        assert!(bak.starts_with(BACKUP_MAGIC));
        assert!(!String::from_utf8_lossy(&bak).contains("cf_live"));

        let b = Vault::from_master(&[9u8; 32]);
        assert!(b.import_backup(&bak, b"wrong-pass").is_err());
        let (restored, files) = b.import_backup(&bak, b"backup-pass-1").unwrap();
        let t = &restored.dns_providers["cf_home"].api_token;
        assert!(t.starts_with(ENC_PREFIX));
        assert_eq!(b.reveal_string("dns_providers.cf_home.api_token", t).unwrap(), "cf_live_abcdefghijk1234");
        assert!(a.open("dns_providers.cf_home.api_token", t).is_err());
        assert_eq!(files["admin.crt"], b"CERTDATA");

        let s = sanitized_export(&c).unwrap();
        assert!(!s.contains("enc:v1:"));
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
        assert_eq!(
            v.reveal_string("acme.example.com.deploy_hooks.0.url", url).unwrap(),
            "https://keep-secret.example/hook1"
        );
    }
}
