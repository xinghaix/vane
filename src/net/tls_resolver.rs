//! Rustls 严格 SNI 证书解析器、rcgen 本地 ECDSA 自签证书自动生成与 ArcSwap 无锁热更新。
use arc_swap::ArcSwap;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::fs;
use std::io::BufReader;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 自签管理证书默认有效期：自部署/签发时间起 5 年（1826 天，覆盖闰年）
pub const SELF_SIGNED_VALIDITY_SECS: u64 = 5 * 365 * 86_400 + 86_400;
/// 临期前自动续期窗口：到期前 30 天内自动轮换更新
pub const SELF_SIGNED_RENEW_BEFORE_SECS: i64 = 30 * 86_400;
const CLOCK_SKEW_GRACE_SECS: u64 = 300;

#[derive(Default)]
pub struct CertTable {
    pub exact: HashMap<String, Arc<CertifiedKey>>,
    pub wildcard: HashMap<String, Arc<CertifiedKey>>,
    pub fallback: Option<Arc<CertifiedKey>>,
}

pub struct DynamicCertResolver {
    table: Arc<ArcSwap<CertTable>>,
    strict_sni: bool,
}

impl std::fmt::Debug for DynamicCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicCertResolver").field("strict_sni", &self.strict_sni).finish()
    }
}

impl DynamicCertResolver {
    pub fn new(table: Arc<ArcSwap<CertTable>>, strict_sni: bool) -> Self {
        Self { table, strict_sni }
    }

    pub fn lookup(&self, sni: Option<&str>) -> Option<Arc<CertifiedKey>> {
        let snap = self.table.load();
        if let Some(host) = sni.map(|s| s.to_ascii_lowercase()) {
            if let Some(ck) = snap.exact.get(&host) {
                return Some(ck.clone());
            }
            if let Some(dot) = host.find('.') {
                let suffix = &host[dot..];
                if let Some(ck) = snap.wildcard.get(suffix) {
                    return Some(ck.clone());
                }
            }
        }
        if self.strict_sni {
            None
        } else {
            snap.fallback.clone()
        }
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.lookup(client_hello.server_name())
    }
}

pub fn generate_self_signed_cert(sans: &[String]) -> Result<(String, String, Arc<CertifiedKey>), String> {
    let now = SystemTime::now();
    let not_before = now.checked_sub(Duration::from_secs(CLOCK_SKEW_GRACE_SECS)).unwrap_or(now);
    let not_after = now + Duration::from_secs(SELF_SIGNED_VALIDITY_SECS);
    generate_self_signed_cert_with_validity(sans, not_before, not_after)
}

pub fn generate_self_signed_cert_with_validity(
    sans: &[String],
    not_before: SystemTime,
    not_after: SystemTime,
) -> Result<(String, String, Arc<CertifiedKey>), String> {
    let mut params = CertificateParams::default();
    params.not_before = not_before.into();
    params.not_after = not_after.into();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Vane Gateway Local CA");
    dn.push(DnType::OrganizationName, "Vane");
    params.distinguished_name = dn;

    let mut subject_alt_names = vec![
        SanType::DnsName("localhost".try_into().map_err(|e| format!("{:?}", e))?),
        SanType::IpAddress(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        SanType::IpAddress(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
        SanType::IpAddress(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1))),
    ];
    for s in sans {
        let ip = s.parse::<std::net::SocketAddr>().map(|addr| addr.ip()).ok()
            .or_else(|| s.trim_matches(['[', ']']).parse::<IpAddr>().ok());
        if let Some(ip) = ip {
            let san = SanType::IpAddress(ip);
            if !subject_alt_names.contains(&san) {
                subject_alt_names.push(san);
            }
        } else if let Ok(dns) = s.clone().try_into() {
            let san = SanType::DnsName(dns);
            if !subject_alt_names.contains(&san) {
                subject_alt_names.push(san);
            }
        }
    }
    params.subject_alt_names = subject_alt_names;

    let key_pair = KeyPair::generate().map_err(|e| format!("生成 ECDSA 密钥对失败: {}", e))?;
    let cert = params.self_signed(&key_pair).map_err(|e| format!("签发自签名证书失败: {}", e))?;
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    let ck = certified_key_from_pem(cert_pem.as_bytes(), key_pem.as_bytes())?;
    Ok((cert_pem, key_pem, ck))
}

/// 生成独立的中性反代回退证书（不包含内网管理 IP 或 canonical_origin SAN），防止 strict_sni=false 泄露管理面拓扑
pub fn generate_neutral_fallback_cert() -> Result<Arc<CertifiedKey>, String> {
    let now = SystemTime::now();
    let mut params = CertificateParams::default();
    params.not_before = now.checked_sub(Duration::from_secs(CLOCK_SKEW_GRACE_SECS)).unwrap_or(now).into();
    params.not_after = (now + Duration::from_secs(SELF_SIGNED_VALIDITY_SECS)).into();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "vane-proxy-fallback");
    params.distinguished_name = dn;
    params.subject_alt_names = vec![SanType::DnsName("localhost".try_into().map_err(|e| format!("{:?}", e))?)];
    let key_pair = KeyPair::generate().map_err(|e| format!("生成回退 ECDSA 密钥对失败: {}", e))?;
    let cert = params.self_signed(&key_pair).map_err(|e| format!("签发回退自签名证书失败: {}", e))?;
    certified_key_from_pem(cert.pem().as_bytes(), key_pair.serialize_pem().as_bytes())
}

/// 解析叶证书的生效与截止 Unix 时间戳
pub fn parse_leaf_validity(cert_pem: &[u8]) -> Result<(i64, i64), String> {
    let mut reader = BufReader::new(cert_pem);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("解析证书 PEM 失败: {}", e))?;
    let leaf = certs.first().ok_or_else(|| "证书链为空".to_string())?;
    let (_, parsed) = x509_parser::parse_x509_certificate(leaf.as_ref())
        .map_err(|e| format!("解析 X.509 证书失败: {}", e))?;
    Ok((
        parsed.validity().not_before.timestamp(),
        parsed.validity().not_after.timestamp(),
    ))
}

/// 判断本地自签管理证书是否已过期、进入临期 30 天续期窗口，或属于旧版 rcgen 默认超长异常有效期（如 1975~4096）
pub fn is_self_signed_cert_due_for_renewal(
    cert_pem: &[u8],
    now_unix: i64,
    renew_before_secs: i64,
) -> Result<bool, String> {
    let (not_before, not_after) = parse_leaf_validity(cert_pem)?;
    let span = not_after.saturating_sub(not_before);
    let legacy_absurd_span = span > 10 * 365 * 86_400;
    let expiring_soon = not_after.saturating_sub(now_unix) <= renew_before_secs;
    let not_yet_valid = not_before > now_unix.saturating_add(86_400);
    Ok(legacy_absurd_span || expiring_soon || not_yet_valid)
}

pub fn certified_key_from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<Arc<CertifiedKey>, String> {
    let mut cert_reader = BufReader::new(cert_pem);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("解析证书 PEM 失败: {}", e))?;
    if certs.is_empty() {
        return Err("证书链为空".into());
    }

    let mut key_reader = BufReader::new(key_pem);
    let key_der: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| format!("解析私钥 PEM 失败: {}", e))?
        .ok_or_else(|| "未找到有效私钥".to_string())?;

    let signing_key = any_supported_type(&key_der).map_err(|e| format!("不支持的私钥算法: {:?}", e))?;
    let key = CertifiedKey::new(certs, signing_key);
    key.keys_match().map_err(|e| format!("证书与私钥不匹配: {}", e))?;
    Ok(Arc::new(key))
}

const MAX_ADMIN_PEM_BYTES: u64 = 256 * 1024;
const ADMIN_GEN_PREFIX: &str = "admin-gen-";

fn is_valid_admin_gen_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix(ADMIN_GEN_PREFIX) else {
        return false;
    };
    !rest.is_empty()
        && rest.len() <= 64
        && rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn ensure_real_certs_dir(certs_dir: &Path) -> Result<(), String> {
    match fs::symlink_metadata(certs_dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err("证书目录为符号链接或非目录，拒绝访问".into());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(certs_dir).map_err(|e| format!("创建证书目录失败: {}", e))?;
        }
        Err(e) => return Err(format!("检查证书目录失败: {}", e)),
    }
    fs::set_permissions(certs_dir, fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("设置证书目录权限失败: {}", e))?;
    Ok(())
}

fn read_checked_pem_file(path: &Path, is_private_key: bool, label: &str) -> Result<Vec<u8>, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| format!("读取{label}元数据失败: {e}"))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(format!("拒绝读取符号链接或非普通文件形式的{label}"));
    }
    if meta.len() == 0 || meta.len() > MAX_ADMIN_PEM_BYTES {
        return Err(format!("{label}大小异常 ({} bytes)", meta.len()));
    }
    if is_private_key && (meta.permissions().mode() & 0o077) != 0 {
        crate::logger::log(
            crate::logger::Level::Warn,
            "admin",
            &format!(
                "管理私钥权限过宽 ({:o})，已强制收紧为 0600",
                meta.permissions().mode() & 0o777
            ),
        );
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("收紧管理私钥权限失败: {e}"))?;
    }
    fs::read(path).map_err(|e| format!("读取{label}失败: {e}"))
}

pub type AdminCertPemPair = (Vec<u8>, Vec<u8>);

/// 读取管理面 TLS 证书与私钥对：优先从原子代际符号链接 `certs/current` 读取，兼容旧版 `certs/admin.{crt,key}`。
/// 强制校验 `symlink_metadata`（拒绝恶意符号链接与超大文件）并确保私钥权限为 `0600`。
pub fn read_admin_cert_pair(certs_dir: &Path) -> Result<Option<AdminCertPemPair>, String> {
    match fs::symlink_metadata(certs_dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err("证书目录为符号链接或非目录，拒绝读取".into());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("检查证书目录失败: {}", e)),
    }

    let current_link = certs_dir.join("current");
    match fs::symlink_metadata(&current_link) {
        Ok(meta) => {
            if !meta.file_type().is_symlink() {
                return Err("管理证书 current 路径不是受管符号链接".into());
            }
            let target = fs::read_link(&current_link)
                .map_err(|e| format!("读取管理证书 current 指针失败: {}", e))?;
            let target_str = target.to_str().ok_or("管理证书 current 指针非 UTF-8")?;
            if target.is_absolute() || !is_valid_admin_gen_name(target_str) {
                return Err("管理证书 current 指针指向非法目标".into());
            }
            let gen_dir = certs_dir.join(target_str);
            let gen_meta = fs::symlink_metadata(&gen_dir)
                .map_err(|e| format!("读取管理证书代际目录失败: {}", e))?;
            if gen_meta.file_type().is_symlink() || !gen_meta.is_dir() {
                return Err("管理证书代际目录为符号链接或非目录".into());
            }
            let cert = read_checked_pem_file(&gen_dir.join("admin.crt"), false, "管理证书")?;
            let key = read_checked_pem_file(&gen_dir.join("admin.key"), true, "管理私钥")?;
            return Ok(Some((cert, key)));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("检查管理证书 current 指针失败: {}", e)),
    }

    // 兼容旧版平铺 certs/admin.{crt,key}
    let crt_path = certs_dir.join("admin.crt");
    let key_path = certs_dir.join("admin.key");
    let crt_exists = fs::symlink_metadata(&crt_path).is_ok();
    let key_exists = fs::symlink_metadata(&key_path).is_ok();
    if crt_exists || key_exists {
        let cert = read_checked_pem_file(&crt_path, false, "管理证书")?;
        let key = read_checked_pem_file(&key_path, true, "管理私钥")?;
        return Ok(Some((cert, key)));
    }
    Ok(None)
}

/// 原子持久化管理面证书与私钥对：
/// 写入 `admin-gen-<ts>-<rand>/admin.{crt,key}`（0600 且无 `.bak` 副本）-> fsync -> 原子切换 `current` 符号链接，
/// 并保持 `admin.{crt,key} -> current/admin.{crt,key}` 兼容指针同步生效，杜绝断电分裂失配。
pub fn save_admin_cert_pair_atomic(certs_dir: &Path, cert_pem: &[u8], key_pem: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::{symlink, DirBuilderExt};

    let _ = certified_key_from_pem(cert_pem, key_pem)?;
    ensure_real_certs_dir(certs_dir)?;

    let current_link = certs_dir.join("current");
    let previous = match fs::symlink_metadata(&current_link) {
        Ok(meta) => {
            if !meta.file_type().is_symlink() {
                return Err("管理证书 current 路径不是受管符号链接".into());
            }
            fs::read_link(&current_link).ok()
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("检查管理证书 current 指针失败: {}", e)),
    };

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let nonce = crate::config::random_nonce();
    let gen_name = format!("{ADMIN_GEN_PREFIX}{ts}-{nonce:016x}");
    let gen_dir = certs_dir.join(&gen_name);

    fs::DirBuilder::new()
        .mode(0o700)
        .create(&gen_dir)
        .map_err(|e| format!("创建管理证书代际目录失败: {}", e))?;
    let _ = fs::set_permissions(&gen_dir, fs::Permissions::from_mode(0o700));

    let write_res = (|| -> Result<(), String> {
        crate::config::crash_safe_atomic_write_with_mode(
            &gen_dir.join("admin.crt"),
            cert_pem,
            nonce,
            0o600,
            false,
        )
        .map_err(|e| format!("写入管理证书失败: {}", e))?;
        crate::config::crash_safe_atomic_write_with_mode(
            &gen_dir.join("admin.key"),
            key_pem,
            nonce.wrapping_add(1),
            0o600,
            false,
        )
        .map_err(|e| format!("写入管理私钥失败: {}", e))?;
        if let Ok(dir_fd) = fs::File::open(&gen_dir) {
            let _ = dir_fd.sync_all();
        }
        Ok(())
    })();
    if let Err(e) = write_res {
        let _ = fs::remove_dir_all(&gen_dir);
        return Err(e);
    }

    let tmp_current = certs_dir.join(format!(".current-{:016x}.tmp", crate::config::random_nonce()));
    if let Err(e) = symlink(&gen_name, &tmp_current) {
        let _ = fs::remove_dir_all(&gen_dir);
        return Err(format!("创建管理证书代际指针失败: {}", e));
    }
    if let Err(e) = fs::rename(&tmp_current, &current_link) {
        let _ = fs::remove_file(&tmp_current);
        let _ = fs::remove_dir_all(&gen_dir);
        return Err(format!("原子切换管理证书代际指针失败: {}", e));
    }

    // 同步原子维护兼容路径 certs/admin.{crt,key} -> current/admin.{crt,key}（rename 替换路径项本身，不跟随外部目标）
    for (name, rel_target) in [
        ("admin.crt", "current/admin.crt"),
        ("admin.key", "current/admin.key"),
    ] {
        let link_path = certs_dir.join(name);
        let already_matches = fs::symlink_metadata(&link_path)
            .ok()
            .filter(|m| m.file_type().is_symlink())
            .and_then(|_| fs::read_link(&link_path).ok())
            .is_some_and(|t| t == Path::new(rel_target));
        if !already_matches {
            let tmp = certs_dir.join(format!(".{name}-{:016x}.lnk", crate::config::random_nonce()));
            if symlink(rel_target, &tmp).is_ok() && fs::rename(&tmp, &link_path).is_err() {
                let _ = fs::remove_file(&tmp);
            }
        }
    }

    // 清理可能遗留的明文私钥 .bak 备份文件（仅删除普通文件，不跟随符号链接）
    for stale_bak in ["admin.key.bak", "admin.crt.bak"] {
        let p = certs_dir.join(stale_bak);
        if let Ok(meta) = fs::symlink_metadata(&p) {
            if meta.is_file() && !meta.file_type().is_symlink() {
                let _ = fs::remove_file(&p);
            }
        }
    }

    if let Ok(dir_fd) = fs::File::open(certs_dir) {
        let _ = dir_fd.sync_all();
    }

    // 仅回收更早的受管代际目录（保留当前代与上一代）
    if let Ok(entries) = fs::read_dir(certs_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_s = name.to_string_lossy();
            if is_valid_admin_gen_name(&name_s)
                && name_s != gen_name
                && previous
                    .as_ref()
                    .is_none_or(|old| old != Path::new(name_s.as_ref()))
                && entry.file_type().is_ok_and(|ft| ft.is_dir() && !ft.is_symlink())
            {
                let _ = fs::remove_dir_all(entry.path());
            }
        }
    }

    Ok(())
}

pub fn load_or_create_admin_cert(data_dir: &Path, listen_lan: &[String]) -> Result<Arc<CertifiedKey>, String> {
    let certs_dir = data_dir.join("certs");
    ensure_real_certs_dir(&certs_dir)?;

    if let Some((cert, key)) = read_admin_cert_pair(&certs_dir)? {
        // 损坏或缺失的持久化证书必须报错，不能静默换证导致信任漂移。
        let ck = certified_key_from_pem(&cert, &key)?;
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        if is_self_signed_cert_due_for_renewal(&cert, now_unix, SELF_SIGNED_RENEW_BEFORE_SECS)? {
            let (cert_pem, key_pem, renewed_ck) = generate_self_signed_cert(listen_lan)?;
            save_admin_cert_pair_atomic(&certs_dir, cert_pem.as_bytes(), key_pem.as_bytes())?;
            crate::logger::log(
                crate::logger::Level::Info,
                "admin",
                "本地自签管理证书已临期或需规范有效期，已自动原子签发新的 5 年期证书",
            );
            return Ok(renewed_ck);
        }
        return Ok(ck);
    }

    let (cert_pem, key_pem, ck) = generate_self_signed_cert(listen_lan)?;
    save_admin_cert_pair_atomic(&certs_dir, cert_pem.as_bytes(), key_pem.as_bytes())?;
    Ok(ck)
}

/// 后台周期巡检：仅当自签管理证书进入临期 30 天窗口时原子签发新 5 年证书并返回热更新句柄。
pub fn renew_admin_cert_if_due(data_dir: &Path, sans: &[String]) -> Result<Option<Arc<CertifiedKey>>, String> {
    let certs_dir = data_dir.join("certs");
    let Some((cert, key)) = read_admin_cert_pair(&certs_dir)? else {
        return Ok(None);
    };
    let _ = certified_key_from_pem(&cert, &key)?;
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if !is_self_signed_cert_due_for_renewal(&cert, now_unix, SELF_SIGNED_RENEW_BEFORE_SECS)? {
        return Ok(None);
    }
    let (cert_pem, key_pem, renewed_ck) = generate_self_signed_cert(sans)?;
    save_admin_cert_pair_atomic(&certs_dir, cert_pem.as_bytes(), key_pem.as_bytes())?;
    Ok(Some(renewed_ck))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_certificate_survives_reload_and_refuses_partial_pair() {
        let dir = std::env::temp_dir().join(format!("vane_cert_test_{}", crate::config::random_nonce()));
        let names = vec!["[::1]:23456".into()];
        let first = load_or_create_admin_cert(&dir, &names).unwrap();
        let second = load_or_create_admin_cert(&dir, &names).unwrap();
        assert_eq!(first.cert, second.cert);
        assert_eq!(fs::metadata(dir.join("certs/admin.key")).unwrap().permissions().mode() & 0o777, 0o600);
        fs::write(dir.join("certs/admin.key"), b"corrupt").unwrap();
        assert!(load_or_create_admin_cert(&dir, &names).is_err());
        assert_eq!(fs::read(dir.join("certs/admin.key")).unwrap(), b"corrupt");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn self_signed_cert_and_resolver_work() {
        let (_, _, ck) = generate_self_signed_cert(&["192.168.1.1:23456".into(), "router.local".into()]).unwrap();
        let mut table = CertTable::default();
        table.exact.insert("nas.example.com".into(), ck.clone());
        table.wildcard.insert(".home.example.com".into(), ck.clone());
        table.fallback = Some(ck);
        let shared = Arc::new(ArcSwap::from_pointee(table));

        let strict = DynamicCertResolver::new(shared.clone(), true);
        assert!(strict.lookup(Some("nas.example.com")).is_some());
        assert!(strict.lookup(Some("sub.home.example.com")).is_some());
        assert!(strict.lookup(Some("unknown.example.com")).is_none());
        assert!(strict.lookup(None).is_none());

        let non_strict = DynamicCertResolver::new(shared, false);
        assert!(non_strict.lookup(None).is_some());
    }

    #[test]
    fn self_signed_cert_has_5_year_validity_and_auto_renews_when_expiring() {
        let dir = std::env::temp_dir().join(format!("vane_cert_renew_{}", crate::config::random_nonce()));
        let names = vec!["127.0.0.1:23456".into(), "localhost".into()];

        // 1) 新生成证书有效期应为部署时间起约 5 年（非 1975~4096）
        let (cert_pem, _, _) = generate_self_signed_cert(&names).unwrap();
        let (nb, na) = parse_leaf_validity(cert_pem.as_bytes()).unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        assert!(nb <= now && nb >= now - 600, "not_before={nb}, now={now}");
        let days = (na - nb) / 86_400;
        assert!((1824..=1828).contains(&days), "expected ~5y (1826d), got {days}d");
        assert!(!is_self_signed_cert_due_for_renewal(cert_pem.as_bytes(), now, SELF_SIGNED_RENEW_BEFORE_SECS).unwrap());

        // 2) 写入一张仅剩 10 天过期的合法自签证书，校验自动续期为新 5 年证书
        fs::create_dir_all(dir.join("certs")).unwrap();
        let soon_nb = SystemTime::now() - Duration::from_secs(86_400);
        let soon_na = SystemTime::now() + Duration::from_secs(10 * 86_400);
        let (old_pem, old_key, old_ck) = generate_self_signed_cert_with_validity(&names, soon_nb, soon_na).unwrap();
        fs::write(dir.join("certs/admin.crt"), old_pem.as_bytes()).unwrap();
        fs::write(dir.join("certs/admin.key"), old_key.as_bytes()).unwrap();

        let renewed = renew_admin_cert_if_due(&dir, &names).unwrap().expect("should auto renew within 30d");
        assert_ne!(renewed.cert, old_ck.cert);
        let disk_pem = fs::read(dir.join("certs/admin.crt")).unwrap();
        let (new_nb, new_na) = parse_leaf_validity(&disk_pem).unwrap();
        assert!((new_na - new_nb) / 86_400 >= 1824);
        assert!(renew_admin_cert_if_due(&dir, &names).unwrap().is_none(), "fresh cert must not renew again");
        // 验证代际目录切换且未残留 admin.key.bak
        assert!(fs::symlink_metadata(dir.join("certs/current")).unwrap().file_type().is_symlink());
        assert!(!dir.join("certs/admin.key.bak").exists());

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn admin_cert_atomic_pair_rejects_symlinks_and_mismatched_keys() {
        use std::os::unix::fs::symlink;
        let dir = std::env::temp_dir().join(format!("vane_cert_atomic_{}", crate::config::random_nonce()));
        let certs_dir = dir.join("certs");
        let (cert1, key1, ck1) = generate_self_signed_cert(&["127.0.0.1:23456".into()]).unwrap();
        let (cert2, key2, _) = generate_self_signed_cert(&["127.0.0.1:23456".into()]).unwrap();

        save_admin_cert_pair_atomic(&certs_dir, cert1.as_bytes(), key1.as_bytes()).unwrap();
        // 失配证书/私钥必须报错且不破坏既有 current
        assert!(save_admin_cert_pair_atomic(&certs_dir, cert1.as_bytes(), key2.as_bytes()).is_err());
        let loaded = load_or_create_admin_cert(&dir, &["127.0.0.1:23456".into()]).unwrap();
        assert_eq!(loaded.cert, ck1.cert);
        assert!(!certs_dir.join("admin.key.bak").exists());

        // 恶意 current 指向受管前缀之外的目录必须拒绝
        let current = certs_dir.join("current");
        let _ = fs::remove_file(&current);
        symlink("/etc", &current).unwrap();
        assert!(read_admin_cert_pair(&certs_dir).is_err());

        // 合法回写后恢复（先移走非法指向以验证 legacy 符号链接拦截）
        let _ = fs::remove_file(&current);
        let _ = fs::remove_file(certs_dir.join("admin.crt"));
        let _ = fs::remove_file(certs_dir.join("admin.key"));
        fs::write(certs_dir.join("admin.crt"), cert2.as_bytes()).unwrap();
        symlink("/etc/hosts", certs_dir.join("admin.key")).unwrap();
        assert!(read_admin_cert_pair(&certs_dir).is_err());

        fs::remove_dir_all(dir).unwrap();
    }
}
