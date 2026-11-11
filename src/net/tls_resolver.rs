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
    let mut params = CertificateParams::default();
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

pub fn load_or_create_admin_cert(data_dir: &Path, listen_lan: &[String]) -> Result<Arc<CertifiedKey>, String> {
    let certs_dir = data_dir.join("certs");
    fs::create_dir_all(&certs_dir).map_err(|e| format!("创建证书目录失败: {}", e))?;
    fs::set_permissions(&certs_dir, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    let crt_path = certs_dir.join("admin.crt");
    let key_path = certs_dir.join("admin.key");

    if crt_path.exists() || key_path.exists() {
        // 损坏或缺失的持久化证书必须报错，不能静默换证导致信任漂移。
        let cert = fs::read(&crt_path).map_err(|e| format!("读取管理证书失败: {}", e))?;
        let key = fs::read(&key_path).map_err(|e| format!("读取管理私钥失败: {}", e))?;
        return certified_key_from_pem(&cert, &key);
    }

    let (cert_pem, key_pem, ck) = generate_self_signed_cert(listen_lan)?;            
    let nonce = crate::config::random_nonce();
    crate::config::crash_safe_atomic_write(&crt_path, cert_pem.as_bytes(), nonce).map_err(|e| e.to_string())?;
    crate::config::crash_safe_atomic_write(&key_path, key_pem.as_bytes(), nonce.wrapping_add(1)).map_err(|e| e.to_string())?;
    Ok(ck)
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
}
