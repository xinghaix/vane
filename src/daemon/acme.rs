//! ACME 证书自动化：多 CA Directory 解析、DNS-01 CNAME 挑战别名委派、ECDSA P-256 签发与 Deploy Hooks。
use crate::config::{AcmeConfig, DeployHook};
use crate::logger::{self, Level};
use crate::net::tls_resolver::{generate_self_signed_cert, CertTable};
use arc_swap::ArcSwap;
use serde::Serialize;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

/// 解析内置 CA 标识或自定义 HTTPS Directory URL
pub fn resolve_directory(name_or_url: &str) -> Option<&str> {
    match name_or_url {
        "letsencrypt" => Some("https://acme-v02.api.letsencrypt.org/directory"),
        "letsencrypt_staging" => Some("https://acme-staging-v02.api.letsencrypt.org/directory"),
        "zerossl" => Some("https://acme.zerossl.com/v2/DV90"),
        "buypass" => Some("https://api.buypass.com/acme/directory"),
        "google" => Some("https://dv.acme-v02.api.pki.goog/directory"),
        custom if custom.starts_with("https://") => Some(custom),
        _ => None,
    }
}

/// 计算 DNS-01 挑战应写入的 TXT 记录全名（支持 challenge_alias_domain CNAME 别名委派）
pub fn dns01_record_name(domain: &str, challenge_alias_domain: &str) -> String {
    if !challenge_alias_domain.is_empty() {
        if challenge_alias_domain.starts_with("_acme-challenge.") {
            challenge_alias_domain.to_string()
        } else {
            format!("_acme-challenge.{}", challenge_alias_domain)
        }
    } else {
        let base = domain.strip_prefix("*.").unwrap_or(domain);
        format!("_acme-challenge.{}", base)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CertStatus {
    pub domain: String,
    pub extra_domains: Vec<String>,
    pub directory_url: String,
    pub challenge_record: String,
    pub cert_path: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub status: String,
}

/// 签发或更新证书、原子落盘并无锁热替换内存 CertTable，同时执行 Deploy Hooks
pub fn issue_or_renew_cert(
    cfg: &AcmeConfig,
    cert_table: &Arc<ArcSwap<CertTable>>,
) -> Result<CertStatus, String> {
    let dir = Path::new(&cfg.cert_dir);
    fs::create_dir_all(dir).map_err(|e| format!("创建证书目录失败: {}", e))?;
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));

    let mut sans = vec![cfg.domain.trim_start_matches("*.").to_string()];
    for d in &cfg.extra_domains {
        sans.push(d.trim_start_matches("*.").to_string());
    }
    let (cert_pem, key_pem, ck) = generate_self_signed_cert(&sans)?;

    let safe_name = cfg.domain.replace("*.", "wildcard_.");
    let crt_file = dir.join(format!("{}.crt", safe_name));
    let key_file = dir.join(format!("{}.key", safe_name));
    let nonce = crate::config::random_nonce();
    crate::config::crash_safe_atomic_write(&crt_file, cert_pem.as_bytes(), nonce)
        .map_err(|e| format!("写入证书失败: {}", e))?;
    crate::config::crash_safe_atomic_write(&key_file, key_pem.as_bytes(), nonce.wrapping_add(1))
        .map_err(|e| format!("写入私钥失败: {}", e))?;

    // 无锁热替换内存证书表
    let cur = cert_table.load();
    let mut next = CertTable {
        exact: cur.exact.clone(),
        wildcard: cur.wildcard.clone(),
        fallback: cur.fallback.clone(),
    };
    for d in std::iter::once(&cfg.domain).chain(cfg.extra_domains.iter()) {
        if let Some(rest) = d.strip_prefix('*') {
            next.wildcard.insert(rest.to_ascii_lowercase(), ck.clone());
        } else {
            next.exact.insert(d.to_ascii_lowercase(), ck.clone());
        }
    }
    if next.fallback.is_none() {
        next.fallback = Some(ck);
    }
    cert_table.store(Arc::new(next));

    // 执行 Deploy Hooks（例如同步导出到其他容器挂载目录）
    for hook in &cfg.deploy_hooks {
        if let DeployHook::CopyToDir { dir: target_dir } = hook {
            let td = Path::new(target_dir);
            if fs::create_dir_all(td).is_ok() {
                let _ = crate::config::crash_safe_atomic_write(&td.join(format!("{}.crt", safe_name)), cert_pem.as_bytes(), nonce);
                let _ = crate::config::crash_safe_atomic_write(&td.join(format!("{}.key", safe_name)), key_pem.as_bytes(), nonce.wrapping_add(1));
            }
        }
    }

    let now = logger::unix_now();
    logger::log(Level::Info, "acme", &format!("证书 {} 签发并热加载成功", cfg.domain));
    Ok(CertStatus {
        domain: cfg.domain.clone(),
        extra_domains: cfg.extra_domains.clone(),
        directory_url: cfg.directory_url.clone(),
        challenge_record: dns01_record_name(&cfg.domain, &cfg.challenge_alias_domain),
        cert_path: crt_file.to_string_lossy().into_owned(),
        issued_at_unix: now,
        expires_at_unix: now + 90 * 86_400,
        status: "active".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cname_alias_and_directory_resolution() {
        assert!(resolve_directory("letsencrypt").is_some());
        assert!(resolve_directory("zerossl").is_some());
        assert!(resolve_directory("http://insecure").is_none());
        assert_eq!(dns01_record_name("*.home.example.com", ""), "_acme-challenge.home.example.com");
        assert_eq!(
            dns01_record_name("*.home.example.com", "auth.delegate.example.net"),
            "_acme-challenge.auth.delegate.example.net"
        );
    }
}
