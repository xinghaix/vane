//! 证书元数据验证和代际持久化：证书与私钥写完后才原子切换 current 指针。
use crate::{
    config::{crash_safe_atomic_write, random_nonce},
    net::tls_resolver::certified_key_from_pem,
};
use serde::{Deserialize, Serialize};
use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::io::AsyncReadExt;

#[derive(Clone, Serialize, Deserialize)]
pub struct Bundle {
    pub directory: String,
    pub domains: Vec<String>,
    pub certificate: String,
    pub private_key: String,
}
pub struct Verified {
    pub key: Arc<rustls::sign::CertifiedKey>,
    pub issued: u64,
    pub expires: u64,
}

pub fn verify(bundle: &Bundle) -> Result<Verified, String> {
    let key = certified_key_from_pem(bundle.certificate.as_bytes(), bundle.private_key.as_bytes())?;
    if key.cert.len() > 8 {
        return Err("证书链超过 8 张证书上限".into());
    }
    for pair in key.cert.windows(2) {
        let (_, child) =
            x509_parser::parse_x509_certificate(pair[0].as_ref()).map_err(|_| "证书 DER 无效")?;
        let (_, issuer) = x509_parser::parse_x509_certificate(pair[1].as_ref())
            .map_err(|_| "签发者证书 DER 无效")?;
        if child.issuer() != issuer.subject() {
            return Err("证书链签发者名称不匹配".into());
        }
        if !issuer
            .basic_constraints()
            .map_err(|_| "签发者约束无效")?
            .is_some_and(|value| value.value.ca)
        {
            return Err("证书链签发者不是 CA".into());
        }
        child
            .verify_signature(Some(issuer.public_key()))
            .map_err(|_| "证书链签名验证失败")?;
    }
    let (_, certificate) =
        x509_parser::parse_x509_certificate(key.cert[0].as_ref()).map_err(|_| "证书 DER 无效")?;
    if certificate.subject() == certificate.issuer() {
        return Err("拒绝将自签证书标记为 ACME 签发结果".into());
    }
    if certificate
        .basic_constraints()
        .map_err(|_| "证书 basicConstraints 无效")?
        .is_some_and(|value| value.value.ca)
    {
        return Err("ACME 返回的是 CA 证书而非服务证书".into());
    }
    let san = certificate
        .subject_alternative_name()
        .map_err(|_| "证书 SAN 无效")?
        .ok_or("证书缺少 SAN")?;
    for domain in &bundle.domains {
        if !san.value.general_names.iter().any(|name|matches!(name,x509_parser::extensions::GeneralName::DNSName(name) if name.eq_ignore_ascii_case(domain))) {
            return Err("签发证书缺少请求的域名 SAN".into());
        }
    }
    let issued = u64::try_from(certificate.validity().not_before.timestamp())
        .map_err(|_| "证书生效时间非法")?;
    let expires = u64::try_from(certificate.validity().not_after.timestamp())
        .map_err(|_| "证书过期时间非法")?;
    if expires <= issued {
        return Err("证书有效期为空".into());
    }
    Ok(Verified {
        key,
        issued,
        expires,
    })
}

pub async fn read_bounded(path: &Path, limit: u64) -> Result<Option<Vec<u8>>, String> {
    let file = match tokio::fs::File::open(path).await {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("读取 ACME 持久化文件失败".into()),
    };
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| "读取 ACME 文件失败")?;
    if bytes.len() as u64 > limit {
        return Err("ACME 文件超过大小上限".into());
    }
    Ok(Some(bytes))
}

pub async fn atomic(path: PathBuf, bytes: Vec<u8>) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|_| "创建 ACME 目录失败")?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| "收紧 ACME 目录权限失败")?;
        }
        crash_safe_atomic_write(&path, &bytes, random_nonce()).map_err(|_| "ACME 原子写入失败")
    })
    .await
    .map_err(|_| "ACME 持久化任务失败")??;
    Ok(())
}

pub fn safe_name(domain: &str) -> String {
    domain.replace("*.", "wildcard_.")
}
pub fn bundle_path(dir: &Path, domain: &str) -> PathBuf {
    dir.join(safe_name(domain))
        .join("current")
        .join("bundle.json")
}

pub async fn store(dir: &Path, domain: &str, bundle: &Bundle) -> Result<PathBuf, String> {
    let verified = verify(bundle)?;
    if verified.expires <= crate::logger::unix_now()
        || verified.issued > crate::logger::unix_now() + 300
    {
        return Err("签发证书不在当前有效期内".into());
    }
    let root = dir.join(safe_name(domain));
    let generation = format!("generation-{:016x}", random_nonce());
    let destination = root.join(&generation);
    atomic(
        destination.join("fullchain.pem"),
        bundle.certificate.as_bytes().to_vec(),
    )
    .await?;
    atomic(
        destination.join("privkey.pem"),
        bundle.private_key.as_bytes().to_vec(),
    )
    .await?;
    atomic(
        destination.join("bundle.json"),
        serde_json::to_vec(bundle).map_err(|_| "证书包序列化失败")?,
    )
    .await?;
    let result = root.join("current").join("fullchain.pem");
    tokio::task::spawn_blocking(move || {
        use std::os::unix::fs::symlink;
        let current = root.join("current");
        let previous = std::fs::read_link(&current).ok();
        if let Ok(metadata) = std::fs::symlink_metadata(&current) {
            if !metadata.file_type().is_symlink() {
                return Err("证书 current 路径不是受管符号链接".to_string());
            }
        }
        let temporary = root.join(format!("current-{:016x}.tmp", random_nonce()));
        symlink(&generation, &temporary).map_err(|_| "创建证书代际指针失败")?;
        std::fs::rename(&temporary, &current).map_err(|_| "切换证书代际指针失败")?;
        std::fs::File::open(&root)
            .and_then(|file| file.sync_all())
            .map_err(|_| "同步证书目录失败")?;
        // 只回收专用目录中的受管代际，保留当前代和上一个代，不跟随目录符号链接。
        for entry in std::fs::read_dir(&root).map_err(|_| "读取证书代际目录失败")? {
            let entry = entry.map_err(|_| "读取证书代际条目失败")?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let managed = name.strip_prefix("generation-").is_some_and(|suffix| {
                suffix.len() == 16 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
            });
            if managed
                && name != generation
                && previous
                    .as_ref()
                    .is_none_or(|old| old != Path::new(name.as_ref()))
                && entry
                    .file_type()
                    .map_err(|_| "读取证书代际类型失败")?
                    .is_dir()
            {
                std::fs::remove_dir_all(entry.path()).map_err(|_| "回收旧证书代际失败")?;
            }
        }
        Ok::<(), String>(())
    })
    .await
    .map_err(|_| "证书切换任务失败")??;
    Ok(result)
}
