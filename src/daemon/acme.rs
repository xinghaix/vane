//! 真实 RFC8555 DNS-01 签发：账户复用、EAB、传播验证、挑战清理、续期和部署钩子。
use super::{
    acme_dns::{ChallengeDns, Lease, ProviderDns},
    acme_store::{self, Bundle},
    acme_transport::AcmeTransport,
    dns_api::DnsApi,
};
use crate::{
    config::{AcmeConfig, Config, DeployHook},
    logger,
    net::tls_resolver::CertTable,
    security::vault::Vault,
};
use arc_swap::ArcSwap;
use base64::{
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, ExternalAccountKey, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ops::Deref,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock, Weak},
    time::Duration,
};

pub fn resolve_directory(value: &str) -> Option<&str> {
    match value {
        "letsencrypt" => Some("https://acme-v02.api.letsencrypt.org/directory"),
        "letsencrypt_staging" => Some("https://acme-staging-v02.api.letsencrypt.org/directory"),
        "zerossl" => Some("https://acme.zerossl.com/v2/DV90"),
        "buypass" => Some("https://api.buypass.com/acme/directory"),
        "google" => Some("https://dv.acme-v02.api.pki.goog/directory"),
        custom if custom.starts_with("https://") => Some(custom),
        _ => None,
    }
}
pub fn dns01_record_name(domain: &str, alias: &str) -> String {
    if alias.starts_with("_acme-challenge.") {
        alias.into()
    } else {
        format!(
            "_acme-challenge.{}",
            if alias.is_empty() {
                domain.strip_prefix("*.").unwrap_or(domain)
            } else {
                alias
            }
        )
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct CertStatus {
    pub domain: String,
    pub extra_domains: Vec<String>,
    pub directory_url: String,
    pub challenge_record: String,
    pub cert_path: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub status: String,
    pub last_error: Option<String>,
}
#[derive(Default)]
pub struct AcmeRuntime {
    statuses: RwLock<BTreeMap<String, CertStatus>>,
    locks: Mutex<BTreeMap<String, Weak<tokio::sync::Mutex<()>>>>,
    data_dir: PathBuf,
    slots: std::sync::OnceLock<tokio::sync::Semaphore>,
}
impl Deref for AcmeRuntime {
    type Target = RwLock<BTreeMap<String, CertStatus>>;
    fn deref(&self) -> &Self::Target {
        &self.statuses
    }
}
impl AcmeRuntime {
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            ..Default::default()
        }
    }
    fn lock(&self, id: &str) -> Result<Arc<tokio::sync::Mutex<()>>, String> {
        let mut locks = self.locks.lock().map_err(|_| "ACME 锁损坏")?;
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(id).and_then(Weak::upgrade) {
            return Ok(lock);
        }
        if locks.len() > 128 {
            return Err("ACME 并发任务超过上限".into());
        }
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        locks.insert(id.into(), Arc::downgrade(&lock));
        Ok(lock)
    }
}

#[derive(Default, Serialize, Deserialize)]
struct Journal {
    provider: String,
    leases: Vec<Lease>,
}
async fn save_journal(path: &Path, journal: &Journal) -> Result<(), String> {
    acme_store::atomic(
        path.to_path_buf(),
        serde_json::to_vec(journal).map_err(|_| "挑战清理日志序列化失败")?,
    )
    .await
}
async fn cleanup(dns: &dyn ChallengeDns, path: &Path, journal: &mut Journal) -> Result<(), String> {
    let mut remaining = Vec::new();
    for lease in &journal.leases {
        if dns.cleanup(lease).await.is_err() {
            remaining.push(lease.clone());
        }
    }
    journal.leases = remaining;
    save_journal(path, journal).await?;
    if journal.leases.is_empty() {
        Ok(())
    } else {
        Err("部分挑战 TXT 清理失败，已保留恢复日志".into())
    }
}

async fn account(
    cfg: &AcmeConfig,
    directory: &str,
    vault: &Vault,
    runtime: &AcmeRuntime,
) -> Result<Account, String> {
    let hash = ring::digest::digest(
        &ring::digest::SHA256,
        format!("{}\n{}\n{}", directory, cfg.email, cfg.eab_kid).as_bytes(),
    );
    let id: String = hash.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    let lock = runtime.lock(&format!("account:{id}"))?;
    let _guard = lock.lock().await;
    let path = runtime
        .data_dir
        .join("acme-accounts")
        .join(format!("{id}.json"));
    let aad = format!("acme.account.{id}");
    let builder = Account::builder_with_http(Box::new(AcmeTransport));
    if let Some(bytes) = acme_store::read_bounded(&path, 128 * 1024).await? {
        let encoded = std::str::from_utf8(&bytes).map_err(|_| "账户文件编码错误")?;
        let plain = vault.reveal_string(&aad, encoded)?;
        let credentials = serde_json::from_str(&plain).map_err(|_| "账户凭据文件损坏")?;
        return builder
            .from_credentials(credentials)
            .await
            .map_err(|_| "恢复 ACME 账户失败".into());
    }
    let eab = if cfg.eab_kid.is_empty() {
        None
    } else {
        let secret = vault.reveal_string(
            &format!("acme.{}.eab_hmac_key", cfg.domain),
            &cfg.eab_hmac_key,
        )?;
        let key = URL_SAFE_NO_PAD
            .decode(&secret)
            .or_else(|_| URL_SAFE.decode(&secret))
            .map_err(|_| "EAB 密钥不是 base64url")?;
        if key.is_empty() {
            return Err("EAB 密钥为空".into());
        }
        Some(ExternalAccountKey::new(cfg.eab_kid.clone(), &key))
    };
    let contact = if cfg.email.is_empty() {
        Vec::new()
    } else {
        vec![format!("mailto:{}", cfg.email)]
    };
    let contacts: Vec<_> = contact.iter().map(String::as_str).collect();
    let (account, credentials) = builder
        .create(
            &NewAccount {
                contact: &contacts,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory.into(),
            eab.as_ref(),
        )
        .await
        .map_err(|_| "创建 ACME 账户失败，请核对 CA、条款和 EAB 凭据")?;
    let bytes = serde_json::to_vec(&credentials).map_err(|_| "账户凭据序列化失败")?;
    acme_store::atomic(path, vault.seal(&aad, &bytes)?.into_bytes()).await?;
    Ok(account)
}

/// 网络取消或进程退出时，已写入的挑战意图日志会在下次签发前恢复清理。
async fn order_certificate(
    cfg: &AcmeConfig,
    directory: &str,
    account: &Account,
    dns: &dyn ChallengeDns,
    journal_path: &Path,
    journal: &mut Journal,
) -> Result<Bundle, String> {
    let domains: Vec<_> = std::iter::once(&cfg.domain)
        .chain(cfg.extra_domains.iter())
        .cloned()
        .collect();
    let identifiers: Vec<_> = domains
        .iter()
        .map(|name| Identifier::Dns(name.clone()))
        .collect();
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .map_err(|_| "创建 ACME 订单失败")?;
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authorization = result.map_err(|_| "读取 ACME 授权失败")?;
        if authorization.status == AuthorizationStatus::Valid {
            continue;
        }
        if authorization.status != AuthorizationStatus::Pending {
            return Err("ACME 授权不处于可验证状态".into());
        }
        let mut challenge = authorization
            .challenge(ChallengeType::Dns01)
            .ok_or("CA 未提供 DNS-01 挑战")?;
        let domain = challenge.identifier().to_string();
        let name = dns01_record_name(&domain, &cfg.challenge_alias_domain);
        let value = challenge.key_authorization().dns_value();
        let lease = dns.prepare(&name, &value).await?;
        journal.leases.push(lease.clone());
        save_journal(journal_path, journal).await?;
        dns.create(&lease).await?;
        // 查询原始挑战名，确保 CNAME 委派本身也已生效，而不只检查目标 TXT。
        let lookup_name = dns01_record_name(&domain, "");
        tokio::time::timeout(Duration::from_secs(cfg.propagation_timeout_secs), async {
            loop {
                if dns.propagated(&lookup_name, &value).await? {
                    return Ok::<(), String>(());
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        })
        .await
        .map_err(|_| "DNS-01 TXT 传播超时")??;
        challenge
            .set_ready()
            .await
            .map_err(|_| "提交 DNS-01 挑战失败")?;
    }
    let retries = RetryPolicy::new()
        .initial_delay(Duration::from_millis(250))
        .backoff(1.5)
        .timeout(Duration::from_secs(120));
    if order
        .poll_ready(&retries)
        .await
        .map_err(|_| "等待 ACME 授权完成失败")?
        != OrderStatus::Ready
    {
        return Err("ACME 订单未通过验证".into());
    }
    let private_key = order.finalize().await.map_err(|_| "提交 CSR 失败")?;
    let certificate = order
        .poll_certificate(&retries)
        .await
        .map_err(|_| "获取 CA 证书失败")?;
    Ok(Bundle {
        directory: directory.into(),
        domains,
        certificate,
        private_key,
    })
}

async fn finish_order(
    cfg: &AcmeConfig,
    directory: &str,
    account: &Account,
    dns: &dyn ChallengeDns,
    path: &Path,
    journal: &mut Journal,
) -> Result<(Bundle, Option<String>), String> {
    let result = tokio::time::timeout(
        Duration::from_secs(
            cfg.propagation_timeout_secs
                .saturating_mul((cfg.extra_domains.len() + 1) as u64)
                + 300,
        ),
        order_certificate(cfg, directory, account, dns, path, journal),
    )
    .await
    .map_err(|_| "ACME 订单整体超时".to_string())
    .and_then(|result| result);
    let cleanup_error = cleanup(dns, path, journal).await.err();
    match result {
        Ok(bundle) => Ok((bundle, cleanup_error)),
        Err(error) => Err(if cleanup_error.is_some() {
            format!("{error}；挑战清理待恢复")
        } else {
            error
        }),
    }
}

async fn deploy(cfg: &AcmeConfig, vault: &Vault, bundle: &Bundle) -> Result<(), String> {
    for (index, hook) in cfg.deploy_hooks.iter().enumerate() {
        let fingerprint = ring::digest::digest(
            &ring::digest::SHA256,
            &serde_json::to_vec(&(hook, &bundle.certificate)).map_err(|_| "部署指纹序列化失败")?,
        );
        let marker = Path::new(&cfg.cert_dir)
            .join(acme_store::safe_name(&cfg.domain))
            .join(format!("deployment-{index}.sha256"));
        if acme_store::read_bounded(&marker, 64).await?.as_deref() == Some(fingerprint.as_ref()) {
            continue;
        }
        match hook {
            DeployHook::CopyToDir { dir } => {
                acme_store::store(Path::new(dir), &cfg.domain, bundle).await?;
            }
            DeployHook::Webhook {
                url,
                include_private_key,
            } => {
                let url = vault.reveal_string(
                    &format!("acme.{}.deploy_hooks.{}.url", cfg.domain, index),
                    url,
                )?;
                let mut payload =
                    serde_json::json!({"domain":cfg.domain,"certificate_pem":bundle.certificate});
                if *include_private_key {
                    if !url.starts_with("https://") {
                        return Err("包含私钥的部署 Webhook 必须使用 HTTPS".into());
                    }
                    payload["private_key_pem"] = serde_json::json!(bundle.private_key);
                }
                let request =
                    crate::net::http_client::HttpRequest::new("POST", &url).json(&payload);
                crate::net::http_client::shared()
                    .execute(request)
                    .await?
                    .ensure_success()?;
            }
        }
        acme_store::atomic(marker, fingerprint.as_ref().to_vec()).await?;
    }
    Ok(())
}

fn activate(
    cfg: &AcmeConfig,
    all: &Config,
    bundle: &Bundle,
    table: &Arc<ArcSwap<CertTable>>,
    admin: &Arc<ArcSwap<rustls::sign::CertifiedKey>>,
) -> Result<CertStatus, String> {
    let verified = acme_store::verify(bundle)?;
    if verified.expires <= logger::unix_now() || verified.issued > logger::unix_now() + 300 {
        return Err("证书尚未生效或已过期".into());
    }
    if cfg.use_for_admin {
        let uri: http::Uri = all
            .admin
            .canonical_origin
            .parse()
            .map_err(|_| "管理域名无效")?;
        let host = uri.host().ok_or("管理域名缺失")?;
        if !bundle.domains.iter().any(|name| {
            name.eq_ignore_ascii_case(host)
                || name.strip_prefix("*.").is_some_and(|suffix| {
                    host.split_once('.')
                        .is_some_and(|(_, tail)| tail.eq_ignore_ascii_case(suffix))
                })
        }) {
            return Err("管理证书不覆盖 canonical_origin 主机名".into());
        }
    }
    table.rcu(|current| {
        let mut next = CertTable {
            exact: current.exact.clone(),
            wildcard: current.wildcard.clone(),
            fallback: current.fallback.clone(),
        };
        for name in &bundle.domains {
            if let Some(suffix) = name.strip_prefix('*') {
                next.wildcard
                    .insert(suffix.to_ascii_lowercase(), verified.key.clone());
            } else {
                next.exact
                    .insert(name.to_ascii_lowercase(), verified.key.clone());
            }
        }
        Arc::new(next)
    });
    if cfg.use_for_admin {
        admin.store(verified.key);
    }
    Ok(CertStatus {
        domain: cfg.domain.clone(),
        extra_domains: cfg.extra_domains.clone(),
        directory_url: bundle.directory.clone(),
        challenge_record: dns01_record_name(&cfg.domain, &cfg.challenge_alias_domain),
        cert_path: Path::new(&cfg.cert_dir)
            .join(acme_store::safe_name(&cfg.domain))
            .join("current/fullchain.pem")
            .to_string_lossy()
            .into_owned(),
        issued_at_unix: verified.issued,
        expires_at_unix: verified.expires,
        status: "active".into(),
        last_error: None,
    })
}

pub async fn issue_or_renew_cert(
    cfg: &AcmeConfig,
    all: &Config,
    vault: &Vault,
    table: &Arc<ArcSwap<CertTable>>,
    runtime: &AcmeRuntime,
    admin: &Arc<ArcSwap<rustls::sign::CertifiedKey>>,
    force: bool,
) -> Result<CertStatus, String> {
    if !all.modules.acme || !cfg.enabled {
        return Err("ACME 模块或规则未启用".into());
    }
    crate::config::validate_domain(&cfg.domain)?;
    let _slot = runtime
        .slots
        .get_or_init(|| tokio::sync::Semaphore::new(2))
        .try_acquire()
        .map_err(|_| "ACME 同时签发任务已达上限")?;
    let lock = runtime.lock(&format!("domain:{}", cfg.domain))?;
    let _guard = lock.try_lock().map_err(|_| "该域名已有签发任务")?;
    let result = async {
        let directory =
            resolve_directory(&cfg.directory_url).ok_or("CA Directory 必须使用 HTTPS")?;
        let journal_path = runtime
            .data_dir
            .join("acme-challenges")
            .join(format!("{}.json", acme_store::safe_name(&cfg.domain)));
        let mut journal = match acme_store::read_bounded(&journal_path, 128 * 1024).await? {
            Some(bytes) => {
                serde_json::from_slice::<Journal>(&bytes).map_err(|_| "挑战清理日志损坏")?
            }
            None => Journal {
                provider: cfg.dns_provider.clone(),
                leases: Vec::new(),
            },
        };
        let mut restored_dns = None;
        if !journal.leases.is_empty() {
            if journal.provider != cfg.dns_provider {
                return Err("遗留挑战属于其他 DNS 账号，需先恢复原账号进行清理".into());
            }
            let provider = all
                .dns_providers
                .get(&cfg.dns_provider)
                .ok_or("清理遗留挑战所需 DNS 服务商不存在")?;
            let dns = ProviderDns::new(DnsApi::new(&cfg.dns_provider, provider, vault)?)?;
            cleanup(&dns, &journal_path, &mut journal).await?;
            restored_dns = Some(dns);
        }
        let path = acme_store::bundle_path(Path::new(&cfg.cert_dir), &cfg.domain);
        if let Some(bytes) = acme_store::read_bounded(&path, 1024 * 1024).await? {
            let bundle: Bundle = serde_json::from_slice(&bytes).map_err(|_| "持久化证书包损坏")?;
            let metadata = acme_store::verify(&bundle)?;
            let mut wanted: Vec<_> = std::iter::once(cfg.domain.clone())
                .chain(cfg.extra_domains.clone())
                .collect();
            wanted.sort();
            let mut existing = bundle.domains.clone();
            existing.sort();
            if !force
                && wanted == existing
                && bundle.directory == directory
                && metadata.expires > logger::unix_now() + u64::from(cfg.renew_before_days) * 86400
            {
                let mut status = activate(cfg, all, &bundle, table, admin)?;
                if let Err(error) = deploy(cfg, vault, &bundle).await {
                    status.status = "deployment_failed".into();
                    status.last_error = Some(error);
                }
                return Ok(status);
            }
        }
        let provider = all
            .dns_providers
            .get(&cfg.dns_provider)
            .ok_or("ACME DNS 服务商不存在")?;
        let dns = match restored_dns {
            Some(dns) => dns,
            None => ProviderDns::new(DnsApi::new(&cfg.dns_provider, provider, vault)?)?,
        };
        journal.provider = cfg.dns_provider.clone();
        let account = account(cfg, directory, vault, runtime).await?;
        let (bundle, cleanup_error) =
            finish_order(cfg, directory, &account, &dns, &journal_path, &mut journal).await?;
        acme_store::store(Path::new(&cfg.cert_dir), &cfg.domain, &bundle).await?;
        let mut status = activate(cfg, all, &bundle, table, admin)?;
        if let Some(error) = cleanup_error {
            status.status = "cleanup_failed".into();
            status.last_error = Some(error);
        }
        if let Err(error) = deploy(cfg, vault, &bundle).await {
            status.status = "deployment_failed".into();
            status.last_error = Some(error);
        }
        super::notify::broadcast_event(
            all,
            vault,
            "acme_renewed",
            &format!("TLS 证书已签发/续期: {}", cfg.domain),
            &format!("域名 {} 证书已更新并热加载，有效期至 {}", cfg.domain, logger::format_iso8601_utc(status.expires_at_unix)),
            "info",
        )
        .await;
        Ok::<_, String>(status)
    }
    .await;
    match &result {
        Ok(status) => {
            runtime
                .write()
                .map_err(|_| "证书状态锁损坏")?
                .insert(cfg.domain.clone(), status.clone());
        }
        Err(error) => {
            let was_failed = {
                let mut statuses = runtime.write().map_err(|_| "证书状态锁损坏")?;
                let status = statuses
                    .entry(cfg.domain.clone())
                    .or_insert_with(|| CertStatus {
                        domain: cfg.domain.clone(),
                        ..Default::default()
                    });
                let prev_failed = status.status == "failed";
                status.status = "failed".into();
                status.last_error = Some(error.clone());
                prev_failed
            };
            if !was_failed {
                super::notify::broadcast_event(
                    all,
                    vault,
                    "acme_failure",
                    &format!("ACME 证书签发失败: {}", cfg.domain),
                    error,
                    "warning",
                )
                .await;
            }
        }
    }
    result
}

#[cfg(test)]
#[path = "acme_mock.rs"]
mod mock;

#[cfg(test)]
#[path = "acme_tests.rs"]
mod tests;
