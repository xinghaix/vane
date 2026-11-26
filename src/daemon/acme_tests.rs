use super::*;

#[test]
fn cname_alias_and_directory_resolution() {
    assert!(resolve_directory("letsencrypt").is_some());
    assert!(resolve_directory("zerossl").is_some());
    assert!(resolve_directory("http://insecure").is_none());
    assert_eq!(
        dns01_record_name("*.home.example.com", ""),
        "_acme-challenge.home.example.com"
    );
    assert_eq!(
        dns01_record_name("home.example.com", "_acme-challenge.auth.example.com"),
        "_acme-challenge.auth.example.com"
    );
}

#[tokio::test]
async fn actual_acme_jws_eab_nonce_csr_cleanup_and_account_restore() {
    use std::sync::atomic::Ordering;
    let dir = std::env::temp_dir().join(format!("vane_acme_{}", crate::config::random_nonce()));
    std::fs::create_dir_all(&dir).unwrap();
    let vault = Vault::from_master(&[2; 32]);
    let runtime = AcmeRuntime::new(dir.clone());
    let dns = Arc::new(super::mock::MockDns::default());
    let (directory, ca, server) = super::mock::start(dns.clone()).await;
    let cfg = AcmeConfig {
        domain: "home.example.com".into(),
        directory_url: directory.clone(),
        eab_kid: "test-eab".into(),
        eab_hmac_key: URL_SAFE_NO_PAD.encode([1; 32]),
        cert_dir: dir.join("certs").to_string_lossy().into_owned(),
        ..Default::default()
    };
    let account = account(&cfg, &directory, &vault, &runtime).await.unwrap();
    let restored = super::account(&cfg, &directory, &vault, &runtime)
        .await
        .unwrap();
    drop(restored);
    assert_eq!(ca.accounts.load(Ordering::Relaxed), 1);
    let journal_path = dir.join("journal.json");
    let mut journal = Journal::default();
    let (bundle, warning) = finish_order(
        &cfg,
        &directory,
        &account,
        dns.as_ref(),
        &journal_path,
        &mut journal,
    )
    .await
    .unwrap();
    assert!(warning.is_none());
    assert!(journal.leases.is_empty());
    assert!(dns.values.lock().unwrap().is_empty());
    assert_eq!(dns.deleted.load(Ordering::Relaxed), 1);
    assert!(ca.orders.load(Ordering::Relaxed) >= 2);
    assert!(ca.signatures.load(Ordering::Relaxed) >= 7);
    let verified = acme_store::verify(&bundle).unwrap();
    assert_eq!(verified.expires, 1893456000);
    let mut broken = bundle.clone();
    let (_, _, foreign) = crate::net::tls_resolver::generate_self_signed_cert(&[]).unwrap();
    let leaf = bundle
        .certificate
        .split_inclusive("-----END CERTIFICATE-----")
        .next()
        .unwrap();
    let foreign_pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64::engine::general_purpose::STANDARD.encode(&foreign.cert[0])
    );
    broken.certificate = format!("{leaf}\n{foreign_pem}");
    assert!(acme_store::verify(&broken).is_err());
    let path = acme_store::store(Path::new(&cfg.cert_dir), &cfg.domain, &bundle)
        .await
        .unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), bundle.certificate);
    let old = std::fs::read_link(path.parent().unwrap()).unwrap();
    let mut invalid = bundle.clone();
    invalid.domains.push("wrong.example.com".into());
    assert!(
        acme_store::store(Path::new(&cfg.cert_dir), &cfg.domain, &invalid)
            .await
            .is_err()
    );
    assert_eq!(std::fs::read_link(path.parent().unwrap()).unwrap(), old);
    let (_, _, admin) = crate::net::tls_resolver::generate_self_signed_cert(&[]).unwrap();
    let admin = Arc::new(ArcSwap::from(admin));
    let table = Arc::new(ArcSwap::from_pointee(CertTable::default()));
    let status = activate(&cfg, &Config::default(), &bundle, &table, &admin).unwrap();
    assert_eq!(status.status, "active");
    assert!(table.load().exact.contains_key("home.example.com"));
    let mut cached = bundle.clone();
    cached.directory = "https://ca.example/directory".into();
    acme_store::store(Path::new(&cfg.cert_dir), &cfg.domain, &cached)
        .await
        .unwrap();
    let cached_cfg = AcmeConfig {
        directory_url: cached.directory.clone(),
        deploy_hooks: vec![DeployHook::CopyToDir {
            dir: dir.join("deployed").to_string_lossy().into_owned(),
        }],
        ..cfg.clone()
    };
    let status = issue_or_renew_cert(
        &cached_cfg,
        &Config::default(),
        &vault,
        &table,
        &runtime,
        &admin,
        false,
    )
    .await
    .unwrap();
    assert_eq!(status.status, "active");
    assert_eq!(ca.accounts.load(Ordering::Relaxed), 1);
    let deployed = dir.join("deployed/home.example.com/current");
    assert!(deployed.join("privkey.pem").exists());
    let before = std::fs::read_link(&deployed).unwrap();
    issue_or_renew_cert(
        &cached_cfg,
        &Config::default(),
        &vault,
        &table,
        &runtime,
        &admin,
        false,
    )
    .await
    .unwrap();
    assert_eq!(std::fs::read_link(&deployed).unwrap(), before);
    let bad_admin_cfg = AcmeConfig {
        use_for_admin: true,
        ..cached_cfg
    };
    let previous = admin.load_full();
    assert!(activate(&bad_admin_cfg, &Config::default(), &cached, &table, &admin).is_err());
    assert!(Arc::ptr_eq(&previous, &admin.load_full()));
    let mut all = Config::default();
    all.admin.canonical_origin = "https://home.example.com:23456".into();
    activate(&bad_admin_cfg, &all, &cached, &table, &admin).unwrap();
    assert!(!Arc::ptr_eq(&previous, &admin.load_full()));
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn propagation_failure_keeps_cleanup_journal_until_recovery() {
    use std::sync::atomic::Ordering;
    let dir = std::env::temp_dir().join(format!(
        "vane_acme_failure_{}",
        crate::config::random_nonce()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let dns = Arc::new(super::mock::MockDns::default());
    dns.propagation_fail.store(true, Ordering::Relaxed);
    dns.cleanup_fail.store(true, Ordering::Relaxed);
    let (directory, _, server) = super::mock::start(dns.clone()).await;
    let cfg = AcmeConfig {
        domain: "home.example.com".into(),
        eab_kid: "test-eab".into(),
        eab_hmac_key: URL_SAFE_NO_PAD.encode([1; 32]),
        propagation_timeout_secs: 0,
        ..Default::default()
    };
    let vault = Vault::from_master(&[2; 32]);
    let runtime = AcmeRuntime::new(dir.clone());
    let account = account(&cfg, &directory, &vault, &runtime).await.unwrap();
    let path = dir.join("journal.json");
    let mut journal = Journal::default();
    let error = finish_order(
        &cfg,
        &directory,
        &account,
        dns.as_ref(),
        &path,
        &mut journal,
    )
    .await
    .err()
    .unwrap();
    assert!(error.contains("传播超时"));
    assert!(error.contains("清理待恢复"));
    let mut restored: Journal = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(restored.leases.len(), 1);
    dns.cleanup_fail.store(false, Ordering::Relaxed);
    cleanup(dns.as_ref(), &path, &mut restored).await.unwrap();
    assert!(restored.leases.is_empty());
    assert!(dns.values.lock().unwrap().is_empty());
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn cancellation_preserves_intent_before_dns_mutation() {
    use std::sync::atomic::Ordering;
    let dir = std::env::temp_dir().join(format!(
        "vane_acme_cancel_{}",
        crate::config::random_nonce()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let dns = Arc::new(super::mock::MockDns::default());
    dns.propagation_fail.store(true, Ordering::Relaxed);
    let (directory, _, server) = super::mock::start(dns.clone()).await;
    let cfg = AcmeConfig {
        domain: "home.example.com".into(),
        eab_kid: "test-eab".into(),
        eab_hmac_key: URL_SAFE_NO_PAD.encode([1; 32]),
        ..Default::default()
    };
    let vault = Vault::from_master(&[2; 32]);
    let runtime = AcmeRuntime::new(dir.clone());
    let account = account(&cfg, &directory, &vault, &runtime).await.unwrap();
    let path = dir.join("journal.json");
    let mut journal = Journal::default();
    tokio::time::timeout(Duration::from_secs(5),async {
        tokio::select! {
            _=dns.created.notified()=>{},
            result=order_certificate(&cfg,&directory,&account,dns.as_ref(),&path,&mut journal)=>panic!("订单意外提前结束: {:?}",result.err()),
        }
    }).await.unwrap();
    let mut restored: Journal = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(restored.leases.len(), 1);
    cleanup(dns.as_ref(), &path, &mut restored).await.unwrap();
    assert!(dns.values.lock().unwrap().is_empty());
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn self_signed_certificates_never_become_active_acme_results() {
    let (certificate, private_key, _) =
        crate::net::tls_resolver::generate_self_signed_cert(&["home.example.com".into()]).unwrap();
    let bundle = Bundle {
        directory: "https://ca.example/directory".into(),
        domains: vec!["home.example.com".into()],
        certificate,
        private_key,
    };
    assert!(acme_store::verify(&bundle).err().unwrap().contains("自签"));
}

#[tokio::test]
async fn acme_store_rejects_empty_single_label_bad_names_plaintext_account_and_pruned_preload() {
    // VANE-M13: safe_name / try_safe_name 拒绝空串与 "."/".."
    assert!(acme_store::try_safe_name("").is_err());
    assert!(acme_store::try_safe_name(".").is_err());
    assert!(acme_store::try_safe_name("..").is_err());
    assert!(acme_store::try_safe_name("...").is_err());
    assert_ne!(acme_store::safe_name("."), ".");
    assert_ne!(acme_store::safe_name(""), "");

    // VANE-M10: 内置公共 CA 启用 PublicOnly，自定义 CA 保留默认策略
    for ca in [
        "letsencrypt",
        "letsencrypt_staging",
        "zerossl",
        "google",
        "buypass",
        "https://acme-v02.api.letsencrypt.org/directory",
    ] {
        assert_eq!(
            AcmeTransport::for_directory(ca).ssrf_policy(),
            crate::net::http_client::SsrfPolicy::PublicOnly
        );
    }
    assert_eq!(
        AcmeTransport::for_directory("https://step-ca.internal/acme/acme/directory").ssrf_policy(),
        crate::net::http_client::SsrfPolicy::default()
    );

    // 签发一张含 2 个域名的测试 CA 证书，用于验证 verify 与 preload 交集过滤
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Vane Test CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_kp = rcgen::KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_kp).unwrap();
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_kp);

    let mut leaf_params =
        rcgen::CertificateParams::new(vec!["keep.example.com".into(), "pruned.example.com".into()]).unwrap();
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "keep.example.com");
    leaf_params.not_before = rcgen::date_time_ymd(2025, 1, 1);
    leaf_params.not_after = rcgen::date_time_ymd(2030, 1, 1);
    let leaf_kp = rcgen::KeyPair::generate().unwrap();
    let leaf_cert = leaf_params.signed_by(&leaf_kp, &issuer).unwrap();
    let fullchain = format!("{}{}", leaf_cert.pem(), ca_cert.pem());
    let privkey = leaf_kp.serialize_pem();

    // VANE-M13: verify 拒绝空 domains 与单标签域名
    let empty_bundle = Bundle {
        directory: "https://ca.example/directory".into(),
        domains: vec![],
        certificate: fullchain.clone(),
        private_key: privkey.clone(),
    };
    assert!(acme_store::verify(&empty_bundle).is_err());
    let single_label = Bundle {
        directory: "https://ca.example/directory".into(),
        domains: vec!["localhost".into()],
        certificate: fullchain.clone(),
        private_key: privkey.clone(),
    };
    assert!(acme_store::verify(&single_label).is_err());

    // VANE-L09: preload_cached_cert 仅加载当前 cfg.domain + extra_domains 的交集
    let dir = std::env::temp_dir().join(format!("vane_acme_preload_{}", crate::config::random_nonce()));
    std::fs::create_dir_all(&dir).unwrap();
    let valid_bundle = Bundle {
        directory: "https://ca.example/directory".into(),
        domains: vec!["keep.example.com".into(), "pruned.example.com".into()],
        certificate: fullchain,
        private_key: privkey,
    };
    acme_store::store(&dir.join("certs"), "keep.example.com", &valid_bundle)
        .await
        .unwrap();
    let cfg = AcmeConfig {
        enabled: true,
        domain: "keep.example.com".into(),
        extra_domains: vec![],
        cert_dir: dir.join("certs").to_string_lossy().into_owned(),
        ..Default::default()
    };
    let (_, _, admin_ck) = crate::net::tls_resolver::generate_self_signed_cert(&[]).unwrap();
    let admin = Arc::new(ArcSwap::from(admin_ck));
    let table = Arc::new(ArcSwap::from_pointee(CertTable::default()));
    let runtime = AcmeRuntime::new(dir.clone());
    preload_cached_cert(&cfg, &Config::default(), &table, &runtime, &admin).await;
    assert!(table.load().exact.contains_key("keep.example.com"));
    assert!(!table.load().exact.contains_key("pruned.example.com"));

    // VANE-L03: 明文未加密的 acme-accounts/*.json 必须被 vault.open 拒绝
    let directory = "https://ca.example/directory";
    let hash = ring::digest::digest(
        &ring::digest::SHA256,
        format!("{}\n{}\n{}", directory, cfg.email, cfg.eab_kid).as_bytes(),
    );
    let id: String = hash.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    let acc_path = dir.join("acme-accounts").join(format!("{id}.json"));
    acme_store::atomic(acc_path, br#"{"id":"https://ca.example/acct/1"}"#.to_vec())
        .await
        .unwrap();
    let vault = Vault::from_master(&[9; 32]);
    assert!(account(&cfg, directory, &vault, &runtime).await.is_err());

    let _ = std::fs::remove_dir_all(dir);
}
