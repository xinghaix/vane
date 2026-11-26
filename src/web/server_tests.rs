use super::*;
use axum::routing::get;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn exercise_listener(bind_addr: &str) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let listener = match bind(bind_addr.parse().unwrap()) {
        Ok(listener) => listener,
        Err(e) if bind_addr.starts_with('[') && matches!(e.kind(), io::ErrorKind::AddrNotAvailable | io::ErrorKind::Unsupported) => return,
        Err(e) => panic!("绑定测试监听器失败: {e}"),
    };
    let addr = listener.local_addr().unwrap();
    let (_, _, key) = crate::net::tls_resolver::generate_self_signed_cert(&[
        "[2001:db8::1234]:23456".into(), "127.0.0.1:23456".into()
    ]).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(key.cert[0].clone()).unwrap();
    let client = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    let app = Router::new().route("/", get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move { peer.ip().to_string() }));
    let quota = Arc::new(Semaphore::new(16));
    let task = tokio::spawn(serve(listener, app, Arc::new(tls_config(key)), "https://router.example:23456".into(), quota,
        Duration::from_secs(1), Duration::from_secs(1)));
    let mut plain = tokio::net::TcpStream::connect(addr).await.unwrap();
    plain.write_all(b"GET / HTTP/1.1\r\nHost: attacker.example\r\n\r\n").await.unwrap();
    let mut buf = [0; 512];
    let n = tokio::time::timeout(Duration::from_secs(2), plain.read(&mut buf)).await.unwrap().unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.starts_with("HTTP/1.1 308"));
    assert!(response.contains("Location: https://router.example:23456/"));
    assert!(!response.contains("attacker.example"));

    // 通过 IPv4 或 IPv6 socket 连接，并用显式 IPv6 SAN 验证证书。
    let socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
    let name = rustls::pki_types::ServerName::IpAddress("2001:db8::1234".parse::<std::net::IpAddr>().unwrap().into());
    let mut secure = connector.connect(name, socket).await.unwrap();
    secure.write_all(b"GET / HTTP/1.1\r\nHost: router.example:23456\r\nConnection: close\r\nX-Real-IP: 198.51.100.4\r\n\r\n").await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), secure.read_to_end(&mut response)).await.unwrap().unwrap();
    let response = String::from_utf8_lossy(&response);
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.ends_with(&addr.ip().to_string()));
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn https_ipv4_and_fixed_plaintext_redirect() { exercise_listener("127.0.0.1:0").await; }

#[tokio::test]
async fn https_ipv6_and_fixed_plaintext_redirect() { exercise_listener("[::1]:0").await; }

mod wave2_security_regressions {
    use crate::config::save_config;
    use crate::daemon::acme::AcmeRuntime;
    use crate::daemon::cron::CronRuntime;
    use crate::firewall::FirewallManager;
    use crate::logger;
    use crate::monitor::alerts::AlertState;
    use crate::monitor::procfs::MonitorSampler;
    use crate::net::dual_stack::BanKey;
    use crate::net::listener::ConnectionQuota;
    use crate::net::tls_resolver::CertTable;
    use crate::security::auth::{base32_encode, totp_code, AuthState, HashGate, PasswordHash, SessionStore};
    use crate::security::fail2ban::{Fail2Ban, ScopedFail2Ban, MAX_TRACKED_KEYS};
    use crate::security::vault::Vault;
    use crate::web::ws_pty::PtyManager;
    use crate::web::{build_router, AppState};
    use arc_swap::ArcSwap;
    use axum::body::{to_bytes, Body};
    use axum::extract::ConnectInfo;
    use axum::http::{header, Request, StatusCode};
    use axum::Router;
    use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
    use base64::Engine;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::sync::Notify;
    use tower::ServiceExt;

    fn req_from(ip: &str) -> axum::http::request::Builder {
        Request::builder()
            .header(header::HOST, "192.168.1.1:23456")
            .header(header::ORIGIN, "https://192.168.1.1:23456")
            .extension(ConnectInfo(format!("{ip}:23456").parse::<SocketAddr>().unwrap()))
    }

    fn trusted_req() -> axum::http::request::Builder {
        req_from("192.168.1.2")
    }

    async fn setup_app(tmp_dir: &std::path::Path) -> (Router, Arc<AppState>, String) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        std::fs::create_dir_all(tmp_dir).unwrap();
        let cfg_path = tmp_dir.join("config.toml");
        let mut outcome = crate::config::load_or_init(&cfg_path).unwrap();
        outcome.config.admin.secret_path = "/".to_string();
        save_config(&cfg_path, &outcome.config).unwrap();
        let vault = Arc::new(Vault::load_or_create(tmp_dir).unwrap());
        let mut fw_cfg = outcome.config.firewall.clone();
        fw_cfg.auto_manage = false;
        let firewall = FirewallManager::detect_and_init(fw_cfg).await;
        firewall.set_data_dir(tmp_dir.to_path_buf());
        let live_listeners: Vec<SocketAddr> = outcome
            .config
            .admin
            .listen_lan
            .iter()
            .filter_map(|s| s.parse::<SocketAddr>().ok())
            .collect();
        let state = Arc::new(AppState {
            config_path: cfg_path,
            config: Arc::new(ArcSwap::from_pointee(outcome.config.clone())),
            config_lock: tokio::sync::Mutex::new(()),
            vault,
            auth: Mutex::new(AuthState::new(outcome.config.admin.canonical_origin.clone(), 0)),
            hash_gate: Arc::new(HashGate::new()),
            fail2ban: Arc::new(Fail2Ban::new()),
            proxy_gate_fail2ban: Arc::new(ScopedFail2Ban::new()),
            firewall,
            health_registry: crate::supervisor::new_health_registry(),
            ddns_status: Arc::new(crate::daemon::ddns::DdnsRuntime::default()),
            cert_table: Arc::new(ArcSwap::from_pointee(CertTable::default())),
            cert_status: Arc::new(AcmeRuntime::new(tmp_dir.to_path_buf())),
            admin_cert: Arc::new(ArcSwap::from(
                crate::net::tls_resolver::generate_self_signed_cert(&[]).unwrap().2,
            )),
            stun_addrs: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            stun_status: crate::net::stun::new_stun_runtime(),
            reverse_proxy_status: crate::net::new_rule_status_map(),
            port_forward_status: crate::net::new_rule_status_map(),
            cron_status: CronRuntime::new(),
            monitor_sampler: MonitorSampler::new(),
            alert_state: AlertState::default(),
            inbox: crate::daemon::inbox::NotificationInbox::load_or_new(tmp_dir),
            updater: Arc::new(crate::daemon::updater::UpdateRuntime::new()),
            global_quota: ConnectionQuota::new(128),
            pty_mgr: Arc::new(PtyManager::new()),
            proxy_gate: Arc::new(crate::security::proxy_gate::ProxyGateStore::new()),
            reauth_tickets: crate::security::tickets::SessionTickets::default(),
            reload_notify: Arc::new(Notify::new()),
            live_admin_listeners: Arc::new(live_listeners),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
        });
        let app = build_router(state.clone());

        let login = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("POST")
                    .uri("/api/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"username":"admin","password":"admin321"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let init_ck = login.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let ch = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("POST")
                    .uri("/api/auth/change-password")
                    .header(header::COOKIE, &init_ck)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"current_password":"admin321","new_password":"Vane#Wave2Pass1"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ch.status(), StatusCode::OK);
        let admin_ck = ch.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        (app, state, admin_ck)
    }

    async fn get_pw_reauth(app: &Router, cookie: &str, pw: &str) -> String {
        let r = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("POST")
                    .uri("/api/auth/reauth/verify")
                    .header(header::COOKIE, cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "method": "password", "password": pw }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        serde_json::from_slice::<serde_json::Value>(&to_bytes(r.into_body(), 8192).await.unwrap()).unwrap()
            ["reauth_token"]
            .as_str()
            .unwrap()
            .to_string()
    }

    async fn get_totp_reauth(app: &Router, cookie: &str, secret: &[u8], step_offset: i64) -> String {
        let base_step = (logger::unix_now() / 30) as i64;
        let step = (base_step + step_offset).max(0) as u64;
        let code = format!("{:06}", totp_code(secret, step));
        let r = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("POST")
                    .uri("/api/auth/reauth/verify")
                    .header(header::COOKIE, cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "method": "totp", "totp_code": code }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        serde_json::from_slice::<serde_json::Value>(&to_bytes(r.into_body(), 8192).await.unwrap()).unwrap()
            ["reauth_token"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn make_valid_bundle(domain: &str) -> crate::daemon::acme_store::Bundle {
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_kp = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_kp).unwrap();
        let issuer = rcgen::Issuer::from_params(&ca_params, &ca_kp);
        let mut leaf_params = rcgen::CertificateParams::new(vec![domain.into()]).unwrap();
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, domain);
        let leaf_kp = rcgen::KeyPair::generate().unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_kp, &issuer).unwrap();
        crate::daemon::acme_store::Bundle {
            directory: "letsencrypt_staging".into(),
            domains: vec![domain.into()],
            certificate: format!("{}{}", leaf_cert.pem(), ca_cert.pem()),
            private_key: leaf_kp.serialize_pem(),
        }
    }

    #[tokio::test]
    async fn vane_h01_live_admin_listeners_blocks_hot_reload_admin_port_exposure() {
        let dir = std::env::temp_dir().join(format!("vane_w2_h01_{}", crate::config::random_nonce()));
        let (app, _state, cookie) = setup_app(&dir).await;

        let get_s = app
            .clone()
            .oneshot(trusted_req().uri("/api/settings").header(header::COOKIE, &cookie).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let mut cfg_v: serde_json::Value =
            serde_json::from_slice(&to_bytes(get_s.into_body(), 131_072).await.unwrap()).unwrap();

        // 企图在同一次提交中把待生效 listen_lan 改为 23457，并立即热加载一条转发到仍绑定在 23456 的活态管理口
        cfg_v["admin"]["listen_lan"] = serde_json::json!(["192.168.1.1:23457"]);
        cfg_v["port_forwards"] = serde_json::json!([{
            "name": "expose_live_admin",
            "enabled": true,
            "proto": "tcp",
            "engine": "userspace_splice",
            "listen_port": 18443,
            "target": "192.168.1.1:23456",
            "open_wan_firewall": true
        }]);

        let tok = get_pw_reauth(&app, &cookie, "Vane#Wave2Pass1").await;
        let put_r = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("PUT")
                    .uri("/api/settings")
                    .header(header::COOKIE, &cookie)
                    .header("x-vane-reauth-token", &tok)
                    .header("content-type", "application/json")
                    .body(Body::from(cfg_v.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put_r.status(), StatusCode::BAD_REQUEST);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn vane_h04_and_m02_scoped_fail2ban_isolation_unban_and_saturation_fail_closed() {
        let dir = std::env::temp_dir().join(format!("vane_w2_h04_{}", crate::config::random_nonce()));
        let (app, state, cookie) = setup_app(&dir).await;

        // 创建反代独立门禁账号
        let create_u = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("POST")
                    .uri("/api/proxy/auth-users")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"username":"gateuser","password":"Gate#Pass2026","session_ttl_secs":3600}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_u.status(), StatusCode::OK);

        let attacker_ip = "203.0.113.55";
        let max_fail = state.config.load().security.max_login_failures;

        // 1) 管理面连续失败 max_fail - 1 次
        for _ in 0..(max_fail - 1) {
            let r = app
                .clone()
                .oneshot(
                    req_from(attacker_ip)
                        .method("POST")
                        .uri("/api/auth/login")
                        .header("content-type", "application/json")
                        .body(Body::from(r#"{"username":"admin","password":"wrong"}"#))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        }

        // 2) 同一来源在反代门禁 a.example.com 登录成功，绝不能清除管理面 Fail2Ban 计数！
        let gate_ok = crate::net::reverse_proxy::ProxyAuthorization::gate_login(
            state.as_ref(),
            "a.example.com".into(),
            vec!["gateuser".into()],
            "gateuser".into(),
            "Gate#Pass2026".into(),
            attacker_ip.parse().unwrap(),
        )
        .await;
        assert!(gate_ok.is_ok());

        // 管理面第 max_fail 次失败必须触发封禁，紧接着第 max_fail + 1 次返回 429
        let ban_trigger = app
            .clone()
            .oneshot(
                req_from(attacker_ip)
                    .method("POST")
                    .uri("/api/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"username":"admin","password":"wrong"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ban_trigger.status(), StatusCode::UNAUTHORIZED);
        let admin_banned = app
            .clone()
            .oneshot(
                req_from(attacker_ip)
                    .method("POST")
                    .uri("/api/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"username":"admin","password":"Vane#Wave2Pass1"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(admin_banned.status(), StatusCode::TOO_MANY_REQUESTS);

        // 3) 反代 host b.example.com 触发独立封禁；a.example.com 仍不受影响
        for _ in 0..max_fail {
            let _ = crate::net::reverse_proxy::ProxyAuthorization::gate_login(
                state.as_ref(),
                "b.example.com".into(),
                vec!["gateuser".into()],
                "gateuser".into(),
                "wrong".into(),
                attacker_ip.parse().unwrap(),
            )
            .await;
        }
        let b_blocked = crate::net::reverse_proxy::ProxyAuthorization::gate_login(
            state.as_ref(),
            "b.example.com".into(),
            vec!["gateuser".into()],
            "gateuser".into(),
            "Gate#Pass2026".into(),
            attacker_ip.parse().unwrap(),
        )
        .await;
        assert_eq!(b_blocked.unwrap_err().0, StatusCode::TOO_MANY_REQUESTS);

        // 4) GET /api/security/bans 必须同时返回 admin 与 b.example.com 作用域，DELETE 统一解封
        let list_r = app
            .clone()
            .oneshot(
                trusted_req()
                    .uri("/api/security/bans")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(list_r.status(), StatusCode::OK);
        let list_j: serde_json::Value =
            serde_json::from_slice(&to_bytes(list_r.into_body(), 16_384).await.unwrap()).unwrap();
        let scopes: Vec<&str> = list_j["bans"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|b| b["scope"].as_str())
            .collect();
        assert!(scopes.contains(&"admin"), "missing admin scope: {list_j}");
        assert!(scopes.contains(&"b.example.com"), "missing proxy_gate scope: {list_j}");

        let unban_r = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("DELETE")
                    .uri(format!("/api/security/bans/{attacker_ip}"))
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unban_r.status(), StatusCode::OK);
        let unban_j: serde_json::Value =
            serde_json::from_slice(&to_bytes(unban_r.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(unban_j["unbanned"], true);
        assert_eq!(unban_j["admin_unbanned"], true);
        assert_eq!(unban_j["proxy_gate_unbanned"], true);
        assert!(!state.fail2ban.is_banned(attacker_ip.parse().unwrap()));
        assert!(!state
            .proxy_gate_fail2ban
            .is_key_banned("b.example.com", BanKey::from_peer(attacker_ip.parse().unwrap())));

        // 5) VANE-M02：当 1024 条活跃封禁填满且未卸载内核时，新来源登录必须 Fail-Closed 返回 429
        for i in 0..MAX_TRACKED_KEYS {
            let k = BanKey::from_peer(IpAddr::V4(Ipv4Addr::new(
                10,
                77,
                ((i >> 8) & 0xff) as u8,
                (i & 0xff) as u8,
            )));
            for _ in 0..3 {
                state.fail2ban.record_failure_checked(k, 3, 600, "flood");
            }
        }
        let sat_r = app
            .clone()
            .oneshot(
                req_from("198.51.100.200")
                    .method("POST")
                    .uri("/api/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"username":"admin","password":"wrong"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(sat_r.status(), StatusCode::TOO_MANY_REQUESTS);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn vane_h05_l02_l03_m13_backup_mfa_downgrade_default_pw_passkey_only_and_atomic_restore() {
        let dir = std::env::temp_dir().join(format!("vane_w2_h05_{}", crate::config::random_nonce()));
        let (app, state, mut cookie) = setup_app(&dir).await;
        let totp_secret = b"W2TOTPSECRET12345678";
        {
            let mut next = (**state.config.load()).clone();
            next.admin.totp_enabled = true;
            next.admin.totp_secret = state
                .vault
                .seal("admin.totp_secret", base32_encode(totp_secret).as_bytes())
                .unwrap();
            next.acme.push(crate::config::AcmeConfig {
                enabled: true,
                domain: "valid.example.com".into(),
                dns_provider: "cf".into(),
                cert_dir: dir.join("acme-certs").to_string_lossy().into_owned(),
                ..Default::default()
            });
            next.dns_providers.insert(
                "cf".into(),
                crate::config::DnsProviderConfig {
                    provider: "cloudflare".into(),
                    api_token: state.vault.seal("dns_providers.cf.api_token", b"tok-123").unwrap(),
                    ..Default::default()
                },
            );
            save_config(&state.config_path, &next).unwrap();
            state.config.store(Arc::new(next));
        }
        // 预先在 cert_table 中植入一条旧域名证书，验证导入后会被 prune_cert_table 清除
        let stale_bundle = make_valid_bundle("stale.example.com");
        let stale_ver = crate::daemon::acme_store::verify(&stale_bundle).unwrap();
        state.cert_table.rcu(|cur| {
            let mut n = CertTable {
                exact: cur.exact.clone(),
                wildcard: cur.wildcard.clone(),
                fallback: cur.fallback.clone(),
            };
            n.exact.insert("stale.example.com".into(), stale_ver.key.clone());
            Arc::new(n)
        });

        // 1) VANE-H05：启用 TOTP 时，仅密码签发令牌导出备份必须返回 403 MFA_REAUTH_REQUIRED
        let pw_tok = get_pw_reauth(&app, &cookie, "Vane#Wave2Pass1").await;
        let exp_pw = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("POST")
                    .uri("/api/backup/export")
                    .header(header::COOKIE, &cookie)
                    .header("x-vane-reauth-token", &pw_tok)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"password":"Backup#Pass2026"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(exp_pw.status(), StatusCode::FORBIDDEN);
        let exp_pw_j: serde_json::Value =
            serde_json::from_slice(&to_bytes(exp_pw.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(exp_pw_j["code"], "MFA_REAUTH_REQUIRED");
        assert_eq!(exp_pw_j["mfa_required"], true);

        // 2) VANE-L03：明文篡改的 acme-accounts/*.json（剥离 enc:v2:）必须导致导出失败（vault.open 拒绝明文回退）
        let acc_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let acc_path = dir.join("acme-accounts").join(format!("{acc_id}.json"));
        crate::daemon::acme_store::atomic(acc_path.clone(), br#"{"id":"tampered-plaintext"}"#.to_vec())
            .await
            .unwrap();
        let mfa_tok1 = get_totp_reauth(&app, &cookie, totp_secret, -1).await;
        let exp_tampered = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("POST")
                    .uri("/api/backup/export")
                    .header(header::COOKIE, &cookie)
                    .header("x-vane-reauth-token", &mfa_tok1)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"password":"Backup#Pass2026"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(exp_tampered.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let _ = std::fs::remove_file(&acc_path);

        // 3) VANE-L02：构造使用默认密码 admin321 的备份，导入必须 400 BACKUP_DEFAULT_PASSWORD_REJECTED
        let mut default_pw_cfg = (**state.config.load()).clone();
        default_pw_cfg.admin.password_hash = PasswordHash::create(b"admin321").unwrap().encode();
        default_pw_cfg.admin.must_change_password = false;
        let bad_blob = B64.encode(
            state
                .vault
                .export_backup(&default_pw_cfg, b"Backup#Pass2026", BTreeMap::new())
                .unwrap(),
        );
        let mfa_tok2 = get_totp_reauth(&app, &cookie, totp_secret, 0).await;
        let imp_def = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("POST")
                    .uri("/api/backup/import")
                    .header(header::COOKIE, &cookie)
                    .header("x-vane-reauth-token", &mfa_tok2)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "backup_blob": bad_blob, "password": "Backup#Pass2026" }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(imp_def.status(), StatusCode::BAD_REQUEST);
        assert!(String::from_utf8_lossy(&to_bytes(imp_def.into_body(), 4096).await.unwrap())
            .contains("BACKUP_DEFAULT_PASSWORD_REJECTED"));

        // 4) VANE-H05 降级确认 + VANE-M13 预校验原子性 + 未匹配 ACME 证书跳过与裁剪 + VANE-L02 纯 Passkey 作用域
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pk_kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let mut pk_only_cfg = (**state.config.load()).clone();
        pk_only_cfg.admin.totp_enabled = false;
        pk_only_cfg.admin.totp_secret.clear();
        pk_only_cfg.admin.password_login_enabled = false;
        pk_only_cfg.admin.password_hash.clear();
        pk_only_cfg.admin.must_change_password = false;
        pk_only_cfg.admin.passkey_enabled = true;
        pk_only_cfg.admin.passkeys = vec![crate::config::PasskeyEntry {
            id: B64URL.encode([0x19u8; 24]),
            name: "Recovery Key".into(),
            rp_id: "localhost".into(),
            alg: crate::security::webauthn::COSE_ALG_EDDSA,
            pubkey_b64: B64URL.encode(pk_kp.public_key().as_ref()),
            sign_count: 1,
            created_at: 1_700_000_000,
            last_used_at: 0,
        }];
        pk_only_cfg.modules.web_terminal = true;

        // 4a) 含畸形挑战 JSON 的备份在预校验阶段失败，不得修改 config.toml 或 cert_table
        let mut bad_files = BTreeMap::new();
        bad_files.insert("acme-challenges/broken.json".into(), b"{not-json".to_vec());
        let broken_blob = B64.encode(
            state
                .vault
                .export_backup(&pk_only_cfg, b"Backup#Pass2026", bad_files)
                .unwrap(),
        );
        let mfa_tok3 = get_totp_reauth(&app, &cookie, totp_secret, 1).await;
        let imp_broken = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("POST")
                    .uri("/api/backup/import")
                    .header(header::COOKIE, &cookie)
                    .header("x-vane-reauth-token", &mfa_tok3)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "backup_blob": broken_blob,
                            "password": "Backup#Pass2026",
                            "allow_security_downgrade": true
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(imp_broken.status(), StatusCode::BAD_REQUEST);
        assert!(state.config.load().admin.totp_enabled, "failed import must not mutate config");
        assert!(state.cert_table.load().exact.contains_key("stale.example.com"));

        // 4b) 含未匹配 ACME 规则证书的备份：未传 allow_security_downgrade 时返回 409 SECURITY_DOWNGRADE_CONFIRM_REQUIRED
        let rogue_bundle = make_valid_bundle("rogue.example.com");
        let mut rogue_files = BTreeMap::new();
        rogue_files.insert(
            "acme-certs/rogue.example.com/bundle.json".into(),
            serde_json::to_vec(&rogue_bundle).unwrap(),
        );
        let pk_blob = B64.encode(
            state
                .vault
                .export_backup(&pk_only_cfg, b"Backup#Pass2026", rogue_files)
                .unwrap(),
        );
        // 用内部直接签发一个 MFA 令牌（避免单调水位耗尽 ±1 窗口）
        let raw_sess = cookie.strip_prefix("vane_session=").unwrap();
        let mfa_tok4 = state
            .reauth_tickets
            .issue_reauth_token_ex(raw_sess, "192.168.1.2".parse().unwrap(), true)
            .unwrap();
        let imp_downgrade = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("POST")
                    .uri("/api/backup/import")
                    .header(header::COOKIE, &cookie)
                    .header("x-vane-reauth-token", &mfa_tok4)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "backup_blob": pk_blob, "password": "Backup#Pass2026" }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(imp_downgrade.status(), StatusCode::CONFLICT);
        let dg_j: serde_json::Value =
            serde_json::from_slice(&to_bytes(imp_downgrade.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(dg_j["code"], "SECURITY_DOWNGRADE_CONFIRM_REQUIRED");
        let dg_list = dg_j["downgrades"].as_array().unwrap();
        assert!(dg_list.iter().any(|v| v == "disable_totp"));
        assert!(dg_list.iter().any(|v| v == "enable_web_terminal"));

        // 4c) 显式确认 allow_security_downgrade=true 后成功导入：
        //     - 未匹配规则的 rogue.example.com 不注入 cert_table
        //     - 旧 stale.example.com 已被 prune_cert_table 裁剪
        //     - 纯 Passkey 备份返回 must_change_password=false 且新会话可正常访问 /api/dashboard！
        let mfa_tok5 = state
            .reauth_tickets
            .issue_reauth_token_ex(raw_sess, "192.168.1.2".parse().unwrap(), true)
            .unwrap();
        let imp_ok = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("POST")
                    .uri("/api/backup/import")
                    .header(header::COOKIE, &cookie)
                    .header("x-vane-reauth-token", &mfa_tok5)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "backup_blob": pk_blob,
                            "password": "Backup#Pass2026",
                            "allow_security_downgrade": true
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(imp_ok.status(), StatusCode::OK);
        cookie = imp_ok.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let imp_ok_j: serde_json::Value =
            serde_json::from_slice(&to_bytes(imp_ok.into_body(), 16_384).await.unwrap()).unwrap();
        assert_eq!(imp_ok_j["must_change_password"], false);
        assert_eq!(imp_ok_j["restored_summary"]["acme_certs"], 0);
        assert!(!state.cert_table.load().exact.contains_key("rogue.example.com"));
        assert!(!state.cert_table.load().exact.contains_key("stale.example.com"));

        let dash_after = app
            .clone()
            .oneshot(
                trusted_req()
                    .uri("/api/dashboard")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dash_after.status(), StatusCode::OK);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn vane_h06_totp_recovery_and_passkey_registration_require_reauth_and_session_binding() {
        let dir = std::env::temp_dir().join(format!("vane_w2_h06_{}", crate::config::random_nonce()));
        let (app, state, cookie) = setup_app(&dir).await;
        let totp_secret = b"H06SECRETKEY12345678";
        {
            let mut next = (**state.config.load()).clone();
            next.admin.totp_enabled = true;
            next.admin.totp_secret = state
                .vault
                .seal("admin.totp_secret", base32_encode(totp_secret).as_bytes())
                .unwrap();
            next.admin.extra_allowed_origins.push("https://localhost:23456".into());
            save_config(&state.config_path, &next).unwrap();
            state.config.store(Arc::new(next));
        }

        // 1) 重置恢复码：无 reauth -> 403；仅密码 reauth -> 403 MFA_REAUTH_REQUIRED；TOTP reauth -> 200
        let rec_no = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("POST")
                    .uri("/api/auth/totp/recovery-codes")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rec_no.status(), StatusCode::FORBIDDEN);

        let pw_tok = get_pw_reauth(&app, &cookie, "Vane#Wave2Pass1").await;
        let rec_pw = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("POST")
                    .uri("/api/auth/totp/recovery-codes")
                    .header(header::COOKIE, &cookie)
                    .header("x-vane-reauth-token", &pw_tok)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rec_pw.status(), StatusCode::FORBIDDEN);
        assert!(String::from_utf8_lossy(&to_bytes(rec_pw.into_body(), 4096).await.unwrap())
            .contains("MFA_REAUTH_REQUIRED"));

        let mfa_tok = get_totp_reauth(&app, &cookie, totp_secret, -1).await;
        let rec_ok = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("POST")
                    .uri("/api/auth/totp/recovery-codes")
                    .header(header::COOKIE, &cookie)
                    .header("x-vane-reauth-token", &mfa_tok)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rec_ok.status(), StatusCode::OK);

        // 2) Passkey register/options：无 reauth 或仅密码 reauth 被拒，TOTP reauth 后签发会话绑定挑战
        let pk_opt_no = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/passkey/register/options")
                    .header(header::HOST, "192.168.1.1:23456")
                    .header(header::ORIGIN, "https://localhost:23456")
                    .header(header::COOKIE, &cookie)
                    .extension(ConnectInfo("192.168.1.2:23456".parse::<SocketAddr>().unwrap()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pk_opt_no.status(), StatusCode::FORBIDDEN);

        let mfa_tok2 = get_totp_reauth(&app, &cookie, totp_secret, 0).await;
        let pk_opt_ok = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/passkey/register/options")
                    .header(header::HOST, "192.168.1.1:23456")
                    .header(header::ORIGIN, "https://localhost:23456")
                    .header(header::COOKIE, &cookie)
                    .header("x-vane-reauth-token", &mfa_tok2)
                    .extension(ConnectInfo("192.168.1.2:23456".parse::<SocketAddr>().unwrap()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pk_opt_ok.status(), StatusCode::OK);

        // 3) 伪造未通过 reauth 的会话绑定挑战（reauth_verified=false）调用 register/verify 必须返回 403 REAUTH_REQUIRED
        let raw_sess = cookie.strip_prefix("vane_session=").unwrap();
        let sess_digest = SessionStore::token_digest(raw_sess);
        let forged_ch = {
            let mut auth = state.auth.lock().unwrap();
            auth.webauthn
                .create_session_registration_challenge_with_reauth(
                    "https://localhost:23456".into(),
                    "localhost".into(),
                    BanKey::from_peer("192.168.1.2".parse().unwrap()),
                    sess_digest,
                    false,
                )
                .unwrap()
        };
        let verify_forged = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/passkey/register/verify")
                    .header(header::HOST, "192.168.1.1:23456")
                    .header(header::ORIGIN, "https://localhost:23456")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .extension(ConnectInfo("192.168.1.2:23456".parse::<SocketAddr>().unwrap()))
                    .body(Body::from(
                        serde_json::json!({
                            "name": "Forged",
                            "challenge": forged_ch,
                            "client_data_json": "e30",
                            "attestation_object": "oA"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(verify_forged.status(), StatusCode::FORBIDDEN);
        assert!(String::from_utf8_lossy(&to_bytes(verify_forged.into_body(), 4096).await.unwrap())
            .contains("REAUTH_REQUIRED"));

        // 4) VANE-H06 边界：Passkey toggle enabled=true（已有已保存通行密钥时）也必须强制 MFA-aware 二次验证
        {
            let mut next = (**state.config.load()).clone();
            next.admin.passkey_enabled = false;
            next.admin.passkeys = vec![crate::config::PasskeyEntry {
                id: base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    [7u8; 24],
                ),
                name: "Test Passkey".into(),
                rp_id: "localhost".into(),
                alg: -8,
                pubkey_b64: base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    [9u8; 32],
                ),
                sign_count: 0,
                created_at: 1,
                last_used_at: 0,
            }];
            save_config(&state.config_path, &next).unwrap();
            state.config.store(Arc::new(next));
        }
        // 无 reauth -> 403 REAUTH_REQUIRED
        let toggle_no = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("POST")
                    .uri("/api/auth/passkey/toggle")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"enabled":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(toggle_no.status(), StatusCode::FORBIDDEN);
        assert!(String::from_utf8_lossy(&to_bytes(toggle_no.into_body(), 4096).await.unwrap())
            .contains("REAUTH_REQUIRED"));

        // 已开启 TOTP 时，仅密码 reauth -> 403 MFA_REAUTH_REQUIRED
        let pw_tok_toggle = get_pw_reauth(&app, &cookie, "Vane#Wave2Pass1").await;
        let toggle_pw = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("POST")
                    .uri("/api/auth/passkey/toggle")
                    .header(header::COOKIE, &cookie)
                    .header("x-vane-reauth-token", &pw_tok_toggle)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"enabled":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(toggle_pw.status(), StatusCode::FORBIDDEN);
        assert!(String::from_utf8_lossy(&to_bytes(toggle_pw.into_body(), 4096).await.unwrap())
            .contains("MFA_REAUTH_REQUIRED"));

        // TOTP MFA reauth -> 200 OK 且 passkey_enabled=true
        let mfa_tok3 = get_totp_reauth(&app, &cookie, totp_secret, 1).await;
        let toggle_ok = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("POST")
                    .uri("/api/auth/passkey/toggle")
                    .header(header::COOKIE, &cookie)
                    .header("x-vane-reauth-token", &mfa_tok3)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"enabled":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(toggle_ok.status(), StatusCode::OK);
        assert!(state.config.load().admin.passkey_enabled);

        // 当 TOTP 与 Passkey 均未开启但存在已保存密钥时：无 reauth -> 403，密码 reauth -> 200 OK
        {
            let mut next = (**state.config.load()).clone();
            next.admin.totp_enabled = false;
            next.admin.passkey_enabled = false;
            save_config(&state.config_path, &next).unwrap();
            state.config.store(Arc::new(next));
        }
        let toggle_nomfa_no = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("POST")
                    .uri("/api/auth/passkey/toggle")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"enabled":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(toggle_nomfa_no.status(), StatusCode::FORBIDDEN);

        let pw_tok_toggle2 = get_pw_reauth(&app, &cookie, "Vane#Wave2Pass1").await;
        let toggle_nomfa_ok = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("POST")
                    .uri("/api/auth/passkey/toggle")
                    .header(header::COOKIE, &cookie)
                    .header("x-vane-reauth-token", &pw_tok_toggle2)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"enabled":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(toggle_nomfa_ok.status(), StatusCode::OK);
        assert!(state.config.load().admin.passkey_enabled);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn vane_h07_and_h08_update_signature_and_lockdown_report_and_reload() {
        let dir = std::env::temp_dir().join(format!("vane_w2_h07_08_{}", crate::config::random_nonce()));
        let (app, state, cookie) = setup_app(&dir).await;

        // VANE-H08：Lockdown 返回完整报告、持久化 .lockdown 并触发 reload_notify
        let notified = state.reload_notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let ld_resp = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("POST")
                    .uri("/api/firewall/lockdown")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"enable":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ld_resp.status(), StatusCode::OK);
        let ld_j: serde_json::Value =
            serde_json::from_slice(&to_bytes(ld_resp.into_body(), 8192).await.unwrap()).unwrap();
        assert_eq!(ld_j["lockdown"], true);
        assert_eq!(ld_j["active"], true);
        assert_eq!(ld_j["kernel_enforced"], false);
        assert!(!ld_j["warnings"].as_array().unwrap().is_empty());
        assert!(crate::firewall::read_persisted_lockdown(&dir));
        tokio::time::timeout(Duration::from_millis(200), notified)
            .await
            .expect("lockdown must notify reload_notify");

        // VANE-H07：启用手动上传 + Ed25519 公钥，测试缺少签名 / 错误签名 / 查询参数 ?signature=
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        {
            let mut next = (**state.config.load()).clone();
            next.admin.allow_manual_update_upload = true;
            next.admin.update_signing_public_key = B64.encode(kp.public_key().as_ref());
            state.config.store(Arc::new(next));
        }

        let status_r = app
            .clone()
            .oneshot(
                trusted_req()
                    .uri("/api/update/status")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status_j: serde_json::Value =
            serde_json::from_slice(&to_bytes(status_r.into_body(), 8192).await.unwrap()).unwrap();
        assert_eq!(status_j["allow_manual_update_upload"], true);
        assert_eq!(status_j["update_signing_key_configured"], true);

        let tok1 = get_pw_reauth(&app, &cookie, "Vane#Wave2Pass1").await;
        let no_sig = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("POST")
                    .uri("/api/update/upload")
                    .header(header::COOKIE, &cookie)
                    .header("x-vane-reauth-token", &tok1)
                    .body(Body::from(b"payload".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(no_sig.status(), StatusCode::BAD_REQUEST);
        assert!(String::from_utf8_lossy(&to_bytes(no_sig.into_body(), 4096).await.unwrap()).contains("Ed25519"));

        let tok2 = get_pw_reauth(&app, &cookie, "Vane#Wave2Pass1").await;
        let payload = b"not-a-valid-tar-gz".to_vec();
        let sig_hex: String = kp
            .sign(&payload)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let query_sig = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("POST")
                    .uri(format!("/api/update/upload?signature={sig_hex}"))
                    .header(header::COOKIE, &cookie)
                    .header("x-vane-reauth-token", &tok2)
                    .body(Body::from(payload))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(query_sig.status(), StatusCode::BAD_REQUEST);
        // 通过 Ed25519 验签后到达 gzip/tar 校验阶段（不是签名错误）
        let qs_body = String::from_utf8_lossy(&to_bytes(query_sig.into_body(), 4096).await.unwrap()).into_owned();
        assert!(!qs_body.contains("Ed25519"), "signature should have verified, got: {qs_body}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn vane_m03_m06_m07_settings_guards_and_cron_run_gates() {
        let dir = std::env::temp_dir().join(format!("vane_w2_m03_06_{}", crate::config::random_nonce()));
        let (app, state, cookie) = setup_app(&dir).await;

        // 1) VANE-M03：开启 ddns 二次认证后，未解锁时修改 dns_providers 必须返回 403 MODULE_REAUTH_REQUIRED (ddns)
        let lock_ddns = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("PUT")
                    .uri("/api/modules/reauth")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"module":"ddns","require_reauth":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(lock_ddns.status(), StatusCode::OK);

        let get_s = app
            .clone()
            .oneshot(trusted_req().uri("/api/settings").header(header::COOKIE, &cookie).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let base_cfg: serde_json::Value =
            serde_json::from_slice(&to_bytes(get_s.into_body(), 131_072).await.unwrap()).unwrap();

        let mut mod_dns = base_cfg.clone();
        mod_dns["dns_providers"]["cf_test"] = serde_json::json!({
            "provider": "cloudflare",
            "api_token": "tok-abc"
        });
        let dns_blocked = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("PUT")
                    .uri("/api/settings")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(mod_dns.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dns_blocked.status(), StatusCode::FORBIDDEN);
        let dns_j: serde_json::Value =
            serde_json::from_slice(&to_bytes(dns_blocked.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(dns_j["error"], "MODULE_REAUTH_REQUIRED");
        assert_eq!(dns_j["module"], "ddns");

        // 2) VANE-M03：无 reauth 修改 secret_path / extra_allowed_origins / username 均必须返回 403 REAUTH_REQUIRED
        for (field, val) in [
            ("secret_path", serde_json::json!("/_new_secret_path_1234")),
            ("extra_allowed_origins", serde_json::json!(["https://evil.local:23456"])),
            ("username", serde_json::json!("otheradmin")),
        ] {
            let mut mutated = base_cfg.clone();
            mutated["admin"][field] = val;
            let r = app
                .clone()
                .oneshot(
                    trusted_req()
                        .method("PUT")
                        .uri("/api/settings")
                        .header(header::COOKIE, &cookie)
                        .header("content-type", "application/json")
                        .body(Body::from(mutated.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::FORBIDDEN, "field {field} must require reauth");
            assert!(String::from_utf8_lossy(&to_bytes(r.into_body(), 4096).await.unwrap())
                .contains("REAUTH_REQUIRED"));
        }

        // 3) VANE-M07 / H07 / M06：配置文件专有字段无法经 PUT /api/settings 篡改
        let mut try_elevate = base_cfg.clone();
        try_elevate["admin"]["docker_socket"] = serde_json::json!("/run/other.sock");
        try_elevate["admin"]["allow_manual_update_upload"] = serde_json::json!(true);
        try_elevate["admin"]["update_signing_public_key"] = serde_json::json!("00".repeat(32));
        try_elevate["admin"]["allow_cron_exec"] = serde_json::json!(true);
        let elev_r = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("PUT")
                    .uri("/api/settings")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(try_elevate.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(elev_r.status(), StatusCode::OK);
        {
            let c = state.config.load();
            assert_eq!(c.admin.docker_socket, "/var/run/docker.sock");
            assert!(!c.admin.allow_manual_update_upload);
            assert!(c.admin.update_signing_public_key.is_empty());
            assert!(!c.admin.allow_cron_exec);
        }

        // 4) VANE-M06：api_cron_run 拒绝已禁用任务，且拒绝未开启 allow_cron_exec 时的 CronAction::Exec
        {
            let mut next = (**state.config.load()).clone();
            next.modules.cron = true;
            next.cron.push(crate::config::CronConfig {
                name: "disabled_job".into(),
                enabled: false,
                schedule: "0 0 * * * *".into(),
                timeout_secs: 10,
                action: crate::config::CronAction::Exec {
                    program: "/bin/echo".into(),
                    args: vec!["hi".into()],
                    cwd: String::new(),
                },
                notify_on_failure: false,
            });
            next.cron.push(crate::config::CronConfig {
                name: "exec_job".into(),
                enabled: true,
                schedule: "0 0 * * * *".into(),
                timeout_secs: 10,
                action: crate::config::CronAction::Exec {
                    program: "/bin/echo".into(),
                    args: vec!["hi".into()],
                    cwd: String::new(),
                },
                notify_on_failure: false,
            });
            state.config.store(Arc::new(next));
        }
        let run_dis = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("POST")
                    .uri("/api/cron/disabled_job/run")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(run_dis.status(), StatusCode::FORBIDDEN);
        assert!(String::from_utf8_lossy(&to_bytes(run_dis.into_body(), 4096).await.unwrap())
            .contains("CRON_JOB_DISABLED"));

        let run_exec = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("POST")
                    .uri("/api/cron/exec_job/run")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(run_exec.status(), StatusCode::FORBIDDEN);
        assert!(String::from_utf8_lossy(&to_bytes(run_exec.into_body(), 4096).await.unwrap())
            .contains("CRON_EXEC_DISABLED"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn vane_m04_m05_pty_docker_reauth_liveness_and_module_disable_revocations() {
        let dir = std::env::temp_dir().join(format!("vane_w2_m04_05_{}", crate::config::random_nonce()));
        let (app, state, cookie) = setup_app(&dir).await;
        let raw_sess = cookie.strip_prefix("vane_session=").unwrap();
        let sess_digest = SessionStore::token_digest(raw_sess);

        {
            let mut next = (**state.config.load()).clone();
            next.modules.web_terminal = true;
            next.modules.docker = true;
            next.modules.cron = true;
            next.module_reauth.web_terminal = true;
            next.web_terminal.require_reauth = true;
            next.module_reauth.docker = true;
            next.port_forwards.push(crate::config::PortForwardConfig {
                name: "pf1".into(),
                enabled: true,
                listen_port: 19001,
                target: "192.168.1.99:8080".into(),
                ..Default::default()
            });
            state.config.store(Arc::new(next));
        }

        // 1) VANE-M04：container:* 终端票据在 docker 未解锁时必须返回 403 MODULE_REAUTH_REQUIRED (module="docker")
        let pty_blocked = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("POST")
                    .uri("/api/pty/ticket")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"target":"container:nginx","shell":"sh"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pty_blocked.status(), StatusCode::FORBIDDEN);
        let pb_j: serde_json::Value =
            serde_json::from_slice(&to_bytes(pty_blocked.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(pb_j["error"], "MODULE_REAUTH_REQUIRED");
        assert_eq!(pb_j["module"], "docker");

        // 解锁 docker 并携带 reauth_token 申请 container:* 票据 -> 成功且同时解锁 web_terminal 使 pty_session_alive=true
        let unlock_dk = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("POST")
                    .uri("/api/auth/reauth/verify")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"method":"password","password":"Vane#Wave2Pass1","unlock_module":"docker"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unlock_dk.status(), StatusCode::OK);
        let tok = serde_json::from_slice::<serde_json::Value>(&to_bytes(unlock_dk.into_body(), 4096).await.unwrap())
            .unwrap()["reauth_token"]
            .as_str()
            .unwrap()
            .to_string();

        let pty_ok = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("POST")
                    .uri("/api/pty/ticket")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "target": "container:nginx", "shell": "sh", "reauth_token": tok })
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pty_ok.status(), StatusCode::OK);
        assert!(state.pty_session_alive(&sess_digest, true));
        assert!(state.pty_session_alive(&sess_digest, false));

        // 锁定 docker 后：容器 PTY 立即失活，宿主机 PTY 仍存活
        let lock_r = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("POST")
                    .uri("/api/auth/module-lock")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"module":"docker"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(lock_r.status(), StatusCode::OK);
        assert!(!state.pty_session_alive(&sess_digest, true));
        assert!(state.pty_session_alive(&sess_digest, false));

        // 守护进程关停标志置位后，所有 PTY 立即失活
        state.shutdown_flag.store(true, Ordering::Release);
        assert!(!state.pty_session_alive(&sess_digest, false));
        state.shutdown_flag.store(false, Ordering::Release);

        // 2) VANE-M05：PUT /api/modules 关闭 reverse_proxy 撤销 proxy_gate 会话，关闭 cron 触发 cancel_all()
        let _gate_tok = state
            .proxy_gate
            .issue(
                "alice",
                "nas.example.com",
                BanKey::from_peer("192.168.1.9".parse().unwrap()),
                Duration::from_secs(3600),
            )
            .unwrap();
        assert_eq!(state.proxy_gate.active_counts_by_user().get("alice").copied(), Some(1));
        let cron_cancel = state.cron_status.cancel_token();
        assert!(!cron_cancel.is_cancelled());

        let mut mods = state.config.load().modules.clone();
        mods.reverse_proxy = false;
        mods.cron = false;
        mods.port_forward = false;
        let put_mods = app
            .clone()
            .oneshot(
                trusted_req()
                    .method("PUT")
                    .uri("/api/modules")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&mods).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put_mods.status(), StatusCode::OK);
        assert!(state.proxy_gate.active_counts_by_user().is_empty());
        assert!(cron_cancel.is_cancelled());

        // 3) VANE-M05：CronAction::RuleToggle 拒绝修改已禁用模块（port_forward）的规则
        {
            let mut next = (**state.config.load()).clone();
            next.modules.cron = true;
            next.modules.port_forward = false;
            state.config.store(Arc::new(next));
        }
        let ctx = state.build_cron_context(state.config.load_full());
        let toggler = ctx.rule_toggler.as_ref().unwrap();
        let err = toggler("port_forward".into(), "pf1".into(), false).await;
        assert!(err.is_err(), "RuleToggle must refuse mutating rules of a disabled module");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
