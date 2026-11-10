//! Vane：面向资源受限路由器的高安全双栈全能网关入口。
pub mod config;
pub mod daemon;
pub mod docker;
pub mod firewall;
pub mod logger;
pub mod monitor;
pub mod net;
pub mod security;
pub mod supervisor;
pub mod web;

use crate::config::{load_or_init, save_config, Config};
use crate::daemon::acme::issue_or_renew_cert;
use crate::daemon::cron::{execute_cron_job, CronSchedule};
use crate::daemon::ddns::sync_ddns_entry;
use crate::firewall::FirewallManager;
use crate::logger::Level;
use crate::net::listener::ConnectionQuota;
use crate::net::port_forward::run_port_forward_rule;
use crate::net::reverse_proxy::run_reverse_proxy_listener;
use crate::net::stun::{format_public_endpoint, probe_stun_once};
use crate::net::tls_resolver::{load_or_create_admin_cert, CertTable};
use crate::security::auth::{AuthState, HashGate, PasswordHash, DEFAULT_INITIAL_PASSWORD};
use crate::security::fail2ban::Fail2Ban;
use crate::security::vault::Vault;
use crate::supervisor::{new_health_registry, set_module_health, supervise_module, ModuleHealth};
use crate::web::ws_pty::PtyManager;
use crate::web::{build_router, AppState};
use arc_swap::ArcSwap;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::sync::{watch, Notify};

#[cfg(feature = "mimalloc-alloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("run");
    let config_path = find_arg(&args, "--config")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config.toml"));
    let listen_override = find_arg(&args, "--listen");

    match cmd {
        "version" | "--version" | "-V" => {
            println!(
                "vane {} ({}/{})",
                env!("CARGO_PKG_VERSION"),
                std::env::consts::OS,
                std::env::consts::ARCH
            );
        }
        "update" => {
            println!("正在通过官方安装脚本检查并更新 Vane (https://github.com/xinghaix/vane)...");
            let status = std::process::Command::new("sh")
                .args(["-c", "curl -fsSL https://raw.githubusercontent.com/xinghaix/vane/main/scripts/install.sh | sh -s -- --update"])
                .status();
            match status {
                Ok(s) if s.success() => println!("Vane 更新完成。"),
                _ => {
                    eprintln!("自动更新失败，请手动执行: curl -fsSL https://raw.githubusercontent.com/xinghaix/vane/main/scripts/install.sh | sh");
                    std::process::exit(1);
                }
            }
        }
        "check" => {
            match load_or_init(&config_path).and_then(|o| o.config.validate().map(|_| o.config)) {
                Ok(c) => {
                    println!("配置校验通过 (监听: {:?}, 模块: {:?})", c.admin.listen_lan, c.modules);
                }
                Err(e) => {
                    eprintln!("配置校验失败: {}", e);
                    std::process::exit(1);
                }
            }
        }
        "auth-reset" => {
            if let Err(e) = reset_admin_password(&config_path) {
                eprintln!("重置密码失败: {}", e);
                std::process::exit(1);
            }
            println!("已将管理员密码重置为初始密码 admin321，下次登录必须修改密码。");
        }
        _ => {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .max_blocking_threads(2)
                .thread_stack_size(512 * 1024)
                .enable_all()
                .build()
                .expect("初始化 Tokio 运行时失败");
            if let Err(e) = rt.block_on(run_gateway(config_path, listen_override)) {
                eprintln!("Vane 运行异常退出: {}", e);
                std::process::exit(1);
            }
        }
    }
}

fn find_arg(args: &[String], flag: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone())
}

fn reset_admin_password(config_path: &Path) -> Result<(), String> {
    let mut outcome = load_or_init(config_path)?;
    let default_hash = PasswordHash::create(DEFAULT_INITIAL_PASSWORD).map_err(|e| e.to_string())?;
    outcome.config.admin.password_hash = default_hash.encode();
    outcome.config.admin.must_change_password = true;
    save_config(config_path, &outcome.config)
}

async fn run_gateway(config_path: PathBuf, listen_override: Option<String>) -> Result<(), String> {
    let data_dir = config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let vault = Arc::new(Vault::load_or_create(&data_dir)?);

    let mut outcome = load_or_init(&config_path)?;
    if let Some(ov) = listen_override {
        outcome.config.admin.listen_lan = vec![ov];
    }
    if vault.auto_seal(&mut outcome.config)? {
        outcome.dirty = true;
    }
    outcome.config.validate()?;
    if outcome.dirty {
        save_config(&config_path, &outcome.config)?;
    }

    logger::global().set_capacity(outcome.config.system.log_ring_capacity);
    logger::log(
        Level::Info,
        "system",
        &format!(
            "Vane 网关已启动 (管理后台: {:?}, 首次需改密: {})",
            outcome.config.admin.listen_lan, outcome.config.admin.must_change_password
        ),
    );

    let firewall = FirewallManager::detect_and_init(outcome.config.firewall.clone()).await;
    let health_registry = new_health_registry();
    let admin_ck = load_or_create_admin_cert(&data_dir, &outcome.config.admin.listen_lan)?;
    let mut init_cert_table = CertTable::default();
    init_cert_table.fallback = Some(admin_ck);
    let cert_table = Arc::new(ArcSwap::from_pointee(init_cert_table));

    let state = Arc::new(AppState {
        config_path: config_path.clone(),
        config: Arc::new(ArcSwap::from_pointee(outcome.config.clone())),
        vault,
        auth: Mutex::new(AuthState::new(
            outcome.config.admin.canonical_origin.clone(),
            outcome.config.admin.totp_last_step,
        )),
        hash_gate: Arc::new(HashGate::new()),
        fail2ban: Arc::new(Fail2Ban::new()),
        firewall: firewall.clone(),
        health_registry: health_registry.clone(),
        ddns_status: Arc::new(RwLock::new(BTreeMap::new())),
        cert_table: cert_table.clone(),
        cert_status: RwLock::new(BTreeMap::new()),
        stun_addrs: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
        global_quota: ConnectionQuota::new(outcome.config.system.global_max_conns),
        pty_mgr: Arc::new(PtyManager::new()),
        reload_notify: Arc::new(Notify::new()),
    });

    // 启动模块编排器（随配置热更新自动启停各子模块）
    let state_for_sup = state.clone();
    tokio::spawn(async move {
        orchestrate_modules(state_for_sup).await;
    });

    // 绑定管理后台监听地址（若配置的局域网 IP 在本机不存在则自动回退 127.0.0.1:23456 以便开发测试）
    let router = build_router(state.clone());
    let mut bound_listeners = Vec::new();
    for addr_str in &outcome.config.admin.listen_lan {
        if let Ok(addr) = addr_str.parse::<SocketAddr>() {
            match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => bound_listeners.push((addr, l)),
                Err(_) => {
                    let fallback = SocketAddr::from(([127, 0, 0, 1], addr.port()));
                    if let Ok(l) = tokio::net::TcpListener::bind(fallback).await {
                        bound_listeners.push((fallback, l));
                    }
                }
            }
        }
    }
    if bound_listeners.is_empty() {
        return Err("无法绑定任何管理面板监听地址".into());
    }

    let mut web_tasks = Vec::new();
    for (addr, listener) in bound_listeners {
        logger::log(Level::Info, "admin", &format!("Web 管理控制台监听于 http://{}", addr));
        let app = router.clone();
        web_tasks.push(tokio::spawn(async move {
            let _ = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await;
        }));
    }

    let _ = tokio::signal::ctrl_c().await;
    logger::log(Level::Info, "system", "收到退出信号，正在清理防火墙规则并优雅停机...");
    let _ = firewall.pre_start_sweep().await;
    for t in web_tasks {
        t.abort();
    }
    Ok(())
}

async fn orchestrate_modules(state: Arc<AppState>) {
    let mut active_stops: Vec<watch::Sender<bool>> = Vec::new();
    loop {
        for stop in active_stops.drain(..) {
            let _ = stop.send(true);
        }
        let cfg: Arc<Config> = state.config.load_full();
        let reg = &state.health_registry;

        // 1. DDNS
        if cfg.modules.ddns {
            set_module_health(reg, "ddns", ModuleHealth::Running);
            let (stop_tx, stop_rx) = watch::channel(false);
            active_stops.push(stop_tx);
            let st = state.clone();
            let entries = cfg.ddns.clone();
            let (htx, _) = watch::channel(ModuleHealth::Running);
            tokio::spawn(supervise_module("ddns", stop_rx, htx, Some(reg.clone()), move |mut rx| {
                let st = st.clone();
                let entries = entries.clone();
                async move {
                    loop {
                        for d in entries.iter().filter(|d| d.enabled) {
                            let _ = sync_ddns_entry(d, &st.firewall, &st.ddns_status).await;
                        }
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_secs(300)) => {}
                            _ = rx.changed() => break,
                        }
                    }
                    Ok(())
                }
            }));
        } else {
            set_module_health(reg, "ddns", ModuleHealth::Disabled);
        }

        // 2. ACME
        if cfg.modules.acme {
            set_module_health(reg, "acme", ModuleHealth::Running);
            for a in cfg.acme.iter().filter(|a| a.enabled) {
                if let Ok(st) = issue_or_renew_cert(a, &state.cert_table) {
                    if let Ok(mut g) = state.cert_status.write() {
                        g.insert(st.domain.clone(), st);
                    }
                }
            }
        } else {
            set_module_health(reg, "acme", ModuleHealth::Disabled);
        }

        // 3. Reverse Proxy
        if cfg.modules.reverse_proxy {
            set_module_health(reg, "reverse_proxy", ModuleHealth::Running);
            for rp in cfg.reverse_proxy.iter().filter(|r| r.enabled).cloned() {
                let (stop_tx, stop_rx) = watch::channel(false);
                active_stops.push(stop_tx);
                let st = state.clone();
                let (htx, _) = watch::channel(ModuleHealth::Running);
                tokio::spawn(supervise_module("reverse_proxy", stop_rx, htx, Some(reg.clone()), move |rx| {
                    let rp = rp.clone();
                    let st = st.clone();
                    async move {
                        run_reverse_proxy_listener(
                            rp,
                            st.cert_table.clone(),
                            st.global_quota.clone(),
                            st.firewall.clone(),
                            st.stun_addrs.clone(),
                            rx,
                        )
                        .await
                    }
                }));
            }
        } else {
            set_module_health(reg, "reverse_proxy", ModuleHealth::Disabled);
        }

        // 4. Port Forwards
        if cfg.modules.port_forward {
            set_module_health(reg, "port_forward", ModuleHealth::Running);
            let tz = cfg.timezone_offset_secs();
            for pf in cfg.port_forwards.iter().filter(|p| p.enabled).cloned() {
                let (stop_tx, stop_rx) = watch::channel(false);
                active_stops.push(stop_tx);
                let st = state.clone();
                let (htx, _) = watch::channel(ModuleHealth::Running);
                tokio::spawn(supervise_module("port_forward", stop_rx, htx, Some(reg.clone()), move |rx| {
                    let pf = pf.clone();
                    let st = st.clone();
                    async move {
                        run_port_forward_rule(pf, tz, st.global_quota.clone(), st.firewall.clone(), rx).await
                    }
                }));
            }
        } else {
            set_module_health(reg, "port_forward", ModuleHealth::Disabled);
        }

        // 5. STUN
        if cfg.modules.stun {
            set_module_health(reg, "stun", ModuleHealth::Running);
            let (stop_tx, stop_rx) = watch::channel(false);
            active_stops.push(stop_tx);
            let st = state.clone();
            let stun_list = cfg.stun.clone();
            let (htx, _) = watch::channel(ModuleHealth::Running);
            tokio::spawn(supervise_module("stun", stop_rx, htx, Some(reg.clone()), move |mut rx| {
                let st = st.clone();
                let stun_list = stun_list.clone();
                async move {
                    loop {
                        for s in stun_list.iter().filter(|s| s.enabled) {
                            if let Ok(addr) = probe_stun_once(s).await {
                                let mut next = (**st.stun_addrs.load()).clone();
                                next.insert(s.name.clone(), format_public_endpoint(addr));
                                st.stun_addrs.store(Arc::new(next));
                            }
                        }
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_secs(25)) => {}
                            _ = rx.changed() => break,
                        }
                    }
                    Ok(())
                }
            }));
        } else {
            set_module_health(reg, "stun", ModuleHealth::Disabled);
        }

        // 6. Cron
        if cfg.modules.cron {
            set_module_health(reg, "cron", ModuleHealth::Running);
            let (stop_tx, stop_rx) = watch::channel(false);
            active_stops.push(stop_tx);
            let jobs = cfg.cron.clone();
            let tz = cfg.timezone_offset_secs();
            let (htx, _) = watch::channel(ModuleHealth::Running);
            tokio::spawn(supervise_module("cron", stop_rx, htx, Some(reg.clone()), move |mut rx| {
                let jobs = jobs.clone();
                async move {
                    loop {
                        let now = logger::unix_now();
                        for j in jobs.iter().filter(|j| j.enabled) {
                            if let Ok(sched) = CronSchedule::parse(&j.schedule) {
                                if sched.matches(now, tz) {
                                    let job_c = j.clone();
                                    tokio::spawn(async move {
                                        let _ = execute_cron_job(&job_c).await;
                                    });
                                }
                            }
                        }
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                            _ = rx.changed() => break,
                        }
                    }
                    Ok(())
                }
            }));
        } else {
            set_module_health(reg, "cron", ModuleHealth::Disabled);
        }

        // 7. Web Terminal & Docker 状态标记
        set_module_health(
            reg,
            "web_terminal",
            if cfg.modules.web_terminal { ModuleHealth::Running } else { ModuleHealth::Disabled },
        );
        set_module_health(
            reg,
            "docker",
            if cfg.modules.docker { ModuleHealth::Running } else { ModuleHealth::Disabled },
        );

        state.reload_notify.notified().await;
    }
}
