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
use crate::daemon::cron::{due_seconds_window, execute_cron_job_with_ctx, CronRuntime, CronSchedule};
use crate::daemon::ddns::sync_ddns_entry;
use crate::daemon::notify::broadcast_event;
use crate::firewall::FirewallManager;
use crate::logger::Level;
use crate::monitor::alerts::AlertState;
use crate::monitor::procfs::MonitorSampler;
use crate::net::listener::ConnectionQuota;
use crate::net::port_forward::run_port_forward_rule;
use crate::net::reverse_proxy::run_reverse_proxy_authorized;
use crate::net::stun::{new_stun_runtime, run_stun_rule};
use crate::net::tls_resolver::{certified_key_from_pem, load_or_create_admin_cert, CertTable};
use crate::security::auth::{AuthState, HashGate, PasswordHash, DEFAULT_INITIAL_PASSWORD};
use crate::security::fail2ban::Fail2Ban;
use crate::security::vault::Vault;
use crate::supervisor::{new_health_registry, set_module_health, supervise_module, ModuleHealth};
use crate::web::ws_pty::PtyManager;
use crate::web::{boundary, build_router, AppState};
use arc_swap::ArcSwap;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{watch, Notify};

#[cfg(feature = "mimalloc-alloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn print_usage() {
    println!(
        "Vane {} — 高安全双栈全能路由器网关\n\n\
         用法:\n  \
           vane [run] [--config <path>] [--listen <ip:port>]   启动网关守护进程\n  \
           vane check [--config <path>]                        校验配置文件语法与安全约束\n  \
           vane auth-reset [--config <path>]                   重置管理员密码为初始密码 admin321\n  \
           vane firewall lockdown [--off] [--config <path>]    一键启用或解除 WAN 紧急防火墙闭锁\n  \
           vane service install [--config <path>]              安装 OpenWrt procd 自启服务与防火墙自愈钩子\n  \
           vane update                                         通过官方脚本校验 SHA256 并在线升级\n  \
           vane version                                        打印版本与目标架构信息",
        env!("CARGO_PKG_VERSION")
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let first = args.get(1).map(|s| s.as_str());
    let cmd = match first {
        None => "run",
        Some(flag) if flag.starts_with("--config") || flag.starts_with("--listen") => "run",
        Some(sub) => sub,
    };
    let config_path = find_arg(&args, "--config")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config.toml"));
    let listen_override = find_arg(&args, "--listen");

    match cmd {
        "help" | "--help" | "-h" => {
            print_usage();
        }
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
                .args([
                    "-c",
                    "curl -fsSL https://raw.githubusercontent.com/xinghaix/vane/main/scripts/install.sh | sh -s -- --update",
                ])
                .status();
            match status {
                Ok(s) if s.success() => println!("Vane 更新完成。"),
                _ => {
                    eprintln!(
                        "自动更新失败，请手动执行: curl -fsSL https://raw.githubusercontent.com/xinghaix/vane/main/scripts/install.sh | sh"
                    );
                    std::process::exit(1);
                }
            }
        }
        "check" => {
            let data_dir = config_path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let verify_secrets = args.iter().any(|a| a == "--verify-secrets");
            match load_or_init(&config_path).and_then(|o| {
                o.config.validate()?;
                if verify_secrets {
                    let v = Vault::load_or_create(data_dir)?;
                    let bad = v.verify_all(&o.config);
                    if !bad.is_empty() {
                        return Err(format!("以下加密机密字段无法以当前主密钥解密: {:?}", bad));
                    }
                }
                Ok(o.config)
            }) {
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
        "firewall" => {
            let sub = args.get(2).map(|s| s.as_str()).unwrap_or("");
            if sub != "lockdown" {
                eprintln!("未知 firewall 子命令: {}（支持: vane firewall lockdown [--off]）", sub);
                std::process::exit(1);
            }
            let enable = !args.iter().any(|a| a == "--off");
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("初始化运行时失败");
            let res = rt.block_on(async {
                let outcome = load_or_init(&config_path)?;
                let fw = FirewallManager::detect_and_init(outcome.config.firewall).await;
                fw.trigger_lockdown(enable).await
            });
            match res {
                Ok(()) => println!("防火墙紧急闭锁已{}", if enable { "启用" } else { "解除" }),
                Err(e) => {
                    eprintln!("执行防火墙闭锁操作失败: {}", e);
                    std::process::exit(1);
                }
            }
        }
        "service" => {
            let sub = args.get(2).map(|s| s.as_str()).unwrap_or("");
            if sub != "install" {
                eprintln!("未知 service 子命令: {}（支持: vane service install）", sub);
                std::process::exit(1);
            }
            if let Err(e) = install_openwrt_service(&config_path) {
                eprintln!("安装系统服务失败: {}", e);
                std::process::exit(1);
            }
        }
        "run" => {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let worker_count = load_or_init(&config_path)
                .map(|o| (o.config.system.worker_threads as usize).clamp(1, 8))
                .unwrap_or(2);
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(worker_count)
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
        other => {
            eprintln!("未知命令: {}\n", other);
            print_usage();
            std::process::exit(1);
        }
    }
}

fn find_arg(args: &[String], flag: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone())
}

fn install_openwrt_service(config_path: &Path) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("无法定位当前二进制路径: {e}"))?;
    let cfg_abs = fs::canonicalize(config_path).unwrap_or_else(|_| config_path.to_path_buf());
    if !Path::new("/etc/openwrt_release").exists() && !Path::new("/sbin/procd").exists() {
        return Err("当前系统未检测到 OpenWrt procd 环境，请使用 scripts/install.sh 安装 systemd 或容器服务".into());
    }
    let init_script = format!(
        "#!/bin/sh /etc/rc.common\n\
         START=95\n\
         STOP=10\n\
         USE_PROCD=1\n\n\
         start_service() {{\n\
             procd_open_instance\n\
             procd_set_param command \"{}\" run --config \"{}\"\n\
             procd_set_param respawn 3600 5 5\n\
             procd_set_param stdout 1\n\
             procd_set_param stderr 1\n\
             procd_close_instance\n\
         }}\n",
        exe.display(),
        cfg_abs.display()
    );
    let init_path = Path::new("/etc/init.d/vane");
    crate::config::crash_safe_atomic_write(init_path, init_script.as_bytes(), crate::config::random_nonce())
        .map_err(|e| format!("写入 /etc/init.d/vane 失败: {e}"))?;
    fs::set_permissions(init_path, fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("设置服务脚本可执行权限失败: {e}"))?;
    let sysupgrade = Path::new("/etc/sysupgrade.conf");
    if let Some(dir) = cfg_abs.parent() {
        let line = format!("{}/", dir.display());
        let existing = fs::read_to_string(sysupgrade).unwrap_or_default();
        if !existing.lines().any(|l| l.trim() == line || l.trim() == dir.to_string_lossy()) {
            let mut updated = existing;
            if !updated.is_empty() && !updated.ends_with('\n') {
                updated.push('\n');
            }
            updated.push_str(&line);
            updated.push('\n');
            let _ = fs::write(sysupgrade, updated);
        }
    }
    println!("已安装 OpenWrt procd 服务脚本 /etc/init.d/vane 并登记固件升级保留目录。");
    Ok(())
}

fn reset_admin_password(config_path: &Path) -> Result<(), String> {
    let mut outcome = load_or_init(config_path)?;
    let default_hash = PasswordHash::create(DEFAULT_INITIAL_PASSWORD).map_err(|e| e.to_string())?;
    outcome.config.admin.password_hash = default_hash.encode();
    outcome.config.admin.must_change_password = true;
    save_config(config_path, &outcome.config)
}

fn load_admin_tls_cert(
    data_dir: &Path,
    cfg: &Config,
) -> Result<Arc<rustls::sign::CertifiedKey>, String> {
    if !cfg.admin.tls_cert_path.trim().is_empty() && !cfg.admin.tls_key_path.trim().is_empty() {
        let crt = fs::read(cfg.admin.tls_cert_path.trim())
            .map_err(|e| format!("读取自定义管理证书 {} 失败: {}", cfg.admin.tls_cert_path, e))?;
        let key = fs::read(cfg.admin.tls_key_path.trim())
            .map_err(|e| format!("读取自定义管理私钥 {} 失败: {}", cfg.admin.tls_key_path, e))?;
        return certified_key_from_pem(&crt, &key);
    }
    let mut admin_sans = cfg.admin.listen_lan.clone();
    if let Ok(origin) = cfg.admin.canonical_origin.parse::<http::Uri>() {
        if let Some(host) = origin.host() {
            admin_sans.push(host.to_string());
        }
    }
    load_or_create_admin_cert(data_dir, &admin_sans)
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
    logger::global().set_tz_offset(outcome.config.timezone_offset_secs());
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
    let admin_ck = load_admin_tls_cert(&data_dir, &outcome.config)?;
    let admin_cert = Arc::new(ArcSwap::from(admin_ck.clone()));
    let admin_tls = Arc::new(web::server::tls_config_dynamic(admin_cert.clone()));
    let mut init_cert_table = CertTable::default();
    init_cert_table.fallback = Some(admin_ck);
    let cert_table = Arc::new(ArcSwap::from_pointee(init_cert_table));

    let state = Arc::new(AppState {
        config_path: config_path.clone(),
        config: Arc::new(ArcSwap::from_pointee(outcome.config.clone())),
        config_lock: tokio::sync::Mutex::new(()),
        vault,
        auth: Mutex::new(AuthState::new(
            outcome.config.admin.canonical_origin.clone(),
            outcome.config.admin.totp_last_step,
        )),
        hash_gate: Arc::new(HashGate::new()),
        fail2ban: Arc::new(Fail2Ban::new()),
        firewall: firewall.clone(),
        health_registry: health_registry.clone(),
        ddns_status: Arc::new(crate::daemon::ddns::DdnsRuntime::new(data_dir.clone())),
        cert_table: cert_table.clone(),
        cert_status: Arc::new(daemon::acme::AcmeRuntime::new(data_dir.clone())),
        admin_cert,
        stun_addrs: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
        stun_status: new_stun_runtime(),
        cron_status: CronRuntime::new(),
        monitor_sampler: MonitorSampler::new(),
        alert_state: AlertState::default(),
        global_quota: ConnectionQuota::new(outcome.config.system.global_max_conns),
        pty_mgr: Arc::new(PtyManager::new()),
        proxy_tickets: crate::security::tickets::SessionTickets::default(),
        reload_notify: Arc::new(Notify::new()),
    });

    // 只绑定显式配置的地址；单一地址失败不影响其他地址，绝不偷偷改绑。
    let router = build_router(state.clone());
    let mut bound_listeners = Vec::new();
    for addr in outcome.config.admin_listen_addrs() {
        match web::server::bind(addr) {
            Ok(listener) => bound_listeners.push((addr, listener)),
            Err(e) => logger::log(Level::Error, "admin", &format!("管理地址 {} 绑定失败: {}", addr, e)),
        }
    }
    if bound_listeners.is_empty() {
        return Err("无法绑定任何管理面板监听地址".into());
    }

    // 管理监听器准备完成后才启动数据面，避免管理绑定失败时先开放公网规则。
    let (network_tx, network_rx) = watch::channel(0u64);
    let network_task = tokio::spawn(async move {
        if let Err(error) = daemon::network_events::watch_changes(network_tx).await {
            logger::log(Level::Warn, "network", &error);
        }
    });
    let state_for_sup = state.clone();
    let orchestrator = tokio::spawn(async move {
        orchestrate_modules(state_for_sup, network_rx).await;
    });

    let entry_suffix = boundary::active_secret_path(&outcome.config).unwrap_or("");
    let mut web_tasks = Vec::new();
    let admin_quota = Arc::new(tokio::sync::Semaphore::new(16));
    for (addr, listener) in bound_listeners {
        logger::log(Level::Info, "admin", &format!("Web 管理控制台监听于 https://{}", addr));
        if !entry_suffix.is_empty() {
            // 仅打印到本机标准错误流供管理员首次访问，不写入 Web 内存环形日志
            eprintln!("==> Vane 管理控制台安全入口: https://{}{}", addr, entry_suffix);
        }
        let app = router.clone();
        let tls = admin_tls.clone();
        let quota = admin_quota.clone();
        let origin = outcome.config.admin.canonical_origin.clone();
        let handshake = Duration::from_secs(outcome.config.security.tls_handshake_timeout_secs);
        let header = Duration::from_secs(outcome.config.security.http_header_timeout_secs);
        web_tasks.push(tokio::spawn(async move {
            if let Err(e) = web::server::serve(listener, app, tls, origin, quota, handshake, header).await {
                logger::log(Level::Error, "admin", &format!("管理监听器 {} 已停止: {}", addr, e));
            }
        }));
    }

    let _ = tokio::signal::ctrl_c().await;
    logger::log(Level::Info, "system", "收到退出信号，正在清理防火墙规则并优雅停机...");
    orchestrator.abort();
    network_task.abort();
    let _ = orchestrator.await;
    let _ = network_task.await;
    state.pty_mgr.notify_revoke();
    let _ = firewall.pre_start_sweep().await;
    for t in web_tasks {
        t.abort();
    }
    Ok(())
}

fn spawn_circuit_alert_watcher(
    module_name: &'static str,
    mut health_rx: watch::Receiver<ModuleHealth>,
    state: Arc<AppState>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut notified_open = false;
        while health_rx.changed().await.is_ok() {
            let cur = health_rx.borrow().clone();
            match cur {
                ModuleHealth::CircuitOpen { reason, .. } if !notified_open => {
                    notified_open = true;
                    let cfg = state.config.load_full();
                    broadcast_event(
                        &cfg,
                        &state.vault,
                        "module_circuit_open",
                        &format!("Vane 子模块熔断告警: {}", module_name),
                        &reason,
                        "critical",
                    )
                    .await;
                }
                ModuleHealth::Running | ModuleHealth::Disabled => {
                    notified_open = false;
                }
                _ => {}
            }
        }
    })
}

async fn reconcile_stale_firewall_and_runtime(state: &AppState, cfg: &Config) {
    for rule in state.firewall.list_rules() {
        let keep = match rule.owner() {
            "ddns" => cfg.modules.ddns && cfg.ddns.iter().any(|e| e.enabled && e.name == rule.name()),
            "reverse_proxy" => {
                cfg.modules.reverse_proxy
                    && cfg
                        .reverse_proxy
                        .iter()
                        .any(|r| r.enabled && r.open_wan_firewall && r.name == rule.name())
            }
            "port_forward" => {
                cfg.modules.port_forward
                    && cfg.port_forwards.iter().any(|p| {
                        p.enabled
                            && (p.open_wan_firewall || p.engine == "kernel_dnat")
                            && (format!("{}_tcp", p.name) == rule.name()
                                || format!("{}_udp", p.name) == rule.name())
                    })
            }
            _ => true,
        };
        if !keep {
            if let Err(err) = state.firewall.remove_rule(rule.owner(), rule.name()).await {
                logger::log(Level::Error, rule.owner(), &err);
            }
        }
    }

    if let Ok(mut statuses) = state.ddns_status.write() {
        statuses.retain(|name, _| cfg.ddns.iter().any(|entry| entry.name == *name));
        for (name, status) in statuses.iter_mut() {
            if !cfg.modules.ddns || !cfg.ddns.iter().any(|entry| entry.enabled && entry.name == *name) {
                status.enabled = false;
                status.status = "disabled".into();
            }
        }
    }

    if let Ok(mut certs) = state.cert_status.write() {
        certs.retain(|domain, _| cfg.acme.iter().any(|a| &a.domain == domain));
    }

    if let Ok(mut stuns) = state.stun_status.write() {
        stuns.retain(|name, _| cfg.stun.iter().any(|s| &s.name == name));
        for (name, status) in stuns.iter_mut() {
            if !cfg.modules.stun || !cfg.stun.iter().any(|s| s.enabled && &s.name == name) {
                status.enabled = false;
                status.status = "disabled".into();
            }
        }
    }
    let mut next_stun_addrs = (**state.stun_addrs.load()).clone();
    next_stun_addrs.retain(|name, _| cfg.modules.stun && cfg.stun.iter().any(|s| s.enabled && &s.name == name));
    state.stun_addrs.store(Arc::new(next_stun_addrs));

    state.cron_status.retain_configured(&cfg.cron);
}

async fn orchestrate_modules(state: Arc<AppState>, network_rx: watch::Receiver<u64>) {
    let mut active_stops: Vec<watch::Sender<bool>> = Vec::new();
    let mut active_tasks = tokio::task::JoinSet::new();
    loop {
        for stop in active_stops.drain(..) {
            let _ = stop.send(true);
        }
        if tokio::time::timeout(Duration::from_secs(3), async {
            while active_tasks.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            active_tasks.abort_all();
            while active_tasks.join_next().await.is_some() {}
        }
        let cfg: Arc<Config> = state.config.load_full();
        let reg = &state.health_registry;

        reconcile_stale_firewall_and_runtime(&state, &cfg).await;

        let data_dir = state
            .config_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        if let Err(error) = daemon::split_dns::reconcile(&cfg, data_dir).await {
            logger::log(Level::Warn, "split_dns", &error);
        }

        // 1. DDNS
        if cfg.modules.ddns {
            set_module_health(reg, "ddns", ModuleHealth::Running);
            for entry in cfg.ddns.iter().filter(|entry| entry.enabled).cloned() {
                let (stop_tx, stop_rx) = watch::channel(false);
                active_stops.push(stop_tx);
                let st = state.clone();
                let snapshot = cfg.clone();
                let changes = network_rx.clone();
                let (htx, hrx) = watch::channel(ModuleHealth::Running);
                let _ = spawn_circuit_alert_watcher("ddns", hrx, state.clone());
                active_tasks.spawn(supervise_module("ddns", stop_rx, htx, Some(reg.clone()), move |mut rx| {
                    let st = st.clone();
                    let entry = entry.clone();
                    let snapshot = snapshot.clone();
                    let mut changes = changes.clone();
                    async move {
                        let mut watch_network = true;
                        loop {
                            if *rx.borrow() {
                                break;
                            }
                            tokio::select! {
                                _ = rx.changed() => break,
                                result = sync_ddns_entry(&entry, &snapshot, &st.vault, &st.firewall, &st.ddns_status) => {
                                    if let Err(error) = result { logger::log(Level::Warn, "ddns", &error); }
                                },
                            }
                            tokio::select! {
                                _ = tokio::time::sleep(Duration::from_secs(entry.reconcile_interval_secs)) => {},
                                _ = rx.changed() => break,
                                event = changes.changed(), if watch_network => {
                                    if event.is_err() { watch_network = false; } else {
                                        tokio::select! { _ = rx.changed() => break, _ = tokio::time::sleep(Duration::from_secs(2)) => {} }
                                        changes.borrow_and_update();
                                    }
                                },
                            }
                        }
                        Ok(())
                    }
                }));
            }
        } else {
            set_module_health(reg, "ddns", ModuleHealth::Disabled);
        }

        // 2. ACME
        if cfg.modules.acme {
            set_module_health(reg, "acme", ModuleHealth::Running);
            for entry in cfg.acme.iter().filter(|entry| entry.enabled).cloned() {
                let (stop_tx, stop_rx) = watch::channel(false);
                active_stops.push(stop_tx);
                let st = state.clone();
                let snapshot = cfg.clone();
                let (htx, hrx) = watch::channel(ModuleHealth::Running);
                let _ = spawn_circuit_alert_watcher("acme", hrx, state.clone());
                active_tasks.spawn(supervise_module("acme", stop_rx, htx, Some(reg.clone()), move |mut rx| {
                    let st = st.clone();
                    let entry = entry.clone();
                    let snapshot = snapshot.clone();
                    async move {
                        loop {
                            if *rx.borrow() {
                                break;
                            }
                            let healthy = tokio::select! {
                                _ = rx.changed() => break,
                                result = issue_or_renew_cert(&entry, &snapshot, &st.vault, &st.cert_table, &st.cert_status, &st.admin_cert, false) => {
                                    match result {
                                        Ok(status) => status.status == "active",
                                        Err(error) => { logger::log(Level::Warn, "acme", &format!("{}: {}", entry.domain, error)); false },
                                    }
                                },
                            };
                            tokio::select! { _ = rx.changed() => break, _ = tokio::time::sleep(Duration::from_secs(if healthy { 3600 } else { 300 })) => {} }
                        }
                        Ok(())
                    }
                }));
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
                let (htx, hrx) = watch::channel(ModuleHealth::Running);
                let _ = spawn_circuit_alert_watcher("reverse_proxy", hrx, state.clone());
                active_tasks.spawn(supervise_module(
                    "reverse_proxy",
                    stop_rx,
                    htx,
                    Some(reg.clone()),
                    move |rx| {
                        let rp = rp.clone();
                        let st = st.clone();
                        async move {
                            run_reverse_proxy_authorized(
                                rp,
                                st.cert_table.clone(),
                                st.global_quota.clone(),
                                st.firewall.clone(),
                                st.stun_addrs.clone(),
                                rx,
                                st.clone(),
                            )
                            .await
                        }
                    },
                ));
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
                let (htx, hrx) = watch::channel(ModuleHealth::Running);
                let _ = spawn_circuit_alert_watcher("port_forward", hrx, state.clone());
                active_tasks.spawn(supervise_module(
                    "port_forward",
                    stop_rx,
                    htx,
                    Some(reg.clone()),
                    move |rx| {
                        let pf = pf.clone();
                        let st = st.clone();
                        async move {
                            run_port_forward_rule(pf, tz, st.global_quota.clone(), st.firewall.clone(), rx).await
                        }
                    },
                ));
            }
        } else {
            set_module_health(reg, "port_forward", ModuleHealth::Disabled);
        }

        // 5. STUN（每条规则独立持有 SO_REUSEPORT 持久会话与 Cloudflare Redirect / Webhook 联动）
        if cfg.modules.stun {
            set_module_health(reg, "stun", ModuleHealth::Running);
            for stun_entry in cfg.stun.iter().filter(|s| s.enabled).cloned() {
                let (stop_tx, stop_rx) = watch::channel(false);
                active_stops.push(stop_tx);
                let st = state.clone();
                let snapshot = cfg.clone();
                let (htx, hrx) = watch::channel(ModuleHealth::Running);
                let _ = spawn_circuit_alert_watcher("stun", hrx, state.clone());
                active_tasks.spawn(supervise_module("stun", stop_rx, htx, Some(reg.clone()), move |rx| {
                    let entry = stun_entry.clone();
                    let snapshot = snapshot.clone();
                    let st = st.clone();
                    async move {
                        run_stun_rule(
                            entry,
                            snapshot,
                            st.vault.clone(),
                            st.stun_addrs.clone(),
                            st.stun_status.clone(),
                            rx,
                        )
                        .await
                    }
                }));
            }
        } else {
            set_module_health(reg, "stun", ModuleHealth::Disabled);
        }

        // 6. Cron（不漏秒、不重入、支持全 5 类真实动作与失败告警）
        if cfg.modules.cron {
            set_module_health(reg, "cron", ModuleHealth::Running);
            let (stop_tx, stop_rx) = watch::channel(false);
            active_stops.push(stop_tx);
            let jobs = cfg.cron.clone();
            let tz = cfg.timezone_offset_secs();
            let cron_ctx = state.build_cron_context(cfg.clone());
            let (htx, hrx) = watch::channel(ModuleHealth::Running);
            let _ = spawn_circuit_alert_watcher("cron", hrx, state.clone());
            active_tasks.spawn(supervise_module("cron", stop_rx, htx, Some(reg.clone()), move |mut rx| {
                let jobs = jobs.clone();
                let cron_ctx = cron_ctx.clone();
                async move {
                    let mut last_tick: Option<u64> = None;
                    loop {
                        if *rx.borrow() {
                            break;
                        }
                        let now = logger::unix_now();
                        for sec in due_seconds_window(&mut last_tick, now) {
                            for j in jobs.iter().filter(|j| j.enabled) {
                                if let Ok(sched) = CronSchedule::parse(&j.schedule) {
                                    if sched.matches(sec, tz) {
                                        let job_c = j.clone();
                                        let ctx_c = cron_ctx.clone();
                                        tokio::spawn(async move {
                                            let _ = execute_cron_job_with_ctx(&job_c, Some(&ctx_c)).await;
                                        });
                                    }
                                }
                            }
                        }
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_millis(500)) => {}
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
            if cfg.modules.web_terminal {
                ModuleHealth::Running
            } else {
                ModuleHealth::Disabled
            },
        );
        set_module_health(
            reg,
            "docker",
            if cfg.modules.docker {
                ModuleHealth::Running
            } else {
                ModuleHealth::Disabled
            },
        );

        state.reload_notify.notified().await;
    }
}
