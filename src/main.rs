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

use crate::config::{encode_secret_segment, load_or_init, save_config, Config};
use crate::daemon::acme::{issue_or_renew_cert, preload_cached_cert};
use crate::daemon::cron::{due_seconds_window, execute_cron_job_cancellable, CronRuntime, CronSchedule};
use crate::daemon::ddns::sync_ddns_entry;
use crate::daemon::notify::broadcast_event;
use crate::firewall::{apply_cli_lockdown_preserve_bans, FirewallManager};
use crate::logger::Level;
use crate::monitor::alerts::{evaluate_and_notify_alerts, AlertState};
use crate::monitor::procfs::MonitorSampler;
use crate::net::listener::ConnectionQuota;
use crate::net::new_rule_status_map;
use crate::net::port_forward::{run_port_forward_rule_with_options, PortForwardRuntimeOptions};
use crate::net::reverse_proxy::{run_reverse_proxy_with_runtime_options, ProxyTimeouts, ReverseProxyRuntimeOptions};
use crate::net::stun::{is_port_or_rule_bound_by_stun, new_stun_runtime, run_stun_rule};
use crate::net::tls_resolver::{certified_key_from_pem, load_or_create_admin_cert, CertTable};
use crate::security::auth::{AuthState, HashGate, PasswordHash, DEFAULT_INITIAL_PASSWORD};
use crate::security::fail2ban::{Fail2Ban, ScopedFail2Ban};
use crate::security::vault::Vault;
use crate::supervisor::{
    clear_module_tasks_health, new_health_registry, new_task_health_map, set_module_health, supervise_module,
    update_task_health, ModuleHealth, TaskHealthMap,
};
use crate::web::ws_pty::PtyManager;
use crate::web::{boundary, build_router, AppState};
use arc_swap::ArcSwap;
use base64::Engine;
use bytes::Bytes;
use http::{header, Method, Request, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use ring::digest::{Context as Sha256Context, SHA256};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{watch, Notify};
use tokio_util::sync::CancellationToken;

const MAX_CUSTOM_ADMIN_TLS_BYTES: u64 = 256 * 1024;
const MAX_UPDATE_REDIRECTS: usize = 5;
const ED25519_SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

#[cfg(feature = "mimalloc-alloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn print_usage() {
    println!(
        "Vane {} — 高安全双栈全能路由器网关\n\n\
         用法:\n  \
           vane [run] [--config <path>] [--listen <ip:port>]                       启动网关守护进程\n  \
           vane check [--config <path>] [--verify-secrets]                         校验配置文件语法与安全约束\n  \
           vane auth-reset [--clear-mfa] [--config <path>]                         重置管理员密码为初始密码 admin321\n  \
           vane firewall lockdown [--off] [--config <path>]                        一键启用或解除 WAN 紧急防火墙闭锁\n  \
           vane service install [--config <path>]                                  安装 OpenWrt procd 自启服务与防火墙自愈钩子\n  \
           vane update [--pubkey <key_or_pem>] [--config <path>] [--repo <o/r>] [--force]\n  \
                                                                                   纯 Rust 严格 HTTPS + Ed25519 验签在线升级\n  \
           vane version                                                            打印版本与目标架构信息",
        env!("CARGO_PKG_VERSION")
    );
}

fn read_small_regular_file(path: &Path, max_bytes: u64, label: &str) -> Result<String, String> {
    let lmeta = fs::symlink_metadata(path)
        .map_err(|e| format!("读取{}元数据 {} 失败: {}", label, path.display(), e))?;
    if lmeta.file_type().is_symlink() {
        return Err(format!("拒绝读取符号链接形式的{}: {}", label, path.display()));
    }
    if !lmeta.file_type().is_file() {
        return Err(format!("{}不是普通文件: {}", label, path.display()));
    }
    if lmeta.len() == 0 || lmeta.len() > max_bytes {
        return Err(format!("{}大小异常 ({} B): {}", label, lmeta.len(), path.display()));
    }
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    opts.custom_flags(libc::O_NOFOLLOW);
    let file = opts
        .open(path)
        .map_err(|e| format!("打开{} {} 失败: {}", label, path.display(), e))?;
    let mut raw = Vec::new();
    file.take(max_bytes + 1)
        .read_to_end(&mut raw)
        .map_err(|e| format!("读取{} {} 失败: {}", label, path.display(), e))?;
    if raw.is_empty() || (raw.len() as u64) > max_bytes {
        return Err(format!("{}大小超出限制: {}", label, path.display()));
    }
    String::from_utf8(raw).map_err(|_| format!("{}不是合法 UTF-8 文本: {}", label, path.display()))
}

fn decode_ed25519_spki_pem(pem: &str) -> Result<[u8; 32], String> {
    let mut in_block = false;
    let mut b64 = String::new();
    for line in pem.lines() {
        let t = line.trim();
        if t == "-----BEGIN PUBLIC KEY-----" {
            in_block = true;
            continue;
        }
        if t == "-----END PUBLIC KEY-----" {
            break;
        }
        if in_block && !t.is_empty() {
            b64.push_str(t);
        }
    }
    if b64.is_empty() {
        return Err("Ed25519 PEM 公钥内容为空".into());
    }
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|_| "Ed25519 PEM 公钥 Base64 解码失败".to_string())?;
    if der.len() != 44 || der[..12] != ED25519_SPKI_PREFIX {
        return Err("PEM 公钥不是标准的 Ed25519 SubjectPublicKeyInfo (RFC 8410)".into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&der[12..44]);
    Ok(out)
}

fn normalize_ed25519_pubkey_input(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Ed25519 公钥为空".into());
    }
    let content = if !trimmed.contains('\n') {
        let p = Path::new(trimmed);
        match fs::symlink_metadata(p) {
            Ok(_) => read_small_regular_file(p, 4096, "Ed25519 公钥文件")?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => trimmed.to_string(),
            Err(e) => return Err(format!("检查 Ed25519 公钥路径 {} 失败: {}", p.display(), e)),
        }
    } else {
        trimmed.to_string()
    };
    let pk_bytes = if content.contains("-----BEGIN PUBLIC KEY-----") {
        decode_ed25519_spki_pem(&content)?
    } else {
        daemon::updater::parse_ed25519_public_key(&content)?
    };
    Ok(daemon::updater::hex_encode(&pk_bytes))
}

fn resolve_update_signing_public_key(
    cli_pubkey: Option<&str>,
    env_pubkey: Option<&str>,
    config_pubkey: Option<&str>,
    builtin_pubkey: Option<&str>,
) -> Result<String, String> {
    let chosen = [cli_pubkey, env_pubkey, config_pubkey, builtin_pubkey]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|s| !s.is_empty())
        .ok_or_else(|| {
            "安全拦截：当前构建未内置官方发布公钥且未配置发布签名 Ed25519 公钥，拒绝执行无签名在线更新。\n\
             正式 Release 构建会自动内置官方公钥；自编译版本请通过以下任一方式提供受信任的 Ed25519 公钥（32 字节 Hex/Base64 或 OpenSSL PEM 文件）：\n  \
               1) CLI 参数: vane update --pubkey <key_or_pem_path>\n  \
               2) 环境变量: VANE_RELEASE_PUBKEY=<key_or_pem_path> vane update\n  \
               3) 配置文件: 在 config.toml 的 [admin] 段配置 update_signing_public_key = \"...\""
                .to_string()
        })?;
    normalize_ed25519_pubkey_input(chosen)
}

fn validate_update_download_url(raw: &str, allow_test_loopback: bool) -> Result<Uri, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.len() > 8192
        || trimmed.contains('#')
        || trimmed.contains(['\r', '\n', '\0'])
    {
        return Err("更新下载 URL 非法或超出长度限制".into());
    }
    let uri: Uri = trimmed.parse().map_err(|_| "更新下载 URL 解析失败".to_string())?;
    if uri.scheme_str() != Some("https") {
        return Err(format!(
            "安全拦截：在线更新仅允许严格 HTTPS 协议，拒绝访问 {}",
            uri.scheme_str().unwrap_or("<missing>")
        ));
    }
    let authority = uri.authority().ok_or("更新下载 URL 缺少主机名")?;
    if authority.as_str().contains('@') {
        return Err("安全拦截：更新下载 URL 禁止包含用户信息凭据".into());
    }
    if uri.port_u16() == Some(0) {
        return Err("更新下载 URL 端口不能为 0".into());
    }
    let host = uri
        .host()
        .ok_or("更新下载 URL 缺少主机名")?
        .trim_matches(['[', ']'])
        .to_ascii_lowercase();
    let is_github_host = host == "github.com"
        || (host.ends_with(".githubusercontent.com")
            && host.len() > ".githubusercontent.com".len()
            && !host.starts_with('.'));
    let is_test_host = cfg!(test) && allow_test_loopback && (host == "127.0.0.1" || host == "localhost");
    if !is_github_host && !is_test_host {
        return Err(format!("安全拦截：拒绝从非 GitHub 受信任主机下载更新资产 ({host})"));
    }
    Ok(uri)
}

fn resolve_https_redirect(location: &str, allow_test_loopback: bool) -> Result<String, String> {
    let next = location.trim();
    if next.is_empty() {
        return Err("远端返回了空的重定向 Location".into());
    }
    validate_update_download_url(next, allow_test_loopback)?;
    Ok(next.to_string())
}

async fn fetch_https_text_strict(
    url: &str,
    limit: usize,
    ssrf_policy: net::http_client::SsrfPolicy,
    allow_test_loopback: bool,
) -> Result<String, String> {
    let mut current_url = url.to_string();
    let client = net::http_client::shared();
    for hop in 0..=MAX_UPDATE_REDIRECTS {
        validate_update_download_url(&current_url, allow_test_loopback)?;
        let mut req = net::http_client::HttpRequest::new("GET", &current_url);
        req.ssrf_policy = ssrf_policy;
        req.response_limit = limit;
        req.timeout = Duration::from_secs(20);
        let resp = client.execute(req).await?;
        if matches!(
            resp.status,
            StatusCode::MOVED_PERMANENTLY
                | StatusCode::FOUND
                | StatusCode::SEE_OTHER
                | StatusCode::TEMPORARY_REDIRECT
                | StatusCode::PERMANENT_REDIRECT
        ) {
            if hop == MAX_UPDATE_REDIRECTS {
                return Err("HTTPS 下载重定向次数超过安全上限".into());
            }
            let loc = resp
                .headers
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or("远端返回重定向但缺少合法 Location 头")?;
            current_url = resolve_https_redirect(loc, allow_test_loopback)?;
            continue;
        }
        resp.ensure_success()?;
        return String::from_utf8(resp.body).map_err(|_| "远端返回的更新校验文本不是合法 UTF-8".to_string());
    }
    Err("HTTPS 下载重定向次数超过安全上限".into())
}

struct AbortOnDropHandle(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDropHandle {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn download_https_archive_to_file_strict(
    url: &str,
    dest_path: &Path,
    max_bytes: u64,
    ssrf_policy: net::http_client::SsrfPolicy,
    allow_test_loopback: bool,
) -> Result<(u64, String), String> {
    let mut current_url = url.to_string();
    let tls_cfg = net::http_client::shared().tls_config();
    for hop in 0..=MAX_UPDATE_REDIRECTS {
        let uri = validate_update_download_url(&current_url, allow_test_loopback)?;
        let authority = uri.authority().ok_or("更新下载 URL 缺少主机")?.as_str().to_string();
        let host = uri
            .host()
            .ok_or("更新下载 URL 缺少主机")?
            .trim_matches(['[', ']'])
            .to_string();
        let port = uri.port_u16().unwrap_or(443);
        let path_q = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");

        let resolved: Vec<SocketAddr> = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::net::lookup_host((host.as_str(), port)),
        )
        .await
        .map_err(|_| format!("解析更新主机 {host} 超时"))?
        .map_err(|e| format!("解析更新主机 {host} 失败: {e}"))?
        .take(32)
        .collect();
        if resolved.is_empty() {
            return Err(format!("更新主机 {host} DNS 解析无可用地址"));
        }
        let filtered: Vec<SocketAddr> = resolved
            .into_iter()
            .filter(|a| net::http_client::is_ip_allowed(a.ip(), ssrf_policy))
            .collect();
        if filtered.is_empty() {
            return Err(format!("安全拦截：更新主机 {host} 命中 SSRF 禁连地址段"));
        }
        let (v6, v4): (Vec<_>, Vec<_>) = filtered.into_iter().partition(SocketAddr::is_ipv6);
        let mut ordered = Vec::with_capacity(v6.len() + v4.len());
        for i in 0..v6.len().max(v4.len()) {
            if let Some(a) = v6.get(i) {
                ordered.push(*a);
            }
            if let Some(a) = v4.get(i) {
                ordered.push(*a);
            }
        }
        let tcp = net::dual_stack::connect_candidates(&ordered, 250)
            .await
            .map_err(|e| format!("连接更新服务器 {host} 失败: {e}"))?;
        let server_name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|_| "非法 TLS 服务器名称".to_string())?;
        let tls_stream = tokio::time::timeout(
            Duration::from_secs(15),
            tokio_rustls::TlsConnector::from(tls_cfg.clone()).connect(server_name, tcp),
        )
        .await
        .map_err(|_| format!("与更新服务器 {host} TLS 握手超时"))?
        .map_err(|e| format!("与更新服务器 {host} TLS 证书校验或握手失败: {e}"))?;

        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls_stream))
            .await
            .map_err(|e| format!("更新下载 HTTP/1.1 握手失败: {e}"))?;
        let _conn_guard = AbortOnDropHandle(tokio::spawn(async move {
            let _ = conn.await;
        }));
        let request = Request::builder()
            .method(Method::GET)
            .uri(path_q)
            .header(header::HOST, &authority)
            .header(header::CONNECTION, "close")
            .header(header::USER_AGENT, concat!("vane/", env!("CARGO_PKG_VERSION")))
            .body(Full::new(Bytes::new()))
            .map_err(|_| "构造更新下载请求失败".to_string())?;
        let response = tokio::time::timeout(Duration::from_secs(30), sender.send_request(request))
            .await
            .map_err(|_| "等待更新下载响应头超时".to_string())?
            .map_err(|e| format!("发送更新下载请求失败: {e}"))?;
        let (parts, mut incoming) = response.into_parts();
        if matches!(
            parts.status,
            StatusCode::MOVED_PERMANENTLY
                | StatusCode::FOUND
                | StatusCode::SEE_OTHER
                | StatusCode::TEMPORARY_REDIRECT
                | StatusCode::PERMANENT_REDIRECT
        ) {
            if hop == MAX_UPDATE_REDIRECTS {
                return Err("HTTPS 归档下载重定向次数超过安全上限".into());
            }
            let loc = parts
                .headers
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or("远端返回重定向但缺少合法 Location 头")?;
            current_url = resolve_https_redirect(loc, allow_test_loopback)?;
            continue;
        }
        if !parts.status.is_success() {
            return Err(format!("下载更新压缩包失败：远端 HTTP 状态码 {}", parts.status.as_u16()));
        }
        if parts
            .headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .is_some_and(|n| n > max_bytes)
        {
            return Err(format!("更新压缩包声明大小超过安全上限 ({max_bytes} B)"));
        }

        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true).mode(0o600);
        #[cfg(unix)]
        opts.custom_flags(libc::O_NOFOLLOW);
        let mut file = opts
            .open(dest_path)
            .map_err(|e| format!("创建临时归档文件失败: {e}"))?;
        let mut hasher = Sha256Context::new(&SHA256);
        let mut written: u64 = 0;

        let stream_res = tokio::time::timeout(Duration::from_secs(180), async {
            while let Some(frame_res) = incoming.frame().await {
                let frame = frame_res.map_err(|e| format!("读取更新压缩包数据流失败: {e}"))?;
                if let Some(chunk) = frame.data_ref() {
                    written = written
                        .checked_add(chunk.len() as u64)
                        .ok_or_else(|| "更新压缩包字节计数溢出".to_string())?;
                    if written > max_bytes {
                        return Err(format!("更新压缩包体积超过安全上限 ({max_bytes} B)"));
                    }
                    hasher.update(chunk);
                    file.write_all(chunk)
                        .map_err(|e| format!("写入临时更新压缩包失败: {e}"))?;
                }
            }
            file.sync_all().map_err(|e| format!("刷盘临时更新压缩包失败: {e}"))?;
            Ok::<(), String>(())
        })
        .await;

        match stream_res {
            Ok(Ok(())) => {
                if written == 0 {
                    let _ = fs::remove_file(dest_path);
                    return Err("下载到的更新压缩包为空".into());
                }
                return Ok((written, daemon::updater::hex_encode(hasher.finish().as_ref())));
            }
            Ok(Err(e)) => {
                let _ = fs::remove_file(dest_path);
                return Err(e);
            }
            Err(_) => {
                let _ = fs::remove_file(dest_path);
                return Err("下载更新压缩包超时 (180s)".into());
            }
        }
    }
    Err("HTTPS 归档下载重定向次数超过安全上限".into())
}

async fn run_cli_self_update(
    config_path: &Path,
    pubkey_override: Option<&str>,
    repo_override: Option<&str>,
    force: bool,
) -> Result<(), String> {
    let existing_cfg = if config_path.exists() {
        Some(load_or_init(config_path)?.config)
    } else {
        None
    };
    let env_pubkey = std::env::var("VANE_RELEASE_PUBKEY").ok();
    let cfg_pubkey = existing_cfg
        .as_ref()
        .map(|c| c.admin.update_signing_public_key.as_str());
    let builtin_pubkey = daemon::updater::builtin_update_signing_public_key();
    let pubkey_hex = resolve_update_signing_public_key(
        pubkey_override,
        env_pubkey.as_deref(),
        cfg_pubkey,
        builtin_pubkey.as_deref(),
    )?;

    let raw_repo = repo_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| existing_cfg.as_ref().map(|c| c.update.repo.as_str()))
        .unwrap_or("xinghaix/vane");
    let clean_repo = daemon::updater::validate_github_repo(raw_repo)?;
    println!(
        "正在通过纯 Rust 严格 HTTPS 检查 Vane 最新版本 (仓库: {}, 架构: {})...",
        clean_repo,
        daemon::updater::current_target_triple()
    );

    let release = daemon::updater::check_github_release(&clean_repo).await?;
    if release.asset_name.is_empty() || release.asset_url.is_empty() {
        return Err(format!(
            "Release {} 未提供匹配当前目标平台 ({}) 的安装包",
            release.tag_name,
            daemon::updater::current_target_triple()
        ));
    }
    if !force && !daemon::updater::is_newer_version(&release.version, daemon::updater::current_version()) {
        println!(
            "当前已是最新版本 v{}（远端最新: {}）；如需验证并重装同版本，请附加 --force。",
            daemon::updater::current_version(),
            release.tag_name
        );
        return Ok(());
    }

    let sig_url = format!("{}.sig.b64", release.asset_url);
    let checksums_url = if release.checksums_url.is_empty() {
        format!(
            "https://github.com/{clean_repo}/releases/download/{}/SHA256SUMS",
            release.tag_name
        )
    } else {
        release.checksums_url.clone()
    };

    println!("发现目标版本 {} ({})，正在获取并预检 Ed25519 分离签名与 SHA256SUMS...", release.tag_name, release.asset_name);
    let sig_text = fetch_https_text_strict(&sig_url, 4096, net::http_client::SsrfPolicy::PublicOnly, false)
        .await
        .map_err(|e| format!("获取 Ed25519 分离签名 ({sig_url}) 失败（已拒绝无签名更新）: {e}"))?;
    let sig_trimmed = sig_text.trim().to_string();
    daemon::updater::parse_ed25519_signature(&sig_trimmed)?;

    let sums_text = fetch_https_text_strict(&checksums_url, 128 * 1024, net::http_client::SsrfPolicy::PublicOnly, false)
        .await
        .map_err(|e| format!("获取 SHA256SUMS ({checksums_url}) 失败: {e}"))?;
    let expected_sha256 = daemon::updater::parse_expected_sha256(&sums_text, Some(&release.asset_name))?
        .ok_or_else(|| format!("SHA256SUMS 中未找到 {} 的摘要条目", release.asset_name))?;

    let sandbox = daemon::updater::TempSandboxDir::create("vane-cli-update")?;
    let archive_path = sandbox.path().join("release.tar.gz");
    println!("正在通过严格 HTTPS 下载更新归档 {}...", release.asset_name);
    let (bytes_len, archive_sha256) = download_https_archive_to_file_strict(
        &release.asset_url,
        &archive_path,
        daemon::updater::MAX_UPLOAD_ARCHIVE_BYTES,
        net::http_client::SsrfPolicy::PublicOnly,
        false,
    )
    .await?;
    println!("下载完成 ({} bytes)，正在执行 Ed25519 验签、SHA-256 核验与降权沙箱预检...", bytes_len);
    if !archive_sha256.eq_ignore_ascii_case(&expected_sha256) {
        return Err(format!(
            "SHA-256 摘要不匹配：下载归档 ({archive_sha256}) != SHA256SUMS ({expected_sha256})"
        ));
    }

    let target_exe = std::env::current_exe().map_err(|e| format!("无法定位当前可执行文件路径: {e}"))?;
    let cfg_owned = config_path.to_path_buf();
    let result = tokio::task::spawn_blocking(move || {
        daemon::updater::verify_and_install_uploaded_archive_signed(
            &sandbox,
            &archive_path,
            &archive_sha256,
            Some(&expected_sha256),
            Some(&sig_trimmed),
            &pubkey_hex,
            &cfg_owned,
            &target_exe,
        )
    })
    .await
    .map_err(|e| format!("执行更新验证线程异常: {e}"))??;

    println!(
        "Vane 已完成密码学验签并原子更新：v{} -> v{} ({}/{})\n  归档 SHA-256: {}\n  程序 SHA-256: {}\n  目标路径: {}\n  回滚备份: {}\n注意: 请重启正在运行的 vane 服务以加载新版本。",
        result.previous_version,
        result.new_version,
        result.os,
        result.arch,
        result.archive_sha256,
        result.binary_sha256,
        result.executable_path,
        result.backup_path
    );
    Ok(())
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
            let _ = rustls::crypto::ring::default_provider().install_default();
            let pubkey_override = find_arg(&args, "--pubkey");
            let repo_override = find_arg(&args, "--repo");
            let force = args.iter().any(|a| a == "--force");
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("初始化运行时失败");
            if let Err(e) = rt.block_on(run_cli_self_update(
                &config_path,
                pubkey_override.as_deref(),
                repo_override.as_deref(),
                force,
            )) {
                eprintln!("在线更新失败: {}", e);
                std::process::exit(1);
            }
        }
        "check" => {
            if !config_path.exists() {
                eprintln!("配置校验失败: 配置文件不存在 ({})", config_path.display());
                std::process::exit(1);
            }
            let data_dir = config_path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let verify_secrets = args.iter().any(|a| a == "--verify-secrets");
            match load_or_init(&config_path).and_then(|o| {
                if verify_secrets {
                    let v = Vault::load_or_create(data_dir)?;
                    o.config.validate_with_vault(Some(&v))?;
                    let bad = v.verify_all(&o.config);
                    if !bad.is_empty() {
                        return Err(format!("以下加密机密字段无法以当前主密钥解密: {:?}", bad));
                    }
                } else {
                    o.config.validate()?;
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
            let clear_mfa = args.iter().any(|a| a == "--clear-mfa");
            match reset_admin_password(&config_path, clear_mfa) {
                Ok(report) => {
                    println!("已将管理员密码重置为初始密码 admin321，下次登录必须修改密码。");
                    if report.cleared_mfa {
                        println!("已同步清除 TOTP 动态口令、恢复码与 Passkey 绑定。");
                    } else if report.totp_remaining || report.passkey_remaining {
                        let mut factors = Vec::new();
                        if report.totp_remaining {
                            factors.push("TOTP");
                        }
                        if report.passkey_remaining {
                            factors.push("Passkey");
                        }
                        eprintln!(
                            "提示: 多因素认证 ({}) 仍保持启用状态；如需同时清除 MFA，请附加 --clear-mfa 参数。",
                            factors.join(" / ")
                        );
                    }
                    eprintln!(
                        "注意: 若 vane 守护进程当前正在运行，请立即重启服务（如 systemctl restart vane 或 /etc/init.d/vane restart）以加载新配置并撤销内存中的所有活跃会话。"
                    );
                }
                Err(e) => {
                    eprintln!("重置密码失败: {}", e);
                    std::process::exit(1);
                }
            }
        }
        "firewall" => {
            let sub = args.get(2).map(|s| s.as_str()).unwrap_or("");
            if sub != "lockdown" {
                eprintln!("未知 firewall 子命令: {}（支持: vane firewall lockdown [--off]）", sub);
                std::process::exit(1);
            }
            let enable = !args.iter().any(|a| a == "--off");
            let data_dir = config_path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("初始化运行时失败");
            let res = rt.block_on(async {
                let outcome = load_or_init(&config_path)?;
                apply_cli_lockdown_preserve_bans(&outcome.config.firewall, &data_dir, enable).await
            });
            match res {
                Ok(report) => {
                    println!(
                        "防火墙紧急闭锁已{} (active={}, kernel_enforced={}, conntrack_flushed={})",
                        if report.active { "启用" } else { "解除" },
                        report.active,
                        report.kernel_enforced,
                        report.conntrack_flushed
                    );
                    for warning in &report.warnings {
                        eprintln!("警告: {}", warning);
                    }
                }
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
                .max_blocking_threads(8)
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

fn posix_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn render_openwrt_init_script(exe: &Path, cfg_abs: &Path) -> Result<String, String> {
    let exe_str = exe
        .to_str()
        .ok_or_else(|| "当前二进制路径包含非 UTF-8 字符".to_string())?;
    let cfg_str = cfg_abs
        .to_str()
        .ok_or_else(|| "配置文件路径包含非 UTF-8 字符".to_string())?;
    if exe_str.contains(['\0', '\r', '\n']) || cfg_str.contains(['\0', '\r', '\n']) {
        return Err("二进制或配置文件路径包含非法控制字符".into());
    }
    Ok(format!(
        "#!/bin/sh /etc/rc.common\n\
         START=95\n\
         STOP=10\n\
         USE_PROCD=1\n\n\
         start_service() {{\n\
             procd_open_instance\n\
             procd_set_param command {} run --config {}\n\
             procd_set_param respawn 3600 5 5\n\
             procd_set_param stdout 1\n\
             procd_set_param stderr 1\n\
             procd_close_instance\n\
         }}\n",
        posix_single_quote(exe_str),
        posix_single_quote(cfg_str)
    ))
}

fn update_sysupgrade_conf(sysupgrade: &Path, cfg_dir: &Path) -> Result<(), String> {
    let dir_str = cfg_dir
        .to_str()
        .ok_or_else(|| "配置目录路径包含非 UTF-8 字符".to_string())?;
    if dir_str.contains(['\0', '\r', '\n']) {
        return Err("配置目录路径包含非法控制字符".into());
    }
    let existing = match fs::symlink_metadata(sysupgrade) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(format!("拒绝修改符号链接 {}", sysupgrade.display()));
            }
            if !meta.file_type().is_file() {
                return Err(format!("{} 不是普通文件", sysupgrade.display()));
            }
            if meta.len() > 256 * 1024 {
                return Err(format!("{} 超过 256 KiB 大小上限", sysupgrade.display()));
            }
            fs::read_to_string(sysupgrade)
                .map_err(|e| format!("读取 {} 失败: {}", sysupgrade.display(), e))?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("检查 {} 失败: {}", sysupgrade.display(), e)),
    };
    let line = format!("{}/", dir_str.trim_end_matches('/'));
    let trimmed_dir = dir_str.trim_end_matches('/');
    if !existing
        .lines()
        .any(|l| l.trim() == line || l.trim() == trimmed_dir)
    {
        let mut updated = existing;
        if !updated.is_empty() && !updated.ends_with('\n') {
            updated.push('\n');
        }
        updated.push_str(&line);
        updated.push('\n');
        crate::config::crash_safe_atomic_write(
            sysupgrade,
            updated.as_bytes(),
            crate::config::random_nonce(),
        )
        .map_err(|e| format!("原子写入 {} 失败: {}", sysupgrade.display(), e))?;
    }
    Ok(())
}

fn install_openwrt_service(config_path: &Path) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("无法定位当前二进制路径: {e}"))?;
    let cfg_abs = fs::canonicalize(config_path).unwrap_or_else(|_| config_path.to_path_buf());
    if !Path::new("/etc/openwrt_release").exists() && !Path::new("/sbin/procd").exists() {
        return Err("当前系统未检测到 OpenWrt procd 环境，请使用 scripts/install.sh 安装 systemd 或容器服务".into());
    }
    let init_script = render_openwrt_init_script(&exe, &cfg_abs)?;
    let init_path = Path::new("/etc/init.d/vane");
    crate::config::crash_safe_atomic_write(init_path, init_script.as_bytes(), crate::config::random_nonce())
        .map_err(|e| format!("写入 /etc/init.d/vane 失败: {e}"))?;
    fs::set_permissions(init_path, fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("设置服务脚本可执行权限失败: {e}"))?;
    let sysupgrade = Path::new("/etc/sysupgrade.conf");
    if let Some(dir) = cfg_abs.parent() {
        update_sysupgrade_conf(sysupgrade, dir)?;
    }
    println!("已安装 OpenWrt procd 服务脚本 /etc/init.d/vane 并登记固件升级保留目录。");
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthResetReport {
    totp_remaining: bool,
    passkey_remaining: bool,
    cleared_mfa: bool,
}

fn reset_admin_password(config_path: &Path, clear_mfa: bool) -> Result<AuthResetReport, String> {
    let mut outcome = load_or_init(config_path)?;
    let default_hash = PasswordHash::create(DEFAULT_INITIAL_PASSWORD).map_err(|e| e.to_string())?;
    outcome.config.admin.password_hash = default_hash.encode();
    outcome.config.admin.must_change_password = true;
    outcome.config.admin.password_login_enabled = true;
    if clear_mfa {
        outcome.config.admin.totp_enabled = false;
        outcome.config.admin.totp_secret.clear();
        outcome.config.admin.totp_recovery_hashes.clear();
        outcome.config.admin.totp_last_step = 0;
        outcome.config.admin.passkey_enabled = false;
        outcome.config.admin.passkeys.clear();
    }
    let report = AuthResetReport {
        totp_remaining: outcome.config.admin.totp_enabled,
        passkey_remaining: outcome.config.admin.passkey_enabled && !outcome.config.admin.passkeys.is_empty(),
        cleared_mfa: clear_mfa,
    };
    save_config(config_path, &outcome.config)?;
    Ok(report)
}

async fn wait_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut sigterm) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = sigterm.recv() => {},
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

fn collect_admin_cert_sans(cfg: &Config) -> Vec<String> {
    let mut admin_sans = cfg.admin.listen_lan.clone();
    if let Ok(origin) = cfg.admin.canonical_origin.parse::<http::Uri>() {
        if let Some(host) = origin.host() {
            admin_sans.push(host.to_string());
        }
    }
    for extra in &cfg.admin.extra_allowed_origins {
        if let Ok(origin) = extra.parse::<http::Uri>() {
            if let Some(host) = origin.host() {
                admin_sans.push(host.to_string());
            }
        }
    }
    admin_sans
}

fn read_custom_admin_tls_file(path: &Path, is_private_key: bool, label: &str) -> Result<Vec<u8>, String> {
    let lmeta = fs::symlink_metadata(path)
        .map_err(|e| format!("读取自定义{}元数据 {} 失败: {}", label, path.display(), e))?;
    if lmeta.file_type().is_symlink() {
        return Err(format!("拒绝读取符号链接形式的自定义{}: {}", label, path.display()));
    }
    if !lmeta.file_type().is_file() {
        return Err(format!("自定义{}不是普通文件: {}", label, path.display()));
    }
    if lmeta.len() == 0 || lmeta.len() > MAX_CUSTOM_ADMIN_TLS_BYTES {
        return Err(format!(
            "自定义{}大小异常 ({} bytes，允许 1..={}): {}",
            label,
            lmeta.len(),
            MAX_CUSTOM_ADMIN_TLS_BYTES,
            path.display()
        ));
    }
    #[cfg(unix)]
    if is_private_key && (lmeta.permissions().mode() & 0o077) != 0 {
        return Err(format!(
            "自定义{} {} 权限过宽 ({:04o})，拒绝加载（请收紧为 0600 或 0400）",
            label,
            path.display(),
            lmeta.permissions().mode() & 0o777
        ));
    }

    let mut open_opts = OpenOptions::new();
    open_opts.read(true);
    #[cfg(unix)]
    open_opts.custom_flags(libc::O_NOFOLLOW);
    let file = open_opts
        .open(path)
        .map_err(|e| format!("打开自定义{} {} 失败: {}", label, path.display(), e))?;
    let fmeta = file
        .metadata()
        .map_err(|e| format!("检查自定义{} {} 元数据失败: {}", label, path.display(), e))?;
    if !fmeta.is_file() {
        return Err(format!("自定义{}不是普通文件: {}", label, path.display()));
    }
    if fmeta.len() == 0 || fmeta.len() > MAX_CUSTOM_ADMIN_TLS_BYTES {
        return Err(format!(
            "自定义{}大小异常 ({} bytes，允许 1..={}): {}",
            label,
            fmeta.len(),
            MAX_CUSTOM_ADMIN_TLS_BYTES,
            path.display()
        ));
    }
    #[cfg(unix)]
    if is_private_key && (fmeta.permissions().mode() & 0o077) != 0 {
        return Err(format!(
            "自定义{} {} 权限过宽 ({:04o})，拒绝加载（请收紧为 0600 或 0400）",
            label,
            path.display(),
            fmeta.permissions().mode() & 0o777
        ));
    }

    let mut buf = Vec::new();
    file.take(MAX_CUSTOM_ADMIN_TLS_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("读取自定义{} {} 失败: {}", label, path.display(), e))?;
    if buf.is_empty() || buf.len() as u64 > MAX_CUSTOM_ADMIN_TLS_BYTES {
        return Err(format!(
            "自定义{}大小超出限制 ({} bytes): {}",
            label,
            MAX_CUSTOM_ADMIN_TLS_BYTES,
            path.display()
        ));
    }
    Ok(buf)
}

fn zeroize_vec(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: b 是有效可写切片元素，volatile 写入防止编译器优化掉敏感内存清零
        unsafe {
            std::ptr::write_volatile(b, 0);
        }
    }
    std::sync::atomic::compiler_fence(Ordering::SeqCst);
}

fn load_admin_tls_cert(
    data_dir: &Path,
    cfg: &Config,
) -> Result<Arc<rustls::sign::CertifiedKey>, String> {
    let cert_path = cfg.admin.tls_cert_path.trim();
    let key_path = cfg.admin.tls_key_path.trim();
    if !cert_path.is_empty() && !key_path.is_empty() {
        let crt = read_custom_admin_tls_file(Path::new(cert_path), false, "管理证书")?;
        let mut key = read_custom_admin_tls_file(Path::new(key_path), true, "管理私钥")?;
        let res = certified_key_from_pem(&crt, &key);
        zeroize_vec(&mut key);
        return res;
    }
    let admin_sans = collect_admin_cert_sans(cfg);
    load_or_create_admin_cert(data_dir, &admin_sans)
}

fn format_admin_entry_stderr_line(addr: SocketAddr, entry_suffix: &str, show_full: bool) -> Option<String> {
    if entry_suffix.is_empty() {
        return None;
    }
    if show_full {
        Some(format!("==> Vane 管理控制台安全入口: https://{}{}", addr, entry_suffix))
    } else {
        Some(format!(
            "==> Vane 管理控制台监听于 https://{} (secret_path: [configured])",
            addr
        ))
    }
}

fn merged_admin_listeners(live: &[SocketAddr], cfg: &Config) -> Vec<SocketAddr> {
    let mut out = live.to_vec();
    for addr in cfg.admin_listen_addrs() {
        if !out.contains(&addr) {
            out.push(addr);
        }
    }
    out
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
    outcome.config.validate_with_vault(Some(&vault))?;
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

    // 先绑定显式配置的管理地址并捕获真实 SocketAddr，避免绑定失败时误清扫防火墙或开放数据面。
    let mut bound_listeners = Vec::new();
    for addr in outcome.config.admin_listen_addrs() {
        match web::server::bind(addr) {
            Ok(listener) => {
                let actual = listener.local_addr().unwrap_or(addr);
                bound_listeners.push((actual, listener));
            }
            Err(e) => logger::log(Level::Error, "admin", &format!("管理地址 {} 绑定失败: {}", addr, e)),
        }
    }
    if bound_listeners.is_empty() {
        return Err("无法绑定任何管理面板监听地址".into());
    }
    let live_admin_addrs: Vec<SocketAddr> = bound_listeners.iter().map(|(a, _)| *a).collect();
    outcome
        .config
        .validate_with_vault_and_listeners(Some(&vault), &live_admin_addrs)?;

    let firewall = FirewallManager::detect_and_init_with_data_dir(outcome.config.firewall.clone(), &data_dir).await;
    let mut protected_admin_ports: Vec<u16> = live_admin_addrs.iter().map(|a| a.port()).collect();
    for addr in outcome.config.admin_listen_addrs() {
        if !protected_admin_ports.contains(&addr.port()) {
            protected_admin_ports.push(addr.port());
        }
    }
    if !protected_admin_ports.contains(&23456) {
        protected_admin_ports.push(23456);
    }
    protected_admin_ports.sort_unstable();
    protected_admin_ports.dedup();
    firewall.set_protected_admin_ports(protected_admin_ports);

    let health_registry = new_health_registry();
    let admin_ck = load_admin_tls_cert(&data_dir, &outcome.config)?;
    let admin_cert = Arc::new(ArcSwap::from(admin_ck));
    let admin_tls = Arc::new(web::server::tls_config_dynamic(admin_cert.clone()));
    let init_cert_table = CertTable {
        fallback: Some(net::tls_resolver::generate_neutral_fallback_cert()?),
        ..Default::default()
    };
    let cert_table = Arc::new(ArcSwap::from_pointee(init_cert_table));
    let inbox = daemon::inbox::NotificationInbox::load_or_new(&data_dir);
    daemon::inbox::register_global(inbox.clone());
    let updater = Arc::new(daemon::updater::UpdateRuntime::new());
    let config_swap = Arc::new(ArcSwap::from_pointee(outcome.config.clone()));
    let cron_runtime = CronRuntime::new();
    cron_runtime.set_live_config(config_swap.clone());
    let shutdown_flag = Arc::new(AtomicBool::new(false));

    let state = Arc::new(AppState {
        config_path: config_path.clone(),
        config: config_swap,
        config_lock: tokio::sync::Mutex::new(()),
        vault,
        auth: Mutex::new(AuthState::new(
            outcome.config.admin.canonical_origin.clone(),
            outcome.config.admin.totp_last_step,
        )),
        hash_gate: Arc::new(HashGate::new()),
        fail2ban: Arc::new(Fail2Ban::new()),
        proxy_gate_fail2ban: Arc::new(ScopedFail2Ban::new()),
        live_admin_listeners: Arc::new(live_admin_addrs),
        shutdown_flag: shutdown_flag.clone(),
        firewall: firewall.clone(),
        health_registry: health_registry.clone(),
        ddns_status: Arc::new(crate::daemon::ddns::DdnsRuntime::new(data_dir.clone())),
        cert_table: cert_table.clone(),
        cert_status: Arc::new(daemon::acme::AcmeRuntime::new(data_dir.clone())),
        admin_cert,
        stun_addrs: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
        stun_status: new_stun_runtime(),
        reverse_proxy_status: new_rule_status_map(),
        port_forward_status: new_rule_status_map(),
        cron_status: cron_runtime,
        monitor_sampler: MonitorSampler::new(),
        alert_state: AlertState::default(),
        inbox,
        updater,
        global_quota: ConnectionQuota::new(outcome.config.system.global_max_conns),
        pty_mgr: Arc::new(PtyManager::new()),
        proxy_gate: Arc::new(crate::security::proxy_gate::ProxyGateStore::new()),
        reauth_tickets: crate::security::tickets::SessionTickets::default(),
        reload_notify: Arc::new(Notify::new()),
    });

    let router = build_router(state.clone());

    // 管理监听器准备完成后才启动数据面，避免管理绑定失败时先开放公网规则。
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (network_tx, network_rx) = watch::channel(0u64);
    let network_task = tokio::spawn(async move {
        if let Err(error) = daemon::network_events::watch_changes(network_tx).await {
            logger::log(Level::Warn, "network", &error);
        }
    });
    let state_for_sup = state.clone();
    let sup_shutdown = shutdown_rx.clone();
    let orchestrator = tokio::spawn(async move {
        orchestrate_modules(state_for_sup, network_rx, sup_shutdown).await;
    });
    let state_for_alert = state.clone();
    let mut alert_shutdown = shutdown_rx.clone();
    let alert_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(60)) => {},
                _ = alert_shutdown.changed() => {
                    if *alert_shutdown.borrow() { break; }
                }
            }
            let cfg = state_for_alert.config.load_full();
            let st = state_for_alert.clone();
            let mcfg = cfg.monitor.clone();
            if let Ok(sys) = tokio::task::spawn_blocking(move || st.monitor_sampler.sample(&mcfg)).await {
                evaluate_and_notify_alerts(&state_for_alert.alert_state, &cfg, &state_for_alert.vault, &sys).await;
            }
        }
    });

    // GitHub Release 新版本定期检查协程（默认关闭；仅检查并提醒，绝不自动下载或自动更新）
    let state_for_update = state.clone();
    let mut update_shutdown = shutdown_rx.clone();
    let update_check_task = tokio::spawn(async move {
        let mut first_wait = true;
        loop {
            let sleep_secs = if first_wait { 120 } else { 3600 };
            first_wait = false;
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(sleep_secs)) => {},
                _ = update_shutdown.changed() => {
                    if *update_shutdown.borrow() { break; }
                }
            }
            let cfg = state_for_update.config.load_full();
            if !cfg.update.auto_check {
                continue;
            }
            let interval_secs = cfg.update.check_interval_hours.clamp(1, 168) * 3600;
            let now = logger::unix_now();
            let last = state_for_update.updater.last_check_unix();
            if last > 0 && now.saturating_sub(last) < interval_secs {
                continue;
            }
            let res = daemon::updater::check_github_release(&cfg.update.repo).await;
            let info_opt = res.as_ref().ok().cloned();
            let should_notify = state_for_update.updater.record_check_result(res);
            if should_notify {
                if let Some(rel) = info_opt {
                    let title = format!("发现 Vane 新版本 {}", rel.tag_name);
                    let msg = format!(
                        "当前运行版本 v{}，GitHub Release 已发布 {}（{}）。请前往「系统设置 → 系统更新」查看更新说明并手动下载上传压缩包更新。",
                        daemon::updater::current_version(),
                        rel.tag_name,
                        rel.html_url
                    );
                    logger::log(Level::Info, "update", &msg);
                    broadcast_event(&cfg, &state_for_update.vault, "system_update", &title, &msg, "info").await;
                }
            }
        }
    });

    // 自签管理证书后台临期自动续期（每 12 小时检查，距到期 <= 30 天时自动热轮换新 5 年证书）
    let state_for_cert = state.clone();
    let data_dir_for_cert = data_dir.clone();
    let mut cert_shutdown = shutdown_rx.clone();
    let admin_cert_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(12 * 3600)) => {},
                _ = cert_shutdown.changed() => {
                    if *cert_shutdown.borrow() { break; }
                }
            }
            let cfg = state_for_cert.config.load_full();
            let uses_custom = !cfg.admin.tls_cert_path.trim().is_empty() && !cfg.admin.tls_key_path.trim().is_empty();
            let uses_acme = cfg.modules.acme && cfg.acme.iter().any(|a| a.enabled && a.use_for_admin);
            if uses_custom || uses_acme {
                continue;
            }
            let sans = collect_admin_cert_sans(&cfg);
            let dir = data_dir_for_cert.clone();
            match tokio::task::spawn_blocking(move || net::tls_resolver::renew_admin_cert_if_due(&dir, &sans)).await {
                Ok(Ok(Some(new_ck))) => {
                    state_for_cert.admin_cert.store(new_ck);
                    logger::log(Level::Info, "admin", "本地自签管理证书已临期自动续签（5 年期）并热加载生效");
                }
                Ok(Ok(None)) => {}
                Ok(Err(e)) => logger::log(Level::Warn, "admin", &format!("检查/自动更新自签管理证书失败: {}", e)),
                Err(_) => {}
            }
        }
    });

    let entry_suffix = boundary::active_secret_path(&outcome.config).unwrap_or("");
    let show_full_secret_path = outcome.created || outcome.config.admin.must_change_password;
    let mut web_tasks = Vec::new();
    let admin_quota = Arc::new(tokio::sync::Semaphore::new(24));
    for (addr, listener) in bound_listeners {
        logger::log(Level::Info, "admin", &format!("Web 管理控制台监听于 https://{}", addr));
        if let Some(line) = format_admin_entry_stderr_line(addr, entry_suffix, show_full_secret_path) {
            // 仅打印到本机标准错误流，且仅首次初始化/待改密时展示完整路径，绝不写入 Web 内存环形日志
            eprintln!("{}", line);
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

    wait_shutdown_signal().await;
    logger::log(Level::Info, "system", "收到退出信号，正在优雅回收子模块并清理防火墙规则...");
    // 先置全局停机标志，再触发 PTY 撤销与 Cron 取消，确保活跃会话立即观测到 session_alive() == false
    shutdown_flag.store(true, Ordering::Release);
    state.pty_mgr.notify_revoke();
    state.cron_status.cancel_all();
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(4), orchestrator).await;
    alert_task.abort();
    update_check_task.abort();
    admin_cert_task.abort();
    network_task.abort();
    let _ = alert_task.await;
    let _ = update_check_task.await;
    let _ = admin_cert_task.await;
    let _ = network_task.await;
    state.pty_mgr.notify_revoke();
    let _ = firewall.pre_start_sweep().await;
    for t in web_tasks {
        t.abort();
    }
    Ok(())
}

fn spawn_rule_health_watcher(
    module_name: &'static str,
    rule_key: String,
    module_enabled: bool,
    mut health_rx: watch::Receiver<ModuleHealth>,
    task_health: TaskHealthMap,
    state: Arc<AppState>,
) {
    update_task_health(
        &task_health,
        &state.health_registry,
        module_enabled,
        module_name,
        &rule_key,
        Some(health_rx.borrow().clone()),
    );
    tokio::spawn(async move {
        let mut notified_open = false;
        while health_rx.changed().await.is_ok() {
            let cur = health_rx.borrow().clone();
            update_task_health(
                &task_health,
                &state.health_registry,
                module_enabled,
                module_name,
                &rule_key,
                Some(cur.clone()),
            );
            match cur {
                ModuleHealth::CircuitOpen { reason, .. } if !notified_open => {
                    notified_open = true;
                    let cfg = state.config.load_full();
                    broadcast_event(
                        &cfg,
                        &state.vault,
                        "module_circuit_open",
                        &format!("Vane 子模块熔断告警: {} ({})", module_name, rule_key),
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
    });
}

async fn reconcile_stale_firewall_and_runtime(state: &AppState, cfg: &Config) {
    let lockdown = state.firewall.is_lockdown();
    for rule in state.firewall.list_rules() {
        let keep = match rule.owner() {
            "ddns" => cfg.modules.ddns && cfg.ddns.iter().any(|e| e.enabled && e.name == rule.name()),
            "reverse_proxy" => {
                !lockdown
                    && cfg.modules.reverse_proxy
                    && cfg
                        .reverse_proxy
                        .iter()
                        .any(|r| r.enabled && r.open_wan_firewall && r.name == rule.name())
            }
            "port_forward" => {
                !lockdown
                    && cfg.modules.port_forward
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

    if let Ok(mut rps) = state.reverse_proxy_status.write() {
        rps.retain(|name, _| cfg.reverse_proxy.iter().any(|r| &r.name == name));
        for rp in &cfg.reverse_proxy {
            if !cfg.modules.reverse_proxy || !rp.enabled || lockdown {
                rps.insert(
                    rp.name.clone(),
                    crate::net::RuleRuntimeStatus {
                        name: rp.name.clone(),
                        enabled: rp.enabled,
                        listen_port: rp.listen_port,
                        stack: rp.stack.clone(),
                        proto: "tcp".into(),
                        status: if lockdown && cfg.modules.reverse_proxy && rp.enabled {
                            "lockdown".into()
                        } else {
                            "disabled".into()
                        },
                        ..Default::default()
                    },
                );
            }
        }
    }

    if let Ok(mut pfs) = state.port_forward_status.write() {
        pfs.retain(|name, _| cfg.port_forwards.iter().any(|p| &p.name == name));
        for pf in &cfg.port_forwards {
            if !cfg.modules.port_forward || !pf.enabled || lockdown {
                pfs.insert(
                    pf.name.clone(),
                    crate::net::RuleRuntimeStatus {
                        name: pf.name.clone(),
                        enabled: pf.enabled,
                        listen_port: pf.listen_port,
                        stack: pf.stack.clone(),
                        proto: pf.proto.clone(),
                        status: if lockdown && cfg.modules.port_forward && pf.enabled {
                            "lockdown".into()
                        } else {
                            "disabled".into()
                        },
                        ..Default::default()
                    },
                );
            }
        }
    }

    state.cron_status.retain_configured(&cfg.cron);
}

#[derive(Default)]
struct ModuleRunner {
    fingerprint: Option<String>,
    stops: Vec<watch::Sender<bool>>,
    tasks: tokio::task::JoinSet<()>,
}

impl ModuleRunner {
    fn begin_stop(&mut self) {
        for stop in self.stops.drain(..) {
            let _ = stop.send(true);
        }
    }

    async fn finish_stop(&mut self) {
        if self.tasks.is_empty() {
            return;
        }
        if tokio::time::timeout(Duration::from_secs(3), async {
            while self.tasks.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            self.tasks.abort_all();
            while self.tasks.join_next().await.is_some() {}
        }
    }
}

struct CancelTokenOnDrop(CancellationToken);

impl Drop for CancelTokenOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

async fn drain_cron_jobs(running_jobs: &mut tokio::task::JoinSet<()>) {
    if running_jobs.is_empty() {
        return;
    }
    if tokio::time::timeout(Duration::from_millis(1500), async {
        while running_jobs.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        running_jobs.abort_all();
        while running_jobs.join_next().await.is_some() {}
    }
}

async fn orchestrate_modules(
    state: Arc<AppState>,
    network_rx: watch::Receiver<u64>,
    shutdown_rx: watch::Receiver<bool>,
) {
    orchestrate_modules_with_lockdown_poll(state, network_rx, shutdown_rx, Duration::from_secs(2)).await;
}

async fn orchestrate_modules_with_lockdown_poll(
    state: Arc<AppState>,
    network_rx: watch::Receiver<u64>,
    mut shutdown_rx: watch::Receiver<bool>,
    lockdown_poll_interval: Duration,
) {
    let task_health = new_task_health_map();
    let mut ddns_runner = ModuleRunner::default();
    let mut acme_runner = ModuleRunner::default();
    let mut rp_runner = ModuleRunner::default();
    let mut pf_runner = ModuleRunner::default();
    let mut stun_runner = ModuleRunner::default();
    let mut cron_runner = ModuleRunner::default();
    let mut last_acme_preload_fp = String::new();

    loop {
        if *shutdown_rx.borrow() {
            break;
        }
        let cfg: Arc<Config> = state.config.load_full();
        let reg = &state.health_registry;
        let lockdown_active = state.firewall.is_lockdown();

        let fp_ddns = serde_json::to_string(&(
            cfg.modules.ddns,
            &cfg.ddns,
            &cfg.dns_providers,
            &cfg.firewall.wan_interfaces,
            &cfg.firewall.lan_interfaces,
            cfg.firewall.auto_manage,
        ))
        .unwrap_or_default();
        let fp_acme_preload = serde_json::to_string(&(
            cfg.modules.acme,
            &cfg.acme,
            &cfg.admin.canonical_origin,
        ))
        .unwrap_or_default();
        let fp_acme = serde_json::to_string(&(
            cfg.modules.acme,
            &cfg.acme,
            &cfg.dns_providers,
            &cfg.admin.canonical_origin,
        ))
        .unwrap_or_default();
        let rp_stun_reuse: Vec<bool> = cfg
            .reverse_proxy
            .iter()
            .map(|r| is_port_or_rule_bound_by_stun(&cfg, &r.name, r.listen_port))
            .collect();
        let fp_rp = serde_json::to_string(&(
            cfg.modules.reverse_proxy,
            lockdown_active,
            &cfg.reverse_proxy,
            &cfg.admin.listen_lan,
            &rp_stun_reuse,
            cfg.security.tls_handshake_timeout_secs,
            cfg.security.http_header_timeout_secs,
            &cfg.firewall.wan_interfaces,
            cfg.firewall.auto_manage,
        ))
        .unwrap_or_default();
        let pf_stun_reuse: Vec<bool> = cfg
            .port_forwards
            .iter()
            .map(|p| is_port_or_rule_bound_by_stun(&cfg, &p.name, p.listen_port))
            .collect();
        let fp_pf = serde_json::to_string(&(
            cfg.modules.port_forward,
            lockdown_active,
            &cfg.port_forwards,
            &pf_stun_reuse,
            cfg.timezone_offset_secs(),
            &cfg.firewall.wan_interfaces,
            &cfg.firewall.lan_interfaces,
            cfg.firewall.auto_manage,
        ))
        .unwrap_or_default();
        let fp_stun = serde_json::to_string(&(
            cfg.modules.stun,
            &cfg.stun,
            cfg.reverse_proxy
                .iter()
                .map(|r| (&r.name, r.listen_port))
                .collect::<Vec<_>>(),
            cfg.port_forwards
                .iter()
                .map(|p| (&p.name, p.listen_port))
                .collect::<Vec<_>>(),
        ))
        .unwrap_or_default();
        let fp_cron = serde_json::to_string(&(
            cfg.modules.cron,
            cfg.modules.docker,
            cfg.admin.allow_cron_exec,
            &cfg.cron,
            cfg.timezone_offset_secs(),
            &cfg.admin.docker_socket,
            &cfg.docker,
            &cfg.notifications,
        ))
        .unwrap_or_default();

        let ch_ddns = ddns_runner.fingerprint.as_ref() != Some(&fp_ddns);
        let ch_acme = acme_runner.fingerprint.as_ref() != Some(&fp_acme);
        let ch_rp = rp_runner.fingerprint.as_ref() != Some(&fp_rp);
        let ch_pf = pf_runner.fingerprint.as_ref() != Some(&fp_pf);
        let ch_stun = stun_runner.fingerprint.as_ref() != Some(&fp_stun);
        let ch_cron = cron_runner.fingerprint.as_ref() != Some(&fp_cron);

        if ch_ddns { ddns_runner.begin_stop(); }
        if ch_acme { acme_runner.begin_stop(); }
        if ch_rp { rp_runner.begin_stop(); }
        if ch_pf { pf_runner.begin_stop(); }
        if ch_stun { stun_runner.begin_stop(); }
        if ch_cron {
            state.cron_status.cancel_all();
            cron_runner.begin_stop();
        }

        if ch_ddns { ddns_runner.finish_stop().await; }
        if ch_acme { acme_runner.finish_stop().await; }
        if ch_rp { rp_runner.finish_stop().await; }
        if ch_pf { pf_runner.finish_stop().await; }
        if ch_stun { stun_runner.finish_stop().await; }
        if ch_cron { cron_runner.finish_stop().await; }

        if *shutdown_rx.borrow() {
            break;
        }

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
        if ch_ddns {
            ddns_runner.fingerprint = Some(fp_ddns);
            clear_module_tasks_health(&task_health, reg, "ddns", cfg.modules.ddns);
            if cfg.modules.ddns {
                for entry in cfg.ddns.iter().filter(|entry| entry.enabled).cloned() {
                    let (stop_tx, stop_rx) = watch::channel(false);
                    ddns_runner.stops.push(stop_tx);
                    let st = state.clone();
                    let snapshot = cfg.clone();
                    let changes = network_rx.clone();
                    let (htx, hrx) = watch::channel(ModuleHealth::Running);
                    spawn_rule_health_watcher("ddns", entry.name.clone(), true, hrx, task_health.clone(), state.clone());
                    ddns_runner.tasks.spawn(supervise_module("ddns", stop_rx, htx, None, move |mut rx| {
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
            }
        }

        // 2. ACME：先修剪已删域名并从磁盘预加载已有合法证书到反代与管理面
        if last_acme_preload_fp != fp_acme_preload {
            last_acme_preload_fp = fp_acme_preload;
            daemon::acme::prune_cert_table(&cfg, &state.cert_table);
            if cfg.modules.acme {
                for entry in cfg.acme.iter().filter(|entry| entry.enabled) {
                    preload_cached_cert(entry, &cfg, &state.cert_table, &state.cert_status, &state.admin_cert).await;
                }
            }
        }
        if ch_acme {
            acme_runner.fingerprint = Some(fp_acme);
            clear_module_tasks_health(&task_health, reg, "acme", cfg.modules.acme);
            if cfg.modules.acme {
                for entry in cfg.acme.iter().filter(|entry| entry.enabled).cloned() {
                    let (stop_tx, stop_rx) = watch::channel(false);
                    acme_runner.stops.push(stop_tx);
                    let st = state.clone();
                    let snapshot = cfg.clone();
                    let (htx, hrx) = watch::channel(ModuleHealth::Running);
                    spawn_rule_health_watcher("acme", entry.domain.clone(), true, hrx, task_health.clone(), state.clone());
                    acme_runner.tasks.spawn(supervise_module("acme", stop_rx, htx, None, move |mut rx| {
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
            }
        }

        // 3. Reverse Proxy（紧急闭锁激活时主动暂停全部 WAN 反代监听器）
        if ch_rp {
            rp_runner.fingerprint = Some(fp_rp);
            let rp_should_run = cfg.modules.reverse_proxy && !lockdown_active;
            clear_module_tasks_health(&task_health, reg, "reverse_proxy", rp_should_run);
            if cfg.modules.reverse_proxy && lockdown_active {
                logger::log(Level::Warn, "reverse_proxy", "防火墙处于紧急闭锁模式，已暂停全部反向代理监听器");
            }
            if rp_should_run {
                let timeouts = ProxyTimeouts {
                    tls_handshake: Duration::from_secs(cfg.security.tls_handshake_timeout_secs),
                    http_header: Duration::from_secs(cfg.security.http_header_timeout_secs),
                };
                let admin_listeners = merged_admin_listeners(&state.live_admin_listeners, &cfg);
                for rp in cfg.reverse_proxy.iter().filter(|r| r.enabled).cloned() {
                    let revealed_rp = match reveal_reverse_proxy_config(&rp, &state.vault) {
                        Ok(r) => r,
                        Err(e) => {
                            logger::log(Level::Error, "reverse_proxy", &format!("反代 {} 请求头解密失败: {}", rp.name, e));
                            net::update_rule_status(
                                &Some(state.reverse_proxy_status.clone()),
                                net::RuleRuntimeStatus {
                                    name: rp.name.clone(),
                                    enabled: rp.enabled,
                                    listen_port: rp.listen_port,
                                    stack: rp.stack.clone(),
                                    proto: "tcp".into(),
                                    status: "failed".into(),
                                    last_error: e.clone(),
                                    ..Default::default()
                                },
                            );
                            update_task_health(
                                &task_health,
                                reg,
                                true,
                                "reverse_proxy",
                                &rp.name,
                                Some(ModuleHealth::Degraded {
                                    recent_failures: 1,
                                    last_error: e,
                                }),
                            );
                            continue;
                        }
                    };
                    let reuse_port = is_port_or_rule_bound_by_stun(&cfg, &rp.name, rp.listen_port);
                    let (stop_tx, stop_rx) = watch::channel(false);
                    rp_runner.stops.push(stop_tx);
                    let st = state.clone();
                    let listeners_for_rp = admin_listeners.clone();
                    let (htx, hrx) = watch::channel(ModuleHealth::Running);
                    spawn_rule_health_watcher("reverse_proxy", rp.name.clone(), true, hrx, task_health.clone(), state.clone());
                    rp_runner.tasks.spawn(supervise_module(
                        "reverse_proxy",
                        stop_rx,
                        htx,
                        None,
                        move |rx| {
                            let rp = revealed_rp.clone();
                            let st = st.clone();
                            let listeners_for_rp = listeners_for_rp.clone();
                            async move {
                                let options = ReverseProxyRuntimeOptions::default()
                                    .with_timeouts(timeouts)
                                    .with_status_map(Some(st.reverse_proxy_status.clone()))
                                    .with_admin_listeners(listeners_for_rp)
                                    .with_fail2ban(Some(st.fail2ban.clone()))
                                    .with_reuse_port(reuse_port);
                                run_reverse_proxy_with_runtime_options(
                                    rp,
                                    st.cert_table.clone(),
                                    st.global_quota.clone(),
                                    st.firewall.clone(),
                                    st.stun_addrs.clone(),
                                    rx,
                                    st.clone(),
                                    options,
                                )
                                .await
                            }
                        },
                    ));
                }
            }
        }

        // 4. Port Forwards（紧急闭锁激活时主动暂停全部端口转发监听器）
        if ch_pf {
            pf_runner.fingerprint = Some(fp_pf);
            let pf_should_run = cfg.modules.port_forward && !lockdown_active;
            clear_module_tasks_health(&task_health, reg, "port_forward", pf_should_run);
            if cfg.modules.port_forward && lockdown_active {
                logger::log(Level::Warn, "port_forward", "防火墙处于紧急闭锁模式，已暂停全部端口转发监听器");
            }
            if pf_should_run {
                let tz = cfg.timezone_offset_secs();
                for pf in cfg.port_forwards.iter().filter(|p| p.enabled).cloned() {
                    let reuse_port = is_port_or_rule_bound_by_stun(&cfg, &pf.name, pf.listen_port);
                    let (stop_tx, stop_rx) = watch::channel(false);
                    pf_runner.stops.push(stop_tx);
                    let st = state.clone();
                    let (htx, hrx) = watch::channel(ModuleHealth::Running);
                    spawn_rule_health_watcher("port_forward", pf.name.clone(), true, hrx, task_health.clone(), state.clone());
                    pf_runner.tasks.spawn(supervise_module(
                        "port_forward",
                        stop_rx,
                        htx,
                        None,
                        move |rx| {
                            let pf = pf.clone();
                            let st = st.clone();
                            async move {
                                let options = PortForwardRuntimeOptions::default()
                                    .with_status_map(Some(st.port_forward_status.clone()))
                                    .with_fail2ban(Some(st.fail2ban.clone()))
                                    .with_reuse_port(reuse_port);
                                run_port_forward_rule_with_options(
                                    pf,
                                    tz,
                                    st.global_quota.clone(),
                                    st.firewall.clone(),
                                    rx,
                                    options,
                                )
                                .await
                            }
                        },
                    ));
                }
            }
        }

        // 5. STUN
        if ch_stun {
            stun_runner.fingerprint = Some(fp_stun);
            clear_module_tasks_health(&task_health, reg, "stun", cfg.modules.stun);
            if cfg.modules.stun {
                for stun_entry in cfg.stun.iter().filter(|s| s.enabled).cloned() {
                    let (stop_tx, stop_rx) = watch::channel(false);
                    stun_runner.stops.push(stop_tx);
                    let st = state.clone();
                    let snapshot = cfg.clone();
                    let (htx, hrx) = watch::channel(ModuleHealth::Running);
                    spawn_rule_health_watcher("stun", stun_entry.name.clone(), true, hrx, task_health.clone(), state.clone());
                    stun_runner.tasks.spawn(supervise_module("stun", stop_rx, htx, None, move |rx| {
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
            }
        }

        // 6. Cron（绑定实时配置与可取消 JoinSet，禁用/重载/停机立即取消并回收全部在途任务）
        if ch_cron {
            cron_runner.fingerprint = Some(fp_cron);
            clear_module_tasks_health(&task_health, reg, "cron", cfg.modules.cron);
            if cfg.modules.cron {
                let (stop_tx, stop_rx) = watch::channel(false);
                cron_runner.stops.push(stop_tx);
                let jobs = cfg.cron.clone();
                let tz = cfg.timezone_offset_secs();
                let cron_ctx = state
                    .build_cron_context(cfg.clone())
                    .with_live_config(state.config.clone());
                let (htx, hrx) = watch::channel(ModuleHealth::Running);
                spawn_rule_health_watcher("cron", "scheduler".into(), true, hrx, task_health.clone(), state.clone());
                cron_runner.tasks.spawn(supervise_module("cron", stop_rx, htx, None, move |mut rx| {
                    let jobs = jobs.clone();
                    let cron_ctx = cron_ctx.clone();
                    async move {
                        let mut run_cancel = cron_ctx.runtime.cancel_token();
                        let mut cancel_guard = CancelTokenOnDrop(run_cancel.clone());
                        let mut running_jobs = tokio::task::JoinSet::new();
                        let mut last_tick: Option<u64> = None;
                        loop {
                            while running_jobs.try_join_next().is_some() {}
                            if *rx.borrow() {
                                break;
                            }
                            if run_cancel.is_cancelled() {
                                drain_cron_jobs(&mut running_jobs).await;
                                if *rx.borrow() {
                                    break;
                                }
                                if !cron_ctx.current_config().modules.cron {
                                    // 模块已在实时配置中关闭，静默等待 orchestrator 发送 stop_rx 退出
                                    let _ = rx.changed().await;
                                    break;
                                }
                                run_cancel = cron_ctx.runtime.cancel_token();
                                cancel_guard = CancelTokenOnDrop(run_cancel.clone());
                                continue;
                            }
                            let now = logger::unix_now();
                            for sec in due_seconds_window(&mut last_tick, now) {
                                for j in jobs.iter().filter(|j| j.enabled) {
                                    if let Ok(sched) = CronSchedule::parse(&j.schedule) {
                                        if sched.matches(sec, tz) {
                                            let job_c = j.clone();
                                            let ctx_c = cron_ctx.clone();
                                            let job_cancel = run_cancel.child_token();
                                            running_jobs.spawn(async move {
                                                let _ = execute_cron_job_cancellable(
                                                    &job_c,
                                                    Some(&ctx_c),
                                                    Some(job_cancel),
                                                )
                                                .await;
                                            });
                                        }
                                    }
                                }
                            }
                            tokio::select! {
                                _ = tokio::time::sleep(Duration::from_millis(500)) => {}
                                _ = rx.changed() => break,
                                _ = run_cancel.cancelled() => {}
                            }
                        }
                        run_cancel.cancel();
                        drop(cancel_guard);
                        drain_cron_jobs(&mut running_jobs).await;
                        Ok(())
                    }
                }));
            }
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

        loop {
            tokio::select! {
                _ = state.reload_notify.notified() => break,
                _ = tokio::time::sleep(lockdown_poll_interval) => {
                    let disk_lockdown = state.firewall.is_lockdown();
                    if disk_lockdown != lockdown_active {
                        logger::log(
                            Level::Warn,
                            "firewall",
                            &format!(
                                "检测到持久化 .lockdown 状态变更 ({} -> {})，立即同步内核规则并重编排数据面监听器",
                                lockdown_active, disk_lockdown
                            ),
                        );
                        let _ = state.firewall.sync_all().await;
                        break;
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
            }
        }
    }

    ddns_runner.begin_stop();
    acme_runner.begin_stop();
    rp_runner.begin_stop();
    pf_runner.begin_stop();
    stun_runner.begin_stop();
    state.cron_status.cancel_all();
    cron_runner.begin_stop();

    ddns_runner.finish_stop().await;
    acme_runner.finish_stop().await;
    rp_runner.finish_stop().await;
    pf_runner.finish_stop().await;
    stun_runner.finish_stop().await;
    cron_runner.finish_stop().await;
}

fn reveal_reverse_proxy_config(
    rp: &crate::config::ReverseProxyConfig,
    vault: &Vault,
) -> Result<crate::config::ReverseProxyConfig, String> {
    let mut out = rp.clone();
    let erp = encode_secret_segment(&rp.name);
    for (i, rule) in out.rules.iter_mut().enumerate() {
        for (header, val) in rule.request_headers_set.iter_mut() {
            let ehdr = encode_secret_segment(header);
            let canonical_path = format!("reverse_proxy.{}.rules.{}.request_headers_set.{}", erp, i, ehdr);
            let legacy_path = format!("reverse_proxy.{}.rules.{}.request_headers_set.{}", rp.name, i, header);
            *val = vault.reveal_string_with_legacy(
                &canonical_path,
                (legacy_path != canonical_path).then_some(legacy_path.as_str()),
                val,
            )?;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PasskeyEntry, ReverseProxyConfig, ReverseProxyRule};
    use std::os::unix::fs::symlink;

    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "vane-main-test-{}-{:016x}",
            tag,
            crate::config::random_nonce()
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn reveal_reverse_proxy_config_supports_v2_canonical_and_rejects_transplanted_aad() {
        let vault = Vault::from_master(&[0x42; 32]);
        let rp_name = "ops.prod";
        let hdr_name = "x-auth.token";
        let canonical = format!(
            "reverse_proxy.{}.rules.0.request_headers_set.{}",
            encode_secret_segment(rp_name),
            encode_secret_segment(hdr_name)
        );
        let legacy = format!("reverse_proxy.{}.rules.0.request_headers_set.{}", rp_name, hdr_name);
        assert_ne!(canonical, legacy);

        let sealed_v2 = vault.seal(&canonical, b"secret-v2-val").unwrap();
        assert!(sealed_v2.starts_with(crate::security::vault::ENC_PREFIX_V2));
        let mut rule = ReverseProxyRule::default();
        rule.request_headers_set.insert(hdr_name.into(), sealed_v2);
        let rp = ReverseProxyConfig {
            name: rp_name.into(),
            rules: vec![rule],
            ..Default::default()
        };
        let revealed = reveal_reverse_proxy_config(&rp, &vault).unwrap();
        assert_eq!(revealed.rules[0].request_headers_set.get(hdr_name).unwrap(), "secret-v2-val");

        // 用未转义 legacy 路径或其它字段路径封套的 enc:v2: 密文不得在规范路径下被解密（阻断跨字段移植）
        let mut bad_rule = ReverseProxyRule::default();
        bad_rule
            .request_headers_set
            .insert(hdr_name.into(), vault.seal(&legacy, b"transplanted").unwrap());
        let bad_rp = ReverseProxyConfig {
            name: rp_name.into(),
            rules: vec![bad_rule],
            ..Default::default()
        };
        assert!(reveal_reverse_proxy_config(&bad_rp, &vault).is_err());
    }

    #[tokio::test]
    async fn cron_cancel_token_and_drain_reaps_running_tasks() {
        let rt = CronRuntime::new();
        let cfg = Arc::new(ArcSwap::from_pointee(Config::default()));
        rt.set_live_config(cfg.clone());
        assert!(rt.live_config().is_some());

        let token = rt.cancel_token();
        let mut jobs = tokio::task::JoinSet::new();
        let finished = Arc::new(AtomicBool::new(false));
        let finished_c = finished.clone();
        let child = token.child_token();
        jobs.spawn(async move {
            child.cancelled().await;
            finished_c.store(true, Ordering::Release);
        });

        rt.cancel_all();
        drain_cron_jobs(&mut jobs).await;
        assert!(token.is_cancelled());
        assert!(finished.load(Ordering::Acquire));
        assert!(jobs.is_empty());
    }

    #[test]
    fn custom_admin_tls_file_rejects_symlinks_oversized_and_loose_key_perms() {
        let dir = tmp_dir("tls");
        let cert = dir.join("custom.crt");
        let key = dir.join("custom.key");
        let link = dir.join("key.link");
        let big = dir.join("big.crt");

        fs::write(&cert, b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n").unwrap();
        fs::write(&key, b"-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n").unwrap();
        symlink(&key, &link).unwrap();
        fs::write(&big, vec![b'A'; (MAX_CUSTOM_ADMIN_TLS_BYTES + 1) as usize]).unwrap();

        // 拒绝符号链接
        assert!(read_custom_admin_tls_file(&link, true, "管理私钥").is_err());
        // 拒绝非普通文件（目录）
        assert!(read_custom_admin_tls_file(&dir, false, "管理证书").is_err());
        // 拒绝超过 256 KiB 的超大文件
        assert!(read_custom_admin_tls_file(&big, false, "管理证书").is_err());

        // 私钥权限 0644 / 0640 必须拒绝
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_custom_admin_tls_file(&key, true, "管理私钥").is_err());
        fs::set_permissions(&key, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(read_custom_admin_tls_file(&key, true, "管理私钥").is_err());

        // 私钥权限 0600 与 0400 放行；证书 0644 放行
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!read_custom_admin_tls_file(&key, true, "管理私钥").unwrap().is_empty());
        fs::set_permissions(&key, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(!read_custom_admin_tls_file(&key, true, "管理私钥").unwrap().is_empty());
        fs::set_permissions(&cert, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!read_custom_admin_tls_file(&cert, false, "管理证书").unwrap().is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn update_pubkey_resolution_precedence_pem_file_and_fail_closed() {
        // 无任何公钥配置（含未内置公钥）时必须 fail-closed
        assert!(resolve_update_signing_public_key(None, None, None, None).is_err());
        assert!(resolve_update_signing_public_key(Some("  "), Some(""), Some(" "), Some("")).is_err());

        let key_a = [0x11u8; 32];
        let key_b = [0x22u8; 32];
        let key_c = [0x33u8; 32];
        let key_d = [0x44u8; 32];
        let hex_a = daemon::updater::hex_encode(&key_a);
        let b64_b = base64::engine::general_purpose::STANDARD.encode(key_b);
        let hex_c = daemon::updater::hex_encode(&key_c);
        let hex_d = daemon::updater::hex_encode(&key_d);

        // 优先级：CLI > ENV > config.toml > 内置官方公钥
        assert_eq!(
            resolve_update_signing_public_key(Some(&hex_a), Some(&b64_b), Some(&hex_c), Some(&hex_d)).unwrap(),
            hex_a
        );
        assert_eq!(
            resolve_update_signing_public_key(None, Some(&b64_b), Some(&hex_c), Some(&hex_d)).unwrap(),
            daemon::updater::hex_encode(&key_b)
        );
        assert_eq!(
            resolve_update_signing_public_key(None, None, Some(&hex_c), Some(&hex_d)).unwrap(),
            hex_c
        );
        assert_eq!(
            resolve_update_signing_public_key(None, None, None, Some(&hex_d)).unwrap(),
            hex_d
        );

        // 支持 OpenSSL Ed25519 SPKI PEM 文本与常规文件，并拒绝符号链接文件
        let mut spki_der = Vec::with_capacity(44);
        spki_der.extend_from_slice(&ED25519_SPKI_PREFIX);
        spki_der.extend_from_slice(&key_a);
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            base64::engine::general_purpose::STANDARD.encode(&spki_der)
        );
        assert_eq!(
            resolve_update_signing_public_key(Some(&pem), None, None, None).unwrap(),
            hex_a
        );

        let dir = tmp_dir("update-pk");
        let pem_path = dir.join("release.pub.pem");
        let pem_link = dir.join("release.pub.link");
        fs::write(&pem_path, &pem).unwrap();
        symlink(&pem_path, &pem_link).unwrap();
        assert_eq!(
            resolve_update_signing_public_key(Some(pem_path.to_str().unwrap()), None, None, None).unwrap(),
            hex_a
        );
        assert!(resolve_update_signing_public_key(Some(pem_link.to_str().unwrap()), None, None, None).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn update_download_url_and_redirect_enforces_strict_https_and_github_hosts() {
        assert!(validate_update_download_url(
            "https://github.com/xinghaix/vane/releases/download/v0.2.0/vane-v0.2.0-x86_64-unknown-linux-musl.tar.gz",
            false
        )
        .is_ok());
        assert!(validate_update_download_url(
            "https://objects.githubusercontent.com/github-production-release-asset/123",
            false
        )
        .is_ok());
        assert!(validate_update_download_url(
            "https://release-assets.githubusercontent.com/github-production-release-asset/456",
            false
        )
        .is_ok());

        // 严禁 HTTP 降级、非 GitHub 主机、域名后缀伪造与 URL 凭据
        assert!(validate_update_download_url("http://github.com/xinghaix/vane/releases/download/v0.2.0/a.tar.gz", false).is_err());
        assert!(validate_update_download_url("https://evil.example.com/a.tar.gz", false).is_err());
        assert!(validate_update_download_url("https://evilgithub.com/a.tar.gz", false).is_err());
        assert!(validate_update_download_url("https://github.com.evil.com/a.tar.gz", false).is_err());
        assert!(validate_update_download_url("https://user:pass@github.com/a.tar.gz", false).is_err());
        assert!(validate_update_download_url("https://.githubusercontent.com/a.tar.gz", false).is_err());

        // 重定向 Location 同样严禁 HTTP 降级、相对路径与非受信任主机
        assert!(resolve_https_redirect("https://release-assets.githubusercontent.com/abc", false).is_ok());
        assert!(resolve_https_redirect("http://objects.githubusercontent.com/abc", false).is_err());
        assert!(resolve_https_redirect("/relative/path", false).is_err());
        assert!(resolve_https_redirect("https://attacker.example/vane.tar.gz", false).is_err());
    }

    #[test]
    fn startup_secret_path_stderr_line_redacts_after_initial_setup() {
        let addr: SocketAddr = "192.168.1.1:23456".parse().unwrap();
        let initial = format_admin_entry_stderr_line(addr, "/_vane_secret1234", true).unwrap();
        assert!(initial.contains("/_vane_secret1234"));

        let subsequent = format_admin_entry_stderr_line(addr, "/_vane_secret1234", false).unwrap();
        assert!(!subsequent.contains("/_vane_secret1234"));
        assert!(subsequent.contains("secret_path: [configured]"));

        assert!(format_admin_entry_stderr_line(addr, "", true).is_none());
    }

    #[test]
    fn openwrt_service_script_posix_quotes_and_sysupgrade_rejects_symlink() {
        let script = render_openwrt_init_script(
            Path::new("/usr/bin/vane $(id) 'evil'"),
            Path::new("/etc/vane/my`cmd` config.toml"),
        )
        .unwrap();
        assert!(script.contains("procd_set_param command '/usr/bin/vane $(id) '\\''evil'\\''' run --config '/etc/vane/my`cmd` config.toml'"));
        assert!(render_openwrt_init_script(Path::new("/usr/bin/vane\nevil"), Path::new("/etc/vane/config.toml")).is_err());

        let dir = tmp_dir("sysupgrade");
        let real_conf = dir.join("sysupgrade.conf");
        let target_cfg_dir = dir.join("etc_vane");
        fs::create_dir_all(&target_cfg_dir).unwrap();
        update_sysupgrade_conf(&real_conf, &target_cfg_dir).unwrap();
        let written = fs::read_to_string(&real_conf).unwrap();
        assert!(written.contains(&format!("{}/", target_cfg_dir.display())));
        // 幂等重复调用不产生重复行
        update_sysupgrade_conf(&real_conf, &target_cfg_dir).unwrap();
        assert_eq!(fs::read_to_string(&real_conf).unwrap(), written);

        let link_conf = dir.join("sysupgrade.link");
        symlink(&real_conf, &link_conf).unwrap();
        assert!(update_sysupgrade_conf(&link_conf, &target_cfg_dir).is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reset_admin_password_reports_remaining_mfa_and_supports_clear_mfa() {
        let dir = tmp_dir("auth-reset");
        let cfg_path = dir.join("config.toml");
        let mut cfg = Config::default();
        cfg.admin.password_hash = PasswordHash::create(b"StrongPass123!").unwrap().encode();
        cfg.admin.must_change_password = false;
        cfg.admin.password_login_enabled = false;
        cfg.admin.totp_enabled = true;
        cfg.admin.totp_secret = "JBSWY3DPEHPK3PXP".into();
        cfg.admin.totp_recovery_hashes = vec!["dummy".into()];
        cfg.admin.passkey_enabled = true;
        cfg.admin.passkeys.push(PasskeyEntry {
            id: "cred1".into(),
            name: "key1".into(),
            rp_id: "example.com".into(),
            alg: -7,
            pubkey_b64: "AAAA".into(),
            sign_count: 1,
            created_at: 1,
            last_used_at: 1,
        });
        save_config(&cfg_path, &cfg).unwrap();

        let keep_report = reset_admin_password(&cfg_path, false).unwrap();
        assert!(keep_report.totp_remaining);
        assert!(keep_report.passkey_remaining);
        assert!(!keep_report.cleared_mfa);
        let after_keep = load_or_init(&cfg_path).unwrap().config;
        assert!(after_keep.admin.must_change_password);
        assert!(after_keep.admin.password_login_enabled);
        assert!(after_keep.admin.totp_enabled);
        assert_eq!(after_keep.admin.passkeys.len(), 1);

        let clear_report = reset_admin_password(&cfg_path, true).unwrap();
        assert!(!clear_report.totp_remaining);
        assert!(!clear_report.passkey_remaining);
        assert!(clear_report.cleared_mfa);
        let after_clear = load_or_init(&cfg_path).unwrap().config;
        assert!(!after_clear.admin.totp_enabled);
        assert!(after_clear.admin.totp_secret.is_empty());
        assert!(after_clear.admin.totp_recovery_hashes.is_empty());
        assert!(!after_clear.admin.passkey_enabled);
        assert!(after_clear.admin.passkeys.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn merged_admin_listeners_includes_both_live_and_configured_addrs() {
        let mut cfg = Config::default();
        cfg.admin.listen_lan = vec!["192.168.1.1:23456".into(), "10.0.0.1:8443".into()];
        let live: Vec<SocketAddr> = vec!["127.0.0.1:23456".parse().unwrap(), "192.168.1.1:23456".parse().unwrap()];
        let merged = merged_admin_listeners(&live, &cfg);
        assert_eq!(merged.len(), 3);
        assert!(merged.contains(&"127.0.0.1:23456".parse().unwrap()));
        assert!(merged.contains(&"192.168.1.1:23456".parse().unwrap()));
        assert!(merged.contains(&"10.0.0.1:8443".parse().unwrap()));
    }

    #[tokio::test]
    async fn orchestrate_modules_pauses_wan_on_lockdown_and_prunes_acme_on_disable() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tmp_dir("orch");
        let cfg_path = dir.join("config.toml");

        // 预先持久化 .lockdown 标记，验证重启后 detect_and_init_with_data_dir 恢复闭锁状态
        crate::firewall::write_persisted_lockdown(&dir, true).unwrap();

        let mut cfg = Config::default();
        cfg.firewall.backend = "dry_run".into();
        cfg.firewall.auto_manage = false;
        cfg.modules.reverse_proxy = true;
        cfg.modules.port_forward = true;
        cfg.modules.acme = true;
        cfg.modules.ddns = false;
        cfg.modules.stun = false;
        cfg.modules.cron = false;
        cfg.reverse_proxy.push(ReverseProxyConfig {
            name: "rp-wan".into(),
            enabled: true,
            listen_port: 18443,
            ..Default::default()
        });
        cfg.port_forwards.push(crate::config::PortForwardConfig {
            name: "pf-wan".into(),
            enabled: true,
            listen_port: 18444,
            ..Default::default()
        });
        cfg.acme.push(crate::config::AcmeConfig {
            enabled: true,
            domain: "example.com".into(),
            cert_dir: dir.join("acme-certs").to_string_lossy().into_owned(),
            directory_url: "https://127.0.0.1:1/dir".into(),
            ..Default::default()
        });
        save_config(&cfg_path, &cfg).unwrap();

        let fw = FirewallManager::detect_and_init_with_data_dir(cfg.firewall.clone(), &dir).await;
        assert!(fw.is_lockdown());

        let fallback = net::tls_resolver::generate_neutral_fallback_cert().unwrap();
        let mut init_table = CertTable::default();
        init_table.exact.insert("example.com".into(), fallback.clone());
        let cert_table = Arc::new(ArcSwap::from_pointee(init_table));

        let config_swap = Arc::new(ArcSwap::from_pointee(cfg.clone()));
        let cron_rt = CronRuntime::new();
        cron_rt.set_live_config(config_swap.clone());

        let state = Arc::new(AppState {
            config_path: cfg_path.clone(),
            config: config_swap.clone(),
            config_lock: tokio::sync::Mutex::new(()),
            vault: Arc::new(Vault::from_master(&[0x11; 32])),
            auth: Mutex::new(AuthState::new(cfg.admin.canonical_origin.clone(), 0)),
            hash_gate: Arc::new(HashGate::new()),
            fail2ban: Arc::new(Fail2Ban::new()),
            proxy_gate_fail2ban: Arc::new(ScopedFail2Ban::new()),
            live_admin_listeners: Arc::new(vec!["127.0.0.1:23456".parse().unwrap()]),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            firewall: fw.clone(),
            health_registry: new_health_registry(),
            ddns_status: Arc::new(crate::daemon::ddns::DdnsRuntime::new(dir.clone())),
            cert_table: cert_table.clone(),
            cert_status: Arc::new(daemon::acme::AcmeRuntime::new(dir.clone())),
            admin_cert: Arc::new(ArcSwap::from(fallback)),
            stun_addrs: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            stun_status: new_stun_runtime(),
            reverse_proxy_status: new_rule_status_map(),
            port_forward_status: new_rule_status_map(),
            cron_status: cron_rt,
            monitor_sampler: MonitorSampler::new(),
            alert_state: AlertState::default(),
            inbox: daemon::inbox::NotificationInbox::load_or_new(&dir),
            updater: Arc::new(daemon::updater::UpdateRuntime::new()),
            global_quota: ConnectionQuota::new(32),
            pty_mgr: Arc::new(PtyManager::new()),
            proxy_gate: Arc::new(crate::security::proxy_gate::ProxyGateStore::new()),
            reauth_tickets: crate::security::tickets::SessionTickets::default(),
            reload_notify: Arc::new(Notify::new()),
        });

        let (_net_tx, net_rx) = watch::channel(0u64);
        let (shut_tx, shut_rx) = watch::channel(false);
        let orch = tokio::spawn(orchestrate_modules(state.clone(), net_rx, shut_rx));

        tokio::time::sleep(Duration::from_millis(120)).await;
        // Lockdown 激活时，反代与端口转发不得绑定，状态必须为 lockdown，健康状态为 Disabled
        assert_eq!(
            state
                .reverse_proxy_status
                .read()
                .unwrap()
                .get("rp-wan")
                .map(|s| s.status.as_str()),
            Some("lockdown")
        );
        assert_eq!(
            state
                .port_forward_status
                .read()
                .unwrap()
                .get("pf-wan")
                .map(|s| s.status.as_str()),
            Some("lockdown")
        );
        assert_eq!(
            state.health_registry.read().unwrap().get("reverse_proxy"),
            Some(&ModuleHealth::Disabled)
        );
        assert_eq!(
            state.health_registry.read().unwrap().get("port_forward"),
            Some(&ModuleHealth::Disabled)
        );
        // ACME 启用期间 example.com 保留在 cert_table 中
        assert!(cert_table.load().exact.contains_key("example.com"));

        // 关闭 modules.acme 后，fp_acme_preload 变化并立即触发 prune_cert_table 清空缓存证书
        let mut next_cfg = cfg.clone();
        next_cfg.modules.acme = false;
        config_swap.store(Arc::new(next_cfg));
        state.reload_notify.notify_one();
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(cert_table.load().exact.is_empty());

        let _ = shut_tx.send(true);
        tokio::time::timeout(Duration::from_secs(3), orch)
            .await
            .expect("orchestrator shutdown timeout")
            .unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn orchestrate_modules_detects_external_cli_lockdown_within_poll_interval() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tmp_dir("cli-lockdown-poll");
        let cfg_path = dir.join("config.toml");

        let rp_port = {
            let l = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let pf_port = {
            let l = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
            l.local_addr().unwrap().port()
        };

        let mut cfg = Config::default();
        cfg.firewall.backend = "dry_run".into();
        cfg.firewall.auto_manage = false;
        cfg.modules.reverse_proxy = true;
        cfg.modules.port_forward = true;
        cfg.modules.acme = false;
        cfg.modules.ddns = false;
        cfg.modules.stun = false;
        cfg.modules.cron = false;
        cfg.reverse_proxy.push(ReverseProxyConfig {
            name: "rp-cli".into(),
            enabled: true,
            listen_port: rp_port,
            stack: "ipv4_only".into(),
            open_wan_firewall: false,
            ..Default::default()
        });
        cfg.port_forwards.push(crate::config::PortForwardConfig {
            name: "pf-cli".into(),
            enabled: true,
            listen_port: pf_port,
            stack: "ipv4_only".into(),
            proto: "tcp".into(),
            target: "198.51.100.10:80".into(),
            open_wan_firewall: false,
            ..Default::default()
        });
        save_config(&cfg_path, &cfg).unwrap();

        let fw = FirewallManager::detect_and_init_with_data_dir(cfg.firewall.clone(), &dir).await;
        assert!(!fw.is_lockdown());

        let fallback = net::tls_resolver::generate_neutral_fallback_cert().unwrap();
        let cert_table = Arc::new(ArcSwap::from_pointee(CertTable {
            fallback: Some(fallback.clone()),
            ..Default::default()
        }));
        let config_swap = Arc::new(ArcSwap::from_pointee(cfg.clone()));
        let cron_rt = CronRuntime::new();
        cron_rt.set_live_config(config_swap.clone());

        let state = Arc::new(AppState {
            config_path: cfg_path.clone(),
            config: config_swap,
            config_lock: tokio::sync::Mutex::new(()),
            vault: Arc::new(Vault::from_master(&[0x22; 32])),
            auth: Mutex::new(AuthState::new(cfg.admin.canonical_origin.clone(), 0)),
            hash_gate: Arc::new(HashGate::new()),
            fail2ban: Arc::new(Fail2Ban::new()),
            proxy_gate_fail2ban: Arc::new(ScopedFail2Ban::new()),
            live_admin_listeners: Arc::new(vec!["127.0.0.1:23456".parse().unwrap()]),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            firewall: fw.clone(),
            health_registry: new_health_registry(),
            ddns_status: Arc::new(crate::daemon::ddns::DdnsRuntime::new(dir.clone())),
            cert_table,
            cert_status: Arc::new(daemon::acme::AcmeRuntime::new(dir.clone())),
            admin_cert: Arc::new(ArcSwap::from(fallback)),
            stun_addrs: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            stun_status: new_stun_runtime(),
            reverse_proxy_status: new_rule_status_map(),
            port_forward_status: new_rule_status_map(),
            cron_status: cron_rt,
            monitor_sampler: MonitorSampler::new(),
            alert_state: AlertState::default(),
            inbox: daemon::inbox::NotificationInbox::load_or_new(&dir),
            updater: Arc::new(daemon::updater::UpdateRuntime::new()),
            global_quota: ConnectionQuota::new(32),
            pty_mgr: Arc::new(PtyManager::new()),
            proxy_gate: Arc::new(crate::security::proxy_gate::ProxyGateStore::new()),
            reauth_tickets: crate::security::tickets::SessionTickets::default(),
            reload_notify: Arc::new(Notify::new()),
        });

        let (_net_tx, net_rx) = watch::channel(0u64);
        let (shut_tx, shut_rx) = watch::channel(false);
        let orch = tokio::spawn(orchestrate_modules_with_lockdown_poll(
            state.clone(),
            net_rx,
            shut_rx,
            Duration::from_millis(40),
        ));

        // 1. 初始无 .lockdown：反代与端口转发均处于 Running
        tokio::time::sleep(Duration::from_millis(160)).await;
        assert_eq!(
            state.health_registry.read().unwrap().get("reverse_proxy"),
            Some(&ModuleHealth::Running)
        );
        assert_eq!(
            state.health_registry.read().unwrap().get("port_forward"),
            Some(&ModuleHealth::Running)
        );

        // 2. 模拟外部 CLI `vane firewall lockdown` 写入 .lockdown（不手动触发 reload_notify）
        crate::firewall::write_persisted_lockdown(&dir, true).unwrap();
        tokio::time::sleep(Duration::from_millis(240)).await;
        assert_eq!(
            state
                .reverse_proxy_status
                .read()
                .unwrap()
                .get("rp-cli")
                .map(|s| s.status.as_str()),
            Some("lockdown")
        );
        assert_eq!(
            state
                .port_forward_status
                .read()
                .unwrap()
                .get("pf-cli")
                .map(|s| s.status.as_str()),
            Some("lockdown")
        );
        assert_eq!(
            state.health_registry.read().unwrap().get("reverse_proxy"),
            Some(&ModuleHealth::Disabled)
        );
        assert_eq!(
            state.health_registry.read().unwrap().get("port_forward"),
            Some(&ModuleHealth::Disabled)
        );

        // 3. 模拟外部 CLI `vane firewall lockdown --off` 清除 .lockdown，守护进程自动恢复监听
        crate::firewall::write_persisted_lockdown(&dir, false).unwrap();
        tokio::time::sleep(Duration::from_millis(240)).await;
        assert_eq!(
            state.health_registry.read().unwrap().get("reverse_proxy"),
            Some(&ModuleHealth::Running)
        );
        assert_eq!(
            state.health_registry.read().unwrap().get("port_forward"),
            Some(&ModuleHealth::Running)
        );

        let _ = shut_tx.send(true);
        tokio::time::timeout(Duration::from_secs(3), orch)
            .await
            .expect("orchestrator shutdown timeout")
            .unwrap();
        let _ = fs::remove_dir_all(&dir);
    }
}
