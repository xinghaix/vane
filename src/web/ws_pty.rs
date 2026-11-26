//! Web 终端子系统（默认关闭 modules.web_terminal = false，可在设置页按需打开）：
//! 基于原生 Unix `openpty` + `TIOCSWINSZ` 实现真实伪终端，支持 16 KiB 流式透传、
//! 一次性会话绑定 Ticket（源网段 + 目标 + 会话摘要）、宿主机 Shell / Docker 容器终端、
//! 空闲超时、会话撤权联动断连与进程组 (`SIGHUP -> SIGKILL + wait`) 完整回收。
use crate::config::{DockerConfig, WebTerminalConfig};
use crate::docker::unix_client::{ensure_not_protected, validate_container_ident};
use crate::logger::{self, Level};
use crate::net::dual_stack::BanKey;
use crate::security::tickets::SessionTickets;
use axum::extract::ws::{Message, WebSocket};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::sync::Notify;

const PTY_CHUNK_BYTES: usize = 16 * 1024;
const RESIZE_PREFIX: &str = "\u{0}resize:";
const SAFE_EXEC_PATH: &str = "/usr/sbin:/sbin:/usr/bin:/bin";
const WS_SEND_TIMEOUT: Duration = Duration::from_secs(2);
const WS_CLOSE_NOTICE_TIMEOUT: Duration = Duration::from_secs(1);
const PTY_WRITE_TIMEOUT: Duration = Duration::from_secs(2);

pub struct PtyManager {
    tickets: SessionTickets,
    active_sessions: AtomicUsize,
    revoke_notify: Notify,
}

impl Default for PtyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PtyManager {
    pub fn new() -> Self {
        Self {
            tickets: SessionTickets::default(),
            active_sessions: AtomicUsize::new(0),
            revoke_notify: Notify::new(),
        }
    }

    pub fn issue_bound_ticket(
        &self,
        session_token: &str,
        target: &str,
        peer: BanKey,
        max_sessions: usize,
    ) -> Result<String, String> {
        self.issue_bound_ticket_with_shell(session_token, target, "auto", peer, max_sessions)
    }

    pub fn issue_bound_ticket_with_shell(
        &self,
        session_token: &str,
        target: &str,
        shell: &str,
        peer: BanKey,
        max_sessions: usize,
    ) -> Result<String, String> {
        if self.active_sessions.load(Ordering::SeqCst) >= max_sessions.clamp(1, 10) {
            return Err("已达到最大并发 Web 终端会话数上限".into());
        }
        validate_pty_target(target)?;
        let shell_norm = validate_shell_choice(shell)?;
        self.tickets
            .issue(session_token, format!("pty:{target}:{shell_norm}"), peer)
    }

    pub fn consume_bound_ticket(&self, ticket: &str, target: &str, peer: BanKey) -> Option<[u8; 32]> {
        self.consume_bound_ticket_with_shell(ticket, target, "auto", peer)
    }

    pub fn consume_bound_ticket_with_shell(
        &self,
        ticket: &str,
        target: &str,
        shell: &str,
        peer: BanKey,
    ) -> Option<[u8; 32]> {
        let shell_norm = validate_shell_choice(shell).ok()?;
        self.tickets
            .consume(ticket, &format!("pty:{target}:{shell_norm}"), peer)
    }

    pub fn notify_revoke(&self) {
        self.revoke_notify.notify_waiters();
    }

    pub fn active_count(&self) -> usize {
        self.active_sessions.load(Ordering::SeqCst)
    }
}

pub fn validate_pty_target(target: &str) -> Result<(), String> {
    if target == "host" {
        return Ok(());
    }
    if let Some(container) = target.strip_prefix("container:") {
        validate_container_ident(container)?;
        return Ok(());
    }
    Err("非法的终端目标（仅支持 host 或 container:<name>）".into())
}

/// 严格校验 Docker Socket 路径：必须为无 `.`/`..`/`//` 的绝对路径，且目标本身为非符号链接的 Unix Domain Socket。
/// 统一错误文案避免文件存在性侧信道探测。
pub fn validate_docker_socket_path(socket_path: &str) -> Result<(), String> {
    let trimmed = socket_path.trim();
    if trimmed.is_empty()
        || !trimmed.starts_with('/')
        || trimmed.contains('\0')
        || trimmed.contains("//")
        || trimmed.bytes().any(|b| b < 0x20 || b == 0x7f)
    {
        return Err("Docker Socket 路径无效或不可访问".into());
    }
    let path = Path::new(trimmed);
    if path
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err("Docker Socket 路径无效或不可访问".into());
    }
    let meta = std::fs::symlink_metadata(path)
        .map_err(|_| "Docker Socket 路径无效或不可访问".to_string())?;
    let ft = meta.file_type();
    if ft.is_symlink() || !ft.is_socket() {
        return Err("Docker Socket 路径无效或不可访问".into());
    }
    Ok(())
}

fn resolve_docker_binary() -> &'static str {
    for cand in ["/usr/sbin/docker", "/sbin/docker", "/usr/bin/docker", "/bin/docker"] {
        if is_executable_file(Path::new(cand)) {
            return cand;
        }
    }
    "docker"
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DetectedShell {
    pub id: String,
    pub path: String,
}

fn is_executable_file(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|m| m.is_file() && (m.permissions().mode() & 0o111 != 0))
        .unwrap_or(false)
}

/// 自动探测宿主机可用的 Shell（支持 bash 与 sh；两者皆存在时按序将 bash 置于首位作为默认项）。
pub fn detect_available_shells() -> Vec<DetectedShell> {
    let mut out = Vec::new();
    for cand in ["/bin/bash", "/usr/bin/bash", "/usr/local/bin/bash", "/opt/homebrew/bin/bash"] {
        if is_executable_file(Path::new(cand)) {
            out.push(DetectedShell {
                id: "bash".to_string(),
                path: cand.to_string(),
            });
            break;
        }
    }
    for cand in ["/bin/sh", "/usr/bin/sh"] {
        if is_executable_file(Path::new(cand)) {
            out.push(DetectedShell {
                id: "sh".to_string(),
                path: cand.to_string(),
            });
            break;
        }
    }
    out
}

pub fn default_shell_id(configured: &str, available: &[DetectedShell]) -> String {
    let pref = configured.trim();
    if (pref == "sh" || pref.ends_with("/sh")) && available.iter().any(|s| s.id == "sh") {
        return "sh".to_string();
    }
    if (pref == "bash" || pref.ends_with("/bash")) && available.iter().any(|s| s.id == "bash") {
        return "bash".to_string();
    }
    if available.iter().any(|s| s.id == "bash") {
        return "bash".to_string();
    }
    if available.iter().any(|s| s.id == "sh") {
        return "sh".to_string();
    }
    "sh".to_string()
}

pub fn validate_shell_choice(shell: &str) -> Result<String, String> {
    let s = shell.trim();
    if s.is_empty() || s == "auto" {
        Ok("auto".to_string())
    } else if s == "bash" || s == "sh" {
        Ok(s.to_string())
    } else {
        Err("不支持的终端 Shell 类型（仅支持 auto、bash、sh）".into())
    }
}

fn resolve_shell(pref: &str, session_shell: &str) -> Result<String, String> {
    let available = detect_available_shells();
    let find_id = |id: &str| available.iter().find(|s| s.id == id).map(|s| s.path.clone());

    match session_shell.trim() {
        "bash" => return find_id("bash").ok_or_else(|| "宿主机未检测到可用的 bash".to_string()),
        "sh" => return find_id("sh").ok_or_else(|| "宿主机未检测到可用的 sh".to_string()),
        "" | "auto" => {}
        other => return Err(format!("不支持的终端 Shell: {other}")),
    }

    let cfg_pref = pref.trim();
    if cfg_pref == "bash" {
        if let Some(p) = find_id("bash") {
            return Ok(p);
        }
    } else if cfg_pref == "sh" {
        if let Some(p) = find_id("sh") {
            return Ok(p);
        }
    } else if !cfg_pref.is_empty() && cfg_pref != "auto" && is_executable_file(Path::new(cfg_pref)) {
        return Ok(cfg_pref.to_string());
    }

    // 默认策略：bash 与 sh 同时可用时优先使用 bash，否则回退至 sh / ash
    if let Some(p) = find_id("bash") {
        return Ok(p);
    }
    if let Some(p) = find_id("sh") {
        return Ok(p);
    }
    for s in ["/bin/ash", "/bin/sh"] {
        if is_executable_file(Path::new(s)) {
            return Ok(s.to_string());
        }
    }
    Err("宿主机未找到可用的 bash 或 sh".into())
}

fn supports_login_flag(shell_path: &str) -> bool {
    let base = Path::new(shell_path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    matches!(base, "bash" | "sh" | "ash" | "dash" | "zsh" | "ksh" | "fish")
}

fn current_user_passwd() -> Option<(String, String)> {
    // SAFETY: getpwuid_r 是 POSIX 线程安全接口，使用栈/堆独立缓冲无共享静态态。
    unsafe {
        let uid = libc::geteuid();
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut buf = vec![0u8; 4096];
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let rc = libc::getpwuid_r(
            uid,
            &mut pwd,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result,
        );
        if rc != 0 || result.is_null() {
            return None;
        }
        let user = if pwd.pw_name.is_null() {
            String::new()
        } else {
            std::ffi::CStr::from_ptr(pwd.pw_name).to_string_lossy().into_owned()
        };
        let home = if pwd.pw_dir.is_null() {
            String::new()
        } else {
            std::ffi::CStr::from_ptr(pwd.pw_dir).to_string_lossy().into_owned()
        };
        Some((user, home))
    }
}

fn build_merged_path(existing: Option<&str>) -> String {
    const BASELINE: [&str; 6] = [
        "/usr/local/sbin",
        "/usr/local/bin",
        "/usr/sbin",
        "/usr/bin",
        "/sbin",
        "/bin",
    ];
    let mut parts: Vec<String> = existing
        .unwrap_or("")
        .split(':')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    for dir in BASELINE {
        if !parts.iter().any(|p| p == dir) {
            parts.push(dir.to_string());
        }
    }
    parts.join(":")
}

fn apply_host_shell_env(cmd: &mut Command, shell_path: &str) {
    let passwd = current_user_passwd();
    let existing_home = std::env::var("HOME").ok().filter(|s| !s.trim().is_empty());
    let home = existing_home
        .or_else(|| passwd.as_ref().map(|(_, h)| h.clone()).filter(|s| !s.trim().is_empty()))
        .unwrap_or_else(|| "/root".to_string());
    let existing_user = std::env::var("USER").ok().filter(|s| !s.trim().is_empty());
    let user = existing_user
        .or_else(|| passwd.as_ref().map(|(u, _)| u.clone()).filter(|s| !s.trim().is_empty()));
    let existing_path = std::env::var("PATH").ok();
    let merged_path = build_merged_path(existing_path.as_deref());

    cmd.env("SHELL", shell_path)
        .env("HOME", &home)
        .env("PATH", merged_path)
        .env("BASH_SILENCE_DEPRECATION_WARNING", "1");

    if let Some(u) = user {
        cmd.env("USER", &u);
        if std::env::var("LOGNAME").ok().filter(|s| !s.trim().is_empty()).is_none() {
            cmd.env("LOGNAME", &u);
        }
    }

    let has_utf8_locale = std::env::var("LC_ALL")
        .ok()
        .or_else(|| std::env::var("LANG").ok())
        .is_some_and(|v| {
            let up = v.to_ascii_uppercase();
            up.contains("UTF-8") || up.contains("UTF8")
        });
    if !has_utf8_locale {
        #[cfg(target_os = "macos")]
        cmd.env("LANG", "en_US.UTF-8");
        #[cfg(not(target_os = "macos"))]
        cmd.env("LANG", "C.UTF-8");
    }

    cmd.env_remove("VANE_MASTER_KEY")
        .env_remove("VANE_MASTER_KEY_FILE");
}

pub struct PtyProcess {
    pub master: Option<AsyncFd<File>>,
    pub child: Option<Child>,
    pub pgid: i32,
}

impl Drop for PtyProcess {
    fn drop(&mut self) {
        drop(self.master.take());
        if let Some(mut child) = self.child.take() {
            if self.pgid > 1 {
                unsafe {
                    let _ = libc::kill(-self.pgid, libc::SIGHUP);
                    let _ = libc::kill(-self.pgid, libc::SIGKILL);
                }
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl PtyProcess {
    pub fn resize(&self, cols: u16, rows: u16) {
        let Some(ref master) = self.master else { return };
        let wsz = libc::winsize {
            ws_row: rows.clamp(10, 300),
            ws_col: cols.clamp(20, 500),
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: master 为有效打开的 PTY 主设备文件描述符。
        unsafe {
            let _ = libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &wsz);
        }
    }

    pub async fn terminate_and_reap(mut self) {
        let pgid = self.pgid;
        // 先关闭 PTY master FD，触发从端 EOF / SIGHUP（容器 exec 场景可让 docker CLI 转发挂断）
        drop(self.master.take());
        let Some(mut child) = self.child.take() else { return };
        tokio::task::spawn_blocking(move || {
            if pgid > 1 {
                // SAFETY: 子进程通过 setsid 成为独立会话与进程组长，负号向整组发送信号。
                // 在调用 child.wait() 回收组长 PID 之前先完成 SIGHUP -> 短优雅期 -> SIGTERM -> 短优雅期 -> SIGKILL，
                // 组长即使已退出也仍保持僵尸占位，确保 pgid 不会被操作系统复用，同时彻底清理后台子孙进程。
                unsafe {
                    let _ = libc::kill(-pgid, libc::SIGHUP);
                }
                std::thread::sleep(Duration::from_millis(80));
                unsafe {
                    let _ = libc::kill(-pgid, libc::SIGTERM);
                }
                std::thread::sleep(Duration::from_millis(80));
                unsafe {
                    let _ = libc::kill(-pgid, libc::SIGKILL);
                }
            }
            let _ = child.kill();
            let _ = child.wait();
        })
        .await
        .ok();
    }
}

pub fn spawn_pty_command(mut cmd: Command, cols: u16, rows: u16) -> Result<PtyProcess, String> {
    let mut master_raw: libc::c_int = -1;
    let mut slave_raw: libc::c_int = -1;
    let mut wsz = libc::winsize {
        ws_row: rows.clamp(10, 300),
        ws_col: cols.clamp(20, 500),
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: openpty 初始化一对新的主从伪终端文件描述符。
    let rc = unsafe {
        libc::openpty(
            &mut master_raw,
            &mut slave_raw,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut wsz,
        )
    };
    if rc != 0 || master_raw < 0 || slave_raw < 0 {
        return Err(format!("openpty 分配伪终端失败: {}", io::Error::last_os_error()));
    }

    // SAFETY: openpty 成功后拥有这两个 FD 的唯一所有权。
    let master_owned = unsafe { OwnedFd::from_raw_fd(master_raw) };
    let slave_owned = unsafe { OwnedFd::from_raw_fd(slave_raw) };

    unsafe {
        let flags = libc::fcntl(master_owned.as_raw_fd(), libc::F_GETFD);
        if flags >= 0 {
            let _ = libc::fcntl(master_owned.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC);
        }
        let fl = libc::fcntl(master_owned.as_raw_fd(), libc::F_GETFL);
        if fl >= 0 {
            let _ = libc::fcntl(master_owned.as_raw_fd(), libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
    }

    let slave_in = slave_owned.try_clone().map_err(|e| format!("复制 PTY slave FD 失败: {e}"))?;
    let slave_out = slave_owned.try_clone().map_err(|e| format!("复制 PTY slave FD 失败: {e}"))?;
    let slave_err = slave_owned;

    cmd.env_remove("VANE_MASTER_KEY")
        .env_remove("VANE_MASTER_KEY_FILE")
        .stdin(Stdio::from(slave_in))
        .stdout(Stdio::from(slave_out))
        .stderr(Stdio::from(slave_err))
        .env("TERM", "xterm-256color");

    // SAFETY: pre_exec 仅调用 async-signal-safe 的 setsid 与 ioctl(0, TIOCSCTTY)。
    unsafe {
        cmd.pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            let _ = libc::ioctl(0, libc::TIOCSCTTY as _, 0);
            Ok(())
        });
    }

    let child = cmd.spawn().map_err(|e| format!("启动终端子进程失败: {e}"))?;
    let pgid = child.id() as i32;
    let master_file = File::from(master_owned);
    #[allow(deprecated)]
    let async_master = AsyncFd::new(master_file).map_err(|e| format!("注册异步 PTY FD 失败: {e}"))?;
    Ok(PtyProcess {
        master: Some(async_master),
        child: Some(child),
        pgid,
    })
}

async fn read_pty_chunk(master: &AsyncFd<File>, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        let mut guard = master.readable().await?;
        match guard.try_io(|inner| inner.get_ref().read(buf)) {
            Ok(res) => return res,
            Err(_would_block) => continue,
        }
    }
}

async fn write_pty_all(master: &AsyncFd<File>, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        let mut guard = master.writable().await?;
        match guard.try_io(|inner| inner.get_ref().write(data)) {
            Ok(Ok(0)) => return Err(io::Error::new(io::ErrorKind::WriteZero, "PTY write zero")),
            Ok(Ok(n)) => data = &data[n..],
            Ok(Err(e)) => return Err(e),
            Err(_would_block) => continue,
        }
    }
    Ok(())
}

#[derive(Deserialize)]
struct ResizeFrame {
    cols: u16,
    rows: u16,
}

fn parse_resize_message(text: &str) -> Option<(u16, u16)> {
    let payload = text.strip_prefix(RESIZE_PREFIX)?;
    let parsed: ResizeFrame = serde_json::from_str(payload).ok()?;
    Some((parsed.cols, parsed.rows))
}

async fn wait_until_revoked<F>(pty_mgr: &PtyManager, session_alive: &F)
where
    F: Fn() -> bool,
{
    loop {
        let notified = pty_mgr.revoke_notify.notified();
        tokio::pin!(notified);
        // 在检查 session_alive 之前先注册等待器，彻底消除漏唤醒竞态。
        notified.as_mut().enable();
        if !session_alive() {
            return;
        }
        notified.await;
    }
}

async fn send_ws_notice_bounded(ws: &mut WebSocket, text: impl Into<String>) {
    let _ = tokio::time::timeout(
        WS_CLOSE_NOTICE_TIMEOUT,
        ws.send(Message::Text(text.into().into())),
    )
    .await;
}

async fn send_ws_bounded<F>(
    ws: &mut WebSocket,
    msg: Message,
    pty_mgr: &PtyManager,
    session_alive: &F,
) -> bool
where
    F: Fn() -> bool,
{
    tokio::select! {
        biased;
        _ = wait_until_revoked(pty_mgr, session_alive) => false,
        res = tokio::time::timeout(WS_SEND_TIMEOUT, ws.send(msg)) => {
            matches!(res, Ok(Ok(())))
        }
    }
}

async fn write_pty_bounded<F>(
    master: &AsyncFd<File>,
    data: &[u8],
    pty_mgr: &PtyManager,
    session_alive: &F,
) -> bool
where
    F: Fn() -> bool,
{
    tokio::select! {
        biased;
        _ = wait_until_revoked(pty_mgr, session_alive) => false,
        res = tokio::time::timeout(PTY_WRITE_TIMEOUT, write_pty_all(master, data)) => {
            matches!(res, Ok(Ok(())))
        }
    }
}

struct SessionSlotGuard<'a>(&'a PtyManager);
impl Drop for SessionSlotGuard<'_> {
    fn drop(&mut self) {
        self.0.active_sessions.fetch_sub(1, Ordering::SeqCst);
    }
}

pub async fn handle_pty_websocket<F>(
    mut ws: WebSocket,
    pty_mgr: &PtyManager,
    cfg: WebTerminalConfig,
    docker_socket: String,
    docker_cfg: DockerConfig,
    target: String,
    shell_choice: String,
    cols: u16,
    rows: u16,
    session_alive: F,
) where
    F: Fn() -> bool + Send + Sync + 'static,
{
    let prev = pty_mgr.active_sessions.fetch_add(1, Ordering::SeqCst);
    let _slot_guard = SessionSlotGuard(pty_mgr);
    if prev >= cfg.max_sessions.clamp(1, 10) {
        send_ws_notice_bounded(&mut ws, "ERROR: 已达到最大终端并发会话数\r\n").await;
        return;
    }

    if !session_alive() {
        send_ws_notice_bounded(&mut ws, "\r\n[登录会话或终端模块已关闭，连接已终止]\r\n").await;
        return;
    }

    if let Err(e) = validate_pty_target(&target) {
        send_ws_notice_bounded(&mut ws, format!("ERROR: {e}\r\n")).await;
        return;
    }
    let shell_norm = match validate_shell_choice(&shell_choice) {
        Ok(s) => s,
        Err(e) => {
            send_ws_notice_bounded(&mut ws, format!("ERROR: {e}\r\n")).await;
            return;
        }
    };

    let cmd = if let Some(container) = target.strip_prefix("container:") {
        let effective_socket = if docker_socket.trim().is_empty() {
            "/var/run/docker.sock"
        } else {
            docker_socket.trim()
        };
        if let Err(e) = validate_docker_socket_path(effective_socket) {
            send_ws_notice_bounded(&mut ws, format!("ERROR: {e}\r\n")).await;
            return;
        }
        let check_res = tokio::select! {
            biased;
            _ = wait_until_revoked(pty_mgr, &session_alive) => {
                send_ws_notice_bounded(&mut ws, "\r\n[登录会话或终端模块已关闭，连接已终止]\r\n").await;
                return;
            }
            res = ensure_not_protected(effective_socket, &docker_cfg, container, "exec") => res,
        };
        if let Err(e) = check_res {
            send_ws_notice_bounded(&mut ws, format!("ERROR: {e}\r\n")).await;
            return;
        }
        let mut c = Command::new(resolve_docker_binary());
        // 清空继承环境并固定最小安全 PATH，杜绝 PATH 劫持、DOCKER_HOST 污染与主密钥泄漏
        c.env_clear()
            .env("PATH", SAFE_EXEC_PATH)
            .env("TERM", "xterm-256color")
            .args(["-H", &format!("unix://{}", effective_socket)]);
        match shell_norm.as_str() {
            "bash" => {
                c.args(["exec", "-it", "--", container, "bash", "-l"]);
            }
            "sh" => {
                c.args(["exec", "-it", "--", container, "/bin/sh", "-l"]);
            }
            _ => {
                c.args([
                    "exec",
                    "-it",
                    "--",
                    container,
                    "/bin/sh",
                    "-c",
                    "if command -v bash >/dev/null 2>&1; then exec bash -l; else exec /bin/sh -l; fi",
                ]);
            }
        }
        c
    } else {
        let shell = match resolve_shell(&cfg.shell, &shell_norm) {
            Ok(s) => s,
            Err(e) => {
                send_ws_notice_bounded(&mut ws, format!("ERROR: {e}\r\n")).await;
                return;
            }
        };
        let mut c = Command::new(&shell);
        if supports_login_flag(&shell) {
            c.arg("-l");
        }
        apply_host_shell_env(&mut c, &shell);
        if !cfg.default_cwd.is_empty() && Path::new(&cfg.default_cwd).exists() {
            c.current_dir(&cfg.default_cwd);
        } else if let Some((_, home)) = current_user_passwd() {
            if !home.is_empty() && Path::new(&home).exists() {
                c.current_dir(home);
            }
        }
        c
    };

    if !session_alive() {
        send_ws_notice_bounded(&mut ws, "\r\n[登录会话或终端模块已关闭，连接已终止]\r\n").await;
        return;
    }

    let pty = match spawn_pty_command(cmd, cols, rows) {
        Ok(p) => p,
        Err(e) => {
            send_ws_notice_bounded(&mut ws, format!("启动 PTY 终端失败: {e}\r\n")).await;
            return;
        }
    };

    logger::log(
        Level::Info,
        "web_terminal",
        &format!("已建立 PTY 终端会话 (target={}, pgid={})", target, pty.pgid),
    );

    let idle_limit = Duration::from_secs(cfg.idle_timeout_secs.clamp(60, 3600));
    let idle_sleep = tokio::time::sleep(idle_limit);
    tokio::pin!(idle_sleep);
    let mut auth_ticker = tokio::time::interval(Duration::from_secs(2));
    auth_ticker.tick().await;
    let mut buf = vec![0u8; PTY_CHUNK_BYTES];
    let mut utf8_carry: Vec<u8> = Vec::with_capacity(4);

    loop {
        tokio::select! {
            biased;
            _ = wait_until_revoked(pty_mgr, &session_alive) => {
                send_ws_notice_bounded(&mut ws, "\r\n[登录会话或终端模块已关闭，连接已终止]\r\n").await;
                break;
            }
            _ = &mut idle_sleep => {
                send_ws_notice_bounded(&mut ws, "\r\n[会话空闲超时已自动断开]\r\n").await;
                break;
            }
            _ = auth_ticker.tick() => {
                if !session_alive() {
                    send_ws_notice_bounded(&mut ws, "\r\n[登录会话已失效，连接已终止]\r\n").await;
                    break;
                }
            }
            read_res = async {
                match pty.master.as_ref() {
                    Some(m) => read_pty_chunk(m, &mut buf).await,
                    None => Err(io::Error::new(io::ErrorKind::BrokenPipe, "PTY closed")),
                }
            } => {
                match read_res {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        idle_sleep.as_mut().reset(tokio::time::Instant::now() + idle_limit);
                        utf8_carry.extend_from_slice(&buf[..n]);
                        let valid_up_to = match std::str::from_utf8(&utf8_carry) {
                            Ok(_) => utf8_carry.len(),
                            Err(e) => {
                                if e.error_len().is_none() {
                                    e.valid_up_to()
                                } else {
                                    utf8_carry.len()
                                }
                            }
                        };
                        if valid_up_to > 0 {
                            let text = String::from_utf8_lossy(&utf8_carry[..valid_up_to]).into_owned();
                            utf8_carry.drain(..valid_up_to);
                            if !send_ws_bounded(&mut ws, Message::Text(text.into()), pty_mgr, &session_alive).await {
                                break;
                            }
                        }
                    }
                }
            }
            msg = ws.recv() => {
                match msg {
                    Some(Ok(Message::Text(txt))) => {
                        idle_sleep.as_mut().reset(tokio::time::Instant::now() + idle_limit);
                        if let Some((c, r)) = parse_resize_message(&txt) {
                            pty.resize(c, r);
                        } else if let Some(ref m) = pty.master {
                            if !write_pty_bounded(m, txt.as_bytes(), pty_mgr, &session_alive).await {
                                break;
                            }
                        }
                    }
                    Some(Ok(Message::Binary(bin))) => {
                        idle_sleep.as_mut().reset(tokio::time::Instant::now() + idle_limit);
                        if let Some(ref m) = pty.master {
                            if !write_pty_bounded(m, &bin, pty_mgr, &session_alive).await {
                                break;
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    _ => {}
                }
            }
        }
    }

    pty.terminate_and_reap().await;
    logger::log(Level::Info, "web_terminal", "Web 终端会话已关闭并完整回收进程组");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn real_openpty_streams_without_newline_and_reaps_process_group() {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "printf 'PROMPT> '; sleep 30 & read line; printf 'GOT:%s!' \"$line\""]);
        let pty = spawn_pty_command(cmd, 80, 24).unwrap();
        let pgid = pty.pgid;
        pty.resize(132, 40);

        let master = pty.master.as_ref().unwrap();
        let mut buf = [0u8; 256];
        let n = tokio::time::timeout(Duration::from_secs(2), read_pty_chunk(master, &mut buf))
            .await
            .unwrap()
            .unwrap();
        let out = String::from_utf8_lossy(&buf[..n]);
        assert!(out.contains("PROMPT> "), "expected unbuffered prompt, got {out:?}");

        write_pty_all(master, b"hello\r").await.unwrap();
        let mut collected = String::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while tokio::time::Instant::now() < deadline && !collected.contains("GOT:hello!") {
            if let Ok(Ok(k)) = tokio::time::timeout(Duration::from_millis(300), read_pty_chunk(master, &mut buf)).await {
                if k == 0 {
                    break;
                }
                collected.push_str(&String::from_utf8_lossy(&buf[..k]));
            }
        }
        assert!(collected.contains("GOT:hello!"), "collected={collected:?}");

        pty.terminate_and_reap().await;
        // 验证进程组（含后台 sleep 30 子孙进程）已被彻底杀死回收
        let alive = unsafe { libc::kill(-pgid, 0) == 0 };
        assert!(!alive, "process group {pgid} must be reaped");
    }

    #[test]
    fn bound_pty_ticket_rejects_wrong_target_or_peer_and_bad_container() {
        let mgr = PtyManager::new();
        let peer_a = BanKey::from_peer("192.168.1.20".parse().unwrap());
        let peer_b = BanKey::from_peer("192.168.1.21".parse().unwrap());
        assert!(mgr.issue_bound_ticket("sess1", "container:--privileged", peer_a, 2).is_err());

        let tok = mgr.issue_bound_ticket("sess1", "host", peer_a, 2).unwrap();
        assert!(mgr.consume_bound_ticket(&tok, "container:nginx", peer_a).is_none());
        let tok2 = mgr.issue_bound_ticket("sess1", "host", peer_a, 2).unwrap();
        assert!(mgr.consume_bound_ticket(&tok2, "host", peer_b).is_none());
        let tok3 = mgr.issue_bound_ticket("sess1", "host", peer_a, 2).unwrap();
        assert!(mgr.consume_bound_ticket(&tok3, "host", peer_a).is_some());
        assert!(mgr.consume_bound_ticket(&tok3, "host", peer_a).is_none());

        // 校验 shell 绑定与非法 shell 拦截
        assert!(mgr.issue_bound_ticket_with_shell("sess1", "host", "/bin/evil", peer_a, 2).is_err());
        let tok4 = mgr.issue_bound_ticket_with_shell("sess1", "host", "bash", peer_a, 2).unwrap();
        assert!(mgr.consume_bound_ticket_with_shell(&tok4, "host", "sh", peer_a).is_none());
        let tok5 = mgr.issue_bound_ticket_with_shell("sess1", "host", "sh", peer_a, 2).unwrap();
        assert!(mgr.consume_bound_ticket_with_shell(&tok5, "host", "sh", peer_a).is_some());
    }

    #[test]
    fn shell_detection_prefers_bash_over_sh_and_allows_override() {
        let both = vec![
            DetectedShell { id: "bash".into(), path: "/bin/bash".into() },
            DetectedShell { id: "sh".into(), path: "/bin/sh".into() },
        ];
        assert_eq!(default_shell_id("auto", &both), "bash");
        assert_eq!(default_shell_id("sh", &both), "sh");
        assert_eq!(default_shell_id("/bin/sh", &both), "sh");
        assert_eq!(default_shell_id("bash", &both), "bash");

        let only_sh = vec![DetectedShell { id: "sh".into(), path: "/bin/sh".into() }];
        assert_eq!(default_shell_id("auto", &only_sh), "sh");
        assert_eq!(default_shell_id("bash", &only_sh), "sh");

        let detected = detect_available_shells();
        assert!(!detected.is_empty(), "at least sh should exist on Unix host");
        if detected.iter().any(|s| s.id == "bash") {
            assert_eq!(detected[0].id, "bash");
            assert_eq!(default_shell_id("auto", &detected), "bash");
        }
        assert!(validate_shell_choice("bash").is_ok());
        assert!(validate_shell_choice("sh").is_ok());
        assert!(validate_shell_choice("auto").is_ok());
        assert!(validate_shell_choice("zsh").is_err());

        assert!(supports_login_flag("/bin/bash"));
        assert!(supports_login_flag("/bin/sh"));
        assert!(supports_login_flag("/bin/ash"));
        assert!(!supports_login_flag("/usr/bin/custom-tool"));

        let merged = build_merged_path(Some("/opt/bin:/usr/bin"));
        assert!(merged.starts_with("/opt/bin:/usr/bin:"));
        assert!(merged.contains("/usr/sbin"));
        assert!(merged.contains("/sbin"));
        assert_eq!(merged.matches("/usr/bin").count(), 1);
    }

    #[tokio::test]
    async fn host_shell_env_sets_shell_path_home_and_strips_master_key() {
        let shell = resolve_shell("auto", "sh").unwrap();
        let mut cmd = Command::new(&shell);
        cmd.env("VANE_MASTER_KEY", "should-never-leak");
        apply_host_shell_env(&mut cmd, &shell);
        cmd.args([
            "-c",
            "printf 'SHELL=%s;HOME=%s;PATH_HAS_SBIN=%s;MK=%s\\n' \"$SHELL\" \"$HOME\" \"$(printf %s \"$PATH\" | grep -c /sbin)\" \"${VANE_MASTER_KEY:-NONE}\"",
        ]);
        let pty = spawn_pty_command(cmd, 80, 24).unwrap();
        let master = pty.master.as_ref().unwrap();
        let mut buf = [0u8; 512];
        let mut out = String::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while tokio::time::Instant::now() < deadline && !out.contains("MK=NONE") {
            if let Ok(Ok(k)) = tokio::time::timeout(Duration::from_millis(300), read_pty_chunk(master, &mut buf)).await {
                if k == 0 {
                    break;
                }
                out.push_str(&String::from_utf8_lossy(&buf[..k]));
            }
        }
        pty.terminate_and_reap().await;
        assert!(out.contains(&format!("SHELL={shell}")), "out={out:?}");
        assert!(!out.contains("HOME=;"), "HOME must be populated: out={out:?}");
        assert!(out.contains("PATH_HAS_SBIN=1"), "PATH must include /sbin: out={out:?}");
        assert!(out.contains("MK=NONE"), "VANE_MASTER_KEY must be stripped: out={out:?}");
    }

    #[test]
    fn docker_socket_validation_accepts_only_real_non_symlink_unix_socket() {
        let pid = std::process::id();
        let sock_path = std::path::PathBuf::from(format!("/tmp/vane-pty-{pid}.sock"));
        let link_path = std::path::PathBuf::from(format!("/tmp/vane-pty-{pid}.link"));
        let file_path = std::path::PathBuf::from(format!("/tmp/vane-pty-{pid}.file"));
        let _ = std::fs::remove_file(&sock_path);
        let _ = std::fs::remove_file(&link_path);
        let _ = std::fs::remove_file(&file_path);

        let listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
        std::os::unix::fs::symlink(&sock_path, &link_path).unwrap();
        std::fs::write(&file_path, b"not a socket").unwrap();

        assert!(validate_docker_socket_path(sock_path.to_str().unwrap()).is_ok());

        // 符号链接、普通文件、目录、路径穿越与不存在路径统一拒绝且报错文案一致
        let err_symlink = validate_docker_socket_path(link_path.to_str().unwrap()).unwrap_err();
        let err_file = validate_docker_socket_path(file_path.to_str().unwrap()).unwrap_err();
        let err_dir = validate_docker_socket_path("/tmp").unwrap_err();
        let err_missing = validate_docker_socket_path("/tmp/vane-nonexistent-999999.sock").unwrap_err();
        let err_traversal = validate_docker_socket_path("/tmp/../tmp/vane.sock").unwrap_err();
        let err_relative = validate_docker_socket_path("var/run/docker.sock").unwrap_err();
        assert_eq!(err_symlink, err_file);
        assert_eq!(err_file, err_dir);
        assert_eq!(err_dir, err_missing);
        assert_eq!(err_missing, err_traversal);
        assert_eq!(err_traversal, err_relative);

        drop(listener);
        let _ = std::fs::remove_file(&sock_path);
        let _ = std::fs::remove_file(&link_path);
        let _ = std::fs::remove_file(&file_path);
    }

    #[tokio::test]
    async fn wait_until_revoked_ignores_spurious_notify_and_wakes_immediately_on_revoke() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let mgr = Arc::new(PtyManager::new());
        let alive = Arc::new(AtomicBool::new(true));

        let mgr_w = mgr.clone();
        let alive_w = alive.clone();
        let waiter = tokio::spawn(async move {
            wait_until_revoked(&mgr_w, &move || alive_w.load(Ordering::SeqCst)).await;
        });

        tokio::task::yield_now().await;
        // 虚假通知（其他会话被撤销但本会话仍存活）不得提前中断
        mgr.notify_revoke();
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!waiter.is_finished(), "spurious revoke_notify must not cancel live session");

        // 本会话被标记失效并通知后应立即唤醒
        alive.store(false, Ordering::SeqCst);
        mgr.notify_revoke();
        tokio::time::timeout(Duration::from_millis(500), waiter)
            .await
            .expect("revoked session must wake immediately")
            .unwrap();
    }
}
