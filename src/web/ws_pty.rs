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
use serde::Deserialize;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::sync::Notify;

const PTY_CHUNK_BYTES: usize = 16 * 1024;
const RESIZE_PREFIX: &str = "\u{0}resize:";

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
        if self.active_sessions.load(Ordering::SeqCst) >= max_sessions.clamp(1, 4) {
            return Err("已达到最大并发 Web 终端会话数上限".into());
        }
        validate_pty_target(target)?;
        self.tickets.issue(session_token, format!("pty:{target}"), peer)
    }

    pub fn consume_bound_ticket(&self, ticket: &str, target: &str, peer: BanKey) -> Option<[u8; 32]> {
        self.tickets.consume(ticket, &format!("pty:{target}"), peer)
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

fn resolve_shell(pref: &str) -> String {
    if pref != "auto" && Path::new(pref).exists() {
        return pref.to_string();
    }
    for s in ["/bin/ash", "/bin/bash", "/bin/sh"] {
        if Path::new(s).exists() {
            return s.to_string();
        }
    }
    "/bin/sh".to_string()
}

pub struct PtyProcess {
    pub master: AsyncFd<File>,
    pub child: Child,
    pub pgid: i32,
}

impl PtyProcess {
    pub fn resize(&self, cols: u16, rows: u16) {
        let wsz = libc::winsize {
            ws_row: rows.clamp(10, 300),
            ws_col: cols.clamp(20, 500),
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: master 为有效打开的 PTY 主设备文件描述符。
        unsafe {
            let _ = libc::ioctl(self.master.as_raw_fd(), libc::TIOCSWINSZ, &wsz);
        }
    }

    pub async fn terminate_and_reap(mut self) {
        let pgid = self.pgid;
        drop(self.master);
        tokio::task::spawn_blocking(move || {
            if pgid > 1 {
                // SAFETY: 子进程通过 setsid 成为独立会话与进程组长，负号向整组发送信号。
                unsafe {
                    let _ = libc::kill(-pgid, libc::SIGHUP);
                }
            }
            for _ in 0..15 {
                if let Ok(Some(_)) = self.child.try_wait() {
                    if pgid > 1 {
                        unsafe {
                            let _ = libc::kill(-pgid, libc::SIGKILL);
                        }
                    }
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            if pgid > 1 {
                unsafe {
                    let _ = libc::kill(-pgid, libc::SIGKILL);
                }
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
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
    let tty_fd = slave_in.as_raw_fd();

    cmd.stdin(Stdio::from(slave_in))
        .stdout(Stdio::from(slave_out))
        .stderr(Stdio::from(slave_err))
        .env("TERM", "xterm-256color");

    // SAFETY: pre_exec 仅调用 async-signal-safe 的 setsid 与 ioctl(TIOCSCTTY)。
    unsafe {
        cmd.pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            let _ = libc::ioctl(tty_fd, libc::TIOCSCTTY as _, 0);
            Ok(())
        });
    }

    let child = cmd.spawn().map_err(|e| format!("启动终端子进程失败: {e}"))?;
    let pgid = child.id() as i32;
    let master_file = File::from(master_owned);
    #[allow(deprecated)]
    let async_master = AsyncFd::new(master_file).map_err(|e| format!("注册异步 PTY FD 失败: {e}"))?;
    Ok(PtyProcess {
        master: async_master,
        child,
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
    cols: u16,
    rows: u16,
    session_alive: F,
) where
    F: Fn() -> bool + Send + Sync + 'static,
{
    let prev = pty_mgr.active_sessions.fetch_add(1, Ordering::SeqCst);
    let _slot_guard = SessionSlotGuard(pty_mgr);
    if prev >= cfg.max_sessions.clamp(1, 4) {
        let _ = ws.send(Message::Text("ERROR: 已达到最大终端并发会话数\r\n".into())).await;
        return;
    }

    if let Err(e) = validate_pty_target(&target) {
        let _ = ws.send(Message::Text(format!("ERROR: {e}\r\n").into())).await;
        return;
    }

    let cmd = if let Some(container) = target.strip_prefix("container:") {
        if let Err(e) = ensure_not_protected(&docker_socket, &docker_cfg, container, "exec").await {
            let _ = ws.send(Message::Text(format!("ERROR: {e}\r\n").into())).await;
            return;
        }
        let mut c = Command::new("docker");
        c.args(["exec", "-it", "--", container, "/bin/sh"]);
        c
    } else {
        let shell = resolve_shell(&cfg.shell);
        let mut c = Command::new(&shell);
        if !cfg.default_cwd.is_empty() && Path::new(&cfg.default_cwd).exists() {
            c.current_dir(&cfg.default_cwd);
        }
        c
    };

    let pty = match spawn_pty_command(cmd, cols, rows) {
        Ok(p) => p,
        Err(e) => {
            let _ = ws.send(Message::Text(format!("启动 PTY 终端失败: {e}\r\n").into())).await;
            return;
        }
    };

    logger::log(
        Level::Info,
        "web_terminal",
        &format!("已建立 PTY 终端会话 (target={}, pgid={})", target, pty.pgid),
    );

    let idle_limit = Duration::from_secs(cfg.idle_timeout_secs.clamp(60, 3600));
    let mut auth_ticker = tokio::time::interval(Duration::from_secs(2));
    auth_ticker.tick().await;
    let mut buf = vec![0u8; PTY_CHUNK_BYTES];
    let mut utf8_carry: Vec<u8> = Vec::with_capacity(4);

    loop {
        tokio::select! {
            _ = tokio::time::sleep(idle_limit) => {
                let _ = ws.send(Message::Text("\r\n[会话空闲超时已自动断开]\r\n".into())).await;
                break;
            }
            _ = pty_mgr.revoke_notify.notified() => {
                if !session_alive() {
                    let _ = ws.send(Message::Text("\r\n[登录会话或终端模块已关闭，连接已终止]\r\n".into())).await;
                    break;
                }
            }
            _ = auth_ticker.tick() => {
                if !session_alive() {
                    let _ = ws.send(Message::Text("\r\n[登录会话已失效，连接已终止]\r\n".into())).await;
                    break;
                }
            }
            read_res = read_pty_chunk(&pty.master, &mut buf) => {
                match read_res {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
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
                            if ws.send(Message::Text(text.into())).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
            msg = ws.recv() => {
                match msg {
                    Some(Ok(Message::Text(txt))) => {
                        if let Some((c, r)) = parse_resize_message(&txt) {
                            pty.resize(c, r);
                        } else if write_pty_all(&pty.master, txt.as_bytes()).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Binary(bin))) => {
                        if write_pty_all(&pty.master, &bin).await.is_err() {
                            break;
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

        let mut buf = [0u8; 256];
        let n = tokio::time::timeout(Duration::from_secs(2), read_pty_chunk(&pty.master, &mut buf))
            .await
            .unwrap()
            .unwrap();
        let out = String::from_utf8_lossy(&buf[..n]);
        assert!(out.contains("PROMPT> "), "expected unbuffered prompt, got {out:?}");

        write_pty_all(&pty.master, b"hello\r").await.unwrap();
        let mut collected = String::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while tokio::time::Instant::now() < deadline && !collected.contains("GOT:hello!") {
            if let Ok(Ok(k)) = tokio::time::timeout(Duration::from_millis(300), read_pty_chunk(&pty.master, &mut buf)).await {
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
    }
}
