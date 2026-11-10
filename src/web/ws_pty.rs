//! Web 终端子系统（默认关闭 modules.web_terminal = false，可在设置页按需打开）：
//! 支持一次性 WS Ticket 鉴权、宿主机 Shell / Docker 容器终端执行、空闲超时与进程组回收。
use crate::config::WebTerminalConfig;
use crate::logger::{self, Level};
use axum::extract::ws::{Message, WebSocket};
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

const TICKET_TTL: Duration = Duration::from_secs(30);

pub struct PtyManager {
    tickets: Mutex<HashMap<String, Instant>>,
    active_sessions: AtomicUsize,
}

impl Default for PtyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PtyManager {
    pub fn new() -> Self {
        Self {
            tickets: Mutex::new(HashMap::new()),
            active_sessions: AtomicUsize::new(0),
        }
    }

    pub fn issue_ticket(&self, max_sessions: usize) -> Result<String, &'static str> {
        if self.active_sessions.load(Ordering::SeqCst) >= max_sessions.clamp(1, 4) {
            return Err("已达到最大并发 Web 终端会话数上限");
        }
        let mut raw = [0u8; 24];
        SystemRandom::new().fill(&mut raw).map_err(|_| "随机源失败")?;
        let ticket: String = raw.iter().map(|b| format!("{:02x}", b)).collect();
        if let Ok(mut map) = self.tickets.lock() {
            map.retain(|_, t| t.elapsed() <= TICKET_TTL);
            map.insert(ticket.clone(), Instant::now());
        }
        Ok(ticket)
    }

    pub fn consume_ticket(&self, ticket: &str) -> bool {
        let Ok(mut map) = self.tickets.lock() else { return false };
        map.retain(|_, t| t.elapsed() <= TICKET_TTL);
        map.remove(ticket).is_some()
    }

    pub fn active_count(&self) -> usize {
        self.active_sessions.load(Ordering::SeqCst)
    }
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

pub async fn handle_pty_websocket(
    mut ws: WebSocket,
    pty_mgr: &PtyManager,
    cfg: WebTerminalConfig,
    target: String,
) {
    let prev = pty_mgr.active_sessions.fetch_add(1, Ordering::SeqCst);
    if prev >= cfg.max_sessions.clamp(1, 4) {
        pty_mgr.active_sessions.fetch_sub(1, Ordering::SeqCst);
        let _ = ws.send(Message::Text("ERROR: 已达到最大终端并发会话数\r\n".into())).await;
        return;
    }

    let shell = resolve_shell(&cfg.shell);
    logger::log(Level::Info, "web_terminal", &format!("已打开 Web 终端会话 (target={}, shell={})", target, shell));

    let mut cmd = if let Some(container) = target.strip_prefix("container:") {
        let mut c = Command::new("docker");
        c.args(["exec", "-i", container, "/bin/sh"]);
        c
    } else {
        let mut c = Command::new(&shell);
        if Path::new(&cfg.default_cwd).exists() {
            c.current_dir(&cfg.default_cwd);
        }
        c
    };
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = ws.send(Message::Text(format!("启动终端失败: {}\r\n", e).into())).await;
            pty_mgr.active_sessions.fetch_sub(1, Ordering::SeqCst);
            return;
        }
    };

    let mut stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<String>(64);

    if let Some(out) = stdout {
        let tx = out_tx.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(out).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if tx.send(format!("{}\r\n", line)).await.is_err() {
                    break;
                }
            }
        });
    }
    if let Some(err) = stderr {
        let tx = out_tx.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(err).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if tx.send(format!("{}\r\n", line)).await.is_err() {
                    break;
                }
            }
        });
    }

    let _ = ws
        .send(Message::Text(format!("Connected to Vane Web Terminal ({})\r\n$ ", shell).into()))
        .await;
    let idle_limit = Duration::from_secs(cfg.idle_timeout_secs.clamp(60, 3600));

    loop {
        tokio::select! {
            _ = tokio::time::sleep(idle_limit) => {
                let _ = ws.send(Message::Text("\r\n[会话空闲超时已自动断开]\r\n".into())).await;
                break;
            }
            Some(chunk) = out_rx.recv() => {
                if ws.send(Message::Text(chunk.into())).await.is_err() {
                    break;
                }
            }
            msg = ws.recv() => {
                match msg {
                    Some(Ok(Message::Text(txt))) => {
                        if let Some(ref mut sin) = stdin {
                            let mut s = txt.to_string();
                            if !s.ends_with('\n') {
                                s.push('\n');
                            }
                            let _ = sin.write_all(s.as_bytes()).await;
                            let _ = sin.flush().await;
                        }
                    }
                    Some(Ok(Message::Binary(bin))) => {
                        if let Some(ref mut sin) = stdin {
                            let _ = sin.write_all(&bin).await;
                            let _ = sin.flush().await;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    _ => {}
                }
            }
        }
    }

    let _ = child.kill().await;
    let _ = child.wait().await;
    pty_mgr.active_sessions.fetch_sub(1, Ordering::SeqCst);
    logger::log(Level::Info, "web_terminal", "Web 终端会话已关闭并回收子进程");
}
