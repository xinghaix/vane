//! 轻量 5/6 段 Cron 表达式解析器（秒 分 时 日 月 周）、未来运行时间精确预览、
//! 任务级互斥锁（防重入叠加）、全动作真实执行器与独立进程组超时 SIGKILL 回收。
use crate::config::{Config, CronAction, CronConfig};
use crate::daemon::notify::broadcast_event;
use crate::docker::unix_client::{container_action, prune_images};
use crate::logger::{self, breakdown, Level};
use crate::net::http_client::{shared as http_shared, HttpRequest};
use crate::security::vault::Vault;
use serde::Serialize;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

#[derive(Clone, Debug, Default, Serialize)]
pub struct CronJobStatus {
    pub name: String,
    pub last_run_unix: u64,
    pub last_duration_ms: u64,
    pub status: String,
    pub last_output: String,
    pub running: bool,
}

#[derive(Default)]
pub struct CronRuntime {
    statuses: RwLock<BTreeMap<String, CronJobStatus>>,
    locks: Mutex<BTreeMap<String, Weak<tokio::sync::Mutex<()>>>>,
}

impl CronRuntime {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn snapshot(&self) -> Vec<CronJobStatus> {
        self.statuses
            .read()
            .map(|g| g.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn retain_configured(&self, jobs: &[CronConfig]) {
        if let Ok(mut g) = self.statuses.write() {
            g.retain(|k, _| jobs.iter().any(|j| &j.name == k));
        }
    }

    fn job_lock(&self, name: &str) -> Result<Arc<tokio::sync::Mutex<()>>, String> {
        let mut locks = self.locks.lock().map_err(|_| "Cron 互斥表损坏")?;
        locks.retain(|_, w| w.strong_count() > 0);
        if let Some(existing) = locks.get(name).and_then(Weak::upgrade) {
            return Ok(existing);
        }
        if locks.len() >= 256 {
            return Err("Cron 并发锁数量超限".into());
        }
        let m = Arc::new(tokio::sync::Mutex::new(()));
        locks.insert(name.to_string(), Arc::downgrade(&m));
        Ok(m)
    }

    fn set_running(&self, name: &str, running: bool) {
        if let Ok(mut g) = self.statuses.write() {
            let entry = g.entry(name.to_string()).or_insert_with(|| CronJobStatus {
                name: name.to_string(),
                status: "idle".into(),
                ..Default::default()
            });
            entry.running = running;
        }
    }

    fn record_finish(&self, name: &str, duration_ms: u64, res: &Result<String, String>) {
        if let Ok(mut g) = self.statuses.write() {
            let (status, out) = match res {
                Ok(msg) => ("ok".to_string(), logger::truncate_utf8(msg.trim(), 512)),
                Err(err) => ("failed".to_string(), logger::truncate_utf8(err.trim(), 512)),
            };
            g.insert(
                name.to_string(),
                CronJobStatus {
                    name: name.to_string(),
                    last_run_unix: logger::unix_now(),
                    last_duration_ms: duration_ms,
                    status,
                    last_output: out,
                    running: false,
                },
            );
        }
    }
}

pub type RuleToggleFn =
    Arc<dyn Fn(String, String, bool) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send>> + Send + Sync>;

#[derive(Clone)]
pub struct CronExecutionContext {
    pub config: Arc<Config>,
    pub vault: Arc<Vault>,
    pub runtime: Arc<CronRuntime>,
    pub rule_toggler: Option<RuleToggleFn>,
}

#[derive(Clone, Debug)]
pub struct CronSchedule {
    seconds: u64,       // 0..60 bitmask
    minutes: u64,       // 0..60 bitmask
    hours: u32,         // 0..24 bitmask
    days_of_month: u32, // 1..=31 bitmask
    months: u16,        // 1..=12 bitmask
    days_of_week: u8,   // 0..=6 bitmask
}

impl CronSchedule {
    /// 解析 6 段（秒 分 时 日 月 周）或 5 段（默认 0 秒）Cron 表达式
    pub fn parse(expr: &str) -> Result<Self, String> {
        let parts: Vec<&str> = expr.split_whitespace().collect();
        let (sec_s, min_s, hour_s, dom_s, mon_s, dow_s) = match parts.len() {
            6 => (parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]),
            5 => ("0", parts[0], parts[1], parts[2], parts[3], parts[4]),
            _ => return Err("Cron 表达式需为 5 段（分 时 日 月 周）或 6 段（秒 分 时 日 月 周）".into()),
        };
        Ok(Self {
            seconds: parse_field_u64(sec_s, 0, 59)?,
            minutes: parse_field_u64(min_s, 0, 59)?,
            hours: parse_field_u64(hour_s, 0, 23)? as u32,
            days_of_month: parse_field_u64(dom_s, 1, 31)? as u32,
            months: parse_field_u64(mon_s, 1, 12)? as u16,
            days_of_week: parse_field_u64(dow_s, 0, 6)? as u8,
        })
    }

    pub fn matches(&self, unix_secs: u64, tz_offset_secs: i64) -> bool {
        let dt = breakdown(unix_secs as i64, tz_offset_secs);
        (self.seconds & (1u64 << dt.second)) != 0
            && (self.minutes & (1u64 << dt.minute)) != 0
            && (self.hours & (1u32 << dt.hour)) != 0
            && (self.days_of_month & (1u32 << dt.day)) != 0
            && (self.months & (1u16 << dt.month)) != 0
            && (self.days_of_week & (1u8 << dt.weekday)) != 0
    }

    /// 计算从 from_unix 之后最近的 count 次触发时间戳（最长向前扫描 366 天，精准兼容半小时时区与月度任务）
    pub fn next_runs(&self, from_unix: u64, tz_offset_secs: i64, count: usize) -> Vec<u64> {
        let count = count.clamp(1, 10);
        let mut out = Vec::with_capacity(count);
        let mut t = from_unix.saturating_add(1);
        let limit = from_unix.saturating_add(366 * 86_400);
        while t <= limit && out.len() < count {
            let dt = breakdown(t as i64, tz_offset_secs);
            if (self.months & (1u16 << dt.month)) == 0
                || (self.days_of_month & (1u32 << dt.day)) == 0
                || (self.days_of_week & (1u8 << dt.weekday)) == 0
            {
                let rem_day = (24 - dt.hour as u64) * 3600 - (dt.minute as u64) * 60 - (dt.second as u64);
                t = t.saturating_add(rem_day.max(1));
                continue;
            }
            if (self.hours & (1u32 << dt.hour)) == 0 {
                let rem_hour = (60 - dt.minute as u64) * 60 - (dt.second as u64);
                t = t.saturating_add(rem_hour.max(1));
                continue;
            }
            if (self.minutes & (1u64 << dt.minute)) == 0 {
                let rem_min = 60 - (dt.second as u64);
                t = t.saturating_add(rem_min.max(1));
                continue;
            }
            if (self.seconds & (1u64 << dt.second)) != 0 {
                out.push(t);
            }
            t = t.saturating_add(1);
        }
        out
    }
}

/// 生成不漏秒、不重复触发的秒级评估窗口（最多回补最近 5 秒以容忍轻微调度抖动）
pub fn due_seconds_window(last_tick: &mut Option<u64>, now_unix: u64) -> std::ops::RangeInclusive<u64> {
    match *last_tick {
        None => {
            *last_tick = Some(now_unix);
            now_unix..=now_unix
        }
        Some(prev) if now_unix <= prev => {
            // 同一秒内或时钟微幅回拨：返回空区间 (1..=0) 避免重复触发
            1..=0
        }
        Some(prev) => {
            let start = (prev + 1).max(now_unix.saturating_sub(5));
            *last_tick = Some(now_unix);
            start..=now_unix
        }
    }
}

fn parse_field_u64(s: &str, min: u32, max: u32) -> Result<u64, String> {
    let mut mask = 0u64;
    for part in s.split(',') {
        let (range_part, step) = if let Some((r, st)) = part.split_once('/') {
            let st_v: u32 = st.parse().map_err(|_| format!("非法步长: {}", part))?;
            if st_v == 0 {
                return Err("步长不能为 0".into());
            }
            (r, st_v)
        } else {
            (part, 1)
        };
        let (lo, hi) = if range_part == "*" {
            (min, max)
        } else if let Some((a, b)) = range_part.split_once('-') {
            let av: u32 = a.parse().map_err(|_| format!("非法范围: {}", part))?;
            let bv: u32 = b.parse().map_err(|_| format!("非法范围: {}", part))?;
            if av < min || bv > max || av > bv {
                return Err(format!("数值超出范围 {}..={}: {}", min, max, part));
            }
            (av, bv)
        } else {
            let v: u32 = range_part.parse().map_err(|_| format!("非法数值: {}", part))?;
            let v = if max == 6 && v == 7 { 0 } else { v };
            if v < min || v > max {
                return Err(format!("数值超出范围 {}..={}: {}", min, max, part));
            }
            (v, v)
        };
        let mut v = lo;
        while v <= hi {
            mask |= 1u64 << v;
            v += step;
        }
    }
    if mask == 0 {
        return Err("Cron 字段为空".into());
    }
    Ok(mask)
}

async fn run_exec_isolated(job_name: &str, program: &str, args: &[String], cwd: &str, timeout: Duration) -> Result<String, String> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true);
    if !cwd.is_empty() {
        cmd.current_dir(cwd);
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("启动外部程序 {} 失败: {}", program, e))?;
    let pgid = child.id().unwrap_or(0) as i32;

    let io_fut = async {
        let mut out_buf = Vec::new();
        let mut err_buf = Vec::new();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let r_out = async {
            if let Some(s) = stdout {
                let _ = s.take(64 * 1024).read_to_end(&mut out_buf).await;
            }
        };
        let r_err = async {
            if let Some(s) = stderr {
                let _ = s.take(16 * 1024).read_to_end(&mut err_buf).await;
            }
        };
        tokio::join!(r_out, r_err);
        let st = child.wait().await.map_err(|e| format!("等待子进程退出失败: {}", e))?;
        Ok::<_, String>((st, out_buf, err_buf))
    };

    match tokio::time::timeout(timeout, io_fut).await {
        Ok(Ok((status, out_buf, err_buf))) => {
            if pgid > 1 {
                // 确保后台脱离标准输出的子孙进程也被清理
                unsafe {
                    let _ = libc::kill(-pgid, libc::SIGKILL);
                }
            }
            let stdout = logger::truncate_utf8(&String::from_utf8_lossy(&out_buf), 512);
            if status.success() {
                logger::log(Level::Info, "cron", &format!("任务 {} 执行成功: {}", job_name, stdout.trim()));
                Ok(stdout)
            } else {
                let stderr = logger::truncate_utf8(&String::from_utf8_lossy(&err_buf), 512);
                Err(format!("退出码 {:?}: {}", status.code(), stderr.trim()))
            }
        }
        Ok(Err(e)) => {
            if pgid > 1 {
                unsafe {
                    let _ = libc::kill(-pgid, libc::SIGKILL);
                }
            }
            let _ = child.kill().await;
            let _ = child.wait().await;
            Err(e)
        }
        Err(_) => {
            if pgid > 1 {
                unsafe {
                    let _ = libc::kill(-pgid, libc::SIGKILL);
                }
            }
            let _ = child.kill().await;
            let _ = child.wait().await;
            Err(format!("任务 {} 超时 ({}s) 已强制终止整个进程组", job_name, timeout.as_secs()))
        }
    }
}

/// 携带完整网关上下文执行单次计划任务（含任务级非重入锁、五类真实动作与失败告警通知）
pub async fn execute_cron_job_with_ctx(job: &CronConfig, ctx: Option<&CronExecutionContext>) -> Result<String, String> {
    let lock_guard = if let Some(c) = ctx {
        let lock = c.runtime.job_lock(&job.name)?;
        match lock.try_lock_owned() {
            Ok(g) => {
                c.runtime.set_running(&job.name, true);
                Some((c.runtime.clone(), g))
            }
            Err(_) => {
                return Err(format!("任务 {} 上一轮仍在运行中，已跳过本次重入执行", job.name));
            }
        }
    } else {
        None
    };

    let started = std::time::Instant::now();
    let timeout = Duration::from_secs(job.timeout_secs.clamp(1, 86_400));

    let res: Result<String, String> = match &job.action {
        CronAction::DockerPruneImages { dangling_only } => {
            let Some(c) = ctx else {
                return Err("缺少 Docker 运行上下文".into());
            };
            if !c.config.modules.docker {
                Err("Docker 模块已关闭，无法执行镜像清理".into())
            } else {
                tokio::time::timeout(timeout, prune_images(&c.config.admin.docker_socket, *dangling_only))
                    .await
                    .map_err(|_| format!("任务 {} 清理镜像超时", job.name))?
                    .map(|raw| {
                        let msg = format!("Docker 镜像清理完成 (dangling_only={}): {}", dangling_only, logger::truncate_utf8(&raw, 240));
                        logger::log(Level::Info, "cron", &msg);
                        msg
                    })
            }
        }
        CronAction::DockerRestartContainer { container } => {
            let Some(c) = ctx else {
                return Err("缺少 Docker 运行上下文".into());
            };
            if !c.config.modules.docker {
                Err("Docker 模块已关闭，无法重启容器".into())
            } else {
                tokio::time::timeout(
                    timeout,
                    container_action(&c.config.admin.docker_socket, &c.config.docker, container, "restart"),
                )
                .await
                .map_err(|_| format!("任务 {} 重启容器 {} 超时", job.name, container))??;
                let msg = format!("已成功重启容器 {}", container);
                logger::log(Level::Info, "cron", &msg);
                Ok(msg)
            }
        }
        CronAction::RuleToggle {
            target_kind,
            rule,
            enable,
        } => {
            let Some(toggler) = ctx.and_then(|c| c.rule_toggler.as_ref()) else {
                return Err("缺少规则状态切换器上下文".into());
            };
            let msg = toggler(target_kind.clone(), rule.clone(), *enable).await?;
            logger::log(Level::Info, "cron", &msg);
            Ok(msg)
        }
        CronAction::HttpRequest {
            method,
            url,
            headers,
            body,
        } => {
            let (plain_url, plain_body, plain_headers) = if let Some(c) = ctx {
                let u = c.vault.reveal_string(&format!("cron.{}.action.url", job.name), url)?;
                let b = c.vault.reveal_string(&format!("cron.{}.action.body", job.name), body)?;
                let mut h = BTreeMap::new();
                for (k, v) in headers {
                    h.insert(
                        k.clone(),
                        c.vault
                            .reveal_string(&format!("cron.{}.action.headers.{}", job.name, k), v)?,
                    );
                }
                (u, b, h)
            } else {
                (url.clone(), body.clone(), headers.clone())
            };
            let m = if method.trim().is_empty() { "GET" } else { method.trim() };
            let mut req = HttpRequest::new(m, &plain_url);
            req.headers = plain_headers;
            req.body = plain_body.into_bytes();
            req.response_limit = 64 * 1024;
            req.timeout = timeout.min(Duration::from_secs(60));
            let resp = tokio::time::timeout(timeout, http_shared().execute(req))
                .await
                .map_err(|_| format!("定时 HTTP 请求 {} 超时", job.name))??;
            resp.ensure_success()?;
            let snippet = logger::truncate_utf8(&String::from_utf8_lossy(&resp.body), 200);
            let msg = format!("HTTP {} -> {} ({})", m, resp.status, snippet.trim());
            logger::log(Level::Info, "cron", &format!("任务 {} 完成: {}", job.name, msg));
            Ok(msg)
        }
        CronAction::Exec { program, args, cwd } => {
            run_exec_isolated(&job.name, program, args, cwd, timeout).await
        }
    };

    let elapsed_ms = started.elapsed().as_millis() as u64;
    if let Some((rt, _guard)) = lock_guard {
        rt.record_finish(&job.name, elapsed_ms, &res);
    }

    if let (Err(ref err), Some(c)) = (&res, ctx) {
        logger::log(Level::Warn, "cron", &format!("计划任务 {} 执行失败: {}", job.name, err));
        if job.notify_on_failure {
            broadcast_event(
                &c.config,
                &c.vault,
                "cron_failure",
                &format!("Vane 计划任务失败: {}", job.name),
                err,
                "warning",
            )
            .await;
        }
    }

    res
}

/// 无状态执行入口（用于纯外部命令测试）
pub async fn execute_cron_job(job: &CronConfig) -> Result<String, String> {
    execute_cron_job_with_ctx(job, None).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn cron_parser_next_runs_and_half_hour_tz_work() {
        let s = CronSchedule::parse("0 */30 * * * *").unwrap();
        let next = s.next_runs(1_700_000_000, 0, 3);
        assert_eq!(next.len(), 3);
        assert_eq!(next[1] - next[0], 1800);
        for ts in &next {
            assert!(s.matches(*ts, 0));
        }

        // 月度任务（跨超过 7 天）与 +05:30 半小时时区均能精确算出下次运行时间
        let monthly = CronSchedule::parse("0 15 3 1 * *").unwrap();
        let m_runs = monthly.next_runs(1_700_000_000, 5 * 3600 + 1800, 2);
        assert_eq!(m_runs.len(), 2);
        for ts in &m_runs {
            assert!(monthly.matches(*ts, 5 * 3600 + 1800));
        }
        assert!(CronSchedule::parse("invalid cron").is_err());
    }

    #[test]
    fn due_seconds_window_prevents_duplicates_and_recovers_jitter() {
        let mut last = None;
        assert_eq!(due_seconds_window(&mut last, 100).collect::<Vec<_>>(), vec![100]);
        assert!(due_seconds_window(&mut last, 100).collect::<Vec<_>>().is_empty());
        assert_eq!(due_seconds_window(&mut last, 102).collect::<Vec<_>>(), vec![101, 102]);
    }

    #[tokio::test]
    async fn exec_timeout_kills_descendant_process_group_and_prevents_overlap() {
        let job = CronConfig {
            name: "slow_tree".into(),
            enabled: true,
            schedule: "0 * * * * *".into(),
            timeout_secs: 1,
            action: CronAction::Exec {
                program: "/bin/sh".into(),
                args: vec!["-c".into(), "sleep 30 & wait".into()],
                cwd: String::new(),
            },
            notify_on_failure: false,
        };
        let err = execute_cron_job(&job).await.unwrap_err();
        assert!(err.contains("超时"));
    }

    #[tokio::test]
    async fn cron_http_request_decrypts_vault_and_validates_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let n = sock.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            assert!(req.contains("x-cron-token: secret-123"));
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong")
                .await
                .unwrap();
        });

        let vault = Arc::new(Vault::from_master(&[9u8; 32]));
        let mut headers = BTreeMap::new();
        headers.insert(
            "x-cron-token".into(),
            vault.seal("cron.ping_job.action.headers.x-cron-token", b"secret-123").unwrap(),
        );
        let job = CronConfig {
            name: "ping_job".into(),
            enabled: true,
            schedule: "0 * * * * *".into(),
            timeout_secs: 5,
            action: CronAction::HttpRequest {
                method: "POST".into(),
                url: vault
                    .seal("cron.ping_job.action.url", format!("http://{}/ping", addr).as_bytes())
                    .unwrap(),
                headers,
                body: String::new(),
            },
            notify_on_failure: false,
        };
        let ctx = CronExecutionContext {
            config: Arc::new(Config::default()),
            vault,
            runtime: CronRuntime::new(),
            rule_toggler: None,
        };
        let out = execute_cron_job_with_ctx(&job, Some(&ctx)).await.unwrap();
        assert!(out.contains("200"));
        assert_eq!(ctx.runtime.snapshot()[0].status, "ok");
        srv.await.unwrap();
    }
}
