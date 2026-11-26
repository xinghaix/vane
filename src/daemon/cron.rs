//! 轻量 5/6 段 Cron 表达式解析器（秒 分 时 日 月 周）、未来运行时间精确预览、
//! 任务级互斥锁（防重入叠加）、实时配置感知、即时取消、全动作真实执行器与
//! `waitid(WNOWAIT)` + 独立进程组 SIGKILL 无竞态回收。
use crate::config::{encode_secret_segment, Config, CronAction, CronConfig};
use crate::daemon::notify::broadcast_event;
use crate::docker::unix_client::{container_action, prune_images};
use crate::logger::{self, breakdown, Level};
use crate::net::http_client::{shared as http_shared, HttpRequest};
use crate::security::vault::Vault;
use arc_swap::ArcSwap;
use serde::Serialize;
use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio_util::sync::CancellationToken;

const SAFE_EXEC_PATH: &str = "/usr/sbin:/sbin:/usr/bin:/bin";

#[derive(Clone, Debug, Default, Serialize)]
pub struct CronJobStatus {
    pub name: String,
    pub last_run_unix: u64,
    pub last_duration_ms: u64,
    pub status: String,
    pub last_output: String,
    pub running: bool,
}

pub struct CronRuntime {
    statuses: RwLock<BTreeMap<String, CronJobStatus>>,
    locks: Mutex<BTreeMap<String, Weak<tokio::sync::Mutex<()>>>>,
    live_config: RwLock<Option<Arc<ArcSwap<Config>>>>,
    cancel_token: Mutex<CancellationToken>,
}

impl Default for CronRuntime {
    fn default() -> Self {
        Self {
            statuses: RwLock::new(BTreeMap::new()),
            locks: Mutex::new(BTreeMap::new()),
            live_config: RwLock::new(None),
            cancel_token: Mutex::new(CancellationToken::new()),
        }
    }
}

impl CronRuntime {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// 绑定实时共享配置句柄，使计划任务在执行期始终读取最新的模块开关与安全策略（如 `modules.docker`、`admin.allow_cron_exec`）
    pub fn set_live_config(&self, live: Arc<ArcSwap<Config>>) {
        if let Ok(mut g) = self.live_config.write() {
            *g = Some(live);
        }
    }

    pub fn live_config(&self) -> Option<Arc<ArcSwap<Config>>> {
        self.live_config.read().ok().and_then(|g| g.clone())
    }

    /// 获取当前世代的子取消令牌；调用 `cancel_all()` 时会立即取消所有已派发的子令牌
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token
            .lock()
            .map(|g| g.child_token())
            .unwrap_or_else(|e| e.into_inner().child_token())
    }

    /// 立即取消所有运行中的计划任务并轮换新的世代令牌（供模块禁用/热重载/停机调用）
    pub fn cancel_all(&self) {
        let prev = match self.cancel_token.lock() {
            Ok(mut g) => std::mem::replace(&mut *g, CancellationToken::new()),
            Err(e) => std::mem::replace(&mut *e.into_inner(), CancellationToken::new()),
        };
        prev.cancel();
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

impl CronExecutionContext {
    /// 获取当前最新配置（若 `runtime` 已绑定 `ArcSwap<Config>` 则动态加载实时快照，否则回退到静态快照）
    pub fn current_config(&self) -> Arc<Config> {
        if let Some(live) = self.runtime.live_config() {
            live.load_full()
        } else {
            self.config.clone()
        }
    }

    pub fn with_live_config(self, live: Arc<ArcSwap<Config>>) -> Self {
        self.runtime.set_live_config(live);
        self
    }
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
            // 同一秒内或时钟微幅回拨：返回空区间避免重复触发
            std::ops::RangeInclusive::new(1, 0)
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
        let (lo, hi, extra_sun) = if range_part == "*" {
            (min, max, false)
        } else if let Some((a, b)) = range_part.split_once('-') {
            let mut av: u32 = a.parse().map_err(|_| format!("非法范围: {}", part))?;
            let mut bv: u32 = b.parse().map_err(|_| format!("非法范围: {}", part))?;
            let mut sun = false;
            if max == 6 && bv == 7 {
                sun = true;
                if av == 7 {
                    av = 0;
                    bv = 0;
                } else {
                    bv = 6;
                }
            }
            if av < min || bv > max || av > bv {
                return Err(format!("数值超出范围 {}..={}: {}", min, max, part));
            }
            (av, bv, sun)
        } else {
            let v: u32 = range_part.parse().map_err(|_| format!("非法数值: {}", part))?;
            let v = if max == 6 && v == 7 { 0 } else { v };
            if v < min || v > max {
                return Err(format!("数值超出范围 {}..={}: {}", min, max, part));
            }
            (v, v, false)
        };
        let mut v = lo;
        while v <= hi {
            mask |= 1u64 << v;
            v = match v.checked_add(step) {
                Some(next) => next,
                None => break,
            };
        }
        if extra_sun && (step == 1 || (7 - lo) % step == 0) {
            mask |= 1u64;
        }
    }
    if mask == 0 {
        return Err("Cron 字段为空".into());
    }
    Ok(mask)
}

struct CancelSignal {
    runtime: Option<CancellationToken>,
    caller: Option<CancellationToken>,
}

impl CancelSignal {
    fn is_cancelled(&self) -> bool {
        self.runtime.as_ref().is_some_and(CancellationToken::is_cancelled)
            || self.caller.as_ref().is_some_and(CancellationToken::is_cancelled)
    }

    async fn cancelled(&self) {
        match (&self.runtime, &self.caller) {
            (Some(a), Some(b)) => {
                tokio::select! {
                    _ = a.cancelled() => {}
                    _ = b.cancelled() => {}
                }
            }
            (Some(a), None) => a.cancelled().await,
            (None, Some(b)) => b.cancelled().await,
            (None, None) => std::future::pending::<()>().await,
        }
    }
}

struct PgidGuard(i32);

impl Drop for PgidGuard {
    fn drop(&mut self) {
        if self.0 > 1 {
            // SAFETY: 子进程以 process_group(0) 创建独立进程组，Drop 仅在未解除前强杀残留进程组
            unsafe {
                let _ = libc::kill(-self.0, libc::SIGKILL);
            }
        }
    }
}

async fn read_bounded_and_drain<R: tokio::io::AsyncRead + Unpin>(mut reader: R, limit: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if out.len() < limit {
                    let take = (limit - out.len()).min(n);
                    out.extend_from_slice(&chunk[..take]);
                }
            }
        }
    }
    out
}

fn spawn_waitid_nowait(pid: i32) -> tokio::task::JoinHandle<io::Result<()>> {
    tokio::task::spawn_blocking(move || {
        let mut siginfo: libc::siginfo_t = unsafe { std::mem::zeroed() };
        loop {
            let rc = unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid as libc::id_t,
                    &mut siginfo,
                    libc::WEXITED | libc::WNOWAIT,
                )
            };
            if rc == 0 {
                return Ok(());
            }
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
    })
}

enum ExecAbort {
    TimedOut,
    Cancelled,
}

async fn run_exec_isolated(
    job_name: &str,
    program: &str,
    args: &[String],
    cwd: &str,
    timeout: Duration,
    cancel: &CancelSignal,
) -> Result<String, String> {
    if cancel.is_cancelled() {
        return Err(format!("任务 {} 已被取消", job_name));
    }
    let mut cmd = Command::new(program);
    cmd.args(args)
        .env_clear()
        .env("PATH", SAFE_EXEC_PATH)
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
    let mut pgid_guard = PgidGuard(pgid);

    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let r_out = async {
        match stdout {
            Some(s) => read_bounded_and_drain(s, 64 * 1024).await,
            None => Vec::new(),
        }
    };
    let r_err = async {
        match stderr {
            Some(s) => read_bounded_and_drain(s, 16 * 1024).await,
            None => Vec::new(),
        }
    };

    // 阶段 1：有界读取 stdout/stderr，期间随时响应超时或取消信号
    let io_res = tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(ExecAbort::Cancelled),
        _ = &mut deadline => Err(ExecAbort::TimedOut),
        pair = async { tokio::join!(r_out, r_err) } => Ok(pair),
    };

    let (out_buf, err_buf) = match io_res {
        Ok(pair) => pair,
        Err(abort) => {
            if pgid > 1 {
                unsafe {
                    let _ = libc::kill(-pgid, libc::SIGKILL);
                }
            }
            let _ = child.kill().await;
            let _ = child.wait().await;
            pgid_guard.0 = 0;
            return Err(match abort {
                ExecAbort::Cancelled => format!("任务 {} 已被取消并强制终止整个进程组", job_name),
                ExecAbort::TimedOut => format!("任务 {} 超时 ({}s) 已强制终止整个进程组", job_name, timeout.as_secs()),
            });
        }
    };

    // 阶段 2：使用 waitid(P_PID, pid, WEXITED | WNOWAIT) 等待主子进程退出但不回收 PID，
    // 在持有僵尸 PID（彻底消除 PID 复用竞态）的前提下向整个进程组发送 SIGKILL 清理所有脱离后代进程，
    // 随后再通过 child.wait() 回收并取得未被篡改的原始退出码！
    if pgid > 1 {
        let mut waitid_task = spawn_waitid_nowait(pgid);
        let wait_abort = tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                unsafe {
                    let _ = libc::kill(-pgid, libc::SIGKILL);
                }
                let _ = waitid_task.await;
                Some(ExecAbort::Cancelled)
            }
            _ = &mut deadline => {
                unsafe {
                    let _ = libc::kill(-pgid, libc::SIGKILL);
                }
                let _ = waitid_task.await;
                Some(ExecAbort::TimedOut)
            }
            _ = &mut waitid_task => {
                unsafe {
                    let _ = libc::kill(-pgid, libc::SIGKILL);
                }
                None
            }
        };
        if let Some(abort) = wait_abort {
            let _ = child.kill().await;
            let _ = child.wait().await;
            pgid_guard.0 = 0;
            return Err(match abort {
                ExecAbort::Cancelled => format!("任务 {} 已被取消并强制终止整个进程组", job_name),
                ExecAbort::TimedOut => format!("任务 {} 超时 ({}s) 已强制终止整个进程组", job_name, timeout.as_secs()),
            });
        }
    }

    let status = child
        .wait()
        .await
        .map_err(|e| format!("等待子进程退出失败: {}", e))?;
    pgid_guard.0 = 0;

    let stdout_text = logger::truncate_utf8(&String::from_utf8_lossy(&out_buf), 512);
    if status.success() {
        logger::log(Level::Info, "cron", &format!("任务 {} 执行成功: {}", job_name, stdout_text.trim()));
        Ok(stdout_text)
    } else {
        let stderr_text = logger::truncate_utf8(&String::from_utf8_lossy(&err_buf), 512);
        Err(format!("退出码 {:?}: {}", status.code(), stderr_text.trim()))
    }
}

fn reveal_cron_secret(vault: &Vault, canonical: &str, legacy: &str, value: &str) -> Result<String, String> {
    vault.reveal_string_with_legacy(canonical, (legacy != canonical).then_some(legacy), value)
}

async fn run_cancellable_with_timeout<F, T>(
    fut: F,
    timeout: Duration,
    cancel: &CancelSignal,
    timeout_msg: String,
    cancel_msg: String,
) -> Result<T, String>
where
    F: Future<Output = Result<T, String>>,
{
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(cancel_msg),
        res = tokio::time::timeout(timeout, fut) => {
            res.map_err(|_| timeout_msg)?
        }
    }
}

struct RunningResetGuard {
    rt: Arc<CronRuntime>,
    name: String,
    finished: bool,
}

impl Drop for RunningResetGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.rt.set_running(&self.name, false);
        }
    }
}

/// 携带完整网关上下文与可取消令牌执行单次计划任务（实时校验模块开关与 `admin.allow_cron_exec`）
pub async fn execute_cron_job_cancellable(
    job: &CronConfig,
    ctx: Option<&CronExecutionContext>,
    caller_cancel: Option<CancellationToken>,
) -> Result<String, String> {
    let cancel = CancelSignal {
        runtime: ctx.map(|c| c.runtime.cancel_token()),
        caller: caller_cancel,
    };
    if cancel.is_cancelled() {
        return Err(format!("任务 {} 已被取消", job.name));
    }

    let (_lock_guard, mut reset_guard) = if let Some(c) = ctx {
        let lock = c.runtime.job_lock(&job.name)?;
        match lock.try_lock_owned() {
            Ok(g) => {
                c.runtime.set_running(&job.name, true);
                (
                    Some(g),
                    Some(RunningResetGuard {
                        rt: c.runtime.clone(),
                        name: job.name.clone(),
                        finished: false,
                    }),
                )
            }
            Err(_) => {
                return Err(format!("任务 {} 上一轮仍在运行中，已跳过本次重入执行", job.name));
            }
        }
    } else {
        (None, None)
    };

    let started = std::time::Instant::now();
    let timeout = Duration::from_secs(job.timeout_secs.clamp(1, 86_400));
    let cancel_msg = format!("任务 {} 已被取消", job.name);

    let res: Result<String, String> = async {
        let live_cfg = ctx.map(|c| c.current_config());
        if let Some(ref cfg) = live_cfg {
            if !cfg.modules.cron {
                return Err("计划任务模块已关闭，已中止执行".into());
            }
        }

        match &job.action {
            CronAction::DockerPruneImages { dangling_only } => {
                let c = ctx.ok_or_else(|| "缺少 Docker 运行上下文".to_string())?;
                let live = c.current_config();
                if !live.modules.docker {
                    Err("Docker 模块已关闭，无法执行镜像清理".into())
                } else {
                    let raw = run_cancellable_with_timeout(
                        prune_images(&live.admin.docker_socket, *dangling_only),
                        timeout,
                        &cancel,
                        format!("任务 {} 清理镜像超时", job.name),
                        cancel_msg.clone(),
                    )
                    .await?;
                    let msg = format!(
                        "Docker 镜像清理完成 (dangling_only={}): {}",
                        dangling_only,
                        logger::truncate_utf8(&raw, 240)
                    );
                    logger::log(Level::Info, "cron", &msg);
                    Ok(msg)
                }
            }
            CronAction::DockerRestartContainer { container } => {
                let c = ctx.ok_or_else(|| "缺少 Docker 运行上下文".to_string())?;
                let live = c.current_config();
                if !live.modules.docker {
                    Err("Docker 模块已关闭，无法重启容器".into())
                } else {
                    run_cancellable_with_timeout(
                        container_action(&live.admin.docker_socket, &live.docker, container, "restart"),
                        timeout,
                        &cancel,
                        format!("任务 {} 重启容器 {} 超时", job.name, container),
                        cancel_msg.clone(),
                    )
                    .await?;
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
                let toggler = ctx
                    .and_then(|c| c.rule_toggler.as_ref())
                    .ok_or_else(|| "缺少规则状态切换器上下文".to_string())?;
                let msg = run_cancellable_with_timeout(
                    toggler(target_kind.clone(), rule.clone(), *enable),
                    timeout,
                    &cancel,
                    format!("任务 {} 切换规则状态超时", job.name),
                    cancel_msg.clone(),
                )
                .await?;
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
                    let enc_name = encode_secret_segment(&job.name);
                    let u = reveal_cron_secret(
                        &c.vault,
                        &format!("cron.{}.action.url", enc_name),
                        &format!("cron.{}.action.url", job.name),
                        url,
                    )?;
                    let b = reveal_cron_secret(
                        &c.vault,
                        &format!("cron.{}.action.body", enc_name),
                        &format!("cron.{}.action.body", job.name),
                        body,
                    )?;
                    let mut h = BTreeMap::new();
                    for (k, v) in headers {
                        let enc_k = encode_secret_segment(k);
                        let pv = reveal_cron_secret(
                            &c.vault,
                            &format!("cron.{}.action.headers.{}", enc_name, enc_k),
                            &format!("cron.{}.action.headers.{}", job.name, k),
                            v,
                        )?;
                        h.insert(k.clone(), pv);
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
                let resp = run_cancellable_with_timeout(
                    http_shared().execute(req),
                    timeout,
                    &cancel,
                    format!("定时 HTTP 请求 {} 超时", job.name),
                    cancel_msg.clone(),
                )
                .await?;
                resp.ensure_success()?;
                let snippet = logger::truncate_utf8(&String::from_utf8_lossy(&resp.body), 200);
                let msg = format!("HTTP {} -> {} ({})", m, resp.status, snippet.trim());
                logger::log(Level::Info, "cron", &format!("任务 {} 完成: {}", job.name, msg));
                Ok(msg)
            }
            CronAction::Exec { program, args, cwd } => {
                let allow_exec = live_cfg.as_ref().is_some_and(|cfg| cfg.admin.allow_cron_exec);
                if !allow_exec {
                    return Err("安全策略拦截：admin.allow_cron_exec 未启用，禁止执行 CronAction::Exec 外部命令".into());
                }
                run_exec_isolated(&job.name, program, args, cwd, timeout, &cancel).await
            }
        }
    }
    .await;

    let elapsed_ms = started.elapsed().as_millis() as u64;
    if let Some(ref mut g) = reset_guard {
        g.finished = true;
        g.rt.record_finish(&job.name, elapsed_ms, &res);
    }

    if let (Err(ref err), Some(c)) = (&res, ctx) {
        logger::log(Level::Warn, "cron", &format!("计划任务 {} 执行失败: {}", job.name, err));
        let notify_cfg = c.current_config();
        if job.notify_on_failure && !cancel.is_cancelled() && notify_cfg.modules.cron {
            broadcast_event(
                &notify_cfg,
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

/// 携带完整网关上下文执行单次计划任务（含任务级非重入锁、五类真实动作与失败告警通知）
pub async fn execute_cron_job_with_ctx(job: &CronConfig, ctx: Option<&CronExecutionContext>) -> Result<String, String> {
    execute_cron_job_cancellable(job, ctx, None).await
}

/// 无状态执行入口（用于测试；无上下文时 `CronAction::Exec` 默认失败关闭）
pub async fn execute_cron_job(job: &CronConfig) -> Result<String, String> {
    execute_cron_job_with_ctx(job, None).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn exec_ctx(allow_cron_exec: bool) -> (CronExecutionContext, Arc<ArcSwap<Config>>) {
        let mut cfg = Config::default();
        cfg.modules.cron = true;
        cfg.admin.allow_cron_exec = allow_cron_exec;
        let live = Arc::new(ArcSwap::from_pointee(cfg.clone()));
        let rt = CronRuntime::new();
        rt.set_live_config(live.clone());
        let ctx = CronExecutionContext {
            config: Arc::new(cfg),
            vault: Arc::new(Vault::from_master(&[9u8; 32])),
            runtime: rt,
            rule_toggler: None,
        };
        (ctx, live)
    }

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
    async fn exec_requires_allow_cron_exec_clears_env_and_kills_detached_descendants_without_clobbering_exit() {
        // 1. 默认 allow_cron_exec = false（或无上下文）必须拒绝执行 Exec
        let job_echo = CronConfig {
            name: "echo_env".into(),
            enabled: true,
            schedule: "0 * * * * *".into(),
            timeout_secs: 5,
            action: CronAction::Exec {
                program: "/bin/sh".into(),
                args: vec!["-c".into(), "env".into()],
                cwd: String::new(),
            },
            notify_on_failure: false,
        };
        assert!(execute_cron_job(&job_echo).await.is_err());
        let (ctx_denied, _) = exec_ctx(false);
        let err = execute_cron_job_with_ctx(&job_echo, Some(&ctx_denied))
            .await
            .unwrap_err();
        assert!(err.contains("allow_cron_exec"));

        // 2. 开启 allow_cron_exec 后执行，仅存在固定安全 PATH，不继承宿主环境
        let (ctx_ok, _) = exec_ctx(true);
        let env_out = execute_cron_job_with_ctx(&job_echo, Some(&ctx_ok)).await.unwrap();
        assert!(env_out.contains("PATH=/usr/sbin:/sbin:/usr/bin:/bin"), "env_out={env_out}");
        assert!(!env_out.contains("VANE_MASTER_KEY"));
        assert!(!env_out.contains("HOME="));

        // 3. 主进程正常退出 0 时，waitid(WNOWAIT) + kill(-pgid) 必须清扫脱离的后台后代且保留退出码 0
        let pid_file = std::env::temp_dir().join(format!("vane_cron_bg_{}.pid", crate::config::random_nonce()));
        let cmd_str = format!(
            "sleep 30 >/dev/null 2>&1 & echo $! > \"{}\"; echo clean_ok",
            pid_file.display()
        );
        let job_detached = CronConfig {
            name: "detached_desc".into(),
            enabled: true,
            schedule: "0 * * * * *".into(),
            timeout_secs: 5,
            action: CronAction::Exec {
                program: "/bin/sh".into(),
                args: vec!["-c".into(), cmd_str],
                cwd: String::new(),
            },
            notify_on_failure: false,
        };
        let out = execute_cron_job_with_ctx(&job_detached, Some(&ctx_ok)).await.unwrap();
        assert!(out.contains("clean_ok"), "unexpected stdout: {out}");
        if let Ok(pid_text) = std::fs::read_to_string(&pid_file) {
            if let Ok(bg_pid) = pid_text.trim().parse::<i32>() {
                let mut alive = true;
                for _ in 0..25 {
                    if unsafe { libc::kill(bg_pid, 0) } != 0 {
                        alive = false;
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                assert!(!alive, "detached descendant pid {} survived parent exit", bg_pid);
            }
        }
        let _ = std::fs::remove_file(&pid_file);
    }

    #[tokio::test]
    async fn exec_timeout_and_cancellation_kill_process_group_and_live_config_blocks_disabled_docker() {
        let (ctx, live) = exec_ctx(true);

        // 1. 超时强杀进程组
        let job_slow = CronConfig {
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
        let err = execute_cron_job_with_ctx(&job_slow, Some(&ctx)).await.unwrap_err();
        assert!(err.contains("超时"));

        // 2. cancel_all 立即中止正在运行的外部命令
        let job_cancel = CronConfig {
            name: "cancel_tree".into(),
            enabled: true,
            schedule: "0 * * * * *".into(),
            timeout_secs: 30,
            action: CronAction::Exec {
                program: "/bin/sh".into(),
                args: vec!["-c".into(), "sleep 30 & wait".into()],
                cwd: String::new(),
            },
            notify_on_failure: false,
        };
        let ctx_c = ctx.clone();
        let handle = tokio::spawn(async move { execute_cron_job_with_ctx(&job_cancel, Some(&ctx_c)).await });
        tokio::time::sleep(Duration::from_millis(120)).await;
        ctx.runtime.cancel_all();
        let err_cancel = tokio::time::timeout(Duration::from_secs(3), handle)
            .await
            .expect("cancelled cron job should exit promptly")
            .unwrap()
            .unwrap_err();
        assert!(err_cancel.contains("取消"), "unexpected cancel err: {err_cancel}");

        // 3. 实时关闭 modules.docker 后，即使 ctx.config 中旧快照为 true，也必须立即拒绝 Docker 动作
        let mut disabled_cfg = (**live.load()).clone();
        disabled_cfg.modules.docker = false;
        live.store(Arc::new(disabled_cfg));
        let job_docker = CronConfig {
            name: "prune_test".into(),
            enabled: true,
            schedule: "0 * * * * *".into(),
            timeout_secs: 5,
            action: CronAction::DockerPruneImages { dangling_only: true },
            notify_on_failure: false,
        };
        let err_docker = execute_cron_job_with_ctx(&job_docker, Some(&ctx)).await.unwrap_err();
        assert!(err_docker.contains("Docker 模块已关闭"));
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
            vault
                .seal("cron.ping_job.action.headers.x-cron-token", b"secret-123")
                .unwrap(),
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
        let mut cfg = Config::default();
        cfg.modules.cron = true;
        let ctx = CronExecutionContext {
            config: Arc::new(cfg),
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
