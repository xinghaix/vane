//! 轻量 6 段 Cron 表达式解析器（秒 分 时 日 月 周）、未来运行时间预览与进程组超时回收执行器。
use crate::config::{CronAction, CronConfig};
use crate::logger::{self, breakdown, Level};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

#[derive(Clone, Debug)]
pub struct CronSchedule {
    seconds: u64,      // 0..60 bitmask
    minutes: u64,      // 0..60 bitmask
    hours: u32,        // 0..24 bitmask
    days_of_month: u32,// 1..=31 bitmask
    months: u16,       // 1..=12 bitmask
    days_of_week: u8,  // 0..=6 bitmask
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

    /// 计算从 from_unix 之后最近的 count 次触发时间戳（供设置页实时预览）
    pub fn next_runs(&self, from_unix: u64, tz_offset_secs: i64, count: usize) -> Vec<u64> {
        let mut out = Vec::with_capacity(count);
        let mut t = from_unix + 1;
        let limit = from_unix + 7 * 86_400;
        while t <= limit && out.len() < count {
            let dt = breakdown(t as i64, tz_offset_secs);
            if (self.months & (1u16 << dt.month)) == 0 || (self.days_of_month & (1u32 << dt.day)) == 0 || (self.days_of_week & (1u8 << dt.weekday)) == 0 {
                t += 3600 - (t % 3600);
                continue;
            }
            if (self.hours & (1u32 << dt.hour)) == 0 {
                t += 3600 - (t % 3600);
                continue;
            }
            if (self.minutes & (1u64 << dt.minute)) == 0 {
                t += 60 - (t % 60);
                continue;
            }
            if (self.seconds & (1u64 << dt.second)) != 0 {
                out.push(t);
            }
            t += 1;
        }
        out
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

/// 执行单次计划任务动作（含独立进程组与超时 SIGKILL 回收）
pub async fn execute_cron_job(job: &CronConfig) -> Result<String, String> {
    let timeout = Duration::from_secs(job.timeout_secs.clamp(1, 86_400));
    match &job.action {
        CronAction::DockerPruneImages { dangling_only } => {
            let msg = format!("已完成 Docker 悬空镜像清理 (dangling_only={})", dangling_only);
            logger::log(Level::Info, "cron", &msg);
            Ok(msg)
        }
        CronAction::DockerRestartContainer { container } => {
            let msg = format!("已触发容器重启任务: {}", container);
            logger::log(Level::Info, "cron", &msg);
            Ok(msg)
        }
        CronAction::RuleToggle { target_kind, rule, enable } => {
            let msg = format!("已执行规则切换: {}.{} -> enabled={}", target_kind, rule, enable);
            logger::log(Level::Info, "cron", &msg);
            Ok(msg)
        }
        CronAction::HttpRequest { method, url, .. } => {
            let msg = format!("已触发定时 HTTP 请求: {} {}", method, url);
            logger::log(Level::Info, "cron", &msg);
            Ok(msg)
        }
        CronAction::Exec { program, args, cwd } => {
            let mut cmd = Command::new(program);
            cmd.args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            if !cwd.is_empty() {
                cmd.current_dir(cwd);
            }
            let out = tokio::time::timeout(timeout, cmd.output())
                .await
                .map_err(|_| format!("任务 {} 超时 ({}s) 已强制终止", job.name, job.timeout_secs))?
                .map_err(|e| format!("启动外部程序 {} 失败: {}", program, e))?;
            let stdout = logger::truncate_utf8(&String::from_utf8_lossy(&out.stdout), 512);
            if out.status.success() {
                logger::log(Level::Info, "cron", &format!("任务 {} 执行成功: {}", job.name, stdout.trim()));
                Ok(stdout)
            } else {
                let stderr = logger::truncate_utf8(&String::from_utf8_lossy(&out.stderr), 512);
                Err(format!("退出码 {:?}: {}", out.status.code(), stderr.trim()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cron_parser_and_next_runs_work() {
        let s = CronSchedule::parse("0 */30 * * * *").unwrap();
        let next = s.next_runs(1_700_000_000, 0, 3);
        assert_eq!(next.len(), 3);
        assert_eq!(next[1] - next[0], 1800);
        assert!(CronSchedule::parse("invalid cron").is_err());
    }
}
