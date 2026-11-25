//! 定长环形内存日志（零磁盘写入），自动截断与敏感凭据脱敏，并提供时间工具函数。
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// 单条日志最大字节数
pub const MAX_ENTRY_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    pub fn parse(s: &str) -> Option<Level> {
        match s.to_ascii_lowercase().as_str() {
            "debug" => Some(Level::Debug),
            "info" => Some(Level::Info),
            "warn" | "warning" => Some(Level::Warn),
            "error" => Some(Level::Error),
            _ => None,
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct LogEntry {
    pub seq: u64,
    pub ts: u64,
    pub level: Level,
    pub module: String,
    pub message: String,
}

pub struct RingLogger {
    inner: Mutex<RingInner>,
}

struct RingInner {
    cap: usize,
    seq: u64,
    buf: VecDeque<LogEntry>,
    tz_offset_secs: i64,
}

impl RingLogger {
    pub fn new(cap: usize) -> Self {
        let cap = cap.clamp(50, 1000);
        Self {
            inner: Mutex::new(RingInner { cap, seq: 0, buf: VecDeque::with_capacity(cap), tz_offset_secs: 0 }),
        }
    }

    pub fn set_capacity(&self, cap: usize) {
        let cap = cap.clamp(50, 1000);
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.cap = cap;
        while g.buf.len() > cap {
            g.buf.pop_front();
        }
        g.buf.shrink_to(cap);
    }

    pub fn set_tz_offset(&self, secs: i64) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.tz_offset_secs = secs;
    }

    pub fn push(&self, level: Level, module: &str, message: &str) {
        let sanitized = sanitize_log_text(message);
        let msg = truncate_utf8(&redact(&sanitized), MAX_ENTRY_BYTES);
        let ts = unix_now();
        let entry = LogEntry {
            seq: 0,
            ts,
            level,
            module: truncate_utf8(&sanitize_log_text(module), 32),
            message: msg,
        };
        let tz = {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.seq += 1;
            let mut stored = entry.clone();
            stored.seq = g.seq;
            if g.buf.len() >= g.cap {
                g.buf.pop_front();
            }
            g.buf.push_back(stored);
            g.tz_offset_secs
        };
        eprintln!("{} [{}] [{}] {}", format_rfc3339(ts, tz), level.as_str(), entry.module, entry.message);
    }

    pub fn query(&self, min_level: Option<Level>, module: Option<&str>, limit: usize, after_seq: u64) -> Vec<LogEntry> {
        self.query_filtered(min_level, module, None, limit, after_seq)
    }

    pub fn query_filtered(
        &self,
        min_level: Option<Level>,
        module: Option<&str>,
        keyword: Option<&str>,
        limit: usize,
        after_seq: u64,
    ) -> Vec<LogEntry> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let kw_lower = keyword.map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty());
        let limit = limit.clamp(1, 1000);
        let matches = |e: &&LogEntry| -> bool {
            e.seq > after_seq
                && min_level.map_or(true, |l| e.level >= l)
                && module.map_or(true, |m| e.module == m)
                && kw_lower.as_ref().map_or(true, |kw| {
                    e.module.to_ascii_lowercase().contains(kw) || e.message.to_ascii_lowercase().contains(kw)
                })
        };
        if after_seq > 0 {
            g.buf.iter().filter(matches).take(limit).cloned().collect()
        } else {
            let mut out: Vec<LogEntry> = g.buf.iter().rev().filter(matches).take(limit).cloned().collect();
            out.reverse();
            out
        }
    }

    pub fn modules(&self) -> Vec<String> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut set = std::collections::BTreeSet::new();
        for e in &g.buf {
            set.insert(e.module.clone());
        }
        set.into_iter().collect()
    }

    pub fn clear(&self) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.buf.clear();
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).buf.len()
    }
}

static GLOBAL: OnceLock<RingLogger> = OnceLock::new();

pub fn global() -> &'static RingLogger {
    GLOBAL.get_or_init(|| RingLogger::new(300))
}

pub fn log(level: Level, module: &str, message: &str) {
    global().push(level, module, message);
}

#[macro_export]
macro_rules! log_info {
    ($m:expr, $($arg:tt)*) => { $crate::logger::log($crate::logger::Level::Info, $m, &format!($($arg)*)) };
}
#[macro_export]
macro_rules! log_warn {
    ($m:expr, $($arg:tt)*) => { $crate::logger::log($crate::logger::Level::Warn, $m, &format!($($arg)*)) };
}
#[macro_export]
macro_rules! log_error {
    ($m:expr, $($arg:tt)*) => { $crate::logger::log($crate::logger::Level::Error, $m, &format!($($arg)*)) };
}
#[macro_export]
macro_rules! log_debug {
    ($m:expr, $($arg:tt)*) => { $crate::logger::log($crate::logger::Level::Debug, $m, &format!($($arg)*)) };
}

/// 按 UTF-8 边界截断
pub fn truncate_utf8(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max.saturating_sub(3);
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

const SENSITIVE_KEYS: &[&str] = &[
    "token", "password", "passwd", "secret", "secret_key", "eab_hmac_key", "private_key",
    "api_key", "apikey", "sign", "signature", "authorization", "access_key", "hmac", "cookie",
    "key", "vane_session", "vane_entry", "vane_ticket",
];

fn sanitize_log_text(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            '\r' | '\n' | '\x1b' => ' ',
            c if c.is_control() => ' ',
            c => c,
        })
        .collect()
}

fn is_unquoted_value_end(b: u8) -> bool {
    b.is_ascii_whitespace() || matches!(b, b'&' | b',' | b')' | b'}' | b']' | b'"' | b'\'' | b'\r' | b'\n' | b';')
}

/// 敏感凭据脱敏：移除 enc:v1: 密文与 key=value / key: value 形式的凭据值
pub fn redact(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if input[i..].starts_with("enc:v1:") {
            out.push_str("enc:v1:****");
            i += 7;
            while i < bytes.len() && is_token_byte(bytes[i]) {
                i += 1;
            }
            continue;
        }
        if input.get(i..i + 7).is_some_and(|s| s.eq_ignore_ascii_case("bearer ")) {
            out.push_str("Bearer ****");
            i += 7;
            while i < bytes.len() && !is_unquoted_value_end(bytes[i]) {
                i += 1;
            }
            continue;
        }
        if input.get(i..i + 6).is_some_and(|s| s.eq_ignore_ascii_case("basic ")) {
            out.push_str("Basic ****");
            i += 6;
            while i < bytes.len() && !is_unquoted_value_end(bytes[i]) {
                i += 1;
            }
            continue;
        }
        let ch = input[i..].chars().next().unwrap_or(' ');
        out.push(ch);
        i += ch.len_utf8();
        if ch == '=' || ch == ':' {
            let trimmed_prefix = out[..out.len() - 1]
                .trim_end_matches(|c: char| c == ' ' || c == '"' || c == '\'')
                .to_ascii_lowercase();
            let key_start = trimmed_prefix
                .char_indices()
                .rev()
                .find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == '_' || *c == '-'))
                .map(|(p, c)| p + c.len_utf8())
                .unwrap_or(0);
            let key = &trimmed_prefix[key_start..];
            if SENSITIVE_KEYS.iter().any(|k| key.ends_with(k)) {
                while i < bytes.len() && bytes[i] == b' ' {
                    out.push(' ');
                    i += 1;
                }
                let quote = bytes.get(i).copied().filter(|&b| b == b'"' || b == b'\'');
                if let Some(q) = quote {
                    out.push(q as char);
                    i += 1;
                }
                if input.get(i..i + 7).is_some_and(|s| s.eq_ignore_ascii_case("bearer ")) {
                    out.push_str("Bearer ");
                    i += 7;
                } else if input.get(i..i + 6).is_some_and(|s| s.eq_ignore_ascii_case("basic ")) {
                    out.push_str("Basic ");
                    i += 6;
                }
                let start = i;
                if let Some(q) = quote {
                    while i < bytes.len() && bytes[i] != q && bytes[i] != b'\n' && bytes[i] != b'\r' {
                        if bytes[i] == b'\\' && i + 1 < bytes.len() {
                            i += 2;
                        } else {
                            i += 1;
                        }
                    }
                    if i > start {
                        out.push_str("****");
                    }
                    if bytes.get(i) == Some(&q) {
                        out.push(q as char);
                        i += 1;
                    }
                } else {
                    while i < bytes.len() && !is_unquoted_value_end(bytes[i]) {
                        i += 1;
                    }
                    if i > start {
                        out.push_str("****");
                    }
                }
            }
        }
    }
    out
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'+' | b'/' | b'=' | b'%' | b'~')
}

pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn unix_now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

/// 由 1970-01-01 起的天数换算公历日期（Howard Hinnant 算法）
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let m = m as u64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

/// 分解后的本地时间
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DateTimeParts {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
    /// 0 = 周日
    pub weekday: u32,
}

pub fn breakdown(unix: i64, offset_secs: i64) -> DateTimeParts {
    let t = unix + offset_secs;
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    DateTimeParts {
        year,
        month,
        day,
        hour: (secs / 3600) as u32,
        minute: ((secs % 3600) / 60) as u32,
        second: (secs % 60) as u32,
        weekday: ((days + 4).rem_euclid(7)) as u32,
    }
}

pub fn format_rfc3339(unix: u64, offset_secs: i64) -> String {
    let p = breakdown(unix as i64, offset_secs);
    let tz = if offset_secs == 0 {
        "Z".to_string()
    } else {
        let sign = if offset_secs < 0 { '-' } else { '+' };
        let a = offset_secs.abs();
        format!("{}{:02}:{:02}", sign, a / 3600, (a % 3600) / 60)
    };
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{}", p.year, p.month, p.day, p.hour, p.minute, p.second, tz)
}

/// UTC ISO8601（阿里云签名等使用）
pub fn format_iso8601_utc(unix: u64) -> String {
    format_rfc3339(unix, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_capacity_and_truncation() {
        let l = RingLogger::new(50);
        for i in 0..80 {
            l.push(Level::Info, "test", &format!("msg {}", i));
        }
        assert_eq!(l.len(), 50);
        let long = "x".repeat(2000);
        l.push(Level::Warn, "test", &long);
        let last = l.query(None, None, 1, 0);
        assert!(last[0].message.len() <= MAX_ENTRY_BYTES);
        l.set_capacity(60);
        l.clear();
        assert_eq!(l.len(), 0);
    }

    #[test]
    fn redacts_secrets() {
        let s = redact(
            r#"api_token=abcdef123 value enc:v1:QUJDREVGRw== Authorization: bearer xyz.abc Authorization: Basic dXNlcjpwYXNz password: Vane#2026!Strong token=123456:SECRET_TAIL Cookie: vane_session=abc123; vane_entry=def456 {"password":"json-secret","token": "tok 123"} secret="quoted val""#,
        );
        assert!(!s.contains("abcdef123"));
        assert!(!s.contains("QUJDREVGRw"));
        assert!(!s.contains("xyz.abc"));
        assert!(!s.contains("dXNlcjpwYXNz"));
        assert!(!s.contains("Vane#2026!Strong"));
        assert!(!s.contains("Strong"));
        assert!(!s.contains("SECRET_TAIL"));
        assert!(!s.contains("abc123"));
        assert!(!s.contains("def456"));
        assert!(!s.contains("json-secret"));
        assert!(!s.contains("tok 123"));
        assert!(!s.contains("quoted val"));
        assert!(s.contains("value"));

        let l = RingLogger::new(50);
        l.push(Level::Info, "test\nmod", "line1\r\n\x1b[31mfake");
        let entry = l.query(None, None, 1, 0).pop().unwrap();
        assert!(!entry.message.contains('\n'));
        assert!(!entry.message.contains('\r'));
        assert!(!entry.message.contains('\x1b'));
        assert!(!entry.module.contains('\n'));
    }

    #[test]
    fn civil_roundtrip() {
        for d in [-1000i64, 0, 1, 365, 19_000, 20_000, 50_000] {
            let (y, m, dd) = civil_from_days(d);
            assert_eq!(days_from_civil(y, m, dd), d);
        }
        assert_eq!(format_rfc3339(0, 0), "1970-01-01T00:00:00Z");
        assert_eq!(format_rfc3339(1_700_000_000, 8 * 3600), "2023-11-15T06:13:20+08:00");
        assert_eq!(breakdown(0, 0).weekday, 4);
    }
}
