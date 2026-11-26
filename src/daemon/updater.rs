//! 系统更新管理：
//! 1) GitHub Release 新版本检查（默认关闭自动检查，永远不自动下载/自动更新，仅发站内与外部提醒）；
//! 2) 手动上传 `.tar.gz` 压缩包安全沙箱更新：
//!    - 流式写入系统临时目录（不占用小内存路由器 RAM），操作前检查临时目录与目标目录可用磁盘空间；
//!    - 可选 SHA-256 摘要强校验（支持粘贴官方 SHA256SUMS 文本行）；
//!    - 独立进程组 + 30 秒超时 + 128 MiB 解压硬字节上限抵御 gzip/tar 解压炸弹；
//!    - 纯 Rust 严格 USTAR/GNU tar 解析：拒绝路径穿越 (`../`)、绝对路径、符号链接、硬链接、设备节点与 FIFO，仅流式提取单个 `vane` 二进制文件，其余文件永不落盘；
//!    - 执行前先校验 ELF / Mach-O 文件头魔数、位宽、字节序与 CPU 架构；
//!    - 清空敏感环境变量（剥离 VANE_MASTER_KEY*）独立进程组沙箱执行 `vane version` 与 `vane check`：校验 OS/Arch 完全匹配、SemVer 严格禁止降级（仅允许同版本或更新版本）、校验当前 `config.toml` 兼容性；
//!    - 备份旧程序为 `.bak`，同挂载点 `sync_all` + POSIX `rename` 原子替换（运行中进程无 ETXTBSY），全程 RAII 自动清理临时目录。
use crate::logger;
use crate::net::http_client::{shared, HttpRequest, SsrfPolicy};
use base64::Engine;
use ring::digest::{Context, SHA256};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{mpsc, Mutex};
use std::time::{Duration, Instant};

pub const MAX_UPLOAD_ARCHIVE_BYTES: u64 = 48 * 1024 * 1024;
pub const MAX_UNCOMPRESSED_TAR_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_TAR_ENTRIES: usize = 64;
pub const MIN_BINARY_BYTES: u64 = 256 * 1024;
pub const MAX_BINARY_BYTES: u64 = 96 * 1024 * 1024;
pub const MIN_TEMP_FREE_BYTES: u64 = 64 * 1024 * 1024;
const GZIP_TIMEOUT_SECS: u64 = 30;
const PROBE_TIMEOUT_SECS: u64 = 5;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseInfo {
    pub tag_name: String,
    pub version: String,
    pub name: String,
    pub html_url: String,
    pub published_at: String,
    pub notes: String,
    pub asset_name: String,
    pub asset_url: String,
    pub checksums_url: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct UpdateStateSnapshot {
    pub current_version: String,
    pub os: String,
    pub arch: String,
    pub target_triple: String,
    pub executable_path: String,
    pub executable_writable: bool,
    pub temp_dir: String,
    pub temp_available_mb: u64,
    pub last_check_unix: u64,
    pub latest: Option<ReleaseInfo>,
    pub has_update: bool,
    pub last_error: Option<String>,
}

#[derive(Default)]
struct UpdateStateInner {
    last_check_unix: u64,
    latest: Option<ReleaseInfo>,
    last_error: Option<String>,
    last_notified_tag: String,
}

pub struct UpdateRuntime {
    inner: Mutex<UpdateStateInner>,
    pub apply_lock: tokio::sync::Mutex<()>,
}

impl Default for UpdateRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl UpdateRuntime {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(UpdateStateInner::default()),
            apply_lock: tokio::sync::Mutex::new(()),
        }
    }

    pub fn last_check_unix(&self) -> u64 {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).last_check_unix
    }

    /// 记录最新检查结果；若发现比当前更新且尚未提醒过的版本，返回 `true`
    pub fn record_check_result(&self, res: Result<ReleaseInfo, String>) -> bool {
        let now = logger::unix_now();
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.last_check_unix = now;
        match res {
            Ok(info) => {
                let is_newer = is_newer_version(&info.version, current_version());
                let should_notify = is_newer && g.last_notified_tag != info.tag_name;
                if should_notify {
                    g.last_notified_tag = info.tag_name.clone();
                }
                g.latest = Some(info);
                g.last_error = None;
                should_notify
            }
            Err(err) => {
                g.last_error = Some(err);
                false
            }
        }
    }

    pub fn snapshot(&self) -> UpdateStateSnapshot {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let has_update = g
            .latest
            .as_ref()
            .is_some_and(|r| is_newer_version(&r.version, current_version()));
        let exe_path = std::env::current_exe()
            .ok()
            .and_then(|p| fs::canonicalize(&p).ok().or(Some(p)));
        let exe_writable = exe_path
            .as_deref()
            .and_then(Path::parent)
            .is_some_and(is_dir_writable);
        let temp_dir = std::env::temp_dir();
        let temp_avail_mb = available_disk_bytes(&temp_dir).unwrap_or(0) / (1024 * 1024);

        UpdateStateSnapshot {
            current_version: current_version().to_string(),
            os: current_os().to_string(),
            arch: current_arch().to_string(),
            target_triple: current_target_triple().to_string(),
            executable_path: exe_path.map(|p| p.display().to_string()).unwrap_or_default(),
            executable_writable: exe_writable,
            temp_dir: temp_dir.display().to_string(),
            temp_available_mb: temp_avail_mb,
            last_check_unix: g.last_check_unix,
            latest: g.latest.clone(),
            has_update,
            last_error: g.last_error.clone(),
        }
    }
}

pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub fn current_os() -> &'static str {
    std::env::consts::OS
}

pub fn current_arch() -> &'static str {
    std::env::consts::ARCH
}

pub fn current_target_triple() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "x86_64-unknown-linux-musl",
        ("linux", "aarch64") => "aarch64-unknown-linux-musl",
        ("linux", "arm") => "armv7-unknown-linux-musleabihf",
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------
// SemVer 严格解析与比较
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreId {
    Numeric(u64),
    AlphaNum(String),
}

impl Ord for PreId {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (PreId::Numeric(a), PreId::Numeric(b)) => a.cmp(b),
            (PreId::Numeric(_), PreId::AlphaNum(_)) => Ordering::Less,
            (PreId::AlphaNum(_), PreId::Numeric(_)) => Ordering::Greater,
            (PreId::AlphaNum(a), PreId::AlphaNum(b)) => a.cmp(b),
        }
    }
}

impl PartialOrd for PreId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemVer {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub pre: Vec<PreId>,
}

impl Ord for SemVer {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater, // 正式版 > 预发布版
                (false, true) => Ordering::Less,
                (false, false) => self.pre.cmp(&other.pre),
            })
    }
}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub fn parse_semver(raw: &str) -> Option<SemVer> {
    let trimmed = raw.trim();
    let s = trimmed
        .strip_prefix('v')
        .or_else(|| trimmed.strip_prefix('V'))
        .unwrap_or(trimmed);
    let without_build = s.split('+').next().unwrap_or(s);
    let (core, pre_str) = match without_build.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (without_build, None),
    };
    let mut parts = core.split('.');
    let major: u64 = parts.next()?.parse().ok()?;
    let minor: u64 = parts.next()?.parse().ok()?;
    let patch: u64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    let mut pre = Vec::new();
    if let Some(p) = pre_str {
        if p.is_empty() {
            return None;
        }
        for seg in p.split('.') {
            if seg.is_empty() || !seg.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                return None;
            }
            if seg.bytes().all(|b| b.is_ascii_digit()) {
                pre.push(PreId::Numeric(seg.parse().ok()?));
            } else {
                pre.push(PreId::AlphaNum(seg.to_string()));
            }
        }
    }
    Some(SemVer { major, minor, patch, pre })
}

pub fn compare_semver(a: &str, b: &str) -> Option<Ordering> {
    Some(parse_semver(a)?.cmp(&parse_semver(b)?))
}

pub fn is_newer_version(candidate: &str, current: &str) -> bool {
    compare_semver(candidate, current) == Some(Ordering::Greater)
}

pub fn is_same_or_newer_version(candidate: &str, current: &str) -> Result<bool, String> {
    match compare_semver(candidate, current) {
        Some(Ordering::Greater | Ordering::Equal) => Ok(true),
        Some(Ordering::Less) => Ok(false),
        None => Err(format!("版本号格式非法: candidate={candidate}, current={current}")),
    }
}

// ---------------------------------------------------------------------------
// GitHub Release 检查（只读查询，永不自动更新）
// ---------------------------------------------------------------------------

pub fn validate_github_repo(repo: &str) -> Result<String, String> {
    let r = repo.trim();
    let Some((owner, name)) = r.split_once('/') else {
        return Err("update.repo 必须为 <owner>/<repo> 格式（如 xinghaix/vane）".into());
    };
    let valid_seg = |s: &str| -> bool {
        !s.is_empty()
            && s.len() <= 100
            && s != "."
            && s != ".."
            && !s.contains("..")
            && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    };
    if !valid_seg(owner) || !valid_seg(name) || name.contains('/') {
        return Err("update.repo 包含非法字符，仅允许 <owner>/<repo>".into());
    }
    Ok(format!("{owner}/{name}"))
}

pub async fn check_github_release(repo: &str) -> Result<ReleaseInfo, String> {
    let clean_repo = validate_github_repo(repo)?;
    let url = format!("https://api.github.com/repos/{clean_repo}/releases/latest");
    check_github_release_url(&url).await
}

async fn check_github_release_url(url: &str) -> Result<ReleaseInfo, String> {
    let mut req = HttpRequest::new("GET", url);
    req.headers.insert("accept".into(), "application/vnd.github+json".into());
    req.headers.insert("x-github-api-version".into(), "2022-11-28".into());
    req.response_limit = 256 * 1024;
    req.timeout = Duration::from_secs(15);
    if !cfg!(test) {
        req.ssrf_policy = SsrfPolicy::PublicOnly;
    }
    let resp = shared().execute(req).await?;
    if resp.status.as_u16() == 404 {
        return Err("该 GitHub 仓库尚未发布正式 Release（HTTP 404）".into());
    }
    if resp.status.as_u16() == 403 {
        return Err("GitHub API 触发速率限制（HTTP 403），请稍后再试".into());
    }
    let json = resp.json()?;
    parse_github_release_json(&json, current_target_triple())
}

pub fn parse_github_release_json(v: &serde_json::Value, target_triple: &str) -> Result<ReleaseInfo, String> {
    let tag_name = v
        .get("tag_name")
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or("GitHub Release 缺少 tag_name 字段")?
        .to_string();
    if parse_semver(&tag_name).is_none() {
        return Err(format!("GitHub Release 版本号格式非 SemVer: {tag_name}"));
    }
    let version = tag_name
        .strip_prefix('v')
        .or_else(|| tag_name.strip_prefix('V'))
        .unwrap_or(&tag_name)
        .to_string();
    let name = v
        .get("name")
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&tag_name)
        .to_string();
    let html_url = v
        .get("html_url")
        .and_then(|x| x.as_str())
        .filter(|u| u.starts_with("https://github.com/"))
        .unwrap_or("")
        .to_string();
    let published_at = v
        .get("published_at")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let raw_notes = v.get("body").and_then(|x| x.as_str()).unwrap_or("");
    let notes = logger::truncate_utf8(raw_notes.trim(), 2048);

    let mut asset_name = String::new();
    let mut asset_url = String::new();
    let mut checksums_url = String::new();
    if let Some(assets) = v.get("assets").and_then(|x| x.as_array()) {
        for a in assets {
            let aname = a.get("name").and_then(|x| x.as_str()).unwrap_or("");
            let aurl = a
                .get("browser_download_url")
                .and_then(|x| x.as_str())
                .filter(|u| u.starts_with("https://github.com/") || u.starts_with("https://objects.githubusercontent.com/"))
                .unwrap_or("");
            if aname == "SHA256SUMS" && !aurl.is_empty() {
                checksums_url = aurl.to_string();
            } else if target_triple != "unknown"
                && aname.contains(target_triple)
                && (aname.ends_with(".tar.gz") || aname.ends_with(".tgz"))
                && !aurl.is_empty()
            {
                asset_name = aname.to_string();
                asset_url = aurl.to_string();
            }
        }
    }

    Ok(ReleaseInfo {
        tag_name,
        version,
        name,
        html_url,
        published_at,
        notes,
        asset_name,
        asset_url,
        checksums_url,
    })
}

// ---------------------------------------------------------------------------
// 磁盘空间、SHA-256、临时沙箱目录守卫
// ---------------------------------------------------------------------------

pub fn available_disk_bytes(dir: &Path) -> Option<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let cpath = CString::new(dir.as_os_str().as_bytes()).ok()?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(cpath.as_ptr(), &mut st) } != 0 {
        return None;
    }
    let avail = st.f_bavail as u64;
    let bsize = if st.f_frsize > 0 { st.f_frsize as u64 } else { st.f_bsize as u64 };
    Some(avail.saturating_mul(bsize))
}

fn is_dir_writable(dir: &Path) -> bool {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let Ok(cpath) = CString::new(dir.as_os_str().as_bytes()) else { return false };
    unsafe { libc::access(cpath.as_ptr(), libc::W_OK | libc::X_OK) == 0 }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

/// 解析管理员填写的预期 SHA-256（支持纯 64 位 Hex、`sha256:<hex>`，或直接粘贴官方 `SHA256SUMS` 单行/多行文本）
pub fn parse_expected_sha256(raw: &str, filename_hint: Option<&str>) -> Result<Option<String>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let lines: Vec<&str> = trimmed
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if lines.len() == 1 {
        let token = lines[0]
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim()
            .strip_prefix("sha256:")
            .or_else(|| lines[0].split_whitespace().next().unwrap_or("").strip_prefix("SHA256:"))
            .unwrap_or_else(|| lines[0].split_whitespace().next().unwrap_or(""));
        if token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(Some(token.to_ascii_lowercase()));
        }
        return Err("预期 SHA-256 格式无效（需 64 位十六进制摘要或官方 SHA256SUMS 对应行）".into());
    }
    // 多行 SHA256SUMS：优先匹配文件名，其次匹配当前 target triple
    let triple = current_target_triple();
    let pick_line = |needle: &str| -> Option<&str> {
        lines.iter().copied().find(|l| !needle.is_empty() && l.contains(needle))
    };
    let chosen = filename_hint
        .and_then(pick_line)
        .or_else(|| (triple != "unknown").then(|| pick_line(triple)).flatten())
        .ok_or_else(|| "多行 SHA256SUMS 中未找到与当前架构或文件名匹配的校验行".to_string())?;
    let token = chosen.split_whitespace().next().unwrap_or("");
    if token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(Some(token.to_ascii_lowercase()))
    } else {
        Err("匹配到的 SHA256SUMS 行格式非法".into())
    }
}

pub struct TempSandboxDir {
    path: PathBuf,
}

impl TempSandboxDir {
    pub fn create(prefix: &str) -> Result<Self, String> {
        let base = std::env::temp_dir();
        if let Some(avail) = available_disk_bytes(&base) {
            if avail < MIN_TEMP_FREE_BYTES {
                return Err(format!(
                    "临时目录 {} 可用空间不足（仅剩 {} MiB，至少需要 {} MiB）",
                    base.display(),
                    avail / (1024 * 1024),
                    MIN_TEMP_FREE_BYTES / (1024 * 1024)
                ));
            }
        }
        let dir = base.join(format!("{}-{}-{:016x}", prefix, std::process::id(), crate::config::random_nonce()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|e| format!("创建临时沙箱目录失败: {e}"))?;
        Ok(Self { path: dir })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempSandboxDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

// ---------------------------------------------------------------------------
// 解压炸弹防护 + 纯 Rust 严格 USTAR/GNU tar 沙箱提取
// ---------------------------------------------------------------------------

struct BoundedStream<R: Read> {
    inner: R,
    remaining: u64,
    total_read: u64,
    child_pgid: i32,
}

impl<R: Read> BoundedStream<R> {
    fn kill_child_group(&self) {
        if self.child_pgid > 0 {
            unsafe {
                libc::kill(-self.child_pgid, libc::SIGKILL);
            }
        }
    }

    fn read_exact_or_eof(&mut self, buf: &mut [u8]) -> Result<bool, String> {
        let mut filled = 0;
        while filled < buf.len() {
            let n = self.read(&mut buf[filled..]).map_err(|e| e.to_string())?;
            if n == 0 {
                if filled == 0 {
                    return Ok(false);
                }
                return Err("压缩包内容被意外截断".into());
            }
            filled += n;
        }
        Ok(true)
    }

    fn skip_exact(&mut self, mut count: u64) -> Result<(), String> {
        let mut discard = [0u8; 8192];
        while count > 0 {
            let step = (count as usize).min(discard.len());
            let n = self.read(&mut discard[..step]).map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("压缩包内容不完整（EOF 提前结束）".into());
            }
            count -= n as u64;
        }
        Ok(())
    }

    fn drain_to_eof(&mut self) -> Result<(), String> {
        let mut discard = [0u8; 8192];
        loop {
            let n = self.read(&mut discard).map_err(|e| e.to_string())?;
            if n == 0 {
                return Ok(());
            }
        }
    }
}

impl<R: Read> Read for BoundedStream<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let max_read = (buf.len() as u64).min(self.remaining.saturating_add(1)) as usize;
        let n = self.inner.read(&mut buf[..max_read])?;
        if (n as u64) > self.remaining {
            self.kill_child_group();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "压缩包解压体积超过 128 MiB 安全上限（疑似解压炸弹，已强制终止）",
            ));
        }
        self.remaining -= n as u64;
        self.total_read += n as u64;
        Ok(n)
    }
}

fn parse_octal_field(field: &[u8]) -> Result<u64, String> {
    if field.first().is_some_and(|b| (b & 0x80) != 0) {
        return Err("拒绝 tar 扩展二进制超大尺寸字段".into());
    }
    let trimmed: Vec<u8> = field
        .iter()
        .copied()
        .take_while(|&b| b != 0)
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if trimmed.is_empty() {
        return Ok(0);
    }
    let mut val = 0u64;
    for b in trimmed {
        if !(b'0'..=b'7').contains(&b) {
            return Err("tar 头部八进制字段非法".into());
        }
        val = val
            .checked_mul(8)
            .and_then(|v| v.checked_add((b - b'0') as u64))
            .ok_or("tar 文件大小溢出")?;
    }
    Ok(val)
}

fn verify_tar_checksum(hdr: &[u8; 512]) -> Result<(), String> {
    let stored = parse_octal_field(&hdr[148..156])?;
    let mut unsigned_sum = 0u64;
    let mut signed_sum = 0i64;
    for (i, &b) in hdr.iter().enumerate() {
        let effective = if (148..156).contains(&i) { b' ' } else { b };
        unsigned_sum += effective as u64;
        signed_sum += (effective as i8) as i64;
    }
    if stored == unsigned_sum || (stored as i64) == signed_sum {
        Ok(())
    } else {
        Err("tar 头部校验和不匹配，压缩包已损坏或非标准 tar.gz".into())
    }
}

fn cstr_field(bytes: &[u8]) -> Result<String, String> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end])
        .map(|s| s.to_string())
        .map_err(|_| "tar 路径包含非 UTF-8 字节".to_string())
}

fn validate_tar_entry_path(raw: &str) -> Result<Vec<String>, String> {
    if raw.is_empty()
        || raw.starts_with('/')
        || raw.contains('\\')
        || raw.contains('\0')
        || raw.bytes().any(|b| b < 0x20 || b == 0x7f)
    {
        return Err(format!("安全拦截：压缩包包含非法路径或绝对路径 ({})", logger::truncate_utf8(raw, 64)));
    }
    let mut parts = Vec::new();
    for seg in raw.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return Err(format!("安全拦截：压缩包包含路径穿越条目 ({})", logger::truncate_utf8(raw, 64)));
        }
        parts.push(seg.to_string());
    }
    Ok(parts)
}

fn parse_pax_records(data: &[u8]) -> (Option<String>, Option<u64>) {
    let mut path = None;
    let mut size = None;
    let mut i = 0usize;
    while i < data.len() {
        let Some(sp) = data[i..].iter().position(|&b| b == b' ') else { break };
        let Ok(len_str) = std::str::from_utf8(&data[i..i + sp]) else { break };
        let Ok(rec_len) = len_str.parse::<usize>() else { break };
        if rec_len <= sp + 1 || i.checked_add(rec_len).is_none_or(|end| end > data.len()) {
            break;
        }
        let body = &data[i + sp + 1..i + rec_len];
        let body = body.strip_suffix(b"\n").unwrap_or(body);
        if let Some(eq) = body.iter().position(|&b| b == b'=') {
            let key = &body[..eq];
            let val = &body[eq + 1..];
            if key == b"path" {
                if let Ok(s) = std::str::from_utf8(val) {
                    path = Some(s.to_string());
                }
            } else if key == b"size" {
                if let Ok(s) = std::str::from_utf8(val) {
                    if let Ok(n) = s.parse::<u64>() {
                        size = Some(n);
                    }
                }
            }
        }
        i += rec_len;
    }
    (path, size)
}

pub struct ExtractedBinary {
    pub size: u64,
    pub sha256: String,
    pub tar_entries: usize,
    pub uncompressed_bytes: u64,
}

struct GzipChildGuard {
    child: Option<std::process::Child>,
    pgid: i32,
    done_tx: Option<mpsc::Sender<()>>,
    watchdog: Option<std::thread::JoinHandle<()>>,
}

impl GzipChildGuard {
    fn kill_group(&self) {
        if self.pgid > 1 {
            unsafe {
                libc::kill(-self.pgid, libc::SIGKILL);
            }
        }
    }

    fn finish(mut self, kill_first: bool) -> io::Result<std::process::ExitStatus> {
        if kill_first {
            self.kill_group();
        }
        if let Some(tx) = self.done_tx.take() {
            let _ = tx.send(());
        }
        let status = match self.child.take() {
            Some(mut c) => c.wait(),
            None => Err(io::Error::other("gzip 进程句柄缺失")),
        };
        if let Some(wd) = self.watchdog.take() {
            let _ = wd.join();
        }
        status
    }
}

impl Drop for GzipChildGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            self.kill_group();
            let _ = c.kill();
            let _ = c.wait();
        }
        if let Some(tx) = self.done_tx.take() {
            let _ = tx.send(());
        }
        if let Some(wd) = self.watchdog.take() {
            let _ = wd.join();
        }
    }
}

/// 在沙箱中以有界流式方式仅提取单个 `vane` 二进制文件，其余文件永不落盘
pub fn extract_vane_binary_from_targz(
    archive_path: &Path,
    dest_bin_path: &Path,
    min_bin_bytes: u64,
    max_uncompressed_bytes: u64,
) -> Result<ExtractedBinary, String> {
    // 1. 校验 Gzip 文件魔数
    {
        let mut f = File::open(archive_path).map_err(|e| format!("无法打开上传压缩包: {e}"))?;
        let mut magic = [0u8; 2];
        f.read_exact(&mut magic)
            .map_err(|_| "上传文件过小，不是有效的 .tar.gz 压缩包")?;
        if magic != [0x1f, 0x8b] {
            return Err("文件格式非法：仅接受 Gzip 压缩的 .tar.gz / .tgz 发布包".into());
        }
    }

    // 2. 在独立进程组与无敏感环境变量下启动 `gzip -dc`
    let mut cmd = Command::new("gzip");
    cmd.args(["-dc", "--"])
        .arg(archive_path)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("无法调用系统 gzip 解压工具: {e}"))?;
    let child_pgid = child.id() as i32;
    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => {
            if child_pgid > 1 {
                unsafe {
                    libc::kill(-child_pgid, libc::SIGKILL);
                }
            }
            let _ = child.kill();
            let _ = child.wait();
            return Err("无法接管 gzip 输出流".into());
        }
    };

    // 超时看门狗：30 秒内未完成直接 SIGKILL 整个子进程组
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let watchdog = std::thread::spawn(move || {
        if done_rx.recv_timeout(Duration::from_secs(GZIP_TIMEOUT_SECS)).is_err() && child_pgid > 1 {
            unsafe {
                libc::kill(-child_pgid, libc::SIGKILL);
            }
        }
    });

    // Drop 守卫必须早于 reader 声明，确保即使在解析发生 panic/unwind 时先关闭管道再强杀并 wait() 回收 gzip
    let gzip_guard = GzipChildGuard {
        child: Some(child),
        pgid: child_pgid,
        done_tx: Some(done_tx),
        watchdog: Some(watchdog),
    };

    let mut reader = BoundedStream {
        inner: stdout,
        remaining: max_uncompressed_bytes,
        total_read: 0,
        child_pgid,
    };

    let parse_res = (|| -> Result<(u64, String, usize), String> {
        let mut hdr = [0u8; 512];
        let mut entry_count = 0usize;
        let mut zero_blocks = 0u8;
        let mut pending_long_name: Option<String> = None;
        let mut pending_pax_path: Option<String> = None;
        let mut pending_pax_size: Option<u64> = None;
        let mut extracted: Option<(u64, String)> = None;

        while reader.read_exact_or_eof(&mut hdr)? {
            if hdr.iter().all(|&b| b == 0) {
                zero_blocks += 1;
                if zero_blocks >= 2 {
                    break;
                }
                continue;
            }
            zero_blocks = 0;
            entry_count += 1;
            if entry_count > MAX_TAR_ENTRIES {
                return Err(format!("安全拦截：压缩包内条目数超过 {MAX_TAR_ENTRIES} 个安全上限"));
            }
            verify_tar_checksum(&hdr)?;

            let typeflag = hdr[156];
            let hdr_size = parse_octal_field(&hdr[124..136])?;
            let padded_pad = (512 - (hdr_size % 512)) % 512;

            // PAX / GNU LongName 扩展头
            if typeflag == b'L' {
                if hdr_size > 4096 {
                    return Err("安全拦截：tar 长文件名元数据超过上限".into());
                }
                let mut buf = vec![0u8; hdr_size as usize];
                reader.read_exact_or_eof(&mut buf)?;
                reader.skip_exact(padded_pad)?;
                let s = cstr_field(&buf)?;
                pending_long_name = Some(s);
                continue;
            }
            if typeflag == b'x' || typeflag == b'g' {
                if hdr_size > 8192 {
                    return Err("安全拦截：tar PAX 扩展头超过上限".into());
                }
                let mut buf = vec![0u8; hdr_size as usize];
                reader.read_exact_or_eof(&mut buf)?;
                reader.skip_exact(padded_pad)?;
                if typeflag == b'x' {
                    let (p, sz) = parse_pax_records(&buf);
                    if p.is_some() {
                        pending_pax_path = p;
                    }
                    if sz.is_some() {
                        pending_pax_size = sz;
                    }
                }
                continue;
            }

            // 严禁符号链接、硬链接、字符/块设备与管道文件
            if matches!(typeflag, b'1' | b'2' | b'3' | b'4' | b'6') {
                return Err(format!(
                    "安全拦截：压缩包包含禁止的特殊文件类型 (typeflag='{}')，拒绝符号链接/硬链接/设备文件",
                    typeflag as char
                ));
            }

            let raw_name = if let Some(p) = pending_pax_path.take() {
                pending_long_name = None;
                p
            } else if let Some(l) = pending_long_name.take() {
                l
            } else {
                let name = cstr_field(&hdr[0..100])?;
                let prefix = cstr_field(&hdr[345..500])?;
                if prefix.is_empty() { name } else { format!("{prefix}/{name}") }
            };
            let entry_size = pending_pax_size.take().unwrap_or(hdr_size);
            let entry_pad = (512 - (entry_size % 512)) % 512;

            let segments = validate_tar_entry_path(&raw_name)?;

            if typeflag == b'5' {
                // 目录条目，仅校验路径不创建磁盘目录
                if entry_size > 0 {
                    reader.skip_exact(entry_size)?;
                    reader.skip_exact(entry_pad)?;
                }
                continue;
            }

            if typeflag != b'0' && typeflag != 0 {
                return Err(format!("安全拦截：压缩包包含不受支持的 tar 条目类型 ({typeflag})"));
            }

            let is_vane_binary = (segments.len() == 1 && segments[0] == "vane")
                || (segments.len() == 2 && segments[1] == "vane");

            if is_vane_binary {
                if extracted.is_some() {
                    return Err("安全拦截：压缩包内包含多个 vane 可执行文件".into());
                }
                if entry_size < min_bin_bytes {
                    return Err(format!(
                        "安全拦截：vane 文件体积过小（{} B < {} B），疑似损坏或伪造脚本",
                        entry_size, min_bin_bytes
                    ));
                }
                if entry_size > MAX_BINARY_BYTES {
                    return Err(format!(
                        "安全拦截：vane 文件体积超过 {} MiB 上限",
                        MAX_BINARY_BYTES / (1024 * 1024)
                    ));
                }
                let mut out_file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(dest_bin_path)
                    .map_err(|e| format!("创建临时二进制文件失败: {e}"))?;
                let mut hasher = Context::new(&SHA256);
                let mut left = entry_size;
                let mut buf = [0u8; 16 * 1024];
                while left > 0 {
                    let want = (left as usize).min(buf.len());
                    let n = reader.read(&mut buf[..want]).map_err(|e| e.to_string())?;
                    if n == 0 {
                        return Err("压缩包中 vane 文件内容被截断".into());
                    }
                    hasher.update(&buf[..n]);
                    out_file
                        .write_all(&buf[..n])
                        .map_err(|e| format!("写入临时二进制文件失败: {e}"))?;
                    left -= n as u64;
                }
                out_file
                    .sync_all()
                    .map_err(|e| format!("落盘同步临时二进制文件失败: {e}"))?;
                reader.skip_exact(entry_pad)?;
                extracted = Some((entry_size, hex_encode(hasher.finish().as_ref())));
            } else {
                // 其他配套文件（README / LICENSE / config.example.toml 等）永不落盘
                reader.skip_exact(entry_size)?;
                reader.skip_exact(entry_pad)?;
            }
        }

        // 排空尾部填充块以让 gzip 完成 CRC32 + ISIZE 校验
        reader.drain_to_eof()?;

        let (bin_size, bin_sha) =
            extracted.ok_or_else(|| "压缩包内未找到 vane 可执行文件（需位于根目录或顶层子目录）".to_string())?;
        Ok((bin_size, bin_sha, entry_count))
    })();

    let uncompressed_bytes = reader.total_read;
    let failed = parse_res.is_err();
    drop(reader);
    let status = gzip_guard.finish(failed);

    let (size, sha256, tar_entries) = parse_res?;
    match status {
        Ok(s) if s.success() => Ok(ExtractedBinary {
            size,
            sha256,
            tar_entries,
            uncompressed_bytes,
        }),
        _ => Err("Gzip 流完整性（CRC32）校验失败或解压进程异常退出".into()),
    }
}

// ---------------------------------------------------------------------------
// 二进制文件头（ELF / Mach-O）平台与架构强校验（执行前拦截）
// ---------------------------------------------------------------------------

pub fn verify_binary_header_for_current_platform(bin_path: &Path) -> Result<(), String> {
    let mut f = File::open(bin_path).map_err(|e| format!("读取待检二进制头失败: {e}"))?;
    let mut header = [0u8; 256];
    let n = f.read(&mut header).map_err(|e| format!("读取二进制文件头失败: {e}"))?;
    verify_binary_header_bytes(&header[..n])
}

pub fn verify_binary_header_bytes(header: &[u8]) -> Result<(), String> {
    if header.starts_with(b"#!") {
        return Err("安全拦截：拒绝脚本文件（#!），仅接受原生编译的 Vane 二进制程序".into());
    }
    #[cfg(target_os = "linux")]
    {
        if header.len() < 20 || &header[0..4] != b"\x7fELF" {
            return Err("安全拦截：提取的 vane 不是有效的 Linux ELF 可执行程序".into());
        }
        let expected_class: u8 = if cfg!(target_pointer_width = "64") { 2 } else { 1 };
        let expected_data: u8 = if cfg!(target_endian = "little") { 1 } else { 2 };
        if header[4] != expected_class {
            return Err("架构不匹配：ELF 位宽（32/64位）与当前系统不一致".into());
        }
        if header[5] != expected_data {
            return Err("架构不匹配：ELF 字节序与当前 CPU 不一致".into());
        }
        let read_u16 = |b: &[u8]| -> u16 {
            if expected_data == 1 {
                u16::from_le_bytes([b[0], b[1]])
            } else {
                u16::from_be_bytes([b[0], b[1]])
            }
        };
        let e_type = read_u16(&header[16..18]);
        if e_type != 2 && e_type != 3 {
            return Err("安全拦截：ELF 文件不是可执行程序（拒绝共享库或中间目标文件）".into());
        }
        let e_machine = read_u16(&header[18..20]);
        let expected_machine: Option<u16> = match std::env::consts::ARCH {
            "x86_64" => Some(62),
            "aarch64" => Some(183),
            "arm" => Some(40),
            "x86" => Some(3),
            "riscv64" => Some(243),
            "mips" | "mips64" => Some(8),
            _ => None,
        };
        if let Some(exp) = expected_machine {
            if e_machine != exp {
                return Err(format!(
                    "CPU 架构不匹配：当前设备为 {}，安装包 ELF e_machine={}",
                    std::env::consts::ARCH,
                    e_machine
                ));
            }
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        if header.len() < 28 {
            return Err("安全拦截：提取的 vane 文件头不完整，不是有效的 macOS Mach-O 程序".into());
        }
        let expected_cputype: Option<u32> = match std::env::consts::ARCH {
            "aarch64" => Some(0x0100_000C),
            "x86_64" => Some(0x0100_0007),
            _ => None,
        };
        let magic_le = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let magic_be = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
        if magic_le == 0xFEED_FACF {
            let cputype = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
            let filetype = u32::from_le_bytes([header[12], header[13], header[14], header[15]]);
            if filetype != 2 {
                return Err("安全拦截：Mach-O 文件不是可执行程序（MH_EXECUTE）".into());
            }
            if let Some(exp) = expected_cputype {
                if cputype != exp {
                    return Err(format!(
                        "CPU 架构不匹配：当前设备为 macOS/{}，安装包 cputype=0x{:x}",
                        std::env::consts::ARCH,
                        cputype
                    ));
                }
            }
            Ok(())
        } else if magic_be == 0xCAFE_BABE {
            let nfat = u32::from_be_bytes([header[4], header[5], header[6], header[7]]).min(8) as usize;
            let mut matched = false;
            for i in 0..nfat {
                let off = 8 + i * 20;
                if off + 4 <= header.len() {
                    let cputype =
                        u32::from_be_bytes([header[off], header[off + 1], header[off + 2], header[off + 3]]);
                    if expected_cputype.is_none_or(|exp| cputype == exp) {
                        matched = true;
                        break;
                    }
                }
            }
            if !matched {
                return Err(format!("CPU 架构不匹配：Universal Mach-O 不含 {} 切片", std::env::consts::ARCH));
            }
            Ok(())
        } else {
            Err("安全拦截：提取的 vane 不是有效的 macOS Mach-O 可执行程序（可能是 Linux ELF 或其他平台包）".into())
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = header;
        Err("当前操作系统不支持在线二进制自更新校验".into())
    }
}

// ---------------------------------------------------------------------------
// 独立 Ed25519 密码学签名校验（在任何解压、chmod +x 或探测执行前强制阻断）
// ---------------------------------------------------------------------------

const NOBODY_UID: libc::uid_t = 65534;
const NOBODY_GID: libc::gid_t = 65534;

fn hex_decode_exact<const N: usize>(raw: &str) -> Option<[u8; N]> {
    if raw.len() != N * 2 || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn b64_decode_exact<const N: usize>(raw: &str) -> Option<[u8; N]> {
    let engines = [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ];
    for eng in engines {
        if let Ok(bytes) = eng.decode(raw) {
            if bytes.len() == N {
                let mut out = [0u8; N];
                out.copy_from_slice(&bytes);
                return Some(out);
            }
        }
    }
    None
}

pub fn parse_ed25519_public_key(raw: &str) -> Result<[u8; 32], String> {
    let trimmed = raw.trim();
    let cleaned = trimmed
        .strip_prefix("ed25519:")
        .or_else(|| trimmed.strip_prefix("ED25519:"))
        .unwrap_or(trimmed)
        .trim();
    if cleaned.is_empty() {
        return Err("未配置更新签名 Ed25519 公钥".into());
    }
    hex_decode_exact::<32>(cleaned)
        .or_else(|| b64_decode_exact::<32>(cleaned))
        .ok_or_else(|| "Ed25519 公钥格式无效（需 32 字节 Base64 或 64 位 Hex）".to_string())
}

pub fn parse_ed25519_signature(raw: &str) -> Result<[u8; 64], String> {
    let trimmed = raw.trim();
    let cleaned = trimmed
        .strip_prefix("ed25519:")
        .or_else(|| trimmed.strip_prefix("ED25519:"))
        .unwrap_or(trimmed)
        .trim();
    if cleaned.is_empty() {
        return Err("缺少更新包 Ed25519 签名".into());
    }
    b64_decode_exact::<64>(cleaned)
        .or_else(|| hex_decode_exact::<64>(cleaned))
        .ok_or_else(|| "Ed25519 签名格式无效（需 64 字节 Base64 或 128 位 Hex）".to_string())
}

/// 对上传压缩包原始字节强制校验独立 Ed25519 签名，并返回经校验的压缩包 SHA-256 摘要
pub fn verify_archive_ed25519_signature(
    archive_path: &Path,
    expected_signature_b64: Option<&str>,
    signing_public_key: &str,
) -> Result<String, String> {
    let pk_bytes = parse_ed25519_public_key(signing_public_key)
        .map_err(|_| "安全拦截：未配置有效的发布签名 Ed25519 公钥，拒绝未签名更新包".to_string())?;
    let sig_raw = expected_signature_b64
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "安全拦截：缺少独立 Ed25519 签名，拒绝未签名更新包".to_string())?;
    let sig_bytes = parse_ed25519_signature(sig_raw)?;

    let meta = fs::symlink_metadata(archive_path).map_err(|e| format!("读取待验签压缩包元信息失败: {e}"))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err("安全拦截：上传压缩包路径非法（拒绝符号链接或非常规文件）".into());
    }
    if meta.len() == 0 || meta.len() > MAX_UPLOAD_ARCHIVE_BYTES {
        return Err(format!(
            "安全拦截：上传压缩包大小非法（{} B，允许 1..={} B）",
            meta.len(),
            MAX_UPLOAD_ARCHIVE_BYTES
        ));
    }

    let f = File::open(archive_path).map_err(|e| format!("打开待验签压缩包失败: {e}"))?;
    let mut archive_bytes = Vec::with_capacity(meta.len() as usize);
    f.take(MAX_UPLOAD_ARCHIVE_BYTES + 1)
        .read_to_end(&mut archive_bytes)
        .map_err(|e| format!("读取待验签压缩包失败: {e}"))?;
    if archive_bytes.is_empty() || (archive_bytes.len() as u64) > MAX_UPLOAD_ARCHIVE_BYTES {
        return Err("安全拦截：压缩包大小超出验签安全上限".into());
    }

    UnparsedPublicKey::new(&ED25519, &pk_bytes)
        .verify(&archive_bytes, &sig_bytes)
        .map_err(|_| "安全拦截：Ed25519 密码学签名校验失败，压缩包已被篡改或签名不匹配".to_string())?;

    let mut hasher = Context::new(&SHA256);
    hasher.update(&archive_bytes);
    Ok(hex_encode(hasher.finish().as_ref()))
}

fn set_root_group_nobody_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let cpath = CString::new(path.as_os_str().as_bytes()).map_err(|_| "路径包含空字节".to_string())?;
    if unsafe { libc::chown(cpath.as_ptr(), 0, NOBODY_GID) } != 0 {
        return Err(format!("调整沙箱属组失败: {}", io::Error::last_os_error()));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|e| format!("设置沙箱降权访问权限失败: {e}"))
}

// ---------------------------------------------------------------------------
// 零敏感环境沙箱预检（version 版本/架构校验 + check 配置兼容性校验）
// ---------------------------------------------------------------------------

struct ProbeChildGuard {
    child: Option<std::process::Child>,
    pgid: i32,
}

impl Drop for ProbeChildGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            if self.pgid > 1 {
                unsafe {
                    libc::kill(-self.pgid, libc::SIGKILL);
                }
            }
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn run_isolated_probe(bin: &Path, args: &[&str], cwd: &Path) -> Result<(bool, String, String), String> {
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .current_dir(cwd)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            // 若主进程以 root (UID 0) 运行，在探测子进程中强制清空附加组并降权至 nobody (65534:65534)
            if libc::geteuid() == 0 {
                if libc::setgroups(0 as _, std::ptr::null()) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::setgid(NOBODY_GID) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::setuid(NOBODY_UID) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let child = cmd
        .spawn()
        .map_err(|e| format!("无法在沙箱中启动待检二进制（可能缺少动态库或 ABI 不兼容）: {e}"))?;
    let pgid = child.id() as i32;
    let mut guard = ProbeChildGuard {
        child: Some(child),
        pgid,
    };
    let deadline = Instant::now() + Duration::from_secs(PROBE_TIMEOUT_SECS);
    loop {
        let try_res = guard
            .child
            .as_mut()
            .ok_or_else(|| "沙箱预检子进程句柄缺失".to_string())?
            .try_wait();
        match try_res {
            Ok(Some(status)) => {
                // 清理可能派生出的同进程组子进程，再读取输出并标记已回收
                if pgid > 1 {
                    unsafe {
                        libc::kill(-pgid, libc::SIGKILL);
                    }
                }
                let mut child = guard.child.take().expect("child present");
                let _ = child.wait();
                let mut out = Vec::new();
                let mut err = Vec::new();
                if let Some(mut s) = child.stdout.take() {
                    let _ = s.by_ref().take(8192).read_to_end(&mut out);
                }
                if let Some(mut s) = child.stderr.take() {
                    let _ = s.by_ref().take(8192).read_to_end(&mut err);
                }
                return Ok((
                    status.success(),
                    String::from_utf8_lossy(&out).trim().to_string(),
                    String::from_utf8_lossy(&err).trim().to_string(),
                ));
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    drop(guard);
                    return Err(format!("待检程序预检超时（>{PROBE_TIMEOUT_SECS}s），已强制终止"));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => {
                drop(guard);
                return Err(format!("等待沙箱预检进程失败: {e}"));
            }
        }
    }
}

pub fn parse_vane_version_output(out: &str) -> Result<(String, String, String), String> {
    let line = out
        .lines()
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or("待检二进制未返回有效版本信息")?;
    let rest = line
        .strip_prefix("vane ")
        .ok_or_else(|| format!("版本输出格式不匹配（非 Vane 程序）: {}", logger::truncate_utf8(line, 80)))?;
    let (ver, plat_part) = rest
        .split_once(' ')
        .ok_or("版本输出缺少操作系统与架构标识")?;
    let plat = plat_part
        .trim()
        .strip_prefix('(')
        .and_then(|s| s.strip_suffix(')'))
        .ok_or("版本输出平台标识格式异常")?;
    let (os, arch) = plat.split_once('/').ok_or("版本输出缺少 os/arch 字段")?;
    if parse_semver(ver).is_none() {
        return Err(format!("待检二进制版本号非合法 SemVer: {ver}"));
    }
    Ok((ver.to_string(), os.to_string(), arch.to_string()))
}

#[derive(Clone, Debug, Serialize)]
pub struct ApplyUpdateResult {
    pub previous_version: String,
    pub new_version: String,
    pub os: String,
    pub arch: String,
    pub archive_sha256: String,
    pub binary_sha256: String,
    pub binary_size: u64,
    pub executable_path: String,
    pub backup_path: String,
    pub restart_required: bool,
}

fn copy_file_with_mode(src: &Path, dst: &Path, mode: u32) -> Result<(), String> {
    let mut r = File::open(src).map_err(|e| format!("打开源文件失败: {e}"))?;
    let mut w = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(dst)
        .map_err(|e| format!("创建目标文件失败: {e}"))?;
    io::copy(&mut r, &mut w).map_err(|e| format!("复制二进制数据失败: {e}"))?;
    w.sync_all().map_err(|e| format!("fsync 同步二进制失败: {e}"))?;
    Ok(())
}

pub fn apply_verified_binary_atomically(staged_bin: &Path, target_exe: &Path) -> Result<(PathBuf, PathBuf), String> {
    let resolved = fs::canonicalize(target_exe).unwrap_or_else(|_| target_exe.to_path_buf());
    let parent = resolved
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or("无法解析当前可执行文件所在目录")?;
    if !is_dir_writable(parent) {
        return Err(format!(
            "当前程序目录 {} 不可写（只读文件系统或权限不足），无法就地替换二进制",
            parent.display()
        ));
    }
    let staged_len = fs::metadata(staged_bin)
        .map_err(|e| format!("读取待安装二进制元信息失败: {e}"))?
        .len();
    if let Some(avail) = available_disk_bytes(parent) {
        let need = staged_len.saturating_mul(2).saturating_add(4 * 1024 * 1024);
        if avail < need {
            return Err(format!(
                "目标程序目录 {} 可用磁盘空间不足（剩余 {} MiB，需至少 {} MiB 用于备份与原子替换）",
                parent.display(),
                avail / (1024 * 1024),
                need / (1024 * 1024)
            ));
        }
    }

    let file_name = resolved
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("vane");
    let nonce = crate::config::random_nonce();
    let pid = std::process::id();

    // 1. 备份当前正在运行的可执行文件为 <exe>.bak（便于异常秒级回滚）
    let mut bak_os = resolved.as_os_str().to_owned();
    bak_os.push(".bak");
    let bak_path = PathBuf::from(bak_os);
    if resolved.exists() {
        let bak_tmp = parent.join(format!(".{file_name}.bak.{pid}.{nonce:016x}.tmp"));
        if let Err(e) = copy_file_with_mode(&resolved, &bak_tmp, 0o755) {
            let _ = fs::remove_file(&bak_tmp);
            return Err(format!("备份旧版二进制失败: {e}"));
        }
        if let Err(e) = fs::rename(&bak_tmp, &bak_path) {
            let _ = fs::remove_file(&bak_tmp);
            return Err(format!("落盘旧版备份文件失败: {e}"));
        }
    }

    // 2. 在同一挂载点写入新版临时文件并 sync_all -> 原子 rename 覆盖（不触发 ETXTBSY）
    let new_tmp = parent.join(format!(".{file_name}.new.{pid}.{nonce:016x}.tmp"));
    if let Err(e) = copy_file_with_mode(staged_bin, &new_tmp, 0o755) {
        let _ = fs::remove_file(&new_tmp);
        return Err(format!("写入新版程序到目标目录失败: {e}"));
    }
    if let Err(e) = fs::rename(&new_tmp, &resolved) {
        let _ = fs::remove_file(&new_tmp);
        return Err(format!("原子替换可执行文件失败: {e}"));
    }
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok((resolved, bak_path))
}

/// 完整手动上传包安全验证与原子更新流水线（强制独立 Ed25519 验签，在 `spawn_blocking` 中调用）
#[allow(clippy::too_many_arguments)]
pub fn verify_and_install_uploaded_archive_signed(
    sandbox: &TempSandboxDir,
    archive_path: &Path,
    archive_sha256: &str,
    expected_sha256: Option<&str>,
    expected_signature_b64: Option<&str>,
    signing_public_key: &str,
    config_path: &Path,
    target_exe: &Path,
) -> Result<ApplyUpdateResult, String> {
    // 1. 在任何解压、chmod +x 或子进程探测之前，强制校验独立 Ed25519 签名与压缩包实际 SHA-256
    let verified_sha256 =
        verify_archive_ed25519_signature(archive_path, expected_signature_b64, signing_public_key)?;
    if !archive_sha256.is_empty() && !verified_sha256.eq_ignore_ascii_case(archive_sha256) {
        return Err("上传压缩包内容在验签期间发生变更（SHA-256 不一致），已中止更新".into());
    }
    if let Some(exp) = expected_sha256 {
        if !exp.eq_ignore_ascii_case(&verified_sha256) {
            return Err(format!(
                "SHA-256 校验失败：上传文件摘要 ({}) 与预期 ({}) 不一致，已中止更新",
                verified_sha256, exp
            ));
        }
    }

    // 2. 解压炸弹防护 + 严格 tar 解析，仅提取单个 vane 二进制到临时沙箱目录
    let staged_bin = sandbox.path().join("vane");
    let extracted = extract_vane_binary_from_targz(
        archive_path,
        &staged_bin,
        MIN_BINARY_BYTES,
        MAX_UNCOMPRESSED_TAR_BYTES,
    )?;

    // 3. 在赋予可执行权限之前，先检验 ELF / Mach-O 文件头与当前系统 CPU 架构
    verify_binary_header_for_current_platform(&staged_bin)?;

    // 4. 设置只读可执行权限（root 下由 root:nobody 0750 授权给降权 nobody 探测且禁止写入），执行 `vane version`
    let running_as_root = unsafe { libc::geteuid() } == 0;
    if running_as_root {
        set_root_group_nobody_mode(sandbox.path(), 0o750)?;
        set_root_group_nobody_mode(&staged_bin, 0o750)?;
    } else {
        fs::set_permissions(&staged_bin, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("设置临时二进制执行权限失败: {e}"))?;
    }
    let (ok, stdout, stderr) = run_isolated_probe(&staged_bin, &["version"], sandbox.path())?;
    if !ok {
        return Err(format!(
            "新版本程序自检失败（可能 libc/内核 ABI 不兼容）: {}",
            logger::truncate_utf8(&stderr, 160)
        ));
    }
    let (new_ver, bin_os, bin_arch) = parse_vane_version_output(&stdout)?;
    if bin_os != current_os() || bin_arch != current_arch() {
        return Err(format!(
            "系统或架构不匹配：安装包为 {bin_os}/{bin_arch}，当前设备为 {}/{}",
            current_os(),
            current_arch()
        ));
    }

    // 5. 严格版本防降级：仅允许相同版本或更高版本
    if !is_same_or_newer_version(&new_ver, current_version())? {
        return Err(format!(
            "安全策略拒绝降级：上传版本 v{new_ver} 低于当前运行版本 v{}（仅允许同版本修复或更高版本更新）",
            current_version()
        ));
    }

    // 6. 拷贝当前 config.toml 到沙箱副本，调用新版 `vane check --config` 验证配置前向兼容性（完成后立即清理副本）
    if config_path.is_file() {
        let cfg_copy = sandbox.path().join("check-config.toml");
        copy_file_with_mode(config_path, &cfg_copy, 0o600)?;
        if running_as_root {
            set_root_group_nobody_mode(&cfg_copy, 0o640)?;
        }
        let cfg_arg = cfg_copy.to_string_lossy().into_owned();
        let probe_res = run_isolated_probe(&staged_bin, &["check", "--config", &cfg_arg], sandbox.path());
        let _ = fs::remove_file(&cfg_copy);
        let (chk_ok, _chk_out, chk_err) = probe_res?;
        if !chk_ok {
            return Err(format!(
                "新版本配置兼容性预检未通过（已保留旧版本未替换）: {}",
                logger::truncate_utf8(&chk_err, 200)
            ));
        }
    }

    // 7. 备份旧二进制 + 同挂载点原子 rename 替换
    let (resolved_exe, backup_path) = apply_verified_binary_atomically(&staged_bin, target_exe)?;

    Ok(ApplyUpdateResult {
        previous_version: current_version().to_string(),
        new_version: new_ver,
        os: bin_os,
        arch: bin_arch,
        archive_sha256: verified_sha256,
        binary_sha256: extracted.sha256,
        binary_size: extracted.size,
        executable_path: resolved_exe.display().to_string(),
        backup_path: backup_path.display().to_string(),
        restart_required: true,
    })
}

/// 向后兼容入口：未提供独立 Ed25519 签名与受信任公钥时默认失败关闭（Fail-Closed），
/// 调用方应迁移至 `verify_and_install_uploaded_archive_signed` 并传入管理员配置的发布公钥与签名。
pub fn verify_and_install_uploaded_archive(
    sandbox: &TempSandboxDir,
    archive_path: &Path,
    archive_sha256: &str,
    expected_sha256: Option<&str>,
    config_path: &Path,
    target_exe: &Path,
) -> Result<ApplyUpdateResult, String> {
    verify_and_install_uploaded_archive_signed(
        sandbox,
        archive_path,
        archive_sha256,
        expected_sha256,
        None,
        "",
        config_path,
        target_exe,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tar_header(name: &str, size: u64, typeflag: u8) -> [u8; 512] {
        let mut hdr = [0u8; 512];
        let nb = name.as_bytes();
        hdr[..nb.len().min(100)].copy_from_slice(&nb[..nb.len().min(100)]);
        hdr[100..108].copy_from_slice(b"0000755\0");
        hdr[108..116].copy_from_slice(b"0000000\0");
        hdr[116..124].copy_from_slice(b"0000000\0");
        let sz = format!("{:011o}\0", size);
        hdr[124..136].copy_from_slice(sz.as_bytes());
        hdr[136..148].copy_from_slice(b"00000000000\0");
        hdr[148..156].fill(b' ');
        hdr[156] = typeflag;
        hdr[257..263].copy_from_slice(b"ustar\0");
        hdr[263..265].copy_from_slice(b"00");
        let sum: u64 = hdr.iter().map(|&b| b as u64).sum();
        let csum = format!("{:06o}\0 ", sum);
        hdr[148..156].copy_from_slice(csum.as_bytes());
        hdr
    }

    fn build_targz(entries: &[(&str, u8, &[u8])], out_path: &Path) {
        let mut tar_bytes = Vec::new();
        for (name, tf, data) in entries {
            let hdr = make_tar_header(name, data.len() as u64, *tf);
            tar_bytes.extend_from_slice(&hdr);
            tar_bytes.extend_from_slice(data);
            let pad = (512 - (data.len() % 512)) % 512;
            tar_bytes.extend(std::iter::repeat_n(0u8, pad));
        }
        tar_bytes.extend(std::iter::repeat_n(0u8, 1024));

        let mut child = Command::new("gzip")
            .args(["-c"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("gzip required for test");
        child.stdin.as_mut().unwrap().write_all(&tar_bytes).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        fs::write(out_path, &out.stdout).unwrap();
    }

    #[test]
    fn semver_ordering_and_downgrade_protection() {
        assert_eq!(compare_semver("v0.2.0", "0.1.0"), Some(Ordering::Greater));
        assert_eq!(compare_semver("0.1.0", "0.1.0"), Some(Ordering::Equal));
        assert_eq!(compare_semver("0.0.9", "0.1.0"), Some(Ordering::Less));
        assert_eq!(compare_semver("0.2.0-rc.1", "0.2.0"), Some(Ordering::Less));
        assert_eq!(compare_semver("0.2.0-rc.2", "0.2.0-rc.1"), Some(Ordering::Greater));
        assert!(is_same_or_newer_version("0.1.0", "0.1.0").unwrap());
        assert!(is_same_or_newer_version("0.2.0", "0.1.0").unwrap());
        assert!(!is_same_or_newer_version("0.0.9", "0.1.0").unwrap());
        assert!(parse_semver("not-a-version").is_none());
    }

    #[test]
    fn parses_expected_sha256_and_checksums_file() {
        let h1 = "a".repeat(64);
        let h2 = "b".repeat(64);
        assert_eq!(parse_expected_sha256("", None).unwrap(), None);
        assert_eq!(parse_expected_sha256(&h1, None).unwrap(), Some(h1.clone()));
        assert_eq!(
            parse_expected_sha256(&format!("sha256:{}", h1.to_uppercase()), None).unwrap(),
            Some(h1.clone())
        );
        let multi = format!("{h1}  vane-v0.2.0-x86_64-unknown-linux-musl.tar.gz\n{h2}  vane-v0.2.0-aarch64-apple-darwin.tar.gz\n");
        assert_eq!(
            parse_expected_sha256(&multi, Some("vane-v0.2.0-aarch64-apple-darwin.tar.gz")).unwrap(),
            Some(h2)
        );
        assert!(parse_expected_sha256("not-hex", None).is_err());
    }

    #[test]
    fn validates_binary_headers_for_current_platform() {
        // 拒绝脚本文件
        assert!(verify_binary_header_bytes(b"#!/bin/sh\nrm -rf /\n").is_err());
        // 当前运行中的测试二进制本身一定符合当前平台架构
        let cur_exe = std::env::current_exe().unwrap();
        assert!(verify_binary_header_for_current_platform(&cur_exe).is_ok());

        // 构造错误架构头应被拦截
        #[cfg(target_os = "macos")]
        {
            let elf_hdr = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0\x02\0\x3e\0\0\0\0\0\0\0\0\0";
            assert!(verify_binary_header_bytes(elf_hdr).is_err());
        }
        #[cfg(target_os = "linux")]
        {
            let mut wrong_elf = [0u8; 32];
            wrong_elf[0..4].copy_from_slice(b"\x7fELF");
            wrong_elf[4] = if cfg!(target_pointer_width = "64") { 2 } else { 1 };
            wrong_elf[5] = 1;
            wrong_elf[16..18].copy_from_slice(&2u16.to_le_bytes());
            wrong_elf[18..20].copy_from_slice(&999u16.to_le_bytes()); // 非法 e_machine
            assert!(verify_binary_header_bytes(&wrong_elf).is_err());
        }
    }

    #[test]
    fn sandbox_tar_rejects_traversal_symlinks_and_gzip_bombs() {
        let sb = TempSandboxDir::create("vane-upd-test").unwrap();

        // 1. 路径穿越 ../evil 必须被拒绝
        let trav = sb.path().join("trav.tar.gz");
        build_targz(&[("../evil", b'0', b"bad"), ("vane", b'0', &[0u8; 4096])], &trav);
        let err = extract_vane_binary_from_targz(&trav, &sb.path().join("out1"), 1024, 1024 * 1024)
            .err()
            .unwrap();
        assert!(err.contains("路径穿越"), "unexpected err: {err}");

        // 2. 符号链接必须被拒绝
        let sym = sb.path().join("sym.tar.gz");
        build_targz(&[("link", b'2', b""), ("vane", b'0', &[0u8; 4096])], &sym);
        let err = extract_vane_binary_from_targz(&sym, &sb.path().join("out2"), 1024, 1024 * 1024)
            .err()
            .unwrap();
        assert!(err.contains("符号链接"), "unexpected err: {err}");

        // 3. 解压炸弹：全零高压缩率文件超出解压硬上限时必须中止
        let bomb = sb.path().join("bomb.tar.gz");
        let big_zeros = vec![0u8; 256 * 1024];
        build_targz(&[("vane", b'0', &big_zeros)], &bomb);
        let err = extract_vane_binary_from_targz(&bomb, &sb.path().join("out3"), 1024, 64 * 1024)
            .err()
            .unwrap();
        assert!(err.contains("解压炸弹") || err.contains("上限"), "unexpected err: {err}");

        // 4. 正常压缩包仅提取 vane，附带的 README/脚本不落盘
        let ok_tgz = sb.path().join("ok.tar.gz");
        let payload = vec![0x42u8; 4096];
        build_targz(
            &[
                ("README.md", b'0', b"hello"),
                ("scripts/install.sh", b'0', b"#!/bin/sh\necho hi\n"),
                ("vane", b'0', &payload),
            ],
            &ok_tgz,
        );
        let dst = sb.path().join("vane-extracted");
        let info = extract_vane_binary_from_targz(&ok_tgz, &dst, 1024, 1024 * 1024).unwrap();
        assert_eq!(info.size, 4096);
        assert_eq!(info.tar_entries, 3);
        assert!(dst.is_file());
        assert!(!sb.path().join("README.md").exists());
        assert!(!sb.path().join("scripts").exists());
    }

    #[test]
    fn parses_github_release_payload_and_picks_matching_asset() {
        let j = serde_json::json!({
            "tag_name": "v0.2.0",
            "name": "Vane v0.2.0",
            "html_url": "https://github.com/xinghaix/vane/releases/tag/v0.2.0",
            "published_at": "2026-11-25T08:00:00Z",
            "body": "Security fixes & inbox",
            "assets": [
                {
                    "name": "vane-v0.2.0-aarch64-unknown-linux-musl.tar.gz",
                    "browser_download_url": "https://github.com/xinghaix/vane/releases/download/v0.2.0/vane-v0.2.0-aarch64-unknown-linux-musl.tar.gz"
                },
                {
                    "name": "SHA256SUMS",
                    "browser_download_url": "https://github.com/xinghaix/vane/releases/download/v0.2.0/SHA256SUMS"
                }
            ]
        });
        let info = parse_github_release_json(&j, "aarch64-unknown-linux-musl").unwrap();
        assert_eq!(info.version, "0.2.0");
        assert_eq!(info.asset_name, "vane-v0.2.0-aarch64-unknown-linux-musl.tar.gz");
        assert!(info.checksums_url.ends_with("/SHA256SUMS"));
    }

    #[test]
    fn temp_sandbox_dir_is_created_with_0700_and_pax_parser_handles_malformed_records() {
        let sb = TempSandboxDir::create("vane-perm-test").unwrap();
        let mode = fs::metadata(sb.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);

        // VANE-L10: 畸形 PAX 记录长度（rec_len <= sp + 1、整数溢出、截断）不得触发切片 panic
        for bad in [
            b"0 \n".as_slice(),
            b"1 a=b\n".as_slice(),
            b"2 path=foo\n".as_slice(),
            b"18446744073709551615 path=overflow\n".as_slice(),
            b"999999 path=trunc\n".as_slice(),
            b"12 path=ok\n1 x=y\n".as_slice(),
        ] {
            let _ = parse_pax_records(bad);
        }
        let (p, sz) = parse_pax_records(b"13 path=vane\n13 size=4096\n");
        assert_eq!(p.as_deref(), Some("vane"));
        assert_eq!(sz, Some(4096));
    }

    #[test]
    fn ed25519_archive_signature_verification_accepts_valid_and_rejects_unsigned_or_tampered() {
        use ring::rand::SystemRandom;
        use ring::signature::{Ed25519KeyPair, KeyPair};

        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pub_b64 = base64::engine::general_purpose::STANDARD.encode(keypair.public_key().as_ref());
        let pub_hex = hex_encode(keypair.public_key().as_ref());

        let sb = TempSandboxDir::create("vane-sig-test").unwrap();
        let archive = sb.path().join("release.tar.gz");
        build_targz(&[("vane", b'0', &[0x42u8; 4096])], &archive);
        let raw_bytes = fs::read(&archive).unwrap();

        let sig = keypair.sign(&raw_bytes);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.as_ref());
        let sig_hex = hex_encode(sig.as_ref());

        // 1. 合法签名（Base64 与 Hex 格式公钥/签名）均通过校验并返回正确 SHA-256
        let sha1 = verify_archive_ed25519_signature(&archive, Some(&sig_b64), &pub_b64).unwrap();
        let sha2 = verify_archive_ed25519_signature(&archive, Some(&sig_hex), &pub_hex).unwrap();
        assert_eq!(sha1, sha2);

        // 2. 缺少签名或未配置公钥必须失败关闭，且不得提取/执行任何文件
        let fake_cfg = sb.path().join("nonexistent.toml");
        let fake_exe = sb.path().join("target_vane");
        assert!(verify_and_install_uploaded_archive(&sb, &archive, &sha1, None, &fake_cfg, &fake_exe).is_err());
        assert!(verify_and_install_uploaded_archive_signed(
            &sb,
            &archive,
            &sha1,
            None,
            None,
            &pub_b64,
            &fake_cfg,
            &fake_exe
        )
        .is_err());
        assert!(verify_and_install_uploaded_archive_signed(
            &sb,
            &archive,
            &sha1,
            None,
            Some(&sig_b64),
            "",
            &fake_cfg,
            &fake_exe
        )
        .is_err());
        assert!(!sb.path().join("vane").exists(), "unsigned archive must never be extracted");

        // 3. 篡改压缩包 1 字节必须被 Ed25519 验签拒绝
        let mut tampered = raw_bytes.clone();
        tampered[0] ^= 0xff;
        let tampered_path = sb.path().join("tampered.tar.gz");
        fs::write(&tampered_path, &tampered).unwrap();
        let err = verify_archive_ed25519_signature(&tampered_path, Some(&sig_b64), &pub_b64).unwrap_err();
        assert!(err.contains("Ed25519") || err.contains("签名"), "unexpected err: {err}");

        // 4. 错误公钥必须被拒绝
        let other_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let other_kp = Ed25519KeyPair::from_pkcs8(other_pkcs8.as_ref()).unwrap();
        let other_pub = base64::engine::general_purpose::STANDARD.encode(other_kp.public_key().as_ref());
        assert!(verify_archive_ed25519_signature(&archive, Some(&sig_b64), &other_pub).is_err());
    }
}
