//! 双栈源地址防爆破封禁表（IPv4 /32 + IPv6 /64 归一化，定长上限 1024 条，饱和 Fail-Closed 与按域隔离）。
use crate::logger;
use crate::net::dual_stack::BanKey;
use serde::Serialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const MAX_TRACKED_KEYS: usize = 1024;
pub const MAX_FAIL2BAN_SCOPES: usize = 64;
const FAILURE_WINDOW: Duration = Duration::from_secs(300);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureOutcome {
    Tracked,
    NewlyBanned,
    SaturatedFailClosed,
}

#[derive(Clone, Debug)]
struct Entry {
    failures: u32,
    first_failure: Instant,
    last_seen: Instant,
    banned_until: Option<Instant>,
    banned_at_unix: u64,
    reason: String,
    kernel_offloaded: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct BanRecord {
    pub cidr: String,
    pub failures: u32,
    pub banned_at_unix: u64,
    pub remaining_secs: u64,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ScopedBanRecord {
    pub scope: String,
    #[serde(flatten)]
    pub record: BanRecord,
}

pub struct Fail2Ban {
    entries: Mutex<HashMap<BanKey, Entry>>,
}

impl Default for Fail2Ban {
    fn default() -> Self {
        Self::new()
    }
}

impl Fail2Ban {
    pub fn new() -> Self {
        Self { entries: Mutex::new(HashMap::with_capacity(128)) }
    }

    pub fn is_banned(&self, ip: IpAddr) -> bool {
        self.is_key_banned(BanKey::from_peer(ip))
    }

    pub fn is_key_banned(&self, key: BanKey) -> bool {
        let Ok(mut map) = self.entries.lock() else { return false };
        let now = Instant::now();
        if let Some(entry) = map.get_mut(&key) {
            if let Some(until) = entry.banned_until {
                if now < until {
                    return true;
                }
                entry.banned_until = None;
                entry.failures = 0;
                entry.kernel_offloaded = false;
            }
        }
        false
    }

    /// 标记某个活跃封禁已确认成功下发至内核防火墙（仅在此条件下表满时才允许按最早到期淘汰）。
    pub fn mark_kernel_offloaded(&self, key: BanKey) -> bool {
        let Ok(mut map) = self.entries.lock() else { return false };
        let now = Instant::now();
        if let Some(entry) = map.get_mut(&key) {
            if entry.banned_until.is_some_and(|u| now < u) {
                entry.kernel_offloaded = true;
                return true;
            }
        }
        false
    }

    /// 当追踪表已被活跃封禁占满且无任何已确认内核卸载的条目可安全淘汰时返回 true。
    pub fn is_saturated(&self) -> bool {
        let Ok(mut map) = self.entries.lock() else { return true };
        let now = Instant::now();
        Self::prune_expired_locked(&mut map, now, FAILURE_WINDOW);
        Self::is_saturated_locked(&map)
    }

    /// 综合封禁与表满 Fail-Closed 判断：若该来源已被封禁，或表已饱和无法接纳新追踪条目，均返回 true（应拒绝返回 429）。
    pub fn is_key_blocked(&self, key: BanKey) -> bool {
        let Ok(mut map) = self.entries.lock() else { return true };
        let now = Instant::now();
        if let Some(entry) = map.get_mut(&key) {
            if let Some(until) = entry.banned_until {
                if now < until {
                    return true;
                }
                entry.banned_until = None;
                entry.failures = 0;
                entry.kernel_offloaded = false;
                return false;
            }
            return false;
        }
        if map.len() < MAX_TRACKED_KEYS {
            return false;
        }
        Self::prune_expired_locked(&mut map, now, FAILURE_WINDOW);
        Self::is_saturated_locked(&map)
    }

    fn prune_expired_locked(map: &mut HashMap<BanKey, Entry>, now: Instant, window: Duration) {
        map.retain(|_, v| {
            v.banned_until.is_some_and(|u| now < u)
                || (v.banned_until.is_none() && now.duration_since(v.last_seen) <= window)
        });
    }

    fn is_saturated_locked(map: &HashMap<BanKey, Entry>) -> bool {
        if map.len() < MAX_TRACKED_KEYS {
            return false;
        }
        !map.values().any(|v| v.banned_until.is_none() || v.kernel_offloaded)
    }

    /// 记录一次认证失败或恶意路径探测（默认 300s 统计窗口），明确区分已追踪、新触发封禁与表满 Fail-Closed。
    pub fn record_failure_checked(
        &self,
        key: BanKey,
        max_failures: u32,
        ban_duration_secs: u64,
        reason: &str,
    ) -> FailureOutcome {
        self.record_failure_with_window(
            key,
            max_failures,
            FAILURE_WINDOW.as_secs(),
            ban_duration_secs,
            reason,
        )
    }

    /// 记录一次失败尝试（支持自定义统计窗口秒数），表满时优先淘汰未封禁项或最早到期且已确认内核卸载的封禁项，否则 Fail-Closed。
    pub fn record_failure_with_window(
        &self,
        key: BanKey,
        max_failures: u32,
        window_secs: u64,
        ban_duration_secs: u64,
        reason: &str,
    ) -> FailureOutcome {
        let Ok(mut map) = self.entries.lock() else {
            return FailureOutcome::SaturatedFailClosed;
        };
        let now = Instant::now();
        let max_failures = max_failures.clamp(3, 50);
        let window = Duration::from_secs(window_secs.clamp(30, 86_400));
        let ban_dur = Duration::from_secs(ban_duration_secs.clamp(60, 86_400));

        if !map.contains_key(&key) && map.len() >= MAX_TRACKED_KEYS {
            // 1. 清理已过期项，绝不驱逐未卸载内核的活跃封禁
            Self::prune_expired_locked(&mut map, now, window);
            if map.len() >= MAX_TRACKED_KEYS {
                // 2. 优先淘汰最久未见的未封禁项
                if let Some(oldest_unbanned) = map
                    .iter()
                    .filter(|(_, v)| v.banned_until.is_none())
                    .min_by_key(|(_, v)| v.last_seen)
                    .map(|(k, _)| *k)
                {
                    map.remove(&oldest_unbanned);
                } else if let Some(earliest_offloaded) = map
                    .iter()
                    .filter(|(_, v)| v.kernel_offloaded && v.banned_until.is_some_and(|u| now < u))
                    .min_by_key(|(_, v)| v.banned_until.unwrap_or(now))
                    .map(|(k, _)| *k)
                {
                    // 3. 全量活跃封禁时，仅淘汰最早到期且已确认在内核防火墙生效的封禁项
                    map.remove(&earliest_offloaded);
                } else {
                    // 4. 全量 1024 条均处于活跃封禁且未确认内核卸载，返回 Fail-Closed 而非 Fail-Open
                    return FailureOutcome::SaturatedFailClosed;
                }
            }
        }

        let entry = map.entry(key).or_insert_with(|| Entry {
            failures: 0,
            first_failure: now,
            last_seen: now,
            banned_until: None,
            banned_at_unix: 0,
            reason: String::new(),
            kernel_offloaded: false,
        });

        if entry.banned_until.is_some_and(|u| now >= u) {
            entry.banned_until = None;
            entry.failures = 0;
            entry.kernel_offloaded = false;
            entry.first_failure = now;
        } else if now.duration_since(entry.first_failure) > window && entry.banned_until.is_none() {
            entry.failures = 0;
            entry.first_failure = now;
        }

        entry.failures = entry.failures.saturating_add(1);
        entry.last_seen = now;
        entry.reason = reason.to_string();

        if entry.failures >= max_failures {
            let newly_banned = entry.banned_until.is_none_or(|u| now >= u);
            entry.banned_until = Some(now + ban_dur);
            entry.banned_at_unix = logger::unix_now();
            if newly_banned {
                entry.kernel_offloaded = false;
                return FailureOutcome::NewlyBanned;
            }
        }
        FailureOutcome::Tracked
    }

    /// 记录一次认证失败或恶意路径探测；若达到阈值返回 true（触发新封禁）
    pub fn record_failure(
        &self,
        key: BanKey,
        max_failures: u32,
        ban_duration_secs: u64,
        reason: &str,
    ) -> bool {
        matches!(
            self.record_failure_checked(key, max_failures, ban_duration_secs, reason),
            FailureOutcome::NewlyBanned
        )
    }

    pub fn record_success(&self, key: BanKey) {
        if let Ok(mut map) = self.entries.lock() {
            map.remove(&key);
        }
    }

    pub fn unban(&self, cidr_or_ip: &str) -> bool {
        let Some(key) = BanKey::parse_cidr_or_ip(cidr_or_ip) else { return false };
        self.unban_key(key)
    }

    pub fn unban_key(&self, key: BanKey) -> bool {
        let Ok(mut map) = self.entries.lock() else { return false };
        map.remove(&key).is_some()
    }

    pub fn has_active_bans(&self) -> bool {
        let Ok(mut map) = self.entries.lock() else { return false };
        let now = Instant::now();
        Self::prune_expired_locked(&mut map, now, FAILURE_WINDOW);
        map.values().any(|v| v.banned_until.is_some_and(|u| now < u))
    }

    pub fn is_empty(&self) -> bool {
        let Ok(mut map) = self.entries.lock() else { return false };
        let now = Instant::now();
        Self::prune_expired_locked(&mut map, now, FAILURE_WINDOW);
        map.is_empty()
    }

    pub fn list_active_bans(&self) -> Vec<BanRecord> {
        let Ok(mut map) = self.entries.lock() else { return Vec::new() };
        let now = Instant::now();
        let mut out = Vec::new();
        map.retain(|k, v| {
            if let Some(until) = v.banned_until {
                if now < until {
                    out.push(BanRecord {
                        cidr: k.display_cidr(),
                        failures: v.failures,
                        banned_at_unix: v.banned_at_unix,
                        remaining_secs: until.duration_since(now).as_secs(),
                        reason: v.reason.clone(),
                    });
                    return true;
                }
            }
            now.duration_since(v.last_seen) <= FAILURE_WINDOW
        });
        out.sort_by(|a, b| b.banned_at_unix.cmp(&a.banned_at_unix));
        out
    }
}

pub type SharedFail2Ban = Arc<Fail2Ban>;

/// 按信任域（例如每个反向代理 host）隔离的 Fail2Ban 容器（最多 64 个作用域，防止随机 Host 泛洪与跨信任域清零）。
pub struct ScopedFail2Ban {
    scopes: Mutex<HashMap<String, Arc<Fail2Ban>>>,
}

impl Default for ScopedFail2Ban {
    fn default() -> Self {
        Self::new()
    }
}

impl ScopedFail2Ban {
    pub fn new() -> Self {
        Self { scopes: Mutex::new(HashMap::new()) }
    }

    fn normalize_scope(scope: &str) -> String {
        scope.trim().to_ascii_lowercase()
    }

    fn get_scope(&self, scope: &str) -> Option<Arc<Fail2Ban>> {
        let key = Self::normalize_scope(scope);
        let guard = self.scopes.lock().ok()?;
        guard.get(&key).cloned()
    }

    fn get_or_create_scope(&self, scope: &str) -> Option<Arc<Fail2Ban>> {
        let key = Self::normalize_scope(scope);
        if key.is_empty() {
            return None;
        }
        let mut guard = self.scopes.lock().ok()?;
        if let Some(existing) = guard.get(&key) {
            return Some(existing.clone());
        }
        if guard.len() >= MAX_FAIL2BAN_SCOPES {
            guard.retain(|_, f2b| !f2b.is_empty());
        }
        if guard.len() >= MAX_FAIL2BAN_SCOPES {
            if let Some(evict) = guard
                .iter()
                .find(|(_, f2b)| !f2b.has_active_bans())
                .map(|(k, _)| k.clone())
            {
                guard.remove(&evict);
            } else {
                return None;
            }
        }
        let f2b = Arc::new(Fail2Ban::new());
        guard.insert(key, f2b.clone());
        Some(f2b)
    }

    pub fn is_key_banned(&self, scope: &str, key: BanKey) -> bool {
        self.get_scope(scope).is_some_and(|f2b| f2b.is_key_banned(key))
    }

    pub fn is_key_banned_any_scope(&self, key: BanKey) -> bool {
        let Ok(guard) = self.scopes.lock() else { return false };
        guard.values().any(|f2b| f2b.is_key_banned(key))
    }

    pub fn is_key_blocked(&self, scope: &str, key: BanKey) -> bool {
        let norm = Self::normalize_scope(scope);
        let Ok(mut guard) = self.scopes.lock() else { return true };
        if let Some(f2b) = guard.get(&norm) {
            return f2b.is_key_blocked(key);
        }
        if guard.len() < MAX_FAIL2BAN_SCOPES {
            return false;
        }
        guard.retain(|_, f2b| !f2b.is_empty());
        if guard.len() < MAX_FAIL2BAN_SCOPES {
            return false;
        }
        // 所有作用域均满且全部持有活跃封禁，Fail-Closed 拒绝新建域绕过
        !guard.values().any(|f2b| !f2b.has_active_bans())
    }

    pub fn record_failure_checked(
        &self,
        scope: &str,
        key: BanKey,
        max_failures: u32,
        ban_duration_secs: u64,
        reason: &str,
    ) -> FailureOutcome {
        let Some(f2b) = self.get_or_create_scope(scope) else {
            return FailureOutcome::SaturatedFailClosed;
        };
        f2b.record_failure_checked(key, max_failures, ban_duration_secs, reason)
    }

    pub fn record_failure_with_window(
        &self,
        scope: &str,
        key: BanKey,
        max_failures: u32,
        window_secs: u64,
        ban_duration_secs: u64,
        reason: &str,
    ) -> FailureOutcome {
        let Some(f2b) = self.get_or_create_scope(scope) else {
            return FailureOutcome::SaturatedFailClosed;
        };
        f2b.record_failure_with_window(key, max_failures, window_secs, ban_duration_secs, reason)
    }

    pub fn record_failure(
        &self,
        scope: &str,
        key: BanKey,
        max_failures: u32,
        ban_duration_secs: u64,
        reason: &str,
    ) -> bool {
        matches!(
            self.record_failure_checked(scope, key, max_failures, ban_duration_secs, reason),
            FailureOutcome::NewlyBanned
        )
    }

    pub fn mark_kernel_offloaded(&self, scope: &str, key: BanKey) -> bool {
        self.get_scope(scope).is_some_and(|f2b| f2b.mark_kernel_offloaded(key))
    }

    /// 仅清除目标作用域内的失败计数，绝不影响管理面或其他反代域名。
    pub fn record_success(&self, scope: &str, key: BanKey) {
        if let Some(f2b) = self.get_scope(scope) {
            f2b.record_success(key);
        }
    }

    pub fn unban_scope(&self, scope: &str, cidr_or_ip: &str) -> bool {
        self.get_scope(scope).is_some_and(|f2b| f2b.unban(cidr_or_ip))
    }

    pub fn unban_all_scopes(&self, key: BanKey) -> bool {
        let Ok(guard) = self.scopes.lock() else { return false };
        let mut removed = false;
        for f2b in guard.values() {
            if f2b.unban_key(key) {
                removed = true;
            }
        }
        removed
    }

    pub fn unban_cidr_all_scopes(&self, cidr_or_ip: &str) -> bool {
        let Some(key) = BanKey::parse_cidr_or_ip(cidr_or_ip) else { return false };
        self.unban_all_scopes(key)
    }

    pub fn list_scope_bans(&self, scope: &str) -> Vec<BanRecord> {
        self.get_scope(scope)
            .map(|f2b| f2b.list_active_bans())
            .unwrap_or_default()
    }

    pub fn list_all_bans(&self) -> Vec<ScopedBanRecord> {
        let Ok(mut guard) = self.scopes.lock() else { return Vec::new() };
        let mut out = Vec::new();
        guard.retain(|scope, f2b| {
            let bans = f2b.list_active_bans();
            for record in bans {
                out.push(ScopedBanRecord {
                    scope: scope.clone(),
                    record,
                });
            }
            !f2b.is_empty()
        });
        out.sort_by(|a, b| {
            b.record
                .banned_at_unix
                .cmp(&a.record.banned_at_unix)
                .then_with(|| a.scope.cmp(&b.scope))
        });
        out
    }
}

pub type SharedScopedFail2Ban = Arc<ScopedFail2Ban>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail2ban_bans_ipv6_subnet_across_rotating_iids() {
        let f2b = Fail2Ban::new();
        let ips = [
            "2001:db8:1111:2222::1",
            "2001:db8:1111:2222::2",
            "2001:db8:1111:2222::3",
            "2001:db8:1111:2222::4",
            "2001:db8:1111:2222::5",
        ];
        for (i, s) in ips.iter().enumerate() {
            let k = BanKey::from_peer(s.parse().unwrap());
            let triggered = f2b.record_failure(k, 5, 600, "auth_failed");
            assert_eq!(triggered, i == 4);
        }
        assert!(f2b.is_banned("2001:db8:1111:2222::9999".parse().unwrap()));
        assert_eq!(f2b.list_active_bans().len(), 1);
        assert!(f2b.unban("2001:db8:1111:2222::/64"));
        assert!(!f2b.is_banned("2001:db8:1111:2222::1".parse().unwrap()));
    }

    #[test]
    fn fail2ban_does_not_evict_active_bans_when_full() {
        let f2b = Fail2Ban::new();
        for i in 0..MAX_TRACKED_KEYS {
            let ip = std::net::Ipv4Addr::new(10, 0, ((i >> 8) & 0xff) as u8, (i & 0xff) as u8);
            let k = BanKey::from_peer(IpAddr::V4(ip));
            for _ in 0..3 {
                f2b.record_failure(k, 3, 600, "flood");
            }
        }
        let victim = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 0));
        assert!(f2b.is_banned(victim));
        assert!(f2b.is_saturated());
        let extra = BanKey::from_peer("203.0.113.5".parse().unwrap());
        assert!(f2b.is_key_blocked(extra));
        assert_eq!(
            f2b.record_failure_checked(extra, 3, 600, "extra"),
            FailureOutcome::SaturatedFailClosed
        );
        assert!(!f2b.record_failure(extra, 3, 600, "extra"));
        assert!(f2b.is_banned(victim));
        assert_eq!(f2b.list_active_bans().len(), MAX_TRACKED_KEYS);
    }

    #[test]
    fn fail2ban_evicts_only_earliest_expiring_kernel_offloaded_ban_when_full() {
        let f2b = Fail2Ban::new();
        let early_key = BanKey::from_peer(IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 0, 0)));
        let late_key = BanKey::from_peer(IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 0, 1)));
        let protected_key = BanKey::from_peer(IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 0, 2)));

        // early_key 封禁 120s，late_key 封禁 1800s，其余均封禁 600s 且未卸载至内核
        for _ in 0..3 {
            f2b.record_failure_checked(early_key, 3, 120, "early");
            f2b.record_failure_checked(late_key, 3, 1800, "late");
        }
        for i in 2..MAX_TRACKED_KEYS {
            let ip = std::net::Ipv4Addr::new(10, 1, ((i >> 8) & 0xff) as u8, (i & 0xff) as u8);
            let k = BanKey::from_peer(IpAddr::V4(ip));
            for _ in 0..3 {
                f2b.record_failure_checked(k, 3, 600, "flood");
            }
        }

        assert!(f2b.is_saturated());
        assert!(f2b.mark_kernel_offloaded(early_key));
        assert!(f2b.mark_kernel_offloaded(late_key));
        assert!(!f2b.is_saturated());

        let extra = BanKey::from_peer("198.51.100.42".parse().unwrap());
        assert!(!f2b.is_key_blocked(extra));
        assert_eq!(
            f2b.record_failure_checked(extra, 3, 600, "extra"),
            FailureOutcome::Tracked
        );
        // 仅淘汰最早到期且已卸载内核的 early_key；late_key 与未卸载的 protected_key 均保留
        assert!(!f2b.is_key_banned(early_key));
        assert!(f2b.is_key_banned(late_key));
        assert!(f2b.is_key_banned(protected_key));
    }

    #[test]
    fn scoped_fail2ban_isolates_hosts_and_fails_closed_at_scope_cap() {
        let admin_f2b = Fail2Ban::new();
        let gate_f2b = ScopedFail2Ban::new();
        let peer = BanKey::from_peer("198.51.100.7".parse().unwrap());

        // 管理面累计 2 次失败（阈值 3）
        assert_eq!(admin_f2b.record_failure_checked(peer, 3, 600, "admin"), FailureOutcome::Tracked);
        assert_eq!(admin_f2b.record_failure_checked(peer, 3, 600, "admin"), FailureOutcome::Tracked);

        // 反代域名 A 登录成功，不得清除管理面或域名 B 的计数
        assert_eq!(gate_f2b.record_failure_checked("b.example.com", peer, 3, 600, "gate"), FailureOutcome::Tracked);
        assert_eq!(gate_f2b.record_failure_checked("b.example.com", peer, 3, 600, "gate"), FailureOutcome::Tracked);
        gate_f2b.record_success("a.example.com", peer);

        // 第 3 次失败立即在管理面与域名 B 各自触发封禁
        assert_eq!(admin_f2b.record_failure_checked(peer, 3, 600, "admin"), FailureOutcome::NewlyBanned);
        assert_eq!(gate_f2b.record_failure_checked("b.example.com", peer, 3, 600, "gate"), FailureOutcome::NewlyBanned);
        assert!(!gate_f2b.is_key_banned("a.example.com", peer));
        assert!(gate_f2b.is_key_banned("B.EXAMPLE.COM", peer));
        assert_eq!(gate_f2b.list_all_bans().len(), 1);
        assert_eq!(gate_f2b.list_all_bans()[0].scope, "b.example.com");

        // 统一跨作用域解封
        assert!(gate_f2b.unban_all_scopes(peer));
        assert!(!gate_f2b.is_key_banned("b.example.com", peer));

        // 填满 64 个带活跃封禁的作用域后，第 65 个新作用域 Fail-Closed
        for idx in 0..MAX_FAIL2BAN_SCOPES {
            let scope = format!("host-{idx}.example.com");
            for _ in 0..3 {
                gate_f2b.record_failure_checked(&scope, peer, 3, 600, "gate_flood");
            }
        }
        assert!(gate_f2b.is_key_blocked("overflow.example.com", peer));
        assert_eq!(
            gate_f2b.record_failure_checked("overflow.example.com", peer, 3, 600, "gate_flood"),
            FailureOutcome::SaturatedFailClosed
        );
    }
}
