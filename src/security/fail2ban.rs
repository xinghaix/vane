//! 双栈源地址防爆破封禁表（IPv4 /32 + IPv6 /64 归一化，定长上限 1024 条 LRU 驱逐）。
use crate::logger;
use crate::net::dual_stack::BanKey;
use serde::Serialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const MAX_TRACKED_KEYS: usize = 1024;
const FAILURE_WINDOW: Duration = Duration::from_secs(300);

#[derive(Clone, Debug)]
struct Entry {
    failures: u32,
    first_failure: Instant,
    last_seen: Instant,
    banned_until: Option<Instant>,
    banned_at_unix: u64,
    reason: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct BanRecord {
    pub cidr: String,
    pub failures: u32,
    pub banned_at_unix: u64,
    pub remaining_secs: u64,
    pub reason: String,
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
            }
        }
        false
    }

    /// 记录一次认证失败或恶意路径探测；若达到阈值返回 true（触发新封禁）
    pub fn record_failure(
        &self,
        key: BanKey,
        max_failures: u32,
        ban_duration_secs: u64,
        reason: &str,
    ) -> bool {
        let Ok(mut map) = self.entries.lock() else { return false };
        let now = Instant::now();
        let max_failures = max_failures.clamp(3, 50);
        let ban_dur = Duration::from_secs(ban_duration_secs.clamp(60, 86_400));

        if !map.contains_key(&key) && map.len() >= MAX_TRACKED_KEYS {
            // 优先清理已过期项，否则驱逐最久未活动的未封禁项
            map.retain(|_, v| {
                v.banned_until.is_some_and(|u| now < u) || now.duration_since(v.last_seen) <= FAILURE_WINDOW
            });
            if map.len() >= MAX_TRACKED_KEYS {
                if let Some(oldest_k) = map
                    .iter()
                    .min_by_key(|(_, v)| (v.banned_until.is_some(), v.last_seen))
                    .map(|(k, _)| *k)
                {
                    map.remove(&oldest_k);
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
        });

        if now.duration_since(entry.first_failure) > FAILURE_WINDOW && entry.banned_until.is_none() {
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
            return newly_banned;
        }
        false
    }

    pub fn record_success(&self, key: BanKey) {
        if let Ok(mut map) = self.entries.lock() {
            map.remove(&key);
        }
    }

    pub fn unban(&self, cidr_or_ip: &str) -> bool {
        let Some(key) = BanKey::parse_cidr_or_ip(cidr_or_ip) else { return false };
        let Ok(mut map) = self.entries.lock() else { return false };
        map.remove(&key).is_some()
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
}
