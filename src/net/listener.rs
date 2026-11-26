//! 共享 TCP/UDP 连接配额与单来源 (BanKey) 并发配额：每条规则实际遵守配置上限，支持热更新容量且防单源耗尽。
use crate::net::dual_stack::BanKey;
use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

struct QuotaInner {
    sem: Arc<Semaphore>,
    cap: usize,
}

#[derive(Clone)]
pub struct ConnectionQuota {
    inner: Arc<ArcSwap<QuotaInner>>,
}

impl std::fmt::Debug for ConnectionQuota {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionQuota")
            .field("active", &self.active_connections())
            .field("capacity", &self.capacity())
            .finish()
    }
}

impl ConnectionQuota {
    pub fn new(max_conns: usize) -> Self {
        let cap = max_conns.clamp(1, 8192);
        Self {
            inner: Arc::new(ArcSwap::from_pointee(QuotaInner {
                sem: Arc::new(Semaphore::new(cap)),
                cap,
            })),
        }
    }

    pub fn set_capacity(&self, max_conns: usize) {
        let cap = max_conns.clamp(1, 8192);
        if self.inner.load().cap == cap {
            return;
        }
        self.inner.store(Arc::new(QuotaInner {
            sem: Arc::new(Semaphore::new(cap)),
            cap,
        }));
    }

    pub fn try_acquire(&self) -> Option<OwnedSemaphorePermit> {
        self.inner.load().sem.clone().try_acquire_owned().ok()
    }

    pub fn active_connections(&self) -> usize {
        let snap = self.inner.load();
        snap.cap.saturating_sub(snap.sem.available_permits())
    }

    pub fn capacity(&self) -> usize {
        self.inner.load().cap
    }
}

/// 单来源 (IPv4 /32 或 IPv6 /64) 并发连接/会话配额，防止单一来源耗尽全局与跨规则配额
#[derive(Clone)]
pub struct PeerQuota {
    counts: Arc<Mutex<HashMap<BanKey, usize>>>,
    max_per_peer: usize,
}

pub struct PeerQuotaGuard {
    counts: Arc<Mutex<HashMap<BanKey, usize>>>,
    key: BanKey,
}

impl Drop for PeerQuotaGuard {
    fn drop(&mut self) {
        if let Ok(mut g) = self.counts.lock() {
            if let Some(cnt) = g.get_mut(&self.key) {
                if *cnt <= 1 {
                    g.remove(&self.key);
                } else {
                    *cnt -= 1;
                }
            }
        }
    }
}

impl PeerQuota {
    pub fn new(max_per_peer: usize) -> Self {
        Self {
            counts: Arc::new(Mutex::new(HashMap::new())),
            max_per_peer: max_per_peer.max(1),
        }
    }

    /// 按规则并发上限推导单来源配额：min(max_conns / 4, 32).max(8)，且不超过规则自身容量
    pub fn for_rule_capacity(max_conns: usize) -> Self {
        let cap = max_conns.clamp(1, 8192);
        let limit = (cap / 4).clamp(8, 32).min(cap);
        Self::new(limit)
    }

    pub fn max_per_peer(&self) -> usize {
        self.max_per_peer
    }

    pub fn try_acquire(&self, key: BanKey) -> Option<PeerQuotaGuard> {
        let mut g = self.counts.lock().ok()?;
        let cnt = g.entry(key).or_insert(0);
        if *cnt >= self.max_per_peer {
            if *cnt == 0 {
                g.remove(&key);
            }
            return None;
        }
        *cnt += 1;
        Some(PeerQuotaGuard {
            counts: self.counts.clone(),
            key,
        })
    }

    pub fn active_for(&self, key: BanKey) -> usize {
        self.counts
            .lock()
            .ok()
            .and_then(|g| g.get(&key).copied())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_quota_bounds_single_source_and_releases_on_drop() {
        let quota = PeerQuota::new(2);
        let k1 = BanKey::from_peer("198.51.100.1".parse().unwrap());
        let k2 = BanKey::from_peer("198.51.100.2".parse().unwrap());
        let g1 = quota.try_acquire(k1).unwrap();
        let g2 = quota.try_acquire(k1).unwrap();
        assert!(quota.try_acquire(k1).is_none());
        assert_eq!(quota.active_for(k1), 2);
        let g3 = quota.try_acquire(k2).unwrap();
        assert_eq!(quota.active_for(k2), 1);
        drop(g1);
        assert_eq!(quota.active_for(k1), 1);
        assert!(quota.try_acquire(k1).is_some());
        drop(g2);
        drop(g3);
        assert_eq!(quota.active_for(k1), 0);
        assert_eq!(quota.active_for(k2), 0);
    }
}
