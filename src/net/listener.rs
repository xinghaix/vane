//! 共享 TCP/UDP 连接配额：每条规则实际遵守配置下限，支持热更新容量且无锁获取信号量许可。
use arc_swap::ArcSwap;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

struct QuotaInner {
    sem: Arc<Semaphore>,
    cap: usize,
}

#[derive(Clone)]
pub struct ConnectionQuota {
    inner: Arc<ArcSwap<QuotaInner>>,
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
