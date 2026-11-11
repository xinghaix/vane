//! 子模块故障舱壁监督器：spawn 内包裹 factory 捕获同步/异步 panic、&mut handle 优雅取消回收、
//! 60s 滑动窗口 5 次失败熔断与 300s 半开自愈探测。
use crate::logger::{self, Level};
use serde::Serialize;
use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::watch;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ModuleHealth {
    Disabled,
    Running,
    Degraded { recent_failures: u32, last_error: String },
    CircuitOpen { reason: String, retry_in_secs: u64 },
}

pub type HealthRegistry = Arc<RwLock<BTreeMap<String, ModuleHealth>>>;

pub fn new_health_registry() -> HealthRegistry {
    let mut map = BTreeMap::new();
    for name in crate::config::MODULE_NAMES {
        map.insert((*name).to_string(), ModuleHealth::Disabled);
    }
    Arc::new(RwLock::new(map))
}

pub fn set_module_health(reg: &HealthRegistry, name: &str, health: ModuleHealth) {
    if let Ok(mut guard) = reg.write() {
        guard.insert(name.to_string(), health);
    }
}

struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for AbortOnDrop<T> { fn drop(&mut self) { self.0.abort(); } }

/// 在独立舱壁中监督运行一个可取消的异步模块任务
pub async fn supervise_module<F, Fut>(
    module_name: &'static str,
    mut shutdown_rx: watch::Receiver<bool>,
    health_tx: watch::Sender<ModuleHealth>,
    registry: Option<HealthRegistry>,
    task_factory: F,
) where
    F: FnMut(watch::Receiver<bool>) -> Fut + Send + 'static,
    Fut: Future<Output = Result<(), String>> + Send + 'static,
{
    const WINDOW: Duration = Duration::from_secs(60);
    const MAX_FAILURES_IN_WINDOW: usize = 5;
    const CIRCUIT_HALF_OPEN_COOLDOWN: Duration = Duration::from_secs(300);

    let task_factory = Arc::new(std::sync::Mutex::new(task_factory));
    let mut failure_timestamps: VecDeque<Instant> = VecDeque::with_capacity(MAX_FAILURES_IN_WINDOW + 1);
    let update = |h: ModuleHealth| {
        let _ = health_tx.send(h.clone());
        if let Some(ref reg) = registry {
            set_module_health(reg, module_name, h);
        }
    };

    loop {
        if shutdown_rx.has_changed().is_err() || *shutdown_rx.borrow() {
            update(ModuleHealth::Disabled);
            break;
        }
        update(ModuleHealth::Running);

        let child_shutdown = shutdown_rx.clone();
        let factory = task_factory.clone();
        // 工厂调用本身也在子任务中；同步 panic 不得杀死监督器。
        let mut handle = AbortOnDrop(tokio::spawn(async move {
            let future = { factory.lock().unwrap_or_else(|error|error.into_inner())(child_shutdown) };
            future.await
        }));

        let outcome = tokio::select! {
            res = &mut handle.0 => Some(res),
            event = shutdown_rx.changed() => {
                if event.is_err() || *shutdown_rx.borrow() {
                    // 先给子模块撤销防火墙、回收进程的机会，再强制取消。
                    if tokio::time::timeout(Duration::from_secs(2), &mut handle.0).await.is_err() {
                        handle.0.abort();
                        let _ = (&mut handle.0).await;
                    }
                    update(ModuleHealth::Disabled);
                    break;
                }
                handle.0.abort();
                let _ = (&mut handle.0).await;
                None
            }
        };

        let Some(join_res) = outcome else { continue };
        let err_msg = match join_res {
            Ok(Ok(())) => {
                failure_timestamps.clear();
                if shutdown_rx.has_changed().is_err() || *shutdown_rx.borrow() {
                    update(ModuleHealth::Disabled);
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
            Ok(Err(e)) => format!("模块运行错误: {}", e),
            Err(join_err) if join_err.is_panic() => {
                format!("捕获到子任务 Panic 异常 (已隔离): {}", join_err)
            }
            Err(_) => break,
        };

        logger::log(Level::Warn, module_name, &err_msg);

        let now = Instant::now();
        while failure_timestamps.front().is_some_and(|t| now.duration_since(*t) > WINDOW) {
            failure_timestamps.pop_front();
        }
        failure_timestamps.push_back(now);

        if failure_timestamps.len() >= MAX_FAILURES_IN_WINDOW {
            let reason = format!("60s 内连续异常 {} 次，触发半开熔断: {}", failure_timestamps.len(), err_msg);
            logger::log(Level::Error, module_name, &reason);
            update(ModuleHealth::CircuitOpen {
                reason,
                retry_in_secs: CIRCUIT_HALF_OPEN_COOLDOWN.as_secs(),
            });

            tokio::select! {
                _ = tokio::time::sleep(CIRCUIT_HALF_OPEN_COOLDOWN) => {
                    failure_timestamps.clear();
                    continue;
                }
                _ = shutdown_rx.changed() => {
                    if shutdown_rx.has_changed().is_err() || *shutdown_rx.borrow() {
                        update(ModuleHealth::Disabled);
                        break;
                    }
                }
            }
        } else {
            let count = failure_timestamps.len() as u32;
            let backoff_secs = (1u64 << count.min(5)).min(30);
            update(ModuleHealth::Degraded {
                recent_failures: count,
                last_error: err_msg,
            });
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(backoff_secs)) => {}
                _ = shutdown_rx.changed() => {
                    if shutdown_rx.has_changed().is_err() || *shutdown_rx.borrow() {
                        update(ModuleHealth::Disabled);
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn synchronous_factory_panic_is_isolated() {
        let (stop_tx,stop_rx)=watch::channel(false);
        let (health_tx,mut health_rx)=watch::channel(ModuleHealth::Disabled);
        let task=tokio::spawn(supervise_module("test",stop_rx,health_tx,None,move |_| {
            panic!("同步工厂失败");
            #[allow(unreachable_code)]
            std::future::ready(Ok(()))
        }));
        tokio::time::timeout(Duration::from_secs(1),async {
            loop {health_rx.changed().await.unwrap();if matches!(*health_rx.borrow(),ModuleHealth::Degraded{..}){break;}}
        }).await.unwrap();
        stop_tx.send(true).unwrap();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn dropped_shutdown_sender_stops_without_respawning() {
        let (stop_tx,stop_rx)=watch::channel(false);
        let (health_tx,_)=watch::channel(ModuleHealth::Disabled);
        let started=Arc::new(tokio::sync::Notify::new());
        let notice=started.clone();
        let task=tokio::spawn(supervise_module("test",stop_rx,health_tx,None,move |mut rx| {
            let notice=notice.clone();
            async move {notice.notify_one();let _=rx.changed().await;Ok(())}
        }));
        started.notified().await;
        drop(stop_tx);
        tokio::time::timeout(Duration::from_secs(1),task).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn supervisor_isolates_panic_and_recovers() {
        let (stop_tx, stop_rx) = watch::channel(false);
        let (health_tx, health_rx) = watch::channel(ModuleHealth::Disabled);
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_clone = attempts.clone();

        let sup = tokio::spawn(async move {
            supervise_module("test_mod", stop_rx, health_tx, None, move |mut rx| {
                let n = attempts_clone.fetch_add(1, Ordering::SeqCst);
                async move {
                    if n == 0 {
                        panic!("simulated panic in module");
                    }
                    let _ = rx.changed().await;
                    Ok(())
                }
            })
            .await;
        });

        tokio::time::sleep(Duration::from_millis(2200)).await;
        assert!(attempts.load(Ordering::SeqCst) >= 2);
        assert_eq!(*health_rx.borrow(), ModuleHealth::Running);
        let _ = stop_tx.send(true);
        let _ = sup.await;
    }
}
