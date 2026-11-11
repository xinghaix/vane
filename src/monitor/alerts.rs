//! 系统监控低内存 / 高温告警阈值评估与冷却去重通知分发。
use crate::config::Config;
use crate::daemon::notify::{dispatch_notification, DeliveryOutcome};
use crate::logger::{self, Level};
use crate::monitor::procfs::SystemSnapshot;
use crate::security::vault::Vault;
use std::collections::BTreeMap;
use std::sync::Mutex;

#[derive(Default)]
pub struct AlertState {
    last_sent_unix: Mutex<BTreeMap<String, u64>>,
}

impl AlertState {
    fn allow_and_mark(&self, key: &str, now_unix: u64, cooldown_secs: u64) -> bool {
        let Ok(mut map) = self.last_sent_unix.lock() else { return false };
        if let Some(&prev) = map.get(key) {
            if now_unix.saturating_sub(prev) < cooldown_secs.max(10) {
                return false;
            }
        }
        map.insert(key.to_string(), now_unix);
        true
    }
}

pub async fn evaluate_and_notify_alerts(
    alert_state: &AlertState,
    cfg: &Config,
    vault: &Vault,
    snapshot: &SystemSnapshot,
) {
    let m = &cfg.monitor;
    let cooldown = m.alert_cooldown_secs.max(60);
    let now = snapshot.timestamp_unix;

    // 1. 高温告警 (soc_temp_celsius > temp_alert_celsius)
    if let Some(temp) = Some(snapshot.soc_temp_celsius).filter(|t| *t > 0.0 && *t >= m.temp_alert_celsius as f32) {
        if alert_state.allow_and_mark("high_temp", now, cooldown) {
            let msg = format!(
                "路由器 SoC 温度达到 {:.1}°C，已超过告警阈值 {}°C",
                temp, m.temp_alert_celsius
            );
            logger::log(Level::Warn, "monitor", &msg);
            for ch in &cfg.notifications {
                if let Ok(DeliveryOutcome::Sent) =
                    dispatch_notification(ch, vault, "high_temp", "Vane 高温告警", &msg, "critical").await
                {
                    logger::log(Level::Info, "monitor", &format!("已向渠道 {} 投递高温告警", ch.name));
                }
            }
        }
    }

    // 2. 可用内存低水位告警 (MemAvailable < mem_low_mb)
    if snapshot.memory.total_kb > 0 && m.mem_low_mb > 0 {
        let avail_mb = snapshot.memory.available_kb / 1024;
        if avail_mb < m.mem_low_mb && alert_state.allow_and_mark("low_memory", now, cooldown) {
            let msg = format!(
                "路由器可用内存仅剩 {} MB，低于安全水位 {} MB",
                avail_mb, m.mem_low_mb
            );
            logger::log(Level::Warn, "monitor", &msg);
            for ch in &cfg.notifications {
                let _ = dispatch_notification(ch, vault, "low_memory", "Vane 低内存告警", &msg, "warning").await;
            }
        }
    }
}
