//! 资源受限设备友好的站内消息通知收件箱：
//! - 双重硬上限：最多保留 100 条消息 且 落盘 JSON <= 64 KiB，自动滚动淘汰最旧消息；
//! - 自动脱敏与控制字符清洗，避免凭据或 ANSI 控制序列进入消息体；
//! - 记录来源模块路由标识，支持前端查看完整详情并一键跳转对应功能模块。
use crate::logger;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

pub const MAX_INBOX_ITEMS: usize = 100;
pub const MAX_INBOX_BYTES: usize = 64 * 1024;
pub const MAX_TITLE_BYTES: usize = 160;
pub const MAX_MESSAGE_BYTES: usize = 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InboxMessage {
    pub id: u64,
    pub ts: u64,
    pub event: String,
    /// info | warning | error | critical
    pub severity: String,
    pub title: String,
    pub message: String,
    /// 前端跳转目标（如 dashboard / ddns / acme / stun / cron / settings/security / settings/update）
    pub module: String,
    pub read: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct InboxStore {
    next_id: u64,
    items: VecDeque<InboxMessage>,
}

pub struct NotificationInbox {
    path: PathBuf,
    inner: Mutex<InboxStore>,
    persist_lock: Arc<Mutex<()>>,
    persist_seq: Arc<AtomicU64>,
}

static GLOBAL_INBOX: OnceLock<Arc<NotificationInbox>> = OnceLock::new();

pub fn register_global(inbox: Arc<NotificationInbox>) {
    let _ = GLOBAL_INBOX.set(inbox);
}

pub fn record_global(event: &str, severity: &str, title: &str, message: &str, module_override: Option<&str>) {
    if let Some(inbox) = GLOBAL_INBOX.get() {
        inbox.push(event, severity, title, message, module_override);
    }
}

pub fn normalize_severity(raw: &str) -> &'static str {
    match raw.trim().to_ascii_lowercase().as_str() {
        "critical" => "critical",
        "error" => "error",
        "warn" | "warning" => "warning",
        _ => "info",
    }
}

/// 根据系统事件名称映射到前端路由模块（支持顶层 Tab 及 `settings/<subTab>`）
pub fn module_for_event(event: &str) -> &'static str {
    let ev = event.trim().to_ascii_lowercase();
    if ev == "system_update" || ev.starts_with("update_") {
        "settings/update"
    } else if ev.starts_with("ddns") {
        "ddns"
    } else if ev.starts_with("acme") {
        "acme"
    } else if ev.starts_with("stun") {
        "stun"
    } else if ev.starts_with("cron") {
        "cron"
    } else if ev.starts_with("reverse_proxy") || ev.starts_with("proxy") {
        "reverse_proxy"
    } else if ev.starts_with("port_forward") || ev.starts_with("forward") {
        "port_forward"
    } else if ev.starts_with("docker") {
        "docker"
    } else if ev.starts_with("web_terminal") || ev.starts_with("pty") {
        "web_terminal"
    } else if matches!(ev.as_str(), "ip_banned" | "security") || ev.starts_with("auth") || ev.starts_with("passkey") {
        "settings/security"
    } else if matches!(ev.as_str(), "high_temp" | "low_memory" | "module_circuit_open") {
        "dashboard"
    } else if ev == "test" {
        "settings/notifications"
    } else {
        "logs"
    }
}

fn sanitize_single_line(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            '\r' | '\n' | '\x1b' => ' ',
            c if c.is_control() => ' ',
            c => c,
        })
        .collect::<String>()
        .trim()
        .to_string()
}

fn sanitize_multiline(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '\r' => {}
            '\n' => out.push('\n'),
            '\x1b' => out.push(' '),
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out.trim().to_string()
}

impl NotificationInbox {
    pub fn load_or_new(data_dir: &Path) -> Arc<Self> {
        let path = data_dir.join("notifications.json");
        let mut store = InboxStore::default();
        if let Ok(meta) = fs::symlink_metadata(&path) {
            if meta.is_file() && meta.len() <= (MAX_INBOX_BYTES as u64) * 2 {
                if let Ok(raw) = fs::read(&path) {
                    if let Ok(parsed) = serde_json::from_slice::<InboxStore>(&raw) {
                        store = parsed;
                    }
                }
            }
        }
        while store.items.len() > MAX_INBOX_ITEMS {
            store.items.pop_front();
        }
        let max_id = store.items.iter().map(|m| m.id).max().unwrap_or(0);
        if store.next_id <= max_id {
            store.next_id = max_id.saturating_add(1);
        }
        Arc::new(Self {
            path,
            inner: Mutex::new(store),
            persist_lock: Arc::new(Mutex::new(())),
            persist_seq: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn push(
        &self,
        event: &str,
        severity: &str,
        title: &str,
        message: &str,
        module_override: Option<&str>,
    ) -> InboxMessage {
        let clean_event = logger::truncate_utf8(&sanitize_single_line(event), 48);
        let clean_title = logger::truncate_utf8(&logger::redact(&sanitize_single_line(title)), MAX_TITLE_BYTES);
        let clean_msg = logger::truncate_utf8(&logger::redact(&sanitize_multiline(message)), MAX_MESSAGE_BYTES);
        let module = module_override
            .map(sanitize_single_line)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| module_for_event(&clean_event).to_string());

        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let id = g.next_id.max(1);
        g.next_id = id.saturating_add(1);
        let msg = InboxMessage {
            id,
            ts: logger::unix_now(),
            event: if clean_event.is_empty() { "system".into() } else { clean_event },
            severity: normalize_severity(severity).to_string(),
            title: clean_title,
            message: clean_msg,
            module,
            read: false,
        };
        g.items.push_back(msg.clone());
        let encoded = Self::trim_and_encode(&mut g);
        let seq = self.persist_seq.fetch_add(1, Ordering::SeqCst).wrapping_add(1);
        drop(g);
        self.persist_bytes(encoded, seq);
        msg
    }

    /// 返回（按最新优先排序的消息列表, 未读数量, 当前占用字节估算）
    pub fn snapshot(&self) -> (Vec<InboxMessage>, usize, usize) {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let unread = g.items.iter().filter(|m| !m.read).count();
        let bytes = serde_json::to_vec(&*g).map(|v| v.len()).unwrap_or(0);
        let mut list: Vec<InboxMessage> = g.items.iter().cloned().collect();
        list.reverse();
        (list, unread, bytes)
    }

    pub fn unread_count(&self) -> usize {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.items.iter().filter(|m| !m.read).count()
    }

    /// 标记单条（Some(id)）或全部（None）已读，返回更新后的未读数
    pub fn mark_read(&self, id: Option<u64>) -> usize {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut changed = false;
        match id {
            Some(target) => {
                for item in g.items.iter_mut() {
                    if item.id == target && !item.read {
                        item.read = true;
                        changed = true;
                        break;
                    }
                }
            }
            None => {
                for item in g.items.iter_mut() {
                    if !item.read {
                        item.read = true;
                        changed = true;
                    }
                }
            }
        }
        let unread = g.items.iter().filter(|m| !m.read).count();
        let persist_job = if changed {
            let encoded = Self::trim_and_encode(&mut g);
            let seq = self.persist_seq.fetch_add(1, Ordering::SeqCst).wrapping_add(1);
            Some((encoded, seq))
        } else {
            None
        };
        drop(g);
        if let Some((bytes, seq)) = persist_job {
            self.persist_bytes(bytes, seq);
        }
        unread
    }

    pub fn delete(&self, id: u64) -> (bool, usize) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let before = g.items.len();
        g.items.retain(|m| m.id != id);
        let removed = g.items.len() != before;
        let unread = g.items.iter().filter(|m| !m.read).count();
        let persist_job = if removed {
            let encoded = Self::trim_and_encode(&mut g);
            let seq = self.persist_seq.fetch_add(1, Ordering::SeqCst).wrapping_add(1);
            Some((encoded, seq))
        } else {
            None
        };
        drop(g);
        if let Some((bytes, seq)) = persist_job {
            self.persist_bytes(bytes, seq);
        }
        (removed, unread)
    }

    pub fn clear(&self) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.items.is_empty() {
            return;
        }
        g.items.clear();
        let encoded = Self::trim_and_encode(&mut g);
        let seq = self.persist_seq.fetch_add(1, Ordering::SeqCst).wrapping_add(1);
        drop(g);
        self.persist_bytes(encoded, seq);
    }

    fn trim_and_encode(store: &mut InboxStore) -> Vec<u8> {
        while store.items.len() > MAX_INBOX_ITEMS {
            store.items.pop_front();
        }
        let mut bytes = serde_json::to_vec(store).unwrap_or_else(|_| b"{}".to_vec());
        while bytes.len() > MAX_INBOX_BYTES && store.items.len() > 1 {
            store.items.pop_front();
            bytes = serde_json::to_vec(store).unwrap_or_else(|_| b"{}".to_vec());
        }
        bytes
    }

    fn write_bytes_serialized(
        path: &Path,
        bytes: &[u8],
        seq: u64,
        persist_lock: &Mutex<()>,
        persist_seq: &AtomicU64,
    ) {
        let _guard = persist_lock.lock().unwrap_or_else(|e| e.into_inner());
        if persist_seq.load(Ordering::SeqCst) > seq {
            return;
        }
        if let Err(e) = crate::config::crash_safe_atomic_write_with_mode(
            path,
            bytes,
            crate::config::random_nonce(),
            0o600,
            false,
        ) {
            logger::log(logger::Level::Warn, "notify", &format!("站内消息通知落盘失败: {}", e));
        }
    }

    fn persist_bytes(&self, bytes: Vec<u8>, seq: u64) {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let path = self.path.clone();
            let persist_lock = self.persist_lock.clone();
            let persist_seq = self.persist_seq.clone();
            handle.spawn_blocking(move || {
                Self::write_bytes_serialized(&path, &bytes, seq, &persist_lock, &persist_seq);
            });
        } else {
            Self::write_bytes_serialized(&self.path, &bytes, seq, &self.persist_lock, &self.persist_seq);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_count_and_byte_bounds_and_persists() {
        let tmp = std::env::temp_dir().join(format!("vane_inbox_test_{}", crate::config::random_nonce()));
        fs::create_dir_all(&tmp).unwrap();
        let inbox = NotificationInbox::load_or_new(&tmp);

        for i in 0..120 {
            inbox.push(
                "ddns_changed",
                "info",
                &format!("标题 #{i}"),
                &format!("token=super_secret_val_{i}\n内容 {}", "A".repeat(400)),
                None,
            );
        }
        let (items, unread, bytes) = inbox.snapshot();
        assert!(items.len() <= MAX_INBOX_ITEMS);
        assert!(bytes <= MAX_INBOX_BYTES, "bytes={bytes}");
        assert_eq!(unread, items.len());
        assert_eq!(items[0].module, "ddns");
        assert!(items[0].message.contains("token=****"));
        assert!(!items[0].message.contains("super_secret_val"));

        // 标记单条已读 & 持久化重载
        let first_id = items[0].id;
        assert_eq!(inbox.mark_read(Some(first_id)), unread - 1);
        let reloaded = NotificationInbox::load_or_new(&tmp);
        let (re_items, re_unread, _) = reloaded.snapshot();
        assert_eq!(re_items.len(), items.len());
        assert_eq!(re_unread, unread - 1);
        assert!(re_items[0].read);

        // 全部已读、删除、清空
        assert_eq!(reloaded.mark_read(None), 0);
        let (removed, _) = reloaded.delete(first_id);
        assert!(removed);
        reloaded.clear();
        assert!(reloaded.snapshot().0.is_empty());

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn maps_events_to_expected_modules() {
        assert_eq!(module_for_event("ddns_failed"), "ddns");
        assert_eq!(module_for_event("acme_renewed"), "acme");
        assert_eq!(module_for_event("stun_changed"), "stun");
        assert_eq!(module_for_event("cron_failed"), "cron");
        assert_eq!(module_for_event("system_update"), "settings/update");
        assert_eq!(module_for_event("ip_banned"), "settings/security");
        assert_eq!(module_for_event("high_temp"), "dashboard");
        assert_eq!(module_for_event("unknown_evt"), "logs");
    }
}
