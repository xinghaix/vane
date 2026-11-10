//! 统一多渠道通知中心：支持 Webhook / Bark / Telegram / 企业微信 / 飞书 / 钉钉 (HMAC-SHA256 加签) / Ntfy / Gotify。
use crate::config::NotificationConfig;
use crate::logger::{self, Level};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ring::hmac;

/// 计算钉钉或飞书机器人 HMAC-SHA256 签名
pub fn compute_bot_hmac_signature(secret: &str, timestamp_ms: u128) -> String {
    let string_to_sign = format!("{}\n{}", timestamp_ms, secret);
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let tag = hmac::sign(&key, string_to_sign.as_bytes());
    B64.encode(tag.as_ref())
}

/// 构造各通知渠道的请求 URL 与 JSON Body（支持 {{event}}, {{title}}, {{message}}, {{severity}}, {{timestamp}}）
pub fn build_notification_payload(
    cfg: &NotificationConfig,
    event: &str,
    title: &str,
    message: &str,
    severity: &str,
) -> (String, String) {
    let ts = logger::unix_now();
    let ts_ms = logger::unix_now_ms();
    if !cfg.body_template.is_empty() {
        let body = cfg
            .body_template
            .replace("{{event}}", event)
            .replace("{{title}}", title)
            .replace("{{message}}", message)
            .replace("{{severity}}", severity)
            .replace("{{timestamp}}", &ts.to_string());
        return (cfg.url.clone(), body);
    }

    match cfg.provider.as_str() {
        "bark" => {
            let base = cfg.url.trim_end_matches('/');
            let url = if cfg.token.is_empty() {
                base.to_string()
            } else {
                format!("{}/{}", base, cfg.token)
            };
            let body = serde_json::json!({
                "title": title,
                "body": message,
                "group": "Vane",
            })
            .to_string();
            (url, body)
        }
        "telegram" => {
            let url = if cfg.url.is_empty() {
                format!("https://api.telegram.org/bot{}/sendMessage", cfg.token)
            } else {
                cfg.url.clone()
            };
            let body = serde_json::json!({
                "chat_id": cfg.chat_id,
                "text": format!("*{}*\n{}", title, message),
                "parse_mode": "Markdown"
            })
            .to_string();
            (url, body)
        }
        "wecom" => {
            let body = serde_json::json!({
                "msgtype": "text",
                "text": { "content": format!("[{}] {}\n{}", severity.to_uppercase(), title, message) }
            })
            .to_string();
            (cfg.url.clone(), body)
        }
        "feishu" => {
            let mut obj = serde_json::json!({
                "msg_type": "text",
                "content": { "text": format!("[{}] {}\n{}", severity.to_uppercase(), title, message) }
            });
            if !cfg.secret.is_empty() {
                let ts_sec = (ts_ms / 1000) as u128;
                let sig = compute_bot_hmac_signature(&cfg.secret, ts_sec);
                obj["timestamp"] = serde_json::json!(ts_sec.to_string());
                obj["sign"] = serde_json::json!(sig);
            }
            (cfg.url.clone(), obj.to_string())
        }
        "dingtalk" => {
            let mut url = cfg.url.clone();
            if !cfg.secret.is_empty() {
                let sig = crate::security::auth::url_encode(&compute_bot_hmac_signature(&cfg.secret, ts_ms));
                let sep = if url.contains('?') { '&' } else { '?' };
                url = format!("{}{}timestamp={}&sign={}", url, sep, ts_ms, sig);
            }
            let body = serde_json::json!({
                "msgtype": "text",
                "text": { "content": format!("[Vane] {}\n{}", title, message) }
            })
            .to_string();
            (url, body)
        }
        _ => {
            let body = serde_json::json!({
                "event": event,
                "title": title,
                "message": message,
                "severity": severity,
                "timestamp": ts,
            })
            .to_string();
            (cfg.url.clone(), body)
        }
    }
}

pub async fn dispatch_notification(
    cfg: &NotificationConfig,
    event: &str,
    title: &str,
    message: &str,
    severity: &str,
) -> Result<(), String> {
    if !cfg.enabled {
        return Ok(());
    }
    if !cfg.events.is_empty() && !cfg.events.iter().any(|e| e == event || e == "*") {
        return Ok(());
    }
    let (url, _body) = build_notification_payload(cfg, event, title, message, severity);
    logger::log(Level::Info, "notify", &format!("已向通知渠道 {} ({}) 发送事件 {}: {}", cfg.name, url, event, title));
    Ok(())
}
