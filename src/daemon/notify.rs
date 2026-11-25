//! 真实通知投递：解密渠道配置、构造报文、检查 HTTP 与业务状态，绝不以日志冒充成功。
use crate::{config::NotificationConfig, logger::{self, Level}, net::http_client::{shared, HttpRequest, HttpResponse}, security::{auth::url_encode, vault::Vault}};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ring::hmac;
use serde::Serialize;
use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryOutcome { Sent, Skipped }

pub fn compute_bot_hmac_signature(secret: &str, timestamp_ms: u128) -> String {
    let text = format!("{}\n{}", timestamp_ms, secret);
    B64.encode(hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes()), text.as_bytes()).as_ref())
}

/// 飞书使用 timestamp + 换行 + secret 作为 HMAC 密钥，对空消息签名，与钉钉不同。
/// 协议：https://open.feishu.cn/document/client-docs/bot-v3/add-custom-bot.md
pub fn feishu_signature(secret: &str, timestamp_secs: u64) -> String {
    let key = format!("{}\n{}", timestamp_secs, secret);
    B64.encode(hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key.as_bytes()), b"").as_ref())
}

fn severity_rank(value: &str) -> Option<u8> {
    match value { "debug" => Some(0), "info" => Some(1), "warn" | "warning" => Some(2), "error" => Some(3), "critical" => Some(4), _ => None }
}

fn reveal_config(cfg: &NotificationConfig, vault: &Vault) -> Result<NotificationConfig, String> {
    let mut plain = cfg.clone();
    let prefix = format!("notifications.{}", cfg.name);
    plain.url = vault.reveal_string(&format!("{prefix}.url"), &cfg.url)?;
    plain.token = vault.reveal_string(&format!("{prefix}.token"), &cfg.token)?;
    plain.secret = vault.reveal_string(&format!("{prefix}.secret"), &cfg.secret)?;
    for (name, value) in &mut plain.headers {
        *value = vault.reveal_string(&format!("{prefix}.headers.{name}"), value)?;
    }
    plain.body_template = vault.reveal_string(&format!("{prefix}.body_template"), &cfg.body_template)?;
    Ok(plain)
}

fn render_template(value: &mut Value, variables: &[(&str, &str)]) {
    match value {
        Value::String(text) => { for (key, value) in variables { *text = text.replace(key, value); } },
        Value::Array(values) => { for value in values { render_template(value, variables); } },
        Value::Object(values) => { for value in values.values_mut() { render_template(value, variables); } },
        _ => {},
    }
}

fn insert_header_ci(headers: &mut std::collections::BTreeMap<String, String>, key: &str, val: String) {
    let existing: Vec<String> = headers
        .keys()
        .filter(|k| k.eq_ignore_ascii_case(key))
        .cloned()
        .collect();
    for k in existing {
        headers.remove(&k);
    }
    headers.insert(key.to_string(), val);
}

fn build_request(cfg: &NotificationConfig, event: &str, title: &str, message: &str, severity: &str, now_ms: u128) -> Result<HttpRequest, String> {
    let mut url = cfg.url.clone();
    let mut payload = match cfg.provider.as_str() {
        "webhook" => json!({"event":event,"title":title,"message":message,"severity":severity,"timestamp":now_ms/1000}),
        "bark" => {
            if !url.ends_with("/push") { url = format!("{}/push", url.trim_end_matches('/')); }
            json!({"device_key":cfg.token,"title":title,"body":message,"group":"Vane"})
        },
        "telegram" => {
            let tok = cfg.token.trim();
            if tok.is_empty() || !tok.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'_' | b'-')) {
                return Err("Telegram Bot Token 格式非法".into());
            }
            if url.is_empty() {
                url = format!("https://api.telegram.org/bot{}/sendMessage", tok);
            } else if !url.contains("/sendMessage") {
                url = format!("{}/bot{}/sendMessage", url.trim_end_matches('/'), tok);
            }
            // 使用纯文本避免用户输入被解析为 Markdown 控制字符。
            json!({"chat_id":cfg.chat_id,"text":format!("{title}\n{message}")})
        },
        "wecom" | "dingtalk" => {
            if cfg.provider == "dingtalk" && !cfg.secret.is_empty() {
                let separator = if url.contains('?') { '&' } else { '?' };
                url = format!("{}{}timestamp={}&sign={}", url, separator, now_ms, url_encode(&compute_bot_hmac_signature(&cfg.secret, now_ms)));
            }
            json!({"msgtype":"text","text":{"content":format!("[{severity}] {title}\n{message}")}})
        },
        "feishu" => {
            let mut value = json!({"msg_type":"text","content":{"text":format!("{title}\n{message}")}});
            if !cfg.secret.is_empty() {
                value["timestamp"] = json!((now_ms/1000).to_string());
                value["sign"] = json!(feishu_signature(&cfg.secret, (now_ms/1000) as u64));
            }
            value
        },
        "gotify" => {
            if !url.ends_with("/message") { url = format!("{}/message", url.trim_end_matches('/')); }
            json!({"title":title,"message":message,"priority":severity_rank(severity).unwrap_or(1) + 2})
        },
        "ntfy" => Value::Null,
        _ => return Err("不支持的通知渠道".into()),
    };
    let timestamp = (now_ms / 1000).to_string();
    if !cfg.body_template.is_empty() {
        // 在 JSON 值内部替换，避免消息中的引号、换行破坏报文或注入字段。
        payload = serde_json::from_str(&cfg.body_template).map_err(|_| "通知 body_template 必须是有效 JSON")?;
        render_template(&mut payload, &[("{{event}}",event),("{{title}}",title),("{{message}}",message),("{{severity}}",severity),("{{timestamp}}",&timestamp)]);
    }
    let method = if cfg.method.is_empty() { "POST" } else { &cfg.method };
    let mut request = HttpRequest::new(method, &url).json(&payload);
    request.response_limit = 64 * 1024;
    for (k, v) in &cfg.headers {
        insert_header_ci(&mut request.headers, k, v.clone());
    }
    if cfg.provider == "gotify" { insert_header_ci(&mut request.headers, "x-gotify-key", cfg.token.clone()); }
    if cfg.provider == "ntfy" {
        if cfg.body_template.is_empty() {
            request.body = message.as_bytes().to_vec();
            insert_header_ci(&mut request.headers, "content-type", "text/plain; charset=utf-8".into());
            insert_header_ci(&mut request.headers, "title", format!("=?UTF-8?B?{}?=", B64.encode(title.as_bytes())));
        }
        if !cfg.token.is_empty() { insert_header_ci(&mut request.headers, "authorization", format!("Bearer {}", cfg.token)); }
    }
    Ok(request)
}

fn validate_delivery(provider: &str, response: HttpResponse) -> Result<(), String> {
    response.ensure_success()?;
    if provider == "webhook" { return Ok(()); }
    let value = response.json()?;
    let accepted = match provider {
        "telegram" => value.get("ok").and_then(Value::as_bool) == Some(true),
        "bark" => value.get("code").and_then(Value::as_i64) == Some(200),
        "wecom" | "dingtalk" => value.get("errcode").and_then(Value::as_i64) == Some(0),
        "feishu" => value.get("code").or_else(|| value.get("StatusCode")).and_then(Value::as_i64) == Some(0),
        "gotify" | "ntfy" => value.get("id").is_some_and(|id| !id.is_null()),
        _ => false,
    };
    // 不把服务商原始响应写入日志，其中可能包含敏感 URL 或令牌。
    if accepted {
        Ok(())
    } else {
        let code = value
            .get("errcode")
            .or_else(|| value.get("code"))
            .or_else(|| value.get("error_code"))
            .or_else(|| value.get("StatusCode"))
            .and_then(|v| v.as_i64().map(|n| n.to_string()).or_else(|| v.as_str().filter(|s| s.len() <= 32 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')).map(str::to_string)));
        match code {
            Some(c) => Err(format!("通知渠道 {provider} 拒绝投递 (code={c})")),
            None => Err(format!("通知渠道 {provider} 拒绝投递")),
        }
    }
}

pub async fn dispatch_notification(cfg: &NotificationConfig, vault: &Vault, event: &str, title: &str, message: &str, severity: &str) -> Result<DeliveryOutcome, String> {
    let rank = severity_rank(severity).ok_or("无效的通知级别")?;
    let minimum = severity_rank(&cfg.min_severity).ok_or("无效的通知最低级别")?;
    if !cfg.enabled || rank < minimum || (!cfg.events.is_empty() && !cfg.events.iter().any(|e| e == event || e == "*")) {
        return Ok(DeliveryOutcome::Skipped);
    }
    let plain = reveal_config(cfg, vault)?;
    let request = build_request(&plain, event, title, message, severity, logger::unix_now_ms())?;
    validate_delivery(&cfg.provider, shared().execute(request).await?)?;
    logger::log(Level::Info, "notify", &format!("通知渠道 {} 已确认投递事件 {}", cfg.name, event));
    Ok(DeliveryOutcome::Sent)
}

/// 手动测试推送：忽略 enabled/events/min_severity 过滤，直接验证凭据与网络连通性
pub async fn send_test_notification(cfg: &NotificationConfig, vault: &Vault, title: &str, message: &str) -> Result<DeliveryOutcome, String> {
    let plain = reveal_config(cfg, vault)?;
    let request = build_request(&plain, "test", title, message, "info", logger::unix_now_ms())?;
    validate_delivery(&cfg.provider, shared().execute(request).await?)?;
    logger::log(Level::Info, "notify", &format!("通知渠道 {} 测试推送已确认投递", cfg.name));
    Ok(DeliveryOutcome::Sent)
}

/// 向所有启用且匹配事件/级别过滤条件的通知渠道广播系统事件（单渠道异常仅记录日志不阻断其他渠道）
pub async fn broadcast_event(
    all_cfg: &crate::config::Config,
    vault: &Vault,
    event: &str,
    title: &str,
    message: &str,
    severity: &str,
) {
    for ch in all_cfg.notifications.iter().filter(|c| c.enabled) {
        if let Err(e) = dispatch_notification(ch, vault, event, title, message, severity).await {
            logger::log(
                Level::Warn,
                "notify",
                &format!("通知渠道 {} 投递事件 {} 失败: {}", ch.name, event, e),
            );
        }
    }
}

#[cfg(test)]
#[path = "notify_tests.rs"]
mod tests;
