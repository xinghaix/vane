use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn independent_bot_signature_vectors() {
    assert_eq!(feishu_signature("demo", 1599360473), "l1N0gAcBjdwBvGm1xMjOF0XSyaLRpR7tuO5dHfhAYc8=");
    assert_eq!(compute_bot_hmac_signature("demo", 1599360473), "DkEDUyVoOOJ539qBvUgMyzkzIdRWlf4e/V3Rq+ONJnQ=");
}

#[test]
fn all_native_channels_build_protocol_payloads() {
    for provider in ["webhook", "bark", "telegram", "wecom", "feishu", "dingtalk", "ntfy", "gotify"] {
        let cfg = NotificationConfig { provider: provider.into(), url: "https://notify.example/topic".into(), token: "test-token".into(), secret: "demo".into(), ..Default::default() };
        let request = build_request(&cfg, "test", "标题", "带引号\"与换行\n", "warn", 1599360473000).unwrap();
        assert!(!request.body.is_empty());
        if provider != "ntfy" { serde_json::from_slice::<Value>(&request.body).unwrap(); }
        if provider == "feishu" { assert!(String::from_utf8_lossy(&request.body).contains("l1N0gAcB")); }
        if provider == "gotify" { assert_eq!(request.headers["x-gotify-key"], "test-token"); }
    }
}

#[test]
fn template_values_cannot_inject_json_fields() {
    let cfg = NotificationConfig { url: "https://notify.example".into(), body_template: r#"{"text":"{{message}}"}"#.into(), ..Default::default() };
    let message = "\",\"admin\":true,\"x\":\"";
    let request = build_request(&cfg, "test", "title", message, "info", 1000).unwrap();
    let value: Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(value["text"], message);
    assert_eq!(value.as_object().unwrap().len(), 1);
}

#[test]
fn provider_errors_are_not_successful_delivery() {
    for provider in ["telegram", "bark", "wecom", "feishu", "dingtalk", "ntfy", "gotify"] {
        let response = HttpResponse { status: http::StatusCode::OK, headers: http::HeaderMap::new(), body: br#"{"ok":false,"code":123,"errcode":123,"secret":"sensitive"}"#.to_vec() };
        let error = validate_delivery(provider, response).unwrap_err();
        assert!(!error.contains("sensitive"));
    }
}

#[tokio::test]
async fn skipped_channels_do_not_attempt_network() {
    let vault = Vault::from_master(&[1;32]);
    let cfg = NotificationConfig { url: "invalid".into(), min_severity: "error".into(), ..Default::default() };
    assert_eq!(dispatch_notification(&cfg, &vault, "test", "title", "body", "info").await.unwrap(), DeliveryOutcome::Skipped);
}

#[tokio::test]
async fn vault_secrets_are_decrypted_and_real_http_is_sent() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/notify", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        loop {
            let mut part = [0;1024];
            let n = stream.read(&mut part).await.unwrap();
            assert!(n > 0);
            bytes.extend_from_slice(&part[..n]);
            if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&bytes[..end]);
                let length: usize = headers.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").and_then(|v| v.trim().parse().ok())).unwrap();
                if bytes.len() >= end + 4 + length { break; }
            }
        }
        stream.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").await.unwrap();
        String::from_utf8(bytes).unwrap()
    });
    let vault = Vault::from_master(&[2;32]);
    let mut cfg = NotificationConfig { name: "local".into(), url: vault.seal("notifications.local.url", url.as_bytes()).unwrap(), ..Default::default() };
    cfg.headers.insert("authorization".into(), vault.seal("notifications.local.headers.authorization", b"Bearer test-token").unwrap());
    assert_eq!(dispatch_notification(&cfg, &vault, "test", "title", "message", "info").await.unwrap(), DeliveryOutcome::Sent);
    let request = task.await.unwrap();
    assert!(request.contains("Bearer test-token"));
    assert!(request.contains("message"));
    assert!(!request.contains("enc:v1:"));
}
