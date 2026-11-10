//! 双栈 DNS 服务商接口（Cloudflare / Aliyun / DNSPod / Custom HTTP 模板）与 ACME TXT 记录管理。
use crate::config::{CustomHttpTemplate, DdnsConfig, DnsProviderConfig};
use std::net::IpAddr;

/// 渲染通用自定义 HTTP DDNS 模板（替换 {{ip}}, {{ipv4}}, {{ipv6}}, {{domain}}, {{token}}）
pub fn render_custom_http_template(
    tpl: &CustomHttpTemplate,
    domain: &str,
    ip: IpAddr,
    token: &str,
) -> (String, String, String) {
    let ip_s = ip.to_string();
    let (v4_s, v6_s) = match ip {
        IpAddr::V4(v4) => (v4.to_string(), String::new()),
        IpAddr::V6(v6) => (String::new(), v6.to_string()),
    };
    let replace_vars = |s: &str| -> String {
        s.replace("{{ip}}", &ip_s)
            .replace("{{ipv4}}", &v4_s)
            .replace("{{ipv6}}", &v6_s)
            .replace("{{domain}}", domain)
            .replace("{{token}}", token)
    };
    let method = if tpl.method.is_empty() { "GET".to_string() } else { tpl.method.to_ascii_uppercase() };
    (method, replace_vars(&tpl.url), replace_vars(&tpl.body))
}

/// 构造 DNS 记录更新Payload摘要（用于 Cloudflare / Aliyun / DNSPod 对账）
pub fn build_dns_update_request(
    provider: &DnsProviderConfig,
    ddns: &DdnsConfig,
    record_type: &str,
    ip: IpAddr,
) -> Result<serde_json::Value, String> {
    match provider.provider.as_str() {
        "cloudflare" => Ok(serde_json::json!({
            "type": record_type,
            "name": ddns.domain,
            "content": ip.to_string(),
            "ttl": if ddns.proxied { 1 } else { ddns.ttl.max(60) },
            "proxied": ddns.proxied,
            "comment": ddns.comment,
        })),
        "aliyun" => Ok(serde_json::json!({
            "Action": "UpdateDomainRecord",
            "DomainName": ddns.domain,
            "Type": record_type,
            "Value": ip.to_string(),
            "TTL": ddns.ttl.max(600),
            "Line": ddns.line,
        })),
        "dnspod" => Ok(serde_json::json!({
            "Domain": ddns.domain,
            "RecordType": record_type,
            "Value": ip.to_string(),
            "TTL": ddns.ttl.max(600),
            "RecordLine": ddns.line,
        })),
        other => Err(format!("不支持的 DNS 服务商: {}", other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_http_template_renders_variables() {
        let tpl = CustomHttpTemplate {
            method: "POST".into(),
            url: "https://dns.example.com/update?hostname={{domain}}&myip={{ip}}".into(),
            body: "token={{token}}&ip6={{ipv6}}".into(),
            ..Default::default()
        };
        let (m, u, b) = render_custom_http_template(&tpl, "home.example.com", "240e:3b0::1".parse().unwrap(), "sec123");
        assert_eq!(m, "POST");
        assert_eq!(u, "https://dns.example.com/update?hostname=home.example.com&myip=240e:3b0::1");
        assert_eq!(b, "token=sec123&ip6=240e:3b0::1");
    }
}
