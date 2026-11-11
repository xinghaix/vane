//! DNS 服务商真实 CRUD：Cloudflare v4、阿里云 RPC 与 DNSPod TC3。
use crate::{config::DnsProviderConfig, logger, net::http_client::{shared, HttpRequest}, security::{auth::url_encode, vault::Vault}};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ring::{digest, hmac};
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct Zone { pub id: String, pub name: String }
#[derive(Clone, Debug)]
pub struct Record { pub id: String, pub name: String, pub kind: String, pub content: String, pub line: String }
#[derive(Clone, Debug)]
pub struct RecordSpec {
    pub name: String, pub kind: String, pub content: String,
    pub ttl: u32, pub proxied: bool, pub line: String, pub comment: String,
}

pub struct DnsApi { cfg: DnsProviderConfig, endpoint: String }

fn sha256(text: &[u8]) -> String { digest::digest(&digest::SHA256, text).as_ref().iter().map(|b| format!("{b:02x}")).collect() }
fn sign256(key: &[u8], data: &str) -> Vec<u8> { hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data.as_bytes()).as_ref().to_vec() }

pub fn aliyun_signature(parameters: &BTreeMap<String, String>, secret: &str) -> String {
    let query = parameters.iter().map(|(k,v)| format!("{}={}",url_encode(k),url_encode(v))).collect::<Vec<_>>().join("&");
    let to_sign = format!("POST&%2F&{}", url_encode(&query));
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, format!("{secret}&").as_bytes());
    B64.encode(hmac::sign(&key, to_sign.as_bytes()).as_ref())
}

pub fn tc3_authorization(id: &str, secret: &str, host: &str, timestamp: u64, body: &[u8]) -> String {
    let date = logger::format_iso8601_utc(timestamp)[..10].to_string();
    let scope = format!("{date}/dnspod/tc3_request");
    let canonical = format!("POST\n/\n\ncontent-type:application/json; charset=utf-8\nhost:{host}\n\ncontent-type;host\n{}", sha256(body));
    let string_to_sign = format!("TC3-HMAC-SHA256\n{timestamp}\n{scope}\n{}", sha256(canonical.as_bytes()));
    let date_key = sign256(format!("TC3{secret}").as_bytes(), &date);
    let service_key = sign256(&date_key, "dnspod");
    let signing_key = sign256(&service_key, "tc3_request");
    let signature: String = sign256(&signing_key, &string_to_sign).iter().map(|b| format!("{b:02x}")).collect();
    format!("TC3-HMAC-SHA256 Credential={id}/{scope}, SignedHeaders=content-type;host, Signature={signature}")
}

fn text(value: &Value, key: &str) -> Result<String, String> {
    match value.get(key) { Some(Value::String(s)) => Ok(s.clone()), Some(Value::Number(n)) => Ok(n.to_string()), _ => Err(format!("DNS 响应缺少 {key}")) }
}
fn within_zone(name: &str, zone: &str) -> bool { name == zone || name.ends_with(&format!(".{zone}")) }
fn relative_name(name: &str, zone: &Zone) -> Result<String, String> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    if name == zone.name { return Ok("@".into()); }
    name.strip_suffix(&format!(".{}", zone.name)).map(str::to_string).ok_or_else(|| "记录不属于指定 DNS 区域".into())
}
fn dnspod_line(line: &str) -> &str {
    match line { "default" => "默认", "telecom" => "电信", "unicom" => "联通", "mobile" => "移动", "oversea" => "境外", other => other }
}

impl DnsApi {
    #[cfg(test)]
    pub(crate) fn with_test_endpoint(mut self, endpoint:String) -> Self { self.endpoint=endpoint; self }

    pub fn new(id: &str, cfg: &DnsProviderConfig, vault: &Vault) -> Result<Self, String> {
        let endpoint = match cfg.provider.as_str() {
            "cloudflare" => "https://api.cloudflare.com/client/v4",
            "aliyun" => "https://alidns.aliyuncs.com/",
            "dnspod" => "https://dnspod.tencentcloudapi.com/",
            _ => return Err("不支持的 DNS 服务商".into()),
        };
        let mut plain = cfg.clone();
        plain.api_token = vault.reveal_string(&format!("dns_providers.{id}.api_token"), &cfg.api_token)?;
        plain.secret_key = vault.reveal_string(&format!("dns_providers.{id}.secret_key"), &cfg.secret_key)?;
        if plain.api_token.is_empty() || (plain.provider != "cloudflare" && plain.secret_key.is_empty()) { return Err("DNS 服务商凭据未配置".into()); }
        Ok(Self { cfg: plain, endpoint: endpoint.into() })
    }

    async fn cloudflare(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value, String> {
        let mut request = HttpRequest::new(method, &format!("{}{path}", self.endpoint));
        request.headers.insert("authorization".into(), format!("Bearer {}", self.cfg.api_token));
        request.happy_eyeballs_delay_ms = self.cfg.happy_eyeballs_delay_ms;
        if let Some(body) = body { request = request.json(&body); }
        let value = shared().execute(request).await?.json()?;
        if value.get("success").and_then(Value::as_bool) != Some(true) { return Err("Cloudflare 拒绝 DNS 请求".into()); }
        Ok(value)
    }

    async fn rpc(&self, action: &str, payload: Value) -> Result<Value, String> {
        let mut request = HttpRequest::new("POST", &self.endpoint);
        request.happy_eyeballs_delay_ms = self.cfg.happy_eyeballs_delay_ms;
        if self.cfg.provider == "aliyun" {
            let mut parameters: BTreeMap<String,String> = payload.as_object().ok_or("非法 RPC 参数")?.iter()
                .map(|(k,v)| (k.clone(), v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string()))).collect();
            parameters.extend([
                ("Action".into(), action.into()), ("Format".into(), "JSON".into()), ("Version".into(), "2015-01-09".into()),
                ("AccessKeyId".into(), self.cfg.api_token.clone()), ("SignatureMethod".into(), "HMAC-SHA1".into()),
                ("SignatureVersion".into(), "1.0".into()), ("SignatureNonce".into(), format!("{:016x}{:016x}", crate::config::random_nonce(), crate::config::random_nonce())),
                ("Timestamp".into(), logger::format_iso8601_utc(logger::unix_now())),
            ]);
            parameters.insert("Signature".into(), aliyun_signature(&parameters, &self.cfg.secret_key));
            request.headers.insert("content-type".into(), "application/x-www-form-urlencoded".into());
            request.body = parameters.iter().map(|(k,v)| format!("{}={}",url_encode(k),url_encode(v))).collect::<Vec<_>>().join("&").into_bytes();
            let value = shared().execute(request).await?.json()?;
            if value.get("Code").is_some() { return Err("阿里云拒绝 DNS 请求".into()); }
            Ok(value)
        } else {
            request = request.json(&payload);
            request.headers.insert("content-type".into(), "application/json; charset=utf-8".into());
            let timestamp = logger::unix_now();
            let uri: http::Uri = self.endpoint.parse().map_err(|_| "非法服务商端点")?;
            let host = uri.authority().ok_or("缺少服务商主机")?.as_str();
            request.headers.insert("authorization".into(), tc3_authorization(&self.cfg.api_token, &self.cfg.secret_key, host, timestamp, &request.body));
            request.headers.insert("x-tc-action".into(), action.into());
            request.headers.insert("x-tc-timestamp".into(), timestamp.to_string());
            request.headers.insert("x-tc-version".into(), "2021-03-23".into());
            let value = shared().execute(request).await?.json()?;
            let response = value.get("Response").ok_or("DNSPod 响应缺少 Response")?;
            if let Some(error) = response.get("Error") {
                if action == "DescribeRecordList" && error.get("Code").and_then(Value::as_str) == Some("ResourceNotFound.NoDataOfRecord") {
                    return Ok(json!({"RecordList":[],"RecordCountInfo":{"TotalCount":0}}));
                }
                return Err("DNSPod 拒绝 DNS 请求".into());
            }
            Ok(response.clone())
        }
    }

    pub async fn zone(&self, name: &str) -> Result<Zone, String> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        if !self.cfg.zone_name.is_empty() {
            let zone_name = self.cfg.zone_name.trim_end_matches('.').to_ascii_lowercase();
            if !within_zone(&name, &zone_name) { return Err("记录不属于配置的 zone_name".into()); }
            if self.cfg.provider != "cloudflare" || !self.cfg.zone_id.is_empty() {
                return Ok(Zone { id: self.cfg.zone_id.clone(), name: zone_name });
            }
        }
        if self.cfg.provider == "cloudflare" {
            let labels: Vec<_> = name.split('.').collect();
            let candidates: Vec<_> = if self.cfg.zone_name.is_empty() {
                (0..labels.len().saturating_sub(1)).map(|index|labels[index..].join(".")).collect()
            } else {vec![self.cfg.zone_name.trim_end_matches('.').to_ascii_lowercase()]};
            for candidate in candidates {
                let value = self.cloudflare("GET", &format!("/zones?name={}&per_page=50",url_encode(&candidate)), None).await?;
                if let Some(zone) = value.get("result").and_then(Value::as_array).and_then(|v| v.first()) {
                    let zone = Zone { id: text(zone,"id")?, name: text(zone,"name")?.to_ascii_lowercase() };
                    if !within_zone(&name, &zone.name) { return Err("服务商返回了不匹配的区域".into()); }
                    return Ok(zone);
                }
            }
        } else {
            let mut best: Option<Zone> = None;
            for page in 0..100u64 {
                let value = if self.cfg.provider == "aliyun" {
                    self.rpc("DescribeDomains", json!({"PageNumber":page+1,"PageSize":100})).await?
                } else { self.rpc("DescribeDomainList", json!({"Offset":page*100,"Limit":100})).await? };
                let zones = if self.cfg.provider == "aliyun" { value.pointer("/Domains/Domain") } else { value.get("DomainList") }
                    .and_then(Value::as_array).ok_or("DNS 区域列表格式错误")?;
                for zone in zones {
                    let zone_name = text(zone, if self.cfg.provider == "aliyun" { "DomainName" } else { "Name" })?.to_ascii_lowercase();
                    if within_zone(&name, &zone_name) && best.as_ref().is_none_or(|old| old.name.len() < zone_name.len()) {
                        best = Some(Zone { id: String::new(), name: zone_name });
                    }
                }
                let total = if self.cfg.provider == "aliyun" { value.get("TotalCount") } else { value.pointer("/DomainCountInfo/AllTotal") }.and_then(Value::as_u64);
                if zones.len() < 100 || total.is_some_and(|n| (page+1)*100 >= n) { return best.ok_or_else(|| "未发现托管 DNS 区域".into()); }
            }
            return Err("DNS 区域列表超过发现上限，请显式设置 zone_name".into());
        }
        Err("未发现托管 DNS 区域".into())
    }

    pub async fn records(&self, zone: &Zone, name: &str, kind: &str) -> Result<Vec<Record>, String> {
        let relative = relative_name(name, zone)?;
        let mut records = Vec::new();
        for page in 0..100u64 {
            let value = match self.cfg.provider.as_str() {
                "cloudflare" => self.cloudflare("GET", &format!("/zones/{}/dns_records?name={}&type={}&per_page=100&page={}", url_encode(&zone.id), url_encode(name), url_encode(kind), page+1), None).await?,
                "aliyun" => self.rpc("DescribeDomainRecords",json!({"DomainName":zone.name,"RRKeyWord":relative,"TypeKeyWord":kind,"SearchMode":"EXACT","PageSize":100,"PageNumber":page+1})).await?,
                _ => self.rpc("DescribeRecordList",json!({"Domain":zone.name,"Subdomain":relative,"RecordType":kind,"Limit":100,"Offset":page*100})).await?,
            };
            let array = match self.cfg.provider.as_str() {
                "cloudflare" => value.get("result"), "aliyun" => value.pointer("/DomainRecords/Record"), _ => value.get("RecordList"),
            }.and_then(Value::as_array).ok_or("DNS 记录列表格式错误")?;
            for record in array {
                let (id_key,name_key,kind_key,value_key) = match self.cfg.provider.as_str() {
                    "cloudflare" => ("id","name","type","content"), "aliyun" => ("RecordId","RR","Type","Value"), _ => ("RecordId","Name","Type","Value"),
                };
                let mut record_name = text(record,name_key)?;
                if self.cfg.provider != "cloudflare" { record_name = if record_name == "@" { zone.name.clone() } else { format!("{record_name}.{}",zone.name) }; }
                let record_kind = text(record,kind_key)?;
                if record_name.trim_end_matches('.').eq_ignore_ascii_case(name.trim_end_matches('.')) && record_kind == kind {
                    records.push(Record { id:text(record,id_key)?, name:record_name, kind:record_kind, content:text(record,value_key)?, line:record.get("Line").and_then(Value::as_str).unwrap_or("default").into() });
                }
            }
            let total = match self.cfg.provider.as_str() { "cloudflare" => value.pointer("/result_info/total_count"), "aliyun" => value.get("TotalCount"), _ => value.pointer("/RecordCountInfo/TotalCount") }.and_then(Value::as_u64);
            if array.len() < 100 || total.is_some_and(|n| (page+1)*100 >= n) { return Ok(records); }
        }
        Err("DNS 记录列表超过安全分页上限".into())
    }

    pub async fn write_record(&self, zone: &Zone, spec: &RecordSpec, id: Option<&str>) -> Result<String, String> {
        let relative = relative_name(&spec.name, zone)?;
        match self.cfg.provider.as_str() {
            "cloudflare" => {
                let path = format!("/zones/{}/dns_records{}", url_encode(&zone.id), id.map(|id|format!("/{}",url_encode(id))).unwrap_or_default());
                let mut body = json!({"type":spec.kind,"name":spec.name,"content":spec.content,"ttl":spec.ttl,"comment":spec.comment});
                if matches!(spec.kind.as_str(),"A"|"AAAA"|"CNAME") { body["proxied"] = json!(spec.proxied); }
                if spec.kind == "SRV" {
                    let parts: Vec<_> = spec.content.split_whitespace().collect();
                    if parts.len()!=4 { return Err("SRV 值必须为 priority weight port target".into()); }
                    let parse = |s:&str| s.parse::<u16>().map_err(|_| "SRV 数值非法".to_string());
                    body.as_object_mut().unwrap().remove("content");
                    body["data"] = json!({"priority":parse(parts[0])?,"weight":parse(parts[1])?,"port":parse(parts[2])?,"target":parts[3]});
                }
                let value = self.cloudflare(if id.is_some(){"PATCH"}else{"POST"}, &path, Some(body)).await?;
                text(value.get("result").ok_or("缺少 DNS 记录结果")?,"id")
            },
            "aliyun" => {
                let mut body = json!({"RR":relative,"Type":spec.kind,"Value":spec.content,"TTL":spec.ttl,"Line":spec.line});
                let action = if let Some(id)=id { body["RecordId"]=json!(id); "UpdateDomainRecord" } else { body["DomainName"]=json!(zone.name); "AddDomainRecord" };
                text(&self.rpc(action,body).await?,"RecordId")
            },
            _ => {
                let mut body = json!({"Domain":zone.name,"SubDomain":relative,"RecordType":spec.kind,"Value":spec.content,"TTL":spec.ttl,"RecordLine":dnspod_line(&spec.line)});
                let action = if let Some(id)=id { body["RecordId"]=json!(id.parse::<u64>().map_err(|_| "DNSPod 记录 ID 非法")?); "ModifyRecord" } else { "CreateRecord" };
                text(&self.rpc(action,body).await?,"RecordId")
            },
        }
    }

    pub async fn upsert(&self, zone: &Zone, spec: &RecordSpec) -> Result<String, String> {
        let existing: Vec<_> = self.records(zone, &spec.name, &spec.kind).await?.into_iter().filter(|record| self.matches_line(record, &spec.line)).collect();
        // 多值记录必须明确选择，不允许随意覆盖其他记录。
        if existing.len() > 1 { return Err("存在多条同名同类型 DNS 记录，拒绝不明确的更新".into()); }
        self.write_record(zone, spec, existing.first().map(|record| record.id.as_str())).await
    }

    pub fn matches_line(&self, record: &Record, line: &str) -> bool {
        self.cfg.provider == "cloudflare" || record.line == line || (self.cfg.provider == "dnspod" && record.line == dnspod_line(line))
    }

    pub async fn delete(&self, zone: &Zone, id: &str) -> Result<(), String> {
        match self.cfg.provider.as_str() {
            "cloudflare" => { self.cloudflare("DELETE", &format!("/zones/{}/dns_records/{}",url_encode(&zone.id),url_encode(id)),None).await?; },
            "aliyun" => { self.rpc("DeleteDomainRecord",json!({"RecordId":id})).await?; },
            _ => { self.rpc("DeleteRecord",json!({"Domain":zone.name,"RecordId":id.parse::<u64>().map_err(|_| "DNSPod 记录 ID 非法")?})).await?; },
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "dns_api_tests.rs"]
mod tests;
