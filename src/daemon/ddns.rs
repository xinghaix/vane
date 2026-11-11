//! DDNS 对账：只有服务商确认后更新成功状态，IPv4/IPv6 分别报告，规则级互斥。
use crate::config::{cidr_contains, parse_cidr, Config, DdnsConfig, DdnsSource};
use crate::daemon::{dns_api::{DnsApi, RecordSpec, Zone}, netlink_ip::{extract_ip_from_text, is_public_gua_ipv6, is_public_ipv4, list_interface_addresses, synthesize_subdevice_ipv6}};
use crate::firewall::{FirewallManager, FirewallRule};
use crate::logger::{self, Level};
use crate::net::http_client::{shared, AddressFamily, HttpRequest};
use crate::security::{auth::url_encode, vault::Vault};
use serde::Serialize;
use std::{collections::BTreeMap, net::{IpAddr, Ipv4Addr, Ipv6Addr}, ops::Deref, sync::{Arc, Mutex, RwLock, Weak}};

#[derive(Clone, Debug, Default, Serialize)]
pub struct FamilyStatus {
    pub action: String,
    pub address: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct DdnsStatus {
    pub name: String,
    pub domain: String,
    pub provider: String,
    pub enabled: bool,
    pub last_ipv4: Option<String>,
    pub last_ipv6: Option<String>,
    pub last_sync_unix: u64,
    pub last_attempt_unix: u64,
    pub ipv4: FamilyStatus,
    pub ipv6: FamilyStatus,
    pub firewall_error: Option<String>,
    pub status: String,
}

#[derive(Default)]
pub struct DdnsRuntime {
    statuses: RwLock<BTreeMap<String, DdnsStatus>>,
    locks: Mutex<BTreeMap<String, Weak<tokio::sync::Mutex<()>>>>,
    data_dir: std::path::PathBuf,
}
impl Deref for DdnsRuntime {
    type Target = RwLock<BTreeMap<String, DdnsStatus>>;
    fn deref(&self) -> &Self::Target { &self.statuses }
}
pub type DdnsStatusMap = Arc<DdnsRuntime>;
impl DdnsRuntime {
    pub fn new(data_dir: std::path::PathBuf) -> Self { Self { data_dir, ..Default::default() } }
    fn rule_lock(&self, name: &str) -> Result<Arc<tokio::sync::Mutex<()>>, String> {
        let mut locks = self.locks.lock().map_err(|_| "DDNS 锁状态损坏")?;
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(name).and_then(Weak::upgrade) { return Ok(lock); }
        if locks.len() >= 256 { return Err("DDNS 并发规则数超过上限".into()); }
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        locks.insert(name.into(), Arc::downgrade(&lock));
        Ok(lock)
    }
}

type AddressResult = Result<Option<IpAddr>, String>;

/// 无网络请求的接口地址源；外部查询及邻居表由异步路径处理。
pub fn resolve_ddns_addresses(cfg: &DdnsConfig) -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
    let ifaces = list_interface_addresses();
    match &cfg.source {
        DdnsSource::Interface { name, preferred_subnet, index } => {
            let Some(iface) = ifaces.get(name) else { return (None, None) };
            let v4 = iface.ipv4.iter().copied().filter(|ip| is_public_ipv4(*ip)).nth(*index);
            let candidates: Vec<_> = iface.ipv6.iter().copied().filter(|ip| is_public_gua_ipv6(*ip)).collect();
            let preferred = parse_cidr(preferred_subnet).ok().and_then(|cidr| candidates.iter().copied().filter(|ip| cidr_contains(&cidr, IpAddr::V6(*ip))).nth(*index));
            (v4, preferred.or_else(|| candidates.get(*index).copied()))
        }
        DdnsSource::PrefixAndIid { prefix_iface, iid } => {
            let prefix = ifaces.get(prefix_iface).and_then(|iface| iface.ipv6.iter().copied().find(|ip| is_public_gua_ipv6(*ip)));
            (None, prefix.zip(iid.parse().ok()).map(|(prefix, iid)| synthesize_subdevice_ipv6(prefix, iid)))
        }
        _ => (None, None),
    }
}

async fn external_address(url: &str, want_v6: bool, force_family: bool) -> AddressResult {
    if url.is_empty() { return Ok(None); }
    let mut request = HttpRequest::new("GET", url);
    request.response_limit = 16 * 1024;
    if force_family { request.family = if want_v6 { AddressFamily::Ipv6 } else { AddressFamily::Ipv4 }; }
    let response = shared().execute(request).await?;
    response.ensure_success()?;
    let text = std::str::from_utf8(&response.body).map_err(|_| "公网 IP 响应不是 UTF-8")?;
    let ip = extract_ip_from_text(text, want_v6).ok_or("公网 IP 响应缺少对应地址族")?;
    let public = match ip { IpAddr::V4(ip) => is_public_ipv4(ip), IpAddr::V6(ip) => is_public_gua_ipv6(ip) };
    Ok(public.then_some(ip))
}

async fn resolve_addresses(cfg: &DdnsConfig, runtime: &DdnsRuntime, vault: &Vault) -> (AddressResult, AddressResult) {
    let want_v4 = cfg.records.iter().any(|r| r == "A");
    let want_v6 = cfg.records.iter().any(|r| r == "AAAA");
    match &cfg.source {
        DdnsSource::ExternalUrl { url_v4, url_v6 } => {
            let v4_url=vault.reveal_string(&format!("ddns.{}.source.url_v4",cfg.name),url_v4);
            let v6_url=vault.reveal_string(&format!("ddns.{}.source.url_v6",cfg.name),url_v6);
            tokio::join!(async { if want_v4 { external_address(&v4_url?, false, true).await } else { Ok(None) } },
                async { if want_v6 { external_address(&v6_url?, true, true).await } else { Ok(None) } })
        }
        DdnsSource::CustomHttpExtract { url } => {
            let url=match vault.reveal_string(&format!("ddns.{}.source.url",cfg.name),url) {Ok(url)=>url,Err(error)=>return (Err(error.clone()),Err(error))};
            tokio::join!(async { if want_v4 { external_address(&url, false, false).await } else { Ok(None) } },
                async { if want_v6 { external_address(&url, true, false).await } else { Ok(None) } })
        }
        DdnsSource::NeighborMac { prefix_iface, mac } => (Ok(None), super::neighbor::resolve(prefix_iface,mac,&runtime.data_dir).await.map(|ip|ip.map(IpAddr::V6))),
        _ => { let (v4,v6) = resolve_ddns_addresses(cfg); (Ok(v4.map(IpAddr::V4)), Ok(v6.map(IpAddr::V6))) }
    }
}

fn template(text: &str, cfg: &DdnsConfig, ip: IpAddr, encode: bool) -> String {
    let mut result = text.to_string();
    let ip_text = ip.to_string();
    for (key,value) in [("{{ip}}",ip_text.as_str()),("{{ipv4}}",if ip.is_ipv4(){&ip_text}else{""}),
        ("{{ipv6}}",if ip.is_ipv6(){&ip_text}else{""}),("{{domain}}",cfg.domain.as_str()),("{{token}}",cfg.token.as_str())] {
        result = result.replace(key, &if encode { url_encode(value) } else { value.into() });
    }
    result
}

fn json_template(value: &mut serde_json::Value, cfg: &DdnsConfig, ip: IpAddr) {
    match value {
        serde_json::Value::String(text) => *text = template(text,cfg,ip,false),
        serde_json::Value::Array(values) => { for value in values { json_template(value,cfg,ip); } },
        serde_json::Value::Object(values) => { for value in values.values_mut() { json_template(value,cfg,ip); } },
        _ => {},
    }
}

async fn custom_update(cfg: &DdnsConfig, ip: IpAddr) -> Result<(), String> {
    let tpl = &cfg.custom_http;
    let mut request = HttpRequest::new(if tpl.method.is_empty(){"GET"}else{&tpl.method}, &template(&tpl.url,cfg,ip,true));
    for (name,value) in &tpl.headers { request.headers.insert(name.clone(),template(value,cfg,ip,false)); }
    let content_type = tpl.headers.iter().find(|(key,_)|key.eq_ignore_ascii_case("content-type")).map(|(_,v)|v.as_str()).unwrap_or("");
    if content_type.starts_with("application/json") && !tpl.body.is_empty() {
        let mut value = serde_json::from_str(&tpl.body).map_err(|_| "自定义 DDNS JSON 模板格式错误")?;
        json_template(&mut value,cfg,ip);
        request.body = serde_json::to_vec(&value).map_err(|_| "序列化 DDNS JSON 失败")?;
    } else { request.body = template(&tpl.body,cfg,ip,content_type.starts_with("application/x-www-form-urlencoded")).into_bytes(); }
    request.response_limit = 64 * 1024;
    let response = shared().execute(request).await?;
    response.ensure_success()?;
    if !tpl.success_keyword.is_empty() && !String::from_utf8_lossy(&response.body).contains(&tpl.success_keyword) {
        return Err("自定义 DDNS 响应未包含成功关键字".into());
    }
    Ok(())
}

enum Backend { Native(DnsApi, Zone), Custom(DdnsConfig) }
impl Backend {
    async fn prepare(cfg: &DdnsConfig, all: &Config, vault: &Vault) -> Result<Self,String> {
        if cfg.provider == "custom_http" {
            let mut plain = cfg.clone();
            let prefix = format!("ddns.{}", cfg.name);
            plain.token = vault.reveal_string(&format!("{prefix}.token"), &cfg.token)?;
            plain.custom_http.url = vault.reveal_string(&format!("{prefix}.custom_http.url"), &cfg.custom_http.url)?;
            plain.custom_http.body = vault.reveal_string(&format!("{prefix}.custom_http.body"), &cfg.custom_http.body)?;
            for (key,value) in &mut plain.custom_http.headers { *value = vault.reveal_string(&format!("{prefix}.custom_http.headers.{key}"), value)?; }
            return Ok(Self::Custom(plain));
        }
        let provider = all.dns_providers.get(&cfg.provider).ok_or("DDNS 服务商不存在")?;
        let api = DnsApi::new(&cfg.provider, provider, vault)?;
        let zone = api.zone(&cfg.domain).await?;
        Ok(Self::Native(api,zone))
    }
    async fn apply(&self, cfg: &DdnsConfig, kind: &str, ip: Option<IpAddr>) -> Result<(),String> {
        match self {
            Self::Custom(plain) => match ip { Some(ip) => custom_update(plain,ip).await, None => Err("自定义 HTTP 不支持隐式删除记录".into()) },
            Self::Native(api,zone) => {
                if let Some(ip) = ip {
                    api.upsert(zone,&RecordSpec { name:cfg.domain.clone(), kind:kind.into(),content:ip.to_string(),ttl:if cfg.proxied{1}else{cfg.ttl},proxied:cfg.proxied,line:cfg.line.clone(),comment:cfg.comment.clone() }).await?;
                } else {
                    for record in api.records(zone,&cfg.domain,kind).await?.into_iter().filter(|record| api.matches_line(record,&cfg.line)) { api.delete(zone,&record.id).await?; }
                }
                Ok(())
            }
        }
    }
}

async fn reconcile_family(cfg: &DdnsConfig, kind: &str, address: AddressResult, backend: &Result<Backend,String>) -> FamilyStatus {
    if !cfg.records.iter().any(|r| r == kind) { return FamilyStatus { action:"disabled".into(), ..Default::default() }; }
    let address = match address { Ok(ip) => ip, Err(e) => return FamilyStatus { action:"failed".into(),error:Some(e),..Default::default() } };
    if address.is_none() && cfg.on_missing_public_ip == "keep_existing" {
        return FamilyStatus { action:"kept_missing_ip".into(), ..Default::default() };
    }
    let result = match backend { Ok(api) => api.apply(cfg,kind,address).await, Err(e) => Err(e.clone()) };
    match result {
        Ok(()) => FamilyStatus { action:if address.is_some(){"synced"}else{"deleted"}.into(),address:address.map(|ip|ip.to_string()),error:None },
        Err(e) => FamilyStatus { action:"failed".into(),error:Some(e),address:None },
    }
}

/// 手动和定时调用共享规则锁；取消会释放锁，不影响其他规则。
pub async fn sync_ddns_entry(cfg: &DdnsConfig, all: &Config, vault: &Vault, firewall: &FirewallManager, status_map: &DdnsStatusMap) -> Result<DdnsStatus, String> {
    let lock = status_map.rule_lock(&cfg.name)?;
    let _guard = lock.lock().await;
    let old = status_map.read().map_err(|_| "DDNS 状态锁损坏")?.get(&cfg.name).cloned()
        .filter(|old| old.domain == cfg.domain && old.provider == cfg.provider).unwrap_or_default();
    let prev_status = old.status.clone();
    let prev_v4 = old.last_ipv4.clone();
    let prev_v6 = old.last_ipv6.clone();
    let mut status = DdnsStatus { name:cfg.name.clone(),domain:cfg.domain.clone(),provider:cfg.provider.clone(),enabled:cfg.enabled && all.modules.ddns,
        last_ipv4:old.last_ipv4, last_ipv6:old.last_ipv6, last_sync_unix:old.last_sync_unix,last_attempt_unix:logger::unix_now(),..Default::default() };
    if !status.enabled {
        firewall.remove_rule("ddns",&cfg.name).await?;
        status.status = "disabled".into();
    } else {
        let (v4,v6) = resolve_addresses(cfg,status_map,vault).await;
        let needs_provider = [("A",&v4),("AAAA",&v6)].into_iter().any(|(kind,address)|
            cfg.records.iter().any(|r|r==kind) && matches!(address,Ok(Some(_))))
            || cfg.on_missing_public_ip == "delete_record" && [("A",&v4),("AAAA",&v6)].into_iter()
                .any(|(kind,address)|cfg.records.iter().any(|r|r==kind) && matches!(address,Ok(None)));
        let backend = if needs_provider { Backend::prepare(cfg,all,vault).await } else { Err("无需服务商请求".into()) };
        let (a,aaaa) = tokio::join!(reconcile_family(cfg,"A",v4,&backend),reconcile_family(cfg,"AAAA",v6,&backend));
        status.ipv4 = a; status.ipv6 = aaaa;
        for (family,last) in [(&status.ipv4,&mut status.last_ipv4),(&status.ipv6,&mut status.last_ipv6)] {
            if matches!(family.action.as_str(),"synced"|"deleted") { *last=family.address.clone(); }
        }
        let failed = status.ipv4.error.is_some() || status.ipv6.error.is_some();
        let success = [status.ipv4.action.as_str(),status.ipv6.action.as_str()].iter().any(|a| matches!(*a,"synced"|"deleted"));
        let missing = status.ipv4.action=="kept_missing_ip" || status.ipv6.action=="kept_missing_ip";
        status.status = if failed { if success {"partial"} else {"failed"} } else if missing { if success {"partial"}else{"waiting_public_ip"} } else {"synced"}.into();
        if !failed && !missing { status.last_sync_unix=logger::unix_now(); }
        // 缺失或失败立即撤销旧 /128 放行；只为明确的子设备源开放 FORWARD。
        let allowed = matches!(cfg.source,DdnsSource::PrefixAndIid{..}|DdnsSource::NeighborMac{..}) && status.ipv6.action=="synced";
        let next = if allowed { status.last_ipv6.as_ref().and_then(|ip|ip.parse::<Ipv6Addr>().ok()) } else {None};
        let existing = firewall.list_rules().into_iter().find(|rule| rule.owner()=="ddns" && rule.name()==cfg.name);
        let unchanged = matches!(existing.as_ref(),Some(FirewallRule::SubDeviceIpv6Forward{device_ip,tcp_ports,udp_ports,..})
            if Some(*device_ip)==next && *tcp_ports==cfg.firewall_allow_tcp_ports && *udp_ports==cfg.firewall_allow_udp_ports);
        let result = async {
            if unchanged { return Ok(()); }
            if existing.is_some() { firewall.remove_rule("ddns",&cfg.name).await?; }
            if let Some(device_ip)=next {
                if !cfg.firewall_allow_tcp_ports.is_empty() || !cfg.firewall_allow_udp_ports.is_empty() {
                    firewall.upsert_rule(FirewallRule::SubDeviceIpv6Forward { owner_module:"ddns".into(),rule_name:cfg.name.clone(),device_ip,
                        tcp_ports:cfg.firewall_allow_tcp_ports.clone(),udp_ports:cfg.firewall_allow_udp_ports.clone() }).await?;
                }
            }
            Ok::<(),String>(())
        }.await;
        if let Err(error)=result {status.firewall_error=Some(error);status.status="partial".into();status.last_sync_unix=old.last_sync_unix;}
    }
    status_map.write().map_err(|_| "DDNS 状态锁损坏")?.insert(cfg.name.clone(),status.clone());
    logger::log(if status.status=="failed"{Level::Warn}else{Level::Info},"ddns",&format!("DDNS {} 对账状态: {}",cfg.name,status.status));
    if status.enabled {
        if (status.last_ipv4 != prev_v4 || status.last_ipv6 != prev_v6)
            && matches!(status.status.as_str(), "synced" | "partial")
        {
            let msg = format!(
                "域名 {} 公网解析已同步 (IPv4={:?}, IPv6={:?})",
                cfg.domain, status.last_ipv4, status.last_ipv6
            );
            super::notify::broadcast_event(all, vault, "ddns_change", &format!("DDNS 更新: {}", cfg.name), &msg, "info")
                .await;
        } else if status.status == "failed" && prev_status != "failed" {
            let err_detail = status
                .ipv4
                .error
                .as_deref()
                .or(status.ipv6.error.as_deref())
                .unwrap_or("未知错误");
            super::notify::broadcast_event(
                all,
                vault,
                "ddns_failure",
                &format!("DDNS 同步失败: {}", cfg.name),
                &format!("域名 {} 对账失败: {}", cfg.domain, err_detail),
                "warning",
            )
            .await;
        }
    }
    Ok(status)
}

#[cfg(test)]
#[path = "ddns_tests.rs"]
mod tests;
