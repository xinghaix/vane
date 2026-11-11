//! 从真实 NDP 邻居表取得 IID 并持久化；从不根据 MAC 假设设备采用 EUI-64。
use crate::{config::{parse_mac, random_nonce, crash_safe_atomic_write}, daemon::netlink_ip::{is_public_gua_ipv6, list_interface_addresses, synthesize_subdevice_ipv6}};
use serde::{Deserialize,Serialize};
use std::{net::Ipv6Addr,path::Path,time::Duration};
use tokio::io::AsyncReadExt;

#[derive(Serialize,Deserialize)]
struct CachedNeighbor { interface:String, mac:String, iid:Ipv6Addr }

pub fn parse_neighbors(value: &serde_json::Value, mac: &str) -> Result<Vec<Ipv6Addr>, String> {
    let wanted=parse_mac(mac).ok_or("无效的邻居 MAC")?;
    let mut addresses=Vec::new();
    for entry in value.as_array().ok_or("NDP 邻居表 JSON 格式错误")? {
        if entry.get("lladdr").and_then(|v|v.as_str()).and_then(parse_mac)!=Some(wanted) {continue;}
        let unusable=entry.get("state").is_some_and(|state| {
            let text=state.to_string().to_ascii_uppercase();
            text.contains("FAILED") || text.contains("INCOMPLETE")
        });
        if unusable {continue;}
        if let Some(ip)=entry.get("dst").and_then(|v|v.as_str()).and_then(|s|s.parse::<Ipv6Addr>().ok()) {
            if is_public_gua_ipv6(ip) {addresses.push(ip);}
        }
    }
    addresses.sort();addresses.dedup();Ok(addresses)
}

async fn query(interface:&str) -> Result<Vec<u8>,String> {
    crate::firewall::validate_iface_name(interface)?;
    if !cfg!(target_os="linux") {return Err("NDP 查询仅支持 Linux；请使用 prefix_and_iid".into());}
    let mut child=tokio::process::Command::new("ip").args(["-j","-6","neigh","show","dev",interface])
        .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null())
        .kill_on_drop(true).spawn().map_err(|_| "无法执行 ip -j -6 neigh，请安装 iproute2")?;
    let mut output=Vec::new();
    let stdout=child.stdout.take().ok_or("无法读取邻居表")?;
    let result=tokio::time::timeout(Duration::from_secs(3),async {
        stdout.take(256*1024+1).read_to_end(&mut output).await.map_err(|_|"读取邻居表失败")?;
        if output.len()>256*1024 {return Err("邻居表超过大小限制");}
        if !child.wait().await.map_err(|_|"等待邻居表命令失败")?.success() {return Err("邻居表命令失败");}
        Ok(())
    }).await;
    match result {
        Ok(Ok(()))=>Ok(output),
        other=>{let _=child.kill().await;let _=child.wait().await;Err(match other {Ok(Err(e))=>e.into(),_=>"邻居表查询超时".into()})}
    }
}

pub async fn resolve(interface:&str,mac:&str,data_dir:&Path) -> Result<Option<Ipv6Addr>,String> {
    let prefix=list_interface_addresses().get(interface).and_then(|entry|entry.ipv6.iter().copied().find(|ip|is_public_gua_ipv6(*ip)));
    let Some(prefix)=prefix else {return Ok(None)};
    let mac_bytes=parse_mac(mac).ok_or("邻居 MAC 非法")?;
    crate::firewall::validate_iface_name(interface)?;
    let cache_path=data_dir.join(format!("neighbor-{}-{}.json",interface,mac_bytes.iter().map(|b|format!("{b:02x}")).collect::<String>()));
    let cached=if let Ok(file)=tokio::fs::File::open(&cache_path).await {
        let mut bytes=Vec::new();
        file.take(4097).read_to_end(&mut bytes).await.map_err(|_|"邻居缓存读取失败")?;
        if bytes.len()>4096 {return Err("邻居缓存超过限制".into());}
        serde_json::from_slice::<CachedNeighbor>(&bytes).ok()
            .filter(|cache|cache.interface==interface && parse_mac(&cache.mac)==Some(mac_bytes))
    } else {None};
    let bytes=query(interface).await?;
    let value=serde_json::from_slice(&bytes).map_err(|_|"NDP 响应不是合法 JSON")?;
    let addresses=parse_neighbors(&value,mac)?;
    let candidates:Vec<_>=addresses.into_iter().filter(|ip|ip.octets()[..8]==prefix.octets()[..8]).collect();
    let known=cached.as_ref().and_then(|cache|candidates.iter().copied().find(|ip|ip.octets()[8..]==cache.iid.octets()[8..]));
    let selected=known.or_else(||candidates.first().copied());
    if let Some(ip)=selected {
        if cached.as_ref().is_none_or(|old|old.iid.octets()[8..]!=ip.octets()[8..]) {
            let body=serde_json::to_vec(&CachedNeighbor{interface:interface.into(),mac:mac.into(),iid:ip}).map_err(|_|"邻居缓存序列化失败")?;
            let path=cache_path.clone();
            tokio::task::spawn_blocking(move||crash_safe_atomic_write(&path,&body,random_nonce()))
                .await.map_err(|_|"邻居缓存写入任务失败")?.map_err(|_|"邻居缓存落盘失败")?;
        }
        Ok(Some(ip))
    } else {Ok(cached.map(|cache|synthesize_subdevice_ipv6(prefix,cache.iid)))}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selects_observed_global_addresses_not_eui64_guesses() {
        let table=serde_json::json!([
            {"dst":"2606:4700::abcd","lladdr":"02:00:00:00:00:01","state":["STALE"]},
            {"dst":"fe80::1","lladdr":"02:00:00:00:00:01","state":["REACHABLE"]},
            {"dst":"2606:4700::2","lladdr":"02:00:00:00:00:01","state":["FAILED"]},
            {"dst":"2606:4700::3","lladdr":"02:00:00:00:00:02","state":["REACHABLE"]}
        ]);
        assert_eq!(parse_neighbors(&table,"02:00:00:00:00:01").unwrap(),vec!["2606:4700::abcd".parse::<Ipv6Addr>().unwrap()]);
    }
}
