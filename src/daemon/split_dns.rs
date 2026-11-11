//! 生成仅由 Vane 管理的 dnsmasq addn-hosts 文件，不覆盖系统 hosts。
use crate::config::{Config,crash_safe_atomic_write,random_nonce};
use std::{collections::BTreeSet,path::Path};

pub fn render(cfg:&Config) -> Result<String,String> {
    let mut lines=BTreeSet::new();
    if cfg.modules.ddns {
        for entry in cfg.ddns.iter().filter(|entry|entry.enabled) {
            crate::config::validate_domain(&entry.domain)?;
            if entry.domain.starts_with("*.") && !entry.split_dns_lan_ips.is_empty() {return Err("Split DNS hosts 不支持通配域名".into());}
            for ip in &entry.split_dns_lan_ips {
                let ip:std::net::IpAddr=ip.parse().map_err(|_|"Split DNS 地址非法")?;
                lines.insert(format!("{} {}",ip,entry.domain.trim_end_matches('.').to_ascii_lowercase()));
            }
        }
    }
    Ok(format!("# 由 Vane 自动生成，请通过管理配置修改。\n{}",lines.into_iter().map(|line|format!("{line}\n")).collect::<String>()))
}

pub async fn reconcile(cfg:&Config,data_dir:&Path) -> Result<bool,String> {
    let body=render(cfg)?;
    let path=data_dir.join("split-dns.hosts");
    if tokio::fs::read(&path).await.ok().as_deref()==Some(body.as_bytes()) {return Ok(false);}
    tokio::task::spawn_blocking(move||crash_safe_atomic_write(&path,body.as_bytes(),random_nonce()))
        .await.map_err(|_|"Split DNS 写入任务失败")?.map_err(|_|"Split DNS 文件写入失败")?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn produces_deterministic_dual_stack_hosts_and_removes_disabled_entries() {
        let mut cfg=Config::default();
        cfg.ddns.push(crate::config::DdnsConfig {name:"home".into(),domain:"home.example.com".into(),split_dns_lan_ips:vec!["192.168.1.10".into(),"fd00::10".into(),"192.168.1.10".into()],..Default::default()});
        let text=render(&cfg).unwrap();
        assert_eq!(text.matches("192.168.1.10").count(),1);
        assert!(text.contains("fd00::10 home.example.com"));
        let dir=std::env::temp_dir().join(format!("vane_split_test_{}",random_nonce()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(reconcile(&cfg,&dir).await.unwrap());
        assert!(!reconcile(&cfg,&dir).await.unwrap());
        cfg.modules.ddns=false;
        assert!(reconcile(&cfg,&dir).await.unwrap());
        assert!(!std::fs::read_to_string(dir.join("split-dns.hosts")).unwrap().contains("home.example.com"));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
