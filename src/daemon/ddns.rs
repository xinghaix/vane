//! 全栈事件驱动 DDNS 状态机：接口公网地址提取、子设备 /128 IPv6 合成与防火墙 FORWARD 原子放行。
use crate::config::{parse_cidr, parse_mac, cidr_contains, DdnsConfig, DdnsSource};
use crate::daemon::netlink_ip::{
    is_public_gua_ipv6, is_public_ipv4, list_interface_addresses, synthesize_eui64_ipv6, synthesize_subdevice_ipv6,
};
use crate::firewall::{FirewallManager, FirewallRule};
use crate::logger::{self, Level};
use serde::Serialize;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};

#[derive(Clone, Debug, Default, Serialize)]
pub struct DdnsStatus {
    pub name: String,
    pub domain: String,
    pub enabled: bool,
    pub last_ipv4: Option<String>,
    pub last_ipv6: Option<String>,
    pub last_sync_unix: u64,
    pub status: String,
}

pub type DdnsStatusMap = Arc<RwLock<BTreeMap<String, DdnsStatus>>>;

/// 根据 DDNS 规则解析当前有效的公网 (IPv4, IPv6) 地址
pub fn resolve_ddns_addresses(cfg: &DdnsConfig) -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
    let ifaces = list_interface_addresses();
    match &cfg.source {
        DdnsSource::Interface { name, preferred_subnet, index } => {
            let Some(iface) = ifaces.get(name) else { return (None, None) };
            let v4 = iface.ipv4.iter().copied().filter(|ip| is_public_ipv4(*ip)).nth(*index);
            let v6_candidates: Vec<Ipv6Addr> = iface.ipv6.iter().copied().filter(|ip| is_public_gua_ipv6(*ip)).collect();
            if !preferred_subnet.is_empty() {
                if let Ok(cidr) = parse_cidr(preferred_subnet) {
                    if let Some(pref) = v6_candidates.iter().copied().find(|ip| cidr_contains(&cidr, IpAddr::V6(*ip))) {
                        return (v4, Some(pref));
                    }
                }
            }
            (v4, v6_candidates.get(*index).copied())
        }
        DdnsSource::PrefixAndIid { prefix_iface, iid } => {
            let Some(iface) = ifaces.get(prefix_iface) else { return (None, None) };
            let Some(prefix) = iface.ipv6.iter().copied().find(|ip| is_public_gua_ipv6(*ip)) else {
                return (None, None);
            };
            let Ok(iid_addr) = iid.parse::<Ipv6Addr>() else { return (None, None) };
            (None, Some(synthesize_subdevice_ipv6(prefix, iid_addr)))
        }
        DdnsSource::NeighborMac { prefix_iface, mac } => {
            let Some(iface) = ifaces.get(prefix_iface) else { return (None, None) };
            let Some(prefix) = iface.ipv6.iter().copied().find(|ip| is_public_gua_ipv6(*ip)) else {
                return (None, None);
            };
            let Some(mac_bytes) = parse_mac(mac) else { return (None, None) };
            (None, Some(synthesize_eui64_ipv6(prefix, mac_bytes)))
        }
        _ => (None, None),
    }
}

/// 执行单条 DDNS 对账并同步子设备 /128 IPv6 防火墙 FORWARD 规则
pub async fn sync_ddns_entry(
    cfg: &DdnsConfig,
    firewall: &FirewallManager,
    status_map: &DdnsStatusMap,
) -> Result<DdnsStatus, String> {
    let (v4, v6) = resolve_ddns_addresses(cfg);
    let want_v4 = cfg.records.iter().any(|r| r == "A");
    let want_v6 = cfg.records.iter().any(|r| r == "AAAA");

    if want_v6 {
        if let Some(ip6) = v6 {
            if !cfg.firewall_allow_tcp_ports.is_empty() || !cfg.firewall_allow_udp_ports.is_empty() {
                let _ = firewall
                    .upsert_rule(FirewallRule::SubDeviceIpv6Forward {
                        owner_module: "ddns".into(),
                        rule_name: cfg.name.clone(),
                        device_ip: ip6,
                        tcp_ports: cfg.firewall_allow_tcp_ports.clone(),
                        udp_ports: cfg.firewall_allow_udp_ports.clone(),
                    })
                    .await;
            }
        }
    }

    let st = DdnsStatus {
        name: cfg.name.clone(),
        domain: cfg.domain.clone(),
        enabled: cfg.enabled,
        last_ipv4: if want_v4 { v4.map(|ip| ip.to_string()) } else { None },
        last_ipv6: if want_v6 { v6.map(|ip| ip.to_string()) } else { None },
        last_sync_unix: logger::unix_now(),
        status: if (want_v4 && v4.is_some()) || (want_v6 && v6.is_some()) {
            "synced".into()
        } else {
            format!("waiting_public_ip ({})", cfg.on_missing_public_ip)
        },
    };
    if let Ok(mut g) = status_map.write() {
        g.insert(cfg.name.clone(), st.clone());
    }
    logger::log(Level::Info, "ddns", &format!("DDNS {} ({}) 同步完成: v4={:?}, v6={:?}", cfg.name, cfg.domain, st.last_ipv4, st.last_ipv6));
    Ok(st)
}
