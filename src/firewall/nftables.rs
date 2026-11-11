//! OpenWrt fw4 (nftables) 驱动：单事务原子提交 table inet vane_shield（高优先级封禁集）
//! 与 table inet fw4 子链（vane_input / vane_forward / vane_dstnat），并幂等挂载父链 jump。
use crate::config::FirewallConfig;
use crate::firewall::{validate_iface_name, validate_proto, FirewallExecutor, FirewallRule};
use crate::net::dual_stack::BanKey;
use std::collections::BTreeMap;

pub async fn apply_rules(
    exec: &dyn FirewallExecutor,
    cfg: &FirewallConfig,
    rules: &[FirewallRule],
    bans: &BTreeMap<BanKey, u64>,
    now_unix: u64,
) -> Result<(), String> {
    let script = build_nft_script(cfg, rules, bans, now_unix)?;
    exec.run("nft", &["-f", "-"], Some(script.as_bytes())).await?;
    ensure_fw4_jumps(exec).await
}

pub async fn ensure_fw4_jumps(exec: &dyn FirewallExecutor) -> Result<(), String> {
    for (parent, child) in [
        ("input_wan", "vane_input"),
        ("forward_wan", "vane_forward"),
        ("dstnat_wan", "vane_dstnat"),
    ] {
        let listed = exec.run("nft", &["list", "chain", "inet", "fw4", parent], None).await?;
        let needle = format!("jump {}", child);
        if !listed.lines().any(|line| line.trim().ends_with(&needle) || line.contains(&format!("jump {} ", child))) {
            exec.run("nft", &["insert", "rule", "inet", "fw4", parent, "jump", child], None)
                .await?;
        }
    }
    Ok(())
}

pub async fn add_ban_cidr(exec: &dyn FirewallExecutor, cidr: &str, duration_secs: u64) -> Result<(), String> {
    let set_name = if cidr.contains(':') { "ban_v6" } else { "ban_v4" };
    let dur = duration_secs.clamp(60, 86_400);
    let elem = format!("{{ {} timeout {}s }}", cidr, dur);
    exec.run("nft", &["add", "element", "inet", "vane_shield", set_name, &elem], None)
        .await
        .map(|_| ())
}

pub async fn remove_ban_cidr(exec: &dyn FirewallExecutor, cidr: &str) -> Result<(), String> {
    let set_name = if cidr.contains(':') { "ban_v6" } else { "ban_v4" };
    let elem = format!("{{ {} }}", cidr);
    match exec
        .run("nft", &["delete", "element", "inet", "vane_shield", set_name, &elem], None)
        .await
    {
        Ok(_) => Ok(()),
        Err(e) if e.contains("No such file") || e.contains("element does not exist") => Ok(()),
        Err(e) => Err(e),
    }
}

pub fn build_nft_script(
    cfg: &FirewallConfig,
    rules: &[FirewallRule],
    bans: &BTreeMap<BanKey, u64>,
    now_unix: u64,
) -> Result<String, String> {
    let wan_ifaces = if cfg.wan_interfaces.is_empty() {
        vec!["pppoe-wan".to_string()]
    } else {
        cfg.wan_interfaces.clone()
    };
    let lan_ifaces = if cfg.lan_interfaces.is_empty() {
        vec!["br-lan".to_string()]
    } else {
        cfg.lan_interfaces.clone()
    };
    for iface in wan_ifaces.iter().chain(lan_ifaces.iter()) {
        validate_iface_name(iface)?;
    }

    let mut lines = vec![
        "add table inet vane_shield".to_string(),
        "flush table inet vane_shield".to_string(),
        "add set inet vane_shield ban_v4 { type ipv4_addr; flags interval, timeout; }".to_string(),
        "add set inet vane_shield ban_v6 { type ipv6_addr; flags interval, timeout; }".to_string(),
        "add chain inet vane_shield prerouting { type filter hook prerouting priority filter - 10; policy accept; }"
            .to_string(),
        "add rule inet vane_shield prerouting ip saddr @ban_v4 counter drop".to_string(),
        "add rule inet vane_shield prerouting ip6 saddr @ban_v6 counter drop".to_string(),
    ];

    for (key, exp) in bans {
        if *exp <= now_unix {
            continue;
        }
        let rem = (*exp - now_unix).clamp(1, 86_400);
        let cidr = key.display_cidr();
        let set_name = match key {
            BanKey::V4(_) => "ban_v4",
            BanKey::V6Prefix64(_) => "ban_v6",
        };
        lines.push(format!("add element inet vane_shield {} {{ {} timeout {}s }}", set_name, cidr, rem));
    }

    for chain in ["vane_input", "vane_forward", "vane_dstnat"] {
        lines.push(format!("add chain inet fw4 {}", chain));
        lines.push(format!("flush chain inet fw4 {}", chain));
    }

    for r in rules {
        match r {
            FirewallRule::WanInput { proto, port, ipv4, ipv6, .. } => {
                validate_proto(proto)?;
                for wan in &wan_ifaces {
                    if *ipv4 && *ipv6 {
                        lines.push(format!(
                            "add rule inet fw4 vane_input iifname \"{}\" {} dport {} accept",
                            wan, proto, port
                        ));
                    } else if *ipv4 {
                        lines.push(format!(
                            "add rule inet fw4 vane_input meta nfproto ipv4 iifname \"{}\" {} dport {} accept",
                            wan, proto, port
                        ));
                    } else if *ipv6 {
                        lines.push(format!(
                            "add rule inet fw4 vane_input meta nfproto ipv6 iifname \"{}\" {} dport {} accept",
                            wan, proto, port
                        ));
                    }
                }
            }
            FirewallRule::KernelDnat { proto, listen_port, target, .. } => {
                validate_proto(proto)?;
                let fam = if target.is_ipv6() { "ip6" } else { "ip" };
                for wan in &wan_ifaces {
                    lines.push(format!(
                        "add rule inet fw4 vane_dstnat iifname \"{}\" {} dport {} dnat {} to {}",
                        wan, proto, listen_port, fam, target
                    ));
                    lines.push(format!(
                        "add rule inet fw4 vane_forward iifname \"{}\" {} daddr {} {} dport {} accept",
                        wan,
                        fam,
                        target.ip(),
                        proto,
                        target.port()
                    ));
                }
            }
            FirewallRule::SubDeviceIpv6Forward { device_ip, tcp_ports, udp_ports, .. } => {
                for wan in &wan_ifaces {
                    for lan in &lan_ifaces {
                        for p in tcp_ports {
                            lines.push(format!(
                                "add rule inet fw4 vane_forward iifname \"{}\" oifname \"{}\" ip6 daddr {} tcp dport {} accept",
                                wan, lan, device_ip, p
                            ));
                        }
                        for p in udp_ports {
                            lines.push(format!(
                                "add rule inet fw4 vane_forward iifname \"{}\" oifname \"{}\" ip6 daddr {} udp dport {} accept",
                                wan, lan, device_ip, p
                            ));
                        }
                    }
                }
            }
        }
    }

    lines.push(String::new());
    Ok(lines.join("
"))
}
