//! OpenWrt fw4 (nftables) 驱动：在 table inet fw4 内挂载 vane_input / vane_forward / vane_dstnat 子链。
use crate::config::FirewallConfig;
use crate::firewall::{run_fw_cmd_async, FirewallRule};

pub async fn reset_chains(cfg: &FirewallConfig) -> Result<(), String> {
    apply_rules(cfg, &[]).await
}

pub async fn apply_rules(cfg: &FirewallConfig, rules: &[FirewallRule]) -> Result<(), String> {
    let cmds = build_nft_commands(cfg, rules);
    for args in cmds {
        let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let _ = run_fw_cmd_async("nft", &refs).await;
    }
    Ok(())
}

pub async fn add_ban_cidr(cidr: &str, duration_secs: u64) -> Result<(), String> {
    let set_name = if cidr.contains(':') { "vane_ban_v6" } else { "vane_ban_v4" };
    let elem = format!("{{ {} timeout {}s }}", cidr, duration_secs.clamp(60, 86_400));
    let _ = run_fw_cmd_async("nft", &["add", "element", "inet", "fw4", set_name, &elem]).await;
    Ok(())
}

pub fn build_nft_script(cfg: &FirewallConfig, rules: &[FirewallRule]) -> String {
    let mut lines = Vec::new();
    for cmd in build_nft_commands(cfg, rules) {
        lines.push(cmd.join(" "));
    }
    lines.join("
")
}

pub fn build_nft_commands(cfg: &FirewallConfig, rules: &[FirewallRule]) -> Vec<Vec<String>> {
    let mut cmds: Vec<Vec<String>> = Vec::new();
    for chain in ["vane_input", "vane_forward", "vane_dstnat"] {
        cmds.push(vec!["add".into(), "chain".into(), "inet".into(), "fw4".into(), chain.into()]);
        cmds.push(vec!["flush".into(), "chain".into(), "inet".into(), "fw4".into(), chain.into()]);
    }

    let wan_ifaces = if cfg.wan_interfaces.is_empty() {
        vec!["pppoe-wan".to_string()]
    } else {
        cfg.wan_interfaces.clone()
    };
    let lan_iface = cfg.lan_interfaces.first().cloned().unwrap_or_else(|| "br-lan".into());

    for r in rules {
        match r {
            FirewallRule::WanInput { proto, port, ipv4, ipv6, .. } => {
                for wan in &wan_ifaces {
                    if *ipv4 && *ipv6 {
                        cmds.push(vec![
                            "add".into(), "rule".into(), "inet".into(), "fw4".into(), "vane_input".into(),
                            "iifname".into(), wan.clone(), proto.clone(), "dport".into(), port.to_string(), "accept".into(),
                        ]);
                    } else if *ipv4 {
                        cmds.push(vec![
                            "add".into(), "rule".into(), "inet".into(), "fw4".into(), "vane_input".into(),
                            "meta".into(), "nfproto".into(), "ipv4".into(),
                            "iifname".into(), wan.clone(), proto.clone(), "dport".into(), port.to_string(), "accept".into(),
                        ]);
                    } else if *ipv6 {
                        cmds.push(vec![
                            "add".into(), "rule".into(), "inet".into(), "fw4".into(), "vane_input".into(),
                            "meta".into(), "nfproto".into(), "ipv6".into(),
                            "iifname".into(), wan.clone(), proto.clone(), "dport".into(), port.to_string(), "accept".into(),
                        ]);
                    }
                }
            }
            FirewallRule::KernelDnat { proto, listen_port, target, .. } => {
                let fam = if target.is_ipv6() { "ip6" } else { "ip" };
                for wan in &wan_ifaces {
                    cmds.push(vec![
                        "add".into(), "rule".into(), "inet".into(), "fw4".into(), "vane_dstnat".into(),
                        "iifname".into(), wan.clone(), proto.clone(), "dport".into(), listen_port.to_string(),
                        "dnat".into(), fam.into(), "to".into(), target.to_string(),
                    ]);
                    cmds.push(vec![
                        "add".into(), "rule".into(), "inet".into(), "fw4".into(), "vane_forward".into(),
                        "iifname".into(), wan.clone(), fam.into(), "daddr".into(), target.ip().to_string(),
                        proto.clone(), "dport".into(), target.port().to_string(), "accept".into(),
                    ]);
                }
            }
            FirewallRule::SubDeviceIpv6Forward { device_ip, tcp_ports, udp_ports, .. } => {
                for wan in &wan_ifaces {
                    for p in tcp_ports {
                        cmds.push(vec![
                            "add".into(), "rule".into(), "inet".into(), "fw4".into(), "vane_forward".into(),
                            "iifname".into(), wan.clone(), "oifname".into(), lan_iface.clone(),
                            "ip6".into(), "daddr".into(), device_ip.to_string(),
                            "tcp".into(), "dport".into(), p.to_string(), "accept".into(),
                        ]);
                    }
                    for p in udp_ports {
                        cmds.push(vec![
                            "add".into(), "rule".into(), "inet".into(), "fw4".into(), "vane_forward".into(),
                            "iifname".into(), wan.clone(), "oifname".into(), lan_iface.clone(),
                            "ip6".into(), "daddr".into(), device_ip.to_string(),
                            "udp".into(), "dport".into(), p.to_string(), "accept".into(),
                        ]);
                    }
                }
            }
        }
    }
    cmds
}
