//! OpenWrt fw3 (iptables-legacy / ip6tables-legacy) 双栈子链驱动。
use crate::config::FirewallConfig;
use crate::firewall::{run_fw_cmd_async, FirewallRule};

pub async fn reset_chains(ipt4: &str, ipt6: &str, cfg: &FirewallConfig) -> Result<(), String> {
    apply_rules(ipt4, ipt6, cfg, &[]).await
}

pub async fn apply_rules(ipt4: &str, ipt6: &str, cfg: &FirewallConfig, rules: &[FirewallRule]) -> Result<(), String> {
    for bin in [ipt4, ipt6] {
        for (table, chain, parent) in [
            ("filter", "VANE_INPUT", "zone_wan_input"),
            ("filter", "VANE_FORWARD", "zone_wan_forward"),
            ("nat", "VANE_PREROUTING", "zone_wan_prerouting"),
        ] {
            let _ = run_fw_cmd_async(bin, &["-w", "2", "-t", table, "-N", chain]).await;
            let _ = run_fw_cmd_async(bin, &["-w", "2", "-t", table, "-F", chain]).await;
            if run_fw_cmd_async(bin, &["-w", "2", "-t", table, "-C", parent, "-j", chain]).await.is_err() {
                let _ = run_fw_cmd_async(bin, &["-w", "2", "-t", table, "-I", parent, "1", "-j", chain]).await;
            }
        }
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
                let port_s = port.to_string();
                for wan in &wan_ifaces {
                    if *ipv4 {
                        let _ = run_fw_cmd_async(
                            ipt4,
                            &["-w", "2", "-A", "VANE_INPUT", "-i", wan, "-p", proto, "--dport", &port_s, "-j", "ACCEPT"],
                        )
                        .await;
                    }
                    if *ipv6 {
                        let _ = run_fw_cmd_async(
                            ipt6,
                            &["-w", "2", "-A", "VANE_INPUT", "-i", wan, "-p", proto, "--dport", &port_s, "-j", "ACCEPT"],
                        )
                        .await;
                    }
                }
            }
            FirewallRule::KernelDnat { proto, listen_port, target, .. } => {
                let bin = if target.is_ipv6() { ipt6 } else { ipt4 };
                let lport = listen_port.to_string();
                let dst = target.to_string();
                let dip = target.ip().to_string();
                let dport = target.port().to_string();
                for wan in &wan_ifaces {
                    let _ = run_fw_cmd_async(
                        bin,
                        &["-w", "2", "-t", "nat", "-A", "VANE_PREROUTING", "-i", wan, "-p", proto, "--dport", &lport, "-j", "DNAT", "--to-destination", &dst],
                    )
                    .await;
                    let _ = run_fw_cmd_async(
                        bin,
                        &["-w", "2", "-A", "VANE_FORWARD", "-i", wan, "-p", proto, "-d", &dip, "--dport", &dport, "-j", "ACCEPT"],
                    )
                    .await;
                }
            }
            FirewallRule::SubDeviceIpv6Forward { device_ip, tcp_ports, udp_ports, .. } => {
                let dip = device_ip.to_string();
                for wan in &wan_ifaces {
                    for p in tcp_ports {
                        let ps = p.to_string();
                        let _ = run_fw_cmd_async(
                            ipt6,
                            &["-w", "2", "-A", "VANE_FORWARD", "-i", wan, "-o", &lan_iface, "-p", "tcp", "-d", &dip, "--dport", &ps, "-j", "ACCEPT"],
                        )
                        .await;
                    }
                    for p in udp_ports {
                        let ps = p.to_string();
                        let _ = run_fw_cmd_async(
                            ipt6,
                            &["-w", "2", "-A", "VANE_FORWARD", "-i", wan, "-o", &lan_iface, "-p", "udp", "-d", &dip, "--dport", &ps, "-j", "ACCEPT"],
                        )
                        .await;
                    }
                }
            }
        }
    }
    Ok(())
}

pub async fn add_ban_cidr(ipt4: &str, ipt6: &str, cidr: &str) -> Result<(), String> {
    let bin = if cidr.contains(':') { ipt6 } else { ipt4 };
    let _ = run_fw_cmd_async(bin, &["-w", "2", "-I", "VANE_INPUT", "1", "-s", cidr, "-j", "DROP"]).await;
    Ok(())
}
