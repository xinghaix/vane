//! OpenWrt fw3 (iptables / ip6tables) 双栈子链驱动：严格传播命令错误，独立维护 VANE_BAN 链防止刷新丢失封禁。
use crate::config::FirewallConfig;
use crate::firewall::{validate_iface_name, validate_proto, FirewallExecutor, FirewallRule};
use crate::net::dual_stack::BanKey;
use std::collections::BTreeMap;

async fn ensure_chain_and_jump(
    exec: &dyn FirewallExecutor,
    bin: &str,
    table: &str,
    chain: &str,
    parent: &str,
    position: &str,
) -> Result<(), String> {
    if let Err(e) = exec.run(bin, &["-w", "2", "-t", table, "-N", chain], None).await {
        if !e.contains("Chain already exists") {
            exec.run(bin, &["-w", "2", "-t", table, "-L", chain, "-n"], None)
                .await
                .map_err(|_| e)?;
        }
    }
    exec.run(bin, &["-w", "2", "-t", table, "-F", chain], None).await?;
    if exec
        .run(bin, &["-w", "2", "-t", table, "-C", parent, "-j", chain], None)
        .await
        .is_err()
    {
        exec.run(bin, &["-w", "2", "-t", table, "-I", parent, position, "-j", chain], None)
            .await?;
    }
    Ok(())
}

pub async fn apply_rules(
    exec: &dyn FirewallExecutor,
    ipt4: &str,
    ipt6: &str,
    cfg: &FirewallConfig,
    rules: &[FirewallRule],
    bans: &BTreeMap<BanKey, u64>,
) -> Result<(), String> {
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

    let has_v6_dnat = rules
        .iter()
        .any(|r| matches!(r, FirewallRule::KernelDnat { target, .. } if target.is_ipv6()));

    for bin in [ipt4, ipt6] {
        ensure_chain_and_jump(exec, bin, "filter", "VANE_INPUT", "zone_wan_input", "1").await?;
        ensure_chain_and_jump(exec, bin, "filter", "VANE_FORWARD", "zone_wan_forward", "1").await?;
        // VANE_BAN 始终插入到第 1 位，确保优先于 VANE_INPUT / VANE_FORWARD 放行规则执行 DROP
        ensure_chain_and_jump(exec, bin, "filter", "VANE_BAN", "zone_wan_input", "1").await?;
        if exec
            .run(bin, &["-w", "2", "-t", "filter", "-C", "zone_wan_forward", "-j", "VANE_BAN"], None)
            .await
            .is_err()
        {
            exec.run(
                bin,
                &["-w", "2", "-t", "filter", "-I", "zone_wan_forward", "1", "-j", "VANE_BAN"],
                None,
            )
            .await?;
        }
    }

    ensure_chain_and_jump(exec, ipt4, "nat", "VANE_PREROUTING", "zone_wan_prerouting", "1").await?;
    if has_v6_dnat {
        ensure_chain_and_jump(exec, ipt6, "nat", "VANE_PREROUTING", "zone_wan_prerouting", "1").await?;
    } else {
        // 部分精简内核未编译 ip6table_nat；无 IPv6 DNAT 规则时仅做最佳努力清空旧链
        let _ = exec.run(ipt6, &["-w", "2", "-t", "nat", "-F", "VANE_PREROUTING"], None).await;
    }

    for key in bans.keys() {
        let cidr = key.display_cidr();
        let bin = match key {
            BanKey::V4(_) => ipt4,
            BanKey::V6Prefix64(_) => ipt6,
        };
        exec.run(bin, &["-w", "2", "-t", "filter", "-A", "VANE_BAN", "-s", &cidr, "-j", "DROP"], None)
            .await?;
    }

    for r in rules {
        match r {
            FirewallRule::WanInput { proto, port, ipv4, ipv6, .. } => {
                validate_proto(proto)?;
                let port_s = port.to_string();
                for wan in &wan_ifaces {
                    if *ipv4 {
                        exec.run(
                            ipt4,
                            &["-w", "2", "-A", "VANE_INPUT", "-i", wan, "-p", proto, "--dport", &port_s, "-j", "ACCEPT"],
                            None,
                        )
                        .await?;
                    }
                    if *ipv6 {
                        exec.run(
                            ipt6,
                            &["-w", "2", "-A", "VANE_INPUT", "-i", wan, "-p", proto, "--dport", &port_s, "-j", "ACCEPT"],
                            None,
                        )
                        .await?;
                    }
                }
            }
            FirewallRule::KernelDnat { proto, listen_port, target, .. } => {
                validate_proto(proto)?;
                let bin = if target.is_ipv6() { ipt6 } else { ipt4 };
                let lport = listen_port.to_string();
                let dst = target.to_string();
                let dip = target.ip().to_string();
                let dport = target.port().to_string();
                for wan in &wan_ifaces {
                    exec.run(
                        bin,
                        &[
                            "-w",
                            "2",
                            "-t",
                            "nat",
                            "-A",
                            "VANE_PREROUTING",
                            "-i",
                            wan,
                            "-p",
                            proto,
                            "--dport",
                            &lport,
                            "-j",
                            "DNAT",
                            "--to-destination",
                            &dst,
                        ],
                        None,
                    )
                    .await?;
                    exec.run(
                        bin,
                        &["-w", "2", "-A", "VANE_FORWARD", "-i", wan, "-p", proto, "-d", &dip, "--dport", &dport, "-j", "ACCEPT"],
                        None,
                    )
                    .await?;
                }
            }
            FirewallRule::SubDeviceIpv6Forward { device_ip, tcp_ports, udp_ports, .. } => {
                let dip = device_ip.to_string();
                for wan in &wan_ifaces {
                    for lan in &lan_ifaces {
                        for p in tcp_ports {
                            let ps = p.to_string();
                            exec.run(
                                ipt6,
                                &[
                                    "-w",
                                    "2",
                                    "-A",
                                    "VANE_FORWARD",
                                    "-i",
                                    wan,
                                    "-o",
                                    lan,
                                    "-p",
                                    "tcp",
                                    "-d",
                                    &dip,
                                    "--dport",
                                    &ps,
                                    "-j",
                                    "ACCEPT",
                                ],
                                None,
                            )
                            .await?;
                        }
                        for p in udp_ports {
                            let ps = p.to_string();
                            exec.run(
                                ipt6,
                                &[
                                    "-w",
                                    "2",
                                    "-A",
                                    "VANE_FORWARD",
                                    "-i",
                                    wan,
                                    "-o",
                                    lan,
                                    "-p",
                                    "udp",
                                    "-d",
                                    &dip,
                                    "--dport",
                                    &ps,
                                    "-j",
                                    "ACCEPT",
                                ],
                                None,
                            )
                            .await?;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}
