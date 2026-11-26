//! OpenWrt fw3 (iptables / ip6tables) 双栈子链驱动：
//! 使用 `iptables-restore --noflush` / `ip6tables-restore --noflush` 单事务原子替换 VANE_BAN 与放行链，
//! 彻底消除清空重加窗口（Fail-Open）与上千次子进程开销；幂等挂载父链 jump 且保证 VANE_BAN 置顶。
use crate::config::FirewallConfig;
use crate::firewall::{validate_iface_name, validate_proto, FirewallExecutor, FirewallRule};
use crate::net::dual_stack::BanKey;
use std::collections::BTreeMap;

fn restore_binary(ipt_bin: &str) -> String {
    format!("{}-restore", ipt_bin)
}

async fn ensure_jump(
    exec: &dyn FirewallExecutor,
    bin: &str,
    table: &str,
    chain: &str,
    parent: &str,
    position: &str,
) -> Result<bool, String> {
    if exec
        .run(bin, &["-w", "2", "-t", table, "-C", parent, "-j", chain], None)
        .await
        .is_err()
    {
        exec.run(bin, &["-w", "2", "-t", table, "-I", parent, position, "-j", chain], None)
            .await?;
        return Ok(true);
    }
    Ok(false)
}

pub fn build_iptables_restore_script(
    is_ipv6: bool,
    cfg: &FirewallConfig,
    rules: &[FirewallRule],
    bans: &BTreeMap<BanKey, u64>,
    include_nat: bool,
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
        "*filter".to_string(),
        ":VANE_INPUT - [0:0]".to_string(),
        ":VANE_FORWARD - [0:0]".to_string(),
        ":VANE_BAN - [0:0]".to_string(),
        "-F VANE_INPUT".to_string(),
        "-F VANE_FORWARD".to_string(),
        "-F VANE_BAN".to_string(),
    ];

    for key in bans.keys() {
        let matches_fam = match key {
            BanKey::V4(_) => !is_ipv6,
            BanKey::V6Prefix64(_) => is_ipv6,
        };
        if matches_fam {
            lines.push(format!("-A VANE_BAN -s {} -j DROP", key.display_cidr()));
        }
    }

    for r in rules {
        match r {
            FirewallRule::WanInput {
                proto,
                port,
                ipv4,
                ipv6,
                ..
            } => {
                validate_proto(proto)?;
                if (!is_ipv6 && *ipv4) || (is_ipv6 && *ipv6) {
                    for wan in &wan_ifaces {
                        lines.push(format!(
                            "-A VANE_INPUT -i {} -p {} --dport {} -j ACCEPT",
                            wan, proto, port
                        ));
                    }
                }
            }
            FirewallRule::KernelDnat { proto, target, .. } => {
                validate_proto(proto)?;
                if target.is_ipv6() == is_ipv6 {
                    for wan in &wan_ifaces {
                        lines.push(format!(
                            "-A VANE_FORWARD -i {} -p {} -d {} --dport {} -m conntrack --ctstate DNAT -j ACCEPT",
                            wan,
                            proto,
                            target.ip(),
                            target.port()
                        ));
                    }
                }
            }
            FirewallRule::SubDeviceIpv6Forward {
                device_ip,
                tcp_ports,
                udp_ports,
                ..
            } => {
                if is_ipv6 {
                    for wan in &wan_ifaces {
                        for lan in &lan_ifaces {
                            for p in tcp_ports {
                                lines.push(format!(
                                    "-A VANE_FORWARD -i {} -o {} -p tcp -d {} --dport {} -j ACCEPT",
                                    wan, lan, device_ip, p
                                ));
                            }
                            for p in udp_ports {
                                lines.push(format!(
                                    "-A VANE_FORWARD -i {} -o {} -p udp -d {} --dport {} -j ACCEPT",
                                    wan, lan, device_ip, p
                                ));
                            }
                        }
                    }
                }
            }
        }
    }
    lines.push("COMMIT".to_string());

    if include_nat {
        lines.push("*nat".to_string());
        lines.push(":VANE_PREROUTING - [0:0]".to_string());
        lines.push("-F VANE_PREROUTING".to_string());
        for r in rules {
            if let FirewallRule::KernelDnat {
                proto,
                listen_port,
                target,
                ..
            } = r
            {
                validate_proto(proto)?;
                if target.is_ipv6() == is_ipv6 {
                    for wan in &wan_ifaces {
                        lines.push(format!(
                            "-A VANE_PREROUTING -i {} -p {} --dport {} -j DNAT --to-destination {}",
                            wan, proto, listen_port, target
                        ));
                    }
                }
            }
        }
        lines.push("COMMIT".to_string());
    }

    lines.push(String::new());
    Ok(lines.join("\n"))
}

/// 仅原子清空 WAN 放行链（VANE_INPUT / VANE_FORWARD / VANE_PREROUTING），完整保留 VANE_BAN 封禁链
pub fn build_lockdown_preserve_bans_script(include_nat: bool) -> String {
    let mut lines = vec![
        "*filter".to_string(),
        ":VANE_INPUT - [0:0]".to_string(),
        ":VANE_FORWARD - [0:0]".to_string(),
        "-F VANE_INPUT".to_string(),
        "-F VANE_FORWARD".to_string(),
        "COMMIT".to_string(),
    ];
    if include_nat {
        lines.push("*nat".to_string());
        lines.push(":VANE_PREROUTING - [0:0]".to_string());
        lines.push("-F VANE_PREROUTING".to_string());
        lines.push("COMMIT".to_string());
    }
    lines.push(String::new());
    lines.join("\n")
}

pub async fn apply_lockdown_preserve_bans(
    exec: &dyn FirewallExecutor,
    ipt4: &str,
    ipt6: &str,
) -> Result<(), String> {
    let v4_script = build_lockdown_preserve_bans_script(true);
    let v6_script = build_lockdown_preserve_bans_script(false);
    let restore4 = restore_binary(ipt4);
    let restore6 = restore_binary(ipt6);
    exec.run(&restore4, &["--noflush", "-w", "2"], Some(v4_script.as_bytes()))
        .await?;
    exec.run(&restore6, &["--noflush", "-w", "2"], Some(v6_script.as_bytes()))
        .await?;
    let _ = exec
        .run(ipt6, &["-w", "2", "-t", "nat", "-F", "VANE_PREROUTING"], None)
        .await;
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
    let has_v6_dnat = rules
        .iter()
        .any(|r| matches!(r, FirewallRule::KernelDnat { target, .. } if target.is_ipv6()));

    let v4_script = build_iptables_restore_script(false, cfg, rules, bans, true)?;
    let v6_script = build_iptables_restore_script(true, cfg, rules, bans, has_v6_dnat)?;
    let restore4 = restore_binary(ipt4);
    let restore6 = restore_binary(ipt6);

    // 单次原子提交所有自定义链规则与 VANE_BAN，消除先 flush 再逐条添加的 Fail-Open 窗口
    exec.run(&restore4, &["--noflush", "-w", "2"], Some(v4_script.as_bytes()))
        .await?;
    exec.run(&restore6, &["--noflush", "-w", "2"], Some(v6_script.as_bytes()))
        .await?;

    if !has_v6_dnat {
        // 部分精简内核未编译 ip6table_nat；无 IPv6 DNAT 规则时仅做最佳努力清空旧链
        let _ = exec
            .run(ipt6, &["-w", "2", "-t", "nat", "-F", "VANE_PREROUTING"], None)
            .await;
    }

    for bin in [ipt4, ipt6] {
        let in_added = ensure_jump(exec, bin, "filter", "VANE_INPUT", "zone_wan_input", "1").await?;
        let fwd_added = ensure_jump(exec, bin, "filter", "VANE_FORWARD", "zone_wan_forward", "1").await?;
        // VANE_BAN 始终位于第 1 位，若前面刚新插入了放行链则重新置顶以确保优先执行 DROP
        let ban_in_added = ensure_jump(exec, bin, "filter", "VANE_BAN", "zone_wan_input", "1").await?;
        if in_added && !ban_in_added {
            let _ = exec
                .run(bin, &["-w", "2", "-t", "filter", "-D", "zone_wan_input", "-j", "VANE_BAN"], None)
                .await;
            exec.run(
                bin,
                &["-w", "2", "-t", "filter", "-I", "zone_wan_input", "1", "-j", "VANE_BAN"],
                None,
            )
            .await?;
        }
        let ban_fwd_exists = exec
            .run(bin, &["-w", "2", "-t", "filter", "-C", "zone_wan_forward", "-j", "VANE_BAN"], None)
            .await
            .is_ok();
        if !ban_fwd_exists || fwd_added {
            if ban_fwd_exists {
                let _ = exec
                    .run(bin, &["-w", "2", "-t", "filter", "-D", "zone_wan_forward", "-j", "VANE_BAN"], None)
                    .await;
            }
            exec.run(
                bin,
                &["-w", "2", "-t", "filter", "-I", "zone_wan_forward", "1", "-j", "VANE_BAN"],
                None,
            )
            .await?;
        }
    }

    ensure_jump(exec, ipt4, "nat", "VANE_PREROUTING", "zone_wan_prerouting", "1").await?;
    if has_v6_dnat {
        ensure_jump(exec, ipt6, "nat", "VANE_PREROUTING", "zone_wan_prerouting", "1").await?;
    }
    Ok(())
}
