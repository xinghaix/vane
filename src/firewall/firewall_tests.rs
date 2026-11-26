use super::*;
use crate::config::FirewallConfig;
use std::sync::Mutex;

type RecordedCall = (String, Vec<String>, Option<String>);

#[derive(Default)]
struct RecordingExecutor {
    calls: Mutex<Vec<RecordedCall>>,
    fail_on_substr: Mutex<Option<String>>,
    existing_jumps: Mutex<Vec<String>>,
}

impl RecordingExecutor {
    fn snapshot(&self) -> Vec<RecordedCall> {
        self.calls.lock().unwrap().clone()
    }

    fn set_fail_substr(&self, pat: Option<&str>) {
        *self.fail_on_substr.lock().unwrap() = pat.map(str::to_string);
    }
}

#[async_trait::async_trait]
impl FirewallExecutor for RecordingExecutor {
    async fn run(&self, program: &str, args: &[&str], stdin_data: Option<&[u8]>) -> Result<String, String> {
        let joined = format!("{} {}", program, args.join(" "));
        let stdin_str = stdin_data.map(|b| String::from_utf8_lossy(b).into_owned());
        self.calls.lock().unwrap().push((
            program.to_string(),
            args.iter().map(|s| (*s).to_string()).collect(),
            stdin_str.clone(),
        ));
        if let Some(ref pat) = *self.fail_on_substr.lock().unwrap() {
            if joined.contains(pat) || stdin_str.as_deref().is_some_and(|s| s.contains(pat)) {
                return Err(format!("simulated command failure on {}", pat));
            }
        }
        if program == "nft" && args.starts_with(&["list", "chain", "inet", "fw4"]) {
            let parent = args.get(4).copied().unwrap_or_default();
            if self.existing_jumps.lock().unwrap().iter().any(|p| p == parent) {
                let child = match parent {
                    "input_wan" => "vane_input",
                    "forward_wan" => "vane_forward",
                    "dstnat_wan" => "vane_dstnat",
                    _ => "",
                };
                return Ok(format!(
                    "table inet fw4 {{\n  chain {} {{\n    jump {}\n  }}\n}}",
                    parent, child
                ));
            }
            return Ok(format!("table inet fw4 {{\n  chain {} {{\n  }}\n}}", parent));
        }
        if program == "nft" && args.starts_with(&["insert", "rule", "inet", "fw4"]) {
            if let Some(parent) = args.get(4) {
                self.existing_jumps.lock().unwrap().push((*parent).to_string());
            }
            return Ok(String::new());
        }
        if args.contains(&"-C") {
            let chain = args.last().copied().unwrap_or_default();
            let key = format!("{}:{}:{}", program, args.get(5).copied().unwrap_or_default(), chain);
            if self.existing_jumps.lock().unwrap().iter().any(|k| k == &key) {
                return Ok(String::new());
            }
            return Err("iptables: Bad rule (does a matching rule exist in that chain?).".into());
        }
        if args.contains(&"-I") {
            let chain = args.last().copied().unwrap_or_default();
            let key = format!("{}:{}:{}", program, args.get(5).copied().unwrap_or_default(), chain);
            self.existing_jumps.lock().unwrap().push(key);
        }
        Ok(String::new())
    }
}

#[tokio::test]
async fn nftables_atomic_script_mounts_jumps_handles_bans_lockdown_and_rolls_back_on_error() {
    let exec = Arc::new(RecordingExecutor::default());
    let cfg = FirewallConfig {
        auto_manage: true,
        wan_interfaces: vec!["pppoe-wan".into()],
        lan_interfaces: vec!["br-lan".into()],
        ..Default::default()
    };

    let mgr = FirewallManager::with_executor(FirewallBackend::Nftables, cfg, exec.clone());
    mgr.pre_start_sweep().await.unwrap();

    mgr.upsert_rule(FirewallRule::WanInput {
        owner_module: "reverse_proxy".into(),
        rule_name: "https_8443".into(),
        proto: "tcp".into(),
        port: 8443,
        ipv4: true,
        ipv6: true,
    })
    .await
    .unwrap();

    mgr.upsert_rule(FirewallRule::SubDeviceIpv6Forward {
        owner_module: "ddns".into(),
        rule_name: "nas_v6".into(),
        device_ip: "2001:db8:1234:5678::10".parse().unwrap(),
        tcp_ports: vec![5001],
        udp_ports: vec![51820],
    })
    .await
    .unwrap();

    mgr.ban_source_cidr("2001:db8:dead:beef::99", 600).await.unwrap();
    mgr.ban_source_cidr("198.51.100.77", 600).await.unwrap();
    mgr.sync_all().await.unwrap();

    let calls = exec.snapshot();
    let jump_inserts = calls
        .iter()
        .filter(|(p, a, _)| p == "nft" && a.first().map(String::as_str) == Some("insert"))
        .count();
    assert_eq!(jump_inserts, 3);

    let last_script = calls
        .iter()
        .rev()
        .find_map(|(p, a, stdin)| (p == "nft" && a == &["-f", "-"]).then(|| stdin.clone()).flatten())
        .unwrap();
    assert!(last_script.contains("add table inet vane_shield"));
    assert!(last_script.contains("priority filter - 10; policy accept;"));
    assert!(last_script.contains(r#"add rule inet vane_shield prerouting iifname "pppoe-wan" ip6 saddr @ban_v6 counter drop"#));
    assert!(last_script.contains("2001:db8:dead:beef::/64 timeout"));
    assert!(last_script.contains("198.51.100.77/32 timeout"));
    assert!(last_script.contains(r#"add rule inet fw4 vane_input iifname "pppoe-wan" tcp dport 8443 accept"#));
    assert!(last_script.contains(
        r#"add rule inet fw4 vane_forward iifname "pppoe-wan" oifname "br-lan" ip6 daddr 2001:db8:1234:5678::10 tcp dport 5001 accept"#
    ));

    assert!(mgr.unban_source_cidr("198.51.100.77").await.unwrap());

    // 插入失败时回滚内存并重新向内核下发旧规则集，恢复成功后不应处于 degraded 状态
    exec.set_fail_substr(Some("9999"));
    let err = mgr
        .upsert_rule(FirewallRule::WanInput {
            owner_module: "port_forward".into(),
            rule_name: "bad_rule".into(),
            proto: "tcp".into(),
            port: 9999,
            ipv4: true,
            ipv6: false,
        })
        .await
        .unwrap_err();
    assert!(err.contains("9999"));
    assert_eq!(mgr.list_rules().len(), 2);
    assert!(!mgr.is_degraded());
    exec.set_fail_substr(None);

    // 移除失败且内核恢复也失败时，回滚内存并标记 degraded = true
    exec.set_fail_substr(Some("-f -"));
    assert!(mgr.remove_rule("reverse_proxy", "https_8443").await.is_err());
    assert_eq!(mgr.list_rules().len(), 2);
    assert!(mgr.is_degraded());
    exec.set_fail_substr(None);

    // 下次同步成功后应清除 degraded 状态
    mgr.sync_all().await.unwrap();
    assert!(!mgr.is_degraded());

    // 回环/链路本地封禁不得下发到内核集合（防止误封整个 LAN / loopback）
    mgr.ban_source_cidr("::1", 600).await.unwrap();
    assert!(!exec
        .snapshot()
        .iter()
        .any(|(_, a, _)| a.iter().any(|s| s.contains("{ ::/64") || s == "::/64")));

    let report = mgr.trigger_lockdown_detailed(true).await.unwrap();
    assert!(report.active);
    assert!(report.kernel_enforced);
    assert!(report.conntrack_flushed);
    assert!(report.warnings.is_empty());

    let after_lockdown = exec.snapshot();
    let lockdown_script = after_lockdown
        .iter()
        .rev()
        .find_map(|(p, a, stdin)| (p == "nft" && a == &["-f", "-"]).then(|| stdin.clone()).flatten())
        .unwrap();
    assert!(!lockdown_script.contains("dport 8443 accept"));
    assert!(lockdown_script.contains("2001:db8:dead:beef::/64 timeout"));
    assert!(after_lockdown
        .iter()
        .any(|(p, a, _)| p == "conntrack" && a.contains(&"ipv6".to_string()) && a.contains(&"8443".to_string())));
}

#[tokio::test]
async fn iptables_uses_atomic_restore_preserves_bans_and_supports_dnat() {
    let exec = Arc::new(RecordingExecutor::default());
    let cfg = FirewallConfig {
        auto_manage: true,
        ..Default::default()
    };
    let mgr = FirewallManager::with_executor(FirewallBackend::IptablesNft, cfg, exec.clone());

    mgr.ban_source_cidr("203.0.113.9", 300).await.unwrap();
    mgr.ban_source_cidr("203.0.113.10", 300).await.unwrap();
    mgr.upsert_rule(FirewallRule::KernelDnat {
        owner_module: "port_forward".into(),
        rule_name: "game_tcp".into(),
        proto: "tcp".into(),
        listen_port: 25565,
        target: "192.168.1.50:25565".parse().unwrap(),
    })
    .await
    .unwrap();

    let calls = exec.snapshot();
    // 必须通过 iptables-restore --noflush 原子提交，严禁单独调用 iptables -F VANE_BAN
    assert!(!calls
        .iter()
        .any(|(p, a, _)| p == "iptables" && a.contains(&"-F".to_string()) && a.contains(&"VANE_BAN".to_string())));
    let last_v4_restore = calls
        .iter()
        .rev()
        .find_map(|(p, a, stdin)| {
            (p == "iptables-restore" && a.contains(&"--noflush".to_string()))
                .then(|| stdin.clone())
                .flatten()
        })
        .expect("should invoke iptables-restore --noflush");
    assert!(last_v4_restore.contains(":VANE_BAN - [0:0]"));
    assert!(last_v4_restore.contains("-A VANE_BAN -s 203.0.113.9/32 -j DROP"));
    assert!(last_v4_restore.contains("-A VANE_BAN -s 203.0.113.10/32 -j DROP"));
    assert!(last_v4_restore.contains("-A VANE_PREROUTING -i pppoe-wan -p tcp --dport 25565 -j DNAT --to-destination 192.168.1.50:25565"));
    assert!(last_v4_restore.contains("-A VANE_FORWARD -i pppoe-wan -p tcp -d 192.168.1.50 --dport 25565 -m conntrack --ctstate DNAT -j ACCEPT"));

    mgr.remove_rule("port_forward", "game_tcp").await.unwrap();
    let calls2 = exec.snapshot();
    assert!(calls2
        .iter()
        .any(|(p, a, _)| p == "conntrack" && a.contains(&"25565".to_string())));
}

#[tokio::test]
async fn upsert_rule_enforces_protected_wan_ports_defense_in_depth() {
    let exec = Arc::new(RecordingExecutor::default());
    let cfg = FirewallConfig {
        auto_manage: true,
        ..Default::default()
    };
    let mgr = FirewallManager::with_executor(FirewallBackend::Nftables, cfg, exec.clone());

    assert!(PROTECTED_LOCAL_INPUT_PORTS.contains(&23456));

    let err_admin = mgr
        .upsert_rule(FirewallRule::WanInput {
            owner_module: "reverse_proxy".into(),
            rule_name: "bad_admin".into(),
            proto: "tcp".into(),
            port: 23456,
            ipv4: true,
            ipv6: true,
        })
        .await
        .unwrap_err();
    assert!(err_admin.contains("23456"));

    let err_ssh = mgr
        .upsert_rule(FirewallRule::WanInput {
            owner_module: "port_forward".into(),
            rule_name: "bad_ssh".into(),
            proto: "tcp".into(),
            port: 22,
            ipv4: true,
            ipv6: false,
        })
        .await
        .unwrap_err();
    assert!(err_ssh.contains("22"));

    assert!(mgr.list_rules().is_empty());
    assert!(exec.snapshot().is_empty());
}

#[tokio::test]
async fn lockdown_reports_dryrun_automanage_conntrack_warnings_and_cli_preserves_bans() {
    let dir = std::env::temp_dir().join(format!("vane-fw-lockdown-{}", crate::config::random_nonce()));
    fs::create_dir_all(&dir).unwrap();

    // 1. 持久化 .lockdown 读写与符号链接防护
    assert!(!read_persisted_lockdown(&dir));
    write_persisted_lockdown(&dir, true).unwrap();
    assert!(read_persisted_lockdown(&dir));
    write_persisted_lockdown(&dir, false).unwrap();
    assert!(!read_persisted_lockdown(&dir));

    let decoy = dir.join("decoy");
    fs::write(&decoy, b"x").unwrap();
    std::os::unix::fs::symlink(&decoy, lockdown_marker_path(&dir)).unwrap();
    assert!(!read_persisted_lockdown(&dir));
    assert!(write_persisted_lockdown(&dir, true).is_err());
    assert!(write_persisted_lockdown(&dir, false).is_err());
    fs::remove_file(lockdown_marker_path(&dir)).unwrap();

    // 2. DryRun 与 auto_manage = false 必须显式报告未生效于内核
    let exec = Arc::new(RecordingExecutor::default());
    let dry_mgr = FirewallManager::with_executor(FirewallBackend::DryRun, FirewallConfig::default(), exec.clone());
    let rep_dry = dry_mgr.trigger_lockdown_detailed(true).await.unwrap();
    assert!(rep_dry.active);
    assert!(!rep_dry.kernel_enforced);
    assert!(!rep_dry.conntrack_flushed);
    assert!(!rep_dry.warnings.is_empty());

    let cfg_no_auto = FirewallConfig {
        auto_manage: false,
        ..Default::default()
    };
    let no_auto_mgr = FirewallManager::with_executor(FirewallBackend::Nftables, cfg_no_auto, exec.clone());
    let rep_no_auto = no_auto_mgr.trigger_lockdown_detailed(true).await.unwrap();
    assert!(rep_no_auto.active);
    assert!(!rep_no_auto.kernel_enforced);
    assert!(!rep_no_auto.warnings.is_empty());

    // 3. conntrack 缺失/失败时显式记录 warning 且 conntrack_flushed = false
    let exec_ct = Arc::new(RecordingExecutor::default());
    let cfg = FirewallConfig {
        auto_manage: true,
        ..Default::default()
    };
    let mgr_ct = FirewallManager::with_executor(FirewallBackend::Nftables, cfg.clone(), exec_ct.clone());
    mgr_ct
        .upsert_rule(FirewallRule::WanInput {
            owner_module: "reverse_proxy".into(),
            rule_name: "web_8443".into(),
            proto: "tcp".into(),
            port: 8443,
            ipv4: true,
            ipv6: false,
        })
        .await
        .unwrap();
    exec_ct.set_fail_substr(Some("conntrack"));
    let rep_ct = mgr_ct.trigger_lockdown_detailed(true).await.unwrap();
    assert!(rep_ct.active);
    assert!(rep_ct.kernel_enforced);
    assert!(!rep_ct.conntrack_flushed);
    assert!(rep_ct.warnings.iter().any(|w| w.contains("conntrack")));

    // 4. CLI lockdown 必须持久化标记并仅清空放行链，绝不触碰 vane_shield 或 VANE_BAN
    let cli_exec_nft = Arc::new(RecordingExecutor::default());
    let cli_rep = apply_cli_lockdown_preserve_bans_with_executor(
        FirewallBackend::Nftables,
        &cfg,
        &dir,
        true,
        cli_exec_nft.as_ref(),
    )
    .await
    .unwrap();
    assert!(cli_rep.active);
    assert!(cli_rep.kernel_enforced);
    assert!(read_persisted_lockdown(&dir));
    let nft_calls = cli_exec_nft.snapshot();
    assert_eq!(nft_calls.len(), 1);
    let nft_script = nft_calls[0].2.as_deref().unwrap();
    assert!(nft_script.contains("flush chain inet fw4 vane_input"));
    assert!(nft_script.contains("flush chain inet fw4 vane_forward"));
    assert!(nft_script.contains("flush chain inet fw4 vane_dstnat"));
    assert!(!nft_script.contains("vane_shield"));

    let cli_exec_ipt = Arc::new(RecordingExecutor::default());
    apply_cli_lockdown_preserve_bans_with_executor(
        FirewallBackend::IptablesNft,
        &cfg,
        &dir,
        true,
        cli_exec_ipt.as_ref(),
    )
    .await
    .unwrap();
    for (prog, _, stdin) in cli_exec_ipt.snapshot() {
        if prog.ends_with("-restore") {
            let s = stdin.unwrap_or_default();
            assert!(s.contains("-F VANE_INPUT"));
            assert!(s.contains("-F VANE_FORWARD"));
            assert!(!s.contains("VANE_BAN"));
        }
    }

    let _ = fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn external_cli_lockdown_marker_flips_is_lockdown_and_blocks_sync_all_from_reopening_wan() {
    let dir = std::env::temp_dir().join(format!("vane-fw-live-lockdown-{}", crate::config::random_nonce()));
    fs::create_dir_all(&dir).unwrap();

    let exec = Arc::new(RecordingExecutor::default());
    let cfg = FirewallConfig {
        auto_manage: true,
        wan_interfaces: vec!["pppoe-wan".into()],
        lan_interfaces: vec!["br-lan".into()],
        ..Default::default()
    };
    let mgr = FirewallManager::with_executor(FirewallBackend::Nftables, cfg, exec.clone());
    mgr.set_data_dir(dir.clone());

    mgr.upsert_rule(FirewallRule::WanInput {
        owner_module: "reverse_proxy".into(),
        rule_name: "web_8443".into(),
        proto: "tcp".into(),
        port: 8443,
        ipv4: true,
        ipv6: true,
    })
    .await
    .unwrap();
    assert!(!mgr.is_lockdown());
    let last_script = || {
        exec.snapshot()
            .into_iter()
            .rev()
            .find_map(|(p, a, stdin)| (p == "nft" && a == ["-f", "-"]).then_some(stdin).flatten())
            .unwrap()
    };
    assert!(last_script().contains("dport 8443 accept"));

    // 模拟外部 CLI `vane firewall lockdown` 写入 .lockdown 标记
    write_persisted_lockdown(&dir, true).unwrap();
    assert!(mgr.is_lockdown());

    // 守护进程后续触发 sync_all / upsert_rule 均不得重新放开任何 WAN 规则
    mgr.sync_all().await.unwrap();
    let script_after_sync = last_script();
    assert!(!script_after_sync.contains("dport 8443 accept"));

    mgr.upsert_rule(FirewallRule::WanInput {
        owner_module: "port_forward".into(),
        rule_name: "pf_9443".into(),
        proto: "tcp".into(),
        port: 9443,
        ipv4: true,
        ipv6: false,
    })
    .await
    .unwrap();
    let script_after_upsert = last_script();
    assert!(!script_after_upsert.contains("dport 8443 accept"));
    assert!(!script_after_upsert.contains("dport 9443 accept"));

    // 模拟外部 CLI `vane firewall lockdown --off` 移除标记，随后同步恢复 WAN 放行
    write_persisted_lockdown(&dir, false).unwrap();
    assert!(!mgr.is_lockdown());
    mgr.sync_all().await.unwrap();
    let script_after_unlock = last_script();
    assert!(script_after_unlock.contains("dport 8443 accept"));
    assert!(script_after_unlock.contains("dport 9443 accept"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn local_forward_target_bypass_is_blocked_while_lan_nas_is_allowed() {
    let listeners = vec!["192.168.1.1:23456".to_string()];
    assert!(validate_forward_target_safety("127.0.0.1:22".parse().unwrap(), "userspace_splice", true, 23456, &listeners).is_err());
    assert!(validate_forward_target_safety("[::1]:23456".parse().unwrap(), "userspace_splice", true, 23456, &listeners).is_err());
    assert!(validate_forward_target_safety("192.168.1.1:23456".parse().unwrap(), "userspace_splice", true, 23456, &listeners).is_err());
    assert!(validate_forward_target_safety("[::ffff:192.168.1.1]:23456".parse().unwrap(), "userspace_splice", true, 23456, &listeners).is_err());
    assert!(validate_forward_target_safety("192.168.1.1:22".parse().unwrap(), "userspace_splice", true, 23456, &listeners).is_err());
    assert!(validate_forward_target_safety("127.0.0.1:9000".parse().unwrap(), "kernel_dnat", true, 23456, &listeners).is_err());
    assert!(validate_forward_target_safety("192.168.1.50:22".parse().unwrap(), "userspace_splice", true, 23456, &listeners).is_ok());
    assert!(validate_forward_target_safety("192.168.1.50:443".parse().unwrap(), "kernel_dnat", true, 23456, &listeners).is_ok());
    assert!(validate_iface_name("-j").is_err());
    assert!(validate_iface_name("..").is_err());
    assert!(validate_iface_name("pppoe-wan").is_ok());
}

#[test]
fn metadata_nat64_and_strict_target_validation_cover_host_ips_and_lan_bounds() {
    // 元数据 / 链路本地 / 多播 / 0.0.0.0/8 / 广播 / NAT64 / IPv4-mapped
    for bad in [
        "169.254.169.254",
        "::ffff:169.254.169.254",
        "fe80::1",
        "224.0.0.1",
        "ff02::1",
        "0.0.0.0",
        "0.1.2.3",
        "255.255.255.255",
        "64:ff9b::169.254.169.254",
        "64:ff9b:1::1",
        "::",
    ] {
        let ip: IpAddr = bad.parse().unwrap();
        assert!(is_disallowed_upstream_or_metadata_ip(ip), "expected disallowed: {}", bad);
        assert!(
            validate_forward_target_safety_strict(ip, 8080, false, true, &[]).is_err(),
            "strict should always reject {}",
            bad
        );
    }
    assert!(!is_disallowed_upstream_or_metadata_ip("192.168.1.50".parse().unwrap()));
    assert!(!is_disallowed_upstream_or_metadata_ip("fd00::10".parse().unwrap()));
    assert!(!is_disallowed_upstream_or_metadata_ip("127.0.0.1".parse().unwrap()));

    let admin_listeners: Vec<SocketAddr> = vec!["192.168.1.1:23456".parse().unwrap(), "10.0.0.1:24444".parse().unwrap()];
    let fake_host_ips: Vec<IpAddr> = vec!["172.17.0.1".parse().unwrap(), "fd12::1".parse().unwrap()];

    // 非 admin.listen_lan 的本机接口 IP（如 docker0 / VLAN IP）在 !lan_bound_only 下必须被拦截
    assert!(validate_forward_target_safety_strict_inner(
        "172.17.0.1".parse().unwrap(),
        22,
        false,
        false,
        &[],
        &admin_listeners,
        &fake_host_ips,
    )
    .is_err());
    assert!(validate_forward_target_safety_strict_inner(
        "fd12::1".parse().unwrap(),
        23456,
        true,
        false,
        &[],
        &admin_listeners,
        &fake_host_ips,
    )
    .is_err());

    // 即使 lan_bound_only == true 且 open_wan_firewall == false，依然禁止指向 admin_listeners 和环回受保护端口
    assert!(validate_forward_target_safety_strict_inner(
        "10.0.0.1".parse().unwrap(),
        24444,
        false,
        true,
        &[],
        &admin_listeners,
        &fake_host_ips,
    )
    .is_err());
    assert!(validate_forward_target_safety_strict_inner(
        "127.0.0.1".parse().unwrap(),
        2375,
        false,
        true,
        &[],
        &admin_listeners,
        &fake_host_ips,
    )
    .is_err());
    // 非本机接口的普通 LAN 主机正常放行
    assert!(validate_forward_target_safety_strict_inner(
        "192.168.1.99".parse().unwrap(),
        8080,
        true,
        false,
        &[],
        &admin_listeners,
        &fake_host_ips,
    )
    .is_ok());
}
