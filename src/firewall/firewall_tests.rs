use super::*;
use crate::config::FirewallConfig;
use std::sync::Mutex;

#[derive(Default)]
struct RecordingExecutor {
    calls: Mutex<Vec<(String, Vec<String>, Option<String>)>>,
    fail_on_substr: Mutex<Option<String>>,
    existing_jumps: Mutex<Vec<String>>,
}

impl RecordingExecutor {
    fn snapshot(&self) -> Vec<(String, Vec<String>, Option<String>)> {
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
                return Ok(format!("table inet fw4 {{
  chain {} {{
    jump {}
  }}
}}", parent, child));
            }
            return Ok(format!("table inet fw4 {{
  chain {} {{
  }}
}}", parent));
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
    let mut cfg = FirewallConfig::default();
    cfg.auto_manage = true;
    cfg.wan_interfaces = vec!["pppoe-wan".into()];
    cfg.lan_interfaces = vec!["br-lan".into()];

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
    assert!(last_script.contains("2001:db8:dead:beef::/64 timeout"));
    assert!(last_script.contains("198.51.100.77/32 timeout"));
    assert!(last_script.contains(r#"add rule inet fw4 vane_input iifname "pppoe-wan" tcp dport 8443 accept"#));
    assert!(last_script.contains(
        r#"add rule inet fw4 vane_forward iifname "pppoe-wan" oifname "br-lan" ip6 daddr 2001:db8:1234:5678::10 tcp dport 5001 accept"#
    ));

    assert!(mgr.unban_source_cidr("198.51.100.77").await.unwrap());

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
    exec.set_fail_substr(None);

    mgr.trigger_lockdown(true).await.unwrap();
    let after_lockdown = exec.snapshot();
    let lockdown_script = after_lockdown
        .iter()
        .rev()
        .find_map(|(p, a, stdin)| (p == "nft" && a == &["-f", "-"]).then(|| stdin.clone()).flatten())
        .unwrap();
    assert!(!lockdown_script.contains("dport 8443 accept"));
    assert!(lockdown_script.contains("2001:db8:dead:beef::/64 timeout"));
    assert!(after_lockdown.iter().any(|(p, a, _)| p == "conntrack" && a.contains(&"8443".to_string())));
}

#[tokio::test]
async fn iptables_preserves_active_bans_across_rule_flushes_and_supports_dnat() {
    let exec = Arc::new(RecordingExecutor::default());
    let mut cfg = FirewallConfig::default();
    cfg.auto_manage = true;
    let mgr = FirewallManager::with_executor(FirewallBackend::IptablesNft, cfg, exec.clone());

    mgr.ban_source_cidr("203.0.113.9", 300).await.unwrap();
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
    assert!(calls.iter().any(|(p, a, _)| {
        p == "iptables" && a.contains(&"VANE_BAN".to_string()) && a.contains(&"203.0.113.9/32".to_string())
    }));
    assert!(calls.iter().any(|(p, a, _)| {
        p == "iptables" && a.contains(&"DNAT".to_string()) && a.contains(&"192.168.1.50:25565".to_string())
    }));

    mgr.remove_rule("port_forward", "game_tcp").await.unwrap();
    let calls2 = exec.snapshot();
    assert!(calls2.iter().any(|(p, a, _)| p == "conntrack" && a.contains(&"25565".to_string())));
}

#[test]
fn local_forward_target_bypass_is_blocked_while_lan_nas_is_allowed() {
    let listeners = vec!["192.168.1.1:23456".to_string()];
    assert!(validate_forward_target_safety("127.0.0.1:22".parse().unwrap(), "userspace_splice", true, 23456, &listeners).is_err());
    assert!(validate_forward_target_safety("[::1]:23456".parse().unwrap(), "userspace_splice", true, 23456, &listeners).is_err());
    assert!(validate_forward_target_safety("192.168.1.1:23456".parse().unwrap(), "userspace_splice", true, 23456, &listeners).is_err());
    assert!(validate_forward_target_safety("127.0.0.1:9000".parse().unwrap(), "kernel_dnat", true, 23456, &listeners).is_err());
    assert!(validate_forward_target_safety("192.168.1.50:22".parse().unwrap(), "userspace_splice", true, 23456, &listeners).is_ok());
    assert!(validate_forward_target_safety("192.168.1.50:443".parse().unwrap(), "kernel_dnat", true, 23456, &listeners).is_ok());
}
