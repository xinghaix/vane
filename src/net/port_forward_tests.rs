use super::*;
use crate::config::{FirewallConfig, PortForwardConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn free_tcp_port(v6: bool) -> u16 {
    let addr: SocketAddr = if v6 { "[::1]:0".parse().unwrap() } else { "127.0.0.1:0".parse().unwrap() };
    std::net::TcpListener::bind(addr).unwrap().local_addr().unwrap().port()
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

#[tokio::test]
async fn cross_family_v6_to_v4_tcp_round_robin_proxy_v2_and_quota_release() {
    let Ok(probe_v6) = TcpListener::bind("[::1]:0").await else { return };
    drop(probe_v6);

    // 后端 1: 关闭不可达（测试主备/轮询跳过故障节点）
    let dead_port = free_tcp_port(false);
    // 后端 2: IPv4 回显服务，校验 Proxy Protocol v2 头 + 请求体
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = backend.accept().await {
            let mut hdr = [0u8; 52]; // v6 client -> v2 AF_INET6 16 + 36 = 52 bytes
            s.read_exact(&mut hdr).await.unwrap();
            assert_eq!(&hdr[0..12], &[0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A]);
            assert_eq!(hdr[13], 0x21); // AF_INET6 STREAM
            let mut payload = [0u8; 11];
            s.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"hello-cross");
            s.write_all(b"ack-from-v4").await.unwrap();
        }
    });

    let listen_port = free_tcp_port(true);
    let mut cfg = PortForwardConfig::default();
    cfg.name = "v6_to_v4".into();
    cfg.proto = "tcp".into();
    cfg.stack = "ipv6_only".into();
    cfg.listen_port = listen_port;
    cfg.targets = vec![format!("127.0.0.1:{}", dead_port), backend_addr.to_string()];
    cfg.load_balance = "round_robin".into();
    cfg.send_proxy_protocol = "v2".into();
    cfg.open_wan_firewall = false;
    cfg.source_ip = "127.0.0.1".into();

    let mut fw_cfg = FirewallConfig::default();
    fw_cfg.auto_manage = false;
    let fw = FirewallManager::detect_and_init(fw_cfg).await;
    let quota = ConnectionQuota::new(8);
    let (stop_tx, stop_rx) = watch::channel(false);
    let quota_check = quota.clone();

    let task = tokio::spawn(async move {
        run_port_forward_rule(cfg, 0, quota, fw, stop_rx).await
    });
    tokio::time::sleep(Duration::from_millis(80)).await;

    let mut client = TcpStream::connect(SocketAddr::new("::1".parse().unwrap(), listen_port))
        .await
        .unwrap();
    client.write_all(b"hello-cross").await.unwrap();
    let mut reply = [0u8; 11];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"ack-from-v4");
    drop(client);

    let _ = stop_tx.send(true);
    task.await.unwrap().unwrap();
    assert_eq!(quota_check.active_connections(), 0);
}

#[tokio::test]
#[ignore]
    async fn large_udp_datagram_and_lease_expiration_automatically_close_listener_and_firewall() {
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        if let Ok((n, peer)) = backend.recv_from(&mut buf).await {
            backend.send_to(&buf[..n], peer).await.unwrap();
        }
    });

    let listen_port = free_udp_port();
    let mut cfg = PortForwardConfig::default();
    cfg.name = "temp_udp".into();
    cfg.proto = "udp".into();
    cfg.stack = "ipv4_only".into();
    cfg.listen_port = listen_port;
    cfg.target = backend_addr.to_string();
    cfg.open_wan_firewall = true;
    cfg.expire_at_unix = logger::unix_now() + 2; // 2 秒租约自动到期

    let mut fw_cfg = FirewallConfig::default();
    fw_cfg.auto_manage = false; // DryRun / 不触碰宿主机，但内存规则表仍真实同步
    let fw = FirewallManager::detect_and_init(fw_cfg).await;
    let fw_observer = fw.clone();
    let quota = ConnectionQuota::new(8);
    let (stop_tx, stop_rx) = watch::channel(false);

    let task = tokio::spawn(async move {
        run_port_forward_rule(cfg, 0, quota, fw, stop_rx).await
    });
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(fw_observer.list_rules().len(), 1);

    // 发送 12 KiB (> 旧 4 KiB 限制) UDP 载荷验证无截断往返
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let big_payload: Vec<u8> = (0..12_288).map(|i| (i % 251) as u8).collect();
    client
        .send_to(&big_payload, SocketAddr::new("127.0.0.1".parse().unwrap(), listen_port))
        .await
        .unwrap();
    let mut recv_buf = vec![0u8; 16_384];
    let (rn, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut recv_buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&recv_buf[..rn], &big_payload[..]);

    // 等待租约自然到期（无需外部 reload）：防火墙规则与监听 Socket 必须自动释放
    tokio::time::sleep(Duration::from_millis(2400)).await;
    assert!(fw_observer.list_rules().is_empty());

    let _ = stop_tx.send(true);
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn tcp_forward_enforces_fail2ban_and_per_peer_quota() {
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend.local_addr().unwrap();
    let backend_task = tokio::spawn(async move {
        while let Ok((mut s, _)) = backend.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 64];
                while s.read(&mut buf).await.unwrap_or(0) > 0 {}
            });
        }
    });

    let listen_port = free_tcp_port(false);
    let cfg = PortForwardConfig {
        name: "quota_f2b_tcp".into(),
        proto: "tcp".into(),
        stack: "ipv4_only".into(),
        listen_port,
        target: backend_addr.to_string(),
        open_wan_firewall: false,
        max_concurrent_conns: 16,
        ..Default::default()
    };

    let fw_cfg = FirewallConfig {
        auto_manage: false,
        ..Default::default()
    };
    let fw = FirewallManager::detect_and_init(fw_cfg).await;
    let quota = ConnectionQuota::new(32);
    let f2b = Arc::new(Fail2Ban::new());
    let (stop_tx, stop_rx) = watch::channel(false);

    let opts = PortForwardRuntimeOptions::default()
        .with_fail2ban(Some(f2b.clone()))
        .with_max_conns_per_peer(2);

    let task = tokio::spawn(run_port_forward_rule_with_options(
        cfg,
        0,
        quota.clone(),
        fw,
        stop_rx,
        opts,
    ));
    tokio::time::sleep(Duration::from_millis(80)).await;

    // 单来源最多占 2 个并发连接，第 3 个应被立即关闭
    let c1 = TcpStream::connect(("127.0.0.1", listen_port)).await.unwrap();
    let c2 = TcpStream::connect(("127.0.0.1", listen_port)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(quota.active_connections(), 2);

    let mut c3 = TcpStream::connect(("127.0.0.1", listen_port)).await.unwrap();
    let mut buf = [0u8; 8];
    let n = tokio::time::timeout(Duration::from_secs(2), c3.read(&mut buf))
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(n, 0, "third connection from same peer should be rejected by PeerQuota");

    drop(c1);
    drop(c2);
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(quota.active_connections(), 0);

    // Fail2Ban 封禁来源在 accept 阶段直接断开
    let k = BanKey::from_peer("127.0.0.1".parse().unwrap());
    for _ in 0..3 {
        f2b.record_failure(k, 3, 600, "test");
    }
    let mut banned = TcpStream::connect(("127.0.0.1", listen_port)).await.unwrap();
    let n2 = tokio::time::timeout(Duration::from_secs(2), banned.read(&mut buf))
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(n2, 0, "banned peer should be rejected immediately");

    let _ = stop_tx.send(true);
    task.await.unwrap().unwrap();
    backend_task.abort();
    let _ = backend_task.await;
    assert_eq!(quota.active_connections(), 0);
}

#[tokio::test]
async fn udp_proxy_pooled_buffers_peer_quota_fail2ban_and_clean_shutdown() {
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend.local_addr().unwrap();
    let backend_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while let Ok((n, peer)) = backend.recv_from(&mut buf).await {
            let _ = backend.send_to(&buf[..n], peer).await;
        }
    });

    let listen_port = free_udp_port();
    let cfg = PortForwardConfig {
        name: "udp_pool_test".into(),
        proto: "udp".into(),
        stack: "ipv4_only".into(),
        listen_port,
        target: backend_addr.to_string(),
        open_wan_firewall: false,
        max_concurrent_conns: 16,
        ..Default::default()
    };

    let fw_cfg = FirewallConfig {
        auto_manage: false,
        ..Default::default()
    };
    let fw = FirewallManager::detect_and_init(fw_cfg).await;
    let quota = ConnectionQuota::new(32);
    let f2b = Arc::new(Fail2Ban::new());
    let (stop_tx, stop_rx) = watch::channel(false);

    let opts = PortForwardRuntimeOptions::default()
        .with_fail2ban(Some(f2b.clone()))
        .with_max_conns_per_peer(2);

    let task = tokio::spawn(run_port_forward_rule_with_options(
        cfg,
        0,
        quota.clone(),
        fw,
        stop_rx,
        opts,
    ));
    tokio::time::sleep(Duration::from_millis(80)).await;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", listen_port).parse().unwrap();
    let payload: Vec<u8> = (0..2048).map(|i| (i % 251) as u8).collect();
    let c1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let c2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let c3 = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // 前 2 个不同源端口会话均可通过缓冲池正常往返
    for c in [&c1, &c2] {
        c.send_to(&payload, proxy_addr).await.unwrap();
        let mut r = vec![0u8; 4096];
        let (rn, _) = tokio::time::timeout(Duration::from_secs(2), c.recv_from(&mut r))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&r[..rn], &payload[..]);
    }
    assert_eq!(quota.active_connections(), 2);

    // 第 3 个来自同一 BanKey 的 UDP 会话被单来源 PeerQuota 拦截
    c3.send_to(b"blocked-by-peer-quota", proxy_addr).await.unwrap();
    let mut r3 = [0u8; 64];
    assert!(tokio::time::timeout(Duration::from_millis(150), c3.recv_from(&mut r3)).await.is_err());
    assert_eq!(quota.active_connections(), 2);

    // 停机取消立即终止全部 UDP 会话任务并归还全局与规则配额
    let _ = stop_tx.send(true);
    task.await.unwrap().unwrap();
    backend_task.abort();
    let _ = backend_task.await;
    assert_eq!(quota.active_connections(), 0);
}
