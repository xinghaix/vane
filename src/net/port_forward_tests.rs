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
