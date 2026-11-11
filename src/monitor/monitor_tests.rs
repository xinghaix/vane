#[cfg(test)]
mod tests {
    use crate::config::{Config, MonitorConfig, NotificationConfig};
    use crate::monitor::alerts::{evaluate_and_notify_alerts, AlertState};
    use crate::monitor::procfs::*;
    use crate::security::vault::Vault;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn test_snapshot_collection_does_not_panic_and_uses_real_metrics() {
        let cfg = MonitorConfig {
            interfaces: vec![],
            thermal_path: "".into(),
            temp_alert_celsius: 85,
            mem_low_mb: 32,
            alert_cooldown_secs: 1800,
            sample_interval_secs: 2,
            top_processes: 5,
        };
        let sampler = MonitorSampler::new();
        let snapshot = sampler.sample(&cfg);
        assert!(snapshot.timestamp_unix > 0);
        assert!(snapshot.memory.total_kb > 0);
    }

    #[test]
    fn parses_fixed_procfs_fixtures_and_cpu_delta_accurately() {
        let meminfo = "\
MemTotal:         512000 kB
MemFree:           64000 kB
MemAvailable:     192000 kB
Buffers:           16000 kB
Cached:           112000 kB
SReclaimable:      12000 kB
SUnreclaim:        28400 kB
SwapTotal:             0 kB
SwapFree:              0 kB
";
        let m = parse_proc_meminfo(meminfo);
        assert_eq!(m.total_kb, 512_000);
        assert_eq!(m.available_kb, 192_000);
        assert_eq!(m.used_kb, 320_000);
        assert_eq!(m.cached_kb, 112_000);
        assert_eq!(m.slab_unreclaim_kb, 28_400);

        let stat_t0 = "\
cpu  1000 0 500 8500 0 0 0 0 0 0
cpu0 600 0 300 4100 0 0 0 0 0 0
cpu1 400 0 200 4400 0 0 0 0 0 0
";
        let stat_t1 = "\
cpu  1250 0 650 9100 0 0 0 0 0 0
cpu0 800 0 400 4300 0 0 0 0 0 0
cpu1 450 0 250 4800 0 0 0 0 0 0
";
        let s0 = parse_proc_stat(stat_t0).unwrap();
        let s1 = parse_proc_stat(stat_t1).unwrap();
        // t0: total=10000, idle=8500; t1: total=11000, idle=9100 => d_total=1000, d_busy=400 => 40.0%
        // cpu0: d_total=500, d_busy=300 => 60.0%; cpu1: d_total=500, d_busy=100 => 20.0%
        let (total, cores) = compute_cpu_delta(&s0, &s1);
        assert!((total - 40.0).abs() < 0.01);
        assert_eq!(cores.len(), 2);
        assert!((cores[0] - 60.0).abs() < 0.01);
        assert!((cores[1] - 20.0).abs() < 0.01);

        let netdev = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:   10240      50    0    0    0     0          0         0    10240      50    0    0    0     0       0          0
pppoe-wan: 104857600 80000    0    0    0     0          0         0 52428800   40000    0    0    0     0       0          0
";
        let map = parse_proc_net_dev(netdev);
        assert_eq!(map.get("pppoe-wan"), Some(&(104_857_600, 52_428_800)));
    }

    #[tokio::test]
    async fn threshold_alerts_respect_cooldown_and_deliver_webhook() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hits_srv = hits.clone();
        let srv = tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf).await;
                hits_srv.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}")
                    .await;
            }
        });

        let mut cfg = Config::default();
        cfg.monitor.temp_alert_celsius = 80;
        cfg.monitor.mem_low_mb = 32;
        cfg.monitor.alert_cooldown_secs = 600;
        cfg.notifications.push(NotificationConfig {
            name: "local_hook".into(),
            enabled: true,
            provider: "webhook".into(),
            url: format!("http://{}/hook", addr),
            min_severity: "info".into(),
            ..Default::default()
        });
        let vault = Vault::from_master(&[7u8; 32]);
        let state = AlertState::default();
        let mut snap = SystemSnapshot::default();
        snap.timestamp_unix = 1_700_000_000;
        snap.soc_temp_celsius = 86.0;
        snap.memory.total_kb = 256 * 1024;
        snap.memory.available_kb = 16 * 1024; // 16 MB < 32 MB

        evaluate_and_notify_alerts(&state, &cfg, &vault, &snap).await;
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 2); // high_temp + low_memory

        // 冷却期内重复评估不重复发送
        snap.timestamp_unix += 60;
        evaluate_and_notify_alerts(&state, &cfg, &vault, &snap).await;
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 2);

        // 超过冷却期后恢复发送
        snap.timestamp_unix += 600;
        evaluate_and_notify_alerts(&state, &cfg, &vault, &snap).await;
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 4);
        srv.abort();
    }
}
