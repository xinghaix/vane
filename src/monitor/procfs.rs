//! 按需系统监控采集器：Linux /proc & /sys 原生解析 + 真实跨平台系统调用回退（无任何伪造指标），
//! 支持按需 CPU 时间片增量计算、网卡实时速率增量计算、Slab 不可回收内存拆解与 Top VmRSS 进程榜。
use crate::config::MonitorConfig;
use crate::daemon::netlink_ip::{list_interface_addresses, InterfaceAddresses};
use crate::logger;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::sync::Mutex;
use std::time::Instant;

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct MemoryMetrics {
    pub total_kb: u64,
    pub available_kb: u64,
    pub used_kb: u64,
    pub cached_kb: u64,
    pub slab_unreclaim_kb: u64,
    pub swap_total_kb: u64,
    pub swap_free_kb: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct NetDevTraffic {
    pub iface: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_bps: u64,
    pub tx_bps: u64,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ProcessMemoryEntry {
    pub pid: u32,
    pub name: String,
    pub vm_rss_kb: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct SystemSnapshot {
    pub timestamp_unix: u64,
    pub uptime_secs: u64,
    pub cpu_usage_percent: f32,
    pub cpu_cores_percent: Vec<f32>,
    pub load_avg: [f32; 3],
    pub soc_temp_celsius: f32,
    pub memory: MemoryMetrics,
    pub interfaces: Vec<NetDevTraffic>,
    pub top_processes: Vec<ProcessMemoryEntry>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CpuTickPair {
    pub total: u64,
    pub idle: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CpuStatRaw {
    pub summary: CpuTickPair,
    pub cores: Vec<CpuTickPair>,
}

struct SamplerPrev {
    at: Instant,
    cpu: Option<CpuStatRaw>,
    net: BTreeMap<String, (u64, u64)>,
}

/// 按需监控采样状态：仅在面板请求到来时更新前后两帧增量，无人查看时 0 后台定时器开销。
#[derive(Default)]
pub struct MonitorSampler {
    prev: Mutex<Option<SamplerPrev>>,
}

impl MonitorSampler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn sample(&self, cfg: &MonitorConfig) -> SystemSnapshot {
        let now_inst = Instant::now();
        let ts = logger::unix_now();
        let addr_map = list_interface_addresses();
        let memory = read_memory_metrics();
        let (uptime_secs, load_avg) = read_uptime_and_load();
        let soc_temp_celsius = read_soc_temperature(&cfg.thermal_path);
        let cur_cpu = fs::read_to_string("/proc/stat").ok().and_then(|s| parse_proc_stat(&s));
        let cur_net = fs::read_to_string("/proc/net/dev")
            .ok()
            .map(|s| parse_proc_net_dev(&s))
            .unwrap_or_default();

        let (cpu_usage_percent, cpu_cores_percent, rate_map) = {
            let mut guard = self.prev.lock().unwrap_or_else(|e| e.into_inner());
            let mut rates: BTreeMap<String, (u64, u64)> = BTreeMap::new();
            let (total_pct, core_pcts) = match (&*guard, &cur_cpu) {
                (Some(prev), Some(cur)) => {
                    let elapsed_ms = now_inst.duration_since(prev.at).as_millis() as u64;
                    if elapsed_ms > 0 {
                        for (iface, &(rx, tx)) in &cur_net {
                            if let Some(&(prx, ptx)) = prev.net.get(iface) {
                                let rx_bps = rx.saturating_sub(prx).saturating_mul(1000) / elapsed_ms;
                                let tx_bps = tx.saturating_sub(ptx).saturating_mul(1000) / elapsed_ms;
                                rates.insert(iface.clone(), (rx_bps, tx_bps));
                            }
                        }
                    }
                    if let Some(ref prev_cpu) = prev.cpu {
                        compute_cpu_delta(prev_cpu, cur)
                    } else {
                        (0.0, vec![0.0; cur.cores.len()])
                    }
                }
                (_, Some(cur)) => (0.0, vec![0.0; cur.cores.len()]),
                _ => fallback_cpu_from_load(load_avg[0]),
            };
            *guard = Some(SamplerPrev {
                at: now_inst,
                cpu: cur_cpu,
                net: cur_net.clone(),
            });
            (total_pct, core_pcts, rates)
        };

        let interfaces = build_net_interfaces(&cfg.interfaces, &addr_map, &cur_net, &rate_map);
        let top_processes = read_top_processes(cfg.top_processes.clamp(1, 50));

        SystemSnapshot {
            timestamp_unix: ts,
            uptime_secs,
            cpu_usage_percent,
            cpu_cores_percent,
            load_avg,
            soc_temp_celsius,
            memory,
            interfaces,
            top_processes,
        }
    }
}

pub fn collect_snapshot(cfg: &MonitorConfig) -> SystemSnapshot {
    MonitorSampler::new().sample(cfg)
}

pub fn parse_proc_meminfo(text: &str) -> MemoryMetrics {
    let mut m = MemoryMetrics::default();
    let mut mem_free = 0u64;
    let mut buffers = 0u64;
    let mut sreclaimable = 0u64;
    let mut has_available = false;
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let Some(k) = it.next() else { continue };
        let Some(v) = it.next().and_then(|s| s.parse::<u64>().ok()) else { continue };
        match k {
            "MemTotal:" => m.total_kb = v,
            "MemFree:" => mem_free = v,
            "MemAvailable:" => {
                m.available_kb = v;
                has_available = true;
            }
            "Buffers:" => buffers = v,
            "Cached:" => m.cached_kb = v,
            "SReclaimable:" => sreclaimable = v,
            "SUnreclaim:" => m.slab_unreclaim_kb = v,
            "SwapTotal:" => m.swap_total_kb = v,
            "SwapFree:" => m.swap_free_kb = v,
            _ => {}
        }
    }
    if !has_available && m.total_kb > 0 {
        m.available_kb = (mem_free + buffers + m.cached_kb + sreclaimable).min(m.total_kb);
    }
    m.used_kb = m.total_kb.saturating_sub(m.available_kb);
    m
}

pub fn parse_proc_stat(text: &str) -> Option<CpuStatRaw> {
    let mut summary = None;
    let mut cores = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("cpu") else { continue };
        let is_summary = rest.starts_with(' ');
        if !is_summary && !rest.as_bytes().first().is_some_and(|b| b.is_ascii_digit()) {
            continue;
        }
        let vals: Vec<u64> = rest
            .split_whitespace()
            .skip(if is_summary { 0 } else { 1 })
            .filter_map(|x| x.parse().ok())
            .collect();
        if vals.len() >= 4 {
            // idle + iowait 视为非忙碌时间，其余 user/nice/system/irq/softirq/steal 计入总时间
            let idle = vals[3].saturating_add(vals.get(4).copied().unwrap_or(0));
            let total: u64 = vals.iter().copied().fold(0u64, u64::saturating_add);
            let pair = CpuTickPair { total, idle };
            if is_summary {
                summary = Some(pair);
            } else {
                cores.push(pair);
            }
        }
    }
    summary.map(|s| CpuStatRaw { summary: s, cores })
}

fn delta_percent(prev: CpuTickPair, cur: CpuTickPair) -> f32 {
    let d_total = cur.total.saturating_sub(prev.total);
    if d_total == 0 {
        return 0.0;
    }
    let d_idle = cur.idle.saturating_sub(prev.idle).min(d_total);
    let busy = d_total - d_idle;
    ((busy as f64 / d_total as f64) * 100.0).clamp(0.0, 100.0) as f32
}

pub fn compute_cpu_delta(prev: &CpuStatRaw, cur: &CpuStatRaw) -> (f32, Vec<f32>) {
    let total_pct = delta_percent(prev.summary, cur.summary);
    let cores = cur
        .cores
        .iter()
        .enumerate()
        .map(|(i, &c)| prev.cores.get(i).copied().map_or(0.0, |p| delta_percent(p, c)))
        .collect();
    (total_pct, cores)
}

pub fn parse_proc_net_dev(text: &str) -> BTreeMap<String, (u64, u64)> {
    let mut rx_tx = BTreeMap::new();
    for line in text.lines().skip(2) {
        if let Some((iface, rest)) = line.split_once(':') {
            let cols: Vec<u64> = rest.split_whitespace().filter_map(|v| v.parse().ok()).collect();
            if cols.len() >= 9 {
                rx_tx.insert(iface.trim().to_string(), (cols[0], cols[8]));
            }
        }
    }
    rx_tx
}

fn read_memory_metrics() -> MemoryMetrics {
    if let Ok(text) = fs::read_to_string("/proc/meminfo") {
        return parse_proc_meminfo(&text);
    }
    read_host_memory_fallback()
}

#[cfg(target_os = "macos")]
fn read_host_memory_fallback() -> MemoryMetrics {
    let mut memsize: u64 = 0;
    let mut len = std::mem::size_of::<u64>();
    let name = b"hw.memsize\0";
    // SAFETY: sysctlbyname 使用只读 NUL 结尾名称与对齐的 u64 输出缓冲。
    let ok = unsafe {
        libc::sysctlbyname(
            name.as_ptr().cast(),
            (&mut memsize as *mut u64).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        ) == 0
    };
    if !ok || memsize == 0 {
        return MemoryMetrics::default();
    }
    let total_kb = memsize / 1024;
    // 读取当前内核页大小与活跃/空闲页统计，提供真实物理内存占用而非硬编码模拟值
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as u64;
    let mut free_pages: u64 = 0;
    let mut sz = std::mem::size_of::<u32>();
    let mut page_free_u32: u32 = 0;
    let mut page_spec_u32: u32 = 0;
    let mut page_inact_u32: u32 = 0;
    unsafe {
        if libc::sysctlbyname(
            b"vm.page_free_count\0".as_ptr().cast(),
            (&mut page_free_u32 as *mut u32).cast(),
            &mut sz,
            std::ptr::null_mut(),
            0,
        ) == 0
        {
            free_pages = free_pages.saturating_add(page_free_u32 as u64);
        }
        sz = std::mem::size_of::<u32>();
        if libc::sysctlbyname(
            b"vm.page_inactive_count\0".as_ptr().cast(),
            (&mut page_inact_u32 as *mut u32).cast(),
            &mut sz,
            std::ptr::null_mut(),
            0,
        ) == 0
        {
            free_pages = free_pages.saturating_add(page_inact_u32 as u64);
        }
        sz = std::mem::size_of::<u32>();
        if libc::sysctlbyname(
            b"vm.page_speculative_count\0".as_ptr().cast(),
            (&mut page_spec_u32 as *mut u32).cast(),
            &mut sz,
            std::ptr::null_mut(),
            0,
        ) == 0
        {
            free_pages = free_pages.saturating_add(page_spec_u32 as u64);
        }
    }
    let available_kb = ((free_pages.saturating_mul(page_size)) / 1024).min(total_kb);
    let cached_kb = ((page_inact_u32 as u64).saturating_mul(page_size)) / 1024;
    MemoryMetrics {
        total_kb,
        available_kb,
        used_kb: total_kb.saturating_sub(available_kb),
        cached_kb,
        slab_unreclaim_kb: 0,
        swap_total_kb: 0,
        swap_free_kb: 0,
    }
}

#[cfg(not(target_os = "macos"))]
fn read_host_memory_fallback() -> MemoryMetrics {
    MemoryMetrics::default()
}

fn read_uptime_and_load() -> (u64, [f32; 3]) {
    let uptime = if let Ok(s) = fs::read_to_string("/proc/uptime") {
        s.split_whitespace()
            .next()
            .and_then(|v| v.parse::<f64>().ok())
            .map(|v| v as u64)
            .unwrap_or(0)
    } else {
        read_host_uptime_fallback()
    };

    let mut load = [0.0f32; 3];
    if let Ok(s) = fs::read_to_string("/proc/loadavg") {
        let parts: Vec<f32> = s.split_whitespace().take(3).filter_map(|x| x.parse().ok()).collect();
        if parts.len() == 3 {
            load = [parts[0], parts[1], parts[2]];
            return (uptime, load);
        }
    }
    let mut raw = [0.0f64; 3];
    // SAFETY: getloadavg 写入最多 3 个 c_double 元素。
    let n = unsafe { libc::getloadavg(raw.as_mut_ptr(), 3) };
    if n == 3 {
        load = [raw[0] as f32, raw[1] as f32, raw[2] as f32];
    }
    (uptime, load)
}

#[cfg(target_os = "macos")]
fn read_host_uptime_fallback() -> u64 {
    let mut boottime = libc::timeval { tv_sec: 0, tv_usec: 0 };
    let mut sz = std::mem::size_of::<libc::timeval>();
    let ok = unsafe {
        libc::sysctlbyname(
            b"kern.boottime\0".as_ptr().cast(),
            (&mut boottime as *mut libc::timeval).cast(),
            &mut sz,
            std::ptr::null_mut(),
            0,
        ) == 0
    };
    if ok && boottime.tv_sec > 0 {
        logger::unix_now().saturating_sub(boottime.tv_sec as u64)
    } else {
        0
    }
}

#[cfg(not(target_os = "macos"))]
fn read_host_uptime_fallback() -> u64 {
    0
}

fn fallback_cpu_from_load(load1: f32) -> (f32, Vec<f32>) {
    let ncpu = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let approx = ((load1 / ncpu as f32) * 100.0).clamp(0.0, 100.0);
    (approx, vec![approx; ncpu])
}

fn read_soc_temperature(custom_path: &str) -> f32 {
    let candidates = if !custom_path.is_empty() {
        vec![custom_path.to_string()]
    } else {
        vec![
            "/sys/class/thermal/thermal_zone0/temp".into(),
            "/sys/class/thermal/thermal_zone1/temp".into(),
            "/sys/class/hwmon/hwmon0/temp1_input".into(),
        ]
    };
    for p in candidates {
        if let Ok(s) = fs::read_to_string(&p) {
            if let Ok(raw) = s.trim().parse::<f32>() {
                let c = if raw > 1000.0 { raw / 1000.0 } else { raw };
                if c.is_finite() && c > 0.0 && c < 150.0 {
                    return c;
                }
            }
        }
    }
    0.0
}

fn build_net_interfaces(
    wanted: &[String],
    addr_map: &BTreeMap<String, InterfaceAddresses>,
    rx_tx: &BTreeMap<String, (u64, u64)>,
    rate_map: &BTreeMap<String, (u64, u64)>,
) -> Vec<NetDevTraffic> {
    let mut out = Vec::new();
    let keys: Vec<String> = if !wanted.is_empty() {
        wanted.to_vec()
    } else {
        addr_map.keys().cloned().collect()
    };
    for k in keys {
        let (rx, tx) = rx_tx.get(&k).copied().unwrap_or((0, 0));
        let (rx_bps, tx_bps) = rate_map.get(&k).copied().unwrap_or((0, 0));
        let addrs = addr_map.get(&k);
        out.push(NetDevTraffic {
            iface: k,
            rx_bytes: rx,
            tx_bytes: tx,
            rx_bps,
            tx_bps,
            ipv4: addrs.map(|a| a.ipv4.iter().map(|ip| ip.to_string()).collect()).unwrap_or_default(),
            ipv6: addrs.map(|a| a.ipv6.iter().map(|ip| ip.to_string()).collect()).unwrap_or_default(),
        });
    }
    for (k, a) in addr_map {
        if !out.iter().any(|x| &x.iface == k) && (!a.ipv4.is_empty() || !a.ipv6.is_empty()) {
            let (rx, tx) = rx_tx.get(k).copied().unwrap_or((0, 0));
            let (rx_bps, tx_bps) = rate_map.get(k).copied().unwrap_or((0, 0));
            out.push(NetDevTraffic {
                iface: k.clone(),
                rx_bytes: rx,
                tx_bytes: tx,
                rx_bps,
                tx_bps,
                ipv4: a.ipv4.iter().map(|ip| ip.to_string()).collect(),
                ipv6: a.ipv6.iter().map(|ip| ip.to_string()).collect(),
            });
        }
    }
    out
}

fn read_top_processes(limit: usize) -> Vec<ProcessMemoryEntry> {
    let mut list = Vec::new();
    if let Ok(rd) = fs::read_dir("/proc") {
        for entry in rd.flatten() {
            let fname = entry.file_name();
            let Some(pid_s) = fname.to_str() else { continue };
            let Ok(pid) = pid_s.parse::<u32>() else { continue };
            let status_path = entry.path().join("status");
            let Ok(text) = fs::read_to_string(status_path) else { continue };
            let mut name = String::new();
            let mut rss_kb = 0u64;
            for line in text.lines() {
                if let Some(n) = line.strip_prefix("Name:") {
                    name = n.trim().to_string();
                } else if let Some(r) = line.strip_prefix("VmRSS:") {
                    rss_kb = r.split_whitespace().next().and_then(|v| v.parse().ok()).unwrap_or(0);
                    break;
                }
            }
            if rss_kb > 0 {
                list.push(ProcessMemoryEntry { pid, name, vm_rss_kb: rss_kb });
            }
        }
    }
    if list.is_empty() {
        let self_rss = read_self_rss_kb();
        if self_rss > 0 {
            list.push(ProcessMemoryEntry {
                pid: std::process::id(),
                name: "vane".into(),
                vm_rss_kb: self_rss,
            });
        }
    }
    list.sort_by(|a, b| b.vm_rss_kb.cmp(&a.vm_rss_kb));
    list.truncate(limit);
    list
}

fn read_self_rss_kb() -> u64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    let ok = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) == 0 };
    if !ok || usage.ru_maxrss <= 0 {
        return 0;
    }
    if cfg!(target_os = "macos") {
        // macOS ru_maxrss 单位为字节，Linux 单位为 KiB
        (usage.ru_maxrss as u64) / 1024
    } else {
        usage.ru_maxrss as u64
    }
}
