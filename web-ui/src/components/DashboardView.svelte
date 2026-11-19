<script>
  import Icons from './Icons.svelte';
  import { formatKB, formatBytes, formatRate, formatUptime, copyText } from '../lib/helpers.js';

  let { t, lang, dashboard, settingsJson, onRefresh, apiFetch, showToast } = $props();

  let cpuHistory = $state([]);
  let netHistory = $state([]);
  let cpuHoverIdx = $state(-1);
  let netHoverIdx = $state(-1);
  let showFwRules = $state(false);

  let tempThreshold = $derived(Number(settingsJson?.monitor?.temp_alert_celsius || 85));
  let pollIntervalMs = $derived(
    Math.max(1000, Math.min(60000, Number(settingsJson?.monitor?.sample_interval_secs || 2) * 1000))
  );

  // 记录实时折线序列（上限 24 个点）
  $effect(() => {
    if (!dashboard?.system) return;
    const cpu = Number(dashboard.system.cpu_usage_percent || 0);
    const totalBps = (dashboard.system.interfaces || []).reduce(
      (acc, i) => acc + Number(i.rx_bps || 0) + Number(i.tx_bps || 0),
      0
    );
    cpuHistory = [...cpuHistory.slice(-23), cpu];
    netHistory = [...netHistory.slice(-23), totalBps];
  });

  // 按需唤醒采样：仅当看板挂载且页面处于前台可见时按配置间隔轮询
  $effect(() => {
    const interval = pollIntervalMs;
    let timer = null;
    const start = () => {
      if (!timer && document.visibilityState === 'visible') {
        timer = setInterval(() => {
          if (document.visibilityState === 'visible') onRefresh(true);
        }, interval);
      }
    };
    const stop = () => {
      if (timer) {
        clearInterval(timer);
        timer = null;
      }
    };
    const onVis = () => (document.visibilityState === 'visible' ? start() : stop());
    start();
    document.addEventListener('visibilitychange', onVis);
    return () => {
      stop();
      document.removeEventListener('visibilitychange', onVis);
    };
  });

  function buildSpark(values, minCeil, width = 340, height = 74) {
    if (!values || values.length < 2) return null;
    const ceil = Math.max(minCeil, ...values, 1);
    const padY = 6;
    const usableH = height - padY * 2;
    const pts = values.map((v, idx) => {
      const x = (idx / (values.length - 1)) * width;
      const y = height - padY - Math.min(1, Math.max(0, v / ceil)) * usableH;
      return { x, y, val: v };
    });
    const linePath = pts.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');
    const areaPath = `${linePath} L${width.toFixed(1)},${(height - padY).toFixed(1)} L0,${(height - padY).toFixed(1)} Z`;
    return { linePath, areaPath, pts, ceil };
  }

  function barTone(pct) {
    if (pct >= 90) return 'danger';
    if (pct >= 70) return 'warn';
    return '';
  }

  async function unbanCidr(cidr) {
    try {
      await apiFetch(`/api/security/bans/${encodeURIComponent(cidr)}`, { method: 'DELETE' });
      showToast(`${t.dash.unban}: ${cidr}`, 'success');
      await onRefresh(true);
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  async function handleCopy(val) {
    if (await copyText(val)) showToast(`${t.copied}: ${val}`, 'success');
  }

  function healthBadge(h) {
    const st = h?.state || 'disabled';
    if (st === 'running') return { cls: 'badge-ok', dot: 'ok', text: t.common.statusRunning };
    if (st === 'degraded') return { cls: 'badge-warn', dot: 'warn', text: `${t.common.statusFailed} (${h.recent_failures || 1})` };
    if (st === 'circuit_open') return { cls: 'badge-danger', dot: 'danger', text: 'CIRCUIT OPEN' };
    return { cls: 'badge-muted', dot: 'muted', text: t.common.statusDisabled };
  }

  function formatFwRule(rule) {
    if (rule.kind === 'wan_input') {
      const fams = [rule.ipv4 ? 'v4' : '', rule.ipv6 ? 'v6' : ''].filter(Boolean).join('+');
      return `${rule.owner_module} · ${rule.rule_name} (${rule.proto}/${rule.port} ${fams})`;
    }
    if (rule.kind === 'kernel_dnat') {
      return `${rule.owner_module} · ${rule.rule_name} (DNAT ${rule.proto}/${rule.listen_port} → ${rule.target})`;
    }
    if (rule.kind === 'sub_device_ipv6_forward') {
      return `${rule.owner_module} · ${rule.rule_name} (${rule.device_ip} TCP:${(rule.tcp_ports || []).join(',')} UDP:${(rule.udp_ports || []).join(',')})`;
    }
    return JSON.stringify(rule);
  }

  function certExpiryDays(unixSecs) {
    if (!unixSecs) return null;
    return Math.floor((unixSecs - Math.floor(Date.now() / 1000)) / 86400);
  }

  let memUsedPct = $derived(
    dashboard?.system?.memory
      ? Math.min(100, (dashboard.system.memory.used_kb / Math.max(1, dashboard.system.memory.total_kb)) * 100)
      : 0
  );
  let swapUsedKb = $derived(
    dashboard?.system?.memory
      ? Math.max(0, (dashboard.system.memory.swap_total_kb || 0) - (dashboard.system.memory.swap_free_kb || 0))
      : 0
  );
  let swapPct = $derived(
    dashboard?.system?.memory?.swap_total_kb > 0
      ? Math.min(100, (swapUsedKb / dashboard.system.memory.swap_total_kb) * 100)
      : 0
  );
  let quotaPct = $derived(
    dashboard
      ? Math.min(100, (dashboard.active_connections / Math.max(1, dashboard.max_connections)) * 100)
      : 0
  );
  let cpuSpark = $derived(buildSpark(cpuHistory, 100));
  let netSpark = $derived(buildSpark(netHistory, 102400));
</script>

{#if !dashboard}
  <div class="bento-grid">
    {#each [1, 2, 3] as _}
      <div class="card">
        <div class="skeleton" style="width:45%;margin-bottom:14px;"></div>
        <div class="skeleton" style="width:65%;height:28px;margin-bottom:10px;"></div>
        <div class="skeleton" style="width:100%;height:8px;"></div>
      </div>
    {/each}
  </div>
{:else}
  <div class="bento-grid">
    <!-- SoC CPU & 温度 -->
    <div class="card">
      <div class="card-header">
        <span class="card-title"><Icons name="activity" size={16} />{t.dash.socTitle}</span>
        {#if dashboard.system.soc_temp_celsius > 0}
          <span
            class="badge {dashboard.system.soc_temp_celsius >= tempThreshold
              ? 'badge-danger'
              : dashboard.system.soc_temp_celsius >= tempThreshold - 10
                ? 'badge-warn'
                : 'badge-ok'} num"
          >
            {dashboard.system.soc_temp_celsius.toFixed(1)} °C
          </span>
        {:else}
          <span class="badge badge-muted">Temp N/A</span>
        {/if}
      </div>
      <div class="num" style="font-size:28px;font-weight:700;margin-bottom:4px;">
        {dashboard.system.cpu_usage_percent.toFixed(1)}%
      </div>
      <div class="progress-bar">
        <div
          class="progress-fill {barTone(dashboard.system.cpu_usage_percent)}"
          style="width:{Math.min(100, dashboard.system.cpu_usage_percent)}%"
        ></div>
      </div>
      {#if dashboard.system.cpu_cores_percent?.length > 1}
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(68px,1fr));gap:6px;margin-top:10px;">
          {#each dashboard.system.cpu_cores_percent as pct, idx}
            <div>
              <div class="row-between mono" style="font-size:10.5px;color:var(--text-secondary);">
                <span>C{idx}</span>
                <span>{pct.toFixed(0)}%</span>
              </div>
              <div class="progress-bar" style="height:4px;margin:2px 0 0;">
                <div class="progress-fill {barTone(pct)}" style="width:{Math.min(100, pct)}%"></div>
              </div>
            </div>
          {/each}
        </div>
      {/if}
      <div class="mono" style="font-size:12px;color:var(--text-secondary);margin-top:10px;">
        {t.dash.load}: {dashboard.system.load_avg.map((v) => v.toFixed(2)).join(' / ')} · {t.dash.uptime}: {formatUptime(dashboard.system.uptime_secs)}
      </div>
    </div>

    <!-- 物理内存与 Swap / Slab SUnreclaim -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">{t.dash.memTitle}</span>
        <span class="badge badge-info num">Avail {formatKB(dashboard.system.memory.available_kb)}</span>
      </div>
      <div class="num" style="font-size:25px;font-weight:700;margin-bottom:4px;">
        {formatKB(dashboard.system.memory.used_kb)}
        <span style="font-size:15px;color:var(--text-secondary);">/ {formatKB(dashboard.system.memory.total_kb)}</span>
      </div>
      <div class="progress-bar">
        <div class="progress-fill {barTone(memUsedPct)}" style="width:{memUsedPct}%"></div>
      </div>
      {#if dashboard.system.memory.swap_total_kb > 0}
        <div style="margin-top:8px;">
          <div class="row-between mono" style="font-size:11px;color:var(--text-secondary);">
            <span>{t.dash.swap}</span>
            <span>{formatKB(swapUsedKb)} / {formatKB(dashboard.system.memory.swap_total_kb)}</span>
          </div>
          <div class="progress-bar" style="height:5px;margin:4px 0;">
            <div class="progress-fill {barTone(swapPct)}" style="width:{swapPct}%"></div>
          </div>
        </div>
      {/if}
      <div class="mono" style="font-size:12px;color:var(--text-secondary);margin-top:8px;">
        Cached: {formatKB(dashboard.system.memory.cached_kb)} · Slab SUnreclaim: {formatKB(dashboard.system.memory.slab_unreclaim_kb)}
      </div>
    </div>

    <!-- 防火墙与全局连接配额 -->
    <div class="card">
      <div class="card-header">
        <span class="card-title"><Icons name="shield" size={16} />{t.dash.fwTitle}</span>
        <span class="badge {dashboard.firewall.lockdown ? 'badge-danger' : 'badge-ok'}">
          {dashboard.firewall.lockdown ? 'LOCKDOWN' : dashboard.firewall.backend}
        </span>
      </div>
      <div class="num" style="font-size:28px;font-weight:700;margin-bottom:4px;">
        {dashboard.active_connections}
        <span style="font-size:16px;color:var(--text-secondary);">/ {dashboard.max_connections}</span>
      </div>
      <div class="progress-bar">
        <div class="progress-fill {barTone(quotaPct)}" style="width:{quotaPct}%"></div>
      </div>
      <div class="row-between" style="margin-top:8px;">
        <span class="mono" style="font-size:12px;color:var(--text-secondary);">
          {t.dash.wanRules}: {dashboard.firewall.rules.length} · {t.dash.activeBans}: {dashboard.bans.length}
        </span>
        <button type="button" class="btn btn-xs btn-ghost" onclick={() => showFwRules = !showFwRules}>
          {t.dash.fwRulesToggle}
        </button>
      </div>
      {#if showFwRules}
        <div class="subcard mono" style="margin-top:10px;padding:10px 12px;font-size:11px;max-height:160px;overflow-y:auto;">
          {#if !dashboard.firewall.rules.length}
            <div style="color:var(--text-muted);">{t.dash.noFwRules}</div>
          {:else}
            {#each dashboard.firewall.rules as r}
              <div style="padding:2px 0;border-bottom:1px solid var(--border-subtle);">{formatFwRule(r)}</div>
            {/each}
          {/if}
        </div>
      {/if}
    </div>
  </div>

  <!-- 实时 SVG 面积趋势曲线 + 舱壁健康度 -->
  <div class="bento-grid-2">
    <div class="card">
      <div class="card-header">
        <div>
          <span class="card-title">{t.dash.trendTitle}</span>
          <div style="font-size:11.5px;color:var(--text-muted);margin-top:2px;">
            {t.dash.trendHint} ({Math.round(pollIntervalMs / 1000)}s)
          </div>
        </div>
        <span class="mono" style="font-size:12px;color:var(--info);font-weight:600;">
          {formatRate(netHistory[netHistory.length - 1] || 0)}
        </span>
      </div>
      <div style="display:grid;gap:10px;">
        <!-- CPU Sparkline -->
        <div class="subcard" style="padding:10px 12px;">
          <div class="row-between" style="font-size:12px;color:var(--text-secondary);margin-bottom:4px;">
            <span>CPU (%)</span>
            <span class="mono" style="color:var(--accent);font-weight:600;">
              {cpuHoverIdx >= 0 && cpuSpark?.pts[cpuHoverIdx]
                ? `${cpuSpark.pts[cpuHoverIdx].val.toFixed(1)}%`
                : `${dashboard.system.cpu_usage_percent.toFixed(1)}%`}
            </span>
          </div>
          {#if cpuSpark}
            <svg
              viewBox="0 0 340 74"
              style="width:100%;height:68px;display:block;"
              role="img"
              aria-label="CPU usage trend"
              onmousemove={(e) => {
                const rect = e.currentTarget.getBoundingClientRect();
                const idx = Math.round(((e.clientX - rect.left) / rect.width) * (cpuSpark.pts.length - 1));
                cpuHoverIdx = Math.max(0, Math.min(cpuSpark.pts.length - 1, idx));
              }}
              onmouseleave={() => cpuHoverIdx = -1}
            >
              <defs>
                <linearGradient id="cpuAreaGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stop-color="var(--accent)" stop-opacity="0.34" />
                  <stop offset="100%" stop-color="var(--accent)" stop-opacity="0.02" />
                </linearGradient>
              </defs>
              {#each [21, 37, 53] as gy}
                <line x1="0" y1={gy} x2="340" y2={gy} stroke="var(--border-subtle)" stroke-dasharray="3 3" />
              {/each}
              <path d={cpuSpark.areaPath} fill="url(#cpuAreaGrad)" />
              <path d={cpuSpark.linePath} fill="none" stroke="var(--accent)" stroke-width="2.2" />
              {#if cpuHoverIdx >= 0 && cpuSpark.pts[cpuHoverIdx]}
                {@const p = cpuSpark.pts[cpuHoverIdx]}
                <line x1={p.x} y1="4" x2={p.x} y2="68" stroke="var(--text-muted)" stroke-dasharray="2 2" />
                <circle cx={p.x} cy={p.y} r="3.6" fill="var(--accent)" stroke="var(--bg-card)" stroke-width="1.5" />
              {/if}
            </svg>
          {:else}
            <div style="height:68px;display:grid;place-items:center;font-size:12px;color:var(--text-muted);">
              {t.dash.collecting}
            </div>
          {/if}
        </div>

        <!-- Throughput Sparkline -->
        <div class="subcard" style="padding:10px 12px;">
          <div class="row-between" style="font-size:12px;color:var(--text-secondary);margin-bottom:4px;">
            <span>WAN+LAN Throughput</span>
            <span class="mono" style="color:var(--info);font-weight:600;">
              {netHoverIdx >= 0 && netSpark?.pts[netHoverIdx]
                ? formatRate(netSpark.pts[netHoverIdx].val)
                : formatRate(netHistory[netHistory.length - 1] || 0)}
              {#if netSpark}
                <span style="color:var(--text-muted);font-weight:400;"> · max {formatRate(netSpark.ceil)}</span>
              {/if}
            </span>
          </div>
          {#if netSpark}
            <svg
              viewBox="0 0 340 74"
              style="width:100%;height:68px;display:block;"
              role="img"
              aria-label="Network throughput trend"
              onmousemove={(e) => {
                const rect = e.currentTarget.getBoundingClientRect();
                const idx = Math.round(((e.clientX - rect.left) / rect.width) * (netSpark.pts.length - 1));
                netHoverIdx = Math.max(0, Math.min(netSpark.pts.length - 1, idx));
              }}
              onmouseleave={() => netHoverIdx = -1}
            >
              <defs>
                <linearGradient id="netAreaGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stop-color="var(--info)" stop-opacity="0.34" />
                  <stop offset="100%" stop-color="var(--info)" stop-opacity="0.02" />
                </linearGradient>
              </defs>
              {#each [21, 37, 53] as gy}
                <line x1="0" y1={gy} x2="340" y2={gy} stroke="var(--border-subtle)" stroke-dasharray="3 3" />
              {/each}
              <path d={netSpark.areaPath} fill="url(#netAreaGrad)" />
              <path d={netSpark.linePath} fill="none" stroke="var(--info)" stroke-width="2.2" />
              {#if netHoverIdx >= 0 && netSpark.pts[netHoverIdx]}
                {@const p = netSpark.pts[netHoverIdx]}
                <line x1={p.x} y1="4" x2={p.x} y2="68" stroke="var(--text-muted)" stroke-dasharray="2 2" />
                <circle cx={p.x} cy={p.y} r="3.6" fill="var(--info)" stroke="var(--bg-card)" stroke-width="1.5" />
              {/if}
            </svg>
          {:else}
            <div style="height:68px;display:grid;place-items:center;font-size:12px;color:var(--text-muted);">
              {t.dash.collecting}
            </div>
          {/if}
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <span class="card-title">{t.dash.healthTitle}</span>
      </div>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(168px,1fr));gap:8px;">
        {#each Object.entries(dashboard.module_health || {}) as [modName, h]}
          {@const b = healthBadge(h)}
          <div class="subcard" style="padding:10px 12px;">
            <div class="row-between">
              <span style="display:inline-flex;align-items:center;gap:7px;font-size:13px;font-weight:600;">
                <span class="status-dot {b.dot}"></span>
                {t.nav[modName] || modName}
              </span>
              <span class="badge {b.cls}" style="font-size:10.5px;padding:2px 7px;">{b.text}</span>
            </div>
            {#if h?.last_error || h?.reason}
              <div class="mono" style="font-size:11px;color:var(--warn);margin-top:5px;word-break:break-all;">
                {h.last_error || h.reason}
              </div>
            {/if}
          </div>
        {/each}
      </div>
    </div>
  </div>

  <!-- 双栈网络接口 + 业务运行摘要 -->
  <div class="bento-grid-2">
    <div class="card">
      <div class="card-header">
        <span class="card-title">{t.dash.ifaceTitle}</span>
        <span class="badge badge-info">{dashboard.system.interfaces.length}</span>
      </div>
      {#if !dashboard.system.interfaces.length}
        <div class="empty-state" style="padding:20px;">{t.dash.noIfaces}</div>
      {:else}
        <div style="display:grid;gap:10px;">
          {#each dashboard.system.interfaces as iface}
            <div class="subcard">
              <div class="row-between" style="margin-bottom:6px;">
                <span class="mono" style="font-weight:700;">{iface.iface}</span>
                <span class="mono" style="font-size:12px;">
                  <span style="color:var(--accent);">↓ {formatRate(iface.rx_bps)}</span>
                  <span style="color:var(--text-muted);">({formatBytes(iface.rx_bytes)})</span>
                  ·
                  <span style="color:var(--info);">↑ {formatRate(iface.tx_bps)}</span>
                  <span style="color:var(--text-muted);">({formatBytes(iface.tx_bytes)})</span>
                </span>
              </div>
              {#if iface.ipv4.length > 0}
                <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:4px;">
                  {#each iface.ipv4 as ip4}
                    <button type="button" class="btn btn-xs mono" style="color:var(--accent);" onclick={() => handleCopy(ip4)}>
                      IPv4 {ip4}
                    </button>
                  {/each}
                </div>
              {/if}
              {#if iface.ipv6.length > 0}
                <div style="display:flex;flex-wrap:wrap;gap:6px;">
                  {#each iface.ipv6 as ip6}
                    <button type="button" class="btn btn-xs mono" style="color:var(--info);word-break:break-all;" onclick={() => handleCopy(ip6)}>
                      IPv6 {ip6}
                    </button>
                  {/each}
                </div>
              {/if}
            </div>
          {/each}
        </div>
      {/if}
    </div>

    <div class="card">
      <div class="card-header">
        <span class="card-title">{t.dash.quickStatus}</span>
      </div>
      <div style="display:grid;gap:8px;">
        {#each dashboard.reverse_proxy_status || [] as rp}
          <div class="subcard row-between">
            <div>
              <div style="font-weight:600;font-size:13px;">Proxy · {rp.name}</div>
              <div class="mono" style="font-size:11px;color:var(--text-secondary);">
                :{rp.listen_port} ({rp.bound_v4 ? 'v4' : ''}{rp.bound_v4 && rp.bound_v6 ? '+' : ''}{rp.bound_v6 ? 'v6' : ''}) · conns={rp.active_conns}
              </div>
            </div>
            <span class="badge {rp.status === 'running' ? 'badge-ok' : rp.status === 'failed' ? 'badge-danger' : 'badge-muted'}">{rp.status}</span>
          </div>
        {/each}
        {#each dashboard.port_forward_status || [] as pf}
          <div class="subcard row-between">
            <div>
              <div style="font-weight:600;font-size:13px;">Forward · {pf.name}</div>
              <div class="mono" style="font-size:11px;color:var(--text-secondary);">
                :{pf.listen_port}/{pf.proto} · conns={pf.active_conns}
              </div>
            </div>
            <span class="badge {pf.status === 'running' ? 'badge-ok' : pf.status === 'failed' ? 'badge-danger' : 'badge-warn'}">{pf.status}</span>
          </div>
        {/each}
        {#each dashboard.ddns || [] as d}
          <div class="subcard row-between">
            <div>
              <div style="font-weight:600;font-size:13px;">DDNS · {d.domain}</div>
              <div class="mono" style="font-size:11px;color:var(--text-secondary);">
                v4: {d.last_ipv4 || '—'} · v6: {d.last_ipv6 || '—'}
              </div>
            </div>
            <span class="badge {d.status === 'synced' ? 'badge-ok' : d.status === 'failed' ? 'badge-danger' : 'badge-warn'}">{d.status}</span>
          </div>
        {/each}
        {#each dashboard.certs || [] as c}
          {@const days = certExpiryDays(c.expires_at_unix)}
          <div class="subcard row-between">
            <div>
              <div style="font-weight:600;font-size:13px;">TLS · {c.domain}</div>
              <div class="mono" style="font-size:11px;color:var(--text-secondary);">
                {t.dash.expires}: {c.expires_at_unix ? new Date(c.expires_at_unix * 1000).toLocaleDateString() : '—'}
                {#if days !== null} ({days}d){/if}
              </div>
            </div>
            <span class="badge {c.status === 'active' && (days === null || days > 14) ? 'badge-ok' : 'badge-warn'}">{c.status}</span>
          </div>
        {/each}
        {#each Object.entries(dashboard.stun_public_addrs || {}) as [name, pubAddr]}
          <div class="subcard row-between">
            <div>
              <div style="font-weight:600;font-size:13px;">STUN · {name}</div>
              <div class="mono" style="font-size:12px;color:var(--info);">{pubAddr}</div>
            </div>
            <button type="button" class="btn btn-xs" onclick={() => handleCopy(pubAddr)}>{t.copy}</button>
          </div>
        {/each}
        {#if !(dashboard.reverse_proxy_status?.length || dashboard.port_forward_status?.length || dashboard.ddns?.length || dashboard.certs?.length || Object.keys(dashboard.stun_public_addrs || {}).length)}
          <div class="empty-state" style="padding:20px;">
            {lang === 'en' ? 'No active gateway rules or runtime tasks yet.' : '暂未配置活跃的代理、转发、DDNS、证书或 STUN 任务'}
          </div>
        {/if}
      </div>
    </div>
  </div>

  <!-- Fail2Ban 封禁表 + Top VmRSS 进程 -->
  <div class="bento-grid-2">
    <div class="card">
      <div class="card-header">
        <span class="card-title">{t.dash.bansTitle}</span>
        <span class="badge {dashboard.bans.length > 0 ? 'badge-danger' : 'badge-ok'}">{dashboard.bans.length}</span>
      </div>
      {#if dashboard.bans.length === 0}
        <div class="empty-state" style="padding:20px;">{t.dash.noBans}</div>
      {:else}
        <div style="display:grid;gap:8px;">
          {#each dashboard.bans as ban}
            <div class="subcard row-between">
              <div>
                <div class="mono" style="font-weight:700;color:var(--danger);">{ban.cidr}</div>
                <div class="mono" style="font-size:11px;color:var(--text-secondary);">
                  {ban.reason} · fails={ban.failures} · {ban.remaining_secs}s
                </div>
              </div>
              <button type="button" class="btn btn-sm" onclick={() => unbanCidr(ban.cidr)}>{t.dash.unban}</button>
            </div>
          {/each}
        </div>
      {/if}
    </div>

    <div class="card">
      <div class="card-header"><span class="card-title">{t.dash.procTitle}</span></div>
      <div style="display:grid;gap:8px;">
        {#each dashboard.system.top_processes as proc}
          <div class="subcard row-between" style="padding:8px 12px;font-size:13px;">
            <span><code class="mono" style="color:var(--text-muted);">#{proc.pid}</code> {proc.name}</span>
            <span class="mono" style="font-weight:600;">{formatKB(proc.vm_rss_kb)}</span>
          </div>
        {/each}
      </div>
    </div>
  </div>
{/if}
