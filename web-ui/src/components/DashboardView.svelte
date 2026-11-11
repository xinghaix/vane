<script>
  import { formatKB, formatBytes, formatRate, formatUptime, copyText } from '../lib/helpers.js';

  let { t, lang, dashboard, onRefresh, apiFetch, showToast } = $props();

  let cpuHistory = $state([]);
  let netHistory = $state([]);

  // 记录实时折线序列（上限 24 个点，纯内存零重排）
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

  // 按需唤醒采样：仅当看板挂载且页面处于前台可见时按 2s 周期请求，切走或最小化立即零轮询
  $effect(() => {
    let timer = null;
    const start = () => {
      if (!timer && document.visibilityState === 'visible') {
        timer = setInterval(() => {
          if (document.visibilityState === 'visible') onRefresh(true);
        }, 2000);
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

  function buildSparkPath(values, maxVal, width = 320, height = 56) {
    if (!values || values.length < 2) return '';
    const ceil = Math.max(maxVal, ...values, 1);
    return values
      .map((v, idx) => {
        const x = (idx / (values.length - 1)) * width;
        const y = height - Math.min(1, Math.max(0, v / ceil)) * (height - 8) - 4;
        return `${idx === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(' ');
  }

  async function unbanCidr(cidr) {
    try {
      await apiFetch(`/api/security/bans/${encodeURIComponent(cidr)}`, { method: 'DELETE' });
      showToast(`${t.dash.unban}: ${cidr}`);
      await onRefresh(true);
    } catch (err) {
      showToast(err.message);
    }
  }

  async function handleCopy(val) {
    if (await copyText(val)) showToast(`${t.copied}: ${val}`);
  }

  function healthBadge(h) {
    const st = h?.state || 'disabled';
    if (st === 'running') return { cls: 'badge-ok', text: 'RUNNING' };
    if (st === 'degraded') return { cls: 'badge-warn', text: `DEGRADED (${h.recent_failures || 1})` };
    if (st === 'circuit_open') return { cls: 'badge-danger', text: 'CIRCUIT OPEN' };
    return { cls: 'badge-muted', text: 'DISABLED' };
  }
</script>

{#if dashboard}
  <div class="bento-grid">
    <!-- SoC CPU & 温度 -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">{t.dash.socTitle}</span>
        {#if dashboard.system.soc_temp_celsius > 0}
          <span class="badge {dashboard.system.soc_temp_celsius >= 80 ? 'badge-danger' : 'badge-ok'} num">
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
        <div class="progress-fill" style="width:{Math.min(100, dashboard.system.cpu_usage_percent)}%"></div>
      </div>
      {#if dashboard.system.cpu_cores_percent?.length > 1}
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(56px,1fr));gap:6px;margin-top:8px;">
          {#each dashboard.system.cpu_cores_percent as pct, idx}
            <div style="font-size:11px;color:var(--text-secondary);" class="mono">
              C{idx}: {pct.toFixed(0)}%
            </div>
          {/each}
        </div>
      {/if}
      <div class="mono" style="font-size:12px;color:var(--text-secondary);margin-top:8px;">
        Load: {dashboard.system.load_avg.map((v) => v.toFixed(2)).join(' / ')} · Up {formatUptime(dashboard.system.uptime_secs)}
      </div>
    </div>

    <!-- 物理内存与 Slab SUnreclaim -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">{t.dash.memTitle}</span>
        <span class="badge badge-info num">Avail {formatKB(dashboard.system.memory.available_kb)}</span>
      </div>
      <div class="num" style="font-size:26px;font-weight:700;margin-bottom:4px;">
        {formatKB(dashboard.system.memory.used_kb)} / {formatKB(dashboard.system.memory.total_kb)}
      </div>
      <div class="progress-bar">
        <div
          class="progress-fill"
          style="width:{Math.min(100, (dashboard.system.memory.used_kb / Math.max(1, dashboard.system.memory.total_kb)) * 100)}%"
        ></div>
      </div>
      <div class="mono" style="font-size:12px;color:var(--text-secondary);margin-top:8px;">
        Cached: {formatKB(dashboard.system.memory.cached_kb)} · Slab SUnreclaim: {formatKB(dashboard.system.memory.slab_unreclaim_kb)}
      </div>
    </div>

    <!-- 防火墙与全局连接配额 -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">{t.dash.fwTitle}</span>
        <span class="badge {dashboard.firewall.lockdown ? 'badge-danger' : 'badge-ok'}">
          {dashboard.firewall.lockdown ? 'LOCKDOWN' : dashboard.firewall.backend}
        </span>
      </div>
      <div class="num" style="font-size:28px;font-weight:700;margin-bottom:4px;">
        {dashboard.active_connections} <span style="font-size:16px;color:var(--text-secondary);">/ {dashboard.max_connections}</span>
      </div>
      <div class="progress-bar">
        <div
          class="progress-fill"
          style="width:{Math.min(100, (dashboard.active_connections / Math.max(1, dashboard.max_connections)) * 100)}%"
        ></div>
      </div>
      <div class="mono" style="font-size:12px;color:var(--text-secondary);margin-top:8px;">
        WAN Open Rules: {dashboard.firewall.rules.length} · Active Bans: {dashboard.bans.length}
      </div>
    </div>
  </div>

  <!-- 实时 SVG 趋势曲线 + 舱壁健康度 -->
  <div class="bento-grid-2">
    <div class="card">
      <div class="card-header">
        <span class="card-title">{t.dash.trendTitle}</span>
        <span class="mono" style="font-size:12px;color:var(--info);">
          {formatRate(netHistory[netHistory.length - 1] || 0)}
        </span>
      </div>
      <div style="display:grid;gap:10px;">
        <div class="subcard" style="padding:10px 12px;">
          <div class="row-between" style="font-size:12px;color:var(--text-secondary);margin-bottom:4px;">
            <span>CPU (%)</span>
            <span class="mono" style="color:var(--accent);">{dashboard.system.cpu_usage_percent.toFixed(1)}%</span>
          </div>
          <svg viewBox="0 0 320 56" style="width:100%;height:52px;display:block;">
            <path d={buildSparkPath(cpuHistory, 100)} fill="none" stroke="var(--accent)" stroke-width="2.2" />
          </svg>
        </div>
        <div class="subcard" style="padding:10px 12px;">
          <div class="row-between" style="font-size:12px;color:var(--text-secondary);margin-bottom:4px;">
            <span>WAN+LAN Throughput</span>
            <span class="mono" style="color:var(--info);">{formatRate(netHistory[netHistory.length - 1] || 0)}</span>
          </div>
          <svg viewBox="0 0 320 56" style="width:100%;height:52px;display:block;">
            <path d={buildSparkPath(netHistory, 102400)} fill="none" stroke="var(--info)" stroke-width="2.2" />
          </svg>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <span class="card-title">{t.dash.healthTitle}</span>
      </div>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:8px;">
        {#each Object.entries(dashboard.module_health || {}) as [modName, h]}
          {@const b = healthBadge(h)}
          <div class="subcard" style="padding:10px 12px;">
            <div class="row-between">
              <span style="font-size:13px;font-weight:600;">{t.nav[modName] || modName}</span>
              <span class="badge {b.cls}" style="font-size:10px;padding:2px 7px;">{b.text}</span>
            </div>
            {#if h?.last_error || h?.reason}
              <div class="mono" style="font-size:11px;color:var(--warn);margin-top:4px;word-break:break-all;">
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
      <div style="display:grid;gap:10px;">
        {#each dashboard.system.interfaces as iface}
          <div class="subcard">
            <div class="row-between" style="margin-bottom:6px;">
              <span class="mono" style="font-weight:700;">{iface.iface}</span>
              <span class="mono" style="font-size:12px;color:var(--text-secondary);">
                ↓ {formatRate(iface.rx_bps)} ({formatBytes(iface.rx_bytes)}) · ↑ {formatRate(iface.tx_bps)} ({formatBytes(iface.tx_bytes)})
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
    </div>

    <div class="card">
      <div class="card-header">
        <span class="card-title">{t.dash.quickStatus}</span>
      </div>
      <div style="display:grid;gap:10px;">
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
          <div class="subcard row-between">
            <div>
              <div style="font-weight:600;font-size:13px;">TLS · {c.domain}</div>
              <div class="mono" style="font-size:11px;color:var(--text-secondary);">
                Exp: {c.expires_at_unix ? new Date(c.expires_at_unix * 1000).toLocaleDateString() : '—'}
              </div>
            </div>
            <span class="badge {c.status === 'active' ? 'badge-ok' : 'badge-warn'}">{c.status}</span>
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
        {#if !(dashboard.ddns?.length || dashboard.certs?.length || Object.keys(dashboard.stun_public_addrs || {}).length)}
          <div class="empty-state" style="padding:20px;">
            {lang === 'en' ? 'No active DDNS / ACME / STUN runtime entries yet.' : '暂未配置活跃的 DDNS、证书或 STUN 映射任务'}
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
