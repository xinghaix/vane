<script>
  import { untrack } from 'svelte';
  import Icons from './Icons.svelte';
  import MetricRing from './MetricRing.svelte';
  import EditorDialog from './EditorDialog.svelte';
  import ComboInput from './ComboInput.svelte';
  import {
    formatKB,
    formatBytes,
    formatRate,
    formatUptime,
    formatDurationSecs,
    translateRuntimeStatus,
    copyText,
    splitCsv,
    joinCsv,
    deepClone,
  } from '../lib/helpers.js';

  let {
    t,
    lang,
    dashboard,
    settingsJson,
    networkInfo = null,
    onEnsureNetworkInfo = null,
    onSaveSettings = null,
    askConfirm = null,
    onRefresh,
    onNavigate,
    apiFetch,
    showToast,
  } = $props();

  let monSettingsOpen = $state(false);
  let monSettingsSaving = $state(false);
  let monIfacesCsv = $state('');
  let monIntervalDraft = $state(2);
  let monTopProcsDraft = $state(10);
  let monTempDraft = $state(85);
  let monMemDraft = $state(32);
  let monCooldownDraft = $state(1800);
  let monThermalDraft = $state('');

  let ifaceOptions = $derived(
    (networkInfo?.interfaces || []).map((i) => {
      const ips = [...(i.ipv4 || []), ...(i.ipv6 || [])];
      return { value: i.iface, label: i.iface, sub: ips.slice(0, 2).join(', ') };
    })
  );

  function openMonitorSettings() {
    if (!settingsJson) return;
    const m = settingsJson.monitor || {};
    monIfacesCsv = joinCsv(m.interfaces);
    monIntervalDraft = Number(m.sample_interval_secs || 2);
    monTopProcsDraft = Number(m.top_processes || 10);
    monTempDraft = Number(m.temp_alert_celsius || 85);
    monMemDraft = Number(m.mem_low_mb ?? 32);
    monCooldownDraft = Number(m.alert_cooldown_secs || 1800);
    monThermalDraft = String(m.thermal_path || '');
    monSettingsOpen = true;
    onEnsureNetworkInfo?.(false);
  }

  async function saveMonitorSettings(e) {
    e.preventDefault();
    if (monSettingsSaving || !settingsJson || !onSaveSettings) return;
    monSettingsSaving = true;
    try {
      const next = deepClone(settingsJson);
      next.monitor = {
        ...next.monitor,
        interfaces: splitCsv(monIfacesCsv),
        sample_interval_secs: Math.max(1, Math.min(60, Number(monIntervalDraft) || 2)),
        top_processes: Math.max(1, Math.min(50, Number(monTopProcsDraft) || 10)),
        temp_alert_celsius: Math.max(40, Math.min(125, Number(monTempDraft) || 85)),
        mem_low_mb: Math.max(0, Math.min(4096, Number(monMemDraft) || 0)),
        alert_cooldown_secs: Math.max(60, Math.min(86400, Number(monCooldownDraft) || 1800)),
        thermal_path: String(monThermalDraft || '').trim(),
      };
      if (await onSaveSettings(next)) {
        monSettingsOpen = false;
      }
    } finally {
      monSettingsSaving = false;
    }
  }

  let cpuHistory = $state([]);
  let netHistory = $state([]);
  let lastSampleTs = 0;
  let cpuHoverIdx = $state(-1);
  let netHoverIdx = $state(-1);
  let showFwRules = $state(false);
  let unbanBusy = $state('');

  let tempThreshold = $derived(Number(settingsJson?.monitor?.temp_alert_celsius || 85));
  let memLowMb = $derived(Number(settingsJson?.monitor?.mem_low_mb || 32));
  let pollIntervalMs = $derived(
    Math.max(1000, Math.min(60000, Number(settingsJson?.monitor?.sample_interval_secs || 2) * 1000))
  );

  // 记录实时折线序列（按 timestamp_unix 去重，上限 24 个点）
  $effect(() => {
    const sys = dashboard?.system;
    if (!sys) return;
    const ts = Number(sys.timestamp_unix || 0);
    if (ts > 0 && ts === lastSampleTs) return;
    lastSampleTs = ts;
    const cpu = Number(sys.cpu_usage_percent || 0);
    const rxBps = (sys.interfaces || []).reduce((acc, i) => acc + Number(i.rx_bps || 0), 0);
    const txBps = (sys.interfaces || []).reduce((acc, i) => acc + Number(i.tx_bps || 0), 0);
    untrack(() => {
      cpuHistory = [...cpuHistory.slice(-23), cpu];
      netHistory = [...netHistory.slice(-23), { total: rxBps + txBps, rx: rxBps, tx: txBps }];
    });
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

  async function unbanCidr(cidr, scope = 'admin') {
    if (unbanBusy) return;
    const effectiveScope = scope || 'admin';
    const busyKey = `${effectiveScope}:${cidr}`;
    unbanBusy = busyKey;
    try {
      const r = await apiFetch(
        `/api/security/bans/${encodeURIComponent(cidr)}?scope=${encodeURIComponent(effectiveScope)}`,
        { method: 'DELETE' }
      );
      if (r?.unbanned === false) {
        showToast(t.dash.unbanNotFound, 'info');
      } else {
        const scopeSuffix = effectiveScope !== 'admin' ? ` (${effectiveScope})` : '';
        showToast(`${t.dash.unban}: ${cidr}${scopeSuffix}`, 'success');
      }
      await onRefresh(true);
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      unbanBusy = '';
    }
  }

  async function handleCopy(val) {
    if (await copyText(val)) showToast(`${t.copied}: ${val}`, 'success');
    else showToast(t.copyFailed, 'error');
  }

  function healthBadge(h) {
    const st = h?.state || 'disabled';
    if (st === 'running') return { cls: 'badge-ok', dot: 'ok', text: t.common.statusRunning };
    if (st === 'degraded') return { cls: 'badge-warn', dot: 'warn', text: `${t.common.statusFailed} (${h.recent_failures || 1})` };
    if (st === 'circuit_open') {
      const retry = h?.retry_in_secs ? ` (${h.retry_in_secs}s)` : '';
      return { cls: 'badge-danger', dot: 'danger', text: `${t.dash.circuitOpen}${retry}` };
    }
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
  let availMb = $derived((dashboard?.system?.memory?.available_kb || 0) / 1024);
  let availBadgeClass = $derived(
    availMb > 0 && availMb < memLowMb
      ? 'badge-danger'
      : availMb > 0 && availMb < memLowMb * 1.5
        ? 'badge-warn'
        : 'badge-info'
  );
  let cpuSpark = $derived(buildSpark(cpuHistory, 100));
  let netSpark = $derived(buildSpark(netHistory.map((p) => p.total), 102400));
  let latestNet = $derived(netHistory[netHistory.length - 1] || { total: 0, rx: 0, tx: 0 });

  // StatStrip 概览统计（对齐 Arcane stat-strip-item）
  let stripStats = $derived.by(() => {
    const mods = Object.values(dashboard?.module_health || {});
    const modRun = mods.filter((h) => h?.state === 'running').length;
    const modWarn = mods.filter((h) => h?.state === 'degraded').length;
    const modErr = mods.filter((h) => h?.state === 'circuit_open').length;

    const rpList = dashboard?.reverse_proxy_status || [];
    const pfList = dashboard?.port_forward_status || [];
    const trafficTotal = rpList.length + pfList.length;
    const trafficRun = [...rpList, ...pfList].filter((x) => x.status === 'running').length;
    const trafficErr = [...rpList, ...pfList].filter((x) => x.status === 'failed').length;

    const ddnsList = dashboard?.ddns || [];
    const certList = dashboard?.certs || [];
    const domTotal = ddnsList.length + certList.length;
    const domOk = ddnsList.filter((d) => d.status === 'synced').length + certList.filter((c) => c.status === 'active').length;
    const domErr = ddnsList.filter((d) => d.status === 'failed').length + certList.filter((c) => c.status === 'failed').length;

    const fwRules = dashboard?.firewall?.rules?.length || 0;
    const bans = dashboard?.bans?.length || 0;

    return { modTotal: mods.length, modRun, modWarn, modErr, trafficTotal, trafficRun, trafficErr, domTotal, domOk, domErr, fwRules, bans };
  });
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
  <!-- Arcane StatStrip 顶部聚合指标带 -->
  <div class="stat-strip-card">
    <div class="stat-strip-grid">
      <button type="button" class="stat-strip-cell" onclick={() => onNavigate?.('settings')}>
        <span class="stat-strip-label"><Icons name="grid" size={13} />{lang === 'en' ? 'Active Modules' : '子模块健康'}</span>
        <span class="stat-strip-val num">{stripStats.modRun}<span style="font-size:15px;color:var(--text-muted);font-weight:500;">/{stripStats.modTotal}</span></span>
        <span class="stat-strip-bar" aria-hidden="true">
          {#if stripStats.modRun > 0}<span class="stat-strip-seg" style={`flex:${stripStats.modRun};background:var(--accent);`}></span>{/if}
          {#if stripStats.modWarn > 0}<span class="stat-strip-seg" style={`flex:${stripStats.modWarn};background:var(--warn);`}></span>{/if}
          {#if stripStats.modErr > 0}<span class="stat-strip-seg" style={`flex:${stripStats.modErr};background:var(--danger);`}></span>{/if}
        </span>
        <span class="stat-strip-sub num">{stripStats.modErr > 0 ? `${stripStats.modErr} ${t.dash.circuitOpen}` : `${stripStats.modRun} ${t.common.statusRunning}`}</span>
      </button>

      <button type="button" class="stat-strip-cell" onclick={() => onNavigate?.('reverse_proxy')}>
        <span class="stat-strip-label"><Icons name="reverse_proxy" size={13} />{t.navGroups.traffic}</span>
        <span class="stat-strip-val num">{stripStats.trafficTotal}</span>
        <span class="stat-strip-bar" aria-hidden="true">
          {#if stripStats.trafficRun > 0}<span class="stat-strip-seg" style={`flex:${stripStats.trafficRun};background:var(--accent);`}></span>{/if}
          {#if stripStats.trafficErr > 0}<span class="stat-strip-seg" style={`flex:${stripStats.trafficErr};background:var(--danger);`}></span>{/if}
          {#if stripStats.trafficTotal - stripStats.trafficRun - stripStats.trafficErr > 0}<span class="stat-strip-seg" style={`flex:${stripStats.trafficTotal - stripStats.trafficRun - stripStats.trafficErr};background:var(--text-muted);opacity:0.4;`}></span>{/if}
        </span>
        <span class="stat-strip-sub num">{stripStats.trafficRun} {t.common.statusRunning}</span>
      </button>

      <button type="button" class="stat-strip-cell" onclick={() => onNavigate?.('ddns')}>
        <span class="stat-strip-label"><Icons name="ddns" size={13} />{t.navGroups.domain}</span>
        <span class="stat-strip-val num">{stripStats.domTotal}</span>
        <span class="stat-strip-bar" aria-hidden="true">
          {#if stripStats.domOk > 0}<span class="stat-strip-seg" style={`flex:${stripStats.domOk};background:var(--info);`}></span>{/if}
          {#if stripStats.domErr > 0}<span class="stat-strip-seg" style={`flex:${stripStats.domErr};background:var(--danger);`}></span>{/if}
          {#if stripStats.domTotal - stripStats.domOk - stripStats.domErr > 0}<span class="stat-strip-seg" style={`flex:${stripStats.domTotal - stripStats.domOk - stripStats.domErr};background:var(--warn);`}></span>{/if}
        </span>
        <span class="stat-strip-sub num">{stripStats.domOk} {lang === 'en' ? 'healthy' : '正常同步'}</span>
      </button>

      <button type="button" class="stat-strip-cell" onclick={() => (showFwRules = !showFwRules)}>
        <span class="stat-strip-label"><Icons name="shield" size={13} />{t.dash.wanRules} / {t.dash.activeBans}</span>
        <span class="stat-strip-val num">{stripStats.fwRules}</span>
        <span class="stat-strip-bar" aria-hidden="true">
          {#if stripStats.fwRules > 0}<span class="stat-strip-seg" style={`flex:${stripStats.fwRules};background:var(--accent);`}></span>{/if}
          {#if stripStats.bans > 0}<span class="stat-strip-seg" style={`flex:${stripStats.bans};background:var(--danger);`}></span>{/if}
        </span>
        <span class="stat-strip-sub num" style={stripStats.bans > 0 ? 'color:var(--danger);font-weight:600;' : ''}>
          {stripStats.bans > 0 ? `${stripStats.bans} ${t.dash.activeBans}` : dashboard.firewall.backend}
        </span>
      </button>
    </div>
  </div>
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
          <span class="badge badge-muted">{t.dash.tempNa}</span>
        {/if}
      </div>
      <div style="display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:6px;">
        <div style="min-width:0;">
          <div class="num" style="font-size:28px;font-weight:700;letter-spacing:-0.02em;line-height:1.1;">
            {dashboard.system.cpu_usage_percent.toFixed(1)}%
          </div>
          <div class="mono" style="font-size:11.5px;color:var(--text-secondary);margin-top:6px;">
            {t.dash.load}: {dashboard.system.load_avg.map((v) => v.toFixed(2)).join(' / ')}
          </div>
          <div class="mono" style="font-size:11.5px;color:var(--text-muted);margin-top:2px;">
            {t.dash.uptime}: {formatUptime(dashboard.system.uptime_secs)}
          </div>
        </div>
        <MetricRing
          percent={dashboard.system.cpu_usage_percent}
          size={58}
          stroke={5}
          tone={barTone(dashboard.system.cpu_usage_percent) || 'info'}
          label={`${Math.round(dashboard.system.cpu_usage_percent)}%`}
          sub="CPU"
        />
      </div>
      {#if dashboard.system.cpu_cores_percent?.length > 1}
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(64px,1fr));gap:6px;margin-top:10px;">
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
    </div>

    <!-- 物理内存与 Swap / Slab SUnreclaim -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">{t.dash.memTitle}</span>
        <span class="badge {availBadgeClass} num">{t.dash.avail} {formatKB(dashboard.system.memory.available_kb)}</span>
      </div>
      <div style="display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:6px;">
        <div style="min-width:0;">
          <div class="num" style="font-size:24px;font-weight:700;letter-spacing:-0.02em;line-height:1.15;">
            {formatKB(dashboard.system.memory.used_kb)}
            <span style="font-size:14px;color:var(--text-secondary);font-weight:500;">/ {formatKB(dashboard.system.memory.total_kb)}</span>
          </div>
          <div class="mono" style="font-size:11.5px;color:var(--text-secondary);margin-top:6px;">
            {t.dash.cached}: {formatKB(dashboard.system.memory.cached_kb)}
          </div>
          <div class="mono" style="font-size:11.5px;color:var(--text-muted);margin-top:2px;">
            {t.dash.slabUnreclaim}: {formatKB(dashboard.system.memory.slab_unreclaim_kb)}
          </div>
        </div>
        <MetricRing
          percent={memUsedPct}
          size={58}
          stroke={5}
          tone={barTone(memUsedPct) || 'accent'}
          label={`${Math.round(memUsedPct)}%`}
          sub="RAM"
        />
      </div>
      {#if dashboard.system.memory.swap_total_kb > 0}
        <div style="margin-top:10px;">
          <div class="row-between mono" style="font-size:11px;color:var(--text-secondary);">
            <span>{t.dash.swap}</span>
            <span>{formatKB(swapUsedKb)} / {formatKB(dashboard.system.memory.swap_total_kb)}</span>
          </div>
          <div class="progress-bar" style="height:5px;margin:4px 0 0;">
            <div class="progress-fill {barTone(swapPct)}" style="width:{swapPct}%"></div>
          </div>
        </div>
      {/if}
    </div>

    <!-- 防火墙与全局连接配额 -->
    <div class="card">
      <div class="card-header">
        <span class="card-title"><Icons name="shield" size={16} />{t.dash.fwTitle}</span>
        <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
          {#if dashboard.firewall.degraded}
            <span class="badge badge-warn" title={t.dash.fwDegradedBanner}>
              <Icons name="alert" size={11} />
              <span>{t.dash.fwDegradedTag}</span>
            </span>
          {/if}
          <span class="badge {dashboard.firewall.lockdown ? 'badge-danger' : dashboard.firewall.degraded ? 'badge-warn' : 'badge-ok'}">
            {dashboard.firewall.lockdown ? t.dash.lockdownTag : dashboard.firewall.backend}
          </span>
        </div>
      </div>
      {#if dashboard.firewall.degraded}
        <div class="banner banner-warn" role="alert" style="margin-bottom:10px;padding:8px 10px;font-size:12px;">
          <Icons name="alert" size={14} />
          <span>{t.dash.fwDegradedBanner}</span>
        </div>
      {/if}
      <div style="display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:6px;">
        <div style="min-width:0;">
          <div class="num" style="font-size:28px;font-weight:700;letter-spacing:-0.02em;line-height:1.1;">
            {dashboard.active_connections}
            <span style="font-size:15px;color:var(--text-secondary);font-weight:500;">/ {dashboard.max_connections}</span>
          </div>
          <div class="mono" style="font-size:11.5px;color:var(--text-secondary);margin-top:6px;">
            {t.dash.wanRules}: {dashboard.firewall.rules.length} · {t.dash.activeBans}: {dashboard.bans.length}
          </div>
        </div>
        <MetricRing
          percent={quotaPct}
          size={58}
          stroke={5}
          tone={barTone(quotaPct) || 'accent'}
          label={`${Math.round(quotaPct)}%`}
          sub="CONN"
        />
      </div>
      <div style="margin-top:8px;">
        <button type="button" class="btn btn-xs btn-ghost" style="margin-left:-8px;" onclick={() => showFwRules = !showFwRules}>
          {t.dash.fwRulesToggle}
        </button>
      </div>
      {#if showFwRules}
        <div class="subcard mono" style="margin-top:8px;padding:10px 12px;font-size:11px;max-height:160px;overflow-y:auto;">
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
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
          <span class="mono" style="font-size:12px;color:var(--info);font-weight:600;">
            ↓ {formatRate(latestNet.rx)} · ↑ {formatRate(latestNet.tx)}
          </span>
          {#if settingsJson && onSaveSettings}
            <button type="button" class="btn btn-xs" onclick={openMonitorSettings}>
              <Icons name="settings" size={12} />
              <span>{lang === 'en' ? 'Monitor Settings' : '监控设置'}</span>
            </button>
          {/if}
        </div>
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
              style="width:100%;height:68px;display:block;touch-action:pan-y;"
              role="img"
              aria-label="CPU usage trend"
              onpointerdown={(e) => {
                const rect = e.currentTarget.getBoundingClientRect();
                const idx = Math.round(((e.clientX - rect.left) / rect.width) * (cpuSpark.pts.length - 1));
                cpuHoverIdx = Math.max(0, Math.min(cpuSpark.pts.length - 1, idx));
              }}
              onpointermove={(e) => {
                const rect = e.currentTarget.getBoundingClientRect();
                const idx = Math.round(((e.clientX - rect.left) / rect.width) * (cpuSpark.pts.length - 1));
                cpuHoverIdx = Math.max(0, Math.min(cpuSpark.pts.length - 1, idx));
              }}
              onpointerleave={() => cpuHoverIdx = -1}
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
              <text x="2" y="13" fill="var(--text-muted)" font-size="9">100%</text>
              <text x="2" y="68" fill="var(--text-muted)" font-size="9">0%</text>
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
            <span>{t.dash.throughputLabel}</span>
            <span class="mono" style="color:var(--info);font-weight:600;">
              {netHoverIdx >= 0 && netHistory[netHoverIdx]
                ? `↓ ${formatRate(netHistory[netHoverIdx].rx)} · ↑ ${formatRate(netHistory[netHoverIdx].tx)}`
                : formatRate(latestNet.total)}
              {#if netSpark}
                <span style="color:var(--text-muted);font-weight:400;"> · max {formatRate(netSpark.ceil)}</span>
              {/if}
            </span>
          </div>
          {#if netSpark}
            <svg
              viewBox="0 0 340 74"
              style="width:100%;height:68px;display:block;touch-action:pan-y;"
              role="img"
              aria-label="Network throughput trend"
              onpointerdown={(e) => {
                const rect = e.currentTarget.getBoundingClientRect();
                const idx = Math.round(((e.clientX - rect.left) / rect.width) * (netSpark.pts.length - 1));
                netHoverIdx = Math.max(0, Math.min(netSpark.pts.length - 1, idx));
              }}
              onpointermove={(e) => {
                const rect = e.currentTarget.getBoundingClientRect();
                const idx = Math.round(((e.clientX - rect.left) / rect.width) * (netSpark.pts.length - 1));
                netHoverIdx = Math.max(0, Math.min(netSpark.pts.length - 1, idx));
              }}
              onpointerleave={() => netHoverIdx = -1}
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
              <text x="2" y="13" fill="var(--text-muted)" font-size="9">{formatRate(netSpark.ceil)}</text>
              <text x="2" y="68" fill="var(--text-muted)" font-size="9">0</text>
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
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(186px,1fr));gap:8px;">
        {#each Object.entries(dashboard.module_health || {}) as [modName, h] (modName)}
          {@const b = healthBadge(h)}
          {@const canJump = h?.state !== 'disabled' && t.nav[modName]}
          <button
            type="button"
            class="subcard {canJump ? 'clickable-card' : ''}"
            style="padding:10px 12px;text-align:left;width:100%;font-family:inherit;color:inherit;"
            disabled={!canJump}
            onclick={() => canJump && onNavigate?.(modName)}
          >
            <div class="row-between" style="gap:8px;">
              <span style="display:inline-flex;align-items:center;gap:8px;font-size:13px;font-weight:600;min-width:0;">
                <span class="icon-tile sm {b.dot === 'ok' ? '' : b.dot === 'warn' ? 'warn' : b.dot === 'danger' ? 'danger' : 'muted'}">
                  <Icons name={modName} size={14} />
                </span>
                <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{t.nav[modName] || modName}</span>
              </span>
              <span class="badge {b.cls}" style="font-size:10.5px;padding:1.5px 7px;">{b.text}</span>
            </div>
            {#if h?.last_error || h?.reason}
              <div class="mono" style="font-size:11px;color:var(--warn);margin-top:6px;word-break:break-all;">
                {h.last_error || h.reason}
              </div>
            {/if}
          </button>
        {/each}
      </div>
    </div>
  </div>

  <!-- 双栈网络接口 + 业务运行摘要 -->
  <div class="bento-grid-2">
    <div class="card">
      <div class="card-header">
        <span class="card-title">{t.dash.ifaceTitle}</span>
        <div class="btn-group">
          <span class="badge badge-info">{dashboard.system.interfaces.length}</span>
          {#if settingsJson && onSaveSettings}
            <button type="button" class="btn btn-xs" onclick={openMonitorSettings}>
              <Icons name="settings" size={12} />
              <span>{lang === 'en' ? 'Select NICs' : '选择网卡'}</span>
            </button>
          {/if}
        </div>
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
                    <button type="button" class="btn btn-xs mono ip-copy-btn" style="color:var(--info);" onclick={() => handleCopy(ip6)}>
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
        {#each dashboard.reverse_proxy_status || [] as rp (rp.name)}
          {@const famLabel = [rp.bound_v4 ? 'v4' : '', rp.bound_v6 ? 'v6' : ''].filter(Boolean).join('+')}
          <div class="subcard row-between clickable-card" role="button" tabindex="0" onclick={() => onNavigate?.('reverse_proxy')} onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onNavigate?.('reverse_proxy'); } }}>
            <div style="min-width:0;flex:1;">
              <div style="font-weight:600;font-size:13px;word-break:break-word;">{t.nav.reverse_proxy} · {rp.name}</div>
              <div class="mono" style="font-size:11px;color:var(--text-secondary);">
                :{rp.listen_port}{famLabel ? ` (${famLabel})` : ''} · conns={rp.active_conns}
              </div>
            </div>
            <span class="badge {rp.status === 'running' ? 'badge-ok' : rp.status === 'failed' ? 'badge-danger' : 'badge-muted'}">{translateRuntimeStatus(rp.status, t)}</span>
          </div>
        {/each}
        {#each dashboard.port_forward_status || [] as pf (pf.name)}
          <div class="subcard row-between clickable-card" role="button" tabindex="0" onclick={() => onNavigate?.('port_forward')} onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onNavigate?.('port_forward'); } }}>
            <div style="min-width:0;flex:1;">
              <div style="font-weight:600;font-size:13px;word-break:break-word;">{t.nav.port_forward} · {pf.name}</div>
              <div class="mono" style="font-size:11px;color:var(--text-secondary);">
                :{pf.listen_port}/{pf.proto} · conns={pf.active_conns}
              </div>
            </div>
            <span class="badge {pf.status === 'running' ? 'badge-ok' : pf.status === 'failed' ? 'badge-danger' : 'badge-warn'}">{translateRuntimeStatus(pf.status, t)}</span>
          </div>
        {/each}
        {#each dashboard.ddns || [] as d (d.name || d.domain)}
          <div class="subcard row-between clickable-card" role="button" tabindex="0" onclick={() => onNavigate?.('ddns')} onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onNavigate?.('ddns'); } }}>
            <div style="min-width:0;flex:1;">
              <div style="font-weight:600;font-size:13px;word-break:break-word;">DDNS · {d.domain}</div>
              <div class="mono" style="font-size:11px;color:var(--text-secondary);word-break:break-all;">
                v4: {d.last_ipv4 || '—'} · v6: {d.last_ipv6 || '—'}
              </div>
            </div>
            <span class="badge {d.status === 'synced' ? 'badge-ok' : d.status === 'failed' ? 'badge-danger' : 'badge-warn'}">{translateRuntimeStatus(d.status, t)}</span>
          </div>
        {/each}
        {#each dashboard.certs || [] as c (c.domain)}
          {@const days = certExpiryDays(c.expires_at_unix)}
          <div class="subcard row-between clickable-card" role="button" tabindex="0" onclick={() => onNavigate?.('acme')} onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onNavigate?.('acme'); } }}>
            <div style="min-width:0;flex:1;">
              <div style="font-weight:600;font-size:13px;word-break:break-word;">TLS · {c.domain}</div>
              <div class="mono" style="font-size:11px;color:var(--text-secondary);">
                {t.dash.expires}: {c.expires_at_unix ? new Date(c.expires_at_unix * 1000).toLocaleDateString() : '—'}
                {#if days !== null} ({days}d){/if}
              </div>
            </div>
            <span class="badge {c.status === 'failed' || (days !== null && days <= 0) ? 'badge-danger' : c.status === 'active' && (days === null || days > 14) ? 'badge-ok' : 'badge-warn'}">
              {translateRuntimeStatus(c.status, t)}
            </span>
          </div>
        {/each}
        {#each Object.entries(dashboard.stun_public_addrs || {}) as [name, pubAddr] (name)}
          <div class="subcard row-between">
            <div style="min-width:0;flex:1;">
              <div style="font-weight:600;font-size:13px;">STUN · {name}</div>
              <div class="mono" style="font-size:12px;color:var(--info);word-break:break-all;">{pubAddr}</div>
            </div>
            <button type="button" class="btn btn-xs" onclick={() => handleCopy(pubAddr)}>{t.copy}</button>
          </div>
        {/each}
        {#each dashboard.cron || [] as cj (cj.name)}
          <div class="subcard row-between clickable-card" role="button" tabindex="0" onclick={() => onNavigate?.('cron')} onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onNavigate?.('cron'); } }}>
            <div style="min-width:0;flex:1;">
              <div style="font-weight:600;font-size:13px;word-break:break-word;">{t.dash.cronSummary} · {cj.name}</div>
              <div class="mono" style="font-size:11px;color:var(--text-secondary);">
                {cj.last_duration_ms ? `${cj.last_duration_ms}ms` : '—'}
              </div>
            </div>
            <span class="badge {cj.running ? 'badge-info' : cj.status === 'ok' ? 'badge-ok' : cj.status === 'failed' ? 'badge-danger' : 'badge-muted'}">
              {cj.running ? t.common.statusRunning : translateRuntimeStatus(cj.status, t)}
            </span>
          </div>
        {/each}
        {#if !(dashboard.reverse_proxy_status?.length || dashboard.port_forward_status?.length || dashboard.ddns?.length || dashboard.certs?.length || dashboard.cron?.length || Object.keys(dashboard.stun_public_addrs || {}).length)}
          <div class="empty-state" style="padding:20px;">
            {lang === 'en' ? 'No active gateway rules or runtime tasks yet.' : '暂未配置活跃的代理、转发、DDNS、证书、STUN 或计划任务'}
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
          {#each dashboard.bans as ban (`${ban.scope || 'admin'}:${ban.cidr}`)}
            {@const banScope = ban.scope || 'admin'}
            {@const banKey = `${banScope}:${ban.cidr}`}
            <div class="subcard row-between">
              <div style="min-width:0;flex:1;">
                <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
                  <span class="mono" style="font-weight:700;color:var(--danger);word-break:break-all;">{ban.cidr}</span>
                  {#if ban.scope && ban.scope !== 'admin'}
                    <span class="badge badge-muted mono" style="font-size:10px;padding:1px 6px;">{ban.scope}</span>
                  {/if}
                </div>
                <div class="mono" style="font-size:11px;color:var(--text-secondary);">
                  {ban.reason} · fails={ban.failures} · {formatDurationSecs(ban.remaining_secs)}
                </div>
              </div>
              <button type="button" class="btn btn-sm" disabled={unbanBusy === banKey} onclick={() => unbanCidr(ban.cidr, banScope)}>
                {unbanBusy === banKey ? '...' : t.dash.unban}
              </button>
            </div>
          {/each}
        </div>
      {/if}
    </div>

    <div class="card">
      <div class="card-header"><span class="card-title">{t.dash.procTitle}</span></div>
      {#if !dashboard.system.top_processes?.length}
        <div class="empty-state" style="padding:20px;">—</div>
      {:else}
        {@const maxProcKb = Math.max(1, ...dashboard.system.top_processes.map((p) => Number(p.vm_rss_kb || 0)))}
        <div class="arcane-table-wrap">
          <table class="arcane-table">
            <thead>
              <tr>
                <th>PID</th>
                <th>{lang === 'en' ? 'Process' : '进程'}</th>
                <th>{lang === 'en' ? 'Memory' : '内存'}</th>
              </tr>
            </thead>
            <tbody>
              {#each dashboard.system.top_processes as proc}
                {@const pct = Math.min(100, (Number(proc.vm_rss_kb || 0) / maxProcKb) * 100)}
                <tr>
                  <td class="mono" style="color:var(--text-muted);width:68px;">#{proc.pid}</td>
                  <td>
                    <div style="font-weight:500;font-size:13px;">{proc.name}</div>
                    <div class="progress-bar" style="height:3px;margin:4px 0 0;max-width:160px;">
                      <div class="progress-fill" style="width:{pct}%;"></div>
                    </div>
                  </td>
                  <td class="mono" style="font-weight:600;white-space:nowrap;">{formatKB(proc.vm_rss_kb)}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </div>
  </div>
{/if}

<!-- 仪表盘监控与告警设置弹窗 -->
<EditorDialog
  open={monSettingsOpen}
  title={t.cfg.groupMonitor}
  size="md"
  busy={monSettingsSaving}
  {t}
  {askConfirm}
  onSubmit={saveMonitorSettings}
  onClose={() => (monSettingsOpen = false)}
>
  <div class="field">
    <label for="dash-mon-if">{t.cfg.lblMonIfaces}</label>
    <ComboInput id="dash-mon-if" multiple placeholder="pppoe-wan, br-lan" options={ifaceOptions} bind:value={monIfacesCsv} />
    <div class="field-hint">{t.cfg.descMonIfaces}</div>
  </div>
  <div class="form-grid">
    <div class="field">
      <label for="dash-mon-iv">{t.cfg.monInterval}</label>
      <input id="dash-mon-iv" type="number" min="1" max="60" bind:value={monIntervalDraft} required />
    </div>
    <div class="field">
      <label for="dash-mon-tp">{t.cfg.topProcs}</label>
      <input id="dash-mon-tp" type="number" min="1" max="50" bind:value={monTopProcsDraft} required />
    </div>
    <div class="field">
      <label for="dash-mon-tmp">{t.cfg.lblTempAlert}</label>
      <input id="dash-mon-tmp" type="number" min="40" max="125" bind:value={monTempDraft} required />
    </div>
    <div class="field">
      <label for="dash-mon-mem">{t.cfg.lblMemLow}</label>
      <input id="dash-mon-mem" type="number" min="0" max="4096" bind:value={monMemDraft} required />
    </div>
    <div class="field">
      <label for="dash-mon-cd">{t.cfg.alertCooldown}</label>
      <input id="dash-mon-cd" type="number" min="60" max="86400" bind:value={monCooldownDraft} required />
    </div>
    <div class="field">
      <label for="dash-mon-th">{t.cfg.thermalPath}</label>
      <input id="dash-mon-th" type="text" class="mono" placeholder="/sys/class/thermal/thermal_zone0/temp" bind:value={monThermalDraft} />
    </div>
  </div>
</EditorDialog>
