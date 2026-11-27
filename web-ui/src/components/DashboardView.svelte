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

  let fwPanelEl = $state(null);

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

  function buildSpark(values, minCeil, width = 300, height = 72) {
    if (!values || values.length < 2) return null;
    const ceil = Math.max(minCeil, ...values, 1);
    const padY = 6;
    const usableH = height - padY * 2;
    const pts = values.map((v, idx) => {
      const ratio = idx / (values.length - 1);
      const x = ratio * width;
      const y = height - padY - Math.min(1, Math.max(0, v / ceil)) * usableH;
      return { x, y, xPct: ratio * 100, yPct: (y / height) * 100, val: v };
    });
    const linePath = pts.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');
    const areaPath = `${linePath} L${width.toFixed(1)},${height.toFixed(1)} L0,${height.toFixed(1)} Z`;
    return { linePath, areaPath, pts, ceil, last: pts[pts.length - 1] };
  }

  function pickSparkIdx(e, len) {
    if (!len || len < 2) return -1;
    const rect = e.currentTarget.getBoundingClientRect();
    const ratio = Math.max(0, Math.min(1, (e.clientX - rect.left) / Math.max(1, rect.width)));
    return Math.round(ratio * (len - 1));
  }

  function barTone(pct) {
    if (pct >= 90) return 'danger';
    if (pct >= 70) return 'warn';
    return '';
  }

  function toggleFwRulesPanel(scrollToPanel = false) {
    showFwRules = !showFwRules;
    if (showFwRules && scrollToPanel) {
      queueMicrotask(() => {
        fwPanelEl?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      });
    }
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

  function parseFwRule(rule) {
    if (rule.kind === 'wan_input') {
      const fams = [rule.ipv4 ? 'v4' : '', rule.ipv6 ? 'v6' : ''].filter(Boolean).join('+');
      return {
        tag: 'WAN',
        tone: 'badge-warn',
        owner: `${rule.owner_module} · ${rule.rule_name}`,
        spec: `${rule.proto}/${rule.port}${fams ? ` (${fams})` : ''}`,
        raw: `${rule.owner_module} · ${rule.rule_name} (${rule.proto}/${rule.port} ${fams})`,
      };
    }
    if (rule.kind === 'kernel_dnat') {
      return {
        tag: 'DNAT',
        tone: 'badge-info',
        owner: `${rule.owner_module} · ${rule.rule_name}`,
        spec: `${rule.proto}/${rule.listen_port} → ${rule.target}`,
        raw: `${rule.owner_module} · ${rule.rule_name} (DNAT ${rule.proto}/${rule.listen_port} → ${rule.target})`,
      };
    }
    if (rule.kind === 'sub_device_ipv6_forward') {
      const ports = [
        rule.tcp_ports?.length ? `TCP:${rule.tcp_ports.join(',')}` : '',
        rule.udp_ports?.length ? `UDP:${rule.udp_ports.join(',')}` : '',
      ]
        .filter(Boolean)
        .join(' ');
      return {
        tag: 'v6 FWD',
        tone: 'badge-ok',
        owner: `${rule.owner_module} · ${rule.rule_name}`,
        spec: `${rule.device_ip}${ports ? ` · ${ports}` : ''}`,
        raw: `${rule.owner_module} · ${rule.rule_name} (${rule.device_ip} ${ports})`,
      };
    }
    const raw = JSON.stringify(rule);
    return { tag: rule.kind || 'RULE', tone: 'badge-muted', owner: rule.owner_module || 'vane', spec: raw, raw };
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
  let totalMemKb = $derived(Math.max(1, Number(dashboard?.system?.memory?.total_kb || 0)));

  let quickStatusTotal = $derived(
    (dashboard?.reverse_proxy_status?.length || 0) +
      (dashboard?.port_forward_status?.length || 0) +
      (dashboard?.ddns?.length || 0) +
      (dashboard?.certs?.length || 0) +
      Object.keys(dashboard?.stun_public_addrs || {}).length +
      (dashboard?.cron?.length || 0)
  );

  // StatStrip 概览统计
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
  <div class="stat-strip-card" aria-busy="true" aria-label={t.common.loading}>
    <div class="stat-strip-grid dash-stat-grid">
      {#each [1, 2, 3, 4] as _}
        <div class="stat-strip-cell dash-stat-cell" style="cursor:default;">
          <div class="skeleton" style="width:62%;height:12px;"></div>
          <div class="skeleton" style="width:44%;height:26px;margin:8px 0;"></div>
          <div class="skeleton" style="width:74px;height:4px;margin-bottom:6px;"></div>
          <div class="skeleton" style="width:48%;height:11px;"></div>
        </div>
      {/each}
    </div>
  </div>
  <div class="bento-grid">
    {#each [1, 2, 3] as _}
      <div class="card">
        <div class="row-between" style="margin-bottom:14px;">
          <div class="skeleton" style="width:46%;height:16px;"></div>
          <div class="skeleton" style="width:62px;height:20px;border-radius:999px;"></div>
        </div>
        <div class="dash-kpi-row">
          <div style="flex:1;">
            <div class="skeleton" style="width:58%;height:28px;margin-bottom:10px;"></div>
            <div class="skeleton" style="width:82%;height:12px;margin-bottom:6px;"></div>
            <div class="skeleton" style="width:64%;height:12px;"></div>
          </div>
          <div class="skeleton" style="width:58px;height:58px;border-radius:999px;flex-shrink:0;"></div>
        </div>
      </div>
    {/each}
  </div>
  <div class="bento-grid-2">
    <div class="card">
      <div class="skeleton" style="width:40%;height:16px;margin-bottom:14px;"></div>
      <div class="skeleton" style="width:100%;height:96px;border-radius:14px;margin-bottom:10px;"></div>
      <div class="skeleton" style="width:100%;height:96px;border-radius:14px;"></div>
    </div>
    <div class="card">
      <div class="skeleton" style="width:40%;height:16px;margin-bottom:14px;"></div>
      <div class="dash-health-grid">
        {#each [1, 2, 3, 4, 5, 6] as _}
          <div class="skeleton" style="width:100%;height:56px;border-radius:14px;"></div>
        {/each}
      </div>
    </div>
  </div>
{:else}
  <!-- Arcane StatStrip 顶部聚合指标带 -->
  <div class="stat-strip-card">
    <div class="stat-strip-grid dash-stat-grid">
      <button type="button" class="stat-strip-cell dash-stat-cell" onclick={() => onNavigate?.('settings')}>
        <span class="stat-strip-label">
          <Icons name="grid" size={13} />
          <span>{t.dash?.activeModules || (lang === 'en' ? 'Active Modules' : '子模块健康')}</span>
        </span>
        <span class="stat-strip-val num">
          {stripStats.modRun}<span class="dash-stat-denom">/{stripStats.modTotal}</span>
        </span>
        <span class="stat-strip-bar" aria-hidden="true">
          {#if stripStats.modRun > 0}<span class="stat-strip-seg" style={`flex:${stripStats.modRun};background:var(--accent);`}></span>{/if}
          {#if stripStats.modWarn > 0}<span class="stat-strip-seg" style={`flex:${stripStats.modWarn};background:var(--warn);`}></span>{/if}
          {#if stripStats.modErr > 0}<span class="stat-strip-seg" style={`flex:${stripStats.modErr};background:var(--danger);`}></span>{/if}
        </span>
        <span class="stat-strip-sub num">{stripStats.modErr > 0 ? `${stripStats.modErr} ${t.dash.circuitOpen}` : `${stripStats.modRun} ${t.common.statusRunning}`}</span>
      </button>

      <button type="button" class="stat-strip-cell dash-stat-cell" onclick={() => onNavigate?.('reverse_proxy')}>
        <span class="stat-strip-label">
          <Icons name="reverse_proxy" size={13} />
          <span>{t.navGroups.traffic}</span>
        </span>
        <span class="stat-strip-val num">{stripStats.trafficTotal}</span>
        <span class="stat-strip-bar" aria-hidden="true">
          {#if stripStats.trafficRun > 0}<span class="stat-strip-seg" style={`flex:${stripStats.trafficRun};background:var(--accent);`}></span>{/if}
          {#if stripStats.trafficErr > 0}<span class="stat-strip-seg" style={`flex:${stripStats.trafficErr};background:var(--danger);`}></span>{/if}
          {#if stripStats.trafficTotal - stripStats.trafficRun - stripStats.trafficErr > 0}<span class="stat-strip-seg" style={`flex:${stripStats.trafficTotal - stripStats.trafficRun - stripStats.trafficErr};background:var(--text-muted);opacity:0.4;`}></span>{/if}
        </span>
        <span class="stat-strip-sub num">{stripStats.trafficRun} {t.common.statusRunning}</span>
      </button>

      <button type="button" class="stat-strip-cell dash-stat-cell" onclick={() => onNavigate?.('ddns')}>
        <span class="stat-strip-label">
          <Icons name="ddns" size={13} />
          <span>{t.navGroups.domain}</span>
        </span>
        <span class="stat-strip-val num">{stripStats.domTotal}</span>
        <span class="stat-strip-bar" aria-hidden="true">
          {#if stripStats.domOk > 0}<span class="stat-strip-seg" style={`flex:${stripStats.domOk};background:var(--info);`}></span>{/if}
          {#if stripStats.domErr > 0}<span class="stat-strip-seg" style={`flex:${stripStats.domErr};background:var(--danger);`}></span>{/if}
          {#if stripStats.domTotal - stripStats.domOk - stripStats.domErr > 0}<span class="stat-strip-seg" style={`flex:${stripStats.domTotal - stripStats.domOk - stripStats.domErr};background:var(--warn);`}></span>{/if}
        </span>
        <span class="stat-strip-sub num">{stripStats.domOk} {lang === 'en' ? 'healthy' : '正常同步'}</span>
      </button>

      <button
        type="button"
        class="stat-strip-cell dash-stat-cell {showFwRules ? 'is-active' : ''}"
        aria-pressed={showFwRules}
        onclick={() => toggleFwRulesPanel(true)}
      >
        <span class="stat-strip-label">
          <Icons name="shield" size={13} />
          <span>{t.dash.wanRules} / {t.dash.activeBans}</span>
        </span>
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

  <!-- 核心硬件与配额指标 3 列卡片 -->
  <div class="bento-grid">
    <!-- SoC CPU & 温度 -->
    <div class="card dash-kpi-card">
      <div class="card-header">
        <span class="card-title">
          <span class="icon-tile sm info"><Icons name="activity" size={14} /></span>
          <span>{t.dash.socTitle}</span>
        </span>
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
      <div class="dash-kpi-row">
        <div class="dash-kpi-body">
          <div class="num dash-kpi-num">{dashboard.system.cpu_usage_percent.toFixed(1)}%</div>
          <div class="mono dash-kpi-meta">
            {t.dash.load}: {dashboard.system.load_avg.map((v) => v.toFixed(2)).join(' / ')}
          </div>
          <div class="mono dash-kpi-meta muted">
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
        <div class="dash-card-foot">
          <div class="dash-cores-grid">
            {#each dashboard.system.cpu_cores_percent as pct, idx}
              <div class="dash-core-item">
                <div class="dash-core-head mono">
                  <span class="dash-core-id">C{idx}</span>
                  <span>{pct.toFixed(0)}%</span>
                </div>
                <div class="progress-bar" style="height:4px;margin:3px 0 0;">
                  <div class="progress-fill {barTone(pct)}" style="width:{Math.min(100, pct)}%"></div>
                </div>
              </div>
            {/each}
          </div>
        </div>
      {/if}
    </div>

    <!-- 物理内存与 Swap / Slab SUnreclaim -->
    <div class="card dash-kpi-card">
      <div class="card-header">
        <span class="card-title">
          <span class="icon-tile sm"><Icons name="database" size={14} /></span>
          <span>{t.dash.memTitle}</span>
        </span>
        <span class="badge {availBadgeClass} num">{t.dash.avail} {formatKB(dashboard.system.memory.available_kb)}</span>
      </div>
      <div class="dash-kpi-row">
        <div class="dash-kpi-body">
          <div class="num dash-kpi-num">
            <span>{formatKB(dashboard.system.memory.used_kb)}</span>
            <span class="dash-kpi-denom">/ {formatKB(dashboard.system.memory.total_kb)}</span>
          </div>
          <div class="mono dash-kpi-meta">
            {t.dash.cached}: {formatKB(dashboard.system.memory.cached_kb)}
          </div>
          <div class="mono dash-kpi-meta muted">
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
        <div class="dash-card-foot">
          <div class="row-between mono" style="font-size:11px;color:var(--text-secondary);">
            <span>{t.dash.swap}</span>
            <span>{formatKB(swapUsedKb)} / {formatKB(dashboard.system.memory.swap_total_kb)}</span>
          </div>
          <div class="progress-bar" style="height:5px;margin:5px 0 0;">
            <div class="progress-fill {barTone(swapPct)}" style="width:{swapPct}%"></div>
          </div>
        </div>
      {/if}
    </div>

    <!-- 防火墙与全局连接配额 -->
    <div class="card dash-kpi-card">
      <div class="card-header">
        <span class="card-title">
          <span class="icon-tile sm {dashboard.firewall.lockdown ? 'danger' : dashboard.firewall.degraded ? 'warn' : ''}">
            <Icons name="shield" size={14} />
          </span>
          <span>{t.dash.fwTitle}</span>
        </span>
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
        <div class="inline-alert inline-alert-warn" role="alert" style="margin-bottom:10px;">
          <Icons name="alert" size={14} />
          <span>{t.dash.fwDegradedBanner}</span>
        </div>
      {/if}
      <div class="dash-kpi-row">
        <div class="dash-kpi-body">
          <div class="num dash-kpi-num">
            <span>{dashboard.active_connections}</span>
            <span class="dash-kpi-denom">/ {dashboard.max_connections}</span>
          </div>
          <div class="mono dash-kpi-meta">
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
      <div class="dash-card-foot">
        <button
          type="button"
          class="dash-fw-toggle"
          aria-expanded={showFwRules}
          onclick={() => toggleFwRulesPanel(false)}
        >
          <span class="dash-fw-toggle-left">
            <span>{showFwRules ? (t.dash?.hideFwRules || t.dash.fwRulesToggle) : t.dash.fwRulesToggle}</span>
            <span class="badge badge-muted num">{dashboard.firewall.rules.length}</span>
          </span>
          <span class="dash-fw-chevron {showFwRules ? 'open' : ''}">
            <Icons name="chevron" size={14} />
          </span>
        </button>
      </div>
    </div>
  </div>

  <!-- 展开的托管防火墙规则面板（独立全宽卡片，避免撑坏上方 3 列高度） -->
  {#if showFwRules}
    <div bind:this={fwPanelEl} class="card dash-fw-panel">
      <div class="card-header" style="margin-bottom:10px;">
        <span class="card-title">
          <span class="icon-tile sm"><Icons name="shield" size={14} /></span>
          <span>{t.dash.fwRulesToggle}</span>
          <span class="badge badge-muted num">{dashboard.firewall.rules.length}</span>
        </span>
        <button
          type="button"
          class="btn btn-xs btn-ghost"
          aria-label={t.common?.collapse || t.close}
          onclick={() => (showFwRules = false)}
        >
          <Icons name="x" size={14} />
          <span>{t.common?.collapse || t.close}</span>
        </button>
      </div>
      {#if !dashboard.firewall.rules.length}
        <div class="empty-state-rich" style="padding:18px;">
          <div class="empty-state-desc">{t.dash.noFwRules}</div>
        </div>
      {:else}
        <div class="dash-fw-list">
          {#each dashboard.firewall.rules as r}
            {@const parsed = parseFwRule(r)}
            <div class="subcard dash-fw-row">
              <div class="dash-fw-row-main">
                <span class="badge {parsed.tone} mono">{parsed.tag}</span>
                <span class="dash-fw-owner">{parsed.owner}</span>
                <span class="mono dash-fw-spec">{parsed.spec}</span>
              </div>
              <button
                type="button"
                class="btn btn-xs btn-ghost btn-icon"
                title={t.copy}
                aria-label={`${t.copy}: ${parsed.raw}`}
                onclick={() => handleCopy(parsed.raw)}
              >
                <Icons name="copy" size={13} />
              </button>
            </div>
          {/each}
        </div>
      {/if}
    </div>
  {/if}

  <!-- 实时 SVG 面积趋势曲线 + 舱壁健康度 -->
  <div class="bento-grid-2">
    <div class="card">
      <div class="card-header">
        <div style="min-width:0;">
          <span class="card-title">
            <span class="icon-tile sm info"><Icons name="activity" size={14} /></span>
            <span>{t.dash.trendTitle}</span>
          </span>
          <div class="dash-card-sub">
            {t.dash.trendHint} ({Math.round(pollIntervalMs / 1000)}s)
          </div>
        </div>
        <div class="btn-group">
          <span class="mono dash-net-pill">
            <span style="color:var(--accent);">↓ {formatRate(latestNet.rx)}</span>
            <span class="dash-sep">·</span>
            <span style="color:var(--info);">↑ {formatRate(latestNet.tx)}</span>
          </span>
          {#if settingsJson && onSaveSettings}
            <button type="button" class="btn btn-xs" onclick={openMonitorSettings}>
              <Icons name="settings" size={12} />
              <span>{t.dash?.monitorSettings || (lang === 'en' ? 'Monitor Settings' : '监控设置')}</span>
            </button>
          {/if}
        </div>
      </div>
      <div style="display:grid;gap:10px;">
        <!-- CPU Sparkline -->
        <div class="subcard spark-card">
          <div class="spark-head">
            <span class="spark-label">CPU (%)</span>
            <div class="spark-val-group mono">
              <span style="color:var(--accent);font-weight:700;">
                {cpuHoverIdx >= 0 && cpuSpark?.pts[cpuHoverIdx]
                  ? `${cpuSpark.pts[cpuHoverIdx].val.toFixed(1)}%`
                  : `${dashboard.system.cpu_usage_percent.toFixed(1)}%`}
              </span>
              <span class="spark-scale">0–100%</span>
            </div>
          </div>
          {#if cpuSpark}
            <div
              class="spark-canvas"
              role="img"
              aria-label="CPU usage trend"
              onpointerdown={(e) => (cpuHoverIdx = pickSparkIdx(e, cpuSpark.pts.length))}
              onpointermove={(e) => (cpuHoverIdx = pickSparkIdx(e, cpuSpark.pts.length))}
              onpointerleave={() => (cpuHoverIdx = -1)}
              onpointercancel={() => (cpuHoverIdx = -1)}
            >
              <svg viewBox="0 0 300 72" preserveAspectRatio="none" class="spark-svg" aria-hidden="true">
                <defs>
                  <linearGradient id="cpuAreaGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stop-color="var(--accent)" stop-opacity="0.32" />
                    <stop offset="100%" stop-color="var(--accent)" stop-opacity="0.02" />
                  </linearGradient>
                </defs>
                {#each [24, 48] as gy}
                  <line x1="0" y1={gy} x2="300" y2={gy} stroke="var(--border-subtle)" stroke-dasharray="3 3" vector-effect="non-scaling-stroke" />
                {/each}
                <path d={cpuSpark.areaPath} fill="url(#cpuAreaGrad)" />
                <path d={cpuSpark.linePath} fill="none" stroke="var(--accent)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" vector-effect="non-scaling-stroke" />
              </svg>
              {#if cpuHoverIdx >= 0 && cpuSpark.pts[cpuHoverIdx]}
                {@const p = cpuSpark.pts[cpuHoverIdx]}
                <span class="spark-crosshair" style={`left:${p.xPct.toFixed(2)}%;`}></span>
                <span class="spark-dot accent" style={`left:${p.xPct.toFixed(2)}%;top:${p.yPct.toFixed(2)}%;`}></span>
              {:else if cpuSpark.last}
                <span class="spark-dot accent latest" style={`left:100%;top:${cpuSpark.last.yPct.toFixed(2)}%;`}></span>
              {/if}
            </div>
          {:else}
            <div class="spark-empty">{t.dash.collecting}</div>
          {/if}
        </div>

        <!-- Throughput Sparkline -->
        <div class="subcard spark-card">
          <div class="spark-head">
            <span class="spark-label">{t.dash.throughputLabel}</span>
            <div class="spark-val-group mono">
              <span style="color:var(--info);font-weight:700;">
                {netHoverIdx >= 0 && netHistory[netHoverIdx]
                  ? `↓ ${formatRate(netHistory[netHoverIdx].rx)} · ↑ ${formatRate(netHistory[netHoverIdx].tx)}`
                  : formatRate(latestNet.total)}
              </span>
              {#if netSpark}
                <span class="spark-scale">max {formatRate(netSpark.ceil)}</span>
              {/if}
            </div>
          </div>
          {#if netSpark}
            <div
              class="spark-canvas"
              role="img"
              aria-label="Network throughput trend"
              onpointerdown={(e) => (netHoverIdx = pickSparkIdx(e, netSpark.pts.length))}
              onpointermove={(e) => (netHoverIdx = pickSparkIdx(e, netSpark.pts.length))}
              onpointerleave={() => (netHoverIdx = -1)}
              onpointercancel={() => (netHoverIdx = -1)}
            >
              <svg viewBox="0 0 300 72" preserveAspectRatio="none" class="spark-svg" aria-hidden="true">
                <defs>
                  <linearGradient id="netAreaGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stop-color="var(--info)" stop-opacity="0.32" />
                    <stop offset="100%" stop-color="var(--info)" stop-opacity="0.02" />
                  </linearGradient>
                </defs>
                {#each [24, 48] as gy}
                  <line x1="0" y1={gy} x2="300" y2={gy} stroke="var(--border-subtle)" stroke-dasharray="3 3" vector-effect="non-scaling-stroke" />
                {/each}
                <path d={netSpark.areaPath} fill="url(#netAreaGrad)" />
                <path d={netSpark.linePath} fill="none" stroke="var(--info)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" vector-effect="non-scaling-stroke" />
              </svg>
              {#if netHoverIdx >= 0 && netSpark.pts[netHoverIdx]}
                {@const p = netSpark.pts[netHoverIdx]}
                <span class="spark-crosshair" style={`left:${p.xPct.toFixed(2)}%;`}></span>
                <span class="spark-dot info" style={`left:${p.xPct.toFixed(2)}%;top:${p.yPct.toFixed(2)}%;`}></span>
              {:else if netSpark.last}
                <span class="spark-dot info latest" style={`left:100%;top:${netSpark.last.yPct.toFixed(2)}%;`}></span>
              {/if}
            </div>
          {:else}
            <div class="spark-empty">{t.dash.collecting}</div>
          {/if}
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <span class="card-title">
          <span class="icon-tile sm"><Icons name="grid" size={14} /></span>
          <span>{t.dash.healthTitle}</span>
        </span>
        <span class="badge badge-muted num">{stripStats.modRun}/{stripStats.modTotal}</span>
      </div>
      <div class="dash-health-grid">
        {#each Object.entries(dashboard.module_health || {}) as [modName, h] (modName)}
          {@const b = healthBadge(h)}
          {@const canJump = h?.state !== 'disabled' && Boolean(t.nav[modName])}
          {@const errText = h?.last_error || h?.reason || ''}
          <button
            type="button"
            class="subcard dash-mod-tile {canJump ? 'clickable-card' : 'is-disabled'}"
            disabled={!canJump}
            title={errText || (t.nav[modName] || modName)}
            onclick={() => canJump && onNavigate?.(modName)}
          >
            <div class="dash-mod-top">
              <span class="dash-mod-name-wrap">
                <span class="icon-tile sm {b.dot === 'ok' ? '' : b.dot === 'warn' ? 'warn' : b.dot === 'danger' ? 'danger' : 'muted'}">
                  <Icons name={modName} size={14} />
                </span>
                <span class="dash-mod-name">{t.nav[modName] || modName}</span>
              </span>
              <span class="badge {b.cls} dash-mod-badge">{b.text}</span>
            </div>
            {#if errText}
              <div class="mono dash-mod-err {b.dot === 'danger' ? 'is-danger' : 'is-warn'}">
                {errText}
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
        <span class="card-title">
          <span class="icon-tile sm info"><Icons name="monitor" size={14} /></span>
          <span>{t.dash.ifaceTitle}</span>
        </span>
        <div class="btn-group">
          <span class="badge badge-info num">{dashboard.system.interfaces.length}</span>
          {#if settingsJson && onSaveSettings}
            <button type="button" class="btn btn-xs" onclick={openMonitorSettings}>
              <Icons name="settings" size={12} />
              <span>{t.dash?.selectNics || (lang === 'en' ? 'Select NICs' : '选择网卡')}</span>
            </button>
          {/if}
        </div>
      </div>
      {#if !dashboard.system.interfaces.length}
        <div class="empty-state-rich" style="padding:22px 16px;">
          <div class="icon-tile muted empty-state-icon"><Icons name="monitor" size={16} /></div>
          <div class="empty-state-desc">{t.dash.noIfaces}</div>
        </div>
      {:else}
        <div style="display:grid;gap:10px;">
          {#each dashboard.system.interfaces as iface}
            <div class="subcard dash-iface-card">
              <div class="dash-iface-head">
                <span class="mono dash-iface-name">{iface.iface}</span>
                <div class="dash-iface-rates mono">
                  <span class="dash-rate-item">
                    <span style="color:var(--accent);font-weight:600;">↓ {formatRate(iface.rx_bps)}</span>
                    <span class="dash-rate-total">({formatBytes(iface.rx_bytes)})</span>
                  </span>
                  <span class="dash-rate-item">
                    <span style="color:var(--info);font-weight:600;">↑ {formatRate(iface.tx_bps)}</span>
                    <span class="dash-rate-total">({formatBytes(iface.tx_bytes)})</span>
                  </span>
                </div>
              </div>
              {#if iface.ipv4.length > 0 || iface.ipv6.length > 0}
                <div class="dash-ip-list">
                  {#each iface.ipv4 as ip4}
                    <button
                      type="button"
                      class="copy-pill mono dash-ip-pill v4"
                      title={t.copy}
                      aria-label={`${t.copy} IPv4 ${ip4}`}
                      onclick={() => handleCopy(ip4)}
                    >
                      <span class="dash-ip-tag">v4</span>
                      <span class="break-anywhere">{ip4}</span>
                      <Icons name="copy" size={12} />
                    </button>
                  {/each}
                  {#each iface.ipv6 as ip6}
                    <button
                      type="button"
                      class="copy-pill mono dash-ip-pill v6"
                      title={t.copy}
                      aria-label={`${t.copy} IPv6 ${ip6}`}
                      onclick={() => handleCopy(ip6)}
                    >
                      <span class="dash-ip-tag">v6</span>
                      <span class="break-anywhere">{ip6}</span>
                      <Icons name="copy" size={12} />
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
        <span class="card-title">
          <span class="icon-tile sm"><Icons name="sliders" size={14} /></span>
          <span>{t.dash.quickStatus}</span>
        </span>
        {#if quickStatusTotal > 0}
          <span class="badge badge-muted num">{quickStatusTotal}</span>
        {/if}
      </div>
      {#if !quickStatusTotal}
        <div class="empty-state-rich" style="padding:22px 16px;">
          <div class="icon-tile muted empty-state-icon"><Icons name="sliders" size={16} /></div>
          <div class="empty-state-desc">
            {t.dash?.emptyQuickStatus || (lang === 'en' ? 'No active gateway rules or runtime tasks yet.' : '暂未配置活跃的代理、转发、DDNS、证书、STUN 或计划任务')}
          </div>
        </div>
      {:else}
        <div class="dash-quick-list">
          {#each dashboard.reverse_proxy_status || [] as rp (rp.name)}
            {@const famLabel = [rp.bound_v4 ? 'v4' : '', rp.bound_v6 ? 'v6' : ''].filter(Boolean).join('+')}
            <button type="button" class="subcard clickable-card dash-quick-row" onclick={() => onNavigate?.('reverse_proxy')}>
              <span class="icon-tile sm {rp.status === 'running' ? '' : rp.status === 'failed' ? 'danger' : 'muted'}">
                <Icons name="reverse_proxy" size={14} />
              </span>
              <div class="dash-quick-main">
                <div class="dash-quick-title">{rp.name}</div>
                <div class="mono dash-quick-sub">
                  :{rp.listen_port}{famLabel ? ` (${famLabel})` : ''} · conns={rp.active_conns}
                </div>
              </div>
              <span class="badge {rp.status === 'running' ? 'badge-ok' : rp.status === 'failed' ? 'badge-danger' : 'badge-muted'}">
                {translateRuntimeStatus(rp.status, t)}
              </span>
            </button>
          {/each}
          {#each dashboard.port_forward_status || [] as pf (pf.name)}
            <button type="button" class="subcard clickable-card dash-quick-row" onclick={() => onNavigate?.('port_forward')}>
              <span class="icon-tile sm {pf.status === 'running' ? '' : pf.status === 'failed' ? 'danger' : 'warn'}">
                <Icons name="port_forward" size={14} />
              </span>
              <div class="dash-quick-main">
                <div class="dash-quick-title">{pf.name}</div>
                <div class="mono dash-quick-sub">
                  :{pf.listen_port}/{pf.proto} · conns={pf.active_conns}
                </div>
              </div>
              <span class="badge {pf.status === 'running' ? 'badge-ok' : pf.status === 'failed' ? 'badge-danger' : 'badge-warn'}">
                {translateRuntimeStatus(pf.status, t)}
              </span>
            </button>
          {/each}
          {#each dashboard.ddns || [] as d (d.name || d.domain)}
            <button type="button" class="subcard clickable-card dash-quick-row" onclick={() => onNavigate?.('ddns')}>
              <span class="icon-tile sm {d.status === 'synced' ? '' : d.status === 'failed' ? 'danger' : 'warn'}">
                <Icons name="ddns" size={14} />
              </span>
              <div class="dash-quick-main">
                <div class="dash-quick-title mono">{d.domain}</div>
                <div class="mono dash-quick-sub break-anywhere">
                  v4: {d.last_ipv4 || '—'} · v6: {d.last_ipv6 || '—'}
                </div>
              </div>
              <span class="badge {d.status === 'synced' ? 'badge-ok' : d.status === 'failed' ? 'badge-danger' : 'badge-warn'}">
                {translateRuntimeStatus(d.status, t)}
              </span>
            </button>
          {/each}
          {#each dashboard.certs || [] as c (c.domain)}
            {@const days = certExpiryDays(c.expires_at_unix)}
            <button type="button" class="subcard clickable-card dash-quick-row" onclick={() => onNavigate?.('acme')}>
              <span class="icon-tile sm {c.status === 'failed' || (days !== null && days <= 0) ? 'danger' : c.status === 'active' && (days === null || days > 14) ? '' : 'warn'}">
                <Icons name="acme" size={14} />
              </span>
              <div class="dash-quick-main">
                <div class="dash-quick-title mono">{c.domain}</div>
                <div class="mono dash-quick-sub">
                  {t.dash.expires}: {c.expires_at_unix ? new Date(c.expires_at_unix * 1000).toLocaleDateString() : '—'}
                  {#if days !== null} ({days}d){/if}
                </div>
              </div>
              <span class="badge {c.status === 'failed' || (days !== null && days <= 0) ? 'badge-danger' : c.status === 'active' && (days === null || days > 14) ? 'badge-ok' : 'badge-warn'}">
                {translateRuntimeStatus(c.status, t)}
              </span>
            </button>
          {/each}
          {#each Object.entries(dashboard.stun_public_addrs || {}) as [name, pubAddr] (name)}
            <div class="subcard dash-quick-split">
              <button type="button" class="dash-quick-split-main" onclick={() => onNavigate?.('stun')}>
                <span class="icon-tile sm info"><Icons name="stun" size={14} /></span>
                <div class="dash-quick-main">
                  <div class="dash-quick-title">{name}</div>
                  <div class="mono dash-quick-sub break-anywhere" style="color:var(--info);">{pubAddr}</div>
                </div>
              </button>
              <button
                type="button"
                class="btn btn-xs btn-icon"
                title={t.copy}
                aria-label={`${t.copy} ${pubAddr}`}
                onclick={() => handleCopy(pubAddr)}
              >
                <Icons name="copy" size={13} />
              </button>
            </div>
          {/each}
          {#each dashboard.cron || [] as cj (cj.name)}
            <button type="button" class="subcard clickable-card dash-quick-row" onclick={() => onNavigate?.('cron')}>
              <span class="icon-tile sm {cj.running ? 'info' : cj.status === 'ok' ? '' : cj.status === 'failed' ? 'danger' : 'muted'}">
                <Icons name="cron" size={14} />
              </span>
              <div class="dash-quick-main">
                <div class="dash-quick-title">{cj.name}</div>
                <div class="mono dash-quick-sub">
                  {t.dash.cronSummary}{cj.last_duration_ms ? ` · ${cj.last_duration_ms}ms` : ''}
                </div>
              </div>
              <span class="badge {cj.running ? 'badge-info' : cj.status === 'ok' ? 'badge-ok' : cj.status === 'failed' ? 'badge-danger' : 'badge-muted'}">
                {cj.running ? t.common.statusRunning : translateRuntimeStatus(cj.status, t)}
              </span>
            </button>
          {/each}
        </div>
      {/if}
    </div>
  </div>

  <!-- Fail2Ban 封禁表 + Top VmRSS 进程 -->
  <div class="bento-grid-2">
    <div class="card">
      <div class="card-header">
        <span class="card-title">
          <span class="icon-tile sm {dashboard.bans.length > 0 ? 'danger' : ''}">
            <Icons name="shield" size={14} />
          </span>
          <span>{t.dash.bansTitle}</span>
        </span>
        <span class="badge {dashboard.bans.length > 0 ? 'badge-danger' : 'badge-ok'} num">{dashboard.bans.length}</span>
      </div>
      {#if dashboard.bans.length === 0}
        <div class="empty-state-rich" style="padding:22px 16px;">
          <div class="icon-tile empty-state-icon"><Icons name="shield" size={16} /></div>
          <div class="empty-state-desc">{t.dash.noBans}</div>
        </div>
      {:else}
        <div style="display:grid;gap:8px;">
          {#each dashboard.bans as ban (`${ban.scope || 'admin'}:${ban.cidr}`)}
            {@const banScope = ban.scope || 'admin'}
            {@const banKey = `${banScope}:${ban.cidr}`}
            <div class="subcard dash-ban-row">
              <div class="dash-ban-main">
                <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
                  <button
                    type="button"
                    class="copy-pill mono dash-ban-cidr"
                    title={t.copy}
                    aria-label={`${t.copy} ${ban.cidr}`}
                    onclick={() => handleCopy(ban.cidr)}
                  >
                    <span class="break-anywhere">{ban.cidr}</span>
                    <Icons name="copy" size={11} />
                  </button>
                  {#if ban.scope && ban.scope !== 'admin'}
                    <span class="meta-chip mono">{ban.scope}</span>
                  {/if}
                </div>
                <div class="mono dash-ban-meta">
                  <span>{ban.reason}</span>
                  <span>·</span>
                  <span>{t.dash?.failsLabel || (lang === 'en' ? 'fails' : '失败')} {ban.failures}</span>
                  <span>·</span>
                  <span>{formatDurationSecs(ban.remaining_secs)}</span>
                </div>
              </div>
              <button
                type="button"
                class="btn btn-sm"
                aria-label={`${t.dash.unban} ${ban.cidr}`}
                disabled={unbanBusy === banKey}
                onclick={() => unbanCidr(ban.cidr, banScope)}
              >
                {unbanBusy === banKey ? '...' : t.dash.unban}
              </button>
            </div>
          {/each}
        </div>
      {/if}
    </div>

    <div class="card">
      <div class="card-header">
        <span class="card-title">
          <span class="icon-tile sm muted"><Icons name="database" size={14} /></span>
          <span>{t.dash.procTitle}</span>
        </span>
        {#if dashboard.system.top_processes?.length}
          <span class="badge badge-muted num">{dashboard.system.top_processes.length}</span>
        {/if}
      </div>
      {#if !dashboard.system.top_processes?.length}
        <div class="empty-state-rich" style="padding:22px 16px;">
          <div class="icon-tile muted empty-state-icon"><Icons name="database" size={16} /></div>
          <div class="empty-state-desc">{t.dash?.noProcs || (lang === 'en' ? 'No process memory data' : '暂无进程内存数据')}</div>
        </div>
      {:else}
        {@const maxProcKb = Math.max(1, ...dashboard.system.top_processes.map((p) => Number(p.vm_rss_kb || 0)))}
        <div class="arcane-table-wrap">
          <table class="arcane-table dash-proc-table">
            <thead>
              <tr>
                <th>PID</th>
                <th>{t.dash?.processCol || (lang === 'en' ? 'Process' : '进程')}</th>
                <th>{t.dash?.memoryCol || (lang === 'en' ? 'Memory' : '内存')}</th>
              </tr>
            </thead>
            <tbody>
              {#each dashboard.system.top_processes as proc}
                {@const rssKb = Number(proc.vm_rss_kb || 0)}
                {@const pct = Math.min(100, (rssKb / maxProcKb) * 100)}
                {@const ramShare = (rssKb / totalMemKb) * 100}
                <tr>
                  <td class="mono dash-proc-pid">#{proc.pid}</td>
                  <td class="dash-proc-name-cell">
                    <div class="dash-proc-name" title={proc.name}>{proc.name}</div>
                    <div class="progress-bar" style="height:3px;margin:4px 0 0;max-width:150px;">
                      <div class="progress-fill" style="width:{pct}%;"></div>
                    </div>
                  </td>
                  <td class="mono dash-proc-mem">
                    <div style="font-weight:600;">{formatKB(rssKb)}</div>
                    {#if dashboard.system.memory?.total_kb > 0}
                      <div class="dash-proc-share">{ramShare.toFixed(1)}%</div>
                    {/if}
                  </td>
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

<style>
  .dash-stat-denom {
    font-size: 15px;
    color: var(--text-muted);
    font-weight: 500;
  }
  .dash-stat-cell.is-active {
    background: color-mix(in srgb, var(--accent) 8%, transparent);
    box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--accent) 26%, transparent);
  }
  @media (max-width: 780px) {
    .dash-stat-grid {
      row-gap: 0;
    }
    .dash-stat-cell {
      padding: 10px 8px;
      border-radius: 10px;
    }
    .dash-stat-cell:nth-child(n + 3) {
      border-top: 1px solid var(--border-subtle);
      margin-top: 6px;
      padding-top: 14px;
    }
  }

  .dash-kpi-card {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .dash-kpi-card .card-header {
    margin-bottom: 0;
  }
  .dash-kpi-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 14px;
  }
  .dash-kpi-body {
    min-width: 0;
    flex: 1;
  }
  .dash-kpi-num {
    font-size: clamp(22px, 2vw, 27px);
    font-weight: 700;
    letter-spacing: -0.025em;
    line-height: 1.15;
    display: flex;
    align-items: baseline;
    flex-wrap: wrap;
    gap: 4px;
  }
  .dash-kpi-denom {
    font-size: 13.5px;
    color: var(--text-secondary);
    font-weight: 500;
    white-space: nowrap;
  }
  .dash-kpi-meta {
    font-size: 11.5px;
    color: var(--text-secondary);
    margin-top: 6px;
  }
  .dash-kpi-meta.muted {
    color: var(--text-muted);
    margin-top: 2px;
  }
  .dash-card-foot {
    margin-top: auto;
    padding-top: 12px;
    border-top: 1px solid var(--border-subtle);
  }
  .dash-card-sub {
    font-size: 11.5px;
    color: var(--text-muted);
    margin-top: 3px;
  }

  /* CPU per-core grid balanced across 4-core desktop & mobile */
  .dash-cores-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(62px, 1fr));
    gap: 8px 10px;
  }
  .dash-core-item {
    min-width: 0;
  }
  .dash-core-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 6px;
    font-size: 10.5px;
    color: var(--text-secondary);
  }
  .dash-core-id {
    color: var(--text-muted);
    font-weight: 600;
  }

  /* Firewall toggle & full-width panel */
  .dash-fw-toggle {
    width: 100%;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    min-height: 32px;
    padding: 4px 8px;
    border-radius: 10px;
    border: 1px solid transparent;
    background: transparent;
    color: var(--text-secondary);
    font-size: 12.5px;
    font-weight: 500;
    font-family: inherit;
    cursor: pointer;
    transition: background-color 0.14s ease, color 0.14s ease, border-color 0.14s ease;
  }
  .dash-fw-toggle:hover {
    background: var(--bg-elevated);
    color: var(--text-primary);
  }
  .dash-fw-toggle:focus-visible {
    outline: none;
    box-shadow: 0 0 0 3px var(--accent-soft);
    border-color: var(--accent);
  }
  .dash-fw-toggle-left {
    display: inline-flex;
    align-items: center;
    gap: 8px;
  }
  .dash-fw-chevron {
    display: inline-flex;
    transition: transform 0.16s ease;
  }
  .dash-fw-chevron.open {
    transform: rotate(180deg);
    color: var(--accent);
  }
  .dash-fw-panel {
    margin-bottom: 16px;
  }
  .dash-fw-list {
    display: grid;
    grid-template-columns: minmax(0, 1fr);
    gap: 6px;
    max-height: 240px;
    overflow-y: auto;
    overflow-x: hidden;
  }
  .dash-fw-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    min-width: 0;
    padding: 8px 12px;
  }
  .dash-fw-row-main {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    min-width: 0;
    flex: 1;
    font-size: 12px;
  }
  .dash-fw-owner {
    font-weight: 600;
    color: var(--text-primary);
  }
  .dash-fw-spec {
    color: var(--text-secondary);
    word-break: break-all;
  }

  /* Full-width non-letterboxed sparklines with HTML crosshair & dots */
  .dash-net-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    padding: 4px 10px;
    border-radius: 999px;
    background: var(--bg-elevated);
    border: 1px solid var(--border-subtle);
  }
  .dash-sep {
    color: var(--text-muted);
  }
  .spark-card {
    padding: 11px 14px 12px;
  }
  .spark-head {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 8px;
    flex-wrap: wrap;
    margin-bottom: 8px;
  }
  .spark-label {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-secondary);
  }
  .spark-val-group {
    display: inline-flex;
    align-items: baseline;
    gap: 8px;
    font-size: 12px;
    flex-wrap: wrap;
    justify-content: flex-end;
  }
  .spark-scale {
    font-size: 10.5px;
    color: var(--text-muted);
    font-weight: 400;
  }
  .spark-canvas {
    position: relative;
    width: 100%;
    height: 74px;
    touch-action: pan-y;
    cursor: crosshair;
  }
  .spark-svg {
    width: 100%;
    height: 100%;
    display: block;
    overflow: visible;
  }
  .spark-crosshair {
    position: absolute;
    top: 2px;
    bottom: 2px;
    width: 1px;
    border-left: 1px dashed var(--text-muted);
    opacity: 0.7;
    pointer-events: none;
  }
  .spark-dot {
    position: absolute;
    width: 8px;
    height: 8px;
    border-radius: 999px;
    transform: translate(-50%, -50%);
    border: 2px solid var(--bg-card);
    pointer-events: none;
  }
  .spark-dot.accent {
    background: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-soft);
  }
  .spark-dot.info {
    background: var(--info);
    box-shadow: 0 0 0 3px var(--info-soft);
  }
  .spark-dot.latest {
    width: 7px;
    height: 7px;
  }
  .spark-empty {
    height: 74px;
    display: grid;
    place-items: center;
    font-size: 12px;
    color: var(--text-muted);
  }

  /* Module Health Grid — uniform balanced heights & crisp 2-col mobile */
  .dash-health-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(195px, 1fr));
    gap: 8px;
    align-items: stretch;
  }
  .dash-mod-tile {
    width: 100%;
    min-height: 60px;
    padding: 10px 12px;
    display: flex;
    flex-direction: column;
    justify-content: center;
    gap: 6px;
    text-align: left;
    font-family: inherit;
    color: inherit;
  }
  .dash-mod-tile.is-disabled {
    opacity: 0.58;
    cursor: default;
  }
  .dash-mod-tile.is-disabled:hover {
    border-color: var(--border-subtle);
  }
  .dash-mod-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    min-width: 0;
  }
  .dash-mod-name-wrap {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
    font-weight: 600;
    min-width: 0;
    flex: 1;
  }
  .dash-mod-name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .dash-mod-badge {
    font-size: 10.5px;
    padding: 1.5px 7px;
    flex-shrink: 0;
  }
  .dash-mod-err {
    font-size: 11px;
    line-height: 1.35;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .dash-mod-err.is-warn {
    color: var(--warn);
  }
  .dash-mod-err.is-danger {
    color: var(--danger);
  }
  @media (max-width: 640px) {
    .dash-health-grid {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
    .dash-mod-top {
      flex-direction: column;
      align-items: flex-start;
      gap: 6px;
    }
    .dash-mod-name-wrap {
      width: 100%;
    }
  }

  /* Network Interfaces */
  .dash-iface-card {
    display: grid;
    gap: 8px;
  }
  .dash-iface-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    flex-wrap: wrap;
  }
  .dash-iface-name {
    font-weight: 700;
    font-size: 13.5px;
  }
  .dash-iface-rates {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
    font-size: 12px;
  }
  .dash-rate-item {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    white-space: nowrap;
  }
  .dash-rate-total {
    color: var(--text-muted);
    font-size: 11px;
  }
  .dash-ip-list {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }
  .dash-ip-pill {
    max-width: 100%;
    text-align: left;
  }
  .dash-ip-pill.v4 {
    color: var(--accent);
  }
  .dash-ip-pill.v6 {
    color: var(--info);
  }
  .dash-ip-tag {
    font-size: 10px;
    font-weight: 700;
    opacity: 0.78;
    text-transform: uppercase;
    flex-shrink: 0;
  }

  /* Quick Status */
  .dash-quick-list {
    display: grid;
    grid-template-columns: minmax(0, 1fr);
    gap: 8px;
    max-height: 410px;
    overflow-y: auto;
    overflow-x: hidden;
    padding-right: 2px;
  }
  .dash-quick-row {
    width: 100%;
    min-width: 0;
    max-width: 100%;
    display: flex;
    align-items: center;
    gap: 10px;
    text-align: left;
    font-family: inherit;
    color: inherit;
    padding: 10px 12px;
  }
  .dash-quick-split {
    width: 100%;
    min-width: 0;
    max-width: 100%;
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 10px 8px 12px;
  }
  .dash-quick-split-main {
    display: flex;
    align-items: center;
    gap: 10px;
    flex: 1;
    min-width: 0;
    border: none;
    background: transparent;
    color: inherit;
    font-family: inherit;
    text-align: left;
    cursor: pointer;
    padding: 2px 0;
    border-radius: 8px;
  }
  .dash-quick-split-main:focus-visible {
    outline: none;
    box-shadow: 0 0 0 3px var(--accent-soft);
  }
  .dash-quick-main {
    min-width: 0;
    flex: 1;
  }
  .dash-quick-title {
    font-weight: 600;
    font-size: 13px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .dash-quick-sub {
    font-size: 11px;
    color: var(--text-secondary);
    margin-top: 2px;
  }

  /* Fail2Ban */
  .dash-ban-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    flex-wrap: wrap;
    padding: 10px 12px;
  }
  .dash-ban-main {
    min-width: 0;
    flex: 1 1 200px;
  }
  .dash-ban-cidr {
    color: var(--danger);
    font-weight: 700;
  }
  .dash-ban-meta {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
    font-size: 11px;
    color: var(--text-secondary);
    margin-top: 5px;
  }

  /* Top Processes Table */
  .dash-proc-pid {
    color: var(--text-muted);
    width: 62px;
    white-space: nowrap;
  }
  .dash-proc-name-cell {
    max-width: 0;
    width: 100%;
  }
  .dash-proc-name {
    font-weight: 500;
    font-size: 13px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .dash-proc-mem {
    white-space: nowrap;
    text-align: right;
  }
  .dash-proc-share {
    font-size: 10.5px;
    color: var(--text-muted);
    font-weight: 400;
  }
  @media (max-width: 640px) {
    .dash-proc-pid {
      width: 50px;
      font-size: 11.5px;
    }
    .dash-fw-toggle {
      min-height: 40px;
    }
  }
</style>
