<script>
  import Icons from './Icons.svelte';
  import {
    splitCsv,
    joinCsv,
    kvObjectToText,
    textToKvObject,
    deepClone,
    formatUnixTime,
    domainMatchesCert,
  } from '../lib/helpers.js';

  let {
    mode = 'reverse_proxy',
    t,
    lang,
    settingsJson,
    dashboard = null,
    networkInfo = null,
    onSaveSettings,
    askConfirm,
    apiFetch,
    showToast,
    onRefresh,
  } = $props();

  let searchQuery = $state('');
  let filterStatus = $state('all'); // all | enabled | disabled
  let saving = $state(false);

  // Reverse Proxy Listener & Rule Drawer 状态
  let rpDrawerOpen = $state(false);
  let rpEditIndex = $state(-1);
  let rpDraft = $state(null);

  let ruleDrawerOpen = $state(false);
  let ruleListenerIndex = $state(-1);
  let ruleEditIndex = $state(-1);
  let ruleDraft = $state(null);
  let ruleAllowedCsv = $state('');
  let ruleDeniedCsv = $state('');
  let ruleReqSetTxt = $state('');
  let ruleReqRemCsv = $state('');
  let ruleRespSetTxt = $state('');
  let ruleRespRemCsv = $state('');

  // Port Forward Drawer 状态
  let pfDrawerOpen = $state(false);
  let pfEditIndex = $state(-1);
  let pfDraft = $state(null);
  let pfTargetsCsv = $state('');
  let pfAllowedCsv = $state('');

  let ifaceNames = $derived((networkInfo?.interfaces || []).map((i) => i.iface));

  function listenerRuntime(name) {
    return (dashboard?.reverse_proxy_status || []).find((s) => s.name === name);
  }
  function pfRuntime(name) {
    return (dashboard?.port_forward_status || []).find((s) => s.name === name);
  }

  function statusMeta(rt, enabled) {
    if (!enabled) return { cls: 'badge-muted', dot: 'muted', text: t.common.statusDisabled };
    const st = rt?.status || 'running';
    if (st === 'failed') return { cls: 'badge-danger', dot: 'danger', text: t.common.statusFailed };
    if (st === 'waiting_window') return { cls: 'badge-warn', dot: 'warn', text: t.common.statusWaiting };
    if (st === 'expired') return { cls: 'badge-danger', dot: 'danger', text: t.common.statusExpired };
    if (st === 'disabled') return { cls: 'badge-muted', dot: 'muted', text: t.common.statusDisabled };
    return { cls: 'badge-ok', dot: 'ok', text: t.common.statusRunning };
  }

  function defaultListener() {
    return {
      name: `https_${(settingsJson?.reverse_proxy?.length || 0) + 1}`,
      enabled: true,
      stack: 'dual',
      listen_port: 8443,
      strict_sni: true,
      open_wan_firewall: true,
      max_concurrent_conns: 256,
      rules: [],
    };
  }

  function defaultProxyRule(preset = 'nas') {
    const base = {
      enabled: true,
      host: 'nas.example.com',
      path_prefix: '/',
      strip_prefix: false,
      mode: 'proxy',
      upstream: 'http://192.168.1.10:5000',
      websocket: true,
      upstream_tls_mode: 'strict',
      upstream_cert_sha256: '',
      upstream_sni: '',
      upstream_host_header: '',
      sanitize_forwarded_headers: true,
      request_headers_set: {},
      request_headers_remove: [],
      response_headers_set: {},
      response_headers_remove: [],
      auth_gate: false,
      allowed_cidrs: [],
      denied_cidrs: [],
      max_body_mb: 0,
      read_timeout_secs: 120,
      redirect_url: '',
      redirect_code: 302,
      static_status: 200,
      static_content_type: 'text/plain; charset=utf-8',
      static_body: '',
    };
    if (preset === 'pve_selfsigned') {
      base.host = 'pve.example.com';
      base.upstream = 'https://192.168.1.2:8006';
      base.upstream_tls_mode = 'insecure_skip_verify';
      base.upstream_host_header = '192.168.1.2:8006';
    } else if (preset === 'stun_redirect') {
      base.host = 'go.example.com';
      base.mode = 'redirect';
      base.redirect_url = 'https://{{stun.home_nat.public_addr}}{{path}}';
      base.redirect_code = 302;
    } else if (preset === 'static_page') {
      base.host = 'status.example.com';
      base.mode = 'static';
      base.static_status = 200;
      base.static_content_type = 'text/plain; charset=utf-8';
      base.static_body = 'Vane Gateway Online';
    }
    return base;
  }

  function openListenerDrawer(idx = -1) {
    rpEditIndex = idx;
    rpDraft = idx >= 0 ? deepClone(settingsJson.reverse_proxy[idx]) : defaultListener();
    rpDrawerOpen = true;
  }

  async function saveListener(e) {
    e.preventDefault();
    if (saving) return;
    saving = true;
    try {
      rpDraft.listen_port = Number(rpDraft.listen_port);
      rpDraft.max_concurrent_conns = Number(rpDraft.max_concurrent_conns);
      const next = deepClone(settingsJson);
      if (rpEditIndex >= 0) next.reverse_proxy[rpEditIndex] = rpDraft;
      else next.reverse_proxy.push(rpDraft);
      if (await onSaveSettings(next)) rpDrawerOpen = false;
    } finally {
      saving = false;
    }
  }

  function deleteListener(idx) {
    const l = settingsJson.reverse_proxy[idx];
    const count = l.rules?.length || 0;
    askConfirm({
      title: t.common.confirmDeleteTitle,
      message: `${l.name} (:${l.listen_port})${count > 0 ? (lang === 'en' ? ` — includes ${count} host rules!` : `（包含 ${count} 条域名子规则将一并移除！）`) : ''}`,
      confirmLabel: t.delete,
      danger: true,
      onConfirm: async () => {
        const next = deepClone(settingsJson);
        next.reverse_proxy.splice(idx, 1);
        await onSaveSettings(next);
      },
    });
  }

  async function toggleListenerEnabled(idx) {
    const next = deepClone(settingsJson);
    next.reverse_proxy[idx].enabled = !next.reverse_proxy[idx].enabled;
    await onSaveSettings(next);
  }

  function openRuleDrawer(lIdx, rIdx = -1, preset = 'nas', cloneFrom = null) {
    ruleListenerIndex = lIdx;
    ruleEditIndex = rIdx;
    const r = cloneFrom
      ? deepClone(cloneFrom)
      : rIdx >= 0
        ? deepClone(settingsJson.reverse_proxy[lIdx].rules[rIdx])
        : defaultProxyRule(preset);
    if (cloneFrom) r.host = `copy-${r.host}`;
    ruleDraft = r;
    ruleAllowedCsv = joinCsv(r.allowed_cidrs);
    ruleDeniedCsv = joinCsv(r.denied_cidrs);
    ruleReqSetTxt = kvObjectToText(r.request_headers_set);
    ruleReqRemCsv = joinCsv(r.request_headers_remove);
    ruleRespSetTxt = kvObjectToText(r.response_headers_set);
    ruleRespRemCsv = joinCsv(r.response_headers_remove);
    ruleDrawerOpen = true;
  }

  async function saveRule(e) {
    e.preventDefault();
    if (saving) return;
    saving = true;
    try {
      ruleDraft.allowed_cidrs = splitCsv(ruleAllowedCsv);
      ruleDraft.denied_cidrs = splitCsv(ruleDeniedCsv);
      ruleDraft.request_headers_set = textToKvObject(ruleReqSetTxt);
      ruleDraft.request_headers_remove = splitCsv(ruleReqRemCsv);
      ruleDraft.response_headers_set = textToKvObject(ruleRespSetTxt);
      ruleDraft.response_headers_remove = splitCsv(ruleRespRemCsv);
      ruleDraft.max_body_mb = Number(ruleDraft.max_body_mb || 0);
      ruleDraft.read_timeout_secs = Number(ruleDraft.read_timeout_secs || 120);
      ruleDraft.redirect_code = Number(ruleDraft.redirect_code || 302);
      ruleDraft.static_status = Number(ruleDraft.static_status || 200);

      const next = deepClone(settingsJson);
      if (ruleEditIndex >= 0) next.reverse_proxy[ruleListenerIndex].rules[ruleEditIndex] = ruleDraft;
      else next.reverse_proxy[ruleListenerIndex].rules.push(ruleDraft);
      if (await onSaveSettings(next)) ruleDrawerOpen = false;
    } finally {
      saving = false;
    }
  }

  async function toggleRuleEnabled(lIdx, rIdx) {
    const next = deepClone(settingsJson);
    next.reverse_proxy[lIdx].rules[rIdx].enabled = !next.reverse_proxy[lIdx].rules[rIdx].enabled;
    await onSaveSettings(next);
  }

  function deleteRule(lIdx, rIdx) {
    const r = settingsJson.reverse_proxy[lIdx].rules[rIdx];
    askConfirm({
      title: t.common.confirmDeleteTitle,
      message: `${r.host}${r.path_prefix}`,
      confirmLabel: t.delete,
      danger: true,
      onConfirm: async () => {
        const next = deepClone(settingsJson);
        next.reverse_proxy[lIdx].rules.splice(rIdx, 1);
        await onSaveSettings(next);
      },
    });
  }

  // ---------------- Port Forward ----------------
  function defaultPortForward(preset = 'v6_to_v4') {
    const base = {
      name: `fwd_${(settingsJson?.port_forwards?.length || 0) + 1}`,
      enabled: true,
      proto: 'tcp',
      stack: 'dual',
      engine: 'userspace_splice',
      listen_port: 18080,
      bind_interface: '',
      source_ip: '',
      target: '192.168.1.10:8080',
      targets: ['192.168.1.10:8080'],
      load_balance: 'failover',
      send_proxy_protocol: 'none',
      open_wan_firewall: true,
      max_concurrent_conns: 64,
      allowed_cidrs: [],
      allowed_time_window: '',
      expire_at_unix: 0,
      udp_session_timeout_secs: 60,
      tcp_idle_timeout_secs: 3600,
      health_check_interval_secs: 10,
    };
    if (preset === 'kernel_dnat') {
      base.stack = 'ipv4_only';
      base.engine = 'kernel_dnat';
      base.listen_port = 51413;
      base.proto = 'tcp_udp';
      base.targets = ['192.168.1.10:51413'];
    } else if (preset === 'temp_ssh') {
      base.name = 'temp_nas_ssh';
      base.listen_port = 22222;
      base.targets = ['192.168.1.10:22'];
      base.allowed_time_window = '08:00-23:30';
    }
    return base;
  }

  function openPfDrawer(idx = -1, preset = 'v6_to_v4', cloneFrom = null) {
    pfEditIndex = idx;
    const p = cloneFrom
      ? deepClone(cloneFrom)
      : idx >= 0
        ? deepClone(settingsJson.port_forwards[idx])
        : defaultPortForward(preset);
    if (cloneFrom) {
      p.name = `${p.name}_copy`;
      p.listen_port = Math.min(65535, Number(p.listen_port) + 1);
    }
    pfDraft = p;
    const effTargets = p.targets?.length ? p.targets : p.target ? [p.target] : [];
    pfTargetsCsv = joinCsv(effTargets);
    pfAllowedCsv = joinCsv(p.allowed_cidrs);
    pfDrawerOpen = true;
  }

  function onPfEngineChange() {
    if (pfDraft?.engine === 'kernel_dnat') {
      if (pfDraft.stack === 'dual') pfDraft.stack = 'ipv4_only';
      pfDraft.send_proxy_protocol = 'none';
      pfAllowedCsv = '';
    }
  }

  async function savePortForward(e) {
    e.preventDefault();
    if (saving) return;
    saving = true;
    try {
      const list = splitCsv(pfTargetsCsv);
      pfDraft.targets = list;
      pfDraft.target = list[0] || '';
      pfDraft.allowed_cidrs = splitCsv(pfAllowedCsv);
      pfDraft.listen_port = Number(pfDraft.listen_port);
      pfDraft.max_concurrent_conns = Number(pfDraft.max_concurrent_conns || 64);
      pfDraft.tcp_idle_timeout_secs = Number(pfDraft.tcp_idle_timeout_secs || 3600);
      pfDraft.udp_session_timeout_secs = Number(pfDraft.udp_session_timeout_secs || 60);
      pfDraft.health_check_interval_secs = Number(pfDraft.health_check_interval_secs ?? 10);

      const next = deepClone(settingsJson);
      if (pfEditIndex >= 0) next.port_forwards[pfEditIndex] = pfDraft;
      else next.port_forwards.push(pfDraft);
      if (await onSaveSettings(next)) pfDrawerOpen = false;
    } finally {
      saving = false;
    }
  }

  function deletePortForward(idx) {
    const pf = settingsJson.port_forwards[idx];
    askConfirm({
      title: t.common.confirmDeleteTitle,
      message: `${pf.name} (:${pf.listen_port}/${pf.proto})`,
      confirmLabel: t.delete,
      danger: true,
      onConfirm: async () => {
        const next = deepClone(settingsJson);
        next.port_forwards.splice(idx, 1);
        await onSaveSettings(next);
      },
    });
  }

  async function togglePfEnabled(idx) {
    const next = deepClone(settingsJson);
    next.port_forwards[idx].enabled = !next.port_forwards[idx].enabled;
    await onSaveSettings(next);
  }

  async function grantLease(name, minutes) {
    try {
      await apiFetch(`/api/port-forwards/${encodeURIComponent(name)}/lease`, {
        method: 'POST',
        body: JSON.stringify({ minutes }),
      });
      showToast(minutes > 0 ? `${name}: +${minutes}m` : `${name}: ${t.pf.permanent}`, 'success');
      await onRefresh();
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  let filteredListeners = $derived(
    (settingsJson?.reverse_proxy || [])
      .map((l, idx) => ({ l, idx }))
      .filter(({ l }) => {
        if (filterStatus === 'enabled' && !l.enabled) return false;
        if (filterStatus === 'disabled' && l.enabled) return false;
        if (!searchQuery.trim()) return true;
        const q = searchQuery.trim().toLowerCase();
        return (
          l.name.toLowerCase().includes(q) ||
          String(l.listen_port).includes(q) ||
          (l.rules || []).some((r) => `${r.host} ${r.upstream} ${r.redirect_url}`.toLowerCase().includes(q))
        );
      })
  );

  let filteredPortForwards = $derived(
    (settingsJson?.port_forwards || [])
      .map((pf, idx) => ({ pf, idx }))
      .filter(({ pf }) => {
        if (filterStatus === 'enabled' && !pf.enabled) return false;
        if (filterStatus === 'disabled' && pf.enabled) return false;
        if (!searchQuery.trim()) return true;
        const q = searchQuery.trim().toLowerCase();
        return `${pf.name} ${pf.listen_port} ${(pf.targets || []).join(' ')} ${pf.target}`
          .toLowerCase()
          .includes(q);
      })
  );
</script>

<svelte:window
  onkeydown={(e) => {
    if (e.key === 'Escape') {
      if (ruleDrawerOpen) ruleDrawerOpen = false;
      else if (rpDrawerOpen) rpDrawerOpen = false;
      else if (pfDrawerOpen) pfDrawerOpen = false;
    }
  }}
/>

<datalist id="net-iface-list">
  {#each ifaceNames as name}
    <option value={name}></option>
  {/each}
</datalist>

{#if settingsJson && mode === 'reverse_proxy'}
  <div class="card" style="margin-bottom:16px;">
    <div class="card-header">
      <div>
        <div class="card-title">{t.nav.reverse_proxy}</div>
        <div style="font-size:12px;color:var(--text-secondary);margin-top:2px;">{t.rp.subtitle}</div>
      </div>
      <button type="button" class="btn btn-primary btn-sm" onclick={() => openListenerDrawer(-1)}>
        <Icons name="plus" size={14} />
        <span>{t.rp.newListener}</span>
      </button>
    </div>

    {#if settingsJson.reverse_proxy?.length}
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon"><Icons name="search" size={15} /></span>
          <input type="text" placeholder={t.search} bind:value={searchQuery} />
        </div>
        <div class="btn-group">
          <button type="button" class="chip {filterStatus === 'all' ? 'active' : ''}" onclick={() => filterStatus = 'all'}>{t.all}</button>
          <button type="button" class="chip {filterStatus === 'enabled' ? 'active' : ''}" onclick={() => filterStatus = 'enabled'}>{t.enabled}</button>
          <button type="button" class="chip {filterStatus === 'disabled' ? 'active' : ''}" onclick={() => filterStatus = 'disabled'}>{t.disabled}</button>
        </div>
      </div>
    {/if}

    {#if !settingsJson.reverse_proxy?.length}
      <div class="empty-state">{t.common.empty}</div>
    {:else if !filteredListeners.length}
      <div class="empty-state">{t.common.noMatches}</div>
    {:else}
      <div style="display:grid;gap:14px;">
        {#each filteredListeners as { l: listener, idx: lIdx }}
          {@const rt = listenerRuntime(listener.name)}
          {@const sm = statusMeta(rt, listener.enabled)}
          <div class="subcard">
            <div class="row-between" style="margin-bottom:10px;">
              <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                <span class="status-dot {sm.dot}"></span>
                <span style="font-weight:700;font-size:15px;">{listener.name}</span>
                <span class="badge badge-info mono">:{listener.listen_port} ({listener.stack})</span>
                <span class="badge {sm.cls}">{sm.text}{#if rt && rt.active_conns > 0} · {rt.active_conns}c{/if}</span>
                <span class="badge {listener.strict_sni ? 'badge-ok' : 'badge-warn'}">
                  {listener.strict_sni ? 'Strict SNI' : 'Fallback Cert'}
                </span>
                {#if listener.open_wan_firewall}
                  <span class="badge badge-warn">WAN Open</span>
                {/if}
              </div>
              <div class="btn-group">
                <button
                  type="button"
                  role="switch"
                  aria-checked={listener.enabled}
                  aria-label="Toggle listener"
                  class="switch"
                  onclick={() => toggleListenerEnabled(lIdx)}
                >
                  <span class="switch-thumb"></span>
                </button>
                <button type="button" class="btn btn-xs" onclick={() => openRuleDrawer(lIdx, -1, 'nas')}>
                  + {t.rp.addRule}
                </button>
                <button type="button" class="btn btn-xs" onclick={() => openListenerDrawer(lIdx)}>{t.edit}</button>
                <button type="button" class="btn btn-xs btn-danger" onclick={() => deleteListener(lIdx)}>{t.delete}</button>
              </div>
            </div>

            {#if rt?.last_error}
              <div class="mono" style="font-size:11.5px;color:var(--danger);margin-bottom:8px;">{rt.last_error}</div>
            {/if}

            <!-- 快捷场景预设条 -->
            <div class="btn-group" style="margin-bottom:10px;">
              <span style="font-size:12px;color:var(--text-muted);">{t.common.presets}:</span>
              <button type="button" class="btn btn-xs" onclick={() => openRuleDrawer(lIdx, -1, 'nas')}>NAS Web</button>
              <button type="button" class="btn btn-xs" onclick={() => openRuleDrawer(lIdx, -1, 'pve_selfsigned')}>
                {lang === 'en' ? 'Self-Signed HTTPS' : '自签 HTTPS 后端'}
              </button>
              <button type="button" class="btn btn-xs" onclick={() => openRuleDrawer(lIdx, -1, 'stun_redirect')}>
                {lang === 'en' ? 'STUN Redirect' : 'STUN 动态跳转'}
              </button>
              <button type="button" class="btn btn-xs" onclick={() => openRuleDrawer(lIdx, -1, 'static_page')}>
                {lang === 'en' ? 'Static Response' : '无后端静态响应'}
              </button>
            </div>

            {#if listener.rules?.length}
              <div style="display:grid;gap:8px;">
                {#each listener.rules as rule, rIdx}
                  {@const certCov = domainMatchesCert(rule.host, settingsJson.acme, dashboard?.certs)}
                  <div class="rule-card">
                    <div class="row-between">
                      <div style="min-width:0;flex:1;">
                        <div style="font-weight:600;font-size:13.5px;word-break:break-all;" class="mono">
                          https://{rule.host}:{listener.listen_port}{rule.path_prefix}
                          <span style="color:var(--accent);">→</span>
                          {#if rule.mode === 'proxy'}
                            {rule.upstream}
                          {:else if rule.mode === 'redirect'}
                            [{rule.redirect_code}] {rule.redirect_url}
                          {:else}
                            [Static {rule.static_status}]
                          {/if}
                        </div>
                        <div class="btn-group" style="margin-top:6px;">
                          <span class="badge {rule.enabled ? 'badge-ok' : 'badge-muted'}">{rule.enabled ? t.enabled : t.disabled}</span>
                          <span class="badge badge-muted">{rule.mode}</span>
                          {#if certCov === 'active'}
                            <span class="badge badge-ok">{t.rp.certOk}</span>
                          {:else if certCov === 'configured'}
                            <span class="badge badge-info">ACME</span>
                          {:else if listener.strict_sni}
                            <span class="badge badge-warn">{t.rp.certMissing}</span>
                          {/if}
                          {#if rule.websocket && rule.mode === 'proxy'}<span class="badge badge-info">WS</span>{/if}
                          {#if rule.auth_gate}<span class="badge badge-warn">Auth Gate</span>{/if}
                          {#if rule.strip_prefix}<span class="badge badge-muted">Strip Prefix</span>{/if}
                          {#if rule.mode === 'proxy' && rule.upstream?.startsWith('https://')}
                            <span class="badge badge-info">TLS: {rule.upstream_tls_mode}</span>
                          {/if}
                        </div>
                      </div>
                      <div class="btn-group">
                        <button
                          type="button"
                          role="switch"
                          aria-checked={rule.enabled}
                          aria-label="Toggle host rule"
                          class="switch"
                          onclick={() => toggleRuleEnabled(lIdx, rIdx)}
                        >
                          <span class="switch-thumb"></span>
                        </button>
                        <button type="button" class="btn btn-xs" title={t.clone} onclick={() => openRuleDrawer(lIdx, -1, 'nas', rule)}>
                          <Icons name="duplicate" size={13} />
                        </button>
                        <button type="button" class="btn btn-xs" onclick={() => openRuleDrawer(lIdx, rIdx)}>{t.edit}</button>
                        <button type="button" class="btn btn-xs btn-danger" onclick={() => deleteRule(lIdx, rIdx)}>{t.delete}</button>
                      </div>
                    </div>
                  </div>
                {/each}
              </div>
            {:else}
              <div style="font-size:12px;color:var(--text-muted);padding:6px 2px;">{t.rp.noRules}</div>
            {/if}
          </div>
        {/each}
      </div>
    {/if}
  </div>
{/if}

{#if settingsJson && mode === 'port_forward'}
  <div class="card">
    <div class="card-header">
      <div>
        <div class="card-title">{t.nav.port_forward}</div>
        <div style="font-size:12px;color:var(--text-secondary);margin-top:2px;">{t.pf.subtitle}</div>
      </div>
      <div class="btn-group">
        <button type="button" class="btn btn-xs" onclick={() => openPfDrawer(-1, 'kernel_dnat')}>+ {t.pf.presetDnat}</button>
        <button type="button" class="btn btn-xs" onclick={() => openPfDrawer(-1, 'temp_ssh')}>+ {t.pf.presetSsh}</button>
        <button type="button" class="btn btn-primary btn-sm" onclick={() => openPfDrawer(-1, 'v6_to_v4')}>
          <Icons name="plus" size={14} />
          <span>{t.add}</span>
        </button>
      </div>
    </div>

    {#if settingsJson.port_forwards?.length}
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon"><Icons name="search" size={15} /></span>
          <input type="text" placeholder={t.search} bind:value={searchQuery} />
        </div>
        <div class="btn-group">
          <button type="button" class="chip {filterStatus === 'all' ? 'active' : ''}" onclick={() => filterStatus = 'all'}>{t.all}</button>
          <button type="button" class="chip {filterStatus === 'enabled' ? 'active' : ''}" onclick={() => filterStatus = 'enabled'}>{t.enabled}</button>
          <button type="button" class="chip {filterStatus === 'disabled' ? 'active' : ''}" onclick={() => filterStatus = 'disabled'}>{t.disabled}</button>
        </div>
      </div>
    {/if}

    {#if !settingsJson.port_forwards?.length}
      <div class="empty-state">{t.common.empty}</div>
    {:else if !filteredPortForwards.length}
      <div class="empty-state">{t.common.noMatches}</div>
    {:else}
      <div style="display:grid;gap:12px;">
        {#each filteredPortForwards as { pf, idx }}
          {@const nowSec = Math.floor(Date.now() / 1000)}
          {@const rt = pfRuntime(pf.name)}
          {@const sm = statusMeta(rt, pf.enabled)}
          <div class="subcard">
            <div class="row-between">
              <div style="min-width:0;flex:1;">
                <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                  <span class="status-dot {sm.dot}"></span>
                  <span style="font-weight:700;font-size:15px;">{pf.name}</span>
                  <span class="badge badge-info mono">:{pf.listen_port}/{pf.proto} ({pf.stack})</span>
                  <span class="badge {sm.cls}">{sm.text}{#if rt && rt.active_conns > 0} · {rt.active_conns}c{/if}</span>
                  <span class="badge badge-muted">{pf.engine}</span>
                  {#if pf.send_proxy_protocol !== 'none'}
                    <span class="badge badge-info">PP {pf.send_proxy_protocol}</span>
                  {/if}
                  {#if pf.allowed_time_window}
                    <span class="badge badge-warn mono">{pf.allowed_time_window}</span>
                  {/if}
                  {#if pf.expire_at_unix > 0}
                    <span class="badge {pf.expire_at_unix > nowSec ? 'badge-ok' : 'badge-danger'} mono">
                      Lease: {pf.expire_at_unix > nowSec ? `${Math.ceil((pf.expire_at_unix - nowSec) / 60)}m` : `Expired (${formatUnixTime(pf.expire_at_unix)})`}
                    </span>
                  {/if}
                </div>
                <div class="mono" style="font-size:12.5px;color:var(--text-secondary);margin-top:6px;">
                  Targets ({pf.load_balance}): {(pf.targets?.length ? pf.targets : [pf.target]).join(', ')}
                  {#if pf.bind_interface} · via {pf.bind_interface}{/if}
                </div>
                {#if rt?.last_error}
                  <div class="mono" style="font-size:11.5px;color:var(--danger);margin-top:4px;">{rt.last_error}</div>
                {/if}
              </div>
              <div class="btn-group">
                <button type="button" class="btn btn-xs" onclick={() => grantLease(pf.name, 15)}>+15m</button>
                <button type="button" class="btn btn-xs" onclick={() => grantLease(pf.name, 60)}>+1h</button>
                {#if pf.expire_at_unix > 0}
                  <button type="button" class="btn btn-xs" title={t.pf.permanent} onclick={() => grantLease(pf.name, 0)}>∞</button>
                {/if}
                <button
                  type="button"
                  role="switch"
                  aria-checked={pf.enabled}
                  aria-label="Toggle port forward"
                  class="switch"
                  onclick={() => togglePfEnabled(idx)}
                >
                  <span class="switch-thumb"></span>
                </button>
                <button type="button" class="btn btn-xs" title={t.clone} onclick={() => openPfDrawer(-1, 'v6_to_v4', pf)}>
                  <Icons name="duplicate" size={13} />
                </button>
                <button type="button" class="btn btn-xs" onclick={() => openPfDrawer(idx)}>{t.edit}</button>
                <button type="button" class="btn btn-xs btn-danger" onclick={() => deletePortForward(idx)}>{t.delete}</button>
              </div>
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </div>
{/if}

<!-- 反代监听器抽屉 -->
{#if rpDrawerOpen && rpDraft}
  <div class="drawer-backdrop" role="presentation" onclick={(e) => { if (e.target === e.currentTarget) rpDrawerOpen = false; }}>
    <form class="drawer-panel" onsubmit={saveListener}>
      <div class="drawer-header">
        <div class="card-title">{rpEditIndex >= 0 ? t.edit : t.add} · {t.nav.reverse_proxy}</div>
        <button type="button" class="btn btn-sm" onclick={() => rpDrawerOpen = false}>{t.cancel}</button>
      </div>
      <div class="drawer-body">
        <div class="form-grid">
          <div class="field">
            <label for="rp-name">{t.rp.listenerName}</label>
            <input id="rp-name" type="text" class="mono" bind:value={rpDraft.name} required />
          </div>
          <div class="field">
            <label for="rp-port">{t.rp.listenPort}</label>
            <input id="rp-port" type="number" min="1" max="65535" bind:value={rpDraft.listen_port} required />
          </div>
          <div class="field">
            <label for="rp-stack">{t.rp.stack}</label>
            <select id="rp-stack" bind:value={rpDraft.stack}>
              <option value="dual">dual (IPv4 + IPv6)</option>
              <option value="ipv4_only">ipv4_only</option>
              <option value="ipv6_only">ipv6_only</option>
            </select>
          </div>
          <div class="field">
            <label for="rp-maxc">{t.rp.maxConns}</label>
            <input id="rp-maxc" type="number" min="1" max="4096" bind:value={rpDraft.max_concurrent_conns} required />
          </div>
        </div>
        <div style="display:grid;gap:4px;">
          <label class="check-row"><input type="checkbox" bind:checked={rpDraft.enabled} /> {t.enabled}</label>
          <label class="check-row"><input type="checkbox" bind:checked={rpDraft.strict_sni} /> {t.rp.strictSni}</label>
          <label class="check-row"><input type="checkbox" bind:checked={rpDraft.open_wan_firewall} /> {t.rp.openWan}</label>
        </div>
      </div>
      <div class="drawer-footer">
        <button type="button" class="btn" onclick={() => rpDrawerOpen = false}>{t.cancel}</button>
        <button type="submit" class="btn btn-primary" disabled={saving}>{saving ? '...' : t.confirm}</button>
      </div>
    </form>
  </div>
{/if}

<!-- 反代子规则抽屉 -->
{#if ruleDrawerOpen && ruleDraft}
  <div class="drawer-backdrop" role="presentation" onclick={(e) => { if (e.target === e.currentTarget) ruleDrawerOpen = false; }}>
    <form class="drawer-panel" onsubmit={saveRule}>
      <div class="drawer-header">
        <div class="card-title">{ruleEditIndex >= 0 ? t.edit : t.add} · {t.rp.addRule}</div>
        <button type="button" class="btn btn-sm" onclick={() => ruleDrawerOpen = false}>{t.cancel}</button>
      </div>
      <div class="drawer-body">
        <div class="form-grid">
          <div class="field">
            <label for="rr-host">{t.rp.host}</label>
            <input id="rr-host" type="text" class="mono" placeholder="nas.example.com" bind:value={ruleDraft.host} required />
          </div>
          <div class="field">
            <label for="rr-path">{t.rp.pathPrefix}</label>
            <input id="rr-path" type="text" class="mono" placeholder="/" bind:value={ruleDraft.path_prefix} required />
          </div>
          <div class="field">
            <label for="rr-mode">{t.rp.mode}</label>
            <select id="rr-mode" bind:value={ruleDraft.mode}>
              <option value="proxy">proxy</option>
              <option value="redirect">redirect (301/302/307/308)</option>
              <option value="static">static</option>
            </select>
          </div>
        </div>

        <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:10px;">
          <label class="check-row"><input type="checkbox" bind:checked={ruleDraft.enabled} /> {t.enabled}</label>
          <label class="check-row"><input type="checkbox" bind:checked={ruleDraft.auth_gate} /> {t.rp.authGate}</label>
        </div>

        {#if ruleDraft.mode === 'proxy'}
          <div class="field">
            <label for="rr-up">{t.rp.upstream}</label>
            <input id="rr-up" type="text" class="mono" placeholder="http://192.168.1.10:5000" bind:value={ruleDraft.upstream} required />
          </div>
          <div class="form-grid">
            <div class="field">
              <label for="rr-tls">{t.rp.tlsVerify}</label>
              <select id="rr-tls" bind:value={ruleDraft.upstream_tls_mode}>
                <option value="strict">strict</option>
                <option value="pinned_sha256">pinned_sha256</option>
                <option value="insecure_skip_verify">insecure_skip_verify</option>
              </select>
            </div>
            <div class="field">
              <label for="rr-sni">{t.rp.upstreamSni}</label>
              <input id="rr-sni" type="text" class="mono" placeholder="Optional" bind:value={ruleDraft.upstream_sni} />
            </div>
            <div class="field">
              <label for="rr-hosth">{t.rp.upstreamHost}</label>
              <input id="rr-hosth" type="text" class="mono" placeholder="Optional" bind:value={ruleDraft.upstream_host_header} />
            </div>
          </div>
          {#if ruleDraft.upstream_tls_mode === 'pinned_sha256'}
            <div class="field">
              <label for="rr-pin">{t.rp.certPin}</label>
              <input id="rr-pin" type="text" class="mono" bind:value={ruleDraft.upstream_cert_sha256} required />
            </div>
          {/if}
          <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:6px;">
            <label class="check-row"><input type="checkbox" bind:checked={ruleDraft.websocket} /> {t.rp.wsLabel}</label>
            <label class="check-row"><input type="checkbox" bind:checked={ruleDraft.strip_prefix} /> {t.rp.stripPrefix}</label>
            <label class="check-row"><input type="checkbox" bind:checked={ruleDraft.sanitize_forwarded_headers} /> {t.rp.sanitizeFwd}</label>
          </div>
          {#if ruleDraft.websocket}
            <div class="field-hint" style="margin-bottom:10px;">{t.rp.wsHint}</div>
          {/if}
        {:else if ruleDraft.mode === 'redirect'}
          <div class="form-grid">
            <div class="field">
              <label for="rr-rcode">{t.rp.redirectCode}</label>
              <select id="rr-rcode" bind:value={ruleDraft.redirect_code}>
                <option value={301}>301</option>
                <option value={302}>302</option>
                <option value={307}>307</option>
                <option value={308}>308</option>
              </select>
            </div>
            <div class="field">
              <label for="rr-rurl">{t.rp.redirectUrl}</label>
              <input id="rr-rurl" type="text" class="mono" bind:value={ruleDraft.redirect_url} required />
            </div>
          </div>
        {:else}
          <div class="form-grid">
            <div class="field">
              <label for="rr-scode">{t.rp.staticStatus}</label>
              <input id="rr-scode" type="number" min="100" max="599" bind:value={ruleDraft.static_status} />
            </div>
            <div class="field">
              <label for="rr-sct">{t.rp.staticCt}</label>
              <input id="rr-sct" type="text" class="mono" bind:value={ruleDraft.static_content_type} />
            </div>
          </div>
          <div class="field">
            <label for="rr-sbody">{t.rp.staticBody}</label>
            <textarea id="rr-sbody" class="mono" bind:value={ruleDraft.static_body}></textarea>
          </div>
        {/if}

        <details style="margin-top:8px;">
          <summary style="cursor:pointer;font-size:13px;font-weight:600;color:var(--text-secondary);padding:6px 0;">
            {t.common.advanced}
          </summary>
          <div style="padding-top:10px;">
            <div class="form-grid">
              <div class="field">
                <label for="rr-allow">{t.rp.allowCidrs}</label>
                <input id="rr-allow" type="text" class="mono" placeholder="192.168.0.0/16, 240e::/20" bind:value={ruleAllowedCsv} />
              </div>
              <div class="field">
                <label for="rr-deny">{t.rp.denyCidrs}</label>
                <input id="rr-deny" type="text" class="mono" bind:value={ruleDeniedCsv} />
              </div>
              <div class="field">
                <label for="rr-maxb">{t.rp.maxBodyMb}</label>
                <input id="rr-maxb" type="number" min="0" bind:value={ruleDraft.max_body_mb} />
              </div>
              <div class="field">
                <label for="rr-rto">{t.rp.readTimeout}</label>
                <input id="rr-rto" type="number" min="1" max="86400" bind:value={ruleDraft.read_timeout_secs} />
              </div>
            </div>
            <div class="form-grid">
              <div class="field">
                <label for="rr-rqset">{t.rp.reqHeadersSet}</label>
                <textarea id="rr-rqset" class="mono" bind:value={ruleReqSetTxt}></textarea>
              </div>
              <div class="field">
                <label for="rr-rsset">{t.rp.respHeadersSet}</label>
                <textarea id="rr-rsset" class="mono" bind:value={ruleRespSetTxt}></textarea>
              </div>
              <div class="field">
                <label for="rr-rqrem">{t.rp.reqHeadersRem}</label>
                <input id="rr-rqrem" type="text" class="mono" placeholder="X-Debug, Server" bind:value={ruleReqRemCsv} />
              </div>
              <div class="field">
                <label for="rr-rsrem">{t.rp.respHeadersRem}</label>
                <input id="rr-rsrem" type="text" class="mono" placeholder="X-Powered-By" bind:value={ruleRespRemCsv} />
              </div>
            </div>
          </div>
        </details>
      </div>
      <div class="drawer-footer">
        <button type="button" class="btn" onclick={() => ruleDrawerOpen = false}>{t.cancel}</button>
        <button type="submit" class="btn btn-primary" disabled={saving}>{saving ? '...' : t.confirm}</button>
      </div>
    </form>
  </div>
{/if}

<!-- 端口转发抽屉 -->
{#if pfDrawerOpen && pfDraft}
  <div class="drawer-backdrop" role="presentation" onclick={(e) => { if (e.target === e.currentTarget) pfDrawerOpen = false; }}>
    <form class="drawer-panel" onsubmit={savePortForward}>
      <div class="drawer-header">
        <div class="card-title">{pfEditIndex >= 0 ? t.edit : t.add} · {t.nav.port_forward}</div>
        <button type="button" class="btn btn-sm" onclick={() => pfDrawerOpen = false}>{t.cancel}</button>
      </div>
      <div class="drawer-body">
        <div class="form-grid">
          <div class="field">
            <label for="pf-name">{t.pf.ruleName}</label>
            <input id="pf-name" type="text" class="mono" bind:value={pfDraft.name} required />
          </div>
          <div class="field">
            <label for="pf-port">{t.pf.listenPort}</label>
            <input id="pf-port" type="number" min="1" max="65535" bind:value={pfDraft.listen_port} required />
          </div>
          <div class="field">
            <label for="pf-proto">{t.pf.proto}</label>
            <select id="pf-proto" bind:value={pfDraft.proto}>
              <option value="tcp">tcp</option>
              <option value="udp">udp</option>
              <option value="tcp_udp">tcp_udp</option>
            </select>
          </div>
          <div class="field">
            <label for="pf-eng">{t.pf.engine}</label>
            <select id="pf-eng" bind:value={pfDraft.engine} onchange={onPfEngineChange}>
              <option value="userspace_splice">userspace_splice</option>
              <option value="kernel_dnat">kernel_dnat</option>
            </select>
          </div>
          <div class="field">
            <label for="pf-stack">{t.pf.stack}</label>
            <select id="pf-stack" bind:value={pfDraft.stack}>
              {#if pfDraft.engine !== 'kernel_dnat'}
                <option value="dual">dual (IPv4 + IPv6)</option>
              {/if}
              <option value="ipv4_only">ipv4_only</option>
              <option value="ipv6_only">ipv6_only</option>
            </select>
          </div>
          {#if pfDraft.engine !== 'kernel_dnat'}
            <div class="field">
              <label for="pf-lb">{t.pf.loadBalance}</label>
              <select id="pf-lb" bind:value={pfDraft.load_balance}>
                <option value="failover">failover</option>
                <option value="round_robin">round_robin</option>
              </select>
            </div>
          {/if}
        </div>

        {#if pfDraft.engine === 'kernel_dnat'}
          <div class="banner banner-info" style="margin-bottom:14px;">{t.pf.dnatHint}</div>
        {/if}

        <div class="field">
          <label for="pf-targets">{t.pf.targets}</label>
          <input id="pf-targets" type="text" class="mono" placeholder="192.168.1.10:8080" bind:value={pfTargetsCsv} required />
        </div>

        {#if pfDraft.engine !== 'kernel_dnat'}
          <div class="form-grid">
            <div class="field">
              <label for="pf-pp">{t.pf.proxyProto}</label>
              <select id="pf-pp" bind:value={pfDraft.send_proxy_protocol}>
                <option value="none">none</option>
                <option value="v1">v1 (Text)</option>
                <option value="v2">v2 (Binary)</option>
              </select>
            </div>
            <div class="field">
              <label for="pf-win">{t.pf.timeWindow}</label>
              <input id="pf-win" type="text" class="mono" placeholder="08:00-23:30" bind:value={pfDraft.allowed_time_window} />
            </div>
            <div class="field">
              <label for="pf-cidr">{t.pf.allowCidrs}</label>
              <input id="pf-cidr" type="text" class="mono" placeholder="192.168.0.0/16" bind:value={pfAllowedCsv} />
            </div>
            <div class="field">
              <label for="pf-iface">{t.pf.bindIface}</label>
              <input id="pf-iface" type="text" class="mono" list="net-iface-list" bind:value={pfDraft.bind_interface} />
            </div>
          </div>

          <details style="margin-bottom:10px;">
            <summary style="cursor:pointer;font-size:13px;font-weight:600;color:var(--text-secondary);padding:6px 0;">
              {t.common.advanced}
            </summary>
            <div class="form-grid" style="padding-top:10px;">
              <div class="field">
                <label for="pf-srcip">{t.pf.sourceIp}</label>
                <input id="pf-srcip" type="text" class="mono" placeholder="Optional" bind:value={pfDraft.source_ip} />
              </div>
              <div class="field">
                <label for="pf-maxc">{t.pf.maxConns}</label>
                <input id="pf-maxc" type="number" min="1" max="4096" bind:value={pfDraft.max_concurrent_conns} />
              </div>
              <div class="field">
                <label for="pf-tcpid">{t.pf.tcpIdle}</label>
                <input id="pf-tcpid" type="number" min="5" max="86400" bind:value={pfDraft.tcp_idle_timeout_secs} />
              </div>
              <div class="field">
                <label for="pf-udpid">{t.pf.udpIdle}</label>
                <input id="pf-udpid" type="number" min="10" max="600" bind:value={pfDraft.udp_session_timeout_secs} />
              </div>
              <div class="field">
                <label for="pf-hci">{t.pf.hcInterval}</label>
                <input id="pf-hci" type="number" min="0" max="3600" bind:value={pfDraft.health_check_interval_secs} />
              </div>
            </div>
          </details>
        {/if}

        <div style="display:flex;gap:18px;flex-wrap:wrap;">
          <label class="check-row"><input type="checkbox" bind:checked={pfDraft.enabled} /> {t.enabled}</label>
          <label class="check-row"><input type="checkbox" bind:checked={pfDraft.open_wan_firewall} /> {t.pf.openWan}</label>
        </div>
      </div>
      <div class="drawer-footer">
        <button type="button" class="btn" onclick={() => pfDrawerOpen = false}>{t.cancel}</button>
        <button type="submit" class="btn btn-primary" disabled={saving}>{saving ? '...' : t.confirm}</button>
      </div>
    </form>
  </div>
{/if}
