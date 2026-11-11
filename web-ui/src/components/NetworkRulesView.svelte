<script>
  import { splitCsv, joinCsv, kvObjectToText, textToKvObject, deepClone, formatUnixTime } from '../lib/helpers.js';

  let { mode = 'reverse_proxy', t, lang, settingsJson, onSaveSettings, apiFetch, showToast, onRefresh } = $props();

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
    rpDraft.listen_port = Number(rpDraft.listen_port);
    rpDraft.max_concurrent_conns = Number(rpDraft.max_concurrent_conns);
    const next = deepClone(settingsJson);
    if (rpEditIndex >= 0) next.reverse_proxy[rpEditIndex] = rpDraft;
    else next.reverse_proxy.push(rpDraft);
    if (await onSaveSettings(next)) rpDrawerOpen = false;
  }

  async function deleteListener(idx) {
    const next = deepClone(settingsJson);
    next.reverse_proxy.splice(idx, 1);
    await onSaveSettings(next);
  }

  async function toggleListenerEnabled(idx) {
    const next = deepClone(settingsJson);
    next.reverse_proxy[idx].enabled = !next.reverse_proxy[idx].enabled;
    await onSaveSettings(next);
  }

  function openRuleDrawer(lIdx, rIdx = -1, preset = 'nas') {
    ruleListenerIndex = lIdx;
    ruleEditIndex = rIdx;
    const r = rIdx >= 0 ? deepClone(settingsJson.reverse_proxy[lIdx].rules[rIdx]) : defaultProxyRule(preset);
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
  }

  async function deleteRule(lIdx, rIdx) {
    const next = deepClone(settingsJson);
    next.reverse_proxy[lIdx].rules.splice(rIdx, 1);
    await onSaveSettings(next);
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

  function openPfDrawer(idx = -1, preset = 'v6_to_v4') {
    pfEditIndex = idx;
    const p = idx >= 0 ? deepClone(settingsJson.port_forwards[idx]) : defaultPortForward(preset);
    pfDraft = p;
    const effTargets = p.targets?.length ? p.targets : p.target ? [p.target] : [];
    pfTargetsCsv = joinCsv(effTargets);
    pfAllowedCsv = joinCsv(p.allowed_cidrs);
    pfDrawerOpen = true;
  }

  async function savePortForward(e) {
    e.preventDefault();
    const list = splitCsv(pfTargetsCsv);
    pfDraft.targets = list;
    pfDraft.target = list[0] || '';
    pfDraft.allowed_cidrs = splitCsv(pfAllowedCsv);
    pfDraft.listen_port = Number(pfDraft.listen_port);
    pfDraft.max_concurrent_conns = Number(pfDraft.max_concurrent_conns || 64);
    pfDraft.tcp_idle_timeout_secs = Number(pfDraft.tcp_idle_timeout_secs || 3600);
    pfDraft.udp_session_timeout_secs = Number(pfDraft.udp_session_timeout_secs || 60);
    pfDraft.health_check_interval_secs = Number(pfDraft.health_check_interval_secs || 10);

    const next = deepClone(settingsJson);
    if (pfEditIndex >= 0) next.port_forwards[pfEditIndex] = pfDraft;
    else next.port_forwards.push(pfDraft);
    if (await onSaveSettings(next)) pfDrawerOpen = false;
  }

  async function deletePortForward(idx) {
    const next = deepClone(settingsJson);
    next.port_forwards.splice(idx, 1);
    await onSaveSettings(next);
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
      showToast(minutes > 0 ? `${name}: +${minutes}m` : `${name}: lease cleared`);
      await onRefresh();
    } catch (err) {
      showToast(err.message);
    }
  }
</script>

{#if settingsJson && mode === 'reverse_proxy'}
  <div class="card" style="margin-bottom:16px;">
    <div class="card-header">
      <div>
        <div class="card-title">{t.nav.reverse_proxy}</div>
        <div style="font-size:12px;color:var(--text-secondary);margin-top:2px;">
          {lang === 'en'
            ? 'Dual-stack SNI TLS reverse proxy with HTTP->HTTPS sniff redirect, H1/H2 streaming, Auth Gate & WS tickets.'
            : '双栈独立监听 + 同端口 HTTP 自动 308 跳 HTTPS + 严格 SNI 拒连 + H1/H2 纯流式反代与前置门禁'}
        </div>
      </div>
      <button type="button" class="btn btn-primary btn-sm" onclick={() => openListenerDrawer(-1)}>
        + {lang === 'en' ? 'New Listener' : '新增反代监听端口'}
      </button>
    </div>

    {#if !settingsJson.reverse_proxy?.length}
      <div class="empty-state">{t.common.empty}</div>
    {:else}
      <div style="display:grid;gap:14px;">
        {#each settingsJson.reverse_proxy as listener, lIdx}
          <div class="subcard">
            <div class="row-between" style="margin-bottom:10px;">
              <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                <span style="font-weight:700;font-size:15px;">{listener.name}</span>
                <span class="badge badge-info mono">:{listener.listen_port} ({listener.stack})</span>
                <span class="badge {listener.strict_sni ? 'badge-ok' : 'badge-warn'}">
                  {listener.strict_sni ? 'Strict SNI' : 'Fallback Cert'}
                </span>
                {#if listener.open_wan_firewall}
                  <span class="badge badge-warn">WAN Open</span>
                {/if}
              </div>
              <div class="btn-group">
                <button type="button" class="btn btn-xs {listener.enabled ? 'btn-primary' : ''}" onclick={() => toggleListenerEnabled(lIdx)}>
                  {listener.enabled ? t.enabled : t.disabled}
                </button>
                <button type="button" class="btn btn-xs" onclick={() => openRuleDrawer(lIdx, -1, 'nas')}>
                  + {lang === 'en' ? 'Add Host Rule' : '添加域名规则'}
                </button>
                <button type="button" class="btn btn-xs" onclick={() => openListenerDrawer(lIdx)}>{t.edit}</button>
                <button type="button" class="btn btn-xs btn-danger" onclick={() => deleteListener(lIdx)}>{t.delete}</button>
              </div>
            </div>

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
                  <div class="card" style="padding:12px 14px;box-shadow:none;">
                    <div class="row-between">
                      <div>
                        <div style="font-weight:600;font-size:14px;" class="mono">
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
                        <div class="btn-group" style="margin-top:5px;">
                          <span class="badge badge-muted">{rule.mode}</span>
                          {#if rule.websocket && rule.mode === 'proxy'}<span class="badge badge-info">WS</span>{/if}
                          {#if rule.auth_gate}<span class="badge badge-warn">Auth Gate</span>{/if}
                          {#if rule.strip_prefix}<span class="badge badge-muted">Strip Prefix</span>{/if}
                          {#if rule.upstream.startsWith('https://')}
                            <span class="badge badge-info">TLS: {rule.upstream_tls_mode}</span>
                          {/if}
                        </div>
                      </div>
                      <div class="btn-group">
                        <button type="button" class="btn btn-xs" onclick={() => openRuleDrawer(lIdx, rIdx)}>{t.edit}</button>
                        <button type="button" class="btn btn-xs btn-danger" onclick={() => deleteRule(lIdx, rIdx)}>{t.delete}</button>
                      </div>
                    </div>
                  </div>
                {/each}
              </div>
            {:else}
              <div style="font-size:12px;color:var(--text-muted);padding:6px 2px;">
                {lang === 'en' ? 'No host routing rules in this listener yet.' : '当前监听器下暂无域名转发规则'}
              </div>
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
        <div style="font-size:12px;color:var(--text-secondary);margin-top:2px;">
          {lang === 'en'
            ? '4x4 IPv4/IPv6 matrix forwarding: Userspace zero-copy splice / PKTINFO UDP + Kernel DNAT + 1-Click Temporary Lease.'
            : '支持 4↔4 / 4↔6 / 6↔4 / 6↔6 全矩阵转发、Proxy Protocol v1/v2、主备轮询、每日时间窗与一键限时开门'}
        </div>
      </div>
      <div class="btn-group">
        <button type="button" class="btn btn-xs" onclick={() => openPfDrawer(-1, 'kernel_dnat')}>
          + {lang === 'en' ? 'Kernel DNAT Preset' : '同栈内核 DNAT 预设'}
        </button>
        <button type="button" class="btn btn-xs" onclick={() => openPfDrawer(-1, 'temp_ssh')}>
          + {lang === 'en' ? 'Time-Window SSH' : '限时窗口预设'}
        </button>
        <button type="button" class="btn btn-primary btn-sm" onclick={() => openPfDrawer(-1, 'v6_to_v4')}>
          + {t.add}
        </button>
      </div>
    </div>

    {#if !settingsJson.port_forwards?.length}
      <div class="empty-state">{t.common.empty}</div>
    {:else}
      <div style="display:grid;gap:12px;">
        {#each settingsJson.port_forwards as pf, idx}
          {@const nowSec = Math.floor(Date.now() / 1000)}
          <div class="subcard">
            <div class="row-between">
              <div>
                <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                  <span style="font-weight:700;font-size:15px;">{pf.name}</span>
                  <span class="badge badge-info mono">:{pf.listen_port}/{pf.proto} ({pf.stack})</span>
                  <span class="badge badge-muted">{pf.engine}</span>
                  {#if pf.send_proxy_protocol !== 'none'}
                    <span class="badge badge-info">PP {pf.send_proxy_protocol}</span>
                  {/if}
                  {#if pf.allowed_time_window}
                    <span class="badge badge-warn mono">{pf.allowed_time_window}</span>
                  {/if}
                  {#if pf.expire_at_unix > 0}
                    <span class="badge {pf.expire_at_unix > nowSec ? 'badge-ok' : 'badge-danger'} mono">
                      Lease: {pf.expire_at_unix > nowSec ? `${Math.ceil((pf.expire_at_unix - nowSec) / 60)}m left` : `Expired (${formatUnixTime(pf.expire_at_unix)})`}
                    </span>
                  {/if}
                </div>
                <div class="mono" style="font-size:13px;color:var(--text-secondary);margin-top:6px;">
                  Targets ({pf.load_balance}): {(pf.targets?.length ? pf.targets : [pf.target]).join(', ')}
                </div>
              </div>
              <div class="btn-group">
                <button type="button" class="btn btn-xs" onclick={() => grantLease(pf.name, 15)}>+15m</button>
                <button type="button" class="btn btn-xs" onclick={() => grantLease(pf.name, 60)}>+1h</button>
                {#if pf.expire_at_unix > 0}
                  <button type="button" class="btn btn-xs" onclick={() => grantLease(pf.name, 0)}>∞</button>
                {/if}
                <button type="button" class="btn btn-xs {pf.enabled ? 'btn-primary' : ''}" onclick={() => togglePfEnabled(idx)}>
                  {pf.enabled ? t.enabled : t.disabled}
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
            <label for="rp-name">Listener Name</label>
            <input id="rp-name" type="text" class="mono" bind:value={rpDraft.name} required />
          </div>
          <div class="field">
            <label for="rp-port">Listen Port (≠ 80/443/22/23456 if WAN open)</label>
            <input id="rp-port" type="number" min="1" max="65535" bind:value={rpDraft.listen_port} required />
          </div>
          <div class="field">
            <label for="rp-stack">IP Stack</label>
            <select id="rp-stack" bind:value={rpDraft.stack}>
              <option value="dual">dual (IPv4 + IPv6)</option>
              <option value="ipv4_only">ipv4_only</option>
              <option value="ipv6_only">ipv6_only</option>
            </select>
          </div>
          <div class="field">
            <label for="rp-maxc">Max Concurrent Conns</label>
            <input id="rp-maxc" type="number" min="1" max="4096" bind:value={rpDraft.max_concurrent_conns} required />
          </div>
        </div>
        <div style="display:flex;gap:18px;flex-wrap:wrap;">
          <label class="check-row"><input type="checkbox" bind:checked={rpDraft.enabled} /> {t.enabled}</label>
          <label class="check-row"><input type="checkbox" bind:checked={rpDraft.strict_sni} /> Strict SNI Reject Unknown</label>
          <label class="check-row"><input type="checkbox" bind:checked={rpDraft.open_wan_firewall} /> Auto Open WAN Firewall</label>
        </div>
      </div>
      <div class="drawer-footer">
        <button type="button" class="btn" onclick={() => rpDrawerOpen = false}>{t.cancel}</button>
        <button type="submit" class="btn btn-primary">{t.confirm}</button>
      </div>
    </form>
  </div>
{/if}

<!-- 反代子规则抽屉 -->
{#if ruleDrawerOpen && ruleDraft}
  <div class="drawer-backdrop" role="presentation" onclick={(e) => { if (e.target === e.currentTarget) ruleDrawerOpen = false; }}>
    <form class="drawer-panel" onsubmit={saveRule}>
      <div class="drawer-header">
        <div class="card-title">{ruleEditIndex >= 0 ? t.edit : t.add} · Host Rule</div>
        <button type="button" class="btn btn-sm" onclick={() => ruleDrawerOpen = false}>{t.cancel}</button>
      </div>
      <div class="drawer-body">
        <div class="form-grid">
          <div class="field">
            <label for="rr-host">Domain / Wildcard Host</label>
            <input id="rr-host" type="text" class="mono" placeholder="nas.example.com" bind:value={ruleDraft.host} required />
          </div>
          <div class="field">
            <label for="rr-path">Path Prefix</label>
            <input id="rr-path" type="text" class="mono" placeholder="/" bind:value={ruleDraft.path_prefix} required />
          </div>
          <div class="field">
            <label for="rr-mode">Rule Mode</label>
            <select id="rr-mode" bind:value={ruleDraft.mode}>
              <option value="proxy">proxy (Reverse Proxy)</option>
              <option value="redirect">redirect (301/302/307/308)</option>
              <option value="static">static (Direct Response)</option>
            </select>
          </div>
        </div>

        {#if ruleDraft.mode === 'proxy'}
          <div class="field">
            <label for="rr-up">Upstream URL (http:// or https://)</label>
            <input id="rr-up" type="text" class="mono" placeholder="http://192.168.1.10:5000" bind:value={ruleDraft.upstream} required />
          </div>
          <div class="form-grid">
            <div class="field">
              <label for="rr-tls">Upstream TLS Verify</label>
              <select id="rr-tls" bind:value={ruleDraft.upstream_tls_mode}>
                <option value="strict">strict (System/WebPKI Roots)</option>
                <option value="pinned_sha256">pinned_sha256 (Cert SHA-256 Pin)</option>
                <option value="insecure_skip_verify">insecure_skip_verify (LAN Self-Signed)</option>
              </select>
            </div>
            <div class="field">
              <label for="rr-hosth">Override Upstream Host Header</label>
              <input id="rr-hosth" type="text" class="mono" placeholder="Optional" bind:value={ruleDraft.upstream_host_header} />
            </div>
          </div>
          {#if ruleDraft.upstream_tls_mode === 'pinned_sha256'}
            <div class="field">
              <label for="rr-pin">Cert SHA-256 Fingerprint (64 hex chars)</label>
              <input id="rr-pin" type="text" class="mono" bind:value={ruleDraft.upstream_cert_sha256} required />
            </div>
          {/if}
          <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:12px;">
            <label class="check-row"><input type="checkbox" bind:checked={ruleDraft.enabled} /> {t.enabled}</label>
            <label class="check-row"><input type="checkbox" bind:checked={ruleDraft.websocket} /> WebSocket</label>
            <label class="check-row"><input type="checkbox" bind:checked={ruleDraft.strip_prefix} /> Strip Path Prefix</label>
            <label class="check-row"><input type="checkbox" bind:checked={ruleDraft.auth_gate} /> Admin Auth Gate</label>
            <label class="check-row"><input type="checkbox" bind:checked={ruleDraft.sanitize_forwarded_headers} /> Clean Forwarded Headers</label>
          </div>
        {:else if ruleDraft.mode === 'redirect'}
          <div class="form-grid">
            <div class="field">
              <label for="rr-rcode">Status Code</label>
              <select id="rr-rcode" bind:value={ruleDraft.redirect_code}>
                <option value={301}>301</option>
                <option value={302}>302</option>
                <option value={307}>307</option>
                <option value={308}>308</option>
              </select>
            </div>
            <div class="field">
              <label for="rr-rurl">Target URL (supports {'{{path}}'} & {'{{stun.<name>.public_addr}}'})</label>
              <input id="rr-rurl" type="text" class="mono" bind:value={ruleDraft.redirect_url} required />
            </div>
          </div>
        {:else}
          <div class="form-grid">
            <div class="field">
              <label for="rr-scode">HTTP Status</label>
              <input id="rr-scode" type="number" min="100" max="599" bind:value={ruleDraft.static_status} />
            </div>
            <div class="field">
              <label for="rr-sct">Content-Type</label>
              <input id="rr-sct" type="text" class="mono" bind:value={ruleDraft.static_content_type} />
            </div>
          </div>
          <div class="field">
            <label for="rr-sbody">Response Body</label>
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
                <label for="rr-allow">Allowed CIDRs (comma separated)</label>
                <input id="rr-allow" type="text" class="mono" placeholder="192.168.0.0/16, 240e::/20" bind:value={ruleAllowedCsv} />
              </div>
              <div class="field">
                <label for="rr-deny">Denied CIDRs</label>
                <input id="rr-deny" type="text" class="mono" bind:value={ruleDeniedCsv} />
              </div>
              <div class="field">
                <label for="rr-maxb">Max Upload Body (MB, 0=unlimited)</label>
                <input id="rr-maxb" type="number" min="0" bind:value={ruleDraft.max_body_mb} />
              </div>
              <div class="field">
                <label for="rr-rto">Read Timeout (secs)</label>
                <input id="rr-rto" type="number" min="1" max="86400" bind:value={ruleDraft.read_timeout_secs} />
              </div>
            </div>
            <div class="form-grid">
              <div class="field">
                <label for="rr-rqset">Set Request Headers (Key: Value per line)</label>
                <textarea id="rr-rqset" class="mono" bind:value={ruleReqSetTxt}></textarea>
              </div>
              <div class="field">
                <label for="rr-rsset">Set Response Headers (Key: Value per line)</label>
                <textarea id="rr-rsset" class="mono" bind:value={ruleRespSetTxt}></textarea>
              </div>
            </div>
          </div>
        </details>
      </div>
      <div class="drawer-footer">
        <button type="button" class="btn" onclick={() => ruleDrawerOpen = false}>{t.cancel}</button>
        <button type="submit" class="btn btn-primary">{t.confirm}</button>
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
            <label for="pf-name">Rule Name</label>
            <input id="pf-name" type="text" class="mono" bind:value={pfDraft.name} required />
          </div>
          <div class="field">
            <label for="pf-port">Listen Port</label>
            <input id="pf-port" type="number" min="1" max="65535" bind:value={pfDraft.listen_port} required />
          </div>
          <div class="field">
            <label for="pf-proto">Protocol</label>
            <select id="pf-proto" bind:value={pfDraft.proto}>
              <option value="tcp">tcp</option>
              <option value="udp">udp</option>
              <option value="tcp_udp">tcp_udp</option>
            </select>
          </div>
          <div class="field">
            <label for="pf-stack">Listen Stack</label>
            <select id="pf-stack" bind:value={pfDraft.stack}>
              <option value="dual">dual (IPv4 + IPv6)</option>
              <option value="ipv4_only">ipv4_only</option>
              <option value="ipv6_only">ipv6_only</option>
            </select>
          </div>
          <div class="field">
            <label for="pf-eng">Forward Engine</label>
            <select id="pf-eng" bind:value={pfDraft.engine}>
              <option value="userspace_splice">userspace_splice (Cross-stack / Policy / ProxyProto)</option>
              <option value="kernel_dnat">kernel_dnat (Same-stack Fast Offload)</option>
            </select>
          </div>
          <div class="field">
            <label for="pf-lb">Load Balance / Failover</label>
            <select id="pf-lb" bind:value={pfDraft.load_balance}>
              <option value="failover">failover (Active-Standby)</option>
              <option value="round_robin">round_robin</option>
            </select>
          </div>
        </div>

        <div class="field">
          <label for="pf-targets">Backend Targets (IP:Port, comma separated; IPv6 as [::1]:8080)</label>
          <input id="pf-targets" type="text" class="mono" placeholder="192.168.1.10:8080" bind:value={pfTargetsCsv} required />
        </div>

        <div class="form-grid">
          <div class="field">
            <label for="pf-pp">HAProxy Proxy Protocol</label>
            <select id="pf-pp" bind:value={pfDraft.send_proxy_protocol}>
              <option value="none">none</option>
              <option value="v1">v1 (Text)</option>
              <option value="v2">v2 (Binary)</option>
            </select>
          </div>
          <div class="field">
            <label for="pf-win">Schedule Window (HH:MM-HH:MM)</label>
            <input id="pf-win" type="text" class="mono" placeholder="e.g. 08:00-23:30" bind:value={pfDraft.allowed_time_window} />
          </div>
          <div class="field">
            <label for="pf-cidr">Allowed Source CIDRs</label>
            <input id="pf-cidr" type="text" class="mono" placeholder="Leave empty for any" bind:value={pfAllowedCsv} />
          </div>
          <div class="field">
            <label for="pf-iface">Bind Interface (optional, e.g. wg0)</label>
            <input id="pf-iface" type="text" class="mono" bind:value={pfDraft.bind_interface} />
          </div>
        </div>

        <div style="display:flex;gap:18px;flex-wrap:wrap;">
          <label class="check-row"><input type="checkbox" bind:checked={pfDraft.enabled} /> {t.enabled}</label>
          <label class="check-row"><input type="checkbox" bind:checked={pfDraft.open_wan_firewall} /> Auto Open WAN Firewall</label>
        </div>
      </div>
      <div class="drawer-footer">
        <button type="button" class="btn" onclick={() => pfDrawerOpen = false}>{t.cancel}</button>
        <button type="submit" class="btn btn-primary">{t.confirm}</button>
      </div>
    </form>
  </div>
{/if}
