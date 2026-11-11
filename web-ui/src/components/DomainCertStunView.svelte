<script>
  import {
    splitCsv,
    joinCsv,
    deepClone,
    copyText,
    formatUnixTime,
    isSecretConfigured,
    secretMaskedHint,
    resolveSecretInput,
  } from '../lib/helpers.js';

  let { mode = 'ddns', t, lang, settingsJson, dashboard, onSaveSettings, apiFetch, showToast, onRefresh } = $props();

  let busyKey = $state('');

  // ---------------- DNS Provider Drawer ----------------
  let provDrawerOpen = $state(false);
  let provEditId = $state('');
  let provDraftId = $state('');
  let provDraft = $state(null);
  let provTokenInput = $state('');
  let provSecretInput = $state('');

  function openProviderDrawer(id = '') {
    provEditId = id;
    provDraftId = id || `cf_${Object.keys(settingsJson?.dns_providers || {}).length + 1}`;
    provDraft = id
      ? deepClone(settingsJson.dns_providers[id])
      : { provider: 'cloudflare', api_token: '', secret_key: '', happy_eyeballs_delay_ms: 250, zone_name: '', zone_id: '' };
    provTokenInput = '';
    provSecretInput = '';
    provDrawerOpen = true;
  }

  async function saveProvider(e) {
    e.preventDefault();
    const cleanId = provDraftId.trim();
    if (!cleanId) return;
    const orig = provEditId ? settingsJson.dns_providers[provEditId] : null;
    provDraft.api_token = resolveSecretInput(orig?.api_token, provTokenInput);
    provDraft.secret_key = resolveSecretInput(orig?.secret_key, provSecretInput);
    provDraft.happy_eyeballs_delay_ms = Number(provDraft.happy_eyeballs_delay_ms || 250);

    const next = deepClone(settingsJson);
    if (provEditId && provEditId !== cleanId) delete next.dns_providers[provEditId];
    next.dns_providers[cleanId] = provDraft;
    if (await onSaveSettings(next)) provDrawerOpen = false;
  }

  async function deleteProvider(id) {
    const next = deepClone(settingsJson);
    delete next.dns_providers[id];
    await onSaveSettings(next);
  }

  // ---------------- DDNS Rule Drawer ----------------
  let ddnsDrawerOpen = $state(false);
  let ddnsEditIdx = $state(-1);
  let ddnsDraft = $state(null);
  let ddnsSourceKind = $state('interface');
  let ddnsRecA = $state(true);
  let ddnsRecAAAA = $state(true);
  let ddnsSplitCsv = $state('');
  let ddnsTcpPortsCsv = $state('');
  let ddnsUdpPortsCsv = $state('');
  let ddnsTokenInput = $state('');
  let ddnsHttpUrlInput = $state('');
  let ddnsHttpBodyInput = $state('');
  let ddnsSrcUrlV4Input = $state('');
  let ddnsSrcUrlV6Input = $state('');
  let ddnsSrcExtractUrlInput = $state('');

  function defaultDdns(preset = 'wan') {
    const firstProv = Object.keys(settingsJson?.dns_providers || {})[0] || 'custom_http';
    const d = {
      name: `ddns_${(settingsJson?.ddns?.length || 0) + 1}`,
      enabled: true,
      provider: firstProv,
      domain: 'home.example.com',
      records: ['A', 'AAAA'],
      source: { kind: 'interface', name: 'pppoe-wan', preferred_subnet: '', index: 0 },
      on_missing_public_ip: 'keep_existing',
      ttl: 300,
      proxied: false,
      line: 'default',
      comment: '',
      split_dns_lan_ips: [],
      firewall_allow_tcp_ports: [],
      firewall_allow_udp_ports: [],
      custom_http: { method: 'GET', url: 'https://example.com/update?ip={{ip}}', headers: {}, body: '', success_keyword: '' },
      token: '',
      reconcile_interval_secs: 600,
    };
    if (preset === 'subdevice_v6') {
      d.name = 'nas_ipv6';
      d.domain = 'nas6.example.com';
      d.records = ['AAAA'];
      d.source = { kind: 'prefix_and_iid', prefix_iface: 'pppoe-wan', iid: '::10' };
      d.firewall_allow_tcp_ports = [5001];
    }
    return d;
  }

  function openDdnsDrawer(idx = -1, preset = 'wan') {
    ddnsEditIdx = idx;
    const d = idx >= 0 ? deepClone(settingsJson.ddns[idx]) : defaultDdns(preset);
    ddnsDraft = d;
    ddnsSourceKind = d.source?.kind || 'interface';
    ddnsRecA = d.records?.includes('A') ?? true;
    ddnsRecAAAA = d.records?.includes('AAAA') ?? true;
    ddnsSplitCsv = joinCsv(d.split_dns_lan_ips);
    ddnsTcpPortsCsv = joinCsv(d.firewall_allow_tcp_ports);
    ddnsUdpPortsCsv = joinCsv(d.firewall_allow_udp_ports);
    ddnsTokenInput = '';
    ddnsHttpUrlInput = '';
    ddnsHttpBodyInput = '';
    ddnsSrcUrlV4Input = '';
    ddnsSrcUrlV6Input = '';
    ddnsSrcExtractUrlInput = '';
    ddnsDrawerOpen = true;
  }

  function onDdnsSourceKindChange() {
    if (ddnsSourceKind === 'interface') ddnsDraft.source = { kind: 'interface', name: 'pppoe-wan', preferred_subnet: '', index: 0 };
    else if (ddnsSourceKind === 'prefix_and_iid') ddnsDraft.source = { kind: 'prefix_and_iid', prefix_iface: 'pppoe-wan', iid: '::10' };
    else if (ddnsSourceKind === 'neighbor_mac') ddnsDraft.source = { kind: 'neighbor_mac', prefix_iface: 'pppoe-wan', mac: '00:11:32:aa:bb:cc' };
    else if (ddnsSourceKind === 'external_url') ddnsDraft.source = { kind: 'external_url', url_v4: '', url_v6: '' };
    else ddnsDraft.source = { kind: 'custom_http_extract', url: '' };
  }

  async function saveDdns(e) {
    e.preventDefault();
    const orig = ddnsEditIdx >= 0 ? settingsJson.ddns[ddnsEditIdx] : null;
    const recs = [];
    if (ddnsRecA) recs.push('A');
    if (ddnsRecAAAA) recs.push('AAAA');
    ddnsDraft.records = recs;
    ddnsDraft.split_dns_lan_ips = splitCsv(ddnsSplitCsv);
    ddnsDraft.firewall_allow_tcp_ports = splitCsv(ddnsTcpPortsCsv).map(Number).filter(Boolean);
    ddnsDraft.firewall_allow_udp_ports = splitCsv(ddnsUdpPortsCsv).map(Number).filter(Boolean);
    ddnsDraft.ttl = Number(ddnsDraft.ttl || 300);
    ddnsDraft.reconcile_interval_secs = Number(ddnsDraft.reconcile_interval_secs || 600);
    ddnsDraft.token = resolveSecretInput(orig?.token, ddnsTokenInput);
    ddnsDraft.custom_http.url = resolveSecretInput(orig?.custom_http?.url, ddnsHttpUrlInput);
    ddnsDraft.custom_http.body = resolveSecretInput(orig?.custom_http?.body, ddnsHttpBodyInput);

    if (ddnsDraft.source.kind === 'external_url') {
      const origSrc = orig?.source?.kind === 'external_url' ? orig.source : null;
      ddnsDraft.source.url_v4 = resolveSecretInput(origSrc?.url_v4, ddnsSrcUrlV4Input);
      ddnsDraft.source.url_v6 = resolveSecretInput(origSrc?.url_v6, ddnsSrcUrlV6Input);
    } else if (ddnsDraft.source.kind === 'custom_http_extract') {
      const origSrc = orig?.source?.kind === 'custom_http_extract' ? orig.source : null;
      ddnsDraft.source.url = resolveSecretInput(origSrc?.url, ddnsSrcExtractUrlInput);
    }

    const next = deepClone(settingsJson);
    if (ddnsEditIdx >= 0) next.ddns[ddnsEditIdx] = ddnsDraft;
    else next.ddns.push(ddnsDraft);
    if (await onSaveSettings(next)) ddnsDrawerOpen = false;
  }

  async function deleteDdns(idx) {
    const next = deepClone(settingsJson);
    next.ddns.splice(idx, 1);
    await onSaveSettings(next);
  }

  async function triggerDdnsSync(name) {
    busyKey = `ddns:${name}`;
    try {
      const st = await apiFetch(`/api/ddns/${encodeURIComponent(name)}/sync`, { method: 'POST' });
      showToast(`${name}: ${st.status}`);
      await onRefresh();
    } catch (err) {
      showToast(err.message);
      await onRefresh();
    } finally {
      busyKey = '';
    }
  }

  // ---------------- ACME Drawer ----------------
  let acmeDrawerOpen = $state(false);
  let acmeEditIdx = $state(-1);
  let acmeDraft = $state(null);
  let acmeExtraCsv = $state('');
  let acmeEabKeyInput = $state('');
  let acmeCopyDir = $state('');

  function openAcmeDrawer(idx = -1) {
    acmeEditIdx = idx;
    const firstProv = Object.keys(settingsJson?.dns_providers || {})[0] || '';
    const a = idx >= 0
      ? deepClone(settingsJson.acme[idx])
      : {
          enabled: true,
          domain: '*.home.example.com',
          extra_domains: ['home.example.com'],
          email: 'admin@example.com',
          dns_provider: firstProv,
          cert_dir: '/data/vane/certs',
          renew_before_days: 30,
          directory_url: 'letsencrypt',
          eab_kid: '',
          eab_hmac_key: '',
          challenge_alias_domain: '',
          propagation_timeout_secs: 180,
          deploy_hooks: [],
          use_for_admin: false,
        };
    acmeDraft = a;
    acmeExtraCsv = joinCsv(a.extra_domains);
    acmeEabKeyInput = '';
    const copyHook = (a.deploy_hooks || []).find((h) => h.kind === 'copy_to_dir');
    acmeCopyDir = copyHook ? copyHook.dir : '';
    acmeDrawerOpen = true;
  }

  async function saveAcme(e) {
    e.preventDefault();
    const orig = acmeEditIdx >= 0 ? settingsJson.acme[acmeEditIdx] : null;
    acmeDraft.extra_domains = splitCsv(acmeExtraCsv);
    acmeDraft.renew_before_days = Number(acmeDraft.renew_before_days || 30);
    acmeDraft.propagation_timeout_secs = Number(acmeDraft.propagation_timeout_secs || 180);
    acmeDraft.eab_hmac_key = resolveSecretInput(orig?.eab_hmac_key, acmeEabKeyInput);
    const keepWebhooks = (acmeDraft.deploy_hooks || []).filter((h) => h.kind === 'webhook');
    if (acmeCopyDir.trim()) {
      acmeDraft.deploy_hooks = [{ kind: 'copy_to_dir', dir: acmeCopyDir.trim() }, ...keepWebhooks];
    } else {
      acmeDraft.deploy_hooks = keepWebhooks;
    }

    const next = deepClone(settingsJson);
    if (acmeEditIdx >= 0) next.acme[acmeEditIdx] = acmeDraft;
    else next.acme.push(acmeDraft);
    if (await onSaveSettings(next)) acmeDrawerOpen = false;
  }

  async function deleteAcme(idx) {
    const next = deepClone(settingsJson);
    next.acme.splice(idx, 1);
    await onSaveSettings(next);
  }

  async function triggerAcmeIssue(domain) {
    busyKey = `acme:${domain}`;
    try {
      const st = await apiFetch(`/api/acme/${encodeURIComponent(domain)}/issue`, { method: 'POST' });
      showToast(`${domain}: ${st.status}`);
      await onRefresh();
    } catch (err) {
      showToast(err.message);
      await onRefresh();
    } finally {
      busyKey = '';
    }
  }

  // ---------------- STUN Drawer ----------------
  let stunDrawerOpen = $state(false);
  let stunEditIdx = $state(-1);
  let stunDraft = $state(null);
  let stunServersCsv = $state('');
  let stunWebhookInput = $state('');
  let stunCfEnabled = $state(false);
  let stunCfDraft = $state(null);
  let stunCfTokenInput = $state('');

  function openStunDrawer(idx = -1) {
    stunEditIdx = idx;
    const s = idx >= 0
      ? deepClone(settingsJson.stun[idx])
      : {
          name: `nat_${(settingsJson?.stun?.length || 0) + 1}`,
          enabled: true,
          proto: 'udp',
          local_port: 8443,
          stun_server: 'stun.miwifi.com:3478',
          stun_servers: ['stun.miwifi.com:3478', 'stun.qq.com:3478'],
          keepalive_secs: 25,
          webhook_url: '',
          bind_rule: '',
          on_change_cloudflare_redirect: null,
        };
    stunDraft = s;
    const allSrvs = s.stun_servers?.length ? s.stun_servers : s.stun_server ? [s.stun_server] : [];
    stunServersCsv = joinCsv(allSrvs);
    stunWebhookInput = '';
    stunCfEnabled = Boolean(s.on_change_cloudflare_redirect);
    stunCfDraft = s.on_change_cloudflare_redirect || {
      zone_id: '',
      ruleset_id: '',
      rule_id: '',
      api_token: '',
      source_host: 'go.example.com',
      target_template: 'https://{{public_addr}}',
      status_code: 302,
    };
    stunCfTokenInput = '';
    stunDrawerOpen = true;
  }

  async function saveStun(e) {
    e.preventDefault();
    const orig = stunEditIdx >= 0 ? settingsJson.stun[stunEditIdx] : null;
    const srvs = splitCsv(stunServersCsv);
    stunDraft.stun_servers = srvs;
    stunDraft.stun_server = srvs[0] || '';
    stunDraft.local_port = Number(stunDraft.local_port || 0);
    stunDraft.keepalive_secs = Number(stunDraft.keepalive_secs || 25);
    stunDraft.webhook_url = resolveSecretInput(orig?.webhook_url, stunWebhookInput);

    if (stunCfEnabled) {
      stunCfDraft.status_code = Number(stunCfDraft.status_code || 302);
      stunCfDraft.api_token = resolveSecretInput(orig?.on_change_cloudflare_redirect?.api_token, stunCfTokenInput);
      stunDraft.on_change_cloudflare_redirect = stunCfDraft;
    } else {
      stunDraft.on_change_cloudflare_redirect = null;
    }

    const next = deepClone(settingsJson);
    if (stunEditIdx >= 0) next.stun[stunEditIdx] = stunDraft;
    else next.stun.push(stunDraft);
    if (await onSaveSettings(next)) stunDrawerOpen = false;
  }

  async function deleteStun(idx) {
    const next = deepClone(settingsJson);
    next.stun.splice(idx, 1);
    await onSaveSettings(next);
  }

  async function triggerStunProbe(name) {
    busyKey = `stun:${name}`;
    try {
      const r = await apiFetch(`/api/stun/${encodeURIComponent(name)}/probe`, { method: 'POST' });
      showToast(`${name} -> ${r.public_addr}`);
      await onRefresh();
    } catch (err) {
      showToast(err.message);
      await onRefresh();
    } finally {
      busyKey = '';
    }
  }
</script>

<!-- ===================== DDNS & DNS 服务商账号 ===================== -->
{#if settingsJson && mode === 'ddns'}
  <div class="card" style="margin-bottom:16px;">
    <div class="card-header">
      <div>
        <div class="card-title">{lang === 'en' ? 'DNS Cloud Provider Accounts' : 'DNS 云服务商凭据池（供 DDNS 与 ACME 共用）'}</div>
        <div style="font-size:12px;color:var(--text-secondary);">Cloudflare / Aliyun DNS / DNSPod · ChaCha20-Poly1305 Vault Sealed</div>
      </div>
      <button type="button" class="btn btn-sm" onclick={() => openProviderDrawer('')}>
        + {lang === 'en' ? 'Add DNS Account' : '添加服务商账号'}
      </button>
    </div>

    {#if !Object.keys(settingsJson.dns_providers || {}).length}
      <div class="empty-state" style="padding:18px;">
        {lang === 'en' ? 'Add a Cloudflare / Aliyun / DNSPod account first (or use custom_http in DDNS).' : '尚未配置云解析账号（可添加 Cloudflare / 阿里云 / DNSPod 供 DDNS 与 ACME 证书签发复用）'}
      </div>
    {:else}
      <div class="bento-grid" style="margin-bottom:0;">
        {#each Object.entries(settingsJson.dns_providers) as [id, p]}
          <div class="subcard row-between">
            <div>
              <div style="font-weight:700;" class="mono">{id} <span class="badge badge-info">{p.provider}</span></div>
              <div class="mono" style="font-size:11px;color:var(--text-secondary);margin-top:4px;">
                Token: {secretMaskedHint(p.api_token, 'empty')} {p.zone_name ? `· Zone: ${p.zone_name}` : ''}
              </div>
            </div>
            <div class="btn-group">
              <button type="button" class="btn btn-xs" onclick={() => openProviderDrawer(id)}>{t.edit}</button>
              <button type="button" class="btn btn-xs btn-danger" onclick={() => deleteProvider(id)}>{t.delete}</button>
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </div>

  <div class="card">
    <div class="card-header">
      <div>
        <div class="card-title">{t.nav.ddns}</div>
        <div style="font-size:12px;color:var(--text-secondary);">
          {lang === 'en'
            ? 'Event-driven IPv4/IPv6 sync, CGNAT/deprecated filtering, /128 sub-device synthesis & Split-DNS.'
            : 'Netlink 事件驱动 + CGNAT/过期前缀自动剔除 + 内网子设备 /128 精准放行与内网回流'}
        </div>
      </div>
      <div class="btn-group">
        <button type="button" class="btn btn-xs" onclick={() => openDdnsDrawer(-1, 'subdevice_v6')}>
          + {lang === 'en' ? 'Sub-Device IPv6 /128' : '子设备 IPv6 直连预设'}
        </button>
        <button type="button" class="btn btn-primary btn-sm" onclick={() => openDdnsDrawer(-1, 'wan')}>+ {t.add}</button>
      </div>
    </div>

    {#if !settingsJson.ddns?.length}
      <div class="empty-state">{t.common.empty}</div>
    {:else}
      <div style="display:grid;gap:12px;">
        {#each settingsJson.ddns as d, idx}
          {@const rt = (dashboard?.ddns || []).find((x) => x.name === d.name)}
          <div class="subcard">
            <div class="row-between">
              <div>
                <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                  <span style="font-weight:700;font-size:15px;" class="mono">{d.domain}</span>
                  <span class="badge badge-muted">{d.name}</span>
                  <span class="badge badge-info">{d.provider} ({d.records.join('+')})</span>
                  {#if rt}
                    <span class="badge {rt.status === 'synced' ? 'badge-ok' : rt.status === 'failed' ? 'badge-danger' : 'badge-warn'}">
                      {rt.status}
                    </span>
                  {/if}
                </div>
                <div class="mono" style="font-size:12px;color:var(--text-secondary);margin-top:6px;">
                  Source: {d.source.kind}
                  {#if rt?.last_ipv4} · A={rt.last_ipv4}{/if}
                  {#if rt?.last_ipv6} · AAAA={rt.last_ipv6}{/if}
                  {#if rt?.last_sync_unix} · Synced {formatUnixTime(rt.last_sync_unix)}{/if}
                </div>
                {#if rt?.ipv4?.error || rt?.ipv6?.error || rt?.firewall_error}
                  <div class="mono" style="font-size:11px;color:var(--danger);margin-top:4px;">
                    {rt.ipv4?.error || rt.ipv6?.error || rt.firewall_error}
                  </div>
                {/if}
              </div>
              <div class="btn-group">
                <button type="button" class="btn btn-xs btn-primary" disabled={busyKey === `ddns:${d.name}`} onclick={() => triggerDdnsSync(d.name)}>
                  {busyKey === `ddns:${d.name}` ? '...' : (lang === 'en' ? 'Sync Now' : '立即同步')}
                </button>
                <button type="button" class="btn btn-xs" onclick={() => openDdnsDrawer(idx)}>{t.edit}</button>
                <button type="button" class="btn btn-xs btn-danger" onclick={() => deleteDdns(idx)}>{t.delete}</button>
              </div>
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </div>
{/if}

<!-- ===================== ACME 自动化证书 ===================== -->
{#if settingsJson && mode === 'acme'}
  <div class="card">
    <div class="card-header">
      <div>
        <div class="card-title">{t.nav.acme}</div>
        <div style="font-size:12px;color:var(--text-secondary);">
          {lang === 'en'
            ? 'RFC 8555 DNS-01 ECDSA P-256 issuance, CNAME alias delegation, ArcSwap hot-reload & deploy hooks.'
            : 'RFC 8555 DNS-01 自动签发与续期、CNAME 挑战委派、ArcSwap 零中断热加载与自动部署钩子'}
        </div>
      </div>
      <button type="button" class="btn btn-primary btn-sm" onclick={() => openAcmeDrawer(-1)}>+ {t.add}</button>
    </div>

    {#if !settingsJson.acme?.length}
      <div class="empty-state">{t.common.empty}</div>
    {:else}
      <div style="display:grid;gap:12px;">
        {#each settingsJson.acme as a, idx}
          {@const st = (dashboard?.certs || []).find((c) => c.domain === a.domain)}
          <div class="subcard">
            <div class="row-between">
              <div>
                <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                  <span style="font-weight:700;font-size:15px;" class="mono">{a.domain}</span>
                  {#if a.extra_domains?.length}
                    <span class="badge badge-muted mono">+{a.extra_domains.length} SAN</span>
                  {/if}
                  <span class="badge badge-info">{a.directory_url}</span>
                  {#if a.use_for_admin}<span class="badge badge-warn">Admin Panel Cert</span>{/if}
                  {#if st}
                    <span class="badge {st.status === 'active' ? 'badge-ok' : 'badge-danger'}">{st.status}</span>
                  {/if}
                </div>
                <div class="mono" style="font-size:12px;color:var(--text-secondary);margin-top:6px;">
                  DNS: {a.dns_provider} · Renew &lt; {a.renew_before_days}d
                  {#if st?.expires_at_unix} · Expires: {formatUnixTime(st.expires_at_unix)}{/if}
                </div>
                {#if st?.last_error}
                  <div class="mono" style="font-size:11px;color:var(--danger);margin-top:4px;">{st.last_error}</div>
                {/if}
              </div>
              <div class="btn-group">
                <button type="button" class="btn btn-xs btn-primary" disabled={busyKey === `acme:${a.domain}`} onclick={() => triggerAcmeIssue(a.domain)}>
                  {busyKey === `acme:${a.domain}` ? '...' : (lang === 'en' ? 'Issue / Renew' : '立即签发/续期')}
                </button>
                <button type="button" class="btn btn-xs" onclick={() => openAcmeDrawer(idx)}>{t.edit}</button>
                <button type="button" class="btn btn-xs btn-danger" onclick={() => deleteAcme(idx)}>{t.delete}</button>
              </div>
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </div>
{/if}

<!-- ===================== STUN 穿透与动态重定向 ===================== -->
{#if settingsJson && mode === 'stun'}
  <div class="card">
    <div class="card-header">
      <div>
        <div class="card-title">{t.nav.stun}</div>
        <div style="font-size:12px;color:var(--text-secondary);">
          {lang === 'en'
            ? 'Persistent SO_REUSEPORT UDP/TCP NAT mapping keepalive with Webhook & Cloudflare Redirect Ruleset sync.'
            : '同端口持久持有 NAT1 公网映射，端口变化自动同步 Cloudflare Redirect 固定域名跳转与通知'}
        </div>
      </div>
      <button type="button" class="btn btn-primary btn-sm" onclick={() => openStunDrawer(-1)}>+ {t.add}</button>
    </div>

    {#if !settingsJson.stun?.length}
      <div class="empty-state">{t.common.empty}</div>
    {:else}
      <div style="display:grid;gap:12px;">
        {#each settingsJson.stun as s, idx}
          {@const st = (dashboard?.stun || []).find((x) => x.name === s.name)}
          {@const pubAddr = st?.public_addr || dashboard?.stun_public_addrs?.[s.name] || ''}
          <div class="subcard">
            <div class="row-between">
              <div>
                <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                  <span style="font-weight:700;font-size:15px;">{s.name}</span>
                  <span class="badge badge-info mono">{s.proto.toUpperCase()} :{s.local_port || 'auto'}</span>
                  {#if s.bind_rule}<span class="badge badge-muted">Bind: {s.bind_rule}</span>{/if}
                  {#if s.on_change_cloudflare_redirect}<span class="badge badge-warn">CF Redirect</span>{/if}
                  {#if st}<span class="badge {st.status === 'active' ? 'badge-ok' : 'badge-danger'}">{st.status}</span>{/if}
                </div>
                <div class="mono" style="font-size:13px;color:var(--info);margin-top:6px;">
                  Public: {pubAddr || (lang === 'en' ? 'Not probed yet' : '等待探测...')}
                </div>
                {#if st?.error}
                  <div class="mono" style="font-size:11px;color:var(--danger);margin-top:4px;">{st.error}</div>
                {/if}
              </div>
              <div class="btn-group">
                {#if pubAddr}
                  <button type="button" class="btn btn-xs" onclick={async () => { if (await copyText(pubAddr)) showToast(t.copied); }}>
                    {t.copy}
                  </button>
                {/if}
                <button type="button" class="btn btn-xs btn-primary" disabled={busyKey === `stun:${s.name}`} onclick={() => triggerStunProbe(s.name)}>
                  {busyKey === `stun:${s.name}` ? '...' : (lang === 'en' ? 'Probe Now' : '立即探测')}
                </button>
                <button type="button" class="btn btn-xs" onclick={() => openStunDrawer(idx)}>{t.edit}</button>
                <button type="button" class="btn btn-xs btn-danger" onclick={() => deleteStun(idx)}>{t.delete}</button>
              </div>
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </div>
{/if}

<!-- DNS 服务商账号抽屉 -->
{#if provDrawerOpen && provDraft}
  <div class="drawer-backdrop" role="presentation" onclick={(e) => { if (e.target === e.currentTarget) provDrawerOpen = false; }}>
    <form class="drawer-panel" onsubmit={saveProvider}>
      <div class="drawer-header">
        <div class="card-title">{provEditId ? t.edit : t.add} · DNS Provider</div>
        <button type="button" class="btn btn-sm" onclick={() => provDrawerOpen = false}>{t.cancel}</button>
      </div>
      <div class="drawer-body">
        <div class="form-grid">
          <div class="field">
            <label for="dp-id">Account ID</label>
            <input id="dp-id" type="text" class="mono" bind:value={provDraftId} required />
          </div>
          <div class="field">
            <label for="dp-kind">Provider</label>
            <select id="dp-kind" bind:value={provDraft.provider}>
              <option value="cloudflare">cloudflare</option>
              <option value="aliyun">aliyun</option>
              <option value="dnspod">dnspod</option>
            </select>
          </div>
        </div>
        <div class="field">
          <label for="dp-tok">API Token / AccessKeyId / SecretId</label>
          <input
            id="dp-tok"
            type="password"
            class="mono"
            placeholder={isSecretConfigured(provDraft.api_token) ? secretMaskedHint(provDraft.api_token) : 'Paste API token'}
            bind:value={provTokenInput}
          />
          <div class="field-hint">{isSecretConfigured(provDraft.api_token) ? t.common.secretConfigured : t.common.secretEmpty}</div>
        </div>
        {#if provDraft.provider !== 'cloudflare'}
          <div class="field">
            <label for="dp-sec">AccessKeySecret / SecretKey</label>
            <input
              id="dp-sec"
              type="password"
              class="mono"
              placeholder={isSecretConfigured(provDraft.secret_key) ? secretMaskedHint(provDraft.secret_key) : 'Paste secret key'}
              bind:value={provSecretInput}
            />
          </div>
        {/if}
        <div class="form-grid">
          <div class="field">
            <label for="dp-zn">Optional Zone Name (e.g. example.com)</label>
            <input id="dp-zn" type="text" class="mono" bind:value={provDraft.zone_name} />
          </div>
          <div class="field">
            <label for="dp-zid">Optional Cloudflare Zone ID</label>
            <input id="dp-zid" type="text" class="mono" bind:value={provDraft.zone_id} />
          </div>
        </div>
      </div>
      <div class="drawer-footer">
        <button type="button" class="btn" onclick={() => provDrawerOpen = false}>{t.cancel}</button>
        <button type="submit" class="btn btn-primary">{t.confirm}</button>
      </div>
    </form>
  </div>
{/if}

<!-- DDNS 规则抽屉 -->
{#if ddnsDrawerOpen && ddnsDraft}
  <div class="drawer-backdrop" role="presentation" onclick={(e) => { if (e.target === e.currentTarget) ddnsDrawerOpen = false; }}>
    <form class="drawer-panel" onsubmit={saveDdns}>
      <div class="drawer-header">
        <div class="card-title">{ddnsEditIdx >= 0 ? t.edit : t.add} · DDNS</div>
        <button type="button" class="btn btn-sm" onclick={() => ddnsDrawerOpen = false}>{t.cancel}</button>
      </div>
      <div class="drawer-body">
        <div class="form-grid">
          <div class="field">
            <label for="dd-name">Rule Name</label>
            <input id="dd-name" type="text" class="mono" bind:value={ddnsDraft.name} required />
          </div>
          <div class="field">
            <label for="dd-dom">Domain (FQDN)</label>
            <input id="dd-dom" type="text" class="mono" placeholder="home.example.com" bind:value={ddnsDraft.domain} required />
          </div>
          <div class="field">
            <label for="dd-prov">DNS Provider Account</label>
            <select id="dd-prov" bind:value={ddnsDraft.provider}>
              {#each Object.keys(settingsJson.dns_providers || {}) as pid}
                <option value={pid}>{pid}</option>
              {/each}
              <option value="custom_http">custom_http (Template)</option>
            </select>
          </div>
          <div class="field">
            <label for="dd-src">IP Source Mode</label>
            <select id="dd-src" bind:value={ddnsSourceKind} onchange={onDdnsSourceKindChange}>
              <option value="interface">interface (Router WAN)</option>
              <option value="prefix_and_iid">prefix_and_iid (PD Prefix + Fixed IID)</option>
              <option value="neighbor_mac">neighbor_mac (LAN NDP MAC Discovery)</option>
              <option value="external_url">external_url (Public IP API)</option>
              <option value="custom_http_extract">custom_http_extract</option>
            </select>
          </div>
        </div>

        {#if ddnsDraft.source.kind === 'interface'}
          <div class="form-grid">
            <div class="field">
              <label for="dd-if">WAN Interface</label>
              <input id="dd-if" type="text" class="mono" bind:value={ddnsDraft.source.name} required />
            </div>
            <div class="field">
              <label for="dd-sub">Preferred Subnet CIDR (optional)</label>
              <input id="dd-sub" type="text" class="mono" bind:value={ddnsDraft.source.preferred_subnet} />
            </div>
          </div>
        {:else if ddnsDraft.source.kind === 'prefix_and_iid'}
          <div class="form-grid">
            <div class="field">
              <label for="dd-pif">PD Prefix Interface</label>
              <input id="dd-pif" type="text" class="mono" bind:value={ddnsDraft.source.prefix_iface} required />
            </div>
            <div class="field">
              <label for="dd-iid">Fixed IPv6 IID Suffix (e.g. ::10)</label>
              <input id="dd-iid" type="text" class="mono" bind:value={ddnsDraft.source.iid} required />
            </div>
          </div>
        {:else if ddnsDraft.source.kind === 'neighbor_mac'}
          <div class="form-grid">
            <div class="field">
              <label for="dd-nif">PD Prefix Interface</label>
              <input id="dd-nif" type="text" class="mono" bind:value={ddnsDraft.source.prefix_iface} required />
            </div>
            <div class="field">
              <label for="dd-mac">Target LAN Device MAC</label>
              <input id="dd-mac" type="text" class="mono" placeholder="00:11:32:aa:bb:cc" bind:value={ddnsDraft.source.mac} required />
            </div>
          </div>
        {:else if ddnsDraft.source.kind === 'external_url'}
          <div class="form-grid">
            <div class="field">
              <label for="dd-uv4">IPv4 Check URL</label>
              <input id="dd-uv4" type="text" class="mono" placeholder="https://4.ipw.cn" bind:value={ddnsSrcUrlV4Input} />
            </div>
            <div class="field">
              <label for="dd-uv6">IPv6 Check URL</label>
              <input id="dd-uv6" type="text" class="mono" placeholder="https://6.ipw.cn" bind:value={ddnsSrcUrlV6Input} />
            </div>
          </div>
        {:else}
          <div class="field">
            <label for="dd-uex">Extract URL</label>
            <input id="dd-uex" type="text" class="mono" bind:value={ddnsSrcExtractUrlInput} />
          </div>
        {/if}

        {#if ddnsDraft.provider === 'custom_http'}
          <div class="form-grid">
            <div class="field">
              <label for="dd-chm">HTTP Method</label>
              <select id="dd-chm" bind:value={ddnsDraft.custom_http.method}>
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
              </select>
            </div>
            <div class="field">
              <label for="dd-tok">Template {'{{token}}'}</label>
              <input id="dd-tok" type="password" class="mono" placeholder={secretMaskedHint(ddnsDraft.token, 'Optional token')} bind:value={ddnsTokenInput} />
            </div>
          </div>
          <div class="field">
            <label for="dd-chu">Custom HTTP URL ({'{{ip}} {{domain}} {{token}}'})</label>
            <input id="dd-chu" type="text" class="mono" placeholder={secretMaskedHint(ddnsDraft.custom_http?.url, 'https://...')} bind:value={ddnsHttpUrlInput} />
          </div>
        {/if}

        <div style="display:flex;gap:18px;flex-wrap:wrap;margin-bottom:12px;">
          <label class="check-row"><input type="checkbox" bind:checked={ddnsDraft.enabled} /> {t.enabled}</label>
          <label class="check-row"><input type="checkbox" bind:checked={ddnsRecA} /> Record A (IPv4)</label>
          <label class="check-row"><input type="checkbox" bind:checked={ddnsRecAAAA} /> Record AAAA (IPv6)</label>
          <label class="check-row"><input type="checkbox" bind:checked={ddnsDraft.proxied} /> Cloudflare Proxied</label>
        </div>

        <div class="form-grid">
          <div class="field">
            <label for="dd-fw6">Sub-Device /128 Allow TCP Ports</label>
            <input id="dd-fw6" type="text" class="mono" placeholder="e.g. 5001, 8443" bind:value={ddnsTcpPortsCsv} />
          </div>
          <div class="field">
            <label for="dd-split">Split-DNS LAN Loopback IPs</label>
            <input id="dd-split" type="text" class="mono" placeholder="e.g. 192.168.1.10" bind:value={ddnsSplitCsv} />
          </div>
        </div>
      </div>
      <div class="drawer-footer">
        <button type="button" class="btn" onclick={() => ddnsDrawerOpen = false}>{t.cancel}</button>
        <button type="submit" class="btn btn-primary">{t.confirm}</button>
      </div>
    </form>
  </div>
{/if}

<!-- ACME 证书抽屉 -->
{#if acmeDrawerOpen && acmeDraft}
  <div class="drawer-backdrop" role="presentation" onclick={(e) => { if (e.target === e.currentTarget) acmeDrawerOpen = false; }}>
    <form class="drawer-panel" onsubmit={saveAcme}>
      <div class="drawer-header">
        <div class="card-title">{acmeEditIdx >= 0 ? t.edit : t.add} · ACME TLS</div>
        <button type="button" class="btn btn-sm" onclick={() => acmeDrawerOpen = false}>{t.cancel}</button>
      </div>
      <div class="drawer-body">
        <div class="form-grid">
          <div class="field">
            <label for="ac-dom">Primary Domain</label>
            <input id="ac-dom" type="text" class="mono" placeholder="*.home.example.com" bind:value={acmeDraft.domain} required />
          </div>
          <div class="field">
            <label for="ac-extra">Extra SAN Domains (comma separated)</label>
            <input id="ac-extra" type="text" class="mono" placeholder="home.example.com" bind:value={acmeExtraCsv} />
          </div>
          <div class="field">
            <label for="ac-prov">DNS-01 Provider Account</label>
            <select id="ac-prov" bind:value={acmeDraft.dns_provider} required>
              {#each Object.keys(settingsJson.dns_providers || {}) as pid}
                <option value={pid}>{pid}</option>
              {/each}
            </select>
          </div>
          <div class="field">
            <label for="ac-ca">CA Directory</label>
            <select id="ac-ca" bind:value={acmeDraft.directory_url}>
              <option value="letsencrypt">Let's Encrypt (Production)</option>
              <option value="letsencrypt_staging">Let's Encrypt (Staging Test)</option>
              <option value="zerossl">ZeroSSL</option>
              <option value="buypass">Buypass</option>
              <option value="google">Google Trust Services</option>
            </select>
          </div>
          <div class="field">
            <label for="ac-email">Account Email</label>
            <input id="ac-email" type="email" bind:value={acmeDraft.email} />
          </div>
          <div class="field">
            <label for="ac-alias">CNAME Challenge Alias Domain (optional)</label>
            <input id="ac-alias" type="text" class="mono" placeholder="auth.secondary-domain.com" bind:value={acmeDraft.challenge_alias_domain} />
          </div>
          <div class="field">
            <label for="ac-dir">Cert Storage Dir (absolute path)</label>
            <input id="ac-dir" type="text" class="mono" bind:value={acmeDraft.cert_dir} required />
          </div>
          <div class="field">
            <label for="ac-copy">Auto Export PEM Copy Dir (optional)</label>
            <input id="ac-copy" type="text" class="mono" placeholder="/mnt/usb/shared-certs" bind:value={acmeCopyDir} />
          </div>
        </div>

        <div class="form-grid">
          <div class="field">
            <label for="ac-kid">EAB Key ID (ZeroSSL / Google)</label>
            <input id="ac-kid" type="text" class="mono" bind:value={acmeDraft.eab_kid} />
          </div>
          <div class="field">
            <label for="ac-hmac">EAB HMAC Key (Base64URL)</label>
            <input id="ac-hmac" type="password" class="mono" placeholder={secretMaskedHint(acmeDraft.eab_hmac_key, 'Optional')} bind:value={acmeEabKeyInput} />
          </div>
        </div>

        <div style="display:flex;gap:18px;flex-wrap:wrap;">
          <label class="check-row"><input type="checkbox" bind:checked={acmeDraft.enabled} /> {t.enabled}</label>
          <label class="check-row"><input type="checkbox" bind:checked={acmeDraft.use_for_admin} /> Also Use for Admin HTTPS Console</label>
        </div>
      </div>
      <div class="drawer-footer">
        <button type="button" class="btn" onclick={() => acmeDrawerOpen = false}>{t.cancel}</button>
        <button type="submit" class="btn btn-primary">{t.confirm}</button>
      </div>
    </form>
  </div>
{/if}

<!-- STUN 规则抽屉 -->
{#if stunDrawerOpen && stunDraft}
  <div class="drawer-backdrop" role="presentation" onclick={(e) => { if (e.target === e.currentTarget) stunDrawerOpen = false; }}>
    <form class="drawer-panel" onsubmit={saveStun}>
      <div class="drawer-header">
        <div class="card-title">{stunEditIdx >= 0 ? t.edit : t.add} · STUN NAT</div>
        <button type="button" class="btn btn-sm" onclick={() => stunDrawerOpen = false}>{t.cancel}</button>
      </div>
      <div class="drawer-body">
        <div class="form-grid">
          <div class="field">
            <label for="st-name">Rule Name</label>
            <input id="st-name" type="text" class="mono" bind:value={stunDraft.name} required />
          </div>
          <div class="field">
            <label for="st-proto">Protocol</label>
            <select id="st-proto" bind:value={stunDraft.proto}>
              <option value="udp">udp</option>
              <option value="tcp">tcp</option>
            </select>
          </div>
          <div class="field">
            <label for="st-port">Local Port (0 = follow Bound Rule)</label>
            <input id="st-port" type="number" min="0" max="65535" bind:value={stunDraft.local_port} />
          </div>
          <div class="field">
            <label for="st-bind">Bind Local Proxy / Forward Rule</label>
            <select id="st-bind" bind:value={stunDraft.bind_rule}>
              <option value="">— None —</option>
              {#each settingsJson.reverse_proxy || [] as rp}
                <option value={rp.name}>[Proxy] {rp.name} (:{rp.listen_port})</option>
              {/each}
              {#each settingsJson.port_forwards || [] as pf}
                <option value={pf.name}>[Forward] {pf.name} (:{pf.listen_port})</option>
              {/each}
            </select>
          </div>
        </div>

        <div class="field">
          <label for="st-srvs">STUN Servers (host:port, comma separated)</label>
          <input id="st-srvs" type="text" class="mono" bind:value={stunServersCsv} required />
        </div>

        <div class="form-grid">
          <div class="field">
            <label for="st-ka">Keepalive Interval (secs)</label>
            <input id="st-ka" type="number" min="5" max="3600" bind:value={stunDraft.keepalive_secs} />
          </div>
          <div class="field">
            <label for="st-wh">On-Change Webhook URL (optional)</label>
            <input id="st-wh" type="password" class="mono" placeholder={secretMaskedHint(stunDraft.webhook_url, 'https://...')} bind:value={stunWebhookInput} />
          </div>
        </div>

        <div style="display:flex;gap:18px;flex-wrap:wrap;margin-bottom:10px;">
          <label class="check-row"><input type="checkbox" bind:checked={stunDraft.enabled} /> {t.enabled}</label>
          <label class="check-row"><input type="checkbox" bind:checked={stunCfEnabled} /> Sync Cloudflare Redirect Ruleset on Change</label>
        </div>

        {#if stunCfEnabled && stunCfDraft}
          <div class="subcard">
            <div class="form-grid">
              <div class="field">
                <label for="cf-host">Entry Host (e.g. go.example.com)</label>
                <input id="cf-host" type="text" class="mono" bind:value={stunCfDraft.source_host} required />
              </div>
              <div class="field">
                <label for="cf-tpl">Target Template ({'{{public_addr}}'})</label>
                <input id="cf-tpl" type="text" class="mono" bind:value={stunCfDraft.target_template} required />
              </div>
              <div class="field">
                <label for="cf-zid">Zone ID</label>
                <input id="cf-zid" type="text" class="mono" bind:value={stunCfDraft.zone_id} required />
              </div>
              <div class="field">
                <label for="cf-rsid">Ruleset ID</label>
                <input id="cf-rsid" type="text" class="mono" bind:value={stunCfDraft.ruleset_id} required />
              </div>
              <div class="field">
                <label for="cf-rid">Rule ID</label>
                <input id="cf-rid" type="text" class="mono" bind:value={stunCfDraft.rule_id} required />
              </div>
              <div class="field">
                <label for="cf-tok">Cloudflare API Token</label>
                <input id="cf-tok" type="password" class="mono" placeholder={secretMaskedHint(stunCfDraft.api_token, 'Bearer Token')} bind:value={stunCfTokenInput} />
              </div>
            </div>
          </div>
        {/if}
      </div>
      <div class="drawer-footer">
        <button type="button" class="btn" onclick={() => stunDrawerOpen = false}>{t.cancel}</button>
        <button type="submit" class="btn btn-primary">{t.confirm}</button>
      </div>
    </form>
  </div>
{/if}
