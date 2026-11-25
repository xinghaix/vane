<script>
  import Icons from './Icons.svelte';
  import SecretField from './SecretField.svelte';
  import HeaderRowsEditor from './HeaderRowsEditor.svelte';
  import {
    splitCsv,
    joinCsv,
    kvObjectToRows,
    rowsToKvObject,
    deepClone,
    copyText,
    formatUnixTime,
    secretMaskedHint,
    isSecretConfigured,
    resolveSecretInput,
    translateRuntimeStatus,
  } from '../lib/helpers.js';

  let {
    mode = 'ddns',
    t,
    lang,
    settingsJson,
    dashboard,
    networkInfo = null,
    onSaveSettings,
    askConfirm,
    apiFetch,
    showToast,
    onRefresh,
  } = $props();

  let busyKey = $state('');
  let busyToggleKey = $state('');
  let saving = $state(false);
  let searchQuery = $state('');
  let filterStatus = $state('all');

  let ifaceNames = $derived((networkInfo?.interfaces || []).map((i) => i.iface));
  let neighborEntries = $derived(networkInfo?.neighbors || []);

  // 切换 Tab 模式时重置筛选和抽屉，避免跨视图状态泄漏
  $effect(() => {
    void mode;
    searchQuery = '';
    filterStatus = 'all';
    provDrawerOpen = false;
    ddnsDrawerOpen = false;
    acmeDrawerOpen = false;
    stunDrawerOpen = false;
  });

  function providerRefs(id) {
    const usedByDdns = (settingsJson?.ddns || []).filter((d) => d.provider === id).map((d) => d.name);
    const usedByAcme = (settingsJson?.acme || []).filter((a) => a.dns_provider === id).map((a) => a.domain);
    return [...usedByDdns, ...usedByAcme];
  }

  function parsePortListStrict(csv) {
    const raw = splitCsv(csv);
    const out = [];
    for (const token of raw) {
      if (!/^\d+$/.test(token)) return { error: token };
      const num = Number(token);
      if (!Number.isInteger(num) || num < 1 || num > 65535) return { error: token };
      out.push(num);
    }
    return { ports: out };
  }

  async function copyOrToast(val) {
    if (await copyText(val)) showToast(t.copied, 'success');
    else showToast(t.copyFailed, 'error');
  }

  // ---------------- DNS Provider Drawer ----------------
  let provDrawerOpen = $state(false);
  let provEditId = $state('');
  let provDraftId = $state('');
  let provDraft = $state(null);
  let provTokenInput = $state('');
  let provTokenClear = $state(false);
  let provSecretInput = $state('');
  let provSecretClear = $state(false);

  function openProviderDrawer(id = '') {
    provEditId = id;
    provDraftId = id || `cf_${Object.keys(settingsJson?.dns_providers || {}).length + 1}`;
    provDraft = id
      ? deepClone(settingsJson.dns_providers[id])
      : { provider: 'cloudflare', api_token: '', secret_key: '', happy_eyeballs_delay_ms: 250, zone_name: '', zone_id: '' };
    provTokenInput = '';
    provTokenClear = false;
    provSecretInput = '';
    provSecretClear = false;
    provDrawerOpen = true;
  }

  async function saveProvider(e) {
    e.preventDefault();
    if (saving) return;
    const cleanId = provDraftId.trim();
    if (!cleanId) return;
    if (cleanId !== provEditId && settingsJson?.dns_providers?.[cleanId]) {
      showToast(lang === 'en' ? `Provider ID "${cleanId}" already exists` : `服务商 ID "${cleanId}" 已存在，请更换名称`, 'error');
      return;
    }
    if (provDraft.provider === 'cloudflare' && provDraft.zone_id?.trim() && !provDraft.zone_name?.trim()) {
      showToast(lang === 'en' ? 'Zone Name is required when Zone ID is specified' : '填写 Cloudflare Zone ID 时必须同时填写 Zone Name', 'error');
      return;
    }
    saving = true;
    try {
      const orig = provEditId ? settingsJson.dns_providers[provEditId] : null;
      provDraft.api_token = resolveSecretInput(orig?.api_token, provTokenInput, provTokenClear);
      provDraft.secret_key =
        provDraft.provider === 'cloudflare'
          ? ''
          : resolveSecretInput(orig?.secret_key, provSecretInput, provSecretClear);
      if (provDraft.provider !== 'cloudflare') provDraft.zone_id = '';
      provDraft.happy_eyeballs_delay_ms = Number(provDraft.happy_eyeballs_delay_ms || 250);

      const next = deepClone(settingsJson);
      const renames = [];
      if (provEditId && provEditId !== cleanId) {
        delete next.dns_providers[provEditId];
        renames.push({ from: `dns_providers.${provEditId}`, to: `dns_providers.${cleanId}` });
        // 级联更新引用该服务商 ID 的 DDNS 与 ACME 规则
        for (const d of next.ddns || []) {
          if (d.provider === provEditId) d.provider = cleanId;
        }
        for (const a of next.acme || []) {
          if (a.dns_provider === provEditId) a.dns_provider = cleanId;
        }
      }
      next.dns_providers[cleanId] = provDraft;
      if (await onSaveSettings(next, renames)) provDrawerOpen = false;
    } finally {
      saving = false;
    }
  }

  function deleteProvider(id) {
    const refs = providerRefs(id);
    if (refs.length > 0) {
      showToast(
        lang === 'en'
          ? `Cannot delete "${id}": still referenced by ${refs.join(', ')}`
          : `无法删除 "${id}"：仍被 ${refs.join(', ')} 引用，请先调整对应规则`,
        'warn'
      );
      return;
    }
    askConfirm({
      title: t.common.confirmDeleteTitle,
      message: `${id}`,
      confirmLabel: t.delete,
      danger: true,
      onConfirm: async () => {
        const next = deepClone(settingsJson);
        delete next.dns_providers[id];
        await onSaveSettings(next);
      },
    });
  }

  // ---------------- DDNS Rule Drawer ----------------
  let ddnsDrawerOpen = $state(false);
  let ddnsEditIdx = $state(-1);
  let ddnsOrigName = $state('');
  let ddnsDraft = $state(null);
  let ddnsSourceKind = $state('interface');
  let ddnsRecA = $state(true);
  let ddnsRecAAAA = $state(true);
  let ddnsSplitCsv = $state('');
  let ddnsTcpPortsCsv = $state('');
  let ddnsUdpPortsCsv = $state('');
  let ddnsTokenInput = $state('');
  let ddnsTokenClear = $state(false);
  let ddnsHttpUrlInput = $state('');
  let ddnsHttpUrlClear = $state(false);
  let ddnsHttpBodyInput = $state('');
  let ddnsHttpBodyClear = $state(false);
  let ddnsHttpHeaderRows = $state([]);
  let ddnsSrcUrlV4Input = $state('');
  let ddnsSrcUrlV4Clear = $state(false);
  let ddnsSrcUrlV6Input = $state('');
  let ddnsSrcUrlV6Clear = $state(false);
  let ddnsSrcExtractUrlInput = $state('');
  let ddnsSrcExtractUrlClear = $state(false);

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
      custom_http: { method: 'GET', url: '', headers: {}, body: '', success_keyword: '' },
      token: '',
      reconcile_interval_secs: 600,
    };
    if (preset === 'subdevice_v6') {
      d.name = 'nas_ipv6';
      d.domain = 'nas6.example.com';
      d.records = ['AAAA'];
      d.source = { kind: 'prefix_and_iid', prefix_iface: 'br-lan', iid: '::10' };
      d.firewall_allow_tcp_ports = [5001];
    }
    return d;
  }

  function openDdnsDrawer(idx = -1, preset = 'wan', cloneFrom = null) {
    ddnsEditIdx = idx;
    const d = cloneFrom
      ? deepClone(cloneFrom)
      : idx >= 0
        ? deepClone(settingsJson.ddns[idx])
        : defaultDdns(preset);
    if (cloneFrom) {
      d.name = `${d.name}_copy`;
      d.domain = `copy-${d.domain}`;
      d.token = '';
      if (d.custom_http) {
        d.custom_http.url = '';
        d.custom_http.body = '';
        d.custom_http.headers = {};
      }
      if (d.source?.kind === 'external_url') {
        d.source.url_v4 = '';
        d.source.url_v6 = '';
      } else if (d.source?.kind === 'custom_http_extract') {
        d.source.url = '';
      }
    }
    ddnsOrigName = idx >= 0 ? d.name : '';
    ddnsDraft = d;
    ddnsSourceKind = d.source?.kind || 'interface';
    ddnsRecA = d.records?.includes('A') ?? true;
    ddnsRecAAAA = d.records?.includes('AAAA') ?? true;
    ddnsSplitCsv = joinCsv(d.split_dns_lan_ips);
    ddnsTcpPortsCsv = joinCsv(d.firewall_allow_tcp_ports);
    ddnsUdpPortsCsv = joinCsv(d.firewall_allow_udp_ports);
    ddnsTokenInput = '';
    ddnsTokenClear = false;
    ddnsHttpUrlInput = '';
    ddnsHttpUrlClear = false;
    ddnsHttpBodyInput = '';
    ddnsHttpBodyClear = false;
    ddnsHttpHeaderRows = kvObjectToRows(d.custom_http?.headers);
    ddnsSrcUrlV4Input = '';
    ddnsSrcUrlV4Clear = false;
    ddnsSrcUrlV6Input = '';
    ddnsSrcUrlV6Clear = false;
    ddnsSrcExtractUrlInput = '';
    ddnsSrcExtractUrlClear = false;
    ddnsDrawerOpen = true;
  }

  function onDdnsSourceKindChange() {
    if (ddnsSourceKind === 'interface') ddnsDraft.source = { kind: 'interface', name: 'pppoe-wan', preferred_subnet: '', index: 0 };
    else if (ddnsSourceKind === 'prefix_and_iid') ddnsDraft.source = { kind: 'prefix_and_iid', prefix_iface: 'br-lan', iid: '::10' };
    else if (ddnsSourceKind === 'neighbor_mac') ddnsDraft.source = { kind: 'neighbor_mac', prefix_iface: 'br-lan', mac: '00:11:32:aa:bb:cc' };
    else if (ddnsSourceKind === 'external_url') ddnsDraft.source = { kind: 'external_url', url_v4: '', url_v6: '' };
    else ddnsDraft.source = { kind: 'custom_http_extract', url: '' };
  }

  let selectedDdnsProviderKind = $derived(
    ddnsDraft?.provider === 'custom_http'
      ? 'custom_http'
      : settingsJson?.dns_providers?.[ddnsDraft?.provider]?.provider || ''
  );

  async function saveDdns(e) {
    e.preventDefault();
    if (saving) return;
    const recs = [];
    if (ddnsRecA) recs.push('A');
    if (ddnsRecAAAA) recs.push('AAAA');
    if (recs.length === 0) {
      showToast(lang === 'en' ? 'Select at least one record type (A or AAAA)' : '请至少勾选 A 或 AAAA 记录类型之一', 'error');
      return;
    }
    if (ddnsDraft.provider === 'custom_http' && ddnsDraft.on_missing_public_ip === 'delete_record') {
      showToast(lang === 'en' ? 'custom_http does not support delete_record; use keep_existing' : 'custom_http 不支持 delete_record，请选择 keep_existing', 'error');
      return;
    }
    const splitList = splitCsv(ddnsSplitCsv);
    if (ddnsDraft.domain?.trim().startsWith('*.') && splitList.length > 0) {
      showToast(lang === 'en' ? 'Split-DNS does not support wildcard domains' : 'Split-DNS 不支持通配符域名', 'error');
      return;
    }
    const tcpParsed = parsePortListStrict(ddnsTcpPortsCsv);
    if (tcpParsed.error) {
      showToast(lang === 'en' ? `Invalid TCP port: ${tcpParsed.error}` : `非法 TCP 端口: ${tcpParsed.error}（需 1~65535 整数）`, 'error');
      return;
    }
    const udpParsed = parsePortListStrict(ddnsUdpPortsCsv);
    if (udpParsed.error) {
      showToast(lang === 'en' ? `Invalid UDP port: ${udpParsed.error}` : `非法 UDP 端口: ${udpParsed.error}（需 1~65535 整数）`, 'error');
      return;
    }
    saving = true;
    try {
      const orig = ddnsEditIdx >= 0 ? settingsJson.ddns[ddnsEditIdx] : null;
      ddnsDraft.name = String(ddnsDraft.name || '').trim();
      ddnsDraft.domain = String(ddnsDraft.domain || '').trim();
      ddnsDraft.records = recs;
      ddnsDraft.split_dns_lan_ips = splitList;
      ddnsDraft.firewall_allow_tcp_ports = tcpParsed.ports;
      ddnsDraft.firewall_allow_udp_ports = udpParsed.ports;
      ddnsDraft.ttl = Number(ddnsDraft.ttl || 300);
      ddnsDraft.reconcile_interval_secs = Number(ddnsDraft.reconcile_interval_secs || 600);
      if (ddnsDraft.source.kind === 'interface') {
        ddnsDraft.source.index = Number(ddnsDraft.source.index || 0);
      }
      ddnsDraft.token = resolveSecretInput(orig?.token, ddnsTokenInput, ddnsTokenClear);
      ddnsDraft.custom_http.url = resolveSecretInput(orig?.custom_http?.url, ddnsHttpUrlInput, ddnsHttpUrlClear);
      ddnsDraft.custom_http.body = resolveSecretInput(orig?.custom_http?.body, ddnsHttpBodyInput, ddnsHttpBodyClear);
      ddnsDraft.custom_http.headers = rowsToKvObject(ddnsHttpHeaderRows, true);

      if (ddnsDraft.source.kind === 'external_url') {
        const origSrc = orig?.source?.kind === 'external_url' ? orig.source : null;
        ddnsDraft.source.url_v4 = resolveSecretInput(origSrc?.url_v4, ddnsSrcUrlV4Input, ddnsSrcUrlV4Clear);
        ddnsDraft.source.url_v6 = resolveSecretInput(origSrc?.url_v6, ddnsSrcUrlV6Input, ddnsSrcUrlV6Clear);
      } else if (ddnsDraft.source.kind === 'custom_http_extract') {
        const origSrc = orig?.source?.kind === 'custom_http_extract' ? orig.source : null;
        ddnsDraft.source.url = resolveSecretInput(origSrc?.url, ddnsSrcExtractUrlInput, ddnsSrcExtractUrlClear);
      }

      const next = deepClone(settingsJson);
      const renames = [];
      if (ddnsEditIdx >= 0) {
        if (ddnsOrigName && ddnsOrigName !== ddnsDraft.name) {
          renames.push({ from: `ddns.${ddnsOrigName}`, to: `ddns.${ddnsDraft.name}` });
        }
        next.ddns[ddnsEditIdx] = ddnsDraft;
      } else {
        next.ddns.push(ddnsDraft);
      }
      if (await onSaveSettings(next, renames)) ddnsDrawerOpen = false;
    } finally {
      saving = false;
    }
  }

  async function toggleDdnsEnabled(idx) {
    const key = `ddns:${idx}`;
    if (busyToggleKey) return;
    busyToggleKey = key;
    try {
      const next = deepClone(settingsJson);
      next.ddns[idx].enabled = !next.ddns[idx].enabled;
      await onSaveSettings(next);
    } finally {
      busyToggleKey = '';
    }
  }

  function deleteDdns(idx) {
    const d = settingsJson.ddns[idx];
    askConfirm({
      title: t.common.confirmDeleteTitle,
      message: `${d.name} (${d.domain})`,
      confirmLabel: t.delete,
      danger: true,
      onConfirm: async () => {
        const next = deepClone(settingsJson);
        next.ddns.splice(idx, 1);
        await onSaveSettings(next);
      },
    });
  }

  async function triggerDdnsSync(name) {
    busyKey = `ddns:${name}`;
    try {
      const st = await apiFetch(`/api/ddns/${encodeURIComponent(name)}/sync`, { method: 'POST' });
      showToast(`${name}: ${st.status}`, st.status === 'synced' ? 'success' : 'warn');
      await onRefresh();
    } catch (err) {
      showToast(err.message, 'error');
      await onRefresh();
    } finally {
      busyKey = '';
    }
  }

  // ---------------- ACME Drawer ----------------
  const PRESET_CA = new Set(['letsencrypt', 'letsencrypt_staging', 'zerossl', 'buypass', 'google']);
  let acmeDrawerOpen = $state(false);
  let acmeEditIdx = $state(-1);
  let acmeOrigDomain = $state('');
  let acmeDraft = $state(null);
  let acmeCaChoice = $state('letsencrypt');
  let acmeExtraCsv = $state('');
  let acmeEabKeyInput = $state('');
  let acmeEabKeyClear = $state(false);
  let acmeCopyDirs = $state([]); // string[] — 保留全部 copy_to_dir 钩子
  let acmeHookEdits = $state([]); // [{ origIdx, urlOrig, urlInput, urlClear, include_private_key }]

  function openAcmeDrawer(idx = -1, cloneFrom = null) {
    acmeEditIdx = idx;
    const firstProv = Object.keys(settingsJson?.dns_providers || {})[0] || '';
    const a = cloneFrom
      ? deepClone(cloneFrom)
      : idx >= 0
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
    if (cloneFrom) {
      a.domain = `copy-${a.domain}`;
      a.use_for_admin = false;
      a.eab_hmac_key = '';
      a.deploy_hooks = (a.deploy_hooks || []).filter((h) => h.kind === 'copy_to_dir');
    }
    acmeOrigDomain = idx >= 0 ? a.domain : '';
    acmeDraft = a;
    acmeCaChoice = PRESET_CA.has(a.directory_url) ? a.directory_url : 'custom';
    acmeExtraCsv = joinCsv(a.extra_domains);
    acmeEabKeyInput = '';
    acmeEabKeyClear = false;
    acmeCopyDirs = (a.deploy_hooks || [])
      .filter((h) => h.kind === 'copy_to_dir')
      .map((h) => h.dir || '');
    acmeHookEdits = (a.deploy_hooks || [])
      .map((h, i) => ({ h, i }))
      .filter(({ h }) => h.kind === 'webhook')
      .map(({ h, i }) => ({
        origIdx: i,
        urlOrig: h.url,
        urlInput: '',
        urlClear: false,
        include_private_key: Boolean(h.include_private_key),
      }));
    acmeDrawerOpen = true;
  }

  function addAcmeCopyDir() {
    acmeCopyDirs = [...acmeCopyDirs, ''];
  }

  function removeAcmeCopyDir(idx) {
    acmeCopyDirs = acmeCopyDirs.filter((_, i) => i !== idx);
  }

  function addAcmeWebhook() {
    acmeHookEdits = [
      ...acmeHookEdits,
      { origIdx: -1, urlOrig: '', urlInput: '', urlClear: false, include_private_key: false },
    ];
  }

  function removeAcmeWebhook(idx) {
    acmeHookEdits = acmeHookEdits.filter((_, i) => i !== idx);
  }

  async function saveAcme(e) {
    e.preventDefault();
    if (saving) return;
    if (!acmeDraft.dns_provider) {
      showToast(lang === 'en' ? 'Add and select a DNS Provider account first' : '请先在上方添加并选择 DNS 服务商账号', 'error');
      return;
    }
    const orig = acmeEditIdx >= 0 ? settingsJson.acme[acmeEditIdx] : null;
    const resolvedEabKey = resolveSecretInput(orig?.eab_hmac_key, acmeEabKeyInput, acmeEabKeyClear);
    const hasKid = Boolean(acmeDraft.eab_kid?.trim());
    const hasHmac = Boolean(resolvedEabKey);
    if (hasKid !== hasHmac) {
      showToast(lang === 'en' ? 'EAB Key ID and HMAC Key must both be configured or both empty' : 'EAB Key ID 与 HMAC Key 必须同时配置或同时留空', 'error');
      return;
    }
    if (
      acmeDraft.enabled &&
      acmeDraft.use_for_admin &&
      (settingsJson?.acme || []).some((other, i) => i !== acmeEditIdx && other.enabled && other.use_for_admin)
    ) {
      showToast(lang === 'en' ? 'Only one enabled ACME rule can be used for Admin HTTPS' : '最多只允许一条已启用 ACME 规则用作管理后台证书', 'error');
      return;
    }
    for (let i = 0; i < acmeHookEdits.length; i++) {
      const wh = acmeHookEdits[i];
      const u = resolveSecretInput(wh.urlOrig, wh.urlInput, wh.urlClear);
      if (!u) {
        showToast(lang === 'en' ? `Webhook #${i + 1} URL is required` : `Webhook #${i + 1} URL 不能为空`, 'error');
        return;
      }
      if (wh.include_private_key && wh.urlInput.trim() && !wh.urlInput.trim().startsWith('https://')) {
        showToast(lang === 'en' ? `Webhook #${i + 1} with private key must use https://` : `携带私钥的 Webhook #${i + 1} 必须使用 https://`, 'error');
        return;
      }
    }

    saving = true;
    try {
      acmeDraft.domain = String(acmeDraft.domain || '').trim();
      acmeDraft.extra_domains = splitCsv(acmeExtraCsv);
      acmeDraft.renew_before_days = Number(acmeDraft.renew_before_days || 30);
      acmeDraft.propagation_timeout_secs = Number(acmeDraft.propagation_timeout_secs || 180);
      acmeDraft.eab_hmac_key = resolvedEabKey;

      const renames = [];
      const oldDomainPrefix = `acme.${acmeOrigDomain || acmeDraft.domain}`;
      const newDomainPrefix = `acme.${acmeDraft.domain}`;

      // 先推送具体的 webhook 索引前移重命名，再推送外层域名重命名，确保精准匹配不串位
      const builtHooks = acmeHookEdits.map((wh, newIdx) => {
        if (wh.origIdx >= 0 && (wh.origIdx !== newIdx || (acmeOrigDomain && acmeOrigDomain !== acmeDraft.domain)) && acmeEditIdx >= 0) {
          renames.push({
            from: `${oldDomainPrefix}.deploy_hooks.${wh.origIdx}.url`,
            to: `${newDomainPrefix}.deploy_hooks.${newIdx}.url`,
          });
        }
        return {
          kind: 'webhook',
          url: resolveSecretInput(wh.urlOrig, wh.urlInput, wh.urlClear),
          include_private_key: wh.include_private_key,
        };
      });
      if (acmeEditIdx >= 0 && acmeOrigDomain && acmeOrigDomain !== acmeDraft.domain) {
        renames.push({ from: `acme.${acmeOrigDomain}`, to: `acme.${acmeDraft.domain}` });
      }
      for (const dir of acmeCopyDirs) {
        const clean = String(dir || '').trim();
        if (clean) builtHooks.push({ kind: 'copy_to_dir', dir: clean });
      }
      acmeDraft.deploy_hooks = builtHooks;

      const next = deepClone(settingsJson);
      if (acmeEditIdx >= 0) next.acme[acmeEditIdx] = acmeDraft;
      else next.acme.push(acmeDraft);
      if (await onSaveSettings(next, renames)) acmeDrawerOpen = false;
    } finally {
      saving = false;
    }
  }

  async function toggleAcmeEnabled(idx) {
    const key = `acme:${idx}`;
    if (busyToggleKey) return;
    busyToggleKey = key;
    try {
      const next = deepClone(settingsJson);
      next.acme[idx].enabled = !next.acme[idx].enabled;
      await onSaveSettings(next);
    } finally {
      busyToggleKey = '';
    }
  }

  function deleteAcme(idx) {
    const a = settingsJson.acme[idx];
    askConfirm({
      title: t.common.confirmDeleteTitle,
      message: a.domain,
      confirmLabel: t.delete,
      danger: true,
      onConfirm: async () => {
        const next = deepClone(settingsJson);
        next.acme.splice(idx, 1);
        await onSaveSettings(next);
      },
    });
  }

  async function triggerAcmeIssue(domain) {
    busyKey = `acme:${domain}`;
    try {
      const st = await apiFetch(`/api/acme/${encodeURIComponent(domain)}/issue`, { method: 'POST' });
      showToast(`${domain}: ${st.status}`, st.status === 'active' ? 'success' : 'warn');
      await onRefresh();
    } catch (err) {
      showToast(err.message, 'error');
      await onRefresh();
    } finally {
      busyKey = '';
    }
  }

  // ---------------- STUN Drawer ----------------
  let stunDrawerOpen = $state(false);
  let stunEditIdx = $state(-1);
  let stunOrigName = $state('');
  let stunDraft = $state(null);
  let stunServersCsv = $state('');
  let stunWebhookInput = $state('');
  let stunWebhookClear = $state(false);
  let stunCfEnabled = $state(false);
  let stunCfDraft = $state(null);
  let stunCfTokenInput = $state('');
  let stunCfTokenClear = $state(false);

  function openStunDrawer(idx = -1, cloneFrom = null) {
    stunEditIdx = idx;
    const s = cloneFrom
      ? deepClone(cloneFrom)
      : idx >= 0
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
    if (cloneFrom) {
      s.name = `${s.name}_copy`;
      s.webhook_url = '';
      if (s.on_change_cloudflare_redirect) s.on_change_cloudflare_redirect.api_token = '';
    }
    stunOrigName = idx >= 0 ? s.name : '';
    stunDraft = s;
    const allSrvs = s.stun_servers?.length ? s.stun_servers : s.stun_server ? [s.stun_server] : [];
    stunServersCsv = joinCsv(allSrvs);
    stunWebhookInput = '';
    stunWebhookClear = false;
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
    stunCfTokenClear = false;
    stunDrawerOpen = true;
  }

  function resolveBoundRulePort(ruleName) {
    if (!ruleName) return null;
    const rp = (settingsJson?.reverse_proxy || []).find((r) => r.name === ruleName);
    if (rp) return rp.listen_port;
    const pf = (settingsJson?.port_forwards || []).find((p) => p.name === ruleName);
    if (pf) return pf.listen_port;
    return null;
  }

  let stunBindRuleDangling = $derived(
    Boolean(stunDraft?.bind_rule) && resolveBoundRulePort(stunDraft.bind_rule) === null
  );

  async function saveStun(e) {
    e.preventDefault();
    if (saving) return;
    saving = true;
    try {
      const orig = stunEditIdx >= 0 ? settingsJson.stun[stunEditIdx] : null;
      const srvs = splitCsv(stunServersCsv);
      stunDraft.stun_servers = srvs;
      stunDraft.stun_server = srvs[0] || '';
      stunDraft.local_port = Number(stunDraft.local_port || 0);
      stunDraft.keepalive_secs = Number(stunDraft.keepalive_secs || 25);
      stunDraft.webhook_url = resolveSecretInput(orig?.webhook_url, stunWebhookInput, stunWebhookClear);

      if (stunCfEnabled) {
        stunCfDraft.status_code = Number(stunCfDraft.status_code || 302);
        stunCfDraft.api_token = resolveSecretInput(
          orig?.on_change_cloudflare_redirect?.api_token,
          stunCfTokenInput,
          stunCfTokenClear
        );
        stunDraft.on_change_cloudflare_redirect = stunCfDraft;
      } else {
        stunDraft.on_change_cloudflare_redirect = null;
      }

      const next = deepClone(settingsJson);
      const renames = [];
      if (stunEditIdx >= 0) {
        if (stunOrigName && stunOrigName !== stunDraft.name) {
          renames.push({ from: `stun.${stunOrigName}`, to: `stun.${stunDraft.name}` });
        }
        next.stun[stunEditIdx] = stunDraft;
      } else {
        next.stun.push(stunDraft);
      }
      if (await onSaveSettings(next, renames)) stunDrawerOpen = false;
    } finally {
      saving = false;
    }
  }

  async function toggleStunEnabled(idx) {
    const key = `stun:${idx}`;
    if (busyToggleKey) return;
    busyToggleKey = key;
    try {
      const next = deepClone(settingsJson);
      next.stun[idx].enabled = !next.stun[idx].enabled;
      await onSaveSettings(next);
    } finally {
      busyToggleKey = '';
    }
  }

  function deleteStun(idx) {
    const s = settingsJson.stun[idx];
    askConfirm({
      title: t.common.confirmDeleteTitle,
      message: s.name,
      confirmLabel: t.delete,
      danger: true,
      onConfirm: async () => {
        const next = deepClone(settingsJson);
        next.stun.splice(idx, 1);
        await onSaveSettings(next);
      },
    });
  }

  async function triggerStunProbe(name) {
    busyKey = `stun:${name}`;
    try {
      const r = await apiFetch(`/api/stun/${encodeURIComponent(name)}/probe`, { method: 'POST' });
      if (r.status === 'degraded') {
        showToast(`${name} → ${r.public_addr} (${r.error || translateRuntimeStatus('degraded', t)})`, 'warn');
      } else {
        showToast(`${name} → ${r.public_addr}`, 'success');
      }
      await onRefresh();
    } catch (err) {
      showToast(err.message, 'error');
      await onRefresh();
    } finally {
      busyKey = '';
    }
  }

  function certDaysRemaining(unixSecs) {
    if (!unixSecs) return null;
    return Math.floor((unixSecs - Math.floor(Date.now() / 1000)) / 86400);
  }

  let filteredDdns = $derived(
    (settingsJson?.ddns || [])
      .map((d, idx) => ({ d, idx }))
      .filter(({ d }) => {
        if (filterStatus === 'enabled' && !d.enabled) return false;
        if (filterStatus === 'disabled' && d.enabled) return false;
        if (!searchQuery.trim()) return true;
        return `${d.name} ${d.domain} ${d.provider}`.toLowerCase().includes(searchQuery.trim().toLowerCase());
      })
  );

  let filteredAcme = $derived(
    (settingsJson?.acme || [])
      .map((a, idx) => ({ a, idx }))
      .filter(({ a }) => {
        if (filterStatus === 'enabled' && !a.enabled) return false;
        if (filterStatus === 'disabled' && a.enabled) return false;
        if (!searchQuery.trim()) return true;
        return `${a.domain} ${(a.extra_domains || []).join(' ')} ${a.dns_provider} ${a.directory_url}`
          .toLowerCase()
          .includes(searchQuery.trim().toLowerCase());
      })
  );

  let filteredStun = $derived(
    (settingsJson?.stun || [])
      .map((s, idx) => ({ s, idx }))
      .filter(({ s }) => {
        if (filterStatus === 'enabled' && !s.enabled) return false;
        if (filterStatus === 'disabled' && s.enabled) return false;
        if (!searchQuery.trim()) return true;
        return `${s.name} ${s.proto} ${s.bind_rule} ${s.stun_server}`
          .toLowerCase()
          .includes(searchQuery.trim().toLowerCase());
      })
  );
</script>

<svelte:window
  onkeydown={(e) => {
    if (e.key === 'Escape' && !e.defaultPrevented && !saving) {
      if (provDrawerOpen) provDrawerOpen = false;
      else if (ddnsDrawerOpen) ddnsDrawerOpen = false;
      else if (acmeDrawerOpen) acmeDrawerOpen = false;
      else if (stunDrawerOpen) stunDrawerOpen = false;
    }
  }}
/>

<datalist id="ddns-iface-list">
  {#each ifaceNames as name}
    <option value={name}></option>
  {/each}
</datalist>
<datalist id="ddns-mac-list">
  {#each neighborEntries as nb}
    <option value={nb.mac}>{nb.iface} · {nb.ip}</option>
  {/each}
</datalist>

<!-- ===================== DNS 云服务商凭据池（DDNS 与 ACME 页面共享展示） ===================== -->
{#if settingsJson && (mode === 'ddns' || mode === 'acme')}
  <div class="card" style="margin-bottom:16px;">
    <div class="card-header">
      <div>
        <div class="card-title">{t.dns.poolTitle}</div>
        <div style="font-size:12px;color:var(--text-secondary);">{t.dns.poolDesc}</div>
      </div>
      <button type="button" class="btn btn-sm" onclick={() => openProviderDrawer('')}>
        <Icons name="plus" size={14} />
        <span>{t.dns.addAccount}</span>
      </button>
    </div>

    {#if !Object.keys(settingsJson.dns_providers || {}).length}
      <div class="empty-state" style="padding:18px;">{t.dns.emptyPool}</div>
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
{/if}

<!-- ===================== DDNS ===================== -->
{#if settingsJson && mode === 'ddns'}
  <div class="card">
    <div class="card-header">
      <div>
        <div class="card-title">{t.nav.ddns}</div>
        <div style="font-size:12px;color:var(--text-secondary);">{t.ddns.subtitle}</div>
      </div>
      <div class="btn-group">
        <button type="button" class="btn btn-xs" onclick={() => openDdnsDrawer(-1, 'subdevice_v6')}>+ {t.ddns.presetSubdevice}</button>
        <button type="button" class="btn btn-primary btn-sm" onclick={() => openDdnsDrawer(-1, 'wan')}>
          <Icons name="plus" size={14} />
          <span>{t.add}</span>
        </button>
      </div>
    </div>

    {#if settingsJson.ddns?.length}
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

    {#if !settingsJson.ddns?.length}
      <div class="empty-state">{t.common.empty}</div>
    {:else if !filteredDdns.length}
      <div class="empty-state">{t.common.noMatches}</div>
    {:else}
      <div style="display:grid;gap:12px;">
        {#each filteredDdns as { d, idx } (d.name)}
          {@const rt = (dashboard?.ddns || []).find((x) => x.name === d.name)}
          {@const ddnsErrors = [rt?.ipv4?.error ? `IPv4: ${rt.ipv4.error}` : '', rt?.ipv6?.error ? `IPv6: ${rt.ipv6.error}` : '', rt?.firewall_error ? `FW: ${rt.firewall_error}` : ''].filter(Boolean)}
          <div class="subcard">
            <div class="row-between">
              <div style="min-width:0;flex:1;">
                <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                  <span class="status-dot {d.enabled ? (rt?.status === 'failed' ? 'danger' : rt?.status === 'synced' ? 'ok' : 'warn') : 'muted'}"></span>
                  <span style="font-weight:700;font-size:15px;word-break:break-all;" class="mono">{d.domain}</span>
                  <span class="badge badge-muted">{d.name}</span>
                  <span class="badge badge-info">{d.provider} ({d.records.join('+')})</span>
                  {#if rt}
                    <span class="badge {rt.status === 'synced' ? 'badge-ok' : rt.status === 'failed' ? 'badge-danger' : 'badge-warn'}">{translateRuntimeStatus(rt.status, t)}</span>
                  {/if}
                </div>
                <div class="mono" style="font-size:12px;color:var(--text-secondary);margin-top:6px;word-break:break-all;">
                  Source: {d.source.kind}
                  {#if rt?.last_ipv4} · A={rt.last_ipv4}{/if}
                  {#if rt?.ipv4?.action && rt.ipv4.action !== 'disabled'} ({rt.ipv4.action}){/if}
                  {#if rt?.last_ipv6} · AAAA={rt.last_ipv6}{/if}
                  {#if rt?.ipv6?.action && rt.ipv6.action !== 'disabled'} ({rt.ipv6.action}){/if}
                  {#if rt?.last_sync_unix} · {formatUnixTime(rt.last_sync_unix)}{/if}
                </div>
                {#if d.split_dns_lan_ips?.length}
                  <div class="mono" style="font-size:11px;color:var(--info);margin-top:4px;word-break:break-all;">
                    Split-DNS: {d.split_dns_lan_ips.join(', ')}
                  </div>
                {/if}
                {#each ddnsErrors as errLine}
                  <div class="mono" style="font-size:11px;color:var(--danger);margin-top:4px;word-break:break-word;">
                    {errLine}
                  </div>
                {/each}
              </div>
              <div class="btn-group">
                <button
                  type="button"
                  role="switch"
                  aria-checked={d.enabled}
                  aria-label={t.nav.ddns}
                  class="switch"
                  disabled={busyToggleKey === `ddns:${idx}`}
                  onclick={() => toggleDdnsEnabled(idx)}
                >
                  <span class="switch-thumb"></span>
                </button>
                <button
                  type="button"
                  class="btn btn-xs btn-primary"
                  disabled={!d.enabled || busyKey === `ddns:${d.name}`}
                  onclick={() => triggerDdnsSync(d.name)}
                >
                  {busyKey === `ddns:${d.name}` ? '...' : t.ddns.syncNow}
                </button>
                <button type="button" class="btn btn-xs" title={t.clone} onclick={() => openDdnsDrawer(-1, 'wan', d)}>
                  <Icons name="duplicate" size={13} />
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
        <div style="font-size:12px;color:var(--text-secondary);">{t.acme.subtitle}</div>
      </div>
      <button type="button" class="btn btn-primary btn-sm" onclick={() => openAcmeDrawer(-1)}>
        <Icons name="plus" size={14} />
        <span>{t.add}</span>
      </button>
    </div>

    {#if settingsJson.acme?.length}
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

    {#if !settingsJson.acme?.length}
      <div class="empty-state">{t.common.empty}</div>
    {:else if !filteredAcme.length}
      <div class="empty-state">{t.common.noMatches}</div>
    {:else}
      <div style="display:grid;gap:12px;">
        {#each filteredAcme as { a, idx } (a.domain)}
          {@const st = (dashboard?.certs || []).find((c) => c.domain === a.domain)}
          {@const days = certDaysRemaining(st?.expires_at_unix)}
          <div class="subcard">
            <div class="row-between">
              <div style="min-width:0;flex:1;">
                <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                  <span class="status-dot {a.enabled ? (st?.status === 'active' ? 'ok' : st?.status === 'failed' ? 'danger' : 'warn') : 'muted'}"></span>
                  <span style="font-weight:700;font-size:15px;word-break:break-all;" class="mono">{a.domain}</span>
                  {#if a.extra_domains?.length}
                    <span class="badge badge-muted mono">+{a.extra_domains.length} SAN</span>
                  {/if}
                  <span class="badge badge-info">{a.directory_url}</span>
                  {#if a.deploy_hooks?.length}
                    <span class="badge badge-muted">{a.deploy_hooks.length} Hook</span>
                  {/if}
                  {#if a.use_for_admin}<span class="badge badge-warn">Admin Panel</span>{/if}
                  {#if st}
                    <span class="badge {st.status === 'active' ? (days !== null && days <= 14 ? 'badge-warn' : 'badge-ok') : st.status === 'failed' ? 'badge-danger' : 'badge-warn'}">
                      {translateRuntimeStatus(st.status, t)}{days !== null ? ` (${days}d)` : ''}
                    </span>
                  {/if}
                </div>
                <div class="mono" style="font-size:12px;color:var(--text-secondary);margin-top:6px;word-break:break-all;">
                  DNS: {a.dns_provider} · Renew &lt; {a.renew_before_days}d
                  {#if st?.expires_at_unix} · {t.dash.expires}: {formatUnixTime(st.expires_at_unix)}{/if}
                </div>
                {#if st?.challenge_record}
                  <div class="mono" style="font-size:11px;color:var(--info);margin-top:4px;word-break:break-all;">
                    DNS-01 TXT: {st.challenge_record}
                  </div>
                {/if}
                {#if st?.last_error}
                  <div class="mono" style="font-size:11px;color:var(--danger);margin-top:4px;word-break:break-word;">{st.last_error}</div>
                {/if}
              </div>
              <div class="btn-group">
                <button
                  type="button"
                  role="switch"
                  aria-checked={a.enabled}
                  aria-label={t.nav.acme}
                  class="switch"
                  disabled={busyToggleKey === `acme:${idx}`}
                  onclick={() => toggleAcmeEnabled(idx)}
                >
                  <span class="switch-thumb"></span>
                </button>
                <button
                  type="button"
                  class="btn btn-xs btn-primary"
                  disabled={!a.enabled || busyKey === `acme:${a.domain}`}
                  onclick={() => triggerAcmeIssue(a.domain)}
                >
                  {busyKey === `acme:${a.domain}` ? '...' : t.acme.issueNow}
                </button>
                <button type="button" class="btn btn-xs" title={t.clone} onclick={() => openAcmeDrawer(-1, a)}>
                  <Icons name="duplicate" size={13} />
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
        <div style="font-size:12px;color:var(--text-secondary);">{t.stun.subtitle}</div>
      </div>
      <button type="button" class="btn btn-primary btn-sm" onclick={() => openStunDrawer(-1)}>
        <Icons name="plus" size={14} />
        <span>{t.add}</span>
      </button>
    </div>

    {#if settingsJson.stun?.length}
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

    {#if !settingsJson.stun?.length}
      <div class="empty-state">{t.common.empty}</div>
    {:else if !filteredStun.length}
      <div class="empty-state">{t.common.noMatches}</div>
    {:else}
      <div style="display:grid;gap:12px;">
        {#each filteredStun as { s, idx } (s.name)}
          {@const st = (dashboard?.stun || []).find((x) => x.name === s.name)}
          {@const pubAddr = st?.public_addr || dashboard?.stun_public_addrs?.[s.name] || ''}
          {@const boundPort = resolveBoundRulePort(s.bind_rule)}
          <div class="subcard">
            <div class="row-between">
              <div style="min-width:0;flex:1;">
                <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                  <span class="status-dot {s.enabled ? (st?.status === 'active' ? 'ok' : st?.status === 'error' ? 'danger' : 'warn') : 'muted'}"></span>
                  <span style="font-weight:700;font-size:15px;">{s.name}</span>
                  <span class="badge badge-info mono">
                    {s.proto.toUpperCase()} :{s.local_port || boundPort || 'auto'}
                  </span>
                  {#if s.bind_rule}<span class="badge badge-muted">Bind: {s.bind_rule}</span>{/if}
                  {#if s.on_change_cloudflare_redirect}<span class="badge badge-warn">CF Redirect</span>{/if}
                  {#if st}
                    <span class="badge {st.status === 'active' ? 'badge-ok' : st.status === 'degraded' ? 'badge-warn' : 'badge-danger'}">
                      {translateRuntimeStatus(st.status, t)}
                    </span>
                  {/if}
                </div>
                <div class="mono" style="font-size:13px;color:var(--info);margin-top:6px;word-break:break-all;">
                  Public: {pubAddr || (lang === 'en' ? 'Not probed yet' : '等待探测...')}
                </div>
                {#if st?.server || st?.local_addr || st?.last_probe_unix}
                  <div class="mono" style="font-size:11px;color:var(--text-secondary);margin-top:3px;word-break:break-all;">
                    {#if st.local_addr}Local: {st.local_addr}{/if}
                    {#if st.server} · Server: {st.server}{/if}
                    {#if st.last_probe_unix} · {formatUnixTime(st.last_probe_unix)}{/if}
                  </div>
                {/if}
                {#if st?.error}
                  <div class="mono" style="font-size:11px;color:var(--danger);margin-top:4px;word-break:break-word;">{st.error}</div>
                {/if}
              </div>
              <div class="btn-group">
                <button
                  type="button"
                  role="switch"
                  aria-checked={s.enabled}
                  aria-label={t.nav.stun}
                  class="switch"
                  disabled={busyToggleKey === `stun:${idx}`}
                  onclick={() => toggleStunEnabled(idx)}
                >
                  <span class="switch-thumb"></span>
                </button>
                {#if pubAddr}
                  <button type="button" class="btn btn-xs" onclick={() => copyOrToast(pubAddr)}>
                    {t.copy}
                  </button>
                {/if}
                <button
                  type="button"
                  class="btn btn-xs btn-primary"
                  disabled={!s.enabled || busyKey === `stun:${s.name}`}
                  onclick={() => triggerStunProbe(s.name)}
                >
                  {busyKey === `stun:${s.name}` ? '...' : t.stun.probeNow}
                </button>
                <button type="button" class="btn btn-xs" title={t.clone} onclick={() => openStunDrawer(-1, s)}>
                  <Icons name="duplicate" size={13} />
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
  <div class="drawer-backdrop" role="presentation" onclick={(e) => { if (e.target === e.currentTarget && !saving) provDrawerOpen = false; }}>
    <div class="drawer-panel" role="dialog" aria-modal="true" aria-label={t.dns.addAccount}>
    <form style="display:contents;" onsubmit={saveProvider}>
      <div class="drawer-header">
        <div class="card-title">{provEditId ? t.edit : t.add} · {t.dns.provider}</div>
        <button type="button" class="btn btn-sm" disabled={saving} onclick={() => provDrawerOpen = false}>{t.cancel}</button>
      </div>
      <div class="drawer-body">
        <div class="form-grid">
          <div class="field">
            <label for="dp-id">{t.dns.accountId}</label>
            <input id="dp-id" type="text" class="mono" bind:value={provDraftId} required />
          </div>
          <div class="field">
            <label for="dp-kind">{t.dns.provider}</label>
            <select id="dp-kind" bind:value={provDraft.provider}>
              <option value="cloudflare">cloudflare</option>
              <option value="aliyun">aliyun</option>
              <option value="dnspod">dnspod</option>
            </select>
          </div>
        </div>
        <SecretField
          id="dp-tok"
          label={t.dns.apiToken}
          original={provDraft.api_token}
          bind:value={provTokenInput}
          bind:clear={provTokenClear}
          placeholder="Paste API token"
          required={true}
          {t}
        />
        {#if provDraft.provider !== 'cloudflare'}
          <SecretField
            id="dp-sec"
            label={t.dns.secretKey}
            original={provDraft.secret_key}
            bind:value={provSecretInput}
            bind:clear={provSecretClear}
            placeholder="Paste secret key"
            required={true}
            {t}
          />
        {/if}
        <div class="form-grid">
          <div class="field">
            <label for="dp-zn">{t.dns.zoneName}</label>
            <input
              id="dp-zn"
              type="text"
              class="mono"
              required={provDraft.provider === 'cloudflare' && Boolean(provDraft.zone_id?.trim())}
              bind:value={provDraft.zone_name}
            />
          </div>
          {#if provDraft.provider === 'cloudflare'}
            <div class="field">
              <label for="dp-zid">{t.dns.zoneId}</label>
              <input id="dp-zid" type="text" class="mono" bind:value={provDraft.zone_id} />
            </div>
          {/if}
          <div class="field">
            <label for="dp-he">{t.dns.happyDelay}</label>
            <input id="dp-he" type="number" min="100" max="2000" bind:value={provDraft.happy_eyeballs_delay_ms} />
          </div>
        </div>
      </div>
      <div class="drawer-footer">
        <button type="button" class="btn" disabled={saving} onclick={() => provDrawerOpen = false}>{t.cancel}</button>
        <button type="submit" class="btn btn-primary" disabled={saving}>{saving ? '...' : t.confirm}</button>
      </div>
    </form>
    </div>
  </div>
{/if}

<!-- DDNS 规则抽屉 -->
{#if ddnsDrawerOpen && ddnsDraft}
  <div class="drawer-backdrop" role="presentation" onclick={(e) => { if (e.target === e.currentTarget && !saving) ddnsDrawerOpen = false; }}>
    <div class="drawer-panel" role="dialog" aria-modal="true" aria-label={t.nav.ddns}>
    <form style="display:contents;" onsubmit={saveDdns}>
      <div class="drawer-header">
        <div class="card-title">{ddnsEditIdx >= 0 ? t.edit : t.add} · {t.nav.ddns}</div>
        <button type="button" class="btn btn-sm" disabled={saving} onclick={() => ddnsDrawerOpen = false}>{t.cancel}</button>
      </div>
      <div class="drawer-body">
        <div class="form-grid">
          <div class="field">
            <label for="dd-name">{t.ddns.ruleName}</label>
            <input id="dd-name" type="text" class="mono" bind:value={ddnsDraft.name} required />
          </div>
          <div class="field">
            <label for="dd-dom">{t.ddns.domain}</label>
            <input id="dd-dom" type="text" class="mono" placeholder="home.example.com" bind:value={ddnsDraft.domain} required />
          </div>
          <div class="field">
            <label for="dd-prov">{t.ddns.providerAccount}</label>
            <select id="dd-prov" bind:value={ddnsDraft.provider}>
              {#each Object.keys(settingsJson.dns_providers || {}) as pid}
                <option value={pid}>{pid}</option>
              {/each}
              <option value="custom_http">custom_http</option>
            </select>
          </div>
          <div class="field">
            <label for="dd-src">{t.ddns.sourceMode}</label>
            <select id="dd-src" bind:value={ddnsSourceKind} onchange={onDdnsSourceKindChange}>
              <option value="interface">interface (WAN)</option>
              <option value="prefix_and_iid">prefix_and_iid (PD + IID)</option>
              <option value="neighbor_mac">neighbor_mac (LAN NDP)</option>
              <option value="external_url">external_url</option>
              <option value="custom_http_extract">custom_http_extract</option>
            </select>
          </div>
        </div>

        {#if ddnsDraft.source.kind === 'interface'}
          <div class="form-grid">
            <div class="field">
              <label for="dd-if">{t.ddns.wanIface}</label>
              <input id="dd-if" type="text" class="mono" list="ddns-iface-list" bind:value={ddnsDraft.source.name} required />
            </div>
            <div class="field">
              <label for="dd-sub">{t.ddns.prefSubnet}</label>
              <input id="dd-sub" type="text" class="mono" bind:value={ddnsDraft.source.preferred_subnet} />
            </div>
            <div class="field">
              <label for="dd-idx">{t.ddns.addrIndex}</label>
              <input id="dd-idx" type="number" min="0" max="16" bind:value={ddnsDraft.source.index} />
            </div>
          </div>
        {:else if ddnsDraft.source.kind === 'prefix_and_iid'}
          <div class="form-grid">
            <div class="field">
              <label for="dd-pif">{t.ddns.prefixIface}</label>
              <input id="dd-pif" type="text" class="mono" list="ddns-iface-list" bind:value={ddnsDraft.source.prefix_iface} required />
            </div>
            <div class="field">
              <label for="dd-iid">{t.ddns.fixedIid}</label>
              <input id="dd-iid" type="text" class="mono" bind:value={ddnsDraft.source.iid} required />
            </div>
          </div>
        {:else if ddnsDraft.source.kind === 'neighbor_mac'}
          <div class="form-grid">
            <div class="field">
              <label for="dd-nif">{t.ddns.prefixIface}</label>
              <input id="dd-nif" type="text" class="mono" list="ddns-iface-list" bind:value={ddnsDraft.source.prefix_iface} required />
            </div>
            <div class="field">
              <label for="dd-mac">{t.ddns.targetMac}</label>
              <input id="dd-mac" type="text" class="mono" list="ddns-mac-list" placeholder="00:11:32:aa:bb:cc" bind:value={ddnsDraft.source.mac} required />
            </div>
          </div>
        {:else if ddnsDraft.source.kind === 'external_url'}
          <div class="form-grid">
            <SecretField
              id="dd-uv4"
              label={t.ddns.extUrlV4}
              original={ddnsDraft.source.url_v4}
              bind:value={ddnsSrcUrlV4Input}
              bind:clear={ddnsSrcUrlV4Clear}
              placeholder="https://4.ipw.cn"
              {t}
            />
            <SecretField
              id="dd-uv6"
              label={t.ddns.extUrlV6}
              original={ddnsDraft.source.url_v6}
              bind:value={ddnsSrcUrlV6Input}
              bind:clear={ddnsSrcUrlV6Clear}
              placeholder="https://6.ipw.cn"
              {t}
            />
          </div>
        {:else}
          <SecretField
            id="dd-uex"
            label={t.ddns.extractUrl}
            original={ddnsDraft.source.url}
            bind:value={ddnsSrcExtractUrlInput}
            bind:clear={ddnsSrcExtractUrlClear}
            placeholder="https://..."
            {t}
          />
        {/if}

        {#if ddnsDraft.provider === 'custom_http'}
          <div class="subcard" style="margin-bottom:12px;">
            <div class="form-grid">
              <div class="field">
                <label for="dd-chm">{t.ddns.httpMethod}</label>
                <select id="dd-chm" bind:value={ddnsDraft.custom_http.method}>
                  <option value="GET">GET</option>
                  <option value="POST">POST</option>
                  <option value="PUT">PUT</option>
                </select>
              </div>
              <SecretField
                id="dd-tok"
                label={t.ddns.httpToken}
                original={ddnsDraft.token}
                bind:value={ddnsTokenInput}
                bind:clear={ddnsTokenClear}
                placeholder="Optional"
                {t}
              />
            </div>
            <SecretField
              id="dd-chu"
              label={t.ddns.httpUrl}
              original={ddnsDraft.custom_http?.url}
              bind:value={ddnsHttpUrlInput}
              bind:clear={ddnsHttpUrlClear}
              placeholder="https://..."
              {t}
            />
            <div class="form-grid">
              <SecretField
                id="dd-chb"
                label={t.ddns.httpBody}
                original={ddnsDraft.custom_http?.body}
                bind:value={ddnsHttpBodyInput}
                bind:clear={ddnsHttpBodyClear}
                placeholder="Optional JSON/form body"
                {t}
              />
              <div class="field">
                <label for="dd-chk">{t.ddns.httpKeyword}</label>
                <input id="dd-chk" type="text" class="mono" bind:value={ddnsDraft.custom_http.success_keyword} />
              </div>
            </div>
            <HeaderRowsEditor label={t.ddns.httpHeaders} bind:rows={ddnsHttpHeaderRows} secret={true} {t} />
          </div>
        {/if}

        <div style="display:flex;gap:18px;flex-wrap:wrap;margin-bottom:12px;">
          <label class="check-row"><input type="checkbox" bind:checked={ddnsDraft.enabled} /> {t.enabled}</label>
          <label class="check-row"><input type="checkbox" bind:checked={ddnsRecA} /> A (IPv4)</label>
          <label class="check-row"><input type="checkbox" bind:checked={ddnsRecAAAA} /> AAAA (IPv6)</label>
          {#if selectedDdnsProviderKind === 'cloudflare'}
            <label class="check-row"><input type="checkbox" bind:checked={ddnsDraft.proxied} /> {t.ddns.proxied}</label>
          {/if}
        </div>

        <div class="form-grid">
          {#if ddnsDraft.source.kind === 'prefix_and_iid' || ddnsDraft.source.kind === 'neighbor_mac'}
            <div class="field">
              <label for="dd-fw6">{t.ddns.tcpPorts}</label>
              <input id="dd-fw6" type="text" class="mono" placeholder="5001, 8443" bind:value={ddnsTcpPortsCsv} />
            </div>
            <div class="field">
              <label for="dd-fwu">{t.ddns.udpPorts}</label>
              <input id="dd-fwu" type="text" class="mono" placeholder="51820" bind:value={ddnsUdpPortsCsv} />
            </div>
          {/if}
          {#if !ddnsDraft.domain?.trim().startsWith('*.')}
            <div class="field">
              <label for="dd-split">{t.ddns.splitIps}</label>
              <input id="dd-split" type="text" class="mono" placeholder="192.168.1.10" bind:value={ddnsSplitCsv} />
            </div>
          {/if}
        </div>

        {#if !ddnsDraft.domain?.trim().startsWith('*.') && splitCsv(ddnsSplitCsv).length > 0 && networkInfo?.split_dns_path}
          <div class="banner banner-info" style="margin-bottom:10px;">
            <div style="flex:1;min-width:0;">
              <div style="font-weight:600;">{t.ddns.splitHint}</div>
              <code class="mono" style="font-size:11.5px;word-break:break-all;">addn-hosts={networkInfo.split_dns_path}</code>
            </div>
            <button
              type="button"
              class="btn btn-xs"
              onclick={() => copyOrToast(`addn-hosts=${networkInfo.split_dns_path}`)}
            >
              {t.copy}
            </button>
          </div>
        {/if}

        <details>
          <summary style="cursor:pointer;font-size:13px;font-weight:600;color:var(--text-secondary);padding:6px 0;">
            {t.common.advanced}
          </summary>
          <div class="form-grid" style="padding-top:10px;">
            <div class="field">
              <label for="dd-miss">{t.ddns.missingPolicy}</label>
              <select id="dd-miss" bind:value={ddnsDraft.on_missing_public_ip}>
                <option value="keep_existing">keep_existing</option>
                {#if ddnsDraft.provider !== 'custom_http'}
                  <option value="delete_record">delete_record</option>
                {/if}
              </select>
            </div>
            <div class="field">
              <label for="dd-ttl">{t.ddns.ttl}</label>
              <input id="dd-ttl" type="number" min="1" max="86400" bind:value={ddnsDraft.ttl} />
            </div>
            <div class="field">
              <label for="dd-int">{t.ddns.interval}</label>
              <input id="dd-int" type="number" min="30" max="86400" bind:value={ddnsDraft.reconcile_interval_secs} />
            </div>
            {#if selectedDdnsProviderKind === 'aliyun' || selectedDdnsProviderKind === 'dnspod'}
              <div class="field">
                <label for="dd-line">{t.ddns.line}</label>
                <select id="dd-line" bind:value={ddnsDraft.line}>
                  <option value="default">default</option>
                  <option value="telecom">telecom</option>
                  <option value="unicom">unicom</option>
                  <option value="mobile">mobile</option>
                  <option value="oversea">oversea</option>
                </select>
              </div>
            {/if}
            <div class="field">
              <label for="dd-cmt">{t.ddns.comment}</label>
              <input id="dd-cmt" type="text" bind:value={ddnsDraft.comment} />
            </div>
          </div>
        </details>
      </div>
      <div class="drawer-footer">
        <button type="button" class="btn" disabled={saving} onclick={() => ddnsDrawerOpen = false}>{t.cancel}</button>
        <button type="submit" class="btn btn-primary" disabled={saving}>{saving ? '...' : t.confirm}</button>
      </div>
    </form>
    </div>
  </div>
{/if}

<!-- ACME 证书抽屉 -->
{#if acmeDrawerOpen && acmeDraft}
  <div class="drawer-backdrop" role="presentation" onclick={(e) => { if (e.target === e.currentTarget && !saving) acmeDrawerOpen = false; }}>
    <div class="drawer-panel" role="dialog" aria-modal="true" aria-label={t.nav.acme}>
    <form style="display:contents;" onsubmit={saveAcme}>
      <div class="drawer-header">
        <div class="card-title">{acmeEditIdx >= 0 ? t.edit : t.add} · {t.nav.acme}</div>
        <button type="button" class="btn btn-sm" disabled={saving} onclick={() => acmeDrawerOpen = false}>{t.cancel}</button>
      </div>
      <div class="drawer-body">
        <div class="form-grid">
          <div class="field">
            <label for="ac-dom">{t.acme.primaryDomain}</label>
            <input id="ac-dom" type="text" class="mono" placeholder="*.home.example.com" bind:value={acmeDraft.domain} required />
          </div>
          <div class="field">
            <label for="ac-extra">{t.acme.extraDomains}</label>
            <input id="ac-extra" type="text" class="mono" placeholder="home.example.com" bind:value={acmeExtraCsv} />
          </div>
          <div class="field">
            <label for="ac-prov">{t.acme.dnsProvider}</label>
            <select id="ac-prov" bind:value={acmeDraft.dns_provider} required>
              {#if !Object.keys(settingsJson.dns_providers || {}).length}
                <option value="">{lang === 'en' ? '— Add DNS Provider first —' : '— 请先添加 DNS 账号 —'}</option>
              {/if}
              {#each Object.keys(settingsJson.dns_providers || {}) as pid (pid)}
                <option value={pid}>{pid}</option>
              {/each}
            </select>
          </div>
          <div class="field">
            <label for="ac-ca">{t.acme.caDir}</label>
            <select
              id="ac-ca"
              value={acmeCaChoice}
              onchange={(e) => {
                acmeCaChoice = e.currentTarget.value;
                if (acmeCaChoice !== 'custom') acmeDraft.directory_url = acmeCaChoice;
                else if (PRESET_CA.has(acmeDraft.directory_url)) acmeDraft.directory_url = 'https://';
              }}
            >
              <option value="letsencrypt">Let's Encrypt (Production)</option>
              <option value="letsencrypt_staging">Let's Encrypt (Staging)</option>
              <option value="zerossl">ZeroSSL</option>
              <option value="buypass">Buypass</option>
              <option value="google">Google Trust Services</option>
              <option value="custom">Custom HTTPS Directory</option>
            </select>
          </div>
        </div>

        {#if acmeCaChoice === 'custom'}
          <div class="field">
            <label for="ac-cdir">{t.acme.customCaUrl}</label>
            <input id="ac-cdir" type="url" class="mono" placeholder="https://..." bind:value={acmeDraft.directory_url} required />
          </div>
        {/if}

        <div class="form-grid">
          <div class="field">
            <label for="ac-email">{t.acme.email}</label>
            <input id="ac-email" type="email" bind:value={acmeDraft.email} />
          </div>
          <div class="field">
            <label for="ac-alias">{t.acme.aliasDomain}</label>
            <input id="ac-alias" type="text" class="mono" placeholder="auth.secondary-domain.com" bind:value={acmeDraft.challenge_alias_domain} />
          </div>
          <div class="field">
            <label for="ac-dir">{t.acme.certDir}</label>
            <input id="ac-dir" type="text" class="mono" bind:value={acmeDraft.cert_dir} required />
          </div>
          <div class="field">
            <label for="ac-rdays">{t.acme.renewDays}</label>
            <input id="ac-rdays" type="number" min="7" max="60" bind:value={acmeDraft.renew_before_days} />
          </div>
          <div class="field">
            <label for="ac-pto">{t.acme.propTimeout}</label>
            <input id="ac-pto" type="number" min="10" max="900" bind:value={acmeDraft.propagation_timeout_secs} />
          </div>
        </div>

        <!-- 支持多条 copy_to_dir 部署钩子，不再静默丢失第 2+ 条 -->
        <div style="margin-bottom:12px;">
          <div class="row-between" style="margin-bottom:6px;">
            <span style="font-size:12.5px;font-weight:600;color:var(--text-secondary);">{t.acme.copyDir}</span>
            <button type="button" class="btn btn-xs" onclick={addAcmeCopyDir}>+ {t.add}</button>
          </div>
          {#each acmeCopyDirs as _dir, cIdx (cIdx)}
            <div style="display:flex;gap:8px;margin-bottom:6px;">
              <input
                type="text"
                class="mono control-compact"
                placeholder="/mnt/usb/shared-certs"
                bind:value={acmeCopyDirs[cIdx]}
              />
              <button type="button" class="btn btn-xs btn-danger" onclick={() => removeAcmeCopyDir(cIdx)}>
                <Icons name="trash" size={12} />
              </button>
            </div>
          {/each}
        </div>

        <div class="form-grid">
          <div class="field">
            <label for="ac-kid">{t.acme.eabKid}</label>
            <input id="ac-kid" type="text" class="mono" bind:value={acmeDraft.eab_kid} />
          </div>
          <SecretField
            id="ac-hmac"
            label={t.acme.eabHmac}
            original={acmeDraft.eab_hmac_key}
            bind:value={acmeEabKeyInput}
            bind:clear={acmeEabKeyClear}
            placeholder="Optional Base64URL"
            {t}
          />
        </div>

        <div style="margin-bottom:12px;">
          <div class="row-between" style="margin-bottom:8px;">
            <span style="font-size:13px;font-weight:600;color:var(--text-secondary);">{t.acme.webhooks}</span>
            <button type="button" class="btn btn-xs" onclick={addAcmeWebhook}>+ {t.acme.addWebhook}</button>
          </div>
          {#each acmeHookEdits as wh, wIdx (wIdx)}
            <div class="subcard" style="margin-bottom:8px;">
              <SecretField
                id="ac-wh-{wIdx}"
                label={`Webhook #${wIdx + 1} URL`}
                original={wh.urlOrig}
                bind:value={wh.urlInput}
                bind:clear={wh.urlClear}
                placeholder="https://..."
                required={true}
                {t}
              />
              <div class="row-between">
                <label class="check-row" style="min-height:30px;">
                  <input type="checkbox" bind:checked={wh.include_private_key} /> {t.acme.includePrivKey}
                </label>
                <button type="button" class="btn btn-xs btn-danger" onclick={() => removeAcmeWebhook(wIdx)}>{t.delete}</button>
              </div>
            </div>
          {/each}
        </div>

        <div style="display:flex;gap:18px;flex-wrap:wrap;">
          <label class="check-row"><input type="checkbox" bind:checked={acmeDraft.enabled} /> {t.enabled}</label>
          <label class="check-row"><input type="checkbox" bind:checked={acmeDraft.use_for_admin} /> {t.acme.useForAdmin}</label>
        </div>
      </div>
      <div class="drawer-footer">
        <button type="button" class="btn" disabled={saving} onclick={() => acmeDrawerOpen = false}>{t.cancel}</button>
        <button type="submit" class="btn btn-primary" disabled={saving}>{saving ? '...' : t.confirm}</button>
      </div>
    </form>
    </div>
  </div>
{/if}

<!-- STUN 规则抽屉 -->
{#if stunDrawerOpen && stunDraft}
  <div class="drawer-backdrop" role="presentation" onclick={(e) => { if (e.target === e.currentTarget && !saving) stunDrawerOpen = false; }}>
    <div class="drawer-panel" role="dialog" aria-modal="true" aria-label={t.nav.stun}>
    <form style="display:contents;" onsubmit={saveStun}>
      <div class="drawer-header">
        <div class="card-title">{stunEditIdx >= 0 ? t.edit : t.add} · {t.nav.stun}</div>
        <button type="button" class="btn btn-sm" disabled={saving} onclick={() => stunDrawerOpen = false}>{t.cancel}</button>
      </div>
      <div class="drawer-body">
        <div class="form-grid">
          <div class="field">
            <label for="st-name">{t.stun.ruleName}</label>
            <input id="st-name" type="text" class="mono" bind:value={stunDraft.name} required />
          </div>
          <div class="field">
            <label for="st-proto">{t.stun.proto}</label>
            <select id="st-proto" bind:value={stunDraft.proto}>
              <option value="udp">udp</option>
              <option value="tcp">tcp</option>
            </select>
          </div>
          <div class="field">
            <label for="st-port">{t.stun.localPort}</label>
            <input id="st-port" type="number" min="0" max="65535" bind:value={stunDraft.local_port} />
            {#if stunDraft.bind_rule && Number(stunDraft.local_port) === 0}
              {@const bp = resolveBoundRulePort(stunDraft.bind_rule)}
              {#if bp}
                <div class="field-hint" style="color:var(--accent);">
                  {lang === 'en' ? `Inheriting port :${bp} from ${stunDraft.bind_rule}` : `将自动继承 ${stunDraft.bind_rule} 的端口 :${bp}`}
                </div>
              {/if}
            {/if}
          </div>
          <div class="field">
            <label for="st-bind">{t.stun.bindRule}</label>
            <select
              id="st-bind"
              bind:value={stunDraft.bind_rule}
              onchange={() => {
                if (stunDraft.bind_rule) stunDraft.local_port = 0;
              }}
            >
              <option value="">— None —</option>
              {#if stunBindRuleDangling}
                <option value={stunDraft.bind_rule}>⚠ {stunDraft.bind_rule} ({lang === 'en' ? 'missing' : '规则不存在'})</option>
              {/if}
              {#each settingsJson.reverse_proxy || [] as rp (rp.name)}
                <option value={rp.name}>[Proxy] {rp.name} (:{rp.listen_port})</option>
              {/each}
              {#each settingsJson.port_forwards || [] as pf (pf.name)}
                <option value={pf.name}>[Forward] {pf.name} (:{pf.listen_port})</option>
              {/each}
            </select>
          </div>
        </div>

        <div class="field">
          <label for="st-srvs">{t.stun.servers}</label>
          <input id="st-srvs" type="text" class="mono" bind:value={stunServersCsv} required />
        </div>

        <div class="form-grid">
          <div class="field">
            <label for="st-ka">{t.stun.keepalive}</label>
            <input id="st-ka" type="number" min="5" max="3600" bind:value={stunDraft.keepalive_secs} />
          </div>
          <SecretField
            id="st-wh"
            label={t.stun.webhook}
            original={stunDraft.webhook_url}
            bind:value={stunWebhookInput}
            bind:clear={stunWebhookClear}
            placeholder="https://..."
            {t}
          />
        </div>

        <div style="display:flex;gap:18px;flex-wrap:wrap;margin-bottom:10px;">
          <label class="check-row"><input type="checkbox" bind:checked={stunDraft.enabled} /> {t.enabled}</label>
          <label class="check-row"><input type="checkbox" bind:checked={stunCfEnabled} /> {t.stun.cfSync}</label>
        </div>

        {#if stunCfEnabled && stunCfDraft}
          <div class="subcard">
            <div class="form-grid">
              <div class="field">
                <label for="cf-host">{t.stun.cfHost}</label>
                <input id="cf-host" type="text" class="mono" bind:value={stunCfDraft.source_host} required />
              </div>
              <div class="field">
                <label for="cf-tpl">{t.stun.cfTpl}</label>
                <input id="cf-tpl" type="text" class="mono" bind:value={stunCfDraft.target_template} required />
              </div>
              <div class="field">
                <label for="cf-code">{t.stun.cfCode}</label>
                <select id="cf-code" bind:value={stunCfDraft.status_code}>
                  <option value={301}>301</option>
                  <option value={302}>302</option>
                  <option value={307}>307</option>
                  <option value={308}>308</option>
                </select>
              </div>
              <div class="field">
                <label for="cf-zid">{t.stun.cfZone}</label>
                <input id="cf-zid" type="text" class="mono" bind:value={stunCfDraft.zone_id} required />
              </div>
              <div class="field">
                <label for="cf-rsid">{t.stun.cfRuleset}</label>
                <input id="cf-rsid" type="text" class="mono" bind:value={stunCfDraft.ruleset_id} required />
              </div>
              <div class="field">
                <label for="cf-rid">{t.stun.cfRule}</label>
                <input id="cf-rid" type="text" class="mono" bind:value={stunCfDraft.rule_id} required />
              </div>
            </div>
            <SecretField
              id="cf-tok"
              label={t.stun.cfToken}
              original={stunCfDraft.api_token}
              bind:value={stunCfTokenInput}
              bind:clear={stunCfTokenClear}
              placeholder="Bearer Token"
              required={true}
              {t}
            />
          </div>
        {/if}
      </div>
      <div class="drawer-footer">
        <button type="button" class="btn" disabled={saving} onclick={() => stunDrawerOpen = false}>{t.cancel}</button>
        <button type="submit" class="btn btn-primary" disabled={saving}>{saving ? '...' : t.confirm}</button>
      </div>
    </form>
    </div>
  </div>
{/if}
