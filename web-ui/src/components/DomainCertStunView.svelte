<script>
  import Icons from './Icons.svelte';
  import SecretField from './SecretField.svelte';
  import HeaderRowsEditor from './HeaderRowsEditor.svelte';
  import EditorDialog from './EditorDialog.svelte';
  import Select from './Select.svelte';
  import ComboInput from './ComboInput.svelte';
  import FacetFilter from './FacetFilter.svelte';
  import {
    splitCsv,
    joinCsv,
    kvObjectToRows,
    rowsToKvObject,
    deepClone,
    copyText,
    formatUnixTime,
    secretMaskedHint,
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
  let dnsPoolExpanded = $state(false);

  let ifaceOptions = $derived(
    (networkInfo?.interfaces || []).map((i) => {
      const ips = [...(i.ipv4 || []), ...(i.ipv6 || [])];
      return { value: i.iface, label: i.iface, sub: ips.slice(0, 2).join(', ') };
    })
  );
  let neighborEntries = $derived(networkInfo?.neighbors || []);
  let dnsProviderEntries = $derived(Object.entries(settingsJson?.dns_providers || {}));
  let showDnsPoolBody = $derived(dnsProviderEntries.length === 0 || dnsPoolExpanded);

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

  function formatCount(tpl, fallbackEn, fallbackZh, n) {
    const raw = tpl || (lang === 'en' ? fallbackEn : fallbackZh);
    return String(raw).replace('{n}', String(n));
  }

  function providerRefs(id) {
    const usedByDdns = (settingsJson?.ddns || []).filter((d) => d.provider === id).map((d) => d.name);
    const usedByAcme = (settingsJson?.acme || []).filter((a) => a.dns_provider === id).map((a) => a.domain);
    return [...usedByDdns, ...usedByAcme];
  }

  function formatDdnsSource(kind) {
    const map = t.ddns?.sourceLabels;
    if (map && map[kind]) return map[kind];
    const fallback =
      lang === 'en'
        ? {
            interface: 'WAN Interface',
            prefix_and_iid: 'LAN Prefix + IID',
            neighbor_mac: 'LAN MAC (NDP)',
            external_url: 'External IP URL',
            custom_http_extract: 'HTTP Extract',
          }
        : {
            interface: 'WAN 网卡',
            prefix_and_iid: 'LAN 前缀+后缀',
            neighbor_mac: '内网 MAC',
            external_url: '外部查询接口',
            custom_http_extract: '自定义提取',
          };
    return fallback[kind] || kind;
  }

  function formatCaLabel(url) {
    if (!url) return '—';
    if (url === 'letsencrypt') return "Let's Encrypt";
    if (url === 'letsencrypt_staging') return 'LE Staging';
    if (url === 'zerossl') return 'ZeroSSL';
    if (url === 'buypass') return 'Buypass';
    if (url === 'google') return 'Google Trust';
    try {
      const u = new URL(url);
      return u.host || (t.acme?.caCustom || (lang === 'en' ? 'Custom CA' : '自定义 CA'));
    } catch {
      return url.length > 26 ? `${url.slice(0, 24)}…` : url;
    }
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
    if (await copyText(val)) showToast(`${t.copied}: ${val}`, 'success');
    else showToast(t.copyFailed, 'error');
  }

  function resetFilters() {
    searchQuery = '';
    filterStatus = 'all';
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

  let provEditRefs = $derived(provEditId ? providerRefs(provEditId) : []);

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
      if (await onSaveSettings(next, renames)) {
        provDrawerOpen = false;
        if (acmeDrawerOpen && acmeDraft && !acmeDraft.dns_provider) {
          acmeDraft.dns_provider = cleanId;
        }
      }
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
  let ddnsPreset = $state('wan');
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
    const defaultWan = settingsJson?.firewall?.wan_interfaces?.[0] || '';
    const defaultLan = settingsJson?.firewall?.lan_interfaces?.[0] || '';
    const d = {
      name: `ddns_${(settingsJson?.ddns?.length || 0) + 1}`,
      enabled: true,
      provider: firstProv,
      domain: '',
      records: ['A', 'AAAA'],
      source: { kind: 'interface', name: defaultWan, preferred_subnet: '', index: 0 },
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
      d.records = ['AAAA'];
      d.source = { kind: 'prefix_and_iid', prefix_iface: defaultLan, iid: '' };
      d.firewall_allow_tcp_ports = [5001];
    }
    return d;
  }

  function applyDdnsPreset(preset) {
    ddnsPreset = preset;
    const d = defaultDdns(preset);
    ddnsDraft = d;
    ddnsSourceKind = d.source?.kind || 'interface';
    ddnsRecA = d.records?.includes('A') ?? true;
    ddnsRecAAAA = d.records?.includes('AAAA') ?? true;
    ddnsTcpPortsCsv = joinCsv(d.firewall_allow_tcp_ports);
    ddnsUdpPortsCsv = joinCsv(d.firewall_allow_udp_ports);
  }

  function openDdnsDrawer(idx = -1, preset = 'wan', cloneFrom = null) {
    ddnsEditIdx = idx;
    ddnsPreset = preset;
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
    const defaultWan = settingsJson?.firewall?.wan_interfaces?.[0] || '';
    const defaultLan = settingsJson?.firewall?.lan_interfaces?.[0] || '';
    if (ddnsSourceKind === 'interface') ddnsDraft.source = { kind: 'interface', name: defaultWan, preferred_subnet: '', index: 0 };
    else if (ddnsSourceKind === 'prefix_and_iid') ddnsDraft.source = { kind: 'prefix_and_iid', prefix_iface: defaultLan, iid: '' };
    else if (ddnsSourceKind === 'neighbor_mac') ddnsDraft.source = { kind: 'neighbor_mac', prefix_iface: defaultLan, mac: '' };
    else if (ddnsSourceKind === 'external_url') ddnsDraft.source = { kind: 'external_url', url_v4: '', url_v6: '' };
    else ddnsDraft.source = { kind: 'custom_http_extract', url: '' };
  }

  let selectedDdnsProviderKind = $derived(
    ddnsDraft?.provider === 'custom_http'
      ? 'custom_http'
      : settingsJson?.dns_providers?.[ddnsDraft?.provider]?.provider || ''
  );

  let ddnsAdvancedCount = $derived.by(() => {
    if (!ddnsDraft) return 0;
    let n = 0;
    if (ddnsDraft.on_missing_public_ip && ddnsDraft.on_missing_public_ip !== 'keep_existing') n++;
    if (Number(ddnsDraft.ttl || 300) !== 300) n++;
    if (Number(ddnsDraft.reconcile_interval_secs || 600) !== 600) n++;
    if (ddnsDraft.line && ddnsDraft.line !== 'default') n++;
    if (ddnsDraft.comment?.trim()) n++;
    return n;
  });

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

  let acmeNeedsEab = $derived(
    acmeCaChoice === 'zerossl' ||
      acmeCaChoice === 'google' ||
      acmeCaChoice === 'custom' ||
      Boolean(acmeDraft?.eab_kid?.trim()) ||
      Boolean(acmeDraft?.eab_hmac_key?.configured || acmeDraft?.eab_hmac_key)
  );

  let acmeAdvancedCount = $derived.by(() => {
    if (!acmeDraft) return 0;
    let n = 0;
    if (acmeDraft.challenge_alias_domain?.trim()) n++;
    if (acmeDraft.cert_dir && acmeDraft.cert_dir !== '/data/vane/certs') n++;
    if (Number(acmeDraft.renew_before_days || 30) !== 30) n++;
    if (Number(acmeDraft.propagation_timeout_secs || 180) !== 180) n++;
    n += acmeCopyDirs.filter((d) => String(d || '').trim()).length;
    n += acmeHookEdits.length;
    return n;
  });

  function openAcmeDrawer(idx = -1, cloneFrom = null) {
    acmeEditIdx = idx;
    const firstProv = Object.keys(settingsJson?.dns_providers || {})[0] || '';
    const a = cloneFrom
      ? deepClone(cloneFrom)
      : idx >= 0
        ? deepClone(settingsJson.acme[idx])
        : {
            enabled: true,
            domain: '',
            extra_domains: [],
            email: '',
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
      source_host: '',
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

  let ddnsFailedCount = $derived(
    (settingsJson?.ddns || []).filter((d) => {
      const rt = (dashboard?.ddns || []).find((x) => x.name === d.name);
      return rt?.status === 'failed';
    }).length
  );
  let acmeFailedCount = $derived(
    (settingsJson?.acme || []).filter((a) => {
      const st = (dashboard?.certs || []).find((c) => c.domain === a.domain);
      return st?.status === 'failed';
    }).length
  );
  let stunFailedCount = $derived(
    (settingsJson?.stun || []).filter((s) => {
      const st = (dashboard?.stun || []).find((x) => x.name === s.name);
      return st?.status === 'error' || st?.status === 'failed';
    }).length
  );

  let filteredDdns = $derived(
    (settingsJson?.ddns || [])
      .map((d, idx) => ({ d, idx }))
      .filter(({ d }) => {
        if (filterStatus === 'enabled' && !d.enabled) return false;
        if (filterStatus === 'disabled' && d.enabled) return false;
        if (filterStatus === 'failed') {
          const rt = (dashboard?.ddns || []).find((x) => x.name === d.name);
          if (rt?.status !== 'failed') return false;
        }
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
        if (filterStatus === 'failed') {
          const st = (dashboard?.certs || []).find((c) => c.domain === a.domain);
          if (st?.status !== 'failed') return false;
        }
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
        if (filterStatus === 'failed') {
          const st = (dashboard?.stun || []).find((x) => x.name === s.name);
          if (st?.status !== 'error' && st?.status !== 'failed') return false;
        }
        if (!searchQuery.trim()) return true;
        return `${s.name} ${s.proto} ${s.bind_rule} ${s.stun_server}`
          .toLowerCase()
          .includes(searchQuery.trim().toLowerCase());
      })
  );
</script>

<!-- ===================== DNS 云服务商凭据池（可折叠，空池自动展开，有账号时紧凑单行） ===================== -->
{#if settingsJson && (mode === 'ddns' || mode === 'acme')}
  <div class="card dcs-pool-card">
    <div class="dcs-pool-head">
      <div class="dcs-pool-title-wrap">
        <span class="icon-tile sm info"><Icons name="key" size={14} /></span>
        <div style="min-width:0;flex:1;">
          <div class="dcs-pool-title-row">
            <span class="card-title">{t.dns.poolTitle}</span>
            <span class="badge badge-muted num">{dnsProviderEntries.length}</span>
          </div>
          {#if !showDnsPoolBody && dnsProviderEntries.length > 0}
            <div class="meta-row" style="margin-top:5px;">
              {#each dnsProviderEntries as [id, p]}
                <span class="meta-chip mono">{id} ({p.provider})</span>
              {/each}
            </div>
          {:else}
            <div class="dcs-pool-desc">{t.dns.poolDesc}</div>
          {/if}
        </div>
      </div>
      <div class="btn-group dcs-pool-actions">
        {#if dnsProviderEntries.length > 0}
          <button
            type="button"
            class="btn btn-xs btn-ghost"
            aria-expanded={showDnsPoolBody}
            onclick={() => (dnsPoolExpanded = !dnsPoolExpanded)}
          >
            <span>{showDnsPoolBody ? (t.common?.collapse || (lang === 'en' ? 'Collapse' : '收起')) : (t.dns?.managePool || (lang === 'en' ? 'Manage' : '管理账号'))}</span>
            <span class="dcs-chevron {showDnsPoolBody ? 'open' : ''}">
              <Icons name="chevron" size={13} />
            </span>
          </button>
        {/if}
        <button type="button" class="btn btn-xs btn-soft" onclick={() => openProviderDrawer('')}>
          <Icons name="plus" size={13} />
          <span>{t.dns.addAccount}</span>
        </button>
      </div>
    </div>

    {#if showDnsPoolBody}
      <div class="dcs-pool-body">
        {#if !dnsProviderEntries.length}
          <div class="empty-state-rich" style="padding:18px 16px;">
            <div class="empty-state-desc">{t.dns.emptyPool}</div>
            <button type="button" class="btn btn-sm btn-soft" onclick={() => openProviderDrawer('')}>
              <Icons name="plus" size={14} />
              <span>{t.dns.addAccount}</span>
            </button>
          </div>
        {:else}
          <div class="bento-grid" style="margin-bottom:0;">
            {#each dnsProviderEntries as [id, p]}
              {@const refs = providerRefs(id)}
              <div class="subcard entity-head dcs-prov-card">
                <div class="entity-main">
                  <div class="dcs-title-row">
                    <span class="mono" style="font-weight:700;font-size:13.5px;word-break:break-all;">{id}</span>
                    <span class="badge badge-info">{p.provider}</span>
                    {#if refs.length > 0}
                      <span class="meta-chip num" title={refs.join(', ')}>
                        {formatCount(t.common?.refsCount, '{n} refs', '{n} 处引用', refs.length)}
                      </span>
                    {/if}
                  </div>
                  <div class="mono dcs-prov-meta break-anywhere">
                    {secretMaskedHint(p.api_token, t.dns?.tokenEmpty || (lang === 'en' ? 'Not set' : '未配置'))}
                    {#if p.zone_name} · {p.zone_name}{/if}
                  </div>
                </div>
                <div class="entity-actions dcs-prov-actions">
                  <button type="button" class="btn btn-xs" onclick={() => openProviderDrawer(id)}>{t.edit}</button>
                  <button
                    type="button"
                    class="btn btn-xs btn-danger"
                    title={refs.length > 0 ? refs.join(', ') : t.delete}
                    onclick={() => deleteProvider(id)}
                  >
                    {t.delete}
                  </button>
                </div>
              </div>
            {/each}
          </div>
        {/if}
      </div>
    {/if}
  </div>
{/if}

<!-- ===================== DDNS ===================== -->
{#if settingsJson && mode === 'ddns'}
  {@const ddTotal = settingsJson.ddns?.length || 0}
  {@const ddOn = (settingsJson.ddns || []).filter((x) => x.enabled).length}
  <div class="page-section-bar">
    <div style="min-width:0;">
      <div class="page-section-desc">{t.ddns.subtitle}</div>
      {#if ddTotal > 0}
        <div class="stat-inline-strip num">
          <span class="stat-inline-item"><span class="status-dot" style="background:var(--info);"></span><span class="stat-inline-num">{ddTotal}</span><span>{t.all}</span></span>
          <span class="stat-inline-item"><span class="status-dot ok"></span><span class="stat-inline-num">{ddOn}</span><span>{t.enabled}</span></span>
          <span class="stat-inline-item"><span class="status-dot muted"></span><span class="stat-inline-num">{ddTotal - ddOn}</span><span>{t.disabled}</span></span>
        </div>
      {/if}
    </div>
    <div class="btn-group">
      <button type="button" class="btn btn-primary btn-sm" onclick={() => openDdnsDrawer(-1, 'wan')}>
        <Icons name="plus" size={14} />
        <span>{t.add}</span>
      </button>
    </div>
  </div>

  {#if ddTotal > 0}
    <div class="toolbar">
      <div class="dcs-toolbar-left">
        <div class="search-wrap">
          <span class="search-icon"><Icons name="search" size={15} /></span>
          <input type="text" placeholder={t.search} bind:value={searchQuery} />
          {#if searchQuery}
            <button
              type="button"
              class="search-clear"
              aria-label={t.common?.clearSearch || (lang === 'en' ? 'Clear search' : '清除搜索')}
              onclick={() => (searchQuery = '')}
            >
              <Icons name="x" size={13} />
            </button>
          {/if}
        </div>
        <FacetFilter
          label={t.common?.state || (lang === 'en' ? 'State' : '状态')}
          bind:value={filterStatus}
          options={[
            { value: 'all', label: t.all, count: ddTotal },
            { value: 'enabled', label: t.enabled, count: ddOn, tone: 'ok' },
            { value: 'disabled', label: t.disabled, count: ddTotal - ddOn, tone: 'muted' },
            ...(ddnsFailedCount > 0
              ? [{ value: 'failed', label: t.common?.statusError || t.common.statusFailed, count: ddnsFailedCount, tone: 'danger' }]
              : []),
          ]}
        />
      </div>
      <span class="mono dcs-count">{filteredDdns.length} / {ddTotal}</span>
    </div>
  {/if}

  {#if !ddTotal}
    <div class="empty-state-rich">
      <div class="icon-tile empty-state-icon"><Icons name="ddns" size={18} /></div>
      <div class="empty-state-title">{t.nav.ddns}</div>
      <div class="empty-state-desc">{t.common.empty}</div>
      <div class="btn-group" style="justify-content:center;">
        <button type="button" class="btn btn-primary btn-sm" onclick={() => openDdnsDrawer(-1, 'wan')}>
          <Icons name="plus" size={14} />
          <span>{t.add}</span>
        </button>
        <button type="button" class="btn btn-sm" onclick={() => openDdnsDrawer(-1, 'subdevice_v6')}>
          {t.ddns.presetSubdevice}
        </button>
      </div>
    </div>
  {:else if !filteredDdns.length}
    <div class="empty-state-rich">
      <div class="icon-tile muted empty-state-icon"><Icons name="search" size={18} /></div>
      <div class="empty-state-desc">{t.common.noMatches}</div>
      <button type="button" class="btn btn-sm" onclick={resetFilters}>
        {t.common?.clearFilters || (lang === 'en' ? 'Reset filters' : '重置筛选')}
      </button>
    </div>
  {:else}
    <div style="display:grid;gap:12px;">
      {#each filteredDdns as { d, idx } (d.name)}
        {@const rt = (dashboard?.ddns || []).find((x) => x.name === d.name)}
        {@const ddnsErrors = [rt?.ipv4?.error ? `IPv4: ${rt.ipv4.error}` : '', rt?.ipv6?.error ? `IPv6: ${rt.ipv6.error}` : '', rt?.firewall_error ? `FW: ${rt.firewall_error}` : ''].filter(Boolean)}
        <div class="card entity-card {!d.enabled ? 'is-disabled' : ''}">
          <div class="entity-head">
            <div class="entity-main">
              <div class="dcs-title-row">
                <span class="icon-tile sm {d.enabled ? (rt?.status === 'failed' ? 'danger' : rt?.status === 'synced' ? '' : 'warn') : 'muted'}">
                  <Icons name="ddns" size={14} />
                </span>
                <button
                  type="button"
                  class="dcs-domain-btn mono"
                  title={t.copy}
                  aria-label={`${t.copy} ${d.domain}`}
                  onclick={() => copyOrToast(d.domain)}
                >
                  <span class="break-anywhere">{d.domain}</span>
                  <Icons name="copy" size={12} />
                </button>
                {#if !d.enabled}
                  <span class="badge badge-muted">{t.common.statusDisabled}</span>
                {:else if rt}
                  <span class="badge {rt.status === 'synced' ? 'badge-ok' : rt.status === 'failed' ? 'badge-danger' : 'badge-warn'}">
                    {translateRuntimeStatus(rt.status, t)}
                  </span>
                {/if}
              </div>

              <div class="meta-row" style="margin-top:7px;">
                <span class="meta-chip mono">{d.name}</span>
                <span class="meta-chip mono">{d.provider} · {d.records.join('+')}</span>
                <span class="meta-chip">{formatDdnsSource(d.source.kind)}</span>
                {#if rt?.last_sync_unix}
                  <span class="meta-chip mono">{formatUnixTime(rt.last_sync_unix)}</span>
                {/if}
              </div>

              {#if rt?.last_ipv4 || rt?.last_ipv6 || d.split_dns_lan_ips?.length}
                <div class="dcs-ip-pills">
                  {#if rt?.last_ipv4}
                    <button
                      type="button"
                      class="copy-pill mono dcs-pill-v4"
                      title={t.copy}
                      aria-label={`${t.copy} IPv4 ${rt.last_ipv4}`}
                      onclick={() => copyOrToast(rt.last_ipv4)}
                    >
                      <span class="dcs-pill-tag">A</span>
                      <span class="break-anywhere">{rt.last_ipv4}</span>
                      {#if rt?.ipv4?.action && rt.ipv4.action !== 'disabled'}
                        <span class="dcs-pill-act">({rt.ipv4.action})</span>
                      {/if}
                      <Icons name="copy" size={11} />
                    </button>
                  {/if}
                  {#if rt?.last_ipv6}
                    <button
                      type="button"
                      class="copy-pill mono dcs-pill-v6"
                      title={t.copy}
                      aria-label={`${t.copy} IPv6 ${rt.last_ipv6}`}
                      onclick={() => copyOrToast(rt.last_ipv6)}
                    >
                      <span class="dcs-pill-tag">AAAA</span>
                      <span class="break-anywhere">{rt.last_ipv6}</span>
                      {#if rt?.ipv6?.action && rt.ipv6.action !== 'disabled'}
                        <span class="dcs-pill-act">({rt.ipv6.action})</span>
                      {/if}
                      <Icons name="copy" size={11} />
                    </button>
                  {/if}
                  {#if d.split_dns_lan_ips?.length}
                    <span class="meta-chip mono" style="color:var(--info);">
                      Split-DNS: {d.split_dns_lan_ips.join(', ')}
                    </span>
                  {/if}
                </div>
              {/if}

              {#if ddnsErrors.length}
                <div class="inline-alert inline-alert-danger" role="alert" style="margin-top:8px;">
                  <Icons name="alert" size={14} />
                  <div class="mono break-anywhere" style="display:grid;gap:2px;">
                    {#each ddnsErrors as errLine}
                      <div>{errLine}</div>
                    {/each}
                  </div>
                </div>
              {/if}
            </div>

            <div class="entity-actions">
              <button
                type="button"
                role="switch"
                aria-checked={d.enabled}
                aria-label={`${t.nav.ddns}: ${d.domain || d.name}`}
                class="switch"
                disabled={busyToggleKey === `ddns:${idx}`}
                onclick={() => toggleDdnsEnabled(idx)}
              >
                <span class="switch-thumb"></span>
              </button>
              <div class="btn-group dcs-action-btns">
                <button
                  type="button"
                  class="btn btn-xs btn-soft"
                  disabled={!d.enabled || busyKey === `ddns:${d.name}`}
                  onclick={() => triggerDdnsSync(d.name)}
                >
                  <Icons name="refresh" size={12} />
                  <span>{busyKey === `ddns:${d.name}` ? (t.ddns?.syncing || '...') : t.ddns.syncNow}</span>
                </button>
                <button
                  type="button"
                  class="btn btn-xs btn-icon"
                  title={t.clone}
                  aria-label={`${t.clone}: ${d.name}`}
                  onclick={() => openDdnsDrawer(-1, 'wan', d)}
                >
                  <Icons name="duplicate" size={13} />
                </button>
                <button type="button" class="btn btn-xs" onclick={() => openDdnsDrawer(idx)}>{t.edit}</button>
                <button type="button" class="btn btn-xs btn-danger" onclick={() => deleteDdns(idx)}>{t.delete}</button>
              </div>
            </div>
          </div>
        </div>
      {/each}
    </div>
  {/if}
{/if}

<!-- ===================== ACME 自动化证书 ===================== -->
{#if settingsJson && mode === 'acme'}
  {@const acTotal = settingsJson.acme?.length || 0}
  {@const acOn = (settingsJson.acme || []).filter((x) => x.enabled).length}
  <div class="page-section-bar">
    <div style="min-width:0;">
      <div class="page-section-desc">{t.acme.subtitle}</div>
      {#if acTotal > 0}
        <div class="stat-inline-strip num">
          <span class="stat-inline-item"><span class="status-dot" style="background:var(--info);"></span><span class="stat-inline-num">{acTotal}</span><span>{t.all}</span></span>
          <span class="stat-inline-item"><span class="status-dot ok"></span><span class="stat-inline-num">{acOn}</span><span>{t.enabled}</span></span>
          <span class="stat-inline-item"><span class="status-dot muted"></span><span class="stat-inline-num">{acTotal - acOn}</span><span>{t.disabled}</span></span>
        </div>
      {/if}
    </div>
    <button type="button" class="btn btn-primary btn-sm" onclick={() => openAcmeDrawer(-1)}>
      <Icons name="plus" size={14} />
      <span>{t.add}</span>
    </button>
  </div>

  {#if acTotal > 0}
    <div class="toolbar">
      <div class="dcs-toolbar-left">
        <div class="search-wrap">
          <span class="search-icon"><Icons name="search" size={15} /></span>
          <input type="text" placeholder={t.search} bind:value={searchQuery} />
          {#if searchQuery}
            <button
              type="button"
              class="search-clear"
              aria-label={t.common?.clearSearch || (lang === 'en' ? 'Clear search' : '清除搜索')}
              onclick={() => (searchQuery = '')}
            >
              <Icons name="x" size={13} />
            </button>
          {/if}
        </div>
        <FacetFilter
          label={t.common?.state || (lang === 'en' ? 'State' : '状态')}
          bind:value={filterStatus}
          options={[
            { value: 'all', label: t.all, count: acTotal },
            { value: 'enabled', label: t.enabled, count: acOn, tone: 'ok' },
            { value: 'disabled', label: t.disabled, count: acTotal - acOn, tone: 'muted' },
            ...(acmeFailedCount > 0
              ? [{ value: 'failed', label: t.common?.statusError || t.common.statusFailed, count: acmeFailedCount, tone: 'danger' }]
              : []),
          ]}
        />
      </div>
      <span class="mono dcs-count">{filteredAcme.length} / {acTotal}</span>
    </div>
  {/if}

  {#if !acTotal}
    <div class="empty-state-rich">
      <div class="icon-tile empty-state-icon"><Icons name="acme" size={18} /></div>
      <div class="empty-state-title">{t.nav.acme}</div>
      <div class="empty-state-desc">{t.common.empty}</div>
      <button type="button" class="btn btn-primary btn-sm" onclick={() => openAcmeDrawer(-1)}>
        <Icons name="plus" size={14} />
        <span>{t.add}</span>
      </button>
    </div>
  {:else if !filteredAcme.length}
    <div class="empty-state-rich">
      <div class="icon-tile muted empty-state-icon"><Icons name="search" size={18} /></div>
      <div class="empty-state-desc">{t.common.noMatches}</div>
      <button type="button" class="btn btn-sm" onclick={resetFilters}>
        {t.common?.clearFilters || (lang === 'en' ? 'Reset filters' : '重置筛选')}
      </button>
    </div>
  {:else}
    <div style="display:grid;gap:12px;">
      {#each filteredAcme as { a, idx } (a.domain)}
        {@const st = (dashboard?.certs || []).find((c) => c.domain === a.domain)}
        {@const days = certDaysRemaining(st?.expires_at_unix)}
        <div class="card entity-card {!a.enabled ? 'is-disabled' : ''}">
          <div class="entity-head">
            <div class="entity-main">
              <div class="dcs-title-row">
                <span class="icon-tile sm {a.enabled ? (st?.status === 'active' ? '' : st?.status === 'failed' ? 'danger' : 'warn') : 'muted'}">
                  <Icons name="acme" size={14} />
                </span>
                <button
                  type="button"
                  class="dcs-domain-btn mono"
                  title={t.copy}
                  aria-label={`${t.copy} ${a.domain}`}
                  onclick={() => copyOrToast(a.domain)}
                >
                  <span class="break-anywhere">{a.domain}</span>
                  <Icons name="copy" size={12} />
                </button>
                {#if !a.enabled}
                  <span class="badge badge-muted">{t.common.statusDisabled}</span>
                {:else if st}
                  <span class="badge {st.status === 'active' ? (days !== null && days <= 14 ? 'badge-warn' : 'badge-ok') : st.status === 'failed' ? 'badge-danger' : 'badge-warn'} num">
                    {translateRuntimeStatus(st.status, t)}{days !== null ? ` · ${days}d` : ''}
                  </span>
                {/if}
                {#if a.use_for_admin}
                  <span class="badge badge-warn">Admin Panel</span>
                {/if}
              </div>

              <div class="meta-row" style="margin-top:7px;">
                <span class="meta-chip badge-trunc" title={a.directory_url}>{formatCaLabel(a.directory_url)}</span>
                <span class="meta-chip mono">DNS: {a.dns_provider}</span>
                {#if a.extra_domains?.length}
                  <span class="meta-chip mono" title={a.extra_domains.join(', ')}>+{a.extra_domains.length} SAN</span>
                {/if}
                <span class="meta-chip num">Renew &lt; {a.renew_before_days}d</span>
                {#if a.deploy_hooks?.length}
                  <span class="meta-chip num">{a.deploy_hooks.length} Hook</span>
                {/if}
                {#if st?.expires_at_unix}
                  <span class="meta-chip mono">{t.dash.expires}: {formatUnixTime(st.expires_at_unix)}</span>
                {/if}
              </div>

              {#if st?.challenge_record}
                <div class="dcs-ip-pills">
                  <button
                    type="button"
                    class="copy-pill mono dcs-pill-v6"
                    title={t.copy}
                    aria-label={`${t.copy} DNS-01 TXT`}
                    onclick={() => copyOrToast(st.challenge_record)}
                  >
                    <span class="dcs-pill-tag">TXT</span>
                    <span class="break-anywhere">{st.challenge_record}</span>
                    <Icons name="copy" size={11} />
                  </button>
                </div>
              {/if}

              {#if st?.last_error}
                <div class="inline-alert inline-alert-danger" role="alert" style="margin-top:8px;">
                  <Icons name="alert" size={14} />
                  <span class="mono break-anywhere">{st.last_error}</span>
                </div>
              {/if}
            </div>

            <div class="entity-actions">
              <button
                type="button"
                role="switch"
                aria-checked={a.enabled}
                aria-label={`${t.nav.acme}: ${a.domain}`}
                class="switch"
                disabled={busyToggleKey === `acme:${idx}`}
                onclick={() => toggleAcmeEnabled(idx)}
              >
                <span class="switch-thumb"></span>
              </button>
              <div class="btn-group dcs-action-btns">
                <button
                  type="button"
                  class="btn btn-xs btn-soft"
                  disabled={!a.enabled || busyKey === `acme:${a.domain}`}
                  onclick={() => triggerAcmeIssue(a.domain)}
                >
                  <Icons name="refresh" size={12} />
                  <span>{busyKey === `acme:${a.domain}` ? (t.acme?.issuing || '...') : t.acme.issueNow}</span>
                </button>
                <button
                  type="button"
                  class="btn btn-xs btn-icon"
                  title={t.clone}
                  aria-label={`${t.clone}: ${a.domain}`}
                  onclick={() => openAcmeDrawer(-1, a)}
                >
                  <Icons name="duplicate" size={13} />
                </button>
                <button type="button" class="btn btn-xs" onclick={() => openAcmeDrawer(idx)}>{t.edit}</button>
                <button type="button" class="btn btn-xs btn-danger" onclick={() => deleteAcme(idx)}>{t.delete}</button>
              </div>
            </div>
          </div>
        </div>
      {/each}
    </div>
  {/if}
{/if}

<!-- ===================== STUN 穿透与动态重定向 ===================== -->
{#if settingsJson && mode === 'stun'}
  {@const stTotal = settingsJson.stun?.length || 0}
  {@const stOn = (settingsJson.stun || []).filter((x) => x.enabled).length}
  <div class="page-section-bar">
    <div style="min-width:0;">
      <div class="page-section-desc">{t.stun.subtitle}</div>
      {#if stTotal > 0}
        <div class="stat-inline-strip num">
          <span class="stat-inline-item"><span class="status-dot" style="background:var(--info);"></span><span class="stat-inline-num">{stTotal}</span><span>{t.all}</span></span>
          <span class="stat-inline-item"><span class="status-dot ok"></span><span class="stat-inline-num">{stOn}</span><span>{t.enabled}</span></span>
          <span class="stat-inline-item"><span class="status-dot muted"></span><span class="stat-inline-num">{stTotal - stOn}</span><span>{t.disabled}</span></span>
        </div>
      {/if}
    </div>
    <button type="button" class="btn btn-primary btn-sm" onclick={() => openStunDrawer(-1)}>
      <Icons name="plus" size={14} />
      <span>{t.add}</span>
    </button>
  </div>

  {#if stTotal > 0}
    <div class="toolbar">
      <div class="dcs-toolbar-left">
        <div class="search-wrap">
          <span class="search-icon"><Icons name="search" size={15} /></span>
          <input type="text" placeholder={t.search} bind:value={searchQuery} />
          {#if searchQuery}
            <button
              type="button"
              class="search-clear"
              aria-label={t.common?.clearSearch || (lang === 'en' ? 'Clear search' : '清除搜索')}
              onclick={() => (searchQuery = '')}
            >
              <Icons name="x" size={13} />
            </button>
          {/if}
        </div>
        <FacetFilter
          label={t.common?.state || (lang === 'en' ? 'State' : '状态')}
          bind:value={filterStatus}
          options={[
            { value: 'all', label: t.all, count: stTotal },
            { value: 'enabled', label: t.enabled, count: stOn, tone: 'ok' },
            { value: 'disabled', label: t.disabled, count: stTotal - stOn, tone: 'muted' },
            ...(stunFailedCount > 0
              ? [{ value: 'failed', label: t.common?.statusError || t.common.statusFailed, count: stunFailedCount, tone: 'danger' }]
              : []),
          ]}
        />
      </div>
      <span class="mono dcs-count">{filteredStun.length} / {stTotal}</span>
    </div>
  {/if}

  {#if !stTotal}
    <div class="empty-state-rich">
      <div class="icon-tile empty-state-icon"><Icons name="stun" size={18} /></div>
      <div class="empty-state-title">{t.nav.stun}</div>
      <div class="empty-state-desc">{t.common.empty}</div>
      <button type="button" class="btn btn-primary btn-sm" onclick={() => openStunDrawer(-1)}>
        <Icons name="plus" size={14} />
        <span>{t.add}</span>
      </button>
    </div>
  {:else if !filteredStun.length}
    <div class="empty-state-rich">
      <div class="icon-tile muted empty-state-icon"><Icons name="search" size={18} /></div>
      <div class="empty-state-desc">{t.common.noMatches}</div>
      <button type="button" class="btn btn-sm" onclick={resetFilters}>
        {t.common?.clearFilters || (lang === 'en' ? 'Reset filters' : '重置筛选')}
      </button>
    </div>
  {:else}
    <div style="display:grid;gap:12px;">
      {#each filteredStun as { s, idx } (s.name)}
        {@const st = (dashboard?.stun || []).find((x) => x.name === s.name)}
        {@const pubAddr = st?.public_addr || dashboard?.stun_public_addrs?.[s.name] || ''}
        {@const boundPort = resolveBoundRulePort(s.bind_rule)}
        {@const bindMissing = Boolean(s.bind_rule) && boundPort === null}
        <div class="card entity-card {!s.enabled ? 'is-disabled' : ''}">
          <div class="entity-head">
            <div class="entity-main">
              <div class="dcs-title-row">
                <span class="icon-tile sm {s.enabled ? (st?.status === 'active' ? '' : st?.status === 'error' ? 'danger' : 'warn') : 'muted'}">
                  <Icons name="stun" size={14} />
                </span>
                <span class="dcs-entity-title">{s.name}</span>
                <span class="port-pill mono">
                  <span class="port-pill-lead">{s.proto.toUpperCase()}</span>
                  <span>:{s.local_port || boundPort || 'auto'}</span>
                </span>
                {#if !s.enabled}
                  <span class="badge badge-muted">{t.common.statusDisabled}</span>
                {:else if st}
                  <span class="badge {st.status === 'active' ? 'badge-ok' : st.status === 'degraded' ? 'badge-warn' : 'badge-danger'}">
                    {translateRuntimeStatus(st.status, t)}
                  </span>
                {/if}
                {#if bindMissing}
                  <span class="badge badge-warn">{t.stun?.bindMissing || (lang === 'en' ? 'Bound rule missing' : '绑定规则缺失')}</span>
                {/if}
                {#if s.on_change_cloudflare_redirect}
                  <span class="badge badge-warn">CF Redirect</span>
                {/if}
              </div>

              <div class="stun-pub-row">
                {#if pubAddr}
                  <button
                    type="button"
                    class="copy-pill mono dcs-pill-v6 stun-pub-pill"
                    title={t.copy}
                    aria-label={`${t.copy} ${pubAddr}`}
                    onclick={() => copyOrToast(pubAddr)}
                  >
                    <span class="dcs-pill-tag">Public</span>
                    <span class="break-anywhere">{pubAddr}</span>
                    <Icons name="copy" size={12} />
                  </button>
                {:else}
                  <span class="mono stun-not-probed">
                    {t.stun?.notProbed || (lang === 'en' ? 'Not probed yet' : '等待探测…')}
                  </span>
                {/if}
              </div>

              <div class="meta-row" style="margin-top:6px;">
                {#if s.bind_rule}
                  <span class="meta-chip mono">Bind: {s.bind_rule}</span>
                {/if}
                {#if st?.local_addr}
                  <span class="meta-chip mono">Local: {st.local_addr}</span>
                {/if}
                {#if st?.server}
                  <span class="meta-chip mono">{st.server}</span>
                {/if}
                {#if st?.last_probe_unix}
                  <span class="meta-chip mono">{formatUnixTime(st.last_probe_unix)}</span>
                {/if}
              </div>

              {#if st?.error}
                <div class="inline-alert inline-alert-danger" role="alert" style="margin-top:8px;">
                  <Icons name="alert" size={14} />
                  <span class="mono break-anywhere">{st.error}</span>
                </div>
              {/if}
            </div>

            <div class="entity-actions">
              <button
                type="button"
                role="switch"
                aria-checked={s.enabled}
                aria-label={`${t.nav.stun}: ${s.name}`}
                class="switch"
                disabled={busyToggleKey === `stun:${idx}`}
                onclick={() => toggleStunEnabled(idx)}
              >
                <span class="switch-thumb"></span>
              </button>
              <div class="btn-group dcs-action-btns">
                <button
                  type="button"
                  class="btn btn-xs btn-soft"
                  disabled={!s.enabled || busyKey === `stun:${s.name}`}
                  onclick={() => triggerStunProbe(s.name)}
                >
                  <Icons name="stun" size={12} />
                  <span>{busyKey === `stun:${s.name}` ? (t.stun?.probing || '...') : t.stun.probeNow}</span>
                </button>
                <button
                  type="button"
                  class="btn btn-xs btn-icon"
                  title={t.clone}
                  aria-label={`${t.clone}: ${s.name}`}
                  onclick={() => openStunDrawer(-1, s)}
                >
                  <Icons name="duplicate" size={13} />
                </button>
                <button type="button" class="btn btn-xs" onclick={() => openStunDrawer(idx)}>{t.edit}</button>
                <button type="button" class="btn btn-xs btn-danger" onclick={() => deleteStun(idx)}>{t.delete}</button>
              </div>
            </div>
          </div>
        </div>
      {/each}
    </div>
  {/if}
{/if}

<!-- DNS 服务商账号编辑弹窗 -->
<EditorDialog
  open={provDrawerOpen && Boolean(provDraft)}
  title={`${provEditId ? t.edit : t.add} · ${t.dns.provider}`}
  size="sm"
  busy={saving}
  {t}
  {askConfirm}
  onSubmit={saveProvider}
  onClose={() => (provDrawerOpen = false)}
>
  {#if provEditRefs.length > 0}
    <div class="inline-alert inline-alert-info" style="margin-bottom:12px;">
      <Icons name="info" size={14} />
      <span>
        {formatCount(
          t.dns?.cascadeRenameHint,
          'Referenced by {n} rule(s); renaming updates references automatically',
          '当前被 {n} 条规则引用，修改账号 ID 时将自动同步更新引用',
          provEditRefs.length
        )}
      </span>
    </div>
  {/if}
  <div class="form-grid">
    <div class="field">
      <label for="dp-id">{t.dns.accountId}</label>
      <input id="dp-id" type="text" class="mono" bind:value={provDraftId} required />
    </div>
    <div class="field">
      <label for="dp-kind">{t.dns.provider}</label>
      <Select
        id="dp-kind"
        bind:value={provDraft.provider}
        options={[
          { value: 'cloudflare', label: 'Cloudflare' },
          { value: 'aliyun', label: lang === 'en' ? 'Alibaba Cloud DNS' : '阿里云解析 DNS' },
          { value: 'dnspod', label: lang === 'en' ? 'Tencent DNSPod' : '腾讯云 DNSPod' },
        ]}
      />
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
</EditorDialog>

<!-- DDNS 规则编辑弹窗 -->
<EditorDialog
  open={ddnsDrawerOpen && Boolean(ddnsDraft)}
  title={`${ddnsEditIdx >= 0 ? t.edit : t.add} · ${t.nav.ddns}`}
  size="md"
  busy={saving}
  {t}
  {askConfirm}
  onSubmit={saveDdns}
  onClose={() => (ddnsDrawerOpen = false)}
>
  {#if ddnsEditIdx < 0}
    <div class="dcs-preset-strip">
      <span class="dcs-preset-label">{t.common.presets}:</span>
      <div class="btn-group">
        <button type="button" data-dirty="1" class="chip {ddnsPreset === 'wan' ? 'active' : ''}" onclick={() => applyDdnsPreset('wan')}>
          {lang === 'en' ? 'WAN Dual-Stack' : '路由器双栈公网'}
        </button>
        <button type="button" data-dirty="1" class="chip {ddnsPreset === 'subdevice_v6' ? 'active' : ''}" onclick={() => applyDdnsPreset('subdevice_v6')}>
          {t.ddns.presetSubdevice}
        </button>
      </div>
    </div>
  {/if}

  <div class="form-section-title">{lang === 'en' ? 'Domain & Provider' : '域名与解析服务商'}</div>
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
      <Select
        id="dd-prov"
        bind:value={ddnsDraft.provider}
        options={[
          ...Object.keys(settingsJson.dns_providers || {}).map((k) => ({ value: k, label: k })),
          { value: 'custom_http', label: lang === 'en' ? 'Custom HTTP Request' : '自定义 HTTP 接口' },
        ]}
      />
    </div>
    <div class="field">
      <label for="dd-src">{t.ddns.sourceMode}</label>
      <Select
        id="dd-src"
        bind:value={ddnsSourceKind}
        options={
          lang === 'en'
            ? [
                { value: 'interface', label: 'Router WAN Interface' },
                { value: 'prefix_and_iid', label: 'LAN Prefix + Fixed Suffix (IPv6)' },
                { value: 'neighbor_mac', label: 'LAN Device by MAC Address (IPv6)' },
                { value: 'external_url', label: 'Public IP Check URL' },
                { value: 'custom_http_extract', label: 'Extract from Custom HTTP Response' },
              ]
            : [
                { value: 'interface', label: '读取路由器 WAN 网卡地址' },
                { value: 'prefix_and_iid', label: '内网前缀 + 固定后缀拼装 (IPv6)' },
                { value: 'neighbor_mac', label: '按内网设备 MAC 识别地址 (IPv6)' },
                { value: 'external_url', label: '通过外部接口查询公网 IP' },
                { value: 'custom_http_extract', label: '从自定义接口响应提取 IP' },
              ]
        }
        onchange={onDdnsSourceKindChange}
      />
    </div>
  </div>

  {#if ddnsDraft.source.kind === 'interface'}
    <div class="form-grid">
      <div class="field">
        <label for="dd-if">{t.ddns.wanIface}</label>
        <ComboInput id="dd-if" placeholder="pppoe-wan" options={ifaceOptions} bind:value={ddnsDraft.source.name} required />
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
        <ComboInput id="dd-pif" placeholder="br-lan" options={ifaceOptions} bind:value={ddnsDraft.source.prefix_iface} required />
      </div>
      <div class="field">
        <label for="dd-iid">{t.ddns.fixedIid}</label>
        <input id="dd-iid" type="text" class="mono" placeholder="::10" bind:value={ddnsDraft.source.iid} required />
      </div>
    </div>
  {:else if ddnsDraft.source.kind === 'neighbor_mac'}
    <div class="form-grid">
      <div class="field">
        <label for="dd-nif">{t.ddns.prefixIface}</label>
        <ComboInput id="dd-nif" placeholder="br-lan" options={ifaceOptions} bind:value={ddnsDraft.source.prefix_iface} required />
      </div>
      <div class="field">
        <label for="dd-mac">{t.ddns.targetMac}</label>
        <ComboInput
          id="dd-mac"
          options={neighborEntries.map((nb) => ({ value: nb.mac, label: nb.mac, sub: `${nb.iface} · ${nb.ip}` }))}
          placeholder="00:11:32:aa:bb:cc"
          bind:value={ddnsDraft.source.mac}
          required
        />
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
          <Select id="dd-chm" mono bind:value={ddnsDraft.custom_http.method} options={['GET', 'POST', 'PUT']} />
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

  <div class="form-section-title">{lang === 'en' ? 'Records, Firewall & Split-DNS' : '解析记录、放行与本地回流'}</div>
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
    <div class="banner banner-info" style="margin-bottom:12px;">
      <div class="banner-main">
        <Icons name="info" size={14} />
        <div style="min-width:0;flex:1;">
          <div style="font-weight:600;">{t.ddns.splitHint}</div>
          <code class="mono code-chip" style="font-size:11.5px;">addn-hosts={networkInfo.split_dns_path}</code>
        </div>
      </div>
      <button
        type="button"
        class="btn btn-xs"
        onclick={() => copyOrToast(`addn-hosts=${networkInfo.split_dns_path}`)}
      >
        <Icons name="copy" size={12} />
        <span>{t.copy}</span>
      </button>
    </div>
  {/if}

  <details class="details-card">
    <summary>
      <span>{t.common.advanced}</span>
      {#if ddnsAdvancedCount > 0}
        <span class="details-count num">
          {formatCount(t.common?.configuredCount, '{n} configured', '已配置 {n} 项', ddnsAdvancedCount)}
        </span>
      {/if}
    </summary>
    <div class="details-body">
      <div class="form-grid">
        <div class="field">
          <label for="dd-miss">{t.ddns.missingPolicy}</label>
          <Select
            id="dd-miss"
            bind:value={ddnsDraft.on_missing_public_ip}
            options={[
              { value: 'keep_existing', label: lang === 'en' ? 'Keep Existing DNS Record' : '保留原解析记录' },
              ...(ddnsDraft.provider !== 'custom_http'
                ? [{ value: 'delete_record', label: lang === 'en' ? 'Delete DNS Record' : '删除对应解析记录' }]
                : []),
            ]}
          />
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
            <Select
              id="dd-line"
              bind:value={ddnsDraft.line}
              options={
                lang === 'en'
                  ? [
                      { value: 'default', label: 'Default' },
                      { value: 'telecom', label: 'China Telecom' },
                      { value: 'unicom', label: 'China Unicom' },
                      { value: 'mobile', label: 'China Mobile' },
                      { value: 'oversea', label: 'Overseas' },
                    ]
                  : [
                      { value: 'default', label: '默认线路' },
                      { value: 'telecom', label: '中国电信' },
                      { value: 'unicom', label: '中国联通' },
                      { value: 'mobile', label: '中国移动' },
                      { value: 'oversea', label: '境外线路' },
                    ]
              }
            />
          </div>
        {/if}
        <div class="field">
          <label for="dd-cmt">{t.ddns.comment}</label>
          <input id="dd-cmt" type="text" bind:value={ddnsDraft.comment} />
        </div>
      </div>
    </div>
  </details>
</EditorDialog>

<!-- ACME 证书编辑弹窗 -->
<EditorDialog
  open={acmeDrawerOpen && Boolean(acmeDraft)}
  title={`${acmeEditIdx >= 0 ? t.edit : t.add} · ${t.nav.acme}`}
  size="md"
  busy={saving}
  {t}
  {askConfirm}
  onSubmit={saveAcme}
  onClose={() => (acmeDrawerOpen = false)}
>
  {#if dnsProviderEntries.length === 0}
    <div class="banner banner-warn" style="margin-bottom:14px;">
      <div class="banner-main">
        <Icons name="alert" size={14} />
        <span>{t.acme?.noProviderHint || (lang === 'en' ? 'No DNS provider account configured yet.' : '尚未配置 DNS 服务商账号，请先添加')}</span>
      </div>
      <button type="button" class="btn btn-xs btn-soft" onclick={() => openProviderDrawer('')}>
        <Icons name="plus" size={12} />
        <span>{t.dns.addAccount}</span>
      </button>
    </div>
  {/if}

  <div class="form-section-title">{lang === 'en' ? 'Certificate Domains & CA' : '证书域名与签发机构'}</div>
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
      <Select
        id="ac-prov"
        mono
        bind:value={acmeDraft.dns_provider}
        required
        placeholder={lang === 'en' ? '— Add DNS Provider first —' : '— 请先添加 DNS 账号 —'}
        options={Object.keys(settingsJson.dns_providers || {})}
      />
    </div>
    <div class="field">
      <label for="ac-ca">{t.acme.caDir}</label>
      <Select
        id="ac-ca"
        value={acmeCaChoice}
        options={[
          { value: 'letsencrypt', label: "Let's Encrypt (Production)" },
          { value: 'letsencrypt_staging', label: "Let's Encrypt (Staging)" },
          { value: 'zerossl', label: 'ZeroSSL' },
          { value: 'buypass', label: 'Buypass' },
          { value: 'google', label: 'Google Trust Services' },
          { value: 'custom', label: 'Custom HTTPS Directory' },
        ]}
        onchange={(val) => {
          acmeCaChoice = val;
          if (acmeCaChoice !== 'custom') acmeDraft.directory_url = acmeCaChoice;
          else if (PRESET_CA.has(acmeDraft.directory_url)) acmeDraft.directory_url = 'https://';
        }}
      />
    </div>
  </div>

  {#if acmeCaChoice === 'custom'}
    <div class="field">
      <label for="ac-cdir">{t.acme.customCaUrl}</label>
      <input id="ac-cdir" type="url" class="mono" placeholder="https://..." bind:value={acmeDraft.directory_url} required />
    </div>
  {/if}

  <div class="field">
    <label for="ac-email">{t.acme.email}</label>
    <input id="ac-email" type="email" placeholder="admin@example.com" bind:value={acmeDraft.email} />
  </div>

  {#if acmeNeedsEab}
    <div class="subcard" style="margin-bottom:12px;">
      <div class="form-grid">
        <div class="field" style="margin-bottom:0;">
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
    </div>
  {/if}

  <div style="display:flex;gap:18px;flex-wrap:wrap;margin-bottom:12px;">
    <label class="check-row"><input type="checkbox" bind:checked={acmeDraft.enabled} /> {t.enabled}</label>
    <label class="check-row"><input type="checkbox" bind:checked={acmeDraft.use_for_admin} /> {t.acme.useForAdmin}</label>
  </div>

  <details class="details-card">
    <summary>
      <span>{t.common.advanced}</span>
      {#if acmeAdvancedCount > 0}
        <span class="details-count num">
          {formatCount(t.common?.configuredCount, '{n} configured', '已配置 {n} 项', acmeAdvancedCount)}
        </span>
      {/if}
    </summary>
    <div class="details-body">
      <div class="form-grid">
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

      <!-- 支持多条 copy_to_dir 部署钩子 -->
      <div style="margin-bottom:12px;">
        <div class="row-between" style="margin-bottom:6px;">
          <span style="font-size:12.5px;font-weight:600;color:var(--text-secondary);">{t.acme.copyDir}</span>
          <button type="button" class="btn btn-xs" data-dirty="1" onclick={addAcmeCopyDir}>+ {t.add}</button>
        </div>
        {#each acmeCopyDirs as _dir, cIdx (cIdx)}
          <div style="display:flex;gap:8px;margin-bottom:6px;">
            <input
              type="text"
              class="mono control-compact"
              placeholder="/mnt/usb/shared-certs"
              aria-label={`${t.acme.copyDir} #${cIdx + 1}`}
              bind:value={acmeCopyDirs[cIdx]}
            />
            <button
              type="button"
              class="btn btn-xs btn-danger btn-icon"
              data-dirty="1"
              aria-label={`${t.delete} #${cIdx + 1}`}
              onclick={() => removeAcmeCopyDir(cIdx)}
            >
              <Icons name="trash" size={12} />
            </button>
          </div>
        {/each}
      </div>

      <div>
        <div class="row-between" style="margin-bottom:8px;">
          <span style="font-size:12.5px;font-weight:600;color:var(--text-secondary);">{t.acme.webhooks}</span>
          <button type="button" class="btn btn-xs" data-dirty="1" onclick={addAcmeWebhook}>+ {t.acme.addWebhook}</button>
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
              <button type="button" class="btn btn-xs btn-danger" data-dirty="1" onclick={() => removeAcmeWebhook(wIdx)}>{t.delete}</button>
            </div>
          </div>
        {/each}
      </div>
    </div>
  </details>
</EditorDialog>

<!-- STUN 规则编辑弹窗 -->
<EditorDialog
  open={stunDrawerOpen && Boolean(stunDraft)}
  title={`${stunEditIdx >= 0 ? t.edit : t.add} · ${t.nav.stun}`}
  size="md"
  busy={saving}
  {t}
  {askConfirm}
  onSubmit={saveStun}
  onClose={() => (stunDrawerOpen = false)}
>
  <div class="form-section-title">{lang === 'en' ? 'Tunnel & Port Binding' : '探测通道与本地端口绑定'}</div>
  <div class="form-grid">
    <div class="field">
      <label for="st-name">{t.stun.ruleName}</label>
      <input id="st-name" type="text" class="mono" bind:value={stunDraft.name} required />
    </div>
    <div class="field">
      <label for="st-proto">{t.stun.proto}</label>
      <Select id="st-proto" mono bind:value={stunDraft.proto} options={['udp', 'tcp']} />
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
      <Select
        id="st-bind"
        bind:value={stunDraft.bind_rule}
        options={[
          { value: '', label: '— None —' },
          ...(stunBindRuleDangling
            ? [{ value: stunDraft.bind_rule, label: `⚠ ${stunDraft.bind_rule} (${lang === 'en' ? 'missing' : '规则不存在'})` }]
            : []),
          ...(settingsJson.reverse_proxy || []).map((rp) => ({
            value: rp.name,
            label: `[Proxy] ${rp.name} (:${rp.listen_port})`,
          })),
          ...(settingsJson.port_forwards || []).map((pf) => ({
            value: pf.name,
            label: `[Forward] ${pf.name} (:${pf.listen_port})`,
          })),
        ]}
        onchange={(val) => {
          if (val) stunDraft.local_port = 0;
        }}
      />
      {#if stunBindRuleDangling}
        <div class="field-hint" style="color:var(--warn);">
          {t.stun?.bindMissing || (lang === 'en' ? 'Bound rule no longer exists — select another or clear.' : '绑定的目标规则已不存在，请重新选择或清空。')}
        </div>
      {/if}
    </div>
  </div>

  <div class="form-section-title">{lang === 'en' ? 'STUN Servers & Keepalive' : 'STUN 服务器与保活回调'}</div>
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
      <div class="form-section-title" style="margin-top:0;">Cloudflare Redirect Ruleset</div>
      <div class="form-grid">
        <div class="field">
          <label for="cf-host">{t.stun.cfHost}</label>
          <input id="cf-host" type="text" class="mono" placeholder="go.example.com" bind:value={stunCfDraft.source_host} required />
        </div>
        <div class="field">
          <label for="cf-tpl">{t.stun.cfTpl}</label>
          <input id="cf-tpl" type="text" class="mono" bind:value={stunCfDraft.target_template} required />
        </div>
        <div class="field">
          <label for="cf-code">{t.stun.cfCode}</label>
          <Select id="cf-code" mono bind:value={stunCfDraft.status_code} options={[301, 302, 307, 308]} />
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
</EditorDialog>

<style>
  /* Collapsible Shared DNS Provider Pool */
  .dcs-pool-card {
    margin-bottom: 16px;
    padding: 14px 18px;
  }
  .dcs-pool-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    flex-wrap: wrap;
  }
  .dcs-pool-title-wrap {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    min-width: 0;
    flex: 1 1 240px;
  }
  .dcs-pool-title-row {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }
  .dcs-pool-desc {
    font-size: 12px;
    color: var(--text-secondary);
    margin-top: 3px;
  }
  .dcs-pool-actions {
    flex-shrink: 0;
  }
  .dcs-pool-body {
    margin-top: 12px;
    padding-top: 12px;
    border-top: 1px solid var(--border-subtle);
  }
  .dcs-chevron {
    display: inline-flex;
    transition: transform 0.16s ease;
  }
  .dcs-chevron.open {
    transform: rotate(180deg);
  }
  .dcs-prov-card {
    align-items: center;
  }
  .dcs-prov-meta {
    font-size: 11px;
    color: var(--text-secondary);
    margin-top: 4px;
  }
  .dcs-prov-actions {
    gap: 6px;
  }

  /* Toolbar & entity typography */
  .dcs-toolbar-left {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    flex: 1;
    min-width: 0;
  }
  .dcs-count {
    font-size: 12px;
    color: var(--text-muted);
    white-space: nowrap;
  }
  .dcs-title-row {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    min-width: 0;
  }
  .dcs-entity-title {
    font-weight: 700;
    font-size: 15px;
    color: var(--text-primary);
    word-break: break-word;
  }
  .dcs-domain-btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 2px 6px;
    margin: -2px -6px;
    border: none;
    border-radius: 8px;
    background: transparent;
    color: var(--text-primary);
    font-weight: 700;
    font-size: 14.5px;
    text-align: left;
    cursor: pointer;
    max-width: 100%;
    transition: background-color 0.14s ease, color 0.14s ease;
  }
  .dcs-domain-btn:hover {
    background: var(--bg-elevated);
    color: var(--accent);
  }
  .dcs-domain-btn:focus-visible {
    outline: none;
    box-shadow: 0 0 0 3px var(--accent-soft);
  }
  .dcs-action-btns {
    gap: 6px;
  }

  /* Click-to-copy IP / TXT / STUN pills */
  .dcs-ip-pills {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin-top: 8px;
  }
  .dcs-pill-v4 {
    color: var(--accent);
  }
  .dcs-pill-v6 {
    color: var(--info);
  }
  .dcs-pill-tag {
    font-size: 10px;
    font-weight: 700;
    opacity: 0.78;
    text-transform: uppercase;
    flex-shrink: 0;
  }
  .dcs-pill-act {
    font-size: 10.5px;
    color: var(--text-muted);
    font-weight: 400;
  }
  .stun-pub-row {
    margin-top: 8px;
  }
  .stun-pub-pill {
    font-size: 12.5px;
    font-weight: 600;
  }
  .stun-not-probed {
    font-size: 12px;
    color: var(--text-muted);
  }

  /* Modal preset strip */
  .dcs-preset-strip {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    margin-bottom: 14px;
    padding: 10px 12px;
    border-radius: 13px;
    background: var(--bg-elevated);
    border: 1px solid var(--border-subtle);
  }
  .dcs-preset-label {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-muted);
  }

  @media (max-width: 680px) {
    .dcs-toolbar-left {
      width: 100%;
    }
    .dcs-pool-card {
      padding: 13px 14px;
    }
  }
</style>
