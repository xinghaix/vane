<script>
  import Icons from './Icons.svelte';
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
    formatUnixTime,
    domainMatchesCert,
  } from '../lib/helpers.js';

  const PROTECTED_WAN_PORTS = new Set([
    21, 22, 23, 53, 67, 68, 80, 139, 443, 445, 1883, 2375, 2376, 3306, 4000, 5432, 6379,
  ]);

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
  let busyToggleKey = $state('');
  let busyLeaseKey = $state('');
  let customLeaseName = $state('');
  let customLeaseMins = $state(30);
  let nowSec = $state(Math.floor(Date.now() / 1000));

  // Reverse Proxy Listener & Rule Drawer 状态
  let rpDrawerOpen = $state(false);
  let rpEditIndex = $state(-1);
  let rpOrigName = $state('');
  let rpDraft = $state(null);

  let ruleDrawerOpen = $state(false);
  let ruleListenerIndex = $state(-1);
  let ruleEditIndex = $state(-1);
  let ruleDraft = $state(null);
  let ruleAllowedCsv = $state('');
  let ruleDeniedCsv = $state('');
  let ruleReqRows = $state([]);
  let ruleReqRemCsv = $state('');
  let ruleRespRows = $state([]);
  let ruleRespRemCsv = $state('');

  // 反向代理独立门禁账号管理弹窗状态
  let gateUsers = $state([]);
  let gateUsersLoaded = $state(false);
  let gateUsersOpen = $state(false);
  let gateUsersLoading = $state(false);
  let gateFormMode = $state(''); // '' | 'create' | 'edit'
  let gateDraft = $state({
    username: '',
    password: '',
    enabled: true,
    session_ttl_secs: 43200,
    note: '',
  });
  let gateSaving = $state(false);
  let gateBusyUser = $state('');
  let gateErr = $state('');
  let gateShowPw = $state(false);

  // Port Forward Drawer 状态
  let pfDrawerOpen = $state(false);
  let pfEditIndex = $state(-1);
  let pfDraft = $state(null);
  let pfTargetsCsv = $state('');
  let pfAllowedCsv = $state('');

  let ifaceOptions = $derived(
    (networkInfo?.interfaces || []).map((i) => {
      const ips = [...(i.ipv4 || []), ...(i.ipv6 || [])];
      return { value: i.iface, label: i.iface, sub: ips.slice(0, 2).join(', ') };
    })
  );
  let stunRuleNames = $derived((settingsJson?.stun || []).map((s) => s.name).filter(Boolean));
  let adminPorts = $derived(
    (settingsJson?.admin?.listen_lan || [])
      .map((a) => Number(String(a).split(':').pop()))
      .filter((n) => n > 0)
  );

  let effectiveGateUsers = $derived(
    gateUsersLoaded
      ? gateUsers
      : (settingsJson?.proxy_auth_users || []).map((u) => ({
          ...u,
          active_sessions: 0,
          bound_rules: (settingsJson?.reverse_proxy || [])
            .flatMap((l) => l.rules || [])
            .filter((r) => r.auth_gate && (r.auth_gate_users || []).includes(u.username)).length,
        }))
  );
  let gateUsersCount = $derived(effectiveGateUsers.length);
  let gateTtlOptions = $derived.by(() => {
    const base = [
      { value: 3600, label: lang === 'en' ? '1 hour' : '1 小时' },
      { value: 43200, label: lang === 'en' ? '12 hours (Recommended)' : '12 小时（推荐）' },
      { value: 86400, label: lang === 'en' ? '24 hours' : '24 小时' },
      { value: 604800, label: lang === 'en' ? '7 days' : '7 天' },
    ];
    const cur = Number(gateDraft?.session_ttl_secs || 43200);
    if (cur > 0 && !base.some((o) => o.value === cur)) {
      base.unshift({ value: cur, label: lang === 'en' ? `Custom (${cur}s)` : `自定义 (${cur} 秒)` });
    }
    return base;
  });

  // 切换 Tab 模式时重置搜索、筛选和抽屉状态，避免跨视图残留
  $effect(() => {
    void mode;
    searchQuery = '';
    filterStatus = 'all';
    rpDrawerOpen = false;
    ruleDrawerOpen = false;
    pfDrawerOpen = false;
    gateUsersOpen = false;
    gateFormMode = '';
    customLeaseName = '';
  });

  // 进入反向代理页面时加载独立门禁账号实时状态（活跃会话数等）
  $effect(() => {
    if (mode === 'reverse_proxy' && settingsJson) {
      loadGateUsers(true);
    }
  });

  // 定时刷新当前时间戳用于端口转发租约倒计时
  $effect(() => {
    const timer = setInterval(() => {
      nowSec = Math.floor(Date.now() / 1000);
    }, 15_000);
    return () => clearInterval(timer);
  });

  function listenerRuntime(name) {
    return (dashboard?.reverse_proxy_status || []).find((s) => s.name === name);
  }
  function pfRuntime(name) {
    return (dashboard?.port_forward_status || []).find((s) => s.name === name);
  }

  function isProtectedPort(port) {
    const p = Number(port);
    return PROTECTED_WAN_PORTS.has(p) || adminPorts.includes(p);
  }

  function statusMeta(rt, enabled) {
    if (!enabled) return { cls: 'badge-muted', dot: 'muted', text: t.common.statusDisabled };
    if (!rt) return { cls: 'badge-muted', dot: 'muted', text: t.common.statusUnknown };
    const st = rt.status;
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
      host: '',
      path_prefix: '/',
      strip_prefix: false,
      mode: 'proxy',
      upstream: '',
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
      auth_gate_users: [],
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
      base.upstream_tls_mode = 'insecure_skip_verify';
    } else if (preset === 'stun_redirect') {
      base.mode = 'redirect';
      base.redirect_url = 'https://{{stun.home_nat.public_addr}}{{path}}';
      base.redirect_code = 302;
    } else if (preset === 'static_page') {
      base.mode = 'static';
      base.static_status = 200;
      base.static_content_type = 'text/plain; charset=utf-8';
      base.static_body = '';
    }
    return base;
  }

  function openListenerDrawer(idx = -1) {
    rpEditIndex = idx;
    rpOrigName = idx >= 0 ? settingsJson.reverse_proxy[idx].name : '';
    rpDraft = idx >= 0 ? deepClone(settingsJson.reverse_proxy[idx]) : defaultListener();
    rpDrawerOpen = true;
  }

  async function saveListener(e) {
    e.preventDefault();
    if (saving) return;
    saving = true;
    try {
      rpDraft.name = String(rpDraft.name || '').trim();
      rpDraft.listen_port = Number(rpDraft.listen_port);
      rpDraft.max_concurrent_conns = Number(rpDraft.max_concurrent_conns);
      const next = deepClone(settingsJson);
      const renames = [];
      if (rpEditIndex >= 0) {
        if (rpOrigName && rpOrigName !== rpDraft.name) {
          renames.push({ from: `reverse_proxy.${rpOrigName}`, to: `reverse_proxy.${rpDraft.name}` });
        }
        next.reverse_proxy[rpEditIndex] = rpDraft;
      } else {
        next.reverse_proxy.push(rpDraft);
      }
      if (await onSaveSettings(next, renames)) rpDrawerOpen = false;
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
    const key = `rp:${idx}`;
    if (busyToggleKey) return;
    busyToggleKey = key;
    try {
      const next = deepClone(settingsJson);
      next.reverse_proxy[idx].enabled = !next.reverse_proxy[idx].enabled;
      await onSaveSettings(next);
    } finally {
      busyToggleKey = '';
    }
  }

  function openRuleDrawer(lIdx, rIdx = -1, preset = 'nas', cloneFrom = null) {
    ruleListenerIndex = lIdx;
    ruleEditIndex = rIdx;
    const r = cloneFrom
      ? deepClone(cloneFrom)
      : rIdx >= 0
        ? deepClone(settingsJson.reverse_proxy[lIdx].rules[rIdx])
        : defaultProxyRule(preset);
    if (cloneFrom) {
      r.host = `copy-${r.host}`;
      // 克隆规则不复用旧规则的 Vault 密文占位符，避免新索引 AAD 不匹配
      r.request_headers_set = {};
    }
    if (!Array.isArray(r.auth_gate_users)) r.auth_gate_users = [];
    ruleDraft = r;
    ruleAllowedCsv = joinCsv(r.allowed_cidrs);
    ruleDeniedCsv = joinCsv(r.denied_cidrs);
    ruleReqRows = kvObjectToRows(r.request_headers_set);
    ruleReqRemCsv = joinCsv(r.request_headers_remove);
    ruleRespRows = kvObjectToRows(r.response_headers_set);
    ruleRespRemCsv = joinCsv(r.response_headers_remove);
    ruleDrawerOpen = true;
    loadGateUsers(true);
  }

  function toggleRuleGateUser(username) {
    if (!ruleDraft) return;
    const list = Array.isArray(ruleDraft.auth_gate_users) ? [...ruleDraft.auth_gate_users] : [];
    const idx = list.indexOf(username);
    if (idx >= 0) list.splice(idx, 1);
    else list.push(username);
    ruleDraft.auth_gate_users = list;
  }

  async function saveRule(e) {
    e.preventDefault();
    if (saving) return;
    saving = true;
    try {
      ruleDraft.allowed_cidrs = splitCsv(ruleAllowedCsv);
      ruleDraft.denied_cidrs = splitCsv(ruleDeniedCsv);
      ruleDraft.request_headers_set = rowsToKvObject(ruleReqRows, true);
      ruleDraft.request_headers_remove = splitCsv(ruleReqRemCsv);
      ruleDraft.response_headers_set = rowsToKvObject(ruleRespRows, false);
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
    const key = `rule:${lIdx}:${rIdx}`;
    if (busyToggleKey) return;
    busyToggleKey = key;
    try {
      const next = deepClone(settingsJson);
      next.reverse_proxy[lIdx].rules[rIdx].enabled = !next.reverse_proxy[lIdx].rules[rIdx].enabled;
      await onSaveSettings(next);
    } finally {
      busyToggleKey = '';
    }
  }

  function deleteRule(lIdx, rIdx) {
    const l = settingsJson.reverse_proxy[lIdx];
    const r = l.rules[rIdx];
    askConfirm({
      title: t.common.confirmDeleteTitle,
      message: `${r.host}${r.path_prefix}`,
      confirmLabel: t.delete,
      danger: true,
      onConfirm: async () => {
        const next = deepClone(settingsJson);
        const oldLen = next.reverse_proxy[lIdx].rules.length;
        next.reverse_proxy[lIdx].rules.splice(rIdx, 1);
        const renames = [];
        for (let i = rIdx + 1; i < oldLen; i++) {
          renames.push({
            from: `reverse_proxy.${l.name}.rules.${i}`,
            to: `reverse_proxy.${l.name}.rules.${i - 1}`,
          });
        }
        await onSaveSettings(next, renames);
      },
    });
  }

  async function loadGateUsers(silent = false) {
    if (!silent) gateUsersLoading = true;
    try {
      const r = await apiFetch('/api/proxy/auth-users');
      gateUsers = Array.isArray(r?.users) ? r.users : [];
      gateUsersLoaded = true;
    } catch (err) {
      if (!silent) showToast(err.message, 'error');
    } finally {
      gateUsersLoading = false;
    }
  }

  function openGateUsersModal() {
    gateFormMode = '';
    gateErr = '';
    gateUsersOpen = true;
    loadGateUsers(false);
  }

  function startCreateGateUser() {
    gateFormMode = 'create';
    gateErr = '';
    gateShowPw = false;
    gateDraft = {
      username: '',
      password: '',
      enabled: true,
      session_ttl_secs: 43200,
      note: '',
    };
  }

  function startEditGateUser(user) {
    gateFormMode = 'edit';
    gateErr = '';
    gateShowPw = false;
    gateDraft = {
      username: user.username,
      password: '',
      enabled: Boolean(user.enabled),
      session_ttl_secs: Number(user.session_ttl_secs || 43200),
      note: user.note || '',
    };
  }

  function formatGateTtl(secs) {
    const s = Number(secs || 0);
    if (s >= 86400 && s % 86400 === 0) return lang === 'en' ? `${s / 86400}d` : `${s / 86400} 天`;
    if (s >= 3600 && s % 3600 === 0) return lang === 'en' ? `${s / 3600}h` : `${s / 3600} 小时`;
    if (s >= 60 && s % 60 === 0) return lang === 'en' ? `${s / 60}m` : `${s / 60} 分钟`;
    return `${s}s`;
  }

  async function submitGateUser(e) {
    e.preventDefault();
    if (gateSaving) return;
    gateErr = '';
    const username = String(gateDraft.username || '').trim();
    if (!username) {
      gateErr = lang === 'en' ? 'Username is required' : '请输入访问账号名称';
      return;
    }
    if (gateFormMode === 'create' && !gateDraft.password) {
      gateErr = lang === 'en' ? 'Password is required' : '请设置访问密码';
      return;
    }
    gateSaving = true;
    try {
      let r;
      if (gateFormMode === 'create') {
        r = await apiFetch('/api/proxy/auth-users', {
          method: 'POST',
          body: JSON.stringify({
            username,
            password: gateDraft.password,
            enabled: Boolean(gateDraft.enabled),
            session_ttl_secs: Number(gateDraft.session_ttl_secs || 43200),
            note: String(gateDraft.note || '').trim(),
          }),
        });
        showToast(t.rp.gateCreatedToast, 'success');
      } else {
        const payload = {
          enabled: Boolean(gateDraft.enabled),
          session_ttl_secs: Number(gateDraft.session_ttl_secs || 43200),
          note: String(gateDraft.note || '').trim(),
        };
        if (gateDraft.password) payload.password = gateDraft.password;
        r = await apiFetch(`/api/proxy/auth-users/${encodeURIComponent(username)}`, {
          method: 'PUT',
          body: JSON.stringify(payload),
        });
        showToast(t.rp.gateUpdatedToast, 'success');
      }
      if (Array.isArray(r?.users)) {
        gateUsers = r.users;
        gateUsersLoaded = true;
      }
      gateFormMode = '';
      await onRefresh();
    } catch (err) {
      gateErr = err.message;
    } finally {
      gateSaving = false;
    }
  }

  async function toggleGateUserEnabled(user) {
    if (gateBusyUser) return;
    gateBusyUser = user.username;
    try {
      const r = await apiFetch(`/api/proxy/auth-users/${encodeURIComponent(user.username)}`, {
        method: 'PUT',
        body: JSON.stringify({ enabled: !user.enabled }),
      });
      if (Array.isArray(r?.users)) {
        gateUsers = r.users;
        gateUsersLoaded = true;
      }
      showToast(t.rp.gateUpdatedToast, 'success');
      await onRefresh();
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      gateBusyUser = '';
    }
  }

  async function revokeGateUserSessions(user) {
    if (gateBusyUser) return;
    gateBusyUser = user.username;
    try {
      const r = await apiFetch(`/api/proxy/auth-users/${encodeURIComponent(user.username)}/revoke`, {
        method: 'POST',
      });
      if (Array.isArray(r?.users)) {
        gateUsers = r.users;
        gateUsersLoaded = true;
      }
      showToast(t.rp.gateRevokedToast, 'success');
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      gateBusyUser = '';
    }
  }

  function deleteGateUser(user) {
    askConfirm({
      title: t.common.confirmDeleteTitle,
      message: `${user.username} — ${t.rp.gateDeleteWarn}`,
      confirmLabel: t.delete,
      danger: true,
      onConfirm: async () => {
        gateBusyUser = user.username;
        try {
          const r = await apiFetch(`/api/proxy/auth-users/${encodeURIComponent(user.username)}`, {
            method: 'DELETE',
          });
          if (Array.isArray(r?.users)) {
            gateUsers = r.users;
            gateUsersLoaded = true;
          }
          if (ruleDraft && Array.isArray(ruleDraft.auth_gate_users)) {
            ruleDraft.auth_gate_users = ruleDraft.auth_gate_users.filter((u) => u !== user.username);
          }
          if (gateFormMode === 'edit' && gateDraft.username === user.username) {
            gateFormMode = '';
          }
          showToast(t.rp.gateDeletedToast, 'success');
          await onRefresh();
        } catch (err) {
          showToast(err.message, 'error');
        } finally {
          gateBusyUser = '';
        }
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
      target: '',
      targets: [],
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
    } else if (preset === 'temp_ssh') {
      base.name = 'temp_nas_ssh';
      base.listen_port = 22222;
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
      const firstTarget = splitCsv(pfTargetsCsv)[0] || '';
      const isV6 = firstTarget.startsWith('[');
      if (pfDraft.stack === 'dual') pfDraft.stack = isV6 ? 'ipv6_only' : 'ipv4_only';
      pfDraft.send_proxy_protocol = 'none';
      pfDraft.open_wan_firewall = true;
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
    const key = `pf:${idx}`;
    if (busyToggleKey) return;
    busyToggleKey = key;
    try {
      const next = deepClone(settingsJson);
      next.port_forwards[idx].enabled = !next.port_forwards[idx].enabled;
      await onSaveSettings(next);
    } finally {
      busyToggleKey = '';
    }
  }

  async function grantLease(name, minutes) {
    if (busyLeaseKey) return;
    busyLeaseKey = `${name}:${minutes}`;
    try {
      await apiFetch(`/api/port-forwards/${encodeURIComponent(name)}/lease`, {
        method: 'POST',
        body: JSON.stringify({ minutes }),
      });
      showToast(minutes > 0 ? `${name}: +${minutes}m` : `${name}: ${t.pf.permanent}`, 'success');
      customLeaseName = '';
      await onRefresh();
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      busyLeaseKey = '';
    }
  }

  function ruleMatchesSearch(r, q) {
    if (!q) return true;
    return `${r.host} ${r.path_prefix} ${r.upstream} ${r.redirect_url}`.toLowerCase().includes(q);
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

{#if settingsJson && mode === 'reverse_proxy'}
  {@const rpTotal = settingsJson.reverse_proxy?.length || 0}
  {@const rpOn = (settingsJson.reverse_proxy || []).filter((x) => x.enabled).length}
  <div class="page-section-bar">
    <div>
      <div class="page-section-desc">{t.rp.subtitle}</div>
      {#if rpTotal > 0}
        <div class="stat-inline-strip num">
          <span class="stat-inline-item"><span class="status-dot" style="background:var(--info);"></span><span class="stat-inline-num">{rpTotal}</span><span>{t.all}</span></span>
          <span class="stat-inline-item"><span class="status-dot ok"></span><span class="stat-inline-num">{rpOn}</span><span>{t.enabled}</span></span>
          <span class="stat-inline-item"><span class="status-dot muted"></span><span class="stat-inline-num">{rpTotal - rpOn}</span><span>{t.disabled}</span></span>
        </div>
      {/if}
    </div>
    <div class="btn-group">
      <button type="button" class="btn btn-sm" onclick={openGateUsersModal}>
        <Icons name="user" size={14} />
        <span>{t.rp.gateUsersBtn}</span>
        {#if gateUsersCount > 0}
          <span class="badge badge-muted num">{gateUsersCount}</span>
        {/if}
      </button>
      <button type="button" class="btn btn-primary btn-sm" onclick={() => openListenerDrawer(-1)}>
        <Icons name="plus" size={14} />
        <span>{t.rp.newListener}</span>
      </button>
    </div>
  </div>

  {#if rpTotal > 0}
    <div class="toolbar">
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;flex:1;min-width:0;">
        <div class="search-wrap">
          <span class="search-icon"><Icons name="search" size={15} /></span>
          <input type="text" placeholder={t.search} bind:value={searchQuery} />
        </div>
        <FacetFilter
          label={lang === 'en' ? 'State' : '状态'}
          bind:value={filterStatus}
          options={[
            { value: 'all', label: t.all, count: rpTotal },
            { value: 'enabled', label: t.enabled, count: rpOn, tone: 'ok' },
            { value: 'disabled', label: t.disabled, count: rpTotal - rpOn, tone: 'muted' },
          ]}
        />
      </div>
      <span class="mono" style="font-size:12px;color:var(--text-muted);">{filteredListeners.length} / {rpTotal}</span>
    </div>
  {/if}

  {#if !rpTotal}
    <div class="empty-state">{t.common.empty}</div>
  {:else if !filteredListeners.length}
    <div class="empty-state">{t.common.noMatches}</div>
  {:else}
    <div style="display:grid;gap:14px;">
      {#each filteredListeners as { l: listener, idx: lIdx }}
        {@const rt = listenerRuntime(listener.name)}
        {@const sm = statusMeta(rt, listener.enabled)}
        <div class="card">
          <div class="row-between" style="margin-bottom:12px;">
            <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
              <span class="icon-tile sm {sm.dot === 'ok' ? '' : sm.dot === 'danger' ? 'danger' : 'muted'}">
                <Icons name="reverse_proxy" size={15} />
              </span>
              <span style="font-weight:700;font-size:15px;">{listener.name}</span>
              <span class="port-pill mono">
                <span class="port-pill-lead accent">:{listener.listen_port}</span>
                <span>{listener.stack}</span>
              </span>
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
                  aria-label={t.nav.reverse_proxy}
                  class="switch"
                  disabled={busyToggleKey === `rp:${lIdx}`}
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
              {@const qLow = searchQuery.trim().toLowerCase()}
              {@const listenerMatchedSelf = !qLow || listener.name.toLowerCase().includes(qLow) || String(listener.listen_port).includes(qLow)}
              <div style="display:grid;gap:8px;">
                {#each listener.rules as rule, rIdx}
                  {#if listenerMatchedSelf || ruleMatchesSearch(rule, qLow)}
                    {@const certCov = domainMatchesCert(rule.host, settingsJson.acme, dashboard?.certs)}
                    {@const hdrCount = Object.keys(rule.request_headers_set || {}).length + Object.keys(rule.response_headers_set || {}).length}
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
                            {#if rule.auth_gate}
                              {@const gCount = (rule.auth_gate_users || []).length}
                              {#if gCount > 0}
                                <span class="badge badge-ok">{t.rp.gateBadge} · {gCount}</span>
                              {:else}
                                <span class="badge badge-warn">{t.rp.gateUnboundBadge}</span>
                              {/if}
                            {/if}
                            {#if rule.strip_prefix}<span class="badge badge-muted">Strip Prefix</span>{/if}
                            {#if rule.mode === 'proxy' && rule.upstream?.startsWith('https://')}
                              <span class="badge {rule.upstream_tls_mode === 'insecure_skip_verify' ? 'badge-warn' : 'badge-info'}">
                                TLS: {rule.upstream_tls_mode}
                              </span>
                            {/if}
                            {#if (rule.allowed_cidrs?.length || 0) + (rule.denied_cidrs?.length || 0) > 0}
                              <span class="badge badge-muted">CIDR</span>
                            {/if}
                            {#if hdrCount > 0}
                              <span class="badge badge-muted">{hdrCount} Hdr</span>
                            {/if}
                            {#if rule.mode === 'proxy' && rule.max_body_mb > 0}
                              <span class="badge badge-muted">{rule.max_body_mb}MB</span>
                            {/if}
                          </div>
                        </div>
                        <div class="btn-group">
                          <button
                            type="button"
                            role="switch"
                            aria-checked={rule.enabled}
                            aria-label={t.rp.addRule}
                            class="switch"
                            disabled={busyToggleKey === `rule:${lIdx}:${rIdx}`}
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
                  {/if}
                {/each}
              </div>
            {:else}
              <div style="font-size:12px;color:var(--text-muted);padding:6px 2px;">{t.rp.noRules}</div>
            {/if}
          </div>
        {/each}
      </div>
    {/if}
{/if}

{#if settingsJson && mode === 'port_forward'}
  {@const pfTotal = settingsJson.port_forwards?.length || 0}
  {@const pfOn = (settingsJson.port_forwards || []).filter((x) => x.enabled).length}
  <div class="page-section-bar">
    <div>
      <div class="page-section-desc">{t.pf.subtitle}</div>
      {#if pfTotal > 0}
        <div class="stat-inline-strip num">
          <span class="stat-inline-item"><span class="status-dot" style="background:var(--info);"></span><span class="stat-inline-num">{pfTotal}</span><span>{t.all}</span></span>
          <span class="stat-inline-item"><span class="status-dot ok"></span><span class="stat-inline-num">{pfOn}</span><span>{t.enabled}</span></span>
          <span class="stat-inline-item"><span class="status-dot muted"></span><span class="stat-inline-num">{pfTotal - pfOn}</span><span>{t.disabled}</span></span>
        </div>
      {/if}
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

  {#if pfTotal > 0}
    <div class="toolbar">
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;flex:1;min-width:0;">
        <div class="search-wrap">
          <span class="search-icon"><Icons name="search" size={15} /></span>
          <input type="text" placeholder={t.search} bind:value={searchQuery} />
        </div>
        <FacetFilter
          label={lang === 'en' ? 'State' : '状态'}
          bind:value={filterStatus}
          options={[
            { value: 'all', label: t.all, count: pfTotal },
            { value: 'enabled', label: t.enabled, count: pfOn, tone: 'ok' },
            { value: 'disabled', label: t.disabled, count: pfTotal - pfOn, tone: 'muted' },
          ]}
        />
      </div>
      <span class="mono" style="font-size:12px;color:var(--text-muted);">{filteredPortForwards.length} / {pfTotal}</span>
    </div>
  {/if}

  {#if !pfTotal}
    <div class="empty-state">{t.common.empty}</div>
  {:else if !filteredPortForwards.length}
    <div class="empty-state">{t.common.noMatches}</div>
  {:else}
    <div style="display:grid;gap:12px;">
      {#each filteredPortForwards as { pf, idx } (pf.name)}
        {@const rt = pfRuntime(pf.name)}
        {@const sm = statusMeta(rt, pf.enabled)}
        {@const famLabel = rt ? [rt.bound_v4 ? 'v4' : '', rt.bound_v6 ? 'v6' : ''].filter(Boolean).join('+') : ''}
        <div class="card" style="padding:15px 18px;">
          <div class="row-between">
            <div style="min-width:0;flex:1;">
              <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                <span class="icon-tile sm {sm.dot === 'ok' ? '' : sm.dot === 'danger' ? 'danger' : 'muted'}">
                  <Icons name="port_forward" size={14} />
                </span>
                <span style="font-weight:700;font-size:15px;">{pf.name}</span>
                <span class="port-pill mono">
                  <span class="port-pill-lead">:{pf.listen_port}/{pf.proto}</span>
                  <span>→ {(pf.targets?.length ? pf.targets : [pf.target])[0]}</span>
                </span>
                <span class="badge {sm.cls}">{sm.text}{#if famLabel} · {famLabel}{/if}{#if rt && rt.active_conns > 0} · {rt.active_conns}c{/if}</span>
                <span class="badge badge-muted">{pf.engine}</span>
                  {#if pf.open_wan_firewall || pf.engine === 'kernel_dnat'}
                    <span class="badge badge-warn">WAN Open</span>
                  {/if}
                  {#if pf.allowed_cidrs?.length}
                    <span class="badge badge-muted">CIDR ({pf.allowed_cidrs.length})</span>
                  {/if}
                  {#if pf.send_proxy_protocol !== 'none'}
                    <span class="badge badge-info">PP {pf.send_proxy_protocol}</span>
                  {/if}
                  {#if pf.allowed_time_window}
                    <span class="badge badge-warn mono">{pf.allowed_time_window}</span>
                  {/if}
                  {#if pf.expire_at_unix > 0}
                    <span class="badge {pf.expire_at_unix > nowSec ? 'badge-ok' : 'badge-danger'} mono">
                      Lease: {pf.expire_at_unix > nowSec ? `${Math.ceil((pf.expire_at_unix - nowSec) / 60)}m` : `${t.common.statusExpired} (${formatUnixTime(pf.expire_at_unix)})`}
                    </span>
                  {/if}
                </div>
                <div class="mono" style="font-size:12.5px;color:var(--text-secondary);margin-top:6px;word-break:break-all;">
                  Targets ({pf.load_balance}): {(pf.targets?.length ? pf.targets : [pf.target]).join(', ')}
                  {#if pf.bind_interface} · via {pf.bind_interface}{/if}
                </div>
                {#if rt?.last_error}
                  <div class="mono" style="font-size:11.5px;color:var(--danger);margin-top:4px;word-break:break-word;">{rt.last_error}</div>
                {/if}
              </div>
              <div class="btn-group">
                <button type="button" class="btn btn-xs" disabled={Boolean(busyLeaseKey)} onclick={() => grantLease(pf.name, 15)}>+15m</button>
                <button type="button" class="btn btn-xs" disabled={Boolean(busyLeaseKey)} onclick={() => grantLease(pf.name, 60)}>+1h</button>
                <button
                  type="button"
                  class="btn btn-xs"
                  onclick={() => { customLeaseName = customLeaseName === pf.name ? '' : pf.name; customLeaseMins = 30; }}
                >
                  +…m
                </button>
                {#if pf.expire_at_unix > 0}
                  <button type="button" class="btn btn-xs" disabled={Boolean(busyLeaseKey)} title={t.pf.permanent} onclick={() => grantLease(pf.name, 0)}>∞</button>
                {/if}
                <button
                  type="button"
                  role="switch"
                  aria-checked={pf.enabled}
                  aria-label={t.nav.port_forward}
                  class="switch"
                  disabled={busyToggleKey === `pf:${idx}`}
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
            {#if customLeaseName === pf.name}
              <div class="btn-group" style="margin-top:8px;padding-top:8px;border-top:1px solid var(--border-subtle);">
                <input
                  type="number"
                  min="1"
                  max="1440"
                  class="mono control-compact"
                  style="width:110px;"
                  bind:value={customLeaseMins}
                />
                <span style="font-size:12px;color:var(--text-secondary);">min (1~1440)</span>
                <button
                  type="button"
                  class="btn btn-xs btn-primary"
                  disabled={Boolean(busyLeaseKey)}
                  onclick={() => grantLease(pf.name, Math.max(1, Math.min(1440, Number(customLeaseMins) || 30)))}
                >
                  {t.confirmAction}
                </button>
              </div>
            {/if}
          </div>
        {/each}
      </div>
    {/if}
{/if}

<!-- 反代监听器编辑弹窗 -->
<EditorDialog
  open={rpDrawerOpen && Boolean(rpDraft)}
  title={`${rpEditIndex >= 0 ? t.edit : t.add} · ${t.nav.reverse_proxy}`}
  size="sm"
  busy={saving}
  {t}
  {askConfirm}
  onSubmit={saveListener}
  onClose={() => (rpDrawerOpen = false)}
>
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
            <Select
              id="rp-stack"
              bind:value={rpDraft.stack}
              options={[
                { value: 'dual', label: lang === 'en' ? 'Dual Stack (IPv4 + IPv6)' : '双栈 (IPv4 + IPv6)' },
                { value: 'ipv4_only', label: lang === 'en' ? 'IPv4 Only' : '仅 IPv4' },
                { value: 'ipv6_only', label: lang === 'en' ? 'IPv6 Only' : '仅 IPv6' },
              ]}
            />
          </div>
          <div class="field">
            <label for="rp-maxc">{t.rp.maxConns}</label>
            <input id="rp-maxc" type="number" min="1" max="4096" bind:value={rpDraft.max_concurrent_conns} required />
          </div>
        </div>
        {#if rpDraft.open_wan_firewall && isProtectedPort(rpDraft.listen_port)}
          <div class="banner banner-warn" style="margin-bottom:10px;">{t.rp.protectedPortWarn}</div>
        {/if}
        <div style="display:grid;gap:4px;">
          <label class="check-row"><input type="checkbox" bind:checked={rpDraft.enabled} /> {t.enabled}</label>
          <label class="check-row"><input type="checkbox" bind:checked={rpDraft.strict_sni} /> {t.rp.strictSni}</label>
          <label class="check-row"><input type="checkbox" bind:checked={rpDraft.open_wan_firewall} /> {t.rp.openWan}</label>
        </div>
</EditorDialog>

<!-- 反代子规则编辑弹窗 -->
<EditorDialog
  open={ruleDrawerOpen && Boolean(ruleDraft)}
  title={`${ruleEditIndex >= 0 ? t.edit : t.add} · ${t.rp.addRule}`}
  size="md"
  busy={saving}
  {t}
  {askConfirm}
  onSubmit={saveRule}
  onClose={() => (ruleDrawerOpen = false)}
>
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
            <Select
              id="rr-mode"
              bind:value={ruleDraft.mode}
              options={[
                { value: 'proxy', label: lang === 'en' ? 'Reverse Proxy' : '反向代理转发' },
                { value: 'redirect', label: lang === 'en' ? 'HTTP Redirect (301/302/307/308)' : '网址跳转重定向' },
                { value: 'static', label: lang === 'en' ? 'Static Response' : '直接返回静态内容' },
              ]}
            />
          </div>
        </div>

        <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:10px;">
          <label class="check-row"><input type="checkbox" bind:checked={ruleDraft.enabled} /> {t.enabled}</label>
          <label class="check-row"><input type="checkbox" bind:checked={ruleDraft.auth_gate} /> {t.rp.authGate}</label>
        </div>

        {#if ruleDraft.auth_gate}
          <div class="subcard" style="margin-bottom:12px;display:grid;gap:8px;">
            <div class="row-between">
              <span style="font-size:12.5px;font-weight:600;color:var(--text-primary);display:flex;align-items:center;gap:6px;">
                <Icons name="lock" size={13} />
                <span>{t.rp.gateRuleUsersLabel}</span>
              </span>
              <button type="button" class="btn btn-xs" onclick={openGateUsersModal}>
                <Icons name="user" size={12} />
                <span>{t.rp.gateRuleManageBtn}</span>
              </button>
            </div>
            {#if effectiveGateUsers.length === 0}
              <div class="banner banner-warn" style="margin:0;">{t.rp.gateRuleNoUsersWarn}</div>
            {:else}
              <div class="btn-group" style="gap:6px;">
                {#each effectiveGateUsers as gu (gu.username)}
                  {@const picked = (ruleDraft.auth_gate_users || []).includes(gu.username)}
                  <button
                    type="button"
                    data-dirty="1"
                    class="chip mono"
                    style={picked ? 'background:var(--accent-soft);border-color:var(--accent);color:var(--accent);font-weight:600;' : ''}
                    onclick={() => toggleRuleGateUser(gu.username)}
                  >
                    {#if picked}<Icons name="check" size={12} />{/if}
                    <span>{gu.username}</span>
                    {#if !gu.enabled}
                      <span style="opacity:.7;font-size:11px;">({t.disabled})</span>
                    {/if}
                  </button>
                {/each}
              </div>
              {#if !(ruleDraft.auth_gate_users || []).length}
                <div class="banner banner-warn" style="margin:0;">{t.rp.gateRuleNoneSelectedWarn}</div>
              {/if}
            {/if}
            <div class="field-hint" style="margin:0;">{t.rp.gateRulePortalHint}</div>
          </div>
        {/if}

        {#if ruleDraft.mode === 'proxy'}
          <div class="field">
            <label for="rr-up">{t.rp.upstream}</label>
            <input id="rr-up" type="text" class="mono" placeholder="http://192.168.1.10:5000" bind:value={ruleDraft.upstream} required />
          </div>
          <div class="form-grid">
            <div class="field">
              <label for="rr-tls">{t.rp.tlsVerify}</label>
              <Select
                id="rr-tls"
                bind:value={ruleDraft.upstream_tls_mode}
                options={[
                  { value: 'strict', label: lang === 'en' ? 'Verify System CA (Recommended)' : '校验有效证书（推荐）' },
                  { value: 'pinned_sha256', label: lang === 'en' ? 'Pin Certificate SHA-256' : '锁定指定证书指纹' },
                  { value: 'insecure_skip_verify', label: lang === 'en' ? 'Skip Verification (Self-Signed LAN)' : '忽略证书校验（内网自签）' },
                ]}
              />
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
              <Select
                id="rr-rcode"
                mono
                bind:value={ruleDraft.redirect_code}
                options={[301, 302, 307, 308]}
              />
            </div>
            <div class="field">
              <label for="rr-rurl">{t.rp.redirectUrl}</label>
              <input id="rr-rurl" type="text" class="mono" bind:value={ruleDraft.redirect_url} required />
            </div>
          </div>
          {#if stunRuleNames.length > 0}
            <div class="btn-group" style="margin-bottom:10px;">
              <span style="font-size:12px;color:var(--text-muted);">{t.rp.stunInsertLabel}</span>
              {#each stunRuleNames as sName (sName)}
                <button
                  type="button"
                  class="chip mono"
                  onclick={() => { ruleDraft.redirect_url = `https://{{stun.${sName}.public_addr}}{{path}}`; }}
                >
                  {sName}
                </button>
              {/each}
            </div>
          {/if}
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
              {#if ruleDraft.mode === 'proxy'}
                <div class="field">
                  <label for="rr-maxb">{t.rp.maxBodyMb}</label>
                  <input id="rr-maxb" type="number" min="0" bind:value={ruleDraft.max_body_mb} />
                </div>
                <div class="field">
                  <label for="rr-rto">{t.rp.readTimeout}</label>
                  <input id="rr-rto" type="number" min="1" max="86400" bind:value={ruleDraft.read_timeout_secs} />
                </div>
              {/if}
            </div>
            {#if ruleDraft.mode === 'proxy'}
              <HeaderRowsEditor
                label={t.rp.reqHeadersSet}
                bind:rows={ruleReqRows}
                secret={true}
                forbidProtocolHeaders={true}
                {t}
              />
            {/if}
            <HeaderRowsEditor
              label={t.rp.respHeadersSet}
              bind:rows={ruleRespRows}
              secret={false}
              forbidProtocolHeaders={true}
              {t}
            />
            <div class="form-grid">
              {#if ruleDraft.mode === 'proxy'}
                <div class="field">
                  <label for="rr-rqrem">{t.rp.reqHeadersRem}</label>
                  <input id="rr-rqrem" type="text" class="mono" placeholder="X-Debug, Server" bind:value={ruleReqRemCsv} />
                </div>
              {/if}
              <div class="field">
                <label for="rr-rsrem">{t.rp.respHeadersRem}</label>
                <input id="rr-rsrem" type="text" class="mono" placeholder="X-Powered-By" bind:value={ruleRespRemCsv} />
              </div>
            </div>
          </div>
        </details>
</EditorDialog>

<!-- 反向代理独立门禁账号管理弹窗 -->
<EditorDialog
  open={gateUsersOpen}
  title={t.rp.gateUsersTitle}
  size="md"
  form={false}
  confirmDiscard={false}
  {t}
  onClose={() => {
    gateUsersOpen = false;
    gateFormMode = '';
  }}
>
  <div class="banner banner-info" style="margin-bottom:12px;">{t.rp.gateUsersDesc}</div>

  <div class="row-between" style="margin-bottom:12px;">
    <span style="font-size:12.5px;color:var(--text-secondary);">
      {t.all}: <strong class="num">{effectiveGateUsers.length}</strong>
    </span>
    {#if gateFormMode === ''}
      <button type="button" class="btn btn-primary btn-xs" onclick={startCreateGateUser}>
        <Icons name="plus" size={13} />
        <span>{t.rp.gateAddUser}</span>
      </button>
    {/if}
  </div>

  {#if gateFormMode !== ''}
    <form class="subcard" style="margin-bottom:12px;display:grid;gap:10px;" onsubmit={submitGateUser}>
      <div class="row-between">
        <span style="font-weight:700;font-size:13.5px;">
          {gateFormMode === 'create' ? t.rp.gateAddUser : `${t.rp.gateEditUser} · ${gateDraft.username}`}
        </span>
        <button type="button" class="btn btn-ghost btn-xs" onclick={() => { gateFormMode = ''; gateErr = ''; }}>
          {t.cancel}
        </button>
      </div>
      {#if gateErr}
        <div role="alert" class="banner banner-danger" style="margin:0;">{gateErr}</div>
      {/if}
      <div class="form-grid">
        <div class="field">
          <label for="gu-name">{t.rp.gateUsername}</label>
          <input
            id="gu-name"
            type="text"
            class="mono"
            placeholder={t.rp.gateUsernamePh}
            bind:value={gateDraft.username}
            disabled={gateFormMode === 'edit'}
            required
          />
        </div>
        <div class="field">
          <label for="gu-ttl">{t.rp.gateTtl}</label>
          <Select id="gu-ttl" bind:value={gateDraft.session_ttl_secs} options={gateTtlOptions} />
        </div>
      </div>
      <div class="field">
        <label for="gu-pw">{t.rp.gatePassword}</label>
        <div style="position:relative;display:flex;align-items:center;">
          <input
            id="gu-pw"
            type={gateShowPw ? 'text' : 'password'}
            autocomplete="new-password"
            placeholder={gateFormMode === 'create' ? t.rp.gatePasswordPh : t.rp.gatePasswordKeepPh}
            bind:value={gateDraft.password}
            required={gateFormMode === 'create'}
            style="padding-right:38px;"
          />
          <button
            type="button"
            class="btn btn-ghost btn-xs"
            aria-label={t.common.toggleSecret}
            style="position:absolute;right:4px;"
            onclick={() => (gateShowPw = !gateShowPw)}
          >
            <Icons name={gateShowPw ? 'eye_off' : 'eye'} size={14} />
          </button>
        </div>
      </div>
      <div class="field">
        <label for="gu-note">{t.rp.gateNote}</label>
        <input id="gu-note" type="text" placeholder={t.rp.gateNotePh} bind:value={gateDraft.note} />
      </div>
      <div class="row-between">
        <label class="check-row"><input type="checkbox" bind:checked={gateDraft.enabled} /> {t.enabled}</label>
        <div class="btn-group">
          <button type="button" class="btn btn-xs" disabled={gateSaving} onclick={() => { gateFormMode = ''; gateErr = ''; }}>
            {t.cancel}
          </button>
          <button type="submit" class="btn btn-primary btn-xs" disabled={gateSaving}>
            {gateSaving ? '...' : t.confirm}
          </button>
        </div>
      </div>
    </form>
  {/if}

  {#if gateUsersLoading && !gateUsersLoaded}
    <div style="font-size:12.5px;color:var(--text-muted);padding:12px 0;text-align:center;">{t.common.loading}</div>
  {:else if !effectiveGateUsers.length}
    <div class="empty-state" style="padding:24px 16px;">{t.rp.gateNoUsers}</div>
  {:else}
    <div style="display:grid;gap:8px;">
      {#each effectiveGateUsers as u (u.username)}
        <div class="rule-card">
          <div class="row-between">
            <div style="min-width:0;flex:1;">
              <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                <span class="mono" style="font-weight:700;font-size:13.5px;">{u.username}</span>
                <span class="badge {u.enabled ? 'badge-ok' : 'badge-muted'}">{u.enabled ? t.enabled : t.disabled}</span>
                <span class="badge badge-muted">{formatGateTtl(u.session_ttl_secs)}</span>
                <span class="badge badge-info">{t.rp.gateBoundRules}: {u.bound_rules || 0}</span>
                {#if (u.active_sessions || 0) > 0}
                  <span class="badge badge-ok">{t.rp.gateActiveSess}: {u.active_sessions}</span>
                {/if}
              </div>
              {#if u.note}
                <div style="font-size:12px;color:var(--text-secondary);margin-top:4px;">{u.note}</div>
              {/if}
            </div>
            <div class="btn-group">
              {#if (u.active_sessions || 0) > 0}
                <button
                  type="button"
                  class="btn btn-xs"
                  disabled={gateBusyUser === u.username}
                  onclick={() => revokeGateUserSessions(u)}
                >
                  <Icons name="logout" size={12} />
                  <span>{t.rp.gateRevokeBtn}</span>
                </button>
              {/if}
              <button
                type="button"
                role="switch"
                aria-checked={u.enabled}
                aria-label={u.username}
                class="switch"
                disabled={gateBusyUser === u.username}
                onclick={() => toggleGateUserEnabled(u)}
              >
                <span class="switch-thumb"></span>
              </button>
              <button type="button" class="btn btn-xs" onclick={() => startEditGateUser(u)}>{t.edit}</button>
              <button
                type="button"
                class="btn btn-xs btn-danger"
                disabled={gateBusyUser === u.username}
                onclick={() => deleteGateUser(u)}
              >
                {t.delete}
              </button>
            </div>
          </div>
        </div>
      {/each}
    </div>
  {/if}
</EditorDialog>

<!-- 端口转发编辑弹窗 -->
<EditorDialog
  open={pfDrawerOpen && Boolean(pfDraft)}
  title={`${pfEditIndex >= 0 ? t.edit : t.add} · ${t.nav.port_forward}`}
  size="md"
  busy={saving}
  {t}
  {askConfirm}
  onSubmit={savePortForward}
  onClose={() => (pfDrawerOpen = false)}
>
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
            <Select
              id="pf-proto"
              bind:value={pfDraft.proto}
              options={[
                { value: 'tcp', label: 'TCP' },
                { value: 'udp', label: 'UDP' },
                { value: 'tcp_udp', label: 'TCP + UDP' },
              ]}
            />
          </div>
          <div class="field">
            <label for="pf-eng">{t.pf.engine}</label>
            <Select
              id="pf-eng"
              bind:value={pfDraft.engine}
              options={[
                { value: 'userspace_splice', label: lang === 'en' ? 'Smart Proxy (Cross-Stack & LB)' : '智能转发（支持跨栈与多目标）' },
                { value: 'kernel_dnat', label: lang === 'en' ? 'Kernel DNAT (Same-Stack Direct)' : '系统内核直转（仅限单目标同协议栈）' },
              ]}
              onchange={onPfEngineChange}
            />
          </div>
          <div class="field">
            <label for="pf-stack">{t.pf.stack}</label>
            <Select
              id="pf-stack"
              bind:value={pfDraft.stack}
              options={[
                ...(pfDraft.engine !== 'kernel_dnat'
                  ? [{ value: 'dual', label: lang === 'en' ? 'Dual Stack (IPv4 + IPv6)' : '双栈 (IPv4 + IPv6)' }]
                  : []),
                { value: 'ipv4_only', label: lang === 'en' ? 'IPv4 Only' : '仅 IPv4' },
                { value: 'ipv6_only', label: lang === 'en' ? 'IPv6 Only' : '仅 IPv6' },
              ]}
            />
          </div>
          {#if pfDraft.engine !== 'kernel_dnat'}
            <div class="field">
              <label for="pf-lb">{t.pf.loadBalance}</label>
              <Select
                id="pf-lb"
                bind:value={pfDraft.load_balance}
                options={[
                  { value: 'failover', label: lang === 'en' ? 'Primary / Backup Failover' : '主备容灾（优先首个目标）' },
                  { value: 'round_robin', label: lang === 'en' ? 'Round Robin' : '轮询分流' },
                ]}
              />
            </div>
          {/if}
        </div>

        {#if (pfDraft.open_wan_firewall || pfDraft.engine === 'kernel_dnat') && isProtectedPort(pfDraft.listen_port)}
          <div class="banner banner-warn" style="margin-bottom:12px;">{t.rp.protectedPortWarn}</div>
        {/if}

        {#if pfDraft.engine === 'kernel_dnat'}
          <div class="banner banner-info" style="margin-bottom:14px;">{t.pf.dnatHint}</div>
        {/if}

        <div class="form-grid">
          <div class="field">
            <label for="pf-targets">{t.pf.targets}</label>
            <input id="pf-targets" type="text" class="mono" placeholder="192.168.1.10:8080" bind:value={pfTargetsCsv} required />
          </div>
          <div class="field">
            <label for="pf-win">{t.pf.timeWindow}</label>
            <input id="pf-win" type="text" class="mono" placeholder="08:00-23:30" bind:value={pfDraft.allowed_time_window} />
          </div>
        </div>

        {#if pfDraft.engine !== 'kernel_dnat'}
          <div class="form-grid">
            {#if pfDraft.proto !== 'udp'}
              <div class="field">
                <label for="pf-pp">{t.pf.proxyProto}</label>
                <Select
                  id="pf-pp"
                  bind:value={pfDraft.send_proxy_protocol}
                  options={[
                    { value: 'none', label: 'none' },
                    { value: 'v1', label: 'v1 (Text)' },
                    { value: 'v2', label: 'v2 (Binary)' },
                  ]}
                />
              </div>
            {/if}
            <div class="field">
              <label for="pf-cidr">{t.pf.allowCidrs}</label>
              <input id="pf-cidr" type="text" class="mono" placeholder="192.168.0.0/16" bind:value={pfAllowedCsv} />
            </div>
            <div class="field">
              <label for="pf-iface">{t.pf.bindIface}</label>
              <ComboInput id="pf-iface" options={ifaceOptions} bind:value={pfDraft.bind_interface} />
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
              {#if pfDraft.proto !== 'udp'}
                <div class="field">
                  <label for="pf-tcpid">{t.pf.tcpIdle}</label>
                  <input id="pf-tcpid" type="number" min="5" max="86400" bind:value={pfDraft.tcp_idle_timeout_secs} />
                </div>
                <div class="field">
                  <label for="pf-hci">{t.pf.hcInterval}</label>
                  <input id="pf-hci" type="number" min="0" max="3600" bind:value={pfDraft.health_check_interval_secs} />
                </div>
              {/if}
              {#if pfDraft.proto !== 'tcp'}
                <div class="field">
                  <label for="pf-udpid">{t.pf.udpIdle}</label>
                  <input id="pf-udpid" type="number" min="10" max="600" bind:value={pfDraft.udp_session_timeout_secs} />
                </div>
              {/if}
            </div>
          </details>
        {/if}

        <div style="display:flex;gap:18px;flex-wrap:wrap;">
          <label class="check-row"><input type="checkbox" bind:checked={pfDraft.enabled} /> {t.enabled}</label>
          <label class="check-row">
            <input
              type="checkbox"
              checked={pfDraft.engine === 'kernel_dnat' ? true : pfDraft.open_wan_firewall}
              disabled={pfDraft.engine === 'kernel_dnat'}
              onchange={(e) => { pfDraft.open_wan_firewall = e.currentTarget.checked; }}
            />
            {t.pf.openWan}
          </label>
        </div>
</EditorDialog>
