<script>
  import { I18N } from './lib/i18n.js';
  import { localizeError } from './lib/helpers.js';
  import Icons from './components/Icons.svelte';
  import ToastStack from './components/ToastStack.svelte';
  import ConfirmModal from './components/ConfirmModal.svelte';
  import AuthGate from './components/AuthGate.svelte';
  import DashboardView from './components/DashboardView.svelte';
  import NetworkRulesView from './components/NetworkRulesView.svelte';
  import DomainCertStunView from './components/DomainCertStunView.svelte';
  import OpsViews from './components/OpsViews.svelte';
  import SettingsView from './components/SettingsView.svelte';

  const VALID_TABS = new Set([
    'dashboard',
    'reverse_proxy',
    'port_forward',
    'ddns',
    'acme',
    'stun',
    'docker',
    'web_terminal',
    'cron',
    'logs',
    'settings',
  ]);

  function parseHash() {
    const raw = (location.hash || '').replace(/^#\/?/, '');
    if (!raw) return { tab: 'dashboard', sub: 'general' };
    const [tabPart, subPart] = raw.split('/');
    return {
      tab: VALID_TABS.has(tabPart) ? tabPart : 'dashboard',
      sub: ['general', 'security', 'notifications', 'backup'].includes(subPart) ? subPart : 'general',
    };
  }

  const storedLang = localStorage.getItem('vane_lang');
  let hasExplicitLang = storedLang === 'zh' || storedLang === 'en';
  let lang = $state(hasExplicitLang ? (storedLang === 'en' ? 'en' : 'zh') : 'zh');
  let t = $derived(I18N[lang] || I18N.zh);

  let loading = $state(true);
  let authenticated = $state(false);
  let mustChangePassword = $state(false);
  let authConnError = $state('');
  let username = $state('admin');
  let passwordLoginEnabled = $state(true);
  let totpEnabled = $state(false);
  let hasEd25519Keys = $state(false);
  let ed25519KeyIds = $state([]);
  let sessionTtlSecs = $state(3600);

  const initHash = parseHash();
  let themeMode = $state(localStorage.getItem('vane_theme_mode') || 'dark');
  let activeTab = $state(initHash.tab);
  let settingsSubTab = $state(initHash.sub);
  let mobileMoreOpen = $state(false);
  let toasts = $state([]);
  let nextToastId = 1;

  // 全局确认框状态
  let confirmState = $state({
    open: false,
    title: '',
    message: '',
    confirmLabel: '',
    danger: true,
    busy: false,
    onConfirm: null,
  });

  let modules = $state({
    reverse_proxy: true,
    port_forward: true,
    ddns: true,
    acme: true,
    stun: false,
    web_terminal: false,
    cron: false,
    docker: true,
  });

  let dashboard = $state(null);
  let settingsJson = $state(null);
  let networkInfo = $state(null);
  let logs = $state([]);
  let logModules = $state([]);
  let logCapacity = $state(300);
  let logLevelFilter = $state('');
  let logModuleFilter = $state('');
  let containers = $state([]);
  let dockerError = $state('');
  let restartRequiredFields = $state([]);
  let refreshing = $state(false);
  let refreshNonce = 0;

  // Web 终端按需异步加载分包（关闭时 0 字节下载），开启连接后切 Tab 不卸载
  let TerminalComp = $state(null);
  let ptyLoadError = $state('');
  let ptyEverOpened = $state(false);
  let terminalInitialTarget = $state('host');
  let terminalTargetNonce = $state(0);
  const toastTimers = new Map();

  let navGroups = $derived.by(() => {
    const groups = [
      {
        label: t.navGroups.overview,
        items: [{ id: 'dashboard', label: t.nav.dashboard, always: true }],
      },
      {
        label: t.navGroups.traffic,
        items: [
          {
            id: 'reverse_proxy',
            label: t.nav.reverse_proxy,
            enabled: modules.reverse_proxy,
            count: settingsJson?.reverse_proxy?.length,
          },
          {
            id: 'port_forward',
            label: t.nav.port_forward,
            enabled: modules.port_forward,
            count: settingsJson?.port_forwards?.length,
          },
        ],
      },
      {
        label: t.navGroups.domain,
        items: [
          { id: 'ddns', label: t.nav.ddns, enabled: modules.ddns, count: settingsJson?.ddns?.length },
          { id: 'acme', label: t.nav.acme, enabled: modules.acme, count: settingsJson?.acme?.length },
          { id: 'stun', label: t.nav.stun, enabled: modules.stun, count: settingsJson?.stun?.length },
        ],
      },
      {
        label: t.navGroups.ops,
        items: [
          {
            id: 'docker',
            label: t.nav.docker,
            enabled: modules.docker,
            count: containers.length || undefined,
          },
          { id: 'web_terminal', label: t.nav.web_terminal, enabled: modules.web_terminal },
          { id: 'cron', label: t.nav.cron, enabled: modules.cron, count: settingsJson?.cron?.length },
          { id: 'logs', label: t.nav.logs, always: true },
        ],
      },
      {
        label: t.navGroups.system,
        items: [{ id: 'settings', label: t.nav.settings, always: true }],
      },
    ];
    return groups
      .map((g) => ({ ...g, items: g.items.filter((item) => item.always || item.enabled) }))
      .filter((g) => g.items.length > 0);
  });

  let navItems = $derived(navGroups.flatMap((g) => g.items));

  let mobilePrimaryItems = $derived.by(() => {
    const picked = [navItems[0]];
    for (const candidate of ['reverse_proxy', 'port_forward', 'ddns', 'docker', 'logs']) {
      if (picked.length >= 3) break;
      const found = navItems.find((n) => n.id === candidate && !picked.some((p) => p.id === n.id));
      if (found) picked.push(found);
    }
    const settingsItem = navItems.find((n) => n.id === 'settings');
    if (settingsItem && !picked.some((p) => p.id === 'settings')) picked.push(settingsItem);
    return picked;
  });

  $effect(() => {
    localStorage.setItem('vane_theme_mode', themeMode);
    const mq = window.matchMedia('(prefers-color-scheme: light)');
    const apply = () => {
      const resolved = themeMode === 'auto' ? (mq.matches ? 'light' : 'dark') : themeMode;
      document.documentElement.setAttribute('data-theme', resolved);
      const meta = document.querySelector('meta[name="theme-color"]');
      if (meta) meta.setAttribute('content', resolved === 'light' ? '#f1f5f9' : '#080a0f');
    };
    apply();
    mq.addEventListener('change', apply);
    return () => mq.removeEventListener('change', apply);
  });

  $effect(() => {
    document.documentElement.setAttribute('lang', lang === 'en' ? 'en' : 'zh-CN');
  });

  function loadTerminalChunk() {
    ptyLoadError = '';
    import('./components/TerminalView.svelte')
      .then((m) => {
        TerminalComp = m.default;
      })
      .catch((err) => {
        ptyLoadError = err?.message || t.ptyLoadFailed;
      });
  }

  $effect(() => {
    if (activeTab === 'web_terminal' && modules.web_terminal) {
      ptyEverOpened = true;
      if (!TerminalComp && !ptyLoadError) {
        loadTerminalChunk();
      }
    }
    if (!modules.web_terminal) {
      ptyEverOpened = false;
    }
  });

  function isTabAvailable(tab) {
    if (['dashboard', 'logs', 'settings'].includes(tab)) return true;
    return Boolean(modules[tab]);
  }

  function syncUrlHash(tab, sub = settingsSubTab, push = false) {
    const nextHash = tab === 'settings' && sub !== 'general' ? `#settings/${sub}` : `#${tab}`;
    if (location.hash !== nextHash) {
      if (push) history.pushState(null, '', nextHash);
      else history.replaceState(null, '', nextHash);
    }
  }

  function handleHashChange() {
    const { tab, sub } = parseHash();
    const safeTab = isTabAvailable(tab) ? tab : 'dashboard';
    if (safeTab !== tab) syncUrlHash(safeTab, 'general', false);
    if (safeTab !== activeTab || sub !== settingsSubTab) {
      activeTab = safeTab;
      settingsSubTab = safeTab === 'settings' ? sub : 'general';
      refreshActiveView(true);
    }
  }

  function toggleLang() {
    lang = lang === 'zh' ? 'en' : 'zh';
    hasExplicitLang = true;
    localStorage.setItem('vane_lang', lang);
  }

  function cycleTheme() {
    themeMode = themeMode === 'dark' ? 'light' : themeMode === 'light' ? 'auto' : 'dark';
  }

  function themeLabel() {
    if (themeMode === 'light') return t.themeLight;
    if (themeMode === 'auto') return t.themeAuto;
    return t.themeDark;
  }

  function themeIcon() {
    if (themeMode === 'light') return 'sun';
    if (themeMode === 'auto') return 'monitor';
    return 'moon';
  }

  function dismissToast(id) {
    const timer = toastTimers.get(id);
    if (timer) {
      clearTimeout(timer);
      toastTimers.delete(id);
    }
    toasts = toasts.filter((x) => x.id !== id);
  }

  function pauseToast(id) {
    const timer = toastTimers.get(id);
    if (timer) {
      clearTimeout(timer);
      toastTimers.delete(id);
    }
  }

  function resumeToast(id) {
    const item = toasts.find((x) => x.id === id);
    if (!item || toastTimers.has(id)) return;
    const duration = item.type === 'error' || item.type === 'warn' ? 4000 : 2500;
    toastTimers.set(id, setTimeout(() => dismissToast(id), duration));
  }

  function showToast(msg, type = 'info') {
    const id = nextToastId++;
    const duration = type === 'error' || type === 'warn' ? 6000 : 3500;
    toasts = [...toasts.slice(-3), { id, message: String(msg), type }];
    toastTimers.set(id, setTimeout(() => dismissToast(id), duration));
  }

  function askConfirm({ title, message, confirmLabel = '', danger = true, onConfirm }) {
    confirmState = {
      open: true,
      title,
      message,
      confirmLabel: confirmLabel || t.confirmAction,
      danger,
      busy: false,
      onConfirm,
    };
  }

  async function runConfirmedAction() {
    if (!confirmState.onConfirm) {
      confirmState.open = false;
      return;
    }
    confirmState.busy = true;
    try {
      await confirmState.onConfirm();
      confirmState.open = false;
    } finally {
      confirmState.busy = false;
    }
  }

  function moduleStatusDot(id) {
    if (id === 'dashboard') {
      if ((dashboard?.bans?.length || 0) > 0) return 'warn';
      return '';
    }
    const st = dashboard?.module_health?.[id]?.state;
    if (st === 'circuit_open') return 'danger';
    if (st === 'degraded') return 'warn';
    return '';
  }

  function clearSessionState() {
    authenticated = false;
    mustChangePassword = false;
    dashboard = null;
    settingsJson = null;
    networkInfo = null;
    containers = [];
    dockerError = '';
    logs = [];
    logModules = [];
    restartRequiredFields = [];
    mobileMoreOpen = false;
    ptyEverOpened = false;
  }

  async function apiFetch(path, options = {}) {
    const res = await fetch(path, {
      headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
      ...options,
    });
    const data = await res.json().catch(() => ({}));
    if (res.status === 403 && data.error === 'MUST_CHANGE_INITIAL_PASSWORD') {
      mustChangePassword = true;
      throw new Error(localizeError(data.message || 'Must change initial password', lang, data.error));
    }
    if (res.status === 401 && !path.startsWith('/api/auth/')) {
      clearSessionState();
      throw new Error(t.errors.UNAUTHORIZED);
    }
    if (!res.ok) {
      throw new Error(localizeError(data.message || data.error || `HTTP ${res.status}`, lang, data.error));
    }
    return data;
  }

  function applyAuthStatus(st) {
    authenticated = Boolean(st.authenticated);
    mustChangePassword = Boolean(st.must_change_password);
    username = st.username || 'admin';
    if ('password_login_enabled' in st) passwordLoginEnabled = Boolean(st.password_login_enabled);
    if ('totp_enabled' in st) totpEnabled = Boolean(st.totp_enabled);
    if ('has_ed25519_keys' in st) hasEd25519Keys = Boolean(st.has_ed25519_keys);
    if (Array.isArray(st.ed25519_key_ids)) ed25519KeyIds = st.ed25519_key_ids;
    sessionTtlSecs = st.session_ttl_secs || 3600;
    if (st.language && !hasExplicitLang) {
      lang = st.language === 'en' ? 'en' : 'zh';
    }
    if (st.modules) modules = st.modules;
  }

  async function checkAuthStatus() {
    loading = true;
    authConnError = '';
    try {
      const st = await apiFetch('/api/auth/status');
      applyAuthStatus(st);
      if (authenticated && !mustChangePassword) {
        if (!modules[activeTab] && !['dashboard', 'logs', 'settings'].includes(activeTab)) {
          activeTab = 'dashboard';
        }
        await refreshActiveView();
      }
    } catch (err) {
      authenticated = false;
      authConnError = err?.message || 'Connection failed';
    } finally {
      loading = false;
    }
  }

  async function refreshAuthStatusOnly() {
    try {
      const st = await apiFetch('/api/auth/status');
      applyAuthStatus(st);
    } catch {
      // ignore
    }
  }

  async function handleAuthenticated(st, toastMsg = '') {
    authConnError = '';
    applyAuthStatus(st);
    if (toastMsg) showToast(toastMsg, 'success');
    if (authenticated && !mustChangePassword) {
      if (!isTabAvailable(activeTab)) {
        activeTab = 'dashboard';
      }
      syncUrlHash(activeTab, settingsSubTab, false);
      await refreshActiveView();
    }
  }

  async function logout() {
    await apiFetch('/api/auth/logout', { method: 'POST' }).catch(() => {});
    clearSessionState();
    await checkAuthStatus();
  }

  async function ensureNetworkInfo(force = false) {
    if (!force && networkInfo) return;
    try {
      networkInfo = await apiFetch('/api/system/network-info');
    } catch {
      // ignore on restricted environments
    }
  }

  async function refreshActiveView(silent = false) {
    if (!authenticated || mustChangePassword) return;
    const myNonce = ++refreshNonce;
    const tab = activeTab;
    if (!silent) refreshing = true;
    try {
      const tasks = [];
      if (['dashboard', 'reverse_proxy', 'port_forward', 'ddns', 'acme', 'stun', 'cron'].includes(tab)) {
        tasks.push(
          apiFetch('/api/dashboard').then((r) => {
            if (myNonce === refreshNonce) dashboard = r;
          })
        );
      } else if (!dashboard) {
        tasks.push(
          apiFetch('/api/dashboard')
            .then((r) => {
              if (myNonce === refreshNonce) dashboard = r;
            })
            .catch(() => {})
        );
      }

      if (tab === 'logs') {
        const params = new URLSearchParams();
        if (logLevelFilter) params.set('level', logLevelFilter);
        if (logModuleFilter) params.set('module', logModuleFilter);
        const qs = params.toString();
        tasks.push(
          apiFetch(`/api/logs${qs ? `?${qs}` : ''}`).then((r) => {
            if (myNonce !== refreshNonce) return;
            logs = r.entries || [];
            logModules = r.modules || [];
            if (r.capacity) logCapacity = r.capacity;
            if (logModuleFilter && !logModules.includes(logModuleFilter)) {
              logModuleFilter = '';
            }
          })
        );
      }

      if (['dashboard', 'settings', 'reverse_proxy', 'port_forward', 'ddns', 'acme', 'stun', 'cron', 'docker', 'web_terminal'].includes(tab)) {
        if (!silent || !settingsJson) {
          tasks.push(
            apiFetch('/api/settings').then((r) => {
              if (myNonce !== refreshNonce) return;
              settingsJson = r;
              if (r?.modules) modules = r.modules;
            })
          );
        }
      }

      if (['reverse_proxy', 'port_forward', 'ddns', 'acme', 'settings'].includes(tab)) {
        tasks.push(ensureNetworkInfo(!silent));
      }

      if ((tab === 'docker' || tab === 'web_terminal' || tab === 'cron') && modules.docker) {
        tasks.push(
          apiFetch('/api/docker/containers')
            .then((r) => {
              if (myNonce !== refreshNonce) return;
              containers = r.containers || [];
              dockerError = '';
            })
            .catch((err) => {
              if (myNonce !== refreshNonce) return;
              containers = [];
              dockerError = err.message;
            })
        );
      }

      await Promise.all(tasks);
    } catch (err) {
      if (!silent) showToast(err.message, 'error');
    } finally {
      if (myNonce === refreshNonce) refreshing = false;
    }
  }

  async function pollIncrementalLogs() {
    if (!authenticated || mustChangePassword || activeTab !== 'logs') return;
    try {
      const lastSeq = logs.length > 0 ? Math.max(...logs.map((e) => Number(e.seq || 0))) : 0;
      const params = new URLSearchParams();
      if (logLevelFilter) params.set('level', logLevelFilter);
      if (logModuleFilter) params.set('module', logModuleFilter);
      if (lastSeq > 0) params.set('after_seq', String(lastSeq));
      const qs = params.toString();
      const r = await apiFetch(`/api/logs${qs ? `?${qs}` : ''}`);
      logModules = r.modules || logModules;
      if (r.capacity) logCapacity = r.capacity;
      if (logModuleFilter && !logModules.includes(logModuleFilter)) {
        logModuleFilter = '';
        await refreshActiveView(true);
        return;
      }
      const incoming = r.entries || [];
      if (lastSeq > 0 && incoming.length > 0) {
        const merged = [...logs, ...incoming];
        logs = merged.slice(-logCapacity);
      } else if (lastSeq === 0) {
        logs = incoming;
      }
    } catch {
      // ignore transient live poll errors
    }
  }

  async function switchTab(id, sub = 'general') {
    if (!isTabAvailable(id)) return;
    activeTab = id;
    if (id === 'settings') settingsSubTab = sub;
    mobileMoreOpen = false;
    syncUrlHash(id, settingsSubTab, true);
    await refreshActiveView();
  }

  async function toggleModule(key) {
    const updated = { ...modules, [key]: !modules[key] };
    try {
      const r = await apiFetch('/api/modules', {
        method: 'PUT',
        body: JSON.stringify(updated),
      });
      modules = r.modules;
      if (settingsJson) settingsJson.modules = r.modules;
      if (!modules[activeTab] && !['dashboard', 'logs', 'settings'].includes(activeTab)) {
        activeTab = 'settings';
        syncUrlHash(activeTab, settingsSubTab);
      }
      showToast(`${t.nav[key] || key}: ${modules[key] ? t.enabled : t.disabled}`, 'success');
      await refreshActiveView();
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  async function saveFullSettings(nextObj, renames = []) {
    try {
      const payload = renames?.length ? { ...nextObj, _renames: renames } : nextObj;
      const res = await fetch('/api/settings', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json().catch(() => ({}));
      if (res.status === 403 && data.error === 'MUST_CHANGE_INITIAL_PASSWORD') {
        mustChangePassword = true;
        throw new Error(localizeError(data.message, lang, data.error));
      }
      if (res.status === 401) {
        clearSessionState();
        throw new Error(t.errors.UNAUTHORIZED);
      }
      if (!res.ok) {
        throw new Error(localizeError(data.message || data.error || `HTTP ${res.status}`, lang, data.error));
      }
      const restartHdr = res.headers.get('x-vane-restart-required');
      if (restartHdr) {
        const nextFields = restartHdr.split(',').map((s) => s.trim()).filter(Boolean);
        restartRequiredFields = [...new Set([...restartRequiredFields, ...nextFields])];
        showToast(t.restartBannerTitle, 'warn');
      } else {
        showToast(t.settingsSaved, 'success');
      }
      settingsJson = data;
      if (data?.modules) modules = data.modules;
      if (data?.admin?.session_ttl_secs) sessionTtlSecs = data.admin.session_ttl_secs;
      await refreshActiveView(true);
      return true;
    } catch (err) {
      showToast(err.message, 'error');
      return false;
    }
  }

  function requestLockdownToggle(enable) {
    askConfirm({
      title: enable ? t.lockdownOnConfirmTitle : t.lockdownOffConfirmTitle,
      message: enable ? t.lockdownOnConfirmDesc : t.lockdownOffConfirmDesc,
      confirmLabel: enable ? t.lockdownOff : t.lockdownOn,
      danger: enable,
      onConfirm: async () => {
        try {
          const r = await apiFetch('/api/firewall/lockdown', {
            method: 'POST',
            body: JSON.stringify({ enable }),
          });
          if (dashboard?.firewall) {
            dashboard = {
              ...dashboard,
              firewall: { ...dashboard.firewall, lockdown: Boolean(r.lockdown) },
            };
          }
          showToast(r.lockdown ? t.lockdownEnabledToast : t.lockdownDisabledToast, r.lockdown ? 'warn' : 'success');
          dashboard = await apiFetch('/api/dashboard').catch(() => dashboard);
        } catch (err) {
          showToast(err.message, 'error');
        }
      },
    });
  }

  function openContainerShell(containerName) {
    terminalInitialTarget = `container:${containerName}`;
    terminalTargetNonce += 1;
    switchTab('web_terminal');
  }

  checkAuthStatus();
</script>

<svelte:window
  onhashchange={handleHashChange}
  onkeydown={(e) => {
    if (e.key === 'Escape' && !e.defaultPrevented && mobileMoreOpen) mobileMoreOpen = false;
  }}
/>

<ToastStack
  {toasts}
  onDismiss={dismissToast}
  onPause={pauseToast}
  onResume={resumeToast}
  dismissLabel={t.common.dismiss}
/>
<ConfirmModal
  open={confirmState.open}
  title={confirmState.title}
  message={confirmState.message}
  confirmLabel={confirmState.confirmLabel}
  cancelLabel={t.cancel}
  danger={confirmState.danger}
  busy={confirmState.busy}
  onConfirm={runConfirmedAction}
  onCancel={() => { confirmState.open = false; }}
/>

{#if loading}
  <div class="auth-shell">
    <div class="card" style="display:flex;align-items:center;gap:12px;">
      <img src="/icon.svg" alt="Vane" class="brand-icon" />
      <span class="mono" style="font-size:14px;">{t.loadingGateway}</span>
    </div>
  </div>
{:else if !authenticated || mustChangePassword}
  <AuthGate
    {t}
    {lang}
    {toggleLang}
    {authenticated}
    {mustChangePassword}
    {username}
    {passwordLoginEnabled}
    {totpEnabled}
    {hasEd25519Keys}
    {ed25519KeyIds}
    connError={authConnError}
    onRetryStatus={checkAuthStatus}
    {apiFetch}
    {showToast}
    onAuthenticated={handleAuthenticated}
    onLogout={logout}
  />
{:else}
  <div class="layout">
    <!-- 桌面端左侧分组导航栏 -->
    <aside class="sidebar">
      <div class="brand">
        <img src="/icon.svg" alt="Vane" class="brand-icon" />
        <div>
          <div style="font-size:16px;font-weight:700;letter-spacing:-0.01em;">Vane</div>
          <div class="mono" style="font-size:11px;color:var(--text-secondary);">{t.dualStackTag}</div>
        </div>
      </div>

      {#each navGroups as group (group.label)}
        <div class="nav-group-label">{group.label}</div>
        {#each group.items as item (item.id)}
          {@const dot = moduleStatusDot(item.id)}
          <button
            type="button"
            class="nav-btn {activeTab === item.id ? 'active' : ''}"
            aria-current={activeTab === item.id ? 'page' : undefined}
            onclick={() => switchTab(item.id)}
          >
            <Icons name={item.id} size={17} />
            <span>{item.label}</span>
            <span class="nav-meta">
              {#if dot}<span class="status-dot {dot}"></span>{/if}
              {#if typeof item.count === 'number'}
                <span class="nav-count num">{item.count}</span>
              {/if}
            </span>
          </button>
        {/each}
      {/each}

      <div style="margin-top:auto;padding-top:12px;border-top:1px solid var(--border-subtle);display:grid;gap:6px;">
        <div style="display:flex;gap:6px;">
          <button type="button" class="btn btn-sm" style="flex:1;" onclick={toggleLang}>
            <Icons name="ddns" size={14} />
            <span>{lang === 'zh' ? 'EN' : '中文'}</span>
          </button>
          <button type="button" class="btn btn-sm" style="flex:1;" onclick={cycleTheme}>
            <Icons name={themeIcon()} size={14} />
            <span>{themeLabel()}</span>
          </button>
        </div>
        <button type="button" class="btn btn-sm" onclick={logout}>
          <Icons name="lock" size={14} />
          <span>{t.logout}</span>
        </button>
      </div>
    </aside>

    <!-- 主内容区 -->
    <main class="main-area">
      <header class="topbar">
        <div>
          <h1 style="font-size:21px;font-weight:700;letter-spacing:-0.01em;">
            {navItems.find((n) => n.id === activeTab)?.label || t.nav.dashboard}
          </h1>
          <div style="font-size:12px;color:var(--text-secondary);margin-top:2px;">
            {t.adminLabel}: <span class="mono">{username}</span> · {t.sessionTtl}: <span class="num">{Math.round(sessionTtlSecs / 60)}m</span>
          </div>
        </div>
        <div class="btn-group">
          <button type="button" class="btn btn-sm" disabled={refreshing} onclick={() => refreshActiveView()}>
            <Icons name="refresh" size={14} />
            <span>{refreshing ? t.common.loading : t.refresh}</span>
          </button>
          {#if dashboard?.firewall}
            <button
              type="button"
              class="btn btn-sm {dashboard.firewall.lockdown ? 'btn-primary' : 'btn-danger'}"
              onclick={() => requestLockdownToggle(!dashboard.firewall.lockdown)}
            >
              <Icons name="shield" size={14} />
              <span>{dashboard.firewall.lockdown ? t.lockdownOn : t.lockdownOff}</span>
            </button>
          {/if}
        </div>
      </header>

      {#if dashboard?.firewall?.lockdown}
        <div class="banner banner-danger" role="alert">
          <div style="display:flex;gap:10px;align-items:flex-start;flex:1;min-width:0;">
            <Icons name="shield" size={18} />
            <div style="min-width:0;">
              <div style="font-weight:700;">{t.lockdownActiveBannerTitle}</div>
              <div style="font-size:12px;color:var(--text-secondary);">{t.lockdownActiveBannerDesc}</div>
            </div>
          </div>
          <button type="button" class="btn btn-xs btn-primary" onclick={() => requestLockdownToggle(false)}>
            {t.lockdownOn}
          </button>
        </div>
      {/if}

      {#if restartRequiredFields.length > 0}
        <div class="banner banner-warn">
          <div style="display:flex;gap:10px;align-items:flex-start;flex:1;min-width:0;">
            <Icons name="alert" size={18} />
            <div style="min-width:0;">
              <div style="font-weight:700;">{t.restartBannerTitle}</div>
              <div style="font-size:12px;color:var(--text-secondary);word-break:break-word;">
                {t.restartBannerDesc} <code class="mono">{restartRequiredFields.join(', ')}</code>
              </div>
            </div>
          </div>
          <button type="button" class="btn btn-xs" aria-label={t.close} onclick={() => restartRequiredFields = []}>
            <Icons name="x" size={13} />
          </button>
        </div>
      {/if}

      {#if activeTab === 'dashboard'}
        <DashboardView
          {t}
          {lang}
          {dashboard}
          {settingsJson}
          onRefresh={refreshActiveView}
          onNavigate={(tab) => switchTab(tab)}
          {apiFetch}
          {showToast}
        />
      {:else if (activeTab === 'reverse_proxy' && modules.reverse_proxy) || (activeTab === 'port_forward' && modules.port_forward)}
        <NetworkRulesView
          mode={activeTab}
          {t}
          {lang}
          {settingsJson}
          {dashboard}
          {networkInfo}
          onSaveSettings={saveFullSettings}
          {askConfirm}
          {apiFetch}
          {showToast}
          onRefresh={refreshActiveView}
        />
      {:else if (activeTab === 'ddns' && modules.ddns) || (activeTab === 'acme' && modules.acme) || (activeTab === 'stun' && modules.stun)}
        <DomainCertStunView
          mode={activeTab}
          {t}
          {lang}
          {settingsJson}
          {dashboard}
          {networkInfo}
          onSaveSettings={saveFullSettings}
          {askConfirm}
          {apiFetch}
          {showToast}
          onRefresh={refreshActiveView}
        />
      {:else if (activeTab === 'docker' && modules.docker) || (activeTab === 'cron' && modules.cron) || activeTab === 'logs'}
        <OpsViews
          mode={activeTab}
          {t}
          {lang}
          {settingsJson}
          {dashboard}
          {containers}
          {dockerError}
          {logs}
          {logModules}
          {logCapacity}
          {logLevelFilter}
          {logModuleFilter}
          onChangeLogFilter={async (lvl, mod) => {
            logLevelFilter = lvl;
            logModuleFilter = mod;
            await refreshActiveView();
          }}
          onPollLogsIncremental={pollIncrementalLogs}
          webTerminalEnabled={modules.web_terminal}
          onOpenContainerTerminal={openContainerShell}
          onSaveSettings={saveFullSettings}
          {askConfirm}
          {apiFetch}
          {showToast}
          onRefresh={refreshActiveView}
        />
      {:else if activeTab === 'settings'}
        <SettingsView
          {t}
          {lang}
          {modules}
          {settingsJson}
          {networkInfo}
          subTab={settingsSubTab}
          onSubTabChange={(sub) => {
            settingsSubTab = sub;
            syncUrlHash('settings', sub, false);
          }}
          onToggleModule={toggleModule}
          onSaveSettings={saveFullSettings}
          onAuthRefresh={refreshAuthStatusOnly}
          onBackupRestored={(st) => {
            applyAuthStatus(st);
            if (Array.isArray(st?.restart_required) && st.restart_required.length > 0) {
              restartRequiredFields = [...new Set([...restartRequiredFields, ...st.restart_required])];
            }
          }}
          {askConfirm}
          {apiFetch}
          {showToast}
          onRefresh={refreshActiveView}
        />
      {/if}

      <!-- Web 终端加载后保持挂载（切 Tab 时用 CSS 隐藏，不误杀正在运行的 PTY 会话） -->
      {#if modules.web_terminal && (ptyEverOpened || activeTab === 'web_terminal')}
        <div style={activeTab === 'web_terminal' ? '' : 'display:none;'}>
          {#if TerminalComp}
            <TerminalComp
              {t}
              {lang}
              visible={activeTab === 'web_terminal'}
              initialTarget={terminalInitialTarget}
              targetNonce={terminalTargetNonce}
              {containers}
              requireReauth={Boolean(settingsJson?.web_terminal?.require_reauth)}
              {apiFetch}
              {showToast}
            />
          {:else if ptyLoadError}
            <div class="card row-between">
              <span class="mono" style="color:var(--danger);font-size:13px;">{ptyLoadError}</span>
              <button type="button" class="btn btn-sm" onclick={loadTerminalChunk}>{t.retry}</button>
            </div>
          {:else}
            <div class="card mono">{t.loadingPty}</div>
          {/if}
        </div>
      {/if}
    </main>

    <!-- 移动端底部拇指区悬浮导航栏 + 全功能抽屉入口 -->
    <nav class="mobile-tabbar">
      {#each mobilePrimaryItems as item (item.id)}
        <button
          type="button"
          class="tab-btn {activeTab === item.id ? 'active' : ''}"
          aria-current={activeTab === item.id ? 'page' : undefined}
          onclick={() => switchTab(item.id)}
        >
          <Icons name={item.id} size={18} />
          <span>{item.label}</span>
        </button>
      {/each}
      <button
        type="button"
        class="tab-btn {mobileMoreOpen || !mobilePrimaryItems.some((p) => p.id === activeTab) ? 'active' : ''}"
        onclick={() => mobileMoreOpen = !mobileMoreOpen}
      >
        <Icons name="more" size={18} />
        <span>{t.more}</span>
      </button>
    </nav>

    {#if mobileMoreOpen}
      <div class="drawer-backdrop" role="presentation" onclick={(e) => { if (e.target === e.currentTarget) mobileMoreOpen = false; }}>
        <div class="drawer-panel" role="dialog" aria-modal="true" aria-label={t.more}>
          <div class="drawer-header">
            <span class="card-title">{t.navGroups.overview} / {t.more}</span>
            <button type="button" class="btn btn-sm" onclick={() => mobileMoreOpen = false}>{t.close}</button>
          </div>
          <div class="drawer-body">
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:16px;">
              {#each navItems as item (item.id)}
                {@const dot = moduleStatusDot(item.id)}
                <button
                  type="button"
                  class="btn {activeTab === item.id ? 'btn-primary' : ''}"
                  style="justify-content:flex-start;min-width:0;overflow:hidden;"
                  onclick={() => switchTab(item.id)}
                >
                  <Icons name={item.id} size={16} />
                  <span style="overflow:hidden;text-overflow:ellipsis;">{item.label}</span>
                  <span class="nav-meta">
                    {#if dot}<span class="status-dot {dot}"></span>{/if}
                    {#if typeof item.count === 'number'}
                      <span class="nav-count num">{item.count}</span>
                    {/if}
                  </span>
                </button>
              {/each}
            </div>
            <div style="display:flex;gap:8px;padding-top:12px;border-top:1px solid var(--border-subtle);">
              <button type="button" class="btn" style="flex:1;" onclick={toggleLang}>{lang === 'zh' ? 'EN' : '中文'}</button>
              <button type="button" class="btn" style="flex:1;" onclick={cycleTheme}>{themeLabel()}</button>
              <button type="button" class="btn btn-danger" onclick={logout}>{t.logout}</button>
            </div>
          </div>
        </div>
      </div>
    {/if}
  </div>
{/if}
