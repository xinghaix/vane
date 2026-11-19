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

  // Web 终端按需异步加载分包（关闭时 0 字节下载）
  let TerminalComp = $state(null);
  let terminalInitialTarget = $state('host');
  let terminalTargetNonce = $state(0);

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

  $effect(() => {
    if (activeTab === 'web_terminal' && modules.web_terminal && !TerminalComp) {
      import('./components/TerminalView.svelte').then((m) => {
        TerminalComp = m.default;
      });
    }
  });

  function syncUrlHash(tab, sub = settingsSubTab) {
    const nextHash = tab === 'settings' && sub !== 'general' ? `#settings/${sub}` : `#${tab}`;
    if (location.hash !== nextHash) {
      history.replaceState(null, '', nextHash);
    }
  }

  function handleHashChange() {
    const { tab, sub } = parseHash();
    if (tab !== activeTab || sub !== settingsSubTab) {
      activeTab = tab;
      settingsSubTab = sub;
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
    toasts = toasts.filter((x) => x.id !== id);
  }

  function showToast(msg, type = 'info') {
    const id = nextToastId++;
    const duration = type === 'error' || type === 'warn' ? 6000 : 3500;
    toasts = [...toasts.slice(-3), { id, message: String(msg), type }];
    setTimeout(() => dismissToast(id), duration);
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
      authenticated = false;
      dashboard = null;
      settingsJson = null;
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
      syncUrlHash(activeTab, settingsSubTab);
      await refreshActiveView();
    }
  }

  async function logout() {
    await apiFetch('/api/auth/logout', { method: 'POST' }).catch(() => {});
    authenticated = false;
    mustChangePassword = false;
    dashboard = null;
    settingsJson = null;
    networkInfo = null;
    containers = [];
    logs = [];
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
    try {
      if (['dashboard', 'reverse_proxy', 'port_forward', 'ddns', 'acme', 'stun', 'cron'].includes(activeTab)) {
        dashboard = await apiFetch('/api/dashboard');
      } else if (!dashboard) {
        dashboard = await apiFetch('/api/dashboard').catch(() => dashboard);
      }

      if (activeTab === 'logs') {
        const params = new URLSearchParams();
        if (logLevelFilter) params.set('level', logLevelFilter);
        if (logModuleFilter) params.set('module', logModuleFilter);
        const qs = params.toString();
        const r = await apiFetch(`/api/logs${qs ? `?${qs}` : ''}`);
        logs = r.entries || [];
        logModules = r.modules || [];
        if (r.capacity) logCapacity = r.capacity;
      }

      if (['dashboard', 'settings', 'reverse_proxy', 'port_forward', 'ddns', 'acme', 'stun', 'cron', 'web_terminal'].includes(activeTab)) {
        if (!silent || !settingsJson) {
          settingsJson = await apiFetch('/api/settings');
          if (settingsJson?.modules) modules = settingsJson.modules;
        }
      }

      if (['reverse_proxy', 'port_forward', 'ddns', 'acme', 'settings'].includes(activeTab)) {
        await ensureNetworkInfo(!silent);
      }

      if ((activeTab === 'docker' || activeTab === 'web_terminal' || activeTab === 'cron') && modules.docker) {
        try {
          const r = await apiFetch('/api/docker/containers');
          containers = r.containers || [];
          dockerError = '';
        } catch (err) {
          containers = [];
          dockerError = err.message;
        }
      }
    } catch (err) {
      if (!silent) showToast(err.message, 'error');
    }
  }

  async function switchTab(id, sub = 'general') {
    activeTab = id;
    if (id === 'settings') settingsSubTab = sub;
    mobileMoreOpen = false;
    syncUrlHash(id, settingsSubTab);
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
        authenticated = false;
        throw new Error(t.errors.UNAUTHORIZED);
      }
      if (!res.ok) {
        throw new Error(localizeError(data.message || data.error || `HTTP ${res.status}`, lang, data.error));
      }
      const restartHdr = res.headers.get('x-vane-restart-required');
      if (restartHdr) {
        restartRequiredFields = restartHdr.split(',').map((s) => s.trim()).filter(Boolean);
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
          showToast(r.lockdown ? t.lockdownOn : t.lockdownOff, r.lockdown ? 'warn' : 'success');
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
    if (e.key === 'Escape' && mobileMoreOpen) mobileMoreOpen = false;
  }}
/>

<ToastStack {toasts} onDismiss={dismissToast} />
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
      <span class="mono" style="font-size:14px;">Loading Vane Gateway...</span>
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
          <div class="mono" style="font-size:11px;color:var(--text-secondary);">IPv4 + IPv6 Dual-Stack</div>
        </div>
      </div>

      {#each navGroups as group}
        <div class="nav-group-label">{group.label}</div>
        {#each group.items as item}
          {@const dot = moduleStatusDot(item.id)}
          <button
            type="button"
            class="nav-btn {activeTab === item.id ? 'active' : ''}"
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
          <button type="button" class="btn btn-sm" onclick={() => refreshActiveView()}>
            <Icons name="refresh" size={14} />
            <span>{t.refresh}</span>
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

      {#if restartRequiredFields.length > 0}
        <div class="banner banner-warn">
          <div style="display:flex;gap:10px;align-items:flex-start;">
            <Icons name="alert" size={18} />
            <div>
              <div style="font-weight:700;">{t.restartBannerTitle}</div>
              <div style="font-size:12px;color:var(--text-secondary);">
                {t.restartBannerDesc} <code class="mono">{restartRequiredFields.join(', ')}</code>
              </div>
            </div>
          </div>
          <button type="button" class="btn btn-xs" onclick={() => restartRequiredFields = []}>
            <Icons name="x" size={13} />
          </button>
        </div>
      {/if}

      {#if activeTab === 'dashboard'}
        <DashboardView {t} {lang} {dashboard} {settingsJson} onRefresh={refreshActiveView} {apiFetch} {showToast} />
      {:else if activeTab === 'reverse_proxy' || activeTab === 'port_forward'}
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
      {:else if activeTab === 'ddns' || activeTab === 'acme' || activeTab === 'stun'}
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
      {:else if activeTab === 'docker' || activeTab === 'cron' || activeTab === 'logs'}
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
          webTerminalEnabled={modules.web_terminal}
          onOpenContainerTerminal={openContainerShell}
          onSaveSettings={saveFullSettings}
          {askConfirm}
          {apiFetch}
          {showToast}
          onRefresh={refreshActiveView}
        />
      {:else if activeTab === 'web_terminal' && modules.web_terminal}
        {#if TerminalComp}
          <TerminalComp
            {t}
            {lang}
            initialTarget={terminalInitialTarget}
            targetNonce={terminalTargetNonce}
            {containers}
            requireReauth={Boolean(settingsJson?.web_terminal?.require_reauth)}
            {apiFetch}
            {showToast}
          />
        {:else}
          <div class="card mono">Loading PTY module...</div>
        {/if}
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
            syncUrlHash('settings', sub);
          }}
          onToggleModule={toggleModule}
          onSaveSettings={saveFullSettings}
          onAuthRefresh={refreshAuthStatusOnly}
          {askConfirm}
          {apiFetch}
          {showToast}
          onRefresh={refreshActiveView}
        />
      {/if}
    </main>

    <!-- 移动端底部拇指区悬浮导航栏 + 全功能抽屉入口 -->
    <nav class="mobile-tabbar">
      {#each mobilePrimaryItems as item}
        <button type="button" class="tab-btn {activeTab === item.id ? 'active' : ''}" onclick={() => switchTab(item.id)}>
          <Icons name={item.id} size={18} />
          <span>{item.label}</span>
        </button>
      {/each}
      <button type="button" class="tab-btn {mobileMoreOpen ? 'active' : ''}" onclick={() => mobileMoreOpen = !mobileMoreOpen}>
        <Icons name="more" size={18} />
        <span>{t.more}</span>
      </button>
    </nav>

    {#if mobileMoreOpen}
      <div class="drawer-backdrop" role="presentation" onclick={(e) => { if (e.target === e.currentTarget) mobileMoreOpen = false; }}>
        <div class="drawer-panel">
          <div class="drawer-header">
            <span class="card-title">{t.navGroups.overview} / {t.more}</span>
            <button type="button" class="btn btn-sm" onclick={() => mobileMoreOpen = false}>{t.close}</button>
          </div>
          <div class="drawer-body">
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:16px;">
              {#each navItems as item}
                <button type="button" class="btn {activeTab === item.id ? 'btn-primary' : ''}" onclick={() => switchTab(item.id)}>
                  <Icons name={item.id} size={16} />
                  <span>{item.label}</span>
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
