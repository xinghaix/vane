<script>
  import { I18N } from './lib/i18n.js';
  import Icons from './components/Icons.svelte';
  import AuthGate from './components/AuthGate.svelte';
  import DashboardView from './components/DashboardView.svelte';
  import NetworkRulesView from './components/NetworkRulesView.svelte';
  import DomainCertStunView from './components/DomainCertStunView.svelte';
  import OpsViews from './components/OpsViews.svelte';
  import SettingsView from './components/SettingsView.svelte';

  let lang = $state(localStorage.getItem('vane_lang') === 'en' ? 'en' : 'zh');
  let t = $derived(I18N[lang] || I18N.zh);

  let loading = $state(true);
  let authenticated = $state(false);
  let mustChangePassword = $state(false);
  let username = $state('admin');
  let passwordLoginEnabled = $state(true);
  let totpEnabled = $state(false);
  let hasEd25519Keys = $state(false);
  let ed25519KeyIds = $state([]);
  let sessionTtlSecs = $state(3600);

  let themeMode = $state(localStorage.getItem('vane_theme_mode') || 'dark'); // dark | light | auto
  let activeTab = $state('dashboard');
  let mobileMoreOpen = $state(false);
  let toast = $state('');

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
  let logs = $state([]);
  let logLevelFilter = $state('');
  let containers = $state([]);

  // Web 终端按需异步加载分包（关闭时 0 字节下载）
  let TerminalComp = $state(null);
  let terminalInitialTarget = $state('host');

  let navItems = $derived(
    [
      { id: 'dashboard', label: t.nav.dashboard, always: true },
      { id: 'reverse_proxy', label: t.nav.reverse_proxy, enabled: modules.reverse_proxy },
      { id: 'port_forward', label: t.nav.port_forward, enabled: modules.port_forward },
      { id: 'ddns', label: t.nav.ddns, enabled: modules.ddns },
      { id: 'acme', label: t.nav.acme, enabled: modules.acme },
      { id: 'stun', label: t.nav.stun, enabled: modules.stun },
      { id: 'docker', label: t.nav.docker, enabled: modules.docker },
      { id: 'web_terminal', label: t.nav.web_terminal, enabled: modules.web_terminal },
      { id: 'cron', label: t.nav.cron, enabled: modules.cron },
      { id: 'logs', label: t.nav.logs, always: true },
      { id: 'settings', label: t.nav.settings, always: true },
    ].filter((item) => item.always || item.enabled)
  );

  // 手机端底部主导航固定展示核心 4 项 + “更多”全量抽屉，确保任何子页在手机上均可一键直达
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
    };
    apply();
    mq.addEventListener('change', apply);
    return () => mq.removeEventListener('change', apply);
  });

  $effect(() => {
    document.documentElement.setAttribute('lang', lang === 'en' ? 'en' : 'zh-CN');
    localStorage.setItem('vane_lang', lang);
  });

  // 当打开 web_terminal 视图时才异步拉取终端分包
  $effect(() => {
    if (activeTab === 'web_terminal' && modules.web_terminal && !TerminalComp) {
      import('./components/TerminalView.svelte').then((m) => {
        TerminalComp = m.default;
      });
    }
  });

  function toggleLang() {
    lang = lang === 'zh' ? 'en' : 'zh';
  }

  function cycleTheme() {
    themeMode = themeMode === 'dark' ? 'light' : themeMode === 'light' ? 'auto' : 'dark';
  }

  function themeLabel() {
    if (themeMode === 'light') return t.themeLight;
    if (themeMode === 'auto') return t.themeAuto;
    return t.themeDark;
  }

  function showToast(msg) {
    toast = msg;
    setTimeout(() => {
      if (toast === msg) toast = '';
    }, 3600);
  }

  async function apiFetch(path, options = {}) {
    const res = await fetch(path, {
      headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
      ...options,
    });
    const data = await res.json().catch(() => ({}));
    if (res.status === 403 && data.error === 'MUST_CHANGE_INITIAL_PASSWORD') {
      mustChangePassword = true;
      throw new Error(data.message || 'Must change initial password');
    }
    if (res.status === 401 && !path.startsWith('/api/auth/')) {
      authenticated = false;
      dashboard = null;
      settingsJson = null;
      throw new Error(lang === 'en' ? 'Session expired' : '会话已过期，请重新登录');
    }
    if (!res.ok) {
      throw new Error(data.message || data.error || `HTTP ${res.status}`);
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
    if (st.language && !localStorage.getItem('vane_lang')) {
      lang = st.language === 'en' ? 'en' : 'zh';
    }
    if (st.modules) modules = st.modules;
  }

  async function checkAuthStatus() {
    loading = true;
    try {
      const st = await apiFetch('/api/auth/status');
      applyAuthStatus(st);
      if (authenticated && !mustChangePassword) {
        await refreshActiveView();
      }
    } catch {
      authenticated = false;
    } finally {
      loading = false;
    }
  }

  async function handleAuthenticated(st, toastMsg = '') {
    applyAuthStatus(st);
    if (toastMsg) showToast(toastMsg);
    if (authenticated && !mustChangePassword) {
      await refreshActiveView();
    }
  }

  async function logout() {
    await apiFetch('/api/auth/logout', { method: 'POST' }).catch(() => {});
    authenticated = false;
    mustChangePassword = false;
    dashboard = null;
    settingsJson = null;
    containers = [];
    logs = [];
  }

  async function refreshActiveView(silent = false) {
    if (!authenticated || mustChangePassword) return;
    try {
      if (['dashboard', 'ddns', 'acme', 'stun', 'cron'].includes(activeTab)) {
        dashboard = await apiFetch('/api/dashboard');
      }
      if (activeTab === 'logs') {
        const q = logLevelFilter ? `?level=${encodeURIComponent(logLevelFilter)}` : '';
        const r = await apiFetch(`/api/logs${q}`);
        logs = r.entries || [];
      }
      if (['settings', 'reverse_proxy', 'port_forward', 'ddns', 'acme', 'stun', 'cron', 'web_terminal'].includes(activeTab)) {
        if (!silent || !settingsJson) {
          settingsJson = await apiFetch('/api/settings');
          if (settingsJson?.modules) modules = settingsJson.modules;
        }
      }
      if ((activeTab === 'docker' || activeTab === 'web_terminal') && modules.docker) {
        const r = await apiFetch('/api/docker/containers').catch(() => ({ containers: [] }));
        containers = r.containers || [];
      }
    } catch (err) {
      if (!silent) showToast(err.message);
    }
  }

  async function switchTab(id) {
    activeTab = id;
    mobileMoreOpen = false;
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
      }
      showToast(`${t.nav[key] || key}: ${modules[key] ? t.enabled : t.disabled}`);
      await refreshActiveView();
    } catch (err) {
      showToast(err.message);
    }
  }

  async function saveFullSettings(nextObj) {
    try {
      nextObj.system.language = lang;
      const saved = await apiFetch('/api/settings', {
        method: 'PUT',
        body: JSON.stringify(nextObj),
      });
      settingsJson = saved;
      if (saved?.modules) modules = saved.modules;
      if (saved?.admin?.session_ttl_secs) sessionTtlSecs = saved.admin.session_ttl_secs;
      showToast(t.settingsSaved);
      await refreshActiveView(true);
      return true;
    } catch (err) {
      showToast(err.message);
      return false;
    }
  }

  async function triggerLockdown(enable) {
    try {
      await apiFetch('/api/firewall/lockdown', {
        method: 'POST',
        body: JSON.stringify({ enable }),
      });
      await refreshActiveView();
    } catch (err) {
      showToast(err.message);
    }
  }

  function openContainerShell(containerName) {
    terminalInitialTarget = `container:${containerName}`;
    switchTab('web_terminal');
  }

  checkAuthStatus();
</script>

{#if toast}
  <div class="toast-banner">{toast}</div>
{/if}

{#if loading}
  <div class="auth-shell">
    <div class="card mono" style="font-size:14px;">Loading Vane Gateway...</div>
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
    {apiFetch}
    onAuthenticated={handleAuthenticated}
    onLogout={logout}
  />
{:else}
  <div class="layout">
    <!-- 桌面端左侧导航栏 -->
    <aside class="sidebar">
      <div class="brand">
        <div class="brand-logo">V</div>
        <div>
          <div style="font-size:16px;font-weight:700;">Vane</div>
          <div class="mono" style="font-size:11px;color:var(--text-secondary);">IPv4 + IPv6 Dual-Stack</div>
        </div>
      </div>

      {#each navItems as item}
        <button type="button" class="nav-btn {activeTab === item.id ? 'active' : ''}" onclick={() => switchTab(item.id)}>
          <Icons name={item.id} size={17} />
          <span>{item.label}</span>
        </button>
      {/each}

      <div style="margin-top:auto;padding-top:14px;border-top:1px solid var(--border-subtle);display:grid;gap:6px;">
        <div style="display:flex;gap:6px;">
          <button type="button" class="btn btn-sm" style="flex:1;" onclick={toggleLang}>
            {lang === 'zh' ? 'EN' : '中文'}
          </button>
          <button type="button" class="btn btn-sm" style="flex:1;" onclick={cycleTheme}>
            {themeLabel()}
          </button>
        </div>
        <button type="button" class="btn btn-sm" onclick={logout}>{t.logout}</button>
      </div>
    </aside>

    <!-- 主内容区 -->
    <main class="main-area">
      <header class="topbar">
        <div>
          <h1 style="font-size:21px;font-weight:700;">
            {navItems.find((n) => n.id === activeTab)?.label || t.nav.dashboard}
          </h1>
          <div style="font-size:12px;color:var(--text-secondary);margin-top:2px;">
            Admin: <span class="mono">{username}</span> · Session TTL: <span class="num">{Math.round(sessionTtlSecs / 60)}m</span>
          </div>
        </div>
        <div class="btn-group">
          {#if dashboard?.firewall}
            <button
              type="button"
              class="btn btn-sm {dashboard.firewall.lockdown ? 'btn-primary' : 'btn-danger'}"
              onclick={() => triggerLockdown(!dashboard.firewall.lockdown)}
            >
              {dashboard.firewall.lockdown ? t.lockdownOn : t.lockdownOff}
            </button>
          {/if}
          <button type="button" class="btn btn-sm" onclick={() => refreshActiveView()}>{t.refresh}</button>
        </div>
      </header>

      {#if activeTab === 'dashboard'}
        <DashboardView {t} {lang} {dashboard} onRefresh={refreshActiveView} {apiFetch} {showToast} />
      {:else if activeTab === 'reverse_proxy' || activeTab === 'port_forward'}
        <NetworkRulesView
          mode={activeTab}
          {t}
          {lang}
          {settingsJson}
          onSaveSettings={saveFullSettings}
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
          onSaveSettings={saveFullSettings}
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
          {logs}
          {logLevelFilter}
          onChangeLogLevel={async (lvl) => { logLevelFilter = lvl; await refreshActiveView(); }}
          webTerminalEnabled={modules.web_terminal}
          onOpenContainerTerminal={openContainerShell}
          onSaveSettings={saveFullSettings}
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
          onToggleModule={toggleModule}
          onSaveSettings={saveFullSettings}
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
            <span class="card-title">Vane Navigation</span>
            <button type="button" class="btn btn-sm" onclick={() => mobileMoreOpen = false}>{t.cancel}</button>
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
