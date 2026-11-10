<script>
  // 仅支持中英文 (zh / en) 双语字典
  const I18N = {
    zh: {
      subtitle: '双栈全能路由器安全网关 · 端口 23456',
      username: '管理员账号',
      password: '登录密码（初始默认: admin321）',
      totpCode: 'TOTP 二步验证码 / 恢复码',
      loginBtn: '安全登录',
      gateBadge: '安全硬门禁 · 必须完成',
      gateTitle: '首次登录请修改初始密码',
      gateDesc: '检测到当前仍在使用默认初始密码 admin321。为保障路由器防火墙与公网端口安全，必须设置符合复杂度要求的新密码后才能解锁管理控制台。',
      curPw: '当前密码（初始为 admin321）',
      newPw: '新强密码（英文 + 数字或符号，至少 8 位）',
      confirmPw: '确认新密码',
      ruleLen: '长度 8 ~ 128 位字符',
      ruleAlpha: '必须包含英文字母 (A-Z / a-z)',
      ruleDigit: '必须包含数字 (0-9) 或特殊字符',
      ruleNotDefault: '不能与初始密码 admin321、旧密码或用户名相同',
      ruleMatch: '两次输入的新密码一致',
      savePwBtn: '保存强密码并进入控制台',
      logout: '退出',
      refresh: '刷新数据',
      lockdownOn: '解除紧急封锁',
      lockdownOff: '一键紧急封锁 WAN',
      nav: {
        dashboard: '全景看板',
        reverse_proxy: '反向代理',
        port_forward: '端口转发',
        ddns: '动态 DDNS',
        acme: 'TLS 证书',
        stun: 'STUN 穿透',
        docker: 'Docker 容器',
        web_terminal: 'Web 终端',
        cron: '计划任务',
        logs: '运行日志',
        settings: '系统设置',
      },
      socTitle: 'SoC 处理器与温度',
      memTitle: '物理内存拆解 (RAM + Slab)',
      fwTitle: '防火墙与连接配额',
      ifaceTitle: '双栈网络接口 (IPv4 + IPv6)',
      procTitle: 'Top 内存占用进程榜 (VmRSS)',
      modSectionTitle: '功能模块按需启停（关闭后立即释放后台任务、防火墙规则与导航栏入口）',
      authSectionTitle: '认证保活与系统设置',
      saveSettings: '保存设置',
      enabled: '已开启',
      disabled: '已关闭',
    },
    en: {
      subtitle: 'Dual-Stack Secure Router Gateway · Port 23456',
      username: 'Admin Username',
      password: 'Password (Initial default: admin321)',
      totpCode: 'TOTP 2FA Code / Recovery Code',
      loginBtn: 'Sign In Securely',
      gateBadge: 'Mandatory Security Gate',
      gateTitle: 'Change Default Initial Password',
      gateDesc: 'Default password admin321 detected. For router firewall and WAN security, you must set a strong password before accessing the console.',
      curPw: 'Current Password (initial: admin321)',
      newPw: 'New Strong Password (letters + digits/symbols, >= 8 chars)',
      confirmPw: 'Confirm New Password',
      ruleLen: 'Length between 8 and 128 characters',
      ruleAlpha: 'Contains ASCII letters (A-Z / a-z)',
      ruleDigit: 'Contains digits (0-9) or special symbols',
      ruleNotDefault: 'Not equal to admin321, current password, or username',
      ruleMatch: 'Passwords match',
      savePwBtn: 'Save Strong Password & Unlock Console',
      logout: 'Logout',
      refresh: 'Refresh',
      lockdownOn: 'Disable WAN Lockdown',
      lockdownOff: '1-Click WAN Lockdown',
      nav: {
        dashboard: 'Dashboard',
        reverse_proxy: 'Reverse Proxy',
        port_forward: 'Port Forward',
        ddns: 'Dynamic DNS',
        acme: 'ACME TLS',
        stun: 'STUN NAT',
        docker: 'Docker',
        web_terminal: 'Web Terminal',
        cron: 'Cron Jobs',
        logs: 'System Logs',
        settings: 'Settings',
      },
      socTitle: 'SoC CPU & Thermal',
      memTitle: 'Memory Breakdown (RAM + Slab)',
      fwTitle: 'Firewall & Connection Quota',
      ifaceTitle: 'Dual-Stack Interfaces (IPv4 + IPv6)',
      procTitle: 'Top Memory Processes (VmRSS)',
      modSectionTitle: 'Pluggable Modules (Disabling stops background tasks, firewall rules & nav entry)',
      authSectionTitle: 'Session TTL & System Settings',
      saveSettings: 'Save Settings',
      enabled: 'Enabled',
      disabled: 'Disabled',
    }
  };

  let lang = $state(localStorage.getItem('vane_lang') === 'en' ? 'en' : 'zh');
  let t = $derived(I18N[lang] || I18N.zh);

  let loading = $state(true);
  let authenticated = $state(false);
  let mustChangePassword = $state(false);
  let username = $state('admin');
  let totpEnabled = $state(false);
  let sessionTtlSecs = $state(3600);
  let theme = $state(localStorage.getItem('vane_theme') || 'dark');
  let activeTab = $state('dashboard');
  let toast = $state('');

  let modules = $state({
    reverse_proxy: true,
    port_forward: true,
    ddns: true,
    acme: true,
    stun: true,
    web_terminal: false,
    cron: true,
    docker: true,
  });

  let loginUser = $state('admin');
  let loginPass = $state('');
  let loginTotp = $state('');
  let loginError = $state('');

  let curPassword = $state('');
  let newPassword = $state('');
  let confirmPassword = $state('');
  let pwChangeError = $state('');

  let pwChecks = $derived({
    lenOk: newPassword.length >= 8 && newPassword.length <= 128,
    hasAlpha: /[A-Za-z]/.test(newPassword),
    hasDigitOrPunct: /[0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(newPassword),
    notDefault: newPassword !== 'admin321' && newPassword !== curPassword && newPassword !== username,
    matchConfirm: newPassword.length > 0 && newPassword === confirmPassword,
  });
  let pwAllValid = $derived(
    pwChecks.lenOk && pwChecks.hasAlpha && pwChecks.hasDigitOrPunct && pwChecks.notDefault && pwChecks.matchConfirm
  );

  let dashboard = $state(null);
  let logs = $state([]);
  let logLevelFilter = $state('');
  let settingsJson = $state(null);
  let containers = $state([]);
  let ptyLines = $state([]);
  let ptyInput = $state('');
  let ptySocket = $state(null);

  let navItems = $derived([
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
  ].filter(item => item.always || item.enabled));

  $effect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('vane_theme', theme);
  });

  $effect(() => {
    document.documentElement.setAttribute('lang', lang === 'en' ? 'en' : 'zh-CN');
    localStorage.setItem('vane_lang', lang);
  });

  function toggleLang() {
    lang = lang === 'zh' ? 'en' : 'zh';
  }

  function showToast(msg) {
    toast = msg;
    setTimeout(() => { if (toast === msg) toast = ''; }, 3500);
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
      throw new Error(lang === 'en' ? 'Session expired' : '会话已过期，请重新登录');
    }
    if (!res.ok) {
      throw new Error(data.message || data.error || `HTTP ${res.status}`);
    }
    return data;
  }

  async function checkAuthStatus() {
    loading = true;
    try {
      const st = await apiFetch('/api/auth/status');
      authenticated = st.authenticated;
      mustChangePassword = st.must_change_password;
      username = st.username || 'admin';
      loginUser = username;
      totpEnabled = st.totp_enabled;
      sessionTtlSecs = st.session_ttl_secs || 3600;
      if (st.language && !localStorage.getItem('vane_lang')) {
        lang = st.language === 'en' ? 'en' : 'zh';
      }
      if (st.modules) modules = st.modules;
      if (authenticated && !mustChangePassword) {
        await refreshActiveView();
      }
    } catch (_) {
      authenticated = false;
    } finally {
      loading = false;
    }
  }

  async function submitLogin(e) {
    e.preventDefault();
    loginError = '';
    try {
      const st = await apiFetch('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username: loginUser, password: loginPass, totp_code: loginTotp }),
      });
      curPassword = loginPass;
      loginPass = '';
      authenticated = st.authenticated;
      mustChangePassword = st.must_change_password;
      if (st.modules) modules = st.modules;
      if (!mustChangePassword) {
        await refreshActiveView();
      }
    } catch (err) {
      loginError = err.message;
    }
  }

  async function submitChangePassword(e) {
    e.preventDefault();
    pwChangeError = '';
    if (!pwAllValid) return;
    try {
      const st = await apiFetch('/api/auth/change-password', {
        method: 'POST',
        body: JSON.stringify({
          current_password: curPassword,
          new_password: newPassword,
          new_username: username,
        }),
      });
      mustChangePassword = st.must_change_password;
      curPassword = '';
      newPassword = '';
      confirmPassword = '';
      showToast(lang === 'en' ? 'Strong password saved' : '强密码已生效，欢迎进入 Vane 网关控制台');
      await refreshActiveView();
    } catch (err) {
      pwChangeError = err.message;
    }
  }

  async function logout() {
    await apiFetch('/api/auth/logout', { method: 'POST' }).catch(() => {});
    authenticated = false;
    mustChangePassword = false;
  }

  async function refreshActiveView() {
    if (!authenticated || mustChangePassword) return;
    try {
      if (['dashboard', 'ddns', 'acme', 'stun'].includes(activeTab)) {
        dashboard = await apiFetch('/api/dashboard');
      }
      if (activeTab === 'logs') {
        const q = logLevelFilter ? `?level=${logLevelFilter}` : '';
        const r = await apiFetch(`/api/logs${q}`);
        logs = r.entries || [];
      }
      if (['settings', 'reverse_proxy', 'port_forward', 'ddns', 'acme', 'stun', 'cron'].includes(activeTab)) {
        settingsJson = await apiFetch('/api/settings');
        if (settingsJson?.modules) modules = settingsJson.modules;
      }
      if (activeTab === 'docker' && modules.docker) {
        const r = await apiFetch('/api/docker/containers');
        containers = r.containers || [];
      }
    } catch (err) {
      showToast(err.message);
    }
  }

  async function switchTab(id) {
    activeTab = id;
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
      showToast(`${key}: ${modules[key] ? t.enabled : t.disabled}`);
      await refreshActiveView();
    } catch (err) {
      showToast(err.message);
    }
  }

  async function saveSettings() {
    if (!settingsJson) return;
    try {
      settingsJson.system.language = lang;
      settingsJson = await apiFetch('/api/settings', {
        method: 'PUT',
        body: JSON.stringify(settingsJson),
      });
      if (settingsJson.modules) modules = settingsJson.modules;
      showToast(lang === 'en' ? 'Settings saved and hot-reloaded' : '配置已原子保存并热重载生效');
    } catch (err) {
      showToast(err.message);
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

  async function openWebTerminal() {
    try {
      const { ticket } = await apiFetch('/api/pty/ticket', { method: 'POST' });
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const ws = new WebSocket(`${proto}//${location.host}/api/pty/ws?ticket=${ticket}&target=host`);
      ptyLines = [];
      ws.onmessage = (ev) => { ptyLines = [...ptyLines.slice(-200), ev.data]; };
      ws.onclose = () => { ptySocket = null; };
      ptySocket = ws;
    } catch (err) {
      showToast(err.message);
    }
  }

  function sendPtyCommand(e) {
    e.preventDefault();
    if (!ptySocket || !ptyInput.trim()) return;
    ptySocket.send(ptyInput + '\n');
    ptyInput = '';
  }

  function formatKB(kb) {
    if (!kb) return '0 MB';
    return (kb / 1024).toFixed(1) + ' MB';
  }

  checkAuthStatus();
</script>

{#if toast}
  <div style="position:fixed;top:18px;right:18px;z-index:200;background:var(--bg-card);border:1px solid var(--accent);padding:12px 18px;border-radius:12px;box-shadow:var(--shadow-card);font-weight:600;">
    {toast}
  </div>
{/if}

{#if loading}
  <div class="auth-shell"><div class="card">Loading Vane Gateway...</div></div>
{:else if !authenticated}
  <div class="auth-shell">
    <div class="auth-card">
      <div class="brand" style="border:none;margin-bottom:14px;padding:0;justify-content:space-between;">
        <div style="display:flex;align-items:center;gap:12px;">
          <div class="brand-logo">V</div>
          <div>
            <div style="font-size:18px;font-weight:700;">Vane Gateway</div>
            <div style="font-size:12px;color:var(--text-secondary);">{t.subtitle}</div>
          </div>
        </div>
        <button type="button" class="btn btn-sm" onclick={toggleLang}>{lang === 'zh' ? 'EN' : '中文'}</button>
      </div>

      {#if loginError}
        <div class="badge badge-danger" style="width:100%;padding:10px 12px;border-radius:10px;margin-bottom:14px;">
          {loginError}
        </div>
      {/if}

      <form onsubmit={submitLogin}>
        <div class="field">
          <label for="login-user">{t.username}</label>
          <input id="login-user" type="text" bind:value={loginUser} autocomplete="username" required />
        </div>
        <div class="field">
          <label for="login-pass">{t.password}</label>
          <input id="login-pass" type="password" bind:value={loginPass} autocomplete="current-password" required />
        </div>
        {#if totpEnabled}
          <div class="field">
            <label for="login-totp">{t.totpCode}</label>
            <input id="login-totp" type="text" class="mono" bind:value={loginTotp} required />
          </div>
        {/if}
        <button type="submit" class="btn btn-primary" style="width:100%;margin-top:6px;">{t.loginBtn}</button>
      </form>
    </div>
  </div>

{:else if mustChangePassword}
  <div class="auth-shell">
    <div class="auth-card" style="max-width:480px;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
        <span class="badge badge-warn">{t.gateBadge}</span>
        <button type="button" class="btn btn-sm" onclick={toggleLang}>{lang === 'zh' ? 'EN' : '中文'}</button>
      </div>
      <h2 style="font-size:20px;margin-bottom:6px;">{t.gateTitle}</h2>
      <p style="font-size:13px;color:var(--text-secondary);margin-bottom:18px;line-height:1.5;">{t.gateDesc}</p>

      {#if pwChangeError}
        <div class="badge badge-danger" style="width:100%;padding:10px 12px;border-radius:10px;margin-bottom:14px;">
          {pwChangeError}
        </div>
      {/if}

      <form onsubmit={submitChangePassword}>
        <div class="field">
          <label for="cur-pw">{t.curPw}</label>
          <input id="cur-pw" type="password" bind:value={curPassword} required />
        </div>
        <div class="field">
          <label for="new-pw">{t.newPw}</label>
          <input id="new-pw" type="password" bind:value={newPassword} autocomplete="new-password" required />
        </div>
        <div class="field">
          <label for="confirm-pw">{t.confirmPw}</label>
          <input id="confirm-pw" type="password" bind:value={confirmPassword} autocomplete="new-password" required />
        </div>

        <div class="card" style="padding:12px 14px;margin-bottom:16px;font-size:13px;display:grid;gap:6px;">
          <div style="color:{pwChecks.lenOk ? 'var(--accent)' : 'var(--text-secondary)'}">{pwChecks.lenOk ? '✓' : '○'} {t.ruleLen}</div>
          <div style="color:{pwChecks.hasAlpha ? 'var(--accent)' : 'var(--text-secondary)'}">{pwChecks.hasAlpha ? '✓' : '○'} {t.ruleAlpha}</div>
          <div style="color:{pwChecks.hasDigitOrPunct ? 'var(--accent)' : 'var(--text-secondary)'}">{pwChecks.hasDigitOrPunct ? '✓' : '○'} {t.ruleDigit}</div>
          <div style="color:{pwChecks.notDefault ? 'var(--accent)' : 'var(--text-secondary)'}">{pwChecks.notDefault ? '✓' : '○'} {t.ruleNotDefault}</div>
          <div style="color:{pwChecks.matchConfirm ? 'var(--accent)' : 'var(--text-secondary)'}">{pwChecks.matchConfirm ? '✓' : '○'} {t.ruleMatch}</div>
        </div>

        <div style="display:flex;gap:10px;">
          <button type="submit" class="btn btn-primary" style="flex:1;" disabled={!pwAllValid}>{t.savePwBtn}</button>
          <button type="button" class="btn" onclick={logout}>{t.logout}</button>
        </div>
      </form>
    </div>
  </div>

{:else}
  <div class="layout">
    <aside class="sidebar">
      <div class="brand">
        <div class="brand-logo">V</div>
        <div>
          <div style="font-size:16px;font-weight:700;">Vane</div>
          <div class="mono" style="font-size:11px;color:var(--text-secondary);">IPv4 + IPv6 Dual-Stack</div>
        </div>
      </div>

      {#each navItems as item}
        <button class="nav-btn {activeTab === item.id ? 'active' : ''}" onclick={() => switchTab(item.id)}>
          <span>{item.label}</span>
        </button>
      {/each}

      <div style="margin-top:auto;padding-top:14px;border-top:1px solid var(--border-subtle);display:flex;gap:6px;">
        <button class="btn btn-sm" style="flex:1;" onclick={toggleLang}>{lang === 'zh' ? 'EN' : '中文'}</button>
        <button class="btn btn-sm" style="flex:1;" onclick={() => theme = theme === 'dark' ? 'light' : 'dark'}>
          {theme === 'dark' ? 'Light' : 'Dark'}
        </button>
        <button class="btn btn-sm" onclick={logout}>{t.logout}</button>
      </div>
    </aside>

    <main class="main-area">
      <header class="topbar">
        <div>
          <h1 style="font-size:22px;font-weight:700;">{navItems.find(n => n.id === activeTab)?.label || t.nav.dashboard}</h1>
          <div style="font-size:13px;color:var(--text-secondary);">
            Admin: <span class="mono">{username}</span> · TTL: <span class="num">{Math.round(sessionTtlSecs / 60)}m</span>
          </div>
        </div>
        <div style="display:flex;gap:8px;align-items:center;">
          <button class="btn btn-sm" onclick={toggleLang}>{lang === 'zh' ? 'EN' : '中文'}</button>
          {#if dashboard?.firewall}
            <button
              class="btn btn-sm {dashboard.firewall.lockdown ? 'btn-primary' : 'btn-danger'}"
              onclick={() => triggerLockdown(!dashboard.firewall.lockdown)}
            >
              {dashboard.firewall.lockdown ? t.lockdownOn : t.lockdownOff}
            </button>
          {/if}
          <button class="btn btn-sm" onclick={refreshActiveView}>{t.refresh}</button>
        </div>
      </header>

      {#if activeTab === 'dashboard' && dashboard}
        <div class="bento-grid">
          <div class="card">
            <div class="card-header">
              <span class="card-title">{t.socTitle}</span>
              <span class="badge badge-ok num">{dashboard.system.soc_temp_celsius.toFixed(1)} °C</span>
            </div>
            <div class="num" style="font-size:28px;font-weight:700;margin-bottom:6px;">{dashboard.system.cpu_usage_percent.toFixed(1)}%</div>
            <div class="progress-bar"><div class="progress-fill" style="width:{Math.min(100, dashboard.system.cpu_usage_percent)}%"></div></div>
            <div class="mono" style="font-size:12px;color:var(--text-secondary);margin-top:8px;">
              Load: {dashboard.system.load_avg.map(v => v.toFixed(2)).join(' / ')} · Uptime {Math.floor(dashboard.system.uptime_secs / 3600)}h
            </div>
          </div>

          <div class="card">
            <div class="card-header">
              <span class="card-title">{t.memTitle}</span>
              <span class="badge badge-info num">Free {formatKB(dashboard.system.memory.available_kb)}</span>
            </div>
            <div class="num" style="font-size:28px;font-weight:700;margin-bottom:6px;">
              {formatKB(dashboard.system.memory.used_kb)} / {formatKB(dashboard.system.memory.total_kb)}
            </div>
            <div class="progress-bar">
              <div class="progress-fill" style="width:{Math.min(100, (dashboard.system.memory.used_kb / Math.max(1, dashboard.system.memory.total_kb)) * 100)}%"></div>
            </div>
            <div class="mono" style="font-size:12px;color:var(--text-secondary);margin-top:8px;">
              Cache: {formatKB(dashboard.system.memory.cached_kb)} · Slab SUnreclaim: {formatKB(dashboard.system.memory.slab_unreclaim_kb)}
            </div>
          </div>

          <div class="card">
            <div class="card-header">
              <span class="card-title">{t.fwTitle}</span>
              <span class="badge {dashboard.firewall.lockdown ? 'badge-danger' : 'badge-ok'}">{dashboard.firewall.backend}</span>
            </div>
            <div class="num" style="font-size:28px;font-weight:700;margin-bottom:6px;">
              {dashboard.active_connections} / {dashboard.max_connections}
            </div>
            <div class="mono" style="font-size:12px;color:var(--text-secondary);">
              Rules: {dashboard.firewall.rules.length} · Active Bans: {dashboard.bans.length}
            </div>
          </div>
        </div>

        <div class="bento-grid">
          <div class="card">
            <div class="card-header">
              <span class="card-title">{t.ifaceTitle}</span>
              <span class="badge badge-info">{dashboard.system.interfaces.length}</span>
            </div>
            <div style="display:grid;gap:10px;">
              {#each dashboard.system.interfaces as iface}
                <div style="padding:10px 12px;border-radius:10px;background:var(--bg-elevated);">
                  <div style="display:flex;justify-content:space-between;font-weight:600;margin-bottom:4px;">
                    <span class="mono">{iface.iface}</span>
                    <span class="mono" style="font-size:12px;color:var(--text-secondary);">
                      RX {(iface.rx_bytes / 1048576).toFixed(1)} MB / TX {(iface.tx_bytes / 1048576).toFixed(1)} MB
                    </span>
                  </div>
                  {#if iface.ipv4.length > 0}<div class="mono" style="font-size:12px;color:var(--accent);">IPv4: {iface.ipv4.join(', ')}</div>{/if}
                  {#if iface.ipv6.length > 0}<div class="mono" style="font-size:12px;color:var(--info);word-break:break-all;">IPv6: {iface.ipv6.join(', ')}</div>{/if}
                </div>
              {/each}
            </div>
          </div>

          <div class="card">
            <div class="card-header"><span class="card-title">{t.procTitle}</span></div>
            <div style="display:grid;gap:8px;">
              {#each dashboard.system.top_processes as proc}
                <div style="display:flex;justify-content:space-between;padding:8px 12px;border-radius:8px;background:var(--bg-elevated);font-size:13px;">
                  <span><code class="mono">#{proc.pid}</code> {proc.name}</span>
                  <span class="mono" style="font-weight:600;">{formatKB(proc.vm_rss_kb)}</span>
                </div>
              {/each}
            </div>
          </div>
        </div>
      {/if}

      {#if activeTab === 'settings' && settingsJson}
        <div class="card" style="margin-bottom:18px;">
          <div class="card-header"><span class="card-title">{t.modSectionTitle}</span></div>
          <div class="bento-grid" style="margin-bottom:0;">
            {#each [
              ['reverse_proxy', t.nav.reverse_proxy],
              ['port_forward', t.nav.port_forward],
              ['ddns', t.nav.ddns],
              ['acme', t.nav.acme],
              ['stun', t.nav.stun],
              ['web_terminal', t.nav.web_terminal],
              ['cron', t.nav.cron],
              ['docker', t.nav.docker]
            ] as [key, title]}
              <div style="padding:14px;border-radius:12px;background:var(--bg-elevated);display:flex;justify-content:space-between;align-items:center;gap:12px;">
                <div style="font-weight:600;font-size:14px;">{title}</div>
                <button class="btn btn-sm {modules[key] ? 'btn-primary' : ''}" onclick={() => toggleModule(key)}>
                  {modules[key] ? t.enabled : t.disabled}
                </button>
              </div>
            {/each}
          </div>
        </div>

        <div class="card">
          <div class="card-header">
            <span class="card-title">{t.authSectionTitle}</span>
            <button class="btn btn-primary btn-sm" onclick={saveSettings}>{t.saveSettings}</button>
          </div>
          <div class="bento-grid" style="margin-bottom:0;">
            <div class="field">
              <label for="ttl-sec">Session TTL (300 ~ 86400s)</label>
              <input id="ttl-sec" type="number" min="300" max="86400" bind:value={settingsJson.admin.session_ttl_secs} />
            </div>
            <div class="field">
              <label for="max-conns">Global Max Connections</label>
              <input id="max-conns" type="number" min="64" max="4096" bind:value={settingsJson.system.global_max_conns} />
            </div>
            <div class="field">
              <label for="wan-iface">WAN Interface</label>
              <input id="wan-iface" type="text" class="mono" bind:value={settingsJson.firewall.wan_interface} />
            </div>
          </div>
        </div>
      {/if}

      {#if activeTab === 'logs'}
        <div class="card">
          <div class="card-header">
            <span class="card-title">{t.nav.logs}</span>
            <select style="width:130px;min-height:36px;padding:4px 8px;" bind:value={logLevelFilter} onchange={refreshActiveView}>
              <option value="">ALL</option>
              <option value="info">INFO+</option>
              <option value="warn">WARN+</option>
              <option value="error">ERROR</option>
            </select>
          </div>
          <div class="mono" style="background:var(--bg-elevated);padding:14px;border-radius:12px;max-height:520px;overflow-y:auto;font-size:12px;line-height:1.6;">
            {#each logs as entry}
              <div>
                <span style="color:var(--text-muted);">#{entry.seq}</span>
                <span style="color:var(--accent);">[{entry.level}]</span>
                <span style="color:var(--info);">[{entry.module}]</span>
                <span>{entry.message}</span>
              </div>
            {/each}
          </div>
        </div>
      {/if}

      {#if activeTab === 'web_terminal'}
        <div class="card">
          <div class="card-header">
            <span class="card-title">{t.nav.web_terminal}</span>
            {#if !ptySocket}
              <button class="btn btn-primary btn-sm" onclick={openWebTerminal}>Connect PTY</button>
            {:else}
              <button class="btn btn-danger btn-sm" onclick={() => ptySocket.close()}>Disconnect</button>
            {/if}
          </div>
          <pre class="mono" style="background:#05070a;color:#10b981;padding:16px;border-radius:12px;min-height:320px;max-height:480px;overflow-y:auto;font-size:13px;white-space:pre-wrap;">{ptyLines.join('') || 'Ready...'}</pre>
          {#if ptySocket}
            <form onsubmit={sendPtyCommand} style="display:flex;gap:8px;margin-top:12px;">
              <input type="text" class="mono" bind:value={ptyInput} placeholder="$ ..." />
              <button type="submit" class="btn btn-primary">Send</button>
            </form>
          {/if}
        </div>
      {/if}

      {#if ['reverse_proxy', 'port_forward', 'ddns', 'acme', 'stun', 'cron', 'docker'].includes(activeTab)}
        <div class="card">
          <div class="card-header">
            <span class="card-title">{navItems.find(n => n.id === activeTab)?.label}</span>
            {#if settingsJson}<button class="btn btn-primary btn-sm" onclick={saveSettings}>{t.saveSettings}</button>{/if}
          </div>
          {#if activeTab === 'docker'}
            <div style="display:grid;gap:10px;">
              {#each containers as c}
                <div style="padding:12px;border-radius:10px;background:var(--bg-elevated);display:flex;justify-content:space-between;align-items:center;">
                  <div>
                    <div style="font-weight:600;">{c.name} <code class="mono" style="font-size:12px;">({c.image})</code></div>
                    <div class="mono" style="font-size:12px;color:var(--text-secondary);">{c.state} · {c.status}</div>
                  </div>
                  <span class="badge {c.state === 'running' ? 'badge-ok' : 'badge-warn'}">{c.state}</span>
                </div>
              {/each}
            </div>
          {:else if settingsJson}
            <pre class="mono" style="background:var(--bg-elevated);padding:14px;border-radius:12px;overflow-x:auto;font-size:12px;">{JSON.stringify(settingsJson[activeTab === 'port_forward' ? 'port_forwards' : activeTab], null, 2)}</pre>
          {/if}
        </div>
      {/if}
    </main>

    <nav class="mobile-tabbar">
      {#each navItems.slice(0, 5) as item}
        <button class="tab-btn {activeTab === item.id ? 'active' : ''}" onclick={() => switchTab(item.id)}>{item.label}</button>
      {/each}
    </nav>
  </div>
{/if}
