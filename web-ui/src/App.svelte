<script>
  // Svelte 5 Runes 全响应式状态机
  let loading = $state(true);
  let authenticated = $state(false);
  let mustChangePassword = $state(false);
  let username = $state('admin');
  let totpEnabled = $state(false);
  let passwordLoginEnabled = $state(true);
  let hasEd25519Keys = $state(false);
  let ed25519KeyIds = $state([]);
  let sessionTtlSecs = $state(3600);
  let theme = $state(localStorage.getItem('vane_theme') || 'dark');
  let activeTab = $state('dashboard');
  let toast = $state('');

  // 可插拔子功能模块总开关（看板、日志、设置常驻开启；其余可随时在设置页启停）
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

  // 登录表单状态
  let authTab = $state('password');
  let loginUser = $state('admin');
  let loginPass = $state('');
  let loginTotp = $state('');
  let loginError = $state('');
  let edKeyId = $state('');
  let edPrivateKeySeedHex = $state('');

  // 首次登录强制改密状态
  let curPassword = $state('');
  let newPassword = $state('');
  let confirmPassword = $state('');
  let pwChangeError = $state('');

  // 强密码实时校验派生状态 ($derived)
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

  // 业务面板状态
  let dashboard = $state(null);
  let logs = $state([]);
  let logLevelFilter = $state('');
  let settingsJson = $state(null);
  let containers = $state([]);
  let totpSetup = $state(null);
  let totpVerifyCode = $state('');
  let recoveryCodes = $state([]);
  let ptyLines = $state([]);
  let ptyInput = $state('');
  let ptySocket = $state(null);

  // 动态可见导航项 ($derived)
  let navItems = $derived([
    { id: 'dashboard', label: '全景看板', always: true },
    { id: 'reverse_proxy', label: '反向代理', enabled: modules.reverse_proxy },
    { id: 'port_forward', label: '端口转发', enabled: modules.port_forward },
    { id: 'ddns', label: '动态 DDNS', enabled: modules.ddns },
    { id: 'acme', label: 'TLS 证书', enabled: modules.acme },
    { id: 'stun', label: 'STUN 穿透', enabled: modules.stun },
    { id: 'docker', label: 'Docker 容器', enabled: modules.docker },
    { id: 'web_terminal', label: 'Web 终端', enabled: modules.web_terminal },
    { id: 'cron', label: '计划任务', enabled: modules.cron },
    { id: 'logs', label: '运行日志', always: true },
    { id: 'settings', label: '系统设置', always: true },
  ].filter(item => item.always || item.enabled));

  $effect(() => {
    const resolved = theme === 'auto'
      ? (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark')
      : theme;
    document.documentElement.setAttribute('data-theme', resolved);
    localStorage.setItem('vane_theme', theme);
  });

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
      throw new Error(data.message || '请先修改初始密码');
    }
    if (res.status === 401 && !path.startsWith('/api/auth/')) {
      authenticated = false;
      throw new Error('会话已过期，请重新登录');
    }
    if (!res.ok) {
      throw new Error(data.message || data.error || `请求失败 (${res.status})`);
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
      passwordLoginEnabled = st.password_login_enabled;
      hasEd25519Keys = st.has_ed25519_keys;
      ed25519KeyIds = st.ed25519_key_ids || [];
      if (ed25519KeyIds.length > 0) edKeyId = ed25519KeyIds[0];
      sessionTtlSecs = st.session_ttl_secs || 3600;
      if (st.modules) modules = st.modules;
      if (authenticated && !mustChangePassword) {
        await refreshActiveView();
      }
    } catch (e) {
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
      showToast('强密码已生效，欢迎进入 Vane 网关控制台');
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
      if (activeTab === 'dashboard' || activeTab === 'ddns' || activeTab === 'acme' || activeTab === 'stun') {
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
      showToast(`已${modules[key] ? '开启' : '关闭'}模块: ${key}`);
      await refreshActiveView();
    } catch (err) {
      showToast(err.message);
    }
  }

  async function saveSettings() {
    if (!settingsJson) return;
    try {
      settingsJson = await apiFetch('/api/settings', {
        method: 'PUT',
        body: JSON.stringify(settingsJson),
      });
      if (settingsJson.modules) modules = settingsJson.modules;
      showToast('配置已原子保存并热重载生效');
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
      showToast(enable ? '已进入紧急封锁模式（所有公网入站已切断）' : '已解除紧急封锁模式');
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
      ws.onmessage = (ev) => {
        ptyLines = [...ptyLines.slice(-200), ev.data];
      };
      ws.onclose = () => {
        ptyLines = [...ptyLines, '\r\n[终端连接已关闭]'];
        ptySocket = null;
      };
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
  <div class="auth-shell"><div class="card">正在加载 Vane 安全网关...</div></div>
{:else if !authenticated}
  <!-- 登录视图 -->
  <div class="auth-shell">
    <div class="auth-card">
      <div class="brand" style="border:none;margin-bottom:14px;padding:0;">
        <div class="brand-logo">V</div>
        <div>
          <div style="font-size:18px;font-weight:700;">Vane Gateway</div>
          <div style="font-size:12px;color:var(--text-secondary);">双栈全能路由器安全网关 · 端口 23456</div>
        </div>
      </div>

      {#if loginError}
        <div class="badge badge-danger" style="width:100%;padding:10px 12px;border-radius:10px;margin-bottom:14px;">
          {loginError}
        </div>
      {/if}

      <form onsubmit={submitLogin}>
        <div class="field">
          <label for="login-user">管理员账号</label>
          <input id="login-user" type="text" bind:value={loginUser} autocomplete="username" required />
        </div>
        <div class="field">
          <label for="login-pass">登录密码（初始默认: admin321）</label>
          <input id="login-pass" type="password" bind:value={loginPass} autocomplete="current-password" required />
        </div>
        {#if totpEnabled}
          <div class="field">
            <label for="login-totp">TOTP 二步验证码 / 恢复码</label>
            <input id="login-totp" type="text" class="mono" bind:value={loginTotp} placeholder="6 位数字或恢复码" required />
          </div>
        {/if}
        <button type="submit" class="btn btn-primary" style="width:100%;margin-top:6px;">安全登录</button>
      </form>
    </div>
  </div>

{:else if mustChangePassword}
  <!-- 首次登录强制改密硬门禁（禁止跳过进入管理页面） -->
  <div class="auth-shell">
    <div class="auth-card" style="max-width:480px;">
      <div class="badge badge-warn" style="margin-bottom:12px;">安全硬门禁 · 必须完成</div>
      <h2 style="font-size:20px;margin-bottom:6px;">首次登录请修改初始密码</h2>
      <p style="font-size:13px;color:var(--text-secondary);margin-bottom:18px;line-height:1.5;">
        检测到当前仍在使用默认初始密码 <code class="mono">admin321</code>。为保障路由器防火墙与公网端口安全，必须设置符合复杂度要求的新密码后才能解锁管理控制台。
      </p>

      {#if pwChangeError}
        <div class="badge badge-danger" style="width:100%;padding:10px 12px;border-radius:10px;margin-bottom:14px;">
          {pwChangeError}
        </div>
      {/if}

      <form onsubmit={submitChangePassword}>
        <div class="field">
          <label for="cur-pw">当前密码（初始为 admin321）</label>
          <input id="cur-pw" type="password" bind:value={curPassword} required />
        </div>
        <div class="field">
          <label for="new-pw">新强密码（英文 + 数字或符号，至少 8 位）</label>
          <input id="new-pw" type="password" bind:value={newPassword} autocomplete="new-password" required />
        </div>
        <div class="field">
          <label for="confirm-pw">确认新密码</label>
          <input id="confirm-pw" type="password" bind:value={confirmPassword} autocomplete="new-password" required />
        </div>

        <div class="card" style="padding:12px 14px;margin-bottom:16px;font-size:13px;display:grid;gap:6px;">
          <div style="color:{pwChecks.lenOk ? 'var(--accent)' : 'var(--text-secondary)'}">
            {pwChecks.lenOk ? '✓' : '○'} 长度 8 ~ 128 位字符
          </div>
          <div style="color:{pwChecks.hasAlpha ? 'var(--accent)' : 'var(--text-secondary)'}">
            {pwChecks.hasAlpha ? '✓' : '○'} 必须包含英文字母 (A-Z / a-z)
          </div>
          <div style="color:{pwChecks.hasDigitOrPunct ? 'var(--accent)' : 'var(--text-secondary)'}">
            {pwChecks.hasDigitOrPunct ? '✓' : '○'} 必须包含数字 (0-9) 或特殊字符
          </div>
          <div style="color:{pwChecks.notDefault ? 'var(--accent)' : 'var(--text-secondary)'}">
            {pwChecks.notDefault ? '✓' : '○'} 不能与初始密码 admin321、旧密码或用户名相同
          </div>
          <div style="color:{pwChecks.matchConfirm ? 'var(--accent)' : 'var(--text-secondary)'}">
            {pwChecks.matchConfirm ? '✓' : '○'} 两次输入的新密码一致
          </div>
        </div>

        <div style="display:flex;gap:10px;">
          <button type="submit" class="btn btn-primary" style="flex:1;" disabled={!pwAllValid}>
            保存强密码并进入控制台
          </button>
          <button type="button" class="btn" onclick={logout}>退出</button>
        </div>
      </form>
    </div>
  </div>

{:else}
  <!-- 主控制台视图 -->
  <div class="layout">
    <aside class="sidebar">
      <div class="brand">
        <div class="brand-logo">V</div>
        <div>
          <div style="font-size:16px;font-weight:700;">Vane 网关</div>
          <div class="mono" style="font-size:11px;color:var(--text-secondary);">IPv4 + IPv6 Dual-Stack</div>
        </div>
      </div>

      {#each navItems as item}
        <button
          class="nav-btn {activeTab === item.id ? 'active' : ''}"
          onclick={() => switchTab(item.id)}
        >
          <span>{item.label}</span>
        </button>
      {/each}

      <div style="margin-top:auto;padding-top:14px;border-top:1px solid var(--border-subtle);display:flex;gap:8px;">
        <button class="btn btn-sm" style="flex:1;" onclick={() => theme = theme === 'dark' ? 'light' : 'dark'}>
          {theme === 'dark' ? '浅色' : '深色'}
        </button>
        <button class="btn btn-sm" onclick={logout}>退出</button>
      </div>
    </aside>

    <main class="main-area">
      <header class="topbar">
        <div>
          <h1 style="font-size:22px;font-weight:700;">
            {navItems.find(n => n.id === activeTab)?.label || '全景看板'}
          </h1>
          <div style="font-size:13px;color:var(--text-secondary);">
            当前账号: <span class="mono">{username}</span> · 会话保活: <span class="num">{Math.round(sessionTtlSecs / 60)}</span> 分钟
          </div>
        </div>
        <div style="display:flex;gap:10px;align-items:center;">
          {#if dashboard?.firewall}
            <button
              class="btn btn-sm {dashboard.firewall.lockdown ? 'btn-primary' : 'btn-danger'}"
              onclick={() => triggerLockdown(!dashboard.firewall.lockdown)}
            >
              {dashboard.firewall.lockdown ? '解除紧急封锁' : '一键紧急封锁 WAN'}
            </button>
          {/if}
          <button class="btn btn-sm" onclick={refreshActiveView}>刷新数据</button>
        </div>
      </header>

      {#if activeTab === 'dashboard' && dashboard}
        <!-- Bento Grid 全景看板 -->
        <div class="bento-grid">
          <div class="card">
            <div class="card-header">
              <span class="card-title">SoC 处理器与温度</span>
              <span class="badge badge-ok num">{dashboard.system.soc_temp_celsius.toFixed(1)} °C</span>
            </div>
            <div class="num" style="font-size:28px;font-weight:700;margin-bottom:6px;">
              {dashboard.system.cpu_usage_percent.toFixed(1)}%
            </div>
            <div class="progress-bar">
              <div class="progress-fill" style="width:{Math.min(100, dashboard.system.cpu_usage_percent)}%"></div>
            </div>
            <div class="mono" style="font-size:12px;color:var(--text-secondary);margin-top:8px;">
              Load: {dashboard.system.load_avg.map(v => v.toFixed(2)).join(' / ')} · 运行 {Math.floor(dashboard.system.uptime_secs / 3600)}h
            </div>
          </div>

          <div class="card">
            <div class="card-header">
              <span class="card-title">物理内存拆解 (RAM + Slab)</span>
              <span class="badge badge-info num">
                可用 {formatKB(dashboard.system.memory.available_kb)}
              </span>
            </div>
            <div class="num" style="font-size:28px;font-weight:700;margin-bottom:6px;">
              {formatKB(dashboard.system.memory.used_kb)} / {formatKB(dashboard.system.memory.total_kb)}
            </div>
            <div class="progress-bar">
              <div class="progress-fill" style="width:{Math.min(100, (dashboard.system.memory.used_kb / Math.max(1, dashboard.system.memory.total_kb)) * 100)}%"></div>
            </div>
            <div class="mono" style="font-size:12px;color:var(--text-secondary);margin-top:8px;">
              PageCache: {formatKB(dashboard.system.memory.cached_kb)} · 内核不可回收 Slab: {formatKB(dashboard.system.memory.slab_unreclaim_kb)}
            </div>
          </div>

          <div class="card">
            <div class="card-header">
              <span class="card-title">防火墙与连接配额</span>
              <span class="badge {dashboard.firewall.lockdown ? 'badge-danger' : 'badge-ok'}">
                {dashboard.firewall.backend} {dashboard.firewall.lockdown ? '(LOCKDOWN)' : '正常'}
              </span>
            </div>
            <div class="num" style="font-size:28px;font-weight:700;margin-bottom:6px;">
              {dashboard.active_connections} / {dashboard.max_connections}
            </div>
            <div class="mono" style="font-size:12px;color:var(--text-secondary);">
              活动防火墙规则: {dashboard.firewall.rules.length} 条 · 封禁网段: {dashboard.bans.length} 个
            </div>
          </div>
        </div>

        <div class="bento-grid">
          <div class="card">
            <div class="card-header">
              <span class="card-title">双栈网络接口 (IPv4 + IPv6)</span>
              <span class="badge badge-info">{dashboard.system.interfaces.length} 个接口</span>
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
                  {#if iface.ipv4.length > 0}
                    <div class="mono" style="font-size:12px;color:var(--accent);">IPv4: {iface.ipv4.join(', ')}</div>
                  {/if}
                  {#if iface.ipv6.length > 0}
                    <div class="mono" style="font-size:12px;color:var(--info);word-break:break-all;">IPv6: {iface.ipv6.join(', ')}</div>
                  {/if}
                </div>
              {/each}
            </div>
          </div>

          <div class="card">
            <div class="card-header">
              <span class="card-title">Top 内存占用进程榜 (VmRSS)</span>
            </div>
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
        <!-- 系统设置与可插拔模块开关 -->
        <div class="card" style="margin-bottom:18px;">
          <div class="card-header">
            <span class="card-title">功能模块按需启停（关闭后立即释放后台任务、防火墙规则与导航栏入口）</span>
          </div>
          <div class="bento-grid" style="margin-bottom:0;">
            {#each [
              ['reverse_proxy', 'HTTPS 反向代理', 'TLS 终结、SNI 路由与 HSTS'],
              ['port_forward', '双栈端口转发', '4x4 TCP/UDP 转发与临时开门租约'],
              ['ddns', '动态域名 DDNS', 'IPv4 + 子设备 /128 IPv6 合成与放行'],
              ['acme', 'ACME 证书管理', '多 CA 自动续期与 CNAME 挑战别名'],
              ['stun', 'STUN 内网穿透', 'RFC5389 公网端口映射探测'],
              ['web_terminal', 'Web 终端 (默认关闭)', '浏览器 PTY 命令行，按需开启'],
              ['cron', '轻量计划任务', '定时清理镜像、重启容器、切换规则'],
              ['docker', 'Docker 容器管理', '直连 docker.sock 管理容器与日志']
            ] as [key, title, desc]}
              <div style="padding:14px;border-radius:12px;background:var(--bg-elevated);display:flex;justify-content:space-between;align-items:center;gap:12px;">
                <div>
                  <div style="font-weight:600;font-size:14px;">{title}</div>
                  <div style="font-size:12px;color:var(--text-secondary);">{desc}</div>
                </div>
                <button
                  class="btn btn-sm {modules[key] ? 'btn-primary' : ''}"
                  onclick={() => toggleModule(key)}
                >
                  {modules[key] ? '已开启' : '已关闭'}
                </button>
              </div>
            {/each}
          </div>
        </div>

        <div class="card">
          <div class="card-header">
            <span class="card-title">认证保活与安全设置</span>
            <button class="btn btn-primary btn-sm" onclick={saveSettings}>保存设置</button>
          </div>
          <div class="bento-grid" style="margin-bottom:0;">
            <div class="field">
              <label for="ttl-sec">登录态保活时长 (秒，默认 3600 = 1h，最大 86400 = 24h)</label>
              <input id="ttl-sec" type="number" min="300" max="86400" bind:value={settingsJson.admin.session_ttl_secs} />
            </div>
            <div class="field">
              <label for="max-conns">全局最大并发连接数上限</label>
              <input id="max-conns" type="number" min="32" max="4096" bind:value={settingsJson.system.global_max_conns} />
            </div>
            <div class="field">
              <label for="wan-iface">WAN 接口名</label>
              <input id="wan-iface" type="text" class="mono" bind:value={settingsJson.firewall.wan_interface} />
            </div>
          </div>
        </div>
      {/if}

      {#if activeTab === 'logs'}
        <div class="card">
          <div class="card-header">
            <span class="card-title">内存环形日志缓冲区（凭据自动脱敏，零 Flash 磨损）</span>
            <div style="display:flex;gap:8px;">
              <select style="width:130px;min-height:36px;padding:4px 8px;" bind:value={logLevelFilter} onchange={refreshActiveView}>
                <option value="">全部级别</option>
                <option value="info">INFO+</option>
                <option value="warn">WARN+</option>
                <option value="error">ERROR</option>
              </select>
            </div>
          </div>
          <div class="mono" style="background:var(--bg-elevated);padding:14px;border-radius:12px;max-height:520px;overflow-y:auto;font-size:12px;line-height:1.6;">
            {#if logs.length === 0}
              <div style="color:var(--text-secondary);">暂无匹配的日志记录</div>
            {:else}
              {#each logs as entry}
                <div>
                  <span style="color:var(--text-muted);">#{entry.seq}</span>
                  <span style="color:var(--accent);">[{entry.level}]</span>
                  <span style="color:var(--info);">[{entry.module}]</span>
                  <span>{entry.message}</span>
                </div>
              {/each}
            {/if}
          </div>
        </div>
      {/if}

      {#if activeTab === 'web_terminal'}
        <div class="card">
          <div class="card-header">
            <span class="card-title">受控 Web 终端（一次性 Ticket 鉴权 · 空闲自动断开）</span>
            {#if !ptySocket}
              <button class="btn btn-primary btn-sm" onclick={openWebTerminal}>连接宿主机终端</button>
            {:else}
              <button class="btn btn-danger btn-sm" onclick={() => ptySocket.close()}>断开连接</button>
            {/if}
          </div>
          <pre class="mono" style="background:#05070a;color:#10b981;padding:16px;border-radius:12px;min-height:320px;max-height:480px;overflow-y:auto;font-size:13px;white-space:pre-wrap;">{ptyLines.join('') || '点击右上角「连接宿主机终端」开启交互式会话...'}</pre>
          {#if ptySocket}
            <form onsubmit={sendPtyCommand} style="display:flex;gap:8px;margin-top:12px;">
              <input type="text" class="mono" bind:value={ptyInput} placeholder="输入 Shell 命令并回车..." />
              <button type="submit" class="btn btn-primary">发送</button>
            </form>
          {/if}
        </div>
      {/if}

      {#if ['reverse_proxy', 'port_forward', 'ddns', 'acme', 'stun', 'cron', 'docker'].includes(activeTab)}
        <div class="card">
          <div class="card-header">
            <span class="card-title">{navItems.find(n => n.id === activeTab)?.label} 配置与状态</span>
            {#if settingsJson}
              <button class="btn btn-primary btn-sm" onclick={saveSettings}>保存修改</button>
            {/if}
          </div>
          {#if activeTab === 'docker'}
            <div style="display:grid;gap:10px;">
              {#if containers.length === 0}
                <div style="color:var(--text-secondary);font-size:14px;">未检测到活动容器或 docker.sock 未挂载</div>
              {:else}
                {#each containers as c}
                  <div style="padding:12px;border-radius:10px;background:var(--bg-elevated);display:flex;justify-content:space-between;align-items:center;">
                    <div>
                      <div style="font-weight:600;">{c.name} <code class="mono" style="font-size:12px;">({c.image})</code></div>
                      <div class="mono" style="font-size:12px;color:var(--text-secondary);">{c.state} · {c.status}</div>
                    </div>
                    <span class="badge {c.state === 'running' ? 'badge-ok' : 'badge-warn'}">{c.state}</span>
                  </div>
                {/each}
              {/if}
            </div>
          {:else if settingsJson}
            <pre class="mono" style="background:var(--bg-elevated);padding:14px;border-radius:12px;overflow-x:auto;font-size:12px;">{JSON.stringify(settingsJson[activeTab === 'port_forward' ? 'port_forwards' : activeTab], null, 2)}</pre>
          {/if}
        </div>
      {/if}
    </main>

    <!-- 手机端底部玻璃态固定导航栏 -->
    <nav class="mobile-tabbar">
      {#each navItems.slice(0, 5) as item}
        <button class="tab-btn {activeTab === item.id ? 'active' : ''}" onclick={() => switchTab(item.id)}>
          {item.label}
        </button>
      {/each}
    </nav>
  </div>
{/if}
