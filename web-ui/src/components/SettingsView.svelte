<script>
  import {
    splitCsv,
    joinCsv,
    deepClone,
    copyText,
    secretMaskedHint,
    resolveSecretInput,
  } from '../lib/helpers.js';

  let {
    t,
    lang,
    modules,
    settingsJson,
    onToggleModule,
    onSaveSettings,
    apiFetch,
    showToast,
    onRefresh,
  } = $props();

  let subTab = $state('general'); // general | security | notifications | backup

  // 通用与防火墙草稿字符串同步
  let wanIfacesCsv = $state('');
  let lanIfacesCsv = $state('');
  let monIfacesCsv = $state('');
  let listenLanCsv = $state('');
  let extraOriginsCsv = $state('');
  let protectedContainersCsv = $state('');

  $effect(() => {
    if (!settingsJson) return;
    wanIfacesCsv = joinCsv(settingsJson.firewall?.wan_interfaces);
    lanIfacesCsv = joinCsv(settingsJson.firewall?.lan_interfaces);
    monIfacesCsv = joinCsv(settingsJson.monitor?.interfaces);
    listenLanCsv = joinCsv(settingsJson.admin?.listen_lan);
    extraOriginsCsv = joinCsv(settingsJson.admin?.extra_allowed_origins);
    protectedContainersCsv = joinCsv(settingsJson.docker?.protected_containers);
  });

  async function saveGeneralSettings(e) {
    e.preventDefault();
    const next = deepClone(settingsJson);
    next.system.language = lang;
    next.system.global_max_conns = Number(next.system.global_max_conns || 512);
    next.system.log_ring_capacity = Number(next.system.log_ring_capacity || 300);
    next.admin.session_ttl_secs = Number(next.admin.session_ttl_secs || 3600);
    next.admin.listen_lan = splitCsv(listenLanCsv);
    next.admin.extra_allowed_origins = splitCsv(extraOriginsCsv);
    next.firewall.wan_interfaces = splitCsv(wanIfacesCsv);
    next.firewall.lan_interfaces = splitCsv(lanIfacesCsv);
    next.monitor.interfaces = splitCsv(monIfacesCsv);
    next.monitor.temp_alert_celsius = Number(next.monitor.temp_alert_celsius || 85);
    next.monitor.mem_low_mb = Number(next.monitor.mem_low_mb || 32);
    next.monitor.alert_cooldown_secs = Number(next.monitor.alert_cooldown_secs || 1800);
    next.security.max_login_failures = Number(next.security.max_login_failures || 5);
    next.security.ban_duration_secs = Number(next.security.ban_duration_secs || 1800);
    next.web_terminal.idle_timeout_secs = Number(next.web_terminal.idle_timeout_secs || 900);
    next.web_terminal.max_sessions = Number(next.web_terminal.max_sessions || 2);
    next.docker.protected_containers = splitCsv(protectedContainersCsv);
    await onSaveSettings(next);
  }

  // ---------------- 安全中心：修改密码 / TOTP / Ed25519 ----------------
  let curPw = $state('');
  let newPw = $state('');
  let newUsername = $state('');
  let totpSetupData = $state(null);
  let totpVerifyCode = $state('');
  let issuedRecoveryCodes = $state([]);
  let newKeyId = $state('');
  let newKeyPub = $state('');

  async function updateAdminCredentials(e) {
    e.preventDefault();
    try {
      await apiFetch('/api/auth/change-password', {
        method: 'POST',
        body: JSON.stringify({
          current_password: curPw,
          new_password: newPw,
          new_username: newUsername,
        }),
      });
      curPw = '';
      newPw = '';
      showToast(lang === 'en' ? 'Password updated' : '管理员密码已成功更新');
      await onRefresh();
    } catch (err) {
      showToast(err.message);
    }
  }

  async function startTotpSetup() {
    try {
      totpSetupData = await apiFetch('/api/auth/totp/setup', { method: 'POST' });
      issuedRecoveryCodes = [];
    } catch (err) {
      showToast(err.message);
    }
  }

  async function confirmTotpEnable(e) {
    e.preventDefault();
    try {
      const r = await apiFetch('/api/auth/totp/enable', {
        method: 'POST',
        body: JSON.stringify({ code: totpVerifyCode }),
      });
      totpSetupData = null;
      totpVerifyCode = '';
      issuedRecoveryCodes = r.recovery_codes || [];
      showToast(lang === 'en' ? 'TOTP 2FA Enabled' : '已开启 TOTP 二步验证，请妥善保存一次性恢复码');
      await onRefresh();
    } catch (err) {
      showToast(err.message);
    }
  }

  async function regenerateRecoveryCodes() {
    try {
      const r = await apiFetch('/api/auth/totp/recovery-codes', { method: 'POST' });
      issuedRecoveryCodes = r.recovery_codes || [];
      showToast(lang === 'en' ? 'Recovery codes regenerated' : '已重新生成一次性恢复码');
      await onRefresh();
    } catch (err) {
      showToast(err.message);
    }
  }

  async function disableTotp() {
    try {
      await apiFetch('/api/auth/totp/disable', { method: 'POST' });
      issuedRecoveryCodes = [];
      showToast(lang === 'en' ? 'TOTP disabled' : '已关闭 TOTP 二步验证');
      await onRefresh();
    } catch (err) {
      showToast(err.message);
    }
  }

  async function addEd25519Key(e) {
    e.preventDefault();
    try {
      await apiFetch('/api/auth/ed25519/keys', {
        method: 'POST',
        body: JSON.stringify({ id: newKeyId.trim(), pubkey: newKeyPub.trim() }),
      });
      newKeyId = '';
      newKeyPub = '';
      showToast(lang === 'en' ? 'Ed25519 key added' : '已添加授权 Ed25519 公钥');
      await onRefresh();
    } catch (err) {
      showToast(err.message);
    }
  }

  async function deleteEd25519Key(id) {
    try {
      await apiFetch(`/api/auth/ed25519/keys/${encodeURIComponent(id)}`, { method: 'DELETE' });
      showToast(`${t.delete}: ${id}`);
      await onRefresh();
    } catch (err) {
      showToast(err.message);
    }
  }

  // ---------------- 通知渠道中心 ----------------
  let notifDrawerOpen = $state(false);
  let notifEditIdx = $state(-1);
  let notifDraft = $state(null);
  let notifEventsCsv = $state('');
  let notifUrlInput = $state('');
  let notifTokenInput = $state('');
  let notifSecretInput = $state('');
  let notifBodyTplInput = $state('');
  let busyNotif = $state('');

  function openNotifDrawer(idx = -1) {
    notifEditIdx = idx;
    const n = idx >= 0
      ? deepClone(settingsJson.notifications[idx])
      : {
          name: `notify_${(settingsJson?.notifications?.length || 0) + 1}`,
          enabled: true,
          provider: 'webhook',
          events: [],
          url: '',
          token: '',
          chat_id: '',
          secret: '',
          method: 'POST',
          headers: {},
          body_template: '',
          min_severity: 'info',
        };
    notifDraft = n;
    notifEventsCsv = joinCsv(n.events);
    notifUrlInput = '';
    notifTokenInput = '';
    notifSecretInput = '';
    notifBodyTplInput = '';
    notifDrawerOpen = true;
  }

  async function saveNotification(e) {
    e.preventDefault();
    const orig = notifEditIdx >= 0 ? settingsJson.notifications[notifEditIdx] : null;
    notifDraft.events = splitCsv(notifEventsCsv);
    notifDraft.url = resolveSecretInput(orig?.url, notifUrlInput);
    notifDraft.token = resolveSecretInput(orig?.token, notifTokenInput);
    notifDraft.secret = resolveSecretInput(orig?.secret, notifSecretInput);
    notifDraft.body_template = resolveSecretInput(orig?.body_template, notifBodyTplInput);

    const next = deepClone(settingsJson);
    if (notifEditIdx >= 0) next.notifications[notifEditIdx] = notifDraft;
    else next.notifications.push(notifDraft);
    if (await onSaveSettings(next)) notifDrawerOpen = false;
  }

  async function deleteNotification(idx) {
    const next = deepClone(settingsJson);
    next.notifications.splice(idx, 1);
    await onSaveSettings(next);
  }

  async function testNotification(name) {
    busyNotif = name;
    try {
      const r = await apiFetch(`/api/notifications/${encodeURIComponent(name)}/test`, { method: 'POST' });
      showToast(`${name}: ${r.outcome}`);
    } catch (err) {
      showToast(err.message);
    } finally {
      busyNotif = '';
    }
  }

  // ---------------- 加密备份与恢复 ----------------
  let backupPass = $state('');
  let restorePass = $state('');
  let restoreBlobB64 = $state('');
  let sanitizedPreview = $state('');

  function b64ToUint8(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  async function exportEncryptedBackup(e) {
    e.preventDefault();
    try {
      const r = await apiFetch('/api/backup/export', {
        method: 'POST',
        body: JSON.stringify({ password: backupPass }),
      });
      const bytes = b64ToUint8(r.backup_blob);
      const blob = new Blob([bytes], { type: 'application/octet-stream' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `vane-backup-${new Date().toISOString().slice(0, 10)}.vane.bak`;
      a.click();
      URL.revokeObjectURL(a.href);
      backupPass = '';
      showToast(lang === 'en' ? 'Encrypted .vane.bak downloaded' : '已导出跨设备加密备份文件 (.vane.bak)');
    } catch (err) {
      showToast(err.message);
    }
  }

  function handleBackupFileSelect(e) {
    const file = e.currentTarget.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const u8 = new Uint8Array(reader.result);
      let s = '';
      for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
      restoreBlobB64 = btoa(s);
    };
    reader.readAsArrayBuffer(file);
  }

  async function importEncryptedBackup(e) {
    e.preventDefault();
    try {
      await apiFetch('/api/backup/import', {
        method: 'POST',
        body: JSON.stringify({ backup_blob: restoreBlobB64, password: restorePass }),
      });
      restorePass = '';
      restoreBlobB64 = '';
      showToast(lang === 'en' ? 'Backup restored & hot-reloaded' : '加密备份已恢复并重新加封生效');
      await onRefresh();
    } catch (err) {
      showToast(err.message);
    }
  }

  async function loadSanitizedToml() {
    try {
      const r = await apiFetch('/api/backup/sanitized', { method: 'POST' });
      sanitizedPreview = r.toml || '';
    } catch (err) {
      showToast(err.message);
    }
  }
</script>

{#if settingsJson}
  <!-- 顶部子面板导航 -->
  <div style="margin-bottom:18px;">
    <div class="pill-tabs">
      <button type="button" class="pill-tab {subTab === 'general' ? 'active' : ''}" onclick={() => subTab = 'general'}>
        {lang === 'en' ? 'Modules & System' : '功能模块与系统参数'}
      </button>
      <button type="button" class="pill-tab {subTab === 'security' ? 'active' : ''}" onclick={() => subTab = 'security'}>
        {lang === 'en' ? 'Auth, 2FA & SSH Keys' : '认证安全 · TOTP · 密钥'}
      </button>
      <button type="button" class="pill-tab {subTab === 'notifications' ? 'active' : ''}" onclick={() => subTab = 'notifications'}>
        {lang === 'en' ? 'Notification Center' : '多渠道通知中心'} ({settingsJson.notifications?.length || 0})
      </button>
      <button type="button" class="pill-tab {subTab === 'backup' ? 'active' : ''}" onclick={() => subTab = 'backup'}>
        {lang === 'en' ? 'Encrypted Backup' : '跨设备备份与恢复'}
      </button>
    </div>
  </div>

  <!-- 1. 模块启停与系统/防火墙设置 -->
  {#if subTab === 'general'}
    <div class="card" style="margin-bottom:18px;">
      <div class="card-header">
        <span class="card-title">
          {lang === 'en'
            ? 'Pluggable Modules (Disabling stops tasks, revokes WAN firewall rules & hides nav)'
            : '子功能模块按需启停（关闭后立即释放后台协程、撤销关联防火墙规则并收敛导航栏）'}
        </span>
      </div>
      <div class="bento-grid" style="margin-bottom:0;">
        {#each [
          ['reverse_proxy', t.nav.reverse_proxy],
          ['port_forward', t.nav.port_forward],
          ['ddns', t.nav.ddns],
          ['acme', t.nav.acme],
          ['stun', t.nav.stun],
          ['web_terminal', t.nav.web_terminal],
          ['cron', t.nav.cron],
          ['docker', t.nav.docker],
        ] as [key, title]}
          <div class="subcard row-between">
            <div style="font-weight:600;font-size:14px;">{title}</div>
            <button type="button" class="btn btn-sm {modules[key] ? 'btn-primary' : ''}" onclick={() => onToggleModule(key)}>
              {modules[key] ? t.enabled : t.disabled}
            </button>
          </div>
        {/each}
      </div>
    </div>

    <form class="card" onsubmit={saveGeneralSettings}>
      <div class="card-header">
        <span class="card-title">{lang === 'en' ? 'System, Firewall & Monitor Thresholds' : '系统配额、防火墙接口与监控告警阈值'}</span>
        <button type="submit" class="btn btn-primary btn-sm">{t.saveSettings}</button>
      </div>

      <div class="form-grid">
        <div class="field">
          <label for="st-ttl">Admin Session TTL (300 ~ 86400s)</label>
          <input id="st-ttl" type="number" min="300" max="86400" bind:value={settingsJson.admin.session_ttl_secs} />
        </div>
        <div class="field">
          <label for="st-maxc">Global Max Connections (64 ~ 4096)</label>
          <input id="st-maxc" type="number" min="64" max="4096" bind:value={settingsJson.system.global_max_conns} />
        </div>
        <div class="field">
          <label for="st-tz">Timezone Offset (UTC / auto / +08:00)</label>
          <input id="st-tz" type="text" class="mono" bind:value={settingsJson.system.timezone_offset} />
        </div>
        <div class="field">
          <label for="st-ring">Memory Log Ring Capacity (50 ~ 1000)</label>
          <input id="st-ring" type="number" min="50" max="1000" bind:value={settingsJson.system.log_ring_capacity} />
        </div>
        <div class="field">
          <label for="st-fwb">Firewall Backend</label>
          <select id="st-fwb" bind:value={settingsJson.firewall.backend}>
            <option value="auto">auto (fw4 nftables / fw3 iptables)</option>
            <option value="nftables">nftables (OpenWrt fw4)</option>
            <option value="iptables_legacy">iptables_legacy</option>
            <option value="iptables_nft">iptables_nft</option>
          </select>
        </div>
        <div class="field">
          <label for="st-wan">WAN Interfaces (comma separated)</label>
          <input id="st-wan" type="text" class="mono" placeholder="pppoe-wan" bind:value={wanIfacesCsv} />
        </div>
        <div class="field">
          <label for="st-lan">LAN Interfaces (comma separated)</label>
          <input id="st-lan" type="text" class="mono" placeholder="br-lan" bind:value={lanIfacesCsv} />
        </div>
        <div class="field">
          <label for="st-mif">Monitored Interfaces</label>
          <input id="st-mif" type="text" class="mono" bind:value={monIfacesCsv} />
        </div>
        <div class="field">
          <label for="st-tmp">High Temp Alert (°C)</label>
          <input id="st-tmp" type="number" min="40" max="125" bind:value={settingsJson.monitor.temp_alert_celsius} />
        </div>
        <div class="field">
          <label for="st-mem">Low Memory Alert (MB)</label>
          <input id="st-mem" type="number" min="0" max="4096" bind:value={settingsJson.monitor.mem_low_mb} />
        </div>
        <div class="field">
          <label for="st-f2b">Fail2Ban Max Login Failures</label>
          <input id="st-f2b" type="number" min="3" max="20" bind:value={settingsJson.security.max_login_failures} />
        </div>
        <div class="field">
          <label for="st-bds">Fail2Ban Duration (secs)</label>
          <input id="st-bds" type="number" min="60" max="86400" bind:value={settingsJson.security.ban_duration_secs} />
        </div>
        <div class="field">
          <label for="st-sp">Secret Entry Path ("/" or "/_vane_...")</label>
          <input id="st-sp" type="text" class="mono" bind:value={settingsJson.admin.secret_path} />
        </div>
        <div class="field">
          <label for="st-org">Canonical HTTPS Origin</label>
          <input id="st-org" type="text" class="mono" bind:value={settingsJson.admin.canonical_origin} />
        </div>
        <div class="field">
          <label for="st-ll">LAN Listen Addresses</label>
          <input id="st-ll" type="text" class="mono" bind:value={listenLanCsv} />
        </div>
        <div class="field">
          <label for="st-dkp">Protected Docker Containers</label>
          <input id="st-dkp" type="text" class="mono" bind:value={protectedContainersCsv} />
        </div>
      </div>

      <div style="display:flex;gap:18px;flex-wrap:wrap;">
        <label class="check-row"><input type="checkbox" bind:checked={settingsJson.firewall.auto_manage} /> Auto-Manage Host Firewall</label>
        <label class="check-row"><input type="checkbox" bind:checked={settingsJson.security.kernel_ban_offload} /> Kernel Fail2Ban Offload</label>
        <label class="check-row"><input type="checkbox" bind:checked={settingsJson.web_terminal.require_reauth} /> Require Password Re-Auth Before Opening PTY</label>
      </div>
    </form>
  {/if}

  <!-- 2. 认证安全中心：改密 + TOTP + Ed25519 + 本地根证书导出 -->
  {#if subTab === 'security'}
    <div class="bento-grid-2">
      <!-- 修改管理员密码 + 导出本地 TLS 证书 -->
      <div class="card">
        <div class="card-header">
          <span class="card-title">{lang === 'en' ? 'Admin Password & Local HTTPS Cert' : '修改管理员口令与导出本地 HTTPS 证书'}</span>
          <a href="/api/auth/ca-cert" class="btn btn-xs" download="vane-admin.crt">
            {lang === 'en' ? 'Download TLS Cert (.crt)' : '下载面板证书 (.crt)'}
          </a>
        </div>
        <form onsubmit={updateAdminCredentials}>
          <div class="field">
            <label for="sec-un">{lang === 'en' ? 'New Username (optional)' : '管理员用户名（留空保持不变）'}</label>
            <input id="sec-un" type="text" placeholder={settingsJson.admin.username} bind:value={newUsername} />
          </div>
          <div class="field">
            <label for="sec-cp">{t.curPw}</label>
            <input id="sec-cp" type="password" bind:value={curPw} required />
          </div>
          <div class="field">
            <label for="sec-np">{t.newPw}</label>
            <input id="sec-np" type="password" bind:value={newPw} required />
          </div>
          <button type="submit" class="btn btn-primary btn-sm">{lang === 'en' ? 'Update Password' : '更新密码'}</button>
        </form>
      </div>

      <!-- TOTP 双因素认证 -->
      <div class="card">
        <div class="card-header">
          <span class="card-title">RFC 6238 TOTP 2FA</span>
          <span class="badge {settingsJson.admin.totp_enabled ? 'badge-ok' : 'badge-muted'}">
            {settingsJson.admin.totp_enabled ? t.enabled : t.disabled}
          </span>
        </div>

        {#if settingsJson.admin.totp_enabled}
          <p style="font-size:13px;color:var(--text-secondary);margin-bottom:12px;">
            {lang === 'en'
              ? `Monotonic replay-protected TOTP is active. Remaining recovery codes: ${settingsJson.admin.totp_recovery_hashes?.remaining ?? 0}`
              : `防回退重放 TOTP 二步验证已开启。当前剩余一次性恢复码：${settingsJson.admin.totp_recovery_hashes?.remaining ?? 0} 个`}
          </p>
          <div class="btn-group">
            <button type="button" class="btn btn-sm" onclick={regenerateRecoveryCodes}>
              {lang === 'en' ? 'Regenerate Recovery Codes' : '重新生成恢复码'}
            </button>
            <button type="button" class="btn btn-sm btn-danger" onclick={disableTotp}>
              {lang === 'en' ? 'Disable TOTP' : '关闭 TOTP'}
            </button>
          </div>
        {:else if !totpSetupData}
          <p style="font-size:13px;color:var(--text-secondary);margin-bottom:12px;">
            {lang === 'en'
              ? 'Protect your router gateway with Authenticator 6-digit TOTP + 6 single-use recovery codes.'
              : '绑定验证器 App 动态口令，登录时强制校验单调递增时间步长并生成 6 枚一次性恢复码。'}
          </p>
          <button type="button" class="btn btn-primary btn-sm" onclick={startTotpSetup}>
            {lang === 'en' ? 'Setup TOTP 2FA' : '开始配置 TOTP'}
          </button>
        {:else}
          <form onsubmit={confirmTotpEnable}>
            <div class="subcard mono" style="font-size:12px;margin-bottom:12px;word-break:break-all;">
              <div><strong>Secret:</strong> {totpSetupData.secret_base32}</div>
              <div style="margin-top:4px;color:var(--text-secondary);">{totpSetupData.otpauth_uri}</div>
            </div>
            <div class="field">
              <label for="totp-vcode">{lang === 'en' ? 'Enter 6-digit code from Authenticator App' : '输入验证器显示的 6 位数字激活'}</label>
              <input id="totp-vcode" type="text" class="mono" placeholder="123456" bind:value={totpVerifyCode} required />
            </div>
            <div class="btn-group">
              <button type="submit" class="btn btn-primary btn-sm">{lang === 'en' ? 'Verify & Enable' : '验证并启用'}</button>
              <button type="button" class="btn btn-sm" onclick={() => totpSetupData = null}>{t.cancel}</button>
            </div>
          </form>
        {/if}

        {#if issuedRecoveryCodes.length > 0}
          <div class="subcard" style="margin-top:14px;border-color:var(--warn);">
            <div class="row-between" style="margin-bottom:6px;">
              <span style="font-size:12px;font-weight:700;color:var(--warn);">
                {lang === 'en' ? 'Save One-Time Recovery Codes Now (Shown Once!)' : '请立即离线保存一次性恢复码（仅展示一次！）'}
              </span>
              <button type="button" class="btn btn-xs" onclick={async () => { if (await copyText(issuedRecoveryCodes.join('\n'))) showToast(t.copied); }}>
                {t.copy}
              </button>
            </div>
            <div class="mono" style="display:grid;grid-template-columns:1fr 1fr;gap:6px;font-size:13px;">
              {#each issuedRecoveryCodes as rc}
                <div>{rc}</div>
              {/each}
            </div>
          </div>
        {/if}
      </div>
    </div>

    <!-- Ed25519 公钥管理 -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">OpenSSH Ed25519 Authorized Keys</span>
        {#if settingsJson.admin.authorized_ed25519_keys?.length > 0}
          <label class="check-row" style="min-height:32px;">
            <input
              type="checkbox"
              checked={settingsJson.admin.password_login_enabled}
              onchange={async (e) => {
                const next = deepClone(settingsJson);
                next.admin.password_login_enabled = e.currentTarget.checked;
                await onSaveSettings(next);
              }}
            />
            {lang === 'en' ? 'Allow Password Login' : '允许密码登录（取消勾选即切换为纯密钥挑战登录）'}
          </label>
        {/if}
      </div>

      {#if settingsJson.admin.authorized_ed25519_keys?.length}
        <div style="display:grid;gap:8px;margin-bottom:14px;">
          {#each settingsJson.admin.authorized_ed25519_keys as k}
            <div class="subcard row-between">
              <div style="min-width:0;">
                <div style="font-weight:700;" class="mono">{k.id}</div>
                <div class="mono" style="font-size:11px;color:var(--text-secondary);word-break:break-all;">{k.pubkey}</div>
              </div>
              <button type="button" class="btn btn-xs btn-danger" onclick={() => deleteEd25519Key(k.id)}>{t.delete}</button>
            </div>
          {/each}
        </div>
      {/if}

      <form onsubmit={addEd25519Key} class="form-grid" style="align-items:end;">
        <div class="field" style="margin-bottom:0;">
          <label for="ed-id">Key ID</label>
          <input id="ed-id" type="text" class="mono" placeholder="macbook" bind:value={newKeyId} required />
        </div>
        <div class="field" style="margin-bottom:0;">
          <label for="ed-pub">OpenSSH Public Key (ssh-ed25519 AAAAC3...)</label>
          <input id="ed-pub" type="text" class="mono" placeholder="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5..." bind:value={newKeyPub} required />
        </div>
        <button type="submit" class="btn btn-primary">{t.add}</button>
      </form>
    </div>
  {/if}

  <!-- 3. 通知渠道中心 -->
  {#if subTab === 'notifications'}
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title">{lang === 'en' ? 'Global Multi-Channel Notification Pool' : '全局多渠道告警与事件通知中心'}</div>
          <div style="font-size:12px;color:var(--text-secondary);">
            Webhook / Bark / Telegram / WeCom / Feishu (HMAC) / DingTalk (HMAC) / Gotify / Ntfy
          </div>
        </div>
        <button type="button" class="btn btn-primary btn-sm" onclick={() => openNotifDrawer(-1)}>+ {t.add}</button>
      </div>

      {#if !settingsJson.notifications?.length}
        <div class="empty-state">{t.common.empty}</div>
      {:else}
        <div style="display:grid;gap:10px;">
          {#each settingsJson.notifications as n, idx}
            <div class="subcard row-between">
              <div>
                <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                  <span style="font-weight:700;">{n.name}</span>
                  <span class="badge badge-info">{n.provider}</span>
                  <span class="badge badge-muted">&gt;= {n.min_severity}</span>
                  {#if !n.enabled}<span class="badge badge-warn">{t.disabled}</span>{/if}
                </div>
                <div class="mono" style="font-size:11px;color:var(--text-secondary);margin-top:4px;">
                  Events: {n.events?.length ? n.events.join(', ') : '* (All Events)'}
                </div>
              </div>
              <div class="btn-group">
                <button type="button" class="btn btn-xs btn-primary" disabled={busyNotif === n.name} onclick={() => testNotification(n.name)}>
                  {busyNotif === n.name ? '...' : (lang === 'en' ? 'Test Push' : '测试推送')}
                </button>
                <button type="button" class="btn btn-xs" onclick={() => openNotifDrawer(idx)}>{t.edit}</button>
                <button type="button" class="btn btn-xs btn-danger" onclick={() => deleteNotification(idx)}>{t.delete}</button>
              </div>
            </div>
          {/each}
        </div>
      {/if}
    </div>
  {/if}

  <!-- 4. 跨机加密备份与脱敏导出 -->
  {#if subTab === 'backup'}
    <div class="bento-grid-2">
      <form class="card" onsubmit={exportEncryptedBackup}>
        <div class="card-header">
          <span class="card-title">{lang === 'en' ? 'Export Encrypted .vane.bak' : '导出跨设备全量加密备份 (.vane.bak)'}</span>
        </div>
        <p style="font-size:13px;color:var(--text-secondary);margin-bottom:14px;">
          {lang === 'en'
            ? 'Decrypts Vault secrets in memory and re-seals the archive with PBKDF2-SHA256 + ChaCha20-Poly1305 so it can be restored on a new router.'
            : '使用独立备份口令经 PBKDF2 (200,000 次) + ChaCha20-Poly1305 整包认证加密，支持跨路由器迁移恢复全部配置与云凭据。'}
        </p>
        <div class="field">
          <label for="bk-pw">{lang === 'en' ? 'Backup Encryption Password (>= 8 chars)' : '设置备份加密密码（至少 8 位）'}</label>
          <input id="bk-pw" type="password" minlength="8" bind:value={backupPass} required />
        </div>
        <button type="submit" class="btn btn-primary btn-sm">
          {lang === 'en' ? 'Download .vane.bak' : '加密并下载 .vane.bak'}
        </button>
      </form>

      <form class="card" onsubmit={importEncryptedBackup}>
        <div class="card-header">
          <span class="card-title">{lang === 'en' ? 'Restore Encrypted .vane.bak' : '导入恢复 .vane.bak 备份'}</span>
        </div>
        <div class="field">
          <label for="bk-file">{lang === 'en' ? 'Select .vane.bak File' : '选择备份文件'}</label>
          <input id="bk-file" type="file" accept=".bak,application/octet-stream" onchange={handleBackupFileSelect} required />
        </div>
        <div class="field">
          <label for="bk-rpw">{lang === 'en' ? 'Decryption Password' : '输入备份解密密码'}</label>
          <input id="bk-rpw" type="password" minlength="8" bind:value={restorePass} required />
        </div>
        <button type="submit" class="btn btn-primary btn-sm" disabled={!restoreBlobB64}>
          {lang === 'en' ? 'Verify, Re-Seal & Restore' : '校验解密并热重载恢复'}
        </button>
      </form>
    </div>

    <div class="card">
      <div class="card-header">
        <span class="card-title">{lang === 'en' ? 'Sanitized Diagnostic TOML Export' : '脱敏排障配置导出（自动剔除全部密钥/哈希/入口路径）'}</span>
        <button type="button" class="btn btn-sm" onclick={loadSanitizedToml}>
          {lang === 'en' ? 'Generate Sanitized TOML' : '生成脱敏配置文本'}
        </button>
      </div>
      {#if sanitizedPreview}
        <pre class="mono" style="background:var(--bg-elevated);padding:14px;border-radius:12px;max-height:320px;overflow:auto;font-size:12px;">{sanitizedPreview}</pre>
      {/if}
    </div>
  {/if}
{/if}

<!-- 通知渠道抽屉 -->
{#if notifDrawerOpen && notifDraft}
  <div class="drawer-backdrop" role="presentation" onclick={(e) => { if (e.target === e.currentTarget) notifDrawerOpen = false; }}>
    <form class="drawer-panel" onsubmit={saveNotification}>
      <div class="drawer-header">
        <div class="card-title">{notifEditIdx >= 0 ? t.edit : t.add} · Notification</div>
        <button type="button" class="btn btn-sm" onclick={() => notifDrawerOpen = false}>{t.cancel}</button>
      </div>
      <div class="drawer-body">
        <div class="form-grid">
          <div class="field">
            <label for="nf-name">Channel Name</label>
            <input id="nf-name" type="text" class="mono" bind:value={notifDraft.name} required />
          </div>
          <div class="field">
            <label for="nf-prov">Provider</label>
            <select id="nf-prov" bind:value={notifDraft.provider}>
              <option value="webhook">webhook</option>
              <option value="bark">bark</option>
              <option value="telegram">telegram</option>
              <option value="wecom">wecom</option>
              <option value="feishu">feishu</option>
              <option value="dingtalk">dingtalk</option>
              <option value="ntfy">ntfy</option>
              <option value="gotify">gotify</option>
            </select>
          </div>
          <div class="field">
            <label for="nf-sev">Minimum Severity</label>
            <select id="nf-sev" bind:value={notifDraft.min_severity}>
              <option value="info">info</option>
              <option value="warning">warning</option>
              <option value="error">error</option>
              <option value="critical">critical</option>
            </select>
          </div>
          <div class="field">
            <label for="nf-chat">Telegram Chat ID (if telegram)</label>
            <input id="nf-chat" type="text" class="mono" bind:value={notifDraft.chat_id} />
          </div>
        </div>

        <div class="field">
          <label for="nf-url">Endpoint / Bot Webhook URL</label>
          <input id="nf-url" type="text" class="mono" placeholder={secretMaskedHint(notifDraft.url, 'https://...')} bind:value={notifUrlInput} />
        </div>

        <div class="form-grid">
          <div class="field">
            <label for="nf-tok">Bot Token / Bark Key / Gotify Key</label>
            <input id="nf-tok" type="password" class="mono" placeholder={secretMaskedHint(notifDraft.token, 'Optional')} bind:value={notifTokenInput} />
          </div>
          <div class="field">
            <label for="nf-sec">DingTalk / Feishu HMAC Secret</label>
            <input id="nf-sec" type="password" class="mono" placeholder={secretMaskedHint(notifDraft.secret, 'Optional')} bind:value={notifSecretInput} />
          </div>
        </div>

        <div class="field">
          <label for="nf-ev">Subscribed Events (empty = all; e.g. ddns_change, acme_renewed, stun_change, ip_banned, high_temp, low_memory, cron_failure, module_circuit_open)</label>
          <input id="nf-ev" type="text" class="mono" bind:value={notifEventsCsv} />
        </div>

        <label class="check-row"><input type="checkbox" bind:checked={notifDraft.enabled} /> {t.enabled}</label>
      </div>
      <div class="drawer-footer">
        <button type="button" class="btn" onclick={() => notifDrawerOpen = false}>{t.cancel}</button>
        <button type="submit" class="btn btn-primary">{t.confirm}</button>
      </div>
    </form>
  </div>
{/if}
