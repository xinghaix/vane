<script>
  import Icons from './Icons.svelte';
  import SecretField from './SecretField.svelte';
  import HeaderRowsEditor from './HeaderRowsEditor.svelte';
  import { renderQrSvgDataUri } from '../lib/qrcode.js';
  import {
    splitCsv,
    joinCsv,
    kvObjectToRows,
    rowsToKvObject,
    deepClone,
    copyText,
    downloadBlob,
    downloadTextFile,
    uint8ToBase64,
    resolveSecretInput,
  } from '../lib/helpers.js';

  let {
    t,
    lang,
    modules,
    settingsJson,
    networkInfo = null,
    subTab = 'general',
    onSubTabChange,
    onToggleModule,
    onSaveSettings,
    onAuthRefresh,
    onBackupRestored,
    askConfirm,
    apiFetch,
    showToast,
    onRefresh,
  } = $props();

  let saving = $state(false);
  let secBusy = $state('');
  let backupBusy = $state('');
  let ifaceNames = $derived((networkInfo?.interfaces || []).map((i) => i.iface));

  async function handleCopy(text) {
    if (await copyText(text)) showToast(t.copied, 'success');
    else showToast(t.copyFailed, 'error');
  }

  function toggleCsvIface(csv, iface) {
    const items = splitCsv(csv);
    if (items.includes(iface)) return joinCsv(items.filter((x) => x !== iface));
    return joinCsv([...items, iface]);
  }

  // ---------------- 1. 通用与系统草稿（独立草稿状态，不直接修改 settingsJson） ----------------
  let generalDraft = $state(null);
  let wanIfacesCsv = $state('');
  let lanIfacesCsv = $state('');
  let monIfacesCsv = $state('');
  let listenLanCsv = $state('');
  let extraOriginsCsv = $state('');
  let protectedContainersCsv = $state('');
  let syncedGeneralSig = $state('');

  function pickGeneralState(src, csvOverrides = null) {
    if (!src) return null;
    const sys = src.system || {};
    const adm = src.admin || {};
    const fw = src.firewall || {};
    const sec = src.security || {};
    const mon = src.monitor || {};
    const wt = src.web_terminal || {};
    const dk = src.docker || {};
    return {
      system: {
        timezone_offset: String(sys.timezone_offset ?? 'UTC'),
        worker_threads: Number(sys.worker_threads ?? 2),
        log_ring_capacity: Number(sys.log_ring_capacity ?? 300),
        global_max_conns: Number(sys.global_max_conns ?? 512),
      },
      admin: {
        session_ttl_secs: Number(adm.session_ttl_secs ?? 3600),
        secret_path: String(adm.secret_path ?? '/'),
        canonical_origin: String(adm.canonical_origin ?? ''),
        listen_lan: csvOverrides ? splitCsv(csvOverrides.listenLanCsv) : (adm.listen_lan || []),
        extra_allowed_origins: csvOverrides ? splitCsv(csvOverrides.extraOriginsCsv) : (adm.extra_allowed_origins || []),
        docker_socket: String(adm.docker_socket ?? '/var/run/docker.sock'),
        tls_cert_path: String(adm.tls_cert_path ?? ''),
        tls_key_path: String(adm.tls_key_path ?? ''),
      },
      firewall: {
        backend: String(fw.backend ?? 'auto'),
        wan_interfaces: csvOverrides ? splitCsv(csvOverrides.wanIfacesCsv) : (fw.wan_interfaces || []),
        lan_interfaces: csvOverrides ? splitCsv(csvOverrides.lanIfacesCsv) : (fw.lan_interfaces || []),
        auto_manage: Boolean(fw.auto_manage),
      },
      security: {
        max_login_failures: Number(sec.max_login_failures ?? 5),
        ban_duration_secs: Number(sec.ban_duration_secs ?? 1800),
        tls_handshake_timeout_secs: Number(sec.tls_handshake_timeout_secs ?? 5),
        http_header_timeout_secs: Number(sec.http_header_timeout_secs ?? 10),
        kernel_ban_offload: Boolean(sec.kernel_ban_offload),
      },
      monitor: {
        interfaces: csvOverrides ? splitCsv(csvOverrides.monIfacesCsv) : (mon.interfaces || []),
        sample_interval_secs: Number(mon.sample_interval_secs ?? 2),
        temp_alert_celsius: Number(mon.temp_alert_celsius ?? 85),
        mem_low_mb: Number(mon.mem_low_mb ?? 32),
        alert_cooldown_secs: Number(mon.alert_cooldown_secs ?? 1800),
        thermal_path: String(mon.thermal_path ?? ''),
        top_processes: Number(mon.top_processes ?? 10),
      },
      web_terminal: {
        shell: String(wt.shell ?? 'auto'),
        default_cwd: String(wt.default_cwd ?? '/root'),
        idle_timeout_secs: Number(wt.idle_timeout_secs ?? 900),
        max_sessions: Number(wt.max_sessions ?? 2),
        require_reauth: Boolean(wt.require_reauth),
      },
      docker: {
        protected_containers: csvOverrides ? splitCsv(csvOverrides.protectedContainersCsv) : (dk.protected_containers || []),
        log_tail_default: Number(dk.log_tail_default ?? 200),
        log_timestamps: Boolean(dk.log_timestamps),
      },
    };
  }

  function syncGeneralDraft(src) {
    if (!src) return;
    const snap = pickGeneralState(src);
    syncedGeneralSig = JSON.stringify(snap);
    generalDraft = deepClone(snap);
    wanIfacesCsv = joinCsv(src.firewall?.wan_interfaces);
    lanIfacesCsv = joinCsv(src.firewall?.lan_interfaces);
    monIfacesCsv = joinCsv(src.monitor?.interfaces);
    listenLanCsv = joinCsv(src.admin?.listen_lan);
    extraOriginsCsv = joinCsv(src.admin?.extra_allowed_origins);
    protectedContainersCsv = joinCsv(src.docker?.protected_containers);
  }

  $effect(() => {
    if (!settingsJson) return;
    const sig = JSON.stringify(pickGeneralState(settingsJson));
    if (sig !== syncedGeneralSig) {
      syncGeneralDraft(settingsJson);
    }
  });

  function formatEntryUrl(secretPath, canonicalOrigin) {
    const sp = String(secretPath || '').trim();
    if (!sp || sp === '/') return '';
    const origin = String(canonicalOrigin || location.origin).trim().replace(/\/$/, '');
    const normalizedPath = sp.startsWith('/') ? sp : `/${sp}`;
    return `${origin}${normalizedPath}`;
  }

  let currentGeneralSig = $derived(
    generalDraft
      ? JSON.stringify(
          pickGeneralState(generalDraft, {
            listenLanCsv,
            extraOriginsCsv,
            wanIfacesCsv,
            lanIfacesCsv,
            monIfacesCsv,
            protectedContainersCsv,
          })
        )
      : ''
  );
  let generalDirty = $derived(Boolean(generalDraft && syncedGeneralSig && currentGeneralSig !== syncedGeneralSig));

  let savedEntryUrl = $derived(
    formatEntryUrl(settingsJson?.admin?.secret_path, settingsJson?.admin?.canonical_origin)
  );
  let draftEntryUrl = $derived(
    formatEntryUrl(generalDraft?.admin?.secret_path, generalDraft?.admin?.canonical_origin)
  );

  function generateRandomSecretPath() {
    if (!generalDraft) return;
    const buf = new Uint8Array(8);
    crypto.getRandomValues(buf);
    const hex = Array.from(buf, (b) => b.toString(16).padStart(2, '0')).join('');
    generalDraft.admin.secret_path = `/_vane_${hex}`;
  }

  async function saveGeneralSettings(e) {
    e.preventDefault();
    if (saving || !generalDraft || !settingsJson) return;
    const picked = pickGeneralState(generalDraft, {
      listenLanCsv,
      extraOriginsCsv,
      wanIfacesCsv,
      lanIfacesCsv,
      monIfacesCsv,
      protectedContainersCsv,
    });
    picked.system.timezone_offset = picked.system.timezone_offset.trim() || 'UTC';
    const rawSp = picked.admin.secret_path.trim();
    picked.admin.secret_path = !rawSp ? '/' : rawSp.startsWith('/') ? rawSp : `/${rawSp}`;
    picked.admin.canonical_origin = picked.admin.canonical_origin.trim();
    picked.admin.docker_socket = picked.admin.docker_socket.trim() || '/var/run/docker.sock';
    picked.admin.tls_cert_path = picked.admin.tls_cert_path.trim();
    picked.admin.tls_key_path = picked.admin.tls_key_path.trim();
    picked.monitor.thermal_path = picked.monitor.thermal_path.trim();
    picked.web_terminal.shell = picked.web_terminal.shell.trim() || 'auto';
    picked.web_terminal.default_cwd = picked.web_terminal.default_cwd.trim() || '/root';

    if (Boolean(picked.admin.tls_cert_path) !== Boolean(picked.admin.tls_key_path)) {
      showToast(
        lang === 'en'
          ? 'Both custom TLS cert path and key path must be specified together'
          : '自定义管理端 TLS 证书路径与私钥路径必须同时填写或同时留空',
        'error'
      );
      return;
    }

    for (const origin of picked.admin.extra_allowed_origins) {
      let ok = false;
      try {
        const u = new URL(origin);
        ok = u.protocol === 'https:' && u.pathname === '/' && !u.search && !u.hash && origin === u.origin;
      } catch {
        ok = false;
      }
      if (!ok) {
        showToast(
          lang === 'en'
            ? `Invalid extra origin "${origin}" (must be https://host[:port] with no path)`
            : `额外受信 Origin "${origin}" 格式无效（必须为不含路径的 https://host[:port]）`,
          'error'
        );
        return;
      }
    }

    saving = true;
    try {
      const next = deepClone(settingsJson);
      next.system = { ...next.system, ...picked.system, language: lang };
      next.admin = { ...next.admin, ...picked.admin };
      next.firewall = { ...next.firewall, ...picked.firewall };
      next.security = { ...next.security, ...picked.security };
      next.monitor = { ...next.monitor, ...picked.monitor };
      next.web_terminal = { ...next.web_terminal, ...picked.web_terminal };
      next.docker = { ...next.docker, ...picked.docker };
      await onSaveSettings(next);
    } finally {
      saving = false;
    }
  }

  // ---------------- 2. 安全中心：修改密码 / TOTP / Ed25519 ----------------
  let curPw = $state('');
  let newPw = $state('');
  let confirmPw = $state('');
  let newUsername = $state('');
  let totpSetupData = $state(null);
  let totpVerifyCode = $state('');
  let issuedRecoveryCodes = $state([]);
  let newKeyId = $state('');
  let newKeyPub = $state('');

  // ---------------- 4. 加密备份与恢复（声明提前以便切 tab 清理敏感态） ----------------
  let backupPass = $state('');
  let backupPassConfirm = $state('');
  let showBkPass = $state(false);
  let restorePass = $state('');
  let restoreBlobB64 = $state('');
  let restoreFileName = $state('');
  let restoreFileInput = $state(null);
  let sanitizedPreview = $state('');

  $effect(() => {
    const tab = subTab;
    if (tab !== 'security') {
      issuedRecoveryCodes = [];
      totpSetupData = null;
      totpVerifyCode = '';
      curPw = '';
      newPw = '';
      confirmPw = '';
    }
    if (tab !== 'backup') {
      backupPass = '';
      backupPassConfirm = '';
      showBkPass = false;
      restorePass = '';
      restoreBlobB64 = '';
      restoreFileName = '';
      sanitizedPreview = '';
    }
  });

  const textEncoder = new TextEncoder();
  let effectiveUsername = $derived((newUsername || '').trim() || settingsJson?.admin?.username || 'admin');
  let newPwBytes = $derived(textEncoder.encode(newPw).length);
  let pwChecks = $derived({
    lenOk: newPwBytes >= 8 && newPwBytes <= 128,
    hasAlpha: /[A-Za-z]/.test(newPw),
    hasDigitOrPunct: /[0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(newPw),
    notDefault: newPw.length > 0 && newPw !== 'admin321' && newPw !== curPw && newPw !== effectiveUsername,
    matchConfirm: newPw.length > 0 && newPw === confirmPw,
  });
  let pwAllValid = $derived(
    curPw.length > 0 &&
      pwChecks.lenOk &&
      pwChecks.hasAlpha &&
      pwChecks.hasDigitOrPunct &&
      pwChecks.notDefault &&
      pwChecks.matchConfirm
  );

  function safeQrDataUri(uri) {
    try {
      const svg = renderQrSvgDataUri(uri);
      return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
    } catch {
      return '';
    }
  }

  async function downloadAdminCert() {
    if (secBusy) return;
    secBusy = 'cert';
    try {
      const res = await fetch('/api/auth/ca-cert');
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || `HTTP ${res.status}`);
      }
      const blob = await res.blob();
      downloadBlob(blob, 'vane-admin.crt');
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      secBusy = '';
    }
  }

  async function updateAdminCredentials(e) {
    e.preventDefault();
    if (!pwAllValid || secBusy) return;
    secBusy = 'pw';
    try {
      await apiFetch('/api/auth/change-password', {
        method: 'POST',
        body: JSON.stringify({
          current_password: curPw,
          new_password: newPw,
          new_username: newUsername.trim(),
        }),
      });
      curPw = '';
      newPw = '';
      confirmPw = '';
      newUsername = '';
      showToast(lang === 'en' ? 'Credentials updated successfully' : '管理员凭据已成功更新', 'success');
      await onAuthRefresh?.();
      await onRefresh();
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      secBusy = '';
    }
  }

  async function startTotpSetup() {
    if (secBusy) return;
    secBusy = 'totp-setup';
    try {
      totpSetupData = await apiFetch('/api/auth/totp/setup', { method: 'POST' });
      issuedRecoveryCodes = [];
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      secBusy = '';
    }
  }

  async function confirmTotpEnable(e) {
    e.preventDefault();
    if (secBusy) return;
    secBusy = 'totp-enable';
    try {
      const r = await apiFetch('/api/auth/totp/enable', {
        method: 'POST',
        body: JSON.stringify({ code: totpVerifyCode.trim() }),
      });
      totpSetupData = null;
      totpVerifyCode = '';
      issuedRecoveryCodes = r.recovery_codes || [];
      showToast(lang === 'en' ? 'TOTP 2FA enabled' : '已开启 TOTP 二步验证，请妥善保存一次性恢复码', 'success');
      await onAuthRefresh?.();
      await onRefresh();
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      secBusy = '';
    }
  }

  async function regenerateRecoveryCodes() {
    if (secBusy) return;
    secBusy = 'totp-regen';
    try {
      const r = await apiFetch('/api/auth/totp/recovery-codes', { method: 'POST' });
      issuedRecoveryCodes = r.recovery_codes || [];
      showToast(lang === 'en' ? 'Recovery codes regenerated' : '已重新生成一次性恢复码', 'success');
      await onAuthRefresh?.();
      await onRefresh();
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      secBusy = '';
    }
  }

  async function disableTotp() {
    if (secBusy) return;
    secBusy = 'totp-disable';
    try {
      await apiFetch('/api/auth/totp/disable', { method: 'POST' });
      issuedRecoveryCodes = [];
      showToast(lang === 'en' ? 'TOTP disabled' : '已关闭 TOTP 二步验证', 'success');
      await onAuthRefresh?.();
      await onRefresh();
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      secBusy = '';
    }
  }

  function requestTogglePasswordLogin() {
    if (secBusy || !settingsJson) return;
    const currentlyEnabled = Boolean(settingsJson.admin.password_login_enabled);
    const exec = async () => {
      secBusy = 'pw-toggle';
      try {
        const next = deepClone(settingsJson);
        next.admin.password_login_enabled = !currentlyEnabled;
        if (await onSaveSettings(next)) {
          await onAuthRefresh?.();
        }
      } finally {
        secBusy = '';
      }
    };
    if (currentlyEnabled) {
      askConfirm({
        title: t.cfg.disablePwConfirmTitle,
        message: t.cfg.disablePwConfirmDesc,
        confirmLabel: t.confirmAction,
        danger: true,
        onConfirm: exec,
      });
    } else {
      exec();
    }
  }

  async function addEd25519Key(e) {
    e.preventDefault();
    if (secBusy) return;
    secBusy = 'ed-add';
    try {
      await apiFetch('/api/auth/ed25519/keys', {
        method: 'POST',
        body: JSON.stringify({ id: newKeyId.trim(), pubkey: newKeyPub.trim() }),
      });
      newKeyId = '';
      newKeyPub = '';
      showToast(lang === 'en' ? 'Ed25519 key added' : '已添加授权 Ed25519 公钥', 'success');
      await onAuthRefresh?.();
      await onRefresh();
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      secBusy = '';
    }
  }

  async function deleteEd25519Key(id) {
    if (secBusy) return;
    secBusy = `ed-del:${id}`;
    try {
      await apiFetch(`/api/auth/ed25519/keys/${encodeURIComponent(id)}`, { method: 'DELETE' });
      showToast(`${t.delete}: ${id}`, 'success');
      await onAuthRefresh?.();
      await onRefresh();
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      secBusy = '';
    }
  }

  // ---------------- 3. 通知渠道中心 ----------------
  const NOTIF_PROVIDERS = ['webhook', 'bark', 'telegram', 'wecom', 'feishu', 'dingtalk', 'ntfy', 'gotify'];
  const ALL_EVENTS = [
    'ddns_change',
    'ddns_failure',
    'acme_renewed',
    'acme_failure',
    'stun_change',
    'ip_banned',
    'high_temp',
    'low_memory',
    'cron_failure',
    'module_circuit_open',
  ];

  let notifDrawerOpen = $state(false);
  let notifEditIdx = $state(-1);
  let notifOrigName = $state('');
  let notifDraft = $state(null);
  let notifUrlInput = $state('');
  let notifUrlClear = $state(false);
  let notifTokenInput = $state('');
  let notifTokenClear = $state(false);
  let notifSecretInput = $state('');
  let notifSecretClear = $state(false);
  let notifBodyTplInput = $state('');
  let notifBodyTplClear = $state(false);
  let notifHeaderRows = $state([]);
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
    notifOrigName = idx >= 0 ? n.name : '';
    notifDraft = n;
    notifUrlInput = '';
    notifUrlClear = false;
    notifTokenInput = '';
    notifTokenClear = false;
    notifSecretInput = '';
    notifSecretClear = false;
    notifBodyTplInput = '';
    notifBodyTplClear = false;
    notifHeaderRows = kvObjectToRows(n.headers);
    notifDrawerOpen = true;
  }

  function onNotifProviderChange() {
    if (!notifDraft) return;
    notifDraft.url = '';
    notifDraft.token = '';
    notifDraft.chat_id = '';
    notifDraft.secret = '';
    notifUrlInput = '';
    notifUrlClear = false;
    notifTokenInput = '';
    notifTokenClear = false;
    notifSecretInput = '';
    notifSecretClear = false;
  }

  function toggleNotifEvent(ev) {
    if (!notifDraft) return;
    const list = notifDraft.events || [];
    if (list.includes(ev)) {
      notifDraft.events = list.filter((x) => x !== ev);
    } else {
      notifDraft.events = [...list, ev];
    }
  }

  async function saveNotification(e) {
    e.preventDefault();
    if (saving || !notifDraft) return;
    notifDraft.name = String(notifDraft.name || '').trim();
    if (!notifDraft.name) {
      showToast(lang === 'en' ? 'Channel name is required' : '请填写通知渠道名称', 'error');
      return;
    }
    const tplTrimmed = notifBodyTplInput.trim();
    if (tplTrimmed) {
      try {
        JSON.parse(tplTrimmed);
      } catch {
        showToast(
          lang === 'en' ? 'Custom Body Template must be valid JSON' : '自定义 Body 模板必须是合法的 JSON 格式',
          'error'
        );
        return;
      }
    }
    saving = true;
    try {
      const orig = notifEditIdx >= 0 ? settingsJson.notifications[notifEditIdx] : null;
      const sameProvider = orig && orig.provider === notifDraft.provider;
      notifDraft.url = resolveSecretInput(sameProvider ? orig?.url : '', notifUrlInput, notifUrlClear);
      notifDraft.token = resolveSecretInput(sameProvider ? orig?.token : '', notifTokenInput, notifTokenClear);
      notifDraft.secret = resolveSecretInput(sameProvider ? orig?.secret : '', notifSecretInput, notifSecretClear);
      notifDraft.body_template = resolveSecretInput(orig?.body_template, notifBodyTplInput, notifBodyTplClear);
      notifDraft.headers = rowsToKvObject(notifHeaderRows, true);

      const next = deepClone(settingsJson);
      const renames = [];
      if (orig && notifOrigName && notifOrigName !== notifDraft.name) {
        renames.push({ from: `notifications.${notifOrigName}`, to: `notifications.${notifDraft.name}` });
      }
      if (notifEditIdx >= 0) next.notifications[notifEditIdx] = notifDraft;
      else next.notifications.push(notifDraft);
      if (await onSaveSettings(next, renames)) notifDrawerOpen = false;
    } finally {
      saving = false;
    }
  }

  async function toggleNotificationEnabled(idx) {
    const n = settingsJson.notifications[idx];
    const key = `toggle:${n.name}`;
    if (busyNotif === key) return;
    busyNotif = key;
    try {
      const next = deepClone(settingsJson);
      next.notifications[idx].enabled = !next.notifications[idx].enabled;
      await onSaveSettings(next);
    } finally {
      busyNotif = '';
    }
  }

  function deleteNotification(idx) {
    const n = settingsJson.notifications[idx];
    askConfirm({
      title: t.common.confirmDeleteTitle,
      message: `${n?.name || ''} (${n?.provider || ''})`,
      confirmLabel: t.delete,
      danger: true,
      onConfirm: async () => {
        const next = deepClone(settingsJson);
        next.notifications.splice(idx, 1);
        await onSaveSettings(next);
      },
    });
  }

  async function testNotification(name) {
    if (busyNotif) return;
    busyNotif = name;
    try {
      const r = await apiFetch(`/api/notifications/${encodeURIComponent(name)}/test`, { method: 'POST' });
      const outcomeLabel =
        r.outcome === 'sent'
          ? lang === 'en'
            ? 'Sent'
            : '推送成功'
          : r.outcome === 'skipped'
            ? lang === 'en'
              ? 'Skipped by severity/event filter'
              : '已跳过（不满足级别或事件过滤）'
            : String(r.outcome || 'OK');
      showToast(`${name}: ${outcomeLabel}`, r.outcome === 'skipped' ? 'warn' : 'success');
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      busyNotif = '';
    }
  }

  // ---------------- 4. 备份操作函数 ----------------
  const MAX_BACKUP_BYTES = 16 * 1024 * 1024;
  const BACKUP_MAGIC = 'VANEBAK1';

  function b64ToUint8(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function formatBackupSummary(sum) {
    if (!sum || typeof sum !== 'object') return '';
    const parts = [];
    if (typeof sum.acme_accounts === 'number') {
      parts.push(lang === 'en' ? `ACME accts: ${sum.acme_accounts}` : `ACME 账户: ${sum.acme_accounts}`);
    }
    if (typeof sum.acme_certs === 'number') {
      parts.push(lang === 'en' ? `Certs: ${sum.acme_certs}` : `证书: ${sum.acme_certs}`);
    }
    if (sum.admin_tls) {
      parts.push(lang === 'en' ? 'Admin TLS: yes' : '面板 TLS: 已含');
    }
    return parts.length ? ` (${parts.join(' · ')})` : '';
  }

  async function exportEncryptedBackup(e) {
    e.preventDefault();
    if (backupBusy) return;
    if (backupPass !== backupPassConfirm) {
      showToast(t.cfg.bkPwMismatch, 'error');
      return;
    }
    backupBusy = 'export';
    try {
      const r = await apiFetch('/api/backup/export', {
        method: 'POST',
        body: JSON.stringify({ password: backupPass }),
      });
      const bytes = b64ToUint8(r.backup_blob);
      const blob = new Blob([bytes], { type: 'application/octet-stream' });
      downloadBlob(blob, `vane-backup-${new Date().toISOString().slice(0, 10)}.vane.bak`);
      backupPass = '';
      backupPassConfirm = '';
      const sumText = formatBackupSummary(r.summary);
      showToast(
        (lang === 'en' ? 'Encrypted .vane.bak downloaded' : '已导出跨设备加密备份文件 (.vane.bak)') + sumText,
        'success'
      );
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      backupBusy = '';
    }
  }

  function handleBackupFileSelect(e) {
    const file = e.currentTarget.files?.[0];
    restoreBlobB64 = '';
    restoreFileName = '';
    if (!file) return;
    if (file.size > MAX_BACKUP_BYTES) {
      showToast(t.cfg.bkTooLarge, 'error');
      e.currentTarget.value = '';
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      const u8 = new Uint8Array(reader.result);
      let magic = '';
      for (let i = 0; i < Math.min(8, u8.length); i++) magic += String.fromCharCode(u8[i]);
      if (magic !== BACKUP_MAGIC) {
        showToast(t.cfg.bkBadMagic, 'error');
        if (restoreFileInput) restoreFileInput.value = '';
        return;
      }
      restoreFileName = file.name;
      restoreBlobB64 = uint8ToBase64(u8);
    };
    reader.readAsArrayBuffer(file);
  }

  async function doImportEncryptedBackup() {
    if (backupBusy) return;
    backupBusy = 'import';
    try {
      const res = await apiFetch('/api/backup/import', {
        method: 'POST',
        body: JSON.stringify({ backup_blob: restoreBlobB64, password: restorePass }),
      });
      restorePass = '';
      restoreBlobB64 = '';
      restoreFileName = '';
      if (restoreFileInput) restoreFileInput.value = '';
      onBackupRestored?.(res);
      const sumText = formatBackupSummary(res?.restored_summary);
      showToast(
        (lang === 'en' ? 'Backup restored & hot-reloaded' : '加密备份已恢复并重新加封生效') + sumText,
        'success'
      );
      if (res?.secret_path && res.secret_path !== '/') {
        showToast(
          lang === 'en'
            ? `Restored secret_path: ${res.secret_path} — bookmark it!`
            : `恢复后的安全入口路径：${res.secret_path}，请及时收藏！`,
          'warn'
        );
      } else if (Array.isArray(res?.restart_required) && res.restart_required.length > 0) {
        showToast(t.restartBannerTitle, 'warn');
      }
      await onAuthRefresh?.();
      await onRefresh();
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      backupBusy = '';
    }
  }

  function importEncryptedBackup(e) {
    e.preventDefault();
    if (!restoreBlobB64 || backupBusy) return;
    askConfirm({
      title: t.cfg.bkImportTitle,
      message: `${restoreFileName ? `${restoreFileName} — ` : ''}${t.cfg.bkImportConfirm}`,
      confirmLabel: t.cfg.bkImportBtn,
      danger: true,
      onConfirm: doImportEncryptedBackup,
    });
  }

  async function loadSanitizedToml() {
    if (backupBusy) return;
    backupBusy = 'sanitized';
    try {
      const r = await apiFetch('/api/backup/sanitized', { method: 'POST' });
      sanitizedPreview = r.toml || '';
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      backupBusy = '';
    }
  }
</script>

<svelte:window
  onkeydown={(e) => {
    if (e.defaultPrevented || saving) return;
    if (e.key === 'Escape' && notifDrawerOpen) notifDrawerOpen = false;
  }}
/>

<datalist id="settings-iface-list">
  {#each ifaceNames as name (name)}
    <option value={name}></option>
  {/each}
</datalist>

{#if settingsJson}
  <!-- 顶部子面板导航 -->
  <div style="margin-bottom:18px;">
    <div class="pill-tabs" role="tablist">
      <button type="button" role="tab" aria-selected={subTab === 'general'} class="pill-tab {subTab === 'general' ? 'active' : ''}" onclick={() => onSubTabChange?.('general')}>
        {t.cfg.tabGeneral}
      </button>
      <button type="button" role="tab" aria-selected={subTab === 'security'} class="pill-tab {subTab === 'security' ? 'active' : ''}" onclick={() => onSubTabChange?.('security')}>
        {t.cfg.tabSecurity}
      </button>
      <button type="button" role="tab" aria-selected={subTab === 'notifications'} class="pill-tab {subTab === 'notifications' ? 'active' : ''}" onclick={() => onSubTabChange?.('notifications')}>
        {t.cfg.tabNotifications} ({settingsJson.notifications?.length || 0})
      </button>
      <button type="button" role="tab" aria-selected={subTab === 'backup'} class="pill-tab {subTab === 'backup' ? 'active' : ''}" onclick={() => onSubTabChange?.('backup')}>
        {t.cfg.tabBackup}
      </button>
    </div>
  </div>

  <!-- 1. 模块启停与系统/防火墙设置 -->
  {#if subTab === 'general'}
    <div class="card" style="margin-bottom:18px;">
      <div class="card-header">
        <div>
          <div class="card-title">{t.cfg.modulesTitle}</div>
          <div style="font-size:12px;color:var(--text-secondary);">{t.cfg.modulesDesc}</div>
        </div>
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
        ] as [key, title] (key)}
          <div class="subcard row-between">
            <div style="display:flex;align-items:center;gap:8px;">
              <Icons name={key} size={16} />
              <span style="font-weight:600;font-size:14px;">{title}</span>
            </div>
            <div style="display:flex;align-items:center;gap:10px;">
              <span class="badge {modules[key] ? 'badge-ok' : 'badge-muted'}">{modules[key] ? t.enabled : t.disabled}</span>
              <button
                type="button"
                class="switch"
                role="switch"
                aria-checked={Boolean(modules[key])}
                aria-label={title}
                onclick={() => onToggleModule(key)}
              >
                <span class="switch-thumb"></span>
              </button>
            </div>
          </div>
        {/each}
      </div>
    </div>

    {#if generalDraft}
      <form class="card" onsubmit={saveGeneralSettings}>
        <div class="card-header">
          <span class="card-title">{t.cfg.sysTitle}</span>
          <div class="btn-group">
            {#if generalDirty}
              <button type="button" class="btn btn-sm" onclick={() => syncGeneralDraft(settingsJson)}>
                {t.common.discardChanges}
              </button>
            {/if}
            <button type="submit" class="btn btn-primary btn-sm" disabled={saving}>{saving ? '...' : t.saveSettings}</button>
          </div>
        </div>

        {#if generalDirty}
          <div class="banner banner-info">
            <div style="display:flex;align-items:center;gap:8px;font-weight:600;">
              <Icons name="info" size={16} />
              <span>{t.common.unsavedChanges}</span>
            </div>
            <div class="btn-group">
              <button type="button" class="btn btn-xs" onclick={() => syncGeneralDraft(settingsJson)}>{t.common.discardChanges}</button>
              <button type="submit" class="btn btn-xs btn-primary" disabled={saving}>{t.saveSettings}</button>
            </div>
          </div>
        {/if}

        <div class="banner banner-warn">
          <div style="display:flex;align-items:flex-start;gap:10px;">
            <Icons name="alert" size={17} />
            <div>
              <div style="font-weight:700;">{t.cfg.originWarnTitle}</div>
              <div style="color:var(--text-secondary);">{t.cfg.originWarnDesc}</div>
              {#if savedEntryUrl}
                <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:8px;">
                  <span style="font-size:12px;color:var(--text-secondary);">{t.cfg.savedEntryUrl}:</span>
                  <code class="mono" style="background:var(--bg-elevated);padding:2px 8px;border-radius:6px;border:1px solid var(--border-subtle);">{savedEntryUrl}</code>
                  <button type="button" class="btn btn-xs" onclick={() => handleCopy(savedEntryUrl)}>
                    <Icons name="copy" size={12} />
                    <span>{t.copy}</span>
                  </button>
                </div>
              {/if}
              {#if draftEntryUrl && draftEntryUrl !== savedEntryUrl}
                <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:6px;">
                  <span style="font-size:12px;color:var(--warn);font-weight:600;">{t.cfg.previewEntryUrl}:</span>
                  <code class="mono" style="background:var(--bg-elevated);padding:2px 8px;border-radius:6px;border:1px solid var(--warn);">{draftEntryUrl}</code>
                  <button type="button" class="btn btn-xs" onclick={() => handleCopy(draftEntryUrl)}>
                    <Icons name="copy" size={12} />
                    <span>{t.copy}</span>
                  </button>
                </div>
              {/if}
            </div>
          </div>
        </div>

        <!-- Core & Admin Listener -->
        <div class="section-label">{t.cfg.groupCore}</div>
        <div class="form-grid">
          <div class="field">
            <label for="st-ttl">{t.cfg.lblSessionTtl}</label>
            <input id="st-ttl" type="number" min="300" max="86400" bind:value={generalDraft.admin.session_ttl_secs} required />
          </div>
          <div class="field">
            <label for="st-maxc">{t.cfg.lblGlobalConns}</label>
            <input id="st-maxc" type="number" min="64" max="4096" bind:value={generalDraft.system.global_max_conns} required />
          </div>
          <div class="field">
            <label for="st-tz">{t.cfg.lblTimezone} (UTC / auto / +08:00)</label>
            <input id="st-tz" type="text" class="mono" bind:value={generalDraft.system.timezone_offset} />
          </div>
          <div class="field">
            <label for="st-ring">{t.cfg.lblLogRing}</label>
            <input id="st-ring" type="number" min="50" max="1000" bind:value={generalDraft.system.log_ring_capacity} required />
          </div>
          <div class="field">
            <label for="st-wk">
              {t.cfg.workerThreads}
              <span class="badge badge-warn" style="margin-left:6px;font-size:10px;">{t.common.restartReqBadge}</span>
            </label>
            <input id="st-wk" type="number" min="1" max="8" bind:value={generalDraft.system.worker_threads} required />
          </div>
          <div class="field">
            <div class="row-between" style="gap:6px;">
              <label for="st-sp" style="margin:0;">{t.cfg.lblSecretPath}</label>
              <button type="button" class="btn btn-ghost btn-xs" style="min-height:22px;padding:0 6px;" onclick={generateRandomSecretPath}>
                {t.cfg.genRandomPath}
              </button>
            </div>
            <input id="st-sp" type="text" class="mono" placeholder="/ or /_vane_..." bind:value={generalDraft.admin.secret_path} />
          </div>
          <div class="field">
            <label for="st-org">
              {t.cfg.lblCanonicalOrigin}
              <span class="badge badge-warn" style="margin-left:6px;font-size:10px;">{t.common.restartReqBadge}</span>
            </label>
            <input id="st-org" type="text" class="mono" bind:value={generalDraft.admin.canonical_origin} />
          </div>
          <div class="field">
            <label for="st-ll">
              {t.cfg.lblListenLan}
              <span class="badge badge-warn" style="margin-left:6px;font-size:10px;">{t.common.restartReqBadge}</span>
            </label>
            <input id="st-ll" type="text" class="mono" bind:value={listenLanCsv} />
          </div>
          <div class="field">
            <label for="st-eo">{t.cfg.extraOrigins}</label>
            <input id="st-eo" type="text" class="mono" placeholder="https://192.168.1.1:5173" bind:value={extraOriginsCsv} />
          </div>
          <div class="field">
            <label for="st-dks">{t.cfg.dockerSocket}</label>
            <input id="st-dks" type="text" class="mono" bind:value={generalDraft.admin.docker_socket} />
          </div>
          <div class="field">
            <label for="st-tcert">
              {t.cfg.tlsCertPath}
              <span class="badge badge-warn" style="margin-left:6px;font-size:10px;">{t.common.restartReqBadge}</span>
            </label>
            <input id="st-tcert" type="text" class="mono" placeholder="/etc/vane/admin.crt" bind:value={generalDraft.admin.tls_cert_path} />
          </div>
          <div class="field">
            <label for="st-tkey">{t.cfg.tlsKeyPath}</label>
            <input id="st-tkey" type="text" class="mono" placeholder="/etc/vane/admin.key" bind:value={generalDraft.admin.tls_key_path} />
          </div>
        </div>

        <!-- Firewall & Fail2Ban -->
        <div class="section-label">{t.cfg.groupFirewall}</div>
        <div class="form-grid">
          <div class="field">
            <label for="st-fwb">
              {t.cfg.lblFwBackend}
              <span class="badge badge-warn" style="margin-left:6px;font-size:10px;">{t.common.restartReqBadge}</span>
            </label>
            <select id="st-fwb" bind:value={generalDraft.firewall.backend}>
              <option value="auto">auto (fw4 nftables / fw3 iptables)</option>
              <option value="nftables">nftables (OpenWrt fw4)</option>
              <option value="iptables_legacy">iptables_legacy</option>
              <option value="iptables_nft">iptables_nft</option>
            </select>
          </div>
          <div class="field">
            <label for="st-wan">{t.cfg.lblWanIfaces}</label>
            <input id="st-wan" type="text" list="settings-iface-list" class="mono" placeholder="pppoe-wan" bind:value={wanIfacesCsv} />
            {#if ifaceNames.length}
              <div style="display:flex;gap:5px;flex-wrap:wrap;margin-top:4px;">
                {#each ifaceNames as ifn (ifn)}
                  {@const picked = splitCsv(wanIfacesCsv).includes(ifn)}
                  <button type="button" class="chip {picked ? 'active' : ''}" onclick={() => (wanIfacesCsv = toggleCsvIface(wanIfacesCsv, ifn))}>
                    {ifn}
                  </button>
                {/each}
              </div>
            {/if}
          </div>
          <div class="field">
            <label for="st-lan">{t.cfg.lblLanIfaces}</label>
            <input id="st-lan" type="text" list="settings-iface-list" class="mono" placeholder="br-lan" bind:value={lanIfacesCsv} />
            {#if ifaceNames.length}
              <div style="display:flex;gap:5px;flex-wrap:wrap;margin-top:4px;">
                {#each ifaceNames as ifn (ifn)}
                  {@const picked = splitCsv(lanIfacesCsv).includes(ifn)}
                  <button type="button" class="chip {picked ? 'active' : ''}" onclick={() => (lanIfacesCsv = toggleCsvIface(lanIfacesCsv, ifn))}>
                    {ifn}
                  </button>
                {/each}
              </div>
            {/if}
          </div>
          <div class="field">
            <label for="st-f2b">{t.cfg.lblMaxFailures}</label>
            <input id="st-f2b" type="number" min="3" max="20" bind:value={generalDraft.security.max_login_failures} required />
          </div>
          <div class="field">
            <label for="st-bds">{t.cfg.lblBanDuration}</label>
            <input id="st-bds" type="number" min="60" max="86400" bind:value={generalDraft.security.ban_duration_secs} required />
          </div>
          <div class="field">
            <label for="st-tlshs">{t.cfg.tlsHsTimeout} (2~30)</label>
            <input id="st-tlshs" type="number" min="2" max="30" bind:value={generalDraft.security.tls_handshake_timeout_secs} required />
          </div>
          <div class="field">
            <label for="st-hdrt">{t.cfg.hdrTimeout} (3~60)</label>
            <input id="st-hdrt" type="number" min="3" max="60" bind:value={generalDraft.security.http_header_timeout_secs} required />
          </div>
        </div>
        <div style="display:flex;gap:18px;flex-wrap:wrap;margin-bottom:8px;">
          <label class="check-row"><input type="checkbox" bind:checked={generalDraft.firewall.auto_manage} /> {t.cfg.lblFwAuto}</label>
          <label class="check-row"><input type="checkbox" bind:checked={generalDraft.security.kernel_ban_offload} /> {t.cfg.lblKernelBan}</label>
        </div>

        <!-- Monitor, Terminal & Docker -->
        <div class="section-label">{t.cfg.groupMonitor}</div>
        <div class="form-grid">
          <div class="field">
            <label for="st-mif">{t.cfg.lblMonIfaces}</label>
            <input id="st-mif" type="text" list="settings-iface-list" class="mono" bind:value={monIfacesCsv} />
            {#if ifaceNames.length}
              <div style="display:flex;gap:5px;flex-wrap:wrap;margin-top:4px;">
                {#each ifaceNames as ifn (ifn)}
                  {@const picked = splitCsv(monIfacesCsv).includes(ifn)}
                  <button type="button" class="chip {picked ? 'active' : ''}" onclick={() => (monIfacesCsv = toggleCsvIface(monIfacesCsv, ifn))}>
                    {ifn}
                  </button>
                {/each}
              </div>
            {/if}
          </div>
          <div class="field">
            <label for="st-msi">{t.cfg.monInterval}</label>
            <input id="st-msi" type="number" min="1" max="60" bind:value={generalDraft.monitor.sample_interval_secs} required />
          </div>
          <div class="field">
            <label for="st-tmp">{t.cfg.lblTempAlert} (40~125)</label>
            <input id="st-tmp" type="number" min="40" max="125" bind:value={generalDraft.monitor.temp_alert_celsius} required />
          </div>
          <div class="field">
            <label for="st-mem">{t.cfg.lblMemLow} (0 = off)</label>
            <input id="st-mem" type="number" min="0" max="4096" bind:value={generalDraft.monitor.mem_low_mb} required />
          </div>
          <div class="field">
            <label for="st-macd">{t.cfg.alertCooldown}</label>
            <input id="st-macd" type="number" min="60" max="86400" bind:value={generalDraft.monitor.alert_cooldown_secs} required />
          </div>
          <div class="field">
            <label for="st-thm">{t.cfg.thermalPath}</label>
            <input id="st-thm" type="text" class="mono" placeholder="/sys/class/thermal/thermal_zone0/temp" bind:value={generalDraft.monitor.thermal_path} />
          </div>
          <div class="field">
            <label for="st-topp">{t.cfg.topProcs}</label>
            <input id="st-topp" type="number" min="1" max="50" bind:value={generalDraft.monitor.top_processes} required />
          </div>
          <div class="field">
            <label for="st-psh">{t.cfg.ptyShell}</label>
            <input id="st-psh" type="text" class="mono" bind:value={generalDraft.web_terminal.shell} />
          </div>
          <div class="field">
            <label for="st-pcwd">{t.cfg.ptyCwd}</label>
            <input id="st-pcwd" type="text" class="mono" bind:value={generalDraft.web_terminal.default_cwd} />
          </div>
          <div class="field">
            <label for="st-pidle">{t.cfg.ptyIdle} (60~3600)</label>
            <input id="st-pidle" type="number" min="60" max="3600" bind:value={generalDraft.web_terminal.idle_timeout_secs} required />
          </div>
          <div class="field">
            <label for="st-pmax">{t.cfg.ptyMaxSess}</label>
            <input id="st-pmax" type="number" min="1" max="4" bind:value={generalDraft.web_terminal.max_sessions} required />
          </div>
          <div class="field">
            <label for="st-dkp">{t.cfg.lblProtectedContainers}</label>
            <input id="st-dkp" type="text" class="mono" bind:value={protectedContainersCsv} />
          </div>
          <div class="field">
            <label for="st-dktail">{t.cfg.dkTail}</label>
            <input id="st-dktail" type="number" min="10" max="2000" bind:value={generalDraft.docker.log_tail_default} required />
          </div>
        </div>
        <div style="display:flex;gap:18px;flex-wrap:wrap;">
          <label class="check-row"><input type="checkbox" bind:checked={generalDraft.web_terminal.require_reauth} /> {t.cfg.lblPtyReauth}</label>
          <label class="check-row"><input type="checkbox" bind:checked={generalDraft.docker.log_timestamps} /> {t.cfg.dkTs}</label>
        </div>
      </form>
    {/if}
  {/if}

  <!-- 2. 认证安全中心：改密 + TOTP + Ed25519 + 本地根证书导出 -->
  {#if subTab === 'security'}
    <div class="bento-grid-2">
      <!-- 修改管理员密码 + 导出本地 TLS 证书 -->
      <div class="card">
        <div class="card-header">
          <span class="card-title">{t.cfg.pwTitle}</span>
          <button type="button" class="btn btn-xs" disabled={secBusy === 'cert'} onclick={downloadAdminCert}>
            <Icons name="download" size={13} />
            <span>{secBusy === 'cert' ? '...' : t.cfg.downloadCert}</span>
          </button>
        </div>
        <form onsubmit={updateAdminCredentials}>
          <div class="field">
            <label for="sec-un">{t.cfg.newUsername}</label>
            <input id="sec-un" type="text" placeholder={settingsJson.admin.username} bind:value={newUsername} autocomplete="username" />
          </div>
          <div class="field">
            <label for="sec-cp">{t.curPw}</label>
            <input id="sec-cp" type="password" bind:value={curPw} autocomplete="current-password" required />
          </div>
          <div class="field">
            <label for="sec-np">{t.newPw}</label>
            <input id="sec-np" type="password" bind:value={newPw} autocomplete="new-password" required />
          </div>
          <div class="field">
            <label for="sec-cnp">{t.confirmPw}</label>
            <input id="sec-cnp" type="password" bind:value={confirmPw} autocomplete="new-password" required />
          </div>

          <div class="subcard" style="margin-bottom:14px;font-size:12.5px;display:grid;gap:5px;">
            <div style="color:{pwChecks.lenOk ? 'var(--accent)' : 'var(--text-secondary)'}">{pwChecks.lenOk ? '✓' : '○'} {t.ruleLen}</div>
            <div style="color:{pwChecks.hasAlpha ? 'var(--accent)' : 'var(--text-secondary)'}">{pwChecks.hasAlpha ? '✓' : '○'} {t.ruleAlpha}</div>
            <div style="color:{pwChecks.hasDigitOrPunct ? 'var(--accent)' : 'var(--text-secondary)'}">{pwChecks.hasDigitOrPunct ? '✓' : '○'} {t.ruleDigit}</div>
            <div style="color:{pwChecks.notDefault ? 'var(--accent)' : 'var(--text-secondary)'}">{pwChecks.notDefault ? '✓' : '○'} {t.ruleNotDefault}</div>
            <div style="color:{pwChecks.matchConfirm ? 'var(--accent)' : 'var(--text-secondary)'}">{pwChecks.matchConfirm ? '✓' : '○'} {t.ruleMatch}</div>
          </div>

          <button type="submit" class="btn btn-primary btn-sm" disabled={!pwAllValid || Boolean(secBusy)}>
            {secBusy === 'pw' ? '...' : t.cfg.updatePw}
          </button>
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
            <button
              type="button"
              class="btn btn-sm"
              disabled={Boolean(secBusy)}
              onclick={() =>
                askConfirm({
                  title: t.cfg.totpRegen,
                  message: t.cfg.totpRegenConfirm,
                  confirmLabel: t.confirmAction,
                  danger: true,
                  onConfirm: regenerateRecoveryCodes,
                })
              }
            >
              {secBusy === 'totp-regen' ? '...' : t.cfg.totpRegen}
            </button>
            <button
              type="button"
              class="btn btn-sm btn-danger"
              disabled={Boolean(secBusy)}
              onclick={() =>
                askConfirm({
                  title: t.cfg.totpDisable,
                  message: t.cfg.totpDisableConfirm,
                  confirmLabel: t.cfg.totpDisable,
                  danger: true,
                  onConfirm: disableTotp,
                })
              }
            >
              {secBusy === 'totp-disable' ? '...' : t.cfg.totpDisable}
            </button>
          </div>
        {:else if !totpSetupData}
          <p style="font-size:13px;color:var(--text-secondary);margin-bottom:12px;">{t.cfg.totpDescOff}</p>
          <button type="button" class="btn btn-primary btn-sm" disabled={Boolean(secBusy)} onclick={startTotpSetup}>
            {secBusy === 'totp-setup' ? '...' : t.cfg.totpSetup}
          </button>
        {:else}
          {@const qrSrc = safeQrDataUri(totpSetupData.otpauth_uri)}
          <form onsubmit={confirmTotpEnable}>
            <div style="font-size:13px;color:var(--text-secondary);margin-bottom:6px;">{t.cfg.totpScanHint}</div>
            <div style="font-size:11.5px;color:var(--warn);margin-bottom:10px;">{t.cfg.totpSetupTtlHint}</div>
            <div style="display:flex;gap:14px;align-items:flex-start;flex-wrap:wrap;margin-bottom:12px;">
              {#if qrSrc}
                <img
                  src={qrSrc}
                  alt="TOTP QR"
                  style="width:176px;height:176px;border-radius:12px;border:1px solid var(--border-subtle);background:#ffffff;padding:6px;display:block;flex-shrink:0;"
                />
              {:else}
                <div class="banner banner-warn" style="margin:0;">{t.cfg.qrTooLong}</div>
              {/if}
              <div class="subcard mono" style="flex:1;min-width:210px;font-size:12px;word-break:break-all;display:grid;gap:8px;">
                <div class="row-between">
                  <div><strong>Secret:</strong> {totpSetupData.secret_base32}</div>
                  <button type="button" class="btn btn-xs" onclick={() => handleCopy(totpSetupData.secret_base32)}>
                    <Icons name="copy" size={12} />
                    <span>{t.copy}</span>
                  </button>
                </div>
                <div class="row-between">
                  <div style="color:var(--text-secondary);font-size:11px;word-break:break-all;">{totpSetupData.otpauth_uri}</div>
                  <button type="button" class="btn btn-xs" onclick={() => handleCopy(totpSetupData.otpauth_uri)}>
                    <Icons name="copy" size={12} />
                    <span>URI</span>
                  </button>
                </div>
              </div>
            </div>
            <div class="field">
              <label for="totp-vcode">{t.cfg.totpCodeInput}</label>
              <input
                id="totp-vcode"
                type="text"
                class="mono"
                inputmode="numeric"
                maxlength="6"
                pattern="[0-9]{6}"
                autocomplete="one-time-code"
                placeholder="123456"
                bind:value={totpVerifyCode}
                required
              />
            </div>
            <div class="btn-group">
              <button type="submit" class="btn btn-primary btn-sm" disabled={Boolean(secBusy)}>
                {secBusy === 'totp-enable' ? '...' : t.cfg.totpEnable}
              </button>
              <button type="button" class="btn btn-sm" onclick={() => (totpSetupData = null)}>{t.cancel}</button>
            </div>
          </form>
        {/if}

        {#if issuedRecoveryCodes.length > 0}
          <div class="subcard" style="margin-top:14px;border-color:var(--warn);">
            <div class="row-between" style="margin-bottom:8px;gap:8px;flex-wrap:wrap;">
              <span style="font-size:12px;font-weight:700;color:var(--warn);">{t.cfg.recoveryTitle}</span>
              <div class="btn-group">
                <button type="button" class="btn btn-xs" onclick={() => handleCopy(issuedRecoveryCodes.join('\n'))}>
                  <Icons name="copy" size={12} />
                  <span>{t.copy}</span>
                </button>
                <button
                  type="button"
                  class="btn btn-xs"
                  onclick={() => downloadTextFile('vane-totp-recovery-codes.txt', `${issuedRecoveryCodes.join('\n')}\n`)}
                >
                  <Icons name="download" size={12} />
                  <span>.txt</span>
                </button>
                <button type="button" class="btn btn-xs" onclick={() => (issuedRecoveryCodes = [])}>
                  {t.cfg.hideRecoveryCodes}
                </button>
              </div>
            </div>
            <div class="mono" style="display:grid;grid-template-columns:1fr 1fr;gap:6px;font-size:13px;">
              {#each issuedRecoveryCodes as rc (rc)}
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
          <div style="display:flex;align-items:center;gap:10px;">
            <span style="font-size:13px;color:var(--text-secondary);">{t.cfg.allowPwLogin}</span>
            <button
              type="button"
              class="switch"
              role="switch"
              aria-checked={Boolean(settingsJson.admin.password_login_enabled)}
              aria-label={t.cfg.allowPwLogin}
              disabled={Boolean(secBusy)}
              onclick={requestTogglePasswordLogin}
            >
              <span class="switch-thumb"></span>
            </button>
          </div>
        {/if}
      </div>

      {#if settingsJson.admin.authorized_ed25519_keys?.length}
        <div style="display:grid;gap:8px;margin-bottom:14px;">
          {#each settingsJson.admin.authorized_ed25519_keys as k (k.id)}
            <div class="subcard row-between">
              <div style="min-width:0;flex:1;">
                <div style="font-weight:700;" class="mono">{k.id}</div>
                <div class="mono" style="font-size:11px;color:var(--text-secondary);word-break:break-all;">{k.pubkey}</div>
              </div>
              <button
                type="button"
                class="btn btn-xs btn-danger"
                disabled={Boolean(secBusy)}
                onclick={() =>
                  askConfirm({
                    title: t.common.confirmDeleteTitle,
                    message: k.id,
                    confirmLabel: t.delete,
                    danger: true,
                    onConfirm: () => deleteEd25519Key(k.id),
                  })
                }
              >
                {secBusy === `ed-del:${k.id}` ? '...' : t.delete}
              </button>
            </div>
          {/each}
        </div>
      {/if}

      <form onsubmit={addEd25519Key} class="ed-key-grid">
        <div class="field" style="margin-bottom:0;">
          <label for="ed-id">{t.cfg.lblKeyId}</label>
          <input id="ed-id" type="text" class="mono" placeholder="macbook" bind:value={newKeyId} required />
        </div>
        <div class="field" style="margin-bottom:0;">
          <label for="ed-pub">{t.cfg.lblKeyPub} (ssh-ed25519 AAAAC3...)</label>
          <input id="ed-pub" type="text" class="mono" placeholder="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5..." bind:value={newKeyPub} required />
        </div>
        <button type="submit" class="btn btn-primary" disabled={Boolean(secBusy)}>
          {secBusy === 'ed-add' ? '...' : t.cfg.addKey}
        </button>
      </form>
    </div>
  {/if}

  <!-- 3. 通知渠道中心 -->
  {#if subTab === 'notifications'}
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title">{t.cfg.notifTitle}</div>
          <div style="font-size:12px;color:var(--text-secondary);">{t.cfg.notifSub}</div>
        </div>
        <button type="button" class="btn btn-primary btn-sm" onclick={() => openNotifDrawer(-1)}>
          <Icons name="plus" size={14} />
          <span>{t.add}</span>
        </button>
      </div>

      {#if !settingsJson.notifications?.length}
        <div class="empty-state">{t.common.empty}</div>
      {:else}
        <div style="display:grid;gap:10px;">
          {#each settingsJson.notifications as n, idx (n.name)}
            <div class="subcard row-between">
              <div style="min-width:0;flex:1;">
                <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                  <span class="status-dot {n.enabled ? 'ok' : 'muted'}"></span>
                  <span style="font-weight:700;">{n.name}</span>
                  <span class="badge badge-info">{n.provider}</span>
                  <span class="badge badge-muted">&gt;= {n.min_severity}</span>
                  {#if !n.enabled}<span class="badge badge-warn">{t.disabled}</span>{/if}
                </div>
                <div style="font-size:12px;color:var(--text-secondary);margin-top:4px;">
                  {n.events?.length ? n.events.map((ev) => t.events?.[ev] || ev).join(' · ') : t.cfg.allEvents}
                </div>
              </div>
              <div class="btn-group">
                <button
                  type="button"
                  class="switch"
                  role="switch"
                  aria-checked={Boolean(n.enabled)}
                  aria-label={n.name}
                  disabled={busyNotif === `toggle:${n.name}`}
                  onclick={() => toggleNotificationEnabled(idx)}
                >
                  <span class="switch-thumb"></span>
                </button>
                <button type="button" class="btn btn-xs btn-primary" disabled={Boolean(busyNotif)} onclick={() => testNotification(n.name)}>
                  {busyNotif === n.name ? '...' : t.cfg.testPush}
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
    <div class="banner banner-info" style="margin-bottom:16px;">
      <div style="display:flex;align-items:flex-start;gap:10px;">
        <Icons name="shield" size={17} />
        <div>
          <div style="font-weight:700;">{t.cfg.bkScopeTitle}</div>
          <div style="font-size:12.5px;color:var(--text-secondary);margin-top:2px;">{t.cfg.bkScopeItems}</div>
        </div>
      </div>
    </div>

    <div class="bento-grid-2">
      <form class="card" onsubmit={exportEncryptedBackup}>
        <div class="card-header">
          <span class="card-title">{t.cfg.bkExportTitle}</span>
        </div>
        <p style="font-size:13px;color:var(--text-secondary);margin-bottom:14px;">{t.cfg.bkExportDesc}</p>
        <div class="field">
          <div class="row-between" style="gap:8px;">
            <label for="bk-pw" style="margin:0;">{t.cfg.bkExportPw}</label>
            <button type="button" class="btn btn-ghost btn-xs" style="min-height:22px;padding:0 6px;" onclick={() => (showBkPass = !showBkPass)}>
              <Icons name={showBkPass ? 'eye_off' : 'eye'} size={13} />
            </button>
          </div>
          <input id="bk-pw" type={showBkPass ? 'text' : 'password'} minlength="8" autocomplete="new-password" bind:value={backupPass} required />
        </div>
        <div class="field">
          <label for="bk-pw2">{t.cfg.bkExportPwConfirm}</label>
          <input id="bk-pw2" type={showBkPass ? 'text' : 'password'} minlength="8" autocomplete="new-password" bind:value={backupPassConfirm} required />
          {#if backupPassConfirm && backupPass !== backupPassConfirm}
            <div style="font-size:12px;color:var(--danger);margin-top:4px;">{t.cfg.bkPwMismatch}</div>
          {/if}
        </div>
        <button
          type="submit"
          class="btn btn-primary btn-sm"
          disabled={Boolean(backupBusy) || !backupPass || backupPass !== backupPassConfirm}
        >
          <Icons name="download" size={14} />
          <span>{backupBusy === 'export' ? '...' : t.cfg.bkExportBtn}</span>
        </button>
      </form>

      <form class="card" onsubmit={importEncryptedBackup}>
        <div class="card-header">
          <span class="card-title">{t.cfg.bkImportTitle}</span>
        </div>
        <div class="field">
          <label for="bk-file">{t.cfg.bkImportFile}</label>
          <input
            bind:this={restoreFileInput}
            id="bk-file"
            type="file"
            accept=".bak,.vane.bak,application/octet-stream"
            onchange={handleBackupFileSelect}
            required
          />
        </div>
        <div class="field">
          <label for="bk-rpw">{t.cfg.bkImportPw}</label>
          <input id="bk-rpw" type="password" minlength="8" autocomplete="off" bind:value={restorePass} required />
        </div>
        <button type="submit" class="btn btn-danger btn-sm" disabled={!restoreBlobB64 || Boolean(backupBusy)}>
          <Icons name="upload" size={14} />
          <span>{backupBusy === 'import' ? '...' : t.cfg.bkImportBtn}</span>
        </button>
      </form>
    </div>

    <div class="card">
      <div class="card-header">
        <span class="card-title">{t.cfg.sanitizedTitle}</span>
        <div class="btn-group">
          {#if sanitizedPreview}
            <button type="button" class="btn btn-sm" onclick={() => handleCopy(sanitizedPreview)}>
              <Icons name="copy" size={13} />
              <span>{t.copy}</span>
            </button>
            <button
              type="button"
              class="btn btn-sm"
              onclick={() => downloadTextFile('vane-sanitized-config.toml', sanitizedPreview)}
            >
              <Icons name="download" size={13} />
              <span>{t.download}</span>
            </button>
          {/if}
          <button type="button" class="btn btn-sm btn-primary" disabled={Boolean(backupBusy)} onclick={loadSanitizedToml}>
            {backupBusy === 'sanitized' ? '...' : t.cfg.sanitizedBtn}
          </button>
        </div>
      </div>
      {#if sanitizedPreview}
        <pre class="mono" style="background:var(--bg-elevated);padding:14px;border-radius:12px;max-height:320px;overflow:auto;font-size:12px;border:1px solid var(--border-subtle);">{sanitizedPreview}</pre>
      {/if}
    </div>
  {/if}
{/if}

<!-- 通知渠道抽屉 -->
{#if notifDrawerOpen && notifDraft}
  <div class="drawer-backdrop" role="presentation" onclick={(e) => { if (e.target === e.currentTarget && !saving) notifDrawerOpen = false; }}>
    <div class="drawer-panel" role="dialog" aria-modal="true" aria-label={t.cfg.tabNotifications}>
    <form style="display:contents;" onsubmit={saveNotification}>
      <div class="drawer-header">
        <div class="card-title">{notifEditIdx >= 0 ? t.edit : t.add} · {t.cfg.tabNotifications}</div>
        <button type="button" class="btn btn-sm" disabled={saving} onclick={() => (notifDrawerOpen = false)}>{t.cancel}</button>
      </div>
      <div class="drawer-body">
        <div class="form-grid">
          <div class="field">
            <label for="nf-name">{t.cfg.lblNotifName}</label>
            <input id="nf-name" type="text" class="mono" bind:value={notifDraft.name} required />
          </div>
          <div class="field">
            <label for="nf-prov">{t.cfg.lblNotifProvider}</label>
            <select id="nf-prov" bind:value={notifDraft.provider} onchange={onNotifProviderChange}>
              {#each NOTIF_PROVIDERS as p (p)}
                <option value={p}>{p}</option>
              {/each}
            </select>
          </div>
          <div class="field">
            <label for="nf-sev">{t.cfg.lblMinSeverity}</label>
            <select id="nf-sev" bind:value={notifDraft.min_severity}>
              <option value="debug">debug</option>
              <option value="info">info</option>
              <option value="warn">warn</option>
              <option value="warning">warning</option>
              <option value="error">error</option>
              <option value="critical">critical</option>
            </select>
          </div>
        </div>

        <!-- 按服务商动态显示凭据字段 -->
        {#if notifDraft.provider === 'telegram'}
          <div class="form-grid">
            <SecretField
              id="nf-tok"
              label="Telegram Bot Token"
              original={notifDraft.token}
              bind:value={notifTokenInput}
              bind:clear={notifTokenClear}
              placeholder="123456:ABC-DEF..."
              required={true}
              {t}
            />
            <div class="field">
              <label for="nf-chat">Telegram Chat ID</label>
              <input id="nf-chat" type="text" class="mono" placeholder="-1001234567890" bind:value={notifDraft.chat_id} required />
            </div>
          </div>
          <SecretField
            id="nf-url"
            label="Custom Bot API Proxy URL (optional)"
            original={notifDraft.url}
            bind:value={notifUrlInput}
            bind:clear={notifUrlClear}
            placeholder="https://api.telegram.org"
            {t}
          />
        {:else if notifDraft.provider === 'bark'}
          <div class="form-grid">
            <SecretField
              id="nf-url"
              label="Bark Server URL"
              original={notifDraft.url}
              bind:value={notifUrlInput}
              bind:clear={notifUrlClear}
              placeholder="https://api.day.app"
              required={true}
              {t}
            />
            <SecretField
              id="nf-tok"
              label="Bark Device Key"
              original={notifDraft.token}
              bind:value={notifTokenInput}
              bind:clear={notifTokenClear}
              placeholder="Device Key"
              required={true}
              {t}
            />
          </div>
        {:else if notifDraft.provider === 'gotify'}
          <div class="form-grid">
            <SecretField
              id="nf-url"
              label="Gotify Server URL"
              original={notifDraft.url}
              bind:value={notifUrlInput}
              bind:clear={notifUrlClear}
              placeholder="https://gotify.example.com"
              required={true}
              {t}
            />
            <SecretField
              id="nf-tok"
              label="Gotify App Token"
              original={notifDraft.token}
              bind:value={notifTokenInput}
              bind:clear={notifTokenClear}
              placeholder="App Token"
              required={true}
              {t}
            />
          </div>
        {:else if notifDraft.provider === 'ntfy'}
          <div class="form-grid">
            <SecretField
              id="nf-url"
              label="Ntfy Topic URL"
              original={notifDraft.url}
              bind:value={notifUrlInput}
              bind:clear={notifUrlClear}
              placeholder="https://ntfy.sh/my-vane-alerts"
              required={true}
              {t}
            />
            <SecretField
              id="nf-tok"
              label="Bearer Token (optional)"
              original={notifDraft.token}
              bind:value={notifTokenInput}
              bind:clear={notifTokenClear}
              placeholder="tk_..."
              {t}
            />
          </div>
        {:else if notifDraft.provider === 'wecom'}
          <SecretField
            id="nf-url"
            label="WeCom Bot Webhook URL"
            original={notifDraft.url}
            bind:value={notifUrlInput}
            bind:clear={notifUrlClear}
            placeholder="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=..."
            required={true}
            {t}
          />
        {:else if notifDraft.provider === 'feishu' || notifDraft.provider === 'dingtalk'}
          <SecretField
            id="nf-url"
            label="{notifDraft.provider === 'feishu' ? 'Feishu' : 'DingTalk'} Webhook URL"
            original={notifDraft.url}
            bind:value={notifUrlInput}
            bind:clear={notifUrlClear}
            placeholder="https://..."
            required={true}
            {t}
          />
          <SecretField
            id="nf-sec"
            label="HMAC Signing Secret (optional)"
            original={notifDraft.secret}
            bind:value={notifSecretInput}
            bind:clear={notifSecretClear}
            placeholder="SEC..."
            {t}
          />
        {:else}
          <SecretField
            id="nf-url"
            label="Webhook Endpoint URL"
            original={notifDraft.url}
            bind:value={notifUrlInput}
            bind:clear={notifUrlClear}
            placeholder="https://..."
            required={true}
            {t}
          />
          <SecretField
            id="nf-tok"
            label="Bearer / Auth Token (optional)"
            original={notifDraft.token}
            bind:value={notifTokenInput}
            bind:clear={notifTokenClear}
            placeholder="Optional"
            {t}
          />
        {/if}

        <div class="field">
          <span style="font-size:12.5px;font-weight:600;color:var(--text-secondary);">{t.cfg.eventsLabel}</span>
          <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:4px;">
            {#each ALL_EVENTS as ev (ev)}
              {@const active = (notifDraft.events || []).includes(ev)}
              <button
                type="button"
                class="chip {active ? 'active' : ''}"
                aria-pressed={active}
                onclick={() => toggleNotifEvent(ev)}
              >
                {#if active}<Icons name="check" size={12} />{/if}
                <span>{t.events?.[ev] || ev}</span>
              </button>
            {/each}
          </div>
        </div>

        <label class="check-row"><input type="checkbox" bind:checked={notifDraft.enabled} /> {t.cfg.lblEnableChannel}</label>

        <details style="margin-top:12px;">
          <summary style="cursor:pointer;font-size:13px;font-weight:600;color:var(--text-secondary);padding:6px 0;">
            {t.common.advanced}
          </summary>
          <div style="padding-top:10px;">
            <div class="field">
              <label for="nf-meth">{t.cfg.notifMethod}</label>
              <select id="nf-meth" bind:value={notifDraft.method}>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="PATCH">PATCH</option>
                <option value="GET">GET</option>
              </select>
            </div>
            <HeaderRowsEditor label={t.cfg.notifHeaders} bind:rows={notifHeaderRows} secret={true} {t} />
            <SecretField
              id="nf-tpl"
              label={t.cfg.notifBodyTpl}
              original={notifDraft.body_template}
              bind:value={notifBodyTplInput}
              bind:clear={notifBodyTplClear}
              placeholder={'{"event":"{{event}}","text":"{{title}}: {{message}}"}'}
              {t}
            />
          </div>
        </details>
      </div>
      <div class="drawer-footer">
        <button type="button" class="btn" disabled={saving} onclick={() => (notifDrawerOpen = false)}>{t.cancel}</button>
        <button type="submit" class="btn btn-primary" disabled={saving}>{saving ? '...' : t.confirm}</button>
      </div>
    </form>
    </div>
  </div>
{/if}
