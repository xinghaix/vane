<script>
  import Icons from './Icons.svelte';
  import SecretField from './SecretField.svelte';
  import HeaderRowsEditor from './HeaderRowsEditor.svelte';
  import EditorDialog from './EditorDialog.svelte';
  import Select from './Select.svelte';
  import ComboInput from './ComboInput.svelte';
  import SystemUpdatePanel from './SystemUpdatePanel.svelte';
  import { renderQrSvgDataUri } from '../lib/qrcode.js';
  import { createPasskeyCredential, detectPasskeyDefaultName, isIpHostname, isPasskeySupported } from '../lib/webauthn.js';
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
    formatUnixTime,
    resolveSecretInput,
  } from '../lib/helpers.js';

  let {
    t,
    lang,
    onSelectLang,
    themeMode = 'auto',
    onSelectThemeMode,
    oledMode = false,
    onToggleOledMode,
    accentColor = 'emerald',
    onSelectAccentColor,
    accentPresets = [],
    sidebarCollapsed = false,
    onToggleSidebar,
    pwaState = { standalone: false, canPrompt: false, iosSafari: false, secureContext: false },
    onInstallPwa = null,
    modules,
    moduleReauth = {},
    isModuleLocked = () => false,
    onNavigate = null,
    settingsJson,
    networkInfo = null,
    subTab = 'general',
    onSubTabChange,
    onToggleModule,
    onToggleModuleReauth,
    onSaveSettings,
    onAuthRefresh,
    onBackupRestored,
    askConfirm,
    requestReauth,
    apiFetch,
    showToast,
    onRefresh,
  } = $props();

  let saving = $state(false);
  let secBusy = $state('');
  let backupBusy = $state('');
  let ifaceOptions = $derived(
    (networkInfo?.interfaces || []).map((i) => {
      const ips = [...(i.ipv4 || []), ...(i.ipv6 || [])];
      return { value: i.iface, label: i.iface, sub: ips.slice(0, 2).join(', ') };
    })
  );

  async function handleCopy(text) {
    if (await copyText(text)) showToast(t.copied, 'success');
    else showToast(t.copyFailed, 'error');
  }

  // ---------------- 1. 全局核心与共用基础设置草稿（独立草稿状态，不触碰各子模块内嵌配置） ----------------
  let generalDraft = $state(null);
  let wanIfacesCsv = $state('');
  let lanIfacesCsv = $state('');
  let listenLanCsv = $state('');
  let extraOriginsCsv = $state('');
  let syncedGeneralSig = $state('');

  function pickGeneralState(src, csvOverrides = null) {
    if (!src) return null;
    const sys = src.system || {};
    const adm = src.admin || {};
    const fw = src.firewall || {};
    const sec = src.security || {};
    return {
      system: {
        timezone_offset: String(sys.timezone_offset ?? 'UTC'),
        worker_threads: Number(sys.worker_threads ?? 2),
        global_max_conns: Number(sys.global_max_conns ?? 512),
      },
      admin: {
        session_ttl_secs: Number(adm.session_ttl_secs ?? 3600),
        secret_path: String(adm.secret_path ?? '/'),
        canonical_origin: String(adm.canonical_origin ?? ''),
        listen_lan: csvOverrides ? splitCsv(csvOverrides.listenLanCsv) : (adm.listen_lan || []),
        extra_allowed_origins: csvOverrides ? splitCsv(csvOverrides.extraOriginsCsv) : (adm.extra_allowed_origins || []),
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
    };
  }

  function syncGeneralDraft(src) {
    if (!src) return;
    const snap = pickGeneralState(src);
    syncedGeneralSig = JSON.stringify(snap);
    generalDraft = deepClone(snap);
    wanIfacesCsv = joinCsv(src.firewall?.wan_interfaces);
    lanIfacesCsv = joinCsv(src.firewall?.lan_interfaces);
    listenLanCsv = joinCsv(src.admin?.listen_lan);
    extraOriginsCsv = joinCsv(src.admin?.extra_allowed_origins);
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

  let sharedDnsVisible = $derived(Boolean(modules?.ddns || modules?.acme));
  let dnsProviderNames = $derived(Object.keys(settingsJson?.dns_providers || {}));
  let fwDeps = $derived([
    { label: t.nav.reverse_proxy, active: Boolean(modules?.reverse_proxy) },
    { label: t.nav.port_forward, active: Boolean(modules?.port_forward) },
    { label: t.nav.ddns, active: Boolean(modules?.ddns) },
    { label: 'Fail2Ban', active: Boolean(generalDraft?.security?.kernel_ban_offload) },
  ]);
  let anyFwDepActive = $derived(fwDeps.some((d) => d.active));

  let draftPicked = $derived(
    generalDraft
      ? pickGeneralState(generalDraft, {
          listenLanCsv,
          extraOriginsCsv,
          wanIfacesCsv,
          lanIfacesCsv,
        })
      : null
  );
  let basePicked = $derived(settingsJson ? pickGeneralState(settingsJson) : null);
  let generalDirty = $derived(
    Boolean(draftPicked && basePicked && JSON.stringify(draftPicked) !== JSON.stringify(basePicked))
  );

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
    });
    picked.system.timezone_offset = picked.system.timezone_offset.trim() || 'UTC';
    const rawSp = picked.admin.secret_path.trim();
    picked.admin.secret_path = !rawSp ? '/' : rawSp.startsWith('/') ? rawSp : `/${rawSp}`;
    picked.admin.canonical_origin = picked.admin.canonical_origin.trim();
    picked.admin.tls_cert_path = picked.admin.tls_cert_path.trim();
    picked.admin.tls_key_path = picked.admin.tls_key_path.trim();

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
      await onSaveSettings(next);
    } finally {
      saving = false;
    }
  }

  // ---------------- 2. 安全中心：修改密码 / TOTP / 通行密钥 ----------------
  let curPw = $state('');
  let newPw = $state('');
  let confirmPw = $state('');
  let newUsername = $state('');
  let totpSetupData = $state(null);
  let totpVerifyCode = $state('');
  let issuedRecoveryCodes = $state([]);
  let newPasskeyName = $state('');
  const passkeyBrowserOk = isPasskeySupported();
  const passkeyOnRawIp = isIpHostname();

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

  function maskTotpSecret(secret) {
    const s = String(secret || '');
    if (s.length <= 8) return '••••••••';
    return `${s.slice(0, 4)}••••••••${s.slice(-4)}`;
  }

  function maskOtpAuthUri(uri) {
    const s = String(uri || '');
    const q = s.indexOf('?');
    return q > 0 ? `${s.slice(0, q)}?secret=••••••••` : 'otpauth://totp/••••';
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
    const tok = await requestReauth({
      title: t.reauth.totpSetupTitle,
      description: t.reauth.totpSetupDesc,
      actionLabel: t.cfg.totpSetup,
      requireMfa: true,
    });
    if (!tok) return;
    secBusy = 'totp-setup';
    try {
      totpSetupData = await apiFetch('/api/auth/totp/setup', {
        method: 'POST',
        headers: { 'x-vane-reauth-token': tok },
        body: JSON.stringify({ reauth_token: tok }),
      });
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
    const tok = await requestReauth({
      title: t.reauth.totpEnableTitle,
      description: t.reauth.totpEnableDesc,
      actionLabel: t.cfg.totpEnable,
      requireMfa: true,
    });
    if (!tok) return;
    secBusy = 'totp-enable';
    try {
      const r = await apiFetch('/api/auth/totp/enable', {
        method: 'POST',
        headers: { 'x-vane-reauth-token': tok },
        body: JSON.stringify({ code: totpVerifyCode.trim(), reauth_token: tok }),
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
    const tok = await requestReauth({
      title: t.reauth.totpRegenTitle,
      description: t.reauth.totpRegenDesc,
      actionLabel: t.cfg.totpRegen,
      requireMfa: true,
    });
    if (!tok) return;
    secBusy = 'totp-regen';
    try {
      const r = await apiFetch('/api/auth/totp/recovery-codes', {
        method: 'POST',
        headers: { 'x-vane-reauth-token': tok },
        body: JSON.stringify({ reauth_token: tok }),
      });
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

  function confirmThenRun(opts, action) {
    askConfirm({
      ...opts,
      onConfirm: () => {
        queueMicrotask(() => {
          action();
        });
      },
    });
  }

  async function disableTotpWithReauth() {
    if (secBusy) return;
    const tok = await requestReauth({
      title: t.reauth.disableTotpTitle,
      description: t.reauth.disableTotpDesc,
      actionLabel: t.cfg.totpDisable,
      requireMfa: true,
    });
    if (!tok) return;
    secBusy = 'totp-disable';
    try {
      await apiFetch('/api/auth/totp/disable', {
        method: 'POST',
        headers: { 'x-vane-reauth-token': tok },
        body: JSON.stringify({ reauth_token: tok }),
      });
      issuedRecoveryCodes = [];
      totpSetupData = null;
      totpVerifyCode = '';
      showToast(lang === 'en' ? 'TOTP disabled and credentials cleared' : '已关闭 TOTP 二步验证并彻底清空旧密钥与恢复码', 'success');
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
      const tok = await requestReauth({
        title: currentlyEnabled ? t.reauth.disablePasswordLoginTitle : t.reauth.enablePasswordLoginTitle,
        description: currentlyEnabled ? t.reauth.disablePasswordLoginDesc : t.reauth.enablePasswordLoginDesc,
        actionLabel: t.reauth.verifyBtn,
        requireMfa: true,
      });
      if (!tok) return;
      secBusy = 'pw-toggle';
      try {
        const next = deepClone(settingsJson);
        next.admin.password_login_enabled = !currentlyEnabled;
        if (await onSaveSettings(next, [], { 'x-vane-reauth-token': tok })) {
          await onAuthRefresh?.();
        }
      } finally {
        secBusy = '';
      }
    };
    if (currentlyEnabled) {
      confirmThenRun(
        {
          title: t.cfg.disablePwConfirmTitle,
          message: t.cfg.disablePwConfirmDesc,
          confirmLabel: t.confirmAction,
          danger: true,
        },
        exec
      );
    } else {
      exec();
    }
  }

  async function registerPasskey(e) {
    e?.preventDefault?.();
    if (secBusy || !passkeyBrowserOk || passkeyOnRawIp) return;
    const label = newPasskeyName.trim() || detectPasskeyDefaultName();
    const tok = await requestReauth({
      title: t.reauth.passkeyRegisterTitle,
      description: t.reauth.passkeyRegisterDesc,
      actionLabel: t.reauth.verifyBtn,
      requireMfa: true,
    });
    if (!tok) return;
    secBusy = 'pk-add';
    try {
      const opts = await apiFetch('/api/auth/passkey/register/options', {
        method: 'POST',
        headers: { 'x-vane-reauth-token': tok },
        body: JSON.stringify({ reauth_token: tok }),
      });
      const att = await createPasskeyCredential(opts, lang);
      await apiFetch('/api/auth/passkey/register/verify', {
        method: 'POST',
        body: JSON.stringify({ name: label, ...att }),
      });
      newPasskeyName = '';
      showToast(
        lang === 'en' ? `Passkey "${label}" registered & enabled` : `通行密钥「${label}」已成功绑定并自动开启`,
        'success'
      );
      await onAuthRefresh?.();
      await onRefresh();
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      secBusy = '';
    }
  }

  async function disableAllPasskeysWithReauth() {
    if (secBusy || !settingsJson) return;
    if (!settingsJson.admin.password_login_enabled) {
      showToast(t.cfg.passkeyLastAuthHint, 'warn');
      return;
    }
    const tok = await requestReauth({
      title: t.reauth.disablePasskeyTitle,
      description: t.reauth.disablePasskeyDesc,
      actionLabel: t.cfg.passkeyDisableAllBtn,
      requireMfa: true,
    });
    if (!tok) return;
    secBusy = 'pk-toggle';
    try {
      await apiFetch('/api/auth/passkey/toggle', {
        method: 'POST',
        headers: { 'x-vane-reauth-token': tok },
        body: JSON.stringify({ enabled: false, reauth_token: tok }),
      });
      showToast(
        lang === 'en' ? 'Passkeys disabled and all saved keys cleared' : '已关闭通行密钥并彻底清空全部已保存密钥',
        'success'
      );
      await onAuthRefresh?.();
      await onRefresh();
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      secBusy = '';
    }
  }

  async function deletePasskeyWithReauth(id, name) {
    if (secBusy || !settingsJson) return;
    if (!settingsJson.admin.password_login_enabled && (settingsJson.admin.passkeys?.length || 0) <= 1) {
      showToast(t.cfg.passkeyLastAuthHint, 'warn');
      return;
    }
    const tok = await requestReauth({
      title: t.reauth.deletePasskeyTitle,
      description: t.reauth.deletePasskeyDesc.replace('{name}', name),
      actionLabel: t.delete,
      requireMfa: true,
    });
    if (!tok) return;
    secBusy = `pk-del:${id}`;
    try {
      await apiFetch(`/api/auth/passkey/${encodeURIComponent(id)}`, {
        method: 'DELETE',
        headers: { 'x-vane-reauth-token': tok },
      });
      showToast(`${t.delete}: ${name}`, 'success');
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
    'system_update',
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
  const MAX_BACKUP_BYTES = 6 * 1024 * 1024;
  const BACKUP_MAGICS = new Set(['VANEBAK1', 'VANEBAK2']);

  let bkPassBytes = $derived(textEncoder.encode(backupPass).length);
  let bkChecks = $derived({
    lenOk: bkPassBytes >= 8 && bkPassBytes <= 128,
    hasAlpha: /[A-Za-z]/.test(backupPass),
    hasDigitOrPunct: /[0-9!"#$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~]/.test(backupPass),
    matchConfirm: backupPass.length > 0 && backupPass === backupPassConfirm,
  });
  let bkPassValid = $derived(
    bkChecks.lenOk && bkChecks.hasAlpha && bkChecks.hasDigitOrPunct && bkChecks.matchConfirm
  );

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
    if (!bkPassValid) {
      showToast(t.cfg.bkPwWeak, 'error');
      return;
    }
    const tok = await requestReauth({
      title: t.reauth.backupExportTitle,
      description: t.reauth.backupExportDesc,
      actionLabel: t.cfg.bkExportBtn,
      requireMfa: true,
    });
    if (!tok) return;
    backupBusy = 'export';
    try {
      const r = await apiFetch('/api/backup/export', {
        method: 'POST',
        headers: { 'x-vane-reauth-token': tok },
        body: JSON.stringify({ password: backupPass, reauth_token: tok }),
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
      if (!BACKUP_MAGICS.has(magic)) {
        showToast(t.cfg.bkBadMagic, 'error');
        if (restoreFileInput) restoreFileInput.value = '';
        return;
      }
      restoreFileName = file.name;
      restoreBlobB64 = uint8ToBase64(u8);
    };
    reader.readAsArrayBuffer(file);
  }

  async function doImportEncryptedBackup(allowSecurityDowngrade = false) {
    if (backupBusy) return;
    const tok = await requestReauth({
      title: t.reauth.backupImportTitle,
      description: t.reauth.backupImportDesc,
      actionLabel: allowSecurityDowngrade ? t.cfg.bkDowngradeConfirmBtn : t.cfg.bkImportBtn,
      requireMfa: true,
    });
    if (!tok) return;
    backupBusy = 'import';
    let downgradePrompt = null;
    try {
      const payload = {
        backup_blob: restoreBlobB64,
        password: restorePass,
        reauth_token: tok,
      };
      if (allowSecurityDowngrade) {
        payload.allow_security_downgrade = true;
      }
      const res = await apiFetch('/api/backup/import', {
        method: 'POST',
        headers: { 'x-vane-reauth-token': tok },
        body: JSON.stringify(payload),
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
      const isDowngrade =
        !allowSecurityDowngrade &&
        (err?.status === 409 ||
          err?.code === 'SECURITY_DOWNGRADE_CONFIRM_REQUIRED' ||
          Array.isArray(err?.data?.downgrades));
      if (isDowngrade) {
        const list = Array.isArray(err?.data?.downgrades) ? err.data.downgrades.filter(Boolean) : [];
        const details = list.length
          ? `\n• ${list.join('\n• ')}`
          : err?.data?.message
            ? `\n${err.data.message}`
            : '';
        downgradePrompt = {
          title: t.cfg.bkDowngradeConfirmTitle,
          message: `${t.cfg.bkDowngradeConfirmDesc}${details}`,
          confirmLabel: t.cfg.bkDowngradeConfirmBtn,
          danger: true,
        };
      } else {
        showToast(err.message, 'error');
      }
    } finally {
      backupBusy = '';
    }
    if (downgradePrompt) {
      confirmThenRun(downgradePrompt, () => doImportEncryptedBackup(true));
    }
  }

  function importEncryptedBackup(e) {
    e.preventDefault();
    if (!restoreBlobB64 || backupBusy) return;
    confirmThenRun(
      {
        title: t.cfg.bkImportTitle,
        message: `${restoreFileName ? `${restoreFileName} — ` : ''}${t.cfg.bkImportConfirm}`,
        confirmLabel: t.cfg.bkImportBtn,
        danger: true,
      },
      () => doImportEncryptedBackup(false)
    );
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

{#if settingsJson}
  <!-- 顶部子面板导航（Arcane 风格带图标下划线标签栏） -->
  <div class="underline-tabs" role="tablist">
    <button type="button" role="tab" aria-selected={subTab === 'general'} class="underline-tab {subTab === 'general' ? 'active' : ''}" onclick={() => onSubTabChange?.('general')}>
      <Icons name="sliders" size={15} />
      <span>{t.cfg.tabGeneral}</span>
    </button>
    <button type="button" role="tab" aria-selected={subTab === 'appearance'} class="underline-tab {subTab === 'appearance' ? 'active' : ''}" onclick={() => onSubTabChange?.('appearance')}>
      <Icons name="palette" size={15} />
      <span>{t.cfg.tabAppearance}</span>
    </button>
    <button type="button" role="tab" aria-selected={subTab === 'security'} class="underline-tab {subTab === 'security' ? 'active' : ''}" onclick={() => onSubTabChange?.('security')}>
      <Icons name="shield" size={15} />
      <span>{t.cfg.tabSecurity}</span>
    </button>
    <button type="button" role="tab" aria-selected={subTab === 'notifications'} class="underline-tab {subTab === 'notifications' ? 'active' : ''}" onclick={() => onSubTabChange?.('notifications')}>
      <Icons name="bell" size={15} />
      <span>{t.cfg.tabNotifications}</span>
      {#if settingsJson.notifications?.length}
        <span class="badge badge-muted num" style="font-size:10.5px;padding:0 6px;">{settingsJson.notifications.length}</span>
      {/if}
    </button>
    <button type="button" role="tab" aria-selected={subTab === 'backup'} class="underline-tab {subTab === 'backup' ? 'active' : ''}" onclick={() => onSubTabChange?.('backup')}>
      <Icons name="database" size={15} />
      <span>{t.cfg.tabBackup}</span>
    </button>
    <button type="button" role="tab" aria-selected={subTab === 'update'} class="underline-tab {subTab === 'update' ? 'active' : ''}" onclick={() => onSubTabChange?.('update')}>
      <Icons name="refresh" size={15} />
      <span>{t.cfg.tabUpdate}</span>
    </button>
  </div>

  <!-- 0. 个性化设置：外观模式、主题色、界面语言与侧边栏布局 -->
  {#if subTab === 'appearance'}
    <div class="bento-grid-2">
      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title"><Icons name="palette" size={16} />{t.cfg.appearanceThemeTitle}</div>
            <div style="font-size:12px;color:var(--text-secondary);margin-top:2px;">{t.cfg.appearanceThemeDesc}</div>
          </div>
        </div>

        <div class="section-label" style="margin-top:0;">{t.themeModeLabel}</div>
        <div class="appearance-mode-grid" style="margin-bottom:16px;">
          {#each [
            { id: 'auto', icon: 'contrast', label: t.themeAuto, desc: t.cfg.themeAutoDesc },
            { id: 'light', icon: 'sun', label: t.themeLight, desc: t.cfg.themeLightDesc },
            { id: 'dark', icon: 'moon', label: t.themeDark, desc: t.cfg.themeDarkDesc },
          ] as m (m.id)}
            <button
              type="button"
              class="appearance-option {themeMode === m.id ? 'active' : ''}"
              aria-pressed={themeMode === m.id}
              onclick={() => onSelectThemeMode?.(m.id)}
            >
              <span class="appearance-option-icon"><Icons name={m.icon} size={17} /></span>
              <div style="min-width:0;flex:1;">
                <div style="font-weight:700;font-size:13.5px;">{m.label}</div>
                <div style="font-size:11.5px;color:var(--text-muted);margin-top:2px;">{m.desc}</div>
              </div>
            </button>
          {/each}
        </div>

        <div class="section-label">{t.themeAccentLabel}</div>
        <div class="accent-grid">
          {#each accentPresets as ap (ap.id)}
            <button
              type="button"
              class="accent-card {accentColor === ap.id ? 'active' : ''}"
              aria-pressed={accentColor === ap.id}
              onclick={() => onSelectAccentColor?.(ap.id)}
            >
              <span class="accent-swatch-dot" style={`background:${ap.color};`}>
                {#if accentColor === ap.id}
                  <Icons name="check" size={13} />
                {/if}
              </span>
              <span>{t.accents?.[ap.id] || ap.id}</span>
            </button>
          {/each}
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title"><Icons name="ddns" size={16} />{t.cfg.appearanceLangTitle}</div>
            <div style="font-size:12px;color:var(--text-secondary);margin-top:2px;">{t.cfg.appearanceLangDesc}</div>
          </div>
        </div>

        <div class="section-label" style="margin-top:0;">{t.cfg.lblLanguage}</div>
        <div class="appearance-lang-grid" style="margin-bottom:18px;">
          {#each [
            { id: 'zh', label: '简体中文', sub: 'Chinese (Simplified)' },
            { id: 'en', label: 'English', sub: 'English (US)' },
          ] as item (item.id)}
            <button
              type="button"
              class="appearance-option {lang === item.id ? 'active' : ''}"
              aria-pressed={lang === item.id}
              onclick={() => onSelectLang?.(item.id)}
            >
              <span class="appearance-option-icon mono" style="font-size:12.5px;font-weight:700;">
                {item.id === 'zh' ? '中' : 'EN'}
              </span>
              <div style="min-width:0;flex:1;">
                <div style="font-weight:700;font-size:13.5px;">{item.label}</div>
                <div style="font-size:11.5px;color:var(--text-muted);margin-top:2px;">{item.sub}</div>
              </div>
              {#if lang === item.id}
                <Icons name="check" size={15} />
              {/if}
            </button>
          {/each}
        </div>

        <div class="section-label">{lang === 'en' ? 'Display & Layout' : '显示与导航布局'}</div>
        <div class="settings-list">
          <div class="settings-row switch-row">
            <div class="settings-row-info">
              <span class="settings-row-label">{t.cfg.oledModeLabel}</span>
              <div class="settings-row-desc">{t.cfg.oledModeDesc}</div>
            </div>
            <div class="settings-row-control">
              <button
                type="button"
                class="switch"
                role="switch"
                aria-checked={Boolean(oledMode)}
                aria-label={t.cfg.oledModeLabel}
                onclick={() => onToggleOledMode?.()}
              >
                <span class="switch-thumb"></span>
              </button>
            </div>
          </div>
          <div class="settings-row switch-row">
            <div class="settings-row-info">
              <span class="settings-row-label">{t.cfg.sidebarCollapseLabel}</span>
              <div class="settings-row-desc">{t.cfg.sidebarCollapseDesc}</div>
            </div>
            <div class="settings-row-control">
              <button
                type="button"
                class="switch"
                role="switch"
                aria-checked={Boolean(sidebarCollapsed)}
                aria-label={t.cfg.sidebarCollapseLabel}
                onclick={() => onToggleSidebar?.()}
              >
                <span class="switch-thumb"></span>
              </button>
            </div>
          </div>
          <div class="settings-row switch-row">
            <div class="settings-row-info">
              <span class="settings-row-label">{t.cfg.pwaInstallLabel}</span>
              <div class="settings-row-desc">
                {#if pwaState?.standalone}
                  {t.cfg.pwaInstallDesc}
                {:else if pwaState?.canPrompt}
                  {t.cfg.pwaInstallDesc}
                {:else if pwaState?.iosSafari}
                  {t.cfg.pwaIosGuide}
                {:else}
                  {t.cfg.pwaHttpsHint}
                {/if}
              </div>
            </div>
            <div class="settings-row-control">
              {#if pwaState?.standalone}
                <span class="badge badge-ok">
                  <Icons name="check" size={12} />
                  <span>{t.cfg.pwaInstalledBadge}</span>
                </span>
              {:else if pwaState?.canPrompt && onInstallPwa}
                <button type="button" class="btn btn-primary btn-sm" onclick={() => onInstallPwa()}>
                  <Icons name="download" size={14} />
                  <span>{t.cfg.pwaInstallBtn}</span>
                </button>
              {:else}
                <span class="badge badge-muted">PWA</span>
              {/if}
            </div>
          </div>
        </div>
      </div>
    </div>
  {/if}

  <!-- 1. 子功能模块中心 + 全局核心与共用基础设置（各子模块专属参数已内聚至对应模块页面） -->
  {#if subTab === 'general'}
    <div class="card" style="margin-bottom:22px;">
      <div class="card-header">
        <div>
          <div class="card-title">{t.cfg.modulesTitle}</div>
          <div style="font-size:12px;color:var(--text-secondary);">
            {lang === 'en'
              ? 'Toggle sub-modules or enable step-up re-auth locks. Each module manages its own dedicated settings directly inside its page.'
              : '按需启停子模块或开启二次验证锁；各模块的专属参数可直接进入对应模块页面内调整。'}
          </div>
        </div>
      </div>
      <div class="modules-grid">
        {#each [
          { key: 'reverse_proxy', title: t.nav.reverse_proxy, sharedTag: t.cfg.moduleSharedTagFw },
          { key: 'port_forward', title: t.nav.port_forward, sharedTag: t.cfg.moduleSharedTagFw },
          { key: 'ddns', title: t.nav.ddns, sharedTag: t.cfg.moduleSharedTagFwDns },
          { key: 'acme', title: t.nav.acme, sharedTag: t.cfg.moduleSharedTagDns },
          { key: 'stun', title: t.nav.stun, sharedTag: '' },
          { key: 'web_terminal', title: t.nav.web_terminal, sharedTag: '' },
          { key: 'cron', title: t.nav.cron, sharedTag: '' },
          { key: 'docker', title: t.nav.docker, sharedTag: '' },
        ] as mod (mod.key)}
          {@const key = mod.key}
          {@const title = mod.title}
          {@const modOn = Boolean(modules[key])}
          {@const reauthOn = Boolean(moduleReauth?.[key])}
          {@const modLocked = Boolean(modOn && isModuleLocked(key))}
          <div class="subcard module-card">
            <div class="row-between">
              <div style="display:flex;align-items:center;gap:8px;min-width:0;">
                <Icons name={key} size={16} />
                <span style="font-weight:600;font-size:14px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{title}</span>
              </div>
              <div style="display:flex;align-items:center;gap:8px;flex-shrink:0;">
                <span class="badge {modOn ? 'badge-ok' : 'badge-muted'}">{modOn ? t.enabled : t.disabled}</span>
                <button
                  type="button"
                  class="switch"
                  role="switch"
                  aria-checked={modOn}
                  aria-label={title}
                  onclick={() => onToggleModule(key)}
                >
                  <span class="switch-thumb"></span>
                </button>
              </div>
            </div>
            <div class="module-card-reauth {reauthOn ? 'active' : ''} {!modOn ? 'disabled' : ''}">
              <span style="display:inline-flex;align-items:center;gap:6px;min-width:0;">
                <Icons name={reauthOn ? (modLocked ? 'lock' : 'unlock') : 'shield'} size={13} />
                <span>{t.cfg.moduleReauthLabel}</span>
                {#if modOn && reauthOn}
                  <span class="badge {modLocked ? 'badge-muted' : 'badge-ok'}" style="font-size:10px;padding:1px 6px;">
                    {modLocked ? (lang === 'en' ? 'Locked' : '已锁定') : (lang === 'en' ? 'Unlocked' : '已解锁')}
                  </span>
                {/if}
              </span>
              <button
                type="button"
                class="switch switch-xs"
                role="switch"
                disabled={!modOn}
                aria-checked={reauthOn}
                aria-label={`${title} ${t.cfg.moduleReauthLabel}`}
                onclick={() => onToggleModuleReauth?.(key)}
              >
                <span class="switch-thumb"></span>
              </button>
            </div>
            {#if modOn && (mod.sharedTag || onNavigate)}
              <div class="module-card-foot">
                <span class="module-card-summary">{mod.sharedTag || ' '}</span>
                {#if onNavigate}
                  <button type="button" class="btn btn-ghost btn-xs" style="padding:0 6px;color:var(--text-secondary);" onclick={() => onNavigate(key)}>
                    <span>{t.cfg.moduleOpenViewBtn}</span>
                    <Icons name="chevron_right" size={12} />
                  </button>
                {/if}
              </div>
            {/if}
          </div>
        {/each}
      </div>
    </div>

    {#if generalDraft}
      <form onsubmit={saveGeneralSettings}>
        <!-- 板块二：总体系统设置（全局核心，始终可见，不受单子模块启停/锁限制） -->
        <div class="settings-tier-head">
          <div>
            <div class="settings-tier-title">{t.cfg.globalTierTitle}</div>
            <div class="settings-tier-desc">{t.cfg.globalTierDesc}</div>
          </div>
          <div class="btn-group">
            {#if generalDirty}
              <button type="button" class="btn btn-sm" onclick={() => syncGeneralDraft(settingsJson)}>
                {t.common.discardChanges}
              </button>
            {/if}
            <button type="submit" class="btn btn-primary btn-sm" disabled={saving || !generalDirty}>
              <Icons name="save" size={14} />
              <span>{saving ? '...' : t.saveSettings}</span>
            </button>
          </div>
        </div>

        <div class="banner banner-warn">
          <div style="display:flex;align-items:flex-start;gap:10px;">
            <Icons name="alert" size={17} />
            <div>
              <div style="font-weight:700;">{t.cfg.originWarnTitle}</div>
              <div style="color:var(--text-secondary);">{t.cfg.originWarnDesc}</div>
              {#if savedEntryUrl}
                <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:8px;">
                  <span style="font-size:12px;color:var(--text-secondary);">{t.cfg.savedEntryUrl}:</span>
                  <code class="mono" style="background:var(--bg-elevated);padding:2px 8px;border-radius:8px;border:1px solid var(--border-subtle);">{savedEntryUrl}</code>
                  <button type="button" class="btn btn-xs" onclick={() => handleCopy(savedEntryUrl)}>
                    <Icons name="copy" size={12} />
                    <span>{t.copy}</span>
                  </button>
                </div>
              {/if}
              {#if draftEntryUrl && draftEntryUrl !== savedEntryUrl}
                <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:6px;">
                  <span style="font-size:12px;color:var(--warn);font-weight:600;">{t.cfg.previewEntryUrl}:</span>
                  <code class="mono" style="background:var(--bg-elevated);padding:2px 8px;border-radius:8px;border:1px solid var(--warn);">{draftEntryUrl}</code>
                  <button type="button" class="btn btn-xs" onclick={() => handleCopy(draftEntryUrl)}>
                    <Icons name="copy" size={12} />
                    <span>{t.copy}</span>
                  </button>
                </div>
              {/if}
            </div>
          </div>
        </div>

        <!-- 分组 1：核心运行与管理入口（总体） -->
        <section class="settings-section">
          <div class="settings-section-head">
            <div>
              <h3 class="settings-section-title">{t.cfg.groupCore}</h3>
            </div>
          </div>
          <div class="settings-list">
            <div class="settings-row">
              <div class="settings-row-info">
                <label class="settings-row-label" for="st-ttl">{t.cfg.lblSessionTtl}</label>
                <div class="settings-row-desc">{t.cfg.descSessionTtl}</div>
              </div>
              <div class="settings-row-control">
                <input id="st-ttl" type="number" min="300" max="86400" bind:value={generalDraft.admin.session_ttl_secs} required />
              </div>
            </div>
            <div class="settings-row">
              <div class="settings-row-info">
                <label class="settings-row-label" for="st-maxc">{t.cfg.lblGlobalConns}</label>
                <div class="settings-row-desc">{t.cfg.descGlobalConns}</div>
              </div>
              <div class="settings-row-control">
                <input id="st-maxc" type="number" min="64" max="4096" bind:value={generalDraft.system.global_max_conns} required />
              </div>
            </div>
            <div class="settings-row">
              <div class="settings-row-info">
                <label class="settings-row-label" for="st-tz">{t.cfg.lblTimezone}</label>
                <div class="settings-row-desc">UTC / auto / +08:00</div>
              </div>
              <div class="settings-row-control">
                <input id="st-tz" type="text" class="mono" bind:value={generalDraft.system.timezone_offset} />
              </div>
            </div>
            <div class="settings-row">
              <div class="settings-row-info">
                <label class="settings-row-label" for="st-wk" style="display:inline-flex;align-items:center;gap:6px;">
                  <span>{t.cfg.workerThreads}</span>
                  <span class="badge badge-warn" style="font-size:10px;padding:1px 6px;">{t.common.restartReqBadge}</span>
                </label>
                <div class="settings-row-desc">{t.cfg.descWorkerThreads}</div>
              </div>
              <div class="settings-row-control">
                <input id="st-wk" type="number" min="1" max="8" bind:value={generalDraft.system.worker_threads} required />
              </div>
            </div>
            <div class="settings-row">
              <div class="settings-row-info">
                <label class="settings-row-label" for="st-sp">{t.cfg.lblSecretPath}</label>
                <div class="settings-row-desc">{t.cfg.descSecretPath}</div>
              </div>
              <div class="settings-row-control">
                <div style="display:flex;gap:8px;align-items:center;">
                  <input id="st-sp" type="text" class="mono" placeholder="/ or /_vane_..." bind:value={generalDraft.admin.secret_path} />
                  <button type="button" class="btn btn-xs" style="flex-shrink:0;" onclick={generateRandomSecretPath}>
                    {t.cfg.genRandomPath}
                  </button>
                </div>
              </div>
            </div>
            <div class="settings-row">
              <div class="settings-row-info">
                <label class="settings-row-label" for="st-org" style="display:inline-flex;align-items:center;gap:6px;">
                  <span>{t.cfg.lblCanonicalOrigin}</span>
                  <span class="badge badge-warn" style="font-size:10px;padding:1px 6px;">{t.common.restartReqBadge}</span>
                </label>
                <div class="settings-row-desc">{t.cfg.descCanonicalOrigin}</div>
              </div>
              <div class="settings-row-control">
                <input id="st-org" type="text" class="mono" bind:value={generalDraft.admin.canonical_origin} />
              </div>
            </div>
            <div class="settings-row">
              <div class="settings-row-info">
                <label class="settings-row-label" for="st-ll" style="display:inline-flex;align-items:center;gap:6px;">
                  <span>{t.cfg.lblListenLan}</span>
                  <span class="badge badge-warn" style="font-size:10px;padding:1px 6px;">{t.common.restartReqBadge}</span>
                </label>
                <div class="settings-row-desc">{t.cfg.descListenLan}</div>
              </div>
              <div class="settings-row-control">
                <input id="st-ll" type="text" class="mono" bind:value={listenLanCsv} />
              </div>
            </div>
            <div class="settings-row">
              <div class="settings-row-info">
                <label class="settings-row-label" for="st-eo">{t.cfg.extraOrigins}</label>
                <div class="settings-row-desc">{t.cfg.descExtraOrigins}</div>
              </div>
              <div class="settings-row-control">
                <input id="st-eo" type="text" class="mono" placeholder="https://192.168.1.1:5173" bind:value={extraOriginsCsv} />
              </div>
            </div>
            <div class="settings-row">
              <div class="settings-row-info">
                <label class="settings-row-label" for="st-tcert" style="display:inline-flex;align-items:center;gap:6px;">
                  <span>{t.cfg.tlsCertPath}</span>
                  <span class="badge badge-warn" style="font-size:10px;padding:1px 6px;">{t.common.restartReqBadge}</span>
                </label>
                <div class="settings-row-desc">{t.cfg.tlsKeyPath}</div>
              </div>
              <div class="settings-row-control">
                <input id="st-tcert" type="text" class="mono" placeholder="/etc/vane/admin.crt" bind:value={generalDraft.admin.tls_cert_path} />
                <input id="st-tkey" type="text" class="mono" placeholder="/etc/vane/admin.key" bind:value={generalDraft.admin.tls_key_path} />
              </div>
            </div>
          </div>
        </section>

        <!-- 分组 2：安全防爆破与协议超时（总体） -->
        <section class="settings-section">
          <div class="settings-section-head">
            <h3 class="settings-section-title">{t.cfg.groupSecurity}</h3>
          </div>
          <div class="settings-list">
            <div class="settings-row switch-row">
              <div class="settings-row-info">
                <span class="settings-row-label">{t.cfg.lblKernelBan}</span>
                <div class="settings-row-desc">{t.cfg.descKernelBan}</div>
              </div>
              <div class="settings-row-control">
                <button
                  type="button"
                  class="switch"
                  role="switch"
                  aria-checked={Boolean(generalDraft.security.kernel_ban_offload)}
                  aria-label={t.cfg.lblKernelBan}
                  onclick={() => (generalDraft.security.kernel_ban_offload = !generalDraft.security.kernel_ban_offload)}
                >
                  <span class="switch-thumb"></span>
                </button>
              </div>
            </div>
            <div class="settings-row">
              <div class="settings-row-info">
                <label class="settings-row-label" for="st-f2b">{t.cfg.lblMaxFailures}</label>
                <div class="settings-row-desc">{t.cfg.lblBanDuration}</div>
              </div>
              <div class="settings-row-control" style="flex-direction:row;gap:8px;">
                <input id="st-f2b" type="number" min="3" max="20" bind:value={generalDraft.security.max_login_failures} required />
                <input id="st-bds" type="number" min="60" max="86400" bind:value={generalDraft.security.ban_duration_secs} required />
              </div>
            </div>
            <div class="settings-row">
              <div class="settings-row-info">
                <label class="settings-row-label" for="st-tlshs">{t.cfg.tlsHsTimeout} / {t.cfg.hdrTimeout}</label>
                <div class="settings-row-desc">{lang === 'en' ? 'TLS (2~30s) · HTTP Header (3~60s)' : '握手超时 (2~30秒) · 请求头超时 (3~60秒)'}</div>
              </div>
              <div class="settings-row-control" style="flex-direction:row;gap:8px;">
                <input id="st-tlshs" type="number" min="2" max="30" bind:value={generalDraft.security.tls_handshake_timeout_secs} required />
                <input id="st-hdrt" type="number" min="3" max="60" bind:value={generalDraft.security.http_header_timeout_secs} required />
              </div>
            </div>
          </div>
        </section>

        <!-- 板块三：多模块共用基础设置（显式展示跨模块共用关系） -->
        <div class="settings-tier-head" style="margin-top:26px;">
          <div>
            <div class="settings-tier-title">{t.cfg.sharedTierTitle}</div>
            <div class="settings-tier-desc">{t.cfg.sharedTierDesc}</div>
          </div>
        </div>

        <section class="settings-section">
          <div class="settings-section-head">
            <div>
              <h3 class="settings-section-title">{t.cfg.groupFirewall}</h3>
              <div class="shared-dep-strip">
                <span class="shared-dep-label">{t.cfg.sharedByLabel}:</span>
                {#each fwDeps as dep (dep.label)}
                  <span class="shared-dep-pill {dep.active ? 'active' : ''}">
                    <span class="status-dot {dep.active ? 'ok' : 'muted'}" style="width:6px;height:6px;box-shadow:none;"></span>
                    <span>{dep.label}</span>
                  </span>
                {/each}
              </div>
            </div>
          </div>
          {#if !anyFwDepActive}
            <div class="banner banner-info" style="margin-bottom:10px;font-size:12.5px;">
              <div style="display:flex;align-items:center;gap:8px;">
                <Icons name="info" size={15} />
                <span>{t.cfg.sharedFirewallUnusedHint}</span>
              </div>
            </div>
          {/if}
          <div class="settings-list">
            <div class="settings-row switch-row">
              <div class="settings-row-info">
                <span class="settings-row-label">{t.cfg.lblFwAuto}</span>
                <div class="settings-row-desc">{t.cfg.descFwAuto}</div>
              </div>
              <div class="settings-row-control">
                <button
                  type="button"
                  class="switch"
                  role="switch"
                  aria-checked={Boolean(generalDraft.firewall.auto_manage)}
                  aria-label={t.cfg.lblFwAuto}
                  onclick={() => (generalDraft.firewall.auto_manage = !generalDraft.firewall.auto_manage)}
                >
                  <span class="switch-thumb"></span>
                </button>
              </div>
            </div>
            <div class="settings-row">
              <div class="settings-row-info">
                <label class="settings-row-label" for="st-fwb" style="display:inline-flex;align-items:center;gap:6px;">
                  <span>{t.cfg.lblFwBackend}</span>
                  <span class="badge badge-warn" style="font-size:10px;padding:1px 6px;">{t.common.restartReqBadge}</span>
                </label>
                <div class="settings-row-desc">{t.cfg.descFwBackend}</div>
              </div>
              <div class="settings-row-control">
                <Select
                  id="st-fwb"
                  bind:value={generalDraft.firewall.backend}
                  options={[
                    { value: 'auto', label: lang === 'en' ? 'Auto Detect (Recommended)' : '自动识别（推荐）' },
                    { value: 'nftables', label: 'nftables (OpenWrt fw4)' },
                    { value: 'iptables_legacy', label: 'iptables (Legacy)' },
                    { value: 'iptables_nft', label: 'iptables-nft' },
                  ]}
                />
              </div>
            </div>
            <div class="settings-row">
              <div class="settings-row-info">
                <label class="settings-row-label" for="st-wan">{t.cfg.lblWanIfaces}</label>
                <div class="settings-row-desc">{t.cfg.descWanIfaces}</div>
              </div>
              <div class="settings-row-control">
                <ComboInput id="st-wan" multiple placeholder="pppoe-wan" options={ifaceOptions} bind:value={wanIfacesCsv} />
              </div>
            </div>
            <div class="settings-row">
              <div class="settings-row-info">
                <label class="settings-row-label" for="st-lan">{t.cfg.lblLanIfaces}</label>
                <div class="settings-row-desc">{t.cfg.descLanIfaces}</div>
              </div>
              <div class="settings-row-control">
                <ComboInput id="st-lan" multiple placeholder="br-lan" options={ifaceOptions} bind:value={lanIfacesCsv} />
              </div>
            </div>
          </div>
        </section>

        {#if sharedDnsVisible}
          {@const dnsTargetTab = modules.ddns ? 'ddns' : 'acme'}
          <section class="settings-section">
            <div class="settings-section-head">
              <div>
                <h3 class="settings-section-title">{t.cfg.sharedDnsTitle}</h3>
                <div class="shared-dep-strip">
                  <span class="shared-dep-label">{t.cfg.sharedByLabel}:</span>
                  <span class="shared-dep-pill {modules.ddns ? 'active' : ''}">
                    <span class="status-dot {modules.ddns ? 'ok' : 'muted'}" style="width:6px;height:6px;box-shadow:none;"></span>
                    <span>{t.nav.ddns}</span>
                  </span>
                  <span class="shared-dep-pill {modules.acme ? 'active' : ''}">
                    <span class="status-dot {modules.acme ? 'ok' : 'muted'}" style="width:6px;height:6px;box-shadow:none;"></span>
                    <span>{t.nav.acme}</span>
                  </span>
                </div>
              </div>
              {#if onNavigate}
                <button type="button" class="btn btn-sm" onclick={() => onNavigate(dnsTargetTab)}>
                  <Icons name="key" size={13} />
                  <span>{t.cfg.sharedDnsManageBtn}</span>
                  <Icons name="chevron_right" size={13} />
                </button>
              {/if}
            </div>
            <div class="settings-list">
              <div class="settings-row switch-row">
                <div class="settings-row-info">
                  <span class="settings-row-label">
                    {dnsProviderNames.length
                      ? t.cfg.sharedDnsCount.replace('{n}', String(dnsProviderNames.length))
                      : t.cfg.sharedDnsEmpty}
                  </span>
                  <div class="settings-row-desc">{t.cfg.sharedDnsDesc}</div>
                </div>
                <div class="settings-row-control" style="flex-direction:row;flex-wrap:wrap;justify-content:flex-end;gap:6px;">
                  {#each dnsProviderNames.slice(0, 6) as pName (pName)}
                    <span class="badge badge-muted mono">{pName}</span>
                  {/each}
                  {#if dnsProviderNames.length > 6}
                    <span class="badge badge-muted num">+{dnsProviderNames.length - 6}</span>
                  {/if}
                </div>
              </div>
            </div>
          </section>
        {/if}

        {#if generalDirty}
          <div class="floating-save-bar">
            <span style="display:inline-flex;align-items:center;gap:8px;font-size:13px;font-weight:600;">
              <Icons name="info" size={15} />
              <span>{t.common.unsavedChanges}</span>
            </span>
            <div class="btn-group">
              <button type="button" class="btn btn-sm" onclick={() => syncGeneralDraft(settingsJson)}>
                {t.common.discardChanges}
              </button>
              <button type="submit" class="btn btn-primary btn-sm" disabled={saving}>
                <Icons name="save" size={14} />
                <span>{saving ? '...' : t.saveSettings}</span>
              </button>
            </div>
          </div>
        {/if}
      </form>
    {/if}
  {/if}

  <!-- 2. 认证安全中心：改密 + TOTP + 通行密钥 -->
  {#if subTab === 'security'}
    <div class="bento-grid-2">
      <!-- 修改管理员用户名与口令 -->
      <div class="card">
        <div class="card-header">
          <span class="card-title">{t.cfg.pwTitle}</span>
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
          <span class="card-title">{lang === 'en' ? 'Authenticator App (TOTP)' : '动态口令验证 (TOTP)'}</span>
          <span class="badge {settingsJson.admin.totp_enabled ? 'badge-ok' : 'badge-muted'}">
            {settingsJson.admin.totp_enabled ? t.enabled : t.disabled}
          </span>
        </div>

        {#if settingsJson.admin.totp_enabled}
          <p style="font-size:13px;color:var(--text-secondary);margin-bottom:12px;">
            {lang === 'en'
              ? `Two-factor authentication is active. Remaining recovery codes: ${settingsJson.admin.totp_recovery_hashes?.remaining ?? 0}`
              : `两步验证已开启。当前剩余一次性恢复码：${settingsJson.admin.totp_recovery_hashes?.remaining ?? 0} 个`}
          </p>
          <div class="btn-group">
            <button
              type="button"
              class="btn btn-sm"
              disabled={Boolean(secBusy)}
              onclick={() =>
                confirmThenRun(
                  {
                    title: t.cfg.totpRegen,
                    message: t.cfg.totpRegenConfirm,
                    confirmLabel: t.confirmAction,
                    danger: true,
                  },
                  regenerateRecoveryCodes
                )
              }
            >
              {secBusy === 'totp-regen' ? '...' : t.cfg.totpRegen}
            </button>
            <button
              type="button"
              class="btn btn-sm btn-danger"
              disabled={Boolean(secBusy)}
              onclick={() =>
                confirmThenRun(
                  {
                    title: t.cfg.totpDisable,
                    message: t.cfg.totpDisableConfirm,
                    confirmLabel: t.cfg.totpDisable,
                    danger: true,
                  },
                  disableTotpWithReauth
                )
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
              <div class="subcard" style="flex:1;min-width:220px;display:grid;gap:12px;">
                <div class="row-between" style="gap:10px;">
                  <div style="min-width:0;">
                    <div style="font-size:11.5px;color:var(--text-muted);font-weight:600;">Base32 Secret</div>
                    <div class="mono" style="font-size:13px;font-weight:600;margin-top:2px;">
                      {maskTotpSecret(totpSetupData.secret_base32)}
                    </div>
                  </div>
                  <button type="button" class="btn btn-xs" onclick={() => handleCopy(totpSetupData.secret_base32)}>
                    <Icons name="copy" size={12} />
                    <span>{lang === 'en' ? 'Copy Secret' : '复制密钥'}</span>
                  </button>
                </div>
                <div class="row-between" style="gap:10px;padding-top:10px;border-top:1px solid var(--border-subtle);">
                  <div style="min-width:0;">
                    <div style="font-size:11.5px;color:var(--text-muted);font-weight:600;">otpauth URI</div>
                    <div class="mono" style="font-size:12px;color:var(--text-secondary);margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                      {maskOtpAuthUri(totpSetupData.otpauth_uri)}
                    </div>
                  </div>
                  <button type="button" class="btn btn-xs" onclick={() => handleCopy(totpSetupData.otpauth_uri)}>
                    <Icons name="copy" size={12} />
                    <span>{lang === 'en' ? 'Copy URI' : '复制 URI'}</span>
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

    <!-- 通行密钥 Passkey (WebAuthn / FIDO2)：遵循行业标准一键添加即启用，关闭时需二次验证并彻底清空 -->
    {@const pkList = settingsJson.admin.passkeys || []}
    {@const passkeyActive = Boolean(settingsJson.admin.passkey_enabled) && pkList.length > 0}
    {@const pwLoginOn = Boolean(settingsJson.admin.password_login_enabled)}
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title">
            <Icons name="passkey" size={16} />
            <span>{t.cfg.passkeyTitle}</span>
            <span class="badge {passkeyActive ? 'badge-ok' : 'badge-muted'}">
              {passkeyActive ? `${t.enabled} · ${pkList.length}/16` : t.disabled}
            </span>
          </div>
          <div style="font-size:12px;color:var(--text-secondary);margin-top:2px;">{t.cfg.passkeyDesc}</div>
        </div>
        {#if passkeyActive}
          <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
            <div style="display:flex;align-items:center;gap:8px;">
              <span style="font-size:13px;color:var(--text-secondary);">{t.cfg.allowPwLogin}</span>
              <button
                type="button"
                class="switch"
                role="switch"
                aria-checked={pwLoginOn}
                aria-label={t.cfg.allowPwLogin}
                disabled={Boolean(secBusy)}
                onclick={requestTogglePasswordLogin}
              >
                <span class="switch-thumb"></span>
              </button>
            </div>
            <button
              type="button"
              class="btn btn-sm btn-danger"
              disabled={Boolean(secBusy) || !pwLoginOn}
              title={!pwLoginOn ? t.cfg.passkeyLastAuthHint : ''}
              onclick={() =>
                confirmThenRun(
                  {
                    title: t.cfg.passkeyDisableConfirmTitle,
                    message: t.cfg.passkeyDisableConfirmDesc,
                    confirmLabel: t.cfg.passkeyDisableAllBtn,
                    danger: true,
                  },
                  disableAllPasskeysWithReauth
                )
              }
            >
              {secBusy === 'pk-toggle' ? '...' : t.cfg.passkeyDisableAllBtn}
            </button>
          </div>
        {/if}
      </div>

      {#if !passkeyBrowserOk}
        <div class="banner banner-warn" style="margin-bottom:12px;">{t.cfg.passkeyUnsupported}</div>
      {:else if passkeyOnRawIp}
        <div class="banner banner-info" style="margin-bottom:12px;">
          <div style="display:flex;align-items:flex-start;gap:8px;">
            <Icons name="info" size={16} />
            <span>{t.cfg.passkeyIpWarn}</span>
          </div>
        </div>
      {/if}

      {#if passkeyActive && !pwLoginOn}
        <div class="banner banner-warn" style="margin-bottom:12px;">
          <div style="display:flex;align-items:flex-start;gap:8px;">
            <Icons name="alert" size={15} />
            <span>{t.cfg.passkeyLastAuthHint}</span>
          </div>
        </div>
      {/if}

      {#if pkList.length}
        <div class="settings-list" style="margin-bottom:14px;">
          {#each pkList as pk (pk.id)}
            {@const isLastProtectedKey = !pwLoginOn && pkList.length <= 1}
            <div class="settings-row switch-row" style="padding:12px 16px;">
              <div style="display:flex;align-items:center;gap:12px;min-width:0;">
                <span class="icon-tile sm"><Icons name="passkey" size={15} /></span>
                <div style="min-width:0;">
                  <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                    <span style="font-weight:600;font-size:13.5px;">{pk.name}</span>
                    <span class="badge badge-info mono" style="font-size:11px;">{pk.rp_id}</span>
                    <span class="badge badge-muted mono" style="font-size:11px;">{pk.alg === -8 ? 'Ed25519' : 'ES256'}</span>
                  </div>
                  <div class="mono" style="font-size:11.5px;color:var(--text-muted);margin-top:3px;">
                    {lang === 'en' ? 'Added' : '绑定时间'}: {formatUnixTime(pk.created_at)}
                    {#if pk.last_used_at}
                      · {lang === 'en' ? 'Last used' : '最近使用'}: {formatUnixTime(pk.last_used_at)}
                    {/if}
                  </div>
                </div>
              </div>
              <button
                type="button"
                class="btn btn-xs btn-danger"
                disabled={Boolean(secBusy) || isLastProtectedKey}
                title={isLastProtectedKey ? t.cfg.passkeyLastAuthHint : ''}
                onclick={() =>
                  confirmThenRun(
                    {
                      title: t.common.confirmDeleteTitle,
                      message: `${pk.name} (${pk.rp_id}) — ${t.cfg.passkeyDeleteConfirmDesc}`,
                      confirmLabel: t.delete,
                      danger: true,
                    },
                    () => deletePasskeyWithReauth(pk.id, pk.name)
                  )
                }
              >
                {secBusy === `pk-del:${pk.id}` ? '...' : t.delete}
              </button>
            </div>
          {/each}
        </div>
      {:else}
        <div style="font-size:12.5px;color:var(--text-secondary);margin-bottom:12px;">{t.cfg.passkeyEmpty}</div>
      {/if}

      <form onsubmit={registerPasskey} style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
        <input
          type="text"
          style="flex:1;min-width:220px;"
          maxlength="64"
          placeholder={t.cfg.passkeyNamePh}
          aria-label={t.cfg.passkeyNamePh}
          disabled={Boolean(secBusy) || pkList.length >= 16}
          bind:value={newPasskeyName}
        />
        <button
          type="submit"
          class="btn btn-primary"
          disabled={Boolean(secBusy) || !passkeyBrowserOk || passkeyOnRawIp || pkList.length >= 16}
        >
          <Icons name="passkey" size={15} />
          <span>{secBusy === 'pk-add' ? '...' : pkList.length ? t.cfg.passkeyAddBtn : t.cfg.passkeyAddFirstBtn}</span>
        </button>
      </form>
    </div>
  {/if}

  <!-- 3. 外部多渠道通知设置（Arcane 分组列表风格） -->
  {#if subTab === 'notifications'}
    <section class="settings-section">
      <div class="settings-section-head">
        <div>
          <h3 class="settings-section-title">{t.cfg.notifTitle}</h3>
          <p class="settings-section-desc">{t.cfg.notifSub}</p>
        </div>
        <button type="button" class="btn btn-primary btn-sm" onclick={() => openNotifDrawer(-1)}>
          <Icons name="plus" size={14} />
          <span>{t.add}</span>
        </button>
      </div>

      {#if !settingsJson.notifications?.length}
        <div class="empty-state">{t.common.empty}</div>
      {:else}
        <div class="settings-list">
          {#each settingsJson.notifications as n, idx (n.name)}
            <div class="settings-row switch-row" style="padding:14px 18px;">
              <div style="display:flex;align-items:center;gap:12px;min-width:0;">
                <span class="icon-tile sm {n.enabled ? '' : 'muted'}">
                  <Icons name="bell" size={15} />
                </span>
                <div style="min-width:0;">
                  <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                    <span style="font-weight:600;font-size:14px;">{n.name}</span>
                    <span class="badge badge-info">{n.provider}</span>
                    <span class="badge badge-muted">&gt;= {n.min_severity}</span>
                    {#if !n.enabled}<span class="badge badge-warn">{t.disabled}</span>{/if}
                  </div>
                  <div style="font-size:12px;color:var(--text-secondary);margin-top:3px;">
                    {n.events?.length ? n.events.map((ev) => t.events?.[ev] || ev).join(' · ') : t.cfg.allEvents}
                  </div>
                </div>
              </div>
              <div class="btn-group">
                <button
                  type="button"
                  class="switch switch-xs"
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
    </section>
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
          <input id="bk-pw" type={showBkPass ? 'text' : 'password'} minlength="8" maxlength="128" autocomplete="new-password" bind:value={backupPass} required />
        </div>
        <div class="field">
          <label for="bk-pw2">{t.cfg.bkExportPwConfirm}</label>
          <input id="bk-pw2" type={showBkPass ? 'text' : 'password'} minlength="8" maxlength="128" autocomplete="new-password" bind:value={backupPassConfirm} required />
          {#if backupPassConfirm && backupPass !== backupPassConfirm}
            <div style="font-size:12px;color:var(--danger);margin-top:4px;">{t.cfg.bkPwMismatch}</div>
          {/if}
        </div>
        <div class="subcard" style="margin-bottom:14px;font-size:12px;display:grid;gap:4px;">
          <div style="color:{bkChecks.lenOk ? 'var(--accent)' : 'var(--text-secondary)'}">{bkChecks.lenOk ? '✓' : '○'} {t.ruleLen}</div>
          <div style="color:{bkChecks.hasAlpha ? 'var(--accent)' : 'var(--text-secondary)'}">{bkChecks.hasAlpha ? '✓' : '○'} {t.ruleAlpha}</div>
          <div style="color:{bkChecks.hasDigitOrPunct ? 'var(--accent)' : 'var(--text-secondary)'}">{bkChecks.hasDigitOrPunct ? '✓' : '○'} {t.ruleDigit}</div>
          <div style="color:{bkChecks.matchConfirm ? 'var(--accent)' : 'var(--text-secondary)'}">{bkChecks.matchConfirm ? '✓' : '○'} {t.ruleMatch}</div>
        </div>
        <button
          type="submit"
          class="btn btn-primary btn-sm"
          disabled={Boolean(backupBusy) || !bkPassValid}
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

  <!-- 5. 系统更新管理（GitHub Release 自动检查提醒 + 安全沙箱手动压缩包更新） -->
  {#if subTab === 'update'}
    <SystemUpdatePanel
      {t}
      {lang}
      {settingsJson}
      {onSaveSettings}
      {requestReauth}
      {apiFetch}
      {showToast}
    />
  {/if}
{/if}

<!-- 通知渠道编辑弹窗 -->
<EditorDialog
  open={notifDrawerOpen && Boolean(notifDraft)}
  title={`${notifEditIdx >= 0 ? t.edit : t.add} · ${t.cfg.tabNotifications}`}
  size="md"
  busy={saving}
  {t}
  {askConfirm}
  onSubmit={saveNotification}
  onClose={() => (notifDrawerOpen = false)}
>
        <div class="form-grid">
          <div class="field">
            <label for="nf-name">{t.cfg.lblNotifName}</label>
            <input id="nf-name" type="text" class="mono" bind:value={notifDraft.name} required />
          </div>
          <div class="field">
            <label for="nf-prov">{t.cfg.lblNotifProvider}</label>
            <Select
              id="nf-prov"
              bind:value={notifDraft.provider}
              options={
                lang === 'en'
                  ? [
                      { value: 'webhook', label: 'Custom Webhook' },
                      { value: 'bark', label: 'Bark (iOS Push)' },
                      { value: 'telegram', label: 'Telegram Bot' },
                      { value: 'wecom', label: 'WeCom Bot' },
                      { value: 'feishu', label: 'Feishu / Lark Bot' },
                      { value: 'dingtalk', label: 'DingTalk Bot' },
                      { value: 'ntfy', label: 'Ntfy' },
                      { value: 'gotify', label: 'Gotify' },
                    ]
                  : [
                      { value: 'webhook', label: '自定义 Webhook' },
                      { value: 'bark', label: 'Bark (iOS 推送)' },
                      { value: 'telegram', label: 'Telegram 机器人' },
                      { value: 'wecom', label: '企业微信机器人' },
                      { value: 'feishu', label: '飞书机器人' },
                      { value: 'dingtalk', label: '钉钉机器人' },
                      { value: 'ntfy', label: 'Ntfy' },
                      { value: 'gotify', label: 'Gotify' },
                    ]
              }
              onchange={onNotifProviderChange}
            />
          </div>
          <div class="field">
            <label for="nf-sev">{t.cfg.lblMinSeverity}</label>
            <Select
              id="nf-sev"
              bind:value={notifDraft.min_severity}
              options={
                lang === 'en'
                  ? [
                      { value: 'info', label: 'Info & Above' },
                      { value: 'warning', label: 'Warning & Above' },
                      { value: 'error', label: 'Error & Above' },
                      { value: 'critical', label: 'Critical Only' },
                    ]
                  : [
                      { value: 'info', label: '普通通知及以上' },
                      { value: 'warning', label: '警告及以上' },
                      { value: 'error', label: '错误及以上' },
                      { value: 'critical', label: '仅严重告警' },
                    ]
              }
            />
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
              <Select id="nf-meth" mono bind:value={notifDraft.method} options={['POST', 'PUT', 'PATCH', 'GET']} />
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
</EditorDialog>
