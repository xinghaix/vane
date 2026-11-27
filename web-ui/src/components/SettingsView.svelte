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
  let subTabsEl = $state(null);
  let subTabsCanLeft = $state(false);
  let subTabsCanRight = $state(false);

  const TIMEZONE_PRESETS = ['auto', 'UTC', '+08:00', '+09:00', '-05:00'];

  function updateSubTabsFade() {
    const el = subTabsEl;
    if (!el) {
      subTabsCanLeft = false;
      subTabsCanRight = false;
      return;
    }
    subTabsCanLeft = el.scrollLeft > 4;
    subTabsCanRight = el.scrollLeft + el.clientWidth < el.scrollWidth - 4;
  }

  $effect(() => {
    const _active = subTab;
    const el = subTabsEl;
    if (!el) return;
    queueMicrotask(() => {
      const btn = el.querySelector(`[data-subtab="${_active}"]`);
      btn?.scrollIntoView({ behavior: 'smooth', inline: 'center', block: 'nearest' });
      updateSubTabsFade();
    });
    const onResize = () => updateSubTabsFade();
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  });

  function handleSubTabSelect(nextSub) {
    if (nextSub === subTab) return;
    if (subTab === 'general' && generalDirty && askConfirm) {
      askConfirm({
        title: t.common.discardConfirmTitle,
        message:
          t.cfg?.unsavedTabConfirm ||
          (lang === 'en'
            ? 'You have unsaved changes in Modules & System. Switch tab and discard them?'
            : '「模块与系统参数」存在尚未保存的修改，切换标签页将放弃这些更改，确认继续？'),
        confirmLabel: t.common.discardConfirmBtn,
        danger: true,
        onConfirm: () => {
          syncGeneralDraft(settingsJson);
          onSubTabChange?.(nextSub);
        },
      });
      return;
    }
    onSubTabChange?.(nextSub);
  }

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

  let secretPathOn = $state(false);
  let lastCustomSecretPath = $state('');

  function syncGeneralDraft(src) {
    if (!src) return;
    const snap = pickGeneralState(src);
    syncedGeneralSig = JSON.stringify(snap);
    generalDraft = deepClone(snap);
    const rawSp = String(snap.admin?.secret_path ?? '/').trim();
    const isCustom = Boolean(rawSp && rawSp !== '/');
    secretPathOn = isCustom;
    if (isCustom) lastCustomSecretPath = rawSp;
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
  let generalDiffStats = $derived.by(() => {
    if (!draftPicked || !basePicked) return { count: 0, needsRestart: false };
    let count = 0;
    let needsRestart = false;
    const restartFields = new Set([
      'system.worker_threads',
      'admin.canonical_origin',
      'admin.listen_lan',
      'admin.tls_cert_path',
      'admin.tls_key_path',
      'firewall.backend',
    ]);
    for (const section of ['system', 'admin', 'firewall', 'security']) {
      const a = draftPicked[section] || {};
      const b = basePicked[section] || {};
      for (const k of Object.keys(a)) {
        if (JSON.stringify(a[k]) !== JSON.stringify(b[k])) {
          count++;
          if (restartFields.has(`${section}.${k}`)) needsRestart = true;
        }
      }
    }
    return { count, needsRestart };
  });
  let generalDirty = $derived(generalDiffStats.count > 0);

  let savedEntryUrl = $derived(
    formatEntryUrl(settingsJson?.admin?.secret_path, settingsJson?.admin?.canonical_origin)
  );
  let draftEntryUrl = $derived(
    secretPathOn ? formatEntryUrl(generalDraft?.admin?.secret_path, generalDraft?.admin?.canonical_origin) : ''
  );

  function normalizeSecretPathValue(raw) {
    const sp = String(raw || '').trim();
    if (!sp || sp === '/') return '/';
    return sp.startsWith('/') ? sp : `/${sp}`;
  }

  let secretPathValid = $derived.by(() => {
    if (!secretPathOn) return true;
    const norm = normalizeSecretPathValue(generalDraft?.admin?.secret_path);
    return /^\/[A-Za-z0-9_-]{8,}$/.test(norm);
  });

  function generateRandomSecretPath() {
    if (!generalDraft) return;
    const buf = new Uint8Array(8);
    crypto.getRandomValues(buf);
    const hex = Array.from(buf, (b) => b.toString(16).padStart(2, '0')).join('');
    const nextPath = `/_vane_${hex}`;
    generalDraft.admin.secret_path = nextPath;
    lastCustomSecretPath = nextPath;
    secretPathOn = true;
  }

  function toggleSecretPath() {
    if (!generalDraft) return;
    if (secretPathOn) {
      const cur = normalizeSecretPathValue(generalDraft.admin.secret_path);
      if (cur !== '/') lastCustomSecretPath = cur;
      secretPathOn = false;
      generalDraft.admin.secret_path = '/';
    } else {
      secretPathOn = true;
      if (lastCustomSecretPath && lastCustomSecretPath !== '/') {
        generalDraft.admin.secret_path = lastCustomSecretPath;
      } else {
        generateRandomSecretPath();
      }
    }
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
    if (!secretPathOn) {
      picked.admin.secret_path = '/';
    } else {
      const normSp = normalizeSecretPathValue(picked.admin.secret_path);
      if (!/^\/[A-Za-z0-9_-]{8,}$/.test(normSp)) {
        showToast(t.cfg.secretPathInvalid, 'error');
        return;
      }
      picked.admin.secret_path = normSp;
    }
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
  let showCurPw = $state(false);
  let showNewPw = $state(false);
  let showConfirmPw = $state(false);
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
  let showRestorePass = $state(false);
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
      showCurPw = false;
      showNewPw = false;
      showConfirmPw = false;
    }
    if (tab !== 'backup') {
      backupPass = '';
      backupPassConfirm = '';
      showBkPass = false;
      restorePass = '';
      showRestorePass = false;
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
  let pwStrengthScore = $derived.by(() => {
    if (!newPw) return 0;
    let s = 0;
    if (pwChecks.lenOk) s++;
    if (pwChecks.hasAlpha && pwChecks.hasDigitOrPunct) s++;
    if (newPwBytes >= 12 && pwChecks.notDefault) s++;
    if (newPwBytes >= 16 && /[A-Z]/.test(newPw) && /[a-z]/.test(newPw) && /[^A-Za-z0-9]/.test(newPw)) s++;
    return Math.min(4, Math.max(1, s));
  });
  let pwStrengthTone = $derived(
    pwStrengthScore <= 1 ? 'danger' : pwStrengthScore === 2 ? 'warn' : 'ok'
  );
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

  function notifProviderLabel(provider) {
    const en = lang === 'en';
    const map = en
      ? {
          webhook: 'Webhook',
          bark: 'Bark',
          telegram: 'Telegram',
          wecom: 'WeCom',
          feishu: 'Feishu',
          dingtalk: 'DingTalk',
          ntfy: 'Ntfy',
          gotify: 'Gotify',
        }
      : {
          webhook: '自定义 Webhook',
          bark: 'Bark',
          telegram: 'Telegram',
          wecom: '企业微信',
          feishu: '飞书',
          dingtalk: '钉钉',
          ntfy: 'Ntfy',
          gotify: 'Gotify',
        };
    return map[provider] || provider;
  }

  function notifSeverityClass(sev) {
    if (sev === 'critical' || sev === 'error') return 'badge-danger';
    if (sev === 'warning') return 'badge-warn';
    return 'badge-info';
  }

  let notifCreds = $derived.by(() => {
    const en = lang === 'en';
    const c = t.cfg?.notifCreds || {};
    return {
      tgToken: c.tgToken || (en ? 'Telegram Bot Token' : 'Telegram 机器人 Token'),
      tgChatId: c.tgChatId || (en ? 'Telegram Chat ID' : 'Telegram Chat ID（会话 ID）'),
      tgProxyUrl: c.tgProxyUrl || (en ? 'Custom Bot API Proxy URL (optional)' : '自定义 Bot API 代理地址（可选）'),
      barkUrl: c.barkUrl || (en ? 'Bark Server URL' : 'Bark 服务地址'),
      barkKey: c.barkKey || (en ? 'Bark Device Key' : 'Bark 设备 Key'),
      gotifyUrl: c.gotifyUrl || (en ? 'Gotify Server URL' : 'Gotify 服务地址'),
      gotifyToken: c.gotifyToken || (en ? 'Gotify App Token' : 'Gotify 应用 Token'),
      ntfyUrl: c.ntfyUrl || (en ? 'Ntfy Topic URL' : 'Ntfy 主题地址'),
      ntfyToken: c.ntfyToken || (en ? 'Bearer Token (optional)' : 'Bearer 认证令牌（可选）'),
      wecomUrl: c.wecomUrl || (en ? 'WeCom Bot Webhook URL' : '企业微信机器人 Webhook 地址'),
      feishuUrl: c.feishuUrl || (en ? 'Feishu Webhook URL' : '飞书机器人 Webhook 地址'),
      dingtalkUrl: c.dingtalkUrl || (en ? 'DingTalk Webhook URL' : '钉钉机器人 Webhook 地址'),
      hmacSecret: c.hmacSecret || (en ? 'HMAC Signing Secret (optional)' : 'HMAC 加签密钥（可选）'),
      webhookUrl: c.webhookUrl || (en ? 'Webhook Endpoint URL' : 'Webhook 回调地址'),
      webhookToken: c.webhookToken || (en ? 'Bearer / Auth Token (optional)' : 'Bearer / 认证令牌（可选）'),
    };
  });

  function toggleNotifEvent(ev) {
    if (!notifDraft) return;
    const list = notifDraft.events || [];
    if (list.includes(ev)) {
      notifDraft.events = list.filter((x) => x !== ev);
    } else {
      notifDraft.events = [...list, ev];
    }
  }

  function selectAllNotifEvents() {
    if (!notifDraft) return;
    notifDraft.events = [...ALL_EVENTS];
  }

  function clearNotifEvents() {
    if (!notifDraft) return;
    notifDraft.events = [];
  }

  function clearRestoreFile() {
    restoreBlobB64 = '';
    restoreFileName = '';
    if (restoreFileInput) restoreFileInput.value = '';
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
  <!-- 顶部子面板导航（带滚动渐变提示与激活项自动居中） -->
  <div
    bind:this={subTabsEl}
    class="underline-tabs sv-subtabs"
    class:fade-left={subTabsCanLeft}
    class:fade-right={subTabsCanRight}
    role="tablist"
    onscroll={updateSubTabsFade}
  >
    <button
      type="button"
      role="tab"
      data-subtab="general"
      aria-selected={subTab === 'general'}
      class="underline-tab {subTab === 'general' ? 'active' : ''}"
      onclick={() => handleSubTabSelect('general')}
    >
      <Icons name="sliders" size={15} />
      <span>{t.cfg.tabGeneral}</span>
      {#if generalDirty}
        <span class="sv-tab-dirty-dot" title={t.common.unsavedChanges}></span>
      {/if}
    </button>
    <button
      type="button"
      role="tab"
      data-subtab="appearance"
      aria-selected={subTab === 'appearance'}
      class="underline-tab {subTab === 'appearance' ? 'active' : ''}"
      onclick={() => handleSubTabSelect('appearance')}
    >
      <Icons name="palette" size={15} />
      <span>{t.cfg.tabAppearance}</span>
    </button>
    <button
      type="button"
      role="tab"
      data-subtab="security"
      aria-selected={subTab === 'security'}
      class="underline-tab {subTab === 'security' ? 'active' : ''}"
      onclick={() => handleSubTabSelect('security')}
    >
      <Icons name="shield" size={15} />
      <span>{t.cfg.tabSecurity}</span>
    </button>
    <button
      type="button"
      role="tab"
      data-subtab="notifications"
      aria-selected={subTab === 'notifications'}
      class="underline-tab {subTab === 'notifications' ? 'active' : ''}"
      onclick={() => handleSubTabSelect('notifications')}
    >
      <Icons name="bell" size={15} />
      <span>{t.cfg.tabNotifications}</span>
      {#if settingsJson.notifications?.length}
        <span class="badge badge-muted num" style="font-size:10.5px;padding:0 6px;">{settingsJson.notifications.length}</span>
      {/if}
    </button>
    <button
      type="button"
      role="tab"
      data-subtab="backup"
      aria-selected={subTab === 'backup'}
      class="underline-tab {subTab === 'backup' ? 'active' : ''}"
      onclick={() => handleSubTabSelect('backup')}
    >
      <Icons name="database" size={15} />
      <span>{t.cfg.tabBackup}</span>
    </button>
    <button
      type="button"
      role="tab"
      data-subtab="update"
      aria-selected={subTab === 'update'}
      class="underline-tab {subTab === 'update' ? 'active' : ''}"
      onclick={() => handleSubTabSelect('update')}
    >
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
        <div class="sv-mode-grid" style="margin-bottom:16px;">
          {#each [
            { id: 'auto', icon: 'contrast', label: t.themeAuto, desc: t.cfg.themeAutoDesc },
            { id: 'light', icon: 'sun', label: t.themeLight, desc: t.cfg.themeLightDesc },
            { id: 'dark', icon: 'moon', label: t.themeDark, desc: t.cfg.themeDarkDesc },
          ] as m (m.id)}
            <button
              type="button"
              class="sv-mode-card {themeMode === m.id ? 'active' : ''}"
              aria-pressed={themeMode === m.id}
              onclick={() => onSelectThemeMode?.(m.id)}
            >
              <span class="sv-mode-preview sv-mode-preview-{m.id}" aria-hidden="true">
                <span class="sv-prev-bar"></span>
                <span class="sv-prev-cards">
                  <span></span>
                  <span></span>
                </span>
              </span>
              <div class="sv-mode-head">
                <Icons name={m.icon} size={14} />
                <span class="sv-mode-label">{m.label}</span>
              </div>
              <div class="sv-mode-desc">{m.desc}</div>
            </button>
          {/each}
        </div>

        <div class="section-label">{t.themeAccentLabel}</div>
        <div class="accent-grid sv-accent-grid">
          {#each accentPresets as ap (ap.id)}
            <button
              type="button"
              class="accent-card sv-accent-card {accentColor === ap.id ? 'active' : ''}"
              aria-pressed={accentColor === ap.id}
              onclick={() => onSelectAccentColor?.(ap.id)}
            >
              <span
                class="accent-swatch-dot"
                style={`background:${ap.color};${accentColor === ap.id ? `box-shadow:0 0 0 3px color-mix(in srgb, ${ap.color} 28%, transparent);` : ''}`}
              >
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
        <div class="appearance-lang-grid sv-lang-grid" style="margin-bottom:18px;">
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
              <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
                <span class="settings-row-label">{t.cfg.oledModeLabel}</span>
                {#if themeMode === 'light'}
                  <span class="badge badge-muted" style="font-size:10.5px;padding:1px 6px;">
                    {lang === 'en' ? 'Dark mode only' : '仅深色模式生效'}
                  </span>
                {/if}
              </div>
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

  <!-- 1. 子功能模块中心 + 全局核心与共用基础设置 -->
  {#if subTab === 'general'}
    <div class="card" style="margin-bottom:22px;">
      <div class="card-header">
        <div>
          <div class="card-title">{t.cfg.modulesTitle}</div>
          <div style="font-size:12px;color:var(--text-secondary);margin-top:2px;">
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
          <div class="subcard module-card sv-mod-card" class:is-enabled={modOn}>
            <div class="sv-mod-head">
              <div style="display:flex;align-items:center;gap:9px;min-width:0;flex:1;">
                <span class="icon-tile sm {modOn ? '' : 'muted'}">
                  <Icons name={key} size={15} />
                </span>
                <span class="sv-mod-title" title={title}>{title}</span>
              </div>
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
            <div class="module-card-reauth {reauthOn ? 'active' : ''} {!modOn ? 'disabled' : ''}">
              <span style="display:inline-flex;align-items:center;gap:6px;min-width:0;flex-wrap:wrap;">
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
            <div class="module-card-foot sv-mod-foot">
              <span class="module-card-summary" title={mod.sharedTag || ''}>
                {modOn ? mod.sharedTag || t.enabled : t.disabled}
              </span>
              {#if modOn && onNavigate}
                <button type="button" class="btn btn-ghost btn-xs sv-mod-open" onclick={() => onNavigate(key)}>
                  <span>{t.cfg.moduleOpenViewBtn}</span>
                  <Icons name="chevron_right" size={12} />
                </button>
              {/if}
            </div>
          </div>
        {/each}
      </div>
    </div>

    {#if generalDraft}
      <form onsubmit={saveGeneralSettings}>
        <!-- 板块二：总体系统设置 -->
        <div class="settings-tier-head">
          <div style="min-width:0;flex:1;">
            <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
              <div class="settings-tier-title">{t.cfg.globalTierTitle}</div>
              {#if generalDirty}
                <span class="badge badge-warn num" style="font-size:11px;">
                  {(t.cfg?.changedCount || (lang === 'en' ? '{n} unsaved' : '已修改 {n} 项')).replace('{n}', String(generalDiffStats.count))}
                </span>
              {/if}
            </div>
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

        <div class="banner banner-warn sv-origin-banner">
          <div class="banner-main">
            <Icons name="alert" size={17} />
            <div style="min-width:0;flex:1;">
              <div style="font-weight:700;">{t.cfg.originWarnTitle}</div>
              <div style="color:var(--text-secondary);font-size:12.5px;margin-top:2px;">{t.cfg.originWarnDesc}</div>
              {#if savedEntryUrl}
                <div class="sv-entry-url-row">
                  <span style="font-size:12px;color:var(--text-secondary);">{t.cfg.savedEntryUrl}:</span>
                  <code class="mono code-chip sv-url-chip">{savedEntryUrl}</code>
                  <button type="button" class="btn btn-xs" onclick={() => handleCopy(savedEntryUrl)}>
                    <Icons name="copy" size={12} />
                    <span>{t.copy}</span>
                  </button>
                </div>
              {/if}
              {#if draftEntryUrl && draftEntryUrl !== savedEntryUrl}
                <div class="sv-entry-url-row">
                  <span style="font-size:12px;color:var(--warn);font-weight:600;">{t.cfg.previewEntryUrl}:</span>
                  <code class="mono code-chip sv-url-chip sv-url-chip-draft">{draftEntryUrl}</code>
                  <button type="button" class="btn btn-xs" onclick={() => handleCopy(draftEntryUrl)}>
                    <Icons name="copy" size={12} />
                    <span>{t.copy}</span>
                  </button>
                </div>
              {:else if savedEntryUrl && !secretPathOn}
                <div class="sv-entry-url-row">
                  <span style="font-size:12px;color:var(--warn);font-weight:600;">{t.cfg.secretPathDisablePreview}</span>
                </div>
              {/if}
            </div>
          </div>
        </div>

        <!-- 分组 1：核心运行与管理入口 -->
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
                <div class="sv-preset-chips">
                  {#each TIMEZONE_PRESETS as tz (tz)}
                    <button
                      type="button"
                      class="sv-mini-chip mono {generalDraft.system.timezone_offset === tz ? 'active' : ''}"
                      onclick={() => (generalDraft.system.timezone_offset = tz)}
                    >
                      {tz}
                    </button>
                  {/each}
                </div>
              </div>
            </div>
            <div class="settings-row">
              <div class="settings-row-info">
                <label class="settings-row-label sv-label-with-badge" for="st-wk">
                  <span>{t.cfg.workerThreads}</span>
                  <span class="badge badge-warn" style="font-size:10px;padding:1px 6px;">{t.common.restartReqBadge}</span>
                </label>
                <div class="settings-row-desc">{t.cfg.descWorkerThreads}</div>
              </div>
              <div class="settings-row-control">
                <input id="st-wk" type="number" min="1" max="8" bind:value={generalDraft.system.worker_threads} required />
              </div>
            </div>
            <div class="sv-sp-block">
              <div class="settings-row switch-row sv-sp-head-row">
                <div class="settings-row-info">
                  <span class="settings-row-label sv-label-with-badge">
                    <span>{t.cfg.lblSecretPath}</span>
                    <span class="badge {secretPathOn ? 'badge-ok' : 'badge-muted'}" style="font-size:10.5px;padding:1px 7px;">
                      {secretPathOn ? t.cfg.secretPathStateOn : t.cfg.secretPathStateOff}
                    </span>
                  </span>
                  <div class="settings-row-desc">
                    {secretPathOn ? t.cfg.descSecretPath : t.cfg.descSecretPathOff}
                  </div>
                </div>
                <button
                  type="button"
                  class="switch"
                  role="switch"
                  aria-checked={secretPathOn}
                  aria-label={t.cfg.lblSecretPath}
                  onclick={toggleSecretPath}
                >
                  <span class="switch-thumb"></span>
                </button>
              </div>
              {#if secretPathOn}
                <div class="sv-sp-panel">
                  <div class="sv-sp-row">
                    <input
                      id="st-sp"
                      type="text"
                      class="mono sv-sp-input"
                      class:sv-input-invalid={!secretPathValid}
                      placeholder="/my-gateway"
                      aria-label={t.cfg.lblSecretPath}
                      aria-invalid={!secretPathValid}
                      bind:value={generalDraft.admin.secret_path}
                      oninput={() => {
                        const v = String(generalDraft?.admin?.secret_path || '').trim();
                        if (v && v !== '/') lastCustomSecretPath = v;
                      }}
                    />
                    <div class="sv-sp-actions">
                      <button type="button" class="btn btn-sm sv-sp-btn" onclick={generateRandomSecretPath}>
                        <Icons name="key" size={13} />
                        <span>{t.cfg.genRandomPath}</span>
                      </button>
                      {#if draftEntryUrl && secretPathValid}
                        <button type="button" class="btn btn-sm sv-sp-btn" onclick={() => handleCopy(draftEntryUrl)}>
                          <Icons name="copy" size={13} />
                          <span>{t.cfg.copyEntryUrl}</span>
                        </button>
                      {/if}
                    </div>
                  </div>
                  <div class="sv-sp-hint" class:sv-sp-hint-error={!secretPathValid}>
                    {secretPathValid ? t.cfg.secretPathFormatHint : t.cfg.secretPathInvalid}
                  </div>
                </div>
              {/if}
            </div>
            <div class="settings-row">
              <div class="settings-row-info">
                <label class="settings-row-label sv-label-with-badge" for="st-org">
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
                <label class="settings-row-label sv-label-with-badge" for="st-ll">
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
                <div class="settings-row-label sv-label-with-badge">
                  <span>{t.cfg.tlsCertPath}</span>
                  <span class="badge badge-warn" style="font-size:10px;padding:1px 6px;">{t.common.restartReqBadge}</span>
                </div>
                <div class="settings-row-desc">{t.cfg.tlsKeyPath}</div>
              </div>
              <div class="settings-row-control" style="gap:8px;">
                <div class="sv-sub-field">
                  <label class="sv-sub-label" for="st-tcert">{lang === 'en' ? 'TLS Certificate Path' : '证书路径 (Cert)'}</label>
                  <input id="st-tcert" type="text" class="mono" placeholder="/etc/vane/admin.crt" bind:value={generalDraft.admin.tls_cert_path} />
                </div>
                <div class="sv-sub-field">
                  <label class="sv-sub-label" for="st-tkey">{lang === 'en' ? 'TLS Private Key Path' : '私钥路径 (Key)'}</label>
                  <input id="st-tkey" type="text" class="mono" placeholder="/etc/vane/admin.key" bind:value={generalDraft.admin.tls_key_path} />
                </div>
              </div>
            </div>
          </div>
        </section>

        <!-- 分组 2：安全防爆破与协议超时 -->
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
                <div class="settings-row-label">Fail2Ban</div>
                <div class="settings-row-desc">{t.cfg.lblMaxFailures} · {t.cfg.lblBanDuration}</div>
              </div>
              <div class="settings-row-control">
                <div class="sv-paired-grid">
                  <div class="sv-sub-field">
                    <label class="sv-sub-label" for="st-f2b">
                      {lang === 'en' ? 'Max Failures (3~20)' : '失败次数阈值 (3~20)'}
                    </label>
                    <div class="sv-unit-wrap">
                      <input id="st-f2b" type="number" min="3" max="20" bind:value={generalDraft.security.max_login_failures} required />
                      <span class="sv-unit-tag">{lang === 'en' ? 'x' : '次'}</span>
                    </div>
                  </div>
                  <div class="sv-sub-field">
                    <label class="sv-sub-label" for="st-bds">
                      {lang === 'en' ? 'Ban Duration (60~86400)' : '封禁时长 (60~86400)'}
                    </label>
                    <div class="sv-unit-wrap">
                      <input id="st-bds" type="number" min="60" max="86400" bind:value={generalDraft.security.ban_duration_secs} required />
                      <span class="sv-unit-tag">{lang === 'en' ? 's' : '秒'}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <div class="settings-row">
              <div class="settings-row-info">
                <div class="settings-row-label">{t.cfg.tlsHsTimeout} / {t.cfg.hdrTimeout}</div>
                <div class="settings-row-desc">{lang === 'en' ? 'TLS Handshake (2~30s) · HTTP Header (3~60s)' : '握手超时 (2~30秒) · 请求头超时 (3~60秒)'}</div>
              </div>
              <div class="settings-row-control">
                <div class="sv-paired-grid">
                  <div class="sv-sub-field">
                    <label class="sv-sub-label" for="st-tlshs">{t.cfg.tlsHsTimeout}</label>
                    <div class="sv-unit-wrap">
                      <input id="st-tlshs" type="number" min="2" max="30" bind:value={generalDraft.security.tls_handshake_timeout_secs} required />
                      <span class="sv-unit-tag">{lang === 'en' ? 's' : '秒'}</span>
                    </div>
                  </div>
                  <div class="sv-sub-field">
                    <label class="sv-sub-label" for="st-hdrt">{t.cfg.hdrTimeout}</label>
                    <div class="sv-unit-wrap">
                      <input id="st-hdrt" type="number" min="3" max="60" bind:value={generalDraft.security.http_header_timeout_secs} required />
                      <span class="sv-unit-tag">{lang === 'en' ? 's' : '秒'}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        <!-- 板块三：多模块共用基础设置 -->
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
              <div class="banner-main">
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
                <label class="settings-row-label sv-label-with-badge" for="st-fwb">
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
              <div class="settings-row action-row sv-action-row">
                <div class="settings-row-info">
                  <span class="settings-row-label">
                    {dnsProviderNames.length
                      ? t.cfg.sharedDnsCount.replace('{n}', String(dnsProviderNames.length))
                      : t.cfg.sharedDnsEmpty}
                  </span>
                  <div class="settings-row-desc">{t.cfg.sharedDnsDesc}</div>
                </div>
                <div class="sv-dns-badges">
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
          <div class="floating-save-bar sv-save-bar">
            <div class="sv-save-bar-info">
              <Icons name="info" size={15} />
              <span>{t.common.unsavedChanges}</span>
              <span class="badge badge-warn num" style="font-size:11px;padding:1px 7px;">
                {generalDiffStats.count}
              </span>
              {#if generalDiffStats.needsRestart}
                <span class="badge badge-muted" style="font-size:10.5px;padding:1px 6px;">
                  {t.common.restartReqBadge}
                </span>
              {/if}
            </div>
            <div class="btn-group sv-save-bar-actions">
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
          <span class="card-title"><Icons name="key" size={16} />{t.cfg.pwTitle}</span>
        </div>
        <form onsubmit={updateAdminCredentials}>
          <div class="field">
            <label for="sec-un">{t.cfg.newUsername}</label>
            <input id="sec-un" type="text" placeholder={settingsJson.admin.username} bind:value={newUsername} autocomplete="username" />
          </div>
          <div class="field">
            <label for="sec-cp">{t.curPw}</label>
            <div class="input-wrap sv-pw-wrap">
              <input id="sec-cp" type={showCurPw ? 'text' : 'password'} bind:value={curPw} autocomplete="current-password" required />
              <button
                type="button"
                class="btn btn-ghost btn-xs input-addon-btn sv-eye-btn"
                aria-label={t.common.toggleSecret}
                onclick={() => (showCurPw = !showCurPw)}
              >
                <Icons name={showCurPw ? 'eye_off' : 'eye'} size={15} />
              </button>
            </div>
          </div>
          <div class="field">
            <label for="sec-np">{t.newPw}</label>
            <div class="input-wrap sv-pw-wrap">
              <input id="sec-np" type={showNewPw ? 'text' : 'password'} bind:value={newPw} autocomplete="new-password" required />
              <button
                type="button"
                class="btn btn-ghost btn-xs input-addon-btn sv-eye-btn"
                aria-label={t.common.toggleSecret}
                onclick={() => (showNewPw = !showNewPw)}
              >
                <Icons name={showNewPw ? 'eye_off' : 'eye'} size={15} />
              </button>
            </div>
            {#if newPw}
              <div class="sv-strength-bar" aria-hidden="true">
                {#each [1, 2, 3, 4] as step (step)}
                  <span class="sv-strength-seg {step <= pwStrengthScore ? `tone-${pwStrengthTone}` : ''}"></span>
                {/each}
              </div>
            {/if}
          </div>
          <div class="field">
            <label for="sec-cnp">{t.confirmPw}</label>
            <div class="input-wrap sv-pw-wrap">
              <input id="sec-cnp" type={showConfirmPw ? 'text' : 'password'} bind:value={confirmPw} autocomplete="new-password" required />
              <button
                type="button"
                class="btn btn-ghost btn-xs input-addon-btn sv-eye-btn"
                aria-label={t.common.toggleSecret}
                onclick={() => (showConfirmPw = !showConfirmPw)}
              >
                <Icons name={showConfirmPw ? 'eye_off' : 'eye'} size={15} />
              </button>
            </div>
          </div>

          <div class="subcard sv-checklist" style="margin-bottom:14px;">
            {#each [
              { ok: pwChecks.lenOk, label: t.ruleLen },
              { ok: pwChecks.hasAlpha, label: t.ruleAlpha },
              { ok: pwChecks.hasDigitOrPunct, label: t.ruleDigit },
              { ok: pwChecks.notDefault, label: t.ruleNotDefault },
              { ok: pwChecks.matchConfirm, label: t.ruleMatch },
            ] as chk (chk.label)}
              <div class="sv-check-item" class:ok={chk.ok}>
                <span class="sv-check-icon">
                  {#if chk.ok}
                    <Icons name="check" size={12} />
                  {:else}
                    <span class="sv-check-dot"></span>
                  {/if}
                </span>
                <span>{chk.label}</span>
              </div>
            {/each}
          </div>

          <button type="submit" class="btn btn-primary btn-sm" disabled={!pwAllValid || Boolean(secBusy)}>
            {secBusy === 'pw' ? '...' : t.cfg.updatePw}
          </button>
        </form>
      </div>

      <!-- TOTP 双因素认证 -->
      <div class="card">
        <div class="card-header">
          <span class="card-title"><Icons name="shield" size={16} />{lang === 'en' ? 'Authenticator App (TOTP)' : '动态口令验证 (TOTP)'}</span>
          <span class="badge {settingsJson.admin.totp_enabled ? 'badge-ok' : 'badge-muted'}">
            {settingsJson.admin.totp_enabled ? t.enabled : t.disabled}
          </span>
        </div>

        {#if settingsJson.admin.totp_enabled}
          {@const remCodes = settingsJson.admin.totp_recovery_hashes?.remaining ?? 0}
          <div class="subcard sv-totp-status" class:is-low={remCodes <= 2}>
            <div class="row-between" style="gap:8px;">
              <span style="font-size:13px;font-weight:600;">
                {lang === 'en' ? 'Two-factor authentication is active' : '两步验证已开启并生效'}
              </span>
              <span class="badge {remCodes <= 2 ? 'badge-warn' : 'badge-ok'} num">
                {lang === 'en' ? `${remCodes} recovery codes left` : `剩余 ${remCodes} 枚恢复码`}
              </span>
            </div>
            {#if remCodes <= 2}
              <div style="font-size:12px;color:var(--warn);margin-top:6px;">
                {lang === 'en'
                  ? 'Low remaining recovery codes — consider regenerating a fresh backup set.'
                  : '剩余一次性恢复码较少，建议重新生成并离线妥善保存。'}
              </div>
            {/if}
          </div>
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
              <Icons name="refresh" size={13} />
              <span>{secBusy === 'totp-regen' ? '...' : t.cfg.totpRegen}</span>
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
          <p style="font-size:13px;color:var(--text-secondary);margin-bottom:14px;line-height:1.55;">{t.cfg.totpDescOff}</p>
          <button type="button" class="btn btn-primary btn-sm" disabled={Boolean(secBusy)} onclick={startTotpSetup}>
            <Icons name="shield" size={14} />
            <span>{secBusy === 'totp-setup' ? '...' : t.cfg.totpSetup}</span>
          </button>
        {:else}
          {@const qrSrc = safeQrDataUri(totpSetupData.otpauth_uri)}
          <form onsubmit={confirmTotpEnable}>
            <div style="font-size:13px;color:var(--text-secondary);margin-bottom:6px;">{t.cfg.totpScanHint}</div>
            <div style="font-size:11.5px;color:var(--warn);margin-bottom:10px;">{t.cfg.totpSetupTtlHint}</div>
            <div class="sv-totp-setup-grid">
              {#if qrSrc}
                <img
                  src={qrSrc}
                  alt="TOTP QR"
                  class="sv-qr-img"
                />
              {:else}
                <div class="banner banner-warn" style="margin:0;">{t.cfg.qrTooLong}</div>
              {/if}
              <div class="subcard sv-totp-secrets">
                <div class="row-between" style="gap:10px;">
                  <div style="min-width:0;flex:1;">
                    <div style="font-size:11.5px;color:var(--text-muted);font-weight:600;">Base32 Secret</div>
                    <div class="mono" style="font-size:13px;font-weight:600;margin-top:2px;word-break:break-all;">
                      {maskTotpSecret(totpSetupData.secret_base32)}
                    </div>
                  </div>
                  <button type="button" class="btn btn-xs" onclick={() => handleCopy(totpSetupData.secret_base32)}>
                    <Icons name="copy" size={12} />
                    <span>{lang === 'en' ? 'Copy Secret' : '复制密钥'}</span>
                  </button>
                </div>
                <div class="row-between" style="gap:10px;padding-top:10px;border-top:1px solid var(--border-subtle);">
                  <div style="min-width:0;flex:1;">
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
                class="mono sv-otp-input"
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
          <div class="subcard sv-recovery-box">
            <div class="row-between" style="margin-bottom:10px;gap:8px;flex-wrap:wrap;">
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
            <div class="mono sv-recovery-grid">
              {#each issuedRecoveryCodes as rc (rc)}
                <div class="sv-recovery-chip">{rc}</div>
              {/each}
            </div>
          </div>
        {/if}
      </div>
    </div>

    <!-- 通行密钥 Passkey (WebAuthn / FIDO2) -->
    {@const pkList = settingsJson.admin.passkeys || []}
    {@const passkeyActive = Boolean(settingsJson.admin.passkey_enabled) && pkList.length > 0}
    {@const pwLoginOn = Boolean(settingsJson.admin.password_login_enabled)}
    <div class="card">
      <div class="card-header">
        <div style="min-width:0;flex:1;">
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
            <Icons name="trash" size={13} />
            <span>{secBusy === 'pk-toggle' ? '...' : t.cfg.passkeyDisableAllBtn}</span>
          </button>
        {/if}
      </div>

      {#if passkeyActive}
        <div class="settings-list" style="margin-bottom:14px;">
          <div class="settings-row switch-row" style="padding:12px 16px;">
            <div class="settings-row-info">
              <span class="settings-row-label">
                {lang === 'en' ? 'Allow Password Sign-In' : '允许密码登录'}
              </span>
              <div class="settings-row-desc">{t.cfg.allowPwLogin}</div>
            </div>
            <div class="settings-row-control">
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
          </div>
        </div>
      {/if}

      {#if !passkeyBrowserOk}
        <div class="banner banner-warn" style="margin-bottom:12px;">
          <div class="banner-main">
            <Icons name="alert" size={16} />
            <span>{t.cfg.passkeyUnsupported}</span>
          </div>
        </div>
      {:else if passkeyOnRawIp}
        <div class="banner banner-info" style="margin-bottom:12px;">
          <div class="banner-main">
            <Icons name="info" size={16} />
            <span>{t.cfg.passkeyIpWarn}</span>
          </div>
        </div>
      {/if}

      {#if passkeyActive && !pwLoginOn}
        <div class="banner banner-warn" style="margin-bottom:12px;">
          <div class="banner-main">
            <Icons name="alert" size={15} />
            <span>{t.cfg.passkeyLastAuthHint}</span>
          </div>
        </div>
      {/if}

      {#if pkList.length}
        <div class="settings-list" style="margin-bottom:14px;">
          {#each pkList as pk (pk.id)}
            {@const isLastProtectedKey = !pwLoginOn && pkList.length <= 1}
            <div class="settings-row action-row sv-action-row" style="padding:12px 16px;">
              <div style="display:flex;align-items:center;gap:12px;min-width:0;">
                <span class="icon-tile sm"><Icons name="passkey" size={15} /></span>
                <div style="min-width:0;flex:1;">
                  <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
                    <span style="font-weight:600;font-size:13.5px;word-break:break-word;">{pk.name}</span>
                    <span class="badge badge-info mono badge-trunc" style="font-size:11px;">{pk.rp_id}</span>
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
              <div class="sv-row-actions">
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
                  <Icons name="trash" size={12} />
                  <span>{secBusy === `pk-del:${pk.id}` ? '...' : t.delete}</span>
                </button>
              </div>
            </div>
          {/each}
        </div>
      {:else}
        <div style="font-size:12.5px;color:var(--text-secondary);margin-bottom:12px;">{t.cfg.passkeyEmpty}</div>
      {/if}

      <form onsubmit={registerPasskey} class="sv-passkey-form">
        <input
          type="text"
          class="sv-passkey-input"
          maxlength="64"
          placeholder={t.cfg.passkeyNamePh}
          aria-label={t.cfg.passkeyNamePh}
          disabled={Boolean(secBusy) || pkList.length >= 16}
          bind:value={newPasskeyName}
        />
        <button
          type="submit"
          class="btn btn-primary sv-passkey-submit"
          disabled={Boolean(secBusy) || !passkeyBrowserOk || passkeyOnRawIp || pkList.length >= 16}
        >
          <Icons name="passkey" size={15} />
          <span>{secBusy === 'pk-add' ? '...' : pkList.length ? t.cfg.passkeyAddBtn : t.cfg.passkeyAddFirstBtn}</span>
        </button>
      </form>
    </div>
  {/if}

  <!-- 3. 外部多渠道通知设置 -->
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
        <div class="empty-state-rich">
          <span class="empty-state-icon"><Icons name="bell" size={22} /></span>
          <div class="empty-state-desc">{t.common.empty}</div>
          <button type="button" class="btn btn-primary btn-sm" style="margin-top:10px;" onclick={() => openNotifDrawer(-1)}>
            <Icons name="plus" size={14} />
            <span>{t.add}</span>
          </button>
        </div>
      {:else}
        <div class="settings-list">
          {#each settingsJson.notifications as n, idx (n.name)}
            {@const evList = n.events || []}
            <div class="settings-row action-row sv-action-row" style="padding:14px 18px;">
              <div style="display:flex;align-items:flex-start;gap:12px;min-width:0;">
                <span class="icon-tile sm {n.enabled ? '' : 'muted'}">
                  <Icons name="bell" size={15} />
                </span>
                <div style="min-width:0;flex:1;">
                  <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
                    <span style="font-weight:600;font-size:14px;word-break:break-word;">{n.name}</span>
                    <span class="badge badge-info">{notifProviderLabel(n.provider)}</span>
                    <span class="badge {notifSeverityClass(n.min_severity)}">&gt;= {n.min_severity}</span>
                    {#if !n.enabled}<span class="badge badge-muted">{t.disabled}</span>{/if}
                  </div>
                  <div class="meta-row sv-event-meta">
                    {#if evList.length}
                      {#each evList.slice(0, 4) as ev (ev)}
                        <span class="meta-chip">{t.events?.[ev] || ev}</span>
                      {/each}
                      {#if evList.length > 4}
                        <span class="meta-chip num">+{evList.length - 4}</span>
                      {/if}
                    {:else}
                      <span class="meta-chip">{t.cfg.allEvents}</span>
                    {/if}
                  </div>
                </div>
              </div>
              <div class="btn-group sv-row-actions">
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
                <button type="button" class="btn btn-xs btn-soft" disabled={Boolean(busyNotif)} onclick={() => testNotification(n.name)}>
                  <Icons name="play" size={11} />
                  <span>{busyNotif === n.name ? '...' : t.cfg.testPush}</span>
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
      <div class="banner-main">
        <Icons name="shield" size={17} />
        <div style="min-width:0;flex:1;">
          <div style="font-weight:700;">{t.cfg.bkScopeTitle}</div>
          <div style="font-size:12.5px;color:var(--text-secondary);margin-top:2px;">{t.cfg.bkScopeItems}</div>
        </div>
      </div>
    </div>

    <div class="bento-grid-2">
      <form class="card" onsubmit={exportEncryptedBackup}>
        <div class="card-header">
          <span class="card-title"><Icons name="download" size={16} />{t.cfg.bkExportTitle}</span>
        </div>
        <p style="font-size:13px;color:var(--text-secondary);margin-bottom:14px;line-height:1.5;">{t.cfg.bkExportDesc}</p>
        <div class="field">
          <label for="bk-pw">{t.cfg.bkExportPw}</label>
          <div class="input-wrap sv-pw-wrap">
            <input id="bk-pw" type={showBkPass ? 'text' : 'password'} minlength="8" maxlength="128" autocomplete="new-password" bind:value={backupPass} required />
            <button
              type="button"
              class="btn btn-ghost btn-xs input-addon-btn sv-eye-btn"
              aria-label={t.common.toggleSecret}
              onclick={() => (showBkPass = !showBkPass)}
            >
              <Icons name={showBkPass ? 'eye_off' : 'eye'} size={15} />
            </button>
          </div>
        </div>
        <div class="field">
          <label for="bk-pw2">{t.cfg.bkExportPwConfirm}</label>
          <input id="bk-pw2" type={showBkPass ? 'text' : 'password'} minlength="8" maxlength="128" autocomplete="new-password" bind:value={backupPassConfirm} required />
          {#if backupPassConfirm && backupPass !== backupPassConfirm}
            <div style="font-size:12px;color:var(--danger);margin-top:4px;">{t.cfg.bkPwMismatch}</div>
          {/if}
        </div>
        <div class="subcard sv-checklist" style="margin-bottom:14px;">
          {#each [
            { ok: bkChecks.lenOk, label: t.ruleLen },
            { ok: bkChecks.hasAlpha, label: t.ruleAlpha },
            { ok: bkChecks.hasDigitOrPunct, label: t.ruleDigit },
            { ok: bkChecks.matchConfirm, label: t.ruleMatch },
          ] as chk (chk.label)}
            <div class="sv-check-item" class:ok={chk.ok}>
              <span class="sv-check-icon">
                {#if chk.ok}
                  <Icons name="check" size={12} />
                {:else}
                  <span class="sv-check-dot"></span>
                {/if}
              </span>
              <span>{chk.label}</span>
            </div>
          {/each}
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

      <form class="card danger-zone-card sv-danger-card" onsubmit={importEncryptedBackup}>
        <div class="card-header">
          <span class="card-title" style="color:var(--danger);">
            <Icons name="upload" size={16} />
            <span>{t.cfg.bkImportTitle}</span>
          </span>
          <span class="badge badge-danger" style="font-size:11px;">
            {lang === 'en' ? 'Overwrites Config' : '覆盖当前配置'}
          </span>
        </div>
        <div class="banner banner-danger" style="margin-bottom:14px;padding:10px 12px;">
          <div class="banner-main">
            <Icons name="alert" size={15} />
            <span style="font-size:12px;line-height:1.45;">{t.cfg.bkImportConfirm}</span>
          </div>
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
          {#if restoreFileName}
            <div class="sv-valid-file">
              <Icons name="check" size={13} />
              <span class="mono sv-valid-file-name" title={restoreFileName}>{restoreFileName}</span>
              <button
                type="button"
                class="btn btn-ghost btn-xs"
                style="min-height:24px;padding:0 5px;"
                aria-label={t.common?.clearAll || (lang === 'en' ? 'Clear file' : '清除文件')}
                onclick={clearRestoreFile}
              >
                <Icons name="x" size={12} />
              </button>
            </div>
          {/if}
        </div>
        <div class="field">
          <label for="bk-rpw">{t.cfg.bkImportPw}</label>
          <div class="input-wrap sv-pw-wrap">
            <input id="bk-rpw" type={showRestorePass ? 'text' : 'password'} minlength="8" autocomplete="off" bind:value={restorePass} required />
            <button
              type="button"
              class="btn btn-ghost btn-xs input-addon-btn sv-eye-btn"
              aria-label={t.common.toggleSecret}
              onclick={() => (showRestorePass = !showRestorePass)}
            >
              <Icons name={showRestorePass ? 'eye_off' : 'eye'} size={15} />
            </button>
          </div>
        </div>
        <button type="submit" class="btn btn-danger btn-sm" disabled={!restoreBlobB64 || Boolean(backupBusy)}>
          <Icons name="upload" size={14} />
          <span>{backupBusy === 'import' ? '...' : t.cfg.bkImportBtn}</span>
        </button>
      </form>
    </div>

    <div class="card">
      <div class="card-header">
        <div style="min-width:0;flex:1;">
          <span class="card-title"><Icons name="logs" size={16} />{t.cfg.sanitizedTitle}</span>
          {#if !sanitizedPreview}
            <div style="font-size:12px;color:var(--text-secondary);margin-top:2px;">
              {lang === 'en'
                ? 'Generates a read-only TOML snapshot with all passwords, API tokens, private keys, and secret paths redacted for safe sharing.'
                : '生成只读 TOML 排障快照，自动抹除全部口令、API 令牌、私钥与安全入口路径，便于安全提交问题反馈。'}
            </div>
          {/if}
        </div>
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
        <pre class="mono sv-toml-pre">{sanitizedPreview}</pre>
      {/if}
    </div>
  {/if}

  <!-- 5. 系统更新管理 -->
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

        <!-- 按服务商动态显示双语凭据字段 -->
        {#if notifDraft.provider === 'telegram'}
          <div class="form-grid">
            <SecretField
              id="nf-tok"
              label={notifCreds.tgToken}
              original={notifDraft.token}
              bind:value={notifTokenInput}
              bind:clear={notifTokenClear}
              placeholder="123456:ABC-DEF..."
              required={true}
              {t}
            />
            <div class="field">
              <label for="nf-chat">{notifCreds.tgChatId}</label>
              <input id="nf-chat" type="text" class="mono" placeholder="-1001234567890" bind:value={notifDraft.chat_id} required />
            </div>
          </div>
          <SecretField
            id="nf-url"
            label={notifCreds.tgProxyUrl}
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
              label={notifCreds.barkUrl}
              original={notifDraft.url}
              bind:value={notifUrlInput}
              bind:clear={notifUrlClear}
              placeholder="https://api.day.app"
              required={true}
              {t}
            />
            <SecretField
              id="nf-tok"
              label={notifCreds.barkKey}
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
              label={notifCreds.gotifyUrl}
              original={notifDraft.url}
              bind:value={notifUrlInput}
              bind:clear={notifUrlClear}
              placeholder="https://gotify.example.com"
              required={true}
              {t}
            />
            <SecretField
              id="nf-tok"
              label={notifCreds.gotifyToken}
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
              label={notifCreds.ntfyUrl}
              original={notifDraft.url}
              bind:value={notifUrlInput}
              bind:clear={notifUrlClear}
              placeholder="https://ntfy.sh/my-vane-alerts"
              required={true}
              {t}
            />
            <SecretField
              id="nf-tok"
              label={notifCreds.ntfyToken}
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
            label={notifCreds.wecomUrl}
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
            label={notifDraft.provider === 'feishu' ? notifCreds.feishuUrl : notifCreds.dingtalkUrl}
            original={notifDraft.url}
            bind:value={notifUrlInput}
            bind:clear={notifUrlClear}
            placeholder="https://..."
            required={true}
            {t}
          />
          <SecretField
            id="nf-sec"
            label={notifCreds.hmacSecret}
            original={notifDraft.secret}
            bind:value={notifSecretInput}
            bind:clear={notifSecretClear}
            placeholder="SEC..."
            {t}
          />
        {:else}
          <SecretField
            id="nf-url"
            label={notifCreds.webhookUrl}
            original={notifDraft.url}
            bind:value={notifUrlInput}
            bind:clear={notifUrlClear}
            placeholder="https://..."
            required={true}
            {t}
          />
          <SecretField
            id="nf-tok"
            label={notifCreds.webhookToken}
            original={notifDraft.token}
            bind:value={notifTokenInput}
            bind:clear={notifTokenClear}
            placeholder="Optional"
            {t}
          />
        {/if}

        <div class="field">
          <div class="row-between" style="gap:8px;margin-bottom:4px;">
            <span style="font-size:12.5px;font-weight:600;color:var(--text-secondary);">
              {t.cfg.eventsLabel}
              {#if notifDraft.events?.length}
                <span class="badge badge-info num" style="font-size:10.5px;padding:0 6px;margin-left:4px;">
                  {notifDraft.events.length}/{ALL_EVENTS.length}
                </span>
              {/if}
            </span>
            <div class="btn-group" style="gap:4px;">
              <button type="button" class="btn btn-ghost btn-xs" data-dirty="1" onclick={selectAllNotifEvents}>
                {t.common?.selectAll || (lang === 'en' ? 'Select all' : '全选')}
              </button>
              <button type="button" class="btn btn-ghost btn-xs" data-dirty="1" onclick={clearNotifEvents}>
                {t.common?.clearAll || (lang === 'en' ? 'Clear (All)' : '清空 (全部)')}
              </button>
            </div>
          </div>
          <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:2px;">
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

        <details class="details-card sv-details" style="margin-top:12px;">
          <summary>
            <span>{t.common.advanced}</span>
            {#if notifHeaderRows.length > 0 || notifDraft.body_template}
              <span class="details-count num">
                {notifHeaderRows.length + (notifDraft.body_template ? 1 : 0)}
              </span>
            {/if}
          </summary>
          <div class="sv-details-body">
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

<style>
  .sv-subtabs {
    scroll-behavior: smooth;
    -webkit-overflow-scrolling: touch;
  }
  .sv-subtabs.fade-right {
    mask-image: linear-gradient(to right, #000 0%, #000 90%, transparent 100%);
    -webkit-mask-image: linear-gradient(to right, #000 0%, #000 90%, transparent 100%);
  }
  .sv-subtabs.fade-left {
    mask-image: linear-gradient(to right, transparent 0%, #000 10%, #000 100%);
    -webkit-mask-image: linear-gradient(to right, transparent 0%, #000 10%, #000 100%);
  }
  .sv-subtabs.fade-left.fade-right {
    mask-image: linear-gradient(to right, transparent 0%, #000 8%, #000 92%, transparent 100%);
    -webkit-mask-image: linear-gradient(to right, transparent 0%, #000 8%, #000 92%, transparent 100%);
  }
  .sv-tab-dirty-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--warn);
    box-shadow: 0 0 0 2px var(--warn-soft);
    flex-shrink: 0;
  }

  /* 外观模式视觉缩略卡片 */
  .sv-mode-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 10px;
  }
  .sv-mode-card {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 8px;
    padding: 11px;
    border-radius: 14px;
    border: 1px solid var(--border-subtle);
    background: var(--bg-elevated);
    color: var(--text-primary);
    text-align: left;
    font-family: inherit;
    cursor: pointer;
    transition: border-color 0.14s ease, background-color 0.14s ease, box-shadow 0.14s ease;
  }
  .sv-mode-card:hover {
    border-color: var(--border-strong);
    background: var(--bg-hover);
  }
  .sv-mode-card.active {
    border-color: var(--accent);
    background: var(--accent-soft);
    box-shadow: 0 0 0 1px var(--border-focus);
  }
  .sv-mode-card:focus-visible {
    outline: none;
    box-shadow: 0 0 0 3px var(--accent-soft);
    border-color: var(--accent);
  }
  .sv-mode-preview {
    width: 100%;
    height: 44px;
    border-radius: 9px;
    border: 1px solid var(--border-subtle);
    padding: 6px;
    display: flex;
    flex-direction: column;
    gap: 5px;
    overflow: hidden;
  }
  .sv-mode-preview-light {
    background: #f4f4f5;
  }
  .sv-mode-preview-dark {
    background: #141418;
  }
  .sv-mode-preview-auto {
    background: linear-gradient(125deg, #f4f4f5 50%, #141418 50%);
  }
  .sv-prev-bar {
    height: 6px;
    width: 48%;
    border-radius: 999px;
    background: var(--accent);
    opacity: 0.85;
  }
  .sv-prev-cards {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 4px;
    flex: 1;
  }
  .sv-prev-cards span {
    border-radius: 4px;
    background: rgba(128, 128, 140, 0.24);
  }
  .sv-mode-head {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-weight: 700;
    font-size: 13px;
  }
  .sv-mode-card.active .sv-mode-head {
    color: var(--accent);
  }
  .sv-mode-desc {
    font-size: 11.5px;
    color: var(--text-muted);
    line-height: 1.35;
  }

  /* 子模块卡片精简均衡布局 */
  .sv-mod-card {
    height: 100%;
  }
  .sv-mod-card.is-enabled {
    border-color: color-mix(in srgb, var(--accent) 24%, var(--border-subtle));
  }
  .sv-mod-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }
  .sv-mod-title {
    font-weight: 600;
    font-size: 13.5px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .sv-mod-foot {
    margin-top: auto;
    min-height: 30px;
  }
  .sv-mod-open {
    padding: 0 6px;
    color: var(--text-secondary);
  }

  /* 安全入口 URL 强制断行，杜绝 390px 视口横向撑破 */
  .sv-origin-banner {
    overflow: hidden;
  }
  .sv-entry-url-row {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    margin-top: 8px;
    min-width: 0;
  }
  .sv-url-chip {
    display: inline-block;
    max-width: 100%;
    word-break: break-all;
    overflow-wrap: anywhere;
    background: var(--bg-elevated);
    padding: 3px 9px;
    border-radius: 8px;
    border: 1px solid var(--border-subtle);
    font-size: 12px;
    line-height: 1.4;
  }
  .sv-url-chip-draft {
    border-color: var(--warn);
  }

  .sv-label-with-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }
  .sv-preset-chips {
    display: flex;
    align-items: center;
    gap: 5px;
    flex-wrap: wrap;
  }
  .sv-mini-chip {
    padding: 2px 8px;
    min-height: 24px;
    border-radius: 999px;
    border: 1px solid var(--border-subtle);
    background: var(--bg-elevated);
    color: var(--text-secondary);
    font-size: 11px;
    cursor: pointer;
    transition: all 0.12s ease;
  }
  .sv-mini-chip:hover {
    border-color: var(--border-strong);
    color: var(--text-primary);
  }
  .sv-mini-chip.active {
    background: var(--accent-soft);
    border-color: var(--border-focus);
    color: var(--accent);
    font-weight: 600;
  }
  .sv-sp-block {
    border-bottom: 1px solid var(--border-subtle);
  }
  .sv-sp-head-row {
    border-bottom: none !important;
  }
  .sv-sp-panel {
    margin: 0 18px 16px;
    padding: 12px 14px;
    border-radius: var(--radius-md);
    background: var(--bg-elevated);
    border: 1px solid var(--border-subtle);
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .sv-sp-row {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }
  .sv-sp-input {
    flex: 1 1 280px;
    min-width: 0;
  }
  .sv-input-invalid {
    border-color: var(--danger) !important;
  }
  .sv-sp-actions {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
    flex-shrink: 0;
  }
  .sv-sp-btn {
    flex-shrink: 0;
  }
  .sv-sp-hint {
    font-size: 12px;
    line-height: 1.5;
    color: var(--text-muted);
  }
  .sv-sp-hint-error {
    color: var(--danger);
    font-weight: 500;
  }

  /* 双输入带标签与单位后缀 */
  .sv-paired-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 10px;
  }
  .sv-sub-field {
    display: flex;
    flex-direction: column;
    gap: 4px;
    min-width: 0;
  }
  .sv-sub-label {
    font-size: 11.5px;
    font-weight: 600;
    color: var(--text-muted);
    line-height: 1.3;
  }
  .sv-unit-wrap {
    position: relative;
    display: flex;
    align-items: center;
  }
  .sv-unit-wrap input {
    padding-right: 34px;
  }
  .sv-unit-tag {
    position: absolute;
    right: 10px;
    font-size: 11.5px;
    font-weight: 600;
    color: var(--text-muted);
    pointer-events: none;
  }
  .sv-dns-badges {
    display: flex;
    flex-wrap: wrap;
    justify-content: flex-end;
    gap: 6px;
  }

  /* 底部悬浮保存条 */
  .sv-save-bar-info {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    flex-wrap: wrap;
    font-size: 13px;
    font-weight: 600;
  }

  /* 密码显隐、强度条与图标规则清单 */
  .sv-pw-wrap {
    position: relative;
    display: flex;
    align-items: center;
  }
  .sv-pw-wrap input {
    padding-right: 42px;
  }
  .sv-eye-btn {
    position: absolute;
    right: 5px;
    min-width: 32px;
    min-height: 32px;
    padding: 0;
    color: var(--text-muted);
  }
  .sv-strength-bar {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 4px;
    margin-top: 6px;
  }
  .sv-strength-seg {
    height: 4px;
    border-radius: 999px;
    background: var(--bg-elevated);
    transition: background-color 0.2s ease;
  }
  .sv-strength-seg.tone-danger { background: var(--danger); }
  .sv-strength-seg.tone-warn { background: var(--warn); }
  .sv-strength-seg.tone-ok { background: var(--accent); }
  .sv-checklist {
    font-size: 12.5px;
    display: grid;
    gap: 6px;
  }
  .sv-check-item {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--text-secondary);
  }
  .sv-check-item.ok {
    color: var(--accent);
  }
  .sv-check-icon {
    width: 16px;
    height: 16px;
    border-radius: 999px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
  .sv-check-item.ok .sv-check-icon {
    background: var(--accent-soft);
    color: var(--accent);
  }
  .sv-check-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    border: 1.5px solid var(--border-strong);
  }

  /* TOTP & 恢复码芯片 */
  .sv-totp-status {
    margin-bottom: 14px;
  }
  .sv-totp-status.is-low {
    border-color: color-mix(in srgb, var(--warn) 45%, var(--border-subtle));
    background: color-mix(in srgb, var(--warn-soft) 35%, var(--bg-elevated));
  }
  .sv-totp-setup-grid {
    display: flex;
    gap: 14px;
    align-items: flex-start;
    flex-wrap: wrap;
    margin-bottom: 12px;
  }
  .sv-qr-img {
    width: 176px;
    height: 176px;
    border-radius: 12px;
    border: 1px solid var(--border-subtle);
    background: #ffffff;
    padding: 6px;
    display: block;
    flex-shrink: 0;
  }
  .sv-totp-secrets {
    flex: 1 1 220px;
    min-width: 0;
    display: grid;
    gap: 12px;
  }
  .sv-otp-input {
    letter-spacing: 0.28em;
    text-align: center;
    font-weight: 700;
    font-size: 16px;
  }
  .sv-recovery-box {
    margin-top: 14px;
    border-color: color-mix(in srgb, var(--warn) 50%, var(--border-subtle));
  }
  .sv-recovery-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 8px;
    font-size: 13px;
  }
  .sv-recovery-chip {
    padding: 7px 10px;
    border-radius: 10px;
    background: var(--bg-card);
    border: 1px solid var(--border-subtle);
    text-align: center;
    font-weight: 600;
    letter-spacing: 0.04em;
  }

  /* Passkey & 通知列表操作行响应式堆叠 */
  .sv-action-row {
    grid-template-columns: minmax(0, 1fr) auto;
  }
  .sv-row-actions {
    justify-content: flex-end;
    flex-shrink: 0;
  }
  .sv-passkey-form {
    display: flex;
    gap: 10px;
    align-items: center;
    flex-wrap: wrap;
  }
  .sv-passkey-input {
    flex: 1 1 220px;
    min-width: 0;
  }
  .sv-event-meta {
    display: flex;
    align-items: center;
    gap: 5px;
    flex-wrap: wrap;
    margin-top: 5px;
  }

  /* 备份危险卡片与已校验文件提示 */
  .sv-danger-card {
    border-color: color-mix(in srgb, var(--danger) 30%, var(--border-subtle));
  }
  .sv-valid-file {
    margin-top: 8px;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    max-width: 100%;
    padding: 4px 8px 4px 10px;
    border-radius: 10px;
    background: var(--accent-soft);
    border: 1px solid color-mix(in srgb, var(--accent) 26%, transparent);
    color: var(--accent);
    font-size: 12px;
  }
  .sv-valid-file-name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .sv-toml-pre {
    background: var(--bg-elevated);
    padding: 14px;
    border-radius: 12px;
    max-height: 340px;
    overflow: auto;
    font-size: 12px;
    line-height: 1.5;
    border: 1px solid var(--border-subtle);
  }
  .sv-details-body {
    padding-top: 10px;
  }

  @media (max-width: 820px) {
    .sv-action-row {
      grid-template-columns: 1fr !important;
      gap: 10px !important;
      padding: 14px 16px !important;
    }
    .sv-row-actions,
    .sv-dns-badges {
      justify-content: flex-start;
    }
    .sv-row-actions {
      width: 100%;
      padding-top: 8px;
      border-top: 1px dashed var(--border-subtle);
    }
  }

  @media (max-width: 640px) {
    .sv-mode-grid {
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 8px;
    }
    .sv-mode-card {
      padding: 9px 8px;
      gap: 6px;
    }
    .sv-mode-preview {
      height: 36px;
    }
    .sv-mode-desc {
      display: none;
    }
    .sv-save-bar {
      border-radius: 16px;
      padding: 10px 12px;
      flex-wrap: wrap;
      gap: 8px;
    }
    .sv-save-bar-actions {
      width: 100%;
      justify-content: flex-end;
    }
    .sv-save-bar-actions :global(.btn) {
      flex: 1 1 auto;
    }
    .sv-qr-img {
      margin: 0 auto;
    }
    .sv-passkey-submit {
      width: 100%;
    }
  }

  @media (max-width: 520px) {
    .sv-lang-grid {
      grid-template-columns: 1fr !important;
    }
    .sv-paired-grid {
      grid-template-columns: 1fr;
    }
    .sv-sp-panel {
      margin: 0 12px 14px;
      padding: 10px 12px;
    }
    .sv-sp-actions {
      width: 100%;
    }
    .sv-sp-btn {
      flex: 1 1 auto;
      justify-content: center;
    }
    .sv-eye-btn {
      min-width: 38px;
      min-height: 38px;
    }
  }
</style>
