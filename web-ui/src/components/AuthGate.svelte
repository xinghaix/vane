<script>
  import Icons from './Icons.svelte';
  import { getPasskeyAssertion, isPasskeySupported } from '../lib/webauthn.js';

  let {
    t,
    lang,
    toggleLang,
    themeMode = 'auto',
    onSelectThemeMode = null,
    authenticated,
    mustChangePassword,
    initialSetup = false,
    username,
    passwordLoginEnabled = true,
    totpEnabled = false,
    passkeyEnabled = false,
    hasPasskeys = false,
    connError = '',
    onRetryStatus,
    apiFetch,
    onAuthenticated,
    onLogout,
  } = $props();

  let canUsePasskey = $derived(Boolean(passkeyEnabled && hasPasskeys && !initialSetup && isPasskeySupported()));

  let loginMode = $state('password');
  let loginUser = $state('admin');
  let loginPass = $state('');
  let showLoginPass = $state(false);
  let loginTotp = $state('');
  let loginError = $state('');
  let busy = $state(false);

  // 首次强制改密状态
  let curPassword = $state('');
  let newUsername = $state('');
  let newPassword = $state('');
  let confirmPassword = $state('');
  let showNewPass = $state(false);
  let pwChangeError = $state('');

  function cycleTheme() {
    if (!onSelectThemeMode) return;
    const order = ['auto', 'light', 'dark'];
    const idx = order.indexOf(themeMode);
    onSelectThemeMode(order[(idx + 1) % order.length]);
  }

  let themeIcon = $derived(themeMode === 'light' ? 'sun' : themeMode === 'dark' ? 'moon' : 'monitor');
  let themeTitle = $derived(
    themeMode === 'light' ? t.themeLight : themeMode === 'dark' ? t.themeDark : t.themeAuto
  );

  $effect(() => {
    if (username && loginUser === 'admin') loginUser = username;
    if (!passwordLoginEnabled && canUsePasskey && loginMode === 'password') {
      loginMode = 'passkey';
    } else if (!canUsePasskey && loginMode === 'passkey') {
      loginMode = 'password';
    }
  });

  async function submitPasskeyLogin() {
    if (busy) return;
    busy = true;
    loginError = '';
    try {
      const opts = await apiFetch('/api/auth/passkey/login/options', {
        method: 'POST',
        body: '{}',
      });
      const assertion = await getPasskeyAssertion(opts, lang);
      const st = await apiFetch('/api/auth/passkey/login/verify', {
        method: 'POST',
        body: JSON.stringify(assertion),
      });
      await onAuthenticated?.(st);
    } catch (err) {
      loginError = err.message;
    } finally {
      busy = false;
    }
  }

  // 退出登录或返回登录页时彻底清空内存中残留密码与错误提示
  $effect(() => {
    if (!authenticated) {
      curPassword = '';
      newUsername = '';
      newPassword = '';
      confirmPassword = '';
      pwChangeError = '';
    }
  });

  let effectiveUsername = $derived(newUsername.trim() || username);
  let newPasswordUtf8Bytes = $derived(new TextEncoder().encode(newPassword).length);
  let pwChecks = $derived({
    lenOk: newPasswordUtf8Bytes >= 8 && newPasswordUtf8Bytes <= 128,
    hasAlpha: /[A-Za-z]/.test(newPassword),
    hasDigitOrPunct: /[0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(newPassword),
    notDefault:
      newPassword.length > 0 &&
      newPassword !== 'admin321' &&
      newPassword !== curPassword &&
      newPassword !== effectiveUsername,
    matchConfirm: newPassword.length > 0 && newPassword === confirmPassword,
  });
  let pwCheckList = $derived([
    { ok: pwChecks.lenOk, text: t.ruleLen },
    { ok: pwChecks.hasAlpha, text: t.ruleAlpha },
    { ok: pwChecks.hasDigitOrPunct, text: t.ruleDigit },
    { ok: pwChecks.notDefault, text: t.ruleNotDefault },
    { ok: pwChecks.matchConfirm, text: t.ruleMatch },
  ]);
  let pwScore = $derived(pwCheckList.filter((c) => c.ok).length);
  let pwAllValid = $derived(pwScore === 5);

  async function submitPasswordLogin(e) {
    e.preventDefault();
    loginError = '';
    busy = true;
    try {
      const st = await apiFetch('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username: loginUser, password: loginPass, totp_code: loginTotp }),
      });
      curPassword = st.must_change_password ? loginPass : '';
      loginPass = '';
      loginTotp = '';
      await onAuthenticated(st);
    } catch (err) {
      loginError = err.message;
    } finally {
      busy = false;
    }
  }

  async function submitChangePassword(e) {
    e.preventDefault();
    pwChangeError = '';
    if (!pwAllValid) return;
    busy = true;
    try {
      const st = await apiFetch('/api/auth/change-password', {
        method: 'POST',
        body: JSON.stringify({
          current_password: curPassword,
          new_password: newPassword,
          new_username: effectiveUsername,
        }),
      });
      curPassword = '';
      newUsername = '';
      newPassword = '';
      confirmPassword = '';
      await onAuthenticated(st, lang === 'en' ? 'Strong password saved' : '强密码已生效，欢迎进入 Vane 网关控制台');
    } catch (err) {
      pwChangeError = err.message;
    } finally {
      busy = false;
    }
  }
</script>

{#if !authenticated}
  <div class="auth-shell">
    <div class="auth-card">
      <div class="auth-card-head">
        <div style="display:flex;align-items:center;gap:12px;min-width:0;">
          <img src="/icon.svg" alt="Vane" class="brand-icon auth-brand-icon" />
          <div style="min-width:0;">
            <div style="font-size:18px;font-weight:750;letter-spacing:-0.02em;line-height:1.2;">Vane Gateway</div>
            <div style="font-size:12px;color:var(--text-secondary);margin-top:2px;line-height:1.35;">{t.subtitle}</div>
          </div>
        </div>
        <div class="auth-head-actions">
          {#if onSelectThemeMode}
            <button
              type="button"
              class="btn btn-icon btn-icon-sm"
              title={`${t.themeModeLabel}: ${themeTitle}`}
              aria-label={`${t.themeModeLabel}: ${themeTitle}`}
              onclick={cycleTheme}
            >
              <Icons name={themeIcon} size={15} />
            </button>
          {/if}
          <button type="button" class="btn btn-sm" aria-label={t.cfg.lblLanguage} onclick={toggleLang}>
            {lang === 'zh' ? 'EN' : '中文'}
          </button>
        </div>
      </div>

      {#if connError}
        <div class="banner banner-danger" style="margin-bottom:14px;">
          <div class="banner-main">
            <Icons name="alert" size={16} />
            <div style="min-width:0;">
              <div style="font-weight:700;">{t.connErrorTitle}</div>
              <div style="font-size:12px;color:var(--text-secondary);margin-top:2px;word-break:break-word;">{connError}</div>
              <div style="font-size:12px;color:var(--text-muted);margin-top:2px;">{t.connErrorDesc}</div>
            </div>
          </div>
          {#if onRetryStatus}
            <button type="button" class="btn btn-xs" onclick={onRetryStatus}>{t.refresh}</button>
          {/if}
        </div>
      {/if}

      {#if passwordLoginEnabled && canUsePasskey}
        <div class="pill-tabs" role="tablist" style="width:100%;margin-bottom:16px;display:flex;">
          <button
            type="button"
            role="tab"
            aria-selected={loginMode === 'password'}
            class="pill-tab {loginMode === 'password' ? 'active' : ''}"
            style="flex:1;"
            onclick={() => { loginMode = 'password'; loginError = ''; }}
          >
            {t.pwLoginTab}
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={loginMode === 'passkey'}
            class="pill-tab {loginMode === 'passkey' ? 'active' : ''}"
            style="flex:1;"
            onclick={() => { loginMode = 'passkey'; loginError = ''; }}
          >
            {t.passkeyLoginTab}
          </button>
        </div>
      {/if}

      {#if loginError}
        <div role="alert" class="inline-alert inline-alert-danger" style="margin-bottom:14px;">
          <Icons name="alert" size={15} />
          <span>{loginError}</span>
        </div>
      {/if}

      {#if loginMode === 'password' && passwordLoginEnabled}
        <form method="post" action="/api/auth/login" onsubmit={submitPasswordLogin}>
          <div class="field">
            <label for="login-user">{t.username}</label>
            <input id="login-user" name="username" type="text" bind:value={loginUser} autocomplete="username" required />
          </div>
          <div class="field">
            <label for="login-pass">{t.password}</label>
            <div class="input-wrap">
              <input
                id="login-pass"
                name="password"
                type={showLoginPass ? 'text' : 'password'}
                class="has-addon"
                placeholder={initialSetup ? t.passwordInitialHint : t.passwordPlaceholder}
                bind:value={loginPass}
                autocomplete="current-password"
                required
              />
              <button
                type="button"
                class="input-addon-btn"
                onclick={() => (showLoginPass = !showLoginPass)}
                aria-label={t.common.toggleSecret}
                aria-pressed={showLoginPass}
              >
                <Icons name={showLoginPass ? 'eye_off' : 'eye'} size={15} />
              </button>
            </div>
          </div>
          {#if totpEnabled}
            <div class="field">
              <label for="login-totp">{t.totpCode}</label>
              <input
                id="login-totp"
                name="otp"
                type="text"
                class="mono"
                inputmode="numeric"
                autocomplete="one-time-code"
                placeholder="123456 / xxxx-xxxx"
                bind:value={loginTotp}
                required
              />
            </div>
          {/if}
          <button type="submit" class="btn btn-primary auth-submit-btn" disabled={busy}>
            {#if busy}
              <Icons name="loader" size={15} class="is-spinning" />
            {:else}
              <Icons name="lock" size={15} />
            {/if}
            <span>{busy ? t.common.loading : t.loginBtn}</span>
          </button>
          {#if canUsePasskey}
            <div class="auth-divider">
              <span></span>
              <em>{t.passkeyOrDivider}</em>
              <span></span>
            </div>
            <button type="button" class="btn auth-submit-btn" disabled={busy} onclick={submitPasskeyLogin}>
              {#if busy}
                <Icons name="loader" size={15} class="is-spinning" />
              {:else}
                <Icons name="passkey" size={16} />
              {/if}
              <span>{t.passkeyLoginBtn}</span>
            </button>
          {/if}
        </form>
      {:else if canUsePasskey}
        <div class="subcard" style="text-align:center;padding:22px 16px;margin-bottom:14px;">
          <div class="icon-tile" style="width:48px;height:48px;border-radius:14px;margin:0 auto 10px;">
            <Icons name="passkey" size={24} />
          </div>
          <div style="font-size:14px;font-weight:700;margin-bottom:4px;">{t.passkeyLoginBtn}</div>
          <div style="font-size:12px;color:var(--text-secondary);line-height:1.45;">{t.reauth.passkeyReadyDesc}</div>
        </div>
        <button type="button" class="btn btn-primary auth-submit-btn" disabled={busy} onclick={submitPasskeyLogin}>
          {#if busy}
            <Icons name="loader" size={15} class="is-spinning" />
          {:else}
            <Icons name="passkey" size={16} />
          {/if}
          <span>{t.passkeyLoginBtn}</span>
        </button>
      {:else}
        <div class="banner banner-warn" style="margin-bottom:12px;">
          <div class="banner-main">
            <Icons name="alert" size={16} />
            <span>
              {lang === 'en'
                ? 'Password login is disabled. Open this console via the HTTPS domain where your Passkey is registered.'
                : '当前已关闭密码登录，请使用已绑定通行密钥的 HTTPS 域名访问并完成免密登录。'}
            </span>
          </div>
        </div>
      {/if}
    </div>
  </div>

{:else if mustChangePassword}
  <div class="auth-shell">
    <div class="auth-card" style="max-width:480px;">
      <div class="row-between" style="margin-bottom:14px;">
        <span class="badge badge-warn">{t.gateBadge}</span>
        <div class="auth-head-actions">
          {#if onSelectThemeMode}
            <button
              type="button"
              class="btn btn-icon btn-icon-sm"
              title={`${t.themeModeLabel}: ${themeTitle}`}
              aria-label={`${t.themeModeLabel}: ${themeTitle}`}
              onclick={cycleTheme}
            >
              <Icons name={themeIcon} size={15} />
            </button>
          {/if}
          <button type="button" class="btn btn-sm" aria-label={t.cfg.lblLanguage} onclick={toggleLang}>
            {lang === 'zh' ? 'EN' : '中文'}
          </button>
        </div>
      </div>
      <h2 style="font-size:20px;font-weight:750;letter-spacing:-0.02em;margin-bottom:6px;">{t.gateTitle}</h2>
      <p style="font-size:13px;color:var(--text-secondary);margin-bottom:18px;line-height:1.5;">{t.gateDesc}</p>

      {#if pwChangeError}
        <div role="alert" class="inline-alert inline-alert-danger" style="margin-bottom:14px;">
          <Icons name="alert" size={15} />
          <span>{pwChangeError}</span>
        </div>
      {/if}

      <form onsubmit={submitChangePassword}>
        <div class="field">
          <label for="new-user-gate">{t.cfg.newUsername}</label>
          <input id="new-user-gate" type="text" autocomplete="username" placeholder={username} bind:value={newUsername} />
        </div>
        <div class="field">
          <label for="cur-pw">{t.curPw}</label>
          <input id="cur-pw" type="password" autocomplete="current-password" bind:value={curPassword} required />
        </div>
        <div class="field">
          <label for="new-pw">{t.newPw}</label>
          <div class="input-wrap">
            <input
              id="new-pw"
              type={showNewPass ? 'text' : 'password'}
              class="has-addon"
              bind:value={newPassword}
              autocomplete="new-password"
              required
            />
            <button
              type="button"
              class="input-addon-btn"
              onclick={() => (showNewPass = !showNewPass)}
              aria-label={t.common.toggleSecret}
              aria-pressed={showNewPass}
            >
              <Icons name={showNewPass ? 'eye_off' : 'eye'} size={15} />
            </button>
          </div>
        </div>
        <div class="field">
          <label for="confirm-pw">{t.confirmPw}</label>
          <input id="confirm-pw" type={showNewPass ? 'text' : 'password'} bind:value={confirmPassword} autocomplete="new-password" required />
        </div>

        <div class="subcard pw-checklist-card">
          <div class="pw-strength-bar" aria-hidden="true">
            {#each [1, 2, 3, 4, 5] as step (step)}
              <span
                class="pw-strength-seg {pwScore >= step ? (pwScore >= 5 ? 'ok' : pwScore >= 3 ? 'warn' : 'danger') : ''}"
              ></span>
            {/each}
          </div>
          <div class="pw-check-list">
            {#each pwCheckList as item (item.text)}
              <div class="pw-check-item {item.ok ? 'ok' : ''}">
                {#if item.ok}
                  <Icons name="check_circle" size={14} />
                {:else}
                  <span class="pw-check-dot" aria-hidden="true"></span>
                {/if}
                <span>{item.text}</span>
              </div>
            {/each}
          </div>
        </div>

        <div class="modal-actions" style="margin-top:4px;">
          <button type="button" class="btn" onclick={onLogout}>{t.logout}</button>
          <button type="submit" class="btn btn-primary" style="flex:1;" disabled={!pwAllValid || busy}>
            {#if busy}
              <Icons name="loader" size={14} class="is-spinning" />
            {/if}
            <span>{t.savePwBtn}</span>
          </button>
        </div>
      </form>
    </div>
  </div>
{/if}
