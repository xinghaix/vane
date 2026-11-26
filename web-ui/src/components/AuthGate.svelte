<script>
  import Icons from './Icons.svelte';
  import { getPasskeyAssertion, isPasskeySupported } from '../lib/webauthn.js';

  let {
    t,
    lang,
    toggleLang,
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
  let pwAllValid = $derived(
    pwChecks.lenOk && pwChecks.hasAlpha && pwChecks.hasDigitOrPunct && pwChecks.notDefault && pwChecks.matchConfirm
  );

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
      <div class="brand" style="border:none;margin-bottom:14px;padding:0;justify-content:space-between;">
        <div style="display:flex;align-items:center;gap:12px;">
          <img src="/icon.svg" alt="Vane" class="brand-icon" />
          <div>
            <div style="font-size:18px;font-weight:700;">Vane Gateway</div>
            <div style="font-size:12px;color:var(--text-secondary);">{t.subtitle}</div>
          </div>
        </div>
        <button type="button" class="btn btn-sm" onclick={toggleLang}>{lang === 'zh' ? 'EN' : '中文'}</button>
      </div>

      {#if connError}
        <div class="banner banner-danger" style="margin-bottom:14px;">
          <div style="flex:1;min-width:0;">
            <div style="font-weight:700;">{t.connErrorTitle}</div>
            <div style="font-size:12px;color:var(--text-secondary);margin-top:2px;">{connError}</div>
            <div style="font-size:12px;color:var(--text-muted);margin-top:2px;">{t.connErrorDesc}</div>
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
        <div role="alert" class="badge badge-danger" style="width:100%;padding:10px 12px;border-radius:10px;margin-bottom:14px;white-space:normal;">
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
            <div style="position:relative;display:flex;align-items:center;">
              <input
                id="login-pass"
                name="password"
                type={showLoginPass ? 'text' : 'password'}
                style="padding-right:42px;"
                placeholder={initialSetup ? t.passwordInitialHint : t.passwordPlaceholder}
                bind:value={loginPass}
                autocomplete="current-password"
                required
              />
              <button
                type="button"
                class="btn btn-ghost btn-xs"
                style="position:absolute;right:6px;min-height:28px;padding:0 6px;"
                onclick={() => showLoginPass = !showLoginPass}
                aria-label={t.common.toggleSecret}
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
                placeholder="123456 / xxxx-xxxx-xxxx-xxxx"
                bind:value={loginTotp}
                required
              />
            </div>
          {/if}
          <button type="submit" class="btn btn-primary" style="width:100%;margin-top:6px;" disabled={busy}>
            <Icons name="lock" size={15} />
            <span>{t.loginBtn}</span>
          </button>
          {#if canUsePasskey}
            <div style="display:flex;align-items:center;gap:10px;margin:14px 0 12px;color:var(--text-muted);font-size:12px;">
              <span style="flex:1;height:1px;background:var(--border-subtle);"></span>
              <span>{t.passkeyOrDivider}</span>
              <span style="flex:1;height:1px;background:var(--border-subtle);"></span>
            </div>
            <button type="button" class="btn" style="width:100%;" disabled={busy} onclick={submitPasskeyLogin}>
              <Icons name="passkey" size={16} />
              <span>{busy ? '...' : t.passkeyLoginBtn}</span>
            </button>
          {/if}
        </form>
      {:else if canUsePasskey}
        <div class="subcard" style="text-align:center;padding:22px 16px;margin-bottom:14px;">
          <div style="width:48px;height:48px;border-radius:14px;background:var(--accent-soft);color:var(--accent);display:grid;place-items:center;margin:0 auto 10px;">
            <Icons name="passkey" size={24} />
          </div>
          <div style="font-size:14px;font-weight:700;margin-bottom:4px;">{t.passkeyLoginBtn}</div>
          <div style="font-size:12px;color:var(--text-secondary);">{t.reauth.passkeyReadyDesc}</div>
        </div>
        <button type="button" class="btn btn-primary" style="width:100%;" disabled={busy} onclick={submitPasskeyLogin}>
          <Icons name="passkey" size={16} />
          <span>{busy ? '...' : t.passkeyLoginBtn}</span>
        </button>
      {:else}
        <div class="banner banner-warn" style="margin-bottom:12px;">
          {lang === 'en'
            ? 'Password login is disabled. Open this console via the HTTPS domain where your Passkey is registered.'
            : '当前已关闭密码登录，请使用已绑定通行密钥的 HTTPS 域名访问并完成免密登录。'}
        </div>
      {/if}
    </div>
  </div>

{:else if mustChangePassword}
  <div class="auth-shell">
    <div class="auth-card" style="max-width:480px;">
      <div class="row-between" style="margin-bottom:12px;">
        <span class="badge badge-warn">{t.gateBadge}</span>
        <button type="button" class="btn btn-sm" onclick={toggleLang}>{lang === 'zh' ? 'EN' : '中文'}</button>
      </div>
      <h2 style="font-size:20px;margin-bottom:6px;">{t.gateTitle}</h2>
      <p style="font-size:13px;color:var(--text-secondary);margin-bottom:18px;line-height:1.5;">{t.gateDesc}</p>

      {#if pwChangeError}
        <div role="alert" class="badge badge-danger" style="width:100%;padding:10px 12px;border-radius:10px;margin-bottom:14px;white-space:normal;">
          {pwChangeError}
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
          <div style="position:relative;display:flex;align-items:center;">
            <input
              id="new-pw"
              type={showNewPass ? 'text' : 'password'}
              style="padding-right:42px;"
              bind:value={newPassword}
              autocomplete="new-password"
              required
            />
            <button
              type="button"
              class="btn btn-ghost btn-xs"
              style="position:absolute;right:6px;min-height:28px;padding:0 6px;"
              onclick={() => showNewPass = !showNewPass}
              aria-label={t.common.toggleSecret}
            >
              <Icons name={showNewPass ? 'eye_off' : 'eye'} size={15} />
            </button>
          </div>
        </div>
        <div class="field">
          <label for="confirm-pw">{t.confirmPw}</label>
          <input id="confirm-pw" type={showNewPass ? 'text' : 'password'} bind:value={confirmPassword} autocomplete="new-password" required />
        </div>

        <div class="subcard" style="margin-bottom:16px;font-size:13px;display:grid;gap:6px;">
          <div style="color:{pwChecks.lenOk ? 'var(--accent)' : 'var(--text-secondary)'}">{pwChecks.lenOk ? '✓' : '○'} {t.ruleLen}</div>
          <div style="color:{pwChecks.hasAlpha ? 'var(--accent)' : 'var(--text-secondary)'}">{pwChecks.hasAlpha ? '✓' : '○'} {t.ruleAlpha}</div>
          <div style="color:{pwChecks.hasDigitOrPunct ? 'var(--accent)' : 'var(--text-secondary)'}">{pwChecks.hasDigitOrPunct ? '✓' : '○'} {t.ruleDigit}</div>
          <div style="color:{pwChecks.notDefault ? 'var(--accent)' : 'var(--text-secondary)'}">{pwChecks.notDefault ? '✓' : '○'} {t.ruleNotDefault}</div>
          <div style="color:{pwChecks.matchConfirm ? 'var(--accent)' : 'var(--text-secondary)'}">{pwChecks.matchConfirm ? '✓' : '○'} {t.ruleMatch}</div>
        </div>

        <div style="display:flex;gap:10px;">
          <button type="submit" class="btn btn-primary" style="flex:1;" disabled={!pwAllValid || busy}>{t.savePwBtn}</button>
          <button type="button" class="btn" onclick={onLogout}>{t.logout}</button>
        </div>
      </form>
    </div>
  </div>
{/if}
