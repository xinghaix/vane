<script>
  import Icons from './Icons.svelte';
  import { copyText } from '../lib/helpers.js';

  let {
    t,
    lang,
    toggleLang,
    authenticated,
    mustChangePassword,
    username,
    passwordLoginEnabled = true,
    totpEnabled = false,
    hasEd25519Keys = false,
    ed25519KeyIds = [],
    connError = '',
    onRetryStatus,
    apiFetch,
    showToast,
    onAuthenticated,
    onLogout,
  } = $props();

  let loginMode = $state('password');
  let loginUser = $state('admin');
  let loginPass = $state('');
  let showLoginPass = $state(false);
  let loginTotp = $state('');
  let loginError = $state('');
  let busy = $state(false);

  // Ed25519 挑战签名状态
  let selectedKeyId = $state('');
  let challengeNonceB64 = $state('');
  let challengeOrigin = $state('');
  let challengeExpiresAt = $state(0);
  let challengeRemainSecs = $state(0);
  let privateSeedInput = $state('');
  let manualSigB64 = $state('');

  // 首次强制改密状态
  let curPassword = $state('');
  let newUsername = $state('');
  let newPassword = $state('');
  let confirmPassword = $state('');
  let showNewPass = $state(false);
  let pwChangeError = $state('');

  $effect(() => {
    if (username && loginUser === 'admin') loginUser = username;
    if (!passwordLoginEnabled && hasEd25519Keys) loginMode = 'ed25519';
    else if (!hasEd25519Keys && loginMode === 'ed25519') loginMode = 'password';
    if (ed25519KeyIds.length > 0 && !ed25519KeyIds.includes(selectedKeyId)) {
      selectedKeyId = ed25519KeyIds[0];
      challengeNonceB64 = '';
      challengeOrigin = '';
    }
  });

  // 退出登录或返回登录页时彻底清空内存中残留密码/私钥种子与错误提示
  $effect(() => {
    if (!authenticated) {
      curPassword = '';
      newUsername = '';
      newPassword = '';
      confirmPassword = '';
      pwChangeError = '';
      privateSeedInput = '';
      manualSigB64 = '';
    }
  });

  $effect(() => {
    if (!challengeNonceB64 || !challengeExpiresAt) {
      challengeRemainSecs = 0;
      return;
    }
    const tick = () => {
      const rem = Math.max(0, Math.ceil((challengeExpiresAt - Date.now()) / 1000));
      challengeRemainSecs = rem;
      if (rem === 0) {
        challengeNonceB64 = '';
        challengeOrigin = '';
      }
    };
    tick();
    const timer = setInterval(tick, 1000);
    return () => clearInterval(timer);
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

  function b64ToBytes(b64) {
    const bin = atob(b64.trim());
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function bytesToB64(bytes) {
    let s = '';
    const u8 = new Uint8Array(bytes);
    for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
    return btoa(s);
  }

  function parseSeed32(text) {
    const clean = text.trim();
    if (/^[0-9a-fA-F]{64}$/.test(clean)) {
      const out = new Uint8Array(32);
      for (let i = 0; i < 32; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
      return out;
    }
    const raw = b64ToBytes(clean);
    if (raw.length === 32) return raw;
    if (raw.length === 64) return raw.slice(0, 32);
    throw new Error(lang === 'en' ? 'Expected 32-byte Ed25519 seed (64 hex chars or Base64)' : '请输入 32 字节 Ed25519 私钥种子（64 位十六进制或 Base64）');
  }

  async function signEd25519InBrowser(seed32, messageBytes) {
    const pkcs8Prefix = new Uint8Array([
      0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
      0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    ]);
    const pkcs8 = new Uint8Array(48);
    pkcs8.set(pkcs8Prefix, 0);
    pkcs8.set(seed32, 16);
    try {
      const key = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
      const sig = await crypto.subtle.sign({ name: 'Ed25519' }, key, messageBytes);
      return bytesToB64(sig);
    } catch {
      throw new Error(t.webCryptoUnsupported);
    } finally {
      pkcs8.fill(0);
      seed32.fill(0);
    }
  }

  function buildChallengePayload(nonceBytes, keyId, origin) {
    const enc = new TextEncoder();
    const p1 = enc.encode('vane-ed25519-auth-v1|');
    const p2 = enc.encode(`|${keyId}|${origin}`);
    const out = new Uint8Array(p1.length + nonceBytes.length + p2.length);
    out.set(p1, 0);
    out.set(nonceBytes, p1.length);
    out.set(p2, p1.length + nonceBytes.length);
    return out;
  }

  async function fetchChallengeInternal() {
    if (!selectedKeyId) return false;
    const r = await apiFetch('/api/auth/challenge', {
      method: 'POST',
      body: JSON.stringify({ key_id: selectedKeyId }),
    });
    challengeNonceB64 = r.nonce_b64;
    challengeOrigin = r.canonical_origin;
    challengeExpiresAt = Date.now() + 60_000;
    return true;
  }

  async function requestEd25519Challenge() {
    loginError = '';
    if (!selectedKeyId) return;
    busy = true;
    try {
      await fetchChallengeInternal();
    } catch (err) {
      loginError = err.message;
    } finally {
      busy = false;
    }
  }

  async function copyChallengeField(val) {
    if (await copyText(val)) showToast?.(t.copied, 'success');
    else showToast?.(t.copyFailed, 'error');
  }

  async function submitEd25519Login(e) {
    e.preventDefault();
    loginError = '';
    busy = true;
    let calledVerifyApi = false;
    try {
      if (!challengeNonceB64) {
        const ok = await fetchChallengeInternal();
        if (!ok || !challengeNonceB64) return;
      }
      let sigB64 = manualSigB64.trim();
      if (!sigB64 && privateSeedInput.trim()) {
        const seed = parseSeed32(privateSeedInput);
        const nonceBytes = b64ToBytes(challengeNonceB64);
        const msg = buildChallengePayload(nonceBytes, selectedKeyId, challengeOrigin);
        sigB64 = await signEd25519InBrowser(seed, msg);
      }
      if (!sigB64) {
        throw new Error(lang === 'en' ? 'Provide private seed or Base64 signature' : '请提供私钥种子或粘贴签名结果');
      }
      calledVerifyApi = true;
      const st = await apiFetch('/api/auth/login-ed25519', {
        method: 'POST',
        body: JSON.stringify({
          key_id: selectedKeyId,
          nonce_b64: challengeNonceB64,
          signature_b64: sigB64,
        }),
      });
      challengeNonceB64 = '';
      challengeExpiresAt = 0;
      manualSigB64 = '';
      await onAuthenticated(st);
    } catch (err) {
      loginError = err.message;
      if (calledVerifyApi) {
        challengeNonceB64 = '';
        challengeExpiresAt = 0;
      }
    } finally {
      privateSeedInput = '';
      busy = false;
    }
  }

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

      {#if passwordLoginEnabled && hasEd25519Keys}
        <div class="pill-tabs" role="tablist" style="width:100%;margin-bottom:16px;display:grid;grid-template-columns:1fr 1fr;">
          <button
            type="button"
            role="tab"
            aria-selected={loginMode === 'password'}
            class="pill-tab {loginMode === 'password' ? 'active' : ''}"
            onclick={() => loginMode = 'password'}
          >
            {t.pwLoginTab}
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={loginMode === 'ed25519'}
            class="pill-tab {loginMode === 'ed25519' ? 'active' : ''}"
            onclick={() => loginMode = 'ed25519'}
          >
            {t.keyLoginTab}
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
        <form onsubmit={submitPasswordLogin}>
          <div class="field">
            <label for="login-user">{t.username}</label>
            <input id="login-user" type="text" bind:value={loginUser} autocomplete="username" required />
          </div>
          <div class="field">
            <label for="login-pass">{t.password}</label>
            <div style="position:relative;display:flex;align-items:center;">
              <input
                id="login-pass"
                type={showLoginPass ? 'text' : 'password'}
                style="padding-right:42px;"
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
                type="text"
                class="mono"
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
        </form>
      {:else}
        <form onsubmit={submitEd25519Login}>
          <div class="field">
            <label for="key-id-sel">{t.keyIdLabel}</label>
            <select
              id="key-id-sel"
              bind:value={selectedKeyId}
              onchange={() => { challengeNonceB64 = ''; challengeOrigin = ''; challengeExpiresAt = 0; }}
            >
              {#each ed25519KeyIds as kid (kid)}
                <option value={kid}>{kid}</option>
              {/each}
            </select>
          </div>
          <div style="margin-bottom:12px;">
            <button type="button" class="btn btn-sm" style="width:100%;" onclick={requestEd25519Challenge} disabled={busy}>
              {t.getChallenge}
            </button>
          </div>
          {#if challengeNonceB64}
            <div class="subcard mono" style="font-size:11px;margin-bottom:12px;word-break:break-all;display:grid;gap:6px;">
              <div class="row-between">
                <span>Origin: {challengeOrigin}</span>
                <span class="badge badge-info num">{challengeRemainSecs}s</span>
              </div>
              <div class="row-between">
                <span style="min-width:0;flex:1;">Nonce: {challengeNonceB64}</span>
                <button type="button" class="btn btn-xs" onclick={() => copyChallengeField(challengeNonceB64)}>
                  {t.copy}
                </button>
              </div>
              <div style="font-size:10.5px;color:var(--text-muted);">
                Format: vane-ed25519-auth-v1|&lt;raw_32B_nonce&gt;|{selectedKeyId}|{challengeOrigin}
              </div>
            </div>
          {/if}
          <div class="field">
            <label for="ed-seed">{t.signWithKey}</label>
            <input
              id="ed-seed"
              type="password"
              class="mono"
              autocomplete="new-password"
              spellcheck="false"
              autocapitalize="off"
              bind:value={privateSeedInput}
              placeholder="64-char hex or Base64 32B seed"
            />
          </div>
          <div class="field">
            <label for="ed-sig">{t.orManualSig}</label>
            <input id="ed-sig" type="text" class="mono" autocomplete="off" spellcheck="false" bind:value={manualSigB64} placeholder="Base64 Ed25519 signature" />
          </div>
          <button type="submit" class="btn btn-primary" style="width:100%;" disabled={busy}>
            <Icons name="key" size={15} />
            <span>{t.verifyKeyBtn}</span>
          </button>
        </form>
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
