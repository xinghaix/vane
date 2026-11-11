<script>
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
    apiFetch,
    onAuthenticated,
    onLogout,
  } = $props();

  let loginMode = $state('password');
  let loginUser = $state('admin');
  let loginPass = $state('');
  let loginTotp = $state('');
  let loginError = $state('');
  let busy = $state(false);

  // Ed25519 挑战签名状态
  let selectedKeyId = $state('');
  let challengeNonceB64 = $state('');
  let challengeOrigin = $state('');
  let privateSeedInput = $state('');
  let manualSigB64 = $state('');

  // 首次强制改密状态
  let curPassword = $state('');
  let newPassword = $state('');
  let confirmPassword = $state('');
  let pwChangeError = $state('');

  $effect(() => {
    if (username && loginUser === 'admin') loginUser = username;
    if (!passwordLoginEnabled && hasEd25519Keys) loginMode = 'ed25519';
    if (!selectedKeyId && ed25519KeyIds.length > 0) selectedKeyId = ed25519KeyIds[0];
  });

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
    // RFC 8410 Ed25519 PKCS#8 v1 ASN.1 前缀 (16 bytes) + 32-byte raw seed
    const pkcs8Prefix = new Uint8Array([
      0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
      0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    ]);
    const pkcs8 = new Uint8Array(48);
    pkcs8.set(pkcs8Prefix, 0);
    pkcs8.set(seed32, 16);
    const key = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
    const sig = await crypto.subtle.sign({ name: 'Ed25519' }, key, messageBytes);
    pkcs8.fill(0);
    seed32.fill(0);
    return bytesToB64(sig);
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

  async function requestEd25519Challenge() {
    loginError = '';
    if (!selectedKeyId) return;
    busy = true;
    try {
      const r = await apiFetch('/api/auth/challenge', {
        method: 'POST',
        body: JSON.stringify({ key_id: selectedKeyId }),
      });
      challengeNonceB64 = r.nonce_b64;
      challengeOrigin = r.canonical_origin;
    } catch (err) {
      loginError = err.message;
    } finally {
      busy = false;
    }
  }

  async function submitEd25519Login(e) {
    e.preventDefault();
    loginError = '';
    busy = true;
    try {
      if (!challengeNonceB64) {
        await requestEd25519Challenge();
        if (!challengeNonceB64) return;
      }
      let sigB64 = manualSigB64.trim();
      if (!sigB64 && privateSeedInput.trim()) {
        const seed = parseSeed32(privateSeedInput);
        const nonceBytes = b64ToBytes(challengeNonceB64);
        const msg = buildChallengePayload(nonceBytes, selectedKeyId, challengeOrigin);
        sigB64 = await signEd25519InBrowser(seed, msg);
        privateSeedInput = '';
      }
      if (!sigB64) {
        throw new Error(lang === 'en' ? 'Provide private seed or Base64 signature' : '请提供私钥种子或粘贴签名结果');
      }
      const st = await apiFetch('/api/auth/login-ed25519', {
        method: 'POST',
        body: JSON.stringify({
          key_id: selectedKeyId,
          nonce_b64: challengeNonceB64,
          signature_b64: sigB64,
        }),
      });
      challengeNonceB64 = '';
      manualSigB64 = '';
      await onAuthenticated(st);
    } catch (err) {
      loginError = err.message;
      challengeNonceB64 = '';
    } finally {
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
      curPassword = loginPass;
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
          new_username: username,
        }),
      });
      curPassword = '';
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
          <div class="brand-logo">V</div>
          <div>
            <div style="font-size:18px;font-weight:700;">Vane Gateway</div>
            <div style="font-size:12px;color:var(--text-secondary);">{t.subtitle}</div>
          </div>
        </div>
        <button type="button" class="btn btn-sm" onclick={toggleLang}>{lang === 'zh' ? 'EN' : '中文'}</button>
      </div>

      {#if passwordLoginEnabled && hasEd25519Keys}
        <div class="pill-tabs" style="width:100%;margin-bottom:16px;display:grid;grid-template-columns:1fr 1fr;">
          <button type="button" class="pill-tab {loginMode === 'password' ? 'active' : ''}" onclick={() => loginMode = 'password'}>
            {t.pwLoginTab}
          </button>
          <button type="button" class="pill-tab {loginMode === 'ed25519' ? 'active' : ''}" onclick={() => loginMode = 'ed25519'}>
            {t.keyLoginTab}
          </button>
        </div>
      {/if}

      {#if loginError}
        <div class="badge badge-danger" style="width:100%;padding:10px 12px;border-radius:10px;margin-bottom:14px;white-space:normal;">
          {loginError}
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
            <input id="login-pass" type="password" bind:value={loginPass} autocomplete="current-password" required />
          </div>
          {#if totpEnabled}
            <div class="field">
              <label for="login-totp">{t.totpCode}</label>
              <input id="login-totp" type="text" class="mono" placeholder="123456 / xxxx-xxxx-xxxx-xxxx" bind:value={loginTotp} required />
            </div>
          {/if}
          <button type="submit" class="btn btn-primary" style="width:100%;margin-top:6px;" disabled={busy}>
            {t.loginBtn}
          </button>
        </form>
      {:else}
        <form onsubmit={submitEd25519Login}>
          <div class="field">
            <label for="key-id-sel">{t.keyIdLabel}</label>
            <select id="key-id-sel" bind:value={selectedKeyId}>
              {#each ed25519KeyIds as kid}
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
            <div class="subcard mono" style="font-size:11px;margin-bottom:12px;word-break:break-all;">
              <div>Origin: {challengeOrigin}</div>
              <div>Nonce: {challengeNonceB64}</div>
            </div>
          {/if}
          <div class="field">
            <label for="ed-seed">{t.signWithKey}</label>
            <input id="ed-seed" type="password" class="mono" bind:value={privateSeedInput} placeholder="64-char hex or Base64 32B seed" />
          </div>
          <div class="field">
            <label for="ed-sig">{t.orManualSig}</label>
            <input id="ed-sig" type="text" class="mono" bind:value={manualSigB64} placeholder="Base64 Ed25519 signature" />
          </div>
          <button type="submit" class="btn btn-primary" style="width:100%;" disabled={busy}>
            {t.verifyKeyBtn}
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
        <div class="badge badge-danger" style="width:100%;padding:10px 12px;border-radius:10px;margin-bottom:14px;white-space:normal;">
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
