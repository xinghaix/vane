<script>
  import Icons from './Icons.svelte';
  import { registerOverlay } from '../lib/overlay.js';
  import { getPasskeyAssertion, isPasskeySupported } from '../lib/webauthn.js';

  let {
    open = false,
    title = '',
    description = '',
    actionLabel = '',
    unlockModule = '',
    requireMfa = false,
    mfaConfigured = false,
    username = 'admin',
    t,
    lang = 'zh',
    apiFetch,
    onSuccess,
    onCancel,
  } = $props();

  let cardEl = $state(null);
  let loadingOpts = $state(false);
  let busy = $state(false);
  let errorMsg = $state('');
  let passkeyHint = $state('');
  let method = $state('password'); // 'passkey' | 'password' | 'totp' | ''
  let methods = $state({ password: true, totp: false, passkey: false });
  let serverMfaEnabled = $state(false);
  let passkeyOptions = $state(null);
  let passkeyReason = $state('');

  let password = $state('');
  let showPassword = $state(false);
  let totpCode = $state('');
  let openNonce = 0;

  let hasUsablePasskey = $derived(Boolean(methods.passkey && isPasskeySupported()));
  let hasUsableTotp = $derived(Boolean(methods.totp));
  // 当操作要求 MFA 且账号已启用 MFA（TOTP 或 Passkey）时，禁止回退至纯密码验证
  let mfaEnforced = $derived(
    Boolean(requireMfa && (serverMfaEnabled || hasUsablePasskey || hasUsableTotp || mfaConfigured || Boolean(passkeyReason)))
  );

  // 优先级：通行密钥 (Passkey) > 管理员密码（非 MFA 强制时） > TOTP 动态码
  let availableMethods = $derived(
    [
      hasUsablePasskey ? 'passkey' : null,
      !mfaEnforced && methods.password ? 'password' : null,
      hasUsableTotp ? 'totp' : null,
    ].filter(Boolean)
  );

  function resetFields() {
    password = '';
    showPassword = false;
    totpCode = '';
    errorMsg = '';
    passkeyHint = '';
    serverMfaEnabled = false;
    busy = false;
  }

  async function loadOptions(myNonce) {
    loadingOpts = true;
    errorMsg = '';
    passkeyHint = '';
    try {
      const r = await apiFetch('/api/auth/reauth/options', { method: 'POST', body: '{}' });
      if (myNonce !== openNonce || !open) return;
      methods = r.methods || { password: true, totp: false, passkey: false };
      passkeyOptions = r.passkey_options || null;
      passkeyReason = r.passkey_unavailable_reason || '';
      serverMfaEnabled = Boolean(
        r.mfa_enabled ?? (methods.totp || methods.passkey || Boolean(passkeyReason) || mfaConfigured)
      );
      const usablePasskey = Boolean(methods.passkey && passkeyOptions && isPasskeySupported());
      const usableTotp = Boolean(methods.totp);
      const enforceMfa = Boolean(requireMfa && (serverMfaEnabled || usablePasskey || usableTotp || mfaConfigured || Boolean(passkeyReason)));
      if (usablePasskey) {
        method = 'passkey';
      } else if (enforceMfa) {
        method = usableTotp ? 'totp' : '';
      } else if (methods.password) {
        method = 'password';
      } else if (usableTotp) {
        method = 'totp';
      } else {
        method = '';
      }
      loadingOpts = false;

      // 若通行密钥可用且被选为默认首选，自动拉起系统/密码管理器通行密钥验证；
      // 若用户取消或浏览器限制自动拉起，则静默回退到按钮/密码/TOTP 切换态。
      if (method === 'passkey' && passkeyOptions && myNonce === openNonce && open) {
        queueMicrotask(() => {
          if (myNonce === openNonce && open && method === 'passkey') {
            submitPasskey(true, myNonce);
          }
        });
      }
    } catch (err) {
      if (myNonce === openNonce) {
        errorMsg = err.message;
        loadingOpts = false;
      }
    }
  }

  $effect(() => {
    if (!open) {
      openNonce += 1;
      resetFields();
      return;
    }
    const myNonce = ++openNonce;
    resetFields();
    loadOptions(myNonce);
    return registerOverlay({
      onDismiss: () => {
        if (!busy) onCancel?.();
      },
      trapContainer: () => cardEl,
    });
  });

  function autofocus(node) {
    queueMicrotask(() => node.focus({ preventScroll: true }));
  }

  async function submitPassword(e) {
    e.preventDefault();
    if (busy || !password || mfaEnforced) return;
    busy = true;
    errorMsg = '';
    try {
      const payload = { method: 'password', password };
      if (unlockModule) payload.unlock_module = unlockModule;
      const r = await apiFetch('/api/auth/reauth/verify', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      resetFields();
      onSuccess?.(r.reauth_token, r.unlocked_modules || null);
    } catch (err) {
      errorMsg = err.message;
      password = '';
    } finally {
      busy = false;
    }
  }

  async function submitTotp(e) {
    e.preventDefault();
    if (busy || !totpCode.trim()) return;
    busy = true;
    errorMsg = '';
    try {
      const payload = { method: 'totp', totp_code: totpCode.trim() };
      if (unlockModule) payload.unlock_module = unlockModule;
      const r = await apiFetch('/api/auth/reauth/verify', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      resetFields();
      onSuccess?.(r.reauth_token, r.unlocked_modules || null);
    } catch (err) {
      errorMsg = err.message;
      totpCode = '';
    } finally {
      busy = false;
    }
  }

  async function submitPasskey(auto = false, myNonce = openNonce) {
    if (busy || myNonce !== openNonce || !open) return;
    busy = true;
    errorMsg = '';
    passkeyHint = '';
    try {
      let opts = passkeyOptions;
      if (!opts) {
        const fresh = await apiFetch('/api/auth/reauth/options', { method: 'POST', body: '{}' });
        if (myNonce !== openNonce || !open) return;
        opts = fresh.passkey_options;
        passkeyOptions = opts;
      }
      if (!opts) {
        throw new Error(passkeyReason || (lang === 'en' ? 'Passkey unavailable on this origin' : '当前访问地址不可用通行密钥'));
      }
      const assertion = await getPasskeyAssertion(opts, lang);
      if (myNonce !== openNonce || !open) return;
      passkeyOptions = null;
      const payload = { method: 'passkey', ...assertion };
      if (unlockModule) payload.unlock_module = unlockModule;
      const r = await apiFetch('/api/auth/reauth/verify', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      if (myNonce !== openNonce || !open) return;
      resetFields();
      onSuccess?.(r.reauth_token, r.unlocked_modules || null);
    } catch (err) {
      if (myNonce !== openNonce || !open) return;
      passkeyOptions = null;
      if (auto) {
        // 自动拉起被用户取消或浏览器要求点击触发时，不弹红错，保留重试按钮与方式切换
        if (mfaEnforced) {
          passkeyHint = hasUsableTotp ? t.reauth.passkeyAutoCancelledMfaHint : t.reauth.passkeyAutoCancelledMfaOnlyHint;
        } else {
          passkeyHint = t.reauth.passkeyAutoCancelledHint;
        }
      } else {
        errorMsg = err.message;
      }
    } finally {
      if (myNonce === openNonce) busy = false;
    }
  }
</script>

{#if open}
  <div
    class="modal-backdrop"
    role="presentation"
    onclick={(e) => {
      if (e.target === e.currentTarget && !busy) onCancel?.();
    }}
  >
    <div
      bind:this={cardEl}
      class="modal-card"
      style="max-width:460px;"
      role="dialog"
      aria-modal="true"
      aria-labelledby="reauth-modal-title"
      tabindex="-1"
    >
      <div class="row-between" style="margin-bottom:10px;flex-wrap:nowrap;">
        <div style="display:flex;align-items:center;gap:11px;min-width:0;flex:1;">
          <div class="icon-tile" style="width:36px;height:36px;border-radius:11px;">
            <Icons name="shield" size={18} />
          </div>
          <h3 id="reauth-modal-title" style="font-size:16px;font-weight:700;line-height:1.3;min-width:0;">
            {title || t.reauth.defaultTitle}
          </h3>
        </div>
        <button type="button" class="btn btn-ghost btn-icon btn-icon-sm" disabled={busy} aria-label={t.close} onclick={() => onCancel?.()}>
          <Icons name="x" size={16} />
        </button>
      </div>

      {#if description}
        <p style="font-size:12.5px;color:var(--text-secondary);margin-bottom:14px;line-height:1.5;">{description}</p>
      {/if}

      {#if loadingOpts}
        <div class="subcard" style="display:flex;align-items:center;justify-content:center;gap:8px;color:var(--text-secondary);font-size:13px;padding:20px;">
          <Icons name="loader" size={15} class="is-spinning" />
          <span>{t.common.loading}</span>
        </div>
      {:else}
        {#if mfaEnforced && availableMethods.length > 0}
          <div class="inline-alert inline-alert-info" style="margin-bottom:12px;">
            <Icons name="shield" size={14} />
            <span>{t.reauth.mfaRequiredHint}</span>
          </div>
        {/if}

        {#if availableMethods.length > 1}
          <div class="pill-tabs" role="tablist" style="width:100%;margin-bottom:14px;display:flex;">
            {#if hasUsablePasskey}
              <button
                type="button"
                role="tab"
                aria-selected={method === 'passkey'}
                class="pill-tab {method === 'passkey' ? 'active' : ''}"
                style="flex:1;"
                onclick={() => { method = 'passkey'; errorMsg = ''; passkeyHint = ''; }}
              >
                {t.reauth.tabPasskey}
              </button>
            {/if}
            {#if !mfaEnforced && methods.password}
              <button
                type="button"
                role="tab"
                aria-selected={method === 'password'}
                class="pill-tab {method === 'password' ? 'active' : ''}"
                style="flex:1;"
                onclick={() => { method = 'password'; errorMsg = ''; passkeyHint = ''; }}
              >
                {t.reauth.tabPassword}
              </button>
            {/if}
            {#if hasUsableTotp}
              <button
                type="button"
                role="tab"
                aria-selected={method === 'totp'}
                class="pill-tab {method === 'totp' ? 'active' : ''}"
                style="flex:1;"
                onclick={() => { method = 'totp'; errorMsg = ''; passkeyHint = ''; }}
              >
                {t.reauth.tabTotp}
              </button>
            {/if}
          </div>
        {/if}

        {#if errorMsg}
          <div role="alert" class="inline-alert inline-alert-danger" style="margin-bottom:12px;">
            <Icons name="alert" size={15} />
            <span>{errorMsg}</span>
          </div>
        {/if}

        {#if method === 'passkey' && hasUsablePasskey}
          <div class="subcard" style="text-align:center;padding:18px 14px;margin-bottom:14px;">
            <div class="icon-tile" style="width:44px;height:44px;border-radius:12px;margin:0 auto 10px;">
              <Icons name="passkey" size={22} />
            </div>
            <div style="font-size:13.5px;font-weight:600;margin-bottom:4px;">{t.reauth.passkeyReadyTitle}</div>
            <div style="font-size:12px;color:var(--text-secondary);line-height:1.45;">
              {passkeyHint || t.reauth.passkeyReadyDesc}
            </div>
          </div>
          <div class="modal-actions">
            <button type="button" class="btn btn-sm" disabled={busy} onclick={() => onCancel?.()}>{t.cancel}</button>
            <button type="button" class="btn btn-primary btn-sm" disabled={busy} onclick={() => submitPasskey(false)}>
              {#if busy}
                <Icons name="loader" size={14} class="is-spinning" />
              {:else}
                <Icons name="passkey" size={15} />
              {/if}
              <span>{actionLabel || t.reauth.verifyPasskeyBtn}</span>
            </button>
          </div>
        {:else if method === 'totp' && hasUsableTotp}
          <form onsubmit={submitTotp}>
            <div class="field">
              <label for="reauth-totp">{t.reauth.totpLabel}</label>
              <input
                use:autofocus
                id="reauth-totp"
                name="otp"
                type="text"
                class="mono otp-input"
                inputmode="numeric"
                maxlength="6"
                pattern="[0-9]{6}"
                autocomplete="one-time-code"
                placeholder="000000"
                bind:value={totpCode}
                required
              />
            </div>
            <div class="modal-actions">
              <button type="button" class="btn btn-sm" disabled={busy} onclick={() => onCancel?.()}>{t.cancel}</button>
              <button type="submit" class="btn btn-primary btn-sm" disabled={busy || totpCode.trim().length < 6}>
                {#if busy}
                  <Icons name="loader" size={14} class="is-spinning" />
                {/if}
                <span>{actionLabel || t.reauth.verifyBtn}</span>
              </button>
            </div>
          </form>
        {:else if !mfaEnforced && methods.password}
          <form method="post" action="/api/auth/reauth/verify" onsubmit={submitPassword}>
            <!-- 隐藏的只读用户名字段，确保 1Password / Bitwarden / iCloud / Chrome 自动填充精准匹配当前管理员凭据 -->
            <input
              type="text"
              name="username"
              autocomplete="username"
              value={username}
              readonly
              tabindex="-1"
              aria-hidden="true"
              class="sr-only"
            />
            <div class="field">
              <label for="reauth-pw">{t.reauth.passwordLabel}</label>
              <div class="input-wrap">
                <input
                  use:autofocus
                  id="reauth-pw"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  class="has-addon"
                  autocomplete="current-password"
                  placeholder={t.passwordPlaceholder}
                  bind:value={password}
                  required
                />
                <button
                  type="button"
                  class="input-addon-btn"
                  aria-label={t.common.toggleSecret}
                  aria-pressed={showPassword}
                  onclick={() => (showPassword = !showPassword)}
                >
                  <Icons name={showPassword ? 'eye_off' : 'eye'} size={15} />
                </button>
              </div>
            </div>
            <div class="modal-actions">
              <button type="button" class="btn btn-sm" disabled={busy} onclick={() => onCancel?.()}>{t.cancel}</button>
              <button type="submit" class="btn btn-primary btn-sm" disabled={busy || !password}>
                {#if busy}
                  <Icons name="loader" size={14} class="is-spinning" />
                {/if}
                <span>{actionLabel || t.reauth.verifyBtn}</span>
              </button>
            </div>
          </form>
        {:else}
          <div class="inline-alert inline-alert-warn" style="margin-bottom:14px;">
            <Icons name="alert" size={15} />
            <span>
              {#if mfaEnforced}
                {passkeyReason ? `${t.reauth.mfaUnavailableHint} (${passkeyReason})` : t.reauth.mfaUnavailableHint}
              {:else}
                {passkeyReason || (lang === 'en' ? 'No interactive re-auth method is currently available on this origin.' : '当前访问地址下暂无可用的二次验证方式，请在安全设置中开启密码、TOTP 或使用域名访问以启用通行密钥。')}
              {/if}
            </span>
          </div>
          <div class="modal-actions">
            <button type="button" class="btn btn-sm" onclick={() => onCancel?.()}>{t.close}</button>
          </div>
        {/if}

        {#if !methods.passkey && passkeyReason && availableMethods.length > 0}
          <div style="margin-top:12px;font-size:11.5px;color:var(--text-muted);display:flex;align-items:flex-start;gap:6px;line-height:1.45;">
            <Icons name="info" size={13} />
            <span>{passkeyReason}</span>
          </div>
        {/if}
      {/if}
    </div>
  </div>
{/if}
