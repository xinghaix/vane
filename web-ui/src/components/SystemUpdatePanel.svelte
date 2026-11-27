<script>
  import Icons from './Icons.svelte';
  import { formatUnixTime, uint8ToBase64, copyText, localizeError } from '../lib/helpers.js';

  let {
    t,
    lang = 'zh',
    settingsJson,
    onSaveSettings,
    requestReauth,
    apiFetch,
    showToast,
  } = $props();

  let status = $state(null);
  let limits = $state({ max_upload_mb: 48, max_uncompressed_mb: 128, max_entries: 64 });
  let allowManualUpload = $state(null);
  let signingKeyConfigured = $state(null);
  let loading = $state(false);
  let checking = $state(false);
  let savingCfg = $state(false);
  let uploading = $state(false);
  let uploadResult = $state(null);
  let uploadError = $state('');

  let autoCheck = $state(false);
  let checkIntervalHours = $state(24);
  let repo = $state('xinghaix/vane');
  let syncedSig = $state('');

  let fileInput = $state(null);
  let selectedFile = $state(null);
  let updateSignature = $state('');
  let expectedSha256 = $state('');

  let manualUploadEnabled = $derived(
    allowManualUpload !== null
      ? allowManualUpload
      : Boolean(settingsJson?.admin?.allow_manual_update_upload)
  );
  let signingKeyReady = $derived(
    signingKeyConfigured !== null
      ? signingKeyConfigured
      : Boolean(settingsJson?.admin?.update_signing_public_key)
  );

  $effect(() => {
    const u = settingsJson?.update;
    if (!u) return;
    const sig = JSON.stringify({
      auto_check: Boolean(u.auto_check),
      check_interval_hours: Number(u.check_interval_hours || 24),
      repo: String(u.repo || 'xinghaix/vane'),
    });
    if (sig !== syncedSig) {
      syncedSig = sig;
      autoCheck = Boolean(u.auto_check);
      checkIntervalHours = Number(u.check_interval_hours || 24);
      repo = String(u.repo || 'xinghaix/vane');
    }
  });

  let cfgDirty = $derived(
    syncedSig !==
      JSON.stringify({
        auto_check: Boolean(autoCheck),
        check_interval_hours: Number(checkIntervalHours || 24),
        repo: String(repo || '').trim(),
      })
  );

  async function loadStatus(silent = false) {
    if (!silent) loading = true;
    try {
      const r = await apiFetch('/api/update/status');
      status = r.status || null;
      if (r.limits) limits = r.limits;
      if (typeof r.allow_manual_update_upload === 'boolean') {
        allowManualUpload = r.allow_manual_update_upload;
      }
      if (typeof r.update_signing_key_configured === 'boolean') {
        signingKeyConfigured = r.update_signing_key_configured;
      }
    } catch (err) {
      if (!silent) showToast(err.message, 'error');
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    loadStatus(true);
  });

  async function saveUpdateConfig(e) {
    e?.preventDefault?.();
    if (savingCfg || !settingsJson) return;
    const cleanRepo = String(repo || '').trim();
    if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(cleanRepo) || cleanRepo.includes('..')) {
      showToast(t.update.invalidRepo, 'error');
      return;
    }
    const hours = Math.max(1, Math.min(168, Number(checkIntervalHours) || 24));
    savingCfg = true;
    try {
      const next = JSON.parse(JSON.stringify(settingsJson));
      next.update = {
        auto_check: Boolean(autoCheck),
        check_interval_hours: hours,
        repo: cleanRepo,
      };
      const ok = await onSaveSettings(next);
      if (ok) {
        await loadStatus(true);
      }
    } finally {
      savingCfg = false;
    }
  }

  async function checkNow() {
    if (checking) return;
    checking = true;
    try {
      const r = await apiFetch('/api/update/check', { method: 'POST' });
      status = r.status || status;
      if (typeof r.allow_manual_update_upload === 'boolean') {
        allowManualUpload = r.allow_manual_update_upload;
      }
      if (typeof r.update_signing_key_configured === 'boolean') {
        signingKeyConfigured = r.update_signing_key_configured;
      }
      if (status?.has_update && status?.latest) {
        showToast(`${t.update.newVersionFound}: ${status.latest.tag_name}`, 'info');
      } else {
        showToast(t.update.upToDate, 'success');
      }
    } catch (err) {
      showToast(err.message, 'error');
      await loadStatus(true);
    } finally {
      checking = false;
    }
  }

  function handleFileChange(e) {
    uploadError = '';
    uploadResult = null;
    const f = e.currentTarget.files?.[0];
    if (!f) {
      selectedFile = null;
      return;
    }
    const maxBytes = (limits.max_upload_mb || 48) * 1024 * 1024;
    if (f.size <= 0) {
      showToast(t.update.emptyFile, 'error');
      e.currentTarget.value = '';
      selectedFile = null;
      return;
    }
    if (f.size > maxBytes) {
      showToast(t.update.fileTooLarge.replace('{mb}', String(limits.max_upload_mb || 48)), 'error');
      e.currentTarget.value = '';
      selectedFile = null;
      return;
    }
    const lower = f.name.toLowerCase();
    if (!lower.endsWith('.tar.gz') && !lower.endsWith('.tgz')) {
      showToast(t.update.invalidExt, 'error');
      e.currentTarget.value = '';
      selectedFile = null;
      return;
    }
    selectedFile = f;
  }

  async function startUploadUpdate(e) {
    e.preventDefault();
    if (!selectedFile || uploading) return;
    uploadError = '';
    uploadResult = null;

    if (!manualUploadEnabled) {
      uploadError = t.update.manualUploadDisabledGuide;
      showToast(t.errors.MANUAL_UPDATE_DISABLED, 'error');
      return;
    }
    const sigText = updateSignature.trim();
    if (!sigText) {
      uploadError = t.update.signatureRequiredErr;
      showToast(t.update.signatureRequiredErr, 'error');
      return;
    }

    const reauthToken = await requestReauth?.({
      title: t.reauth.updateTitle,
      description: t.reauth.updateDesc,
      actionLabel: t.update.verifyAndUpload,
      requireMfa: true,
    });
    if (!reauthToken) return;

    uploading = true;
    try {
      const headers = {
        'Content-Type': 'application/octet-stream',
        'X-Vane-Reauth-Token': reauthToken,
        'X-Vane-Filename': selectedFile.name,
        'X-Vane-Update-Signature': sigText,
      };
      const shaText = expectedSha256.trim();
      if (shaText) {
        headers['X-Vane-Expected-Sha256-B64'] = uint8ToBase64(new TextEncoder().encode(shaText));
      }

      const res = await fetch('/api/update/upload', {
        method: 'POST',
        headers,
        body: selectedFile,
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        const errCode =
          data.code || (typeof data.error === 'string' && /^[A-Z0-9_]+$/.test(data.error) ? data.error : '');
        if (res.status === 403 && errCode === 'MANUAL_UPDATE_DISABLED') {
          allowManualUpload = false;
          uploadError = t.update.manualUploadDisabledGuide;
          showToast(t.errors.MANUAL_UPDATE_DISABLED, 'error');
          return;
        }
        const msg = localizeError(data.message || data.error || `HTTP ${res.status}`, lang, errCode);
        uploadError = msg;
        showToast(msg, 'error');
        return;
      }
      uploadResult = data.result || null;
      selectedFile = null;
      updateSignature = '';
      expectedSha256 = '';
      if (fileInput) fileInput.value = '';
      showToast(t.update.uploadSuccessToast, 'success');
      await loadStatus(true);
    } catch (err) {
      uploadError = err?.message || String(err);
      showToast(uploadError, 'error');
    } finally {
      uploading = false;
    }
  }

  function formatMB(bytes) {
    return `${(Number(bytes || 0) / (1024 * 1024)).toFixed(2)} MiB`;
  }

  async function copyTextSafe(val) {
    if (await copyText(val)) showToast(t.copied, 'success');
    else showToast(t.copyFailed, 'error');
  }

  function resetUpdateConfig() {
    const u = settingsJson?.update;
    if (!u) return;
    autoCheck = Boolean(u.auto_check);
    checkIntervalHours = Number(u.check_interval_hours || 24);
    repo = String(u.repo || 'xinghaix/vane');
  }

  const MANUAL_UPDATE_SNIPPET = `[admin]\nallow_manual_update_upload = true\nupdate_signing_public_key = "<Ed25519 public key>"`;
  let uploadLocked = $derived(!manualUploadEnabled || !signingKeyReady);
  let copySnippetLabel = $derived(
    t.update?.copyConfigSnippet || (lang === 'en' ? 'Copy config.toml snippet' : '复制 config.toml 配置片段')
  );
  let uploadStepLabels = $derived(
    lang === 'en'
      ? ['1. Release archive', '2. Ed25519 signature', '3. Optional SHA-256']
      : ['1. 选择更新包', '2. 填写 Ed25519 签名', '3. 可选 SHA-256 校验']
  );
</script>

<!-- 安全承诺横幅：永不自动更新 -->
<div class="banner banner-info upd-banner-gap">
  <div class="banner-main">
    <Icons name="shield" size={18} />
    <div style="min-width:0;flex:1;">
      <div style="font-weight:700;">{t.update.neverAutoTitle}</div>
      <div style="font-size:12.5px;color:var(--text-secondary);margin-top:2px;">
        {t.update.neverAutoDesc}
      </div>
    </div>
  </div>
</div>

<!-- 1. 当前版本状态与 GitHub Release 自动检查提醒 -->
<div class="card" style="margin-bottom:18px;">
  <div class="card-header">
    <div style="min-width:0;flex:1;">
      <div class="card-title">
        <Icons name="refresh" size={16} />
        <span>{t.update.checkCardTitle}</span>
      </div>
      <div style="font-size:12px;color:var(--text-secondary);margin-top:2px;">
        {t.update.checkCardDesc}
      </div>
    </div>
    <button type="button" class="btn btn-primary btn-sm" disabled={checking} onclick={checkNow}>
      <span class:is-spinning={checking} class="upd-icon-inline">
        <Icons name="refresh" size={14} />
      </span>
      <span>{checking ? t.update.checking : t.update.checkNow}</span>
    </button>
  </div>

  {#if status}
    <div class="upd-meta-grid">
      <div class="subcard upd-meta-card">
        <div class="update-meta-label">{t.update.currentVersion}</div>
        <div class="update-meta-val mono">v{status.current_version}</div>
      </div>
      <div class="subcard upd-meta-card">
        <div class="update-meta-label">{t.update.tempSpace}</div>
        <div class="update-meta-val mono">{status.temp_available_mb} MiB</div>
      </div>
      <div class="subcard upd-meta-card upd-meta-card-wide">
        <div class="update-meta-label">{t.update.platformArch}</div>
        <div class="update-meta-val mono">{status.os} / {status.arch}</div>
      </div>
    </div>

    {#if !status.executable_writable}
      <div class="banner banner-warn upd-banner-gap">
        <div class="banner-main">
          <Icons name="alert" size={16} />
          <div style="font-size:12.5px;min-width:0;flex:1;">
            {t.update.notWritableWarn} <code class="code-chip mono">{status.executable_path}</code>
          </div>
        </div>
      </div>
    {/if}

    {#if status.last_error}
      <div class="banner banner-danger upd-banner-gap">
        <div class="banner-main">
          <Icons name="alert" size={16} />
          <div style="font-size:12.5px;min-width:0;flex:1;word-break:break-word;">{status.last_error}</div>
        </div>
      </div>
    {/if}

    {#if status.latest}
      <div class="subcard upd-release-card" class:has-update={status.has_update}>
        <div class="row-between" style="gap:10px;margin-bottom:8px;">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;min-width:0;">
            <span class="badge {status.has_update ? 'badge-ok' : 'badge-muted'}">
              {status.has_update ? t.update.newVersionFound : t.update.upToDate}
            </span>
            {#if status.has_update}
              <span class="upd-ver-jump mono">
                <span class="upd-ver-old">v{status.current_version}</span>
                <Icons name="arrow_right" size={12} />
                <span class="upd-ver-new">{status.latest.tag_name}</span>
              </span>
            {:else}
              <span class="mono" style="font-weight:700;font-size:14.5px;">{status.latest.tag_name}</span>
            {/if}
            {#if status.latest.name && status.latest.name !== status.latest.tag_name}
              <span style="font-size:13px;color:var(--text-secondary);">{status.latest.name}</span>
            {/if}
          </div>
          {#if status.last_check_unix}
            <span class="mono" style="font-size:11.5px;color:var(--text-muted);">
              {t.update.lastChecked}: {formatUnixTime(status.last_check_unix)}
            </span>
          {/if}
        </div>
        {#if status.latest.asset_name}
          <div class="upd-asset-row">
            <span class="meta-chip mono upd-asset-chip" title={status.latest.asset_name}>
              {status.latest.asset_name}
            </span>
          </div>
        {/if}
        {#if status.latest.notes}
          <pre class="inbox-detail-body" style="max-height:180px;margin-bottom:10px;">{status.latest.notes}</pre>
        {/if}
        <div class="btn-group upd-release-actions">
          {#if status.latest.asset_url}
            <a
              class="btn btn-sm btn-primary"
              href={status.latest.asset_url}
              target="_blank"
              rel="noopener noreferrer"
              title={status.latest.asset_name || t.update.downloadMatching}
            >
              <Icons name="download" size={14} />
              <span>{t.update.downloadMatching}</span>
            </a>
          {/if}
          {#if status.latest.html_url}
            <a class="btn btn-sm" href={status.latest.html_url} target="_blank" rel="noopener noreferrer">
              <Icons name="external_link" size={13} />
              <span>{t.update.viewRelease}</span>
            </a>
          {/if}
          {#if status.latest.checksums_url}
            <a class="btn btn-sm" href={status.latest.checksums_url} target="_blank" rel="noopener noreferrer">
              <Icons name="shield" size={13} />
              <span>SHA256SUMS</span>
            </a>
          {/if}
        </div>
      </div>
    {:else if status.last_check_unix}
      <div style="font-size:12px;color:var(--text-muted);margin-bottom:14px;">
        {t.update.lastChecked}: {formatUnixTime(status.last_check_unix)}
      </div>
    {/if}
  {:else if loading}
    <div class="skeleton" style="height:70px;margin-bottom:14px;"></div>
  {/if}

  <form onsubmit={saveUpdateConfig}>
    <div class="subcard row-between" style="margin-bottom:12px;">
      <div style="min-width:0;flex:1;">
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
          <span style="font-weight:600;font-size:13.5px;">{t.update.autoCheckToggle}</span>
          <span class="badge {autoCheck ? 'badge-ok' : 'badge-muted'}" style="font-size:10.5px;padding:1px 7px;">
            {autoCheck ? t.enabled : t.disabled}
          </span>
        </div>
        <div style="font-size:12px;color:var(--text-secondary);margin-top:2px;">{t.update.autoCheckDesc}</div>
      </div>
      <button
        type="button"
        class="switch"
        role="switch"
        aria-checked={Boolean(autoCheck)}
        aria-label={t.update.autoCheckToggle}
        onclick={() => (autoCheck = !autoCheck)}
      >
        <span class="switch-thumb"></span>
      </button>
    </div>

    <div class="form-grid" class:upd-dimmed={!autoCheck} style="margin-bottom:12px;">
      <div class="field" style="margin-bottom:0;">
        <label for="upd-interval">{t.update.checkInterval}</label>
        <input id="upd-interval" type="number" min="1" max="168" bind:value={checkIntervalHours} />
      </div>
      <div class="field" style="margin-bottom:0;">
        <label for="upd-repo">{t.update.repoLabel}</label>
        <input id="upd-repo" type="text" class="mono" bind:value={repo} placeholder="xinghaix/vane" required />
      </div>
    </div>

    <div class="row-between" style="justify-content:flex-end;gap:8px;">
      {#if cfgDirty}
        <span class="badge badge-warn" style="margin-right:auto;">{t.common.unsavedChanges}</span>
        <button type="button" class="btn btn-sm" disabled={savingCfg} onclick={resetUpdateConfig}>
          {t.common.discardChanges}
        </button>
      {/if}
      <button type="submit" class="btn btn-sm btn-primary" disabled={savingCfg || !cfgDirty}>
        <Icons name="save" size={14} />
        <span>{savingCfg ? '...' : t.saveSettings}</span>
      </button>
    </div>
  </form>
</div>

<!-- 2. 手动上传压缩包安全沙箱更新 -->
<div class="card">
  <div class="card-header">
    <div style="min-width:0;flex:1;">
      <div class="card-title">
        <Icons name="upload" size={16} />
        <span>{t.update.uploadCardTitle}</span>
      </div>
      <div style="font-size:12px;color:var(--text-secondary);margin-top:2px;">
        {t.update.uploadCardDesc}
      </div>
    </div>
    <span class="badge badge-muted mono">
      &lt;= {limits.max_upload_mb} MiB (.tar.gz)
    </span>
  </div>

  {#if !manualUploadEnabled}
    <div class="banner banner-warn upd-banner-gap">
      <div class="banner-main">
        <Icons name="shield" size={16} />
        <div style="min-width:0;flex:1;">
          <div style="font-weight:700;font-size:13px;">{t.update.manualUploadDisabledTitle}</div>
          <div style="font-size:12px;color:var(--text-secondary);margin-top:3px;line-height:1.5;">
            {t.update.manualUploadDisabledGuide}
          </div>
          <div class="upd-snippet-box">
            <pre class="mono upd-snippet-pre">{MANUAL_UPDATE_SNIPPET}</pre>
            <button
              type="button"
              class="btn btn-xs"
              onclick={() => copyTextSafe(MANUAL_UPDATE_SNIPPET)}
            >
              <Icons name="copy" size={12} />
              <span>{copySnippetLabel}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  {:else if !signingKeyReady}
    <div class="banner banner-warn upd-banner-gap">
      <div class="banner-main">
        <Icons name="alert" size={16} />
        <div style="font-size:12.5px;min-width:0;flex:1;">
          <div>{t.update.signingKeyMissingWarn}</div>
          <div class="upd-snippet-box">
            <pre class="mono upd-snippet-pre">{MANUAL_UPDATE_SNIPPET}</pre>
            <button
              type="button"
              class="btn btn-xs"
              onclick={() => copyTextSafe(MANUAL_UPDATE_SNIPPET)}
            >
              <Icons name="copy" size={12} />
              <span>{copySnippetLabel}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  {/if}

  <div class="upd-step-strip" aria-hidden="true">
    {#each uploadStepLabels as stepLabel, idx (stepLabel)}
      <span class="upd-step-pill" class:done={(idx === 0 && Boolean(selectedFile)) || (idx === 1 && Boolean(updateSignature.trim())) || (idx === 2 && Boolean(expectedSha256.trim()))}>
        {#if (idx === 0 && Boolean(selectedFile)) || (idx === 1 && Boolean(updateSignature.trim())) || (idx === 2 && Boolean(expectedSha256.trim()))}
          <Icons name="check" size={12} />
        {/if}
        <span>{stepLabel}</span>
      </span>
    {/each}
  </div>

  <form onsubmit={startUploadUpdate} class:upd-form-locked={uploadLocked}>
    <div class="field">
      <label for="upd-file">{t.update.selectArchive}</label>
      <input
        bind:this={fileInput}
        id="upd-file"
        type="file"
        accept=".tar.gz,.tgz,application/gzip,application/x-gzip"
        disabled={uploading || uploadLocked}
        onchange={handleFileChange}
        required
      />
      {#if selectedFile}
        <div class="upd-file-pill mono">
          <Icons name="check" size={13} />
          <span class="upd-file-name">{selectedFile.name}</span>
          <span class="upd-file-size">{formatMB(selectedFile.size)}</span>
        </div>
      {/if}
    </div>

    <div class="field">
      <label for="upd-sig">{t.update.signatureLabel}</label>
      <input
        id="upd-sig"
        type="text"
        class="mono upd-mono-input"
        placeholder={t.update.signaturePh}
        autocomplete="off"
        spellcheck="false"
        autocapitalize="off"
        disabled={uploading || uploadLocked}
        bind:value={updateSignature}
        required
      />
      <div class="field-hint">{t.update.signatureHint}</div>
    </div>

    <div class="field">
      <label for="upd-sha">{t.update.expectedShaLabel}</label>
      <textarea
        id="upd-sha"
        rows="2"
        class="mono upd-mono-input"
        placeholder={t.update.expectedShaPh}
        autocomplete="off"
        spellcheck="false"
        autocapitalize="off"
        disabled={uploading || uploadLocked}
        bind:value={expectedSha256}
      ></textarea>
      <div class="field-hint">{t.update.expectedShaHint}</div>
    </div>

    {#if uploadError}
      <div class="banner banner-danger upd-banner-gap">
        <div class="banner-main">
          <Icons name="alert" size={16} />
          <div style="font-size:12.5px;min-width:0;flex:1;word-break:break-word;">{uploadError}</div>
        </div>
      </div>
    {/if}

    {#if uploadResult}
      <div class="banner banner-ok upd-banner-gap" style="display:block;">
        <div style="display:flex;align-items:center;gap:8px;font-weight:700;margin-bottom:8px;flex-wrap:wrap;">
          <Icons name="check" size={16} />
          <span>{t.update.uploadSuccessTitle}: v{uploadResult.previous_version} → v{uploadResult.new_version} ({uploadResult.os}/{uploadResult.arch})</span>
        </div>
        <div class="mono upd-result-paths">
          <div>{t.update.installedPath}: <span class="upd-path-val">{uploadResult.executable_path}</span></div>
          <div>{t.update.backupPath}: <span class="upd-path-val">{uploadResult.backup_path}</span></div>
        </div>
        <div style="margin-top:10px;font-size:12.5px;font-weight:600;color:var(--text-primary);">
          {t.update.restartNotice}
        </div>
        <div class="btn-group" style="margin-top:8px;">
          <button type="button" class="btn btn-sm" onclick={() => copyTextSafe('/etc/init.d/vane restart')}>
            <Icons name="copy" size={12} />
            <span class="mono">/etc/init.d/vane restart</span>
          </button>
          <button type="button" class="btn btn-sm" onclick={() => copyTextSafe('systemctl restart vane')}>
            <Icons name="copy" size={12} />
            <span class="mono">systemctl restart vane</span>
          </button>
        </div>
      </div>
    {/if}

    <div class="row-between upd-submit-bar">
      <div style="font-size:12px;color:var(--text-muted);flex:1;min-width:200px;">
        {t.update.reauthRequiredNote}
      </div>
      <button
        type="submit"
        class="btn btn-primary btn-sm upd-submit-btn"
        disabled={uploadLocked || !selectedFile || !updateSignature.trim() || uploading || (status && !status.executable_writable)}
      >
        <Icons name="shield" size={14} />
        <span>{uploading ? t.update.uploading : t.update.verifyAndUpload}</span>
      </button>
    </div>
  </form>
</div>

<style>
  .upd-banner-gap {
    margin-bottom: 14px;
  }
  .upd-icon-inline {
    display: inline-flex;
    align-items: center;
  }
  .upd-meta-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 10px;
    margin-bottom: 16px;
  }
  .upd-meta-card {
    min-width: 0;
  }
  .upd-release-card {
    margin-bottom: 16px;
  }
  .upd-release-card.has-update {
    border-color: color-mix(in srgb, var(--accent) 45%, var(--border-subtle));
    background: color-mix(in srgb, var(--accent-soft) 35%, var(--bg-elevated));
  }
  .upd-ver-jump {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 13.5px;
    font-weight: 700;
  }
  .upd-ver-old {
    color: var(--text-muted);
    font-weight: 500;
  }
  .upd-ver-new {
    color: var(--accent);
  }
  .upd-asset-row {
    margin-bottom: 10px;
    min-width: 0;
  }
  .upd-asset-chip {
    display: inline-block;
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    padding: 3px 9px;
    border-radius: 8px;
    font-size: 11.5px;
    background: var(--bg-card);
    border: 1px solid var(--border-subtle);
    color: var(--text-secondary);
  }
  .upd-dimmed {
    opacity: 0.72;
  }
  .upd-snippet-box {
    margin-top: 10px;
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 8px;
  }
  .upd-snippet-pre {
    width: 100%;
    margin: 0;
    padding: 10px 12px;
    border-radius: 10px;
    background: var(--bg-card);
    border: 1px solid var(--border-subtle);
    font-size: 12px;
    line-height: 1.5;
    color: var(--text-primary);
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
  }
  .upd-step-strip {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
    margin-bottom: 14px;
  }
  .upd-step-pill {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 3px 10px;
    border-radius: 999px;
    font-size: 11.5px;
    font-weight: 600;
    background: var(--bg-elevated);
    border: 1px solid var(--border-subtle);
    color: var(--text-secondary);
  }
  .upd-step-pill.done {
    background: var(--accent-soft);
    border-color: color-mix(in srgb, var(--accent) 30%, transparent);
    color: var(--accent);
  }
  .upd-form-locked {
    opacity: 0.78;
  }
  .upd-file-pill {
    margin-top: 8px;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    max-width: 100%;
    padding: 4px 10px;
    border-radius: 10px;
    background: var(--accent-soft);
    border: 1px solid color-mix(in srgb, var(--accent) 26%, transparent);
    color: var(--accent);
    font-size: 12px;
  }
  .upd-file-name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .upd-file-size {
    flex-shrink: 0;
    color: var(--text-secondary);
  }
  .upd-mono-input {
    font-size: 12.5px;
  }
  .upd-result-paths {
    font-size: 12px;
    color: var(--text-secondary);
    display: grid;
    gap: 4px;
  }
  .upd-path-val {
    word-break: break-all;
    overflow-wrap: anywhere;
  }
  .upd-submit-bar {
    gap: 10px;
    margin-top: 4px;
  }
  @media (max-width: 920px) {
    .upd-mono-input {
      font-size: 16px;
    }
  }
  @media (max-width: 640px) {
    .upd-meta-grid {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
    .upd-meta-card-wide {
      grid-column: 1 / -1;
    }
    .upd-release-actions {
      width: 100%;
    }
    .upd-release-actions :global(.btn) {
      flex: 1 1 auto;
    }
    .upd-submit-btn {
      width: 100%;
    }
  }
</style>
