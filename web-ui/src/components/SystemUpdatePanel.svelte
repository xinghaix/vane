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
  }
</script>

<!-- 安全承诺横幅：永不自动更新 -->
<div class="banner banner-info" style="margin-bottom:16px;">
  <div style="display:flex;align-items:flex-start;gap:10px;">
    <Icons name="shield" size={18} />
    <div>
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
    <div>
      <div class="card-title">
        <Icons name="refresh" size={16} />
        <span>{t.update.checkCardTitle}</span>
      </div>
      <div style="font-size:12px;color:var(--text-secondary);margin-top:2px;">
        {t.update.checkCardDesc}
      </div>
    </div>
    <button type="button" class="btn btn-primary btn-sm" disabled={checking} onclick={checkNow}>
      <Icons name="refresh" size={14} />
      <span>{checking ? t.update.checking : t.update.checkNow}</span>
    </button>
  </div>

  {#if status}
    <div class="update-meta-grid" style="margin-bottom:16px;grid-template-columns:repeat(3, minmax(0, 1fr));">
      <div class="subcard">
        <div class="update-meta-label">{t.update.currentVersion}</div>
        <div class="update-meta-val mono">v{status.current_version}</div>
      </div>
      <div class="subcard">
        <div class="update-meta-label">{t.update.platformArch}</div>
        <div class="update-meta-val mono">{status.os} / {status.arch}</div>
      </div>
      <div class="subcard">
        <div class="update-meta-label">{t.update.tempSpace}</div>
        <div class="update-meta-val mono">{status.temp_available_mb} MiB</div>
      </div>
    </div>

    {#if !status.executable_writable}
      <div class="banner banner-warn" style="margin-bottom:14px;">
        <Icons name="alert" size={16} />
        <div style="font-size:12.5px;">
          {t.update.notWritableWarn} <code class="mono">{status.executable_path}</code>
        </div>
      </div>
    {/if}

    {#if status.last_error}
      <div class="banner banner-danger" style="margin-bottom:14px;">
        <Icons name="alert" size={16} />
        <div style="font-size:12.5px;">{status.last_error}</div>
      </div>
    {/if}

    {#if status.latest}
      <div class="subcard" style="margin-bottom:16px;border-color:{status.has_update ? 'var(--accent)' : 'var(--border-subtle)'};">
        <div class="row-between" style="gap:10px;flex-wrap:wrap;margin-bottom:8px;">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
            <span class="badge {status.has_update ? 'badge-ok' : 'badge-muted'}">
              {status.has_update ? t.update.newVersionFound : t.update.upToDate}
            </span>
            <span class="mono" style="font-weight:700;font-size:14.5px;">{status.latest.tag_name}</span>
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
        {#if status.latest.notes}
          <pre class="inbox-detail-body" style="max-height:180px;margin-bottom:10px;">{status.latest.notes}</pre>
        {/if}
        <div class="btn-group">
          {#if status.latest.html_url}
            <a class="btn btn-xs" href={status.latest.html_url} target="_blank" rel="noopener noreferrer">
              <Icons name="external_link" size={13} />
              <span>{t.update.viewRelease}</span>
            </a>
          {/if}
          {#if status.latest.asset_url}
            <a class="btn btn-xs btn-primary" href={status.latest.asset_url} target="_blank" rel="noopener noreferrer">
              <Icons name="download" size={13} />
              <span>{t.update.downloadMatching} ({status.latest.asset_name})</span>
            </a>
          {/if}
          {#if status.latest.checksums_url}
            <a class="btn btn-xs" href={status.latest.checksums_url} target="_blank" rel="noopener noreferrer">
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
        <div style="font-weight:600;font-size:13.5px;">{t.update.autoCheckToggle}</div>
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

    <div class="form-grid" style="margin-bottom:12px;">
      <div class="field" style="margin-bottom:0;">
        <label for="upd-interval">{t.update.checkInterval}</label>
        <input id="upd-interval" type="number" min="1" max="168" bind:value={checkIntervalHours} />
      </div>
      <div class="field" style="margin-bottom:0;">
        <label for="upd-repo">{t.update.repoLabel}</label>
        <input id="upd-repo" type="text" class="mono" bind:value={repo} placeholder="xinghaix/vane" required />
      </div>
    </div>

    <div style="display:flex;justify-content:flex-end;">
      <button type="submit" class="btn btn-sm btn-primary" disabled={savingCfg || !cfgDirty}>
        {savingCfg ? '...' : t.saveSettings}
      </button>
    </div>
  </form>
</div>

<!-- 2. 手动上传压缩包安全沙箱更新 -->
<div class="card">
  <div class="card-header">
    <div>
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
    <div class="banner banner-warn" style="margin-bottom:14px;">
      <div style="display:flex;align-items:flex-start;gap:10px;">
        <Icons name="shield" size={16} />
        <div>
          <div style="font-weight:700;font-size:13px;">{t.update.manualUploadDisabledTitle}</div>
          <div style="font-size:12px;color:var(--text-secondary);margin-top:2px;line-height:1.5;">
            {t.update.manualUploadDisabledGuide}
          </div>
        </div>
      </div>
    </div>
  {:else if !signingKeyReady}
    <div class="banner banner-warn" style="margin-bottom:14px;">
      <div style="display:flex;align-items:flex-start;gap:10px;">
        <Icons name="alert" size={16} />
        <div style="font-size:12.5px;">{t.update.signingKeyMissingWarn}</div>
      </div>
    </div>
  {/if}

  <form onsubmit={startUploadUpdate}>
    <div class="field">
      <label for="upd-file">{t.update.selectArchive}</label>
      <input
        bind:this={fileInput}
        id="upd-file"
        type="file"
        accept=".tar.gz,.tgz,application/gzip,application/x-gzip"
        disabled={uploading || !manualUploadEnabled || !signingKeyReady}
        onchange={handleFileChange}
        required
      />
      {#if selectedFile}
        <div class="mono" style="font-size:12px;color:var(--text-secondary);margin-top:6px;">
          {selectedFile.name} · {formatMB(selectedFile.size)}
        </div>
      {/if}
    </div>

    <div class="field">
      <label for="upd-sig">{t.update.signatureLabel}</label>
      <input
        id="upd-sig"
        type="text"
        class="mono"
        style="font-size:12px;"
        placeholder={t.update.signaturePh}
        disabled={uploading || !manualUploadEnabled || !signingKeyReady}
        bind:value={updateSignature}
        required
      />
      <div style="font-size:11.5px;color:var(--text-muted);margin-top:4px;">
        {t.update.signatureHint}
      </div>
    </div>

    <div class="field">
      <label for="upd-sha">{t.update.expectedShaLabel}</label>
      <textarea
        id="upd-sha"
        rows="2"
        class="mono"
        style="font-size:12px;"
        placeholder={t.update.expectedShaPh}
        disabled={uploading || !manualUploadEnabled || !signingKeyReady}
        bind:value={expectedSha256}
      ></textarea>
      <div style="font-size:11.5px;color:var(--text-muted);margin-top:4px;">
        {t.update.expectedShaHint}
      </div>
    </div>

    {#if uploadError}
      <div class="banner banner-danger" style="margin-bottom:14px;">
        <Icons name="alert" size={16} />
        <div style="font-size:12.5px;word-break:break-word;">{uploadError}</div>
      </div>
    {/if}

    {#if uploadResult}
      <div class="banner banner-ok" style="margin-bottom:14px;display:block;">
        <div style="display:flex;align-items:center;gap:8px;font-weight:700;margin-bottom:8px;">
          <Icons name="check" size={16} />
          <span>{t.update.uploadSuccessTitle}: v{uploadResult.previous_version} → v{uploadResult.new_version} ({uploadResult.os}/{uploadResult.arch})</span>
        </div>
        <div class="mono" style="font-size:12px;color:var(--text-secondary);display:grid;gap:4px;">
          <div>{t.update.installedPath}: {uploadResult.executable_path}</div>
          <div>{t.update.backupPath}: {uploadResult.backup_path}</div>
        </div>
        <div style="margin-top:10px;font-size:12.5px;font-weight:600;color:var(--text-primary);">
          {t.update.restartNotice}
        </div>
        <div class="btn-group" style="margin-top:8px;">
          <button type="button" class="btn btn-xs" onclick={() => copyTextSafe('/etc/init.d/vane restart')}>
            <Icons name="copy" size={12} />
            <span class="mono">/etc/init.d/vane restart</span>
          </button>
          <button type="button" class="btn btn-xs" onclick={() => copyTextSafe('systemctl restart vane')}>
            <Icons name="copy" size={12} />
            <span class="mono">systemctl restart vane</span>
          </button>
        </div>
      </div>
    {/if}

    <div class="row-between" style="flex-wrap:wrap;gap:10px;">
      <div style="font-size:12px;color:var(--text-muted);">
        {t.update.reauthRequiredNote}
      </div>
      <button
        type="submit"
        class="btn btn-primary btn-sm"
        disabled={!manualUploadEnabled || !signingKeyReady || !selectedFile || !updateSignature.trim() || uploading || (status && !status.executable_writable)}
      >
        <Icons name="shield" size={14} />
        <span>{uploading ? t.update.uploading : t.update.verifyAndUpload}</span>
      </button>
    </div>
  </form>
</div>
