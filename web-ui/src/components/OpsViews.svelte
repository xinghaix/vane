<script>
  import Icons from './Icons.svelte';
  import SecretField from './SecretField.svelte';
  import HeaderRowsEditor from './HeaderRowsEditor.svelte';
  import {
    splitLines,
    kvObjectToRows,
    rowsToKvObject,
    deepClone,
    copyText,
    downloadTextFile,
    formatBytes,
    formatUnixTime,
    resolveSecretInput,
    translateRuntimeStatus,
  } from '../lib/helpers.js';

  let {
    mode = 'docker',
    t,
    lang,
    settingsJson,
    dashboard,
    containers = [],
    dockerError = '',
    logs = [],
    logModules = [],
    logCapacity = 300,
    logLevelFilter = '',
    logModuleFilter = '',
    onChangeLogFilter,
    onPollLogsIncremental,
    webTerminalEnabled = false,
    onOpenContainerTerminal,
    onSaveSettings,
    askConfirm,
    apiFetch,
    showToast,
    onRefresh,
  } = $props();

  let busyKey = $state('');
  let busyToggleKey = $state('');
  let saving = $state(false);
  let dockerQuery = $state('');
  let dockerStateFilter = $state('all'); // all | running | exited

  // ---------------- Docker Logs Modal ----------------
  let logModalOpen = $state(false);
  let logModalContainerId = $state('');
  let logModalContainerName = $state('');
  let logModalLines = $state(200);
  let logModalText = $state('');
  let logModalQuery = $state('');
  let logModalAutoRefresh = $state(false);
  let logModalLoading = $state(false);
  let logModalPreEl = $state(null);
  let logModalReqSeq = 0;

  const TAIL_OPTIONS = [100, 200, 300, 500, 1000];

  function closeLogModal() {
    logModalOpen = false;
    logModalAutoRefresh = false;
    logModalLoading = false;
    logModalText = '';
    logModalQuery = '';
  }

  function runContainerActionConfirmed(c, action) {
    const label = c.name || c.id;
    const exec = async () => {
      busyKey = `dk:${c.id}:${action}`;
      try {
        await apiFetch(`/api/docker/containers/${encodeURIComponent(c.id)}/${action}`, { method: 'POST' });
        showToast(`${label}: ${action} OK`, 'success');
        await onRefresh();
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        busyKey = '';
      }
    };
    if (action === 'start') {
      exec();
      return;
    }
    askConfirm({
      title: action === 'stop' ? t.dk.stopConfirmTitle : t.dk.restartConfirmTitle,
      message: `${label} (${c.image})`,
      confirmLabel: action === 'stop' ? t.dk.stop : t.dk.restart,
      danger: action === 'stop',
      onConfirm: exec,
    });
  }

  async function viewContainerLogs(c) {
    logModalContainerId = c.id;
    logModalContainerName = c.name || c.id;
    logModalLines = Number(settingsJson?.docker?.log_tail_default || 200);
    logModalQuery = '';
    logModalText = '';
    logModalAutoRefresh = false;
    logModalOpen = true;
    await reloadContainerLogs(false);
  }

  async function reloadContainerLogs(silent = false) {
    if (!logModalContainerId) return;
    const seq = ++logModalReqSeq;
    if (!silent) logModalLoading = true;
    try {
      const r = await apiFetch(
        `/api/docker/containers/${encodeURIComponent(logModalContainerId)}/logs?tail=${logModalLines}`
      );
      if (seq !== logModalReqSeq) return;
      logModalText = r.logs || '';
      if (!logModalQuery.trim()) {
        queueMicrotask(() => {
          if (logModalPreEl) logModalPreEl.scrollTop = logModalPreEl.scrollHeight;
        });
      }
    } catch (err) {
      if (seq !== logModalReqSeq) return;
      logModalText = `Error: ${err.message}`;
    } finally {
      if (seq === logModalReqSeq) logModalLoading = false;
    }
  }

  $effect(() => {
    if (!logModalOpen || !logModalAutoRefresh) return;
    const timer = setInterval(() => {
      if (document.visibilityState === 'visible') reloadContainerLogs(true);
    }, 3000);
    return () => clearInterval(timer);
  });

  function triggerDockerPrune() {
    askConfirm({
      title: t.dk.pruneConfirmTitle,
      message: t.cfg.lblPruneDesc,
      confirmLabel: t.dk.prune,
      danger: true,
      onConfirm: async () => {
        busyKey = 'dk:prune';
        try {
          const r = await apiFetch('/api/docker/prune', { method: 'POST' });
          let detail = '';
          try {
            const parsed = JSON.parse(r.result || '{}');
            const parts = [];
            const deletedCount = Array.isArray(parsed.ImagesDeleted) ? parsed.ImagesDeleted.length : 0;
            if (deletedCount > 0) {
              parts.push(lang === 'en' ? `${deletedCount} images` : `${deletedCount} 个镜像`);
            }
            if (typeof parsed.SpaceReclaimed === 'number') {
              parts.push(formatBytes(parsed.SpaceReclaimed));
            }
            if (parts.length) detail = ` (${parts.join(' · ')})`;
          } catch {
            // ignore
          }
          showToast(`${t.dk.prune}${detail}`, 'success');
          await onRefresh();
        } catch (err) {
          showToast(err.message, 'error');
        } finally {
          busyKey = '';
        }
      },
    });
  }

  let runningContainersCount = $derived((containers || []).filter((c) => c.state === 'running').length);
  let exitedContainersCount = $derived((containers || []).filter((c) => c.state !== 'running').length);

  let filteredContainers = $derived(
    (containers || []).filter((c) => {
      if (dockerStateFilter === 'running' && c.state !== 'running') return false;
      if (dockerStateFilter === 'exited' && c.state === 'running') return false;
      if (!dockerQuery.trim()) return true;
      return `${c.name} ${c.id} ${c.image} ${c.state}`.toLowerCase().includes(dockerQuery.trim().toLowerCase());
    })
  );

  let filteredContainerLogText = $derived.by(() => {
    if (!logModalText) return '';
    if (!logModalQuery.trim()) return logModalText;
    const q = logModalQuery.trim().toLowerCase();
    return logModalText
      .split('\n')
      .filter((l) => l.toLowerCase().includes(q))
      .join('\n');
  });

  // ---------------- Cron Drawer & Preview ----------------
  let cronDrawerOpen = $state(false);
  let cronEditIdx = $state(-1);
  let cronOrigName = $state('');
  let cronDraft = $state(null);
  let cronActionKind = $state('docker_prune_images');
  let cronArgsLines = $state('');
  let cronHttpUrlInput = $state('');
  let cronHttpUrlClear = $state(false);
  let cronHttpBodyInput = $state('');
  let cronHttpBodyClear = $state(false);
  let cronHttpHeaderRows = $state([]);
  let cronPreviewRuns = $state([]);
  let cronPreviewError = $state('');
  let expandedCronOutput = $state({});
  let cronPreviewTimer = null;
  let cronPreviewSeq = 0;

  let ruleNamesForKind = $derived(
    cronDraft?.action?.target_kind === 'reverse_proxy'
      ? (settingsJson?.reverse_proxy || []).map((r) => r.name)
      : (settingsJson?.port_forwards || []).map((p) => p.name)
  );

  $effect(() => {
    void mode;
    closeLogModal();
    cronDrawerOpen = false;
    dockerQuery = '';
    dockerStateFilter = 'all';
    if (cronPreviewTimer) {
      clearTimeout(cronPreviewTimer);
      cronPreviewTimer = null;
    }
  });

  $effect(() => {
    return () => {
      if (cronPreviewTimer) clearTimeout(cronPreviewTimer);
    };
  });

  async function refreshCronPreview(expr) {
    const trimmed = String(expr || '').trim();
    const seq = ++cronPreviewSeq;
    if (!trimmed) {
      cronPreviewRuns = [];
      cronPreviewError = '';
      return;
    }
    try {
      const r = await apiFetch(`/api/cron/preview?expr=${encodeURIComponent(trimmed)}`);
      if (seq !== cronPreviewSeq) return;
      if (r.valid) {
        cronPreviewRuns = r.formatted || [];
        cronPreviewError = '';
      } else {
        cronPreviewRuns = [];
        cronPreviewError = r.error || (lang === 'en' ? 'Invalid cron expression' : 'Cron 表达式格式错误');
      }
    } catch (err) {
      if (seq !== cronPreviewSeq) return;
      cronPreviewRuns = [];
      cronPreviewError = err.message || '';
    }
  }

  function scheduleCronPreview(expr) {
    if (cronPreviewTimer) clearTimeout(cronPreviewTimer);
    if (!String(expr || '').trim()) {
      cronPreviewSeq++;
      cronPreviewRuns = [];
      cronPreviewError = '';
      return;
    }
    cronPreviewTimer = setTimeout(() => {
      cronPreviewTimer = null;
      refreshCronPreview(expr);
    }, 300);
  }

  function cronActionSummary(action) {
    if (!action) return '';
    if (action.kind === 'docker_prune_images') {
      return action.dangling_only !== false ? 'dangling=true' : 'all unused';
    }
    if (action.kind === 'docker_restart_container') {
      return action.container || '';
    }
    if (action.kind === 'rule_toggle') {
      return `${action.target_kind}/${action.rule || '?'} → ${action.enable ? 'ON' : 'OFF'}`;
    }
    if (action.kind === 'http_request') {
      return `${action.method || 'POST'} HTTP`;
    }
    if (action.kind === 'exec') {
      const args = (action.args || []).join(' ');
      return args ? `${action.program} ${args}` : action.program || '';
    }
    return '';
  }

  function openCronDrawer(idx = -1) {
    if (cronPreviewTimer) {
      clearTimeout(cronPreviewTimer);
      cronPreviewTimer = null;
    }
    cronPreviewRuns = [];
    cronPreviewError = '';
    cronEditIdx = idx;
    const c = idx >= 0
      ? deepClone(settingsJson.cron[idx])
      : {
          name: `job_${(settingsJson?.cron?.length || 0) + 1}`,
          enabled: true,
          schedule: '0 0 4 * * *',
          timeout_secs: 60,
          action: { kind: 'docker_prune_images', dangling_only: true },
          notify_on_failure: true,
        };
    cronOrigName = idx >= 0 ? c.name : '';
    cronDraft = c;
    cronActionKind = c.action?.kind || 'docker_prune_images';
    cronArgsLines = c.action?.kind === 'exec' ? (c.action.args || []).join('\n') : '';
    cronHttpUrlInput = '';
    cronHttpUrlClear = false;
    cronHttpBodyInput = '';
    cronHttpBodyClear = false;
    cronHttpHeaderRows = c.action?.kind === 'http_request' ? kvObjectToRows(c.action.headers) : [];
    cronDrawerOpen = true;
    refreshCronPreview(c.schedule);
  }

  function onCronKindChange() {
    cronHttpUrlInput = '';
    cronHttpUrlClear = false;
    cronHttpBodyInput = '';
    cronHttpBodyClear = false;
    cronHttpHeaderRows = [];
    if (cronActionKind === 'docker_prune_images') {
      cronDraft.action = { kind: 'docker_prune_images', dangling_only: true };
    } else if (cronActionKind === 'docker_restart_container') {
      cronDraft.action = { kind: 'docker_restart_container', container: '' };
    } else if (cronActionKind === 'rule_toggle') {
      cronDraft.action = { kind: 'rule_toggle', target_kind: 'port_forward', rule: '', enable: false };
    } else if (cronActionKind === 'http_request') {
      cronDraft.action = { kind: 'http_request', method: 'POST', url: '', headers: {}, body: '' };
    } else {
      cronDraft.action = { kind: 'exec', program: '/usr/bin/logger', args: ['vane-cron'], cwd: '' };
      cronArgsLines = 'vane-cron';
    }
  }

  async function saveCron(e) {
    e.preventDefault();
    if (saving || !cronDraft) return;
    cronDraft.name = String(cronDraft.name || '').trim();
    if (!cronDraft.name) {
      showToast(lang === 'en' ? 'Job name is required' : '请填写任务名称', 'error');
      return;
    }
    saving = true;
    try {
      const orig = cronEditIdx >= 0 ? settingsJson.cron[cronEditIdx] : null;
      cronDraft.timeout_secs = Number(cronDraft.timeout_secs || 60);
      cronDraft.schedule = String(cronDraft.schedule || '').trim();
      if (cronDraft.action.kind === 'exec') {
        cronDraft.action.program = String(cronDraft.action.program || '').trim();
        cronDraft.action.cwd = String(cronDraft.action.cwd || '').trim();
        cronDraft.action.args = splitLines(cronArgsLines);
      } else if (cronDraft.action.kind === 'http_request') {
        const origAct = orig?.action?.kind === 'http_request' ? orig.action : null;
        cronDraft.action.url = resolveSecretInput(origAct?.url, cronHttpUrlInput, cronHttpUrlClear);
        cronDraft.action.body = resolveSecretInput(origAct?.body, cronHttpBodyInput, cronHttpBodyClear);
        cronDraft.action.headers = rowsToKvObject(cronHttpHeaderRows, true);
      } else if (cronDraft.action.kind === 'docker_restart_container') {
        cronDraft.action.container = String(cronDraft.action.container || '').trim();
      } else if (cronDraft.action.kind === 'rule_toggle') {
        cronDraft.action.rule = String(cronDraft.action.rule || '').trim();
      }

      const next = deepClone(settingsJson);
      const renames = [];
      if (cronEditIdx >= 0) {
        if (cronOrigName && cronOrigName !== cronDraft.name) {
          renames.push({ from: `cron.${cronOrigName}`, to: `cron.${cronDraft.name}` });
        }
        next.cron[cronEditIdx] = cronDraft;
      } else {
        next.cron.push(cronDraft);
      }
      if (await onSaveSettings(next, renames)) cronDrawerOpen = false;
    } finally {
      saving = false;
    }
  }

  async function toggleCronEnabled(idx) {
    const key = `cron:${idx}`;
    if (busyToggleKey === key) return;
    busyToggleKey = key;
    try {
      const next = deepClone(settingsJson);
      next.cron[idx].enabled = !next.cron[idx].enabled;
      await onSaveSettings(next);
    } finally {
      busyToggleKey = '';
    }
  }

  function deleteCron(idx) {
    const job = settingsJson.cron[idx];
    askConfirm({
      title: t.common.confirmDeleteTitle,
      message: job.name,
      confirmLabel: t.delete,
      danger: true,
      onConfirm: async () => {
        const next = deepClone(settingsJson);
        next.cron.splice(idx, 1);
        await onSaveSettings(next);
      },
    });
  }

  async function runCronNow(name) {
    busyKey = `cron:${name}`;
    try {
      const r = await apiFetch(`/api/cron/${encodeURIComponent(name)}/run`, { method: 'POST' });
      const rawOut = String(r.output || 'OK').trim();
      const shortOut = rawOut.length > 120 ? `${rawOut.slice(0, 120)}…` : rawOut;
      showToast(`${name}: ${shortOut}`, 'success');
      await onRefresh();
    } catch (err) {
      showToast(err.message, 'error');
      await onRefresh();
    } finally {
      busyKey = '';
    }
  }

  // ---------------- Logs Search, Live Tail & Export ----------------
  let logQuery = $state('');
  let logNewestFirst = $state(true);
  let logLiveTail = $state(false);
  let sysLogsEl = $state(null);

  $effect(() => {
    if (mode !== 'logs' || !logLiveTail) return;
    const timer = setInterval(() => {
      if (document.visibilityState === 'visible') {
        if (onPollLogsIncremental) onPollLogsIncremental();
        else onRefresh(true);
      }
    }, 2000);
    return () => clearInterval(timer);
  });

  let filteredLogs = $derived.by(() => {
    const list = (logs || []).filter((e) => {
      if (logModuleFilter && e.module !== logModuleFilter) return false;
      if (logQuery && !`${e.module} ${e.message}`.toLowerCase().includes(logQuery.toLowerCase())) return false;
      return true;
    });
    return logNewestFirst ? [...list].reverse() : list;
  });

  $effect(() => {
    const count = filteredLogs.length;
    if (mode === 'logs' && logLiveTail && !logNewestFirst && count > 0) {
      queueMicrotask(() => {
        if (sysLogsEl) sysLogsEl.scrollTop = sysLogsEl.scrollHeight;
      });
    }
  });

  function logLevelColor(level) {
    const l = String(level || '').toLowerCase();
    if (l === 'error') return 'var(--danger)';
    if (l === 'warn' || l === 'warning') return 'var(--warn)';
    if (l === 'debug') return 'var(--text-muted)';
    return 'var(--accent)';
  }

  function formatLogLines(entries) {
    return entries
      .map((e) => `#${e.seq} ${new Date(e.ts * 1000).toISOString()} [${e.level.toUpperCase()}] [${e.module}] ${e.message}`)
      .join('\n');
  }

  async function handleCopyText(text) {
    if (await copyText(text)) showToast(t.copied, 'success');
    else showToast(t.copyFailed, 'error');
  }

  function clearAllLogs() {
    askConfirm({
      title: t.logsPage.clearConfirmTitle,
      message: t.logsPage.clearConfirmDesc,
      confirmLabel: t.logsPage.clear,
      danger: true,
      onConfirm: async () => {
        try {
          await apiFetch('/api/logs', { method: 'DELETE' });
          showToast(t.logsPage.clear, 'success');
          await onRefresh();
        } catch (err) {
          showToast(err.message, 'error');
        }
      },
    });
  }
</script>

<svelte:window
  onkeydown={(e) => {
    if (e.defaultPrevented || saving) return;
    if (e.key === 'Escape') {
      if (logModalOpen) closeLogModal();
      else if (cronDrawerOpen) cronDrawerOpen = false;
    }
  }}
/>

<!-- ===================== Docker 容器管理 ===================== -->
{#if mode === 'docker'}
  <div class="card">
    <div class="card-header">
      <div>
        <div class="card-title">{t.nav.docker}</div>
        <div style="font-size:12px;color:var(--text-secondary);">{t.dk.subtitle}</div>
      </div>
      <div class="btn-group">
        <button type="button" class="btn btn-sm btn-danger" disabled={busyKey === 'dk:prune'} onclick={triggerDockerPrune}>
          {busyKey === 'dk:prune' ? '...' : t.dk.prune}
        </button>
        <button type="button" class="btn btn-sm" onclick={() => onRefresh()}>{t.refresh}</button>
      </div>
    </div>

    {#if dockerError}
      <div class="banner banner-danger">
        <div style="display:flex;align-items:center;gap:8px;">
          <Icons name="alert" size={16} />
          <span class="mono" style="font-size:12.5px;">{dockerError}</span>
        </div>
      </div>
    {/if}

    {#if containers?.length}
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon"><Icons name="search" size={15} /></span>
          <input type="text" placeholder={t.search} aria-label={t.search} bind:value={dockerQuery} />
        </div>
        <div class="btn-group">
          <button type="button" class="chip {dockerStateFilter === 'all' ? 'active' : ''}" onclick={() => (dockerStateFilter = 'all')}>
            {t.all} ({containers.length})
          </button>
          <button type="button" class="chip {dockerStateFilter === 'running' ? 'active' : ''}" onclick={() => (dockerStateFilter = 'running')}>
            {t.statuses.running} ({runningContainersCount})
          </button>
          <button type="button" class="chip {dockerStateFilter === 'exited' ? 'active' : ''}" onclick={() => (dockerStateFilter = 'exited')}>
            {t.statuses.exited} ({exitedContainersCount})
          </button>
        </div>
      </div>
    {/if}

    {#if !containers?.length}
      {#if !dockerError}
        <div class="empty-state">{t.dk.empty}</div>
      {/if}
    {:else if !filteredContainers.length}
      <div class="empty-state">{t.common.noMatches}</div>
    {:else}
      <div style="display:grid;gap:10px;">
        {#each filteredContainers as c (c.id)}
          {@const protectedHint = c.protected
            ? lang === 'en'
              ? 'Protected container (configured in Settings)'
              : '受保护容器（已在系统设置中锁定）'
            : undefined}
          <div class="subcard row-between">
            <div style="min-width:0;flex:1;">
              <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                <span class="status-dot {c.state === 'running' ? 'ok' : c.state === 'exited' ? 'muted' : 'warn'}"></span>
                <span style="font-weight:700;font-size:15px;">{c.name || c.id}</span>
                <code class="mono" style="font-size:12px;color:var(--text-secondary);word-break:break-all;">{c.image}</code>
                <span class="badge {c.state === 'running' ? 'badge-ok' : c.state === 'exited' ? 'badge-muted' : 'badge-warn'}">
                  {translateRuntimeStatus(c.state, t)}
                </span>
                {#if c.protected}
                  <span class="badge badge-info" title={protectedHint}>{t.dk.protected}</span>
                {/if}
              </div>
              <div class="mono" style="font-size:12px;color:var(--text-secondary);margin-top:4px;">
                ID: {c.id} · {c.status}
              </div>
            </div>
            <div class="btn-group">
              {#if c.state !== 'running'}
                <button
                  type="button"
                  class="btn btn-xs btn-primary"
                  disabled={busyKey.startsWith(`dk:${c.id}`)}
                  onclick={() => runContainerActionConfirmed(c, 'start')}
                >
                  {t.dk.start}
                </button>
              {:else}
                <button
                  type="button"
                  class="btn btn-xs"
                  title={protectedHint}
                  disabled={c.protected || busyKey.startsWith(`dk:${c.id}`)}
                  onclick={() => runContainerActionConfirmed(c, 'restart')}
                >
                  {t.dk.restart}
                </button>
                <button
                  type="button"
                  class="btn btn-xs btn-danger"
                  title={protectedHint}
                  disabled={c.protected || busyKey.startsWith(`dk:${c.id}`)}
                  onclick={() => runContainerActionConfirmed(c, 'stop')}
                >
                  {t.dk.stop}
                </button>
                {#if webTerminalEnabled}
                  <button
                    type="button"
                    class="btn btn-xs"
                    title={protectedHint}
                    disabled={c.protected}
                    onclick={() => onOpenContainerTerminal(c.name || c.id)}
                  >
                    {t.dk.shell}
                  </button>
                {/if}
              {/if}
              <button type="button" class="btn btn-xs" onclick={() => viewContainerLogs(c)}>{t.dk.logs}</button>
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </div>
{/if}

<!-- ===================== Cron 计划任务 ===================== -->
{#if mode === 'cron' && settingsJson}
  <div class="card">
    <div class="card-header">
      <div>
        <div class="card-title">{t.nav.cron}</div>
        <div style="font-size:12px;color:var(--text-secondary);">{t.cronPage.subtitle}</div>
      </div>
      <button type="button" class="btn btn-primary btn-sm" onclick={() => openCronDrawer(-1)}>
        <Icons name="plus" size={14} />
        <span>{t.add}</span>
      </button>
    </div>

    {#if !settingsJson.cron?.length}
      <div class="empty-state">{t.common.empty}</div>
    {:else}
      <div style="display:grid;gap:12px;">
        {#each settingsJson.cron as job, idx (job.name)}
          {@const st = (dashboard?.cron || []).find((x) => x.name === job.name)}
          {@const summary = cronActionSummary(job.action)}
          {@const outStr = st?.last_output || ''}
          {@const isLongOut = outStr.length > 120 || outStr.includes('\n')}
          {@const isExpanded = Boolean(expandedCronOutput[job.name])}
          <div class="subcard">
            <div class="row-between">
              <div style="min-width:0;flex:1;">
                <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                  <span class="status-dot {job.enabled ? (st?.status === 'failed' ? 'danger' : 'ok') : 'muted'}"></span>
                  <span style="font-weight:700;font-size:15px;">{job.name}</span>
                  <span class="badge badge-info mono">{job.schedule}</span>
                  <span class="badge badge-muted">{job.action.kind}</span>
                  <span class="badge badge-muted mono">{job.timeout_secs || 60}s</span>
                  {#if job.notify_on_failure}
                    <span class="badge badge-info">{lang === 'en' ? 'Notify' : '失败告警'}</span>
                  {/if}
                  {#if st}
                    <span class="badge {st.running ? 'badge-info' : st.status === 'ok' ? 'badge-ok' : st.status === 'failed' ? 'badge-danger' : 'badge-warn'}">
                      {st.running ? t.statuses.running : translateRuntimeStatus(st.status, t)}
                    </span>
                  {/if}
                </div>
                {#if summary}
                  <div class="mono" style="font-size:12px;color:var(--text-secondary);margin-top:4px;word-break:break-all;">
                    {summary}
                  </div>
                {/if}
                {#if st?.last_run_unix}
                  <div class="mono" style="font-size:12px;color:var(--text-secondary);margin-top:5px;">
                    <span>Last: {formatUnixTime(st.last_run_unix)} ({st.last_duration_ms}ms)</span>
                    {#if outStr}
                      <span> · {isLongOut && !isExpanded ? `${outStr.slice(0, 120)}…` : outStr}</span>
                      {#if isLongOut}
                        <button
                          type="button"
                          class="btn btn-ghost btn-xs"
                          style="margin-left:4px;min-height:22px;padding:0 6px;"
                          onclick={() => (expandedCronOutput = { ...expandedCronOutput, [job.name]: !isExpanded })}
                        >
                          {isExpanded ? (lang === 'en' ? 'Collapse' : '收起') : (lang === 'en' ? 'Expand' : '展开')}
                        </button>
                      {/if}
                      <button
                        type="button"
                        class="btn btn-ghost btn-xs"
                        style="margin-left:2px;min-height:22px;padding:0 6px;"
                        aria-label={t.copy}
                        onclick={() => handleCopyText(outStr)}
                      >
                        <Icons name="copy" size={12} />
                      </button>
                    {/if}
                  </div>
                {/if}
              </div>
              <div class="btn-group">
                <button
                  type="button"
                  role="switch"
                  aria-checked={job.enabled}
                  aria-label={`Toggle ${job.name}`}
                  class="switch"
                  disabled={busyToggleKey === `cron:${idx}`}
                  onclick={() => toggleCronEnabled(idx)}
                >
                  <span class="switch-thumb"></span>
                </button>
                <button
                  type="button"
                  class="btn btn-xs btn-primary"
                  disabled={Boolean(st?.running) || busyKey === `cron:${job.name}`}
                  onclick={() => runCronNow(job.name)}
                >
                  {st?.running || busyKey === `cron:${job.name}` ? '...' : t.cronPage.runNow}
                </button>
                <button type="button" class="btn btn-xs" onclick={() => openCronDrawer(idx)}>{t.edit}</button>
                <button type="button" class="btn btn-xs btn-danger" onclick={() => deleteCron(idx)}>{t.delete}</button>
              </div>
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </div>
{/if}

<!-- ===================== 运行日志 ===================== -->
{#if mode === 'logs'}
  <div class="card">
    <div class="card-header">
      <div>
        <span class="card-title">{t.nav.logs}</span>
        <span class="mono" style="font-size:11.5px;color:var(--text-muted);margin-left:8px;">
          {filteredLogs.length} / {logCapacity}
        </span>
      </div>
      <div class="btn-group">
        <div class="search-wrap" style="min-width:170px;max-width:220px;">
          <span class="search-icon"><Icons name="search" size={14} /></span>
          <input type="text" class="control-compact" placeholder={t.search} aria-label={t.search} bind:value={logQuery} />
        </div>
        <select
          class="control-compact"
          style="width:130px;padding:4px 8px;"
          aria-label={t.logsPage.allModules}
          value={logModuleFilter}
          onchange={(e) => onChangeLogFilter?.(logLevelFilter, e.currentTarget.value)}
        >
          <option value="">{t.logsPage.allModules}</option>
          {#each logModules as modName (modName)}
            <option value={modName}>{modName}</option>
          {/each}
        </select>
        <select
          class="control-compact"
          style="width:105px;padding:4px 8px;"
          aria-label="Log Level"
          value={logLevelFilter}
          onchange={(e) => onChangeLogFilter?.(e.currentTarget.value, logModuleFilter)}
        >
          <option value="">ALL</option>
          <option value="info">INFO+</option>
          <option value="warn">WARN+</option>
          <option value="error">ERROR</option>
        </select>
        <button type="button" class="btn btn-sm" onclick={() => (logNewestFirst = !logNewestFirst)}>
          {logNewestFirst ? t.logsPage.newestFirst : t.logsPage.oldestFirst}
        </button>
        <button type="button" class="btn btn-sm {logLiveTail ? 'btn-primary' : ''}" onclick={() => (logLiveTail = !logLiveTail)}>
          {t.logsPage.liveTail}
        </button>
        <button
          type="button"
          class="btn btn-sm"
          disabled={!filteredLogs.length}
          onclick={() => handleCopyText(formatLogLines(filteredLogs))}
        >
          <Icons name="copy" size={13} />
          <span>{t.copy}</span>
        </button>
        <button
          type="button"
          class="btn btn-sm"
          disabled={!filteredLogs.length}
          onclick={() => downloadTextFile(`vane-logs-${new Date().toISOString().slice(0, 10)}.log`, formatLogLines(filteredLogs))}
        >
          <Icons name="download" size={13} />
          <span>{t.logsPage.exportLog}</span>
        </button>
        <button type="button" class="btn btn-sm btn-danger" onclick={clearAllLogs}>{t.logsPage.clear}</button>
      </div>
    </div>

    <div
      bind:this={sysLogsEl}
      class="mono"
      style="background:var(--bg-elevated);padding:14px;border-radius:12px;max-height:560px;overflow-y:auto;font-size:12px;line-height:1.65;"
    >
      {#if !filteredLogs.length}
        <div style="color:var(--text-muted);">{t.logsPage.empty}</div>
      {:else}
        {#each filteredLogs as entry (entry.seq)}
          <div class="log-row">
            <span style="color:var(--text-muted);">#{entry.seq} {formatUnixTime(entry.ts)}</span>
            <span style="color:{logLevelColor(entry.level)};font-weight:600;">
              [{entry.level.toUpperCase()}]
            </span>
            <span style="color:var(--info);">[{entry.module}]</span>
            <span>{entry.message}</span>
          </div>
        {/each}
      {/if}
    </div>
  </div>
{/if}

<!-- 容器日志抽屉 -->
{#if logModalOpen}
  <div class="drawer-backdrop" role="presentation" onclick={(e) => { if (e.target === e.currentTarget) closeLogModal(); }}>
    <div class="drawer-panel" role="dialog" aria-modal="true" aria-label={`Logs ${logModalContainerName}`}>
      <div class="drawer-header">
        <div class="card-title" style="min-width:0;overflow:hidden;text-overflow:ellipsis;">
          {t.dk.logs} · {logModalContainerName}
        </div>
        <button type="button" class="btn btn-sm" onclick={closeLogModal}>{t.close}</button>
      </div>
      <div class="drawer-body" style="display:flex;flex-direction:column;gap:12px;">
        <div class="btn-group" style="flex-wrap:wrap;">
          <input
            type="text"
            class="control-compact"
            style="width:160px;"
            placeholder={t.dk.filterLogs}
            aria-label={t.dk.filterLogs}
            bind:value={logModalQuery}
          />
          <select
            class="control-compact"
            style="width:110px;"
            aria-label={t.dk.lines}
            bind:value={logModalLines}
            onchange={() => reloadContainerLogs(false)}
          >
            {#each TAIL_OPTIONS.includes(logModalLines) ? TAIL_OPTIONS : [logModalLines, ...TAIL_OPTIONS].sort((a, b) => a - b) as n (n)}
              <option value={n}>{n} {t.dk.lines}</option>
            {/each}
          </select>
          <button
            type="button"
            class="btn btn-sm {logModalAutoRefresh ? 'btn-primary' : ''}"
            onclick={() => (logModalAutoRefresh = !logModalAutoRefresh)}
          >
            {t.cfg.lblAutoRefresh}
          </button>
          <button
            type="button"
            class="btn btn-sm"
            disabled={!filteredContainerLogText}
            onclick={() => handleCopyText(filteredContainerLogText)}
          >
            {t.copy}
          </button>
          <button
            type="button"
            class="btn btn-sm"
            disabled={!filteredContainerLogText}
            onclick={() => downloadTextFile(`${logModalContainerName}.log`, filteredContainerLogText)}
          >
            {t.download}
          </button>
          <button type="button" class="btn btn-sm" disabled={logModalLoading} onclick={() => reloadContainerLogs(false)}>
            {logModalLoading ? '...' : t.refresh}
          </button>
        </div>

        <pre
          bind:this={logModalPreEl}
          class="mono"
          style="background:#05070a;color:#e2e8f0;padding:14px;border-radius:12px;font-size:12px;white-space:pre-wrap;word-break:break-all;flex:1;min-height:240px;max-height:68vh;overflow-y:auto;margin:0;"
        >{logModalLoading && !logModalText ? t.common.loading : filteredContainerLogText || '(empty)'}</pre>
      </div>
    </div>
  </div>
{/if}

<!-- Cron 编辑抽屉 -->
{#if cronDrawerOpen && cronDraft}
  <datalist id="cron-containers-list">
    {#each containers || [] as c (c.id)}
      <option value={c.name || c.id}>{c.image}</option>
    {/each}
  </datalist>
  <datalist id="cron-rules-list">
    {#each ruleNamesForKind as rn (rn)}
      <option value={rn}></option>
    {/each}
  </datalist>

  <div class="drawer-backdrop" role="presentation" onclick={(e) => { if (e.target === e.currentTarget && !saving) cronDrawerOpen = false; }}>
    <div class="drawer-panel" role="dialog" aria-modal="true" aria-label={t.nav.cron}>
    <form style="display:contents;" onsubmit={saveCron}>
      <div class="drawer-header">
        <div class="card-title">{cronEditIdx >= 0 ? t.edit : t.add} · {t.nav.cron}</div>
        <button type="button" class="btn btn-sm" disabled={saving} onclick={() => (cronDrawerOpen = false)}>{t.cancel}</button>
      </div>
      <div class="drawer-body">
        <div class="form-grid">
          <div class="field">
            <label for="cr-name">{t.cronPage.jobName}</label>
            <input id="cr-name" type="text" class="mono" bind:value={cronDraft.name} required />
          </div>
          <div class="field">
            <label for="cr-to">{t.cronPage.timeout}</label>
            <input id="cr-to" type="number" min="1" max="86400" bind:value={cronDraft.timeout_secs} required />
          </div>
        </div>

        <div class="field">
          <label for="cr-sched">{t.cronPage.expr}</label>
          <input
            id="cr-sched"
            type="text"
            class="mono"
            bind:value={cronDraft.schedule}
            oninput={(e) => scheduleCronPreview(e.currentTarget.value)}
            required
          />
          <div class="btn-group" style="margin-top:4px;">
            {#each [['0 0 4 * * *', '04:00 Daily'], ['0 */30 * * * *', '30m'], ['0 0 3 * * 0', 'Sun 03:00']] as [expr, label] (expr)}
              <button
                type="button"
                class="btn btn-xs"
                onclick={() => {
                  cronDraft.schedule = expr;
                  refreshCronPreview(expr);
                }}
              >
                {label}
              </button>
            {/each}
          </div>
          {#if cronPreviewError}
            <div style="font-size:12px;color:var(--danger);margin-top:4px;">{cronPreviewError}</div>
          {:else if cronPreviewRuns.length}
            <div class="mono" style="font-size:11px;color:var(--accent);margin-top:4px;">Next: {cronPreviewRuns.join(' · ')}</div>
          {/if}
        </div>

        <div class="field">
          <label for="cr-kind">{t.cronPage.actionType}</label>
          <select id="cr-kind" bind:value={cronActionKind} onchange={onCronKindChange}>
            <option value="docker_prune_images">docker_prune_images</option>
            <option value="docker_restart_container">docker_restart_container</option>
            <option value="rule_toggle">rule_toggle</option>
            <option value="http_request">http_request</option>
            <option value="exec">exec</option>
          </select>
        </div>

        {#if (cronDraft.action.kind === 'docker_prune_images' || cronDraft.action.kind === 'docker_restart_container') && !settingsJson?.modules?.docker}
          <div class="banner banner-warn" style="margin-bottom:12px;">
            <span style="font-size:12.5px;">
              {lang === 'en'
                ? 'Docker module is currently disabled; this action will fail until Docker is enabled in Settings.'
                : '当前 Docker 模块未开启，此动作在开启 Docker 模块前执行将会失败。'}
            </span>
          </div>
        {/if}

        {#if cronDraft.action.kind === 'docker_prune_images'}
          <label class="check-row"><input type="checkbox" bind:checked={cronDraft.action.dangling_only} /> {t.cronPage.danglingOnly}</label>
        {:else if cronDraft.action.kind === 'docker_restart_container'}
          <div class="field">
            <label for="cr-cnt">{t.cronPage.container}</label>
            <input id="cr-cnt" type="text" class="mono" list="cron-containers-list" bind:value={cronDraft.action.container} required />
          </div>
        {:else if cronDraft.action.kind === 'rule_toggle'}
          <div class="form-grid">
            <div class="field">
              <label for="cr-rtk">{t.cronPage.targetMod}</label>
              <select
                id="cr-rtk"
                bind:value={cronDraft.action.target_kind}
                onchange={() => {
                  if (cronDraft?.action) cronDraft.action.rule = '';
                }}
              >
                <option value="port_forward">port_forward</option>
                <option value="reverse_proxy">reverse_proxy</option>
              </select>
            </div>
            <div class="field">
              <label for="cr-rtn">{t.cronPage.targetRule}</label>
              <input id="cr-rtn" type="text" class="mono" list="cron-rules-list" bind:value={cronDraft.action.rule} required />
            </div>
          </div>
          <label class="check-row"><input type="checkbox" bind:checked={cronDraft.action.enable} /> {t.cronPage.setEnable}</label>
        {:else if cronDraft.action.kind === 'http_request'}
          <div class="form-grid">
            <div class="field">
              <label for="cr-hm">{t.cronPage.httpMethod}</label>
              <select id="cr-hm" bind:value={cronDraft.action.method}>
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="PATCH">PATCH</option>
                <option value="DELETE">DELETE</option>
                <option value="HEAD">HEAD</option>
              </select>
            </div>
            <SecretField
              id="cr-hu"
              label={t.cronPage.httpUrl}
              original={cronDraft.action.url}
              bind:value={cronHttpUrlInput}
              bind:clear={cronHttpUrlClear}
              placeholder="https://..."
              required={true}
              {t}
            />
          </div>
          <SecretField
            id="cr-hb"
            label={t.cronPage.httpBody}
            original={cronDraft.action.body}
            bind:value={cronHttpBodyInput}
            bind:clear={cronHttpBodyClear}
            placeholder="Optional payload"
            {t}
          />
          <HeaderRowsEditor label={t.cronPage.httpHeaders} bind:rows={cronHttpHeaderRows} secret={true} {t} />
        {:else}
          <div class="form-grid">
            <div class="field">
              <label for="cr-prg">{t.cronPage.program}</label>
              <input id="cr-prg" type="text" class="mono" placeholder="/usr/bin/logger" bind:value={cronDraft.action.program} required />
            </div>
            <div class="field">
              <label for="cr-cwd">{t.cronPage.cwd}</label>
              <input id="cr-cwd" type="text" class="mono" placeholder="/tmp" bind:value={cronDraft.action.cwd} />
            </div>
          </div>
          <div class="field">
            <label for="cr-arg">{t.cronPage.args}</label>
            <textarea id="cr-arg" class="mono" bind:value={cronArgsLines}></textarea>
          </div>
        {/if}

        <div style="display:flex;gap:18px;flex-wrap:wrap;margin-top:8px;">
          <label class="check-row"><input type="checkbox" bind:checked={cronDraft.enabled} /> {t.enabled}</label>
          <label class="check-row"><input type="checkbox" bind:checked={cronDraft.notify_on_failure} /> {t.cronPage.notifyFail}</label>
        </div>
      </div>
      <div class="drawer-footer">
        <button type="button" class="btn" disabled={saving} onclick={() => (cronDrawerOpen = false)}>{t.cancel}</button>
        <button type="submit" class="btn btn-primary" disabled={saving}>{saving ? '...' : t.confirm}</button>
      </div>
    </form>
    </div>
  </div>
{/if}
