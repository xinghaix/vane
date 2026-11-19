<script>
  import Icons from './Icons.svelte';
  import SecretField from './SecretField.svelte';
  import {
    splitLines,
    kvObjectToText,
    textToKvObject,
    deepClone,
    copyText,
    formatBytes,
    formatUnixTime,
    resolveSecretInput,
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
    webTerminalEnabled = false,
    onOpenContainerTerminal,
    onSaveSettings,
    askConfirm,
    apiFetch,
    showToast,
    onRefresh,
  } = $props();

  let busyKey = $state('');
  let saving = $state(false);
  let dockerQuery = $state('');

  // ---------------- Docker Logs Modal ----------------
  let logModalOpen = $state(false);
  let logModalContainer = $state('');
  let logModalLines = $state(200);
  let logModalText = $state('');
  let logModalQuery = $state('');

  const TAIL_OPTIONS = [100, 200, 300, 500, 1000];

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

  async function viewContainerLogs(idOrName) {
    logModalContainer = idOrName;
    logModalLines = Number(settingsJson?.docker?.log_tail_default || 200);
    logModalQuery = '';
    logModalText = 'Loading...';
    logModalOpen = true;
    await reloadContainerLogs();
  }

  async function reloadContainerLogs() {
    try {
      const r = await apiFetch(
        `/api/docker/containers/${encodeURIComponent(logModalContainer)}/logs?tail=${logModalLines}`
      );
      logModalText = r.logs || '(empty)';
    } catch (err) {
      logModalText = `Error: ${err.message}`;
    }
  }

  function triggerDockerPrune() {
    askConfirm({
      title: t.dk.pruneConfirmTitle,
      message: t.dk.subtitle,
      confirmLabel: t.dk.prune,
      danger: true,
      onConfirm: async () => {
        busyKey = 'dk:prune';
        try {
          const r = await apiFetch('/api/docker/prune', { method: 'POST' });
          let detail = '';
          try {
            const parsed = JSON.parse(r.result || '{}');
            if (typeof parsed.SpaceReclaimed === 'number') {
              detail = ` (${formatBytes(parsed.SpaceReclaimed)})`;
            }
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

  function downloadTextFile(filename, content) {
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  let filteredContainers = $derived(
    (containers || []).filter(
      (c) =>
        !dockerQuery.trim() ||
        `${c.name} ${c.id} ${c.image} ${c.state}`.toLowerCase().includes(dockerQuery.trim().toLowerCase())
    )
  );

  let filteredContainerLogText = $derived.by(() => {
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
  let cronHttpHeadersTxt = $state('');
  let cronPreviewRuns = $state([]);
  let cronPreviewError = $state('');

  let ruleNamesForKind = $derived(
    cronDraft?.action?.target_kind === 'reverse_proxy'
      ? (settingsJson?.reverse_proxy || []).map((r) => r.name)
      : (settingsJson?.port_forwards || []).map((p) => p.name)
  );

  async function refreshCronPreview(expr) {
    if (!expr) return;
    try {
      const r = await apiFetch(`/api/cron/preview?expr=${encodeURIComponent(expr)}`);
      if (r.valid) {
        cronPreviewRuns = r.formatted || [];
        cronPreviewError = '';
      } else {
        cronPreviewRuns = [];
        cronPreviewError = r.error || 'Invalid cron';
      }
    } catch {
      cronPreviewRuns = [];
    }
  }

  function openCronDrawer(idx = -1) {
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
    cronHttpHeadersTxt = c.action?.kind === 'http_request' ? kvObjectToText(c.action.headers) : '';
    cronDrawerOpen = true;
    refreshCronPreview(c.schedule);
  }

  function onCronKindChange() {
    if (cronActionKind === 'docker_prune_images') {
      cronDraft.action = { kind: 'docker_prune_images', dangling_only: true };
    } else if (cronActionKind === 'docker_restart_container') {
      cronDraft.action = { kind: 'docker_restart_container', container: '' };
    } else if (cronActionKind === 'rule_toggle') {
      cronDraft.action = { kind: 'rule_toggle', target_kind: 'port_forward', rule: '', enable: false };
    } else if (cronActionKind === 'http_request') {
      cronDraft.action = { kind: 'http_request', method: 'POST', url: '', headers: {}, body: '' };
      cronHttpUrlInput = '';
      cronHttpBodyInput = '';
      cronHttpHeadersTxt = '';
    } else {
      cronDraft.action = { kind: 'exec', program: '/usr/bin/logger', args: ['vane-cron'], cwd: '' };
      cronArgsLines = 'vane-cron';
    }
  }

  async function saveCron(e) {
    e.preventDefault();
    if (saving) return;
    saving = true;
    try {
      const orig = cronEditIdx >= 0 ? settingsJson.cron[cronEditIdx] : null;
      cronDraft.timeout_secs = Number(cronDraft.timeout_secs || 60);
      if (cronDraft.action.kind === 'exec') {
        cronDraft.action.args = splitLines(cronArgsLines);
      } else if (cronDraft.action.kind === 'http_request') {
        const origAct = orig?.action?.kind === 'http_request' ? orig.action : null;
        cronDraft.action.url = resolveSecretInput(origAct?.url, cronHttpUrlInput, cronHttpUrlClear);
        cronDraft.action.body = resolveSecretInput(origAct?.body, cronHttpBodyInput, cronHttpBodyClear);
        cronDraft.action.headers = textToKvObject(cronHttpHeadersTxt, origAct?.headers || {});
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
    const next = deepClone(settingsJson);
    next.cron[idx].enabled = !next.cron[idx].enabled;
    await onSaveSettings(next);
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
      showToast(`${name}: ${r.output || 'OK'}`, 'success');
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

  $effect(() => {
    if (mode !== 'logs' || !logLiveTail) return;
    const timer = setInterval(() => {
      if (document.visibilityState === 'visible') onRefresh(true);
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

  function formatLogLines(entries) {
    return entries
      .map((e) => `#${e.seq} ${new Date(e.ts * 1000).toISOString()} [${e.level.toUpperCase()}] [${e.module}] ${e.message}`)
      .join('\n');
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
    if (e.key === 'Escape') {
      if (logModalOpen) logModalOpen = false;
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
          {t.dk.prune}
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
          <input type="text" placeholder={t.search} bind:value={dockerQuery} />
        </div>
      </div>
    {/if}

    {#if !containers?.length}
      <div class="empty-state">{t.dk.empty}</div>
    {:else if !filteredContainers.length}
      <div class="empty-state">{t.common.noMatches}</div>
    {:else}
      <div style="display:grid;gap:10px;">
        {#each filteredContainers as c}
          <div class="subcard row-between">
            <div>
              <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                <span class="status-dot {c.state === 'running' ? 'ok' : 'warn'}"></span>
                <span style="font-weight:700;font-size:15px;">{c.name || c.id}</span>
                <code class="mono" style="font-size:12px;color:var(--text-secondary);">{c.image}</code>
                <span class="badge {c.state === 'running' ? 'badge-ok' : 'badge-warn'}">{c.state}</span>
                {#if c.protected}
                  <span class="badge badge-info">{t.dk.protected}</span>
                {/if}
              </div>
              <div class="mono" style="font-size:12px;color:var(--text-secondary);margin-top:4px;">
                ID: {c.id} · {c.status}
              </div>
            </div>
            <div class="btn-group">
              {#if c.state !== 'running'}
                <button type="button" class="btn btn-xs btn-primary" disabled={busyKey.startsWith(`dk:${c.id}`)} onclick={() => runContainerActionConfirmed(c, 'start')}>
                  {t.dk.start}
                </button>
              {:else}
                <button type="button" class="btn btn-xs" disabled={c.protected || busyKey.startsWith(`dk:${c.id}`)} onclick={() => runContainerActionConfirmed(c, 'restart')}>
                  {t.dk.restart}
                </button>
                <button type="button" class="btn btn-xs btn-danger" disabled={c.protected || busyKey.startsWith(`dk:${c.id}`)} onclick={() => runContainerActionConfirmed(c, 'stop')}>
                  {t.dk.stop}
                </button>
                {#if webTerminalEnabled && !c.protected}
                  <button type="button" class="btn btn-xs" onclick={() => onOpenContainerTerminal(c.name || c.id)}>
                    {t.dk.shell}
                  </button>
                {/if}
              {/if}
              <button type="button" class="btn btn-xs" onclick={() => viewContainerLogs(c.id)}>{t.dk.logs}</button>
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
        {#each settingsJson.cron as job, idx}
          {@const st = (dashboard?.cron || []).find((x) => x.name === job.name)}
          <div class="subcard">
            <div class="row-between">
              <div style="min-width:0;flex:1;">
                <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                  <span class="status-dot {job.enabled ? (st?.status === 'failed' ? 'danger' : 'ok') : 'muted'}"></span>
                  <span style="font-weight:700;font-size:15px;">{job.name}</span>
                  <span class="badge badge-info mono">{job.schedule}</span>
                  <span class="badge badge-muted">{job.action.kind}</span>
                  {#if st}
                    <span class="badge {st.status === 'ok' ? 'badge-ok' : st.status === 'failed' ? 'badge-danger' : 'badge-warn'}">
                      {st.running ? 'RUNNING' : st.status}
                    </span>
                  {/if}
                </div>
                {#if st?.last_run_unix}
                  <div class="mono" style="font-size:12px;color:var(--text-secondary);margin-top:5px;">
                    Last: {formatUnixTime(st.last_run_unix)} ({st.last_duration_ms}ms) · {st.last_output}
                  </div>
                {/if}
              </div>
              <div class="btn-group">
                <button
                  type="button"
                  role="switch"
                  aria-checked={job.enabled}
                  aria-label="Toggle cron job"
                  class="switch"
                  onclick={() => toggleCronEnabled(idx)}
                >
                  <span class="switch-thumb"></span>
                </button>
                <button type="button" class="btn btn-xs btn-primary" disabled={busyKey === `cron:${job.name}`} onclick={() => runCronNow(job.name)}>
                  {busyKey === `cron:${job.name}` ? '...' : t.cronPage.runNow}
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
          <input type="text" style="min-height:34px;font-size:13px;" placeholder={t.search} bind:value={logQuery} />
        </div>
        <select
          style="width:130px;min-height:34px;padding:4px 8px;font-size:13px;"
          value={logModuleFilter}
          onchange={(e) => onChangeLogFilter?.(logLevelFilter, e.currentTarget.value)}
        >
          <option value="">{t.logsPage.allModules}</option>
          {#each logModules as modName}
            <option value={modName}>{modName}</option>
          {/each}
        </select>
        <select
          style="width:105px;min-height:34px;padding:4px 8px;font-size:13px;"
          value={logLevelFilter}
          onchange={(e) => onChangeLogFilter?.(e.currentTarget.value, logModuleFilter)}
        >
          <option value="">ALL</option>
          <option value="info">INFO+</option>
          <option value="warn">WARN+</option>
          <option value="error">ERROR</option>
        </select>
        <button type="button" class="btn btn-sm" onclick={() => logNewestFirst = !logNewestFirst}>
          {logNewestFirst ? t.logsPage.newestFirst : t.logsPage.oldestFirst}
        </button>
        <button type="button" class="btn btn-sm {logLiveTail ? 'btn-primary' : ''}" onclick={() => logLiveTail = !logLiveTail}>
          {t.logsPage.liveTail}
        </button>
        <button
          type="button"
          class="btn btn-sm"
          onclick={async () => {
            if (await copyText(formatLogLines(filteredLogs))) showToast(t.copied, 'success');
          }}
        >
          <Icons name="copy" size={13} />
          <span>{t.copy}</span>
        </button>
        <button
          type="button"
          class="btn btn-sm"
          onclick={() => downloadTextFile(`vane-logs-${new Date().toISOString().slice(0, 10)}.log`, formatLogLines(filteredLogs))}
        >
          <Icons name="download" size={13} />
          <span>{t.logsPage.exportLog}</span>
        </button>
        <button type="button" class="btn btn-sm btn-danger" onclick={clearAllLogs}>{t.logsPage.clear}</button>
      </div>
    </div>

    <div class="mono" style="background:var(--bg-elevated);padding:14px;border-radius:12px;max-height:560px;overflow-y:auto;font-size:12px;line-height:1.65;">
      {#if !filteredLogs.length}
        <div style="color:var(--text-muted);">{t.logsPage.empty}</div>
      {:else}
        {#each filteredLogs as entry}
          <div class="log-row">
            <span style="color:var(--text-muted);">#{entry.seq} {new Date(entry.ts * 1000).toLocaleTimeString()}</span>
            <span style="color:{entry.level === 'error' ? 'var(--danger)' : entry.level === 'warn' ? 'var(--warn)' : 'var(--accent)'};font-weight:600;">
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
  <div class="drawer-backdrop" role="presentation" onclick={(e) => { if (e.target === e.currentTarget) logModalOpen = false; }}>
    <div class="drawer-panel">
      <div class="drawer-header">
        <div class="card-title">Logs · {logModalContainer}</div>
        <div class="btn-group">
          <input
            type="text"
            style="width:140px;min-height:34px;font-size:13px;"
            placeholder={t.dk.filterLogs}
            bind:value={logModalQuery}
          />
          <select style="width:105px;min-height:34px;font-size:13px;" bind:value={logModalLines} onchange={reloadContainerLogs}>
            {#each TAIL_OPTIONS.includes(logModalLines) ? TAIL_OPTIONS : [logModalLines, ...TAIL_OPTIONS].sort((a, b) => a - b) as n}
              <option value={n}>{n} {t.dk.lines}</option>
            {/each}
          </select>
          <button
            type="button"
            class="btn btn-sm"
            onclick={async () => { if (await copyText(filteredContainerLogText)) showToast(t.copied, 'success'); }}
          >
            {t.copy}
          </button>
          <button
            type="button"
            class="btn btn-sm"
            onclick={() => downloadTextFile(`${logModalContainer}.log`, filteredContainerLogText)}
          >
            {t.download}
          </button>
          <button type="button" class="btn btn-sm" onclick={reloadContainerLogs}>{t.refresh}</button>
          <button type="button" class="btn btn-sm" onclick={() => logModalOpen = false}>{t.close}</button>
        </div>
      </div>
      <div class="drawer-body">
        <pre class="mono" style="background:#05070a;color:#e2e8f0;padding:14px;border-radius:12px;font-size:12px;white-space:pre-wrap;word-break:break-all;">{filteredContainerLogText}</pre>
      </div>
    </div>
  </div>
{/if}

<!-- Cron 编辑抽屉 -->
{#if cronDrawerOpen && cronDraft}
  <datalist id="cron-containers-list">
    {#each containers || [] as c}
      <option value={c.name || c.id}>{c.image}</option>
    {/each}
  </datalist>
  <datalist id="cron-rules-list">
    {#each ruleNamesForKind as rn}
      <option value={rn}></option>
    {/each}
  </datalist>

  <div class="drawer-backdrop" role="presentation" onclick={(e) => { if (e.target === e.currentTarget) cronDrawerOpen = false; }}>
    <form class="drawer-panel" onsubmit={saveCron}>
      <div class="drawer-header">
        <div class="card-title">{cronEditIdx >= 0 ? t.edit : t.add} · {t.nav.cron}</div>
        <button type="button" class="btn btn-sm" onclick={() => cronDrawerOpen = false}>{t.cancel}</button>
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
            oninput={(e) => refreshCronPreview(e.currentTarget.value)}
            required
          />
          <div class="btn-group" style="margin-top:4px;">
            {#each [['0 0 4 * * *', '04:00 Daily'], ['0 */30 * * * *', '30m'], ['0 0 3 * * 0', 'Sun 03:00']] as [expr, label]}
              <button type="button" class="btn btn-xs" onclick={() => { cronDraft.schedule = expr; refreshCronPreview(expr); }}>{label}</button>
            {/each}
          </div>
          {#if cronPreviewError}
            <div style="font-size:12px;color:var(--danger);">{cronPreviewError}</div>
          {:else if cronPreviewRuns.length}
            <div class="mono" style="font-size:11px;color:var(--accent);">Next: {cronPreviewRuns.join(' · ')}</div>
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
              <select id="cr-rtk" bind:value={cronDraft.action.target_kind}>
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
          <div class="field">
            <label for="cr-hh">{t.cronPage.httpHeaders}</label>
            <textarea id="cr-hh" class="mono" bind:value={cronHttpHeadersTxt}></textarea>
          </div>
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
        <button type="button" class="btn" onclick={() => cronDrawerOpen = false}>{t.cancel}</button>
        <button type="submit" class="btn btn-primary" disabled={saving}>{saving ? '...' : t.confirm}</button>
      </div>
    </form>
  </div>
{/if}
