<script>
  import {
    splitCsv,
    joinCsv,
    deepClone,
    formatUnixTime,
    secretMaskedHint,
    resolveSecretInput,
  } from '../lib/helpers.js';

  let {
    mode = 'docker',
    t,
    lang,
    settingsJson,
    dashboard,
    containers = [],
    logs = [],
    logLevelFilter = '',
    onChangeLogLevel,
    webTerminalEnabled = false,
    onOpenContainerTerminal,
    onSaveSettings,
    apiFetch,
    showToast,
    onRefresh,
  } = $props();

  let busyKey = $state('');

  // ---------------- Docker Logs Modal ----------------
  let logModalOpen = $state(false);
  let logModalContainer = $state('');
  let logModalLines = $state(200);
  let logModalText = $state('');

  async function runContainerAction(idOrName, action) {
    busyKey = `dk:${idOrName}:${action}`;
    try {
      await apiFetch(`/api/docker/containers/${encodeURIComponent(idOrName)}/${action}`, { method: 'POST' });
      showToast(`${idOrName}: ${action} OK`);
      await onRefresh();
    } catch (err) {
      showToast(err.message);
    } finally {
      busyKey = '';
    }
  }

  async function viewContainerLogs(idOrName) {
    logModalContainer = idOrName;
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

  async function triggerDockerPrune() {
    busyKey = 'dk:prune';
    try {
      await apiFetch('/api/docker/prune', { method: 'POST' });
      showToast(lang === 'en' ? 'Dangling images pruned' : '已完成悬空镜像清理');
      await onRefresh();
    } catch (err) {
      showToast(err.message);
    } finally {
      busyKey = '';
    }
  }

  // ---------------- Cron Drawer & Preview ----------------
  let cronDrawerOpen = $state(false);
  let cronEditIdx = $state(-1);
  let cronDraft = $state(null);
  let cronActionKind = $state('docker_prune_images');
  let cronArgsCsv = $state('');
  let cronHttpUrlInput = $state('');
  let cronHttpBodyInput = $state('');
  let cronPreviewRuns = $state([]);
  let cronPreviewError = $state('');

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
    cronDraft = c;
    cronActionKind = c.action?.kind || 'docker_prune_images';
    cronArgsCsv = c.action?.kind === 'exec' ? joinCsv(c.action.args) : '';
    cronHttpUrlInput = '';
    cronHttpBodyInput = '';
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
    } else {
      cronDraft.action = { kind: 'exec', program: '/usr/bin/logger', args: ['vane-cron'], cwd: '' };
      cronArgsCsv = 'vane-cron';
    }
  }

  async function saveCron(e) {
    e.preventDefault();
    const orig = cronEditIdx >= 0 ? settingsJson.cron[cronEditIdx] : null;
    cronDraft.timeout_secs = Number(cronDraft.timeout_secs || 60);
    if (cronDraft.action.kind === 'exec') {
      cronDraft.action.args = splitCsv(cronArgsCsv);
    } else if (cronDraft.action.kind === 'http_request') {
      const origAct = orig?.action?.kind === 'http_request' ? orig.action : null;
      cronDraft.action.url = resolveSecretInput(origAct?.url, cronHttpUrlInput);
      cronDraft.action.body = resolveSecretInput(origAct?.body, cronHttpBodyInput);
    }

    const next = deepClone(settingsJson);
    if (cronEditIdx >= 0) next.cron[cronEditIdx] = cronDraft;
    else next.cron.push(cronDraft);
    if (await onSaveSettings(next)) cronDrawerOpen = false;
  }

  async function deleteCron(idx) {
    const next = deepClone(settingsJson);
    next.cron.splice(idx, 1);
    await onSaveSettings(next);
  }

  async function runCronNow(name) {
    busyKey = `cron:${name}`;
    try {
      const r = await apiFetch(`/api/cron/${encodeURIComponent(name)}/run`, { method: 'POST' });
      showToast(`${name}: ${r.output || 'OK'}`);
      await onRefresh();
    } catch (err) {
      showToast(err.message);
      await onRefresh();
    } finally {
      busyKey = '';
    }
  }

  // ---------------- Logs Search & Clear ----------------
  let logModuleFilter = $state('');
  let logQuery = $state('');

  let filteredLogs = $derived(
    (logs || []).filter((e) => {
      if (logModuleFilter && e.module !== logModuleFilter) return false;
      if (logQuery && !`${e.module} ${e.message}`.toLowerCase().includes(logQuery.toLowerCase())) return false;
      return true;
    })
  );

  async function clearAllLogs() {
    try {
      await apiFetch('/api/logs', { method: 'DELETE' });
      showToast(lang === 'en' ? 'Logs cleared' : '运行日志已清空');
      await onRefresh();
    } catch (err) {
      showToast(err.message);
    }
  }
</script>

<!-- ===================== Docker 容器管理 ===================== -->
{#if mode === 'docker'}
  <div class="card">
    <div class="card-header">
      <div>
        <div class="card-title">{t.nav.docker}</div>
        <div style="font-size:12px;color:var(--text-secondary);">
          {lang === 'en'
            ? 'Direct /var/run/docker.sock operations with self-protection shield and bounded log demultiplexing.'
            : '直连 /var/run/docker.sock 零额外常驻进程，内置受保护容器防误停护盾与多路复用日志查看'}
        </div>
      </div>
      <div class="btn-group">
        <button type="button" class="btn btn-sm" disabled={busyKey === 'dk:prune'} onclick={triggerDockerPrune}>
          {lang === 'en' ? 'Prune Dangling Images' : '清理悬空镜像'}
        </button>
        <button type="button" class="btn btn-sm" onclick={() => onRefresh()}>{t.refresh}</button>
      </div>
    </div>

    {#if !containers?.length}
      <div class="empty-state">
        {lang === 'en' ? 'No containers returned or Docker socket unavailable.' : '暂无容器或当前未挂载 /var/run/docker.sock'}
      </div>
    {:else}
      <div style="display:grid;gap:10px;">
        {#each containers as c}
          <div class="subcard row-between">
            <div>
              <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                <span style="font-weight:700;font-size:15px;">{c.name || c.id}</span>
                <code class="mono" style="font-size:12px;color:var(--text-secondary);">{c.image}</code>
                <span class="badge {c.state === 'running' ? 'badge-ok' : 'badge-warn'}">{c.state}</span>
                {#if c.protected}
                  <span class="badge badge-info">{lang === 'en' ? 'Protected' : '受保护'}</span>
                {/if}
              </div>
              <div class="mono" style="font-size:12px;color:var(--text-secondary);margin-top:4px;">
                ID: {c.id} · {c.status}
              </div>
            </div>
            <div class="btn-group">
              {#if c.state !== 'running'}
                <button type="button" class="btn btn-xs btn-primary" disabled={busyKey.startsWith(`dk:${c.id}`)} onclick={() => runContainerAction(c.id, 'start')}>
                  Start
                </button>
              {:else}
                <button type="button" class="btn btn-xs" disabled={c.protected || busyKey.startsWith(`dk:${c.id}`)} onclick={() => runContainerAction(c.id, 'restart')}>
                  Restart
                </button>
                <button type="button" class="btn btn-xs btn-danger" disabled={c.protected || busyKey.startsWith(`dk:${c.id}`)} onclick={() => runContainerAction(c.id, 'stop')}>
                  Stop
                </button>
                {#if webTerminalEnabled && !c.protected}
                  <button type="button" class="btn btn-xs" onclick={() => onOpenContainerTerminal(c.name || c.id)}>
                    Shell
                  </button>
                {/if}
              {/if}
              <button type="button" class="btn btn-xs" onclick={() => viewContainerLogs(c.id)}>Logs</button>
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
        <div style="font-size:12px;color:var(--text-secondary);">
          {lang === 'en'
            ? 'Shell-free structured actions, non-overlapping mutex, process-group timeout reap & failure notifications.'
            : '支持 5/6 段 Cron 表达式、免 Shell 注入安全动作库、防重入互斥与进程组超时强杀回收'}
        </div>
      </div>
      <button type="button" class="btn btn-primary btn-sm" onclick={() => openCronDrawer(-1)}>+ {t.add}</button>
    </div>

    {#if !settingsJson.cron?.length}
      <div class="empty-state">{t.common.empty}</div>
    {:else}
      <div style="display:grid;gap:12px;">
        {#each settingsJson.cron as job, idx}
          {@const st = (dashboard?.cron || []).find((x) => x.name === job.name)}
          <div class="subcard">
            <div class="row-between">
              <div>
                <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
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
                <button type="button" class="btn btn-xs btn-primary" disabled={busyKey === `cron:${job.name}`} onclick={() => runCronNow(job.name)}>
                  {busyKey === `cron:${job.name}` ? '...' : (lang === 'en' ? 'Run Now' : '立即执行')}
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
      <span class="card-title">{t.nav.logs}</span>
      <div class="btn-group">
        <input
          type="text"
          style="width:180px;min-height:36px;padding:4px 10px;font-size:13px;"
          placeholder={lang === 'en' ? 'Filter keyword...' : '搜索关键字...'}
          bind:value={logQuery}
        />
        <input
          type="text"
          class="mono"
          style="width:120px;min-height:36px;padding:4px 10px;font-size:13px;"
          placeholder="module"
          bind:value={logModuleFilter}
        />
        <select
          style="width:115px;min-height:36px;padding:4px 8px;font-size:13px;"
          value={logLevelFilter}
          onchange={(e) => onChangeLogLevel(e.currentTarget.value)}
        >
          <option value="">ALL</option>
          <option value="info">INFO+</option>
          <option value="warn">WARN+</option>
          <option value="error">ERROR</option>
        </select>
        <button type="button" class="btn btn-sm btn-danger" onclick={clearAllLogs}>
          {lang === 'en' ? 'Clear' : '清空'}
        </button>
      </div>
    </div>

    <div class="mono" style="background:var(--bg-elevated);padding:14px;border-radius:12px;max-height:560px;overflow-y:auto;font-size:12px;line-height:1.65;">
      {#if !filteredLogs.length}
        <div style="color:var(--text-muted);">{lang === 'en' ? 'No matching log entries in memory ring.' : '内存环形缓冲区中暂无匹配日志'}</div>
      {:else}
        {#each filteredLogs as entry}
          <div style="padding:2px 0;border-bottom:1px solid rgba(255,255,255,0.03);word-break:break-all;">
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
        <div class="card-title">Container Logs · {logModalContainer}</div>
        <div class="btn-group">
          <select style="width:100px;min-height:34px;font-size:13px;" bind:value={logModalLines} onchange={reloadContainerLogs}>
            <option value={100}>100 lines</option>
            <option value={300}>300 lines</option>
            <option value={1000}>1000 lines</option>
          </select>
          <button type="button" class="btn btn-sm" onclick={reloadContainerLogs}>{t.refresh}</button>
          <button type="button" class="btn btn-sm" onclick={() => logModalOpen = false}>{t.cancel}</button>
        </div>
      </div>
      <div class="drawer-body">
        <pre class="mono" style="background:#05070a;color:#e2e8f0;padding:14px;border-radius:12px;font-size:12px;white-space:pre-wrap;word-break:break-all;">{logModalText}</pre>
      </div>
    </div>
  </div>
{/if}

<!-- Cron 编辑抽屉 -->
{#if cronDrawerOpen && cronDraft}
  <div class="drawer-backdrop" role="presentation" onclick={(e) => { if (e.target === e.currentTarget) cronDrawerOpen = false; }}>
    <form class="drawer-panel" onsubmit={saveCron}>
      <div class="drawer-header">
        <div class="card-title">{cronEditIdx >= 0 ? t.edit : t.add} · {t.nav.cron}</div>
        <button type="button" class="btn btn-sm" onclick={() => cronDrawerOpen = false}>{t.cancel}</button>
      </div>
      <div class="drawer-body">
        <div class="form-grid">
          <div class="field">
            <label for="cr-name">Job Name</label>
            <input id="cr-name" type="text" class="mono" bind:value={cronDraft.name} required />
          </div>
          <div class="field">
            <label for="cr-to">Timeout (secs)</label>
            <input id="cr-to" type="number" min="1" max="86400" bind:value={cronDraft.timeout_secs} required />
          </div>
        </div>

        <div class="field">
          <label for="cr-sched">Cron Expression (5-field or 6-field with seconds)</label>
          <input
            id="cr-sched"
            type="text"
            class="mono"
            bind:value={cronDraft.schedule}
            oninput={(e) => refreshCronPreview(e.currentTarget.value)}
            required
          />
          <div class="btn-group" style="margin-top:4px;">
            {#each [['0 0 4 * * *', 'Daily 04:00'], ['0 */30 * * * *', 'Every 30m'], ['0 0 3 * * 0', 'Weekly Sun 03:00']] as [expr, label]}
              <button type="button" class="btn btn-xs" onclick={() => { cronDraft.schedule = expr; refreshCronPreview(expr); }}>{label}</button>
            {/each}
          </div>
          {#if cronPreviewError}
            <div style="font-size:12px;color:var(--danger);">{cronPreviewError}</div>
          {:else if cronPreviewRuns.length}
            <div class="mono" style="font-size:11px;color:var(--accent);">
              Next: {cronPreviewRuns.join(' · ')}
            </div>
          {/if}
        </div>

        <div class="field">
          <label for="cr-kind">Action Type</label>
          <select id="cr-kind" bind:value={cronActionKind} onchange={onCronKindChange}>
            <option value="docker_prune_images">docker_prune_images (Clean Docker Images)</option>
            <option value="docker_restart_container">docker_restart_container</option>
            <option value="rule_toggle">rule_toggle (Enable/Disable Proxy or Forward Rule)</option>
            <option value="http_request">http_request (Scheduled Webhook)</option>
            <option value="exec">exec (Shell-free Program + Args Array)</option>
          </select>
        </div>

        {#if cronDraft.action.kind === 'docker_prune_images'}
          <label class="check-row"><input type="checkbox" bind:checked={cronDraft.action.dangling_only} /> Dangling Images Only</label>
        {:else if cronDraft.action.kind === 'docker_restart_container'}
          <div class="field">
            <label for="cr-cnt">Container Name or ID</label>
            <input id="cr-cnt" type="text" class="mono" bind:value={cronDraft.action.container} required />
          </div>
        {:else if cronDraft.action.kind === 'rule_toggle'}
          <div class="form-grid">
            <div class="field">
              <label for="cr-rtk">Target Module</label>
              <select id="cr-rtk" bind:value={cronDraft.action.target_kind}>
                <option value="port_forward">port_forward</option>
                <option value="reverse_proxy">reverse_proxy</option>
              </select>
            </div>
            <div class="field">
              <label for="cr-rtn">Rule Name</label>
              <input id="cr-rtn" type="text" class="mono" bind:value={cronDraft.action.rule} required />
            </div>
          </div>
          <label class="check-row"><input type="checkbox" bind:checked={cronDraft.action.enable} /> Set Enabled = true</label>
        {:else if cronDraft.action.kind === 'http_request'}
          <div class="form-grid">
            <div class="field">
              <label for="cr-hm">HTTP Method</label>
              <select id="cr-hm" bind:value={cronDraft.action.method}>
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
              </select>
            </div>
            <div class="field">
              <label for="cr-hu">URL (Vault Sealed)</label>
              <input id="cr-hu" type="text" class="mono" placeholder={secretMaskedHint(cronDraft.action.url, 'https://...')} bind:value={cronHttpUrlInput} />
            </div>
          </div>
        {:else}
          <div class="form-grid">
            <div class="field">
              <label for="cr-prg">Absolute Program Path</label>
              <input id="cr-prg" type="text" class="mono" placeholder="/usr/bin/logger" bind:value={cronDraft.action.program} required />
            </div>
            <div class="field">
              <label for="cr-arg">Arguments (comma separated)</label>
              <input id="cr-arg" type="text" class="mono" bind:value={cronArgsCsv} />
            </div>
          </div>
        {/if}

        <div style="display:flex;gap:18px;flex-wrap:wrap;margin-top:8px;">
          <label class="check-row"><input type="checkbox" bind:checked={cronDraft.enabled} /> {t.enabled}</label>
          <label class="check-row"><input type="checkbox" bind:checked={cronDraft.notify_on_failure} /> Notify Channels on Failure</label>
        </div>
      </div>
      <div class="drawer-footer">
        <button type="button" class="btn" onclick={() => cronDrawerOpen = false}>{t.cancel}</button>
        <button type="submit" class="btn btn-primary">{t.confirm}</button>
      </div>
    </form>
  </div>
{/if}
