<script>
  import Icons from './Icons.svelte';
  import SecretField from './SecretField.svelte';
  import HeaderRowsEditor from './HeaderRowsEditor.svelte';
  import EditorDialog from './EditorDialog.svelte';
  import Select from './Select.svelte';
  import ComboInput from './ComboInput.svelte';
  import FacetFilter from './FacetFilter.svelte';
  import CronSchedulePicker from './CronSchedulePicker.svelte';
  import { describeCronExpr, validateCronExpr } from '../lib/cron.js';
  import {
    splitCsv,
    joinCsv,
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
  let dockerSettingsOpen = $state(false);
  let dockerSocketDraft = $state('/var/run/docker.sock');
  let dockerProtectedCsv = $state('');
  let dockerLogTailDraft = $state(200);
  let dockerLogTsDraft = $state(false);
  let logSettingsOpen = $state(false);
  let logRingCapDraft = $state(300);

  let containerNameOptions = $derived(
    (containers || []).map((c) => ({ value: c.name || c.id, label: c.name || c.id, sub: c.image || '' }))
  );

  function openDockerSettings() {
    if (!settingsJson) return;
    dockerSocketDraft = String(settingsJson.admin?.docker_socket || '/var/run/docker.sock');
    dockerProtectedCsv = joinCsv(settingsJson.docker?.protected_containers);
    dockerLogTailDraft = Number(settingsJson.docker?.log_tail_default || 200);
    dockerLogTsDraft = Boolean(settingsJson.docker?.log_timestamps);
    dockerSettingsOpen = true;
  }

  async function saveDockerSettings(e) {
    e.preventDefault();
    if (saving || !settingsJson) return;
    saving = true;
    try {
      const next = deepClone(settingsJson);
      next.docker = {
        ...next.docker,
        protected_containers: splitCsv(dockerProtectedCsv),
        log_tail_default: Math.max(10, Math.min(2000, Number(dockerLogTailDraft) || 200)),
        log_timestamps: Boolean(dockerLogTsDraft),
      };
      if (await onSaveSettings(next)) {
        dockerSettingsOpen = false;
      }
    } finally {
      saving = false;
    }
  }

  function openLogsSettings() {
    if (!settingsJson) return;
    logRingCapDraft = Number(settingsJson.system?.log_ring_capacity || logCapacity || 300);
    logSettingsOpen = true;
  }

  async function saveLogsSettings(e) {
    e.preventDefault();
    if (saving || !settingsJson) return;
    saving = true;
    try {
      const next = deepClone(settingsJson);
      next.system = {
        ...next.system,
        log_ring_capacity: Math.max(50, Math.min(1000, Number(logRingCapDraft) || 300)),
      };
      if (await onSaveSettings(next)) {
        logSettingsOpen = false;
      }
    } finally {
      saving = false;
    }
  }

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
  let expandedCronOutput = $state({});

  let ruleNamesForKind = $derived(
    cronDraft?.action?.target_kind === 'reverse_proxy'
      ? (settingsJson?.reverse_proxy || []).map((r) => r.name)
      : (settingsJson?.port_forwards || []).map((p) => p.name)
  );

  $effect(() => {
    void mode;
    closeLogModal();
    cronDrawerOpen = false;
    dockerSettingsOpen = false;
    logSettingsOpen = false;
    dockerQuery = '';
    dockerStateFilter = 'all';
  });

  function cronActionLabel(kind) {
    const en = lang === 'en';
    switch (kind) {
      case 'docker_prune_images':
        return en ? 'Prune Docker Images' : '清理 Docker 镜像';
      case 'docker_restart_container':
        return en ? 'Restart Container' : '重启容器';
      case 'rule_toggle':
        return en ? 'Toggle Rule' : '开关规则';
      case 'http_request':
        return en ? 'HTTP Request' : 'HTTP 请求';
      case 'exec':
        return en ? 'Run Command' : '执行命令';
      default:
        return kind || '';
    }
  }

  function cronActionSummary(action) {
    if (!action) return '';
    const en = lang === 'en';
    if (action.kind === 'docker_prune_images') {
      return action.dangling_only !== false
        ? en
          ? 'Dangling images only'
          : '仅清理悬空镜像'
        : en
          ? 'All unused images'
          : '清理全部未用镜像';
    }
    if (action.kind === 'docker_restart_container') {
      return action.container || '';
    }
    if (action.kind === 'rule_toggle') {
      const modName =
        action.target_kind === 'reverse_proxy'
          ? t.nav.reverse_proxy
          : t.nav.port_forward;
      const act = action.enable ? (en ? 'Enable' : '开启') : en ? 'Disable' : '关闭';
      return `${act} ${modName} · ${action.rule || '?'}`;
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
    cronEditIdx = idx;
    const c = idx >= 0
      ? deepClone(settingsJson.cron[idx])
      : {
          name: `job_${(settingsJson?.cron?.length || 0) + 1}`,
          enabled: true,
          schedule: '0 4 * * *',
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
      cronDraft.action = { kind: 'exec', program: '', args: [], cwd: '' };
      cronArgsLines = '';
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
    const schedCheck = validateCronExpr(cronDraft.schedule, lang);
    if (!schedCheck.valid) {
      showToast(schedCheck.error, 'error');
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

<!-- ===================== Docker 容器管理（对齐 Arcane Screenshot 1 无冗余嵌套） ===================== -->
{#if mode === 'docker'}
  <div class="page-section-bar">
    <div>
      <div class="page-section-desc">{t.dk.subtitle}</div>
      {#if containers?.length}
        <div class="stat-inline-strip num">
          <span class="stat-inline-item"><span class="status-dot" style="background:var(--info);"></span><span class="stat-inline-num">{containers.length}</span><span>{t.all}</span></span>
          <span class="stat-inline-item"><span class="status-dot ok"></span><span class="stat-inline-num">{runningContainersCount}</span><span>{t.statuses.running}</span></span>
          <span class="stat-inline-item"><span class="status-dot muted"></span><span class="stat-inline-num">{exitedContainersCount}</span><span>{t.statuses.exited}</span></span>
        </div>
      {/if}
    </div>
    <div class="btn-group">
      <button type="button" class="btn btn-sm" onclick={openDockerSettings}>
        <Icons name="settings" size={14} />
        <span>{lang === 'en' ? 'Docker Settings' : 'Docker 设置'}</span>
      </button>
      <button type="button" class="btn btn-sm btn-danger" disabled={busyKey === 'dk:prune'} onclick={triggerDockerPrune}>
        {busyKey === 'dk:prune' ? '...' : t.dk.prune}
      </button>
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
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;flex:1;min-width:0;">
        <div class="search-wrap">
          <span class="search-icon"><Icons name="search" size={15} /></span>
          <input type="text" placeholder={t.search} aria-label={t.search} bind:value={dockerQuery} />
        </div>
        <FacetFilter
          label={lang === 'en' ? 'State' : '状态'}
          bind:value={dockerStateFilter}
          options={[
            { value: 'all', label: t.all, count: containers.length },
            { value: 'running', label: t.statuses.running, count: runningContainersCount, tone: 'ok' },
            { value: 'exited', label: t.statuses.exited, count: exitedContainersCount, tone: 'muted' },
          ]}
        />
      </div>
      <span class="mono" style="font-size:12px;color:var(--text-muted);">
        {filteredContainers.length} / {containers.length}
      </span>
    </div>
  {/if}

  {#if !containers?.length}
    {#if !dockerError}
      <div class="empty-state">{t.dk.empty}</div>
    {/if}
  {:else if !filteredContainers.length}
    <div class="empty-state">{t.common.noMatches}</div>
  {:else}
    <div class="card" style="padding:10px 12px;">
      <div class="arcane-table-wrap">
        <table class="arcane-table">
          <thead>
            <tr>
              <th>{lang === 'en' ? 'Container' : '名称'}</th>
              <th>{lang === 'en' ? 'State' : '状态'}</th>
              <th>{lang === 'en' ? 'Status' : '运行时间'}</th>
              <th>{lang === 'en' ? 'Actions' : '操作'}</th>
            </tr>
          </thead>
          <tbody>
            {#each filteredContainers as c (c.id)}
              {@const protectedHint = c.protected
                ? lang === 'en'
                  ? 'Protected container (edit in Docker Settings)'
                  : '受保护容器（可在右上角「Docker 设置」中调整）'
                : undefined}
              <tr>
                <td>
                  <div style="display:flex;align-items:center;gap:10px;min-width:0;">
                    <span
                      style="width:32px;height:32px;border-radius:10px;background:{c.state === 'running' ? 'var(--accent-soft)' : 'var(--bg-elevated)'};color:{c.state === 'running' ? 'var(--accent)' : 'var(--text-muted)'};display:grid;place-items:center;flex-shrink:0;"
                    >
                      <Icons name="docker" size={16} />
                    </span>
                    <div style="min-width:0;">
                      <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
                        <span style="font-weight:600;color:var(--text-primary);">{c.name || c.id}</span>
                        {#if c.protected}
                          <span class="badge badge-info" style="font-size:10.5px;padding:1px 7px;" title={protectedHint}>{t.dk.protected}</span>
                        {/if}
                      </div>
                      <div class="mono" style="font-size:11.5px;color:var(--text-muted);max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                        {c.image}
                      </div>
                    </div>
                  </div>
                </td>
                <td>
                  <span class="badge {c.state === 'running' ? 'badge-ok' : c.state === 'exited' ? 'badge-muted' : 'badge-warn'}">
                    {translateRuntimeStatus(c.state, t)}
                  </span>
                </td>
                <td>
                  <div class="mono" style="font-size:12px;color:var(--text-secondary);">{c.status}</div>
                  <div class="mono" style="font-size:11px;color:var(--text-muted);">{String(c.id || '').slice(0, 12)}</div>
                </td>
                <td>
                  <div class="btn-group" style="justify-content:flex-end;">
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
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </div>
  {/if}
{/if}

<!-- ===================== Cron 计划任务 ===================== -->
{#if mode === 'cron' && settingsJson}
  {@const crTotal = settingsJson.cron?.length || 0}
  {@const crOn = (settingsJson.cron || []).filter((x) => x.enabled).length}
  <div class="page-section-bar">
    <div>
      <div class="page-section-desc">{t.cronPage.subtitle}</div>
      {#if crTotal > 0}
        <div class="stat-inline-strip num">
          <span class="stat-inline-item"><span class="status-dot" style="background:var(--info);"></span><span class="stat-inline-num">{crTotal}</span><span>{t.all}</span></span>
          <span class="stat-inline-item"><span class="status-dot ok"></span><span class="stat-inline-num">{crOn}</span><span>{t.enabled}</span></span>
          <span class="stat-inline-item"><span class="status-dot muted"></span><span class="stat-inline-num">{crTotal - crOn}</span><span>{t.disabled}</span></span>
        </div>
      {/if}
    </div>
    <button type="button" class="btn btn-primary btn-sm" onclick={() => openCronDrawer(-1)}>
      <Icons name="plus" size={14} />
      <span>{t.add}</span>
    </button>
  </div>

  {#if !crTotal}
    <div class="empty-state">{t.common.empty}</div>
  {:else}
    <div class="card" style="padding:10px 12px;">
      <div class="arcane-table-wrap">
        <table class="arcane-table">
          <thead>
            <tr>
              <th>{t.cronPage.jobName}</th>
              <th>{lang === 'en' ? 'Schedule' : '调度'}</th>
              <th>{lang === 'en' ? 'Last Run' : '最近执行'}</th>
              <th>{lang === 'en' ? 'Actions' : '操作'}</th>
            </tr>
          </thead>
          <tbody>
            {#each settingsJson.cron as job, idx (job.name)}
              {@const st = (dashboard?.cron || []).find((x) => x.name === job.name)}
              {@const summary = cronActionSummary(job.action)}
              {@const outStr = st?.last_output || ''}
              {@const isLongOut = outStr.length > 90 || outStr.includes('\n')}
              {@const isExpanded = Boolean(expandedCronOutput[job.name])}
              <tr>
                <td>
                  <div style="display:flex;align-items:center;gap:10px;min-width:0;">
                    <span class="icon-tile sm {job.enabled ? (st?.status === 'failed' ? 'danger' : '') : 'muted'}">
                      <Icons name="cron" size={14} />
                    </span>
                    <div style="min-width:0;">
                      <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
                        <span style="font-weight:600;">{job.name}</span>
                        <span class="badge badge-muted" style="font-size:10.5px;">{cronActionLabel(job.action.kind)}</span>
                        {#if job.notify_on_failure}
                          <span class="badge badge-info" style="font-size:10.5px;">{lang === 'en' ? 'Notify' : '失败告警'}</span>
                        {/if}
                      </div>
                      {#if summary}
                        <div style="font-size:11.5px;color:var(--text-muted);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                          {summary}
                        </div>
                      {/if}
                    </div>
                  </div>
                </td>
                <td>
                  <div style="display:flex;flex-direction:column;gap:3px;align-items:flex-start;">
                    <span style="font-size:12.5px;font-weight:500;color:var(--text-primary);">
                      {describeCronExpr(job.schedule, lang) || job.schedule}
                    </span>
                    <span class="port-pill mono" style="font-size:11px;">
                      <span class="port-pill-lead">{job.schedule}</span>
                      <span>{job.timeout_secs || 60}s</span>
                    </span>
                  </div>
                </td>
                <td>
                  <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
                    {#if st}
                      <span class="badge {st.running ? 'badge-info' : st.status === 'ok' ? 'badge-ok' : st.status === 'failed' ? 'badge-danger' : 'badge-warn'}">
                        {st.running ? t.statuses.running : translateRuntimeStatus(st.status, t)}
                      </span>
                    {:else}
                      <span class="badge badge-muted">{t.statuses.idle}</span>
                    {/if}
                    {#if st?.last_run_unix}
                      <span class="mono" style="font-size:11.5px;color:var(--text-muted);">
                        {formatUnixTime(st.last_run_unix)} ({st.last_duration_ms}ms)
                      </span>
                    {/if}
                  </div>
                  {#if outStr}
                    <div class="mono" style="font-size:11px;color:var(--text-secondary);margin-top:4px;max-width:320px;word-break:break-word;">
                      {isLongOut && !isExpanded ? `${outStr.slice(0, 90)}…` : outStr}
                      {#if isLongOut}
                        <button
                          type="button"
                          class="btn btn-ghost btn-xs"
                          style="min-height:20px;padding:0 5px;"
                          onclick={() => (expandedCronOutput = { ...expandedCronOutput, [job.name]: !isExpanded })}
                        >
                          {isExpanded ? (lang === 'en' ? 'Collapse' : '收起') : (lang === 'en' ? 'Expand' : '展开')}
                        </button>
                      {/if}
                    </div>
                  {/if}
                </td>
                <td>
                  <div class="btn-group" style="justify-content:flex-end;">
                    <button
                      type="button"
                      role="switch"
                      aria-checked={job.enabled}
                      aria-label={`Toggle ${job.name}`}
                      class="switch switch-xs"
                      disabled={busyToggleKey === `cron:${idx}`}
                      onclick={() => toggleCronEnabled(idx)}
                    >
                      <span class="switch-thumb"></span>
                    </button>
                    <button
                      type="button"
                      class="btn btn-xs btn-primary"
                      title={!job.enabled ? t.cronPage.disabledRunHint : ''}
                      disabled={!job.enabled || Boolean(st?.running) || busyKey === `cron:${job.name}`}
                      onclick={() => runCronNow(job.name)}
                    >
                      {st?.running || busyKey === `cron:${job.name}` ? '...' : t.cronPage.runNow}
                    </button>
                    <button type="button" class="btn btn-xs" onclick={() => openCronDrawer(idx)}>{t.edit}</button>
                    <button type="button" class="btn btn-xs btn-danger" onclick={() => deleteCron(idx)}>{t.delete}</button>
                  </div>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </div>
  {/if}
{/if}

<!-- ===================== 运行日志（Arcane 分面筛选 + 结构化控制台） ===================== -->
{#if mode === 'logs'}
  <div class="toolbar">
    <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;flex:1;min-width:0;">
      <div class="search-wrap" style="max-width:260px;">
        <span class="search-icon"><Icons name="search" size={14} /></span>
        <input type="text" placeholder={t.search} aria-label={t.search} bind:value={logQuery} />
      </div>
      <FacetFilter
        label={lang === 'en' ? 'Module' : '模块'}
        value={logModuleFilter || 'all'}
        options={[
          { value: 'all', label: t.logsPage.allModules },
          ...logModules.map((m) => ({ value: m, label: m })),
        ]}
        onchange={(val) => onChangeLogFilter?.(logLevelFilter, val === 'all' ? '' : val)}
      />
      <FacetFilter
        label={lang === 'en' ? 'Level' : '级别'}
        value={logLevelFilter || 'all'}
        options={[
          { value: 'all', label: 'ALL' },
          { value: 'info', label: 'INFO+', tone: 'ok' },
          { value: 'warn', label: 'WARN+', tone: 'warn' },
          { value: 'error', label: 'ERROR', tone: 'danger' },
        ]}
        onchange={(val) => onChangeLogFilter?.(val === 'all' ? '' : val, logModuleFilter)}
      />
      <span class="mono" style="font-size:12px;color:var(--text-muted);">
        {filteredLogs.length} / {logCapacity}
      </span>
    </div>
    <div class="btn-group">
      <button type="button" class="btn btn-sm" onclick={() => (logNewestFirst = !logNewestFirst)}>
        {logNewestFirst ? t.logsPage.newestFirst : t.logsPage.oldestFirst}
      </button>
      <button type="button" class="btn btn-sm {logLiveTail ? 'btn-primary' : ''}" onclick={() => (logLiveTail = !logLiveTail)}>
        {#if logLiveTail}<span class="status-dot" style="background:#fff;width:6px;height:6px;"></span>{/if}
        <span>{t.logsPage.liveTail}</span>
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
      <button type="button" class="btn btn-sm" onclick={openLogsSettings}>
        <Icons name="settings" size={13} />
        <span>{lang === 'en' ? 'Settings' : '日志设置'}</span>
      </button>
      <button type="button" class="btn btn-sm btn-danger" onclick={clearAllLogs}>{t.logsPage.clear}</button>
    </div>
  </div>

  <div bind:this={sysLogsEl} class="log-console mono">
    {#if !filteredLogs.length}
      <div class="empty-state" style="border:none;background:transparent;">{t.logsPage.empty}</div>
    {:else}
      {#each filteredLogs as entry (entry.seq)}
        <div class="log-entry">
          <span style="color:var(--text-muted);white-space:nowrap;">{formatUnixTime(entry.ts)}</span>
          <span
            class="badge {entry.level === 'error' ? 'badge-danger' : entry.level === 'warn' ? 'badge-warn' : entry.level === 'info' ? 'badge-ok' : 'badge-muted'}"
            style="font-size:10px;padding:1px 6px;justify-content:center;"
          >
            {entry.level.toUpperCase()}
          </span>
          <span style="color:var(--info);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{entry.module}</span>
          <span style="word-break:break-word;color:var(--text-primary);">{entry.message}</span>
        </div>
      {/each}
    {/if}
  </div>
{/if}

<!-- 容器日志弹窗 -->
<EditorDialog
  open={logModalOpen}
  title={`${t.dk.logs} · ${logModalContainerName}`}
  size="lg"
  form={false}
  confirmDiscard={false}
  {t}
  onClose={closeLogModal}
>
  <div style="display:flex;flex-direction:column;gap:12px;height:100%;">
    <div class="btn-group" style="flex-wrap:wrap;">
      <input
        type="text"
        class="control-compact"
        style="width:160px;"
        placeholder={t.dk.filterLogs}
        aria-label={t.dk.filterLogs}
        bind:value={logModalQuery}
      />
      <Select
        compact
        style="width:116px;"
        ariaLabel={t.dk.lines}
        bind:value={logModalLines}
        options={(TAIL_OPTIONS.includes(logModalLines) ? TAIL_OPTIONS : [logModalLines, ...TAIL_OPTIONS].sort((a, b) => a - b)).map((n) => ({
          value: n,
          label: `${n} ${t.dk.lines}`,
        }))}
        onchange={() => reloadContainerLogs(false)}
      />
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
      style="background:#05070a;color:#e2e8f0;padding:14px;border-radius:12px;font-size:12px;white-space:pre-wrap;word-break:break-all;flex:1;min-height:260px;max-height:66dvh;overflow-y:auto;margin:0;"
    >{logModalLoading && !logModalText ? t.common.loading : filteredContainerLogText || '(empty)'}</pre>
  </div>
</EditorDialog>

<!-- Cron 编辑弹窗 -->
<EditorDialog
  open={cronDrawerOpen && Boolean(cronDraft)}
  title={`${cronEditIdx >= 0 ? t.edit : t.add} · ${t.nav.cron}`}
  size="md"
  busy={saving}
  {t}
  {askConfirm}
  onSubmit={saveCron}
  onClose={() => (cronDrawerOpen = false)}
>
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

        <CronSchedulePicker bind:value={cronDraft.schedule} {lang} {t} {apiFetch} />

        <div class="field">
          <label for="cr-kind">{t.cronPage.actionType}</label>
          <Select
            id="cr-kind"
            bind:value={cronActionKind}
            options={
              lang === 'en'
                ? [
                    { value: 'docker_prune_images', label: 'Prune Unused Docker Images' },
                    { value: 'docker_restart_container', label: 'Restart Docker Container' },
                    { value: 'rule_toggle', label: 'Enable / Disable Proxy or Forward Rule' },
                    { value: 'http_request', label: 'Send HTTP / Webhook Request' },
                    { value: 'exec', label: 'Run Local Program Command' },
                  ]
                : [
                    { value: 'docker_prune_images', label: '清理无用 Docker 镜像' },
                    { value: 'docker_restart_container', label: '定时重启 Docker 容器' },
                    { value: 'rule_toggle', label: '定时开关转发 / 反代规则' },
                    { value: 'http_request', label: '发送 HTTP / Webhook 请求' },
                    { value: 'exec', label: '执行本地程序命令' },
                  ]
            }
            onchange={onCronKindChange}
          />
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
            <ComboInput
              id="cr-cnt"
              options={(containers || []).map((c) => ({ value: c.name || c.id, label: c.name || c.id, sub: c.image || '' }))}
              bind:value={cronDraft.action.container}
              required
            />
          </div>
        {:else if cronDraft.action.kind === 'rule_toggle'}
          <div class="form-grid">
            <div class="field">
              <label for="cr-rtk">{t.cronPage.targetMod}</label>
              <Select
                id="cr-rtk"
                bind:value={cronDraft.action.target_kind}
                options={[
                  { value: 'port_forward', label: t.nav.port_forward },
                  { value: 'reverse_proxy', label: t.nav.reverse_proxy },
                ]}
                onchange={() => {
                  if (cronDraft?.action) cronDraft.action.rule = '';
                }}
              />
            </div>
            <div class="field">
              <label for="cr-rtn">{t.cronPage.targetRule}</label>
              <ComboInput id="cr-rtn" options={ruleNamesForKind} bind:value={cronDraft.action.rule} required />
            </div>
          </div>
          <label class="check-row"><input type="checkbox" bind:checked={cronDraft.action.enable} /> {t.cronPage.setEnable}</label>
        {:else if cronDraft.action.kind === 'http_request'}
          <div class="form-grid">
            <div class="field">
              <label for="cr-hm">{t.cronPage.httpMethod}</label>
              <Select
                id="cr-hm"
                mono
                bind:value={cronDraft.action.method}
                options={['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD']}
              />
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
          {#if !settingsJson?.admin?.allow_cron_exec}
            <div class="banner banner-warn" style="margin-bottom:12px;">
              <div style="display:flex;align-items:flex-start;gap:8px;">
                <Icons name="alert" size={15} />
                <span style="font-size:12.5px;">{t.cronPage.execDisabledBanner}</span>
              </div>
            </div>
          {/if}
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
            <textarea
              id="cr-arg"
              class="mono"
              placeholder={lang === 'en' ? 'One argument per line (optional)' : '每行一个参数（可选）'}
              bind:value={cronArgsLines}
            ></textarea>
          </div>
        {/if}

        <div style="display:flex;gap:18px;flex-wrap:wrap;margin-top:8px;">
          <label class="check-row"><input type="checkbox" bind:checked={cronDraft.enabled} /> {t.enabled}</label>
          <label class="check-row"><input type="checkbox" bind:checked={cronDraft.notify_on_failure} /> {t.cronPage.notifyFail}</label>
        </div>
</EditorDialog>

<!-- Docker 模块专属设置弹窗 -->
<EditorDialog
  open={dockerSettingsOpen}
  title={t.cfg.groupDocker}
  size="sm"
  busy={saving}
  {t}
  {askConfirm}
  onSubmit={saveDockerSettings}
  onClose={() => (dockerSettingsOpen = false)}
>
  <div class="field">
    <label for="dk-mod-sock" style="display:inline-flex;align-items:center;gap:6px;">
      <span>{t.cfg.dockerSocket}</span>
      <span class="badge badge-muted" style="font-size:10px;padding:1px 6px;">{t.cfg.configFileOnlyBadge}</span>
    </label>
    <input id="dk-mod-sock" type="text" class="mono" value={dockerSocketDraft} readonly disabled />
    <div class="field-hint">{t.cfg.dockerSocketReadonlyHint}</div>
  </div>
  <div class="field">
    <label for="dk-mod-prot">{t.cfg.lblProtectedContainers}</label>
    <ComboInput
      id="dk-mod-prot"
      multiple
      placeholder="vane, openwrt-core"
      options={containerNameOptions}
      bind:value={dockerProtectedCsv}
    />
  </div>
  <div class="field">
    <label for="dk-mod-tail">{t.cfg.dkTail}</label>
    <input id="dk-mod-tail" type="number" min="10" max="2000" bind:value={dockerLogTailDraft} required />
  </div>
  <label class="check-row">
    <input type="checkbox" bind:checked={dockerLogTsDraft} />
    <span>{t.cfg.dkTs}</span>
  </label>
</EditorDialog>

<!-- 运行日志设置弹窗 -->
<EditorDialog
  open={logSettingsOpen}
  title={lang === 'en' ? 'System Log Settings' : '运行日志设置'}
  size="sm"
  busy={saving}
  {t}
  {askConfirm}
  onSubmit={saveLogsSettings}
  onClose={() => (logSettingsOpen = false)}
>
  <div class="field">
    <label for="lg-mod-cap">{t.cfg.lblLogRing}</label>
    <input id="lg-mod-cap" type="number" min="50" max="1000" bind:value={logRingCapDraft} required />
    <div class="field-hint">{t.cfg.descLogRing}</div>
  </div>
</EditorDialog>
