<script>
  import Icons from './Icons.svelte';
  import TerminalPane from './TerminalPane.svelte';
  import EditorDialog from './EditorDialog.svelte';
  import ComboInput from './ComboInput.svelte';
  import { deepClone } from '../lib/helpers.js';

  let {
    t,
    lang,
    visible = true,
    initialTarget = 'host',
    targetNonce = 0,
    containers = [],
    maxSessions = 10,
    requireReauth = false,
    dockerRequireReauth = false,
    onUnlockModule = null,
    settingsJson = null,
    onSaveSettings = null,
    askConfirm = null,
    requestReauth = null,
    apiFetch,
    showToast,
  } = $props();

  let termSettingsOpen = $state(false);
  let termSettingsSaving = $state(false);
  let termShellDraft = $state('auto');
  let termCwdDraft = $state('/root');
  let termIdleDraft = $state(900);
  let termMaxDraft = $state(10);

  function openTermSettings() {
    const wt = settingsJson?.web_terminal || {};
    termShellDraft = String(wt.shell || 'auto');
    termCwdDraft = String(wt.default_cwd || '/root');
    termIdleDraft = Number(wt.idle_timeout_secs || 900);
    termMaxDraft = Number(wt.max_sessions || 10);
    termSettingsOpen = true;
  }

  async function saveTermSettings(e) {
    e.preventDefault();
    if (termSettingsSaving || !settingsJson || !onSaveSettings) return;
    termSettingsSaving = true;
    try {
      const next = deepClone(settingsJson);
      next.web_terminal = {
        ...next.web_terminal,
        shell: String(termShellDraft || '').trim() || 'auto',
        default_cwd: String(termCwdDraft || '').trim() || '/root',
        idle_timeout_secs: Math.max(60, Math.min(3600, Number(termIdleDraft) || 900)),
        max_sessions: Math.max(1, Math.min(10, Number(termMaxDraft) || 10)),
      };
      if (await onSaveSettings(next)) {
        termSettingsOpen = false;
      }
    } finally {
      termSettingsSaving = false;
    }
  }

  let maxTabs = $derived(Math.min(10, Math.max(1, Number(maxSessions) || 10)));
  let availableShells = $state([]);
  let defaultHostShell = $state('bash');
  let shellsLoaded = $state(false);

  let nextTabId = 1;
  let lastHandledNonce = -1;

  function nextAvailableHostSeq(list) {
    const used = new Set(
      (list || [])
        .filter((tb) => tb.target === 'host' && tb.seq > 0)
        .map((tb) => tb.seq)
    );
    let n = 1;
    while (used.has(n)) n++;
    return n;
  }

  function makeTab(target = 'host', autoConnect = false, existingTabs = []) {
    const id = nextTabId++;
    const seq = target === 'host' ? nextAvailableHostSeq(existingTabs) : 0;
    return {
      id,
      seq,
      initialTarget: target,
      target,
      shell: target === 'host' ? '' : 'auto',
      connState: 'disconnected',
      hasOutput: false,
      unread: false,
      customTitle: '',
      autoConnect,
    };
  }

  let tabs = $state([makeTab('host', false, [])]);
  let activeTabId = $state(1);
  let editingTabId = $state(0);
  let editingTitle = $state('');
  let tabListEl = $state(null);
  let tabsCanScrollLeft = $state(false);
  let tabsCanScrollRight = $state(false);

  let connectedCount = $derived(
    tabs.filter((tb) => tb.connState === 'connected' || tb.connState === 'connecting').length
  );

  function updateTabScrollFade() {
    const el = tabListEl;
    if (!el) {
      tabsCanScrollLeft = false;
      tabsCanScrollRight = false;
      return;
    }
    tabsCanScrollLeft = el.scrollLeft > 4;
    tabsCanScrollRight = el.scrollLeft + el.clientWidth < el.scrollWidth - 4;
  }

  $effect(() => {
    const _active = activeTabId;
    const _len = tabs.length;
    const el = tabListEl;
    if (!el) return;
    queueMicrotask(() => {
      const activeNode = el.querySelector(`[data-pty-tab="${_active}"]`);
      activeNode?.scrollIntoView({ behavior: 'smooth', inline: 'nearest', block: 'nearest' });
      updateTabScrollFade();
    });
    const onResize = () => updateTabScrollFade();
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  });

  async function loadAvailableShells() {
    try {
      const r = await apiFetch('/api/pty/shells');
      const list = Array.isArray(r.available) ? r.available : [];
      availableShells = list;
      defaultHostShell = r.default || (list.some((s) => s.id === 'bash') ? 'bash' : list[0]?.id || 'sh');
    } catch {
      availableShells = [
        { id: 'bash', path: '/bin/bash' },
        { id: 'sh', path: '/bin/sh' },
      ];
      defaultHostShell = 'bash';
    } finally {
      shellsLoaded = true;
    }
  }

  $effect(() => {
    if (visible && !shellsLoaded) {
      loadAvailableShells();
    }
  });

  // 从 Docker 容器页点击「终端」进入时：复用已有容器标签，或在未达上限时新开独立标签页，不打断宿主机终端
  $effect(() => {
    const nonce = targetNonce;
    const reqTarget = initialTarget || 'host';
    if (nonce === lastHandledNonce) return;
    lastHandledNonce = nonce;
    if (nonce === 0 && reqTarget === 'host') return;

    const existing = tabs.find((tb) => tb.target === reqTarget);
    if (existing) {
      selectTab(existing.id);
      return;
    }

    const active = tabs.find((tb) => tb.id === activeTabId);
    const shouldAutoConnect = !requireReauth && !(reqTarget.startsWith('container:') && dockerRequireReauth);
    if (active && active.connState === 'disconnected' && !active.hasOutput && active.target === 'host' && reqTarget !== 'host') {
      const replaced = makeTab(reqTarget, shouldAutoConnect, tabs);
      tabs = tabs.map((tb) => (tb.id === active.id ? replaced : tb));
      activeTabId = replaced.id;
      return;
    }

    if (tabs.length >= maxTabs) {
      showToast(t.term.tabLimitReached.replace('{max}', String(maxTabs)), 'warn');
      return;
    }

    const created = makeTab(reqTarget, shouldAutoConnect, tabs);
    tabs = [...tabs, created];
    activeTabId = created.id;
  });

  function tabDisplayTitle(tb) {
    if (tb.customTitle) return tb.customTitle;
    if (tb.target && tb.target.startsWith('container:')) {
      return tb.target.slice('container:'.length);
    }
    return `${t.term.hostTab} #${tb.seq || 1}`;
  }

  function isTabClosable(tb) {
    if (tabs.length > 1) return true;
    return (
      tb.connState === 'connected' ||
      tb.connState === 'connecting' ||
      tb.hasOutput ||
      tb.target !== 'host' ||
      Boolean(tb.customTitle)
    );
  }

  function selectTab(id) {
    activeTabId = id;
    tabs = tabs.map((tb) => (tb.id === id && tb.unread ? { ...tb, unread: false } : tb));
  }

  function addNewTab() {
    if (tabs.length >= maxTabs) {
      showToast(t.term.tabLimitReached.replace('{max}', String(maxTabs)), 'warn');
      return;
    }
    const created = makeTab('host', false, tabs);
    tabs = [...tabs, created];
    activeTabId = created.id;
  }

  function removeTabNow(id) {
    const idx = tabs.findIndex((tb) => tb.id === id);
    if (idx < 0) return;
    const remaining = tabs.filter((tb) => tb.id !== id);
    if (remaining.length === 0) {
      const fresh = makeTab('host', false, []);
      tabs = [fresh];
      activeTabId = fresh.id;
      return;
    }
    tabs = remaining;
    if (activeTabId === id) {
      const fallback = remaining[Math.min(idx, remaining.length - 1)];
      activeTabId = fallback.id;
      tabs = tabs.map((tb) => (tb.id === fallback.id ? { ...tb, unread: false } : tb));
    }
  }

  function requestCloseTab(tb) {
    if (!isTabClosable(tb)) return;
    const isRunning = tb.connState === 'connected' || tb.connState === 'connecting';
    if (isRunning && askConfirm) {
      askConfirm({
        title: t.term.closeTabConfirmTitle,
        message: `${tabDisplayTitle(tb)} — ${t.term.closeTabConfirmDesc}`,
        confirmLabel: t.term.closeTab,
        danger: true,
        onConfirm: () => removeTabNow(tb.id),
      });
      return;
    }
    removeTabNow(tb.id);
  }

  function autofocus(node) {
    node.focus();
    node.select();
  }

  function startRenameTab(tb) {
    editingTabId = tb.id;
    editingTitle = tabDisplayTitle(tb);
  }

  function commitRenameTab() {
    if (!editingTabId) return;
    const nextTitle = editingTitle.trim().slice(0, 32);
    const id = editingTabId;
    editingTabId = 0;
    tabs = tabs.map((tb) => (tb.id === id ? { ...tb, customTitle: nextTitle } : tb));
  }

  function cancelRenameTab() {
    editingTabId = 0;
  }

  function updateTabState(id, patch) {
    const cur = tabs.find((tb) => tb.id === id);
    if (!cur) return;
    if (
      cur.connState === patch.connState &&
      cur.target === patch.target &&
      cur.shell === patch.shell &&
      cur.hasOutput === patch.hasOutput
    ) {
      return;
    }
    const nextPatch =
      patch.target === 'host' && cur.target !== 'host' && !cur.seq
        ? { ...patch, seq: nextAvailableHostSeq(tabs) }
        : patch;
    tabs = tabs.map((tb) => (tb.id === id ? { ...tb, ...nextPatch } : tb));
  }

  function markTabUnread(id) {
    if (id === activeTabId) return;
    const cur = tabs.find((tb) => tb.id === id);
    if (!cur || cur.unread) return;
    tabs = tabs.map((tb) => (tb.id === id ? { ...tb, unread: true } : tb));
  }
</script>

<div class="card pty-shell-card">
  <!-- 多标签终端顶栏 -->
  <div class="pty-tabbar tv-tabbar">
    <div class="tv-tabs-group">
      <div
        bind:this={tabListEl}
        class="pty-tab-list tv-tab-list"
        class:fade-left={tabsCanScrollLeft}
        class:fade-right={tabsCanScrollRight}
        role="tablist"
        aria-label={t.nav.web_terminal}
        onscroll={updateTabScrollFade}
      >
        {#each tabs as tb (tb.id)}
          {@const isActive = tb.id === activeTabId}
          <div
            data-pty-tab={tb.id}
            class="pty-tab tv-tab {isActive ? 'active' : ''}"
            onauxclick={(e) => {
              if (e.button === 1) {
                e.preventDefault();
                requestCloseTab(tb);
              }
            }}
          >
            {#if editingTabId === tb.id}
              <input
                use:autofocus
                type="text"
                class="pty-tab-rename tv-tab-rename"
                maxlength="32"
                aria-label={t.term?.renameTab || t.term.renameHint}
                bind:value={editingTitle}
                onblur={commitRenameTab}
                onkeydown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    commitRenameTab();
                  } else if (e.key === 'Escape') {
                    e.preventDefault();
                    cancelRenameTab();
                  }
                }}
              />
            {:else}
              <button
                type="button"
                role="tab"
                aria-selected={isActive}
                class="pty-tab-main tv-tab-main"
                title={t.term.renameHint}
                onclick={() => selectTab(tb.id)}
                ondblclick={() => startRenameTab(tb)}
              >
                <span
                  class="status-dot {tb.connState === 'connected'
                    ? 'ok'
                    : tb.connState === 'connecting'
                      ? 'warn'
                      : 'muted'}"
                ></span>
                {#if tb.target.startsWith('container:')}
                  <Icons name="docker" size={13} />
                {/if}
                <span class="pty-tab-title tv-tab-title">{tabDisplayTitle(tb)}</span>
                {#if tb.shell && tb.shell !== 'auto'}
                  <span class="pty-tab-shell mono tv-tab-shell">{tb.shell}</span>
                {/if}
                {#if tb.unread && !isActive}
                  <span class="pty-tab-unread" aria-label="Unread output"></span>
                {/if}
              </button>
            {/if}
            {#if isTabClosable(tb)}
              <button
                type="button"
                class="pty-tab-close tv-tab-close"
                title={t.term.closeTab}
                aria-label={`${t.term.closeTab} ${tabDisplayTitle(tb)}`}
                onclick={() => requestCloseTab(tb)}
              >
                <Icons name="x" size={12} />
              </button>
            {/if}
          </div>
        {/each}
      </div>

      <!-- 新建标签按钮固定于滚动列表右侧，窄屏下永不被挤出可视区 -->
      <button
        type="button"
        class="pty-tab-add tv-tab-add"
        disabled={tabs.length >= maxTabs}
        title={tabs.length >= maxTabs ? t.term.tabLimitReached.replace('{max}', String(maxTabs)) : t.term.newTab}
        aria-label={t.term.newTab}
        onclick={addNewTab}
      >
        <Icons name="plus" size={15} />
      </button>
    </div>

    <div class="pty-tabbar-meta tv-tabbar-meta">
      <span
        class="badge {connectedCount > 0 ? 'badge-ok' : 'badge-muted'} num tv-count-badge"
        title={lang === 'en'
          ? `${connectedCount} active / ${maxTabs} max sessions`
          : `活跃会话 ${connectedCount} / 上限 ${maxTabs}`}
      >
        {connectedCount}/{maxTabs}
      </span>
      {#if settingsJson && onSaveSettings}
        <button
          type="button"
          class="btn btn-xs tv-settings-btn"
          aria-label={lang === 'en' ? 'Terminal Settings' : '终端设置'}
          title={lang === 'en' ? 'Terminal Settings' : '终端设置'}
          onclick={openTermSettings}
        >
          <Icons name="settings" size={14} />
          <span class="tv-settings-label">{lang === 'en' ? 'Settings' : '终端设置'}</span>
        </button>
      {/if}
    </div>
  </div>

  <!-- 各终端会话独立保活挂载（切换标签页不中断正在执行的后台命令） -->
  <div class="pty-panes-wrap">
    {#each tabs as tb (tb.id)}
      <div style={tb.id === activeTabId ? '' : 'display:none;'}>
        <TerminalPane
          {t}
          {lang}
          active={visible && tb.id === activeTabId}
          initialTarget={tb.initialTarget}
          initialShell={tb.shell}
          autoConnect={tb.autoConnect}
          {availableShells}
          {defaultHostShell}
          {shellsLoaded}
          {containers}
          {requireReauth}
          {dockerRequireReauth}
          {onUnlockModule}
          {requestReauth}
          {apiFetch}
          {showToast}
          tabTitle={tabDisplayTitle(tb)}
          onStartRename={() => startRenameTab(tb)}
          onStateChange={(patch) => updateTabState(tb.id, patch)}
          onBackgroundActivity={() => markTabUnread(tb.id)}
        />
      </div>
    {/each}
  </div>
</div>

<!-- Web 终端专属设置弹窗 -->
<EditorDialog
  open={termSettingsOpen}
  title={t.cfg.groupTerminal}
  size="sm"
  busy={termSettingsSaving}
  {t}
  {askConfirm}
  onSubmit={saveTermSettings}
  onClose={() => (termSettingsOpen = false)}
>
  <div class="field">
    <label for="wt-mod-shell">{t.cfg.ptyShell}</label>
    <ComboInput
      id="wt-mod-shell"
      placeholder="auto / bash / sh"
      options={[
        { value: 'auto', label: 'auto', sub: 'bash > sh' },
        { value: 'bash', label: 'bash' },
        { value: 'sh', label: 'sh' },
        { value: '/bin/bash', label: '/bin/bash' },
        { value: '/bin/sh', label: '/bin/sh' },
      ]}
      bind:value={termShellDraft}
    />
  </div>
  <div class="field">
    <label for="wt-mod-cwd">{t.cfg.ptyCwd}</label>
    <input id="wt-mod-cwd" type="text" class="mono" bind:value={termCwdDraft} required />
  </div>
  <div class="form-grid">
    <div class="field">
      <label for="wt-mod-idle">{t.cfg.ptyIdle}</label>
      <input id="wt-mod-idle" type="number" min="60" max="3600" bind:value={termIdleDraft} required />
    </div>
    <div class="field">
      <label for="wt-mod-max">{t.cfg.ptyMaxSess}</label>
      <input id="wt-mod-max" type="number" min="1" max="10" bind:value={termMaxDraft} required />
    </div>
  </div>
</EditorDialog>

<style>
  .tv-tabbar {
    gap: 8px;
  }
  .tv-tabs-group {
    display: flex;
    align-items: center;
    gap: 6px;
    flex: 1;
    min-width: 0;
  }
  .tv-tab-list {
    flex: 0 1 auto;
    max-width: 100%;
    min-width: 0;
    scroll-behavior: smooth;
    -webkit-overflow-scrolling: touch;
  }
  .tv-tab-list.fade-right {
    mask-image: linear-gradient(to right, #000 0%, #000 88%, transparent 100%);
    -webkit-mask-image: linear-gradient(to right, #000 0%, #000 88%, transparent 100%);
  }
  .tv-tab-list.fade-left {
    mask-image: linear-gradient(to right, transparent 0%, #000 12%, #000 100%);
    -webkit-mask-image: linear-gradient(to right, transparent 0%, #000 12%, #000 100%);
  }
  .tv-tab-list.fade-left.fade-right {
    mask-image: linear-gradient(to right, transparent 0%, #000 10%, #000 90%, transparent 100%);
    -webkit-mask-image: linear-gradient(to right, transparent 0%, #000 10%, #000 90%, transparent 100%);
  }
  .tv-tab-add {
    flex-shrink: 0;
  }
  .tv-tabbar-meta {
    gap: 6px;
  }
  .tv-count-badge {
    padding: 2px 8px;
    font-size: 11.5px;
  }
  @media (max-width: 920px) {
    .tv-tabbar {
      padding: 8px 10px;
    }
    .tv-tab-main {
      min-height: 36px;
      padding: 0 4px 0 10px;
    }
    .tv-tab-close {
      width: 30px;
      height: 30px;
      margin-right: 3px;
    }
    .tv-tab-add {
      width: 36px;
      height: 36px;
    }
    .tv-tab-rename {
      font-size: 16px !important;
      min-height: 34px !important;
      width: 132px !important;
    }
  }
  @media (max-width: 640px) {
    .tv-tab-title {
      max-width: 88px;
    }
    .tv-tab-shell {
      display: none;
    }
    .tv-settings-label {
      display: none;
    }
    .tv-settings-btn {
      min-width: 36px;
      min-height: 36px;
      padding: 0;
    }
  }
</style>
