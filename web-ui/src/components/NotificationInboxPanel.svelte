<script>
  import Icons from './Icons.svelte';
  import { registerOverlay } from '../lib/overlay.js';
  import { copyText, formatUnixTime } from '../lib/helpers.js';

  let {
    open = false,
    sidebarCollapsed = false,
    t,
    lang,
    apiFetch,
    showToast,
    askConfirm,
    onClose,
    onNavigate,
    onOpenChannelSettings,
    onUnreadChange,
  } = $props();

  let items = $state([]);
  let unreadCount = $state(0);
  let capacity = $state(100);
  let storageBytes = $state(0);
  let maxStorageBytes = $state(65536);
  let loading = $state(false);
  let busy = $state('');
  let filter = $state('all'); // 'all' | 'unread' | 'alerts'
  let expanded = $state(false);
  let detailItem = $state(null);

  let alertCount = $derived(
    items.filter((m) => ['warning', 'error', 'critical'].includes(m.severity)).length
  );

  let filteredItems = $derived.by(() => {
    if (filter === 'unread') return items.filter((m) => !m.read);
    if (filter === 'alerts') return items.filter((m) => ['warning', 'error', 'critical'].includes(m.severity));
    return items;
  });

  let expandLabel = $derived(
    expanded
      ? t.inbox?.collapse || t.common?.collapse || (lang === 'en' ? 'Collapse' : '收起')
      : t.inbox?.expand || t.common?.expand || (lang === 'en' ? 'Expand' : '展开')
  );
  let copyMsgLabel = $derived(
    t.inbox?.copyMessage || (lang === 'en' ? 'Copy' : '复制正文')
  );

  async function copyDetailMessage() {
    if (!detailItem) return;
    const text = `[${detailItem.title}]\n${detailItem.message || ''}`.trim();
    if (await copyText(text)) showToast(t.copied, 'success');
    else showToast(t.copyFailed, 'error');
  }

  function moduleLabel(mod) {
    if (!mod) return t.nav.logs;
    if (mod === 'settings/update') return t.cfg.tabUpdate;
    if (mod === 'settings/security') return t.cfg.tabSecurity;
    if (mod === 'settings/notifications') return t.cfg.tabNotifications;
    if (mod === 'settings/backup') return t.cfg.tabBackup;
    if (mod === 'settings/general' || mod === 'settings') return t.nav.settings;
    return t.nav?.[mod] || mod;
  }

  function severityClass(sev) {
    if (sev === 'critical' || sev === 'error') return 'badge-danger';
    if (sev === 'warning') return 'badge-warn';
    return 'badge-info';
  }

  function severityLabel(sev) {
    if (sev === 'critical') return lang === 'en' ? 'Critical' : '严重';
    if (sev === 'error') return lang === 'en' ? 'Error' : '错误';
    if (sev === 'warning') return lang === 'en' ? 'Warning' : '警告';
    return lang === 'en' ? 'Info' : '通知';
  }

  function formatRelative(ts) {
    const diff = Math.max(0, Math.floor(Date.now() / 1000) - Number(ts || 0));
    if (diff < 60) return lang === 'en' ? 'Just now' : '刚刚';
    if (diff < 3600) return lang === 'en' ? `${Math.floor(diff / 60)}m ago` : `${Math.floor(diff / 60)}分钟前`;
    if (diff < 86400) return lang === 'en' ? `${Math.floor(diff / 3600)}h ago` : `${Math.floor(diff / 3600)}小时前`;
    return formatUnixTime(ts);
  }

  function formatKiB(bytes) {
    return `${(Number(bytes || 0) / 1024).toFixed(1)} KiB`;
  }

  async function loadInbox(silent = false) {
    if (!silent) loading = true;
    try {
      const r = await apiFetch('/api/notifications/inbox');
      items = Array.isArray(r.items) ? r.items : [];
      unreadCount = Number(r.unread_count || 0);
      capacity = Number(r.capacity || 100);
      storageBytes = Number(r.storage_bytes || 0);
      maxStorageBytes = Number(r.max_storage_bytes || 65536);
      onUnreadChange?.(unreadCount);
    } catch (err) {
      if (!silent) showToast(err.message, 'error');
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    if (!open) {
      detailItem = null;
      expanded = false;
      return;
    }
    detailItem = null;
    loadInbox(items.length > 0);
    return registerOverlay({
      onDismiss: () => onClose?.(),
    });
  });

  async function markRead(id = null) {
    const key = id === null ? 'read-all' : `read-${id}`;
    if (busy) return;
    busy = key;
    try {
      const r = await apiFetch('/api/notifications/inbox/read', {
        method: 'POST',
        body: JSON.stringify(id === null ? {} : { id }),
      });
      if (id === null) {
        items = items.map((m) => ({ ...m, read: true }));
      } else {
        items = items.map((m) => (m.id === id ? { ...m, read: true } : m));
        if (detailItem && detailItem.id === id) detailItem = { ...detailItem, read: true };
      }
      unreadCount = Number(r.unread_count ?? items.filter((m) => !m.read).length);
      onUnreadChange?.(unreadCount);
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      busy = '';
    }
  }

  async function openDetail(item) {
    detailItem = item;
    if (!item.read) await markRead(item.id);
  }

  async function jumpToModule(item) {
    if (!item) return;
    if (!item.read) await markRead(item.id);
    detailItem = null;
    onNavigate?.(item.module || 'logs');
  }

  async function deleteItem(id) {
    if (busy) return;
    busy = `del-${id}`;
    try {
      const r = await apiFetch(`/api/notifications/inbox/${id}`, { method: 'DELETE' });
      items = items.filter((m) => m.id !== id);
      if (detailItem?.id === id) detailItem = null;
      unreadCount = Number(r.unread_count ?? items.filter((m) => !m.read).length);
      onUnreadChange?.(unreadCount);
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      busy = '';
    }
  }

  function confirmClearAll() {
    if (!items.length || busy) return;
    askConfirm({
      title: t.inbox.clearConfirmTitle,
      message: t.inbox.clearConfirmDesc,
      confirmLabel: t.inbox.clearAll,
      danger: true,
      onConfirm: async () => {
        busy = 'clear';
        try {
          await apiFetch('/api/notifications/inbox', { method: 'DELETE' });
          items = [];
          unreadCount = 0;
          storageBytes = 0;
          detailItem = null;
          onUnreadChange?.(0);
          showToast(t.inbox.clearedToast, 'success');
        } catch (err) {
          showToast(err.message, 'error');
        } finally {
          busy = '';
        }
      },
    });
  }
</script>

{#if open}
  <div
    class="activity-tray-backdrop"
    role="presentation"
    onclick={(e) => {
      if (e.target === e.currentTarget) onClose?.();
    }}
  ></div>

  <div
    class="activity-tray {sidebarCollapsed ? 'collapsed-anchor' : ''} {expanded ? 'expanded' : ''}"
    role="dialog"
    aria-modal="true"
    aria-label={t.inbox.title}
  >
    <!-- Arcane 活动/通知浮层顶栏 -->
    <div class="activity-tray-head">
      <div style="display:flex;align-items:center;gap:8px;min-width:0;">
        {#if detailItem}
          <button
            type="button"
            class="btn btn-ghost btn-icon inbox-head-btn"
            style="margin-left:-4px;"
            aria-label={t.inbox.backToList}
            title={t.inbox.backToList}
            onclick={() => (detailItem = null)}
          >
            <Icons name="arrow_left" size={16} />
          </button>
          <span style="font-size:14.5px;font-weight:700;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
            {t.inbox.detailTitle}
          </span>
        {:else}
          <span style="font-size:15px;font-weight:700;white-space:nowrap;">{t.inbox.title}</span>
          {#if unreadCount > 0}
            <span class="badge badge-info num" style="font-size:11px;padding:1px 8px;">
              {unreadCount} {t.inbox.unreadUnit}
            </span>
          {/if}
        {/if}
      </div>

      <div class="inbox-head-actions">
        {#if !detailItem}
          <button
            type="button"
            class="btn btn-ghost btn-icon inbox-head-btn"
            aria-label={t.refresh}
            title={t.refresh}
            disabled={loading}
            onclick={() => loadInbox(false)}
          >
            <span class:is-spinning={loading} style="display:inline-flex;">
              <Icons name="refresh" size={14} />
            </span>
          </button>
          {#if unreadCount > 0}
            <button
              type="button"
              class="btn btn-ghost btn-icon inbox-head-btn"
              aria-label={t.inbox.markAllRead}
              title={t.inbox.markAllRead}
              disabled={Boolean(busy)}
              onclick={() => markRead(null)}
            >
              <Icons name="check" size={14} />
            </button>
          {/if}
          {#if items.length > 0}
            <button
              type="button"
              class="btn btn-ghost btn-icon btn-icon-danger inbox-head-btn"
              style="color:var(--danger);"
              aria-label={t.inbox.clearAll}
              title={t.inbox.clearAll}
              disabled={Boolean(busy)}
              onclick={confirmClearAll}
            >
              <Icons name="trash" size={14} />
            </button>
          {/if}
        {/if}
        <button
          type="button"
          class="btn btn-ghost btn-icon inbox-head-btn inbox-expand-btn"
          aria-label={expandLabel}
          title={expandLabel}
          onclick={() => (expanded = !expanded)}
        >
          <Icons name="expand" size={14} />
        </button>
        <button
          type="button"
          class="btn btn-ghost btn-icon inbox-head-btn"
          aria-label={t.close}
          title={t.close}
          onclick={() => onClose?.()}
        >
          <Icons name="x" size={15} />
        </button>
      </div>
    </div>

    <!-- 主内容区：列表或详情 -->
    <div class="activity-tray-body">
      {#if detailItem}
        <div style="display:grid;gap:12px;padding:6px 6px;">
          <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
            <span class="badge {severityClass(detailItem.severity)}">{severityLabel(detailItem.severity)}</span>
            <span class="badge badge-muted">{moduleLabel(detailItem.module)}</span>
            <span class="badge badge-muted" class:mono={!t.events?.[detailItem.event]}>
              {t.events?.[detailItem.event] || detailItem.event}
            </span>
          </div>
          <div style="font-size:15.5px;font-weight:700;line-height:1.4;word-break:break-word;">
            {detailItem.title}
          </div>
          <div class="row-between" style="gap:8px;">
            <div class="mono" style="font-size:11.5px;color:var(--text-muted);">
              {formatUnixTime(detailItem.ts)}
            </div>
            <div class="btn-group" style="gap:6px;">
              <button type="button" class="btn btn-xs" onclick={copyDetailMessage}>
                <Icons name="copy" size={12} />
                <span>{copyMsgLabel}</span>
              </button>
              <button
                type="button"
                class="btn btn-xs btn-danger"
                disabled={busy === `del-${detailItem.id}`}
                onclick={() => deleteItem(detailItem.id)}
              >
                <Icons name="trash" size={12} />
                <span>{t.delete}</span>
              </button>
            </div>
          </div>
          <pre class="inbox-detail-body">{detailItem.message}</pre>
        </div>
      {:else}
        <div class="inbox-filter-bar">
          <div class="btn-group" style="gap:6px;">
            <button
              type="button"
              class="chip inbox-filter-chip {filter === 'all' ? 'active' : ''}"
              aria-pressed={filter === 'all'}
              onclick={() => (filter = 'all')}
            >
              <span>{t.all}</span>
              <span class="num inbox-chip-num">{items.length}</span>
            </button>
            <button
              type="button"
              class="chip inbox-filter-chip {filter === 'unread' ? 'active' : ''}"
              aria-pressed={filter === 'unread'}
              onclick={() => (filter = 'unread')}
            >
              <span>{t.inbox.filterUnread}</span>
              <span class="num inbox-chip-num">{unreadCount}</span>
            </button>
            <button
              type="button"
              class="chip inbox-filter-chip {filter === 'alerts' ? 'active' : ''}"
              aria-pressed={filter === 'alerts'}
              onclick={() => (filter = 'alerts')}
            >
              <span>{t.inbox.filterAlerts}</span>
              <span class="num inbox-chip-num">{alertCount}</span>
            </button>
          </div>
          <span
            class="mono inbox-quota"
            title={`${t.inbox.quotaTip} (${formatKiB(storageBytes)} / ${formatKiB(maxStorageBytes)})`}
          >
            {items.length}/{capacity}
          </span>
        </div>

        {#if loading && !items.length}
          <div style="padding:6px;display:grid;gap:8px;">
            <div class="skeleton" style="height:56px;"></div>
            <div class="skeleton" style="height:56px;"></div>
            <div class="skeleton" style="height:56px;"></div>
          </div>
        {:else if !filteredItems.length}
          <div class="empty-state-rich inbox-empty">
            <span class="empty-state-icon"><Icons name="bell" size={20} /></span>
            <div class="empty-state-desc">
              {items.length ? t.common.noMatches : t.inbox.empty}
            </div>
            {#if items.length && filter !== 'all'}
              <button type="button" class="btn btn-xs" style="margin-top:8px;" onclick={() => (filter = 'all')}>
                {t.common?.clearFilters || (lang === 'en' ? 'Show all' : '查看全部')}
              </button>
            {/if}
          </div>
        {:else}
          <div class="inbox-list">
            {#each filteredItems as item (item.id)}
              <div class="activity-row inbox-row {item.read ? '' : 'unread'}">
                <span class="activity-dot {item.severity}"></span>
                <button
                  type="button"
                  class="inbox-row-main"
                  onclick={() => openDetail(item)}
                >
                  <div class="inbox-row-top">
                    <span class="inbox-row-title" class:is-unread={!item.read}>
                      {item.title}
                    </span>
                    <span class="inbox-row-time num">
                      {formatRelative(item.ts)}
                    </span>
                  </div>
                  <div class="inbox-row-msg">
                    <span class="inbox-row-mod">{moduleLabel(item.module)}</span>
                    <span>{item.message}</span>
                  </div>
                </button>
                <div class="inbox-row-actions">
                  <button
                    type="button"
                    class="btn btn-ghost btn-icon inbox-row-btn inbox-jump-btn"
                    aria-label={`${t.inbox.jumpTo} ${moduleLabel(item.module)}`}
                    title={`${t.inbox.jumpTo} ${moduleLabel(item.module)}`}
                    onclick={() => jumpToModule(item)}
                  >
                    <Icons name="arrow_right" size={14} />
                  </button>
                  <button
                    type="button"
                    class="btn btn-ghost btn-icon inbox-row-btn inbox-del-btn"
                    aria-label={`${t.delete} ${item.title}`}
                    title={t.delete}
                    disabled={busy === `del-${item.id}`}
                    onclick={() => deleteItem(item.id)}
                  >
                    <Icons name="x" size={14} />
                  </button>
                </div>
              </div>
            {/each}
          </div>
        {/if}
      {/if}
    </div>

    <!-- 底部操作栏 -->
    <div class="activity-tray-foot">
      {#if detailItem}
        <button type="button" class="btn btn-sm" onclick={() => (detailItem = null)}>
          <Icons name="arrow_left" size={13} />
          <span>{t.inbox.backToList}</span>
        </button>
        <button type="button" class="btn btn-sm btn-primary" onclick={() => jumpToModule(detailItem)}>
          <span>{t.inbox.jumpTo} {moduleLabel(detailItem.module)}</span>
          <Icons name="arrow_right" size={13} />
        </button>
      {:else}
        <div class="btn-group" style="gap:6px;">
          <button type="button" class="btn btn-sm btn-ghost" onclick={() => onOpenChannelSettings?.()}>
            <Icons name="settings" size={13} />
            <span>{t.inbox.channelSettingsBtn}</span>
          </button>
          {#if unreadCount > 0}
            <button
              type="button"
              class="btn btn-sm btn-soft"
              disabled={Boolean(busy)}
              onclick={() => markRead(null)}
            >
              <Icons name="check" size={13} />
              <span>{t.inbox.markAllRead}</span>
            </button>
          {/if}
        </div>
        <button type="button" class="btn btn-sm" onclick={() => onClose?.()}>{t.close}</button>
      {/if}
    </div>
  </div>
{/if}

<style>
  .inbox-head-actions {
    display: flex;
    align-items: center;
    gap: 4px;
    flex-shrink: 0;
  }
  .inbox-head-btn {
    min-width: 34px;
    min-height: 34px;
    padding: 0;
  }
  .inbox-filter-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 4px 4px 10px;
    flex-wrap: wrap;
  }
  .inbox-filter-chip {
    min-height: 30px;
    padding: 3px 11px;
    font-size: 12px;
  }
  .inbox-chip-num {
    font-size: 11px;
    opacity: 0.78;
  }
  .inbox-quota {
    font-size: 11px;
    color: var(--text-muted);
    white-space: nowrap;
  }
  .inbox-empty {
    margin: 6px;
    padding: 28px 16px;
  }
  .inbox-list {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .inbox-row {
    align-items: flex-start;
    position: relative;
  }
  .inbox-row.unread {
    box-shadow: inset 2.5px 0 0 0 var(--accent);
  }
  .inbox-row-main {
    border: none;
    background: transparent;
    padding: 0;
    text-align: left;
    min-width: 0;
    flex: 1;
    cursor: pointer;
    font-family: inherit;
    color: inherit;
  }
  .inbox-row-main:focus-visible {
    outline: none;
    border-radius: 8px;
    box-shadow: 0 0 0 2px var(--accent-soft);
  }
  .inbox-row-top {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 8px;
  }
  .inbox-row-title {
    font-size: 13.5px;
    font-weight: 500;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .inbox-row-title.is-unread {
    font-weight: 700;
  }
  .inbox-row-time {
    font-size: 11.5px;
    color: var(--text-muted);
    flex-shrink: 0;
  }
  .inbox-row-msg {
    font-size: 12px;
    color: var(--text-secondary);
    margin-top: 3px;
    line-height: 1.45;
    display: -webkit-box;
    -webkit-line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
    word-break: break-word;
  }
  .inbox-row-mod {
    display: inline-block;
    font-size: 11px;
    font-weight: 600;
    color: var(--text-primary);
    background: var(--bg-elevated);
    border: 1px solid var(--border-subtle);
    border-radius: 6px;
    padding: 0 5px;
    margin-right: 5px;
    vertical-align: baseline;
  }
  .inbox-row-actions {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-shrink: 0;
    margin-left: 2px;
  }
  .inbox-row-btn {
    min-width: 32px;
    min-height: 32px;
    padding: 0;
  }
  .inbox-jump-btn {
    color: var(--accent);
    background: color-mix(in srgb, var(--accent) 8%, transparent);
  }
  .inbox-jump-btn:hover:not(:disabled) {
    background: var(--accent-soft);
  }
  .inbox-del-btn {
    color: var(--text-muted);
  }
  .inbox-del-btn:hover:not(:disabled) {
    color: var(--danger);
    background: var(--danger-soft);
  }
  @media (max-width: 920px) {
    .inbox-expand-btn {
      display: none;
    }
    .inbox-head-btn {
      min-width: 40px;
      min-height: 40px;
    }
    .inbox-filter-chip {
      min-height: 38px;
      padding: 4px 12px;
      font-size: 12.5px;
    }
    .inbox-row-actions {
      gap: 8px;
    }
    .inbox-row-btn {
      min-width: 38px;
      min-height: 38px;
    }
  }
</style>
