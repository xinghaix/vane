<script>
  import Icons from './Icons.svelte';
  import { registerOverlay } from '../lib/overlay.js';
  import { formatUnixTime } from '../lib/helpers.js';

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

  let filteredItems = $derived.by(() => {
    if (filter === 'unread') return items.filter((m) => !m.read);
    if (filter === 'alerts') return items.filter((m) => ['warning', 'error', 'critical'].includes(m.severity));
    return items;
  });

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
            class="btn btn-ghost btn-xs"
            style="padding:0 6px;margin-left:-4px;"
            aria-label={t.inbox.backToList}
            onclick={() => (detailItem = null)}
          >
            <Icons name="arrow_left" size={16} />
          </button>
          <span style="font-size:14.5px;font-weight:700;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
            {t.inbox.detailTitle}
          </span>
        {:else}
          <span style="font-size:15px;font-weight:700;">{t.inbox.title}</span>
          {#if unreadCount > 0}
            <span class="badge badge-info num" style="font-size:11px;padding:1px 8px;">
              {unreadCount} {t.inbox.unreadUnit}
            </span>
          {/if}
        {/if}
      </div>

      <div style="display:flex;align-items:center;gap:4px;">
        {#if !detailItem}
          <button type="button" class="btn btn-ghost btn-xs" style="padding:0 6px;" title={t.refresh} disabled={loading} onclick={() => loadInbox(false)}>
            <Icons name="refresh" size={14} />
          </button>
          {#if unreadCount > 0}
            <button type="button" class="btn btn-ghost btn-xs" style="padding:0 7px;" title={t.inbox.markAllRead} disabled={Boolean(busy)} onclick={() => markRead(null)}>
              <Icons name="check" size={14} />
            </button>
          {/if}
          {#if items.length > 0}
            <button type="button" class="btn btn-ghost btn-xs" style="padding:0 6px;color:var(--danger);" title={t.inbox.clearAll} disabled={Boolean(busy)} onclick={confirmClearAll}>
              <Icons name="trash" size={14} />
            </button>
          {/if}
        {/if}
        <button
          type="button"
          class="btn btn-ghost btn-xs"
          style="padding:0 6px;"
          title={expanded ? t.close : 'Expand'}
          onclick={() => (expanded = !expanded)}
        >
          <Icons name="expand" size={14} />
        </button>
        <button type="button" class="btn btn-ghost btn-xs" style="padding:0 6px;" aria-label={t.close} onclick={() => onClose?.()}>
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
            <span class="badge badge-muted mono">{t.events?.[detailItem.event] || detailItem.event}</span>
          </div>
          <div style="font-size:15.5px;font-weight:700;line-height:1.4;word-break:break-word;">
            {detailItem.title}
          </div>
          <div class="mono" style="font-size:11.5px;color:var(--text-muted);">
            {formatUnixTime(detailItem.ts)}
          </div>
          <pre class="inbox-detail-body">{detailItem.message}</pre>
        </div>
      {:else}
        <div class="row-between" style="gap:6px;padding:4px 4px 10px;">
          <div class="btn-group" style="gap:5px;">
            <button type="button" class="chip {filter === 'all' ? 'active' : ''}" style="min-height:27px;padding:2px 10px;font-size:12px;" onclick={() => (filter = 'all')}>
              {t.all} ({items.length})
            </button>
            <button type="button" class="chip {filter === 'unread' ? 'active' : ''}" style="min-height:27px;padding:2px 10px;font-size:12px;" onclick={() => (filter = 'unread')}>
              {t.inbox.filterUnread} ({unreadCount})
            </button>
            <button type="button" class="chip {filter === 'alerts' ? 'active' : ''}" style="min-height:27px;padding:2px 10px;font-size:12px;" onclick={() => (filter = 'alerts')}>
              {t.inbox.filterAlerts}
            </button>
          </div>
          <span class="mono" style="font-size:11px;color:var(--text-muted);" title={t.inbox.quotaTip}>
            {items.length}/{capacity}
          </span>
        </div>

        {#if loading && !items.length}
          <div style="padding:6px;display:grid;gap:8px;">
            <div class="skeleton" style="height:48px;"></div>
            <div class="skeleton" style="height:48px;"></div>
          </div>
        {:else if !filteredItems.length}
          <div class="empty-state" style="margin:6px;padding:32px 16px;">
            {items.length ? t.common.noMatches : t.inbox.empty}
          </div>
        {:else}
          <div style="display:flex;flex-direction:column;gap:2px;">
            {#each filteredItems as item (item.id)}
              <div class="activity-row {item.read ? '' : 'unread'}">
                <span class="activity-dot {item.severity}"></span>
                <button
                  type="button"
                  style="border:none;background:transparent;padding:0;text-align:left;min-width:0;flex:1;cursor:pointer;font-family:inherit;color:inherit;"
                  onclick={() => openDetail(item)}
                >
                  <div style="display:flex;align-items:baseline;justify-content:space-between;gap:8px;">
                    <span style="font-size:13.5px;font-weight:{item.read ? '500' : '700'};overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                      {item.title}
                    </span>
                    <span style="font-size:11.5px;color:var(--text-muted);flex-shrink:0;" class="num">
                      {formatRelative(item.ts)}
                    </span>
                  </div>
                  <div style="font-size:12px;color:var(--text-secondary);margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                    {moduleLabel(item.module)} · {item.message}
                  </div>
                </button>
                <div style="display:flex;align-items:center;gap:2px;flex-shrink:0;">
                  <button
                    type="button"
                    class="btn btn-ghost btn-xs"
                    style="padding:0 6px;color:var(--accent);"
                    title={`${t.inbox.jumpTo} ${moduleLabel(item.module)}`}
                    onclick={() => jumpToModule(item)}
                  >
                    <Icons name="arrow_right" size={13} />
                  </button>
                  <button
                    type="button"
                    class="btn btn-ghost btn-xs"
                    style="padding:0 5px;color:var(--text-muted);"
                    aria-label={t.delete}
                    disabled={busy === `del-${item.id}`}
                    onclick={() => deleteItem(item.id)}
                  >
                    <Icons name="x" size={13} />
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
        <button type="button" class="btn btn-xs" onclick={() => (detailItem = null)}>
          <Icons name="arrow_left" size={13} />
          <span>{t.inbox.backToList}</span>
        </button>
        <button type="button" class="btn btn-xs btn-primary" onclick={() => jumpToModule(detailItem)}>
          <span>{t.inbox.jumpTo} {moduleLabel(detailItem.module)}</span>
          <Icons name="arrow_right" size={13} />
        </button>
      {:else}
        <button type="button" class="btn btn-xs btn-ghost" onclick={() => onOpenChannelSettings?.()}>
          <Icons name="settings" size={13} />
          <span>{t.inbox.channelSettingsBtn}</span>
        </button>
        <button type="button" class="btn btn-xs" onclick={() => onClose?.()}>{t.close}</button>
      {/if}
    </div>
  </div>
{/if}
