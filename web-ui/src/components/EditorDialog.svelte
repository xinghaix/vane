<script>
  import Icons from './Icons.svelte';
  import { registerOverlay } from '../lib/overlay.js';

  let {
    open = false,
    title = '',
    size = 'md', // 'sm' | 'md' | 'lg'
    busy = false,
    dirty = false,
    form = true,
    confirmDiscard = true,
    submitLabel = '',
    cancelLabel = '',
    closeLabel = '',
    t,
    askConfirm = null,
    onSubmit = null,
    onClose,
    children,
    footer = null,
  } = $props();

  let internalDirty = $state(false);
  let effectiveDirty = $derived(confirmDiscard && Boolean(dirty || internalDirty));

  $effect(() => {
    if (!open) {
      internalDirty = false;
      return;
    }
    internalDirty = false;
    return registerOverlay({
      onDismiss: () => requestClose(),
    });
  });

  function forceClose() {
    internalDirty = false;
    onClose?.();
  }

  function requestClose() {
    if (busy) return;
    if (effectiveDirty && askConfirm) {
      askConfirm({
        title: t?.common?.discardConfirmTitle || 'Discard unsaved changes?',
        message: t?.common?.discardConfirmDesc || 'Unsaved edits will be lost.',
        confirmLabel: t?.common?.discardConfirmBtn || 'Discard',
        danger: true,
        onConfirm: () => {
          forceClose();
        },
      });
      return;
    }
    forceClose();
  }

  function markDirtyFromInput() {
    if (confirmDiscard) internalDirty = true;
  }

  function handleBodyClick(e) {
    if (!confirmDiscard) return;
    const target = e.target;
    if (target && typeof target.closest === 'function') {
      if (target.closest('button.chip, button[data-dirty]')) {
        internalDirty = true;
      }
    }
  }

  function handleSubmit(e) {
    e.preventDefault();
    onSubmit?.(e);
  }
</script>

{#if open}
  <div
    class="editor-backdrop"
    role="presentation"
    onclick={(e) => {
      if (e.target === e.currentTarget) requestClose();
    }}
  >
    <div
      class="editor-panel editor-size-{size}"
      role="dialog"
      aria-modal="true"
      aria-label={title}
      oninput={markDirtyFromInput}
      onchange={markDirtyFromInput}
    >
      {#if form}
        <form style="display:contents;" onsubmit={handleSubmit}>
          <div class="editor-header">
            <div class="editor-header-left">
              <button
                type="button"
                class="btn btn-ghost btn-sm editor-back-btn"
                disabled={busy}
                aria-label={t?.common?.back || 'Back'}
                onclick={requestClose}
              >
                <Icons name="arrow_left" size={18} />
              </button>
              <div class="card-title" style="min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                {title}
              </div>
              {#if effectiveDirty}
                <span class="badge badge-warn" style="font-size:10.5px;">{t?.common?.unsavedDot || 'Unsaved'}</span>
              {/if}
            </div>
            <button
              type="button"
              class="btn btn-ghost btn-sm editor-close-btn"
              disabled={busy}
              aria-label={closeLabel || t?.close || 'Close'}
              onclick={requestClose}
            >
              <Icons name="x" size={16} />
            </button>
          </div>

          <div class="editor-body" role="presentation" onclick={handleBodyClick}>
            {@render children?.()}
          </div>

          <div class="editor-footer">
            {#if footer}
              {@render footer({ requestClose, busy })}
            {:else}
              <button type="button" class="btn" disabled={busy} onclick={requestClose}>
                {cancelLabel || t?.cancel || 'Cancel'}
              </button>
              <button type="submit" class="btn btn-primary" disabled={busy}>
                {busy ? '...' : (submitLabel || t?.confirm || 'Save')}
              </button>
            {/if}
          </div>
        </form>
      {:else}
        <div class="editor-header">
          <div class="editor-header-left">
            <button
              type="button"
              class="btn btn-ghost btn-sm editor-back-btn"
              disabled={busy}
              aria-label={t?.common?.back || 'Back'}
              onclick={requestClose}
            >
              <Icons name="arrow_left" size={18} />
            </button>
            <div class="card-title" style="min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
              {title}
            </div>
          </div>
          <button
            type="button"
            class="btn btn-ghost btn-sm editor-close-btn"
            disabled={busy}
            aria-label={closeLabel || t?.close || 'Close'}
            onclick={requestClose}
          >
            <Icons name="x" size={16} />
          </button>
        </div>

        <div class="editor-body">
          {@render children?.()}
        </div>

        {#if footer}
          <div class="editor-footer">
            {@render footer({ requestClose, busy })}
          </div>
        {/if}
      {/if}
    </div>
  </div>
{/if}
