<script>
  import Icons from './Icons.svelte';
  import { registerOverlay } from '../lib/overlay.js';

  let {
    open = false,
    title = '',
    message = '',
    confirmLabel = 'Confirm',
    cancelLabel = 'Cancel',
    danger = true,
    busy = false,
    onConfirm,
    onCancel,
  } = $props();

  let cardEl = $state(null);
  let cancelBtnEl = $state(null);
  let confirmBtnEl = $state(null);

  $effect(() => {
    if (!open) return;
    return registerOverlay({
      onDismiss: () => {
        if (!busy) onCancel?.();
      },
      trapContainer: () => cardEl,
      initialFocus: () => (danger ? cancelBtnEl : confirmBtnEl),
    });
  });
</script>

{#if open}
  <div
    class="modal-backdrop"
    role="presentation"
    onclick={(e) => {
      if (e.target === e.currentTarget && !busy) onCancel?.();
    }}
  >
    <div
      bind:this={cardEl}
      class="modal-card"
      role="dialog"
      aria-modal="true"
      aria-labelledby="confirm-modal-title"
      aria-describedby="confirm-modal-desc"
      tabindex="-1"
    >
      <div style="display:flex;align-items:flex-start;gap:13px;margin-bottom:14px;">
        <div class="icon-tile {danger ? 'danger' : 'warn'}" style="width:38px;height:38px;border-radius:12px;">
          <Icons name="alert" size={18} />
        </div>
        <div style="min-width:0;flex:1;">
          <h3 id="confirm-modal-title" style="font-size:16px;font-weight:700;line-height:1.35;">{title}</h3>
          <p id="confirm-modal-desc" style="font-size:13px;color:var(--text-secondary);margin-top:6px;line-height:1.55;white-space:pre-line;word-break:break-word;">
            {message}
          </p>
        </div>
      </div>

      <div class="modal-actions">
        <button bind:this={cancelBtnEl} type="button" class="btn btn-sm" disabled={busy} onclick={() => onCancel?.()}>
          {cancelLabel}
        </button>
        <button
          bind:this={confirmBtnEl}
          type="button"
          class="btn btn-sm {danger ? 'btn-danger' : 'btn-primary'}"
          disabled={busy}
          onclick={() => onConfirm?.()}
        >
          {#if busy}
            <Icons name="loader" size={14} class="is-spinning" />
          {/if}
          <span>{confirmLabel}</span>
        </button>
      </div>
    </div>
  </div>
{/if}
