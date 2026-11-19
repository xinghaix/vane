<script>
  import Icons from './Icons.svelte';

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

  function handleKeydown(e) {
    if (open && e.key === 'Escape' && !busy) {
      e.preventDefault();
      onCancel?.();
    }
  }
</script>

<svelte:window onkeydown={handleKeydown} />

{#if open}
  <div
    class="modal-backdrop"
    role="presentation"
    onclick={(e) => {
      if (e.target === e.currentTarget && !busy) onCancel?.();
    }}
  >
    <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="confirm-modal-title">
      <div style="display:flex;align-items:flex-start;gap:12px;margin-bottom:12px;">
        <div
          style="width:36px;height:36px;border-radius:10px;display:grid;place-items:center;flex-shrink:0;background:{danger
            ? 'var(--danger-soft)'
            : 'var(--warn-soft)'};color:{danger ? 'var(--danger)' : 'var(--warn)'};"
        >
          <Icons name="alert" size={18} />
        </div>
        <div style="min-width:0;flex:1;">
          <h3 id="confirm-modal-title" style="font-size:16px;font-weight:700;line-height:1.35;">{title}</h3>
          <p style="font-size:13px;color:var(--text-secondary);margin-top:6px;line-height:1.55;">{message}</p>
        </div>
      </div>

      <div style="display:flex;justify-content:flex-end;gap:10px;margin-top:18px;">
        <button type="button" class="btn btn-sm" disabled={busy} onclick={() => onCancel?.()}>
          {cancelLabel}
        </button>
        <button
          type="button"
          class="btn btn-sm {danger ? 'btn-danger' : 'btn-primary'}"
          disabled={busy}
          onclick={() => onConfirm?.()}
        >
          {busy ? '...' : confirmLabel}
        </button>
      </div>
    </div>
  </div>
{/if}
