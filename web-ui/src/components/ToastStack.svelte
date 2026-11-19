<script>
  import Icons from './Icons.svelte';

  let { toasts = [], onDismiss } = $props();

  function iconName(type) {
    if (type === 'success') return 'check';
    if (type === 'error' || type === 'warn') return 'alert';
    return 'info';
  }
</script>

{#if toasts.length > 0}
  <div class="toast-stack" role="status" aria-live="polite">
    {#each toasts as item (item.id)}
      <div class="toast-item toast-{item.type || 'info'}">
        <span class="toast-icon">
          <Icons name={iconName(item.type)} size={16} />
        </span>
        <span class="toast-msg">{item.message}</span>
        <button
          type="button"
          class="toast-close"
          aria-label="Dismiss"
          onclick={() => onDismiss?.(item.id)}
        >
          <Icons name="x" size={14} />
        </button>
      </div>
    {/each}
  </div>
{/if}
