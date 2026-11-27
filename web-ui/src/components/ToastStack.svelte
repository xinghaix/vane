<script>
  import Icons from './Icons.svelte';

  let { toasts = [], onDismiss, onPause, onResume, dismissLabel = 'Dismiss' } = $props();

  function iconName(type) {
    if (type === 'success') return 'check_circle';
    if (type === 'error' || type === 'warn') return 'alert';
    return 'info';
  }
</script>

{#if toasts.length > 0}
  <div class="toast-stack" aria-live="polite">
    {#each toasts as item (item.id)}
      <div
        class="toast-item toast-{item.type || 'info'}"
        role={item.type === 'error' ? 'alert' : 'status'}
        aria-atomic="true"
        onmouseenter={() => onPause?.(item.id)}
        onmouseleave={() => onResume?.(item.id)}
        onfocusin={() => onPause?.(item.id)}
        onfocusout={() => onResume?.(item.id)}
      >
        <span class="toast-icon" aria-hidden="true">
          <Icons name={iconName(item.type)} size={17} />
        </span>
        <span class="toast-msg">{item.message}</span>
        <button
          type="button"
          class="toast-close"
          aria-label={dismissLabel}
          onclick={() => onDismiss?.(item.id)}
        >
          <Icons name="x" size={14} />
        </button>
      </div>
    {/each}
  </div>
{/if}
