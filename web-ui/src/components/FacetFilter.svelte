<script>
  import Icons from './Icons.svelte';

  let {
    label = '',
    value = $bindable('all'),
    options = [], // [{ value, label, count?, tone? }]
    placeholder = '',
    onchange = undefined,
  } = $props();

  let open = $state(false);
  let query = $state('');
  let triggerEl = $state(null);
  let menuEl = $state(null);
  let menuStyle = $state('');

  let activeOpt = $derived((options || []).find((o) => o.value === value) || null);
  let isFiltered = $derived(value !== '' && value !== 'all');
  let filteredOpts = $derived.by(() => {
    const q = query.trim().toLowerCase();
    if (!q) return options || [];
    return (options || []).filter((o) => String(o.label || '').toLowerCase().includes(q));
  });

  function portal(node) {
    document.body.appendChild(node);
    return {
      destroy() {
        node.remove();
      },
    };
  }

  function updatePos() {
    if (!triggerEl) return;
    const rect = triggerEl.getBoundingClientRect();
    const width = Math.max(200, Math.min(248, window.innerWidth - 16));
    const left = Math.max(8, Math.min(rect.left, window.innerWidth - width - 8));
    const spaceBelow = window.innerHeight - rect.bottom - 12;
    if (spaceBelow >= 200 || spaceBelow >= rect.top) {
      menuStyle = `top:${Math.round(rect.bottom + 6)}px;left:${Math.round(left)}px;width:${Math.round(width)}px;`;
    } else {
      menuStyle = `bottom:${Math.round(window.innerHeight - rect.top + 6)}px;left:${Math.round(left)}px;width:${Math.round(width)}px;`;
    }
  }

  function toggle() {
    if (open) {
      open = false;
      query = '';
    } else {
      query = '';
      updatePos();
      open = true;
      queueMicrotask(updatePos);
    }
  }

  function pick(val) {
    value = val;
    open = false;
    query = '';
    onchange?.(val);
  }

  $effect(() => {
    if (!open) return;
    const onDown = (e) => {
      if (triggerEl?.contains(e.target) || menuEl?.contains(e.target)) return;
      open = false;
    };
    const onKey = (e) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        open = false;
      }
    };
    window.addEventListener('pointerdown', onDown, true);
    window.addEventListener('keydown', onKey, true);
    window.addEventListener('resize', updatePos);
    return () => {
      window.removeEventListener('pointerdown', onDown, true);
      window.removeEventListener('keydown', onKey, true);
      window.removeEventListener('resize', updatePos);
    };
  });
</script>

<button
  bind:this={triggerEl}
  type="button"
  class="facet-trigger {isFiltered ? 'active' : ''}"
  aria-expanded={open}
  aria-haspopup="listbox"
  onclick={toggle}
>
  <Icons name="filter" size={13} />
  <span>{label}</span>
  {#if isFiltered && activeOpt}
    <span class="facet-sep"></span>
    <span class="facet-val">{activeOpt.label}</span>
  {/if}
</button>

{#if open}
  <div use:portal bind:this={menuEl} class="facet-menu" role="listbox" style={menuStyle}>
    {#if (options || []).length > 4}
      <div class="facet-search-box">
        <Icons name="search" size={14} />
        <input type="text" placeholder={placeholder || label} bind:value={query} />
      </div>
    {/if}
    <div class="facet-options">
      {#each filteredOpts as opt (opt.value)}
        {@const picked = opt.value === value}
        <button
          type="button"
          role="option"
          aria-selected={picked}
          class="facet-opt {picked ? 'selected' : ''}"
          onclick={() => pick(opt.value)}
        >
          <span class="facet-radio {picked ? 'checked' : ''}">
            {#if picked}<span class="facet-radio-dot"></span>{/if}
          </span>
          {#if opt.tone}
            <span class="status-dot {opt.tone}" style="width:7px;height:7px;"></span>
          {/if}
          <span class="facet-opt-label">{opt.label}</span>
          {#if typeof opt.count === 'number'}
            <span class="facet-opt-count num">{opt.count}</span>
          {/if}
        </button>
      {/each}
    </div>
  </div>
{/if}
