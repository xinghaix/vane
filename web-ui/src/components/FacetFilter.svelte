<script>
  import Icons from './Icons.svelte';

  let nextFacetId = 0;

  let {
    label = '',
    value = $bindable('all'),
    options = [], // [{ value, label, count?, tone? }]
    placeholder = '',
    onchange = undefined,
  } = $props();

  const uid = `vfacet-${++nextFacetId}-${Math.random().toString(36).slice(2, 7)}`;

  let open = $state(false);
  let query = $state('');
  let activeIdx = $state(-1);
  let openUp = $state(false);
  let triggerEl = $state(null);
  let menuEl = $state(null);
  let searchEl = $state(null);
  let menuStyle = $state('');

  function isZh() {
    return typeof document !== 'undefined' && (document.documentElement.lang || '').toLowerCase().startsWith('zh');
  }

  let activeOpt = $derived((options || []).find((o) => o.value === value) || null);
  let defaultVal = $derived((options || []).some((o) => o.value === 'all') ? 'all' : '');
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

  function getViewport() {
    const vv = typeof window !== 'undefined' ? window.visualViewport : null;
    return {
      vw: vv?.width || window.innerWidth,
      vh: vv?.height || window.innerHeight,
      offsetTop: vv?.offsetTop || 0,
      offsetLeft: vv?.offsetLeft || 0,
    };
  }

  function updatePos() {
    if (!triggerEl) return;
    const rect = triggerEl.getBoundingClientRect();
    const { vw, vh, offsetTop, offsetLeft } = getViewport();
    const width = Math.max(204, Math.min(256, vw - 16));
    const left = Math.max(8 + offsetLeft, Math.min(rect.left, offsetLeft + vw - width - 8));
    const topEdge = offsetTop + 10;
    const bottomEdge = offsetTop + vh - 10;
    const spaceBelow = bottomEdge - rect.bottom - 6;
    const spaceAbove = rect.top - topEdge - 6;

    if (spaceBelow >= 210 || spaceBelow >= spaceAbove) {
      openUp = false;
      const maxH = Math.min(320, Math.max(130, spaceBelow));
      menuStyle = `top:${Math.round(rect.bottom + 6)}px;left:${Math.round(left)}px;width:${Math.round(width)}px;max-height:${Math.round(maxH)}px;`;
    } else {
      openUp = true;
      const maxH = Math.min(320, Math.max(130, spaceAbove));
      menuStyle = `bottom:${Math.round(window.innerHeight - rect.top + 6)}px;left:${Math.round(left)}px;width:${Math.round(width)}px;max-height:${Math.round(maxH)}px;`;
    }
  }

  function openMenu() {
    query = '';
    activeIdx = Math.max(0, (options || []).findIndex((o) => o.value === value));
    updatePos();
    open = true;
    queueMicrotask(() => {
      updatePos();
      if ((options || []).length > 4) {
        searchEl?.focus({ preventScroll: true });
      }
    });
  }

  function closeMenu(focusTrigger = false) {
    open = false;
    query = '';
    activeIdx = -1;
    if (focusTrigger) triggerEl?.focus();
  }

  function toggle() {
    if (open) closeMenu(false);
    else openMenu();
  }

  function pick(val) {
    value = val;
    closeMenu(true);
    onchange?.(val);
  }

  function moveActive(delta) {
    if (!filteredOpts.length) return;
    activeIdx = (activeIdx + delta + filteredOpts.length) % filteredOpts.length;
    const el = menuEl?.querySelector(`[data-facet-idx="${activeIdx}"]`);
    el?.scrollIntoView({ block: 'nearest' });
  }

  function handleKeydown(e) {
    if (!open) {
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault();
        openMenu();
      }
      return;
    }
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      moveActive(1);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      moveActive(-1);
    } else if (e.key === 'Home') {
      e.preventDefault();
      activeIdx = 0;
    } else if (e.key === 'End') {
      e.preventDefault();
      activeIdx = Math.max(0, filteredOpts.length - 1);
    } else if (e.key === 'Enter') {
      if (activeIdx >= 0 && filteredOpts[activeIdx]) {
        e.preventDefault();
        pick(filteredOpts[activeIdx].value);
      }
    } else if (e.key === 'Tab') {
      closeMenu(false);
    }
  }

  $effect(() => {
    if (!open) return;
    const onDown = (e) => {
      if (triggerEl?.contains(e.target) || menuEl?.contains(e.target)) return;
      closeMenu(false);
    };
    const onKey = (e) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        e.stopPropagation();
        closeMenu(true);
      }
    };
    const onScroll = (e) => {
      if (menuEl && (e.target === menuEl || menuEl.contains(e.target))) return;
      if (!triggerEl) return;
      const r = triggerEl.getBoundingClientRect();
      if (r.bottom < 0 || r.top > window.innerHeight) {
        closeMenu(false);
      } else {
        updatePos();
      }
    };
    window.addEventListener('pointerdown', onDown, true);
    window.addEventListener('keydown', onKey, true);
    window.addEventListener('resize', updatePos);
    window.addEventListener('scroll', onScroll, true);
    window.visualViewport?.addEventListener('resize', updatePos);
    window.visualViewport?.addEventListener('scroll', updatePos);
    return () => {
      window.removeEventListener('pointerdown', onDown, true);
      window.removeEventListener('keydown', onKey, true);
      window.removeEventListener('resize', updatePos);
      window.removeEventListener('scroll', onScroll, true);
      window.visualViewport?.removeEventListener('resize', updatePos);
      window.visualViewport?.removeEventListener('scroll', updatePos);
    };
  });
</script>

<button
  bind:this={triggerEl}
  type="button"
  class="facet-trigger {isFiltered ? 'active' : ''}"
  aria-expanded={open}
  aria-haspopup="listbox"
  aria-controls={open ? `${uid}-list` : undefined}
  onclick={toggle}
  onkeydown={handleKeydown}
>
  <Icons name="filter" size={13} />
  <span>{label}</span>
  {#if isFiltered && activeOpt}
    <span class="facet-sep"></span>
    <span class="facet-val">{activeOpt.label}</span>
  {/if}
</button>

{#if open}
  <div
    use:portal
    bind:this={menuEl}
    id={`${uid}-list`}
    class="facet-menu {openUp ? 'up' : ''}"
    role="listbox"
    aria-label={label}
    style={menuStyle}
  >
    {#if (options || []).length > 4}
      <div class="facet-search-box">
        <Icons name="search" size={14} />
        <input
          bind:this={searchEl}
          type="text"
          placeholder={placeholder || label}
          bind:value={query}
          oninput={() => (activeIdx = 0)}
          onkeydown={handleKeydown}
        />
      </div>
    {/if}
    <div class="facet-options">
      {#if filteredOpts.length === 0}
        <div class="vcombo-empty">{isZh() ? '无匹配选项' : 'No matching options'}</div>
      {:else}
        {#each filteredOpts as opt, idx (opt.value)}
          {@const picked = opt.value === value}
          <button
            type="button"
            role="option"
            data-facet-idx={idx}
            aria-selected={picked}
            class="facet-opt {picked ? 'selected' : ''} {idx === activeIdx ? 'active' : ''}"
            onmouseenter={() => (activeIdx = idx)}
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
      {/if}
    </div>
    {#if isFiltered}
      <div class="facet-footer">
        <button type="button" class="facet-reset-btn" onclick={() => pick(defaultVal)}>
          <Icons name="x" size={12} />
          <span>{isZh() ? '重置筛选' : 'Clear filter'}</span>
        </button>
      </div>
    {/if}
  </div>
{/if}
