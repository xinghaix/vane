<script>
  import Icons from './Icons.svelte';

  let nextId = 0;

  let {
    id = undefined,
    value = $bindable(),
    options = [],
    placeholder = '',
    disabled = false,
    compact = false,
    mono = false,
    required = false,
    searchable = null, // null = auto when >= 16 options; true/false = explicit
    searchPlaceholder = '',
    ariaLabel = undefined,
    title = undefined,
    style = '',
    onchange = undefined,
  } = $props();

  const uid = `vselect-${++nextId}-${Math.random().toString(36).slice(2, 7)}`;

  let open = $state(false);
  let activeIdx = $state(-1);
  let query = $state('');
  let triggerEl = $state(null);
  let menuEl = $state(null);
  let searchEl = $state(null);
  let menuStyle = $state('');
  let openUp = $state(false);

  function isZh() {
    return typeof document !== 'undefined' && (document.documentElement.lang || '').toLowerCase().startsWith('zh');
  }

  let normalized = $derived(
    (options || []).map((opt) =>
      opt !== null && typeof opt === 'object'
        ? {
            value: opt.value,
            label: opt.label ?? String(opt.value ?? ''),
            sub: opt.sub || '',
            disabled: Boolean(opt.disabled),
          }
        : {
            value: opt,
            label: String(opt ?? ''),
            sub: '',
            disabled: false,
          }
    )
  );

  let showSearch = $derived(searchable === null ? normalized.length >= 16 : Boolean(searchable));

  let visibleOptions = $derived.by(() => {
    const q = query.trim().toLowerCase();
    if (!showSearch || !q) return normalized;
    return normalized.filter(
      (o) =>
        String(o.label).toLowerCase().includes(q) ||
        String(o.value ?? '').toLowerCase().includes(q) ||
        String(o.sub).toLowerCase().includes(q)
    );
  });

  let selectedOption = $derived(normalized.find((o) => o.value === value) || null);
  let displayLabel = $derived(
    selectedOption ? selectedOption.label : placeholder || (value !== undefined && value !== null && value !== '' ? String(value) : '—')
  );

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

  function updatePosition() {
    if (!triggerEl) return;
    const rect = triggerEl.getBoundingClientRect();
    const { vw, vh, offsetTop, offsetLeft } = getViewport();
    const minW = Math.max(rect.width, 144);
    const width = Math.min(Math.max(minW, rect.width), vw - 16);
    const left = Math.max(8 + offsetLeft, Math.min(rect.left, offsetLeft + vw - width - 8));
    const estH = Math.min(296, Math.max(52, visibleOptions.length * 40 + (showSearch ? 52 : 12)));
    const topEdge = offsetTop + 10;
    const bottomEdge = offsetTop + vh - 10;
    const spaceBelow = bottomEdge - rect.bottom - 6;
    const spaceAbove = rect.top - topEdge - 6;

    if (spaceBelow >= estH || spaceBelow >= spaceAbove) {
      openUp = false;
      const maxH = Math.min(296, Math.max(120, spaceBelow));
      menuStyle = `top:${Math.round(rect.bottom + 6)}px;left:${Math.round(left)}px;width:${Math.round(width)}px;max-height:${Math.round(maxH)}px;`;
    } else {
      openUp = true;
      const maxH = Math.min(296, Math.max(120, spaceAbove));
      menuStyle = `bottom:${Math.round(window.innerHeight - rect.top + 6)}px;left:${Math.round(left)}px;width:${Math.round(width)}px;max-height:${Math.round(maxH)}px;`;
    }
  }

  function findInitialIndex() {
    const idx = visibleOptions.findIndex((o) => o.value === value && !o.disabled);
    if (idx >= 0) return idx;
    return visibleOptions.findIndex((o) => !o.disabled);
  }

  function openMenu() {
    if (disabled || normalized.length === 0) return;
    query = '';
    activeIdx = findInitialIndex();
    updatePosition();
    open = true;
    queueMicrotask(() => {
      updatePosition();
      scrollActiveIntoView();
    });
  }

  function closeMenu(focusTrigger = false) {
    open = false;
    query = '';
    activeIdx = -1;
    if (focusTrigger) triggerEl?.focus();
  }

  function toggleMenu() {
    if (open) closeMenu(false);
    else openMenu();
  }

  function selectOption(opt) {
    if (!opt || opt.disabled) return;
    const changed = value !== opt.value;
    value = opt.value;
    closeMenu(true);
    if (changed) {
      onchange?.(opt.value);
      triggerEl?.dispatchEvent(new Event('change', { bubbles: true }));
    }
  }

  function moveActive(delta) {
    if (!visibleOptions.length) return;
    let idx = activeIdx;
    for (let step = 0; step < visibleOptions.length; step++) {
      idx = (idx + delta + visibleOptions.length) % visibleOptions.length;
      if (!visibleOptions[idx].disabled) {
        activeIdx = idx;
        scrollActiveIntoView();
        return;
      }
    }
  }

  function scrollActiveIntoView() {
    if (!menuEl || activeIdx < 0) return;
    const el = menuEl.querySelector(`[data-opt-idx="${activeIdx}"]`);
    el?.scrollIntoView({ block: 'nearest' });
  }

  function handleMenuKeydown(e) {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      moveActive(1);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      moveActive(-1);
    } else if (e.key === 'Home') {
      e.preventDefault();
      activeIdx = visibleOptions.findIndex((o) => !o.disabled);
      scrollActiveIntoView();
    } else if (e.key === 'End') {
      e.preventDefault();
      for (let i = visibleOptions.length - 1; i >= 0; i--) {
        if (!visibleOptions[i].disabled) {
          activeIdx = i;
          scrollActiveIntoView();
          break;
        }
      }
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (activeIdx >= 0 && visibleOptions[activeIdx]) {
        selectOption(visibleOptions[activeIdx]);
      } else {
        closeMenu(true);
      }
    } else if (e.key === 'Tab') {
      closeMenu(false);
    }
  }

  function handleTriggerKeydown(e) {
    if (disabled) return;
    if (!open) {
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp' || e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        openMenu();
      }
      return;
    }
    if (e.key === ' ') {
      e.preventDefault();
      if (activeIdx >= 0 && visibleOptions[activeIdx]) {
        selectOption(visibleOptions[activeIdx]);
      } else {
        closeMenu(true);
      }
      return;
    }
    handleMenuKeydown(e);
  }

  $effect(() => {
    if (!open) return;
    const onPointerDown = (e) => {
      if (triggerEl?.contains(e.target) || menuEl?.contains(e.target)) return;
      closeMenu(false);
    };
    const onKeyDownCapture = (e) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        e.stopPropagation();
        closeMenu(true);
      }
    };
    const onResize = () => updatePosition();
    const onScroll = (e) => {
      if (menuEl && (e.target === menuEl || menuEl.contains(e.target))) return;
      if (!triggerEl) return;
      const r = triggerEl.getBoundingClientRect();
      if (r.bottom < 0 || r.top > window.innerHeight) {
        closeMenu(false);
      } else {
        updatePosition();
      }
    };
    window.addEventListener('pointerdown', onPointerDown, true);
    window.addEventListener('keydown', onKeyDownCapture, true);
    window.addEventListener('resize', onResize);
    window.addEventListener('scroll', onScroll, true);
    window.visualViewport?.addEventListener('resize', onResize);
    window.visualViewport?.addEventListener('scroll', onResize);
    return () => {
      window.removeEventListener('pointerdown', onPointerDown, true);
      window.removeEventListener('keydown', onKeyDownCapture, true);
      window.removeEventListener('resize', onResize);
      window.removeEventListener('scroll', onScroll, true);
      window.visualViewport?.removeEventListener('resize', onResize);
      window.visualViewport?.removeEventListener('scroll', onResize);
    };
  });
</script>

<div class="vselect-wrap" style={style}>
  {#if required && !disabled}
    <input
      type="text"
      class="vselect-native-req"
      tabindex="-1"
      aria-hidden="true"
      required
      value={value === undefined || value === null ? '' : String(value)}
      onfocus={() => triggerEl?.focus()}
    />
  {/if}
  <button
    bind:this={triggerEl}
    {id}
    type="button"
    role="combobox"
    aria-haspopup="listbox"
    aria-expanded={open}
    aria-controls={open ? `${uid}-list` : undefined}
    aria-activedescendant={open && activeIdx >= 0 ? `${uid}-opt-${activeIdx}` : undefined}
    aria-label={ariaLabel}
    {title}
    {disabled}
    class="vselect-trigger {compact ? 'compact' : ''} {mono ? 'mono' : ''} {open ? 'open' : ''}"
    onclick={toggleMenu}
    onkeydown={handleTriggerKeydown}
  >
    <span class="vselect-value {!selectedOption && placeholder ? 'placeholder' : ''}">{displayLabel}</span>
    <span class="vselect-caret {open ? 'open' : ''}">
      <Icons name="chevron" size={15} />
    </span>
  </button>

  {#if open}
    <div
      use:portal
      bind:this={menuEl}
      id={`${uid}-list`}
      role="listbox"
      aria-label={ariaLabel || (isZh() ? '选项列表' : 'Options')}
      class="vselect-menu {openUp ? 'up' : ''} {mono ? 'mono' : ''}"
      style={menuStyle}
    >
      {#if showSearch}
        <div class="vcombo-search-wrap">
          <input
            bind:this={searchEl}
            type="text"
            class="vcombo-search"
            placeholder={searchPlaceholder || (isZh() ? '筛选选项…' : 'Filter options...')}
            bind:value={query}
            oninput={() => {
              activeIdx = visibleOptions.findIndex((o) => !o.disabled);
            }}
            onkeydown={handleMenuKeydown}
          />
        </div>
      {/if}
      {#if visibleOptions.length === 0}
        <div class="vcombo-empty">{isZh() ? '无匹配选项' : 'No matching options'}</div>
      {:else}
        {#each visibleOptions as opt, idx (String(opt.value) + ':' + idx)}
          {@const isSelected = opt.value === value}
          {@const isActive = idx === activeIdx}
          <button
            type="button"
            id={`${uid}-opt-${idx}`}
            role="option"
            aria-selected={isSelected}
            data-opt-idx={idx}
            disabled={opt.disabled}
            class="vselect-opt {isSelected ? 'selected' : ''} {isActive ? 'active' : ''}"
            onmouseenter={() => (activeIdx = idx)}
            onclick={() => selectOption(opt)}
          >
            <span class="vselect-opt-text">
              <span class="vselect-opt-label">{opt.label}</span>
              {#if opt.sub}
                <span class="vselect-opt-sub">{opt.sub}</span>
              {/if}
            </span>
            {#if isSelected}
              <span class="vselect-check">
                <Icons name="check" size={14} />
              </span>
            {/if}
          </button>
        {/each}
      {/if}
    </div>
  {/if}
</div>
