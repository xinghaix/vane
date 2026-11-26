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
    ariaLabel = undefined,
    title = undefined,
    style = '',
    onchange = undefined,
  } = $props();

  const uid = `vselect-${++nextId}-${Math.random().toString(36).slice(2, 7)}`;

  let open = $state(false);
  let activeIdx = $state(-1);
  let triggerEl = $state(null);
  let menuEl = $state(null);
  let menuStyle = $state('');
  let openUp = $state(false);

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

  function updatePosition() {
    if (!triggerEl) return;
    const rect = triggerEl.getBoundingClientRect();
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    const minW = Math.max(rect.width, 136);
    const width = Math.min(Math.max(minW, rect.width), vw - 16);
    const left = Math.max(8, Math.min(rect.left, vw - width - 8));
    const estH = Math.min(280, Math.max(52, normalized.length * 40 + 12));
    const spaceBelow = vh - rect.bottom - 12;
    const spaceAbove = rect.top - 12;

    if (spaceBelow >= estH || spaceBelow >= spaceAbove) {
      openUp = false;
      const maxH = Math.min(280, Math.max(110, spaceBelow));
      menuStyle = `top:${Math.round(rect.bottom + 6)}px;left:${Math.round(left)}px;width:${Math.round(width)}px;max-height:${Math.round(maxH)}px;`;
    } else {
      openUp = true;
      const maxH = Math.min(280, Math.max(110, spaceAbove));
      menuStyle = `bottom:${Math.round(vh - rect.top + 6)}px;left:${Math.round(left)}px;width:${Math.round(width)}px;max-height:${Math.round(maxH)}px;`;
    }
  }

  function findInitialIndex() {
    const idx = normalized.findIndex((o) => o.value === value && !o.disabled);
    if (idx >= 0) return idx;
    return normalized.findIndex((o) => !o.disabled);
  }

  function openMenu() {
    if (disabled || normalized.length === 0) return;
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
    if (!normalized.length) return;
    let idx = activeIdx;
    for (let step = 0; step < normalized.length; step++) {
      idx = (idx + delta + normalized.length) % normalized.length;
      if (!normalized[idx].disabled) {
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

  function handleTriggerKeydown(e) {
    if (disabled) return;
    if (!open) {
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp' || e.key === 'Enter' || e.key === ' ') {
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
      activeIdx = normalized.findIndex((o) => !o.disabled);
      scrollActiveIntoView();
    } else if (e.key === 'End') {
      e.preventDefault();
      for (let i = normalized.length - 1; i >= 0; i--) {
        if (!normalized[i].disabled) {
          activeIdx = i;
          scrollActiveIntoView();
          break;
        }
      }
    } else if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      if (activeIdx >= 0 && normalized[activeIdx]) {
        selectOption(normalized[activeIdx]);
      } else {
        closeMenu(true);
      }
    } else if (e.key === 'Tab') {
      closeMenu(false);
    }
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
    return () => {
      window.removeEventListener('pointerdown', onPointerDown, true);
      window.removeEventListener('keydown', onKeyDownCapture, true);
      window.removeEventListener('resize', onResize);
      window.removeEventListener('scroll', onScroll, true);
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
      aria-label={ariaLabel || 'Options'}
      class="vselect-menu {openUp ? 'up' : ''} {mono ? 'mono' : ''}"
      style={menuStyle}
    >
      {#each normalized as opt, idx (String(opt.value) + ':' + idx)}
        {@const isSelected = opt.value === value}
        {@const isActive = idx === activeIdx}
        <button
          type="button"
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
    </div>
  {/if}
</div>
