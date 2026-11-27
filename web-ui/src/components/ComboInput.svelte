<script>
  import Icons from './Icons.svelte';
  import { splitCsv, joinCsv } from '../lib/helpers.js';

  let nextId = 0;

  let {
    id = undefined,
    value = $bindable(''),
    options = [],
    multiple = false,
    placeholder = '',
    disabled = false,
    mono = true,
    required = false,
    ariaLabel = undefined,
    style = '',
    onchange = undefined,
  } = $props();

  const uid = `vcombo-${++nextId}-${Math.random().toString(36).slice(2, 7)}`;

  let open = $state(false);
  let filtering = $state(false);
  let menuSearch = $state('');
  let activeIdx = $state(-1);
  let wrapEl = $state(null);
  let inputEl = $state(null);
  let menuEl = $state(null);
  let menuStyle = $state('');
  let openUp = $state(false);

  function isZh() {
    return typeof document !== 'undefined' && (document.documentElement.lang || '').toLowerCase().startsWith('zh');
  }

  let normalized = $derived(
    (options || []).map((opt) =>
      opt !== null && typeof opt === 'object'
        ? {
            value: String(opt.value ?? ''),
            label: String(opt.label ?? opt.value ?? ''),
            sub: String(opt.sub || ''),
          }
        : {
            value: String(opt ?? ''),
            label: String(opt ?? ''),
            sub: '',
          }
    )
  );

  let selectedSet = $derived(
    multiple ? new Set(splitCsv(value)) : new Set(value ? [String(value)] : [])
  );

  let filterKeyword = $derived.by(() => {
    if (multiple && menuSearch.trim()) return menuSearch.trim().toLowerCase();
    if (!filtering) return '';
    const raw = String(value || '');
    if (multiple) {
      const idx = raw.lastIndexOf(',');
      return (idx >= 0 ? raw.slice(idx + 1) : raw).trim().toLowerCase();
    }
    return raw.trim().toLowerCase();
  });

  let filteredOptions = $derived.by(() => {
    const q = filterKeyword;
    if (!q) return normalized;
    return normalized.filter(
      (o) =>
        o.value.toLowerCase().includes(q) ||
        o.label.toLowerCase().includes(q) ||
        o.sub.toLowerCase().includes(q)
    );
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

  function updatePosition() {
    if (!wrapEl) return;
    const rect = wrapEl.getBoundingClientRect();
    const { vw, vh, offsetTop, offsetLeft } = getViewport();
    const width = Math.min(Math.max(rect.width, 200), vw - 16);
    const left = Math.max(8 + offsetLeft, Math.min(rect.left, offsetLeft + vw - width - 8));
    const estH = Math.min(300, Math.max(64, filteredOptions.length * 42 + (multiple ? 52 : 16)));
    const topEdge = offsetTop + 10;
    const bottomEdge = offsetTop + vh - 10;
    const spaceBelow = bottomEdge - rect.bottom - 6;
    const spaceAbove = rect.top - topEdge - 6;

    if (spaceBelow >= estH || spaceBelow >= spaceAbove) {
      openUp = false;
      const maxH = Math.min(300, Math.max(120, spaceBelow));
      menuStyle = `top:${Math.round(rect.bottom + 6)}px;left:${Math.round(left)}px;width:${Math.round(width)}px;max-height:${Math.round(maxH)}px;`;
    } else {
      openUp = true;
      const maxH = Math.min(300, Math.max(120, spaceAbove));
      menuStyle = `bottom:${Math.round(window.innerHeight - rect.top + 6)}px;left:${Math.round(left)}px;width:${Math.round(width)}px;max-height:${Math.round(maxH)}px;`;
    }
  }

  function openMenu(withFilter = false) {
    if (disabled || normalized.length === 0) return;
    filtering = withFilter;
    if (!withFilter) menuSearch = '';
    activeIdx = -1;
    updatePosition();
    open = true;
    queueMicrotask(() => updatePosition());
  }

  function closeMenu(focusInput = false) {
    open = false;
    filtering = false;
    menuSearch = '';
    activeIdx = -1;
    if (focusInput) inputEl?.focus();
  }

  function toggleMenu() {
    if (open) {
      closeMenu(false);
    } else {
      openMenu(false);
      inputEl?.focus();
    }
  }

  function emitChange(nextVal) {
    onchange?.(nextVal);
    inputEl?.dispatchEvent(new Event('input', { bubbles: true }));
    inputEl?.dispatchEvent(new Event('change', { bubbles: true }));
  }

  function pickOption(opt) {
    if (!opt) return;
    if (multiple) {
      const list = splitCsv(value);
      const next = list.includes(opt.value)
        ? joinCsv(list.filter((x) => x !== opt.value))
        : joinCsv([...list, opt.value]);
      value = next;
      filtering = false;
      emitChange(next);
    } else {
      value = opt.value;
      closeMenu(true);
      emitChange(opt.value);
    }
  }

  function handleInput() {
    if (!disabled && normalized.length > 0) {
      filtering = true;
      if (!open) {
        updatePosition();
        open = true;
      }
      activeIdx = -1;
    }
  }

  function handleKeydown(e) {
    if (disabled || normalized.length === 0) return;
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (!open) {
        openMenu(false);
        activeIdx = 0;
      } else if (filteredOptions.length > 0) {
        activeIdx = (activeIdx + 1) % filteredOptions.length;
        scrollActiveIntoView();
      }
    } else if (e.key === 'ArrowUp' && open && filteredOptions.length > 0) {
      e.preventDefault();
      activeIdx = (activeIdx - 1 + filteredOptions.length) % filteredOptions.length;
      scrollActiveIntoView();
    } else if (e.key === 'Enter' && open && activeIdx >= 0 && filteredOptions[activeIdx]) {
      e.preventDefault();
      pickOption(filteredOptions[activeIdx]);
    } else if (e.key === 'Tab') {
      closeMenu(false);
    }
  }

  function scrollActiveIntoView() {
    if (!menuEl || activeIdx < 0) return;
    const el = menuEl.querySelector(`[data-opt-idx="${activeIdx}"]`);
    el?.scrollIntoView({ block: 'nearest' });
  }

  $effect(() => {
    if (!open) return;
    const onPointerDown = (e) => {
      if (wrapEl?.contains(e.target) || menuEl?.contains(e.target)) return;
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
      if (!wrapEl) return;
      const r = wrapEl.getBoundingClientRect();
      if (r.bottom < 0 || r.top > window.innerHeight) closeMenu(false);
      else updatePosition();
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

<div bind:this={wrapEl} class="vcombo-wrap" {style}>
  <input
    bind:this={inputEl}
    {id}
    type="text"
    role="combobox"
    aria-autocomplete="list"
    aria-expanded={open}
    aria-controls={open ? `${uid}-list` : undefined}
    aria-activedescendant={open && activeIdx >= 0 ? `${uid}-opt-${activeIdx}` : undefined}
    aria-label={ariaLabel}
    class="{mono ? 'mono' : ''} {normalized.length > 0 ? 'vcombo-has-toggle' : ''}"
    {placeholder}
    {disabled}
    {required}
    autocomplete="off"
    spellcheck="false"
    bind:value
    oninput={handleInput}
    onkeydown={handleKeydown}
  />
  {#if normalized.length > 0}
    <button
      type="button"
      class="vcombo-toggle {open ? 'open' : ''}"
      tabindex="-1"
      {disabled}
      aria-label={isZh() ? '展开或收起建议列表' : 'Toggle suggestions'}
      onclick={toggleMenu}
    >
      <Icons name="chevron" size={15} />
    </button>
  {/if}

  {#if open}
    <div
      use:portal
      bind:this={menuEl}
      id={`${uid}-list`}
      role="listbox"
      aria-multiselectable={multiple || undefined}
      class="vselect-menu {openUp ? 'up' : ''} {mono ? 'mono' : ''}"
      style={menuStyle}
    >
      {#if multiple && normalized.length > 6}
        <div class="vcombo-search-wrap">
          <input
            type="text"
            class="vcombo-search mono"
            placeholder={isZh() ? '筛选选项…' : 'Filter options...'}
            bind:value={menuSearch}
            onkeydown={(e) => {
              if (e.key === 'Escape') {
                e.stopPropagation();
                closeMenu(true);
              }
            }}
          />
        </div>
      {/if}
      {#if filteredOptions.length === 0}
        <div class="vcombo-empty">{isZh() ? '无匹配选项' : 'No matching options'}</div>
      {:else}
        {#each filteredOptions as opt, idx (opt.value)}
          {@const selected = selectedSet.has(opt.value)}
          <button
            type="button"
            id={`${uid}-opt-${idx}`}
            role="option"
            data-opt-idx={idx}
            aria-selected={selected}
            class="vselect-opt {selected ? 'selected' : ''} {idx === activeIdx ? 'active' : ''}"
            onmouseenter={() => (activeIdx = idx)}
            onpointerdown={(e) => e.preventDefault()}
            onclick={() => pickOption(opt)}
          >
            <span class="vselect-opt-main">
              <span class="vselect-opt-label">{opt.label}</span>
              {#if opt.sub}
                <span class="vselect-opt-sub">{opt.sub}</span>
              {/if}
            </span>
            {#if selected}
              <span class="vselect-opt-check">
                <Icons name="check" size={14} />
              </span>
            {/if}
          </button>
        {/each}
      {/if}
    </div>
  {/if}
</div>
