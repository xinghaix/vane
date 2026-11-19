<script>
  import Icons from './Icons.svelte';
  import { isSecretConfigured, secretMaskedHint } from '../lib/helpers.js';

  let {
    id,
    label,
    original = null,
    value = $bindable(''),
    clear = $bindable(false),
    placeholder = '',
    required = false,
    t,
  } = $props();

  let reveal = $state(false);
  let configured = $derived(isSecretConfigured(original));
  let hint = $derived(
    clear
      ? t.common.secretClearedHint
      : configured
        ? t.common.secretConfigured
        : t.common.secretEmpty
  );
  let effectivePlaceholder = $derived(
    clear
      ? '—'
      : configured
        ? secretMaskedHint(original, placeholder)
        : placeholder
  );
</script>

<div class="field">
  <div class="row-between" style="gap:6px;">
    <label for={id}>{label}</label>
    {#if configured && !required}
      <button
        type="button"
        class="btn btn-xs {clear ? '' : 'btn-ghost'}"
        style="min-height:24px;font-size:11.5px;color:{clear ? 'var(--info)' : 'var(--danger)'};"
        onclick={() => {
          clear = !clear;
          if (clear) value = '';
        }}
      >
        <Icons name={clear ? 'x' : 'trash'} size={12} />
        <span>{clear ? t.common.undoClear : t.common.clearSecret}</span>
      </button>
    {/if}
  </div>
  <div style="position:relative;display:flex;align-items:center;">
    <input
      {id}
      type={reveal ? 'text' : 'password'}
      class="mono"
      style="padding-right:40px;"
      placeholder={effectivePlaceholder}
      disabled={clear}
      required={required && !configured}
      value={value}
      oninput={(e) => {
        value = e.currentTarget.value;
        if (value.length > 0 && clear) clear = false;
      }}
    />
    <button
      type="button"
      class="btn btn-ghost btn-xs"
      style="position:absolute;right:5px;min-height:28px;padding:0 6px;"
      disabled={clear}
      onclick={() => reveal = !reveal}
      aria-label="Toggle secret visibility"
    >
      <Icons name={reveal ? 'eye_off' : 'eye'} size={14} />
    </button>
  </div>
  <div class="field-hint" style="color:{clear ? 'var(--warn)' : 'var(--text-muted)'};">{hint}</div>
</div>
