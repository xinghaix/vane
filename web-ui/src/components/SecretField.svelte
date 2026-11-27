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
  <div class="field-label-row">
    <label for={id}>{label}</label>
    {#if configured && !required}
      <button
        type="button"
        class="field-action-btn {clear ? 'is-undo' : 'is-danger'}"
        data-dirty="1"
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
  <div class="input-wrap">
    <input
      {id}
      type={reveal ? 'text' : 'password'}
      class="mono has-addon"
      autocomplete="new-password"
      spellcheck="false"
      autocapitalize="off"
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
      class="input-addon-btn"
      disabled={clear}
      onclick={() => (reveal = !reveal)}
      aria-label={t?.common?.toggleSecret || 'Toggle visibility'}
      aria-pressed={reveal}
    >
      <Icons name={reveal ? 'eye_off' : 'eye'} size={15} />
    </button>
  </div>
  <div class="field-hint" style="color:{clear ? 'var(--warn)' : 'var(--text-muted)'};">{hint}</div>
</div>
