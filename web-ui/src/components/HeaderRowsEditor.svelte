<script>
  import Icons from './Icons.svelte';
  import { isSecretConfigured, secretMaskedHint } from '../lib/helpers.js';

  const FORBIDDEN_PROTOCOL_HEADERS = new Set([
    'host',
    'content-length',
    'connection',
    'keep-alive',
    'proxy-authenticate',
    'proxy-authorization',
    'te',
    'trailer',
    'trailers',
    'transfer-encoding',
    'upgrade',
  ]);

  let {
    label = '',
    rows = $bindable([]),
    secret = false,
    forbidProtocolHeaders = false,
    t,
  } = $props();

  let revealed = $state({});

  function addRow() {
    rows = [...rows, { key: '', value: '', original: null, origKey: '' }];
  }

  function removeRow(idx) {
    rows = rows.filter((_, i) => i !== idx);
  }

  function isForbiddenKey(k) {
    return forbidProtocolHeaders && FORBIDDEN_PROTOCOL_HEADERS.has(String(k || '').trim().toLowerCase());
  }
</script>

<div class="field">
  <div class="row-between" style="gap:8px;margin-bottom:4px;">
    <span style="font-size:12.5px;font-weight:600;color:var(--text-secondary);">{label}</span>
    <button type="button" class="btn btn-xs" data-dirty="1" onclick={addRow}>
      <Icons name="plus" size={12} />
      <span>{t?.common?.addHeader || '+'}</span>
    </button>
  </div>

  {#if rows.length === 0}
    <div class="header-empty-box">{t?.common?.noHeaders || '—'}</div>
  {:else}
    <div style="display:grid;gap:8px;">
      {#each rows as row, i (i)}
        {@const keepMasked = secret && isSecretConfigured(row.original) && row.origKey === String(row.key || '').trim() && !row.value}
        {@const badKey = isForbiddenKey(row.key)}
        <div class="rule-card" style="padding:8px 10px;border-color:{badKey ? 'var(--danger)' : 'var(--border-subtle)'};">
          <div style="display:grid;grid-template-columns:minmax(110px, 0.9fr) minmax(140px, 1.3fr) auto;gap:8px;align-items:center;">
            <input
              type="text"
              class="mono control-compact"
              placeholder={t?.common?.headerNamePh || 'Header-Name'}
              aria-label={t?.common?.headerNamePh || 'Header name'}
              bind:value={row.key}
            />
            <div style="position:relative;display:flex;align-items:center;">
              <input
                type={secret && !revealed[i] ? 'password' : 'text'}
                class="mono control-compact"
                style={secret ? 'padding-right:38px;' : ''}
                autocomplete={secret ? 'new-password' : 'off'}
                spellcheck="false"
                placeholder={keepMasked ? secretMaskedHint(row.original, '****') : (t?.common?.headerValPh || 'Value')}
                aria-label={t?.common?.headerValPh || 'Header value'}
                bind:value={row.value}
              />
              {#if secret}
                <button
                  type="button"
                  class="btn btn-ghost btn-xs"
                  style="position:absolute;right:4px;min-height:26px;padding:0 5px;"
                  aria-label={t?.common?.toggleSecret || 'Toggle visibility'}
                  onclick={() => (revealed = { ...revealed, [i]: !revealed[i] })}
                >
                  <Icons name={revealed[i] ? 'eye_off' : 'eye'} size={13} />
                </button>
              {/if}
            </div>
            <button
              type="button"
              class="btn btn-xs btn-danger"
              data-dirty="1"
              aria-label={t?.delete || 'Delete'}
              onclick={() => removeRow(i)}
            >
              <Icons name="trash" size={12} />
            </button>
          </div>
          {#if badKey}
            <div style="font-size:11.5px;color:var(--danger);margin-top:4px;">
              {t?.rp?.forbiddenHeaderHint || 'Host / Content-Length / hop-by-hop headers are not allowed'}
            </div>
          {:else if keepMasked}
            <div style="font-size:11.5px;color:var(--accent);margin-top:4px;">
              {t?.common?.keepEncryptedHint || 'Encrypted value kept unless replaced'}
            </div>
          {/if}
        </div>
      {/each}
    </div>
  {/if}
</div>
