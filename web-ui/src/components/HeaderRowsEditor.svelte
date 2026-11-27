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

  // WeakMap 为每行对象分配稳定的运行时唯一键，既不污染序列化对象，又彻底避免删除行时 revealed 索引错位
  const rowKeys = new WeakMap();
  let nextRowKey = 1;
  function getRowKey(row) {
    if (!row || typeof row !== 'object') return `row-${nextRowKey++}`;
    let k = rowKeys.get(row);
    if (!k) {
      k = `hdr-${nextRowKey++}`;
      rowKeys.set(row, k);
    }
    return k;
  }

  let revealed = $state({});

  function addRow() {
    rows = [...rows, { key: '', value: '', original: null, origKey: '' }];
  }

  function removeRow(idx) {
    const removed = rows[idx];
    if (removed && rowKeys.has(removed)) {
      const rk = rowKeys.get(removed);
      if (rk in revealed) {
        const copy = { ...revealed };
        delete copy[rk];
        revealed = copy;
      }
    }
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
      {#each rows as row, i (getRowKey(row))}
        {@const rk = getRowKey(row)}
        {@const keepMasked = secret && isSecretConfigured(row.original) && row.origKey === String(row.key || '').trim() && !row.value}
        {@const badKey = isForbiddenKey(row.key)}
        <div class="rule-card header-row-card {badKey ? 'has-error' : ''}">
          <div class="header-row-grid">
            <input
              type="text"
              class="mono control-compact header-row-key"
              placeholder={t?.common?.headerNamePh || 'Header-Name'}
              aria-label={t?.common?.headerNamePh || 'Header name'}
              bind:value={row.key}
            />
            <div class="input-wrap header-row-val">
              <input
                type={secret && !revealed[rk] ? 'password' : 'text'}
                class="mono control-compact {secret ? 'has-addon' : ''}"
                autocomplete={secret ? 'new-password' : 'off'}
                spellcheck="false"
                placeholder={keepMasked ? secretMaskedHint(row.original, '****') : (t?.common?.headerValPh || 'Value')}
                aria-label={t?.common?.headerValPh || 'Header value'}
                bind:value={row.value}
              />
              {#if secret}
                <button
                  type="button"
                  class="input-addon-btn"
                  aria-label={t?.common?.toggleSecret || 'Toggle visibility'}
                  aria-pressed={Boolean(revealed[rk])}
                  onclick={() => (revealed = { ...revealed, [rk]: !revealed[rk] })}
                >
                  <Icons name={revealed[rk] ? 'eye_off' : 'eye'} size={14} />
                </button>
              {/if}
            </div>
            <button
              type="button"
              class="btn btn-icon btn-icon-sm btn-danger header-row-del"
              data-dirty="1"
              aria-label={t?.delete || 'Delete'}
              onclick={() => removeRow(i)}
            >
              <Icons name="trash" size={13} />
            </button>
          </div>
          {#if badKey}
            <div style="font-size:11.5px;color:var(--danger);margin-top:5px;">
              {t?.rp?.forbiddenHeaderHint || 'Host / Content-Length / hop-by-hop headers are not allowed'}
            </div>
          {:else if keepMasked}
            <div style="font-size:11.5px;color:var(--accent);margin-top:5px;">
              {t?.common?.keepEncryptedHint || 'Encrypted value kept unless replaced'}
            </div>
          {/if}
        </div>
      {/each}
    </div>
  {/if}
</div>
