export const UNCHANGED_SENTINEL = '__UNCHANGED__';

export function isMaskedSecret(val) {
  return val && typeof val === 'object' && 'configured' in val && 'masked' in val;
}

export function isSecretConfigured(val) {
  if (isMaskedSecret(val)) return Boolean(val.configured);
  if (typeof val === 'string') return val.length > 0 && val !== UNCHANGED_SENTINEL;
  return false;
}

export function secretMaskedHint(val, fallbackEmpty = '') {
  if (isMaskedSecret(val)) return val.configured ? val.masked : fallbackEmpty;
  return fallbackEmpty;
}

export function resolveSecretInput(originalVal, newDraft, clearRequested = false) {
  if (clearRequested) return '';
  if (typeof newDraft === 'string' && newDraft.trim().length > 0) {
    return newDraft.trim();
  }
  if (isMaskedSecret(originalVal)) {
    return originalVal.configured ? UNCHANGED_SENTINEL : '';
  }
  if (typeof originalVal === 'string') return originalVal;
  return '';
}

export function formatKB(kb) {
  if (!kb || kb <= 0) return '0 MB';
  if (kb >= 1048576) return (kb / 1048576).toFixed(2) + ' GB';
  return (kb / 1024).toFixed(1) + ' MB';
}

export function formatBytes(bytes) {
  if (!bytes || bytes <= 0) return '0 B';
  if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(2) + ' GB';
  if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + ' MB';
  if (bytes >= 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return bytes + ' B';
}

export function formatRate(bps) {
  if (!bps || bps <= 0) return '0 KB/s';
  if (bps >= 1048576) return (bps / 1048576).toFixed(2) + ' MB/s';
  return (bps / 1024).toFixed(1) + ' KB/s';
}

export function formatUptime(secs) {
  if (!secs || secs <= 0) return '0m';
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

export function formatUnixTime(unixSecs) {
  if (!unixSecs || unixSecs <= 0) return '—';
  try {
    return new Date(unixSecs * 1000).toLocaleString();
  } catch {
    return String(unixSecs);
  }
}

export function splitCsv(str) {
  if (!str) return [];
  return String(str)
    .split(/[\n,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export function joinCsv(arr) {
  if (!Array.isArray(arr)) return '';
  return arr.join(', ');
}

export function kvObjectToText(obj) {
  if (!obj || typeof obj !== 'object') return '';
  return Object.entries(obj)
    .map(([k, v]) => `${k}: ${isMaskedSecret(v) ? (v.configured ? UNCHANGED_SENTINEL : '') : v}`)
    .join('\n');
}

export function textToKvObject(text, prevObj = {}) {
  const out = {};
  if (!text) return out;
  for (const line of String(text).split('\n')) {
    const t = line.trim();
    if (!t) continue;
    const idx = t.indexOf(':');
    const eq = t.indexOf('=');
    const sep = idx >= 0 ? idx : eq;
    if (sep <= 0) continue;
    const k = t.slice(0, sep).trim();
    let v = t.slice(sep + 1).trim();
    if (v === UNCHANGED_SENTINEL && prevObj && isMaskedSecret(prevObj[k])) {
      v = prevObj[k].configured ? UNCHANGED_SENTINEL : '';
    }
    if (k) out[k] = v;
  }
  return out;
}

export async function copyText(text) {
  if (!text) return false;
  try {
    await navigator.clipboard.writeText(String(text));
    return true;
  } catch {
    return false;
  }
}

export function deepClone(obj) {
  return JSON.parse(JSON.stringify(obj));
}
