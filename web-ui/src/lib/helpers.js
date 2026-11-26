import { I18N } from './i18n.js';

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

export function localizeError(rawMsg, lang = 'zh', code = '') {
  const dict = (I18N[lang] || I18N.zh).errors || {};
  if (code && dict[code]) return dict[code];
  const msg = String(rawMsg || '').trim();
  if (dict[msg]) return dict[msg];
  if (lang === 'en' && msg) {
    const zhFallback = [
      ['认证繁忙', 'Authentication queue busy, please retry shortly.'],
      ['繁忙', 'Server busy, please retry shortly.'],
      ['原密码错误', 'Current password is incorrect.'],
      ['备份密码错误或文件已损坏', 'Incorrect backup password or corrupted archive.'],
      ['不是有效的 .vane.bak 备份文件', 'Invalid .vane.bak backup archive.'],
      ['备份文件超过 16 MiB 大小上限', 'Backup file exceeds the size limit.'],
      ['备份密码长度必须在', 'Backup password must be between 8 and 128 characters.'],
      ['备份密码需包含英文字母', 'Backup password must contain ASCII letters and digits or symbols.'],
      ['手动上传更新未启用', 'Manual update upload is disabled in config.toml.'],
      ['Ed25519 签名', 'Ed25519 signature verification failed or missing.'],
      ['Docker 模块已关闭', 'Docker module is disabled.'],
      ['已达到最大并发 Web 终端会话数上限', 'Maximum concurrent Web Terminal sessions reached.'],
      ['端口冲突', 'Listen port conflict detected.'],
      ['安全底线拦截', 'Blocked by gateway security guardrail.'],
      ['配置格式错误', 'Invalid configuration payload.'],
      ['转发规则不存在', 'Port-forward rule not found.'],
      ['DDNS 规则不存在', 'DDNS rule not found.'],
    ];
    for (const [needle, enText] of zhFallback) {
      if (msg.includes(needle)) return enText;
    }
  }
  return msg || (lang === 'en' ? 'Operation failed' : '操作失败');
}

export function translateRuntimeStatus(status, t) {
  const s = String(status || '').toLowerCase();
  const map = t?.statuses || {};
  return map[s] || status || map.unknown || '—';
}

export function formatDurationSecs(secs) {
  const n = Math.max(0, Math.floor(Number(secs) || 0));
  if (n < 60) return `${n}s`;
  const h = Math.floor(n / 3600);
  const m = Math.floor((n % 3600) / 60);
  const s = n % 60;
  if (h > 0) return `${h}h ${m}m`;
  return s > 0 ? `${m}m ${s}s` : `${m}m`;
}

export function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function downloadTextFile(filename, content) {
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
  downloadBlob(blob, filename);
}

export function uint8ToBase64(u8) {
  let chunks = [];
  const step = 0x8000;
  for (let i = 0; i < u8.length; i += step) {
    chunks.push(String.fromCharCode.apply(null, u8.subarray(i, i + step)));
  }
  return btoa(chunks.join(''));
}

export function kvObjectToRows(obj) {
  if (!obj || typeof obj !== 'object') return [];
  return Object.entries(obj).map(([key, val]) => ({
    key,
    value: isMaskedSecret(val) ? '' : String(val ?? ''),
    original: isMaskedSecret(val) ? val : null,
    origKey: key,
  }));
}

export function rowsToKvObject(rows, secret = false) {
  const out = {};
  for (const row of rows || []) {
    const k = String(row.key || '').trim();
    if (!k) continue;
    const v = String(row.value || '').trim();
    if (secret && !v && row.original && isMaskedSecret(row.original) && row.original.configured && row.origKey === k) {
      out[k] = UNCHANGED_SENTINEL;
    } else if (v) {
      out[k] = v;
    }
  }
  return out;
}

export function domainMatchesCert(host, acmeRules = [], certStatuses = []) {
  if (!host) return false;
  const h = host.toLowerCase();
  const matches = (pattern) => {
    const p = String(pattern || '').toLowerCase();
    if (!p) return false;
    if (p === h) return true;
    if (p.startsWith('*.')) {
      const suffix = p.slice(2);
      const dot = h.indexOf('.');
      return dot > 0 && h.slice(dot + 1) === suffix;
    }
    return false;
  };
  const activeCerts = (certStatuses || []).filter((c) => c.status === 'active');
  for (const c of activeCerts) {
    if (matches(c.domain) || (c.extra_domains || []).some(matches)) return 'active';
  }
  for (const a of acmeRules || []) {
    if (a.enabled && (matches(a.domain) || (a.extra_domains || []).some(matches))) return 'configured';
  }
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

export function splitLines(str) {
  if (!str) return [];
  return String(str)
    .split('\n')
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
    let sep = -1;
    if (idx > 0 && eq > 0) sep = Math.min(idx, eq);
    else if (idx > 0) sep = idx;
    else if (eq > 0) sep = eq;
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
  const str = String(text);
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(str);
      return true;
    }
  } catch {
    // fall through to textarea fallback
  }
  try {
    const ta = document.createElement('textarea');
    ta.value = str;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    ta.style.pointerEvents = 'none';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return Boolean(ok);
  } catch {
    return false;
  }
}

export function deepClone(obj) {
  return JSON.parse(JSON.stringify(obj));
}
