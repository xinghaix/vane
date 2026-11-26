// 零依赖 5/6 段 Cron 合法性校验、可视化双向解析与自然语言描述（严格对齐后端 src/daemon/cron.rs）

const WEEKDAY_ZH = ['周日', '周一', '周二', '周三', '周四', '周五', '周六'];
const WEEKDAY_EN = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

const FIELD_META = [
  { key: 'sec', zh: '秒', en: 'Sec', min: 0, max: 59 },
  { key: 'min', zh: '分', en: 'Min', min: 0, max: 59 },
  { key: 'hour', zh: '时', en: 'Hour', min: 0, max: 23 },
  { key: 'dom', zh: '日', en: 'Day', min: 1, max: 31 },
  { key: 'mon', zh: '月', en: 'Month', min: 1, max: 12 },
  { key: 'dow', zh: '周', en: 'Weekday', min: 0, max: 6 },
];

const MAX_DAYS_IN_MONTH = [0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

function parseIntStrict(str) {
  if (!/^\d+$/.test(str)) return null;
  const n = Number(str);
  return Number.isSafeInteger(n) ? n : null;
}

function parseCronField(raw, meta, lang = 'zh') {
  const name = lang === 'en' ? meta.en : meta.zh;
  const values = new Set();
  if (!raw) {
    return { ok: false, error: lang === 'en' ? `${name} field is empty` : `「${name}」字段不能为空` };
  }
  for (const part of raw.split(',')) {
    if (!part) {
      return { ok: false, error: lang === 'en' ? `Invalid syntax in ${name}: "${raw}"` : `「${name}」格式有误: "${raw}"` };
    }
    let rangePart = part;
    let step = 1;
    if (part.includes('/')) {
      const segs = part.split('/');
      if (segs.length !== 2) {
        return { ok: false, error: lang === 'en' ? `Invalid step in ${name}: "${part}"` : `「${name}」步长格式有误: "${part}"` };
      }
      rangePart = segs[0];
      const st = parseIntStrict(segs[1]);
      if (st === null || st <= 0) {
        return { ok: false, error: lang === 'en' ? `Step must be >= 1 in ${name}: "${part}"` : `「${name}」间隔步长必须大于 0: "${part}"` };
      }
      step = st;
    }

    let lo = meta.min;
    let hi = meta.max;
    let extraSun = false;

    if (rangePart === '*') {
      lo = meta.min;
      hi = meta.max;
    } else if (rangePart.includes('-')) {
      const bounds = rangePart.split('-');
      if (bounds.length !== 2) {
        return { ok: false, error: lang === 'en' ? `Invalid range in ${name}: "${part}"` : `「${name}」范围格式有误: "${part}"` };
      }
      let av = parseIntStrict(bounds[0]);
      let bv = parseIntStrict(bounds[1]);
      if (av === null || bv === null) {
        return { ok: false, error: lang === 'en' ? `Invalid number in ${name}: "${part}"` : `「${name}」包含无效数字: "${part}"` };
      }
      if (meta.max === 6 && bv === 7) {
        extraSun = true;
        if (av === 7) {
          av = 0;
          bv = 0;
        } else {
          bv = 6;
        }
      }
      if (av < meta.min || bv > meta.max || av > bv) {
        return {
          ok: false,
          error:
            lang === 'en'
              ? `${name} out of range (${meta.min}~${meta.max}): "${part}"`
              : `「${name}」超出有效范围 (${meta.min}~${meta.max}): "${part}"`,
        };
      }
      lo = av;
      hi = bv;
    } else {
      let v = parseIntStrict(rangePart);
      if (v === null) {
        return { ok: false, error: lang === 'en' ? `Invalid value in ${name}: "${part}"` : `「${name}」包含无效数值: "${part}"` };
      }
      if (meta.max === 6 && v === 7) v = 0;
      if (v < meta.min || v > meta.max) {
        return {
          ok: false,
          error:
            lang === 'en'
              ? `${name} out of range (${meta.min}~${meta.max}): "${part}"`
              : `「${name}」超出有效范围 (${meta.min}~${meta.max}): "${part}"`,
        };
      }
      lo = v;
      hi = v;
    }

    for (let v = lo; v <= hi; v += step) {
      values.add(v);
    }
    if (extraSun && (step === 1 || (7 - lo) % step === 0)) {
      values.add(0);
    }
  }

  if (values.size === 0) {
    return { ok: false, error: lang === 'en' ? `${name} matches no values` : `「${name}」未匹配任何有效时间` };
  }
  return { ok: true, values: [...values].sort((a, b) => a - b) };
}

export function validateCronExpr(expr, lang = 'zh') {
  const trimmed = String(expr || '').trim();
  if (!trimmed) {
    return {
      valid: false,
      error: lang === 'en' ? 'Please enter a schedule expression' : '请设置执行时间或输入 Cron 表达式',
      parts: [],
    };
  }
  const parts = trimmed.split(/\s+/);
  if (parts.length !== 5 && parts.length !== 6) {
    return {
      valid: false,
      error:
        lang === 'en'
          ? `Expected 5 fields (min hour day month weekday) or 6 fields (with seconds), got ${parts.length}`
          : `格式需为 5 段（分 时 日 月 周）或 6 段（秒 分 时 日 月 周），当前为 ${parts.length} 段`,
      parts,
    };
  }
  const sixParts = parts.length === 6 ? parts : ['0', ...parts];
  const parsed = [];
  for (let i = 0; i < 6; i++) {
    const res = parseCronField(sixParts[i], FIELD_META[i], lang);
    if (!res.ok) {
      return { valid: false, error: res.error, parts };
    }
    parsed.push(res.values);
  }

  // 检查是否存在任何合法月-日组合（例如 2 月 31 日永不触发）
  const days = parsed[3];
  const months = parsed[4];
  const hasPossibleCalendarDay = months.some((m) => days.some((d) => d <= MAX_DAYS_IN_MONTH[m]));
  if (!hasPossibleCalendarDay) {
    return {
      valid: false,
      error: lang === 'en' ? 'Selected day never occurs in the selected month(s)' : '所选日期在对应月份中不存在（如 2 月 30 日），任务将永远不会触发',
      parts,
    };
  }

  return { valid: true, error: '', parts, sixParts, parsed };
}

function pad2(n) {
  return String(Number(n) || 0).padStart(2, '0');
}

/**
 * 尝试将标准 Cron 表达式反向识别为可视化预设结构；复杂表达式返回 { mode: 'custom' }
 */
export function parseCronToVisual(expr) {
  const check = validateCronExpr(expr, 'zh');
  if (!check.valid) return { mode: 'custom' };
  const [secS, minS, hourS, domS, monS, dowS] = check.sixParts;
  if (secS !== '0' && secS !== '00') return { mode: 'custom' };
  if (monS !== '*') return { mode: 'custom' };

  // 1) 每隔 N 分钟: */N * * * * (或 * * * * * = 每 1 分钟)
  if (hourS === '*' && domS === '*' && dowS === '*') {
    if (minS === '*') {
      return { mode: 'every_minutes', intervalMinutes: 1 };
    }
    const mStep = minS.match(/^\*\/(\d+)$/);
    if (mStep) {
      const n = Number(mStep[1]);
      if (n >= 1 && n <= 59) return { mode: 'every_minutes', intervalMinutes: n };
    }
  }

  // 2) 每隔 N 小时: M */H * * * (或 M * * * * = 每 1 小时)
  if (/^\d+$/.test(minS) && domS === '*' && dowS === '*') {
    const minute = Number(minS);
    if (hourS === '*') {
      return { mode: 'every_hours', intervalHours: 1, minute };
    }
    const hStep = hourS.match(/^\*\/(\d+)$/);
    if (hStep) {
      const h = Number(hStep[1]);
      if (h >= 1 && h <= 23) return { mode: 'every_hours', intervalHours: h, minute };
    }
  }

  // 固定时:分
  if (/^\d+$/.test(minS) && /^\d+$/.test(hourS)) {
    const minute = Number(minS);
    const hour = Number(hourS);

    // 3) 每天固定时间: M H * * *
    if (domS === '*' && dowS === '*') {
      return { mode: 'daily', hour, minute };
    }

    // 4) 每周指定星期: M H * * d1,d2...
    if (domS === '*' && /^\d+(,\d+)*$/.test(dowS)) {
      const weekdays = [...new Set(dowS.split(',').map((x) => (Number(x) === 7 ? 0 : Number(x))))].sort((a, b) => a - b);
      if (weekdays.length > 0 && weekdays.every((d) => d >= 0 && d <= 6)) {
        return { mode: 'weekly', weekdays, hour, minute };
      }
    }

    // 5) 每月固定日期: M H D * *
    if (/^\d+$/.test(domS) && dowS === '*') {
      const dayOfMonth = Number(domS);
      if (dayOfMonth >= 1 && dayOfMonth <= 31) {
        return { mode: 'monthly', dayOfMonth, hour, minute };
      }
    }
  }

  return { mode: 'custom' };
}

export function buildCronFromVisual(state) {
  const m = Math.max(0, Math.min(59, Number(state.minute) || 0));
  const h = Math.max(0, Math.min(23, Number(state.hour) || 0));
  switch (state.mode) {
    case 'every_minutes': {
      const iv = Math.max(1, Math.min(59, Number(state.intervalMinutes) || 30));
      return iv === 1 ? '* * * * *' : `*/${iv} * * * *`;
    }
    case 'every_hours': {
      const ih = Math.max(1, Math.min(23, Number(state.intervalHours) || 6));
      return ih === 1 ? `${m} * * * *` : `${m} */${ih} * * *`;
    }
    case 'weekly': {
      const days = Array.isArray(state.weekdays) && state.weekdays.length ? [...new Set(state.weekdays)].sort((a, b) => a - b) : [0];
      return `${m} ${h} * * ${days.join(',')}`;
    }
    case 'monthly': {
      const dom = Math.max(1, Math.min(31, Number(state.dayOfMonth) || 1));
      return `${m} ${h} ${dom} * *`;
    }
    case 'daily':
    default:
      return `${m} ${h} * * *`;
  }
}

export function describeCronExpr(expr, lang = 'zh') {
  const check = validateCronExpr(expr, lang);
  if (!check.valid) return '';
  const vis = parseCronToVisual(expr);
  const en = lang === 'en';
  if (vis.mode === 'daily') {
    const hm = `${pad2(vis.hour)}:${pad2(vis.minute)}`;
    return en ? `Every day at ${hm}` : `每天 ${hm} 执行`;
  }
  if (vis.mode === 'every_minutes') {
    return vis.intervalMinutes === 1
      ? en
        ? 'Every minute'
        : '每分钟执行一次'
      : en
        ? `Every ${vis.intervalMinutes} minutes`
        : `每隔 ${vis.intervalMinutes} 分钟执行`;
  }
  if (vis.mode === 'every_hours') {
    const mm = pad2(vis.minute);
    return vis.intervalHours === 1
      ? en
        ? `Every hour at :${mm}`
        : `每小时第 ${mm} 分执行`
      : en
        ? `Every ${vis.intervalHours} hours at :${mm}`
        : `每隔 ${vis.intervalHours} 小时（第 ${mm} 分）执行`;
  }
  if (vis.mode === 'weekly') {
    const hm = `${pad2(vis.hour)}:${pad2(vis.minute)}`;
    const order = [1, 2, 3, 4, 5, 6, 0];
    const sorted = [...vis.weekdays].sort((a, b) => order.indexOf(a) - order.indexOf(b));
    const names = sorted.map((d) => (en ? WEEKDAY_EN[d] : WEEKDAY_ZH[d])).join(en ? ', ' : '、');
    return en ? `Every ${names} at ${hm}` : `每${names} ${hm} 执行`;
  }
  if (vis.mode === 'monthly') {
    const hm = `${pad2(vis.hour)}:${pad2(vis.minute)}`;
    return en ? `Day ${vis.dayOfMonth} of every month at ${hm}` : `每月 ${vis.dayOfMonth} 日 ${hm} 执行`;
  }

  // 自定义表达式简要说明
  const [secS] = check.sixParts;
  if (secS !== '0' && secS !== '00') {
    return en ? `Custom schedule (with seconds: ${expr.trim()})` : `自定义定时规则（精确到秒）`;
  }
  return en ? 'Custom schedule expression' : '自定义 Cron 定时规则';
}

export function formatFriendlyRunTime(isoOrRfc3339, unixSec, lang = 'zh') {
  const s = String(isoOrRfc3339 || '');
  // 将 "2026-11-27T04:00:00+08:00" 转为清爽的 "2026-11-27 04:00"（秒非 00 时保留 :ss）
  const m = s.match(/^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}):(\d{2})/);
  const base = m ? (m[3] === '00' ? `${m[1]} ${m[2]}` : `${m[1]} ${m[2]}:${m[3]}`) : s;
  if (!unixSec) return base;
  const diffSec = Math.round(Number(unixSec) - Date.now() / 1000);
  if (diffSec <= 0) return base;
  let rel = '';
  if (diffSec < 60) {
    rel = lang === 'en' ? `in ${diffSec}s` : `${diffSec} 秒后`;
  } else if (diffSec < 3600) {
    const mins = Math.round(diffSec / 60);
    rel = lang === 'en' ? `in ${mins} min` : `约 ${mins} 分钟后`;
  } else if (diffSec < 86400) {
    const hrs = Math.floor(diffSec / 3600);
    const mins = Math.round((diffSec % 3600) / 60);
    rel =
      mins > 0
        ? lang === 'en'
          ? `in ${hrs}h ${mins}m`
          : `约 ${hrs} 小时 ${mins} 分后`
        : lang === 'en'
          ? `in ${hrs}h`
          : `约 ${hrs} 小时后`;
  } else {
    const days = Math.round(diffSec / 86400);
    rel = lang === 'en' ? `in ~${days}d` : `约 ${days} 天后`;
  }
  return `${base} (${rel})`;
}
