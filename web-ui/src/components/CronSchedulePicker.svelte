<script>
  import Icons from './Icons.svelte';
  import Select from './Select.svelte';
  import {
    buildCronFromVisual,
    describeCronExpr,
    formatFriendlyRunTime,
    parseCronToVisual,
    validateCronExpr,
  } from '../lib/cron.js';

  let {
    value = $bindable('0 4 * * *'),
    lang = 'zh',
    t,
    apiFetch,
  } = $props();

  let editorMode = $state('visual'); // 'visual' | 'custom'
  let freq = $state('daily'); // 'daily' | 'weekly' | 'monthly' | 'every_minutes' | 'every_hours'
  let hour = $state(4);
  let minute = $state(0);
  let intervalMinutes = $state(30);
  let intervalHours = $state(6);
  let weekdays = $state([0]); // 0=Sun, 1=Mon ... 6=Sat
  let dayOfMonth = $state(1);

  let serverRuns = $state([]); // [{ ts, text }]
  let serverError = $state('');
  let loadingPreview = $state(false);
  let syncedExpr = '';
  let previewTimer = null;
  let previewSeq = 0;

  let hourOptions = $derived(
    Array.from({ length: 24 }, (_, i) => ({
      value: i,
      label: lang === 'en' ? String(i).padStart(2, '0') : `${String(i).padStart(2, '0')} 时`,
    }))
  );
  let minuteOptions = $derived(
    Array.from({ length: 60 }, (_, i) => ({
      value: i,
      label: lang === 'en' ? String(i).padStart(2, '0') : `${String(i).padStart(2, '0')} 分`,
    }))
  );
  let domOptions = $derived(
    Array.from({ length: 31 }, (_, i) => ({
      value: i + 1,
      label: lang === 'en' ? `Day ${i + 1}` : `每月 ${i + 1} 日`,
    }))
  );
  let hourStepOptions = $derived(
    [1, 2, 3, 4, 6, 8, 12].map((h) => ({
      value: h,
      label: lang === 'en' ? `Every ${h} hour${h > 1 ? 's' : ''}` : `每隔 ${h} 小时`,
    }))
  );
  let freqOptions = $derived(
    lang === 'en'
      ? [
          { value: 'daily', label: 'Every day at a fixed time' },
          { value: 'weekly', label: 'Specific days of the week' },
          { value: 'monthly', label: 'Specific day of the month' },
          { value: 'every_minutes', label: 'Every N minutes' },
          { value: 'every_hours', label: 'Every N hours' },
        ]
      : [
          { value: 'daily', label: '每天固定时间' },
          { value: 'weekly', label: '每周指定星期' },
          { value: 'monthly', label: '每月指定日期' },
          { value: 'every_minutes', label: '每隔 N 分钟' },
          { value: 'every_hours', label: '每隔 N 小时' },
        ]
  );

  const WEEKDAY_ITEMS = [
    { d: 1, zh: '周一', en: 'Mon' },
    { d: 2, zh: '周二', en: 'Tue' },
    { d: 3, zh: '周三', en: 'Wed' },
    { d: 4, zh: '周四', en: 'Thu' },
    { d: 5, zh: '周五', en: 'Fri' },
    { d: 6, zh: '周六', en: 'Sat' },
    { d: 0, zh: '周日', en: 'Sun' },
  ];

  let presets = $derived(
    lang === 'en'
      ? [
          { expr: '0 4 * * *', label: 'Daily 04:00' },
          { expr: '*/30 * * * *', label: 'Every 30m' },
          { expr: '0 */6 * * *', label: 'Every 6h' },
          { expr: '0 3 * * 0', label: 'Sun 03:00' },
          { expr: '30 3 1 * *', label: '1st of Month' },
        ]
      : [
          { expr: '0 4 * * *', label: '每天 04:00' },
          { expr: '*/30 * * * *', label: '每 30 分钟' },
          { expr: '0 */6 * * *', label: '每 6 小时' },
          { expr: '0 3 * * 0', label: '每周日 03:00' },
          { expr: '30 3 1 * *', label: '每月 1 日 03:30' },
        ]
  );

  let localValidation = $derived(validateCronExpr(value, lang));
  let humanSummary = $derived(localValidation.valid ? describeCronExpr(value, lang) : '');
  let effectiveError = $derived(!localValidation.valid ? localValidation.error : serverError);

  let rawTokens = $derived(String(value || '').trim().split(/\s+/).filter(Boolean));
  let slotLabels = $derived(
    rawTokens.length === 6
      ? lang === 'en'
        ? ['Sec (0-59)', 'Min (0-59)', 'Hour (0-23)', 'Day (1-31)', 'Month (1-12)', 'Week (0-6)']
        : ['秒 (0-59)', '分 (0-59)', '时 (0-23)', '日 (1-31)', '月 (1-12)', '周 (0-6)']
      : lang === 'en'
        ? ['Min (0-59)', 'Hour (0-23)', 'Day (1-31)', 'Month (1-12)', 'Week (0-6)']
        : ['分 (0-59)', '时 (0-23)', '日 (1-31)', '月 (1-12)', '周 (0-6)']
  );

  function hydrateVisualFromExpr(expr) {
    const parsed = parseCronToVisual(expr);
    if (parsed.mode === 'custom') {
      editorMode = 'custom';
      return;
    }
    editorMode = 'visual';
    freq = parsed.mode;
    if (typeof parsed.hour === 'number') hour = parsed.hour;
    if (typeof parsed.minute === 'number') minute = parsed.minute;
    if (typeof parsed.intervalMinutes === 'number') intervalMinutes = parsed.intervalMinutes;
    if (typeof parsed.intervalHours === 'number') intervalHours = parsed.intervalHours;
    if (Array.isArray(parsed.weekdays) && parsed.weekdays.length) weekdays = parsed.weekdays;
    if (typeof parsed.dayOfMonth === 'number') dayOfMonth = parsed.dayOfMonth;
  }

  function applyVisualChange() {
    const next = buildCronFromVisual({
      mode: freq,
      hour,
      minute,
      intervalMinutes,
      intervalHours,
      weekdays,
      dayOfMonth,
    });
    syncedExpr = next;
    value = next;
    triggerServerPreview(next, true);
  }

  function toggleWeekday(d) {
    if (weekdays.includes(d)) {
      if (weekdays.length <= 1) return; // 至少保留 1 天
      weekdays = weekdays.filter((x) => x !== d);
    } else {
      weekdays = [...weekdays, d];
    }
    applyVisualChange();
  }

  function pickPreset(expr) {
    syncedExpr = expr;
    value = expr;
    const parsed = parseCronToVisual(expr);
    if (parsed.mode !== 'custom' && editorMode === 'visual') {
      hydrateVisualFromExpr(expr);
    }
    triggerServerPreview(expr, true);
  }

  async function fetchPreview(expr) {
    const check = validateCronExpr(expr, lang);
    if (!check.valid || !apiFetch) {
      serverRuns = [];
      serverError = '';
      loadingPreview = false;
      return;
    }
    const seq = ++previewSeq;
    loadingPreview = true;
    try {
      const r = await apiFetch(`/api/cron/preview?expr=${encodeURIComponent(String(expr).trim())}`);
      if (seq !== previewSeq) return;
      if (r.valid) {
        const formatted = r.formatted || [];
        const unixList = r.next_runs || [];
        serverRuns = formatted.map((iso, i) => ({
          iso,
          ts: unixList[i] || 0,
        }));
        serverError = '';
      } else {
        serverRuns = [];
        serverError = r.error || '';
      }
    } catch (err) {
      if (seq !== previewSeq) return;
      serverRuns = [];
      serverError = err?.message || '';
    } finally {
      if (seq === previewSeq) loadingPreview = false;
    }
  }

  function triggerServerPreview(expr, immediate = false) {
    if (previewTimer) {
      clearTimeout(previewTimer);
      previewTimer = null;
    }
    const check = validateCronExpr(expr, lang);
    if (!check.valid) {
      previewSeq++;
      serverRuns = [];
      serverError = '';
      loadingPreview = false;
      return;
    }
    if (immediate) {
      fetchPreview(expr);
    } else {
      previewTimer = setTimeout(() => {
        previewTimer = null;
        fetchPreview(expr);
      }, 220);
    }
  }

  $effect(() => {
    const incoming = String(value || '').trim();
    if (incoming !== syncedExpr) {
      syncedExpr = incoming;
      hydrateVisualFromExpr(incoming);
      triggerServerPreview(incoming, true);
    }
  });

  $effect(() => {
    return () => {
      if (previewTimer) clearTimeout(previewTimer);
    };
  });
</script>

<div class="field">
  <div class="field-label-row" style="margin-bottom:4px;">
    <label for="cr-sched">{t.cronPage.scheduleLabel || t.cronPage.expr}</label>
    <div class="pill-tabs" role="tablist" style="padding:2px;">
      <button
        type="button"
        role="tab"
        aria-selected={editorMode === 'visual'}
        class="pill-tab {editorMode === 'visual' ? 'active' : ''}"
        style="min-height:26px;padding:0 11px;font-size:12px;"
        onclick={() => {
          editorMode = 'visual';
          const parsed = parseCronToVisual(value);
          if (parsed.mode !== 'custom') {
            hydrateVisualFromExpr(value);
          } else {
            applyVisualChange();
          }
        }}
      >
        {lang === 'en' ? 'Visual Schedule' : '可视化设置'}
      </button>
      <button
        type="button"
        role="tab"
        aria-selected={editorMode === 'custom'}
        class="pill-tab {editorMode === 'custom' ? 'active' : ''}"
        style="min-height:26px;padding:0 11px;font-size:12px;"
        onclick={() => (editorMode = 'custom')}
      >
        {lang === 'en' ? 'Custom Cron' : '自定义 Cron'}
      </button>
    </div>
  </div>

  {#if editorMode === 'visual'}
    <div class="subcard" style="display:grid;gap:12px;">
      <div class="form-grid" style="align-items:end;">
        <div class="field" style="margin-bottom:0;">
          <label for="cr-freq">{lang === 'en' ? 'Repeat' : '重复周期'}</label>
          <Select id="cr-freq" bind:value={freq} options={freqOptions} onchange={applyVisualChange} />
        </div>

        {#if freq === 'daily' || freq === 'weekly'}
          <div class="field" style="margin-bottom:0;">
            <label for="cr-hm-h">{lang === 'en' ? 'Time of Day' : '执行时间点'}</label>
            <div style="display:grid;grid-template-columns:1fr auto 1fr;gap:6px;align-items:center;">
              <Select id="cr-hm-h" mono bind:value={hour} options={hourOptions} onchange={applyVisualChange} />
              <span style="font-weight:700;color:var(--text-muted);">:</span>
              <Select id="cr-hm-m" mono bind:value={minute} options={minuteOptions} onchange={applyVisualChange} />
            </div>
          </div>
        {:else if freq === 'monthly'}
          <div class="field" style="margin-bottom:0;">
            <label for="cr-dom">{lang === 'en' ? 'Day of Month' : '执行日期'}</label>
            <Select id="cr-dom" bind:value={dayOfMonth} options={domOptions} onchange={applyVisualChange} />
          </div>
        {:else if freq === 'every_minutes'}
          <div class="field" style="margin-bottom:0;">
            <label for="cr-ev-m">{lang === 'en' ? 'Every (1~59 mins)' : '间隔分钟数 (1~59)'}</label>
            <input
              id="cr-ev-m"
              type="number"
              min="1"
              max="59"
              class="mono"
              bind:value={intervalMinutes}
              oninput={applyVisualChange}
            />
          </div>
        {:else if freq === 'every_hours'}
          <div class="field" style="margin-bottom:0;">
            <label for="cr-ev-h">{lang === 'en' ? 'Interval & Minute' : '小时间隔与触发分钟'}</label>
            <div style="display:grid;grid-template-columns:1.2fr 1fr;gap:8px;">
              <Select id="cr-ev-h" bind:value={intervalHours} options={hourStepOptions} onchange={applyVisualChange} />
              <Select id="cr-ev-hm" mono bind:value={minute} options={minuteOptions} onchange={applyVisualChange} />
            </div>
          </div>
        {/if}
      </div>

      {#if freq === 'monthly'}
        <div class="field" style="margin-bottom:0;max-width:280px;">
          <label for="cr-mhm-h">{lang === 'en' ? 'Time of Day' : '执行时间点'}</label>
          <div style="display:grid;grid-template-columns:1fr auto 1fr;gap:6px;align-items:center;">
            <Select id="cr-mhm-h" mono bind:value={hour} options={hourOptions} onchange={applyVisualChange} />
            <span style="font-weight:700;color:var(--text-muted);">:</span>
            <Select id="cr-mhm-m" mono bind:value={minute} options={minuteOptions} onchange={applyVisualChange} />
          </div>
        </div>
      {:else if freq === 'weekly'}
        <div>
          <div style="font-size:12px;font-weight:600;color:var(--text-secondary);margin-bottom:6px;">
            {lang === 'en' ? 'Select Weekdays' : '选择执行星期（可多选）'}
          </div>
          <div class="btn-group" style="gap:6px;">
            {#each WEEKDAY_ITEMS as wd (wd.d)}
              {@const picked = weekdays.includes(wd.d)}
              <button
                type="button"
                class="chip {picked ? 'active' : ''}"
                style="min-height:30px;padding:2px 11px;"
                onclick={() => toggleWeekday(wd.d)}
              >
                {lang === 'en' ? wd.en : wd.zh}
              </button>
            {/each}
          </div>
        </div>
      {:else if freq === 'every_minutes'}
        <div class="btn-group" style="gap:6px;">
          {#each [5, 10, 15, 30] as mStep (mStep)}
            <button
              type="button"
              class="chip {Number(intervalMinutes) === mStep ? 'active' : ''}"
              style="min-height:28px;padding:2px 10px;font-size:12px;"
              onclick={() => {
                intervalMinutes = mStep;
                applyVisualChange();
              }}
            >
              {lang === 'en' ? `Every ${mStep}m` : `每 ${mStep} 分钟`}
            </button>
          {/each}
        </div>
      {/if}
    </div>
  {:else}
    <div class="subcard" style="display:grid;gap:10px;">
      <div>
        <input
          id="cr-sched"
          type="text"
          class="mono"
          style={effectiveError ? 'border-color:var(--danger);' : ''}
          placeholder="0 4 * * *"
          spellcheck="false"
          autocomplete="off"
          bind:value
          oninput={(e) => {
            syncedExpr = String(e.currentTarget.value || '').trim();
            triggerServerPreview(e.currentTarget.value, false);
          }}
          required
        />
        <div class="cron-slots-grid" style="grid-template-columns:repeat({slotLabels.length}, minmax(0, 1fr));">
          {#each slotLabels as sl, idx (sl)}
            <div class="cron-slot-chip">
              <span class="mono" style="font-weight:700;color:var(--text-primary);">{rawTokens[idx] ?? '—'}</span>
              <span>{sl}</span>
            </div>
          {/each}
        </div>
      </div>

      <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
        <span style="font-size:11.5px;color:var(--text-muted);">{lang === 'en' ? 'Quick fill:' : '常用模板：'}</span>
        {#each presets as p (p.expr)}
          <button
            type="button"
            class="chip {String(value || '').trim() === p.expr ? 'active' : ''}"
            style="min-height:26px;padding:2px 10px;font-size:12px;"
            onclick={() => pickPreset(p.expr)}
          >
            {p.label}
          </button>
        {/each}
      </div>
    </div>
  {/if}

  <!-- 实时合法性校验与下次运行时间卡片 -->
  {#if effectiveError}
    <div class="cron-preview-box invalid" role="alert">
      <Icons name="alert" size={15} />
      <div style="min-width:0;flex:1;">
        <div style="font-weight:600;">{lang === 'en' ? 'Invalid Schedule' : '定时规则格式有误'}</div>
        <div style="font-size:12px;margin-top:1px;">{effectiveError}</div>
      </div>
    </div>
  {:else}
    <div class="cron-preview-box valid">
      <div class="row-between" style="gap:8px;">
        <div style="display:inline-flex;align-items:center;gap:7px;font-weight:600;color:var(--text-primary);">
          <Icons name="cron" size={14} />
          <span>{humanSummary}</span>
        </div>
        <span class="badge badge-muted mono" style="font-size:11.5px;">{String(value || '').trim()}</span>
      </div>
      {#if serverRuns.length > 0}
        <div style="font-size:12px;color:var(--text-secondary);margin-top:6px;display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
          <span style="color:var(--text-muted);">{lang === 'en' ? 'Next run:' : '下次运行：'}</span>
          <span class="mono" style="font-weight:600;color:var(--accent);">
            {formatFriendlyRunTime(serverRuns[0].iso, serverRuns[0].ts, lang)}
          </span>
          {#if serverRuns.length > 1}
            <span style="color:var(--text-muted);">· {lang === 'en' ? 'Then:' : '后续：'}</span>
            <span class="mono" style="font-size:11.5px;color:var(--text-muted);">
              {serverRuns
                .slice(1)
                .map((r) => formatFriendlyRunTime(r.iso, 0, lang))
                .join(' / ')}
            </span>
          {/if}
        </div>
      {:else if loadingPreview}
        <div style="font-size:11.5px;color:var(--text-muted);margin-top:4px;">{t.common.loading}</div>
      {/if}
    </div>
  {/if}
</div>
