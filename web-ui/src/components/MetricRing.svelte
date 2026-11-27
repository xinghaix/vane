<script>
  let {
    percent = 0,
    size = 44,
    stroke = 4,
    tone = 'accent', // 'accent' | 'info' | 'warn' | 'danger'
    label = '',
    sub = '',
  } = $props();

  let clamped = $derived(Math.max(0, Math.min(100, Number(percent) || 0)));
  let radius = $derived((size - stroke) / 2);
  let circumference = $derived(2 * Math.PI * radius);
  let dashOffset = $derived(circumference * (1 - clamped / 100));
  let strokeColor = $derived(
    tone === 'danger'
      ? 'var(--danger)'
      : tone === 'warn'
        ? 'var(--warn)'
        : tone === 'info'
          ? 'var(--info)'
          : 'var(--accent)'
  );
</script>

<span
  class="metric-ring"
  role="img"
  style={`width:${size}px;height:${size}px;`}
  aria-label={label ? `${label} ${sub}` : `${clamped.toFixed(0)}%`}
>
  <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} class="metric-ring-svg" aria-hidden="true">
    <circle
      cx={size / 2}
      cy={size / 2}
      r={radius}
      fill="none"
      stroke="var(--border-strong)"
      stroke-opacity="0.55"
      stroke-width={stroke}
    />
    {#if clamped > 0}
      <circle
        cx={size / 2}
        cy={size / 2}
        r={radius}
        fill="none"
        stroke={strokeColor}
        stroke-width={stroke}
        stroke-linecap={clamped >= 3 ? 'round' : 'butt'}
        stroke-dasharray={circumference}
        stroke-dashoffset={dashOffset}
        style="transition: stroke-dashoffset 0.35s cubic-bezier(0.22, 1, 0.36, 1);"
      />
    {/if}
  </svg>
  <span class="metric-ring-center num">
    {#if label}
      <span class="metric-ring-val">{label}</span>
    {/if}
    {#if sub}
      <span class="metric-ring-sub">{sub}</span>
    {/if}
  </span>
</span>
