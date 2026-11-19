<script>
  let {
    t,
    lang,
    initialTarget = 'host',
    targetNonce = 0,
    containers = [],
    requireReauth = false,
    apiFetch,
    showToast,
  } = $props();

  const ANSI_COLORS = {
    30: '#475569',
    31: '#f87171',
    32: '#34d399',
    33: '#fbbf24',
    34: '#60a5fa',
    35: '#c084fc',
    36: '#22d3ee',
    37: '#e2e8f0',
    90: '#94a3b8',
    91: '#fca5a5',
    92: '#6ee7b7',
    93: '#fde047',
    94: '#93c5fd',
    95: '#d8b4fe',
    96: '#67e8f9',
    97: '#f8fafc',
  };

  let target = $state('host');
  let lastNonce = -1;
  let reauthPassword = $state('');
  let ptySocket = $state(null);
  let connState = $state('disconnected'); // disconnected | connecting | connected
  let rawScreen = $state('');
  let lineInput = $state('');
  let viewportEl = $state(null);

  $effect(() => {
    const nonce = targetNonce;
    const nextTarget = initialTarget || 'host';
    if (nonce !== lastNonce) {
      lastNonce = nonce;
      if (nextTarget !== target) {
        if (ptySocket) {
          ptySocket.close();
          ptySocket = null;
          connState = 'disconnected';
        }
        target = nextTarget;
      }
    }
  });

  $effect(() => {
    return () => {
      if (ptySocket) {
        ptySocket.close();
        ptySocket = null;
      }
    };
  });

  function sanitizePtyChunk(str) {
    // 统一换行，剥离 OSC 与非 SGR 的 CSI 控制序列，保留 \x1b[...m 配色转义
    return String(str || '')
      .replace(/\r\n/g, '\n')
      .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, '')
      .replace(/\x1b\[[0-9;?]*[A-Za-ln-z]/g, '')
      .replace(/\x1b\([A-Z0-9]|\x1b[=>NOM]/g, '');
  }

  function parseAnsiSgr(text) {
    if (!text) return [];
    const segs = [];
    const re = /\x1b\[([0-9;]*)m/g;
    let lastIdx = 0;
    let curColor = '';
    let curBold = false;
    let match;

    while ((match = re.exec(text)) !== null) {
      if (match.index > lastIdx) {
        segs.push({ text: text.slice(lastIdx, match.index), color: curColor, bold: curBold });
      }
      const codes = match[1] ? match[1].split(';').map((n) => parseInt(n, 10)) : [0];
      for (const c of codes) {
        if (Number.isNaN(c) || c === 0) {
          curColor = '';
          curBold = false;
        } else if (c === 1) {
          curBold = true;
        } else if (c === 22) {
          curBold = false;
        } else if (c === 39) {
          curColor = '';
        } else if (ANSI_COLORS[c]) {
          curColor = ANSI_COLORS[c];
        }
      }
      lastIdx = re.lastIndex;
    }
    if (lastIdx < text.length) {
      segs.push({ text: text.slice(lastIdx), color: curColor, bold: curBold });
    }
    return segs;
  }

  let segments = $derived(parseAnsiSgr(rawScreen));

  function estimateGrid() {
    if (!viewportEl) return { cols: 100, rows: 28 };
    const cols = Math.max(40, Math.min(240, Math.floor((viewportEl.clientWidth - 32) / 8)));
    const rows = Math.max(16, Math.min(80, Math.floor((viewportEl.clientHeight - 32) / 19)));
    return { cols, rows };
  }

  function sendResize() {
    if (!ptySocket || ptySocket.readyState !== WebSocket.OPEN) return;
    const { cols, rows } = estimateGrid();
    ptySocket.send(`\u0000resize:${JSON.stringify({ cols, rows })}`);
  }

  async function connectPty() {
    if (connState === 'connecting') return;
    connState = 'connecting';
    try {
      const { cols, rows } = estimateGrid();
      const { ticket } = await apiFetch('/api/pty/ticket', {
        method: 'POST',
        body: JSON.stringify({ target, reauth_password: reauthPassword }),
      });
      reauthPassword = '';
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const ws = new WebSocket(
        `${proto}//${location.host}/api/pty/ws?ticket=${encodeURIComponent(ticket)}&target=${encodeURIComponent(target)}&cols=${cols}&rows=${rows}`
      );
      rawScreen = '';
      ws.onopen = () => {
        connState = 'connected';
        sendResize();
      };
      ws.onmessage = (ev) => {
        const chunk = sanitizePtyChunk(ev.data);
        const combined = rawScreen + chunk;
        if (combined.length > 32768) {
          const cut = combined.indexOf('\n', combined.length - 32768);
          rawScreen = cut >= 0 ? combined.slice(cut + 1) : combined.slice(-32768);
        } else {
          rawScreen = combined;
        }
        queueMicrotask(() => {
          if (viewportEl) viewportEl.scrollTop = viewportEl.scrollHeight;
        });
      };
      ws.onerror = () => {
        showToast(lang === 'en' ? 'PTY WebSocket connection error' : '终端 WebSocket 连接异常', 'error');
      };
      ws.onclose = () => {
        ptySocket = null;
        connState = 'disconnected';
      };
      ptySocket = ws;
    } catch (err) {
      connState = 'disconnected';
      showToast(err.message, 'error');
    }
  }

  function sendRaw(data) {
    if (ptySocket && ptySocket.readyState === WebSocket.OPEN) {
      ptySocket.send(data);
    }
  }

  function submitLine(e) {
    e.preventDefault();
    if (!ptySocket) return;
    sendRaw(lineInput + '\r');
    lineInput = '';
  }

  function handleTerminalPaste(e) {
    if (!ptySocket || ptySocket.readyState !== WebSocket.OPEN) return;
    const pasted = e.clipboardData?.getData('text/plain');
    if (pasted) {
      e.preventDefault();
      sendRaw(pasted);
    }
  }

  function handleTerminalKeydown(e) {
    if (!ptySocket || ptySocket.readyState !== WebSocket.OPEN) return;
    if (e.ctrlKey && !e.metaKey && !e.altKey) {
      const k = e.key.toLowerCase();
      if (k === 'c') { e.preventDefault(); sendRaw('\x03'); return; }
      if (k === 'd') { e.preventDefault(); sendRaw('\x04'); return; }
      if (k === 'l') { e.preventDefault(); rawScreen = ''; sendRaw('\x0c'); return; }
    }
    if (e.key === 'Enter') { e.preventDefault(); sendRaw('\r'); }
    else if (e.key === 'Backspace') { e.preventDefault(); sendRaw('\x7f'); }
    else if (e.key === 'Tab') { e.preventDefault(); sendRaw('\t'); }
    else if (e.key === 'Escape') { e.preventDefault(); sendRaw('\x1b'); }
    else if (e.key === 'Home') { e.preventDefault(); sendRaw('\x1b[H'); }
    else if (e.key === 'End') { e.preventDefault(); sendRaw('\x1b[F'); }
    else if (e.key === 'Delete') { e.preventDefault(); sendRaw('\x1b[3~'); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); sendRaw('\x1b[A'); }
    else if (e.key === 'ArrowDown') { e.preventDefault(); sendRaw('\x1b[B'); }
    else if (e.key === 'ArrowRight') { e.preventDefault(); sendRaw('\x1b[C'); }
    else if (e.key === 'ArrowLeft') { e.preventDefault(); sendRaw('\x1b[D'); }
    else if (e.key.length === 1 && !e.ctrlKey && !e.metaKey) {
      e.preventDefault();
      sendRaw(e.key);
    }
  }
</script>

<svelte:window onresize={sendResize} />

<div class="card">
  <div class="card-header">
    <div>
      <div class="card-title">
        <span>{t.nav.web_terminal}</span>
        <span class="badge {connState === 'connected' ? 'badge-ok' : connState === 'connecting' ? 'badge-warn' : 'badge-muted'}">
          <span class="status-dot {connState === 'connected' ? 'ok' : connState === 'connecting' ? 'warn' : 'muted'}"></span>
          <span>{connState === 'connected' ? t.term.connected : connState === 'connecting' ? t.term.connecting : t.term.disconnected}</span>
        </span>
      </div>
      <div style="font-size:12px;color:var(--text-secondary);">{t.term.subtitle}</div>
    </div>
    <div class="btn-group">
      <select style="width:210px;min-height:38px;font-size:13px;" bind:value={target} disabled={Boolean(ptySocket)}>
        <option value="host">{t.term.hostShell}</option>
        {#each (containers || []).filter((c) => c.state === 'running' && !c.protected) as c}
          <option value={`container:${c.name || c.id}`}>Docker: {c.name || c.id}</option>
        {/each}
      </select>
      {#if requireReauth && !ptySocket}
        <input
          type="password"
          style="width:160px;min-height:38px;font-size:13px;"
          placeholder={t.term.reauthPh}
          bind:value={reauthPassword}
        />
      {/if}
      {#if !ptySocket}
        <button type="button" class="btn btn-primary btn-sm" disabled={connState === 'connecting'} onclick={connectPty}>
          {connState === 'connecting' ? t.term.connecting : t.term.connect}
        </button>
      {:else}
        <button type="button" class="btn btn-danger btn-sm" onclick={() => ptySocket.close()}>
          {t.term.disconnect}
        </button>
      {/if}
    </div>
  </div>

  <!-- 触屏 / 快捷控制键栏 -->
  {#if ptySocket}
    <div class="btn-group" style="margin-bottom:10px;">
      <button type="button" class="btn btn-xs mono" onclick={() => sendRaw('\x1b')}>Esc</button>
      <button type="button" class="btn btn-xs mono" onclick={() => sendRaw('\t')}>Tab</button>
      <button type="button" class="btn btn-xs mono" onclick={() => sendRaw('\x03')}>Ctrl+C</button>
      <button type="button" class="btn btn-xs mono" onclick={() => sendRaw('\x04')}>Ctrl+D</button>
      <button type="button" class="btn btn-xs mono" onclick={() => sendRaw('\x1b[A')}>↑</button>
      <button type="button" class="btn btn-xs mono" onclick={() => sendRaw('\x1b[B')}>↓</button>
      <button type="button" class="btn btn-xs" onclick={() => { rawScreen = ''; }}>Clear</button>
    </div>
  {/if}

  <!-- 交互式 PTY 视口（支持直接键盘输入、粘贴文本、ANSI SGR 配色；下方保留命令栏兼容移动端输入法） -->
  <div
    bind:this={viewportEl}
    role="textbox"
    aria-label="PTY Terminal Viewport"
    tabindex="0"
    onkeydown={handleTerminalKeydown}
    onpaste={handleTerminalPaste}
    class="mono"
    style="background:#05070a;color:#e2e8f0;padding:16px;border-radius:12px;min-height:340px;max-height:500px;overflow-y:auto;font-size:13px;line-height:1.45;white-space:pre-wrap;word-break:break-all;outline:none;border:1px solid var(--border-subtle);"
  >
    {#if segments.length > 0}
      {#each segments as seg}
        {#if seg.color || seg.bold}
          <span style={`${seg.color ? `color:${seg.color};` : ''}${seg.bold ? 'font-weight:700;' : ''}`}>{seg.text}</span>
        {:else}
          {seg.text}
        {/if}
      {/each}
    {:else if !ptySocket}
      <span style="color:#94a3b8;">{t.term.placeholder}</span>
    {/if}
  </div>

  {#if ptySocket}
    <form onsubmit={submitLine} style="display:flex;gap:8px;margin-top:12px;">
      <input
        type="text"
        class="mono"
        bind:value={lineInput}
        placeholder={t.term.inputPh}
      />
      <button type="submit" class="btn btn-primary">{t.term.send}</button>
    </form>
  {/if}
</div>
