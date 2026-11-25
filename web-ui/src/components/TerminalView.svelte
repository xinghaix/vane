<script>
  import Icons from './Icons.svelte';
  import { copyText } from '../lib/helpers.js';

  let {
    t,
    lang,
    visible = true,
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

  function ansi256ToHex(n) {
    const idx = Math.max(0, Math.min(255, n | 0));
    if (idx < 8) return ANSI_COLORS[30 + idx] || '#e2e8f0';
    if (idx < 16) return ANSI_COLORS[90 + (idx - 8)] || '#f8fafc';
    if (idx < 232) {
      const c = idx - 16;
      const r = Math.floor(c / 36);
      const g = Math.floor((c % 36) / 6);
      const b = c % 6;
      const map = [0, 95, 135, 175, 215, 255];
      return `rgb(${map[r]},${map[g]},${map[b]})`;
    }
    const v = 8 + (idx - 232) * 10;
    return `rgb(${v},${v},${v})`;
  }

  let target = $state('host');
  let lastNonce = -1;
  let reauthPassword = $state('');
  let ptySocket = $state(null);
  let connState = $state('disconnected'); // disconnected | connecting | connected
  let rawScreen = $state('');
  let lineInput = $state('');
  let viewportEl = $state(null);
  let gridCols = $state(100);
  let gridRows = $state(28);
  let resizeTimer = null;

  let runningAllowedContainers = $derived((containers || []).filter((c) => c.state === 'running' && !c.protected));
  let hasCustomTargetOption = $derived(
    target.startsWith('container:') &&
      !runningAllowedContainers.some((c) => `container:${c.name || c.id}` === target)
  );

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
      if (resizeTimer) clearTimeout(resizeTimer);
      if (ptySocket) {
        ptySocket.close();
        ptySocket = null;
      }
    };
  });

  $effect(() => {
    if (!viewportEl || typeof ResizeObserver === 'undefined') return;
    const ro = new ResizeObserver(() => {
      if (!visible) return;
      if (resizeTimer) clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => {
        resizeTimer = null;
        const { cols, rows } = estimateGrid();
        gridCols = cols;
        gridRows = rows;
        sendResize();
      }, 100);
    });
    ro.observe(viewportEl);
    return () => ro.disconnect();
  });

  $effect(() => {
    if (!visible) return;
    queueMicrotask(() => {
      const { cols, rows } = estimateGrid();
      gridCols = cols;
      gridRows = rows;
      sendResize();
    });
  });

  function applyPtyChunk(current, raw) {
    let str = String(raw || '').replace(/\r\n/g, '\n');

    // 处理清屏控制序列 (\x1b[2J / \x1b[3J / \x1b[H\x1b[J)
    const clearParts = str.split(/\x1b\[(?:2|3)J|\x1b\[H\x1b\[J/);
    let buf = current;
    if (clearParts.length > 1) {
      buf = '';
      str = clearParts[clearParts.length - 1];
    }

    // 剥离 OSC、字符集与非 SGR 的 CSI 控制序列，保留 \x1b[...m 配色转义
    str = str
      .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, '')
      .replace(/\x1b\[[0-9;?]*[A-Za-ln-z]/g, '')
      .replace(/\x1b\([A-Z0-9]|\x1b[=>NOM]/g, '');

    if (str.includes('\r') || str.includes('\x08')) {
      for (let i = 0; i < str.length; i++) {
        const ch = str[i];
        if (ch === '\x1b' && str[i + 1] === '[') {
          const end = str.indexOf('m', i + 2);
          if (end !== -1 && end - i <= 32) {
            buf += str.slice(i, end + 1);
            i = end;
            continue;
          }
        }
        if (ch === '\r') {
          const nl = buf.lastIndexOf('\n');
          buf = nl >= 0 ? buf.slice(0, nl + 1) : '';
        } else if (ch === '\x08') {
          const nl = buf.lastIndexOf('\n');
          // 若当前行末尾不是转义符且有字符，则退格删除最后一个可见字符
          if (buf.length > nl + 1) {
            if (buf.endsWith('m')) {
              const esc = buf.lastIndexOf('\x1b[');
              if (esc > nl && /^\x1b\[[0-9;]*m$/.test(buf.slice(esc))) {
                const beforeEsc = buf.slice(0, esc);
                if (beforeEsc.length > nl + 1) {
                  buf = beforeEsc.slice(0, -1) + buf.slice(esc);
                }
                continue;
              }
            }
            buf = buf.slice(0, -1);
          }
        } else {
          buf += ch;
        }
      }
    } else {
      buf += str;
    }

    const MAX_LEN = 65536;
    if (buf.length > MAX_LEN) {
      const cut = buf.indexOf('\n', buf.length - MAX_LEN);
      buf = cut >= 0 ? buf.slice(cut + 1) : buf.slice(-MAX_LEN);
    }
    return buf;
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
      for (let i = 0; i < codes.length; i++) {
        const c = codes[i];
        if (Number.isNaN(c) || c === 0) {
          curColor = '';
          curBold = false;
        } else if (c === 1) {
          curBold = true;
        } else if (c === 22) {
          curBold = false;
        } else if (c === 39) {
          curColor = '';
        } else if (c === 38 || c === 48) {
          const mode = codes[i + 1];
          if (mode === 5 && i + 2 < codes.length) {
            if (c === 38 && !Number.isNaN(codes[i + 2])) {
              curColor = ansi256ToHex(codes[i + 2]);
            }
            i += 2;
          } else if (mode === 2 && i + 4 < codes.length) {
            if (c === 38) {
              const r = Math.max(0, Math.min(255, codes[i + 2] || 0));
              const g = Math.max(0, Math.min(255, codes[i + 3] || 0));
              const b = Math.max(0, Math.min(255, codes[i + 4] || 0));
              curColor = `rgb(${r},${g},${b})`;
            }
            i += 4;
          }
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
    if (!viewportEl || viewportEl.clientWidth <= 0 || viewportEl.clientHeight <= 0) {
      return { cols: gridCols || 100, rows: gridRows || 28 };
    }
    const cols = Math.max(40, Math.min(240, Math.floor((viewportEl.clientWidth - 32) / 8)));
    const rows = Math.max(16, Math.min(80, Math.floor((viewportEl.clientHeight - 32) / 19)));
    return { cols, rows };
  }

  function sendResize() {
    const { cols, rows } = estimateGrid();
    gridCols = cols;
    gridRows = rows;
    if (!ptySocket || ptySocket.readyState !== WebSocket.OPEN) return;
    ptySocket.send(`\u0000resize:${JSON.stringify({ cols, rows })}`);
  }

  async function connectPty() {
    if (connState === 'connecting') return;
    connState = 'connecting';
    try {
      const { cols, rows } = estimateGrid();
      gridCols = cols;
      gridRows = rows;
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
        queueMicrotask(() => viewportEl?.focus());
      };
      ws.onmessage = (ev) => {
        const shouldStick =
          !viewportEl ||
          viewportEl.scrollHeight - viewportEl.scrollTop - viewportEl.clientHeight < 48;
        rawScreen = applyPtyChunk(rawScreen, ev.data);
        if (shouldStick) {
          queueMicrotask(() => {
            if (viewportEl) viewportEl.scrollTop = viewportEl.scrollHeight;
          });
        }
      };
      ws.onerror = () => {
        showToast(lang === 'en' ? 'PTY WebSocket connection error' : '终端 WebSocket 连接异常', 'error');
      };
      ws.onclose = () => {
        if (ptySocket === ws) {
          ptySocket = null;
          connState = 'disconnected';
        }
      };
      ptySocket = ws;
    } catch (err) {
      connState = 'disconnected';
      showToast(err.message, 'error');
    }
  }

  function reconnectPty() {
    if (ptySocket) {
      const old = ptySocket;
      ptySocket = null;
      connState = 'disconnected';
      old.close();
    }
    connectPty();
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

  async function copyScreenOutput() {
    const plain = rawScreen.replace(/\x1b\[[0-9;]*m/g, '');
    if (!plain) return;
    if (await copyText(plain)) showToast(t.copied, 'success');
    else showToast(t.copyFailed, 'error');
  }

  function handleTerminalKeydown(e) {
    if (e.isComposing) return;
    if (!ptySocket || ptySocket.readyState !== WebSocket.OPEN) return;
    if (e.ctrlKey && !e.metaKey && !e.altKey) {
      const k = e.key.toLowerCase();
      if (k === 'c' && window.getSelection?.()?.toString()) {
        return; // 允许用户复制选中的终端输出
      }
      if (k.length === 1 && k >= 'a' && k <= 'z') {
        e.preventDefault();
        if (k === 'l') rawScreen = '';
        sendRaw(String.fromCharCode(k.charCodeAt(0) - 96));
        return;
      }
    }
    if (e.key === 'Enter') { e.preventDefault(); sendRaw('\r'); }
    else if (e.key === 'Backspace') { e.preventDefault(); sendRaw('\x7f'); }
    else if (e.key === 'Tab') { e.preventDefault(); sendRaw('\t'); }
    else if (e.key === 'Escape') { e.preventDefault(); sendRaw('\x1b'); }
    else if (e.key === 'Home') { e.preventDefault(); sendRaw('\x1b[H'); }
    else if (e.key === 'End') { e.preventDefault(); sendRaw('\x1b[F'); }
    else if (e.key === 'Delete') { e.preventDefault(); sendRaw('\x1b[3~'); }
    else if (e.key === 'PageUp') { e.preventDefault(); sendRaw('\x1b[5~'); }
    else if (e.key === 'PageDown') { e.preventDefault(); sendRaw('\x1b[6~'); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); sendRaw('\x1b[A'); }
    else if (e.key === 'ArrowDown') { e.preventDefault(); sendRaw('\x1b[B'); }
    else if (e.key === 'ArrowRight') { e.preventDefault(); sendRaw('\x1b[C'); }
    else if (e.key === 'ArrowLeft') { e.preventDefault(); sendRaw('\x1b[D'); }
    else if (e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) {
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
        <span class="badge badge-muted mono">{gridCols}×{gridRows}</span>
      </div>
      <div style="font-size:12px;color:var(--text-secondary);">{t.term.subtitle}</div>
    </div>
    <form
      class="btn-group"
      onsubmit={(e) => {
        e.preventDefault();
        if (!ptySocket) connectPty();
      }}
    >
      <select
        class="control-compact"
        style="width:210px;"
        aria-label={t.term.hostShell}
        bind:value={target}
        disabled={Boolean(ptySocket)}
      >
        <option value="host">{t.term.hostShell}</option>
        {#if hasCustomTargetOption}
          <option value={target}>Docker: {target.slice('container:'.length)}</option>
        {/if}
        {#each runningAllowedContainers as c (c.id)}
          <option value={`container:${c.name || c.id}`}>Docker: {c.name || c.id}</option>
        {/each}
      </select>
      {#if requireReauth && !ptySocket}
        <input
          type="password"
          class="control-compact"
          style="width:165px;"
          autocomplete="current-password"
          aria-label={t.term.reauthPh}
          placeholder={t.term.reauthPh}
          bind:value={reauthPassword}
        />
      {/if}
      {#if !ptySocket}
        <button type="submit" class="btn btn-primary btn-sm" disabled={connState === 'connecting'}>
          {connState === 'connecting' ? t.term.connecting : t.term.connect}
        </button>
      {:else}
        <button type="button" class="btn btn-danger btn-sm" onclick={() => ptySocket?.close()}>
          {t.term.disconnect}
        </button>
      {/if}
    </form>
  </div>

  <!-- 触屏 / 快捷控制键栏（onmousedown preventDefault 防止抢走终端焦点） -->
  {#if ptySocket || rawScreen}
    <div class="btn-group" style="margin-bottom:10px;align-items:center;" aria-label={t.cfg.lblQuickKeys}>
      {#if ptySocket}
        <button type="button" class="btn btn-xs mono" onmousedown={(e) => e.preventDefault()} onclick={() => sendRaw('\x1b')}>Esc</button>
        <button type="button" class="btn btn-xs mono" onmousedown={(e) => e.preventDefault()} onclick={() => sendRaw('\t')}>Tab</button>
        <button type="button" class="btn btn-xs mono" onmousedown={(e) => e.preventDefault()} onclick={() => sendRaw('\x03')}>Ctrl+C</button>
        <button type="button" class="btn btn-xs mono" onmousedown={(e) => e.preventDefault()} onclick={() => sendRaw('\x04')}>Ctrl+D</button>
        <button type="button" class="btn btn-xs mono" onmousedown={(e) => e.preventDefault()} onclick={() => sendRaw('\x1a')}>Ctrl+Z</button>
        <button
          type="button"
          class="btn btn-xs mono"
          onmousedown={(e) => e.preventDefault()}
          onclick={() => {
            rawScreen = '';
            sendRaw('\x0c');
          }}
        >
          Ctrl+L
        </button>
        <button type="button" class="btn btn-xs mono" onmousedown={(e) => e.preventDefault()} onclick={() => sendRaw('\x1b[D')}>←</button>
        <button type="button" class="btn btn-xs mono" onmousedown={(e) => e.preventDefault()} onclick={() => sendRaw('\x1b[A')}>↑</button>
        <button type="button" class="btn btn-xs mono" onmousedown={(e) => e.preventDefault()} onclick={() => sendRaw('\x1b[B')}>↓</button>
        <button type="button" class="btn btn-xs mono" onmousedown={(e) => e.preventDefault()} onclick={() => sendRaw('\x1b[C')}>→</button>
      {/if}
      <button type="button" class="btn btn-xs" onmousedown={(e) => e.preventDefault()} onclick={() => (rawScreen = '')}>
        {t.cfg.lblClearScreen}
      </button>
      <button
        type="button"
        class="btn btn-xs"
        disabled={!rawScreen}
        onmousedown={(e) => e.preventDefault()}
        onclick={copyScreenOutput}
      >
        <Icons name="copy" size={12} />
        <span>{t.cfg.lblCopyOut}</span>
      </button>
      <button
        type="button"
        class="btn btn-xs"
        disabled={connState === 'connecting' || (requireReauth && !reauthPassword && !ptySocket)}
        onclick={reconnectPty}
      >
        {t.cfg.lblReconnect}
      </button>
    </div>
  {/if}

  <!-- 交互式 PTY 视口（支持直接键盘输入、粘贴文本、ANSI SGR/256/TrueColor 配色；下方保留命令栏兼容移动端输入法） -->
  <div
    bind:this={viewportEl}
    role="textbox"
    aria-multiline="true"
    aria-label="PTY Terminal Viewport"
    tabindex="0"
    onkeydown={handleTerminalKeydown}
    onpaste={handleTerminalPaste}
    class="mono"
    style="background:#05070a;color:#e2e8f0;padding:16px;border-radius:12px;min-height:340px;max-height:520px;overflow-y:auto;font-size:13px;line-height:1.45;white-space:pre-wrap;word-break:break-all;outline:none;border:1px solid var(--border-subtle);"
  >
    {#if segments.length > 0}
      {#each segments as seg, i (i)}
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
        aria-label={t.term.inputPh}
        bind:value={lineInput}
        placeholder={t.term.inputPh}
      />
      <button type="submit" class="btn btn-primary">{t.term.send}</button>
    </form>
  {/if}
</div>
