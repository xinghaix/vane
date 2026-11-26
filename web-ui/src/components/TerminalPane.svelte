<script>
  import Icons from './Icons.svelte';
  import Select from './Select.svelte';
  import { copyText } from '../lib/helpers.js';

  let {
    t,
    lang,
    active = true,
    initialTarget = 'host',
    initialShell = '',
    autoConnect = false,
    availableShells = [],
    defaultHostShell = 'bash',
    shellsLoaded = false,
    containers = [],
    requireReauth = false,
    dockerRequireReauth = false,
    onUnlockModule = null,
    requestReauth = null,
    apiFetch,
    showToast,
    onStateChange,
    onBackgroundActivity,
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

  function collapseCells(cells) {
    const segs = [];
    for (const cell of cells) {
      const last = segs[segs.length - 1];
      if (last && last.color === cell.color && last.bold === cell.bold) {
        last.text += cell.ch;
      } else {
        segs.push({ text: cell.ch, color: cell.color, bold: cell.bold });
      }
    }
    return segs;
  }

  let target = $state('host');
  let selectedShell = $state('bash');
  let shellUserPicked = $state(false);
  let initialized = false;
  let ptySocket = $state(null);
  let connState = $state('disconnected'); // disconnected | connecting | connected
  let lineInput = $state('');
  let viewportEl = $state(null);
  let viewportFocused = $state(false);
  let cursorTyping = $state(false);
  let gridCols = $state(100);
  let gridRows = $state(24);
  let autoConnectDone = false;

  // 终端屏幕缓冲
  let historyLines = $state([]);
  let activeLine = $state([]);
  let cursorCol = $state(0);
  let cursorHidden = $state(false);

  let curColor = '';
  let curBold = false;
  let pendingEsc = '';
  let justHomed = false;
  let lineSeq = 0;
  let resizeTimer = null;
  let typingTimer = null;

  let hasOutput = $derived(historyLines.length > 0 || activeLine.length > 0);
  let beforeCursorSegs = $derived(collapseCells(activeLine.slice(0, cursorCol)));
  let cursorCell = $derived(
    cursorCol < activeLine.length
      ? activeLine[cursorCol]
      : { ch: '\u00a0', color: '', bold: false }
  );
  let afterCursorSegs = $derived(
    cursorCol + 1 < activeLine.length ? collapseCells(activeLine.slice(cursorCol + 1)) : []
  );

  let runningAllowedContainers = $derived((containers || []).filter((c) => c.state === 'running' && !c.protected));
  let hasCustomTargetOption = $derived(
    target.startsWith('container:') &&
      !runningAllowedContainers.some((c) => `container:${c.name || c.id}` === target)
  );

  $effect(() => {
    if (!initialized) {
      initialized = true;
      const t0 = initialTarget || 'host';
      target = t0;
      if (initialShell) {
        selectedShell = initialShell;
        shellUserPicked = true;
      } else {
        selectedShell = t0 === 'host' ? (defaultHostShell || 'bash') : 'auto';
      }
    }
    if (shellsLoaded && !shellUserPicked && target === 'host' && connState === 'disconnected') {
      selectedShell = defaultHostShell || 'bash';
    }
  });

  $effect(() => {
    onStateChange?.({
      connState,
      target,
      shell: selectedShell,
      hasOutput,
    });
  });

  $effect(() => {
    if (
      autoConnect &&
      !autoConnectDone &&
      !requireReauth &&
      !(target.startsWith('container:') && dockerRequireReauth) &&
      shellsLoaded &&
      connState === 'disconnected'
    ) {
      autoConnectDone = true;
      queueMicrotask(() => connectPty());
    }
  });

  $effect(() => {
    return () => {
      if (resizeTimer) clearTimeout(resizeTimer);
      if (typingTimer) clearTimeout(typingTimer);
      if (ptySocket) {
        ptySocket.close();
        ptySocket = null;
      }
    };
  });

  $effect(() => {
    if (!viewportEl || typeof ResizeObserver === 'undefined') return;
    const ro = new ResizeObserver(() => {
      if (!active) return;
      if (resizeTimer) clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => {
        resizeTimer = null;
        sendResize();
      }, 100);
    });
    ro.observe(viewportEl);
    return () => ro.disconnect();
  });

  $effect(() => {
    if (!active) return;
    queueMicrotask(() => {
      sendResize();
      if (ptySocket && connState === 'connected') {
        viewportEl?.focus();
      }
    });
  });

  function onTargetChange() {
    shellUserPicked = false;
    if (target === 'host') {
      selectedShell = defaultHostShell || (availableShells.some((s) => s.id === 'bash') ? 'bash' : 'sh');
    } else {
      selectedShell = 'auto';
    }
  }

  function resetScreen() {
    historyLines = [];
    activeLine = [];
    cursorCol = 0;
    cursorHidden = false;
    curColor = '';
    curBold = false;
    pendingEsc = '';
    justHomed = false;
  }

  function bumpCursorTyping() {
    cursorTyping = true;
    if (typingTimer) clearTimeout(typingTimer);
    typingTimer = setTimeout(() => {
      cursorTyping = false;
      typingTimer = null;
    }, 450);
  }

  function applySgr(params) {
    const codes = params ? params.split(';').map((n) => (n === '' ? 0 : parseInt(n, 10))) : [0];
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
  }

  function processPtyChunk(raw) {
    const data = pendingEsc + String(raw || '');
    pendingEsc = '';

    let nextHistory = historyLines.slice();
    let nextActive = activeLine.slice();
    let col = cursorCol;
    let hidden = cursorHidden;
    const maxCol = Math.max(240, gridCols * 2);

    for (let i = 0; i < data.length; i++) {
      const ch = data[i];
      if (ch === '\x1b') {
        if (i + 1 >= data.length) {
          pendingEsc = data.slice(i);
          break;
        }
        const next = data[i + 1];
        if (next === '[') {
          let j = i + 2;
          while (j < data.length) {
            const cc = data.charCodeAt(j);
            if (cc >= 0x40 && cc <= 0x7e) break;
            j++;
          }
          if (j >= data.length) {
            if (data.length - i < 64) {
              pendingEsc = data.slice(i);
            }
            break;
          }
          const params = data.slice(i + 2, j);
          const cmd = data[j];
          const wasHomed = justHomed;
          justHomed = false;

          if (cmd === 'm') {
            applySgr(params);
          } else if (cmd === 'H' || cmd === 'f') {
            if (!params || params === '1;1' || params === ';') {
              justHomed = true;
            }
          } else if (cmd === 'J') {
            const p = parseInt(params || '0', 10) || 0;
            if (p === 2 || p === 3 || (p === 0 && wasHomed)) {
              nextHistory = [];
              nextActive = [];
              col = 0;
            } else if (p === 0) {
              nextActive.length = Math.min(nextActive.length, col);
            }
          } else if (cmd === 'K') {
            const p = parseInt(params || '0', 10) || 0;
            if (p === 0) {
              nextActive.length = Math.min(nextActive.length, col);
            } else if (p === 1) {
              const end = Math.min(col, nextActive.length);
              for (let k = 0; k < end; k++) {
                nextActive[k] = { ch: ' ', color: '', bold: false };
              }
            } else if (p === 2) {
              nextActive = [];
              col = 0;
            }
          } else if (cmd === 'D') {
            const n = Math.max(1, parseInt(params || '1', 10) || 1);
            col = Math.max(0, col - n);
          } else if (cmd === 'C') {
            const n = Math.max(1, parseInt(params || '1', 10) || 1);
            col = Math.min(maxCol, col + n);
            while (nextActive.length < col) {
              nextActive.push({ ch: ' ', color: '', bold: false });
            }
          } else if (cmd === 'G') {
            const n = Math.max(1, parseInt(params || '1', 10) || 1);
            col = Math.min(maxCol, n - 1);
            while (nextActive.length < col) {
              nextActive.push({ ch: ' ', color: '', bold: false });
            }
          } else if (cmd === 'P') {
            const n = Math.max(1, parseInt(params || '1', 10) || 1);
            nextActive.splice(col, n);
          } else if (cmd === '@') {
            const n = Math.min(256, Math.max(1, parseInt(params || '1', 10) || 1));
            const blanks = Array.from({ length: n }, () => ({ ch: ' ', color: '', bold: false }));
            nextActive.splice(col, 0, ...blanks);
          } else if (cmd === 'l' && params === '?25') {
            hidden = true;
          } else if (cmd === 'h' && params === '?25') {
            hidden = false;
          }
          i = j;
          continue;
        } else if (next === ']') {
          let j = i + 2;
          let found = false;
          while (j < data.length) {
            if (data[j] === '\x07') {
              found = true;
              break;
            }
            if (data[j] === '\x1b' && data[j + 1] === '\\') {
              j++;
              found = true;
              break;
            }
            j++;
          }
          if (!found) {
            if (data.length - i < 256) pendingEsc = data.slice(i);
            break;
          }
          i = j;
          continue;
        } else if (next === '(' || next === ')') {
          if (i + 2 >= data.length) {
            pendingEsc = data.slice(i);
            break;
          }
          i += 2;
          continue;
        } else {
          i += 1;
          continue;
        }
      }

      justHomed = false;

      if (ch === '\r') {
        col = 0;
      } else if (ch === '\n') {
        nextHistory.push({
          id: ++lineSeq,
          segs: collapseCells(nextActive),
          plain: nextActive.map((c) => c.ch).join('').trimEnd(),
        });
        nextActive = [];
        col = 0;
      } else if (ch === '\x08') {
        col = Math.max(0, col - 1);
      } else if (ch === '\t') {
        const spaces = 8 - (col % 8);
        for (let s = 0; s < spaces && col < maxCol; s++) {
          while (nextActive.length < col) {
            nextActive.push({ ch: ' ', color: '', bold: false });
          }
          nextActive[col] = { ch: ' ', color: curColor, bold: curBold };
          col++;
        }
      } else {
        const code = data.charCodeAt(i);
        if (code < 0x20 || code === 0x7f) continue;
        let glyph = ch;
        if (code >= 0xd800 && code <= 0xdbff && i + 1 < data.length) {
          glyph = ch + data[i + 1];
          i++;
        }
        while (nextActive.length < col) {
          nextActive.push({ ch: ' ', color: '', bold: false });
        }
        nextActive[col] = { ch: glyph, color: curColor, bold: curBold };
        col++;
      }
    }

    if (nextHistory.length > 1000) {
      nextHistory = nextHistory.slice(nextHistory.length - 1000);
    }

    historyLines = nextHistory;
    activeLine = nextActive;
    cursorCol = col;
    cursorHidden = hidden;
  }

  function estimateGrid() {
    if (!viewportEl || viewportEl.clientWidth <= 0 || viewportEl.clientHeight <= 0) {
      return { cols: gridCols || 100, rows: gridRows || 24 };
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

  async function unlockRequiredModule(mod) {
    if (onUnlockModule) return onUnlockModule(mod);
    if (!requestReauth) return null;
    const modName = t.nav?.[mod] || mod;
    return requestReauth({
      title: t.reauth.moduleTitle.replace('{name}', modName),
      description: t.reauth.moduleDesc,
      actionLabel: t.reauth.unlockBtn,
      unlockModule: mod,
    });
  }

  async function connectPty(retryState = {}) {
    if (connState === 'connecting') return;
    let reauthToken = retryState.reauthToken || '';
    const isContainerTarget = target.startsWith('container:');
    if (isContainerTarget && dockerRequireReauth && !retryState.unlockedDocker) {
      const tok = await unlockRequiredModule('docker');
      if (!tok) return;
      retryState = { ...retryState, unlockedDocker: true };
    }
    if (requireReauth && !reauthToken && !retryState.unlockedTerminal) {
      if (!requestReauth) {
        showToast(t.errors.REAUTH_REQUIRED, 'error');
        return;
      }
      const tok = await requestReauth({
        title: t.reauth.ptyTitle,
        description: t.reauth.ptyDesc,
        actionLabel: t.term.connect,
        unlockModule: 'web_terminal',
      });
      if (!tok) return;
      reauthToken = tok;
      retryState = { ...retryState, unlockedTerminal: true };
    }
    connState = 'connecting';
    try {
      const { cols, rows } = estimateGrid();
      gridCols = cols;
      gridRows = rows;
      const shellParam = selectedShell || (target === 'host' ? defaultHostShell : 'auto');
      const { ticket } = await apiFetch('/api/pty/ticket', {
        method: 'POST',
        body: JSON.stringify({ target, shell: shellParam, reauth_token: reauthToken }),
      });
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const ws = new WebSocket(
        `${proto}//${location.host}/api/pty/ws?ticket=${encodeURIComponent(ticket)}&target=${encodeURIComponent(target)}&shell=${encodeURIComponent(shellParam)}&cols=${cols}&rows=${rows}`
      );
      resetScreen();
      ws.onopen = () => {
        connState = 'connected';
        sendResize();
        if (active) {
          queueMicrotask(() => viewportEl?.focus());
        }
      };
      ws.onmessage = (ev) => {
        const shouldStick =
          !viewportEl ||
          viewportEl.scrollHeight - viewportEl.scrollTop - viewportEl.clientHeight < 48;
        processPtyChunk(ev.data);
        bumpCursorTyping();
        if (!active) {
          onBackgroundActivity?.();
        } else if (shouldStick) {
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
      if (err?.status === 403 && err?.code === 'MODULE_REAUTH_REQUIRED') {
        const mod = err?.module || err?.data?.module || (isContainerTarget ? 'docker' : 'web_terminal');
        if (mod === 'docker' && !retryState.retriedDocker) {
          const tok = await unlockRequiredModule('docker');
          if (!tok) return;
          return connectPty({ ...retryState, unlockedDocker: true, retriedDocker: true });
        }
        if (mod === 'web_terminal' && !retryState.retriedTerminal) {
          const tok = await unlockRequiredModule('web_terminal');
          if (!tok) return;
          return connectPty({
            ...retryState,
            unlockedTerminal: true,
            retriedTerminal: true,
            reauthToken: tok,
          });
        }
      }
      if (
        err?.status === 403 &&
        (err?.code === 'REAUTH_REQUIRED' || err?.code === 'MFA_REAUTH_REQUIRED') &&
        !retryState.retriedReauth &&
        requestReauth
      ) {
        const tok = await requestReauth({
          title: t.reauth.ptyTitle,
          description: t.reauth.ptyDesc,
          actionLabel: t.term.connect,
          unlockModule: 'web_terminal',
          requireMfa: Boolean(err?.mfa_required),
        });
        if (!tok) return;
        return connectPty({
          ...retryState,
          unlockedTerminal: true,
          retriedReauth: true,
          reauthToken: tok,
        });
      }
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
      bumpCursorTyping();
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
    const lines = historyLines.map((l) => l.plain);
    const activePlain = activeLine.map((c) => c.ch).join('').trimEnd();
    if (activePlain || lines.length === 0) lines.push(activePlain);
    const plain = lines.join('\n').trimEnd();
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
        return;
      }
      if (k.length === 1 && k >= 'a' && k <= 'z') {
        e.preventDefault();
        if (k === 'l') resetScreen();
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

<!-- 单标签操作工具栏：左侧快捷控制键，右侧目标/Shell/连接控制 -->
<div class="pty-pane-bar">
  <div class="btn-group" aria-label={t.cfg.lblQuickKeys}>
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
          resetScreen();
          sendRaw('\x0c');
        }}
      >
        Ctrl+L
      </button>
      <button type="button" class="btn btn-xs mono" onmousedown={(e) => e.preventDefault()} onclick={() => sendRaw('\x1b[D')}>←</button>
      <button type="button" class="btn btn-xs mono" onmousedown={(e) => e.preventDefault()} onclick={() => sendRaw('\x1b[A')}>↑</button>
      <button type="button" class="btn btn-xs mono" onmousedown={(e) => e.preventDefault()} onclick={() => sendRaw('\x1b[B')}>↓</button>
      <button type="button" class="btn btn-xs mono" onmousedown={(e) => e.preventDefault()} onclick={() => sendRaw('\x1b[C')}>→</button>
    {:else}
      <span class="badge badge-muted">
        <span class="status-dot {connState === 'connecting' ? 'warn' : 'muted'}"></span>
        <span>{connState === 'connecting' ? t.term.connecting : t.term.disconnected}</span>
      </span>
    {/if}
    {#if ptySocket || hasOutput}
      <button type="button" class="btn btn-xs" onmousedown={(e) => e.preventDefault()} onclick={resetScreen}>
        {t.cfg.lblClearScreen}
      </button>
      <button
        type="button"
        class="btn btn-xs"
        disabled={!hasOutput}
        onmousedown={(e) => e.preventDefault()}
        onclick={copyScreenOutput}
      >
        <Icons name="copy" size={12} />
        <span>{t.cfg.lblCopyOut}</span>
      </button>
      <button
        type="button"
        class="btn btn-xs"
        disabled={connState === 'connecting'}
        onclick={reconnectPty}
      >
        {t.cfg.lblReconnect}
      </button>
    {/if}
  </div>

  <form
    class="btn-group"
    onsubmit={(e) => {
      e.preventDefault();
      if (!ptySocket) connectPty();
    }}
  >
    {#if runningAllowedContainers.length > 0 || hasCustomTargetOption}
      {@const targetOptions = [
        { value: 'host', label: t.term.hostShell },
        ...(hasCustomTargetOption ? [{ value: target, label: `Docker: ${target.slice('container:'.length)}` }] : []),
        ...runningAllowedContainers.map((c) => ({
          value: `container:${c.name || c.id}`,
          label: `Docker: ${c.name || c.id}`,
        })),
      ]}
      <Select
        compact
        style="width:auto;min-width:160px;max-width:230px;"
        ariaLabel={t.term.hostShell}
        bind:value={target}
        options={targetOptions}
        onchange={onTargetChange}
        disabled={Boolean(ptySocket)}
      />
    {/if}
    {#if target === 'host'}
      {@const hostShells = availableShells.length ? availableShells : [{ id: 'bash', path: '/bin/bash' }, { id: 'sh', path: '/bin/sh' }]}
      {#if hostShells.length > 1}
        <Select
          compact
          mono
          style="width:auto;min-width:92px;"
          ariaLabel="Shell"
          title={hostShells.find((s) => s.id === selectedShell)?.path || ''}
          bind:value={selectedShell}
          options={hostShells.map((sh) => ({ value: sh.id, label: sh.id, sub: sh.path }))}
          onchange={() => (shellUserPicked = true)}
          disabled={Boolean(ptySocket)}
        />
      {:else if hostShells.length === 1}
        <span class="badge badge-muted mono" title={hostShells[0].path}>{hostShells[0].id}</span>
      {/if}
    {:else}
      <Select
        compact
        mono
        style="width:auto;min-width:132px;"
        ariaLabel="Shell"
        bind:value={selectedShell}
        options={[
          { value: 'auto', label: 'auto (bash/sh)' },
          { value: 'bash', label: 'bash' },
          { value: 'sh', label: 'sh' },
        ]}
        onchange={() => (shellUserPicked = true)}
        disabled={Boolean(ptySocket)}
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

<!-- 交互式 PTY 视口 -->
<div
  bind:this={viewportEl}
  role="textbox"
  aria-multiline="true"
  aria-label="PTY Terminal Viewport"
  tabindex="0"
  onfocus={() => (viewportFocused = true)}
  onblur={() => (viewportFocused = false)}
  onkeydown={handleTerminalKeydown}
  onpaste={handleTerminalPaste}
  class="mono pty-viewport {viewportFocused ? 'focused' : ''}"
>
  {#if hasOutput || connState === 'connected'}
    {#each historyLines as line (line.id)}<div class="pty-line">{#if line.segs.length > 0}{#each line.segs as seg, i (i)}{#if seg.color || seg.bold}<span style={`${seg.color ? `color:${seg.color};` : ''}${seg.bold ? 'font-weight:700;' : ''}`}>{seg.text}</span>{:else}{seg.text}{/if}{/each}{:else}{'\u00a0'}{/if}</div>{/each}<div class="pty-line">{#each beforeCursorSegs as seg, i (i)}{#if seg.color || seg.bold}<span style={`${seg.color ? `color:${seg.color};` : ''}${seg.bold ? 'font-weight:700;' : ''}`}>{seg.text}</span>{:else}{seg.text}{/if}{/each}{#if connState === 'connected' && !cursorHidden}<span class="pty-cursor {viewportFocused ? 'focused' : ''} {cursorTyping ? 'typing' : ''}" style={`${cursorCell.color ? `color:${cursorCell.color};` : ''}${cursorCell.bold ? 'font-weight:700;' : ''}`}>{cursorCell.ch === ' ' ? '\u00a0' : cursorCell.ch}</span>{:else if cursorCol < activeLine.length}{#if cursorCell.color || cursorCell.bold}<span style={`${cursorCell.color ? `color:${cursorCell.color};` : ''}${cursorCell.bold ? 'font-weight:700;' : ''}`}>{cursorCell.ch}</span>{:else}{cursorCell.ch}{/if}{/if}{#each afterCursorSegs as seg, i (i)}{#if seg.color || seg.bold}<span style={`${seg.color ? `color:${seg.color};` : ''}${seg.bold ? 'font-weight:700;' : ''}`}>{seg.text}</span>{:else}{seg.text}{/if}{/each}</div>
  {:else}
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
