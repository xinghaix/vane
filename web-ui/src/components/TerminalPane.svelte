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
    tabTitle = '',
    onStartRename = null,
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
  let isAtBottom = $state(true);
  let gridCols = $state(100);
  let gridRows = $state(24);
  let autoConnectDone = false;

  function onViewportScroll() {
    if (!viewportEl) return;
    isAtBottom = viewportEl.scrollHeight - viewportEl.scrollTop - viewportEl.clientHeight < 48;
  }

  function scrollToBottom() {
    if (!viewportEl) return;
    viewportEl.scrollTop = viewportEl.scrollHeight;
    isAtBottom = true;
  }

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
    let fontSize = 13;
    try {
      const parsed = parseFloat(getComputedStyle(viewportEl).fontSize || '13');
      if (Number.isFinite(parsed) && parsed > 0) fontSize = parsed;
    } catch {
      // ignore
    }
    const charW = Math.max(6.8, fontSize * 0.62);
    const lineH = Math.max(16, fontSize * 1.45);
    const cols = Math.max(40, Math.min(240, Math.floor((viewportEl.clientWidth - 28) / charW)));
    const rows = Math.max(14, Math.min(80, Math.floor((viewportEl.clientHeight - 28) / lineH)));
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
          isAtBottom = true;
          queueMicrotask(() => {
            if (viewportEl) viewportEl.scrollTop = viewportEl.scrollHeight;
          });
        } else {
          isAtBottom = false;
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

<!-- 单标签会话顶栏：状态、会话操作与目标/Shell/连接控制 -->
<div class="pty-pane-bar tp-session-bar">
  <div class="tp-session-left">
    <span class="badge {connState === 'connected' ? 'badge-ok' : connState === 'connecting' ? 'badge-warn' : 'badge-muted'}">
      <span class="status-dot {connState === 'connected' ? 'ok' : connState === 'connecting' ? 'warn' : 'muted'}"></span>
      <span>
        {connState === 'connected'
          ? t.term.connected
          : connState === 'connecting'
            ? t.term.connecting
            : t.term.disconnected}
      </span>
    </span>

    {#if connState === 'connected'}
      <span class="meta-chip mono tp-grid-chip" title={`${gridCols} cols × ${gridRows} rows`}>
        {gridCols}×{gridRows}
      </span>
    {/if}

    {#if onStartRename}
      <button
        type="button"
        class="btn btn-ghost btn-xs tp-rename-btn"
        title={t.term?.renameTab || t.term.renameHint}
        aria-label={`${t.term?.renameTab || (lang === 'en' ? 'Rename tab' : '重命名标签')} ${tabTitle || ''}`.trim()}
        onclick={() => onStartRename?.()}
      >
        <Icons name="sliders" size={12} />
        <span>{t.term?.renameTab || (lang === 'en' ? 'Rename' : '重命名')}</span>
      </button>
    {/if}

    {#if ptySocket || hasOutput}
      <div class="btn-group tp-util-group">
        <button
          type="button"
          class="btn btn-xs"
          onmousedown={(e) => e.preventDefault()}
          onclick={resetScreen}
        >
          <span>{t.cfg.lblClearScreen}</span>
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
          <Icons name="refresh" size={12} />
          <span>{t.cfg.lblReconnect}</span>
        </button>
      </div>
    {/if}
  </div>

  <form
    class="tp-connect-form"
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
      <div class="tp-select-target">
        <Select
          compact
          ariaLabel={t.term.hostShell}
          bind:value={target}
          options={targetOptions}
          onchange={onTargetChange}
          disabled={Boolean(ptySocket)}
        />
      </div>
    {/if}
    {#if target === 'host'}
      {@const hostShells = availableShells.length ? availableShells : [{ id: 'bash', path: '/bin/bash' }, { id: 'sh', path: '/bin/sh' }]}
      {#if hostShells.length > 1}
        <div class="tp-select-shell">
          <Select
            compact
            mono
            ariaLabel="Shell"
            title={hostShells.find((s) => s.id === selectedShell)?.path || ''}
            bind:value={selectedShell}
            options={hostShells.map((sh) => ({ value: sh.id, label: sh.id, sub: sh.path }))}
            onchange={() => (shellUserPicked = true)}
            disabled={Boolean(ptySocket)}
          />
        </div>
      {:else if hostShells.length === 1}
        <span class="badge badge-muted mono" title={hostShells[0].path}>{hostShells[0].id}</span>
      {/if}
    {:else}
      <div class="tp-select-shell tp-select-shell-wide">
        <Select
          compact
          mono
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
      </div>
    {/if}
    {#if !ptySocket}
      <button type="submit" class="btn btn-primary btn-sm tp-conn-btn" disabled={connState === 'connecting'}>
        <Icons name="terminal" size={14} />
        <span>{connState === 'connecting' ? t.term.connecting : t.term.connect}</span>
      </button>
    {:else}
      <button type="button" class="btn btn-danger btn-sm tp-conn-btn" onclick={() => ptySocket?.close()}>
        <Icons name="x" size={14} />
        <span>{t.term.disconnect}</span>
      </button>
    {/if}
  </form>
</div>

<!-- 交互式 PTY 视口 -->
<div class="tp-viewport-wrap">
  <div
    bind:this={viewportEl}
    role="textbox"
    aria-multiline="true"
    aria-label="PTY Terminal Viewport"
    tabindex="0"
    onfocus={() => (viewportFocused = true)}
    onblur={() => (viewportFocused = false)}
    onscroll={onViewportScroll}
    onkeydown={handleTerminalKeydown}
    onpaste={handleTerminalPaste}
    class="mono pty-viewport tp-viewport {viewportFocused ? 'focused' : ''}"
  >
    {#if hasOutput || connState === 'connected'}
      {#each historyLines as line (line.id)}<div class="pty-line">{#if line.segs.length > 0}{#each line.segs as seg, i (i)}{#if seg.color || seg.bold}<span style={`${seg.color ? `color:${seg.color};` : ''}${seg.bold ? 'font-weight:700;' : ''}`}>{seg.text}</span>{:else}{seg.text}{/if}{/each}{:else}{'\u00a0'}{/if}</div>{/each}<div class="pty-line">{#each beforeCursorSegs as seg, i (i)}{#if seg.color || seg.bold}<span style={`${seg.color ? `color:${seg.color};` : ''}${seg.bold ? 'font-weight:700;' : ''}`}>{seg.text}</span>{:else}{seg.text}{/if}{/each}{#if connState === 'connected' && !cursorHidden}<span class="pty-cursor {viewportFocused ? 'focused' : ''} {cursorTyping ? 'typing' : ''}" style={`${cursorCell.color ? `color:${cursorCell.color};` : ''}${cursorCell.bold ? 'font-weight:700;' : ''}`}>{cursorCell.ch === ' ' ? '\u00a0' : cursorCell.ch}</span>{:else if cursorCol < activeLine.length}{#if cursorCell.color || cursorCell.bold}<span style={`${cursorCell.color ? `color:${cursorCell.color};` : ''}${cursorCell.bold ? 'font-weight:700;' : ''}`}>{cursorCell.ch}</span>{:else}{cursorCell.ch}{/if}{/if}{#each afterCursorSegs as seg, i (i)}{#if seg.color || seg.bold}<span style={`${seg.color ? `color:${seg.color};` : ''}${seg.bold ? 'font-weight:700;' : ''}`}>{seg.text}</span>{:else}{seg.text}{/if}{/each}</div>
    {:else}
      <div class="tp-empty-hero">
        <span class="tp-hero-icon">
          <Icons name={target.startsWith('container:') ? 'docker' : 'terminal'} size={22} />
        </span>
        <div class="tp-hero-target">
          {target === 'host' ? t.term.hostShell : `Docker · ${target.slice('container:'.length)}`}
          {#if selectedShell}
            <span class="tp-hero-shell">{selectedShell}</span>
          {/if}
        </div>
        <div class="tp-hero-desc">{t.term.placeholder}</div>
        {#if !ptySocket}
          <button
            type="button"
            class="btn btn-primary btn-sm"
            disabled={connState === 'connecting'}
            onclick={() => connectPty()}
          >
            <Icons name="play" size={13} />
            <span>{connState === 'connecting' ? t.term.connecting : t.term.connect}</span>
          </button>
        {/if}
      </div>
    {/if}
  </div>

  {#if hasOutput && !isAtBottom}
    <button
      type="button"
      class="btn btn-xs tp-jump-bottom"
      onmousedown={(e) => e.preventDefault()}
      onclick={scrollToBottom}
    >
      <Icons name="chevron" size={13} />
      <span>{t.term?.scrollToBottom || (lang === 'en' ? 'Jump to bottom' : '回到底部')}</span>
    </button>
  {/if}
</div>

<!-- 底部独立快捷按键坞 + 移动端友好命令行输入（始终贴近虚拟键盘） -->
{#if ptySocket}
  <div class="tp-bottom-dock">
    <div class="tp-quick-keys" role="toolbar" aria-label={t.cfg.lblQuickKeys}>
      <button type="button" class="tp-keycap mono" onmousedown={(e) => e.preventDefault()} onclick={() => sendRaw('\x1b')}>Esc</button>
      <button type="button" class="tp-keycap mono" onmousedown={(e) => e.preventDefault()} onclick={() => sendRaw('\t')}>Tab</button>
      <button type="button" class="tp-keycap mono tp-keycap-warn" onmousedown={(e) => e.preventDefault()} onclick={() => sendRaw('\x03')}>Ctrl+C</button>
      <button type="button" class="tp-keycap mono" onmousedown={(e) => e.preventDefault()} onclick={() => sendRaw('\x04')}>Ctrl+D</button>
      <button type="button" class="tp-keycap mono" onmousedown={(e) => e.preventDefault()} onclick={() => sendRaw('\x1a')}>Ctrl+Z</button>
      <button
        type="button"
        class="tp-keycap mono"
        onmousedown={(e) => e.preventDefault()}
        onclick={() => {
          resetScreen();
          sendRaw('\x0c');
        }}
      >
        Ctrl+L
      </button>
      <span class="tp-keycap-sep" aria-hidden="true"></span>
      <button type="button" class="tp-keycap mono tp-keycap-arrow" aria-label="Left arrow" onmousedown={(e) => e.preventDefault()} onclick={() => sendRaw('\x1b[D')}>←</button>
      <button type="button" class="tp-keycap mono tp-keycap-arrow" aria-label="Up arrow" onmousedown={(e) => e.preventDefault()} onclick={() => sendRaw('\x1b[A')}>↑</button>
      <button type="button" class="tp-keycap mono tp-keycap-arrow" aria-label="Down arrow" onmousedown={(e) => e.preventDefault()} onclick={() => sendRaw('\x1b[B')}>↓</button>
      <button type="button" class="tp-keycap mono tp-keycap-arrow" aria-label="Right arrow" onmousedown={(e) => e.preventDefault()} onclick={() => sendRaw('\x1b[C')}>→</button>
    </div>

    <form onsubmit={submitLine} class="tp-cmd-form">
      <div class="tp-cmd-input-wrap">
        <span class="tp-cmd-prompt mono" aria-hidden="true">$</span>
        <input
          type="text"
          class="mono tp-cmd-input"
          aria-label={t.term.inputPh}
          autocomplete="off"
          autocorrect="off"
          autocapitalize="off"
          spellcheck="false"
          enterkeyhint="send"
          bind:value={lineInput}
          placeholder={t.term.inputPh}
        />
      </div>
      <button type="submit" class="btn btn-primary tp-send-btn">{t.term.send}</button>
    </form>
  </div>
{/if}

<style>
  .tp-session-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    flex-wrap: wrap;
    margin-bottom: 12px;
  }
  .tp-session-left {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    min-width: 0;
  }
  .tp-grid-chip {
    font-size: 11px;
    padding: 2px 7px;
    border-radius: 999px;
    background: var(--bg-elevated);
    border: 1px solid var(--border-subtle);
    color: var(--text-muted);
  }
  .tp-rename-btn {
    color: var(--text-secondary);
  }
  .tp-util-group {
    gap: 6px;
  }
  .tp-connect-form {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    min-width: 0;
  }
  .tp-select-target {
    width: 196px;
    max-width: 100%;
    min-width: 0;
  }
  .tp-select-shell {
    width: 102px;
    min-width: 0;
  }
  .tp-select-shell-wide {
    width: 144px;
  }
  .tp-viewport-wrap {
    position: relative;
  }
  .tp-viewport {
    box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.06);
  }
  .tp-empty-hero {
    height: 100%;
    min-height: 220px;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
    gap: 10px;
    padding: 24px 16px;
    font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Text', 'Inter', 'PingFang SC', system-ui, sans-serif;
  }
  .tp-hero-icon {
    width: 48px;
    height: 48px;
    border-radius: 14px;
    background: rgba(52, 211, 153, 0.12);
    border: 1px solid rgba(52, 211, 153, 0.25);
    color: #34d399;
    display: inline-grid;
    place-items: center;
  }
  .tp-hero-target {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    justify-content: center;
    font-size: 14px;
    font-weight: 600;
    color: #f4f4f5;
  }
  .tp-hero-shell {
    font-family: 'JetBrains Mono', ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
    font-size: 11.5px;
    padding: 1px 8px;
    border-radius: 999px;
    background: rgba(255, 255, 255, 0.08);
    color: #a1a1aa;
  }
  .tp-hero-desc {
    max-width: 440px;
    font-size: 12.5px;
    line-height: 1.5;
    color: #a1a1aa;
    margin-bottom: 4px;
  }
  .tp-jump-bottom {
    position: absolute;
    right: 14px;
    bottom: 14px;
    z-index: 5;
    background: rgba(24, 24, 27, 0.9);
    color: #f4f4f5;
    border-color: rgba(255, 255, 255, 0.18);
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
    box-shadow: 0 6px 18px rgba(0, 0, 0, 0.45);
  }
  .tp-jump-bottom:hover:not(:disabled) {
    background: rgba(39, 39, 42, 0.96);
    border-color: var(--accent);
    color: #ffffff;
  }
  .tp-bottom-dock {
    margin-top: 10px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .tp-quick-keys {
    display: flex;
    align-items: center;
    gap: 6px;
    overflow-x: auto;
    overflow-y: hidden;
    -webkit-overflow-scrolling: touch;
    scrollbar-width: none;
    padding: 4px 2px;
  }
  .tp-quick-keys::-webkit-scrollbar {
    display: none;
  }
  .tp-keycap {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-height: 30px;
    min-width: 34px;
    padding: 0 10px;
    border-radius: 9px;
    border: 1px solid var(--border-strong);
    background: var(--bg-elevated);
    color: var(--text-primary);
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    flex-shrink: 0;
    box-shadow: 0 1px 0 var(--border-strong);
    transition: background-color 0.12s ease, border-color 0.12s ease, transform 0.08s ease;
  }
  .tp-keycap:hover {
    background: var(--bg-hover);
    border-color: var(--accent);
  }
  .tp-keycap:active {
    transform: translateY(1px);
  }
  .tp-keycap:focus-visible {
    outline: none;
    box-shadow: 0 0 0 3px var(--accent-soft);
    border-color: var(--accent);
  }
  .tp-keycap-warn {
    color: var(--danger);
    border-color: color-mix(in srgb, var(--danger) 32%, var(--border-subtle));
    background: color-mix(in srgb, var(--danger-soft) 55%, var(--bg-elevated));
  }
  .tp-keycap-arrow {
    min-width: 36px;
    font-size: 13px;
  }
  .tp-keycap-sep {
    width: 1px;
    height: 18px;
    background: var(--border-strong);
    flex-shrink: 0;
    margin: 0 2px;
  }
  .tp-cmd-form {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .tp-cmd-input-wrap {
    position: relative;
    flex: 1;
    min-width: 0;
    display: flex;
    align-items: center;
  }
  .tp-cmd-prompt {
    position: absolute;
    left: 13px;
    color: var(--accent);
    font-weight: 700;
    font-size: 13px;
    pointer-events: none;
  }
  .tp-cmd-input {
    padding-left: 28px !important;
  }
  .tp-send-btn {
    flex-shrink: 0;
  }
  @media (max-width: 920px) {
    .tp-viewport {
      font-size: 12px;
      padding: 12px;
      height: min(360px, 46dvh);
    }
    .tp-keycap {
      min-height: 38px;
      min-width: 42px;
      padding: 0 12px;
      font-size: 12.5px;
    }
  }
  @media (max-width: 680px) {
    .tp-session-bar {
      flex-direction: column;
      align-items: stretch;
      gap: 8px;
    }
    .tp-session-left {
      justify-content: space-between;
    }
    .tp-connect-form {
      width: 100%;
    }
    .tp-select-target {
      flex: 1 1 150px;
      width: auto;
    }
    .tp-select-shell,
    .tp-select-shell-wide {
      flex: 0 1 112px;
      width: auto;
    }
    .tp-conn-btn {
      flex: 1 0 auto;
    }
  }
</style>
