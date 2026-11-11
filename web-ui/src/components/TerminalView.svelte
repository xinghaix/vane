<script>
  let {
    t,
    lang,
    initialTarget = 'host',
    containers = [],
    requireReauth = false,
    apiFetch,
    showToast,
  } = $props();

  let target = $state('host');
  let reauthPassword = $state('');
  let ptySocket = $state(null);
  let screenText = $state('');
  let lineInput = $state('');
  let viewportEl = $state(null);

  $effect(() => {
    if (initialTarget) target = initialTarget;
  });

  $effect(() => {
    return () => {
      if (ptySocket) {
        ptySocket.close();
        ptySocket = null;
      }
    };
  });

  function stripAnsi(str) {
    // 保留换行/回车并剥离控制转义，轻量无依赖地清晰呈现交互式 Shell 输出
    return str
      .replace(/\x1b\[[0-9;?]*[a-zA-Z]/g, '')
      .replace(/\x1b\][^\x07]*(\x07|\x1b\\)/g, '');
  }

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
      screenText = '';
      ws.onopen = () => sendResize();
      ws.onmessage = (ev) => {
        const chunk = stripAnsi(String(ev.data || ''));
        screenText = (screenText + chunk).slice(-32768);
        queueMicrotask(() => {
          if (viewportEl) viewportEl.scrollTop = viewportEl.scrollHeight;
        });
      };
      ws.onclose = () => {
        ptySocket = null;
      };
      ptySocket = ws;
    } catch (err) {
      showToast(err.message);
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

  function handleTerminalKeydown(e) {
    if (!ptySocket || ptySocket.readyState !== WebSocket.OPEN) return;
    if (e.ctrlKey && !e.metaKey && !e.altKey) {
      const k = e.key.toLowerCase();
      if (k === 'c') { e.preventDefault(); sendRaw('\x03'); return; }
      if (k === 'd') { e.preventDefault(); sendRaw('\x04'); return; }
      if (k === 'l') { e.preventDefault(); screenText = ''; sendRaw('\x0c'); return; }
    }
    if (e.key === 'Enter') { e.preventDefault(); sendRaw('\r'); }
    else if (e.key === 'Backspace') { e.preventDefault(); sendRaw('\x7f'); }
    else if (e.key === 'Tab') { e.preventDefault(); sendRaw('\t'); }
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
      <div class="card-title">{t.nav.web_terminal}</div>
      <div style="font-size:12px;color:var(--text-secondary);">
        {lang === 'en'
          ? 'Real Unix openpty + TIOCSWINSZ session bound to single-use ticket and process-group SIGHUP/SIGKILL reap.'
          : '原生 openpty 伪终端流式会话（一次性票据绑定 + 空闲自动断连 + 登出即时强杀进程组回收）'}
      </div>
    </div>
    <div class="btn-group">
      <select style="width:210px;min-height:38px;font-size:13px;" bind:value={target} disabled={Boolean(ptySocket)}>
        <option value="host">{lang === 'en' ? 'Host Router Shell' : '宿主机 Shell (host)'}</option>
        {#each (containers || []).filter((c) => c.state === 'running' && !c.protected) as c}
          <option value={`container:${c.name || c.id}`}>Docker: {c.name || c.id}</option>
        {/each}
      </select>
      {#if requireReauth && !ptySocket}
        <input
          type="password"
          style="width:160px;min-height:38px;font-size:13px;"
          placeholder={lang === 'en' ? 'Admin password' : '二次验证密码'}
          bind:value={reauthPassword}
        />
      {/if}
      {#if !ptySocket}
        <button type="button" class="btn btn-primary btn-sm" onclick={connectPty}>
          {lang === 'en' ? 'Connect PTY' : '连接终端'}
        </button>
      {:else}
        <button type="button" class="btn btn-danger btn-sm" onclick={() => ptySocket.close()}>
          {lang === 'en' ? 'Disconnect' : '断开终端'}
        </button>
      {/if}
    </div>
  </div>

  <!-- 触屏 / 快捷控制键栏 -->
  {#if ptySocket}
    <div class="btn-group" style="margin-bottom:10px;">
      <button type="button" class="btn btn-xs mono" onclick={() => sendRaw('\t')}>Tab</button>
      <button type="button" class="btn btn-xs mono" onclick={() => sendRaw('\x03')}>Ctrl+C</button>
      <button type="button" class="btn btn-xs mono" onclick={() => sendRaw('\x04')}>Ctrl+D</button>
      <button type="button" class="btn btn-xs mono" onclick={() => sendRaw('\x1b[A')}>↑</button>
      <button type="button" class="btn btn-xs mono" onclick={() => sendRaw('\x1b[B')}>↓</button>
      <button type="button" class="btn btn-xs" onclick={() => { screenText = ''; }}>Clear</button>
    </div>
  {/if}

  <!-- 交互式 PTY 视口（点击聚焦后可直接键盘盲打交互，同时保留下方命令输入框兼容手机输入法） -->
  <div
    bind:this={viewportEl}
    role="textbox"
    aria-label="PTY Terminal Viewport"
    tabindex="0"
    onkeydown={handleTerminalKeydown}
    class="mono"
    style="background:#05070a;color:#10b981;padding:16px;border-radius:12px;min-height:340px;max-height:500px;overflow-y:auto;font-size:13px;line-height:1.45;white-space:pre-wrap;word-break:break-all;outline:none;border:1px solid var(--border-subtle);"
  >{screenText || (ptySocket ? '' : (lang === 'en' ? 'Click "Connect PTY" to start an interactive session...' : '点击右上角「连接终端」开启交互式 PTY 会话（点击黑框可直接键盘输入）...'))}</div>

  {#if ptySocket}
    <form onsubmit={submitLine} style="display:flex;gap:8px;margin-top:12px;">
      <input
        type="text"
        class="mono"
        bind:value={lineInput}
        placeholder={lang === 'en' ? 'Type command and press Enter...' : '输入命令并回车发送（支持移动端输入法）...'}
      />
      <button type="submit" class="btn btn-primary">{lang === 'en' ? 'Send' : '发送'}</button>
    </form>
  {/if}
</div>
