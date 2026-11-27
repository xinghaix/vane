<script>
  import { I18N } from './lib/i18n.js';
  import { localizeError } from './lib/helpers.js';
  import { registerOverlay } from './lib/overlay.js';
  import { getPwaState, initPwaListeners, promptPwaInstall, subscribePwaState } from './lib/pwa.js';
  import Icons from './components/Icons.svelte';
  import ToastStack from './components/ToastStack.svelte';
  import ConfirmModal from './components/ConfirmModal.svelte';
  import ReauthModal from './components/ReauthModal.svelte';
  import NotificationInboxPanel from './components/NotificationInboxPanel.svelte';
  import AuthGate from './components/AuthGate.svelte';
  import DashboardView from './components/DashboardView.svelte';
  import NetworkRulesView from './components/NetworkRulesView.svelte';
  import DomainCertStunView from './components/DomainCertStunView.svelte';
  import OpsViews from './components/OpsViews.svelte';
  import SettingsView from './components/SettingsView.svelte';

  const VALID_TABS = new Set([
    'dashboard',
    'reverse_proxy',
    'port_forward',
    'ddns',
    'acme',
    'stun',
    'docker',
    'web_terminal',
    'cron',
    'logs',
    'settings',
  ]);

  function parseHash() {
    const raw = (location.hash || '').replace(/^#\/?/, '');
    if (!raw) return { tab: 'dashboard', sub: 'general', hadHash: false };
    const [tabPart, subPart] = raw.split('/');
    const tab = VALID_TABS.has(tabPart) ? tabPart : 'dashboard';
    const sub =
      tab === 'settings' && ['general', 'appearance', 'security', 'notifications', 'backup', 'update'].includes(subPart)
        ? subPart
        : 'general';
    return { tab, sub, hadHash: true };
  }

  const storedLang = localStorage.getItem('vane_lang');
  let hasExplicitLang = storedLang === 'zh' || storedLang === 'en';
  let lang = $state(hasExplicitLang ? (storedLang === 'en' ? 'en' : 'zh') : 'zh');
  let t = $derived(I18N[lang] || I18N.zh);

  let loading = $state(true);
  let authenticated = $state(false);
  let mustChangePassword = $state(false);
  let initialSetup = $state(false);
  let authConnError = $state('');
  let username = $state('admin');
  let passwordLoginEnabled = $state(true);
  let totpEnabled = $state(false);
  let passkeyEnabled = $state(false);
  let hasPasskeys = $state(false);
  let sessionTtlSecs = $state(3600);
  let unreadNotifications = $state(0);
  let inboxModalOpen = $state(false);

  const MODULE_REAUTH_IDS = new Set([
    'reverse_proxy',
    'port_forward',
    'ddns',
    'acme',
    'stun',
    'web_terminal',
    'cron',
    'docker',
  ]);
  let moduleReauth = $state({
    reverse_proxy: false,
    port_forward: false,
    ddns: false,
    acme: false,
    stun: false,
    web_terminal: false,
    cron: false,
    docker: false,
  });
  let unlockedModules = $state({});
  let nowTick = $state(Date.now());

  const ACCENT_PRESETS = [
    { id: 'emerald', color: '#10b981' },
    { id: 'ocean', color: '#0284c7' },
    { id: 'indigo', color: '#4f46e5' },
    { id: 'violet', color: '#7c3aed' },
    { id: 'amber', color: '#d97706' },
    { id: 'rose', color: '#e11d48' },
  ];

  const initHash = parseHash();
  let themeMode = $state(localStorage.getItem('vane_theme_mode') || 'auto');
  let oledMode = $state(localStorage.getItem('vane_oled_mode') === '1');
  let accentColor = $state(localStorage.getItem('vane_theme_accent') || 'emerald');
  let sidebarCollapsed = $state(localStorage.getItem('vane_sidebar_collapsed') === '1');
  let settingsMenuOpen = $state(initHash.tab === 'settings');
  let userMenuOpen = $state(false);
  let userBtnEl = $state(null);
  let mobileUserBtnEl = $state(null);
  let userPopoverEl = $state(null);
  let userMenuStyle = $state('');
  let sidebarScrollEl = $state(null);
  let sidebarCanScrollTop = $state(false);
  let sidebarCanScrollBottom = $state(false);
  let sidebarFlyout = $state(null);
  let activeTab = $state(initHash.tab);
  let settingsSubTab = $state(initHash.sub);
  let pendingPostLoginRoute = $state(
    initHash.hadHash ? { tab: initHash.tab, sub: initHash.sub } : null
  );
  let mobileDockScrollEl = $state(null);
  let dockCanScrollLeft = $state(false);
  let dockCanScrollRight = $state(false);
  let pwaState = $state(getPwaState());
  let toasts = $state([]);
  let nextToastId = 1;

  // 全局确认框状态
  let confirmState = $state({
    open: false,
    title: '',
    message: '',
    confirmLabel: '',
    danger: true,
    busy: false,
    onConfirm: null,
  });

  // 全局敏感操作二次验证弹框（支持密码 / TOTP / 通行密钥）
  let reauthState = $state({
    open: false,
    title: '',
    description: '',
    actionLabel: '',
    unlockModule: '',
    requireMfa: false,
    resolve: null,
  });

  let lockdownWarnings = $state([]);
  let lockdownKernelEnforced = $state(true);

  let modules = $state({
    reverse_proxy: true,
    port_forward: true,
    ddns: true,
    acme: true,
    stun: false,
    web_terminal: false,
    cron: false,
    docker: true,
  });

  let dashboard = $state(null);
  let settingsJson = $state(null);
  let networkInfo = $state(null);
  let logs = $state([]);
  let logModules = $state([]);
  let logCapacity = $state(300);
  let logLevelFilter = $state('');
  let logModuleFilter = $state('');
  let containers = $state([]);
  let dockerError = $state('');
  let restartRequiredFields = $state([]);
  let refreshing = $state(false);
  let refreshNonce = 0;

  // Web 终端按需异步加载分包（关闭时 0 字节下载），开启连接后切 Tab 不卸载
  let TerminalComp = $state(null);
  let ptyLoadError = $state('');
  let ptyEverOpened = $state(false);
  let terminalInitialTarget = $state('host');
  let terminalTargetNonce = $state(0);
  const toastTimers = new Map();

  let navGroups = $derived.by(() => {
    const groups = [
      {
        label: t.navGroups.overview,
        items: [{ id: 'dashboard', label: t.nav.dashboard, always: true }],
      },
      {
        label: t.navGroups.traffic,
        items: [
          {
            id: 'reverse_proxy',
            label: t.nav.reverse_proxy,
            enabled: modules.reverse_proxy,
            count: settingsJson?.reverse_proxy?.length,
          },
          {
            id: 'port_forward',
            label: t.nav.port_forward,
            enabled: modules.port_forward,
            count: settingsJson?.port_forwards?.length,
          },
        ],
      },
      {
        label: t.navGroups.domain,
        items: [
          { id: 'ddns', label: t.nav.ddns, enabled: modules.ddns, count: settingsJson?.ddns?.length },
          { id: 'acme', label: t.nav.acme, enabled: modules.acme, count: settingsJson?.acme?.length },
          { id: 'stun', label: t.nav.stun, enabled: modules.stun, count: settingsJson?.stun?.length },
        ],
      },
      {
        label: t.navGroups.ops,
        items: [
          {
            id: 'docker',
            label: t.nav.docker,
            enabled: modules.docker,
            count: containers.length || undefined,
          },
          { id: 'web_terminal', label: t.nav.web_terminal, enabled: modules.web_terminal },
          { id: 'cron', label: t.nav.cron, enabled: modules.cron, count: settingsJson?.cron?.length },
          { id: 'logs', label: t.nav.logs, always: true },
        ],
      },
      {
        label: t.navGroups.system,
        items: [{ id: 'settings', label: t.nav.settings, always: true }],
      },
    ];
    return groups
      .map((g) => ({ ...g, items: g.items.filter((item) => item.always || item.enabled) }))
      .filter((g) => g.items.length > 0);
  });

  let navItems = $derived(navGroups.flatMap((g) => g.items));

  let settingsSubItems = $derived([
    { id: 'general', icon: 'sliders', label: t.cfg.tabGeneral, shortLabel: t.cfg.tabGeneral },
    { id: 'appearance', icon: 'palette', label: t.cfg.tabAppearance, shortLabel: t.cfg.tabAppearance },
    { id: 'security', icon: 'shield', label: t.cfg.tabSecurity, shortLabel: t.cfg.tabSecurityShort || t.cfg.tabSecurity },
    { id: 'notifications', icon: 'bell', label: t.cfg.tabNotifications, shortLabel: t.cfg.tabNotifications },
    { id: 'backup', icon: 'database', label: t.cfg.tabBackup, shortLabel: t.cfg.tabBackup },
    { id: 'update', icon: 'refresh', label: t.cfg.tabUpdate, shortLabel: t.cfg.tabUpdate },
  ]);

  let mobileScrollItems = $derived(navItems.filter((n) => n.id !== 'settings'));
  let appVersionLabel = $derived.by(() => {
    const raw = String(dashboard?.version || '').trim();
    if (!raw) return 'v0.1.0';
    return raw.startsWith('v') ? raw : `v${raw}`;
  });

  function updateSidebarScrollState() {
    const el = sidebarScrollEl;
    if (!el) {
      sidebarCanScrollTop = false;
      sidebarCanScrollBottom = false;
      return;
    }
    sidebarCanScrollTop = el.scrollTop > 4;
    sidebarCanScrollBottom = el.scrollTop + el.clientHeight < el.scrollHeight - 4;
  }

  $effect(() => {
    const _open = settingsMenuOpen;
    const _collapsed = sidebarCollapsed;
    const _len = navItems.length;
    const el = sidebarScrollEl;
    if (!el) return;
    queueMicrotask(() => {
      if (_open && !_collapsed) {
        const subList = el.querySelector('.nav-sub-list');
        subList?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
      updateSidebarScrollState();
    });
    const onResize = () => updateSidebarScrollState();
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  });

  let dockDragging = $state(false);
  let dockGlideEl = $state(null);
  let dockPointerId = null;
  let dockDragStartX = 0;
  let dockDragStartScroll = 0;
  let dockLastMoveX = 0;
  let dockLastMoveTs = 0;
  let dockVelX = 0;
  let dockJustDragged = false;
  let dockLensRaf = 0;
  let dockInertiaRaf = 0;
  let dockGlideInitialized = false;

  function prefersReducedMotion() {
    return typeof window !== 'undefined' && Boolean(window.matchMedia?.('(prefers-reduced-motion: reduce)').matches);
  }

  function stopDockInertia() {
    if (dockInertiaRaf) {
      cancelAnimationFrame(dockInertiaRaf);
      dockInertiaRaf = 0;
    }
  }

  function applyDockLensNow() {
    const el = mobileDockScrollEl;
    if (!el) {
      dockCanScrollLeft = false;
      dockCanScrollRight = false;
      return;
    }
    const viewW = el.clientWidth;
    const scrollW = el.scrollWidth;
    const scrollL = el.scrollLeft;
    const maxScroll = Math.max(0, scrollW - viewW);

    dockCanScrollLeft = scrollL > 4;
    dockCanScrollRight = maxScroll > 4 && scrollL < maxScroll - 4;

    if (viewW <= 0) return;
    const reduced = prefersReducedMotion();
    const scrollable = maxScroll > 4;
    // 边界感知衰减：在最左端不压暗首项，在最右端不压暗末项，仅向有隐藏菜单的边缘柔和收束
    const leftAtten = scrollable ? Math.min(1, scrollL / 36) : 0;
    const rightAtten = scrollable ? Math.min(1, (maxScroll - scrollL) / 36) : 0;
    const halfW = Math.max(1, viewW / 2);

    const items = el.querySelectorAll('.dock-scroll-item');
    for (const btn of items) {
      const centerInView = btn.offsetLeft + btn.offsetWidth / 2 - scrollL;
      const signed = (centerInView - halfW) / halfW;
      const absDist = Math.min(1.15, Math.abs(signed));
      const atten = signed < 0 ? leftAtten : rightAtten;
      const edgeT = Math.max(0, absDist - 0.2) / 0.8;
      const falloff = Math.pow(edgeT, 1.55) * atten;

      let scale = reduced ? 1 : scrollable ? 1.02 - falloff * 0.16 : 1;
      let opacity = scrollable ? 1 - falloff * 0.56 : 1;
      if (btn.dataset.dockId === activeTab) {
        scale = Math.max(scale, reduced ? 1 : 0.96);
        opacity = Math.max(opacity, 0.88);
      }
      btn.style.transform = reduced ? '' : `scale(${scale.toFixed(3)})`;
      btn.style.opacity = opacity.toFixed(3);
    }
  }

  function scheduleDockLensUpdate() {
    if (dockLensRaf) return;
    dockLensRaf = requestAnimationFrame(() => {
      dockLensRaf = 0;
      applyDockLensNow();
    });
  }

  function positionDockGlidePill(animate = true) {
    const el = mobileDockScrollEl;
    const pill = dockGlideEl;
    if (!el || !pill) return;
    const btn = activeTab !== 'settings' ? el.querySelector(`[data-dock-id="${activeTab}"]`) : null;
    if (!btn) {
      pill.style.opacity = '0';
      return;
    }
    const useAnim = animate && dockGlideInitialized && !prefersReducedMotion();
    if (!useAnim) pill.style.transition = 'none';
    pill.style.opacity = '1';
    pill.style.width = `${btn.offsetWidth}px`;
    pill.style.transform = `translateX(${btn.offsetLeft}px)`;
    if (!useAnim) {
      pill.getBoundingClientRect();
      pill.style.transition = '';
    }
    dockGlideInitialized = true;
  }

  function handleDockWheel(e) {
    const el = mobileDockScrollEl;
    if (!el || el.scrollWidth <= el.clientWidth) return;
    stopDockInertia();
    if (Math.abs(e.deltaY) > Math.abs(e.deltaX)) {
      e.preventDefault();
      el.scrollLeft += e.deltaY;
      scheduleDockLensUpdate();
    }
  }

  function handleDockPointerDown(e) {
    // 真实触屏走浏览器原生惯性横滑（touch-action: pan-x）；鼠标/触控笔支持按住拖拽 + 惯性滑行
    if (e.pointerType === 'touch' || e.button !== 0) return;
    const el = mobileDockScrollEl;
    if (!el || el.scrollWidth <= el.clientWidth) return;
    stopDockInertia();
    dockPointerId = e.pointerId;
    dockDragStartX = e.clientX;
    dockDragStartScroll = el.scrollLeft;
    dockLastMoveX = e.clientX;
    dockLastMoveTs = performance.now();
    dockVelX = 0;
    dockDragging = false;
    dockJustDragged = false;
  }

  function handleDockPointerMove(e) {
    if (dockPointerId === null || e.pointerId !== dockPointerId) return;
    const el = mobileDockScrollEl;
    if (!el) return;
    const dx = e.clientX - dockDragStartX;
    const now = performance.now();
    const dt = Math.max(4, now - dockLastMoveTs);
    const stepDx = e.clientX - dockLastMoveX;
    const instV = (stepDx / dt) * 16;
    dockVelX = dockVelX * 0.45 + instV * 0.55;
    dockLastMoveX = e.clientX;
    dockLastMoveTs = now;

    if (!dockDragging && Math.abs(dx) >= 6) {
      dockDragging = true;
      dockJustDragged = true;
      try {
        el.setPointerCapture(e.pointerId);
      } catch {}
    }
    if (dockDragging) {
      el.scrollLeft = dockDragStartScroll - dx;
      scheduleDockLensUpdate();
    }
  }

  function startDockInertia() {
    const el = mobileDockScrollEl;
    if (!el || prefersReducedMotion() || Math.abs(dockVelX) < 1.2) return;
    stopDockInertia();
    const step = () => {
      if (!mobileDockScrollEl) {
        dockInertiaRaf = 0;
        return;
      }
      const prev = mobileDockScrollEl.scrollLeft;
      mobileDockScrollEl.scrollLeft = prev - dockVelX;
      dockVelX *= 0.91;
      applyDockLensNow();
      if (Math.abs(dockVelX) >= 0.35 && Math.abs(mobileDockScrollEl.scrollLeft - prev) > 0.1) {
        dockInertiaRaf = requestAnimationFrame(step);
      } else {
        dockInertiaRaf = 0;
      }
    };
    dockInertiaRaf = requestAnimationFrame(step);
  }

  function endDockDrag(e) {
    if (dockPointerId === null || (e && e.pointerId !== dockPointerId)) return;
    const el = mobileDockScrollEl;
    const wasDragging = dockDragging;
    if (wasDragging && el) {
      try {
        el.releasePointerCapture(dockPointerId);
      } catch {}
    }
    dockPointerId = null;
    dockDragging = false;
    if (wasDragging) {
      const stale = performance.now() - dockLastMoveTs > 90;
      if (!stale) startDockInertia();
    }
    if (dockJustDragged) {
      setTimeout(() => {
        dockJustDragged = false;
      }, 60);
    }
  }

  function centerDockItem(id, smooth = true) {
    const el = mobileDockScrollEl;
    if (!el || !id || id === 'settings') return;
    const btn = el.querySelector(`[data-dock-id="${id}"]`);
    if (!btn) return;
    stopDockInertia();
    const targetLeft = btn.offsetLeft - (el.clientWidth - btn.offsetWidth) / 2;
    const maxLeft = Math.max(0, el.scrollWidth - el.clientWidth);
    const clamped = Math.max(0, Math.min(maxLeft, targetLeft));
    const useSmooth = smooth && !prefersReducedMotion();
    el.scrollTo({ left: clamped, behavior: useSmooth ? 'smooth' : 'auto' });
  }

  $effect(() => {
    const _tab = activeTab;
    const _len = mobileScrollItems.length;
    const el = mobileDockScrollEl;
    if (!el) return;
    const wasInit = dockGlideInitialized;
    queueMicrotask(() => {
      positionDockGlidePill(wasInit);
      if (_tab !== 'settings') {
        centerDockItem(_tab, wasInit);
      }
      applyDockLensNow();
      if (!wasInit) {
        requestAnimationFrame(() => {
          positionDockGlidePill(false);
          applyDockLensNow();
        });
      }
    });
    const onResize = () => {
      positionDockGlidePill(false);
      scheduleDockLensUpdate();
    };
    window.addEventListener('resize', onResize);
    return () => {
      window.removeEventListener('resize', onResize);
      stopDockInertia();
      if (dockLensRaf) {
        cancelAnimationFrame(dockLensRaf);
        dockLensRaf = 0;
      }
    };
  });

  function toggleUserMenu(anchorEl = null, fromTop = false) {
    if (userMenuOpen) {
      userMenuOpen = false;
      return;
    }
    const target = anchorEl || userBtnEl;
    if (target) {
      const r = target.getBoundingClientRect();
      if (fromTop) {
        const top = Math.min(Math.round(r.bottom + 8), Math.max(12, window.innerHeight - 280));
        const right = Math.max(12, Math.round(window.innerWidth - r.right));
        userMenuStyle = `top:${top}px;right:${right}px;`;
      } else {
        const left = Math.min(window.innerWidth - 260, Math.round(r.right + 12));
        const bottom = Math.max(12, Math.round(window.innerHeight - r.bottom));
        userMenuStyle = `left:${left}px;bottom:${bottom}px;`;
      }
    } else {
      userMenuStyle = 'left:264px;bottom:14px;';
    }
    userMenuOpen = true;
  }

  $effect(() => {
    if (!userMenuOpen) return;
    const onDown = (e) => {
      if (userBtnEl?.contains(e.target) || mobileUserBtnEl?.contains(e.target)) return;
      if (userPopoverEl?.contains(e.target)) return;
      userMenuOpen = false;
    };
    const unregister = registerOverlay({
      onDismiss: () => {
        userMenuOpen = false;
      },
      lockScroll: false,
      trapContainer: () => userPopoverEl,
    });
    window.addEventListener('pointerdown', onDown, true);
    return () => {
      unregister();
      window.removeEventListener('pointerdown', onDown, true);
    };
  });

  $effect(() => {
    localStorage.setItem('vane_theme_mode', themeMode);
    localStorage.setItem('vane_oled_mode', oledMode ? '1' : '0');
    document.documentElement.setAttribute('data-oled', oledMode ? '1' : '0');
    const mq = window.matchMedia('(prefers-color-scheme: light)');
    const apply = () => {
      const resolved = themeMode === 'auto' ? (mq.matches ? 'light' : 'dark') : themeMode;
      document.documentElement.setAttribute('data-theme', resolved);
      const meta = document.querySelector('meta[name="theme-color"]');
      if (meta) meta.setAttribute('content', resolved === 'light' ? '#f6f6f7' : oledMode ? '#000000' : '#09090b');
    };
    apply();
    mq.addEventListener('change', apply);
    return () => mq.removeEventListener('change', apply);
  });

  $effect(() => {
    const offWin = initPwaListeners();
    const offSub = subscribePwaState((snap) => {
      pwaState = snap;
    });
    return () => {
      offSub();
      offWin();
    };
  });

  async function handleInstallPwa() {
    const outcome = await promptPwaInstall();
    if (outcome === 'accepted') {
      showToast(t.cfg.pwaInstalledToast, 'success');
    }
  }

  $effect(() => {
    localStorage.setItem('vane_theme_accent', accentColor);
    document.documentElement.setAttribute('data-accent', accentColor);
  });

  $effect(() => {
    document.documentElement.setAttribute('lang', lang === 'en' ? 'en' : 'zh-CN');
  });

  function loadTerminalChunk() {
    ptyLoadError = '';
    import('./components/TerminalView.svelte')
      .then((m) => {
        TerminalComp = m.default;
      })
      .catch((err) => {
        ptyLoadError = err?.message || t.ptyLoadFailed;
      });
  }

  $effect(() => {
    if (!Object.keys(unlockedModules).length) return;
    const timer = setInterval(() => {
      nowTick = Date.now();
    }, 15_000);
    return () => clearInterval(timer);
  });

  function syncUnlockedModules(remMap) {
    if (!remMap || typeof remMap !== 'object') return;
    const now = Date.now();
    const next = {};
    for (const [k, secs] of Object.entries(remMap)) {
      const n = Number(secs || 0);
      if (n > 0) next[k] = now + n * 1000;
    }
    unlockedModules = next;
    nowTick = now;
  }

  function isModuleProtected(id) {
    return MODULE_REAUTH_IDS.has(id) && Boolean(moduleReauth?.[id]);
  }

  function isModuleLocked(id) {
    return isModuleProtected(id) && !(Number(unlockedModules?.[id] || 0) > nowTick);
  }

  $effect(() => {
    if (activeTab === 'web_terminal' && modules.web_terminal && !isModuleLocked('web_terminal')) {
      ptyEverOpened = true;
      if (!TerminalComp && !ptyLoadError) {
        loadTerminalChunk();
      }
    }
    if (!modules.web_terminal || isModuleLocked('web_terminal')) {
      ptyEverOpened = false;
    }
  });

  function isTabAvailable(tab) {
    if (['dashboard', 'logs', 'settings'].includes(tab)) return true;
    return Boolean(modules[tab]);
  }

  function clearUrlHash() {
    if (location.hash) {
      history.replaceState(null, '', `${location.pathname}${location.search}`);
    }
  }

  function syncUrlHash(tab, sub = settingsSubTab, push = false) {
    const nextHash = tab === 'settings' && sub !== 'general' ? `#settings/${sub}` : `#${tab}`;
    if (location.hash !== nextHash) {
      if (push) history.pushState(null, '', nextHash);
      else history.replaceState(null, '', nextHash);
    }
  }

  function handleHashChange() {
    const { tab, sub, hadHash } = parseHash();
    if (!authenticated || mustChangePassword) {
      if (hadHash) {
        pendingPostLoginRoute = { tab, sub };
        clearUrlHash();
      }
      return;
    }
    const safeTab = isTabAvailable(tab) ? tab : 'dashboard';
    const safeSub = safeTab === 'settings' ? sub : 'general';
    if (safeTab !== tab || safeSub !== sub) {
      syncUrlHash(safeTab, safeSub, false);
    }
    if (safeTab !== activeTab || safeSub !== settingsSubTab) {
      activeTab = safeTab;
      settingsSubTab = safeSub;
      refreshActiveView(true);
    }
  }

  function toggleSidebar() {
    sidebarCollapsed = !sidebarCollapsed;
    sidebarFlyout = null;
    localStorage.setItem('vane_sidebar_collapsed', sidebarCollapsed ? '1' : '0');
  }

  function showSidebarFlyout(el, info) {
    if (!sidebarCollapsed || !el) return;
    const rect = el.getBoundingClientRect();
    const centerY = rect.top + rect.height / 2;
    const top = Math.max(28, Math.min(centerY, window.innerHeight - 40));
    sidebarFlyout = {
      top: Math.round(top),
      left: Math.round(rect.right + 12),
      ...info,
    };
  }

  function hideSidebarFlyout() {
    sidebarFlyout = null;
  }

  function buildNavFlyout(item, groupLabel) {
    const dot = moduleStatusDot(item.id);
    const en = lang === 'en';
    let badge = typeof item.count === 'number' ? String(item.count) : '';
    let desc = groupLabel;
    let statusLabel = '';
    let statusKind = '';

    if (dot === 'danger') {
      statusLabel = t.dash.circuitOpen;
      statusKind = 'danger';
    } else if (dot === 'warn') {
      statusLabel = item.id === 'dashboard' ? (en ? 'Active bans' : '活跃封禁') : t.statuses.degraded;
      statusKind = 'warn';
    }

    if (item.id === 'dashboard') {
      const bans = dashboard?.bans?.length || 0;
      if (bans > 0) badge = `${bans}`;
      if (dashboard?.system) {
        const cpu = Math.round(dashboard.system.cpu_usage_pct || 0);
        const load = Number(dashboard.system.load_1m || 0).toFixed(2);
        desc = `CPU ${cpu}% · ${t.dash.load} ${load}`;
      }
    } else if (item.id === 'reverse_proxy') {
      const listeners = settingsJson?.reverse_proxy || [];
      const rules = listeners.reduce((n, l) => n + (l.rules?.length || 0), 0);
      desc = en
        ? `${groupLabel} · ${listeners.length} listeners / ${rules} rules`
        : `${groupLabel} · ${listeners.length} 监听器 / ${rules} 条规则`;
    } else if (item.id === 'port_forward') {
      const list = settingsJson?.port_forwards || [];
      const on = list.filter((p) => p.enabled).length;
      desc = en ? `${groupLabel} · ${on}/${list.length} enabled` : `${groupLabel} · ${on}/${list.length} 已启用`;
    } else if (item.id === 'ddns') {
      const list = settingsJson?.ddns || [];
      const on = list.filter((d) => d.enabled).length;
      desc = en ? `${groupLabel} · ${on}/${list.length} enabled` : `${groupLabel} · ${on}/${list.length} 已启用`;
    } else if (item.id === 'acme') {
      const list = settingsJson?.acme || [];
      const active = (dashboard?.certs || []).filter((c) => c.status === 'active').length;
      desc = en ? `${groupLabel} · ${active}/${list.length} active certs` : `${groupLabel} · ${active}/${list.length} 有效证书`;
    } else if (item.id === 'stun') {
      const list = settingsJson?.stun || [];
      const on = list.filter((s) => s.enabled).length;
      desc = en ? `${groupLabel} · ${on}/${list.length} enabled` : `${groupLabel} · ${on}/${list.length} 已启用`;
    } else if (item.id === 'docker') {
      const running = (containers || []).filter((c) => c.state === 'running').length;
      desc = containers.length
        ? en
          ? `${groupLabel} · ${running}/${containers.length} running`
          : `${groupLabel} · ${running}/${containers.length} 运行中`
        : `${groupLabel} · Docker Socket`;
    } else if (item.id === 'web_terminal') {
      desc = en ? `${groupLabel} · Interactive PTY Shell` : `${groupLabel} · 交互式 PTY 伪终端`;
    } else if (item.id === 'cron') {
      const list = settingsJson?.cron || [];
      const on = list.filter((c) => c.enabled).length;
      desc = en ? `${groupLabel} · ${on}/${list.length} enabled` : `${groupLabel} · ${on}/${list.length} 已启用`;
    } else if (item.id === 'logs') {
      desc = logs.length
        ? `${groupLabel} · ${logs.length} / ${logCapacity}`
        : en
          ? `${groupLabel} · In-memory ring log`
          : `${groupLabel} · 内存环形运行日志`;
    } else if (item.id === 'settings') {
      const onMods = Object.values(modules || {}).filter(Boolean).length;
      desc = en ? `${groupLabel} · ${onMods}/8 modules on` : `${groupLabel} · ${onMods}/8 子模块已开启`;
    }

    const lockState = isModuleProtected(item.id)
      ? isModuleLocked(item.id)
        ? 'locked'
        : 'unlocked'
      : '';
    return { title: item.label, badge, desc, statusLabel, statusKind, lockState };
  }

  function selectLang(nextLang) {
    lang = nextLang === 'en' ? 'en' : 'zh';
    hasExplicitLang = true;
    localStorage.setItem('vane_lang', lang);
  }

  function toggleLang() {
    selectLang(lang === 'zh' ? 'en' : 'zh');
  }

  function dismissToast(id) {
    const timer = toastTimers.get(id);
    if (timer) {
      clearTimeout(timer);
      toastTimers.delete(id);
    }
    toasts = toasts.filter((x) => x.id !== id);
  }

  function pauseToast(id) {
    const timer = toastTimers.get(id);
    if (timer) {
      clearTimeout(timer);
      toastTimers.delete(id);
    }
  }

  function resumeToast(id) {
    const item = toasts.find((x) => x.id === id);
    if (!item || toastTimers.has(id)) return;
    const duration = item.type === 'error' || item.type === 'warn' ? 4000 : 2500;
    toastTimers.set(id, setTimeout(() => dismissToast(id), duration));
  }

  function showToast(msg, type = 'info', customDuration = 0) {
    const id = nextToastId++;
    const duration = customDuration > 0 ? customDuration : type === 'error' || type === 'warn' ? 6000 : 3500;
    toasts = [...toasts.slice(-3), { id, message: String(msg), type }];
    toastTimers.set(id, setTimeout(() => dismissToast(id), duration));
  }

  function askConfirm({ title, message, confirmLabel = '', danger = true, onConfirm }) {
    confirmState = {
      open: true,
      title,
      message,
      confirmLabel: confirmLabel || t.confirmAction,
      danger,
      busy: false,
      onConfirm,
    };
  }

  async function runConfirmedAction() {
    if (!confirmState.onConfirm) {
      confirmState.open = false;
      return;
    }
    confirmState.busy = true;
    try {
      await confirmState.onConfirm();
      confirmState.open = false;
    } finally {
      confirmState.busy = false;
    }
  }

  function requestReauth({ title = '', description = '', actionLabel = '', unlockModule = '', requireMfa = false } = {}) {
    return new Promise((resolve) => {
      if (reauthState.open && reauthState.resolve) {
        reauthState.resolve(null);
      }
      reauthState = {
        open: true,
        title,
        description,
        actionLabel,
        unlockModule,
        requireMfa: Boolean(requireMfa),
        resolve,
      };
    });
  }

  function finishReauth(token, unlockedMap = null) {
    if (unlockedMap) syncUnlockedModules(unlockedMap);
    const fn = reauthState.resolve;
    reauthState = {
      open: false,
      title: '',
      description: '',
      actionLabel: '',
      unlockModule: '',
      requireMfa: false,
      resolve: null,
    };
    fn?.(token || null);
  }

  async function unlockModuleFlow(modId) {
    const modName = t.nav?.[modId] || modId;
    const tok = await requestReauth({
      title: t.reauth.moduleTitle.replace('{name}', modName),
      description: t.reauth.moduleDesc,
      actionLabel: t.reauth.unlockBtn,
      unlockModule: modId,
    });
    if (tok && modId === 'docker' && modules.docker && containers.length === 0) {
      apiFetch('/api/docker/containers')
        .then((r) => {
          containers = r.containers || [];
          dockerError = '';
        })
        .catch(() => {});
    }
    return tok;
  }

  async function relockCurrentModule(modId) {
    try {
      const r = await apiFetch('/api/auth/module-lock', {
        method: 'POST',
        body: JSON.stringify({ module: modId }),
      });
      syncUnlockedModules(r.unlocked_modules || {});
      showToast(t.reauth.relockedToast, 'info');
      if (activeTab === modId) {
        activeTab = 'dashboard';
        syncUrlHash('dashboard', 'general', false);
        await refreshActiveView(true);
      }
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  function moduleStatusDot(id) {
    if (id === 'dashboard') {
      if ((dashboard?.bans?.length || 0) > 0) return 'warn';
      return '';
    }
    const st = dashboard?.module_health?.[id]?.state;
    if (st === 'circuit_open') return 'danger';
    if (st === 'degraded') return 'warn';
    return '';
  }

  function clearSessionState(wipeRoute = false) {
    authenticated = false;
    mustChangePassword = false;
    dashboard = null;
    settingsJson = null;
    networkInfo = null;
    containers = [];
    dockerError = '';
    logs = [];
    logModules = [];
    restartRequiredFields = [];
    ptyEverOpened = false;
    unreadNotifications = 0;
    inboxModalOpen = false;
    userMenuOpen = false;
    unlockedModules = {};
    lockdownWarnings = [];
    lockdownKernelEnforced = true;
    if (wipeRoute) {
      pendingPostLoginRoute = null;
      activeTab = 'dashboard';
      settingsSubTab = 'general';
    } else if (activeTab !== 'dashboard' || settingsSubTab !== 'general') {
      pendingPostLoginRoute = { tab: activeTab, sub: settingsSubTab };
    }
    clearUrlHash();
  }

  function extractApiErrorCode(data) {
    if (!data || typeof data !== 'object') return '';
    if (typeof data.code === 'string' && data.code.trim()) return data.code.trim();
    if (typeof data.error === 'string' && /^[A-Z0-9_]+$/.test(data.error.trim())) return data.error.trim();
    return '';
  }

  function makeApiError(resStatus, data, fallbackMsg = '') {
    const code = extractApiErrorCode(data);
    const rawMsg = data?.message || data?.error || fallbackMsg || `HTTP ${resStatus}`;
    const err = new Error(localizeError(rawMsg, lang, code));
    err.status = resStatus;
    err.code = code;
    err.data = data || {};
    err.mfa_required = Boolean(data?.mfa_required || code === 'MFA_REAUTH_REQUIRED');
    err.module = data?.module || '';
    return err;
  }

  async function apiFetch(path, options = {}) {
    const { headers: optHeaders, ...restOptions } = options;
    const headers = new Headers(optHeaders || {});
    const isFormData = typeof FormData !== 'undefined' && restOptions.body instanceof FormData;
    if (!isFormData && !headers.has('content-type')) {
      headers.set('Content-Type', 'application/json');
    }
    const res = await fetch(path, {
      ...restOptions,
      headers,
    });
    const data = await res.json().catch(() => ({}));
    const errCode = extractApiErrorCode(data);
    if (res.status === 403 && errCode === 'MUST_CHANGE_INITIAL_PASSWORD') {
      mustChangePassword = true;
      throw makeApiError(res.status, data, 'Must change initial password');
    }
    if (res.status === 403 && errCode === 'MODULE_REAUTH_REQUIRED' && data.module) {
      const copy = { ...unlockedModules };
      delete copy[data.module];
      unlockedModules = copy;
    }
    if (res.status === 401 && !path.startsWith('/api/auth/')) {
      clearSessionState();
      const err = new Error(t.errors.UNAUTHORIZED);
      err.status = 401;
      err.code = 'UNAUTHORIZED';
      err.data = data;
      throw err;
    }
    if (!res.ok) {
      throw makeApiError(res.status, data);
    }
    return data;
  }

  function applyAuthStatus(st) {
    authenticated = Boolean(st.authenticated);
    mustChangePassword = Boolean(st.must_change_password);
    if ('initial_setup' in st) initialSetup = Boolean(st.initial_setup);
    username = st.username || 'admin';
    if ('password_login_enabled' in st) passwordLoginEnabled = Boolean(st.password_login_enabled);
    if ('totp_enabled' in st) totpEnabled = Boolean(st.totp_enabled);
    if ('passkey_enabled' in st) passkeyEnabled = Boolean(st.passkey_enabled);
    if ('has_passkeys' in st) hasPasskeys = Boolean(st.has_passkeys);
    sessionTtlSecs = st.session_ttl_secs || 3600;
    if (st.language && !hasExplicitLang) {
      lang = st.language === 'en' ? 'en' : 'zh';
    }
    if (st.modules) modules = st.modules;
    if (st.module_reauth) moduleReauth = st.module_reauth;
    if (st.unlocked_modules) syncUnlockedModules(st.unlocked_modules);
    if (typeof st.unread_notifications === 'number') unreadNotifications = st.unread_notifications;
  }

  async function checkAuthStatus() {
    loading = true;
    authConnError = '';
    try {
      const st = await apiFetch('/api/auth/status');
      applyAuthStatus(st);
      if (authenticated && !mustChangePassword) {
        pendingPostLoginRoute = null;
        if (!isTabAvailable(activeTab)) {
          activeTab = 'dashboard';
          settingsSubTab = 'general';
        }
        syncUrlHash(activeTab, settingsSubTab, false);
        await refreshActiveView();
      } else {
        clearUrlHash();
      }
    } catch (err) {
      authenticated = false;
      authConnError = err?.message || 'Connection failed';
      clearUrlHash();
    } finally {
      loading = false;
    }
  }

  async function refreshAuthStatusOnly() {
    try {
      const st = await apiFetch('/api/auth/status');
      applyAuthStatus(st);
    } catch {
      // ignore
    }
  }

  async function handleAuthenticated(st, toastMsg = '') {
    authConnError = '';
    applyAuthStatus(st);
    if (toastMsg) showToast(toastMsg, 'success');
    if (authenticated && !mustChangePassword) {
      if (pendingPostLoginRoute) {
        activeTab = pendingPostLoginRoute.tab;
        settingsSubTab = pendingPostLoginRoute.sub;
        pendingPostLoginRoute = null;
      }
      if (!isTabAvailable(activeTab)) {
        activeTab = 'dashboard';
        settingsSubTab = 'general';
      }
      if (activeTab === 'settings') settingsMenuOpen = true;
      syncUrlHash(activeTab, settingsSubTab, false);
      await refreshActiveView();
    } else {
      clearUrlHash();
    }
  }

  async function logout() {
    await apiFetch('/api/auth/logout', { method: 'POST' }).catch(() => {});
    clearSessionState(true);
    await checkAuthStatus();
  }

  function requestLogout() {
    askConfirm({
      title: t.logoutConfirmTitle,
      message: t.logoutConfirmDesc,
      confirmLabel: t.logout,
      danger: true,
      onConfirm: logout,
    });
  }

  async function ensureNetworkInfo(force = false) {
    if (!force && networkInfo) return;
    try {
      networkInfo = await apiFetch('/api/system/network-info');
    } catch {
      // ignore on restricted environments
    }
  }

  async function refreshActiveView(silent = false) {
    if (!authenticated || mustChangePassword) return;
    const myNonce = ++refreshNonce;
    const tab = activeTab;
    if (!silent) refreshing = true;
    try {
      const tasks = [];
      if (['dashboard', 'reverse_proxy', 'port_forward', 'ddns', 'acme', 'stun', 'cron'].includes(tab)) {
        tasks.push(
          apiFetch('/api/dashboard').then((r) => {
            if (myNonce === refreshNonce) {
              dashboard = r;
              if (typeof r?.unread_notifications === 'number') unreadNotifications = r.unread_notifications;
            }
          })
        );
      } else if (!dashboard) {
        tasks.push(
          apiFetch('/api/dashboard')
            .then((r) => {
              if (myNonce === refreshNonce) {
                dashboard = r;
                if (typeof r?.unread_notifications === 'number') unreadNotifications = r.unread_notifications;
              }
            })
            .catch(() => {})
        );
      }

      if (tab === 'logs') {
        const params = new URLSearchParams();
        if (logLevelFilter) params.set('level', logLevelFilter);
        if (logModuleFilter) params.set('module', logModuleFilter);
        const qs = params.toString();
        tasks.push(
          apiFetch(`/api/logs${qs ? `?${qs}` : ''}`).then((r) => {
            if (myNonce !== refreshNonce) return;
            logs = r.entries || [];
            logModules = r.modules || [];
            if (r.capacity) logCapacity = r.capacity;
            if (logModuleFilter && !logModules.includes(logModuleFilter)) {
              logModuleFilter = '';
            }
          })
        );
      }

      if (['dashboard', 'settings', 'reverse_proxy', 'port_forward', 'ddns', 'acme', 'stun', 'cron', 'docker', 'web_terminal'].includes(tab)) {
        if (!silent || !settingsJson) {
          tasks.push(
            apiFetch('/api/settings').then((r) => {
              if (myNonce !== refreshNonce) return;
              settingsJson = r;
              if (r?.modules) modules = r.modules;
              if (r?.module_reauth) moduleReauth = r.module_reauth;
            })
          );
        }
      }

      if (['reverse_proxy', 'port_forward', 'ddns', 'acme', 'settings'].includes(tab)) {
        tasks.push(ensureNetworkInfo(!silent));
      }

      if ((tab === 'docker' || tab === 'web_terminal' || tab === 'cron') && modules.docker && !isModuleLocked('docker')) {
        tasks.push(
          apiFetch('/api/docker/containers')
            .then((r) => {
              if (myNonce !== refreshNonce) return;
              containers = r.containers || [];
              dockerError = '';
            })
            .catch((err) => {
              if (myNonce !== refreshNonce) return;
              containers = [];
              dockerError = err.message;
            })
        );
      }

      await Promise.all(tasks);
    } catch (err) {
      if (!silent) showToast(err.message, 'error');
    } finally {
      if (myNonce === refreshNonce) refreshing = false;
    }
  }

  async function pollIncrementalLogs() {
    if (!authenticated || mustChangePassword || activeTab !== 'logs') return;
    try {
      const lastSeq = logs.length > 0 ? Math.max(...logs.map((e) => Number(e.seq || 0))) : 0;
      const params = new URLSearchParams();
      if (logLevelFilter) params.set('level', logLevelFilter);
      if (logModuleFilter) params.set('module', logModuleFilter);
      if (lastSeq > 0) params.set('after_seq', String(lastSeq));
      const qs = params.toString();
      const r = await apiFetch(`/api/logs${qs ? `?${qs}` : ''}`);
      logModules = r.modules || logModules;
      if (r.capacity) logCapacity = r.capacity;
      if (logModuleFilter && !logModules.includes(logModuleFilter)) {
        logModuleFilter = '';
        await refreshActiveView(true);
        return;
      }
      const incoming = r.entries || [];
      if (lastSeq > 0 && incoming.length > 0) {
        const merged = [...logs, ...incoming];
        logs = merged.slice(-logCapacity);
      } else if (lastSeq === 0) {
        logs = incoming;
      }
    } catch {
      // ignore transient live poll errors
    }
  }

  async function switchTab(id, sub = 'general') {
    if (!isTabAvailable(id)) return;
    if (isModuleLocked(id)) {
      const tok = await unlockModuleFlow(id);
      if (!tok) return;
    }
    activeTab = id;
    if (id === 'settings') settingsSubTab = sub;
    syncUrlHash(id, settingsSubTab, true);
    await refreshActiveView();
  }

  async function navigateTarget(target) {
    const raw = String(target || 'dashboard').replace(/^#\/?/, '');
    const [tabPart, subPart] = raw.split('/');
    if (tabPart === 'settings') {
      const validSub = ['general', 'appearance', 'security', 'notifications', 'backup', 'update'].includes(subPart)
        ? subPart
        : 'general';
      await switchTab('settings', validSub);
      return;
    }
    if (VALID_TABS.has(tabPart) && isTabAvailable(tabPart)) {
      await switchTab(tabPart);
      return;
    }
    showToast(t.errors.MODULE_DISABLED, 'warn');
  }

  async function toggleModule(key) {
    const turningOff = Boolean(modules[key]);
    let reauthToken = '';
    if (turningOff && isModuleLocked(key)) {
      const tok = await requestReauth({
        title: t.reauth.disableModuleTitle,
        description: t.reauth.disableModuleDesc.replace('{name}', t.nav[key] || key),
        actionLabel: t.reauth.verifyBtn,
      });
      if (!tok) return;
      reauthToken = tok;
    }
    const updated = { ...modules, [key]: !modules[key] };
    try {
      const payload = reauthToken ? { ...updated, reauth_token: reauthToken } : updated;
      const r = await apiFetch('/api/modules', {
        method: 'PUT',
        body: JSON.stringify(payload),
      });
      modules = r.modules;
      if (r.unlocked_modules) syncUnlockedModules(r.unlocked_modules);
      if (settingsJson) settingsJson.modules = r.modules;
      if (!modules[activeTab] && !['dashboard', 'logs', 'settings'].includes(activeTab)) {
        activeTab = 'settings';
        syncUrlHash(activeTab, settingsSubTab, false);
      }
      showToast(`${t.nav[key] || key}: ${modules[key] ? t.enabled : t.disabled}`, 'success');
      await refreshActiveView();
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  async function toggleModuleReauth(key, retryState = {}) {
    const wasOn = Boolean(moduleReauth?.[key]);
    let reauthToken = retryState.reauthToken || '';
    if (wasOn && !reauthToken) {
      const tok = await requestReauth({
        title: t.reauth.disableModuleReauthTitle,
        description: t.reauth.disableModuleReauthDesc.replace('{name}', t.nav[key] || key),
        actionLabel: t.reauth.verifyBtn,
        requireMfa: true,
      });
      if (!tok) return;
      reauthToken = tok;
    }
    try {
      const r = await apiFetch('/api/modules/reauth', {
        method: 'PUT',
        headers: reauthToken ? { 'x-vane-reauth-token': reauthToken } : {},
        body: JSON.stringify({
          module: key,
          require_reauth: !wasOn,
          reauth_token: reauthToken,
        }),
      });
      if (r.module_reauth) moduleReauth = r.module_reauth;
      if (r.unlocked_modules) syncUnlockedModules(r.unlocked_modules);
      if (settingsJson) {
        settingsJson.module_reauth = moduleReauth;
        if (settingsJson.web_terminal && key === 'web_terminal') {
          settingsJson.web_terminal.require_reauth = Boolean(moduleReauth.web_terminal);
        }
      }
      showToast(
        `${t.nav[key] || key}: ${!wasOn ? t.cfg.moduleReauthEnabledToast : t.cfg.moduleReauthDisabledToast}`,
        'success'
      );
    } catch (err) {
      if (
        err?.status === 403 &&
        (err?.code === 'MFA_REAUTH_REQUIRED' || err?.code === 'REAUTH_REQUIRED') &&
        !retryState.retried
      ) {
        const tok = await requestReauth({
          title: t.reauth.disableModuleReauthTitle,
          description: t.reauth.disableModuleReauthDesc.replace('{name}', t.nav[key] || key),
          actionLabel: t.reauth.verifyBtn,
          requireMfa: Boolean(err?.mfa_required || err?.code === 'MFA_REAUTH_REQUIRED'),
        });
        if (!tok) return;
        return toggleModuleReauth(key, { retried: true, reauthToken: tok });
      }
      showToast(err.message, 'error');
    }
  }

  async function saveFullSettings(nextObj, renames = [], extraHeaders = {}, retryState = {}) {
    try {
      const payload = renames?.length ? { ...nextObj, _renames: renames } : nextObj;
      const res = await fetch('/api/settings', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', ...(extraHeaders || {}) },
        body: JSON.stringify(payload),
      });
      const data = await res.json().catch(() => ({}));
      const errCode = extractApiErrorCode(data);
      if (res.status === 403 && errCode === 'MUST_CHANGE_INITIAL_PASSWORD') {
        mustChangePassword = true;
        throw makeApiError(res.status, data);
      }
      if (res.status === 403 && errCode === 'MODULE_REAUTH_REQUIRED' && data.module) {
        const copy = { ...unlockedModules };
        delete copy[data.module];
        unlockedModules = copy;
        const retriedModules = retryState.retriedModules instanceof Set ? retryState.retriedModules : new Set();
        if (!retriedModules.has(data.module)) {
          const tok = await unlockModuleFlow(data.module);
          if (!tok) return false;
          const nextRetried = new Set(retriedModules);
          nextRetried.add(data.module);
          return saveFullSettings(nextObj, renames, extraHeaders, { ...retryState, retriedModules: nextRetried });
        }
      }
      if (
        res.status === 403 &&
        (errCode === 'REAUTH_REQUIRED' || errCode === 'MFA_REAUTH_REQUIRED') &&
        !retryState.retriedReauth
      ) {
        const needMfa = Boolean(data.mfa_required || errCode === 'MFA_REAUTH_REQUIRED');
        const tok = await requestReauth({
          title: t.reauth.sensitiveSettingsTitle,
          description: needMfa ? t.reauth.sensitiveSettingsMfaDesc : t.reauth.sensitiveSettingsDesc,
          actionLabel: t.saveSettings,
          requireMfa: needMfa,
        });
        if (!tok) return false;
        return saveFullSettings(
          nextObj,
          renames,
          { ...(extraHeaders || {}), 'x-vane-reauth-token': tok },
          { ...retryState, retriedReauth: true }
        );
      }
      if (res.status === 401) {
        clearSessionState();
        throw new Error(t.errors.UNAUTHORIZED);
      }
      if (!res.ok) {
        throw makeApiError(res.status, data);
      }
      const restartHdr = res.headers.get('x-vane-restart-required');
      if (restartHdr) {
        const nextFields = restartHdr.split(',').map((s) => s.trim()).filter(Boolean);
        restartRequiredFields = [...new Set([...restartRequiredFields, ...nextFields])];
        showToast(t.restartBannerTitle, 'warn');
      } else {
        showToast(t.settingsSaved, 'success');
      }
      settingsJson = data;
      if (data?.modules) modules = data.modules;
      if (data?.admin?.session_ttl_secs) sessionTtlSecs = data.admin.session_ttl_secs;
      if (data?.admin && 'password_login_enabled' in data.admin) {
        passwordLoginEnabled = Boolean(data.admin.password_login_enabled);
      }
      await refreshActiveView(true);
      return true;
    } catch (err) {
      showToast(err.message, 'error');
      return false;
    }
  }

  function requestLockdownToggle(enable) {
    askConfirm({
      title: enable ? t.lockdownOnConfirmTitle : t.lockdownOffConfirmTitle,
      message: enable ? t.lockdownOnConfirmDesc : t.lockdownOffConfirmDesc,
      confirmLabel: enable ? t.lockdownOff : t.lockdownOn,
      danger: enable,
      onConfirm: async () => {
        try {
          const r = await apiFetch('/api/firewall/lockdown', {
            method: 'POST',
            body: JSON.stringify({ enable }),
          });
          const isActive = 'lockdown' in r ? Boolean(r.lockdown) : Boolean(r.active);
          const warnings = Array.isArray(r.warnings)
            ? r.warnings.map((w) => String(w || '').trim()).filter(Boolean)
            : [];
          const kernelEnforced = r.kernel_enforced !== false;
          lockdownWarnings = isActive ? warnings : [];
          lockdownKernelEnforced = isActive ? kernelEnforced : true;

          if (dashboard?.firewall) {
            dashboard = {
              ...dashboard,
              firewall: { ...dashboard.firewall, lockdown: isActive },
            };
          }
          if (!kernelEnforced) {
            const detail = warnings.length ? ` (${warnings.join(' · ')})` : '';
            showToast(`${t.lockdownKernelNotEnforcedToast}${detail}`, 'warn', 10000);
          } else if (warnings.length > 0) {
            showToast(isActive ? t.lockdownEnabledToast : t.lockdownDisabledToast, isActive ? 'warn' : 'success');
            showToast(`${t.lockdownWarningsPrefix}: ${warnings.join(' · ')}`, 'warn', 10000);
          } else {
            showToast(isActive ? t.lockdownEnabledToast : t.lockdownDisabledToast, isActive ? 'warn' : 'success');
          }
          dashboard = await apiFetch('/api/dashboard').catch(() => dashboard);
        } catch (err) {
          showToast(err.message, 'error');
        }
      },
    });
  }

  async function openContainerShell(containerName) {
    if (isModuleLocked('docker')) {
      const tok = await unlockModuleFlow('docker');
      if (!tok) return;
    }
    terminalInitialTarget = `container:${containerName}`;
    terminalTargetNonce += 1;
    await switchTab('web_terminal');
  }

  checkAuthStatus();
</script>

<svelte:window onhashchange={handleHashChange} />

<ToastStack
  {toasts}
  onDismiss={dismissToast}
  onPause={pauseToast}
  onResume={resumeToast}
  dismissLabel={t.common.dismiss}
/>
<ConfirmModal
  open={confirmState.open}
  title={confirmState.title}
  message={confirmState.message}
  confirmLabel={confirmState.confirmLabel}
  cancelLabel={t.cancel}
  danger={confirmState.danger}
  busy={confirmState.busy}
  onConfirm={runConfirmedAction}
  onCancel={() => { if (!confirmState.busy) confirmState.open = false; }}
/>
<ReauthModal
  open={reauthState.open}
  title={reauthState.title}
  description={reauthState.description}
  actionLabel={reauthState.actionLabel}
  unlockModule={reauthState.unlockModule}
  requireMfa={reauthState.requireMfa}
  mfaConfigured={totpEnabled || (passkeyEnabled && hasPasskeys)}
  {username}
  {t}
  {lang}
  {apiFetch}
  onSuccess={(tok, unlocked) => finishReauth(tok, unlocked)}
  onCancel={() => finishReauth(null)}
/>
<NotificationInboxPanel
  open={inboxModalOpen}
  {sidebarCollapsed}
  {t}
  {lang}
  {apiFetch}
  {showToast}
  {askConfirm}
  onClose={() => (inboxModalOpen = false)}
  onNavigate={(mod) => {
    inboxModalOpen = false;
    navigateTarget(mod);
  }}
  onOpenChannelSettings={() => {
    inboxModalOpen = false;
    switchTab('settings', 'notifications');
  }}
  onUnreadChange={(n) => (unreadNotifications = Number(n || 0))}
/>

{#if loading}
  <div class="auth-shell">
    <div class="card boot-card">
      <img src="/icon.svg" alt="Vane" class="brand-icon" />
      <Icons name="loader" size={16} class="is-spinning" />
      <span class="mono" style="font-size:13.5px;color:var(--text-secondary);">{t.loadingGateway}</span>
    </div>
  </div>
{:else if !authenticated || mustChangePassword}
  <AuthGate
    {t}
    {lang}
    {toggleLang}
    {themeMode}
    onSelectThemeMode={(m) => (themeMode = m)}
    {authenticated}
    {mustChangePassword}
    {initialSetup}
    {username}
    {passwordLoginEnabled}
    {totpEnabled}
    {passkeyEnabled}
    {hasPasskeys}
    connError={authConnError}
    onRetryStatus={checkAuthStatus}
    {apiFetch}
    onAuthenticated={handleAuthenticated}
    onLogout={logout}
  />
{:else}
  {@const activeNav = navItems.find((n) => n.id === activeTab)}
  {@const activeSubItem = activeTab === 'settings' ? settingsSubItems.find((s) => s.id === settingsSubTab) : null}
  {@const activeSubLabel = activeSubItem?.label || ''}
  {@const hasMobileTopbarControls = (isModuleProtected(activeTab) && !isModuleLocked(activeTab)) || Boolean(dashboard?.firewall)}
  <div class="layout {sidebarCollapsed ? 'sidebar-collapsed' : ''}">
    <!-- 桌面端左侧悬浮玻璃侧边栏（对齐 Arcane 布局：分组导航 + 可展开设置树 + 底部版本/消息圆钮/用户弹框/折叠） -->
    <aside class="sidebar" onmouseleave={hideSidebarFlyout}>
      <div class="brand">
        <img src="/icon.svg" alt="Vane" class="brand-icon" />
        {#if !sidebarCollapsed}
          <div style="min-width:0;flex:1;">
            <div class="brand-name">Vane</div>
            <div class="brand-sub">{t.dualStackTag}</div>
          </div>
        {/if}
      </div>

      <div
        bind:this={sidebarScrollEl}
        class="sidebar-scroll {sidebarCanScrollTop ? 'fade-top' : ''} {sidebarCanScrollBottom ? 'fade-bottom' : ''}"
        onscroll={() => {
          hideSidebarFlyout();
          updateSidebarScrollState();
        }}
      >
        {#each navGroups as group, gIdx (group.label)}
          <div class="nav-group-label {gIdx === 0 ? 'first' : ''}">{group.label}</div>
          {#each group.items as item (item.id)}
            {@const dot = moduleStatusDot(item.id)}
            {@const collapsedCount =
              item.id === 'dashboard'
                ? (dashboard?.bans?.length || 0)
                : typeof item.count === 'number'
                  ? item.count
                  : 0}
            {@const isSettingsItem = item.id === 'settings'}
            <button
              type="button"
              class="nav-btn {activeTab === item.id ? 'active' : ''}"
              aria-label={item.label}
              aria-current={activeTab === item.id ? 'page' : undefined}
              aria-expanded={isSettingsItem && !sidebarCollapsed ? settingsMenuOpen : undefined}
              onmouseenter={(e) => showSidebarFlyout(e.currentTarget, buildNavFlyout(item, group.label))}
              onfocus={(e) => showSidebarFlyout(e.currentTarget, buildNavFlyout(item, group.label))}
              onmouseleave={hideSidebarFlyout}
              onblur={hideSidebarFlyout}
              onclick={() => {
                hideSidebarFlyout();
                if (isSettingsItem && !sidebarCollapsed) {
                  if (activeTab === 'settings') {
                    settingsMenuOpen = !settingsMenuOpen;
                  } else {
                    settingsMenuOpen = true;
                    switchTab('settings', settingsSubTab);
                  }
                } else {
                  switchTab(item.id);
                }
              }}
            >
              <Icons name={item.id} size={17} />
              {#if !sidebarCollapsed}
                <span class="nav-label">{item.label}</span>
                <span class="nav-meta">
                  {#if isModuleProtected(item.id)}
                    <span style="display:inline-flex;color:{isModuleLocked(item.id) ? 'var(--text-muted)' : 'var(--accent)'};">
                      <Icons name={isModuleLocked(item.id) ? 'lock' : 'unlock'} size={12} />
                    </span>
                  {/if}
                  {#if dot}<span class="status-dot {dot}"></span>{/if}
                  {#if typeof item.count === 'number'}
                    <span class="nav-count num">{item.count}</span>
                  {/if}
                  {#if isSettingsItem}
                    <span class="nav-chevron {settingsMenuOpen ? 'open' : ''}">
                      <Icons name="chevron_right" size={14} />
                    </span>
                  {/if}
                </span>
              {:else}
                {#if collapsedCount > 0}
                  <span class="nav-badge-collapsed num {dot === 'danger' ? 'danger' : dot === 'warn' ? 'warn' : ''}">
                    {collapsedCount > 99 ? '99+' : collapsedCount}
                  </span>
                {:else if dot}
                  <span class="status-dot {dot} nav-dot-collapsed"></span>
                {/if}
                {#if isModuleProtected(item.id)}
                  <span
                    class="nav-lock-collapsed {isModuleLocked(item.id) ? '' : 'unlocked'}"
                    aria-hidden="true"
                  >
                    <Icons name={isModuleLocked(item.id) ? 'lock' : 'unlock'} size={9} />
                  </span>
                {/if}
              {/if}
            </button>

            {#if isSettingsItem && !sidebarCollapsed && settingsMenuOpen}
              <div class="nav-sub-list">
                {#each settingsSubItems as sub (sub.id)}
                  <button
                    type="button"
                    class="nav-sub-btn {activeTab === 'settings' && settingsSubTab === sub.id ? 'active' : ''}"
                    title={sub.label}
                    aria-current={activeTab === 'settings' && settingsSubTab === sub.id ? 'page' : undefined}
                    onclick={() => switchTab('settings', sub.id)}
                  >
                    <Icons name={sub.icon} size={14} />
                    <span class="nav-label">{sub.shortLabel}</span>
                  </button>
                {/each}
              </div>
            {/if}
          {/each}
        {/each}
      </div>

      <!-- Arcane 底部双行区：版本 + 圆形消息通知按钮 / 用户弹框 + 侧边栏折叠按钮 -->
      <div class="sidebar-footer">
        <div class="sidebar-footer-row">
          {#if !sidebarCollapsed}
            <button
              type="button"
              class="sidebar-ver-btn mono"
              title={t.cfg.tabUpdate}
              onclick={() => {
                settingsMenuOpen = true;
                switchTab('settings', 'update');
              }}
            >
              {appVersionLabel}
            </button>
          {/if}
          <button
            type="button"
            class="activity-circle-btn {inboxModalOpen ? 'active' : ''}"
            title={t.inbox.topbarLabel}
            aria-label={t.inbox.topbarLabel}
            aria-expanded={inboxModalOpen}
            onclick={() => {
              userMenuOpen = false;
              inboxModalOpen = !inboxModalOpen;
            }}
          >
            <Icons name="bell" size={15} />
            {#if unreadNotifications > 0}
              <span class="activity-circle-badge num">{unreadNotifications > 99 ? '99+' : unreadNotifications}</span>
            {/if}
          </button>
        </div>

        <div class="sidebar-footer-row">
          <button
            bind:this={userBtnEl}
            type="button"
            class="sidebar-user-btn {userMenuOpen ? 'open' : ''}"
            aria-haspopup="menu"
            aria-expanded={userMenuOpen}
            onclick={() => {
              inboxModalOpen = false;
              toggleUserMenu();
            }}
          >
            <span class="sidebar-avatar" aria-hidden="true">
              {(username || 'A').slice(0, 1).toUpperCase()}
            </span>
            {#if !sidebarCollapsed}
              <span class="sidebar-username">{username}</span>
            {/if}
          </button>
          <button
            type="button"
            class="sidebar-pin-btn"
            title={sidebarCollapsed ? t.expandSidebar : t.collapseSidebar}
            aria-label={sidebarCollapsed ? t.expandSidebar : t.collapseSidebar}
            aria-expanded={!sidebarCollapsed}
            onclick={toggleSidebar}
          >
            <Icons name="panel_left" size={15} />
          </button>
        </div>
      </div>
    </aside>

    <!-- Arcane 用户弹出菜单（含快捷主题与语言切换） -->
    {#if userMenuOpen}
      <div
        bind:this={userPopoverEl}
        id="vane-user-popover"
        class="user-popover"
        role="menu"
        tabindex="-1"
        style={userMenuStyle}
      >
        <div class="user-popover-head">
          <span class="sidebar-avatar" style="width:34px;height:34px;font-size:14px;" aria-hidden="true">
            {(username || 'A').slice(0, 1).toUpperCase()}
          </span>
          <div style="min-width:0;flex:1;">
            <div style="font-size:14px;font-weight:700;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{username}</div>
            <div style="font-size:11.5px;color:var(--text-muted);">{t.adminLabel} · Vane</div>
          </div>
        </div>

        <div class="user-popover-quick">
          <div class="user-popover-seg" role="group" aria-label={t.themeModeLabel}>
            {#each [
              { id: 'auto', icon: 'monitor', label: t.themeAuto },
              { id: 'light', icon: 'sun', label: t.themeLight },
              { id: 'dark', icon: 'moon', label: t.themeDark },
            ] as mode (mode.id)}
              <button
                type="button"
                class="user-popover-seg-btn {themeMode === mode.id ? 'active' : ''}"
                aria-pressed={themeMode === mode.id}
                title={mode.label}
                onclick={() => (themeMode = mode.id)}
              >
                <Icons name={mode.icon} size={13} />
                <span>{mode.label}</span>
              </button>
            {/each}
          </div>
          <button
            type="button"
            class="user-popover-lang-btn"
            aria-label={t.cfg.lblLanguage}
            onclick={toggleLang}
          >
            <Icons name="globe" size={13} />
            <span>{lang === 'zh' ? 'Switch to English' : '切换为简体中文'}</span>
          </button>
        </div>

        <div class="user-popover-sep"></div>
        <button
          type="button"
          class="user-popover-item"
          role="menuitem"
          onclick={() => {
            userMenuOpen = false;
            settingsMenuOpen = true;
            switchTab('settings', 'security');
          }}
        >
          <Icons name="user" size={15} />
          <span>{t.cfg.tabSecurityShort || t.cfg.tabSecurity}</span>
        </button>
        <button
          type="button"
          class="user-popover-item"
          role="menuitem"
          onclick={() => {
            userMenuOpen = false;
            settingsMenuOpen = true;
            switchTab('settings', 'appearance');
          }}
        >
          <Icons name="palette" size={15} />
          <span>{t.cfg.tabAppearance}</span>
        </button>
        {#if pwaState.canPrompt}
          <button
            type="button"
            class="user-popover-item"
            role="menuitem"
            onclick={() => {
              userMenuOpen = false;
              handleInstallPwa();
            }}
          >
            <Icons name="download" size={15} />
            <span>{t.cfg.pwaInstallBtn}</span>
          </button>
        {/if}
        <div class="user-popover-sep"></div>
        <button
          type="button"
          class="user-popover-item danger"
          role="menuitem"
          onclick={() => {
            userMenuOpen = false;
            requestLogout();
          }}
        >
          <Icons name="logout" size={15} />
          <span>{t.logout}</span>
        </button>
      </div>
    {/if}

    <!-- 侧边栏折叠态悬停详情浮层 -->
    {#if sidebarCollapsed && sidebarFlyout}
      <div
        class="sidebar-flyout"
        role="tooltip"
        style={`top:${sidebarFlyout.top}px;left:${sidebarFlyout.left}px;`}
      >
        <div class="sidebar-flyout-head">
          <span class="sidebar-flyout-title">{sidebarFlyout.title}</span>
          {#if sidebarFlyout.badge}
            <span class="badge badge-muted num" style="padding:1px 7px;font-size:11px;">{sidebarFlyout.badge}</span>
          {/if}
          {#if sidebarFlyout.lockState}
            <span
              class="badge {sidebarFlyout.lockState === 'locked' ? 'badge-muted' : 'badge-ok'}"
              style="padding:1px 7px;font-size:11px;"
            >
              <Icons name={sidebarFlyout.lockState === 'locked' ? 'lock' : 'unlock'} size={10} />
              <span>
                {sidebarFlyout.lockState === 'locked'
                  ? lang === 'en'
                    ? 'Re-auth'
                    : '需二次验证'
                  : lang === 'en'
                    ? 'Unlocked'
                    : '已解锁'}
              </span>
            </span>
          {/if}
          {#if sidebarFlyout.statusLabel}
            <span class="badge {sidebarFlyout.statusKind === 'danger' ? 'badge-danger' : 'badge-warn'}" style="padding:1px 7px;font-size:11px;">
              {sidebarFlyout.statusLabel}
            </span>
          {/if}
        </div>
        {#if sidebarFlyout.desc}
          <div class="sidebar-flyout-desc">{sidebarFlyout.desc}</div>
        {/if}
      </div>
    {/if}

    <!-- 右侧独立圆角主内容玻璃外壳 -->
    <div class="main-shell">
      <!-- 移动端吸顶悬浮磨砂顶栏（单标题、大触控区、快捷刷新/消息/账户） -->
      <div class="mobile-topbar">
        <div class="mobile-crumb">
          {#if activeTab !== 'dashboard'}
            <button type="button" class="mobile-crumb-back" aria-label={t.nav.dashboard} onclick={() => switchTab('dashboard')}>
              <Icons name="arrow_left" size={17} />
            </button>
          {:else}
            <img src="/icon.svg" alt="" class="mobile-brand-mark" aria-hidden="true" />
          {/if}
          <span class="mobile-crumb-title">
            {#if activeTab === 'settings' && activeSubItem}
              {activeSubItem.shortLabel}
            {:else}
              {activeNav?.label || t.nav.dashboard}
            {/if}
          </span>
        </div>
        <div class="mobile-topbar-actions">
          <button
            type="button"
            class="mobile-icon-btn"
            aria-label={t.refresh}
            title={t.refresh}
            disabled={refreshing}
            onclick={() => refreshActiveView()}
          >
            <Icons name="refresh" size={16} class={refreshing ? 'is-spinning' : ''} />
          </button>
          <button
            type="button"
            class="activity-circle-btn {inboxModalOpen ? 'active' : ''}"
            aria-label={t.inbox.topbarLabel}
            aria-expanded={inboxModalOpen}
            onclick={() => {
              userMenuOpen = false;
              inboxModalOpen = !inboxModalOpen;
            }}
          >
            <Icons name="bell" size={16} />
            {#if unreadNotifications > 0}
              <span class="activity-circle-badge num">{unreadNotifications > 99 ? '99+' : unreadNotifications}</span>
            {/if}
          </button>
          <button
            bind:this={mobileUserBtnEl}
            type="button"
            class="mobile-avatar-btn"
            aria-label={username || t.adminLabel}
            aria-haspopup="menu"
            aria-expanded={userMenuOpen}
            onclick={() => {
              inboxModalOpen = false;
              toggleUserMenu(mobileUserBtnEl, true);
            }}
          >
            <span class="sidebar-avatar" aria-hidden="true">
              {(username || 'A').slice(0, 1).toUpperCase()}
            </span>
          </button>
        </div>
      </div>

      <main class="main-area">
        <header class="topbar {hasMobileTopbarControls ? '' : 'mobile-empty'}">
          <div class="topbar-title-group">
            <h1 class="topbar-title">
              {activeSubLabel || activeNav?.label || t.nav.dashboard}
            </h1>
            {#if activeTab === 'settings' && activeSubLabel}
              <div class="topbar-sub">{t.nav.settings}</div>
            {/if}
          </div>
          <div class="btn-group topbar-actions">
            {#if isModuleProtected(activeTab) && !isModuleLocked(activeTab)}
              <button
                type="button"
                class="btn btn-sm btn-soft"
                onclick={() => relockCurrentModule(activeTab)}
              >
                <Icons name="unlock" size={13} />
                <span>{t.reauth.relockModule}</span>
              </button>
            {/if}
            <button type="button" class="btn btn-sm desktop-only" disabled={refreshing} onclick={() => refreshActiveView()}>
              <Icons name="refresh" size={14} class={refreshing ? 'is-spinning' : ''} />
              <span>{refreshing ? t.common.loading : t.refresh}</span>
            </button>
            {#if dashboard?.firewall}
              <span class="topbar-action-sep desktop-only" aria-hidden="true"></span>
              <button
                type="button"
                class="btn btn-sm {dashboard.firewall.lockdown ? 'btn-primary' : 'btn-lockdown-standby'}"
                onclick={() => requestLockdownToggle(!dashboard.firewall.lockdown)}
              >
                <Icons name="shield" size={14} />
                <span>{dashboard.firewall.lockdown ? t.lockdownOn : t.lockdownOff}</span>
              </button>
            {/if}
          </div>
        </header>

      {#if dashboard?.firewall?.lockdown}
        <div class="banner banner-danger" role="alert">
          <div style="display:flex;gap:10px;align-items:flex-start;flex:1;min-width:0;">
            <Icons name="shield" size={18} />
            <div style="min-width:0;">
              <div style="font-weight:700;">{t.lockdownActiveBannerTitle}</div>
              <div style="font-size:12px;color:var(--text-secondary);">{t.lockdownActiveBannerDesc}</div>
              {#if !lockdownKernelEnforced || lockdownWarnings.length > 0}
                <div style="font-size:12px;color:var(--warn);margin-top:4px;word-break:break-word;">
                  {t.lockdownDegradedBannerHint}{!lockdownKernelEnforced
                    ? `${t.lockdownKernelNotEnforcedToast}${lockdownWarnings.length ? ` (${lockdownWarnings.join(' · ')})` : ''}`
                    : lockdownWarnings.join(' · ')}
                </div>
              {/if}
            </div>
          </div>
          <button type="button" class="btn btn-xs btn-primary" onclick={() => requestLockdownToggle(false)}>
            {t.lockdownOn}
          </button>
        </div>
      {/if}

      {#if restartRequiredFields.length > 0}
        <div class="banner banner-warn">
          <div style="display:flex;gap:10px;align-items:flex-start;flex:1;min-width:0;">
            <Icons name="alert" size={18} />
            <div style="min-width:0;">
              <div style="font-weight:700;">{t.restartBannerTitle}</div>
              <div style="font-size:12px;color:var(--text-secondary);word-break:break-word;">
                {t.restartBannerDesc} <code class="mono">{restartRequiredFields.join(', ')}</code>
              </div>
            </div>
          </div>
          <button type="button" class="btn btn-xs" aria-label={t.close} onclick={() => restartRequiredFields = []}>
            <Icons name="x" size={13} />
          </button>
        </div>
      {/if}

      {#key activeTab === 'settings' ? `settings:${settingsSubTab}` : activeTab}
        <div class="view-stage">
          {#if isModuleLocked(activeTab)}
            <div class="card module-lock-gate">
          <div style="width:52px;height:52px;border-radius:14px;background:var(--accent-soft);color:var(--accent);display:grid;place-items:center;margin:0 auto 14px;">
            <Icons name="lock" size={24} />
          </div>
          <h2 style="font-size:18px;font-weight:700;margin-bottom:8px;">
            {t.reauth.moduleLockedTitle.replace('{name}', t.nav[activeTab] || activeTab)}
          </h2>
          <p style="font-size:13px;color:var(--text-secondary);margin-bottom:18px;line-height:1.55;">
            {t.reauth.moduleLockedDesc}
          </p>
          <button
            type="button"
            class="btn btn-primary"
            onclick={async () => {
              const tok = await unlockModuleFlow(activeTab);
              if (tok) await refreshActiveView();
            }}
          >
            <Icons name="shield" size={15} />
            <span>{t.reauth.unlockBtn}</span>
          </button>
        </div>
      {:else if activeTab === 'dashboard'}
        <DashboardView
          {t}
          {lang}
          {dashboard}
          {settingsJson}
          {networkInfo}
          onEnsureNetworkInfo={ensureNetworkInfo}
          onSaveSettings={saveFullSettings}
          {askConfirm}
          onRefresh={refreshActiveView}
          onNavigate={(tab) => switchTab(tab)}
          {apiFetch}
          {showToast}
        />
      {:else if (activeTab === 'reverse_proxy' && modules.reverse_proxy) || (activeTab === 'port_forward' && modules.port_forward)}
        <NetworkRulesView
          mode={activeTab}
          {t}
          {lang}
          {settingsJson}
          {dashboard}
          {networkInfo}
          onSaveSettings={saveFullSettings}
          {askConfirm}
          {apiFetch}
          {showToast}
          onRefresh={refreshActiveView}
        />
      {:else if (activeTab === 'ddns' && modules.ddns) || (activeTab === 'acme' && modules.acme) || (activeTab === 'stun' && modules.stun)}
        <DomainCertStunView
          mode={activeTab}
          {t}
          {lang}
          {settingsJson}
          {dashboard}
          {networkInfo}
          onSaveSettings={saveFullSettings}
          {askConfirm}
          {apiFetch}
          {showToast}
          onRefresh={refreshActiveView}
        />
      {:else if (activeTab === 'docker' && modules.docker) || (activeTab === 'cron' && modules.cron) || activeTab === 'logs'}
        <OpsViews
          mode={activeTab}
          {t}
          {lang}
          {settingsJson}
          {dashboard}
          {containers}
          {dockerError}
          {logs}
          {logModules}
          {logCapacity}
          {logLevelFilter}
          {logModuleFilter}
          onChangeLogFilter={async (lvl, mod) => {
            logLevelFilter = lvl;
            logModuleFilter = mod;
            await refreshActiveView();
          }}
          onPollLogsIncremental={pollIncrementalLogs}
          webTerminalEnabled={modules.web_terminal}
          onOpenContainerTerminal={openContainerShell}
          onSaveSettings={saveFullSettings}
          {askConfirm}
          {apiFetch}
          {showToast}
          onRefresh={refreshActiveView}
        />
      {:else if activeTab === 'settings'}
        <SettingsView
          {t}
          {lang}
          onSelectLang={selectLang}
          {themeMode}
          onSelectThemeMode={(m) => (themeMode = m)}
          {oledMode}
          onToggleOledMode={() => (oledMode = !oledMode)}
          {accentColor}
          onSelectAccentColor={(c) => (accentColor = c)}
          accentPresets={ACCENT_PRESETS}
          {sidebarCollapsed}
          onToggleSidebar={toggleSidebar}
          {pwaState}
          onInstallPwa={handleInstallPwa}
          {modules}
          {moduleReauth}
          {isModuleLocked}
          onNavigate={switchTab}
          {settingsJson}
          {networkInfo}
          subTab={settingsSubTab}
          onSubTabChange={(sub) => {
            settingsSubTab = sub;
            syncUrlHash('settings', sub, false);
          }}
          onToggleModule={toggleModule}
          onToggleModuleReauth={toggleModuleReauth}
          onSaveSettings={saveFullSettings}
          onAuthRefresh={refreshAuthStatusOnly}
          onBackupRestored={(st) => {
            applyAuthStatus(st);
            if (Array.isArray(st?.restart_required) && st.restart_required.length > 0) {
              restartRequiredFields = [...new Set([...restartRequiredFields, ...st.restart_required])];
            }
          }}
          {askConfirm}
          {requestReauth}
          {apiFetch}
          {showToast}
          onRefresh={refreshActiveView}
        />
          {/if}
        </div>
      {/key}

      <!-- Web 终端加载后保持挂载（切 Tab 时用 CSS 隐藏，不误杀正在运行的 PTY 会话；受二次验证锁定时卸载保护） -->
      {#if modules.web_terminal && !isModuleLocked('web_terminal') && (ptyEverOpened || activeTab === 'web_terminal')}
        <div style={activeTab === 'web_terminal' ? '' : 'display:none;'}>
          {#if TerminalComp}
            <TerminalComp
              {t}
              {lang}
              visible={activeTab === 'web_terminal'}
              initialTarget={terminalInitialTarget}
              targetNonce={terminalTargetNonce}
              {containers}
              maxSessions={Number(settingsJson?.web_terminal?.max_sessions || 10)}
              requireReauth={isModuleLocked('web_terminal')}
              dockerRequireReauth={isModuleLocked('docker')}
              onUnlockModule={unlockModuleFlow}
              {settingsJson}
              onSaveSettings={saveFullSettings}
              {askConfirm}
              {requestReauth}
              {apiFetch}
              {showToast}
            />
          {:else if ptyLoadError}
            <div class="card row-between">
              <span class="mono" style="color:var(--danger);font-size:13px;">{ptyLoadError}</span>
              <button type="button" class="btn btn-sm" onclick={loadTerminalChunk}>{t.retry}</button>
            </div>
          {:else}
            <div class="card mono">{t.loadingPty}</div>
          {/if}
        </div>
      {/if}
      </main>
    </div>

    <!-- 移动端底部悬浮分离式双液态玻璃胶囊：中心焦点微缩光感 + 丝滑滑移高亮 + 独立设置圆钮 -->
    <nav class="mobile-dock" aria-label={t.nav.dashboard}>
      <div class="mobile-dock-main">
        <div
          bind:this={mobileDockScrollEl}
          role="group"
          aria-label={t.nav.dashboard}
          class="mobile-dock-scroll {mobileScrollItems.length > 3 ? 'peek-scroll' : ''} {dockCanScrollLeft ? 'fade-left' : ''} {dockCanScrollRight ? 'fade-right' : ''} {dockDragging ? 'is-dragging' : ''}"
          onscroll={scheduleDockLensUpdate}
          onwheel={handleDockWheel}
          onpointerdown={handleDockPointerDown}
          onpointermove={handleDockPointerMove}
          onpointerup={endDockDrag}
          onpointercancel={endDockDrag}
        >
          <div bind:this={dockGlideEl} class="dock-glide-pill" aria-hidden="true"></div>
          {#each mobileScrollItems as item (item.id)}
            {@const dot = moduleStatusDot(item.id)}
            <button
              type="button"
              data-dock-id={item.id}
              class="dock-btn dock-scroll-item {activeTab === item.id ? 'active' : ''}"
              aria-label={item.label}
              aria-current={activeTab === item.id ? 'page' : undefined}
              onclick={() => {
                if (dockJustDragged) return;
                switchTab(item.id);
              }}
            >
              <span class="dock-icon-wrap">
                <Icons name={item.id} size={18} />
                {#if dot}
                  <span class="dock-status-dot {dot}" aria-hidden="true"></span>
                {/if}
                {#if isModuleProtected(item.id)}
                  <span class="dock-lock-badge {isModuleLocked(item.id) ? '' : 'unlocked'}" aria-hidden="true">
                    <Icons name={isModuleLocked(item.id) ? 'lock' : 'unlock'} size={8} />
                  </span>
                {/if}
              </span>
              <span>{t.navShort?.[item.id] || item.label}</span>
            </button>
          {/each}
        </div>
      </div>

      <button
        type="button"
        class="dock-btn dock-fixed-settings {activeTab === 'settings' ? 'active' : ''}"
        aria-label={t.nav.settings}
        aria-current={activeTab === 'settings' ? 'page' : undefined}
        onclick={() => switchTab('settings', settingsSubTab)}
      >
        <span class="dock-icon-wrap">
          <Icons name="settings" size={18} />
        </span>
        <span>{t.navShort?.settings || t.nav.settings}</span>
      </button>
    </nav>
  </div>
{/if}
