// 共享弹层栈管理：
// 1. 引用计数锁定背景页面滚动（防移动端滚动穿透，可按需关闭如轻量弹出菜单）
// 2. 统一 Escape 快捷键分发与 Tab 焦点陷阱（始终仅作用于栈顶弹层）
// 3. 关闭弹层后自动恢复焦点至触发元素（提升键盘与无障碍体验）
// 4. 单一共享 History 守卫（手机系统返回键 / iOS 右滑返回优先关闭栈顶弹层而不跳出当前页）

const overlayStack = [];
let scrollLockCount = 0;
let savedHtmlOverflow = '';
let savedBodyOverflow = '';
let savedHtmlOverscroll = '';
let savedBodyOverscroll = '';
let listenersReady = false;
let historyGuardActive = false;
let ignoreNextPops = 0;

const FOCUSABLE_SELECTOR = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
  'summary',
].join(', ');

function resolveEl(ref) {
  if (!ref) return null;
  return typeof ref === 'function' ? ref() : ref;
}

function getFocusable(container) {
  if (!container || typeof container.querySelectorAll !== 'function') return [];
  return [...container.querySelectorAll(FOCUSABLE_SELECTOR)].filter((el) => {
    if (el.getAttribute('aria-hidden') === 'true') return false;
    if (el.tabIndex < 0) return false;
    const style = window.getComputedStyle(el);
    if (style.display === 'none' || style.visibility === 'hidden') return false;
    return el.offsetParent !== null || style.position === 'fixed';
  });
}

function acquireScrollLock() {
  if (typeof document === 'undefined') return () => {};
  if (scrollLockCount === 0) {
    savedHtmlOverflow = document.documentElement.style.overflow;
    savedBodyOverflow = document.body.style.overflow;
    savedHtmlOverscroll = document.documentElement.style.overscrollBehavior;
    savedBodyOverscroll = document.body.style.overscrollBehavior;
    document.documentElement.style.overflow = 'hidden';
    document.body.style.overflow = 'hidden';
    document.documentElement.style.overscrollBehavior = 'contain';
    document.body.style.overscrollBehavior = 'contain';
  }
  scrollLockCount += 1;
  let released = false;
  return () => {
    if (released) return;
    released = true;
    scrollLockCount = Math.max(0, scrollLockCount - 1);
    if (scrollLockCount === 0) {
      document.documentElement.style.overflow = savedHtmlOverflow;
      document.body.style.overflow = savedBodyOverflow;
      document.documentElement.style.overscrollBehavior = savedHtmlOverscroll;
      document.body.style.overscrollBehavior = savedBodyOverscroll;
    }
  };
}

function pushHistoryGuard() {
  if (typeof window === 'undefined' || historyGuardActive) return;
  try {
    const prev = history.state && typeof history.state === 'object' ? history.state : {};
    history.pushState({ ...prev, __vaneOverlayGuard: true }, '', location.href);
    historyGuardActive = true;
  } catch {
    // 忽略受限环境
  }
}

function popHistoryGuardIfNeeded() {
  if (typeof window === 'undefined' || !historyGuardActive) return;
  historyGuardActive = false;
  if (history.state && history.state.__vaneOverlayGuard) {
    ignoreNextPops += 1;
    try {
      history.back();
    } catch {
      ignoreNextPops = Math.max(0, ignoreNextPops - 1);
    }
  }
}

function handleGlobalKeyDown(e) {
  if (overlayStack.length === 0) return;
  const top = overlayStack[overlayStack.length - 1];

  if (e.key === 'Escape') {
    if (e.defaultPrevented) return;
    e.preventDefault();
    top.onDismiss?.('escape');
    return;
  }

  if (e.key === 'Tab') {
    const container = resolveEl(top.trapContainer);
    if (!container) return;
    const focusables = getFocusable(container);
    if (focusables.length === 0) {
      e.preventDefault();
      if (typeof container.focus === 'function') {
        if (!container.hasAttribute('tabindex')) container.setAttribute('tabindex', '-1');
        container.focus({ preventScroll: true });
      }
      return;
    }
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    const active = document.activeElement;
    if (!container.contains(active)) {
      e.preventDefault();
      (e.shiftKey ? last : first).focus({ preventScroll: true });
    } else if (e.shiftKey && active === first) {
      e.preventDefault();
      last.focus({ preventScroll: true });
    } else if (!e.shiftKey && active === last) {
      e.preventDefault();
      first.focus({ preventScroll: true });
    }
  }
}

function handleGlobalPopState() {
  if (ignoreNextPops > 0) {
    ignoreNextPops -= 1;
    return;
  }
  if (overlayStack.length === 0) {
    historyGuardActive = false;
    return;
  }
  // 浏览器已弹出我们的返回守卫条目
  historyGuardActive = false;
  const top = overlayStack[overlayStack.length - 1];
  top.onDismiss?.('popstate');
  // 若关闭被拦截（如脏表单弹出了二次确认框），或栈中仍有下层弹层，立即补回守卫
  queueMicrotask(() => {
    if (overlayStack.length > 0 && !historyGuardActive) {
      pushHistoryGuard();
    }
  });
}

function ensureGlobalListeners() {
  if (listenersReady || typeof window === 'undefined') return;
  listenersReady = true;
  window.addEventListener('keydown', handleGlobalKeyDown);
  window.addEventListener('popstate', handleGlobalPopState);
}

/**
 * 将一个打开中的弹层压入全局栈，返回清理函数（适合直接作为 Svelte `$effect` 返回值）。
 * 支持可选焦点陷阱（trapContainer）、初始聚焦（initialFocus）、关闭后焦点还原（restoreFocus）与滚动锁定控制（lockScroll）。
 */
export function registerOverlay({
  onDismiss,
  lockScroll = true,
  trapContainer = null,
  initialFocus = null,
  restoreFocus = true,
}) {
  ensureGlobalListeners();
  const prevFocused =
    restoreFocus && typeof document !== 'undefined' && document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null;
  const releaseScroll = lockScroll ? acquireScrollLock() : () => {};
  const entry = { onDismiss, trapContainer };
  const wasEmpty = overlayStack.length === 0;
  overlayStack.push(entry);
  if (wasEmpty) {
    pushHistoryGuard();
  }

  // 在微任务后将焦点移入弹层（若子元素尚未自行 autofocus）
  if (trapContainer || initialFocus) {
    queueMicrotask(() => {
      if (!overlayStack.includes(entry)) return;
      const container = resolveEl(trapContainer);
      const explicit = resolveEl(initialFocus);
      if (explicit && typeof explicit.focus === 'function') {
        explicit.focus({ preventScroll: true });
        return;
      }
      if (container && !container.contains(document.activeElement)) {
        const focusables = getFocusable(container);
        if (focusables.length > 0) {
          focusables[0].focus({ preventScroll: true });
        } else if (typeof container.focus === 'function') {
          if (!container.hasAttribute('tabindex')) container.setAttribute('tabindex', '-1');
          container.focus({ preventScroll: true });
        }
      }
    });
  }

  let disposed = false;
  return () => {
    if (disposed) return;
    disposed = true;
    const idx = overlayStack.indexOf(entry);
    if (idx >= 0) overlayStack.splice(idx, 1);
    releaseScroll();
    if (overlayStack.length === 0) {
      popHistoryGuardIfNeeded();
    }
    if (prevFocused && prevFocused.isConnected && typeof prevFocused.focus === 'function') {
      queueMicrotask(() => {
        if (prevFocused.isConnected) {
          prevFocused.focus({ preventScroll: true });
        }
      });
    }
  };
}
