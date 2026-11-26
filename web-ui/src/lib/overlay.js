// 共享弹层栈管理：
// 1. 引用计数锁定背景页面滚动（防移动端滚动穿透）
// 2. 统一 Escape 快捷键分发（始终仅作用于栈顶弹层）
// 3. 单一共享 History 守卫（手机系统返回键 / iOS 右滑返回优先关闭栈顶弹层而不跳出当前页）

const overlayStack = [];
let scrollLockCount = 0;
let savedHtmlOverflow = '';
let savedBodyOverflow = '';
let savedHtmlOverscroll = '';
let savedBodyOverscroll = '';
let listenersReady = false;
let historyGuardActive = false;
let ignoreNextPops = 0;

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
  if (e.key !== 'Escape' || e.defaultPrevented || overlayStack.length === 0) return;
  const top = overlayStack[overlayStack.length - 1];
  e.preventDefault();
  top.onDismiss?.('escape');
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
 */
export function registerOverlay({ onDismiss }) {
  ensureGlobalListeners();
  const releaseScroll = acquireScrollLock();
  const entry = { onDismiss };
  const wasEmpty = overlayStack.length === 0;
  overlayStack.push(entry);
  if (wasEmpty) {
    pushHistoryGuard();
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
  };
}
