// 轻量零依赖 PWA 安装与运行态检测（支持 Chrome / Edge / Android / iOS Safari）

let deferredPrompt = null;
const listeners = new Set();

function notify() {
  const snap = getPwaState();
  for (const fn of listeners) {
    try {
      fn(snap);
    } catch {
      // ignore listener errors
    }
  }
}

export function isStandalonePwa() {
  if (typeof window === 'undefined') return false;
  return Boolean(
    window.matchMedia?.('(display-mode: standalone)')?.matches ||
      window.matchMedia?.('(display-mode: window-controls-overlay)')?.matches ||
      window.navigator?.standalone === true
  );
}

export function isIosSafari() {
  if (typeof navigator === 'undefined') return false;
  const ua = navigator.userAgent || '';
  const isIos =
    /iPhone|iPad|iPod/i.test(ua) ||
    (navigator.platform === 'MacIntel' && (navigator.maxTouchPoints || 0) > 1);
  if (!isIos) return false;
  const isSafari = /Safari/i.test(ua) && !/CriOS|FxiOS|EdgiOS|OPiOS|DuckDuckGo/i.test(ua);
  return isSafari;
}

export function getPwaState() {
  const standalone = isStandalonePwa();
  return {
    standalone,
    canPrompt: Boolean(!standalone && deferredPrompt),
    iosSafari: !standalone && isIosSafari(),
    secureContext: typeof window !== 'undefined' && Boolean(window.isSecureContext),
  };
}

export function initPwaListeners() {
  if (typeof window === 'undefined') return () => {};
  const onBeforeInstall = (e) => {
    e.preventDefault();
    deferredPrompt = e;
    notify();
  };
  const onAppInstalled = () => {
    deferredPrompt = null;
    notify();
  };
  const mq = window.matchMedia?.('(display-mode: standalone)');
  const onModeChange = () => notify();

  window.addEventListener('beforeinstallprompt', onBeforeInstall);
  window.addEventListener('appinstalled', onAppInstalled);
  mq?.addEventListener?.('change', onModeChange);
  return () => {
    window.removeEventListener('beforeinstallprompt', onBeforeInstall);
    window.removeEventListener('appinstalled', onAppInstalled);
    mq?.removeEventListener?.('change', onModeChange);
  };
}

export function subscribePwaState(fn) {
  listeners.add(fn);
  fn(getPwaState());
  return () => listeners.delete(fn);
}

export async function promptPwaInstall() {
  if (!deferredPrompt) return 'unavailable';
  const evt = deferredPrompt;
  deferredPrompt = null;
  notify();
  try {
    await evt.prompt();
    const choice = await evt.userChoice;
    return choice?.outcome === 'accepted' ? 'accepted' : 'dismissed';
  } catch {
    return 'dismissed';
  }
}
