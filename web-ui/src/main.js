import './app.css';
import App from './App.svelte';
import { mount } from 'svelte';

// 在首次渲染前同步应用已保存的主题模式与主题色（默认自适应跟随系统，遵循严格 CSP）
try {
  const savedTheme = localStorage.getItem('vane_theme_mode') || 'auto';
  const resolved =
    savedTheme === 'auto'
      ? window.matchMedia?.('(prefers-color-scheme: light)')?.matches
        ? 'light'
        : 'dark'
      : savedTheme;
  document.documentElement.dataset.theme = resolved === 'light' ? 'light' : 'dark';
  const savedAccent = localStorage.getItem('vane_theme_accent') || 'emerald';
  if (/^(emerald|ocean|indigo|violet|amber|rose)$/.test(savedAccent)) {
    document.documentElement.dataset.accent = savedAccent;
  }
} catch {
  // ignore storage errors
}

const app = mount(App, {
  target: document.getElementById('app')
});

if ('serviceWorker' in navigator && (location.protocol === 'https:' || location.hostname === 'localhost')) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch(() => {});
  });
}

export default app;
