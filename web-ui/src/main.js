import './app.css';
import App from './App.svelte';
import { mount } from 'svelte';

// 在首次渲染前同步应用已保存的主题模式（遵循严格 CSP，不在 index.html 中使用内联脚本）
try {
  const savedTheme = localStorage.getItem('vane_theme_mode') || 'dark';
  const resolved =
    savedTheme === 'auto'
      ? window.matchMedia?.('(prefers-color-scheme: light)')?.matches
        ? 'light'
        : 'dark'
      : savedTheme;
  document.documentElement.dataset.theme = resolved === 'light' ? 'light' : 'dark';
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
