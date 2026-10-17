// Tiny DOM helpers shared by the pages.

export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

export function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') e.className = v;
    else if (k === 'text') e.textContent = v;
    else if (k.startsWith('on') && typeof v === 'function') e.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined) e.setAttribute(k, v);
  }
  for (const c of children) {
    if (c == null) continue;
    e.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return e;
}

export function show(node, visible = true) {
  if (typeof node === 'string') node = $(node);
  if (node) node.hidden = !visible;
}

export function hide(node) {
  show(node, false);
}

/** Show exactly one of the given panels (selectors). */
export function showOnly(id, all) {
  for (const p of all) show(p, p === id);
}

export function setProgress(bar, done, total) {
  if (typeof bar === 'string') bar = $(bar);
  if (!bar) return;
  const pct = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 0;
  bar.value = pct;
  bar.max = 100;
}

let toastTimer = null;
export function toast(message, kind = 'info') {
  let t = $('#toast');
  if (!t) {
    t = el('div', { id: 'toast' });
    document.body.append(t);
  }
  t.textContent = message;
  t.className = 'toast ' + kind;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), kind === 'error' ? 8000 : 4000);
}

export function downloadBytes(filename, bytes, type = 'application/octet-stream') {
  const blob = new Blob([bytes], { type });
  const url = URL.createObjectURL(blob);
  const a = el('a', { href: url, download: filename });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast('Copied to clipboard');
  } catch (e) {
    toast('Could not copy: ' + e.message, 'error');
  }
}

export function formatDate(ts) {
  if (!ts) return '';
  return new Date(ts).toLocaleString();
}

/** Read an <input type=file> file as bytes. */
export function readFileBytes(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(new Uint8Array(r.result));
    r.onerror = () => reject(r.error);
    r.readAsArrayBuffer(file);
  });
}

export function openPage(path) {
  const api = globalThis.browser ?? globalThis.chrome;
  api.tabs.create({ url: api.runtime.getURL(path) });
}
