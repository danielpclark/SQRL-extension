// Toolbar popup: log in on the current page, show identities and the QuickPass state.

import * as store from './storage.js';
import { $, el, show, openPage } from './ui.js';

const api = globalThis.browser ?? globalThis.chrome;

function hostOf(sqrlUrl) {
  const m = /^s?qrl:\/\/(?:[^@/?#]*@)?([^/?#:]+)/i.exec(sqrlUrl);
  return m ? m[1].toLowerCase() : sqrlUrl;
}

/** Find sqrl:// links on the active tab. Runs in the page under the activeTab grant. */
function scanPageForSqrlLinks() {
  const re = /^s?qrl:\/\//i;
  const out = [];
  for (const a of document.querySelectorAll('a[href]')) {
    const href = (a.getAttribute('href') || '').trim();
    if (re.test(href) && !out.includes(href)) out.push(href);
    if (out.length >= 10) break;
  }
  return out;
}

async function findLinks(tab) {
  // Opening the popup is the user gesture that grants activeTab for this tab.
  try {
    const results = await api.scripting.executeScript({ target: { tabId: tab.id, allFrames: true }, func: scanPageForSqrlLinks });
    const urls = [];
    for (const r of results || []) for (const u of r.result || []) if (!urls.includes(u)) urls.push(u);
    if (urls.length) return urls;
  } catch (e) {
    /* chrome:// pages, the store, PDFs: nothing to scan */
  }
  // Links reported by the optional always-on content script, if enabled.
  const { urls } = await api.runtime.sendMessage({ type: 'get-tab-links', tabId: tab.id }).catch(() => ({ urls: [] }));
  return urls || [];
}

async function init() {
  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  const links = $('#links');
  if (tab) {
    const urls = await findLinks(tab);
    if (urls && urls.length) {
      links.append(el('div', { class: 'muted small' }, 'SQRL login available on this page'));
      for (const url of urls.slice(0, 3)) {
        links.append(
          el('div', { class: 'row', style: 'margin-top:6px' },
            el('button', {
              class: 'primary',
              onclick: async () => {
                await api.runtime.sendMessage({ type: 'open-auth', url, tabId: tab.id });
                window.close();
              }
            }, 'Log in at ' + hostOf(url))
          )
        );
      }
      links.append(el('hr', { style: 'border:none;border-top:1px solid var(--border);margin:12px 0' }));
    }
  }

  const ids = await store.listIdentities();
  const settings = await store.getSettings();
  const box = $('#identities');
  if (!ids.length) {
    box.append(el('p', { class: 'muted' }, 'No identity yet.'), el('button', { class: 'primary', onclick: () => openPage('identity.html') }, 'Create or import an identity'));
  } else {
    const ul = el('ul', { class: 'list' });
    for (const id of ids) {
      ul.append(
        el('li', {},
          el('div', { class: 'grow' }, el('div', { class: 'name' }, id.name), el('div', { class: 'muted small mono' }, id.fingerprint ? id.fingerprint : '')),
          id.id === settings.defaultIdentity ? el('span', { class: 'badge' }, 'default') : null
        )
      );
    }
    box.append(ul);
  }

  const qp = await store.getQuickPass();
  if (qp) {
    const name = (ids.find((i) => i.id === qp.identityId) || {}).name || 'identity';
    $('#quickpass').textContent = `QuickPass active for "${name}" (${qp.hintLength} characters).`;
    show('#btnLock', true);
  } else {
    $('#quickpass').textContent = 'QuickPass not active (full password required).';
  }
}

$('#btnManage').addEventListener('click', () => openPage('identity.html'));
$('#btnOptions').addEventListener('click', () => openPage('options.html'));
$('#btnLock').addEventListener('click', async () => {
  await store.clearQuickPass('user request');
  $('#quickpass').textContent = 'QuickPass cleared.';
  show('#btnLock', false);
});

init().catch((e) => {
  $('#identities').textContent = 'Error: ' + e.message;
});
