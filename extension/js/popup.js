// Toolbar popup: log in on the current page, show identities and the QuickPass state.

import * as store from './storage.js';
import { $, el, show, openPage } from './ui.js';

const api = globalThis.browser ?? globalThis.chrome;

function hostOf(sqrlUrl) {
  const m = /^s?qrl:\/\/(?:[^@/?#]*@)?([^/?#:]+)/i.exec(sqrlUrl);
  return m ? m[1].toLowerCase() : sqrlUrl;
}

async function init() {
  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  const links = $('#links');
  if (tab) {
    const { urls } = await api.runtime.sendMessage({ type: 'get-tab-links', tabId: tab.id }).catch(() => ({ urls: [] }));
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
