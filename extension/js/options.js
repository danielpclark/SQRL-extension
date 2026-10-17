// Settings page.

import * as store from './storage.js';
import { $, el, toast } from './ui.js';

const api = globalThis.browser ?? globalThis.chrome;

async function refreshQuickPass() {
  const qp = await store.getQuickPass();
  if (qp) {
    const ids = await store.listIdentities();
    const name = (ids.find((i) => i.id === qp.identityId) || {}).name || 'identity';
    $('#qpStatus').textContent = `QuickPass is active for "${name}" since ${new Date(qp.createdAt).toLocaleTimeString()} (idle timeout ${qp.idleTimeoutMinutes || 'none'} min).`;
  } else {
    $('#qpStatus').textContent = 'QuickPass is not active.';
  }
}

async function init() {
  const settings = await store.getSettings();
  const ids = await store.listIdentities();
  const sel = $('#defaultIdentity');
  sel.textContent = '';
  if (!ids.length) sel.append(el('option', { value: '' }, '(no identities)'));
  for (const id of ids) sel.append(el('option', { value: id.id }, id.name));
  sel.value = settings.defaultIdentity || (ids[0] ? ids[0].id : '');
  $('#askAltId').checked = !!settings.askAltId;
  const { enabled } = await api.runtime.sendMessage({ type: 'link-handler-status' }).catch(() => ({ enabled: false }));
  $('#autoLinks').checked = !!enabled;
  $('#closeAfterLogin').checked = !!settings.closeAfterLogin;
  $('#noiptest').checked = !!settings.noiptest;
  $('#rescueSeconds').value = settings.rescueSeconds;
  $('#extId').textContent = api.runtime.id;
  await refreshQuickPass();
}

$('#btnSave').addEventListener('click', async () => {
  await store.setSettings({
    defaultIdentity: $('#defaultIdentity').value || null,
    askAltId: $('#askAltId').checked,
    closeAfterLogin: $('#closeAfterLogin').checked,
    noiptest: $('#noiptest').checked,
    rescueSeconds: Math.max(1, Math.min(60, Number($('#rescueSeconds').value) || 5))
  });
  toast('Settings saved', 'success');
});
const ALL_SITES = { origins: ['https://*/*', 'http://*/*'] };
$('#autoLinks').addEventListener('change', async (e) => {
  const box = e.target;
  try {
    if (box.checked) {
      // permissions.request must run inside the click that toggled the box
      const granted = await api.permissions.request(ALL_SITES);
      if (!granted) {
        box.checked = false;
        toast('Access to all sites was not granted; the toolbar button still works per page.');
        return;
      }
    }
    const { enabled } = await api.runtime.sendMessage({ type: 'set-link-handler', enabled: box.checked });
    await store.setSettings({ autoLinks: !!enabled });
    if (!box.checked) await api.permissions.remove(ALL_SITES).catch(() => {});
    box.checked = !!enabled;
    toast(enabled ? 'sqrl:// links are now handled automatically' : 'Automatic link handling disabled', 'success');
  } catch (err) {
    box.checked = false;
    toast(err.message, 'error');
  }
});

$('#btnLock').addEventListener('click', async () => {
  await store.clearQuickPass('user request');
  await refreshQuickPass();
  toast('QuickPass cleared');
});
$('#btnRules').addEventListener('click', async () => {
  await api.runtime.sendMessage({ type: 'reinstall-rules' });
  toast('CPS rules re-installed');
});

init().catch((e) => toast(e.message, 'error'));
