// Identity manager: list, create, import, export, change password / settings, re-key, delete.

import { core } from './client.js';
import * as store from './storage.js';
import { $, $$, el, show, setProgress, toast, downloadBytes, copyText, formatDate, readFileBytes } from './ui.js';
import { drawToCanvas } from './qr.js';

const FLAG_SQRL_ONLY = 0x0004;
const FLAG_NO_BYPASS = 0x0008;
const FLAG_WARN_MITM = 0x0010;
const FLAG_CLEAR_QP_ON_IDLE = 0x0080;

const S = { identities: [], selected: null, globals: null, created: null };

function tab(name) {
  $$('.tabs button').forEach((b) => b.classList.toggle('active', b.dataset.tab === name));
  for (const n of ['list', 'create', 'import']) show('#tab-' + n, n === name);
}
$$('.tabs button').forEach((b) => b.addEventListener('click', () => tab(b.dataset.tab)));

function progressStage(stage, done, total) {
  const names = { password: 'Encrypting with your password (EnScrypt)…', rescue: 'Encrypting with the rescue code (EnScrypt)…' };
  return names[stage] || 'Working…';
}

// --- list ------------------------------------------------------------------------------

async function refresh() {
  S.identities = await store.listIdentities();
  S.globals = await store.getSettings();
  const ul = $('#identityList');
  ul.textContent = '';
  show('#emptyList', !S.identities.length);
  for (const id of S.identities) {
    ul.append(
      el('li', {},
        el('div', { class: 'grow' },
          el('div', { class: 'name' }, id.name, ' ', id.id === S.globals.defaultIdentity ? el('span', { class: 'badge' }, 'default') : null),
          el('div', { class: 'muted small' }, (id.fingerprint ? id.fingerprint + ' · ' : '') + 'created ' + formatDate(id.created))
        ),
        el('button', { onclick: () => select(id.id) }, 'Manage')
      )
    );
  }
  if (S.selected && !S.identities.some((i) => i.id === S.selected)) S.selected = null;
  if (S.selected) await select(S.selected);
  else show('#detail', false);
}

async function select(id) {
  S.selected = id;
  const rec = S.identities.find((i) => i.id === id);
  if (!rec) return;
  let info;
  try {
    info = await core().call('parseFile', { text: rec.text });
    await core().free(info.file);
  } catch (e) {
    toast('This identity could not be parsed: ' + e.message, 'error');
    return;
  }
  $('#detailName').textContent = rec.name;
  $('#detailFp').textContent = rec.fingerprint || '(log in once to compute)';
  $('#detailCreated').textContent = formatDate(rec.created);
  $('#detailPrev').textContent = `${info.previousCount} stored` + (info.edition ? ` (edition ${info.edition})` : '');
  $('#detailIters').textContent = `${info.iterations} (log N = ${info.settings.logN}, ${info.settings.pwVerifySeconds} s on the creating device)`;
  show('#detail', true);
  show('#export', false);
  show('#changePw', false);
  show('#rekey', false);
  $('#detail').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function current() {
  return S.identities.find((i) => i.id === S.selected);
}

$('#btnRename').addEventListener('click', async () => {
  const rec = current();
  const name = prompt('New name for this identity', rec.name);
  if (!name || !name.trim()) return;
  await store.saveIdentity({ id: rec.id, name: name.trim() });
  await refresh();
});

$('#btnDefault').addEventListener('click', async () => {
  await store.setSettings({ defaultIdentity: S.selected });
  toast('Default identity set', 'success');
  await refresh();
});

$('#btnDelete').addEventListener('click', async () => {
  const rec = current();
  if (!confirm(`Delete the identity "${rec.name}" from this browser?\n\nMake sure you have a backup (identity file or rescue code + textual identity). This cannot be undone.`)) return;
  await store.deleteIdentity(rec.id);
  S.selected = null;
  toast('Identity deleted');
  await refresh();
});

// --- export ----------------------------------------------------------------------------

async function showExport() {
  const rec = current();
  const info = await core().call('parseFile', { text: rec.text });
  const exp = await core().call('exportFile', { file: info.file });
  await core().free(info.file);
  const base = rec.name.replace(/[^A-Za-z0-9._-]+/g, '_') || 'identity';
  $('#btnExportFile').onclick = () => downloadBytes(base + '.sqrl', exp.bytes);
  $('#btnExportRescueFile').onclick = () => exp.rescueBytes && downloadBytes(base + '.sqrc', exp.rescueBytes);
  $('#btnExportRescueFile').disabled = !exp.hasRescue;
  $('#btnExportText').onclick = () => copyText(exp.text);
  $('#textual').value = exp.textual || '(this identity has no rescue code block)';
  $('#btnCopyTextual').onclick = () => copyText(exp.textual || '');
  try {
    drawToCanvas($('#qrCanvas'), exp.bytes, { scale: 4, ecl: 'L' });
  } catch (e) {
    toast('QR code: ' + e.message, 'error');
  }
  show('#export', true);
  show('#changePw', false);
  show('#rekey', false);
}
$('#btnExport').addEventListener('click', () => showExport().catch((e) => toast(e.message, 'error')));

// --- change password / settings --------------------------------------------------------

$('#btnChangePw').addEventListener('click', async () => {
  const rec = current();
  const info = await core().call('parseFile', { text: rec.text });
  await core().free(info.file);
  const s = info.settings;
  $('#cpOld').value = '';
  $('#cpNew').value = '';
  $('#cpNew2').value = '';
  $('#cpHint').value = s.hintLength;
  $('#cpIdle').value = s.idleTimeoutMinutes;
  $('#cpVerify').value = s.pwVerifySeconds;
  $('#cpSqrlOnly').checked = !!(s.optionFlags & FLAG_SQRL_ONLY);
  $('#cpHardlock').checked = !!(s.optionFlags & FLAG_NO_BYPASS);
  $('#cpClearIdle').checked = !!(s.optionFlags & FLAG_CLEAR_QP_ON_IDLE);
  $('#cpWarnRemote').checked = !!(s.optionFlags & FLAG_WARN_MITM);
  show('#changePw', true);
  show('#export', false);
  show('#rekey', false);
  $('#cpOld').focus();
});
$('#btnChangePwCancel').addEventListener('click', () => show('#changePw', false));

$('#changePwForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const rec = current();
  const oldPw = $('#cpOld').value;
  const newPw = $('#cpNew').value;
  if (newPw && newPw !== $('#cpNew2').value) return toast('The new passwords do not match', 'error');
  const btn = e.submitter;
  btn.disabled = true;
  try {
    const info = await core().call('parseFile', { text: rec.text });
    const settings = { ...info.settings };
    settings.hintLength = Math.max(0, Math.min(255, Number($('#cpHint').value) || 0));
    settings.idleTimeoutMinutes = Math.max(0, Math.min(65535, Number($('#cpIdle').value) || 0));
    settings.pwVerifySeconds = Math.max(1, Math.min(255, Number($('#cpVerify').value) || 5));
    const setFlag = (flag, on) => (settings.optionFlags = on ? settings.optionFlags | flag : settings.optionFlags & ~flag);
    setFlag(FLAG_SQRL_ONLY, $('#cpSqrlOnly').checked);
    setFlag(FLAG_NO_BYPASS, $('#cpHardlock').checked);
    setFlag(FLAG_CLEAR_QP_ON_IDLE, $('#cpClearIdle').checked);
    setFlag(FLAG_WARN_MITM, $('#cpWarnRemote').checked);
    toast('Verifying current password…');
    const u = await core().call('unlock', { file: info.file, password: oldPw });
    toast('Re-encrypting…');
    const out = await core().call('setPassword', { file: info.file, unlocked: u.unlocked, password: newPw || oldPw, settings });
    await store.saveIdentity({ id: rec.id, text: out.text, fingerprint: u.fingerprint });
    await core().free(u.unlocked);
    await core().free(info.file);
    await store.clearQuickPass('password changed');
    toast(newPw ? 'Password and settings updated' : 'Settings updated', 'success');
    show('#changePw', false);
    await refresh();
  } catch (err) {
    toast(err.message, 'error');
  } finally {
    btn.disabled = false;
  }
});

// --- re-key ----------------------------------------------------------------------------

$('#btnRekey').addEventListener('click', () => {
  $('#rkPassword').value = '';
  $('#rkRescue').value = '';
  show('#rekey', true);
  show('#export', false);
  show('#changePw', false);
  $('#rkPassword').focus();
});
$('#btnRekeyCancel').addEventListener('click', () => show('#rekey', false));

$('#rekeyForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const rec = current();
  const btn = e.submitter;
  btn.disabled = true;
  try {
    const info = await core().call('parseFile', { text: rec.text });
    toast('Verifying password…');
    const u = await core().call('unlock', { file: info.file, password: $('#rkPassword').value });
    toast('Verifying rescue code…');
    const { iuk } = await core().call('unlockIuk', { file: info.file, rescueCode: $('#rkRescue').value });
    const { matches } = await core().call('matchesIuk', { unlocked: u.unlocked, iuk });
    if (!matches) throw new Error('That rescue code belongs to a different identity');
    const rescue = await core().call('generateRescueCode');
    const settings = info.settings;
    tab('create');
    showCreateStep(2);
    $('#createProgressText').textContent = 'Re-keying…';
    const out = await core().call(
      'rekey',
      { file: info.file, unlocked: u.unlocked, oldIuk: iuk, password: $('#rkPassword').value, rescueCode: rescue, settings, rescueMs: (S.globals.rescueSeconds || 5) * 1000 },
      (p) => {
        $('#createProgressText').textContent = progressStage(p.stage);
        setProgress('#createProgress', p.done, p.total);
      }
    );
    S.created = { id: rec.id, name: rec.name, text: out.text, fingerprint: out.fingerprint, rescue, rekey: true };
    await core().free(u.unlocked);
    await core().free(out.unlocked);
    await core().free(info.file);
    await store.clearQuickPass('identity re-keyed');
    showRescueCode(rescue);
  } catch (err) {
    toast(err.message, 'error');
    tab('list');
  } finally {
    btn.disabled = false;
  }
});

// --- create ----------------------------------------------------------------------------

function showCreateStep(n) {
  for (let i = 1; i <= 4; i++) show('#create-step' + i, i === n);
}

function showRescueCode(rescue) {
  core()
    .call('formatRescueCode', { code: rescue })
    .then((formatted) => {
      $('#rescueShow').textContent = formatted;
      $('#rescueConfirm').value = '';
      showCreateStep(3);
      $('#rescueConfirm').focus();
    });
}

$('#createForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const name = $('#crName').value.trim() || 'My identity';
  const pw = $('#crPassword').value;
  if (pw.length < 8) return toast('Use a password of at least 8 characters', 'error');
  if (pw !== $('#crPassword2').value) return toast('The passwords do not match', 'error');
  showCreateStep(2);
  try {
    const rescue = await core().call('generateRescueCode');
    const settings = await core().call('defaultSettings');
    const info = await core().call(
      'createIdentity',
      { password: pw, rescueCode: rescue, settings, rescueMs: (S.globals.rescueSeconds || 5) * 1000 },
      (p) => {
        $('#createProgressText').textContent = progressStage(p.stage);
        setProgress('#createProgress', p.done, p.total);
      }
    );
    $('#createProgressText').textContent = 'Verifying…';
    const u = await core().call('unlock', { file: info.file, password: pw }, (p) => setProgress('#createProgress', p.done, p.total));
    S.created = { id: store.newIdentityId(), name, text: info.text, fingerprint: u.fingerprint, rescue };
    await core().free(u.unlocked);
    await core().free(info.file);
    $('#crPassword').value = '';
    $('#crPassword2').value = '';
    showRescueCode(rescue);
  } catch (err) {
    toast(err.message, 'error');
    showCreateStep(1);
  }
});

$('#confirmRescueForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const typed = $('#rescueConfirm').value.replace(/[^0-9]/g, '');
  if (typed !== S.created.rescue) return toast('That does not match the rescue code shown above', 'error');
  await store.saveIdentity({ id: S.created.id, name: S.created.name, text: S.created.text, fingerprint: S.created.fingerprint });
  $('#rescueShow').textContent = '';
  S.created.rescue = null;
  showCreateStep(4);
  toast(S.created.rekey ? 'Identity re-keyed' : 'Identity created', 'success');
  await refresh();
});

$('#btnCreatedExport').addEventListener('click', async () => {
  S.selected = S.created.id;
  tab('list');
  await refresh();
  await showExport();
});
$('#btnCreatedDone').addEventListener('click', async () => {
  S.selected = S.created.id;
  tab('list');
  showCreateStep(1);
  await refresh();
});

// --- import ----------------------------------------------------------------------------

let importState = null;

$('#importForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    let info;
    const file = $('#imFile').files[0];
    const text = $('#imText').value.trim();
    if (file) {
      const bytes = await readFileBytes(file);
      const head = String.fromCharCode(...bytes.slice(0, 8));
      if (head === 'sqrldata' || head === 'SQRLDATA') info = await core().call('parseFile', { bytes });
      else info = await core().call('parseTextual', { text: new TextDecoder().decode(bytes) });
    } else if (text) {
      if (text.startsWith('SQRLDATA')) info = await core().call('parseFile', { text });
      else info = await core().call('parseTextual', { text });
    } else {
      return toast('Choose a file or paste the identity text', 'error');
    }
    importState = { info, name: $('#imName').value.trim() || 'Imported identity' };
    const parts = [];
    parts.push(info.hasPassword ? 'password block present' : 'no password block (rescue-code import)');
    parts.push(info.hasRescue ? 'rescue code block present' : 'no rescue code block');
    if (info.previousCount) parts.push(`${info.previousCount} previous identit${info.previousCount === 1 ? 'y' : 'ies'}`);
    $('#importInfo').textContent = 'Identity data parsed: ' + parts.join(', ') + '.';
    show('#imPwRow', info.hasPassword);
    show('#imRescueRow', !info.hasPassword);
    show('#import-step2', true);
    (info.hasPassword ? $('#imPassword') : $('#imRescue')).focus();
  } catch (err) {
    toast('Could not read that identity: ' + err.message, 'error');
  }
});
$('#btnImportCancel').addEventListener('click', async () => {
  if (importState) await core().free(importState.info.file);
  importState = null;
  show('#import-step2', false);
});

$('#importForm2').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!importState) return;
  const { info, name } = importState;
  show('#import-step2', false);
  show('#import-step3', true);
  const prog = (text) => (p) => {
    $('#importProgressText').textContent = text;
    setProgress('#importProgress', p.done, p.total);
  };
  try {
    let text, fingerprint;
    if (info.hasPassword) {
      const u = await core().call('unlock', { file: info.file, password: $('#imPassword').value }, prog('Verifying password (EnScrypt)…'));
      text = info.text;
      fingerprint = u.fingerprint;
      await core().free(u.unlocked);
    } else {
      const newPw = $('#imNewPassword').value;
      if (newPw.length < 8) throw new Error('Use a password of at least 8 characters');
      if (newPw !== $('#imNewPassword2').value) throw new Error('The passwords do not match');
      const { iuk } = await core().call('unlockIuk', { file: info.file, rescueCode: $('#imRescue').value }, prog('Decrypting with the rescue code (EnScrypt)…'));
      const u = await core().call('fromIuk', { iuk, file: info.file });
      const settings = await core().call('defaultSettings');
      const out = await core().call('fromUnlocked', { unlocked: u.unlocked, file: info.file, password: newPw, settings }, prog('Encrypting with your new password (EnScrypt)…'));
      text = out.text;
      fingerprint = u.fingerprint;
      await core().free(u.unlocked);
      await core().free(out.file);
    }
    await core().free(info.file);
    const id = store.newIdentityId();
    await store.saveIdentity({ id, name, text, fingerprint });
    importState = null;
    $('#imFile').value = '';
    $('#imText').value = '';
    $('#imPassword').value = '';
    $('#imRescue').value = '';
    $('#imNewPassword').value = '';
    $('#imNewPassword2').value = '';
    toast('Identity imported', 'success');
    S.selected = id;
    tab('list');
    await refresh();
  } catch (err) {
    toast(err.message, 'error');
    show('#import-step2', true);
  } finally {
    show('#import-step3', false);
  }
});

refresh().catch((e) => toast(e.message, 'error'));
