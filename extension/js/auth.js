// The authentication dialog. Runs either
//   * in a popup window opened by the background script after a sqrl:// link was clicked
//     (query: u=<sqrl url>&tab=<origin tab id>), or
//   * inside the website's own tab, when the site navigated to http://localhost:25519/<b64>
//     and the declarativeNetRequest rule redirected here (query: cps=<b64url sqrl url>).
//
// Flow: pick identity → password / QuickPass → query → (ask / confirm) → ident → CPS redirect.

import { core, postRequest, ensureHostPermission } from './client.js';
import * as store from './storage.js';
import { $, el, show, showOnly, setProgress, toast } from './ui.js';

const api = globalThis.browser ?? globalThis.chrome;
const PANELS = ['#panel-identity', '#panel-noidentity', '#panel-progress', '#panel-rescue', '#panel-confirm', '#panel-ask', '#panel-result'];
// Type 1 option flags (S4 specification, "Cross-Client Options & Flags").
const FLAG_SQRL_ONLY = 0x0004;
const FLAG_NO_BYPASS = 0x0008;
const FLAG_WARN_MITM = 0x0010;
const FLAG_CLEAR_QP_ON_IDLE = 0x0080;
const FLAG_WARN_NON_CPS = 0x0100;

const params = new URLSearchParams(location.search);
const cpsParam = params.get('cps');
const inTab = !!cpsParam;
const originTab = params.get('tab') ? Number(params.get('tab')) : null;
let sqrlUrl = params.get('u') || '';

const S = {
  urlInfo: null,
  identities: [],
  record: null,
  file: null, // worker handle of the parsed identity file
  unlocked: null, // worker handle of the unlocked identity
  session: null, // worker handle
  key: null, // derived password key (Uint8Array), kept only to set up QuickPass
  settings: null, // identity settings (type 1 block)
  globals: null, // extension settings
  iuk: null,
  busy: false
};

function b64uDecodeToString(s) {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  return decodeURIComponent(
    Array.from(atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4)), (c) => '%' + c.charCodeAt(0).toString(16).padStart(2, '0')).join('')
  );
}

function panel(id) {
  showOnly(id, PANELS);
}

function progress(text, p) {
  panel('#panel-progress');
  $('#progressText').textContent = text;
  if (p) setProgress('#progressBar', p.done, p.total);
  else setProgress('#progressBar', 0, 1);
}

function result(text, { kind = 'ok', retry = false } = {}) {
  panel('#panel-result');
  const r = $('#resultText');
  r.textContent = text;
  r.className = kind === 'error' ? 'error' : kind === 'ok' ? 'ok' : '';
  show('#btnRetry', retry);
}

function confirm(text, yesLabel = 'Continue') {
  return new Promise((resolve) => {
    panel('#panel-confirm');
    $('#confirmText').textContent = text;
    $('#btnConfirmYes').textContent = yesLabel;
    $('#btnConfirmYes').onclick = () => resolve(true);
    $('#btnConfirmNo').onclick = () => resolve(false);
  });
}

function askRescueCode(text) {
  return new Promise((resolve) => {
    panel('#panel-rescue');
    $('#rescueText').textContent = text;
    $('#rescueCode').value = '';
    $('#rescueCode').focus();
    $('#btnRescueOk').onclick = () => resolve($('#rescueCode').value);
    $('#btnRescueCancel').onclick = () => resolve(null);
    $('#rescueCode').onkeydown = (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        resolve($('#rescueCode').value);
      }
    };
  });
}

/**
 * Show a server `ask=`. Resolves with the btn value to send (0 = the plain OK that is shown
 * only when the ask has no buttons, 1/2 = first/second button) or null when the user
 * cancels, which ends the transaction without any further command. Focus is placed on
 * Cancel so that a stray Enter never acknowledges anything (GRC client behaviour).
 */
function askQuestion(ask) {
  return new Promise((resolve) => {
    panel('#panel-ask');
    $('#askText').textContent = ask.message;
    const box = $('#askButtons');
    box.textContent = '';
    if (ask.buttons.length) {
      ask.buttons.slice(0, 2).forEach((b, i) => {
        box.append(el('button', { class: 'primary', onclick: () => resolve(i + 1) }, b.label));
      });
    } else {
      box.append(el('button', { class: 'primary', onclick: () => resolve(0) }, 'OK'));
    }
    const cancel = el('button', { onclick: () => resolve(null) }, 'Cancel');
    box.append(cancel);
    cancel.focus();
  });
}

async function navigateAway(url) {
  if (inTab) {
    location.replace(url);
    return;
  }
  await api.runtime.sendMessage({ type: 'navigate-tab', tabId: originTab, url });
}

async function cancel() {
  const cancelUrl = S.session ? (await core().call('sessionState', { session: S.session })).cancelUrl : S.urlInfo && S.urlInfo.cancelUrl;
  if (inTab) {
    if (cancelUrl) location.replace(cancelUrl);
    else if (history.length > 1) history.back();
    else result('Login cancelled. You can close this tab.', { kind: '' });
    return;
  }
  if (cancelUrl && originTab != null) {
    try {
      await api.runtime.sendMessage({ type: 'navigate-tab', tabId: originTab, url: cancelUrl });
    } catch (e) {
      /* ignore */
    }
  }
  window.close();
}

async function done() {
  if (inTab) {
    const st = S.session ? await core().call('sessionState', { session: S.session }).catch(() => null) : null;
    const back = (st && st.cancelUrl) || (S.urlInfo && S.urlInfo.cancelUrl) || null;
    if (back) location.replace(back);
    else if (history.length > 1) history.back();
    else result('You can close this tab now.', { kind: '' });
    return;
  }
  window.close();
}

// ---------------------------------------------------------------------------------------

async function init() {
  if (cpsParam) {
    try {
      sqrlUrl = b64uDecodeToString(cpsParam);
    } catch (e) {
      result('The site handed over an unreadable SQRL URL.', { kind: 'error' });
      return;
    }
  }
  if (!sqrlUrl) {
    result('No SQRL URL was provided.', { kind: 'error' });
    return;
  }
  try {
    S.urlInfo = await core().call('parseUrl', { url: sqrlUrl });
  } catch (e) {
    result('Invalid SQRL URL: ' + e.message, { kind: 'error' });
    return;
  }
  $('#host').textContent = S.urlInfo.host;
  $('#siteKey').textContent = S.urlInfo.siteKey !== S.urlInfo.host ? 'site key: ' + S.urlInfo.siteKey : '';
  show('#insecure', S.urlInfo.insecure);
  document.title = 'SQRL Login – ' + S.urlInfo.host;

  S.globals = await store.getSettings();
  S.identities = await store.listIdentities();
  if (!S.identities.length) {
    panel('#panel-noidentity');
    return;
  }
  const sel = $('#identity');
  sel.textContent = '';
  for (const id of S.identities) sel.append(el('option', { value: id.id }, id.name));
  const def = await store.getDefaultIdentity();
  sel.value = def.id;
  show('#altIdRow', !!S.globals.askAltId);
  await identityChanged();
  panel('#panel-identity');
  $('#password').focus();
}

async function identityChanged() {
  S.record = S.identities.find((i) => i.id === $('#identity').value) || S.identities[0];
  if (S.file) await core().free(S.file);
  const info = await core().call('parseFile', { text: S.record.text });
  S.file = info.file;
  S.settings = info.settings;
  $('#optSqrlOnly').checked = !!(S.settings.optionFlags & FLAG_SQRL_ONLY);
  $('#optHardlock').checked = !!(S.settings.optionFlags & FLAG_NO_BYPASS);
  const qp = await store.getQuickPass();
  const usable = qp && qp.identityId === S.record.id;
  show('#qpHint', !!usable);
  if (usable) {
    $('#qpHint').textContent = `QuickPass is active: enter just the first ${qp.hintLength} character${qp.hintLength === 1 ? '' : 's'} of your password.`;
    $('#pwLabel').firstChild.textContent = 'Password or QuickPass';
  } else {
    $('#pwLabel').firstChild.textContent = 'Password';
  }
}

/** Unlock the selected identity with the password typed by the user (or the QuickPass). */
async function unlock(password) {
  const qp = await store.getQuickPass();
  let key = null;
  if (qp && qp.identityId === S.record.id && password.length === qp.hintLength) {
    progress('Checking QuickPass…');
    try {
      ({ key } = await core().call('quickpassOpen', { blob: store.b64ToBytes(qp.blob), hint: password, logN: qp.logN }));
      await store.touchQuickPass(qp);
    } catch (e) {
      // One wrong QuickPass clears it: the full password is now required.
      await store.clearQuickPass('wrong QuickPass');
      throw new Error('Incorrect QuickPass. It has been cleared; please enter your full password.');
    }
  }
  if (!key) {
    ({ key } = await core().call('deriveKey', { file: S.file, password }, (p) => progress('Decrypting identity (EnScrypt)…', p)));
  }
  progress('Unlocking…');
  const u = await core().call('unlock', { file: S.file, key });
  S.unlocked = u.unlocked;
  S.key = key;
  if (!S.record.fingerprint) {
    S.record.fingerprint = u.fingerprint;
    await store.saveIdentity({ id: S.record.id, fingerprint: u.fingerprint });
  }
  // (Re)arm QuickPass with the full password's leading characters.
  const remember = $('#optRemember').checked;
  const hintLen = S.settings.hintLength || 0;
  if (remember && hintLen > 0 && password.length > hintLen) {
    const { blob } = await core().call('quickpassSeal', { key, hint: password.slice(0, hintLen), logN: S.settings.logN, ms: 1000 });
    // The idle timeout only applies when flag 0x0080 is set ("both are required").
    const idleEnabled = !!(S.settings.optionFlags & FLAG_CLEAR_QP_ON_IDLE);
    await store.setQuickPass({
      identityId: S.record.id,
      blob: store.bytesToB64(blob),
      hintLength: hintLen,
      logN: S.settings.logN,
      idleTimeoutMinutes: idleEnabled ? S.settings.idleTimeoutMinutes : 0,
      clearOnIdle: idleEnabled,
      createdAt: Date.now()
    });
  }
}

function options() {
  return {
    cps: true,
    sqrlonly: $('#optSqrlOnly').checked,
    hardlock: $('#optHardlock').checked,
    noiptest: !!S.globals.noiptest
  };
}

/**
 * Build a request with `build()`, POST it and feed the reply. A transient error (TIF 0x20)
 * means "reissue the same command with the fresh nut"; if the retry fails identically the
 * page the user is logging in from has expired.
 */
async function send(build) {
  let st = null;
  for (let attempt = 0; attempt < 2; attempt++) {
    const req = await build();
    progress(`Contacting ${S.urlInfo.host} (${req.command})…`);
    const body = await postRequest(req);
    st = await core().call('sessionFeed', { session: S.session, body });
    if (st.state !== 'transient') return st;
  }
  st.message = 'The login page has expired. Reload it in the website and try again.';
  return st;
}

/** Open the session and run the initial query (trying older previous identities as needed). */
async function startSession() {
  if (S.session) await core().free(S.session);
  const altId = S.globals.askAltId ? $('#altId').value.trim() : '';
  const s = await core().call('sessionNew', { unlocked: S.unlocked, url: sqrlUrl, options: options(), altId });
  S.session = s.session;
  const query = () => core().call('sessionQuery', { session: S.session });
  let st = await send(query);
  // "If neither the 0x01 nor 0x02 bits are set, and if the client has earlier previous
  // identity credentials, it should successively try each one, in turn."
  while (st.state === 'unknown' && s.hasPrevious) {
    const { more } = await core().call('sessionTryNextPrevious', { session: S.session });
    if (!more) break;
    st = await send(query);
  }
  return st;
}

function describeFailure(st) {
  if (st.state === 'superseded') {
    return `${S.urlInfo.host} reports that this identity is obsolete: it was re-keyed on another of your devices and the site already knows the newer identity. Export the current identity from that device and import it here, then try again.`;
  }
  if (st.state === 'transient') return st.message || 'The site reported a transient error. Please try again.';
  return st.message || 'The site rejected the request.';
}

async function finishLogin(st, verb = 'Logged in') {
  if (st.cpsUrlError) {
    result(`${verb}, but the site tried to redirect to a different host (${st.cpsUrlError}). Not following it.`, { kind: 'error' });
    return;
  }
  if (st.cpsUrl) {
    result(`${verb}. Redirecting…`);
    await navigateAway(st.cpsUrl);
    if (!inTab && S.globals.closeAfterLogin) window.close();
    return;
  }
  // The server did not use CPS (no url=). Flag 0x0100 asks the client to point this out,
  // since without CPS the login is open to spoofing by a page that relayed another site's link.
  const warn = S.settings.optionFlags & FLAG_WARN_NON_CPS ? ' Note: this site did not use SQRL\'s Client Provided Session; without it, make sure the page you came from really belongs to ' + S.urlInfo.host + '.' : '';
  result(`${verb} at ${S.urlInfo.host}. The website should update by itself; if it does not, reload it.${warn}`, { kind: warn ? '' : 'ok' });
  if (!inTab && S.globals.closeAfterLogin && !warn) setTimeout(() => window.close(), 2500);
}

/**
 * Handle a pending server question, if any. Returns false when the user cancelled, in which
 * case no further command is sent. A button may carry a same-origin URL that is opened too.
 */
async function handleAsk(st) {
  if (!st.ask) return true;
  const btn = await askQuestion(st.ask);
  if (btn === null) return false;
  await core().call('sessionSetButton', { session: S.session, btn });
  if (btn > 0) {
    const { url } = await core().call('sessionAskButtonUrl', { session: S.session, index: btn - 1 });
    if (url) api.tabs.create({ url, active: false }).catch(() => {});
  }
  return true;
}

async function login() {
  const st = await startSession();
  if (st.state === 'failed' || st.state === 'superseded') {
    result(describeFailure(st), { kind: 'error', retry: st.state !== 'superseded' });
    return;
  }
  if (!st.ipsMatched && S.settings.optionFlags & FLAG_WARN_MITM) {
    const ok = await confirm(
      `${S.urlInfo.host} reports that this login was requested from a different network address than the one you are using now. That can happen behind proxies, but it can also mean someone else started this login. Continue?`
    );
    if (!ok) return cancel();
  }
  if (st.state === 'known' && st.disabled) {
    result(`SQRL login is currently disabled for your account at ${S.urlInfo.host}. Use "Advanced" to re-enable it with your rescue code.`, { kind: 'error' });
    return;
  }
  if (st.state === 'unknown') {
    const ok = await confirm(`You do not have a SQRL account at ${S.urlInfo.host} yet. Create one now with this identity?`, 'Create account');
    if (!ok) return cancel();
  } else if (st.state === 'previousKnown') {
    if (st.disabled) {
      result(`SQRL login is disabled for your (previous) account at ${S.urlInfo.host}. Use "Advanced" → Re-enable.`, { kind: 'error' });
      return;
    }
    const ok = await confirm(`${S.urlInfo.host} knows a previous version of your identity. Continue to update your account to your current identity?`, 'Update and log in');
    if (!ok) return cancel();
  }
  if (!(await handleAsk(st))) return cancel();
  const st2 = await send(() => core().call('sessionIdent', { session: S.session }));
  if (st2.state === 'known' && !st2.disabled) {
    await finishLogin(st2);
  } else {
    result(describeFailure(st2), { kind: 'error', retry: true });
  }
}

async function disableSite() {
  const st = await startSession();
  if (st.state !== 'known' && st.state !== 'previousKnown') {
    result(st.state === 'unknown' ? `${S.urlInfo.host} does not know this identity; nothing to disable.` : describeFailure(st), { kind: 'error' });
    return;
  }
  if (st.disabled) {
    result('SQRL login is already disabled at this site.', { kind: '' });
    return;
  }
  const ok = await confirm(
    `Disable SQRL login for your account at ${S.urlInfo.host}? You will need your rescue code to re-enable it. (Use this if you suspect your identity was stolen.)`,
    'Disable'
  );
  if (!ok) return cancel();
  if (!(await handleAsk(st))) return cancel();
  const st2 = await send(() => core().call('sessionDisable', { session: S.session }));
  if (st2.sqrlDisabled && !st2.message) result(`SQRL login is now disabled at ${S.urlInfo.host}.`);
  else result(describeFailure(st2), { kind: 'error' });
}

async function withIuk(st, purpose) {
  // A previous-identity match lets the session sign with the stored previous IUK.
  if (st.previousIdMatch && !st.idMatch) return null;
  while (true) {
    const code = await askRescueCode(`Enter the rescue code of "${S.record.name}" to ${purpose}.`);
    if (code == null) return false;
    try {
      const { iuk } = await core().call('unlockIuk', { file: S.file, rescueCode: code }, (p) => progress('Decrypting rescue code (EnScrypt)…', p));
      return iuk;
    } catch (e) {
      toast(e.message, 'error');
    }
  }
}

async function enableSite() {
  const st = await startSession();
  if (st.state !== 'known' && st.state !== 'previousKnown') {
    result(st.state === 'unknown' ? `${S.urlInfo.host} does not know this identity.` : describeFailure(st), { kind: 'error' });
    return;
  }
  if (!st.disabled) {
    result('SQRL login is already enabled at this site.', { kind: '' });
    return;
  }
  const iuk = await withIuk(st, 're-enable SQRL login');
  if (iuk === false) return cancel();
  if (!(await handleAsk(st))) return cancel();
  const st2 = await send(() => core().call('sessionEnable', { session: S.session, iuk }));
  if (st2.state === 'known' && !st2.disabled) await finishLogin(st2, 'SQRL login re-enabled and logged in');
  else result(describeFailure(st2), { kind: 'error' });
}

async function removeSite() {
  const st = await startSession();
  if (st.state !== 'known' && st.state !== 'previousKnown') {
    result(st.state === 'unknown' ? `${S.urlInfo.host} does not know this identity; nothing to remove.` : describeFailure(st), { kind: 'error' });
    return;
  }
  const ok = await confirm(
    `Remove the SQRL association from your account at ${S.urlInfo.host}? The site will forget this identity; you may lose access to the account unless the site offers another login method.`,
    'Remove'
  );
  if (!ok) return cancel();
  const iuk = await withIuk(st, 'remove the association');
  if (iuk === false) return cancel();
  if (!(await handleAsk(st))) return cancel();
  const st2 = await send(() => core().call('sessionRemove', { session: S.session, iuk }));
  if (st2.state === 'unknown' && !st2.message) {
    result(`The SQRL association at ${S.urlInfo.host} has been removed.`);
    if (st2.cpsUrl) await navigateAway(st2.cpsUrl);
  } else result(describeFailure(st2), { kind: 'error' });
}

async function run(action) {
  if (S.busy) return;
  S.busy = true;
  try {
    const password = $('#password').value;
    if (!password) {
      toast('Enter your password', 'error');
      $('#password').focus();
      return;
    }
    // Access to this one site is requested here, while the click that submitted the form
    // still counts as a user gesture (EnScrypt below takes seconds and would outlive it).
    if (!(await ensureHostPermission(S.urlInfo.postUrl))) {
      result(`The browser did not grant access to ${S.urlInfo.host}, so the login cannot be sent. Try again and allow the request.`, { kind: 'error', retry: true });
      return;
    }
    await unlock(password);
    $('#password').value = '';
    await action();
  } catch (e) {
    console.error(e);
    result(e.message || String(e), { kind: 'error', retry: true });
  } finally {
    S.busy = false;
  }
}

$('#unlockForm').addEventListener('submit', (e) => {
  e.preventDefault();
  run(login);
});
$('#btnDisable').addEventListener('click', () => run(disableSite));
$('#btnEnable').addEventListener('click', () => run(enableSite));
$('#btnRemove').addEventListener('click', () => run(removeSite));
$('#identity').addEventListener('change', () => identityChanged().catch((e) => toast(e.message, 'error')));
$('#btnCancel').addEventListener('click', cancel);
$('#btnCancel2').addEventListener('click', cancel);
$('#btnDone').addEventListener('click', done);
$('#btnRetry').addEventListener('click', () => {
  panel('#panel-identity');
  $('#password').focus();
});
$('#btnCreate').addEventListener('click', () => {
  api.tabs.create({ url: api.runtime.getURL('identity.html') });
  if (!inTab) window.close();
});

init().catch((e) => result(e.message || String(e), { kind: 'error' }));
