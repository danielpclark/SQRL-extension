// Persistent data: identities (encrypted S4 files as SQRLDATA text) and settings live in
// chrome.storage.local; the QuickPass lives in chrome.storage.session (memory only).

const api = globalThis.browser ?? globalThis.chrome;

export const DEFAULT_SETTINGS = {
  defaultIdentity: null,
  askAltId: false,
  rescueSeconds: 5,
  closeAfterLogin: true,
  // Register content.js on all sites to catch sqrl:// link clicks (needs all-sites access,
  // granted from the options page). Off by default; the popup scans the active tab instead.
  autoLinks: false,
  // Send opt=noiptest. Off by default: for a same-device login the IPs must match, and the
  // server's IP check is one of SQRL's anti-spoofing protections. Only for VPN/proxy setups
  // where the check is known to fail.
  noiptest: false
};

export async function getSettings() {
  const { settings } = await api.storage.local.get('settings');
  return { ...DEFAULT_SETTINGS, ...(settings || {}) };
}

export async function setSettings(patch) {
  const cur = await getSettings();
  const next = { ...cur, ...patch };
  await api.storage.local.set({ settings: next });
  return next;
}

export async function listIdentities() {
  const { identities } = await api.storage.local.get('identities');
  return Array.isArray(identities) ? identities : [];
}

export async function getIdentity(id) {
  return (await listIdentities()).find((i) => i.id === id) || null;
}

export async function getDefaultIdentity() {
  const ids = await listIdentities();
  if (!ids.length) return null;
  const settings = await getSettings();
  return ids.find((i) => i.id === settings.defaultIdentity) || ids[0];
}

export async function saveIdentity(record) {
  const ids = await listIdentities();
  const i = ids.findIndex((x) => x.id === record.id);
  if (i >= 0) ids[i] = { ...ids[i], ...record, updated: Date.now() };
  else ids.push({ created: Date.now(), ...record });
  await api.storage.local.set({ identities: ids });
  const settings = await getSettings();
  if (!settings.defaultIdentity) await setSettings({ defaultIdentity: record.id });
  return record;
}

export async function deleteIdentity(id) {
  const ids = (await listIdentities()).filter((x) => x.id !== id);
  await api.storage.local.set({ identities: ids });
  const settings = await getSettings();
  if (settings.defaultIdentity === id) await setSettings({ defaultIdentity: ids[0] ? ids[0].id : null });
  const qp = await getQuickPass();
  if (qp && qp.identityId === id) await clearQuickPass('identity deleted');
}

export function newIdentityId() {
  const a = new Uint8Array(8);
  crypto.getRandomValues(a);
  return Array.from(a, (b) => b.toString(16).padStart(2, '0')).join('');
}

// --- QuickPass -------------------------------------------------------------------------

export async function getQuickPass() {
  try {
    const { quickpass } = await api.storage.session.get('quickpass');
    return quickpass || null;
  } catch (e) {
    return null;
  }
}

export async function setQuickPass(qp) {
  await api.runtime.sendMessage({ type: 'quickpass-set', quickpass: qp });
}

export async function touchQuickPass(qp) {
  await api.runtime.sendMessage({ type: 'quickpass-touch', idleTimeoutMinutes: qp.idleTimeoutMinutes });
}

export async function clearQuickPass(reason) {
  await api.runtime.sendMessage({ type: 'quickpass-clear', reason });
}

// --- helpers ---------------------------------------------------------------------------

export function bytesToB64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function b64ToBytes(b64) {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
