// Crypto worker: owns the WebAssembly instance so that the slow EnScrypt derivations never
// block the UI thread. Pages talk to it through js/client.js.
//
// Objects that live in WebAssembly memory (identity files, unlocked identities, sessions)
// are referenced by numeric handles; the page frees them explicitly or when the page goes
// away (the worker dies with it).

import init, * as sqrl from '../pkg/sqrl_wasm.js';

const ready = init();
const handles = new Map();
let nextHandle = 1;

function keep(obj) {
  const id = nextHandle++;
  handles.set(id, obj);
  return id;
}
function take(id) {
  const o = handles.get(id);
  if (!o) throw new Error('invalid handle ' + id);
  return o;
}
function fileInfo(file, handle) {
  return {
    file: handle,
    hasPassword: file.hasPasswordBlock(),
    hasRescue: file.hasRescueBlock(),
    previousCount: file.previousCount(),
    settings: JSON.parse(file.settings()),
    iterations: file.passwordIterations(),
    text: file.toText()
  };
}

const ops = {
  defaultSettings: () => JSON.parse(sqrl.defaultSettings()),
  generateRescueCode: () => sqrl.generateRescueCode(),
  formatRescueCode: ({ code }) => sqrl.formatRescueCode(code),
  parseUrl: ({ url }) => JSON.parse(sqrl.parseSqrlUrl(url)),
  randomBytes: ({ n }) => sqrl.randomBytes(n),

  parseFile: ({ text, bytes }) => {
    const file = bytes ? sqrl.SqrlIdentityFile.parse(bytes) : sqrl.SqrlIdentityFile.parseText(text);
    return fileInfo(file, keep(file));
  },
  parseTextual: ({ text }) => {
    const file = sqrl.SqrlIdentityFile.parseTextual(text);
    return fileInfo(file, keep(file));
  },
  createIdentity: ({ password, rescueCode, settings, rescueMs }, progress) => {
    const file = sqrl.SqrlIdentityFile.create(password, rescueCode, JSON.stringify(settings || {}), rescueMs || 5000, (stage, a, b) =>
      progress({ stage, done: a, total: b })
    );
    return fileInfo(file, keep(file));
  },
  deriveKey: ({ file, password }, progress) => {
    const key = take(file).deriveKey(password, (a, b) => progress({ done: a, total: b }));
    return { key };
  },
  unlock: ({ file, key, password }, progress) => {
    const f = take(file);
    const unlocked = key ? f.unlockWithKey(key) : f.unlock(password, (a, b) => progress({ done: a, total: b }));
    return { unlocked: keep(unlocked), fingerprint: unlocked.fingerprint(), previousCount: unlocked.previousCount() };
  },
  unlockIuk: ({ file, rescueCode }, progress) => {
    const iuk = take(file).unlockIuk(rescueCode, (a, b) => progress({ done: a, total: b }));
    return { iuk };
  },
  fromIuk: ({ iuk, file }) => {
    const unlocked = sqrl.SqrlUnlocked.fromIuk(iuk);
    let previousCount = 0;
    if (file != null) previousCount = unlocked.loadPreviousFrom(take(file));
    return { unlocked: keep(unlocked), fingerprint: unlocked.fingerprint(), previousCount };
  },
  matchesIuk: ({ unlocked, iuk }) => ({ matches: take(unlocked).matchesIuk(iuk) }),
  setPassword: ({ file, unlocked, password, settings }, progress) => {
    const f = take(file);
    f.setPassword(take(unlocked), password, JSON.stringify(settings || {}), (a, b) => progress({ done: a, total: b }));
    return fileInfo(f, file);
  },
  fromUnlocked: ({ unlocked, file, password, settings }, progress) => {
    const f = sqrl.SqrlIdentityFile.fromUnlocked(take(unlocked), take(file), password, JSON.stringify(settings || {}), (a, b) =>
      progress({ done: a, total: b })
    );
    return fileInfo(f, keep(f));
  },
  rekey: ({ file, unlocked, oldIuk, password, rescueCode, settings, rescueMs }, progress) => {
    const f = take(file);
    const newUnlocked = f.rekey(take(unlocked), oldIuk, password, rescueCode, JSON.stringify(settings || {}), rescueMs || 5000, (stage, a, b) =>
      progress({ stage, done: a, total: b })
    );
    return { ...fileInfo(f, file), unlocked: keep(newUnlocked), fingerprint: newUnlocked.fingerprint(), previousCount: newUnlocked.previousCount() };
  },
  exportFile: ({ file }) => {
    const f = take(file);
    const out = { text: f.toText(), bytes: f.toBytes(), hasRescue: f.hasRescueBlock() };
    if (f.hasRescueBlock()) {
      out.textual = f.toTextual();
      out.rescueText = f.rescueOnlyText();
      out.rescueBytes = f.rescueOnlyBytes();
    }
    return out;
  },
  quickpassSeal: ({ key, hint, logN, ms }) => ({ blob: sqrl.quickpassSeal(key, hint, logN || 9, ms || 500) }),
  quickpassOpen: ({ blob, hint, logN }) => ({ key: sqrl.quickpassOpen(blob, hint, logN || 9) }),

  sessionNew: ({ unlocked, url, options, altId }) => {
    const s = new sqrl.SqrlSession(take(unlocked), url, JSON.stringify(options || {}), altId || null);
    return { session: keep(s), siteKey: s.siteKey(), host: s.host(), idk: s.idk(), hasPrevious: s.hasPrevious() };
  },
  sessionQuery: ({ session }) => JSON.parse(take(session).query()),
  sessionIdent: ({ session }) => JSON.parse(take(session).ident()),
  sessionDisable: ({ session }) => JSON.parse(take(session).disable()),
  sessionEnable: ({ session, iuk }) => JSON.parse(take(session).enable(iuk || undefined)),
  sessionRemove: ({ session, iuk }) => JSON.parse(take(session).remove(iuk || undefined)),
  sessionFeed: ({ session, body }) => JSON.parse(take(session).feed(body)),
  sessionState: ({ session }) => JSON.parse(take(session).state()),
  sessionSetButton: ({ session, btn }) => {
    take(session).setButton(btn);
    return {};
  },
  sessionTryNextPrevious: ({ session }) => ({ more: take(session).tryNextPrevious() }),

  free: ({ handle }) => {
    const o = handles.get(handle);
    if (o) {
      handles.delete(handle);
      if (typeof o.free === 'function') o.free();
    }
    return {};
  }
};

self.onmessage = async (ev) => {
  const { id, op, args } = ev.data;
  try {
    await ready;
    const fn = ops[op];
    if (!fn) throw new Error('unknown operation ' + op);
    const result = await fn(args || {}, (progress) => self.postMessage({ id, progress }));
    self.postMessage({ id, ok: true, result });
  } catch (e) {
    self.postMessage({ id, ok: false, error: e && e.message ? e.message : String(e) });
  }
};
