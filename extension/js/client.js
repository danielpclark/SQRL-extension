// Promise-based wrapper around the crypto worker (js/worker.js).

const api = globalThis.browser ?? globalThis.chrome;

export class SqrlCore {
  constructor() {
    this.worker = new Worker(api.runtime.getURL('js/worker.js'), { type: 'module' });
    this.pending = new Map();
    this.nextId = 1;
    this.worker.onmessage = (ev) => {
      const { id, progress, ok, result, error } = ev.data;
      const p = this.pending.get(id);
      if (!p) return;
      if (progress !== undefined) {
        if (p.onProgress) p.onProgress(progress);
        return;
      }
      this.pending.delete(id);
      if (ok) p.resolve(result);
      else p.reject(new Error(error));
    };
    this.worker.onerror = (ev) => {
      for (const p of this.pending.values()) p.reject(new Error('crypto worker failed: ' + (ev.message || 'unknown error')));
      this.pending.clear();
    };
  }

  call(op, args, onProgress) {
    return new Promise((resolve, reject) => {
      const id = this.nextId++;
      this.pending.set(id, { resolve, reject, onProgress });
      this.worker.postMessage({ id, op, args: args || {} });
    });
  }

  free(handle) {
    if (handle != null) return this.call('free', { handle }).catch(() => {});
  }

  terminate() {
    this.worker.terminate();
  }
}

let shared = null;
export function core() {
  if (!shared) shared = new SqrlCore();
  return shared;
}

/** POST a SQRL request built by the session and return the response body. */
export async function postRequest(req) {
  const res = await fetch(req.url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: req.body,
    credentials: 'omit',
    cache: 'no-store',
    redirect: 'error'
  });
  if (!res.ok) throw new Error(`server answered HTTP ${res.status}`);
  return (await res.text()).trim();
}

/** Ensure (and if necessary request) host permission for a URL. Returns true if granted. */
export async function ensureHostPermission(url) {
  try {
    const u = new URL(url);
    const origin = `${u.protocol}//${u.hostname}/*`;
    const perm = { origins: [origin] };
    if (await api.permissions.contains(perm)) return true;
    return await api.permissions.request(perm);
  } catch (e) {
    return true;
  }
}
