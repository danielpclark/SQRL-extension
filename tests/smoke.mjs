// End-to-end smoke test of the WebAssembly package against the HTTP test server.
//
//   cargo build --release -p sqrl-test-server && ./build.sh
//   node tests/smoke.mjs            (starts the server itself on 127.0.0.1:8099)
import { readFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import assert from 'node:assert/strict';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const pkg = await import(path.join(root, 'extension/pkg/sqrl_wasm.js'));
const wasmBytes = readFileSync(path.join(root, 'extension/pkg/sqrl_wasm_bg.wasm'));
pkg.initSync({ module: wasmBytes });

const PORT = 8099;
const server = spawn(path.join(root, 'target/release/sqrl-test-server'), [`127.0.0.1:${PORT}`], { stdio: ['ignore', 'ignore', 'pipe'] });
server.stderr.on('data', (d) => process.env.VERBOSE && process.stderr.write(d));
process.on('exit', () => server.kill());
await new Promise((r) => setTimeout(r, 400));

const base = `http://127.0.0.1:${PORT}`;
const t0 = Date.now();

// --- identity creation --------------------------------------------------------------------
const settings = JSON.parse(pkg.defaultSettings());
settings.pwVerifySeconds = 1;
const rescue = pkg.generateRescueCode();
assert.equal(rescue.length, 24);
let stages = [];
const file = pkg.SqrlIdentityFile.create('correct horse', rescue, JSON.stringify(settings), 300, (stage, a, b) => stages.push(stage));
assert(stages.includes('password') && stages.includes('rescue'));
console.log(`identity created in ${Date.now() - t0} ms, ${file.passwordIterations()} password iterations`);
const text = file.toText();
assert(text.startsWith('SQRLDATA'));
const textual = file.toTextual();
assert(/^[2-9A-Za-z ]+(\n[2-9A-Za-z ]+)*$/.test(textual));

// --- unlock, quickpass ----------------------------------------------------------------------
const reparsed = pkg.SqrlIdentityFile.parseText(text);
assert.throws(() => reparsed.unlock('wrong', null));
let t = Date.now();
const key = reparsed.deriveKey('correct horse', null);
const perIter = (Date.now() - t) / reparsed.passwordIterations();
console.log(`EnScrypt in wasm: ${perIter.toFixed(1)} ms per iteration`);
const unlocked = reparsed.unlockWithKey(key);
const fp = unlocked.fingerprint();
assert.equal(fp.length, 16);
const qp = pkg.quickpassSeal(key, 'corr', settings.logN, 100);
assert.equal(qp.length, 80);
assert.deepEqual(Array.from(pkg.quickpassOpen(qp, 'corr', settings.logN)), Array.from(key));
assert.throws(() => pkg.quickpassOpen(qp, 'cors', settings.logN));

// --- rescue-only import: textual identity + rescue code → new password -----------------------
const rescueFile = pkg.SqrlIdentityFile.parseTextual(textual);
assert(!rescueFile.hasPasswordBlock() && rescueFile.hasRescueBlock());
const iuk = rescueFile.unlockIuk(rescue, null);
const fromIuk = pkg.SqrlUnlocked.fromIuk(iuk);
assert.equal(fromIuk.fingerprint(), fp);
assert(unlocked.matchesIuk(iuk));
const rebuilt = pkg.SqrlIdentityFile.fromUnlocked(fromIuk, rescueFile, 'new password', JSON.stringify(settings), null);
assert.equal(rebuilt.unlock('new password', null).fingerprint(), fp);

// --- protocol against the test server ---------------------------------------------------------
async function loginPage() {
  const html = await (await fetch(base + '/')).text();
  const url = html.match(/<code>(qrl:\/\/[^<]+)<\/code>/)[1];
  const session = html.match(/session=([A-Za-z0-9_-]+)/)[1];
  return { url, session };
}
async function post(req) {
  const r = await fetch(req.url, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: req.body, credentials: 'omit' });
  assert.equal(r.status, 200);
  return r.text();
}
async function status(session) {
  return (await (await fetch(`${base}/status?session=${session}`)).json()).authenticated;
}

// create account
let { url, session } = await loginPage();
const u = JSON.parse(pkg.parseSqrlUrl(url));
assert.equal(u.siteKey, `localhost`);
assert.equal(u.postUrl, `http://localhost:${PORT}/cli.sqrl?nut=${u.nut}`.replace(`nut=${u.nut}`, u.postUrl.split('nut=')[1] ? `nut=${u.postUrl.split('nut=')[1]}` : ''));
let s = new pkg.SqrlSession(unlocked, url, JSON.stringify({ cps: true }), null);
let req = JSON.parse(s.query());
// the browser-side fetch targets localhost; the server listens on 127.0.0.1
req.url = req.url.replace('localhost', '127.0.0.1');
let state = JSON.parse(s.feed(await post(req)));
assert.equal(state.state, 'unknown');
req = JSON.parse(s.ident());
req.url = req.url.replace('localhost', '127.0.0.1');
state = JSON.parse(s.feed(await post(req)));
assert.equal(state.state, 'known');
assert.equal(state.cpsUrl, `http://localhost:${PORT}/loggedin?session=${session}`);
assert.equal(await status(session), s.idk());
s.free();

// log in again, then disable / enable / remove
({ url, session } = await loginPage());
s = new pkg.SqrlSession(unlocked, url, '{}', null);
req = JSON.parse(s.query()); req.url = req.url.replace('localhost', '127.0.0.1');
state = JSON.parse(s.feed(await post(req)));
assert.equal(state.state, 'known'); assert(state.hasSuk);
req = JSON.parse(s.disable()); req.url = req.url.replace('localhost', '127.0.0.1');
state = JSON.parse(s.feed(await post(req)));
assert(state.sqrlDisabled);
s.free();

({ url, session } = await loginPage());
s = new pkg.SqrlSession(unlocked, url, '{}', null);
req = JSON.parse(s.query()); req.url = req.url.replace('localhost', '127.0.0.1');
state = JSON.parse(s.feed(await post(req)));
assert.deepEqual([state.state, state.disabled], ['known', true]);
assert.throws(() => s.enable(null));
req = JSON.parse(s.enable(iuk)); req.url = req.url.replace('localhost', '127.0.0.1');
state = JSON.parse(s.feed(await post(req)));
assert(!state.sqrlDisabled && state.state === 'known');
assert.equal(await status(session), s.idk());
s.free();

({ url, session } = await loginPage());
s = new pkg.SqrlSession(unlocked, url, '{}', null);
req = JSON.parse(s.query()); req.url = req.url.replace('localhost', '127.0.0.1');
s.feed(await post(req));
req = JSON.parse(s.remove(iuk)); req.url = req.url.replace('localhost', '127.0.0.1');
state = JSON.parse(s.feed(await post(req)));
assert.equal(state.state, 'unknown');
s.free();

unlocked.free(); fromIuk.free(); file.free(); reparsed.free(); rescueFile.free(); rebuilt.free();
console.log(`smoke test passed in ${Date.now() - t0} ms`);
server.kill();
process.exit(0);
