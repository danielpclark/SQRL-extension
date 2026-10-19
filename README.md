# SQRL Login – browser extension

<img src="extension/icons/icon128.png" alt="SQRL" width="96" align="right">

A complete client for **SQRL (Secure Quick Reliable Login)**, Steve Gibson's password-less
authentication system (<https://www.grc.com/sqrl/sqrl.htm>), packaged as a Manifest V3
browser extension for Chrome, Edge, Brave and Firefox.

All of the protocol, cryptography and identity-storage logic is written in **Rust** and
compiled to WebAssembly; JavaScript is used only for the browser-extension plumbing (tabs,
storage, fetch) and the user interface.

## What it implements

The implementation follows GRC's four specification documents (SQRL Explained, Operating
Details v1.01, Cryptography v1.04 and On The Wire v1.07, all from late 2019), the spec
pages on grc.com, and the rulings Steve Gibson made in the `grc.sqrl` newsgroup where the
documents are ambiguous. Where an older decision was later reversed, the later one is used.

* **Identities** – creation from 256 bits of entropy, the 24-digit rescue code (extracted
  by long division, as specified), `EnHash`, the Identity Master / Lock / Unlock keys.
* **EnScrypt** – iterated, XOR-chained scrypt (N=512, r=256, p=1), both iteration-count
  and time-based, verified against every published test vector (the grc.com vectors, the
  Spec-Vectors-Identity logs, and the community vectors cross-checked against GRC's
  `EnScrypt.exe`). Passwords are NFKC-normalized before use.
* **S4 storage** – type 1, 2 and 3 blocks (AES-256-GCM with the specified IVs and
  authenticated plaintext), the `sqrldata`/`SQRLDATA` binary and base64url forms, unknown
  block preservation, duplicate-block rejection, the type 3 *edition* counter, password
  changes, settings, and re-keying with up to four previous identities.
* **Textual identity** – the base56 export/import format with per-line check characters,
  verified against GRC's own export and the Spec-Vectors-Identity.
* **QR code export** of the binary identity (the format other SQRL clients import).
* **Protocol** – `query`, `ident`, `disable`, `enable`, `remove`; `ids`/`pids`/`urs`
  signatures; the identity lock (SUK/VUK/URSK) for account creation, re-keying, enable and
  remove; iteration through previous identities; `sin`/`ins`/`pins` indexed secrets;
  `ask`/`btn` (0/1/2, same-origin button URLs); `sqrlonly`/`hardlock`/`cps`/`suk`/`noiptest`
  options; every TIF bit including *identity superseded*, with undefined bits aborting the
  transaction; transient-error retry; `can=` cancel URLs; the `x=` path extension and
  Alt-IDs (NUL-separated). The query and ident POST bodies reproduce GRC's reference client
  log byte for byte.
* **Client Provided Session (CPS)** – the extension is an "internal browser client" in the
  sense of the Operating Details document: it captures `sqrl://` links, performs the
  authentication, and sends the tab straight to the server's `url=`. For sites written
  for native clients it also answers the `http(s)://localhost:25519/*.gif` probe and turns
  the `localhost:25519/<base64url>` navigation into its own login page, so CPS works with
  unmodified SQRL sites (including GRC's SSP API pages).
* **QuickPass** – the first *n* password characters, EnScrypted for one second, re-encrypt
  the password key in `storage.session` (memory only); one wrong QuickPass clears it, as do
  the idle timeout (flag 0x0080) and system lock/sleep.

## Repository layout

| Path | Contents |
| --- | --- |
| `crates/sqrl-core` | Pure-Rust library: crypto, identity, S4 storage, textual identity, URL parsing, protocol session, and a reference server used by the tests. |
| `crates/sqrl-wasm` | `wasm-bindgen` bindings exposing the core to JavaScript. |
| `crates/sqrl-test-server` | A small plain-HTTP SQRL site for exercising the extension locally. |
| `extension/` | The MV3 extension: `manifest.json`, `background.js`, `content.js`, pages, and `js/` (crypto worker, login dialog, identity manager, options, QR encoder). `extension/pkg/` is generated. |
| `tests/` | Node smoke test of the wasm package against the test server, and a decoder-based check of the QR encoder. |
| `store/` | Promotional images for the store listings, generated from the official artwork. |
| `.github/workflows/` | CI (tests, build, lint) and the tag-driven release that attaches store bundles to a GitHub release. |

## Building

Requirements: a Rust toolchain with the `wasm32-unknown-unknown` target, `wasm-bindgen-cli`
**0.2.129** (the version pinned in `crates/sqrl-wasm/Cargo.toml`), Python 3, `zip`, and
Node 20+ for the JavaScript tests.

```fish
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.129 --locked
./build.sh --test       # runs the Rust tests, builds the wasm, assembles dist/
```

`build.sh` produces `extension/pkg/` (the wasm and its glue) and, under `dist/`, unpacked
`chrome/` and `firefox/` bundles plus `sqrl-login-chrome-vX.Y.Z.zip` and
`sqrl-login-firefox-vX.Y.Z.zip`. The two differ only in their manifests: Chrome gets
`background.service_worker`, Firefox gets `background.scripts` and its
`browser_specific_settings`.

### Tests

```fish
cargo test --release -p sqrl-core              # 62 unit, flow and test-vector tests
cargo build --release -p sqrl-test-server; and node tests/smoke.mjs
python3 -m pip install zxing-cpp numpy; and node tests/qr-check.mjs
npx --yes web-ext lint --source-dir dist/firefox
```

The Rust tests run EnScrypt many times, so use `--release`.

## Installing a development build

**Chrome / Edge / Brave:** open `chrome://extensions`, enable *Developer mode*, choose
*Load unpacked* and select `dist/chrome`.

**Firefox:** open `about:debugging#/runtime/this-firefox`, choose *Load Temporary Add-on*
and select `dist/firefox/manifest.json`. Firefox asks for host permission on first use of
a site; the login dialog requests it.

## Using it

1. Click the toolbar icon, open **Identities**, and create an identity (you choose a
   password; the extension generates the rescue code, which you must write down and
   re-type). Back it up: the identity file (`.sqrl`), the textual identity, or the QR code.
   Existing identities from GRC's client or any other SQRL client import directly.
2. On a SQRL-enabled site, click its *Sign in with SQRL* link (sites using SQRL's standard
   same-device handoff land in the extension automatically), or click the toolbar button,
   which lists the SQRL links on the current page. The first login to a site asks the
   browser for permission to contact that one site. The login dialog shows the site's
   domain, asks for your password (or QuickPass), and logs you in. Unknown sites ask
   before an account is created; re-keyed identities update the site silently.
   To have plain `sqrl://` link clicks handled on every site, turn on "Handle sqrl:// link
   clicks automatically" in the settings; that is the only option that asks for access to
   all sites.
3. *Advanced* in the login dialog disables, re-enables or removes your SQRL association on
   the site. Re-enabling and removal need the rescue code, as the protocol requires.

For local testing: `cargo run --release -p sqrl-test-server` and open
<http://localhost:8080/>. The site uses `qrl://` (plain HTTP), which the extension accepts
only for localhost.

### Releases on GitHub

Creating a tag that matches the manifest version (for example `v1.0.0`) runs
`.github/workflows/release.yml`, which rebuilds, lints, and attaches the Chrome zip, the
Firefox zip and a source archive to a GitHub release with generated notes:

```fish
git tag v1.0.0; and git push origin v1.0.0
```

The workflow file contains commented jobs that upload to the Chrome Web Store
(`chrome-webstore-upload-cli`) and sign/publish on AMO (`web-ext sign`) once the store API
credentials are added as repository secrets.

## Security notes

* Decrypted keys live only inside the WebAssembly heap of a dedicated worker in the login
  page and are zeroized when freed. Identities at rest are the password-encrypted S4
  file in `chrome.storage.local`; nothing is ever uploaded anywhere.
* The server's `qry=` is pinned to the original host; `url=` (CPS) is followed only if it
  points at the same host; `ask` button URLs are forced onto the site's origin. Responses
  with TIF bits outside protocol version 1 abort the login.
* The same-IP check is left on (no `noiptest`) because a same-device login must come from
  the page's own IP; a setting exists for VPN/proxy setups.
* As Steve Gibson noted on the newsgroup, SQRL defends against network attacks, not against
  malicious software on the same machine: another extension or local program that can drive
  a browser tab could trigger a login prompt. The dialog therefore always shows the domain
  and always requires your password or QuickPass.
* Internationalized domain names must appear in the `sqrl://` link in Punycode form (as
  DNS sees them); the extension does not convert Unicode hosts.

## Credits

SQRL was designed by Steve Gibson of Gibson Research Corporation, who published the
specification and placed it, together with the official logo used here, in the public
domain (<https://www.grc.com/sqrl/logo.htm>). The colors follow the official logo background
(RGB 0/124/195) and the sqrl.grc.com site theme.

## License

This project is released under the **MIT License**. You may use, copy, modify, merge,
publish, distribute, sublicense and sell copies of it, provided the copyright notice and
permission notice in [LICENSE](LICENSE) are included; it comes without warranty of any kind.
See the [LICENSE](LICENSE) file for the full text.

Copyright © 2026 Daniel P. Clark.
