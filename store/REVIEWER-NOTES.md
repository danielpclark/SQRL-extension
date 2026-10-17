# Notes for store reviewers (source code and build instructions)

The extension package contains one compiled file, `pkg/sqrl_wasm_bg.wasm`, and its
`wasm-bindgen`-generated loader `pkg/sqrl_wasm.js`. Both are produced from the Rust source in
this repository by `build.sh`; nothing is minified or obfuscated, and all other JavaScript is
shipped as written.

## Reproducing the build

Tested on Ubuntu 24.04 and macOS 15 (arm64). The exact commands are also in
`.github/workflows/release.yml`, which is what produced the uploaded package.

```sh
# Rust toolchain (stable) with the WebAssembly target
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"
rustup target add wasm32-unknown-unknown

# wasm-bindgen CLI, pinned to the exact version of the wasm-bindgen crate in
# crates/sqrl-wasm/Cargo.toml (the two must match)
cargo install wasm-bindgen-cli --version 0.2.129 --locked

# Build
./build.sh
```

`build.sh` runs `cargo build --release -p sqrl-wasm --target wasm32-unknown-unknown`,
then `wasm-bindgen --target web --out-dir extension/pkg --no-typescript`, copies `extension/`
into `dist/chrome` and `dist/firefox` with the per-browser manifest, and zips each.

To compare with the uploaded package: unzip it next to `dist/firefox` (or `dist/chrome`) and
`diff -r`. `pkg/sqrl_wasm.js` is byte-identical given the same wasm-bindgen version.
`pkg/sqrl_wasm_bg.wasm` is identical given the same Rust compiler release (`Cargo.lock` pins
every crate); if `wasm-opt` happens to be installed on the build machine it is run with
`-Oz`, which changes the bytes but not the behaviour, so compare with it absent.

## Tests

```sh
cargo test --release -p sqrl-core          # 62 tests incl. GRC's published test vectors
cargo build --release -p sqrl-test-server && node tests/smoke.mjs
python3 -m pip install zxing-cpp numpy && node tests/qr-check.mjs
```

## What the network code does

The only network requests the extension makes are HTTPS POSTs of SQRL protocol messages
(`extension/js/client.js`, `postRequest`) to the SQRL endpoint of the site the user is
signing in to, with `credentials: 'omit'` and `redirect: 'error'`. The content script
(`extension/content.js`) only looks for anchors whose `href` uses the `sqrl:` scheme. The two
`declarativeNetRequest` rules (`extension/background.js`, `installRules`) only match
`http(s)://localhost:25519/` and `http(s)://127.0.0.1:25519/`, the port the SQRL
specification assigns to local clients.

Specification: https://www.grc.com/sqrl/sqrl.htm (Steve Gibson, GRC; public domain).
