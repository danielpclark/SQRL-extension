#!/usr/bin/env bash
# Builds the Rust core to WebAssembly and assembles the extension in ./dist.
#
#   ./build.sh            # release build into extension/pkg and dist/
#   ./build.sh --test     # also run the Rust test-suite first
#
# Requirements: rustup target wasm32-unknown-unknown, wasm-bindgen-cli (same version as the
# wasm-bindgen crate in crates/sqrl-wasm/Cargo.toml).
set -euo pipefail
cd "$(dirname "$0")"

if [[ "${1:-}" == "--test" ]]; then
  cargo test --release -p sqrl-core
fi

cargo build --release -p sqrl-wasm --target wasm32-unknown-unknown
rm -rf extension/pkg
wasm-bindgen --target web --out-dir extension/pkg --no-typescript \
  target/wasm32-unknown-unknown/release/sqrl_wasm.wasm
if command -v wasm-opt >/dev/null 2>&1; then
  wasm-opt -Oz -o extension/pkg/sqrl_wasm_bg.wasm extension/pkg/sqrl_wasm_bg.wasm
fi

rm -rf dist && mkdir -p dist
cp -r extension dist/sqrl-extension
( cd dist && zip -qr sqrl-extension.zip sqrl-extension )
echo "Built dist/sqrl-extension (unpacked) and dist/sqrl-extension.zip"
ls -la extension/pkg
