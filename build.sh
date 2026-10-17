#!/usr/bin/env bash
# Builds the Rust core to WebAssembly and assembles store-ready extension bundles.
#
#   ./build.sh            # build into extension/pkg and dist/
#   ./build.sh --test     # run the Rust test-suite first
#
# Output:
#   extension/pkg/                     wasm-bindgen output used by the unpacked extension
#   dist/chrome/                       unpacked bundle for Chrome / Edge / Brave (manifest without Firefox keys)
#   dist/firefox/                      unpacked bundle for Firefox (manifest with background.scripts)
#   dist/sqrl-login-chrome-vX.Y.Z.zip  upload this to the Chrome Web Store
#   dist/sqrl-login-firefox-vX.Y.Z.zip upload this to addons.mozilla.org
#
# Requirements: rustup target wasm32-unknown-unknown, wasm-bindgen-cli (same version as the
# wasm-bindgen crate in crates/sqrl-wasm/Cargo.toml), python3, zip.
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

VERSION=$(python3 -c "import json;print(json.load(open('extension/manifest.json'))['version'])")
rm -rf dist && mkdir -p dist

# Chrome and Firefox each ignore the other's background key, but the store linters do not,
# so each bundle gets a manifest with only its own keys.
for BROWSER in chrome firefox; do
  OUT="dist/$BROWSER"
  mkdir -p "$OUT"
  # icon512.png and the SVG are for store listings / documentation, not for the bundle
  rsync -a --exclude 'icons/icon512.png' --exclude 'icons/sqrl-icon.svg' --exclude '.DS_Store' extension/ "$OUT/"
  python3 - "$OUT/manifest.json" "$BROWSER" <<'PY'
import json, sys
path, browser = sys.argv[1], sys.argv[2]
m = json.load(open(path))
if browser == "chrome":
    m["background"].pop("scripts", None)
    m.pop("browser_specific_settings", None)
else:
    m["background"].pop("service_worker", None)
json.dump(m, open(path, "w"), indent=2)
open(path, "a").write("\n")
PY
  ( cd "$OUT" && zip -qr "../sqrl-login-$BROWSER-v$VERSION.zip" . -x '.DS_Store' )
done

echo "Built version $VERSION:"
ls -la dist/*.zip
