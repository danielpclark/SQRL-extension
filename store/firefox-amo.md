# Firefox Add-ons (addons.mozilla.org) listing – copy and paste

Developer hub: <https://addons.mozilla.org/developers/>
Submit a New Add-on → **On this site** (listed).
Upload: `dist/sqrl-login-firefox-v1.0.0.zip` (from `./build.sh`).

## Step 1 – Upload

Platforms: Firefox (desktop). Firefox for Android can be enabled later; the manifest's
`strict_min_version` of 142 satisfies both.

**"Do you use any compiled, minified or obfuscated code?"** → **Yes.**
The bundle contains `pkg/sqrl_wasm_bg.wasm`, compiled from the Rust crates in this
repository. Upload the source archive (`sqrl-login-vX.Y.Z-source.zip` from the GitHub
release, or `git archive --format=zip HEAD`) and paste the contents of
`store/REVIEWER-NOTES.md` into the "notes to reviewer" field.

## Step 2 – Describe the add-on

**Name:** SQRL Login

**Add-on URL slug:** sqrl-login

**Summary** (250 characters max):
Passwordless sign-in with SQRL (Secure Quick Reliable Login): one identity, a unique cryptographic key for every site, nothing to phish. Rust/WebAssembly core, verified against GRC's specification.

**Description:**

SQRL Login is a complete client for SQRL, the Secure Quick Reliable Login system designed by Steve Gibson of GRC. With SQRL you sign in to websites without usernames or passwords: your single identity derives a different cryptographic key for every site, the site stores only that site-specific public key, and signing in means signing a one-time challenge. There is nothing to remember per site, nothing to reuse, and nothing a phishing page can capture.

<b>What the extension does</b>
<ul>
<li>Signs you in to any SQRL-enabled website when you click its "Sign in with SQRL" link, including Client Provided Session (CPS), SQRL's protection against spoofed sites.</li>
<li>Creates your identity, protected by one password you choose and a 24-digit rescue code the extension generates for recovery.</li>
<li>Imports and exports identities in the standard SQRL formats (identity file, textual identity, QR code), so the same identity works in GRC's Windows client and the Android and iOS apps.</li>
<li>QuickPass: after the first login, just the first few characters of your password are needed; it is cleared on idle, lock or a wrong entry.</li>
<li>Lets you disable, re-enable or remove your SQRL access on a site, and re-key your identity, exactly as the SQRL specification describes.</li>
</ul>

<b>Built for trust</b>
<ul>
<li>All cryptography and protocol code is written in Rust and compiled to WebAssembly; the source is open (MIT) at https://github.com/danielpclark/SQRL-extension.</li>
<li>Verified against GRC's published specification and test vectors.</li>
<li>Nothing is ever sent anywhere except the SQRL protocol messages to the site you are signing in to. No accounts, no analytics, no servers of our own.</li>
</ul>

**Categories:** Privacy & Security (primary), Other.

**Tags:** sqrl, login, passwordless, authentication, security, privacy

**Support email / website:** https://github.com/danielpclark/SQRL-extension/issues

**License:** MIT License

**Privacy policy:** paste the text of `PRIVACY.md`.

**Icon:** `extension/icons/icon128.png` (AMO also accepts the 256 px or 512 px file).

**Screenshots:** `store/screenshots/*.png` (1280×800).

**Version notes (1.0.0):** First public release.

## Data collection (required for new submissions)

The manifest declares `browser_specific_settings.gecko.data_collection_permissions.required: ["none"]`,
which AMO shows to users as "This extension does not collect any data". No other data
disclosure is needed.

## Before each upload

1. Bump `version` in `extension/manifest.json` and `Cargo.toml`.
2. `./build.sh --test` and `npx --yes web-ext lint --source-dir dist/firefox` (expect 0 warnings).
3. Upload the new zip and a matching source archive.
