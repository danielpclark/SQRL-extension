# Chrome Web Store listing – copy and paste

Developer console: <https://chrome.google.com/webstore/devconsole/>
Upload: `dist/sqrl-login-chrome-v1.0.0.zip` (from `./build.sh`).

## Store listing tab

**Name** (from manifest): SQRL Login

**Summary** (from manifest, 132 characters max):
Passwordless sign-in with SQRL (Secure Quick Reliable Login): one identity, a unique key per site, nothing to phish.

**Description:**

SQRL Login is a complete client for SQRL, the Secure Quick Reliable Login system designed by Steve Gibson of GRC. With SQRL you sign in to websites without usernames or passwords: your single identity derives a different cryptographic key for every site, the site stores only that site-specific public key, and signing in means signing a one-time challenge. There is nothing to remember per site, nothing to reuse, and nothing a phishing page can capture.

What the extension does:
• Signs you in to any SQRL-enabled website when you click its "Sign in with SQRL" link, including Client Provided Session (CPS), SQRL's protection against spoofed sites.
• Creates your identity, protected by one password you choose and a 24-digit rescue code the extension generates for recovery.
• Imports and exports identities in the standard SQRL formats (identity file, textual identity, QR code), so the same identity works in GRC's Windows client and the Android and iOS apps.
• QuickPass: after the first login, just the first few characters of your password are needed; it is cleared on idle, lock or a wrong entry.
• Lets you disable, re-enable or remove your SQRL access on a site, and re-key your identity, exactly as the SQRL specification describes.

Built for trust:
• All cryptography and protocol code is written in Rust and compiled to WebAssembly; the source is open (MIT) at https://github.com/danielpclark/SQRL-extension.
• Verified against GRC's published specification and test vectors.
• Nothing is ever sent anywhere except the SQRL protocol messages to the site you are signing in to. No accounts, no analytics, no servers of our own.

**Category:** Productivity (alternative: Developer Tools)

**Language:** English

**Icon:** `extension/icons/icon128.png`

**Screenshots** (1280×800): `store/screenshots/*.png`

**Small promo tile** (440×280): `store/promo-small-440x280.png`
**Marquee promo tile** (1400×560): `store/marquee-1400x560.png`

**Official URL / Homepage:** https://github.com/danielpclark/SQRL-extension
**Support URL:** https://github.com/danielpclark/SQRL-extension/issues

## Privacy practices tab

**Single purpose description:**
Signs the user in to SQRL-enabled websites using the SQRL authentication protocol, and manages the user's SQRL identities locally.

**Permission justifications:**

- `storage`: Stores the user's SQRL identities (encrypted with the user's password in the standard S4 format) and the extension's settings locally. Session storage holds the QuickPass material in memory only.
- `tabs`: After a successful SQRL login the website returns a one-time logged-in URL (Client Provided Session); the extension navigates the originating tab to it. Also used to show "Log in" buttons in the popup for SQRL links found on the active tab.
- `alarms`: Expires the QuickPass after the idle timeout configured in the user's identity.
- `idle`: Clears the QuickPass when the system locks or goes idle, as the SQRL specification's identity options require.
- `declarativeNetRequest`: SQRL websites detect a local SQRL client by requesting an image from http://localhost:25519/ and then navigate to http://localhost:25519/<encoded login URL>. Two redirect rules answer that probe with a bundled 1×1 GIF and turn that navigation into the extension's own login page. No request to any other host is observed or modified.
- Host permission `https://*/*` (and `http://localhost/*`, `http://127.0.0.1/*` for local development servers): The extension must POST SQRL authentication messages to the SQRL endpoint of whichever website the user chooses to sign in to; the set of such sites is not known in advance. The content script runs on pages only to detect links using the `sqrl:` scheme and hand them to the extension when clicked.

**Remote code:** No, I am not using remote code. (The WebAssembly module is bundled in the package; `'wasm-unsafe-eval'` in the CSP only allows the bundled module to be instantiated.)

**Data usage:** The extension does not collect or transmit any user data. Check **none** of the data categories. Certify all three disclosures (no sale, no unrelated use, no creditworthiness use).

**Privacy policy URL:** https://github.com/danielpclark/SQRL-extension/blob/main/PRIVACY.md (or a copy hosted on GitHub Pages).

## Distribution tab

Visibility: Public. Regions: all. Pricing: free.

## Before each upload

1. Bump `version` in `extension/manifest.json` and `Cargo.toml`.
2. `./build.sh --test`
3. Upload the new zip; the store rejects a version it has already seen.
