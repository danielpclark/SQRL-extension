# Privacy Policy – SQRL Login browser extension

**Summary: the extension collects no data and sends nothing to its author or to any third
party.**

## What the extension stores

* Your SQRL identities, encrypted with your password in the S4 format defined by GRC, in
  the browser's local extension storage (`storage.local`). They never leave your browser
  unless you export them yourself.
* Your preferences (default identity, dialog options) in the same local storage.
* While a QuickPass is active, a re-encrypted copy of the password-derived key in the
  browser's session storage (`storage.session`), which lives in memory only and is cleared
  on browser exit, idle timeout, system lock, or one wrong QuickPass.

## What the extension sends, and to whom

When you sign in to a SQRL-enabled website, the extension sends SQRL protocol messages
**only to that website**, over HTTPS, exactly as the SQRL specification requires: a
per-site public key (different for every site, unlinkable between sites), cryptographic
signatures, and the server's own nonce echoed back. No password, email address, name or
other personal information is ever sent. The extension never contacts any other server,
has no analytics, no telemetry, no update checks of its own, and no remote code.

## Permissions

* `storage`: to keep your encrypted identities and settings.
* `alarms`, `idle`: to expire the QuickPass after your chosen idle time and on system lock.
* `activeTab` and `scripting`: when you open the toolbar popup, a small function runs in
  the current tab to look for links with the `sqrl:` scheme, so the popup can offer a
  "Log in" button for them. Nothing else on the page is read, and nothing runs on tabs you
  did not open the popup on.
* `declarativeNetRequest` with host access to `localhost` and `127.0.0.1`: to answer
  websites' probes for a local SQRL client on `localhost:25519` and to turn their
  same-device login navigation into the extension's own login page. No request to any
  other host is observed or modified.
* Per-site access, requested when you log in: before the extension POSTs the SQRL
  authentication messages to a site, the browser asks you to allow access to that one
  site. Access is only ever requested for sites you chose to sign in to.
* Optional access to all sites: the options page offers "Handle `sqrl://` link clicks
  automatically on every website". If you enable it, the browser asks for access to all
  sites and a content script that only watches for `sqrl:` links is installed. It is off by
  default and can be turned off again, which also removes the access.

## Contact

Questions: open an issue at <https://github.com/danielpclark/SQRL-extension/issues>.
