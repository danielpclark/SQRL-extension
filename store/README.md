# Store submission kit

| File | Use |
| --- | --- |
| `chrome-web-store.md` | Everything to paste into the Chrome Web Store developer console (listing text, permission justifications, privacy answers). |
| `firefox-amo.md` | The same for addons.mozilla.org, including the compiled-code / source-upload answers. |
| `REVIEWER-NOTES.md` | Build-reproduction notes for AMO reviewers; paste into "notes to reviewer" and ship with the source archive. |
| `screenshots/` | 1280×800 listing screenshots (rendered from the extension pages with sample data). |
| `promo-small-440x280.png`, `marquee-1400x560.png` | Chrome Web Store promo tiles. |
| `../PRIVACY.md` | Privacy policy to host and link from both listings. |
| `../extension/icons/icon128.png`, `icon512.png` | Listing icons. |

Packages come from `./build.sh`: `dist/sqrl-login-chrome-v<version>.zip` and
`dist/sqrl-login-firefox-v<version>.zip`. A GitHub release created by tagging `v<version>`
carries both plus the source archive.
