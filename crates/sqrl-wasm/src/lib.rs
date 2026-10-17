//! wasm-bindgen bindings for `sqrl-core`.
//!
//! Everything structured crosses the boundary as JSON strings (parsed with `JSON.parse` on
//! the JavaScript side) and raw bytes as `Uint8Array`. Secret material lives inside the
//! WebAssembly heap in `SqrlUnlocked` / `SqrlSession` objects and is zeroized when they are
//! freed.

use js_sys::Function;
use serde::{Deserialize, Serialize};
use sqrl_core::crypto::{aes_gcm_decrypt, aes_gcm_encrypt, enscrypt_duration, enscrypt_iterations};
use sqrl_core::identity::UnlockedIdentity;
use sqrl_core::protocol::{ClientOptions, Request, SessionState};
use sqrl_core::storage::{
    format_rescue_code, generate_rescue_code, normalize_password, normalize_rescue_code,
    IdentitySettings, S4Identity,
};
use sqrl_core::url::SqrlUrl;
use sqrl_core::util::{b64u_decode, b64u_encode, random_array, random_bytes};
use sqrl_core::{textual, Session};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

fn js_err(e: impl core::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}

fn now_ms() -> u64 {
    js_sys::Date::now() as u64
}

fn call_progress(cb: &Option<Function>, a: f64, b: f64) {
    if let Some(f) = cb {
        let _ = f.call2(&JsValue::NULL, &JsValue::from_f64(a), &JsValue::from_f64(b));
    }
}

#[derive(Serialize, Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct SettingsJson {
    option_flags: u16,
    hint_length: u8,
    pw_verify_seconds: u8,
    idle_timeout_minutes: u16,
    log_n: u8,
}

impl From<IdentitySettings> for SettingsJson {
    fn from(s: IdentitySettings) -> Self {
        Self {
            option_flags: s.option_flags,
            hint_length: s.hint_length,
            pw_verify_seconds: s.pw_verify_seconds,
            idle_timeout_minutes: s.idle_timeout_minutes,
            log_n: s.log_n,
        }
    }
}

impl From<SettingsJson> for IdentitySettings {
    fn from(s: SettingsJson) -> Self {
        let d = IdentitySettings::default();
        Self {
            option_flags: s.option_flags,
            hint_length: if s.hint_length == 0 {
                d.hint_length
            } else {
                s.hint_length
            },
            pw_verify_seconds: if s.pw_verify_seconds == 0 {
                d.pw_verify_seconds
            } else {
                s.pw_verify_seconds
            },
            idle_timeout_minutes: s.idle_timeout_minutes,
            log_n: if s.log_n == 0 { d.log_n } else { s.log_n },
        }
    }
}

fn parse_settings(json: &str) -> Result<IdentitySettings, JsValue> {
    if json.trim().is_empty() {
        return Ok(IdentitySettings::default());
    }
    let s: SettingsJson = serde_json::from_str(json).map_err(js_err)?;
    Ok(s.into())
}

/// Default identity settings as JSON.
#[wasm_bindgen(js_name = defaultSettings)]
pub fn default_settings() -> String {
    serde_json::to_string(&SettingsJson::from(IdentitySettings::default())).unwrap()
}

/// Cryptographically random bytes.
#[wasm_bindgen(js_name = randomBytes)]
pub fn random_bytes_js(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    random_bytes(&mut v);
    v
}

/// Generate a 24-digit rescue code.
#[wasm_bindgen(js_name = generateRescueCode)]
pub fn generate_rescue_code_js() -> String {
    generate_rescue_code()
}

/// `1234-5678-...` formatting.
#[wasm_bindgen(js_name = formatRescueCode)]
pub fn format_rescue_code_js(code: &str) -> Result<String, JsValue> {
    Ok(format_rescue_code(
        &normalize_rescue_code(code).map_err(js_err)?,
    ))
}

/// base64url encode.
#[wasm_bindgen(js_name = base64urlEncode)]
pub fn b64u_encode_js(data: &[u8]) -> String {
    b64u_encode(data)
}

/// base64url decode.
#[wasm_bindgen(js_name = base64urlDecode)]
pub fn b64u_decode_js(text: &str) -> Result<Vec<u8>, JsValue> {
    b64u_decode(text).map_err(js_err)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UrlJson {
    original: String,
    scheme: String,
    host: String,
    authority: String,
    path: String,
    nut: Option<String>,
    site_key: String,
    post_url: String,
    cancel_url: Option<String>,
    insecure: bool,
}

/// Parse a `sqrl://` URL into its parts (JSON).
#[wasm_bindgen(js_name = parseSqrlUrl)]
pub fn parse_sqrl_url(url: &str) -> Result<String, JsValue> {
    let u = SqrlUrl::parse(url).map_err(js_err)?;
    let j = UrlJson {
        original: u.original.clone(),
        scheme: u.scheme.clone(),
        host: u.host.clone(),
        authority: u.authority.clone(),
        path: u.path.clone(),
        nut: u.nut.clone(),
        site_key: u.site_key.clone(),
        post_url: u.post_url(),
        cancel_url: u.cancel_url.clone(),
        insecure: u.scheme == "qrl",
    };
    Ok(serde_json::to_string(&j).unwrap())
}

/// An S4 identity file.
#[wasm_bindgen]
pub struct SqrlIdentityFile {
    inner: S4Identity,
}

#[wasm_bindgen]
impl SqrlIdentityFile {
    /// Parse binary (`sqrldata`) or textual (`SQRLDATA...`) identity data.
    #[wasm_bindgen]
    pub fn parse(data: &[u8]) -> Result<SqrlIdentityFile, JsValue> {
        Ok(Self {
            inner: S4Identity::parse(data).map_err(js_err)?,
        })
    }

    /// Parse a textual `SQRLDATA...` string.
    #[wasm_bindgen(js_name = parseText)]
    pub fn parse_text(text: &str) -> Result<SqrlIdentityFile, JsValue> {
        Ok(Self {
            inner: S4Identity::parse(text.as_bytes()).map_err(js_err)?,
        })
    }

    /// Parse a base56 textual identity (rescue blocks only).
    #[wasm_bindgen(js_name = parseTextual)]
    pub fn parse_textual(text: &str) -> Result<SqrlIdentityFile, JsValue> {
        let bytes = textual::decode(text).map_err(js_err)?;
        Ok(Self {
            inner: S4Identity::parse_blocks(&bytes).map_err(js_err)?,
        })
    }

    /// Binary file bytes.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }

    /// `SQRLDATA...` text.
    #[wasm_bindgen(js_name = toText)]
    pub fn to_text(&self) -> String {
        self.inner.to_text()
    }

    /// `SQRLDATA...` text containing only the rescue blocks.
    #[wasm_bindgen(js_name = rescueOnlyText)]
    pub fn rescue_only_text(&self) -> String {
        self.inner.rescue_only().to_text()
    }

    /// Binary rescue-only file bytes.
    #[wasm_bindgen(js_name = rescueOnlyBytes)]
    pub fn rescue_only_bytes(&self) -> Vec<u8> {
        self.inner.rescue_only().to_bytes()
    }

    /// Base56 textual identity (rescue blocks), formatted for display.
    #[wasm_bindgen(js_name = toTextual)]
    pub fn to_textual(&self) -> Result<String, JsValue> {
        let bytes = self.inner.rescue_blocks_to_bytes();
        if bytes.is_empty() {
            return Err(js_err("identity has no rescue block to export"));
        }
        Ok(textual::format_for_display(&textual::encode(&bytes)))
    }

    /// Whether a password (type 1) block is present.
    #[wasm_bindgen(js_name = hasPasswordBlock)]
    pub fn has_password_block(&self) -> bool {
        self.inner.type1.is_some()
    }

    /// Whether a rescue (type 2) block is present.
    #[wasm_bindgen(js_name = hasRescueBlock)]
    pub fn has_rescue_block(&self) -> bool {
        self.inner.type2.is_some()
    }

    /// Number of previous identities stored.
    #[wasm_bindgen(js_name = previousCount)]
    pub fn previous_count(&self) -> usize {
        self.inner
            .type3
            .as_ref()
            .map(|t| t.enc_keys.len())
            .unwrap_or(0)
    }

    /// Edition (re-key counter), 0 if never re-keyed.
    #[wasm_bindgen]
    pub fn edition(&self) -> u16 {
        self.inner.edition()
    }

    /// Settings JSON.
    #[wasm_bindgen]
    pub fn settings(&self) -> String {
        serde_json::to_string(&SettingsJson::from(self.inner.settings())).unwrap()
    }

    /// EnScrypt iteration count of the password block.
    #[wasm_bindgen(js_name = passwordIterations)]
    pub fn password_iterations(&self) -> u32 {
        self.inner.type1.as_ref().map(|t| t.iterations).unwrap_or(0)
    }

    /// Derive the password key (slow). `progress(done, total)`.
    #[wasm_bindgen(js_name = deriveKey)]
    pub fn derive_key(
        &self,
        password: &str,
        progress: Option<Function>,
    ) -> Result<Vec<u8>, JsValue> {
        let total = self.password_iterations() as f64;
        let key = self
            .inner
            .derive_password_key(password, |done| {
                call_progress(&progress, done as f64, total)
            })
            .map_err(js_err)?;
        Ok(key.to_vec())
    }

    /// Unlock with a previously derived key.
    #[wasm_bindgen(js_name = unlockWithKey)]
    pub fn unlock_with_key(&self, key: &[u8]) -> Result<SqrlUnlocked, JsValue> {
        let mut k: [u8; 32] = key.try_into().map_err(|_| js_err("key must be 32 bytes"))?;
        let r = self.inner.unlock_with_key(&k).map_err(js_err);
        k.zeroize();
        Ok(SqrlUnlocked { inner: r? })
    }

    /// Unlock with the password (slow).
    #[wasm_bindgen]
    pub fn unlock(
        &self,
        password: &str,
        progress: Option<Function>,
    ) -> Result<SqrlUnlocked, JsValue> {
        let total = self.password_iterations() as f64;
        let id = self
            .inner
            .unlock(password, |done| {
                call_progress(&progress, done as f64, total)
            })
            .map_err(js_err)?;
        Ok(SqrlUnlocked { inner: id })
    }

    /// Decrypt the IUK with the rescue code (slow).
    #[wasm_bindgen(js_name = unlockIuk)]
    pub fn unlock_iuk(
        &self,
        rescue_code: &str,
        progress: Option<Function>,
    ) -> Result<Vec<u8>, JsValue> {
        let total = self.inner.type2.as_ref().map(|t| t.iterations).unwrap_or(0) as f64;
        let iuk = self
            .inner
            .unlock_iuk(rescue_code, |done| {
                call_progress(&progress, done as f64, total)
            })
            .map_err(js_err)?;
        Ok(iuk.to_vec())
    }

    /// Create a brand-new identity. `progress(stage, elapsedMs, totalMs)`.
    #[wasm_bindgen]
    pub fn create(
        password: &str,
        rescue_code: &str,
        settings_json: &str,
        rescue_duration_ms: u32,
        progress: Option<Function>,
    ) -> Result<SqrlIdentityFile, JsValue> {
        let settings = parse_settings(settings_json)?;
        let mut iuk: [u8; 32] = random_array();
        let r = S4Identity::create(
            &iuk,
            password,
            rescue_code,
            settings,
            rescue_duration_ms as u64,
            now_ms,
            |stage, a, b| {
                if let Some(f) = &progress {
                    let _ = f.call3(
                        &JsValue::NULL,
                        &JsValue::from_str(stage),
                        &JsValue::from_f64(a as f64),
                        &JsValue::from_f64(b as f64),
                    );
                }
            },
        );
        iuk.zeroize();
        Ok(Self {
            inner: r.map_err(js_err)?,
        })
    }

    /// Re-encrypt under a new password and/or new settings. `progress(elapsedMs, totalMs)`.
    #[wasm_bindgen(js_name = setPassword)]
    pub fn set_password(
        &mut self,
        unlocked: &SqrlUnlocked,
        password: &str,
        settings_json: &str,
        progress: Option<Function>,
    ) -> Result<(), JsValue> {
        let settings = parse_settings(settings_json)?;
        self.inner
            .set_password(&unlocked.inner, password, settings, now_ms, |a, b| {
                call_progress(&progress, a as f64, b as f64)
            });
        Ok(())
    }

    /// Re-key: a new IUK is generated; the old one (recovered with the old rescue code) becomes
    /// a previous identity. Returns the new unlocked identity.
    #[wasm_bindgen]
    #[allow(clippy::too_many_arguments)]
    pub fn rekey(
        &mut self,
        unlocked: &SqrlUnlocked,
        old_iuk: &[u8],
        new_password: &str,
        new_rescue_code: &str,
        settings_json: &str,
        rescue_duration_ms: u32,
        progress: Option<Function>,
    ) -> Result<SqrlUnlocked, JsValue> {
        let settings = parse_settings(settings_json)?;
        let old: [u8; 32] = old_iuk
            .try_into()
            .map_err(|_| js_err("iuk must be 32 bytes"))?;
        let mut new_iuk: [u8; 32] = random_array();
        let r = self.inner.rekey(
            &unlocked.inner,
            &old,
            &new_iuk,
            new_password,
            new_rescue_code,
            settings,
            rescue_duration_ms as u64,
            now_ms,
            |stage, a, b| {
                if let Some(f) = &progress {
                    let _ = f.call3(
                        &JsValue::NULL,
                        &JsValue::from_str(stage),
                        &JsValue::from_f64(a as f64),
                        &JsValue::from_f64(b as f64),
                    );
                }
            },
        );
        new_iuk.zeroize();
        Ok(SqrlUnlocked {
            inner: r.map_err(js_err)?,
        })
    }

    /// Build an identity file from an IUK (e.g. after importing a rescue-only identity), with
    /// a fresh password block and the given previous IUKs.
    #[wasm_bindgen(js_name = fromUnlocked)]
    pub fn from_unlocked(
        unlocked: &SqrlUnlocked,
        rescue_block_source: &SqrlIdentityFile,
        password: &str,
        settings_json: &str,
        progress: Option<Function>,
    ) -> Result<SqrlIdentityFile, JsValue> {
        let settings = parse_settings(settings_json)?;
        let mut inner = rescue_block_source.inner.rescue_only();
        inner.set_password(&unlocked.inner, password, settings, now_ms, |a, b| {
            call_progress(&progress, a as f64, b as f64)
        });
        Ok(Self { inner })
    }
}

/// A decrypted identity (IMK, ILK, previous IUKs) held in WebAssembly memory.
#[wasm_bindgen]
pub struct SqrlUnlocked {
    inner: UnlockedIdentity,
}

#[wasm_bindgen]
impl SqrlUnlocked {
    /// Build directly from an IUK (used when importing a rescue-only identity).
    #[wasm_bindgen(js_name = fromIuk)]
    pub fn from_iuk(iuk: &[u8]) -> Result<SqrlUnlocked, JsValue> {
        let mut k: [u8; 32] = iuk.try_into().map_err(|_| js_err("iuk must be 32 bytes"))?;
        let id = UnlockedIdentity::from_iuk(&k);
        k.zeroize();
        Ok(Self { inner: id })
    }

    /// Attach the previous IUKs decrypted from a type 3 block of `file` (needs the IMK, so
    /// this only works when `self` is the identity that encrypted them).
    #[wasm_bindgen(js_name = loadPreviousFrom)]
    pub fn load_previous_from(&mut self, file: &SqrlIdentityFile) -> Result<usize, JsValue> {
        if let Some(t3) = &file.inner.type3 {
            self.inner.previous_iuks = t3.decrypt(&self.inner.imk).map_err(js_err)?;
        }
        Ok(self.inner.previous_iuks.len())
    }

    /// Number of previous identities.
    #[wasm_bindgen(js_name = previousCount)]
    pub fn previous_count(&self) -> usize {
        self.inner.previous_count()
    }

    /// Per-site public key (base64url) for a site key string.
    #[wasm_bindgen(js_name = sitePublicKey)]
    pub fn site_public_key(&self, site_key: &str) -> String {
        b64u_encode(&self.inner.site_public_key(site_key.as_bytes()))
    }

    /// A fingerprint of the identity: the per-site public key for a fixed pseudo-site, hex
    /// truncated. Safe to show in the UI to tell identities apart.
    #[wasm_bindgen]
    pub fn fingerprint(&self) -> String {
        let pk = self.inner.site_public_key(b"sqrl-extension.fingerprint");
        sqrl_core::util::hex_encode(&pk[..8])
    }

    /// Verify that `iuk` is this identity's IUK (used before a re-key).
    #[wasm_bindgen(js_name = matchesIuk)]
    pub fn matches_iuk(&self, iuk: &[u8]) -> bool {
        match <[u8; 32]>::try_from(iuk) {
            Ok(k) => sqrl_core::identity::imk_from_iuk(&k) == self.inner.imk,
            Err(_) => false,
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct OptionsJson {
    sqrlonly: bool,
    hardlock: bool,
    cps: bool,
    suk: bool,
    noiptest: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestJson {
    url: String,
    body: String,
    command: String,
    client_text: String,
}

fn request_json(r: Request) -> String {
    serde_json::to_string(&RequestJson {
        url: r.url,
        body: r.body,
        command: r.command.as_str().into(),
        client_text: r.client_text,
    })
    .unwrap()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AskJson {
    message: String,
    buttons: Vec<AskButtonJson>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AskButtonJson {
    label: String,
    url: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StateJson {
    state: String,
    disabled: bool,
    message: Option<String>,
    tif: u32,
    tif_hex: String,
    id_match: bool,
    previous_id_match: bool,
    ips_matched: bool,
    sqrl_disabled: bool,
    has_suk: bool,
    sin: Option<String>,
    ask: Option<AskJson>,
    cps_url: Option<String>,
    cps_url_error: Option<String>,
    cancel_url: Option<String>,
    nut: Option<String>,
    previous_index: usize,
    has_more_previous: bool,
    ip_check_failed: bool,
    last_command: Option<String>,
}

/// One SQRL transaction.
#[wasm_bindgen]
pub struct SqrlSession {
    inner: Session,
}

#[wasm_bindgen]
impl SqrlSession {
    /// Start a session for `unlocked` against `url` with `options` (JSON: sqrlonly, hardlock,
    /// cps, suk, noiptest) and an optional Alt-ID.
    #[wasm_bindgen(constructor)]
    pub fn new(
        unlocked: &SqrlUnlocked,
        url: &str,
        options_json: &str,
        alt_id: Option<String>,
    ) -> Result<SqrlSession, JsValue> {
        let u = SqrlUrl::parse(url).map_err(js_err)?;
        let o: OptionsJson = if options_json.trim().is_empty() {
            OptionsJson::default()
        } else {
            serde_json::from_str(options_json).map_err(js_err)?
        };
        let options = ClientOptions {
            sqrlonly: o.sqrlonly,
            hardlock: o.hardlock,
            cps: o.cps,
            suk: o.suk,
            noiptest: o.noiptest,
        };
        let alt = alt_id.as_deref().map(str::trim).filter(|s| !s.is_empty());
        Ok(Self {
            inner: Session::new(unlocked.inner.clone(), u, options, alt),
        })
    }

    /// Site key string in use.
    #[wasm_bindgen(js_name = siteKey)]
    pub fn site_key(&self) -> String {
        self.inner.url().site_key.clone()
    }

    /// Host of the site.
    #[wasm_bindgen]
    pub fn host(&self) -> String {
        self.inner.url().host.clone()
    }

    /// Per-site public key (base64url).
    #[wasm_bindgen]
    pub fn idk(&self) -> String {
        b64u_encode(&self.inner.idk())
    }

    /// Whether the identity has previous identities.
    #[wasm_bindgen(js_name = hasPrevious)]
    pub fn has_previous(&self) -> bool {
        self.inner.has_previous()
    }

    /// Offer the next older previous identity on the next query.
    #[wasm_bindgen(js_name = tryNextPrevious)]
    pub fn try_next_previous(&mut self) -> bool {
        self.inner.try_next_previous()
    }

    /// Record the user's `ask` answer (0 = OK, 1/2 = first/second button).
    #[wasm_bindgen(js_name = setButton)]
    pub fn set_button(&mut self, btn: u8) {
        self.inner.set_button(btn);
    }

    /// Same-origin URL attached to an ask button, if any.
    #[wasm_bindgen(js_name = askButtonUrl)]
    pub fn ask_button_url(&self, index: usize) -> Option<String> {
        self.inner.ask_button_url(index)
    }

    /// The command of the most recently built request (`query`, `ident`, ...).
    #[wasm_bindgen(js_name = lastCommand)]
    pub fn last_command(&self) -> Option<String> {
        self.inner.last_command().map(|c| c.as_str().to_string())
    }

    /// Build a `query` (JSON request).
    #[wasm_bindgen]
    pub fn query(&mut self) -> Result<String, JsValue> {
        self.inner.query().map(request_json).map_err(js_err)
    }

    /// Build an `ident`.
    #[wasm_bindgen]
    pub fn ident(&mut self) -> Result<String, JsValue> {
        self.inner.ident().map(request_json).map_err(js_err)
    }

    /// Build a `disable`.
    #[wasm_bindgen]
    pub fn disable(&mut self) -> Result<String, JsValue> {
        self.inner.disable().map(request_json).map_err(js_err)
    }

    /// Build an `enable` (IUK needed unless a previous identity matched).
    #[wasm_bindgen]
    pub fn enable(&mut self, iuk: Option<Vec<u8>>) -> Result<String, JsValue> {
        let k = iuk_arg(iuk)?;
        self.inner
            .enable(k.as_ref())
            .map(request_json)
            .map_err(js_err)
    }

    /// Build a `remove` (IUK needed unless a previous identity matched).
    #[wasm_bindgen]
    pub fn remove(&mut self, iuk: Option<Vec<u8>>) -> Result<String, JsValue> {
        let k = iuk_arg(iuk)?;
        self.inner
            .remove(k.as_ref())
            .map(request_json)
            .map_err(js_err)
    }

    /// Feed the server's response body; returns the state JSON.
    #[wasm_bindgen]
    pub fn feed(&mut self, body: &str) -> Result<String, JsValue> {
        self.inner.feed(body).map_err(js_err)?;
        Ok(self.state())
    }

    /// Current state as JSON.
    #[wasm_bindgen]
    pub fn state(&self) -> String {
        let (state, disabled, message) = match self.inner.state() {
            SessionState::NoResponse => ("noResponse", false, None),
            SessionState::Unknown => ("unknown", false, None),
            SessionState::Known { disabled } => ("known", disabled, None),
            SessionState::PreviousKnown { disabled } => ("previousKnown", disabled, None),
            SessionState::Transient => ("transient", false, None),
            SessionState::Superseded => ("superseded", false, None),
            SessionState::Failed(m) => ("failed", false, Some(m)),
        };
        let last = self.inner.last_response();
        let tif = last.map(|r| r.tif).unwrap_or_default();
        let (cps_url, cps_url_error) = match self.inner.cps_url() {
            Ok(u) => (u, None),
            Err(e) => (None, Some(e.to_string())),
        };
        let j = StateJson {
            state: state.into(),
            disabled,
            message,
            tif: tif.0,
            tif_hex: tif.to_hex(),
            id_match: tif.id_match(),
            previous_id_match: tif.previous_id_match(),
            ips_matched: tif.ips_matched(),
            sqrl_disabled: tif.sqrl_disabled(),
            has_suk: last.map(|r| r.suk.is_some()).unwrap_or(false),
            sin: last.and_then(|r| r.sin.clone()),
            ask: self.inner.pending_ask().map(|a| AskJson {
                message: a.message.clone(),
                buttons: a
                    .buttons
                    .iter()
                    .map(|b| AskButtonJson {
                        label: b.label.clone(),
                        url: b.url.clone(),
                    })
                    .collect(),
            }),
            cps_url,
            cps_url_error,
            cancel_url: self.inner.cancel_url(),
            nut: last.map(|r| r.nut.clone()),
            previous_index: self.inner.previous_index(),
            has_more_previous: self.inner.previous_index() + 1 < self.inner.previous_count(),
            ip_check_failed: self.inner.ip_check_failed(),
            last_command: self.inner.last_command().map(|c| c.as_str().to_string()),
        };
        serde_json::to_string(&j).unwrap()
    }
}

fn iuk_arg(iuk: Option<Vec<u8>>) -> Result<Option<[u8; 32]>, JsValue> {
    match iuk {
        None => Ok(None),
        Some(v) => Ok(Some(
            v.as_slice()
                .try_into()
                .map_err(|_| js_err("iuk must be 32 bytes"))?,
        )),
    }
}

/// QuickPass: seal a 32-byte password-derived key under the password's first characters.
/// Returns `iterations(4) || salt(16) || iv(12) || ciphertext(32) || tag(16)`.
#[wasm_bindgen(js_name = quickpassSeal)]
pub fn quickpass_seal(
    key: &[u8],
    hint: &str,
    log_n: u8,
    duration_ms: u32,
) -> Result<Vec<u8>, JsValue> {
    if key.len() != 32 {
        return Err(js_err("key must be 32 bytes"));
    }
    let salt: [u8; 16] = random_array();
    let iv: [u8; 12] = random_array();
    let mut hint = normalize_password(hint);
    let (mut qk, iterations) = enscrypt_duration(
        hint.as_bytes(),
        &salt,
        log_n,
        duration_ms.max(1) as u64,
        now_ms,
        |_, _| {},
    );
    hint.zeroize();
    let ct = aes_gcm_encrypt(&qk, &iv, b"", key);
    qk.zeroize();
    let mut out = Vec::with_capacity(80);
    out.extend_from_slice(&iterations.to_le_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// QuickPass: recover the password-derived key. Fails if the hint is wrong.
#[wasm_bindgen(js_name = quickpassOpen)]
pub fn quickpass_open(blob: &[u8], hint: &str, log_n: u8) -> Result<Vec<u8>, JsValue> {
    if blob.len() != 80 {
        return Err(js_err("invalid quickpass blob"));
    }
    let iterations = u32::from_le_bytes(blob[0..4].try_into().unwrap());
    let salt = &blob[4..20];
    let iv: [u8; 12] = blob[20..32].try_into().unwrap();
    let mut hint = normalize_password(hint);
    let mut qk = enscrypt_iterations(hint.as_bytes(), salt, log_n, iterations, |_| {});
    hint.zeroize();
    let r = aes_gcm_decrypt(&qk, &iv, b"", &blob[32..]).map_err(|_| js_err("incorrect QuickPass"));
    qk.zeroize();
    r
}
