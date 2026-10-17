//! The SQRL client ⇄ server wire protocol.
//!
//! A transaction is a sequence of HTTPS POSTs. Every POST body is
//! `client=<b64u>&server=<b64u>&ids=<b64u>[&pids=<b64u>][&urs=<b64u>]` where
//!
//! * `client` is a CRLF-separated list of `name=value` pairs (`ver`, `cmd`, `idk`, ...),
//! * `server` is, for the first request, the complete `sqrl://` URL as received, and for
//!   every following request the server's previous response *verbatim*,
//! * `ids` is the Ed25519 signature (per-site identity key) over the concatenation of the
//!   `client` and `server` base64url strings; `pids` the same with a previous identity key;
//!   `urs` the same with the Unlock Request Signing Key.
//!
//! The server answers with a base64url-encoded CRLF list containing at least `ver`, `nut`,
//! `tif` (hex transaction information flags) and `qry` (the path to POST the next request to).
//!
//! [`Session`] drives one complete transaction for one identity against one URL.

use crate::crypto::ed25519_sign;
use crate::identity::{
    indexed_secret, make_server_lock, unlock_request_seed, ServerLock, UnlockedIdentity,
};
use crate::url::SqrlUrl;
use crate::util::{b64u_decode, b64u_decode_array, b64u_encode};
use crate::{Error, Result};
use zeroize::Zeroize;

/// Protocol version this client speaks.
pub const PROTOCOL_VERSION: u32 = 1;

/// Transaction Information Flags returned by the server.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tif(pub u32);

impl Tif {
    /// The current identity (`idk`) is known to the server.
    pub const ID_MATCH: u32 = 0x01;
    /// The previous identity (`pidk`) is known to the server.
    pub const PREVIOUS_ID_MATCH: u32 = 0x02;
    /// The IP of this request matches the IP that requested the nut.
    pub const IPS_MATCHED: u32 = 0x04;
    /// The account has SQRL authentication disabled.
    pub const SQRL_DISABLED: u32 = 0x08;
    /// The server does not support the requested command / function.
    pub const FUNCTION_NOT_SUPPORTED: u32 = 0x10;
    /// Transient error (e.g. stale nut): the client may retry with the new nut.
    pub const TRANSIENT_ERROR: u32 = 0x20;
    /// The command could not be executed.
    pub const COMMAND_FAILED: u32 = 0x40;
    /// The request was malformed or failed verification.
    pub const CLIENT_FAILURE: u32 = 0x80;
    /// The identity does not match the one that started this transaction.
    pub const BAD_ID_ASSOCIATION: u32 = 0x100;
    /// The identity has been superseded by a newer (re-keyed) identity.
    pub const IDENTITY_SUPERSEDED: u32 = 0x200;
    /// Every bit defined by protocol version 1. "All SQRL clients MUST immediately terminate
    /// any connection and abort any authentication operation with any SQRL server which
    /// includes TIF bits not defined" (On The Wire §tif).
    pub const DEFINED_BITS: u32 = 0x3FF;

    /// Parse the hexadecimal `tif=` value.
    pub fn parse(hex: &str) -> Result<Self> {
        u32::from_str_radix(hex.trim(), 16)
            .map(Tif)
            .map_err(|_| Error::Format(format!("invalid tif '{hex}'")))
    }

    /// Whether only version-1 bits are set.
    pub fn is_defined(self) -> bool {
        self.0 & !Self::DEFINED_BITS == 0
    }

    /// Test a flag.
    pub fn has(self, flag: u32) -> bool {
        self.0 & flag != 0
    }
    /// `ID_MATCH`
    pub fn id_match(self) -> bool {
        self.has(Self::ID_MATCH)
    }
    /// `PREVIOUS_ID_MATCH`
    pub fn previous_id_match(self) -> bool {
        self.has(Self::PREVIOUS_ID_MATCH)
    }
    /// `IPS_MATCHED`
    pub fn ips_matched(self) -> bool {
        self.has(Self::IPS_MATCHED)
    }
    /// `SQRL_DISABLED`
    pub fn sqrl_disabled(self) -> bool {
        self.has(Self::SQRL_DISABLED)
    }
    /// `TRANSIENT_ERROR`
    pub fn transient_error(self) -> bool {
        self.has(Self::TRANSIENT_ERROR)
    }
    /// `COMMAND_FAILED`
    pub fn command_failed(self) -> bool {
        self.has(Self::COMMAND_FAILED)
    }
    /// `CLIENT_FAILURE`
    pub fn client_failure(self) -> bool {
        self.has(Self::CLIENT_FAILURE)
    }
    /// `BAD_ID_ASSOCIATION`
    pub fn bad_id_association(self) -> bool {
        self.has(Self::BAD_ID_ASSOCIATION)
    }
    /// `IDENTITY_SUPERSEDED`
    pub fn identity_superseded(self) -> bool {
        self.has(Self::IDENTITY_SUPERSEDED)
    }
    /// `FUNCTION_NOT_SUPPORTED`
    pub fn function_not_supported(self) -> bool {
        self.has(Self::FUNCTION_NOT_SUPPORTED)
    }
    /// Any of the error flags.
    pub fn is_error(self) -> bool {
        self.has(
            Self::FUNCTION_NOT_SUPPORTED
                | Self::TRANSIENT_ERROR
                | Self::COMMAND_FAILED
                | Self::CLIENT_FAILURE
                | Self::BAD_ID_ASSOCIATION
                | Self::IDENTITY_SUPERSEDED,
        )
    }
    /// Lower-case hex as sent on the wire.
    pub fn to_hex(self) -> String {
        format!("{:x}", self.0)
    }
}

/// Client commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    /// Ask the server whether it knows this identity.
    Query,
    /// Authenticate (log in / create account / re-key).
    Ident,
    /// Disable SQRL authentication for the account.
    Disable,
    /// Re-enable SQRL authentication (requires `urs`).
    Enable,
    /// Remove the SQRL association from the account (requires `urs`).
    Remove,
}

impl Command {
    /// The wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Command::Query => "query",
            Command::Ident => "ident",
            Command::Disable => "disable",
            Command::Enable => "enable",
            Command::Remove => "remove",
        }
    }

    /// Parse the wire name.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "query" => Some(Command::Query),
            "ident" => Some(Command::Ident),
            "disable" => Some(Command::Disable),
            "enable" => Some(Command::Enable),
            "remove" => Some(Command::Remove),
            _ => None,
        }
    }
}

/// Client `opt=` flags.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClientOptions {
    /// Request that the site disable all non-SQRL authentication.
    pub sqrlonly: bool,
    /// Request that the site disable all non-SQRL account recovery.
    pub hardlock: bool,
    /// The client can perform Client Provided Session redirection (`url=` expected).
    pub cps: bool,
    /// Ask the server to return the account's SUK (needed before enable/remove).
    pub suk: bool,
    /// Do not require the request IP to match the nut's IP.
    pub noiptest: bool,
}

impl ClientOptions {
    /// Render the `opt=` value (`~` separated), or `None` when no option is set.
    pub fn to_wire(self) -> Option<String> {
        let mut v = Vec::new();
        if self.sqrlonly {
            v.push("sqrlonly");
        }
        if self.hardlock {
            v.push("hardlock");
        }
        if self.cps {
            v.push("cps");
        }
        if self.suk {
            v.push("suk");
        }
        if self.noiptest {
            v.push("noiptest");
        }
        if v.is_empty() {
            None
        } else {
            Some(v.join("~"))
        }
    }

    /// Parse an `opt=` value.
    pub fn from_wire(s: &str) -> Self {
        let mut o = Self::default();
        for part in s.split('~') {
            match part.trim() {
                "sqrlonly" => o.sqrlonly = true,
                "hardlock" => o.hardlock = true,
                "cps" => o.cps = true,
                "suk" => o.suk = true,
                "noiptest" => o.noiptest = true,
                _ => {}
            }
        }
        o
    }
}

/// One button of a server `ask=`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AskButton {
    /// Button caption.
    pub label: String,
    /// Optional URL the server attached to the button (informational).
    pub url: Option<String>,
}

/// A server question (`ask=<msg>~<button1>[;url]~<button2>[;url]`, each part base64url).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ask {
    /// The question text.
    pub message: String,
    /// Zero, one or two buttons. A client shows "OK" when there are none.
    pub buttons: Vec<AskButton>,
}

impl Ask {
    /// Parse the wire form.
    pub fn parse(value: &str) -> Result<Self> {
        let mut parts = value.split('~');
        let message = decode_text(parts.next().unwrap_or(""))?;
        let mut buttons = Vec::new();
        for p in parts.take(2) {
            let (label_b64, url) = match p.split_once(';') {
                Some((l, u)) => (l, Some(u.to_string())),
                None => (p, None),
            };
            buttons.push(AskButton {
                label: decode_text(label_b64)?,
                url,
            });
        }
        Ok(Self { message, buttons })
    }

    /// Render the wire form.
    pub fn to_wire(&self) -> String {
        let mut s = b64u_encode(self.message.as_bytes());
        for b in &self.buttons {
            s.push('~');
            s.push_str(&b64u_encode(b.label.as_bytes()));
            if let Some(u) = &b.url {
                s.push(';');
                s.push_str(u);
            }
        }
        s
    }
}

fn decode_text(b64: &str) -> Result<String> {
    String::from_utf8(b64u_decode(b64)?).map_err(|_| Error::Format("ask text is not UTF-8".into()))
}

/// Parse a CRLF-separated `name=value` list (LF-only input is tolerated).
pub fn parse_pairs(text: &str) -> Vec<(String, String)> {
    text.split("\r\n")
        .flat_map(|l| l.split('\n'))
        .filter(|l| !l.trim().is_empty())
        .map(|l| match l.split_once('=') {
            Some((k, v)) => (k.trim().to_string(), v.trim_end_matches('\r').to_string()),
            None => (l.trim().to_string(), String::new()),
        })
        .collect()
}

/// Whether a `ver=` value (e.g. `1`, `1,2`, `1-3,5`) includes a given version.
pub fn version_supported(ver: &str, wanted: u32) -> bool {
    ver.split(',').any(|part| {
        let part = part.trim();
        match part.split_once('-') {
            Some((a, b)) => match (a.trim().parse::<u32>(), b.trim().parse::<u32>()) {
                (Ok(a), Ok(b)) => a <= wanted && wanted <= b,
                _ => false,
            },
            None => part.parse::<u32>().map(|v| v == wanted).unwrap_or(false),
        }
    })
}

/// A parsed server response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerResponse {
    /// The response exactly as received (whitespace trimmed): what the next request's
    /// `server=` parameter carries.
    pub raw: String,
    /// All `name=value` pairs in order.
    pub params: Vec<(String, String)>,
    /// `ver=`
    pub ver: String,
    /// `nut=`
    pub nut: String,
    /// `tif=`
    pub tif: Tif,
    /// `qry=`
    pub qry: String,
    /// `url=` (CPS success URL)
    pub url: Option<String>,
    /// `sin=` (secret index challenge)
    pub sin: Option<String>,
    /// `suk=` (server unlock key)
    pub suk: Option<[u8; 32]>,
    /// `ask=`
    pub ask: Option<Ask>,
    /// `can=` (cancel URL)
    pub can: Option<String>,
}

impl ServerResponse {
    /// Parse a base64url response body.
    pub fn parse(body: &str) -> Result<Self> {
        let raw: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        if raw.is_empty() {
            return Err(Error::Protocol("empty server response".into()));
        }
        let decoded = String::from_utf8(b64u_decode(&raw)?)
            .map_err(|_| Error::Protocol("server response is not UTF-8".into()))?;
        let params = parse_pairs(&decoded);
        let get = |k: &str| params.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        let ver = get("ver").ok_or_else(|| Error::Protocol("response lacks ver".into()))?;
        if !version_supported(&ver, PROTOCOL_VERSION) {
            return Err(Error::Protocol(format!(
                "server speaks version {ver}, not {PROTOCOL_VERSION}"
            )));
        }
        let nut = get("nut").ok_or_else(|| Error::Protocol("response lacks nut".into()))?;
        if nut.is_empty() {
            return Err(Error::Protocol("response has an empty nut".into()));
        }
        let tif =
            Tif::parse(&get("tif").ok_or_else(|| Error::Protocol("response lacks tif".into()))?)?;
        if !tif.is_defined() {
            return Err(Error::Protocol(format!(
                "server returned undefined TIF bits ({}); aborting",
                tif.to_hex()
            )));
        }
        let qry = get("qry").ok_or_else(|| Error::Protocol("response lacks qry".into()))?;
        let suk = match get("suk") {
            Some(s) if !s.is_empty() => Some(b64u_decode_array::<32>(&s)?),
            _ => None,
        };
        let ask = match get("ask") {
            Some(a) if !a.is_empty() => Some(Ask::parse(&a)?),
            _ => None,
        };
        Ok(Self {
            raw,
            ver,
            nut,
            tif,
            qry,
            url: get("url").filter(|s| !s.is_empty()),
            sin: get("sin").filter(|s| !s.is_empty()),
            suk,
            ask,
            can: get("can").filter(|s| !s.is_empty()),
            params,
        })
    }
}

/// A request ready to be POSTed (`Content-Type: application/x-www-form-urlencoded`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// Absolute URL to POST to.
    pub url: String,
    /// Form body.
    pub body: String,
    /// The command being sent.
    pub command: Command,
    /// The decoded `client=` text (for display / debugging).
    pub client_text: String,
}

/// High-level summary of where a transaction stands, derived from the last response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// No response received yet.
    NoResponse,
    /// The server does not know this identity (nor the previous one tried).
    Unknown,
    /// The current identity is known; `disabled` tells whether SQRL login is disabled.
    Known { disabled: bool },
    /// Only a previous identity is known; an `ident` will re-key the account.
    PreviousKnown { disabled: bool },
    /// Transient error: retry with a fresh query.
    Transient,
    /// The identity has been superseded by a newer one.
    Superseded,
    /// A hard error; see the message.
    Failed(String),
}

/// Drives one SQRL transaction for one unlocked identity against one `sqrl://` URL.
pub struct Session {
    url: SqrlUrl,
    identity: UnlockedIdentity,
    site_key: Vec<u8>,
    options: ClientOptions,
    prev_index: usize,
    last: Option<ServerResponse>,
    last_command: Option<Command>,
    pending_btn: Option<u8>,
    answered_ask: bool,
    last_lock: Option<ServerLock>,
}

impl Session {
    /// Start a session. `alt_id` is the optional "Alt-ID" that selects a different identity
    /// for the same site.
    pub fn new(
        identity: UnlockedIdentity,
        url: SqrlUrl,
        options: ClientOptions,
        alt_id: Option<&str>,
    ) -> Self {
        let site_key = url.site_key_bytes(alt_id);
        Self {
            url,
            identity,
            site_key,
            options,
            prev_index: 0,
            last: None,
            last_command: None,
            pending_btn: None,
            answered_ask: false,
            last_lock: None,
        }
    }

    /// The command of the most recently built request, if any.
    pub fn last_command(&self) -> Option<Command> {
        self.last_command
    }

    /// The URL this session was started with.
    pub fn url(&self) -> &SqrlUrl {
        &self.url
    }

    /// Options in use.
    pub fn options(&self) -> ClientOptions {
        self.options
    }

    /// Change options for subsequent requests.
    pub fn set_options(&mut self, options: ClientOptions) {
        self.options = options;
    }

    /// The most recent server response.
    pub fn last_response(&self) -> Option<&ServerResponse> {
        self.last.as_ref()
    }

    /// Per-site public key (`idk`) of the current identity.
    pub fn idk(&self) -> [u8; 32] {
        self.identity.site_public_key(&self.site_key)
    }

    /// Whether the identity has any previous identities to offer as `pidk`.
    pub fn has_previous(&self) -> bool {
        self.identity.previous_count() > 0
    }

    /// Number of previous identities available.
    pub fn previous_count(&self) -> usize {
        self.identity.previous_count()
    }

    /// Index of the previous identity currently offered as `pidk`.
    pub fn previous_index(&self) -> usize {
        self.prev_index
    }

    /// Move on to the next older previous identity. Returns `false` when none remain.
    pub fn try_next_previous(&mut self) -> bool {
        if self.prev_index + 1 < self.identity.previous_count() {
            self.prev_index += 1;
            true
        } else {
            false
        }
    }

    /// Record the user's answer to the server's `ask=`: `0` for the plain "OK" (shown when the
    /// ask carries no buttons), `1` or `2` for the first or second button. Cancelling the ask
    /// means not sending any further command at all, so there is no value for it.
    pub fn set_button(&mut self, btn: u8) {
        self.pending_btn = Some(btn.min(2));
        self.answered_ask = true;
    }

    /// The server's pending question, if the last response carried one and it has not been
    /// answered yet. Per the specification an `ask=` is only honoured in the reply to a
    /// `query` whose TIF has the current-ID-match bit set; anywhere else it is ignored.
    pub fn pending_ask(&self) -> Option<&Ask> {
        if self.answered_ask || self.last_command != Some(Command::Query) {
            return None;
        }
        let r = self.last.as_ref()?;
        if !r.tif.id_match() || r.tif.command_failed() {
            return None;
        }
        r.ask.as_ref()
    }

    /// The URL bound to ask button `index` (0-based), if the server attached one. The server
    /// may only supply a root-anchored path; it is forced to start with `/` and is resolved
    /// against this site's scheme, host and port, so it can never point elsewhere.
    pub fn ask_button_url(&self, index: usize) -> Option<String> {
        let ask = self.last.as_ref()?.ask.as_ref()?;
        let raw = ask.buttons.get(index)?.url.as_deref()?.trim();
        if raw.is_empty() {
            return None;
        }
        let path = raw.trim_start_matches('/');
        Some(format!("{}/{}", self.url.origin(), path))
    }

    /// Summary of the last response.
    pub fn state(&self) -> SessionState {
        let Some(r) = &self.last else {
            return SessionState::NoResponse;
        };
        let t = r.tif;
        if t.identity_superseded() {
            return SessionState::Superseded;
        }
        if t.transient_error() {
            return SessionState::Transient;
        }
        if t.client_failure() {
            return SessionState::Failed("the server rejected the request (client failure)".into());
        }
        if t.bad_id_association() {
            return SessionState::Failed(
                "identity does not match the one that started this session".into(),
            );
        }
        if t.function_not_supported() {
            return SessionState::Failed("the server does not support that command".into());
        }
        if t.command_failed() {
            if t.0 == Tif::COMMAND_FAILED {
                return SessionState::Failed(
                    "the server refused the request, most likely because this connection's IP address differs from the one that requested the login page".into(),
                );
            }
            return SessionState::Failed("the server could not perform the command".into());
        }
        if t.id_match() {
            SessionState::Known {
                disabled: t.sqrl_disabled(),
            }
        } else if t.previous_id_match() {
            SessionState::PreviousKnown {
                disabled: t.sqrl_disabled(),
            }
        } else {
            SessionState::Unknown
        }
    }

    /// The CPS success URL from the last response, validated to point at this site.
    pub fn cps_url(&self) -> Result<Option<String>> {
        let Some(u) = self.last.as_ref().and_then(|r| r.url.clone()) else {
            return Ok(None);
        };
        let resolved = self.url.resolve(&u);
        if !self.url.is_same_host(&resolved) {
            return Err(Error::Protocol(format!(
                "CPS url '{u}' does not point at {}",
                self.url.host
            )));
        }
        Ok(Some(resolved))
    }

    /// The cancel URL: the server's most recent `can=` reply parameter (a plain URL or
    /// root-relative path) if any, else the base64url-encoded `can=` of the SQRL URL.
    pub fn cancel_url(&self) -> Option<String> {
        if let Some(c) = self.last.as_ref().and_then(|r| r.can.clone()) {
            return Some(self.url.resolve(&c));
        }
        self.url.cancel_url.clone()
    }

    fn server_param(&self) -> String {
        match &self.last {
            Some(r) => r.raw.clone(),
            None => b64u_encode(self.url.original.as_bytes()),
        }
    }

    fn post_url(&self) -> Result<String> {
        match &self.last {
            Some(r) => self.url.post_url_for_qry(&r.qry),
            None => Ok(self.url.post_url()),
        }
    }

    fn last_tif(&self) -> Tif {
        self.last.as_ref().map(|r| r.tif).unwrap_or_default()
    }

    /// Build and sign a request.
    fn build(
        &mut self,
        command: Command,
        include_pidk: bool,
        lock: Option<ServerLock>,
        urs_seed: Option<[u8; 32]>,
    ) -> Result<Request> {
        let url = self.post_url()?;
        let server = self.server_param();

        let mut client = String::new();
        client.push_str(&format!("ver={PROTOCOL_VERSION}\r\n"));
        client.push_str(&format!("cmd={}\r\n", command.as_str()));
        client.push_str(&format!("idk={}\r\n", b64u_encode(&self.idk())));
        let mut pseed: Option<[u8; 32]> = None;
        if include_pidk && self.has_previous() {
            let seed = self
                .identity
                .previous_site_seed(self.prev_index, &self.site_key)
                .ok_or_else(|| Error::Protocol("no such previous identity".into()))?;
            let pidk = crate::crypto::ed25519_public(&seed);
            client.push_str(&format!("pidk={}\r\n", b64u_encode(&pidk)));
            pseed = Some(seed);
        }
        if let Some(l) = &lock {
            client.push_str(&format!("suk={}\r\n", b64u_encode(&l.suk)));
            client.push_str(&format!("vuk={}\r\n", b64u_encode(&l.vuk)));
        }
        // The SUK is requested with every command (as GRC's reference client does) so that a
        // later enable/remove always has it. sqrlonly/hardlock only make sense while an
        // association exists, so they are never sent with `remove`.
        let mut opts = self.options;
        opts.suk = true;
        if command == Command::Remove {
            opts.sqrlonly = false;
            opts.hardlock = false;
        }
        if let Some(opt) = opts.to_wire() {
            client.push_str(&format!("opt={opt}\r\n"));
        }
        if let Some(b) = self.pending_btn.take() {
            client.push_str(&format!("btn={b}\r\n"));
        }
        if let Some(sin) = self.last.as_ref().and_then(|r| r.sin.clone()) {
            let mut seed = self.identity.site_seed(&self.site_key);
            client.push_str(&format!(
                "ins={}\r\n",
                b64u_encode(&indexed_secret(&seed, sin.as_bytes()))
            ));
            seed.zeroize();
            if let Some(ps) = &pseed {
                client.push_str(&format!(
                    "pins={}\r\n",
                    b64u_encode(&indexed_secret(ps, sin.as_bytes()))
                ));
            }
        }

        let client_b64 = b64u_encode(client.as_bytes());
        let mut msg = Vec::with_capacity(client_b64.len() + server.len());
        msg.extend_from_slice(client_b64.as_bytes());
        msg.extend_from_slice(server.as_bytes());

        let mut seed = self.identity.site_seed(&self.site_key);
        let ids = ed25519_sign(&seed, &msg);
        seed.zeroize();

        let mut body = format!(
            "client={client_b64}&server={server}&ids={}",
            b64u_encode(&ids)
        );
        if let Some(mut ps) = pseed {
            let pids = ed25519_sign(&ps, &msg);
            ps.zeroize();
            body.push_str(&format!("&pids={}", b64u_encode(&pids)));
        }
        if let Some(mut us) = urs_seed {
            let urs = ed25519_sign(&us, &msg);
            us.zeroize();
            body.push_str(&format!("&urs={}", b64u_encode(&urs)));
        }
        self.last_lock = lock;
        self.last_command = Some(command);
        Ok(Request {
            url,
            body,
            command,
            client_text: client,
        })
    }

    /// Build the initial (or a repeated) `query`, offering the current previous identity.
    pub fn query(&mut self) -> Result<Request> {
        self.build(Command::Query, true, None, None)
    }

    /// Whether the server's last answer says the account is still bound to the previous
    /// identity (and must therefore be re-keyed by the next command).
    fn needs_rekey(&self) -> bool {
        let t = self.last_tif();
        t.previous_id_match() && !t.id_match()
    }

    /// Lock material and `urs` seed for a re-key (previous identity matched).
    fn rekey_material(&self) -> Result<(ServerLock, [u8; 32])> {
        let suk = self.last.as_ref().and_then(|r| r.suk).ok_or_else(|| {
            Error::Protocol("server matched a previous identity but sent no suk".into())
        })?;
        let urs_seed = self
            .identity
            .previous_unlock_request_seed(self.prev_index, &suk)
            .ok_or_else(|| Error::Protocol("no such previous identity".into()))?;
        Ok((make_server_lock(&self.identity.ilk), urs_seed))
    }

    /// Build an `ident`: log in, create the account, or re-key it, depending on the last
    /// query's answer.
    pub fn ident(&mut self) -> Result<Request> {
        if self.last.is_none() {
            return Err(Error::Protocol("send a query before ident".into()));
        }
        let t = self.last_tif();
        if self.needs_rekey() {
            let (lock, urs) = self.rekey_material()?;
            self.build(Command::Ident, true, Some(lock), Some(urs))
        } else if !t.id_match() {
            let lock = make_server_lock(&self.identity.ilk);
            self.build(Command::Ident, false, Some(lock), None)
        } else {
            self.build(Command::Ident, false, None, None)
        }
    }

    /// Build a `disable`.
    pub fn disable(&mut self) -> Result<Request> {
        if self.last.is_none() {
            return Err(Error::Protocol("send a query before disable".into()));
        }
        if self.needs_rekey() {
            let (lock, urs) = self.rekey_material()?;
            self.build(Command::Disable, true, Some(lock), Some(urs))
        } else {
            self.build(Command::Disable, false, None, None)
        }
    }

    /// `urs` seed for `enable`/`remove`: the current IUK (from the rescue code) when the
    /// current identity matched, or the previous IUK when only a previous identity matched.
    fn unlock_material(&self, iuk: Option<&[u8; 32]>) -> Result<(Option<ServerLock>, [u8; 32])> {
        if self.needs_rekey() {
            let (lock, urs) = self.rekey_material()?;
            return Ok((Some(lock), urs));
        }
        let suk = self.last.as_ref().and_then(|r| r.suk).ok_or_else(|| {
            Error::Protocol("the server did not provide the account's suk".into())
        })?;
        let iuk = iuk
            .ok_or_else(|| Error::Protocol("this operation needs the rescue code (IUK)".into()))?;
        Ok((None, unlock_request_seed(iuk, &suk)))
    }

    /// Build an `enable`. `iuk` is required unless only a previous identity matched.
    pub fn enable(&mut self, iuk: Option<&[u8; 32]>) -> Result<Request> {
        if self.last.is_none() {
            return Err(Error::Protocol("send a query before enable".into()));
        }
        let (lock, urs) = self.unlock_material(iuk)?;
        let include_pidk = lock.is_some();
        self.build(Command::Enable, include_pidk, lock, Some(urs))
    }

    /// Build a `remove`. `iuk` is required unless only a previous identity matched.
    pub fn remove(&mut self, iuk: Option<&[u8; 32]>) -> Result<Request> {
        if self.last.is_none() {
            return Err(Error::Protocol("send a query before remove".into()));
        }
        let (lock, urs) = self.unlock_material(iuk)?;
        let include_pidk = lock.is_some();
        self.build(Command::Remove, include_pidk, lock, Some(urs))
    }

    /// Feed the body of the server's HTTP response. Validates it and makes it the basis of
    /// the next request.
    pub fn feed(&mut self, body: &str) -> Result<&ServerResponse> {
        let resp = ServerResponse::parse(body)?;
        // qry must stay on this host
        self.url.post_url_for_qry(&resp.qry)?;
        if resp.ask.is_some() {
            self.answered_ask = false;
        }
        self.last = Some(resp);
        Ok(self.last.as_ref().unwrap())
    }

    /// Whether the last reply was the "exactly 0x40" a server returns when the query IP does
    /// not match the IP that requested the SQRL URL and `noiptest` was not offered.
    pub fn ip_check_failed(&self) -> bool {
        self.last
            .as_ref()
            .map(|r| r.tif.0 == Tif::COMMAND_FAILED)
            .unwrap_or(false)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.site_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tif_parsing() {
        let t = Tif::parse("5").unwrap();
        assert!(t.id_match() && t.ips_matched() && !t.previous_id_match());
        assert_eq!(Tif(0x2c0).to_hex(), "2c0");
        assert!(Tif::parse("zz").is_err());
        assert!(Tif(Tif::COMMAND_FAILED).is_error());
        assert!(!Tif(Tif::ID_MATCH | Tif::SQRL_DISABLED).is_error());
    }

    #[test]
    fn version_ranges() {
        assert!(version_supported("1", 1));
        assert!(version_supported("1,2", 1));
        assert!(version_supported("1-3", 2));
        assert!(!version_supported("2", 1));
        assert!(!version_supported("2-4,6", 1));
        assert!(!version_supported("x", 1));
    }

    #[test]
    fn ask_roundtrip() {
        let ask = Ask {
            message: "Delete everything?".into(),
            buttons: vec![
                AskButton {
                    label: "Yes".into(),
                    url: Some("https://example.com/yes".into()),
                },
                AskButton {
                    label: "No".into(),
                    url: None,
                },
            ],
        };
        let wire = ask.to_wire();
        assert!(wire.starts_with("RGVsZXRlIGV2ZXJ5dGhpbmc_~"));
        assert_eq!(Ask::parse(&wire).unwrap(), ask);
        let simple = Ask::parse(&b64u_encode(b"Hello")).unwrap();
        assert_eq!(simple.message, "Hello");
        assert!(simple.buttons.is_empty());
    }

    #[test]
    fn options_wire() {
        let o = ClientOptions {
            sqrlonly: true,
            cps: true,
            ..Default::default()
        };
        assert_eq!(o.to_wire().as_deref(), Some("sqrlonly~cps"));
        assert_eq!(
            ClientOptions::from_wire("cps~suk~noiptest"),
            ClientOptions {
                cps: true,
                suk: true,
                noiptest: true,
                ..Default::default()
            }
        );
        assert_eq!(ClientOptions::default().to_wire(), None);
    }

    #[test]
    fn response_parsing() {
        let text = "ver=1\r\nnut=abc\r\ntif=5\r\nqry=/cli.sqrl?nut=abc\r\nsin=0\r\n";
        let r = ServerResponse::parse(&b64u_encode(text.as_bytes())).unwrap();
        assert_eq!(r.nut, "abc");
        assert_eq!(r.tif, Tif(5));
        assert_eq!(r.sin.as_deref(), Some("0"));
        assert!(r.suk.is_none());
        let bad = ServerResponse::parse(&b64u_encode(b"ver=2\r\nnut=a\r\ntif=0\r\nqry=/x\r\n"))
            .unwrap_err();
        assert!(format!("{bad}").contains("version"));
        assert!(ServerResponse::parse(&b64u_encode(b"ver=1\r\ntif=0\r\nqry=/x\r\n")).is_err());
    }

    #[test]
    fn first_query_is_well_formed() {
        let id = UnlockedIdentity::from_iuk(&[1u8; 32]);
        let url = SqrlUrl::parse("sqrl://example.com/cli.sqrl?nut=n1").unwrap();
        let mut s = Session::new(id, url, ClientOptions::default(), None);
        let req = s.query().unwrap();
        assert_eq!(req.url, "https://example.com/cli.sqrl?nut=n1");
        assert!(req.client_text.starts_with("ver=1\r\ncmd=query\r\nidk="));
        assert!(req.client_text.contains("opt=suk\r\n"));
        assert!(!req.client_text.contains("pidk="));
        let server_param = b64u_encode(b"sqrl://example.com/cli.sqrl?nut=n1");
        assert!(req.body.contains(&format!("&server={server_param}&ids=")));
        assert!(!req.body.contains("&pids="));
        // ident before a query is refused
        assert!(s.ident().is_err());
    }

    #[test]
    fn remove_never_carries_sqrlonly_or_hardlock() {
        let id = UnlockedIdentity::from_iuk(&[1u8; 32]);
        let url = SqrlUrl::parse("sqrl://example.com/cli.sqrl?nut=n1").unwrap();
        let mut s = Session::new(
            id,
            url,
            ClientOptions {
                sqrlonly: true,
                hardlock: true,
                cps: true,
                ..Default::default()
            },
            None,
        );
        let q = s.query().unwrap();
        assert!(q.client_text.contains("opt=sqrlonly~hardlock~cps~suk\r\n"));
        let suk = b64u_encode(&[9u8; 32]);
        s.feed(&b64u_encode(
            format!("ver=1\r\nnut=a\r\ntif=5\r\nqry=/cli.sqrl?nut=a\r\nsuk={suk}\r\n").as_bytes(),
        ))
        .unwrap();
        let r = s.remove(Some(&[1u8; 32])).unwrap();
        assert!(r.client_text.contains("opt=cps~suk\r\n"));
        let i = s.ident().unwrap();
        assert!(i.client_text.contains("opt=sqrlonly~hardlock~cps~suk\r\n"));
    }

    #[test]
    fn undefined_tif_bits_abort() {
        let id = UnlockedIdentity::from_iuk(&[1u8; 32]);
        let url = SqrlUrl::parse("sqrl://example.com/cli.sqrl?nut=n1").unwrap();
        let mut s = Session::new(id, url, ClientOptions::default(), None);
        assert!(s
            .feed(&b64u_encode(
                b"ver=1\r\nnut=a\r\ntif=405\r\nqry=/cli.sqrl?nut=a\r\n"
            ))
            .is_err());
        assert!(s
            .feed(&b64u_encode(
                b"ver=1\r\nnut=a\r\ntif=3ff\r\nqry=/cli.sqrl?nut=a\r\n"
            ))
            .is_ok());
    }

    #[test]
    fn ask_only_counts_in_query_replies_with_id_match() {
        let id = UnlockedIdentity::from_iuk(&[1u8; 32]);
        let url = SqrlUrl::parse("sqrl://example.com/cli.sqrl?nut=n1").unwrap();
        let mut s = Session::new(id, url, ClientOptions::default(), None);
        let ask = Ask {
            message: "Sure?".into(),
            buttons: vec![AskButton {
                label: "Go".into(),
                url: Some("extra/confirm.html".into()),
            }],
        }
        .to_wire();
        s.query().unwrap();
        // unknown identity: ignored
        s.feed(&b64u_encode(
            format!("ver=1\r\nnut=a\r\ntif=4\r\nqry=/cli.sqrl?nut=a\r\nask={ask}\r\n").as_bytes(),
        ))
        .unwrap();
        assert!(s.pending_ask().is_none());
        // known identity: honoured, and the button URL is pinned to this origin
        s.query().unwrap();
        s.feed(&b64u_encode(
            format!("ver=1\r\nnut=b\r\ntif=5\r\nqry=/cli.sqrl?nut=b\r\nask={ask}\r\n").as_bytes(),
        ))
        .unwrap();
        assert!(s.pending_ask().is_some());
        assert_eq!(
            s.ask_button_url(0).as_deref(),
            Some("https://example.com/extra/confirm.html")
        );
        s.set_button(1);
        assert!(s.pending_ask().is_none());
        let i = s.ident().unwrap();
        assert!(i.client_text.contains("btn=1\r\n"));
        // an ask in a non-query reply is ignored
        s.feed(&b64u_encode(
            format!("ver=1\r\nnut=c\r\ntif=5\r\nqry=/cli.sqrl?nut=c\r\nask={ask}\r\n").as_bytes(),
        ))
        .unwrap();
        assert!(s.pending_ask().is_none());
    }

    #[test]
    fn server_can_is_a_plain_url_or_path() {
        let id = UnlockedIdentity::from_iuk(&[1u8; 32]);
        let can = b64u_encode(b"https://example.com/login");
        let url = SqrlUrl::parse(&format!("sqrl://example.com/cli.sqrl?nut=n1&can={can}")).unwrap();
        let mut s = Session::new(id, url, ClientOptions::default(), None);
        assert_eq!(s.cancel_url().as_deref(), Some("https://example.com/login"));
        s.feed(&b64u_encode(
            b"ver=1\r\nnut=a\r\ntif=5\r\nqry=/cli.sqrl?nut=a\r\ncan=/bye?x=1\r\n",
        ))
        .unwrap();
        assert_eq!(
            s.cancel_url().as_deref(),
            Some("https://example.com/bye?x=1")
        );
    }
}
