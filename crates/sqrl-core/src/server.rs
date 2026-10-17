//! A reference SQRL server (feature `server`).
//!
//! This is a faithful but minimal implementation of the server side of the protocol: nut
//! issuance and single-use enforcement, signature verification (`ids`, `pids`, `urs`),
//! account creation, login, re-keying from a previous identity, disable / enable / remove,
//! `ask`/`btn`, `sin`/`ins` and CPS `url=` generation. It keeps everything in memory and is
//! used by the crate's flow tests and by the `sqrl-test-server` binary.

use crate::crypto::ed25519_verify;
use crate::protocol::{
    parse_pairs, version_supported, Ask, ClientOptions, Command, Tif, PROTOCOL_VERSION,
};
use crate::util::{b64u_decode, b64u_decode_array, b64u_encode, random_array};
use std::collections::{HashMap, HashSet};

/// A SQRL association stored by the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    /// Identity key.
    pub idk: [u8; 32],
    /// Server unlock key.
    pub suk: [u8; 32],
    /// Verify unlock key.
    pub vuk: [u8; 32],
    /// SQRL login disabled?
    pub disabled: bool,
    /// Client requested `sqrlonly`.
    pub sqrlonly: bool,
    /// Client requested `hardlock`.
    pub hardlock: bool,
    /// The `ins` the client supplied for our `sin` challenge, if any.
    pub ins: Option<String>,
    /// Number of successful logins.
    pub logins: u32,
}

#[derive(Clone, Debug)]
struct NutRecord {
    session: String,
    expected_server: String,
    ip: String,
    bound_idk: Option<[u8; 32]>,
    used: bool,
}

/// A browser session (one login page) as far as the server is concerned.
#[derive(Clone, Debug, Default)]
pub struct BrowserSession {
    /// The identity that authenticated this session, if any.
    pub authenticated: Option<[u8; 32]>,
    /// The `btn` answer received, if an `ask` was posed.
    pub btn: Option<u8>,
    /// Whether an `ask` has been posed in this session.
    pub asked: bool,
    /// The last command processed.
    pub last_command: Option<Command>,
}

/// The in-memory reference server.
#[derive(Clone, Debug)]
pub struct ReferenceServer {
    /// Host (with optional port) placed in issued `sqrl://` URLs.
    pub host: String,
    /// Path of the SQRL endpoint (e.g. `/cli.sqrl`).
    pub path: String,
    /// URL scheme to issue (`sqrl`, or `qrl` for plain-http localhost testing).
    pub scheme: String,
    /// Optional `x=` path extension to include in issued URLs.
    pub path_extension: Option<usize>,
    /// If set, every `query` is answered with this question until the client answers.
    pub ask: Option<Ask>,
    /// If set, every response carries this `sin=` challenge.
    pub sin: Option<String>,
    /// Prefix for the CPS success URL; the session id is appended.
    pub cps_url_prefix: String,
    /// When true, ignore IP mismatches even without `noiptest`.
    pub ignore_ip: bool,
    accounts: HashMap<[u8; 32], Account>,
    superseded: HashSet<[u8; 32]>,
    nuts: HashMap<String, NutRecord>,
    sessions: HashMap<String, BrowserSession>,
    counter: u64,
}

impl ReferenceServer {
    /// Create a server for `host` with its SQRL endpoint at `path`.
    pub fn new(host: &str, path: &str) -> Self {
        Self {
            host: host.to_string(),
            path: path.to_string(),
            scheme: "sqrl".into(),
            path_extension: None,
            ask: None,
            sin: None,
            cps_url_prefix: format!("https://{host}/loggedin?session="),
            ignore_ip: false,
            accounts: HashMap::new(),
            superseded: HashSet::new(),
            nuts: HashMap::new(),
            sessions: HashMap::new(),
            counter: 0,
        }
    }

    fn new_nut(&mut self) -> String {
        self.counter += 1;
        let r: [u8; 8] = random_array();
        format!("{}{}", b64u_encode(&r), self.counter)
    }

    /// Issue a fresh `sqrl://` login URL for a browser session. Returns `(session id, url)`.
    pub fn new_login_url(&mut self, ip: &str, cancel_url: Option<&str>) -> (String, String) {
        let session = format!("s{}", self.new_nut());
        let nut = self.new_nut();
        let mut url = format!("{}://{}{}?", self.scheme, self.host, self.path);
        if let Some(x) = self.path_extension {
            url.push_str(&format!("x={x}&"));
        }
        url.push_str(&format!("nut={nut}"));
        if let Some(c) = cancel_url {
            url.push_str(&format!("&can={}", b64u_encode(c.as_bytes())));
        }
        self.nuts.insert(
            nut,
            NutRecord {
                session: session.clone(),
                expected_server: b64u_encode(url.as_bytes()),
                ip: ip.to_string(),
                bound_idk: None,
                used: false,
            },
        );
        self.sessions
            .insert(session.clone(), BrowserSession::default());
        (session, url)
    }

    /// State of a browser session.
    pub fn session(&self, session: &str) -> Option<&BrowserSession> {
        self.sessions.get(session)
    }

    /// Look up an account by identity key.
    pub fn account(&self, idk: &[u8; 32]) -> Option<&Account> {
        self.accounts.get(idk)
    }

    /// Number of accounts.
    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    /// Whether an identity key has been superseded by a re-key.
    pub fn is_superseded(&self, idk: &[u8; 32]) -> bool {
        self.superseded.contains(idk)
    }

    /// Handle a POST to the SQRL endpoint. `nut` is the `nut=` from the request URL's
    /// query string, `body` the form body, `ip` the client's address. Returns the response
    /// body (base64url text).
    pub fn handle(&mut self, nut: &str, body: &str, ip: &str) -> String {
        let mut tif = Tif(0);
        let mut extra: Vec<(String, String)> = Vec::new();

        // --- nut lookup -----------------------------------------------------------------
        let record = match self.nuts.get(nut) {
            Some(r) if !r.used => r.clone(),
            _ => {
                // Unknown or reused nut: transient error, hand out a fresh nut bound to a new
                // anonymous session so the client can retry.
                tif.0 |= Tif::TRANSIENT_ERROR | Tif::COMMAND_FAILED;
                let session = format!("s{}", self.new_nut());
                self.sessions
                    .insert(session.clone(), BrowserSession::default());
                return self.respond(tif, &session, ip.to_string(), None, extra);
            }
        };
        self.nuts.get_mut(nut).unwrap().used = true;
        let session = record.session.clone();

        // --- form parsing ---------------------------------------------------------------
        let form = parse_form(body);
        let get = |k: &str| form.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        let (client_b64, server_b64, ids_b64) = match (get("client"), get("server"), get("ids")) {
            (Some(c), Some(s), Some(i)) => (c, s, i),
            _ => {
                tif.0 |= Tif::CLIENT_FAILURE | Tif::COMMAND_FAILED;
                return self.respond(tif, &session, record.ip, record.bound_idk, extra);
            }
        };
        if server_b64 != record.expected_server {
            tif.0 |= Tif::CLIENT_FAILURE | Tif::COMMAND_FAILED;
            return self.respond(tif, &session, record.ip, record.bound_idk, extra);
        }
        let client_text = match b64u_decode(&client_b64)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
        {
            Some(t) => t,
            None => {
                tif.0 |= Tif::CLIENT_FAILURE | Tif::COMMAND_FAILED;
                return self.respond(tif, &session, record.ip, record.bound_idk, extra);
            }
        };
        let params = parse_pairs(&client_text);
        let cget = |k: &str| params.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());

        let ver_ok = cget("ver")
            .map(|v| version_supported(&v, PROTOCOL_VERSION))
            .unwrap_or(false);
        let cmd = cget("cmd").and_then(|c| Command::parse(&c));
        let idk = cget("idk").and_then(|v| b64u_decode_array::<32>(&v).ok());
        let (cmd, idk) = match (ver_ok, cmd, idk) {
            (true, Some(c), Some(i)) => (c, i),
            (true, None, _) => {
                tif.0 |= Tif::FUNCTION_NOT_SUPPORTED | Tif::COMMAND_FAILED;
                return self.respond(tif, &session, record.ip, record.bound_idk, extra);
            }
            _ => {
                tif.0 |= Tif::CLIENT_FAILURE | Tif::COMMAND_FAILED;
                return self.respond(tif, &session, record.ip, record.bound_idk, extra);
            }
        };

        // --- signature verification -----------------------------------------------------
        let signed = format!("{client_b64}{server_b64}");
        let sig_ok = b64u_decode_array::<64>(&ids_b64)
            .ok()
            .map(|s| ed25519_verify(&idk, signed.as_bytes(), &s).is_ok())
            .unwrap_or(false);
        let pidk = cget("pidk").and_then(|v| b64u_decode_array::<32>(&v).ok());
        let pids_ok = match (pidk, get("pids")) {
            (Some(p), Some(sig)) => b64u_decode_array::<64>(&sig)
                .ok()
                .map(|s| ed25519_verify(&p, signed.as_bytes(), &s).is_ok())
                .unwrap_or(false),
            (None, None) => true,
            _ => false,
        };
        if !sig_ok || !pids_ok {
            tif.0 |= Tif::CLIENT_FAILURE | Tif::COMMAND_FAILED;
            return self.respond(tif, &session, record.ip, record.bound_idk, extra);
        }

        // --- identity binding to the session ---------------------------------------------
        if let Some(bound) = record.bound_idk {
            if bound != idk {
                tif.0 |= Tif::BAD_ID_ASSOCIATION | Tif::COMMAND_FAILED;
                return self.respond(tif, &session, record.ip, Some(bound), extra);
            }
        }
        let opts = cget("opt")
            .map(|o| ClientOptions::from_wire(&o))
            .unwrap_or_default();
        if record.ip == ip {
            tif.0 |= Tif::IPS_MATCHED;
        } else if !opts.noiptest && !self.ignore_ip {
            tif.0 |= Tif::COMMAND_FAILED;
            return self.respond(tif, &session, record.ip, Some(idk), extra);
        }

        if self.superseded.contains(&idk) {
            tif.0 |= Tif::IDENTITY_SUPERSEDED | Tif::COMMAND_FAILED;
            return self.respond(tif, &session, record.ip, Some(idk), extra);
        }

        // --- which identity does the server know? ----------------------------------------
        let mut id_match = self.accounts.contains_key(&idk);
        let prev_match = !id_match
            && pidk
                .map(|p| self.accounts.contains_key(&p))
                .unwrap_or(false);
        if id_match {
            tif.0 |= Tif::ID_MATCH;
        }
        if prev_match {
            tif.0 |= Tif::PREVIOUS_ID_MATCH;
        }
        let matched_key = if id_match {
            Some(idk)
        } else if prev_match {
            pidk
        } else {
            None
        };
        if let Some(k) = matched_key {
            if self.accounts[&k].disabled {
                tif.0 |= Tif::SQRL_DISABLED;
            }
        }

        // ask / btn bookkeeping
        let btn = cget("btn").and_then(|b| b.parse::<u8>().ok());
        {
            let s = self.sessions.entry(session.clone()).or_default();
            if let Some(b) = btn {
                s.btn = Some(b);
            }
            s.last_command = Some(cmd);
        }
        let ask_pending = self.ask.is_some() && self.sessions[&session].btn.is_none();

        let suk_b64 = cget("suk");
        let vuk_b64 = cget("vuk");
        let urs_ok = |vuk: &[u8; 32]| -> bool {
            get("urs")
                .and_then(|u| b64u_decode_array::<64>(&u).ok())
                .map(|s| ed25519_verify(vuk, signed.as_bytes(), &s).is_ok())
                .unwrap_or(false)
        };

        // --- re-key: previous identity matched and the new keys were supplied ---------------
        let mut rekey_failed = false;
        if prev_match && cmd != Command::Query {
            let old = pidk.unwrap();
            match (
                suk_b64
                    .as_deref()
                    .and_then(|s| b64u_decode_array::<32>(s).ok()),
                vuk_b64
                    .as_deref()
                    .and_then(|s| b64u_decode_array::<32>(s).ok()),
            ) {
                (Some(new_suk), Some(new_vuk))
                    if urs_ok(&self.accounts[&old].vuk)
                        && (self.sin.is_none()
                            || self.accounts[&old].ins.is_none()
                            || self.accounts[&old].ins == cget("pins")) =>
                {
                    let mut acct = self.accounts.remove(&old).unwrap();
                    acct.idk = idk;
                    acct.suk = new_suk;
                    acct.vuk = new_vuk;
                    // the indexed secret now belongs to the new identity
                    acct.ins = cget("ins");
                    self.accounts.insert(idk, acct);
                    self.superseded.insert(old);
                    id_match = true;
                    tif.0 |= Tif::ID_MATCH;
                }
                _ => rekey_failed = true,
            }
        }

        // --- execute ---------------------------------------------------------------------
        let mut suk_to_return: Option<[u8; 32]> = None;
        match cmd {
            Command::Query => {
                if let Some(k) = matched_key {
                    let a = &self.accounts[&k];
                    if opts.suk || a.disabled || prev_match {
                        suk_to_return = Some(a.suk);
                    }
                }
                // An ask is only valid in a query reply that recognises the current identity.
                if ask_pending && id_match {
                    extra.push(("ask".into(), self.ask.as_ref().unwrap().to_wire()));
                    self.sessions.get_mut(&session).unwrap().asked = true;
                }
            }
            Command::Ident => {
                if rekey_failed || (ask_pending && self.sessions[&session].asked) {
                    tif.0 |= Tif::COMMAND_FAILED;
                } else if id_match {
                    let a = self.accounts.get_mut(&idk).unwrap();
                    if a.disabled {
                        tif.0 |= Tif::COMMAND_FAILED;
                    } else {
                        a.sqrlonly = opts.sqrlonly;
                        a.hardlock = opts.hardlock;
                        if self.sin.is_some() {
                            match cget("ins") {
                                Some(ins) if a.ins.as_deref().map(|x| x == ins).unwrap_or(true) => {
                                    a.ins = Some(ins)
                                }
                                _ => {
                                    tif.0 |= Tif::COMMAND_FAILED;
                                    return self.respond(
                                        tif,
                                        &session,
                                        record.ip,
                                        Some(idk),
                                        extra,
                                    );
                                }
                            }
                        }
                        a.logins += 1;
                        self.sessions.get_mut(&session).unwrap().authenticated = Some(idk);
                        if opts.cps {
                            extra.push((
                                "url".into(),
                                format!("{}{}", self.cps_url_prefix, session),
                            ));
                        }
                    }
                } else {
                    // new account
                    match (
                        suk_b64
                            .as_deref()
                            .and_then(|s| b64u_decode_array::<32>(s).ok()),
                        vuk_b64
                            .as_deref()
                            .and_then(|s| b64u_decode_array::<32>(s).ok()),
                    ) {
                        (Some(suk), Some(vuk)) => {
                            self.accounts.insert(
                                idk,
                                Account {
                                    idk,
                                    suk,
                                    vuk,
                                    disabled: false,
                                    sqrlonly: opts.sqrlonly,
                                    hardlock: opts.hardlock,
                                    ins: cget("ins"),
                                    logins: 1,
                                },
                            );
                            tif.0 |= Tif::ID_MATCH;
                            self.sessions.get_mut(&session).unwrap().authenticated = Some(idk);
                            if opts.cps {
                                extra.push((
                                    "url".into(),
                                    format!("{}{}", self.cps_url_prefix, session),
                                ));
                            }
                        }
                        _ => tif.0 |= Tif::COMMAND_FAILED | Tif::CLIENT_FAILURE,
                    }
                }
            }
            Command::Disable => {
                if rekey_failed || !id_match {
                    tif.0 |= Tif::COMMAND_FAILED;
                } else {
                    self.accounts.get_mut(&idk).unwrap().disabled = true;
                    tif.0 |= Tif::SQRL_DISABLED;
                }
            }
            Command::Enable => {
                if rekey_failed || !id_match {
                    tif.0 |= Tif::COMMAND_FAILED;
                } else {
                    let vuk = self.accounts[&idk].vuk;
                    // after a re-key the urs was already verified against the old vuk
                    if prev_match || urs_ok(&vuk) {
                        let a = self.accounts.get_mut(&idk).unwrap();
                        a.disabled = false;
                        tif.0 &= !Tif::SQRL_DISABLED;
                        a.logins += 1;
                        self.sessions.get_mut(&session).unwrap().authenticated = Some(idk);
                        if opts.cps {
                            extra.push((
                                "url".into(),
                                format!("{}{}", self.cps_url_prefix, session),
                            ));
                        }
                    } else {
                        tif.0 |= Tif::COMMAND_FAILED | Tif::CLIENT_FAILURE;
                    }
                }
            }
            Command::Remove => {
                if rekey_failed || !id_match {
                    tif.0 |= Tif::COMMAND_FAILED;
                } else {
                    let vuk = self.accounts[&idk].vuk;
                    if prev_match || urs_ok(&vuk) {
                        self.accounts.remove(&idk);
                        tif.0 &= !(Tif::ID_MATCH | Tif::SQRL_DISABLED);
                        if opts.cps {
                            extra.push((
                                "url".into(),
                                format!("{}{}", self.cps_url_prefix, session),
                            ));
                        }
                    } else {
                        tif.0 |= Tif::COMMAND_FAILED | Tif::CLIENT_FAILURE;
                    }
                }
            }
        }

        if let Some(s) = suk_to_return {
            extra.push(("suk".into(), b64u_encode(&s)));
        }
        self.respond(tif, &session, record.ip, Some(idk), extra)
    }

    fn respond(
        &mut self,
        tif: Tif,
        session: &str,
        ip: String,
        bound_idk: Option<[u8; 32]>,
        extra: Vec<(String, String)>,
    ) -> String {
        let nut = self.new_nut();
        let mut text = format!(
            "ver=1\r\nnut={nut}\r\ntif={}\r\nqry={}?nut={nut}\r\n",
            tif.to_hex(),
            self.path
        );
        if let Some(sin) = &self.sin {
            text.push_str(&format!("sin={sin}\r\n"));
        }
        for (k, v) in extra {
            text.push_str(&format!("{k}={v}\r\n"));
        }
        let body = b64u_encode(text.as_bytes());
        self.nuts.insert(
            nut,
            NutRecord {
                session: session.to_string(),
                expected_server: body.clone(),
                ip,
                bound_idk,
                used: false,
            },
        );
        body
    }
}

/// Parse an `application/x-www-form-urlencoded` body. SQRL values are base64url, so no
/// percent-decoding is needed beyond tolerating a stray trailing newline.
pub fn parse_form(body: &str) -> Vec<(String, String)> {
    body.trim()
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|kv| match kv.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (kv.to_string(), String::new()),
        })
        .collect()
}
