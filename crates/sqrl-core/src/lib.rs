//! # sqrl-core
//!
//! A pure-Rust implementation of Steve Gibson's SQRL ("Secure Quick Reliable Login")
//! client protocol, as published at <https://www.grc.com/sqrl/sqrl.htm>.
//!
//! The crate is split into the following modules:
//!
//! * [`crypto`]   – EnScrypt, EnHash, HMAC-SHA256, AES-256-GCM, Ed25519 and X25519 helpers.
//! * [`identity`] – the in-memory (unlocked) identity: IMK/ILK/IUK handling, per-site key
//!   derivation and the identity-lock (SUK/VUK/URS) mathematics.
//! * [`storage`]  – the S4 "SQRL Secure Storage System" file format (type 1, 2 and 3 blocks),
//!   rescue-code generation, password changes and re-keying.
//! * [`textual`]  – the base56 "textual identity" export / import format.
//! * [`url`]      – parsing of `sqrl://` URLs into the site key, POST URL and cancel URL.
//! * [`protocol`] – the client/server wire protocol: client requests, server responses,
//!   TIF flags, and a [`protocol::Session`] state machine that drives a full transaction.
//! * [`server`]   – (feature `server`) a small reference server implementation used by the
//!   test-suite and by the `sqrl-test-server` binary.
//!
//! Everything is `wasm32` friendly: there is no threading, no filesystem access, and the
//! only platform dependency is `getrandom`.

#![forbid(unsafe_code)]

pub mod crypto;
pub mod identity;
pub mod protocol;
pub mod storage;
pub mod textual;
pub mod url;
pub mod util;

#[cfg(feature = "server")]
pub mod server;

pub use identity::UnlockedIdentity;
pub use protocol::{ClientOptions, Command, ServerResponse, Session, Tif};
pub use storage::S4Identity;
pub use url::SqrlUrl;




/// Error type used throughout the crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Input could not be parsed (bad base64, bad header, bad length...).
    Format(String),
    /// A cryptographic check failed (bad password, bad rescue code, bad signature...).
    Crypto(String),
    /// The protocol state does not permit the requested operation.
    Protocol(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Format(s) => write!(f, "format error: {s}"),
            Error::Crypto(s) => write!(f, "crypto error: {s}"),
            Error::Protocol(s) => write!(f, "protocol error: {s}"),
        }
    }
}

impl std::error::Error for Error {}

/// Convenience result alias.
pub type Result<T> = core::result::Result<T, Error>;
