//! The S4 ("SQRL Secure Storage System") identity file format.
//!
//! An identity file starts with the 8 byte header `sqrldata` (binary) or `SQRLDATA` followed
//! by base64url text, and then a sequence of length-prefixed blocks:
//!
//! * **Type 1** (125 bytes) – the password-protected IMK and ILK plus the user's settings.
//!   AES-256-GCM, key = `EnScrypt(password, salt, logN, iterations)`, IV from the block,
//!   AAD = the 45 plaintext bytes of the block.
//! * **Type 2** (73 bytes) – the rescue-code-protected IUK. AES-256-GCM, key =
//!   `EnScrypt(rescue code digits, salt, logN, iterations)`, IV = 12 zero bytes,
//!   AAD = the 25 plaintext bytes of the block.
//! * **Type 3** (54/86/118/150 bytes) – up to four previous IUKs. AES-256-GCM, key = IMK,
//!   IV = 12 zero bytes, AAD = the 6 plaintext bytes of the block.
//!
//! Unknown block types are preserved verbatim so that files written by other clients
//! survive a round trip.

use crate::crypto::{
    aes_gcm_decrypt, aes_gcm_encrypt, enscrypt_duration, enscrypt_iterations, DEFAULT_LOG_N,
};
use crate::identity::{ilk_from_iuk, imk_from_iuk, UnlockedIdentity};
use crate::util::{b64u_decode, b64u_encode, le_u16, le_u32, random_array};
use crate::{Error, Result};
use zeroize::Zeroize;

/// Binary file header.
pub const HEADER_BINARY: &[u8; 8] = b"sqrldata";
/// Header of the base64url textual representation.
pub const HEADER_TEXT: &[u8; 8] = b"SQRLDATA";

/// Type 1 option flag: the client should check for updates.
pub const FLAG_CHECK_FOR_UPDATES: u16 = 0x0001;
/// Type 1 option flag: the client may update itself automatically.
pub const FLAG_UPDATE_AUTOMATICALLY: u16 = 0x0002;
/// Type 1 option flag: request that sites disable non-SQRL authentication (`sqrlonly`).
pub const FLAG_SQRL_ONLY: u16 = 0x0004;
/// Type 1 option flag: request that sites disable account recovery by other means (`hardlock`).
pub const FLAG_NO_BYPASS: u16 = 0x0008;
/// Type 1 option flag 0x0010: warn of a possible MITM attack when the server reports that the
/// query's IP does not match the IP that requested the SQRL URL.
pub const FLAG_WARN_MITM: u16 = 0x0010;
/// Type 1 option flag 0x0020: discard the QuickPass when the system blanks, sleeps or suspends.
pub const FLAG_CLEAR_QUICKPASS_ON_SLEEP: u16 = 0x0020;
/// Type 1 option flag 0x0040: discard the QuickPass when the user is switched.
pub const FLAG_CLEAR_QUICKPASS_ON_SWITCH: u16 = 0x0040;
/// Type 1 option flag 0x0080: discard the QuickPass after the idle timeout (minutes) elapses.
pub const FLAG_CLEAR_QUICKPASS_ON_IDLE: u16 = 0x0080;
/// Type 1 option flag 0x0100: warn whenever a non-CPS authentication is attempted.
pub const FLAG_WARN_NON_CPS: u16 = 0x0100;
/// Default option flags for a newly created identity (0x01F3, per the S4 specification).
pub const DEFAULT_OPTION_FLAGS: u16 = FLAG_CHECK_FOR_UPDATES
    | FLAG_UPDATE_AUTOMATICALLY
    | FLAG_WARN_MITM
    | FLAG_CLEAR_QUICKPASS_ON_SLEEP
    | FLAG_CLEAR_QUICKPASS_ON_SWITCH
    | FLAG_CLEAR_QUICKPASS_ON_IDLE
    | FLAG_WARN_NON_CPS;

/// Normalize user-typed secret text the way all SQRL clients must before EnScrypt: Unicode
/// NFKC composition, then UTF-8 (SQRL Cryptography §"Processing User Input").
pub fn normalize_password(password: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    password.nfkc().collect()
}

const ZERO_IV: [u8; 12] = [0u8; 12];
const TYPE1_LEN: usize = 125;
const TYPE1_PT_LEN: usize = 45;
const TYPE2_LEN: usize = 73;
const TYPE2_PT_LEN: usize = 25;
const TYPE3_PT_LEN: usize = 6;
/// Maximum number of previous IUKs stored in a type 3 block.
pub const MAX_PREVIOUS_KEYS: usize = 4;

/// User-adjustable settings stored in the plaintext part of the type 1 block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentitySettings {
    /// Bit flags, see the `FLAG_*` constants.
    pub option_flags: u16,
    /// Number of leading password characters that form the QuickPass.
    pub hint_length: u8,
    /// Seconds to run EnScrypt when (re)encrypting with the full password.
    pub pw_verify_seconds: u8,
    /// Minutes of idleness after which the QuickPass is discarded.
    pub idle_timeout_minutes: u16,
    /// scrypt log2(N) for the password block.
    pub log_n: u8,
}

impl Default for IdentitySettings {
    fn default() -> Self {
        Self {
            option_flags: DEFAULT_OPTION_FLAGS,
            hint_length: 4,
            pw_verify_seconds: 5,
            idle_timeout_minutes: 15,
            log_n: DEFAULT_LOG_N,
        }
    }
}

/// Type 1 block: password-encrypted IMK and ILK.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Type1Block {
    /// AES-GCM initialization vector.
    pub iv: [u8; 12],
    /// EnScrypt salt.
    pub salt: [u8; 16],
    /// Settings (plaintext, authenticated).
    pub settings: IdentitySettings,
    /// EnScrypt iteration count.
    pub iterations: u32,
    /// Encrypted IMK.
    pub enc_imk: [u8; 32],
    /// Encrypted ILK.
    pub enc_ilk: [u8; 32],
    /// AES-GCM authentication tag.
    pub tag: [u8; 16],
}

impl Type1Block {
    /// The 45 plaintext bytes (which double as the AES-GCM additional authenticated data).
    pub fn plaintext(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(TYPE1_PT_LEN);
        v.extend_from_slice(&(TYPE1_LEN as u16).to_le_bytes());
        v.extend_from_slice(&1u16.to_le_bytes());
        v.extend_from_slice(&(TYPE1_PT_LEN as u16).to_le_bytes());
        v.extend_from_slice(&self.iv);
        v.extend_from_slice(&self.salt);
        v.push(self.settings.log_n);
        v.extend_from_slice(&self.iterations.to_le_bytes());
        v.extend_from_slice(&self.settings.option_flags.to_le_bytes());
        v.push(self.settings.hint_length);
        v.push(self.settings.pw_verify_seconds);
        v.extend_from_slice(&self.settings.idle_timeout_minutes.to_le_bytes());
        debug_assert_eq!(v.len(), TYPE1_PT_LEN);
        v
    }

    /// Serialize the full 125-byte block.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = self.plaintext();
        v.extend_from_slice(&self.enc_imk);
        v.extend_from_slice(&self.enc_ilk);
        v.extend_from_slice(&self.tag);
        v
    }

    fn parse(b: &[u8]) -> Result<Self> {
        if b.len() != TYPE1_LEN {
            return Err(Error::Format(format!(
                "type 1 block must be {TYPE1_LEN} bytes, got {}",
                b.len()
            )));
        }
        let pt_len = le_u16(&b[4..6]) as usize;
        if pt_len != TYPE1_PT_LEN {
            return Err(Error::Format(format!(
                "unsupported type 1 plaintext length {pt_len}"
            )));
        }
        Ok(Self {
            iv: b[6..18].try_into().unwrap(),
            salt: b[18..34].try_into().unwrap(),
            settings: IdentitySettings {
                log_n: b[34],
                option_flags: le_u16(&b[39..41]),
                hint_length: b[41],
                pw_verify_seconds: b[42],
                idle_timeout_minutes: le_u16(&b[43..45]),
            },
            iterations: le_u32(&b[35..39]),
            enc_imk: b[45..77].try_into().unwrap(),
            enc_ilk: b[77..109].try_into().unwrap(),
            tag: b[109..125].try_into().unwrap(),
        })
    }

    /// Derive the AES key from the password (slow: runs EnScrypt for `iterations`).
    pub fn derive_key(&self, password: &str, progress: impl FnMut(u32)) -> [u8; 32] {
        let mut pw = normalize_password(password);
        let key = enscrypt_iterations(
            pw.as_bytes(),
            &self.salt,
            self.settings.log_n,
            self.iterations,
            progress,
        );
        pw.zeroize();
        key
    }

    /// Decrypt IMK and ILK with an already-derived key.
    pub fn decrypt_with_key(&self, key: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
        let mut ct = Vec::with_capacity(80);
        ct.extend_from_slice(&self.enc_imk);
        ct.extend_from_slice(&self.enc_ilk);
        ct.extend_from_slice(&self.tag);
        let mut pt = aes_gcm_decrypt(key, &self.iv, &self.plaintext(), &ct)
            .map_err(|_| Error::Crypto("incorrect password".into()))?;
        let imk: [u8; 32] = pt[0..32].try_into().unwrap();
        let ilk: [u8; 32] = pt[32..64].try_into().unwrap();
        pt.zeroize();
        Ok((imk, ilk))
    }

    /// Build a fresh block encrypting `imk`/`ilk` under `password`, running EnScrypt for
    /// `settings.pw_verify_seconds` (as measured by `now_ms`).
    pub fn encrypt(
        imk: &[u8; 32],
        ilk: &[u8; 32],
        password: &str,
        settings: IdentitySettings,
        now_ms: impl FnMut() -> u64,
        progress: impl FnMut(u64, u64),
    ) -> Self {
        let salt: [u8; 16] = random_array();
        let iv: [u8; 12] = random_array();
        let duration_ms = settings.pw_verify_seconds.max(1) as u64 * 1000;
        let mut pw = normalize_password(password);
        let (mut key, iterations) = enscrypt_duration(
            pw.as_bytes(),
            &salt,
            settings.log_n,
            duration_ms,
            now_ms,
            progress,
        );
        pw.zeroize();
        let block = Self::encrypt_with_key(imk, ilk, &key, salt, iv, iterations, settings);
        key.zeroize();
        block
    }

    /// Build a block with a pre-derived key (used by tests and for deterministic rebuilds).
    pub fn encrypt_with_key(
        imk: &[u8; 32],
        ilk: &[u8; 32],
        key: &[u8; 32],
        salt: [u8; 16],
        iv: [u8; 12],
        iterations: u32,
        settings: IdentitySettings,
    ) -> Self {
        let mut block = Self {
            iv,
            salt,
            settings,
            iterations,
            enc_imk: [0; 32],
            enc_ilk: [0; 32],
            tag: [0; 16],
        };
        let mut pt = Vec::with_capacity(64);
        pt.extend_from_slice(imk);
        pt.extend_from_slice(ilk);
        let ct = aes_gcm_encrypt(key, &block.iv, &block.plaintext(), &pt);
        pt.zeroize();
        block.enc_imk.copy_from_slice(&ct[0..32]);
        block.enc_ilk.copy_from_slice(&ct[32..64]);
        block.tag.copy_from_slice(&ct[64..80]);
        block
    }
}

/// Type 2 block: rescue-code-encrypted IUK.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Type2Block {
    /// EnScrypt salt.
    pub salt: [u8; 16],
    /// scrypt log2(N).
    pub log_n: u8,
    /// EnScrypt iteration count.
    pub iterations: u32,
    /// Encrypted IUK.
    pub enc_iuk: [u8; 32],
    /// AES-GCM authentication tag.
    pub tag: [u8; 16],
}

impl Type2Block {
    /// The 25 plaintext bytes (also the AAD).
    pub fn plaintext(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(TYPE2_PT_LEN);
        v.extend_from_slice(&(TYPE2_LEN as u16).to_le_bytes());
        v.extend_from_slice(&2u16.to_le_bytes());
        v.extend_from_slice(&self.salt);
        v.push(self.log_n);
        v.extend_from_slice(&self.iterations.to_le_bytes());
        debug_assert_eq!(v.len(), TYPE2_PT_LEN);
        v
    }

    /// Serialize the full 73-byte block.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = self.plaintext();
        v.extend_from_slice(&self.enc_iuk);
        v.extend_from_slice(&self.tag);
        v
    }

    fn parse(b: &[u8]) -> Result<Self> {
        if b.len() != TYPE2_LEN {
            return Err(Error::Format(format!(
                "type 2 block must be {TYPE2_LEN} bytes, got {}",
                b.len()
            )));
        }
        Ok(Self {
            salt: b[4..20].try_into().unwrap(),
            log_n: b[20],
            iterations: le_u32(&b[21..25]),
            enc_iuk: b[25..57].try_into().unwrap(),
            tag: b[57..73].try_into().unwrap(),
        })
    }

    /// Decrypt the IUK with the rescue code (slow: runs EnScrypt for `iterations`).
    pub fn decrypt(&self, rescue_code: &str, progress: impl FnMut(u32)) -> Result<[u8; 32]> {
        let digits = normalize_rescue_code(rescue_code)?;
        let mut key = enscrypt_iterations(
            digits.as_bytes(),
            &self.salt,
            self.log_n,
            self.iterations,
            progress,
        );
        let mut ct = Vec::with_capacity(48);
        ct.extend_from_slice(&self.enc_iuk);
        ct.extend_from_slice(&self.tag);
        let res = aes_gcm_decrypt(&key, &ZERO_IV, &self.plaintext(), &ct)
            .map_err(|_| Error::Crypto("incorrect rescue code".into()));
        key.zeroize();
        let mut pt = res?;
        let iuk: [u8; 32] = pt[..].try_into().unwrap();
        pt.zeroize();
        Ok(iuk)
    }

    /// Encrypt an IUK under a rescue code, running EnScrypt for `duration_ms`.
    pub fn encrypt(
        iuk: &[u8; 32],
        rescue_code: &str,
        log_n: u8,
        duration_ms: u64,
        now_ms: impl FnMut() -> u64,
        progress: impl FnMut(u64, u64),
    ) -> Result<Self> {
        let digits = normalize_rescue_code(rescue_code)?;
        let salt: [u8; 16] = random_array();
        let (mut key, iterations) = enscrypt_duration(
            digits.as_bytes(),
            &salt,
            log_n,
            duration_ms,
            now_ms,
            progress,
        );
        let block = Self::encrypt_with_key(iuk, &key, salt, log_n, iterations);
        key.zeroize();
        Ok(block)
    }

    /// Encrypt with a pre-derived key.
    pub fn encrypt_with_key(
        iuk: &[u8; 32],
        key: &[u8; 32],
        salt: [u8; 16],
        log_n: u8,
        iterations: u32,
    ) -> Self {
        let mut block = Self {
            salt,
            log_n,
            iterations,
            enc_iuk: [0; 32],
            tag: [0; 16],
        };
        let ct = aes_gcm_encrypt(key, &ZERO_IV, &block.plaintext(), iuk);
        block.enc_iuk.copy_from_slice(&ct[0..32]);
        block.tag.copy_from_slice(&ct[32..48]);
        block
    }
}

/// Type 3 block: previous IUKs encrypted under the current IMK.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Type3Block {
    /// The identity's "edition": a counter incremented once per re-keying. It is part of
    /// the authenticated plaintext, so it can be shown (e.g. on printouts) without the
    /// password. The number of stored keys is given by the block length, not by this field.
    pub edition: u16,
    /// Encrypted previous IUKs, most recent first. 1 to 4 entries.
    pub enc_keys: Vec<[u8; 32]>,
    /// AES-GCM authentication tag.
    pub tag: [u8; 16],
}

impl Type3Block {
    /// Total block length for this many keys.
    pub fn len(&self) -> usize {
        TYPE3_PT_LEN + 32 * self.enc_keys.len() + 16
    }

    /// Whether the block holds no keys (never true for a well-formed block).
    pub fn is_empty(&self) -> bool {
        self.enc_keys.is_empty()
    }

    /// The 6 plaintext bytes (also the AAD).
    pub fn plaintext(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(TYPE3_PT_LEN);
        v.extend_from_slice(&(self.len() as u16).to_le_bytes());
        v.extend_from_slice(&3u16.to_le_bytes());
        v.extend_from_slice(&self.edition.to_le_bytes());
        v
    }

    /// Serialize the block.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = self.plaintext();
        for k in &self.enc_keys {
            v.extend_from_slice(k);
        }
        v.extend_from_slice(&self.tag);
        v
    }

    fn parse(b: &[u8]) -> Result<Self> {
        if b.len() < TYPE3_PT_LEN + 32 + 16 {
            return Err(Error::Format("type 3 block too short".into()));
        }
        let edition = le_u16(&b[4..6]);
        if edition == 0 {
            return Err(Error::Format("type 3 block has edition 0".into()));
        }
        let body = b.len() - TYPE3_PT_LEN - 16;
        if !body.is_multiple_of(32) || body == 0 || body / 32 > MAX_PREVIOUS_KEYS {
            return Err(Error::Format(format!(
                "type 3 block length {} is not 54, 86, 118 or 150",
                b.len()
            )));
        }
        let count = body / 32;
        let mut enc_keys = Vec::with_capacity(count);
        for i in 0..count {
            let start = TYPE3_PT_LEN + 32 * i;
            enc_keys.push(b[start..start + 32].try_into().unwrap());
        }
        Ok(Self {
            edition,
            enc_keys,
            tag: b[b.len() - 16..].try_into().unwrap(),
        })
    }

    /// Decrypt the previous IUKs with the current IMK.
    pub fn decrypt(&self, imk: &[u8; 32]) -> Result<Vec<[u8; 32]>> {
        let mut ct = Vec::with_capacity(32 * self.enc_keys.len() + 16);
        for k in &self.enc_keys {
            ct.extend_from_slice(k);
        }
        ct.extend_from_slice(&self.tag);
        let mut pt = aes_gcm_decrypt(imk, &ZERO_IV, &self.plaintext(), &ct)
            .map_err(|_| Error::Crypto("previous identity block does not verify".into()))?;
        let keys = pt.chunks(32).map(|c| c.try_into().unwrap()).collect();
        pt.zeroize();
        Ok(keys)
    }

    /// Encrypt previous IUKs (most recent first; at most four are kept) under `imk`, with the
    /// given edition number.
    pub fn encrypt(previous_iuks: &[[u8; 32]], imk: &[u8; 32], edition: u16) -> Option<Self> {
        let keys: Vec<[u8; 32]> = previous_iuks
            .iter()
            .take(MAX_PREVIOUS_KEYS)
            .copied()
            .collect();
        if keys.is_empty() {
            return None;
        }
        let mut block = Self {
            edition: edition.max(1),
            enc_keys: vec![[0; 32]; keys.len()],
            tag: [0; 16],
        };
        let mut pt = Vec::with_capacity(32 * keys.len());
        for k in &keys {
            pt.extend_from_slice(k);
        }
        let ct = aes_gcm_encrypt(imk, &ZERO_IV, &block.plaintext(), &pt);
        pt.zeroize();
        for (i, k) in block.enc_keys.iter_mut().enumerate() {
            k.copy_from_slice(&ct[32 * i..32 * i + 32]);
        }
        block.tag.copy_from_slice(&ct[32 * keys.len()..]);
        Some(block)
    }
}

/// A parsed S4 identity file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct S4Identity {
    /// Password block.
    pub type1: Option<Type1Block>,
    /// Rescue code block.
    pub type2: Option<Type2Block>,
    /// Previous identities block.
    pub type3: Option<Type3Block>,
    /// Blocks of unknown type, preserved verbatim (each including its length/type prefix).
    pub unknown: Vec<Vec<u8>>,
}

impl S4Identity {
    /// Parse either the binary (`sqrldata`) or the textual base64url (`SQRLDATA`) form.
    pub fn parse(input: &[u8]) -> Result<Self> {
        let trimmed = trim_ascii(input);
        if trimmed.len() < 8 {
            return Err(Error::Format("identity data too short".into()));
        }
        if &trimmed[..8] == HEADER_TEXT {
            let text = core::str::from_utf8(&trimmed[8..])
                .map_err(|_| Error::Format("invalid SQRLDATA text".into()))?;
            let body = b64u_decode(text)?;
            return Self::parse_blocks(&body);
        }
        if &trimmed[..8] == HEADER_BINARY {
            return Self::parse_blocks(&trimmed[8..]);
        }
        Err(Error::Format("missing sqrldata header".into()))
    }

    /// Parse a sequence of blocks without the file header (used for the textual identity too).
    pub fn parse_blocks(mut data: &[u8]) -> Result<Self> {
        let mut id = Self::default();
        while data.len() >= 4 {
            let len = le_u16(&data[0..2]) as usize;
            let typ = le_u16(&data[2..4]);
            if len == 0 {
                // zero padding (textual identities may carry trailing zero bytes)
                if data.iter().all(|b| *b == 0) {
                    break;
                }
                return Err(Error::Format("zero-length block".into()));
            }
            if len < 4 || len > data.len() {
                return Err(Error::Format(format!(
                    "block of type {typ} claims {len} bytes but only {} remain",
                    data.len()
                )));
            }
            let block = &data[..len];
            // "Any client encountering an identity containing more than one of either type
            // should reject the entire identity as suspicious and invalid."
            let duplicate = match typ {
                1 => id.type1.is_some(),
                2 => id.type2.is_some(),
                3 => id.type3.is_some(),
                _ => false,
            };
            if duplicate {
                return Err(Error::Format(format!(
                    "identity contains more than one type {typ} block"
                )));
            }
            match typ {
                1 => id.type1 = Some(Type1Block::parse(block)?),
                2 => id.type2 = Some(Type2Block::parse(block)?),
                3 => id.type3 = Some(Type3Block::parse(block)?),
                _ => id.unknown.push(block.to_vec()),
            }
            data = &data[len..];
        }
        if data.iter().any(|b| *b != 0) {
            return Err(Error::Format("trailing garbage after last block".into()));
        }
        if id.type1.is_none() && id.type2.is_none() {
            return Err(Error::Format(
                "identity contains neither a password nor a rescue block".into(),
            ));
        }
        Ok(id)
    }

    /// Serialize the blocks (type 1, 2, 3, then unknown) without a header.
    pub fn blocks_to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        if let Some(b) = &self.type1 {
            v.extend(b.to_bytes());
        }
        if let Some(b) = &self.type2 {
            v.extend(b.to_bytes());
        }
        if let Some(b) = &self.type3 {
            v.extend(b.to_bytes());
        }
        for u in &self.unknown {
            v.extend_from_slice(u);
        }
        v
    }

    /// The type 2 + type 3 blocks only: what the textual identity and the rescue-only export
    /// contain. (Type 1 is omitted because it is tied to the password of this installation.)
    pub fn rescue_blocks_to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        if let Some(b) = &self.type2 {
            v.extend(b.to_bytes());
        }
        if let Some(b) = &self.type3 {
            v.extend(b.to_bytes());
        }
        v
    }

    /// Binary `sqrldata` file.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = HEADER_BINARY.to_vec();
        v.extend(self.blocks_to_bytes());
        v
    }

    /// Textual `SQRLDATA` + base64url representation.
    pub fn to_text(&self) -> String {
        format!("SQRLDATA{}", b64u_encode(&self.blocks_to_bytes()))
    }

    /// A copy containing only the rescue (type 2) and previous (type 3) blocks.
    pub fn rescue_only(&self) -> Self {
        Self {
            type1: None,
            type2: self.type2.clone(),
            type3: self.type3.clone(),
            unknown: Vec::new(),
        }
    }

    /// Settings from the type 1 block, or defaults.
    pub fn settings(&self) -> IdentitySettings {
        self.type1
            .as_ref()
            .map(|b| b.settings.clone())
            .unwrap_or_default()
    }

    /// The identity's edition: 0 for a never re-keyed identity, else the type 3 counter.
    pub fn edition(&self) -> u16 {
        self.type3.as_ref().map(|b| b.edition).unwrap_or(0)
    }

    /// Derive the password key (slow). `progress(done)` reports completed EnScrypt iterations
    /// out of `type1.iterations`.
    pub fn derive_password_key(
        &self,
        password: &str,
        progress: impl FnMut(u32),
    ) -> Result<[u8; 32]> {
        let t1 = self
            .type1
            .as_ref()
            .ok_or_else(|| Error::Format("identity has no password block".into()))?;
        Ok(t1.derive_key(password, progress))
    }

    /// Unlock the identity with an already-derived password key.
    pub fn unlock_with_key(&self, key: &[u8; 32]) -> Result<UnlockedIdentity> {
        let t1 = self
            .type1
            .as_ref()
            .ok_or_else(|| Error::Format("identity has no password block".into()))?;
        let (imk, ilk) = t1.decrypt_with_key(key)?;
        let previous = match &self.type3 {
            Some(t3) => t3.decrypt(&imk)?,
            None => Vec::new(),
        };
        Ok(UnlockedIdentity::new(imk, ilk, previous))
    }

    /// Unlock the identity with the password (slow).
    pub fn unlock(&self, password: &str, progress: impl FnMut(u32)) -> Result<UnlockedIdentity> {
        let mut key = self.derive_password_key(password, progress)?;
        let r = self.unlock_with_key(&key);
        key.zeroize();
        r
    }

    /// Decrypt the IUK with the rescue code (slow).
    pub fn unlock_iuk(&self, rescue_code: &str, progress: impl FnMut(u32)) -> Result<[u8; 32]> {
        let t2 = self
            .type2
            .as_ref()
            .ok_or_else(|| Error::Format("identity has no rescue code block".into()))?;
        t2.decrypt(rescue_code, progress)
    }

    /// Create a complete new identity file from an IUK.
    ///
    /// `rescue_duration_ms` controls how long EnScrypt runs for the rescue block (the
    /// reference client uses a long time because the rescue code is only 24 digits).
    pub fn create(
        iuk: &[u8; 32],
        password: &str,
        rescue_code: &str,
        settings: IdentitySettings,
        rescue_duration_ms: u64,
        mut now_ms: impl FnMut() -> u64,
        mut progress: impl FnMut(&str, u64, u64),
    ) -> Result<Self> {
        let mut imk = imk_from_iuk(iuk);
        let mut ilk = ilk_from_iuk(iuk);
        let type1 = Type1Block::encrypt(
            &imk,
            &ilk,
            password,
            settings.clone(),
            &mut now_ms,
            |a, b| progress("password", a, b),
        );
        let type2 = Type2Block::encrypt(
            iuk,
            rescue_code,
            settings.log_n,
            rescue_duration_ms,
            &mut now_ms,
            |a, b| progress("rescue", a, b),
        )?;
        imk.zeroize();
        ilk.zeroize();
        Ok(Self {
            type1: Some(type1),
            type2: Some(type2),
            type3: None,
            unknown: Vec::new(),
        })
    }

    /// Re-encrypt the type 1 (and type 3) blocks for an unlocked identity under a new
    /// password / settings. Used for password changes, settings changes and after importing a
    /// rescue-only identity.
    pub fn set_password(
        &mut self,
        identity: &UnlockedIdentity,
        password: &str,
        settings: IdentitySettings,
        now_ms: impl FnMut() -> u64,
        progress: impl FnMut(u64, u64),
    ) {
        self.type1 = Some(Type1Block::encrypt(
            &identity.imk,
            &identity.ilk,
            password,
            settings,
            now_ms,
            progress,
        ));
        let edition = self.edition().max(identity.previous_iuks.len() as u16);
        self.type3 = Type3Block::encrypt(&identity.previous_iuks, &identity.imk, edition);
    }

    /// Re-key the identity: a new IUK is generated, the old IUK (recovered with the old rescue
    /// code) moves to the front of the previous-identity list, and new type 1 / 2 / 3 blocks
    /// are produced for `new_password` and `new_rescue_code`.
    ///
    /// Returns the new unlocked identity (with the previous IUKs) and the new IUK.
    #[allow(clippy::too_many_arguments)]
    pub fn rekey(
        &mut self,
        old_identity: &UnlockedIdentity,
        old_iuk: &[u8; 32],
        new_iuk: &[u8; 32],
        new_password: &str,
        new_rescue_code: &str,
        settings: IdentitySettings,
        rescue_duration_ms: u64,
        mut now_ms: impl FnMut() -> u64,
        mut progress: impl FnMut(&str, u64, u64),
    ) -> Result<UnlockedIdentity> {
        let mut previous = Vec::with_capacity(MAX_PREVIOUS_KEYS);
        previous.push(*old_iuk);
        for k in old_identity
            .previous_iuks
            .iter()
            .take(MAX_PREVIOUS_KEYS - 1)
        {
            previous.push(*k);
        }
        let mut new_identity = UnlockedIdentity::from_iuk(new_iuk);
        new_identity.previous_iuks = previous;
        let type1 = Type1Block::encrypt(
            &new_identity.imk,
            &new_identity.ilk,
            new_password,
            settings.clone(),
            &mut now_ms,
            |a, b| progress("password", a, b),
        );
        let type2 = Type2Block::encrypt(
            new_iuk,
            new_rescue_code,
            settings.log_n,
            rescue_duration_ms,
            &mut now_ms,
            |a, b| progress("rescue", a, b),
        )?;
        let edition = self.edition().saturating_add(1);
        self.type1 = Some(type1);
        self.type2 = Some(type2);
        self.type3 = Type3Block::encrypt(&new_identity.previous_iuks, &new_identity.imk, edition);
        Ok(new_identity)
    }
}

/// Generate a new 24-digit rescue code from 256 bits of entropy.
///
/// Digits are extracted by repeated long division of the 256-bit number by 10 (i.e. the
/// code is `entropy mod 10^24`, which is uniform to within 2^-176).
pub fn generate_rescue_code() -> String {
    let mut entropy: [u8; 32] = random_array();
    let code = rescue_code_from_entropy(&entropy);
    entropy.zeroize();
    code
}

/// Deterministic core of [`generate_rescue_code`].
pub fn rescue_code_from_entropy(entropy: &[u8; 32]) -> String {
    let mut num = entropy.to_vec(); // big-endian
    let mut digits = [0u8; 24];
    for d in digits.iter_mut() {
        let mut rem = 0u32;
        for byte in num.iter_mut() {
            let cur = (rem << 8) | *byte as u32;
            *byte = (cur / 10) as u8;
            rem = cur % 10;
        }
        *d = b'0' + rem as u8;
    }
    num.zeroize();
    String::from_utf8(digits.to_vec()).unwrap()
}

/// Strip separators and whitespace from a rescue code and verify it has 24 digits.
pub fn normalize_rescue_code(code: &str) -> Result<String> {
    let digits: String = code.chars().filter(|c| c.is_ascii_digit()).collect();
    let non_digits = code
        .chars()
        .any(|c| !c.is_ascii_digit() && !c.is_ascii_whitespace() && c != '-');
    if digits.len() != 24 || non_digits {
        return Err(Error::Format("a rescue code is 24 decimal digits".into()));
    }
    Ok(digits)
}

/// Format a rescue code as six groups of four digits separated by dashes.
pub fn format_rescue_code(code: &str) -> String {
    code.as_bytes()
        .chunks(4)
        .map(|c| core::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("-")
}

fn trim_ascii(b: &[u8]) -> &[u8] {
    let start = b
        .iter()
        .position(|c| !c.is_ascii_whitespace())
        .unwrap_or(b.len());
    let end = b
        .iter()
        .rposition(|c| !c.is_ascii_whitespace())
        .map(|i| i + 1)
        .unwrap_or(start);
    &b[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::enhash;
    use crate::util::hex_decode;

    /// A real identity file (from the open-source Android SQRL client's test code) with the
    /// password `Testing1234` and rescue code `7276-0587-2230-1119-8559-3839`.
    const TEST_IDENTITY_HEX: &str = "7371726c646174617d0001002d00b51fd99559b887d106a8d877c70133bb20a12fa1a7c829b194db94f309c5000000f30104050f000d174cc6e7b70baa158aa4ce75e2f2b99a02a40e4beb2e5d16c2f03442bd3e932035419a63885a663125a600e5486c42b38f708c1094ced1ab0b0050137f6df449caf78581fec678408a804caf74f91c490002005528fc85e3e36866a85574146fe7776d09cf0000004a4e12277dd48366fc1f335dd37188bbcba02bc32a12aef0188f5e83593665518483d638b80051c2b4b013491eb06835";

    fn test_identity() -> S4Identity {
        S4Identity::parse(&hex_decode(TEST_IDENTITY_HEX).unwrap()).unwrap()
    }

    #[test]
    fn parse_and_roundtrip_reference_identity() {
        let bytes = hex_decode(TEST_IDENTITY_HEX).unwrap();
        let id = S4Identity::parse(&bytes).unwrap();
        let t1 = id.type1.as_ref().unwrap();
        assert_eq!(t1.iterations, 197);
        assert_eq!(t1.settings.log_n, 9);
        assert_eq!(t1.settings.option_flags, 0x01f3);
        assert_eq!(t1.settings.hint_length, 4);
        assert_eq!(t1.settings.pw_verify_seconds, 5);
        assert_eq!(t1.settings.idle_timeout_minutes, 15);
        let t2 = id.type2.as_ref().unwrap();
        assert_eq!(t2.iterations, 207);
        assert!(id.type3.is_none());
        assert_eq!(id.to_bytes(), bytes);
        // textual form round trip
        let text = id.to_text();
        assert!(text.starts_with("SQRLDATA"));
        assert_eq!(S4Identity::parse(text.as_bytes()).unwrap(), id);
    }

    #[test]
    fn unlock_reference_identity_with_password() {
        let id = test_identity();
        assert!(id.unlock("wrong password", |_| {}).is_err());
        let unlocked = id.unlock("Testing1234", |_| {}).unwrap();
        assert_eq!(unlocked.previous_count(), 0);
        // Decrypting the IUK with the rescue code must reproduce the same IMK and ILK.
        let iuk = id
            .unlock_iuk("7276-0587-2230-1119-8559-3839", |_| {})
            .unwrap();
        assert_eq!(enhash(&iuk), unlocked.imk);
        assert_eq!(ilk_from_iuk(&iuk), unlocked.ilk);
    }

    #[test]
    fn bad_rescue_code_is_rejected() {
        let id = test_identity();
        assert!(id
            .unlock_iuk("0000-0000-0000-0000-0000-0000", |_| {})
            .is_err());
        assert!(id.unlock_iuk("1234", |_| {}).is_err());
    }

    fn fake_clock() -> impl FnMut() -> u64 {
        let mut t = 0u64;
        move || {
            t += 1000;
            t
        }
    }

    #[test]
    fn create_change_password_and_rekey() {
        let iuk = [11u8; 32];
        let mut settings = IdentitySettings::default();
        settings.pw_verify_seconds = 1;
        let rescue = "1234-5678-9012-3456-7890-1234";
        let mut id = S4Identity::create(
            &iuk,
            "hunter2",
            rescue,
            settings.clone(),
            1,
            fake_clock(),
            |_, _, _| {},
        )
        .unwrap();
        let unlocked = id.unlock("hunter2", |_| {}).unwrap();
        assert_eq!(unlocked.imk, imk_from_iuk(&iuk));
        assert_eq!(id.unlock_iuk(rescue, |_| {}).unwrap(), iuk);

        // change password
        id.set_password(
            &unlocked,
            "correct horse",
            settings.clone(),
            fake_clock(),
            |_, _| {},
        );
        assert!(id.unlock("hunter2", |_| {}).is_err());
        let unlocked2 = id.unlock("correct horse", |_| {}).unwrap();
        assert_eq!(unlocked2.imk, unlocked.imk);

        // rekey
        let new_iuk = [12u8; 32];
        let new_rescue = "0000-1111-2222-3333-4444-5555";
        let rekeyed = id
            .rekey(
                &unlocked2,
                &iuk,
                &new_iuk,
                "pw3",
                new_rescue,
                settings.clone(),
                1,
                fake_clock(),
                |_, _, _| {},
            )
            .unwrap();
        assert_eq!(rekeyed.previous_iuks, vec![iuk]);
        let reloaded = S4Identity::parse(&id.to_bytes()).unwrap();
        let unlocked3 = reloaded.unlock("pw3", |_| {}).unwrap();
        assert_eq!(unlocked3.imk, imk_from_iuk(&new_iuk));
        assert_eq!(unlocked3.previous_iuks, vec![iuk]);
        assert_eq!(reloaded.unlock_iuk(new_rescue, |_| {}).unwrap(), new_iuk);
        assert_eq!(reloaded.type3.as_ref().unwrap().len(), 54);

        // rekey three more times: only four previous keys are kept
        let mut cur_iuk = new_iuk;
        let mut cur_unlocked = unlocked3;
        for i in 20u8..24 {
            let next = [i; 32];
            cur_unlocked = id
                .rekey(
                    &cur_unlocked,
                    &cur_iuk,
                    &next,
                    "pw",
                    new_rescue,
                    settings.clone(),
                    1,
                    fake_clock(),
                    |_, _, _| {},
                )
                .unwrap();
            cur_iuk = next;
        }
        assert_eq!(cur_unlocked.previous_iuks.len(), 4);
        assert_eq!(cur_unlocked.previous_iuks[0], [22u8; 32]);
        assert_eq!(cur_unlocked.previous_iuks[3], [new_iuk[0]; 32]);
        let reloaded = S4Identity::parse(&id.to_bytes()).unwrap();
        assert_eq!(reloaded.type3.as_ref().unwrap().len(), 150);
        assert_eq!(
            reloaded.unlock("pw", |_| {}).unwrap().previous_iuks,
            cur_unlocked.previous_iuks
        );
        // five re-keyings in total: the edition keeps counting past the four stored keys
        assert_eq!(reloaded.edition(), 5);
    }

    #[test]
    fn duplicate_blocks_are_rejected() {
        let id = test_identity();
        let mut bytes = id.to_bytes();
        let t2 = id.type2.as_ref().unwrap().to_bytes();
        bytes.extend_from_slice(&t2);
        assert!(S4Identity::parse(&bytes).is_err());
    }

    #[test]
    fn password_is_nfkc_normalized() {
        // U+FB01 (ﬁ ligature) normalizes to "fi"; U+212B (Å angstrom sign) to U+00C5.
        assert_eq!(normalize_password("\u{FB01}sh \u{212B}"), "fish \u{C5}");
        let iuk = [3u8; 32];
        let mut settings = IdentitySettings::default();
        settings.pw_verify_seconds = 1;
        let id = S4Identity::create(
            &iuk,
            "\u{FB01}sh",
            "1234-5678-9012-3456-7890-1234",
            settings,
            1,
            fake_clock(),
            |_, _, _| {},
        )
        .unwrap();
        assert!(id.unlock("fish", |_| {}).is_ok());
    }

    #[test]
    fn unknown_blocks_are_preserved() {
        let id = test_identity();
        let mut bytes = id.to_bytes();
        bytes.extend_from_slice(&[9, 0, 7, 0, 1, 2, 3, 4, 5]); // 9-byte block of type 7
        let parsed = S4Identity::parse(&bytes).unwrap();
        assert_eq!(parsed.unknown.len(), 1);
        assert_eq!(parsed.to_bytes(), bytes);
    }

    #[test]
    fn rescue_code_generation() {
        let code = generate_rescue_code();
        assert_eq!(code.len(), 24);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(
            rescue_code_from_entropy(&[0u8; 32]),
            "000000000000000000000000"
        );
        // 2^256 mod 10^24, with digits least-significant first.
        let mut e = [0u8; 32];
        e[31] = 1;
        assert_eq!(rescue_code_from_entropy(&e), "100000000000000000000000");
        assert_eq!(
            format_rescue_code("123456789012345678901234"),
            "1234-5678-9012-3456-7890-1234"
        );
        assert_eq!(
            normalize_rescue_code(" 1234-5678 9012-3456-7890-1234 ").unwrap(),
            "123456789012345678901234"
        );
        assert!(normalize_rescue_code("1234-5678-9012-3456-7890-12x4").is_err());
    }
}
