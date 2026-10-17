//! The unlocked, in-memory identity and all key derivations that flow from it.
//!
//! Key names follow the SQRL specification:
//!
//! * **IUK** – Identity Unlock Key: the 256-bit root secret. Only ever available after the
//!   user enters their rescue code. Needed to `enable`/`remove` an account, and to re-key.
//! * **IMK** – Identity Master Key = `EnHash(IUK)`. Used to derive every per-site key.
//! * **ILK** – Identity Lock Key = `X25519(IUK, basepoint)`. Given to sites (via SUK/VUK) so
//!   that a future unlock request can be verified.
//! * Per-site key seed = `HMAC-SHA256(key = IMK, msg = site key string)`; the Ed25519 key
//!   pair derived from that seed is the site's identity (`idk` / `ids`).
//! * **INK** – Indexed secret key = `EnHash(per-site seed)`; `ins = HMAC(INK, sin)`.
//! * **RLK/SUK/VUK** – per-account identity lock values; see [`UnlockedIdentity::make_lock`].
//! * **URSK** – Unlock Request Signing Key = Ed25519 key with seed `X25519(IUK, SUK)`.

use crate::crypto::{ed25519_public, enhash, hmac_sha256, x25519, x25519_base};
use crate::util::random_array;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Identity Master Key derived from an Identity Unlock Key.
pub fn imk_from_iuk(iuk: &[u8; 32]) -> [u8; 32] {
    enhash(iuk)
}

/// Identity Lock Key derived from an Identity Unlock Key.
pub fn ilk_from_iuk(iuk: &[u8; 32]) -> [u8; 32] {
    x25519_base(iuk)
}

/// Per-site Ed25519 seed (the "private key" in SQRL parlance) from a master key.
pub fn site_seed(imk: &[u8; 32], site_key: &[u8]) -> [u8; 32] {
    hmac_sha256(imk, site_key)
}

/// Indexed-secret response: `ins = HMAC-SHA256(key = EnHash(site seed), msg = sin)`.
pub fn indexed_secret(site_seed: &[u8; 32], sin: &[u8]) -> [u8; 32] {
    let ink = enhash(site_seed);
    hmac_sha256(&ink, sin)
}

/// The identity-lock values a client sends to a server when creating (or re-keying) an
/// account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerLock {
    /// Server Unlock Key: `X25519(RLK, basepoint)`.
    pub suk: [u8; 32],
    /// Verify Unlock Key: Ed25519 public key with seed `X25519(RLK, ILK)`.
    pub vuk: [u8; 32],
}

/// Generate SUK/VUK for an Identity Lock Key using a fresh Random Lock Key.
pub fn make_server_lock(ilk: &[u8; 32]) -> ServerLock {
    let rlk: [u8; 32] = random_array();
    make_server_lock_with_rlk(ilk, &rlk)
}

/// Deterministic variant of [`make_server_lock`] (for tests).
pub fn make_server_lock_with_rlk(ilk: &[u8; 32], rlk: &[u8; 32]) -> ServerLock {
    let suk = x25519_base(rlk);
    let mut dhk = x25519(rlk, ilk);
    let vuk = ed25519_public(&dhk);
    dhk.zeroize();
    ServerLock { suk, vuk }
}

/// Unlock Request Signing Key seed: `X25519(IUK, SUK)`. Its Ed25519 public key equals the
/// VUK the server stored, which is what lets the server verify a `urs` signature.
pub fn unlock_request_seed(iuk: &[u8; 32], suk: &[u8; 32]) -> [u8; 32] {
    x25519(iuk, suk)
}

/// A decrypted identity held in memory.
///
/// `previous_iuks` are ordered most-recent first (edition order of the S4 type 3 block).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct UnlockedIdentity {
    /// Identity Master Key.
    pub imk: [u8; 32],
    /// Identity Lock Key.
    pub ilk: [u8; 32],
    /// Previous Identity Unlock Keys (up to four), most recent first.
    pub previous_iuks: Vec<[u8; 32]>,
}

impl core::fmt::Debug for UnlockedIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UnlockedIdentity")
            .field("previous_iuks", &self.previous_iuks.len())
            .finish_non_exhaustive()
    }
}

impl UnlockedIdentity {
    /// Build from master and lock keys plus any previous unlock keys.
    pub fn new(imk: [u8; 32], ilk: [u8; 32], previous_iuks: Vec<[u8; 32]>) -> Self {
        Self { imk, ilk, previous_iuks }
    }

    /// Build a brand-new identity from an Identity Unlock Key.
    pub fn from_iuk(iuk: &[u8; 32]) -> Self {
        Self::new(imk_from_iuk(iuk), ilk_from_iuk(iuk), Vec::new())
    }

    /// Per-site Ed25519 seed for the current identity.
    pub fn site_seed(&self, site_key: &[u8]) -> [u8; 32] {
        site_seed(&self.imk, site_key)
    }

    /// Per-site Ed25519 public key (`idk`) for the current identity.
    pub fn site_public_key(&self, site_key: &[u8]) -> [u8; 32] {
        let mut seed = self.site_seed(site_key);
        let pk = ed25519_public(&seed);
        seed.zeroize();
        pk
    }

    /// Number of previous identities available.
    pub fn previous_count(&self) -> usize {
        self.previous_iuks.len()
    }

    /// Per-site Ed25519 seed for previous identity `index` (0 = most recent).
    pub fn previous_site_seed(&self, index: usize, site_key: &[u8]) -> Option<[u8; 32]> {
        let iuk = self.previous_iuks.get(index)?;
        let mut pimk = imk_from_iuk(iuk);
        let seed = site_seed(&pimk, site_key);
        pimk.zeroize();
        Some(seed)
    }

    /// Per-site public key (`pidk`) for previous identity `index`.
    pub fn previous_site_public_key(&self, index: usize, site_key: &[u8]) -> Option<[u8; 32]> {
        let mut seed = self.previous_site_seed(index, site_key)?;
        let pk = ed25519_public(&seed);
        seed.zeroize();
        Some(pk)
    }

    /// Generate the SUK/VUK pair for a new account association on a server.
    pub fn make_lock(&self) -> ServerLock {
        make_server_lock(&self.ilk)
    }

    /// Unlock request signing seed using a previous identity's IUK (used when re-keying an
    /// account that is still associated with a previous identity).
    pub fn previous_unlock_request_seed(&self, index: usize, suk: &[u8; 32]) -> Option<[u8; 32]> {
        let iuk = self.previous_iuks.get(index)?;
        Some(unlock_request_seed(iuk, suk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{ed25519_sign, ed25519_verify};

    #[test]
    fn identity_lock_roundtrip() {
        // The whole point of the identity lock: a signature made with the URSK (which needs
        // the IUK) must verify under the VUK the server was given at account creation (which
        // only needed the ILK).
        let iuk = [42u8; 32];
        let id = UnlockedIdentity::from_iuk(&iuk);
        let lock = id.make_lock();
        let ursk = unlock_request_seed(&iuk, &lock.suk);
        let sig = ed25519_sign(&ursk, b"unlock me");
        ed25519_verify(&lock.vuk, b"unlock me", &sig).unwrap();

        // A different IUK cannot produce a valid unlock signature.
        let wrong = unlock_request_seed(&[43u8; 32], &lock.suk);
        let sig2 = ed25519_sign(&wrong, b"unlock me");
        assert!(ed25519_verify(&lock.vuk, b"unlock me", &sig2).is_err());
    }

    #[test]
    fn site_keys_differ_per_site_and_identity() {
        let a = UnlockedIdentity::from_iuk(&[1u8; 32]);
        let b = UnlockedIdentity::from_iuk(&[2u8; 32]);
        assert_ne!(a.site_public_key(b"example.com"), a.site_public_key(b"example.org"));
        assert_ne!(a.site_public_key(b"example.com"), b.site_public_key(b"example.com"));
        assert_eq!(a.site_public_key(b"example.com"), a.site_public_key(b"example.com"));
    }

    #[test]
    fn previous_identity_keys() {
        let old_iuk = [5u8; 32];
        let old = UnlockedIdentity::from_iuk(&old_iuk);
        let mut new = UnlockedIdentity::from_iuk(&[6u8; 32]);
        new.previous_iuks.push(old_iuk);
        assert_eq!(
            new.previous_site_public_key(0, b"example.com").unwrap(),
            old.site_public_key(b"example.com")
        );
        assert!(new.previous_site_public_key(1, b"example.com").is_none());
    }
}
