//! Cryptographic primitives used by SQRL.
//!
//! * **EnHash** – 16 chained iterations of SHA-256 whose outputs are XORed together.
//! * **EnScrypt** – scrypt (N=2^logN, r=256, p=1, dkLen=32) chained and XORed over many
//!   iterations, either for a fixed iteration count or for a fixed duration.
//! * HMAC-SHA256, AES-256-GCM, Ed25519 (via `ed25519-dalek`) and X25519 (via `x25519-dalek`).

use crate::util::xor_into;
use crate::{Error, Result};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::Zeroize;

/// scrypt `r` parameter mandated by SQRL.
pub const SCRYPT_R: u32 = 256;
/// scrypt `p` parameter mandated by SQRL.
pub const SCRYPT_P: u32 = 1;
/// Default scrypt log2(N) used by SQRL clients (N = 512).
pub const DEFAULT_LOG_N: u8 = 9;

/// SHA-256 digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// HMAC-SHA256.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// EnHash: SHA-256 is applied 16 times in a chain, and all 16 outputs are XORed together.
pub fn enhash(input: &[u8]) -> [u8; 32] {
    let mut current = sha256(input);
    let mut acc = current;
    for _ in 1..16 {
        current = sha256(&current);
        xor_into(&mut acc, &current);
    }
    current.zeroize();
    acc
}

/// One raw scrypt invocation with SQRL's parameters (r=256, p=1, dkLen=32).
pub fn scrypt_once(password: &[u8], salt: &[u8], log_n: u8) -> [u8; 32] {
    let params = scrypt::Params::new(log_n, SCRYPT_R, SCRYPT_P, 32).expect("valid scrypt params");
    let mut out = [0u8; 32];
    scrypt::scrypt(password, salt, &params, &mut out).expect("32-byte output is valid");
    out
}

/// EnScrypt with a fixed iteration count.
///
/// The first iteration uses the caller-supplied salt; each subsequent iteration uses the
/// previous iteration's output as its salt, and the final result is the XOR of every
/// iteration's output. `progress` is invoked after each completed iteration with the number
/// of iterations done so far.
pub fn enscrypt_iterations(
    password: &[u8],
    salt: &[u8],
    log_n: u8,
    iterations: u32,
    mut progress: impl FnMut(u32),
) -> [u8; 32] {
    let iterations = iterations.max(1);
    let mut key = scrypt_once(password, salt, log_n);
    let mut acc = key;
    progress(1);
    for i in 1..iterations {
        key = scrypt_once(password, &key, log_n);
        xor_into(&mut acc, &key);
        progress(i + 1);
    }
    key.zeroize();
    acc
}

/// EnScrypt for (at least) a fixed duration.
///
/// `now_ms` must return a monotonic-ish millisecond clock (e.g. `Date.now()` in the browser,
/// `Instant` on native). Returns the derived key together with the number of iterations that
/// were performed, which must be stored so the key can later be re-derived with
/// [`enscrypt_iterations`].
pub fn enscrypt_duration(
    password: &[u8],
    salt: &[u8],
    log_n: u8,
    duration_ms: u64,
    mut now_ms: impl FnMut() -> u64,
    mut progress: impl FnMut(u64, u64),
) -> ([u8; 32], u32) {
    let start = now_ms();
    let mut key = scrypt_once(password, salt, log_n);
    let mut acc = key;
    let mut iterations: u32 = 1;
    let mut elapsed = now_ms().saturating_sub(start);
    progress(elapsed, duration_ms);
    while elapsed < duration_ms && iterations < u32::MAX {
        key = scrypt_once(password, &key, log_n);
        xor_into(&mut acc, &key);
        iterations += 1;
        elapsed = now_ms().saturating_sub(start);
        progress(elapsed, duration_ms);
    }
    key.zeroize();
    (acc, iterations)
}

/// AES-256-GCM encryption. Returns ciphertext followed by the 16-byte tag.
pub fn aes_gcm_encrypt(key: &[u8; 32], iv: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(
            Nonce::from_slice(iv),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("AES-GCM encryption cannot fail for valid inputs")
}

/// AES-256-GCM decryption of `ciphertext || tag`. Fails if the tag does not verify.
pub fn aes_gcm_decrypt(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(iv),
            Payload {
                msg: ciphertext_and_tag,
                aad,
            },
        )
        .map_err(|_| Error::Crypto("authentication tag mismatch".into()))
}

/// Derive an Ed25519 signing key from a 32-byte seed (libsodium `crypto_sign_seed_keypair`).
pub fn ed25519_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

/// Public key bytes of the Ed25519 key derived from `seed`.
pub fn ed25519_public(seed: &[u8; 32]) -> [u8; 32] {
    ed25519_from_seed(seed).verifying_key().to_bytes()
}

/// Sign `msg` with the Ed25519 key derived from `seed`; returns the 64-byte signature.
pub fn ed25519_sign(seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    ed25519_from_seed(seed).sign(msg).to_bytes()
}

/// Verify an Ed25519 signature.
pub fn ed25519_verify(public: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<()> {
    let vk = VerifyingKey::from_bytes(public)
        .map_err(|e| Error::Crypto(format!("bad public key: {e}")))?;
    let sig = Signature::from_bytes(sig);
    vk.verify(msg, &sig)
        .map_err(|_| Error::Crypto("signature verification failed".into()))
}

/// X25519 base-point multiplication (libsodium `crypto_scalarmult_base`): the scalar is clamped.
pub fn x25519_base(scalar: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*scalar);
    XPublicKey::from(&secret).to_bytes()
}

/// X25519 Diffie-Hellman (libsodium `crypto_scalarmult`): the scalar is clamped.
pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*scalar);
    secret.diffie_hellman(&XPublicKey::from(*point)).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hex_decode, hex_encode};

    fn enscrypt_hex(pw: &str, salt: &[u8], iterations: u32) -> String {
        hex_encode(&enscrypt_iterations(
            pw.as_bytes(),
            salt,
            9,
            iterations,
            |_| {},
        ))
    }

    // Official EnScrypt test vectors from https://www.grc.com/sqrl/storage.htm
    #[test]
    fn enscrypt_vector_empty_1() {
        assert_eq!(
            enscrypt_hex("", b"", 1),
            "a8ea62a6e1bfd20e4275011595307aa302645c1801600ef5cd79bf9d884d911c"
        );
    }

    #[test]
    fn enscrypt_vector_empty_100() {
        assert_eq!(
            enscrypt_hex("", b"", 100),
            "45a42a01709a0012a37b7b6874cf16623543409d19e7740ed96741d2e99aab67"
        );
    }

    #[test]
    fn enscrypt_vector_password_123() {
        assert_eq!(
            enscrypt_hex("password", b"", 123),
            "129d96d1e735618517259416a605be7094c2856a53c14ef7d4e4ba8e4ea36aeb"
        );
    }

    #[test]
    fn enscrypt_vector_password_salt_123() {
        let salt =
            hex_decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        assert_eq!(
            enscrypt_hex("password", &salt, 123),
            "2f30b9d4e5c48056177ff90a6cc9da04b648a7e8451dfa60da56c148187f6a7d"
        );
    }

    #[test]
    fn enscrypt_duration_matches_iterations() {
        let mut t = 0u64;
        let clock = || {
            t += 30;
            t
        };
        let (key, iters) = enscrypt_duration(b"pw", b"salt", 9, 100, clock, |_, _| {});
        assert!(iters >= 2);
        let again = enscrypt_iterations(b"pw", b"salt", 9, iters, |_| {});
        assert_eq!(key, again);
    }

    #[test]
    fn enhash_is_deterministic_and_differs_from_sha256() {
        let x = enhash(b"hello");
        assert_eq!(x, enhash(b"hello"));
        assert_ne!(x, sha256(b"hello"));
    }

    #[test]
    fn aes_gcm_roundtrip_and_tamper() {
        let key = [7u8; 32];
        let iv = [9u8; 12];
        let ct = aes_gcm_encrypt(&key, &iv, b"aad", b"secret");
        assert_eq!(ct.len(), 6 + 16);
        assert_eq!(aes_gcm_decrypt(&key, &iv, b"aad", &ct).unwrap(), b"secret");
        assert!(aes_gcm_decrypt(&key, &iv, b"xad", &ct).is_err());
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(aes_gcm_decrypt(&key, &iv, b"aad", &bad).is_err());
    }

    #[test]
    fn ed25519_sign_verify() {
        let seed = [3u8; 32];
        let pk = ed25519_public(&seed);
        let sig = ed25519_sign(&seed, b"msg");
        ed25519_verify(&pk, b"msg", &sig).unwrap();
        assert!(ed25519_verify(&pk, b"msh", &sig).is_err());
    }

    #[test]
    fn x25519_agreement() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(x25519(&a, &x25519_base(&b)), x25519(&b, &x25519_base(&a)));
        // RFC 7748 test vector for the base point multiplication
        let alice =
            hex_decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a").unwrap();
        let alice_pub = x25519_base(alice.as_slice().try_into().unwrap());
        assert_eq!(
            hex_encode(&alice_pub),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
    }
}
