//! Small helpers: base64url (no padding), hex, random bytes, little-endian integers.

use crate::{Error, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

/// Encode bytes as base64url without padding (the only base64 variant SQRL uses).
pub fn b64u_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decode base64url. Padding characters and ASCII whitespace are tolerated and ignored,
/// as the SQRL storage spec requires for the textual `SQRLDATA` form.
pub fn b64u_decode(text: &str) -> Result<Vec<u8>> {
    let cleaned: String = text
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != '=')
        .collect();
    URL_SAFE_NO_PAD
        .decode(cleaned.as_bytes())
        .map_err(|e| Error::Format(format!("invalid base64url: {e}")))
}

/// Decode base64url into a fixed-size array.
pub fn b64u_decode_array<const N: usize>(text: &str) -> Result<[u8; N]> {
    let v = b64u_decode(text)?;
    v.as_slice()
        .try_into()
        .map_err(|_| Error::Format(format!("expected {N} bytes, got {}", v.len())))
}

/// Lower-case hex encoding.
pub fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Hex decoding (case-insensitive, whitespace ignored).
pub fn hex_decode(text: &str) -> Result<Vec<u8>> {
    let cleaned: Vec<u8> = text
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if cleaned.len() % 2 != 0 {
        return Err(Error::Format("odd-length hex string".into()));
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for pair in cleaned.chunks(2) {
        let s = core::str::from_utf8(pair).map_err(|_| Error::Format("bad hex".into()))?;
        out.push(u8::from_str_radix(s, 16).map_err(|_| Error::Format("bad hex".into()))?);
    }
    Ok(out)
}

/// Fill a buffer with cryptographically secure random bytes from the platform RNG.
pub fn random_bytes(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("platform RNG unavailable");
}

/// Return `N` random bytes.
pub fn random_array<const N: usize>() -> [u8; N] {
    let mut a = [0u8; N];
    random_bytes(&mut a);
    a
}

pub(crate) fn le_u16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}

pub(crate) fn le_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// XOR `b` into `a`.
pub(crate) fn xor_into(a: &mut [u8], b: &[u8]) {
    for (x, y) in a.iter_mut().zip(b) {
        *x ^= *y;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_roundtrip() {
        let data = [0u8, 1, 2, 250, 251, 252, 253, 254, 255];
        let enc = b64u_encode(&data);
        assert!(!enc.contains('='));
        assert!(!enc.contains('+'));
        assert!(!enc.contains('/'));
        assert_eq!(b64u_decode(&enc).unwrap(), data);
        // tolerant decoding
        assert_eq!(b64u_decode(" AAEC\n -vv8 _f7_ == ").unwrap(), data);
    }

    #[test]
    fn hex_roundtrip() {
        assert_eq!(hex_decode("00ff10Ab").unwrap(), vec![0, 255, 16, 171]);
        assert_eq!(hex_encode(&[0, 255, 16, 171]), "00ff10ab");
    }
}
