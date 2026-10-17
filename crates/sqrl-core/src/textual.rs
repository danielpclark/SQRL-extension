//! The base56 "textual identity" format.
//!
//! The rescue (type 2) and previous-identity (type 3) blocks are treated as one
//! little-endian number and written in base56 (digits `2-9`, upper-case letters without
//! `I` and `O`, lower-case letters without `l` and `o`). After every 19 characters a check
//! character is inserted: `SHA-256(19 chars || line number)` interpreted as a little-endian
//! number, modulo 56. For display the characters are grouped in fours, five groups per line.

use crate::crypto::sha256;
use crate::{Error, Result};

/// The base56 alphabet.
pub const ALPHABET: &[u8; 56] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz";
const CHARS_PER_LINE: usize = 19;
const LOG2_56: f64 = 5.807_354_922_057_604;

fn alphabet_index(c: u8) -> Option<u8> {
    ALPHABET.iter().position(|a| *a == c).map(|i| i as u8)
}

/// Divide a little-endian big number in place by 56 and return the remainder.
fn divmod56(num: &mut [u8]) -> u8 {
    let mut rem: u32 = 0;
    for byte in num.iter_mut().rev() {
        let cur = (rem << 8) | *byte as u32;
        *byte = (cur / 56) as u8;
        rem = cur % 56;
    }
    rem as u8
}

fn check_char(line_chars: &[u8], line: u8) -> u8 {
    let mut input = line_chars.to_vec();
    input.push(line);
    let digest = sha256(&input);
    // Interpret the digest as a little-endian number and reduce mod 56.
    let mut rem: u32 = 0;
    for byte in digest.iter().rev() {
        rem = ((rem << 8) | *byte as u32) % 56;
    }
    ALPHABET[rem as usize]
}

/// Encode bytes into the raw textual identity string (check characters included, no spacing).
pub fn encode(data: &[u8]) -> String {
    let expected_len = ((data.len() * 8) as f64 / LOG2_56).ceil() as usize;
    let mut num = data.to_vec();
    let mut out = Vec::with_capacity(expected_len + expected_len / CHARS_PER_LINE + 1);
    let mut line_chars: Vec<u8> = Vec::with_capacity(CHARS_PER_LINE);
    let mut line: u8 = 0;
    for _ in 0..expected_len {
        if line_chars.len() == CHARS_PER_LINE {
            out.push(check_char(&line_chars, line));
            line_chars.clear();
            line = line.wrapping_add(1);
        }
        let c = if num.iter().all(|b| *b == 0) {
            ALPHABET[0]
        } else {
            ALPHABET[divmod56(&mut num) as usize]
        };
        out.push(c);
        line_chars.push(c);
    }
    out.push(check_char(&line_chars, line));
    String::from_utf8(out).unwrap()
}

/// Format a raw textual identity for display: groups of four, five groups per line.
pub fn format_for_display(raw: &str) -> String {
    let chars: Vec<char> = raw.chars().collect();
    let mut s = String::with_capacity(raw.len() * 5 / 4 + 8);
    for (i, c) in chars.iter().enumerate() {
        if i > 0 {
            if i % 20 == 0 {
                s.push('\n');
            } else if i % 4 == 0 {
                s.push(' ');
            }
        }
        s.push(*c);
    }
    s
}

/// Decode a textual identity (whitespace and dashes are ignored) into the block bytes.
///
/// Returns `Err` naming the (1-based) line whose check character failed.
pub fn decode(text: &str) -> Result<Vec<u8>> {
    let cleaned: Vec<u8> = text
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'-')
        .collect();
    if cleaned.is_empty() {
        return Err(Error::Format("empty textual identity".into()));
    }
    // Every character must be from the alphabet (this also catches 0, 1, I, O, l, o typos).
    for &c in &cleaned {
        if alphabet_index(c).is_none() {
            return Err(Error::Format(format!(
                "invalid character '{}' in textual identity",
                c as char
            )));
        }
    }
    // Split into data characters and check characters: every 20th char (and the final char)
    // is a check char.
    let total = cleaned.len();
    let mut data_chars: Vec<u8> = Vec::with_capacity(total);
    let mut line_chars: Vec<u8> = Vec::with_capacity(CHARS_PER_LINE);
    let mut line: u8 = 0;
    for (i, &c) in cleaned.iter().enumerate() {
        let is_check = line_chars.len() == CHARS_PER_LINE || i == total - 1;
        if is_check {
            if c != check_char(&line_chars, line) {
                return Err(Error::Format(format!(
                    "check character mismatch on line {}",
                    line as usize + 1
                )));
            }
            line_chars.clear();
            line = line.wrapping_add(1);
        } else {
            data_chars.push(c);
            line_chars.push(c);
        }
    }
    let expected_bytes = ((data_chars.len() as f64) * LOG2_56 / 8.0).floor() as usize;
    // Rebuild the little-endian number: num = sum(digit_i * 56^i).
    let mut num: Vec<u8> = vec![0u8; expected_bytes + 2];
    for &c in data_chars.iter().rev() {
        // num = num * 56 + digit
        let mut carry: u32 = alphabet_index(c).unwrap() as u32;
        for byte in num.iter_mut() {
            let cur = *byte as u32 * 56 + carry;
            *byte = (cur & 0xff) as u8;
            carry = cur >> 8;
        }
        if carry != 0 {
            return Err(Error::Format("textual identity value out of range".into()));
        }
    }
    if num[expected_bytes..].iter().any(|b| *b != 0) {
        return Err(Error::Format("textual identity value out of range".into()));
    }
    num.truncate(expected_bytes);
    Ok(num)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::random_bytes;

    #[test]
    fn alphabet_is_well_formed() {
        assert_eq!(ALPHABET.len(), 56);
        for bad in b"01IOlo" {
            assert!(alphabet_index(*bad).is_none());
        }
        let mut sorted = ALPHABET.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 56);
    }

    #[test]
    fn roundtrip_various_lengths() {
        for len in [1usize, 2, 19, 20, 73, 127, 159, 191, 223] {
            let mut data = vec![0u8; len];
            random_bytes(&mut data);
            let enc = encode(&data);
            assert_eq!(
                enc.len(),
                ((len * 8) as f64 / LOG2_56).ceil() as usize
                    + (((len * 8) as f64 / LOG2_56).ceil() as usize).div_ceil(19)
            );
            let dec = decode(&enc).unwrap();
            assert_eq!(dec, data, "len {len}");
            let shown = format_for_display(&enc);
            assert_eq!(decode(&shown).unwrap(), data);
        }
    }

    #[test]
    fn leading_zero_bytes_survive() {
        let data = [0u8, 0, 0, 5, 0, 0, 0, 0];
        assert_eq!(decode(&encode(&data)).unwrap(), data);
        let data = [0u8; 73];
        assert_eq!(decode(&encode(&data)).unwrap(), data);
    }

    #[test]
    fn check_characters_catch_typos() {
        let data = [7u8; 73];
        let enc = encode(&data);
        let mut bytes = enc.into_bytes();
        // Swap the first two characters (both data chars on line 1).
        bytes.swap(0, 1);
        let err = decode(core::str::from_utf8(&bytes).unwrap()).unwrap_err();
        assert!(format!("{err}").contains("line 1"), "{err}");
    }

    #[test]
    fn android_sample_text_validates() {
        // Sample textual identity found in the Android client's test harness.
        let s = "KB3Z 8My9 CVUX C34K B8NM bEXm jcUK RAq6 JT9p DaYW UstG K9hH xX98 KxHU weVa RvpV wJd5 JXbf eEDf 4cYy hzNL j6dW Ehq3 KXCV YSBf nRJd rAN";
        let bytes = decode(s).unwrap();
        assert_eq!(bytes.len(), 73);
        assert_eq!(&bytes[0..4], &[73, 0, 2, 0]); // a single type 2 block
        assert_eq!(decode(&encode(&bytes)).unwrap(), bytes);
    }

    #[test]
    fn display_formatting() {
        let raw: String = (0..45).map(|i| ALPHABET[i % 56] as char).collect();
        let shown = format_for_display(&raw);
        let lines: Vec<&str> = shown.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].len(), 24);
        assert_eq!(lines[0].split(' ').count(), 5);
    }
}
