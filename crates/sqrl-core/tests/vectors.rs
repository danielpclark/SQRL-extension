//! Test vectors published by GRC and by the SQRL developer community.
//!
//! Sources:
//! * "SQRL Cryptography" v1.04 (December 2019), §"SQRL Cryptography Test Vectors": the
//!   Spec-Vectors-Identity (password, rescue code, textual identity) and the client-side
//!   SQRL-PASS.log / SQRL.log excerpts.
//! * grc.sqrl.dev newsgroup, "SQRL Identity encryption" (Adam Comley, 2014): EnScrypt with a
//!   16-byte salt, cross-validated against GRC's EnScrypt.exe.
//! * grc.sqrl newsgroup, "Base56 Examples" (Paul Holder, March 2019): base56 textual
//!   encodings validated against the GRC SQRL client's export.

use sqrl_core::crypto::{ed25519_public, enhash, enscrypt_iterations, hmac_sha256};
use sqrl_core::identity::UnlockedIdentity;
use sqrl_core::protocol::ClientOptions;
use sqrl_core::storage::S4Identity;
use sqrl_core::url::SqrlUrl;
use sqrl_core::util::{b64u_encode, hex_decode, hex_encode};
use sqrl_core::{textual, Session};

const SPEC_PASSWORD: &str = "Zingo-Bingo-Slingo-Dingo";
const SPEC_RESCUE_CODE: &str = "1198-8748-7132-2838-8318-7570";
const SPEC_TEXTUAL: &str = "KKcC 3BaX akxc Xwbf xki7
k7mF GHhg jQes gzWd 6TrK
vMsZ dBtB pZbC zsz8 cUWj
DtS2 ZK2s ZdAQ 8Yx3 iDyt
QuXt CkTC y6gc qG8n Xfj9
bHDA 422";
const SPEC_IMK: &str = "2E471E106D758F3C7B242C8A4A0513A7192D8EDDB917BDD019F19E38ED292BA8";

fn enscrypt_hex(pw: &str, salt_hex: &str, iterations: u32) -> String {
    let salt = hex_decode(salt_hex).unwrap();
    hex_encode(&enscrypt_iterations(
        pw.as_bytes(),
        &salt,
        9,
        iterations,
        |_| {},
    ))
}

#[test]
fn enscrypt_spec_vectors_identity_password() {
    // SQRL-PASS.log: "Password DeScryption iterations: 179 ... DeScryption ScryptSalt is: F501...
    // Symmetric Key is: BC15..."
    assert_eq!(
        enscrypt_hex(SPEC_PASSWORD, "F5019F96E9F64D32BEAE43145ACEF2CF", 179),
        "bc151224fc6b72152021edbe3ade523f98be99c491334bba9fd8b587eb51e36d"
    );
}

#[test]
fn enscrypt_spec_vectors_quickpass_hint() {
    // SQRL-PASS.log: hint "Zing", "Hint EnScrypt IV: CD2E...", 31 iterations → DDC7...
    assert_eq!(
        enscrypt_hex("Zing", "CD2E1EA56DE20FE036B6D2FA867DF50A", 31),
        "ddc7f5d12caa26a869488ad83df8ed480072076dfd94eee5f6f1bd0dde02b9d9"
    );
}

#[test]
fn enscrypt_newsgroup_vectors_16_and_32_byte_salts() {
    assert_eq!(
        enscrypt_hex("Sqrl123Test", "0123456789abcdef0123456789abcdef", 63),
        "83961678d0e808f29b5dcc045236ad7fd249d7dfd7284b461976b1f1b8a45df0"
    );
    assert_eq!(
        enscrypt_hex(
            "Sqrl123Test",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            63
        ),
        "da06576fbe58fb20bd8c4f1204a87aa8fad21078473dd770bb7ee7faff8a2f4a"
    );
}

#[test]
fn spec_vectors_identity_textual_rescue_code_and_keys() {
    // The textual identity holds the type 2 block only (no re-keying): 73 bytes, 101 chars + 6 check chars.
    let cleaned: String = SPEC_TEXTUAL
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    assert_eq!(cleaned.len(), 107);
    let bytes = textual::decode(SPEC_TEXTUAL).unwrap();
    assert_eq!(bytes.len(), 73);
    let id = S4Identity::parse_blocks(&bytes).unwrap();
    assert!(id.type1.is_none() && id.type2.is_some() && id.type3.is_none());
    // Re-encoding reproduces GRC's text exactly.
    assert_eq!(
        textual::format_for_display(&textual::encode(&bytes)),
        SPEC_TEXTUAL
    );

    // Rescue code → IUK → EnHash → the IMK shown in SQRL.log.
    let iuk = id.unlock_iuk(SPEC_RESCUE_CODE, |_| {}).unwrap();
    let imk = enhash(&iuk);
    assert_eq!(hex_encode(&imk).to_uppercase(), SPEC_IMK);

    // Per-site key for sqrl.grc.com (SQRL.log: "HMAC256 HashOut", "Site Public Key", "IDK").
    let seed = hmac_sha256(&imk, b"sqrl.grc.com");
    assert_eq!(
        hex_encode(&seed).to_uppercase(),
        "7A550E0797EF9E617D0E544EBE27FDE749D9EC2472BF9618DEE4C063EEFD51B5"
    );
    let pk = ed25519_public(&seed);
    assert_eq!(
        hex_encode(&pk).to_uppercase(),
        "DA3801F9C47E1279588253DD193A0EB9C29823A083EAC52A7F893D32D92E897B"
    );
    assert_eq!(
        b64u_encode(&pk),
        "2jgB-cR-EnlYglPdGToOucKYI6CD6sUqf4k9MtkuiXs"
    );
}

#[test]
fn spec_vectors_identity_query_and_ident_signatures() {
    // SQRL.log transaction 1: the query. Everything the client sends is deterministic, so the
    // whole POST body must match GRC's client byte for byte.
    let imk: [u8; 32] = hex_decode(SPEC_IMK).unwrap().try_into().unwrap();
    let identity = UnlockedIdentity::new(imk, [0u8; 32], Vec::new());
    let url = SqrlUrl::parse(
        "sqrl://sqrl.grc.com/cli.sqrl?nut=fXkb4MBToCm7&can=aHR0cHM6Ly9zcXJsLmdyYy5jb20vZGVtbw",
    )
    .unwrap();
    assert_eq!(url.site_key, "sqrl.grc.com");
    assert_eq!(url.cancel_url.as_deref(), Some("https://sqrl.grc.com/demo"));
    let mut s = Session::new(
        identity,
        url,
        ClientOptions {
            cps: true,
            ..Default::default()
        },
        None,
    );
    let q = s.query().unwrap();
    assert_eq!(
        q.url,
        "https://sqrl.grc.com/cli.sqrl?nut=fXkb4MBToCm7&can=aHR0cHM6Ly9zcXJsLmdyYy5jb20vZGVtbw"
    );
    assert_eq!(
        q.client_text,
        "ver=1\r\ncmd=query\r\nidk=2jgB-cR-EnlYglPdGToOucKYI6CD6sUqf4k9MtkuiXs\r\nopt=cps~suk\r\n"
    );
    assert!(q.body.starts_with("client=dmVyPTENCmNtZD1xdWVyeQ0KaWRrPTJqZ0ItY1ItRW5sWWdsUGRHVG9PdWNLWUk2Q0Q2c1VxZjRrOU10a3Vp"));
    assert!(q.body.contains("&server=c3FybDovL3NxcmwuZ3JjLmNvbS9jbGkuc3FybD9udXQ9ZlhrYjRNQlRvQ203JmNhbj1hSFIwY0hNNkx5OXpj"));
    assert!(q.body.ends_with("&ids=qXFikmg_jZQJ7GjKCA_zBwzras2QyQAwWw2s80ZcUHmLLBUN5_hPuFtB6ZoV5wUcNs5XmSrqg1FQwGA6RlVBAQ"));

    // Server reply 1 (decoded in the log; ContentLength 151 is the base64url length).
    let reply1 = b64u_encode(b"ver=1\r\nnut=1WM9lfF1ST-z\r\ntif=5\r\nqry=/cli.sqrl?nut=1WM9lfF1ST-z\r\nsuk=BMFDm7bPlsQojuJsoDTvlS1McnwgScvktF84vLjscGk\r\n");
    assert_eq!(reply1.len(), 151);
    assert!(reply1.starts_with(
        "dmVyPTENCm51dD0xV005bGZGMVNULXoNCnRpZj01DQpxcnk9L2NsaS5zcXJsP251dD0xV005bGZGMVNULXoN"
    ));
    let r = s.feed(&reply1).unwrap();
    assert!(r.tif.id_match() && r.tif.ips_matched());
    assert_eq!(
        b64u_encode(&r.suk.unwrap()),
        "BMFDm7bPlsQojuJsoDTvlS1McnwgScvktF84vLjscGk"
    );

    // Transaction 2: the ident, signed over the client text and the reply exactly as received.
    let i = s.ident().unwrap();
    assert_eq!(i.url, "https://sqrl.grc.com/cli.sqrl?nut=1WM9lfF1ST-z");
    assert_eq!(
        i.client_text,
        "ver=1\r\ncmd=ident\r\nidk=2jgB-cR-EnlYglPdGToOucKYI6CD6sUqf4k9MtkuiXs\r\nopt=cps~suk\r\n"
    );
    assert!(i.body.starts_with("client=dmVyPTENCmNtZD1pZGVudA0KaWRrPTJqZ0ItY1ItRW5sWWdsUGRHVG9PdWNLWUk2Q0Q2c1VxZjRrOU10a3Vp"));
    assert!(i.body.ends_with("&ids=kQI05IpE_cu4u0mf7jymbap09hmS6ZCWjBGKUYnSNVRTXPbreTvDWHKNbSkUlQT2bx3wXwW3cCLBD0Qedd64AA"));

    // Server reply 2 with the CPS url.
    let reply2 = b64u_encode(b"ver=1\r\nnut=BEFAI1tJYfBm\r\ntif=5\r\nqry=/cli.sqrl?nut=BEFAI1tJYfBm\r\nsuk=BMFDm7bPlsQojuJsoDTvlS1McnwgScvktF84vLjscGk\r\nurl=https://sqrl.grc.com/auth.test?4hVTe9LGHhMTuxz_mm6vRc_q\r\n");
    assert_eq!(reply2.len(), 232);
    s.feed(&reply2).unwrap();
    assert_eq!(
        s.cps_url().unwrap().as_deref(),
        Some("https://sqrl.grc.com/auth.test?4hVTe9LGHhMTuxz_mm6vRc_q")
    );
}

fn b56(hex: &str) -> String {
    textual::encode(&hex_decode(hex).unwrap())
}

#[test]
fn base56_vectors_validated_against_grc_client() {
    // 1, 2 and 3 byte inputs (2 chars + check, 3 + check, 4/5 + check).
    assert_eq!(b56("00"), "22Y");
    assert_eq!(b56("01"), "32B");
    assert_eq!(b56("0F"), "H2M");
    assert_eq!(b56("55"), "X3v");
    assert_eq!(b56("C5"), "X57");
    assert_eq!(b56("FE"), "Y6e");
    assert_eq!(b56("FF"), "Z6V");
    assert_eq!(b56("0000"), "222B");
    assert_eq!(b56("0101"), "b628");
    assert_eq!(b56("0F0F"), "rE3N");
    assert_eq!(b56("1010"), "SK3T");
    assert_eq!(b56("7F7F"), "rQCj");
    assert_eq!(b56("8080"), "SVC5");
    assert_eq!(b56("FEFE"), "gpN7");
    assert_eq!(b56("FFFF"), "HuNh");
    assert_eq!(b56("000000"), "22222z");
    assert_eq!(b56("010101"), "tyN22r");
    assert_eq!(b56("7F7F7F"), "9Tar2S");
    assert_eq!(b56("808080"), "2Sxr2D");
    assert_eq!(b56("FEFEFE"), "GuAh3n");
    assert_eq!(b56("FFFFFF"), "9tXh3W");
    // (The 4-byte examples from the earlier "Known good examples" post are deliberately not
    // used: their author found the next day that they lacked the line-number byte in the
    // check character and superseded them with the vectors above and below.)
    // 16 bytes (one full line plus a partial line)
    assert_eq!(
        b56("0102030405060708090A0B0C0D0E0F10"),
        "tG5vDbjTXT2zfJ5cMfvg3A62d"
    );
    // 80 bytes, 6 lines
    let eighty = "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F50";
    let expected = "b6w8 RYMv S427 Gtt5 sXBj
UB5n vHZH PbHr uAM9 MgUR
fzT8 qs8f EEEp kUPV GH6R
ac4u Zdrk CwLJ Wxmy 8upX
rU9N Bn6P qcY9 HXKt ybEC
Sdh9 R22r SjAd 48i2 Y";
    assert_eq!(textual::format_for_display(&b56(eighty)), expected);
    assert_eq!(
        hex_encode(&textual::decode(expected).unwrap()).to_uppercase(),
        eighty
    );
    // 87 random bytes
    let random87 = "18A2D975F61A3B6F1975FA2A9E3FBA2C7BE73732A0E34F006328E4BD938CFB6E292A50845C5A6B83F7697EAC8A49BF97221C2F06C1F4B251BDB865AF1E1E28E62D635959BEF7927CD658A7C2CA1AD5570DC6C066BA6EAF";
    let expected87 = "sMrK xrbJ dHz5 s3mu EGWw
RjWM UbAV MMsq SwMM R7C6
theF MsSg PDJ4 BHVb jLau
KpW8 cbsU mTpd eueZ ZYMU
HgcB kffR Nviu pxb9 UvxN
fN54 3id9 CdRe L254 ZzEb
4LBd pNL";
    assert_eq!(textual::format_for_display(&b56(random87)), expected87);
    assert_eq!(
        hex_encode(&textual::decode(expected87).unwrap()).to_uppercase(),
        random87
    );
}
