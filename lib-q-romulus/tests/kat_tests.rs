//! Known-answer tests from LWC `LWC_AEAD_KAT_128_128.txt` (Romulus v1.3; vectors vendored under `tests/fixtures`).

#![cfg(feature = "std")]

use std::vec::Vec;

use aead::array::Array;
use aead::{
    AeadInOut,
    KeyInit,
};
use lib_q_romulus::{
    RomulusM,
    RomulusN,
};

const KAT_N: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/romulus-n/LWC_AEAD_KAT_128_128.txt"
));
const KAT_M: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/romulus-m/LWC_AEAD_KAT_128_128.txt"
));

struct Entry {
    key: [u8; 16],
    nonce: [u8; 16],
    pt: Vec<u8>,
    ad: Vec<u8>,
    ct: Vec<u8>,
}

fn hex_bytes(s: &str) -> Vec<u8> {
    let t = s.trim();
    if t.is_empty() {
        return Vec::new();
    }
    hex::decode(t).expect("hex decode")
}

fn parse_lwc_kat(data: &str) -> Vec<Entry> {
    let data = data.strip_prefix('\u{feff}').unwrap_or(data);
    let mut out = Vec::new();
    let mut key: Option<Vec<u8>> = None;
    let mut nonce: Option<Vec<u8>> = None;
    let mut pt: Option<Vec<u8>> = None;
    let mut ad: Option<Vec<u8>> = None;
    let mut ct: Option<Vec<u8>> = None;

    fn field_hex(line: &str, prefix: &str) -> Option<Vec<u8>> {
        let rest = line.strip_prefix(prefix)?;
        Some(hex_bytes(rest))
    }

    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() {
            if let (Some(k), Some(n), Some(p), Some(a), Some(c)) =
                (key.take(), nonce.take(), pt.take(), ad.take(), ct.take())
            {
                out.push(Entry {
                    key: k.try_into().expect("key len"),
                    nonce: n.try_into().expect("nonce len"),
                    pt: p,
                    ad: a,
                    ct: c,
                });
            }
            continue;
        }
        // Official LWC files use `AD =` with no trailing space when AD is empty.
        if let Some(v) = field_hex(line, "Key =") {
            key = Some(v);
        } else if let Some(v) = field_hex(line, "Nonce =") {
            nonce = Some(v);
        } else if let Some(v) = field_hex(line, "PT =") {
            pt = Some(v);
        } else if let Some(v) = field_hex(line, "AD =") {
            ad = Some(v);
        } else if let Some(v) = field_hex(line, "CT =") {
            ct = Some(v);
        }
    }
    if let (Some(k), Some(n), Some(p), Some(a), Some(c)) = (key, nonce, pt, ad, ct) {
        out.push(Entry {
            key: k.try_into().expect("key len"),
            nonce: n.try_into().expect("nonce len"),
            pt: p,
            ad: a,
            ct: c,
        });
    }
    out
}

#[test]
fn kat_romulus_n_all() {
    let vectors = parse_lwc_kat(KAT_N);
    assert_eq!(
        vectors.len(),
        1089,
        "expected 1089 KAT vectors (official LWC file)"
    );

    for e in &vectors {
        let key = Array::from(e.key);
        let nonce = Array::from(e.nonce);
        let cipher = RomulusN::new(&key);

        let mut buf = e.pt.clone();
        let tag = cipher
            .encrypt_inout_detached(&nonce, &e.ad, buf.as_mut_slice().into())
            .expect("encrypt");
        let mut combined = buf.clone();
        combined.extend_from_slice(tag.as_slice());
        assert_eq!(combined, e.ct, "Romulus-N encrypt mismatch");

        let body_len = e.ct.len().saturating_sub(16);
        let mut buf2 = e.ct[..body_len].to_vec();
        let tag2 = Array::try_from(&e.ct[body_len..]).expect("tag len");
        cipher
            .decrypt_inout_detached(&nonce, &e.ad, buf2.as_mut_slice().into(), &tag2)
            .expect("decrypt");
        assert_eq!(buf2, e.pt, "Romulus-N decrypt mismatch");
    }
}

#[test]
fn kat_romulus_m_all() {
    let vectors = parse_lwc_kat(KAT_M);
    assert_eq!(
        vectors.len(),
        1089,
        "expected 1089 KAT vectors (official LWC file)"
    );

    for e in &vectors {
        let key = Array::from(e.key);
        let nonce = Array::from(e.nonce);
        let cipher = RomulusM::new(&key);

        let mut buf = e.pt.clone();
        let tag = cipher
            .encrypt_inout_detached(&nonce, &e.ad, buf.as_mut_slice().into())
            .expect("encrypt");
        let mut combined = buf.clone();
        combined.extend_from_slice(tag.as_slice());
        assert_eq!(combined, e.ct, "Romulus-M encrypt mismatch");

        let body_len = e.ct.len().saturating_sub(16);
        let mut buf2 = e.ct[..body_len].to_vec();
        let tag2 = Array::try_from(&e.ct[body_len..]).expect("tag len");
        cipher
            .decrypt_inout_detached(&nonce, &e.ad, buf2.as_mut_slice().into(), &tag2)
            .expect("decrypt");
        assert_eq!(buf2, e.pt, "Romulus-M decrypt mismatch");
    }
}
