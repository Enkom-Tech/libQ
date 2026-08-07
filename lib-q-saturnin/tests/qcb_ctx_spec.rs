//! Independent transcription gate for the CTX commitment layer on `SaturninQcb` (card
//! `t_16ddf21c`).
//!
//! Oracle: John Chan and Phillip Rogaway, *On Committing Authenticated-Encryption*, ESORICS 2022
//! (IACR ePrint 2022/1260), Fig. 2 / Theorem 2 — `T' = H(K, N, A, T)`, instantiated here with
//! [`SaturninHash`]. This file builds the CTX hash input from scratch, using:
//!
//! - its own transcription of QCB Algorithm 1 to obtain the raw (pre-CTX) tag `T` (deliberately
//!   duplicated from `tests/qcb_spec.rs` rather than shared, so a mistake in one does not
//!   propagate into the other and silently cancel out — the two files are meant to independently
//!   agree, not to reuse each other's code);
//! - the documented byte layout `LABEL ‖ K ‖ N ‖ T ‖ A` (see `lib-q-saturnin/src/commit.rs`);
//! - the public [`SaturninHash`] API, not `lib_q_saturnin::commit::ctx_tag`.
//!
//! and asserts the result equals the last 32 bytes of `SaturninQcb::encrypt`'s output. This is
//! the gate that catches `commit.rs` and the published byte layout drifting apart — the failure
//! mode that matters most for a format meant to be frozen and put in hardware.
//!
//! Every property test below (`label_is_load_bearing`, `ad_is_bound_by_the_commitment`,
//! `nonce_is_bound`, `key_is_bound`) was confirmed to FAIL first by temporarily deleting the
//! corresponding field from the local `ctx_input` construction and observing the two tags
//! collide; see the red-then-green evidence in the PR / card `t_16ddf21c`.

#![cfg(all(feature = "alloc", feature = "qcb"))]

use lib_q_saturnin::{
    Aead,
    AeadKey,
    Nonce,
    SaturninHash,
    SaturninQcb,
    SaturninTbc,
};

const B: usize = 32;
const D_MSG_FULL: u8 = 9;
const D_MSG_FINAL: u8 = 10;
const D_AD_FULL: u8 = 11;
const D_AD_FINAL: u8 = 12;
const D_TAG: u8 = 13;

/// `crate::commit::QCB_CTX_LABEL_V0`, hardcoded (not imported — see module docs).
const CTX_LABEL: &[u8] = b"libq.saturnin.qcb.ctx.v0";

/// `pad(IV) || i`, transcribed from the specs rather than from `src/qcb.rs`. Byte 16 is the `10*`
/// pad bit that closes the 161-bit IV field — see `tests/qcb_spec.rs::tweak` for the derivation
/// and the quoted spec text.
fn tweak(nonce16: &[u8; 16], block_index: u64) -> [u8; B] {
    let mut t = [0u8; B];
    t[0..16].copy_from_slice(nonce16);
    t[16] = 0x80;
    t[24..32].copy_from_slice(&block_index.to_be_bytes());
    t
}

fn xor_into(acc: &mut [u8; B], v: &[u8; B]) {
    for i in 0..B {
        acc[i] ^= v[i];
    }
}

fn pad_tail(tail: &[u8]) -> [u8; B] {
    assert!(tail.len() < B);
    let mut out = [0u8; B];
    out[..tail.len()].copy_from_slice(tail);
    out[tail.len()] = 0x80;
    out
}

/// Independent transcription of QCB Algorithm 1's raw tag `T` (lines 8-13), duplicated from
/// `tests/qcb_spec.rs` on purpose (see module docs).
fn raw_qcb_tag(key: &[u8; 32], nonce: &[u8; 16], m: &[u8], a: &[u8]) -> [u8; B] {
    let e9 = SaturninTbc::new(D_MSG_FULL).unwrap();
    let e10 = SaturninTbc::new(D_MSG_FINAL).unwrap();
    let e11 = SaturninTbc::new(D_AD_FULL).unwrap();
    let e12 = SaturninTbc::new(D_AD_FINAL).unwrap();
    let e13 = SaturninTbc::new(D_TAG).unwrap();

    let m_full = m.len() / B;
    let l = m_full.saturating_sub(1) as u64;
    let mut checksum = [0u8; B];
    for i in 0..m_full {
        let mut blk = [0u8; B];
        blk.copy_from_slice(&m[i * B..(i + 1) * B]);
        xor_into(&mut checksum, &blk);
        e9.encrypt_block(key, &tweak(nonce, i as u64), &mut blk)
            .unwrap();
    }
    let mut last = pad_tail(&m[m_full * B..]);
    xor_into(&mut checksum, &last);
    e10.encrypt_block(key, &tweak(nonce, l), &mut last).unwrap();

    let a_full = a.len() / B;
    let j = a_full.saturating_sub(1) as u64;
    let mut tag = [0u8; B];
    for i in 0..a_full {
        let mut blk = [0u8; B];
        blk.copy_from_slice(&a[i * B..(i + 1) * B]);
        e11.encrypt_block(key, &tweak(nonce, i as u64), &mut blk)
            .unwrap();
        xor_into(&mut tag, &blk);
    }
    let mut a_last = pad_tail(&a[a_full * B..]);
    e12.encrypt_block(key, &tweak(nonce, j), &mut a_last)
        .unwrap();
    xor_into(&mut tag, &a_last);

    let mut chk = checksum;
    e13.encrypt_block(key, &tweak(nonce, l), &mut chk).unwrap();
    xor_into(&mut tag, &chk);
    tag
}

/// The CTX hash input, built field-by-field from the documented layout. `omit` lets the property
/// tests below drop one field at a time to demonstrate that field is load-bearing.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Omit {
    None,
    Label,
    Key,
    Nonce,
    Ad,
}

fn ctx_input(
    label: &[u8],
    key: &[u8; 32],
    nonce: &[u8],
    tag: &[u8; B],
    a: &[u8],
    omit: Omit,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(label.len() + key.len() + nonce.len() + B + a.len());
    if omit != Omit::Label {
        buf.extend_from_slice(label);
    }
    if omit != Omit::Key {
        buf.extend_from_slice(key);
    }
    if omit != Omit::Nonce {
        buf.extend_from_slice(nonce);
    }
    buf.extend_from_slice(tag);
    if omit != Omit::Ad {
        buf.extend_from_slice(a);
    }
    buf
}

fn ctx_tag_ref(label: &[u8], key: &[u8; 32], nonce: &[u8], tag: &[u8; B], a: &[u8]) -> Vec<u8> {
    SaturninHash::new()
        .hash(&ctx_input(label, key, nonce, tag, a, Omit::None))
        .unwrap()
}

fn k() -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = i as u8;
    }
    k
}

fn n() -> [u8; 16] {
    [0x44u8; 16]
}

/// **The transcription gate.** `SaturninQcb::encrypt`'s last 32 bytes must equal this file's
/// from-scratch reconstruction of `T' = SaturninHash(label || K || N || T || A)`, for a sweep of
/// message/AD lengths that cross every block-count boundary the mode has.
#[test]
fn ctx_tag_matches_independent_reconstruction() {
    let key_bytes = k();
    let nonce_bytes = n();
    let key = AeadKey::new(key_bytes.to_vec());
    let nonce = Nonce::new(nonce_bytes.to_vec());
    let aead = SaturninQcb::new();

    for m_len in [0usize, 1, 31, 32, 33, 64, 95] {
        for a_len in [0usize, 1, 31, 32, 63, 64] {
            let m: Vec<u8> = (0..m_len).map(|i| i as u8).collect();
            let a: Vec<u8> = (0..a_len).map(|i| (0x5A ^ i) as u8).collect();
            let ad_opt = if a.is_empty() {
                None
            } else {
                Some(a.as_slice())
            };

            let ct = aead.encrypt(&key, &nonce, &m, ad_opt).unwrap();
            let got_tag = &ct[ct.len() - B..];

            let raw_t = raw_qcb_tag(&key_bytes, &nonce_bytes, &m, &a);
            let want_tag = ctx_tag_ref(CTX_LABEL, &key_bytes, &nonce_bytes, &raw_t, &a);

            assert_eq!(
                got_tag, want_tag,
                "CTX tag mismatch at m_len={m_len} a_len={a_len}"
            );
        }
    }
}

/// The label must be load-bearing: two otherwise-identical CTX computations with different
/// labels must produce different tags. Shown failing first by using `Omit::Label` on both sides
/// (which collapses to comparing identical inputs).
#[test]
fn label_is_load_bearing() {
    let key = k();
    let nonce = n();
    let tag = [0x77u8; B];
    let a = b"associated-data";

    let t1 = SaturninHash::new()
        .hash(&ctx_input(CTX_LABEL, &key, &nonce, &tag, a, Omit::None))
        .unwrap();
    let t2 = SaturninHash::new()
        .hash(&ctx_input(
            b"libq.saturnin.cascade.ctx.v0",
            &key,
            &nonce,
            &tag,
            a,
            Omit::None,
        ))
        .unwrap();
    assert_ne!(t1, t2, "changing only the label must change the CTX tag");

    // Falsification: with the label omitted from BOTH sides the two inputs coincide.
    let f1 = SaturninHash::new()
        .hash(&ctx_input(CTX_LABEL, &key, &nonce, &tag, a, Omit::Label))
        .unwrap();
    let f2 = SaturninHash::new()
        .hash(&ctx_input(
            b"libq.saturnin.cascade.ctx.v0",
            &key,
            &nonce,
            &tag,
            a,
            Omit::Label,
        ))
        .unwrap();
    assert_eq!(
        f1, f2,
        "sanity check on the falsification itself: omitting the label from both sides must \
         collapse the two inputs to identical bytes"
    );
}

/// AD must be bound by the commitment (the CMT-4-shaped property, and the one the pre-CTX XOR
/// structure failed — see `tests/key_commitment.rs`). Falsified the same way as above.
#[test]
fn ad_is_bound_by_the_commitment() {
    let key = k();
    let nonce = n();
    let tag = [0x77u8; B];

    let t1 = ctx_tag_ref(CTX_LABEL, &key, &nonce, &tag, b"associated-data-alpha");
    let t2 = ctx_tag_ref(CTX_LABEL, &key, &nonce, &tag, b"associated-data-bravo");
    assert_ne!(t1, t2, "changing only the AD must change the CTX tag");

    let f1 = SaturninHash::new()
        .hash(&ctx_input(
            CTX_LABEL,
            &key,
            &nonce,
            &tag,
            b"associated-data-alpha",
            Omit::Ad,
        ))
        .unwrap();
    let f2 = SaturninHash::new()
        .hash(&ctx_input(
            CTX_LABEL,
            &key,
            &nonce,
            &tag,
            b"associated-data-bravo",
            Omit::Ad,
        ))
        .unwrap();
    assert_eq!(
        f1, f2,
        "sanity check: omitting AD from both sides must collapse the two inputs"
    );
}

/// The nonce must be bound (this is precisely QCB's own D1 concern, now additionally enforced by
/// the outer commitment — see the caveat in `tests/qcb_spec.rs`).
#[test]
fn nonce_is_bound() {
    let key = k();
    let tag = [0x77u8; B];
    let a = b"ad";

    let t1 = ctx_tag_ref(CTX_LABEL, &key, &[0x11u8; 16], &tag, a);
    let t2 = ctx_tag_ref(CTX_LABEL, &key, &[0x22u8; 16], &tag, a);
    assert_ne!(t1, t2, "changing only the nonce must change the CTX tag");

    let f1 = SaturninHash::new()
        .hash(&ctx_input(
            CTX_LABEL,
            &key,
            &[0x11u8; 16],
            &tag,
            a,
            Omit::Nonce,
        ))
        .unwrap();
    let f2 = SaturninHash::new()
        .hash(&ctx_input(
            CTX_LABEL,
            &key,
            &[0x22u8; 16],
            &tag,
            a,
            Omit::Nonce,
        ))
        .unwrap();
    assert_eq!(
        f1, f2,
        "sanity check: omitting the nonce from both sides must collapse the two inputs"
    );
}

/// The key must be bound (this is the whole point: CMT-1 asks exactly this question).
#[test]
fn key_is_bound() {
    let nonce = n();
    let tag = [0x77u8; B];
    let a = b"ad";

    let k1 = k();
    let mut k2 = k();
    k2[0] ^= 0x01;

    let t1 = ctx_tag_ref(CTX_LABEL, &k1, &nonce, &tag, a);
    let t2 = ctx_tag_ref(CTX_LABEL, &k2, &nonce, &tag, a);
    assert_ne!(t1, t2, "changing only the key must change the CTX tag");

    let f1 = SaturninHash::new()
        .hash(&ctx_input(CTX_LABEL, &k1, &nonce, &tag, a, Omit::Key))
        .unwrap();
    let f2 = SaturninHash::new()
        .hash(&ctx_input(CTX_LABEL, &k2, &nonce, &tag, a, Omit::Key))
        .unwrap();
    assert_eq!(
        f1, f2,
        "sanity check: omitting the key from both sides must collapse the two inputs"
    );
}
