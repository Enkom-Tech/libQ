//! Layout gate + property tests for the CTX commitment layer on `SaturninAeadCtx` (CTX applied to
//! Saturnin CTR-Cascade).
//!
//! Oracle: John Chan and Phillip Rogaway, *On Committing Authenticated-Encryption*, ESORICS 2022
//! (IACR ePrint 2022/1260), Fig. 2 / Theorem 2 — `T' = H(K, N, A, T)`, instantiated here with
//! `SaturninHash`. Modeled on `tests/qcb_ctx_spec.rs`.
//!
//! **What is and is not independent here.** This file rebuilds the CTX layer from the documented
//! byte layout, using the public `SaturninHash` and a *hardcoded* copy of the label rather than
//! importing `commit::CASCADE_CTX_LABEL_V0` or calling `commit::ctx_tag` — so a wrong label, a
//! wrong field order, or a dropped field in `src/aead_ctx.rs` cannot cancel out against this file.
//! It does **not** re-derive CTR-Cascade's own tag `T`: the cascade core (`SaturninCore`, domains
//! 1–5) is not public, so `T` is taken from the *uncommitted* `SaturninAead`'s tag on identical
//! inputs. That is a legitimate independent source of `T` for the layer under test (and
//! `cross_mode_ciphertexts_rejected` pins the body-sharing property it relies on), but it means
//! the cascade arithmetic itself is covered by `tests/kat_tests.rs` / `tests/reference_oracle.rs`,
//! not by this file.
//!
//! No fabricated CMT-1 attack test exists in this file. There is no known cheap CMT-1 break on
//! CTR-Cascade (a 256-bit tag over a 256-bit cascade state, no GHASH-like algebraic structure);
//! see `lib-q-aead/tests/key_commitment.rs` for the bounded search that covers the base mode and
//! why a null result there is not evidence of commitment. These tests cover the *transform's
//! properties* (determinism, and that the tag genuinely binds each of K, N, A, T) instead.
//!
//! **Which tests actually guard `src/aead_ctx.rs`.** Only the ones that call `SaturninAeadCtx`:
//! `ctx_tag_matches_independent_reconstruction`, `production_ctx_tag_binds_label_key_nonce_ad_and_base_tag`,
//! `pinned_ctx_kat_vectors`, `round_trip_and_rejection`, `cross_mode_ciphertexts_rejected`,
//! `ctx_tag_is_deterministic` and `empty_edges`. The five `Omit`-pattern tests
//! (`label_is_load_bearing`, `key_is_bound`, `nonce_is_bound`, `ad_is_bound_by_the_commitment`,
//! `base_tag_is_bound`) exercise only the documented input encoding via `SaturninHash`; they stay
//! green under a broken implementation (OBSERVED — see
//! `production_ctx_tag_binds_label_key_nonce_ad_and_base_tag`'s doc comment for the two source
//! mutations that demonstrated it) and must not be cited as evidence that production binds a field.
//!
//! Every production-facing test above was observed FAILING under a deliberate source mutation
//! during review; each test's doc comment names the mutation that reddened it.

#![cfg(all(feature = "alloc", feature = "aead", feature = "hash"))]

use lib_q_saturnin::{
    Aead,
    AeadDecryptSemantic,
    AeadKey,
    DecryptSemanticOutcome,
    Error,
    Nonce,
    SaturninAead,
    SaturninAeadCtx,
    SaturninHash,
};

const B: usize = 32;

/// `crate::commit::CASCADE_CTX_LABEL_V0`, hardcoded (not imported — see module docs).
const CTX_LABEL: &[u8] = b"libq.saturnin.cascade.ctx.v0";
/// `crate::commit::QCB_CTX_LABEL_V0`, for the cross-label domain-separation test.
const QCB_LABEL: &[u8] = b"libq.saturnin.qcb.ctx.v0";

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

fn key_from(bytes: &[u8; 32]) -> AeadKey {
    AeadKey::new(bytes.to_vec())
}

fn nonce_from(bytes: &[u8; 16]) -> Nonce {
    Nonce::new(bytes.to_vec())
}

// --- Reconstruction of the CTX layer from the documented byte layout --------------------------
//
// This is the CTX *layout* gate, not a re-derivation of the cascade arithmetic. The cascade's
// internal core (`SaturninCore`, domains 1-5) is not public, so the raw base tag `T` is not
// recomputed here; it is read from the last 32 bytes of the *uncommitted* `SaturninAead::encrypt`
// on identical inputs. `SaturninAead::base_tag_over` is deliberately NOT called (that is the very
// helper `src/aead_ctx.rs` uses, so calling it would make this file test itself). The cascade
// arithmetic proper is covered by `tests/kat_tests.rs` and `tests/reference_oracle.rs`; what this
// file adds is the CTX layer on top of it, rebuilt from the documented layout with a hardcoded
// label and the public `SaturninHash`.

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

/// **The transcription gate.** `SaturninAeadCtx::encrypt`'s last 32 bytes must equal
/// `SaturninHash(CTX_LABEL || K || N || T || A)`, where `T` is recovered independently by asking
/// the *uncommitted* `SaturninAead` (a different type, same K/N/pt/ad) for its own tag — since
/// CTX only ever replaces the last 32 bytes and CTR-Cascade's ciphertext body is identical between
/// the two types for the same inputs (see `cross_mode_ciphertexts_rejected` below, which pins that
/// body-sharing property directly), this is a valid independent source of `T` that does not import
/// `crate::commit::ctx_tag` or `SaturninAeadCtx`'s internals.
#[test]
fn ctx_tag_matches_independent_reconstruction() {
    let key_bytes = k();
    let nonce_bytes = n();
    let key = key_from(&key_bytes);
    let nonce = nonce_from(&nonce_bytes);
    let plain = SaturninAead::new();
    let committed = SaturninAeadCtx::new();

    for m_len in [0usize, 1, 31, 32, 33, 64, 95] {
        for a_len in [0usize, 1, 31, 32, 63, 64] {
            let m: Vec<u8> = (0..m_len).map(|i| i as u8).collect();
            let a: Vec<u8> = (0..a_len).map(|i| (0x5A ^ i) as u8).collect();
            let ad_opt = if a.is_empty() {
                None
            } else {
                Some(a.as_slice())
            };

            let plain_ct = plain.encrypt(&key, &nonce, &m, ad_opt).unwrap();
            let raw_t = &plain_ct[plain_ct.len() - B..];
            let mut raw_t_arr = [0u8; B];
            raw_t_arr.copy_from_slice(raw_t);

            let committed_ct = committed.encrypt(&key, &nonce, &m, ad_opt).unwrap();
            let got_tag = &committed_ct[committed_ct.len() - B..];

            let want_tag = ctx_tag_ref(CTX_LABEL, &key_bytes, &nonce_bytes, &raw_t_arr, &a);

            assert_eq!(
                got_tag, want_tag,
                "CTX tag mismatch at m_len={m_len} a_len={a_len}"
            );

            // Sanity: the body (everything but the last 32 bytes) must be identical between the
            // plain and committed encryptions for the same inputs (CTX only replaces the tag).
            assert_eq!(
                plain_ct[..plain_ct.len() - B],
                committed_ct[..committed_ct.len() - B],
                "ciphertext body diverged at m_len={m_len} a_len={a_len}"
            );
        }
    }
}

/// Two `encrypt` calls with identical inputs must produce identical full ciphertext.
/// *Observed red* during review by injecting nondeterminism into `SaturninAeadCtx::encrypt_bytes`
/// (`key32[0] ^= <per-call counter>`): `assertion `left == right` failed` at this assert.
#[test]
fn ctx_tag_is_deterministic() {
    let aead = SaturninAeadCtx::new();
    let key = key_from(&k());
    let nonce = nonce_from(&n());
    let a = aead
        .encrypt(&key, &nonce, b"deterministic", Some(b"ad"))
        .unwrap();
    let b = aead
        .encrypt(&key, &nonce, b"deterministic", Some(b"ad"))
        .unwrap();
    assert_eq!(a, b);
}

/// The label must be load-bearing: two otherwise-identical CTX computations with different labels
/// must produce different tags. Falsified by using `Omit::Label` on both sides (collapses to
/// comparing identical inputs).
///
/// Scope: this exercises the documented input *encoding* via `SaturninHash` only; it never
/// calls `SaturninAeadCtx` and stays green under a broken implementation. The production
/// gates are `ctx_tag_matches_independent_reconstruction` and
/// `production_ctx_tag_binds_label_key_nonce_ad_and_base_tag`.
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
        .hash(&ctx_input(QCB_LABEL, &key, &nonce, &tag, a, Omit::None))
        .unwrap();
    assert_ne!(t1, t2, "changing only the label must change the CTX tag");

    let f1 = SaturninHash::new()
        .hash(&ctx_input(CTX_LABEL, &key, &nonce, &tag, a, Omit::Label))
        .unwrap();
    let f2 = SaturninHash::new()
        .hash(&ctx_input(QCB_LABEL, &key, &nonce, &tag, a, Omit::Label))
        .unwrap();
    assert_eq!(
        f1, f2,
        "sanity check on the falsification itself: omitting the label from both sides must \
         collapse the two inputs to identical bytes"
    );
}

/// The two label constants must differ at a fixed absolute byte offset (14, right after the
/// shared `libq.saturnin.` prefix), which is the structural reason no cross-mode `H_input` can
/// coincide regardless of `K, N, T, A` (see `crate::commit::CASCADE_CTX_LABEL_V0` docs).
#[test]
fn labels_domain_separate_qcb_and_cascade() {
    assert_eq!(&CTX_LABEL[..14], b"libq.saturnin.");
    assert_eq!(&QCB_LABEL[..14], b"libq.saturnin.");
    assert_ne!(
        CTX_LABEL[14], QCB_LABEL[14],
        "the two labels must diverge at byte 14"
    );

    let key = k();
    let nonce = n();
    let tag = [0x99u8; B];
    let a = b"cross-mode";
    let t_cascade = ctx_tag_ref(CTX_LABEL, &key, &nonce, &tag, a);
    let t_qcb = ctx_tag_ref(QCB_LABEL, &key, &nonce, &tag, a);
    assert_ne!(t_cascade, t_qcb);

    // Falsification: same label on both sides collapses to equal.
    let t_same_a = ctx_tag_ref(CTX_LABEL, &key, &nonce, &tag, a);
    let t_same_b = ctx_tag_ref(CTX_LABEL, &key, &nonce, &tag, a);
    assert_eq!(t_same_a, t_same_b);
}

/// AD must be bound by the commitment.
///
/// Scope: this exercises the documented input *encoding* via `SaturninHash` only; it never
/// calls `SaturninAeadCtx` and stays green under a broken implementation. The production
/// gates are `ctx_tag_matches_independent_reconstruction` and
/// `production_ctx_tag_binds_label_key_nonce_ad_and_base_tag`.
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

/// The nonce must be bound.
///
/// Scope: this exercises the documented input *encoding* via `SaturninHash` only; it never
/// calls `SaturninAeadCtx` and stays green under a broken implementation. The production
/// gates are `ctx_tag_matches_independent_reconstruction` and
/// `production_ctx_tag_binds_label_key_nonce_ad_and_base_tag`.
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

/// The key must be bound (the whole point of CMT-1).
///
/// Scope: this exercises the documented input *encoding* via `SaturninHash` only; it never
/// calls `SaturninAeadCtx` and stays green under a broken implementation. The production
/// gates are `ctx_tag_matches_independent_reconstruction` and
/// `production_ctx_tag_binds_label_key_nonce_ad_and_base_tag`.
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

/// Encrypt `pt`/`ad` under both types and return `(transmitted CTX tag T', raw base tag T)`.
/// `T` is taken from the uncommitted `SaturninAead`'s own tag on identical inputs — the same
/// independent source of `T` used by `ctx_tag_matches_independent_reconstruction`, and pinned
/// valid by `cross_mode_ciphertexts_rejected`'s body-sharing assertion.
fn prod_tag_and_base_t(
    key: &AeadKey,
    nonce: &Nonce,
    pt: &[u8],
    ad: Option<&[u8]>,
) -> ([u8; B], [u8; B]) {
    let plain_ct = SaturninAead::new().encrypt(key, nonce, pt, ad).unwrap();
    let committed_ct = SaturninAeadCtx::new().encrypt(key, nonce, pt, ad).unwrap();
    let mut t = [0u8; B];
    t.copy_from_slice(&plain_ct[plain_ct.len() - B..]);
    let mut t_prime = [0u8; B];
    t_prime.copy_from_slice(&committed_ct[committed_ct.len() - B..]);
    (t_prime, t)
}

/// **Per-field, production-facing statement of what the transmitted tag binds.**
///
/// Scope, stated honestly: `ctx_tag_matches_independent_reconstruction` above already covers the
/// same ground and does so over a length grid, so it — not this test — is the strongest gate on
/// `src/aead_ctx.rs`. What this test adds is a per-field assertion with a localized failure
/// message ("K is not bound in production", …), so a layout regression names the field it broke
/// instead of printing two opaque 32-byte arrays.
///
/// It exists mainly because the five `Omit`-pattern tests in this file (`label_is_load_bearing`,
/// `key_is_bound`, `nonce_is_bound`, `ad_is_bound_by_the_commitment`, `base_tag_is_bound`) read
/// as if they were that gate and are not: they operate purely on `ctx_input` + `SaturninHash` and
/// never call `SaturninAeadCtx`, so a production bug leaves all five green. OBSERVED during
/// review: with `CASCADE_CTX_LABEL_V0` swapped for `QCB_CTX_LABEL_V0` on both `aead_ctx.rs`
/// paths, all five still passed; with the real `&base_tag` argument replaced by a constant
/// `&[0x42u8; 32]`, `base_tag_is_bound` still passed. This test went red under both.
///
/// Confirmed red under three source mutations exercised during review (each applied to
/// `src/aead_ctx.rs`, observed, then reverted): label swap; constant base tag; `encrypt_bytes`
/// stubbed to forward the base tag instead of the CTX tag.
#[test]
fn production_ctx_tag_binds_label_key_nonce_ad_and_base_tag() {
    let kb = k();
    let nb = n();
    let key = key_from(&kb);
    let nonce = nonce_from(&nb);
    let pt = b"production binding";
    let a: &[u8] = b"ad-alpha";

    let (t_prime, t) = prod_tag_and_base_t(&key, &nonce, pt, Some(a));

    // The transmitted tag must be exactly the documented reconstruction. This single assertion
    // catches a wrong label, a wrong field order, and any field dropped from the real call.
    assert_eq!(
        t_prime.to_vec(),
        ctx_tag_ref(CTX_LABEL, &kb, &nb, &t, a),
        "transmitted CTX tag does not match LABEL || K || N || T || A over the real inputs"
    );

    // ...and must disagree once any single field is perturbed.
    assert_ne!(
        t_prime.to_vec(),
        ctx_tag_ref(QCB_LABEL, &kb, &nb, &t, a),
        "LABEL is not bound in production"
    );
    let mut kb2 = kb;
    kb2[0] ^= 0x01;
    assert_ne!(
        t_prime.to_vec(),
        ctx_tag_ref(CTX_LABEL, &kb2, &nb, &t, a),
        "K is not bound in production"
    );
    let mut nb2 = nb;
    nb2[0] ^= 0x01;
    assert_ne!(
        t_prime.to_vec(),
        ctx_tag_ref(CTX_LABEL, &kb, &nb2, &t, a),
        "N is not bound in production"
    );
    assert_ne!(
        t_prime.to_vec(),
        ctx_tag_ref(CTX_LABEL, &kb, &nb, &t, b"ad-bravo"),
        "A is not bound in production"
    );
    let mut t2 = t;
    t2[0] ^= 0x01;
    assert_ne!(
        t_prime.to_vec(),
        ctx_tag_ref(CTX_LABEL, &kb, &nb, &t2, a),
        "T is not bound in production"
    );

    // `T` must genuinely flow through to the transmitted tag: two messages sharing `(K, N, A)`
    // but not the plaintext have different base tags, and that difference must reach `T'`. This
    // is the half that a constant-`base_tag` implementation fails.
    let (t_prime_b, t_b) = prod_tag_and_base_t(&key, &nonce, b"production bindinG", Some(a));
    assert_ne!(
        t, t_b,
        "control: a different plaintext must change the base tag"
    );
    assert_ne!(
        t_prime, t_prime_b,
        "a change in the base tag T must propagate to the transmitted tag T'"
    );
}

/// The base tag `T` must be bound in the *documented encoding*: flipping one bit of `T` in the
/// reconstruction must change `T'`. This does **not** exercise `SaturninAeadCtx` — see
/// `production_ctx_tag_binds_label_key_nonce_ad_and_base_tag` for the gate that does.
#[test]
fn base_tag_is_bound() {
    let key = k();
    let nonce = n();
    let a = b"ad";
    let t1 = [0x55u8; B];
    let mut t2 = t1;
    t2[0] ^= 0x01;

    let got1 = ctx_tag_ref(CTX_LABEL, &key, &nonce, &t1, a);
    let got2 = ctx_tag_ref(CTX_LABEL, &key, &nonce, &t2, a);
    assert_ne!(
        got1, got2,
        "flipping one bit of the base tag must change T'"
    );
}

/// Round-trip for a range of lengths, with and without AD, plus every rejection path.
#[test]
fn round_trip_and_rejection() {
    let aead = SaturninAeadCtx::new();
    let key = key_from(&k());
    let nonce = nonce_from(&n());

    for len in [0usize, 1, 31, 32, 33, 64, 100] {
        let pt: Vec<u8> = (0..len).map(|i| i as u8).collect();
        for ad_opt in [None, Some(b"ad".as_slice())] {
            let ct = aead.encrypt(&key, &nonce, &pt, ad_opt).unwrap();
            assert_eq!(ct.len(), len + 32, "len={len}");
            let dec = aead.decrypt(&key, &nonce, &ct, ad_opt).unwrap();
            assert_eq!(dec, pt, "len={len}");
        }
    }

    // Oracle-discrimination guard: correct inputs decrypt, one-bit-off key does not, before any
    // negative assertion below is treated as meaningful.
    let ct_good = aead.encrypt(&key, &nonce, b"oracle control", None).unwrap();
    assert!(aead.decrypt(&key, &nonce, &ct_good, None).is_ok());
    let mut bad_key_bytes = k();
    bad_key_bytes[0] ^= 0x01;
    let bad_key = key_from(&bad_key_bytes);
    assert!(matches!(
        aead.decrypt(&bad_key, &nonce, &ct_good, None),
        Err(Error::VerificationFailed { .. })
    ));

    let ct = aead
        .encrypt(&key, &nonce, b"hello world", Some(b"ad"))
        .unwrap();

    // Tampered body byte.
    let mut bad_body = ct.clone();
    bad_body[0] ^= 0x80;
    assert!(matches!(
        aead.decrypt(&key, &nonce, &bad_body, Some(b"ad")),
        Err(Error::VerificationFailed { .. })
    ));
    assert_eq!(
        aead.decrypt_semantic(&key, &nonce, &bad_body, Some(b"ad"))
            .unwrap(),
        DecryptSemanticOutcome::AuthenticationFailed
    );

    // Tampered tag byte.
    let mut bad_tag = ct.clone();
    *bad_tag.last_mut().unwrap() ^= 0x01;
    assert!(matches!(
        aead.decrypt(&key, &nonce, &bad_tag, Some(b"ad")),
        Err(Error::VerificationFailed { .. })
    ));
    assert_eq!(
        aead.decrypt_semantic(&key, &nonce, &bad_tag, Some(b"ad"))
            .unwrap(),
        DecryptSemanticOutcome::AuthenticationFailed
    );

    // Wrong key (one bit off).
    assert!(aead.decrypt(&bad_key, &nonce, &ct, Some(b"ad")).is_err());

    // Wrong AD.
    assert!(aead.decrypt(&key, &nonce, &ct, Some(b"other-ad")).is_err());
    assert!(aead.decrypt(&key, &nonce, &ct, None).is_err());

    // Wrong nonce.
    let other_nonce = Nonce::new(vec![0xFFu8; 16]);
    assert!(aead.decrypt(&key, &other_nonce, &ct, Some(b"ad")).is_err());
}

/// `SaturninAead` ciphertext must be rejected by `SaturninAeadCtx::decrypt` and vice versa, even
/// though the two share the ciphertext *body* (only the last 32 bytes differ). This is the
/// wire-incompatibility proof the data-at-rest migration story depends on.
///
/// *Observed red* during review with `SaturninAeadCtx::encrypt_bytes` stubbed to append the base
/// tag instead of the CTX tag: `assertion `left != right` failed: the two modes must NOT share
/// the tag`. Also red with the tag check in `decrypt_core` forced true: `assertion failed:
/// matches!(committed.decrypt(&key, &nonce, &ct_plain, Some(b"ad")), ...)`.
#[test]
fn cross_mode_ciphertexts_rejected() {
    let key = key_from(&k());
    let nonce = nonce_from(&n());
    let plain = SaturninAead::new();
    let committed = SaturninAeadCtx::new();

    let ct_plain = plain
        .encrypt(&key, &nonce, b"hello world", Some(b"ad"))
        .unwrap();
    let ct_committed = committed
        .encrypt(&key, &nonce, b"hello world", Some(b"ad"))
        .unwrap();

    assert_eq!(ct_plain.len(), ct_committed.len());
    let body_len = ct_plain.len() - 32;
    assert_eq!(
        ct_plain[..body_len],
        ct_committed[..body_len],
        "the two modes must share the ciphertext body for identical inputs"
    );
    assert_ne!(
        ct_plain[body_len..],
        ct_committed[body_len..],
        "the two modes must NOT share the tag"
    );

    // A plain-mode ciphertext must not decrypt under the committed type.
    assert!(matches!(
        committed.decrypt(&key, &nonce, &ct_plain, Some(b"ad")),
        Err(Error::VerificationFailed { .. })
    ));
    // A committed-mode ciphertext must not decrypt under the plain type.
    assert!(matches!(
        plain.decrypt(&key, &nonce, &ct_committed, Some(b"ad")),
        Err(Error::VerificationFailed { .. })
    ));
}

/// Empty-input edges: empty pt + empty AD round-trips; `None` and `Some(b"")` AD produce identical
/// ciphertext (both reach the tag computation as `&[]`); empty vs 1-byte AD differ.
#[test]
fn empty_edges() {
    let aead = SaturninAeadCtx::new();
    let key = key_from(&k());
    let nonce = nonce_from(&n());

    let ct = aead.encrypt(&key, &nonce, b"", None).unwrap();
    assert_eq!(ct.len(), 32);
    assert_eq!(aead.decrypt(&key, &nonce, &ct, None).unwrap(), b"");

    let ct_none = aead.encrypt(&key, &nonce, b"msg", None).unwrap();
    let ct_empty_some = aead.encrypt(&key, &nonce, b"msg", Some(b"")).unwrap();
    assert_eq!(ct_none, ct_empty_some);

    let ct_one_byte_ad = aead.encrypt(&key, &nonce, b"msg", Some(b"x")).unwrap();
    assert_ne!(ct_none, ct_one_byte_ad);
}

/// Pinned CTX KAT: `SaturninAeadCtx` ciphertext hex, frozen from birth. Key/nonce are this file's
/// `k()` / `n()` — key = `00..1f`, nonce = `44` repeated 16 times (NOT `00..0f`; regenerate with
/// `n()`, not with `tests/aead_kat_pin.rs`'s nonce, or every vector below will mismatch).
/// Generated from this implementation once `ctx_tag_matches_independent_reconstruction` passed.
/// *Observed red* during review by swapping `CASCADE_CTX_LABEL_V0` for `QCB_CTX_LABEL_V0` in
/// `src/aead_ctx.rs`: `assertion `left == right` failed: pt= ad=`. Regenerate deliberately, never
/// to make a red test green: a change here means the wire format moved.
#[test]
fn pinned_ctx_kat_vectors() {
    let aead = SaturninAeadCtx::new();
    let key = key_from(&k());
    let nonce = nonce_from(&n());

    let cases: &[(&str, &str, &str)] = &[
        ("", "", CTX_KAT_EMPTY),
        ("616263", "686472", CTX_KAT_ABC_HDR),
    ];

    for (pt_hex, ad_hex, ct_hex) in cases {
        let pt = from_hex(pt_hex);
        let ad = from_hex(ad_hex);
        let ad_opt = if ad.is_empty() {
            None
        } else {
            Some(ad.as_slice())
        };
        let ct = aead.encrypt(&key, &nonce, &pt, ad_opt).unwrap();
        assert_eq!(ct, from_hex(ct_hex), "pt={pt_hex} ad={ad_hex}");
        let dec = aead.decrypt(&key, &nonce, &ct, ad_opt).unwrap();
        assert_eq!(dec, pt);
    }
}

// Generated by running this file's tests once `ctx_tag_matches_independent_reconstruction`
// passed, with this file's `k()` (= 00..1f) and `n()` (= 0x44 x16). Reproduce with:
//   cargo test -p lib-q-saturnin --features alloc,aead,hash --test cascade_ctx_spec
// Independently reproduced by a reviewer lane from a standalone crate
// outside the repo (scratchpad `gen-cur`), recomputing T' = SaturninHash(label || K || N || T || A)
// by hand — both constants matched.
const CTX_KAT_EMPTY: &str = "9d9abd60013c1d9b003690c48eaf9cc2f2fb04af521986832b7347387a7b26c5";
const CTX_KAT_ABC_HDR: &str =
    "bd09d6b6523dd56d3d5ef96fc1e6611acb967e204f2ae2c483ef35d121fca456a2d94a";

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
