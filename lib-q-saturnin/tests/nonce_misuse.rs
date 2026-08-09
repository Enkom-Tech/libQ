//! Nonce-reuse universal forgery against Saturnin-QCB (card `t_883438eb`).
//!
//! # The claim under test
//!
//! `src/qcb.rs`'s module docs assert: "A single repeated nonce is a universal forgery. ...
//! Three chosen-plaintext queries at one repeated nonce are enough to produce a valid,
//! authenticating ciphertext for a chosen plaintext that was never queried." This file is the
//! reproduction that backs that sentence and the `Cargo.toml` `qcb` feature-gate rationale that
//! cites it. Until this file existed, that citation pointed at
//! `lib-q-aead/tests/nonce_misuse.rs`, which measures **keystream leakage** (a confidentiality
//! property, via `leaked_bytes`/`contiguous_leak_run`) and contains no QCB test at all — it does
//! not demonstrate "universal forgery, not merely a keystream leak", the one thing the citation
//! used it to distinguish.
//!
//! # Why this is a genuine forgery and not a replay
//!
//! The target plaintext is chosen **first**, before any oracle query is made (see
//! `TARGET IS CHOSEN FIRST` below) — a test that instead picked its target after seeing query
//! responses would only be demonstrating replay. The forged ciphertext is assembled entirely
//! from bytes returned by three queries, is checked to differ from all three of them, and is
//! then handed to the *production* [`Aead::decrypt`] entry point, which must accept it and
//! recover exactly the pre-chosen target.
//!
//! # The mechanism (why three queries at one nonce suffice)
//!
//! For a fixed `(key, nonce)`, every per-block Saturnin-QCB tweak `nonce ‖ pad ‖ block_index`
//! collapses to a value that depends only on the block index and domain, not on the message
//! content — so `E9,i := TBC_message(tweak(N,i))` and `E10,l := TBC_message_final(tweak(N,l))`
//! are *fixed* permutations once the nonce repeats, and the checksum fed into the tag's TBC
//! (`TBC_tag(tweak(N,l))`) is the plain XOR of (attacker-chosen!) plaintext blocks. XOR is
//! commutative, so:
//!
//! - Querying `B1 ‖ P` and `P ‖ B1` (same two blocks, swapped) gives the same checksum (`B1 ^ P ^
//!   PAD`, `PAD` = the mandatory `10*` padding block Algorithm 1 always appends) via two
//!   *different* block splits, exposing `E9,0(P)` from one query and `E9,1(P)` from the other.
//! - Querying `B3 ‖ B3` (two copies of an unrelated block) drives the checksum to exactly `PAD`
//!   (`B3 ^ B3 = 0`), which is also the checksum of the doubled target block `P ‖ P` — so that
//!   query's tag *is* the target's tag, and its final `10*` padding ciphertext block *is* the
//!   target's final block (same tweak, same plaintext `PAD`).
//!
//! Splicing `E9,0(P)` (from query 2), `E9,1(P)` (from query 1), and the final block + committed
//! tag (from query 3) reproduces, byte for byte, what `SaturninQcb::encrypt` would have output
//! for `P ‖ P` — without ever having queried `P ‖ P`. The CTX committing tag does not interrupt
//! this: `T' = SaturninHash(label ‖ K ‖ N ‖ T ‖ A)` depends only on the *raw* tag `T`, and `T`
//! collides by construction (same checksum, same tweak, same empty AD).
//!
//! # Controls
//!
//! - `distinct_nonces_do_not_forge` — the identical query/splice recipe, but each query (and the
//!   forgery attempt) uses a distinct nonce. If this failed to fail, the "success" above would be
//!   a bug in the test harness, not a property of the mode.
//! - `ctr_cascade_rejects_the_analogous_splice` — the same repeated-nonce splice recipe run
//!   against `SaturninAead` (CTR-Cascade), the mode the module docs claim is the contrast case:
//!   "degrades gracefully to a keystream leak but a forgery still requires breaking the underlying
//!   PRP/MAC". Confirms QCB is not merely "a test that always says forge" and pins that
//!   CTR-Cascade is not vulnerable to this specific splice.

#![cfg(feature = "qcb")]

use lib_q_saturnin::{
    Aead,
    AeadKey,
    Nonce,
    SaturninAead,
    SaturninQcb,
};

fn key() -> AeadKey {
    AeadKey::new((0..32u8).collect::<Vec<_>>())
}

fn nonce(seed: u8) -> Nonce {
    Nonce::new(vec![seed; 16])
}

/// One chosen-plaintext query: encrypt the 64-byte concatenation of two 32-byte blocks under
/// `(k, n)` with empty associated data.
fn qcb_query(
    aead: &SaturninQcb,
    k: &AeadKey,
    n: &Nonce,
    first: &[u8; 32],
    second: &[u8; 32],
) -> Vec<u8> {
    let mut pt = Vec::with_capacity(64);
    pt.extend_from_slice(first);
    pt.extend_from_slice(second);
    aead.encrypt(k, n, &pt, None)
        .expect("query encrypt must succeed")
}

/// Splice the forged ciphertext from three query responses, per the mechanism above:
/// block0 <- q2's block0 (E9,0(P)), block1 <- q1's block1 (E9,1(P)), final pad block + committed
/// tag <- q3 (checksum collapses to PAD, matching the target's).
fn splice(q1: &[u8], q2: &[u8], q3: &[u8]) -> Vec<u8> {
    let mut forged = Vec::with_capacity(128);
    forged.extend_from_slice(&q2[0..32]);
    forged.extend_from_slice(&q1[32..64]);
    forged.extend_from_slice(&q3[64..96]);
    forged.extend_from_slice(&q3[96..128]);
    forged
}

#[test]
fn qcb_nonce_reuse_is_a_universal_forgery() {
    let aead = SaturninQcb::new();
    let k = key();
    let n = nonce(0x42);

    // --- TARGET IS CHOSEN FIRST, before any query is made. -------------------------------
    let target_block: [u8; 32] = core::array::from_fn(|i| 0xABu8.wrapping_add(i as u8));
    let target_plaintext: Vec<u8> = target_block
        .iter()
        .chain(target_block.iter())
        .copied()
        .collect();
    assert_eq!(
        target_plaintext.len(),
        64,
        "target is the 64-byte plaintext P || P"
    );

    // --- Exactly three chosen-plaintext queries, all at the SAME (repeated) nonce. -------
    let b1: [u8; 32] = core::array::from_fn(|i| 0x11u8.wrapping_add(i as u8));
    let b3: [u8; 32] = core::array::from_fn(|i| 0x77u8.wrapping_add(i as u8));
    assert_ne!(b1, target_block);
    assert_ne!(b3, target_block);

    let q1 = qcb_query(&aead, &k, &n, &b1, &target_block); // B1 || P
    let q2 = qcb_query(&aead, &k, &n, &target_block, &b1); // P || B1
    let q3 = qcb_query(&aead, &k, &n, &b3, &b3); // B3 || B3

    // Two full blocks + mandatory 10* pad block + 32-byte CTX tag.
    assert_eq!(q1.len(), 128);
    assert_eq!(q2.len(), 128);
    assert_eq!(q3.len(), 128);

    let forged = splice(&q1, &q2, &q3);

    // The forged ciphertext must never have been returned by any query.
    assert_ne!(
        forged, q1,
        "forged ciphertext must not equal query 1's response"
    );
    assert_ne!(
        forged, q2,
        "forged ciphertext must not equal query 2's response"
    );
    assert_ne!(
        forged, q3,
        "forged ciphertext must not equal query 3's response"
    );

    // This IS the forgery: production decrypt accepts a ciphertext assembled purely from
    // spliced query bytes, and recovers the pre-chosen target plaintext.
    let decrypted = aead
        .decrypt(&k, &n, &forged, None)
        .expect("forged ciphertext must be ACCEPTED by production decrypt -- this is the forgery");
    assert_eq!(
        decrypted, target_plaintext,
        "forged ciphertext must decrypt to exactly the pre-chosen target, not something incidental"
    );
}

/// CONTROL (negative): the identical recipe, but every query (and the forgery attempt) uses a
/// distinct nonce. If this test failed to fail, the "success" above would be a bug in the
/// splicing harness, not a property of nonce reuse.
#[test]
fn control_distinct_nonces_do_not_forge() {
    let aead = SaturninQcb::new();
    let k = key();

    let target_block: [u8; 32] = core::array::from_fn(|i| 0xABu8.wrapping_add(i as u8));
    let target_plaintext: Vec<u8> = target_block
        .iter()
        .chain(target_block.iter())
        .copied()
        .collect();

    let b1: [u8; 32] = core::array::from_fn(|i| 0x11u8.wrapping_add(i as u8));
    let b3: [u8; 32] = core::array::from_fn(|i| 0x77u8.wrapping_add(i as u8));

    let n1 = nonce(0x01);
    let n2 = nonce(0x02);
    let n3 = nonce(0x03);
    assert_ne!(n1.data, n2.data);
    assert_ne!(n2.data, n3.data);
    assert_ne!(n1.data, n3.data);

    let q1 = qcb_query(&aead, &k, &n1, &b1, &target_block);
    let q2 = qcb_query(&aead, &k, &n2, &target_block, &b1);
    let q3 = qcb_query(&aead, &k, &n3, &b3, &b3);

    let forged = splice(&q1, &q2, &q3);

    // Try the forgery under every nonce that appeared; none may accept it, and none may
    // produce the target plaintext.
    for n in [&n1, &n2, &n3] {
        match aead.decrypt(&k, n, &forged, None) {
            Err(_) => {}
            Ok(pt) => assert_ne!(
                pt, target_plaintext,
                "distinct-nonce splice must not forge the target plaintext under nonce {:?}",
                n.data
            ),
        }
    }
}

/// CONTROL (contrast mode): the same repeated-nonce splice recipe against `SaturninAead`
/// (CTR-Cascade) — the mode the module docs single out as the one that "degrades gracefully to a
/// keystream leak but a forgery still requires breaking the underlying PRP/MAC". CTR-Cascade's
/// tag is a cascade over the *ciphertext* (not an XOR checksum of chosen plaintext encrypted by a
/// keyed permutation), so the same splice must not authenticate.
#[test]
fn control_ctr_cascade_rejects_the_analogous_splice() {
    let aead = SaturninAead::new();
    let k = key();
    let n = nonce(0x42); // same repeated nonce as the QCB forgery, deliberately

    let target_block: [u8; 32] = core::array::from_fn(|i| 0xABu8.wrapping_add(i as u8));
    let target_plaintext: Vec<u8> = target_block
        .iter()
        .chain(target_block.iter())
        .copied()
        .collect();

    let b1: [u8; 32] = core::array::from_fn(|i| 0x11u8.wrapping_add(i as u8));
    let b3: [u8; 32] = core::array::from_fn(|i| 0x77u8.wrapping_add(i as u8));

    let mut pt1 = Vec::with_capacity(64);
    pt1.extend_from_slice(&b1);
    pt1.extend_from_slice(&target_block);
    let mut pt2 = Vec::with_capacity(64);
    pt2.extend_from_slice(&target_block);
    pt2.extend_from_slice(&b1);
    let mut pt3 = Vec::with_capacity(64);
    pt3.extend_from_slice(&b3);
    pt3.extend_from_slice(&b3);

    let q1 = aead.encrypt(&k, &n, &pt1, None).unwrap();
    let q2 = aead.encrypt(&k, &n, &pt2, None).unwrap();
    let q3 = aead.encrypt(&k, &n, &pt3, None).unwrap();

    // CTR-Cascade ciphertext is exactly plaintext_len + 32-byte tag, no padding block: 96 bytes.
    assert_eq!(q1.len(), 96);
    assert_eq!(q2.len(), 96);
    assert_eq!(q3.len(), 96);

    // Analogous splice: keystream-block0 from q2, keystream-block1 from q1, tag from q3.
    let mut forged = Vec::with_capacity(96);
    forged.extend_from_slice(&q2[0..32]);
    forged.extend_from_slice(&q1[32..64]);
    forged.extend_from_slice(&q3[64..96]);

    assert_ne!(forged, q1);
    assert_ne!(forged, q2);
    assert_ne!(forged, q3);

    match aead.decrypt(&k, &n, &forged, None) {
        Err(_) => {} // expected: the cascade tag does not validate.
        Ok(pt) => assert_ne!(
            pt, target_plaintext,
            "CTR-Cascade must reject the QCB-style splice, not silently authenticate the forged target"
        ),
    }
}
