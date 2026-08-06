//! Spec-conformance tests for Saturnin-QCB against the normative QCB definition.
//!
//! Oracle: Bhaumik, Bonnetain, Chailloux, Leurent, Naya-Plasencia, Schrottenloher and Seurin,
//! *QCB: Efficient Quantum-secure Authenticated Encryption*, ASIACRYPT 2021 (IACR ePrint
//! 2020/1304; full version). **Algorithm 1** and **Figures 2 and 3** define the mode; the
//! paragraph *Instantiation with Saturnin: Saturnin-QCB* fixes the domain separators.
//!
//! Algorithm 1, verbatim:
//!
//! ```text
//!  2: Split M into full blocks M_0, M_1, ... M_l and a final block M_* (partial or empty)
//!  3: Split A into A_0, A_1, ... A_j, A_*
//!  4: for all i = 0 to l do
//!  5:     C_i <- E~_{K,(0,IV,i)}(M_i)              > Encryption of block i
//!  6: end for
//!  7: C_* <- E~_{K,(1,IV,l)}(pad(M_*))             > Encryption of the final block
//!  8: T <- 0
//!  9: for all i = 0 to j do
//! 10:     T <- T (+) E~_{K,(2,IV,i)}(A_i)          > Absorb AD block i
//! 11: end for
//! 12: T <- T (+) E~_{K,(3,IV,j)}(pad(A_*))         > Absorb the final AD block
//! 13: T <- T (+) E~_{K,(4,IV,l)}(M_0 (+) ... (+) M_l (+) pad(M_*))
//! ```
//!
//! and the Saturnin instantiation: "The other modes of operation of the Saturnin submission use
//! values from 0 to 8 included, so we use `D = 9, 10, 11, 12 and 13` in Algorithm 1. ... We
//! define `E~_{k,(D,IV,i)}(x) = Saturnin^D_16(k XOR (IV||i), x)` ... The IV and the block number
//! are simply concatenated."
//!
//! Hence the five normative domains are
//!
//! | D  | Algorithm 1 | role                                    |
//! |----|-------------|-----------------------------------------|
//! | 9  | line 5      | full message block `M_i`                |
//! | 10 | line 7      | final padded message block `pad(M_*)`   |
//! | 11 | line 10     | full associated-data block `A_i`        |
//! | 12 | line 12     | final padded AD block `pad(A_*)`        |
//! | 13 | line 13     | tag / message checksum                  |
//!
//! and **every** tweak — AD tweaks included — carries the IV. The paper states the reason
//! explicitly (Section 5, *Avoiding Quantum Attacks*): "It is important to include the IV in the
//! tweak when processing the AD. Otherwise, there is a quantum forgery attack based on Deutsch's
//! algorithm."

#![cfg(all(feature = "alloc", feature = "qcb"))]

use lib_q_saturnin::{
    Aead,
    AeadKey,
    Nonce,
    SaturninQcb,
    SaturninTbc,
};

/// Saturnin block size in bytes (256-bit block).
const B: usize = 32;

/// Normative domain separators (QCB paper, Saturnin instantiation).
const D_MSG_FULL: u8 = 9;
const D_MSG_FINAL: u8 = 10;
const D_AD_FULL: u8 = 11;
const D_AD_FINAL: u8 = 12;
const D_TAG: u8 = 13;

/// `T = IV || i`: the 128-bit IV in the high half, the block index big-endian in the low half.
fn tweak(nonce16: &[u8; 16], block_index: u64) -> [u8; B] {
    let mut t = [0u8; B];
    t[0..16].copy_from_slice(nonce16);
    t[24..32].copy_from_slice(&block_index.to_be_bytes());
    t
}

fn xor_into(acc: &mut [u8; B], v: &[u8; B]) {
    for i in 0..B {
        acc[i] ^= v[i];
    }
}

/// `10*` padding of a partial (possibly empty) tail into exactly one block.
fn pad_tail(tail: &[u8]) -> [u8; B] {
    assert!(tail.len() < B, "pad() takes the partial tail only");
    let mut out = [0u8; B];
    out[..tail.len()].copy_from_slice(tail);
    out[tail.len()] = 0x80;
    out
}

/// An independent transcription of Algorithm 1 for the Saturnin instantiation, written from the
/// paper and using only the public [`SaturninTbc`] primitive. This is the oracle the mode is
/// checked against; it deliberately shares no code with `qcb.rs`.
///
/// Convention where the paper is silent: when the input has no full blocks, `l` (resp. `j`) is
/// taken to be `0`. No tweak collision arises, because in that case no domain-9 (resp. domain-11)
/// call is made at all.
fn qcb_reference_encrypt(key: &[u8; 32], nonce: &[u8; 16], m: &[u8], a: &[u8]) -> Vec<u8> {
    let e9 = SaturninTbc::new(D_MSG_FULL).unwrap();
    let e10 = SaturninTbc::new(D_MSG_FINAL).unwrap();
    let e11 = SaturninTbc::new(D_AD_FULL).unwrap();
    let e12 = SaturninTbc::new(D_AD_FINAL).unwrap();
    let e13 = SaturninTbc::new(D_TAG).unwrap();

    let m_full = m.len() / B;
    let l = m_full.saturating_sub(1) as u64;

    let mut out = Vec::with_capacity((m_full + 2) * B);
    let mut checksum = [0u8; B];

    // Lines 4-6.
    for i in 0..m_full {
        let mut blk = [0u8; B];
        blk.copy_from_slice(&m[i * B..(i + 1) * B]);
        xor_into(&mut checksum, &blk);
        e9.encrypt_block(key, &tweak(nonce, i as u64), &mut blk)
            .unwrap();
        out.extend_from_slice(&blk);
    }
    // Line 7.
    let mut last = pad_tail(&m[m_full * B..]);
    xor_into(&mut checksum, &last);
    e10.encrypt_block(key, &tweak(nonce, l), &mut last).unwrap();
    out.extend_from_slice(&last);

    // Lines 8-12.
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

    // Line 13.
    let mut chk = checksum;
    e13.encrypt_block(key, &tweak(nonce, l), &mut chk).unwrap();
    xor_into(&mut tag, &chk);

    out.extend_from_slice(&tag);
    out
}

fn k() -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = i as u8;
    }
    k
}

fn n1() -> [u8; 16] {
    [0x11u8; 16]
}

fn n2() -> [u8; 16] {
    [0x22u8; 16]
}

/// The oracle must be able to disagree with itself, or "reference matches" would be vacuous.
#[test]
fn reference_oracle_discriminates() {
    let a = qcb_reference_encrypt(&k(), &n1(), b"abc", b"hdr");
    assert_ne!(
        a,
        qcb_reference_encrypt(&k(), &n2(), b"abc", b"hdr"),
        "reference must depend on the nonce"
    );
    assert_ne!(
        a,
        qcb_reference_encrypt(&k(), &n1(), b"abc", b"hdX"),
        "reference must depend on the associated data"
    );
    assert_ne!(
        a,
        qcb_reference_encrypt(&k(), &n1(), b"abd", b"hdr"),
        "reference must depend on the message"
    );
}

/// **D2.** `SaturninQcb::encrypt` must equal Algorithm 1 with `D = 9, 10, 11, 12, 13`.
#[test]
fn matches_algorithm_1_of_the_qcb_paper() {
    let key = AeadKey::new(k().to_vec());
    let nonce = Nonce::new(n1().to_vec());
    let aead = SaturninQcb::new();

    for m_len in [0usize, 1, 31, 32, 33, 64, 95, 96, 200] {
        for a_len in [0usize, 1, 31, 32, 33, 64, 100] {
            let m: Vec<u8> = (0..m_len).map(|i| i as u8).collect();
            let a: Vec<u8> = (0..a_len).map(|i| (0xA0 ^ i) as u8).collect();
            let ad_opt = if a.is_empty() {
                None
            } else {
                Some(a.as_slice())
            };
            let got = aead.encrypt(&key, &nonce, &m, ad_opt).unwrap();
            let want = qcb_reference_encrypt(&k(), &n1(), &m, &a);
            assert_eq!(
                got, want,
                "Algorithm 1 mismatch at m_len={m_len} a_len={a_len}"
            );
        }
    }
}

/// **D1.** Every AD tweak must carry the IV (QCB paper, Section 5, *Avoiding Quantum Attacks*).
///
/// Observable consequence if it does not: the AD's whole contribution to the tag is a function of
/// the AD alone, so the tag difference produced by swapping `A -> A'` is identical under every
/// nonce.
#[test]
fn ad_contribution_to_the_tag_depends_on_the_nonce() {
    let aead = SaturninQcb::new();
    let key = AeadKey::new(k().to_vec());
    let m = b"fixed message, one block or so..";
    let a = b"associated-data-alpha";
    let a2 = b"associated-data-bravo";

    let delta = |nonce: &[u8; 16]| -> Vec<u8> {
        let nn = Nonce::new(nonce.to_vec());
        let t1 = aead.encrypt(&key, &nn, m, Some(a)).unwrap();
        let t2 = aead.encrypt(&key, &nn, m, Some(a2)).unwrap();
        t1.iter().zip(t2.iter()).map(|(x, y)| x ^ y).collect()
    };

    assert_ne!(
        delta(&n1()),
        delta(&n2()),
        "the AD tweak does not bind the nonce: swapping the AD moves the tag by a \
         nonce-independent constant, which is exactly the configuration the QCB paper warns \
         about (quantum forgery via Deutsch's algorithm)"
    );
}

/// **D1, impact.** The forgery the paper warns about, carried out end to end.
///
/// The nonce-independent constant `Sigma(A) XOR Sigma(A')` learned under one nonce is replayed to
/// forge a *fresh-nonce* ciphertext with swapped associated data. A Q2 adversary learns that
/// constant with a **single in-model superposition query** at `N1` (Deutsch / Bernstein-Vazirani
/// on the AD register: the AD's contribution is an F2-affine function of the per-block choices,
/// so its coefficients fall out of one query). This harness has no quantum oracle, so it learns
/// the same constant classically with two queries at `N1`; the transfer step — the part D1 breaks
/// — uses a fresh nonce `N2` and is what this test asserts must fail.
#[test]
fn ad_difference_does_not_transfer_across_nonces() {
    let aead = SaturninQcb::new();
    let key = AeadKey::new(k().to_vec());
    let m = b"transfer-probe message payload..";
    let a = b"associated-data-alpha";
    let a2 = b"associated-data-bravo";

    // Learn the constant at N1 (a Q2 adversary needs one superposition query here).
    let nonce1 = Nonce::new(n1().to_vec());
    let c_a = aead.encrypt(&key, &nonce1, m, Some(a)).unwrap();
    let c_b = aead.encrypt(&key, &nonce1, m, Some(a2)).unwrap();
    let tag_len = SaturninQcb::tag_size();
    let off = c_a.len() - tag_len;
    let delta: Vec<u8> = c_a[off..]
        .iter()
        .zip(c_b[off..].iter())
        .map(|(x, y)| x ^ y)
        .collect();

    // Transfer to a FRESH nonce and forge.
    let nonce2 = Nonce::new(n2().to_vec());
    let genuine = aead
        .encrypt(&key, &nonce2, b"a different plaintext entirely!!", Some(a))
        .unwrap();
    let mut forged = genuine.clone();
    let foff = forged.len() - tag_len;
    for (i, d) in delta.iter().enumerate() {
        forged[foff + i] ^= d;
    }
    assert_ne!(forged, genuine, "the forgery must be a new ciphertext");

    assert!(
        aead.decrypt(&key, &nonce2, &forged, Some(a2)).is_err(),
        "FORGERY ACCEPTED: an AD-swap offset learned under nonce N1 verified under a fresh \
         nonce N2. The AD tweak is nonce-independent, so the mode has no Q2 unforgeability."
    );
}

/// **D2, structural.** The tag must not be computable from only three domains: the spec needs
/// five distinct Saturnin permutations, and in particular the final padded AD block must use a
/// different domain from the full AD blocks. Detects the collapse `D_AD_FINAL == D_AD_FULL`.
#[test]
fn final_ad_block_uses_its_own_domain() {
    let aead = SaturninQcb::new();
    let key = AeadKey::new(k().to_vec());
    let nonce = Nonce::new(n1().to_vec());
    let m = b"m";

    // `A1` is one full block plus an empty tail -> blocks (A_0 = X, pad(A_*) = 10*).
    // `A2` is 31 bytes -> a single block pad(A_*) = X'||0x80, no full block.
    // Build a case where a single-domain implementation folds two equal ciphertext blocks and
    // cancels them, while the spec's two distinct domains do not.
    let x = [0x5Au8; B];
    let mut a_same = Vec::new();
    a_same.extend_from_slice(&x);
    a_same.extend_from_slice(&x[..31]); // second block pads to x[..31] || 0x80

    let ct = aead.encrypt(&key, &nonce, m, Some(&a_same)).unwrap();
    let want = qcb_reference_encrypt(&k(), &n1(), m, &a_same);
    assert_eq!(
        ct, want,
        "final AD block must be absorbed under domain 12, distinct from the domain 11 used for \
         full AD blocks"
    );
}

/// **D2 / spec.** Empty associated data still absorbs one padded block (Algorithm 1 line 12 is
/// unconditional): `pad(A_*) = 10*`. Skipping it makes `A = \"\"` fold to zero.
#[test]
fn empty_ad_still_absorbs_one_padded_block() {
    let aead = SaturninQcb::new();
    let key = AeadKey::new(k().to_vec());
    let nonce = Nonce::new(n1().to_vec());

    let with_none = aead.encrypt(&key, &nonce, b"payload", None).unwrap();
    let want = qcb_reference_encrypt(&k(), &n1(), b"payload", b"");
    assert_eq!(
        with_none, want,
        "empty AD must still contribute E~_{{K,(12,IV,0)}}(10*) to the tag"
    );
}
