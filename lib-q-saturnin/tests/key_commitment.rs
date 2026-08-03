//! Key-commitment (CMT-1) tests for the Saturnin AEAD modes.
//!
//! CMT-1 asks: can one ciphertext be made to decrypt successfully under two *distinct* keys?
//! The standard definition lets the adversary pick the nonce and associated data on each side
//! (only the ciphertext string is shared), which is exactly the multi-recipient / envelope
//! setting where each recipient's blob carries its own header.
//!
//! Result: **Saturnin-QCB is not key-committing.** The attack has two parts:
//!
//! 1. a `1/256`-per-try search for a ciphertext body whose decryption carries valid `10*`
//!    padding under *both* keys — expected `~2^8` tries, `2` Saturnin block calls each, and
//!    2. a closed-form solve for the second side's associated data — `5` block calls, no search.
//!
//! Part 1 dominates and is what the cost figure in the crate READMEs quotes; it is measured over
//! independent key pairs by [`qcb_cmt1_attack_cost_measured`], not read off a single lucky run.
//! Neither part searches the 256-bit tag.
//!
//! The cause of part 2 is structural and is visible in `qcb.rs::compute_tag`:
//!
//! ```text
//! tag = TBC_10(K, tweak(N, last))(checksum)  XOR  ad_auth
//! ad_auth = XOR_j TBC_11(K, ad_tweak(j))(pad(A)_j)
//! ```
//!
//! `ad_auth` enters the tag by plain XOR, and `TBC_11` is a *public, invertible* permutation
//! once the key is known. An adversary who holds both keys therefore solves for the second
//! side's associated data in closed form instead of searching for it.
//!
//! Saturnin-CTR-Cascade (`aead.rs`) does not have this shape: its associated data is folded
//! through a Matyas–Meyer–Oseas chain, which is not invertible in the data, so steering the
//! running tag to a chosen value is a preimage problem. See `lib-q-aead/tests/key_commitment.rs`
//! for the bounded search that covers it and the other registry AEADs — and for why a null
//! search result there is **not** evidence that those modes commit.

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
/// `qcb.rs::DOMAIN_MESSAGE`
const DOMAIN_MESSAGE: u8 = 9;
/// `qcb.rs::DOMAIN_TAG`
const DOMAIN_TAG: u8 = 10;
/// `qcb.rs::DOMAIN_AD`
const DOMAIN_AD: u8 = 11;

/// Block calls the attack spends outside the padding search, counted against `qcb.rs`:
/// `Aead::encrypt` of a one-block plaintext with empty associated data is 1 `msg.encrypt_block`
/// plus 1 `tag.encrypt_block` (`absorb_ad` returns early on empty AD) = 2; the closed-form solve
/// is 1 `tag.encrypt_block` + 1 `ad.encrypt_block` + 1 `ad.decrypt_block` = 3.
const FIXED_BLOCK_CALLS: u64 = 5;
/// Block calls per padding-search try: one `encrypt_block` under `k2`, one `decrypt_block`
/// under `k1`.
const BLOCK_CALLS_PER_TRIAL: u64 = 2;

/// `qcb.rs::SaturninQcb::tweak` — `N (16) || 0x00 * 8 || block_index_be_u64 (8)`.
fn tweak(nonce16: &[u8; 16], block_index: u64) -> [u8; B] {
    let mut t = [0u8; B];
    t[0..16].copy_from_slice(nonce16);
    t[24..32].copy_from_slice(&block_index.to_be_bytes());
    t
}

/// `qcb.rs::SaturninQcb::ad_tweak` — same layout with the nonce field zeroed.
fn ad_tweak(block_index: u64) -> [u8; B] {
    let mut t = [0u8; B];
    t[24..32].copy_from_slice(&block_index.to_be_bytes());
    t
}

fn xor32(a: &[u8; B], b: &[u8; B]) -> [u8; B] {
    let mut out = [0u8; B];
    for i in 0..B {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// Deterministic xorshift64* — test-only, not a CSPRNG.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&v[..n]);
        }
    }
}

/// One completed CMT-1 break.
struct Break {
    /// Padding-search tries consumed (each costs [`BLOCK_CALLS_PER_TRIAL`] block calls).
    trials: u64,
    ciphertext: Vec<u8>,
    ad2: Vec<u8>,
    pt1: Vec<u8>,
    pt2: Vec<u8>,
}

impl Break {
    fn block_calls(&self) -> u64 {
        self.trials * BLOCK_CALLS_PER_TRIAL + FIXED_BLOCK_CALLS
    }
}

/// Run the whole CMT-1 attack for one `(k1, k2, nonce)` instance and verify it through the
/// public [`Aead`] API. Returns `None` only if the padding search exhausts its bound (expected
/// probability ~`(1 - 2^-8)^500_000`, i.e. never).
///
/// Search condition is the *strict* one — byte 31 of side 1's decrypted block must be `0x80`,
/// with no trailing zeros — because that is what makes `pt1 = m1[..31]` reconstruct exactly the
/// block the attacker chose. `qcb.rs::unpad_len` also accepts `0x80` followed by zeros, which is
/// marginally cheaper for the attacker (`1/255` rather than `1/256`) but would break the
/// reconstruction, so this harness does not use it.
fn qcb_cmt1_attack(k1: &[u8; 32], k2: &[u8; 32], n: &[u8; 16]) -> Option<Break> {
    let aead = SaturninQcb::new();
    let msg_tbc = SaturninTbc::new(DOMAIN_MESSAGE).unwrap();
    let tag_tbc = SaturninTbc::new(DOMAIN_TAG).unwrap();
    let ad_tbc = SaturninTbc::new(DOMAIN_AD).unwrap();
    assert_ne!(k1, k2, "the two keys must be distinct for this to be CMT-1");

    // ---- step 1: the search ----------------------------------------------------------------
    // Pick a one-block ciphertext body whose decryption carries valid `10*` padding under BOTH
    // keys. Under k2 that holds by construction; under k1 it is a 1-in-256 coin. This loop is
    // the whole "search" in the attack — everything after it is deterministic algebra.
    let mut trials = 0u64;
    let mut found: Option<([u8; B], [u8; B], [u8; B])> = None;
    for t in 0u32..500_000 {
        trials = u64::from(t) + 1;
        let mut m2 = [0u8; B];
        m2[..4].copy_from_slice(&t.to_le_bytes());
        m2[31] = 0x80; // pad(31-byte plaintext)

        let mut blk = m2;
        msg_tbc.encrypt_block(k2, &tweak(n, 0), &mut blk).unwrap();

        let mut m1 = blk;
        msg_tbc.decrypt_block(k1, &tweak(n, 0), &mut m1).unwrap();
        if m1[31] == 0x80 {
            // checksum of a one-block message == the block itself
            found = Some((blk, m1, m2));
            break;
        }
    }
    let (body, cs1, cs2) = found?;

    // ---- step 2: side 1 --------------------------------------------------------------------
    // Side 1 uses empty associated data, so ad_auth1 == 0 and the tag is just the encrypted
    // checksum. Take the whole ciphertext straight from the public encrypt API so the test
    // cannot drift from the implementation.
    let pt1 = cs1[..31].to_vec();
    let key1 = AeadKey::new(k1.to_vec());
    let key2 = AeadKey::new(k2.to_vec());
    let nonce = Nonce::new(n.to_vec());
    let ciphertext = aead.encrypt(&key1, &nonce, &pt1, None).unwrap();
    assert_eq!(ciphertext.len(), 2 * B);
    assert_eq!(&ciphertext[..B], &body[..], "body reconstruction diverged");

    let mut tag = [0u8; B];
    tag.copy_from_slice(&ciphertext[B..]);

    // ---- step 3: solve side 2's associated data in closed form -----------------------------
    // Required: ad_auth2 == TBC_10(k2,..)(cs2) XOR tag.
    let mut t2core = cs2;
    tag_tbc
        .encrypt_block(k2, &tweak(n, 0), &mut t2core)
        .unwrap();
    let want_ad_auth2 = xor32(&t2core, &tag);

    // A two-block associated data gives one fully free block (`b0`) plus one block whose tail
    // must hold the padding marker (`b1`). Fix b1, then invert TBC_11 for b0. No search.
    let mut b1 = [0u8; B];
    b1[31] = 0x80; // pad(63-byte AD) == A2 || 0x80
    let mut v1 = b1;
    ad_tbc.encrypt_block(k2, &ad_tweak(1), &mut v1).unwrap();

    let mut b0 = xor32(&want_ad_auth2, &v1);
    ad_tbc.decrypt_block(k2, &ad_tweak(0), &mut b0).unwrap();

    let mut ad2 = Vec::with_capacity(63);
    ad2.extend_from_slice(&b0);
    ad2.extend_from_slice(&b1[..31]);
    assert_eq!(ad2.len(), 63);

    // ---- verdict: both sides verified through the public API only --------------------------
    let out1 = aead
        .decrypt(&key1, &nonce, &ciphertext, None)
        .expect("side 1 must decrypt");
    let out2 = aead
        .decrypt(&key2, &nonce, &ciphertext, Some(&ad2))
        .expect("CMT-1 break failed: side 2 did not decrypt");
    assert_ne!(out1, out2, "the two plaintexts should differ");

    Some(Break {
        trials,
        ciphertext,
        ad2,
        pt1: out1,
        pt2: out2,
    })
}

/// The oracle used to declare success must be able to say both yes and no, or a "no hits found"
/// result would be worthless. Pin both directions before any attack runs.
#[test]
fn qcb_decrypt_oracle_discriminates() {
    let aead = SaturninQcb::new();
    let k_good = AeadKey::new(vec![0x11u8; 32]);
    let k_bad = AeadKey::new(vec![0x12u8; 32]);
    let n = Nonce::new(vec![0x33u8; 16]);
    let ct = aead.encrypt(&k_good, &n, b"oracle control", None).unwrap();

    assert!(
        aead.decrypt(&k_good, &n, &ct, None).is_ok(),
        "oracle refused the correct key: a negative search result would be meaningless"
    );
    assert!(
        aead.decrypt(&k_bad, &n, &ct, None).is_err(),
        "oracle accepted a wrong key that differs in one bit: the gate cannot fail"
    );
}

/// **CMT-1 break on Saturnin-QCB.** Produces one ciphertext that decrypts successfully under two
/// distinct 256-bit keys, with the *same* nonce.
#[test]
fn qcb_is_not_key_committing_ad_is_solvable_in_closed_form() {
    let brk = qcb_cmt1_attack(&[0x11u8; 32], &[0x22u8; 32], &[0x33u8; 16])
        .expect("no dual-padding body in 500k tries (expected ~256)");
    println!(
        "QCB CMT-1 break: 1 ciphertext ({} B) valid under 2 distinct keys; \
         padding-search tries = {}, block calls = {}, tag searches = 0; \
         pt1 = {} B, pt2 = {} B, ad2 = {} B",
        brk.ciphertext.len(),
        brk.trials,
        brk.block_calls(),
        brk.pt1.len(),
        brk.pt2.len(),
        brk.ad2.len()
    );
}

/// **The cost figure quoted in the crate READMEs is produced here.**
///
/// A single run of the attack is one sample from a geometric distribution with `p = 2^-8`, so it
/// says almost nothing: consecutive honest runs land anywhere from a handful of tries to a few
/// thousand. This test runs the *complete* attack — search, closed-form solve, and verification
/// of both sides through the public API — over [`INSTANCES`] independent `(k1, k2, nonce)`
/// triples and reports the distribution.
///
/// Falsifiability: the asserted band on the mean is ~±4 standard errors around the predicted
/// `2^8`. A build in which the padding check were removed would drive the mean to 1 and fail the
/// lower bound; a build that added any further redundancy to the message block (say a second
/// checked byte) would drive it to ~2^16 and fail the upper bound.
#[test]
fn qcb_cmt1_attack_cost_measured() {
    /// Independent key/nonce triples attacked. 200 samples put the standard error of the mean at
    /// `2^8 / sqrt(200)` ~ 18 tries.
    const INSTANCES: usize = 200;

    let mut rng = Rng(0x0BAD_C0DE_0000_0001);
    let mut samples: Vec<u64> = Vec::with_capacity(INSTANCES);

    for _ in 0..INSTANCES {
        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        let mut n = [0u8; 16];
        rng.fill(&mut k1);
        rng.fill(&mut k2);
        rng.fill(&mut n);
        let brk = qcb_cmt1_attack(&k1, &k2, &n).expect("padding search exhausted 500k tries");
        samples.push(brk.trials);
    }

    assert_eq!(samples.len(), INSTANCES, "every instance must have broken");
    let total: u64 = samples.iter().sum();
    #[allow(clippy::cast_precision_loss)]
    let mean_trials = total as f64 / INSTANCES as f64;
    let mean_block_calls = mean_trials * BLOCK_CALLS_PER_TRIAL as f64 + FIXED_BLOCK_CALLS as f64;

    let mut sorted = samples.clone();
    sorted.sort_unstable();
    let median = sorted[INSTANCES / 2];
    let min = sorted[0];
    let max = sorted[INSTANCES - 1];

    println!(
        "QCB CMT-1 attack cost over {INSTANCES} independent (k1,k2,nonce) instances, \
         all of which broke: padding-search tries mean={mean_trials:.1} median={median} \
         min={min} max={max}; Saturnin block calls mean={mean_block_calls:.0} \
         (= 2*tries + {FIXED_BLOCK_CALLS}); tag searches = 0"
    );

    assert!(
        (170.0..=350.0).contains(&mean_trials),
        "mean padding-search tries {mean_trials:.1} is outside the predicted 2^8 band \
         170..=350 — the attack model no longer matches the implementation"
    );
}

/// Same-associated-data control. With the associated data pinned equal on both sides the closed
/// form is unavailable and the adversary is back to a 256-bit tag collision. This test asserts
/// only that the *specific* solved value stops working when the degree of freedom is removed —
/// it is the falsification for the test above, not a commitment proof.
#[test]
fn qcb_break_depends_on_the_associated_data_degree_of_freedom() {
    let aead = SaturninQcb::new();
    let msg_tbc = SaturninTbc::new(DOMAIN_MESSAGE).unwrap();

    let k1 = [0x11u8; 32];
    let k2 = [0x22u8; 32];
    let n = [0x33u8; 16];

    let mut found = None;
    for t in 0u32..500_000 {
        let mut m2 = [0u8; B];
        m2[..4].copy_from_slice(&t.to_le_bytes());
        m2[31] = 0x80;
        let mut blk = m2;
        msg_tbc.encrypt_block(&k2, &tweak(&n, 0), &mut blk).unwrap();
        let mut m1 = blk;
        msg_tbc.decrypt_block(&k1, &tweak(&n, 0), &mut m1).unwrap();
        if m1[31] == 0x80 {
            found = Some(m1);
            break;
        }
    }
    let cs1 = found.expect("no dual-padding body");
    let key1 = AeadKey::new(k1.to_vec());
    let key2 = AeadKey::new(k2.to_vec());
    let nonce = Nonce::new(n.to_vec());
    let ciphertext = aead.encrypt(&key1, &nonce, &cs1[..31], None).unwrap();

    assert!(aead.decrypt(&key1, &nonce, &ciphertext, None).is_ok());
    assert!(
        aead.decrypt(&key2, &nonce, &ciphertext, None).is_err(),
        "with associated data pinned equal (empty) the second key must not validate"
    );
}
