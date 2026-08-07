//! Key-commitment (CMT-1) tests for Saturnin-QCB.
//!
//! CMT-1 asks: can one ciphertext be made to decrypt successfully under two *distinct* keys?
//! The standard definition lets the adversary pick the nonce and associated data on each side
//! (only the ciphertext string is shared), which is exactly the multi-recipient / envelope
//! setting where each recipient's blob carries its own header.
//!
//! # History (card `t_16ddf21c`) — the break, and the fix
//!
//! **Saturnin-QCB was not key-committing.** The attack had two parts:
//!
//! 1. a `1/256`-per-try search for a ciphertext body whose decryption carries valid `10*`
//!    padding under *both* keys — expected `~2^8` tries, `2` Saturnin block calls each, and
//!    2. a closed-form solve for the second side's associated data — `6` block calls, no search.
//!
//! The cause of part 2 was structural and is still visible in `qcb.rs::compute_tag`, which
//! computes the mode's *raw, pre-commitment* tag:
//!
//! ```text
//! T = TBC_13(K, tweak(N, l))(checksum)  XOR  ad_auth
//! ad_auth = XOR_i TBC_11(K, tweak(N, i))(A_i)  XOR  TBC_12(K, tweak(N, j))(pad(A_*))
//! ```
//!
//! `ad_auth` enters `T` by plain XOR, and `TBC_11` / `TBC_12` are *public, invertible*
//! permutations once the key is known. An adversary who holds both keys could therefore solve for
//! the second side's associated data in closed form instead of searching for it. Note this shape
//! was unchanged by the QCB Algorithm-1 conformance fix (five domains, the IV in every tweak,
//! unconditional absorption of `pad(A_*)`, commit `bae2717`): that fix closed a forgery, not
//! CMT-1.
//!
//! **The fix:** `qcb.rs::encrypt`/`decrypt_core` now emit/check `T' = SaturninHash(label ‖ K ‖ N
//! ‖ T ‖ A)` instead of `T` — the **CTX** transform (Chan-Rogaway, ESORICS 2022; see
//! `crate::commit`). `T'` does not XOR-decompose, so the closed-form solve below no longer steers
//! it: [`qcb_ctx_defeats_the_closed_form_ad_solve`] asserts exactly that, and would go red again
//! if the transform were removed (see the red-then-green evidence quoted on card `t_16ddf21c`).
//! Every step of the original attack (the padding search, the closed-form algebra) is retained
//! verbatim below — only the verdict changed, from "side 2 decrypts" to "side 2 must not decrypt".
//!
//! Saturnin-CTR-Cascade (`aead.rs`) does not have this shape: its associated data is folded
//! through a Matyas–Meyer–Oseas chain, which is not invertible in the data, so steering the
//! running tag to a chosen value is a preimage problem. See `lib-q-aead/tests/key_commitment.rs`
//! for the bounded search that covers it and the other registry AEADs — and for why a null
//! search result there is **not** evidence that those modes commit. Plain `SaturninAead` itself
//! is unchanged and remains non-committing; it now has an opt-in, wire-incompatible committing
//! sibling, `SaturninAeadCtx` (CTX applied to CTR-Cascade, `src/aead_ctx.rs`), for callers that
//! want the property — see that module and `lib-q-saturnin/README.md`'s Key commitment section.

#![cfg(all(feature = "alloc", feature = "qcb"))]

use lib_q_saturnin::{
    Aead,
    AeadKey,
    Error,
    Nonce,
    SaturninQcb,
    SaturninTbc,
};

/// Saturnin block size in bytes (256-bit block).
const B: usize = 32;
/// `qcb.rs::DOMAIN_MESSAGE_FINAL` — the 31-byte plaintexts this attack uses have no full block,
/// so their single body block is the *final padded* one (Algorithm 1 line 7).
const DOMAIN_MESSAGE_FINAL: u8 = 10;
/// `qcb.rs::DOMAIN_AD` — full associated-data blocks (Algorithm 1 line 10).
const DOMAIN_AD: u8 = 11;
/// `qcb.rs::DOMAIN_AD_FINAL` — the final padded associated-data block (Algorithm 1 line 12).
const DOMAIN_AD_FINAL: u8 = 12;
/// `qcb.rs::DOMAIN_TAG` — the tag / message checksum (Algorithm 1 line 13).
const DOMAIN_TAG: u8 = 13;

/// Block calls the attack spends outside the padding search, counted against `qcb.rs`:
/// `Aead::encrypt` of a 31-byte plaintext with empty associated data costs 3 (one `msg_final`,
/// one `ad_final` — `absorb_ad` absorbs `pad(A_*)` unconditionally — and one `tag`); the
/// closed-form solve costs 3 (one `tag.encrypt_block`, one `ad_final.encrypt_block`, one
/// `ad.decrypt_block`).
const FIXED_BLOCK_CALLS: u64 = 6;
/// Block calls per padding-search try: one `encrypt_block` under `k2`, one `decrypt_block`
/// under `k1`.
const BLOCK_CALLS_PER_TRIAL: u64 = 2;

/// `N (16) || 0x80 || 0x00 * 7 || block_index_be_u64 (8)`. Used for every domain, associated data
/// included; the QCB paper requires the IV in the AD tweak too. Byte 16 is the `10*` pad bit that
/// closes the 161-bit IV field — see `tests/qcb_spec.rs::tweak` for the derivation and the quoted
/// spec text.
fn tweak(nonce16: &[u8; 16], block_index: u64) -> [u8; B] {
    let mut t = [0u8; B];
    t[0..16].copy_from_slice(nonce16);
    t[16] = 0x80;
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

/// One completed run of the CMT-1 attack *attempt*. Pre-CTX, `side2` always succeeded (the
/// break). Post-CTX, every step through the closed-form solve still runs unchanged — only the
/// verdict is now a returned [`lib_q_saturnin::Result`] instead of an `.expect()` panic, so
/// callers decide what a given outcome means instead of the attack function assuming it must
/// succeed.
struct AttackAttempt {
    /// Padding-search tries consumed (each costs [`BLOCK_CALLS_PER_TRIAL`] block calls).
    trials: u64,
    /// `true` iff the 1/256 dual-padding search found a body within the trial bound — i.e. the
    /// search half of the attack still works, independent of what the closed-form solve achieves.
    search_found: bool,
    ciphertext: Vec<u8>,
    ad2: Vec<u8>,
    /// Side 1 (empty AD, the honest recipient) — must always decrypt.
    side1: lib_q_saturnin::Result<Vec<u8>>,
    /// Side 2 (solved AD, distinct key) — pre-CTX this decrypted (the break); post-CTX it must
    /// fail tag verification.
    side2: lib_q_saturnin::Result<Vec<u8>>,
}

impl AttackAttempt {
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
fn qcb_cmt1_attack(k1: &[u8; 32], k2: &[u8; 32], n: &[u8; 16]) -> Option<AttackAttempt> {
    let aead = SaturninQcb::new();
    let msg_tbc = SaturninTbc::new(DOMAIN_MESSAGE_FINAL).unwrap();
    let tag_tbc = SaturninTbc::new(DOMAIN_TAG).unwrap();
    let ad_tbc = SaturninTbc::new(DOMAIN_AD).unwrap();
    let ad_final_tbc = SaturninTbc::new(DOMAIN_AD_FINAL).unwrap();
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
    // Side 1 uses empty associated data. Its tag is whatever the mode produces (with the
    // Algorithm-1 fix that now includes TBC_12(k1, tweak(n,0))(10*), no longer zero) — the attack
    // never needs to model it, because it takes the whole ciphertext straight from the public
    // encrypt API so the test cannot drift from the implementation.
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
    // Required: ad_auth2 == TBC_13(k2,..)(cs2) XOR tag.
    let mut t2core = cs2;
    tag_tbc
        .encrypt_block(k2, &tweak(n, 0), &mut t2core)
        .unwrap();
    let want_ad_auth2 = xor32(&t2core, &tag);

    // A 63-byte associated data splits into one full block (`b0`, domain 11, index 0) plus a
    // 31-byte tail that pads to one final block (`b1`, domain 12, index j = 0). Fix b1, then
    // invert TBC_11 for b0. No search.
    let mut b1 = [0u8; B];
    b1[31] = 0x80; // pad(A_*) for a 31-byte tail == A_* || 0x80
    let mut v1 = b1;
    ad_final_tbc
        .encrypt_block(k2, &tweak(n, 0), &mut v1)
        .unwrap();

    let mut b0 = xor32(&want_ad_auth2, &v1);
    ad_tbc.decrypt_block(k2, &tweak(n, 0), &mut b0).unwrap();

    let mut ad2 = Vec::with_capacity(63);
    ad2.extend_from_slice(&b0);
    ad2.extend_from_slice(&b1[..31]);
    assert_eq!(ad2.len(), 63);

    // ---- verdict: both sides attempted through the public API only, no panics here ----------
    let side1 = aead.decrypt(&key1, &nonce, &ciphertext, None);
    let side2 = aead.decrypt(&key2, &nonce, &ciphertext, Some(&ad2));

    Some(AttackAttempt {
        trials,
        search_found: true,
        ciphertext,
        ad2,
        side1,
        side2,
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

/// **The CMT-1 break of card `t_16ddf21c`, retained verbatim, now expected to FAIL.**
///
/// Every step still runs: the 1/256 padding search still finds a dual-padding body, and the
/// closed-form solve still produces the `ad2` that satisfied the pre-CTX tag equation
/// `tag = TBC_13(cs) XOR ad_auth`. What changed is that the transmitted tag is now
/// `T' = SaturninHash(label ‖ K ‖ N ‖ T ‖ A)`, which does not XOR-decompose, so `ad2` no longer
/// steers it. This test would go red again if the CTX transform were removed — see the
/// red-then-green evidence quoted on card `t_16ddf21c`.
///
/// Three assertions, in order, all required or the test is vacuous:
/// 1. the search still works (the harness itself did not silently break);
/// 2. side 1 (empty AD, the honest recipient) still decrypts (so side 2's "no" is meaningful);
/// 3. side 2 (the attacker's solved key + AD) now fails tag verification.
#[test]
fn qcb_ctx_defeats_the_closed_form_ad_solve() {
    let attempt = qcb_cmt1_attack(&[0x11u8; 32], &[0x22u8; 32], &[0x33u8; 16])
        .expect("no dual-padding body in 500k tries (expected ~256)");

    assert!(
        attempt.search_found,
        "the 1/256 padding search itself failed to find a dual-padding body — that would make \
         side 2's failure meaningless (the whole attack setup never got off the ground)"
    );
    assert!(
        attempt.side1.is_ok(),
        "side 1 (empty AD, honest recipient) failed to decrypt its own ciphertext — the harness \
         is broken, not the attack"
    );
    assert!(
        matches!(&attempt.side2, Err(Error::VerificationFailed { .. })),
        "CMT-1 BREAK STILL WORKS: side 2 decrypted under the solved (key2, ad2) pair — the CTX \
         transform is not doing its job. Got: {:?}",
        attempt.side2.as_ref().map(Vec::len)
    );

    println!(
        "QCB CTX regression test: 1 ciphertext ({} B), padding-search tries = {}, \
         block calls = {}; side 1 (honest) decrypts = {}, side 2 (attacker) decrypts = {} \
         (must be false); ad2 = {} B",
        attempt.ciphertext.len(),
        attempt.trials,
        attempt.block_calls(),
        attempt.side1.is_ok(),
        attempt.side2.is_ok(),
        attempt.ad2.len()
    );
}

/// **Inverted: the padding search still succeeds at the predicted rate, but the break itself must
/// now fail on every one of [`INSTANCES`] independent `(k1, k2, nonce)` triples.**
///
/// Before CTX, this test measured the mean cost of a break that always succeeded (the padding
/// search's `~2^8` tries dominate; see the CHANGELOG / README history). After CTX, the *search*
/// half of the attack is unaffected by the fix — it is purely about `qcb.rs::pad_tail` /
/// `unpad_len` at the message layer, which CTX does not touch — so it still finds a dual-padding
/// body at the same rate. What must change is the *outcome*: side 2 must fail on every instance.
///
/// A build that reports "0 breaks, 0 successful searches" must FAIL, not pass — that would be the
/// harness silently doing nothing rather than the algorithm resisting the attack. The mean-tries
/// assertion is retained as exactly that check: it fails if the search stops finding hits (e.g. a
/// harness bug), independent of the break-count assertion.
#[test]
fn qcb_cmt1_attack_no_longer_breaks_commitment() {
    /// Independent key/nonce triples attacked. 200 samples put the standard error of the mean at
    /// `2^8 / sqrt(200)` ~ 18 tries.
    const INSTANCES: usize = 200;

    let mut rng = Rng(0x0BAD_C0DE_0000_0001);
    let mut samples: Vec<u64> = Vec::with_capacity(INSTANCES);
    let mut breaks = 0usize;

    for _ in 0..INSTANCES {
        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        let mut n = [0u8; 16];
        rng.fill(&mut k1);
        rng.fill(&mut k2);
        rng.fill(&mut n);
        let attempt = qcb_cmt1_attack(&k1, &k2, &n).expect("padding search exhausted 500k tries");
        assert!(
            attempt.search_found,
            "padding search failed for one instance — the search half of the harness broke"
        );
        assert!(
            attempt.side1.is_ok(),
            "side 1 (honest recipient) failed to decrypt its own ciphertext for one instance"
        );
        if attempt.side2.is_ok() {
            breaks += 1;
        }
        samples.push(attempt.trials);
    }

    assert_eq!(
        samples.len(),
        INSTANCES,
        "every instance must have run the search to completion"
    );
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
        "QCB CMT-1 attack, post-CTX, over {INSTANCES} independent (k1,k2,nonce) instances: \
         breaks = {breaks} (must be 0); padding-search tries mean={mean_trials:.1} \
         median={median} min={min} max={max} — the search itself still succeeds at the \
         predicted rate (Saturnin block calls mean={mean_block_calls:.0} = 2*tries + \
         {FIXED_BLOCK_CALLS}); it is only the closed-form tag solve that CTX now defeats."
    );

    assert_eq!(
        breaks, 0,
        "{breaks} of {INSTANCES} instances broke commitment — the CTX transform is not \
         defeating the closed-form AD solve"
    );
    assert!(
        (170.0..=350.0).contains(&mean_trials),
        "mean padding-search tries {mean_trials:.1} is outside the predicted 2^8 band \
         170..=350 — the search half of the harness no longer matches the implementation (a \
         report of 0 breaks alongside a search that has silently stopped finding hits would be \
         worthless, not reassuring)"
    );
}

/// Same-associated-data control. With the associated data pinned equal on both sides the closed
/// form is unavailable and the adversary is back to a 256-bit tag collision. This test asserts
/// only that the *specific* solved value stops working when the degree of freedom is removed —
/// it is the falsification for the test above, not a commitment proof.
#[test]
fn qcb_break_depends_on_the_associated_data_degree_of_freedom() {
    let aead = SaturninQcb::new();
    let msg_tbc = SaturninTbc::new(DOMAIN_MESSAGE_FINAL).unwrap();

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
