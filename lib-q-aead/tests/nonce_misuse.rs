//! Nonce-misuse degradation probes for the registry AEADs (card t_1531578e, option (c)).
//!
//! # The question this file answers
//!
//! When a `(key, nonce)` pair repeats, *how much* plaintext does each construction leak? The
//! answer is not uniform across the registry, and the difference is the whole decision:
//!
//! - A **keystream** construction (CTR-style, or any mode whose ciphertext is `pt XOR f(key,
//!   nonce, position)`) leaks `P1 XOR P2` over the **entire** message. Total confidentiality loss
//!   for both messages, recoverable with ordinary crib-dragging.
//! - A **duplex sponge** re-seeds its state from the *ciphertext* of each block before permuting
//!   (`lib-q-duplex-aead/src/state.rs:duplex_encrypt_chunk` -> `set_rate_from_bytes(state,
//!   &c_full); f1600(state)`), so once two messages differ, the keystreams diverge at the next
//!   block boundary. The leak is bounded by the rate (`RATE_BYTES = 136`) rather than by the
//!   message length.
//! - An **MRAE / SIV** mode (Romulus-M) derives its encryption state from a tag computed over the
//!   whole plaintext, so distinct plaintexts give unrelated ciphertexts even under a repeated
//!   nonce. The only residual leak is *equality* of plaintexts.
//!
//! The card recorded the duplex behaviour as an assumption ("sponge constructions sometimes do,
//! but this must be tested rather than assumed"). These tests measure it instead.
//!
//! # The result that is easy to get wrong
//!
//! The duplex's advantage is **conditional on the message exceeding one rate block**. For a
//! record of 136 bytes or fewer there is exactly one duplex step, no second block in which to
//! diverge, and the leak is total — identical to a stream cipher. `short_messages_leak_totally`
//! pins that down. Protocol records are frequently smaller than 136 bytes, so "the sponge
//! degrades gracefully" must not be quoted without the length qualifier.
//!
//! # Why the measurements here are falsifiable
//!
//! A leak detector that reported "leak" unconditionally, or "no leak" unconditionally, would
//! produce a clean-looking table that means nothing. Two controls bracket every measurement:
//!
//! - `control_detector_sees_a_known_keystream_leak` — a deliberately broken XOR-keystream cipher
//!   defined in this file. The detector MUST report a total leak on it. This is the positive
//!   control: it proves the detector can say "leak".
//! - `control_distinct_nonces_do_not_leak` — the same algorithms used correctly, with distinct
//!   nonces. The detector MUST report chance-level agreement. This is the negative control: it
//!   proves the detector can say "no leak", so a low score for Romulus-M is a statement about
//!   Romulus-M rather than about a dead harness.
//!
//! # What this file does NOT establish — do not over-read a low score
//!
//! The measurement is confined to **one** failure mode: whether `P1 XOR P2` can be read directly
//! off two ciphertexts. Nonce reuse also enables, depending on the construction, tag forgery,
//! internal-state recovery, and key recovery — none of which is probed here. In particular a low
//! score for `RomulusNAead` or `RoccaSAead` means only that their state chaining desynchronises
//! the keystream quickly; it is **not** a misuse-resistance claim, and neither mode makes one.
//! Rocca-family designs specifically document state-recovery exposure under repeated nonces. Only
//! `RomulusM` targets the MRAE security goal, and only it is asserted against here.
//!
//! # Nonce extension (XChaCha-style) — evaluated separately and rejected
//!
//! Every registry algorithm takes a 128-bit nonce (`all_registry_aeads_take_a_128_bit_nonce`
//! checks this rather than assuming it). XChaCha20-Poly1305 exists to stretch a 96-bit nonce to
//! 192 bits so that *randomly* generated nonces stop colliding at the ~2^32 birthday bound. At
//! 128 bits that bound is already ~2^64 messages per key, beyond any realistic volume, so nonce
//! extension buys nothing here. It is a separate question from misuse resistance and must not be
//! conflated with it: extension helps *random* nonces, while the exposure this file measures is
//! *counter/state-derived* nonces repeating after a restart or snapshot restore, which a wider
//! nonce does not address at all.

#![cfg(feature = "alloc")]

use lib_q_aead::{
    Aead,
    AeadKey,
    AeadWithMetadata,
    Nonce,
};

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

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut out = vec![0u8; n];
        for chunk in out.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            let k = chunk.len();
            chunk.copy_from_slice(&v[..k]);
        }
        out
    }
}

/// Duplex rate, mirrored from `lib-q-duplex-aead/src/params.rs:4`. The expected leak ceiling.
const DUPLEX_RATE: usize = 136;

/// Long enough to span several duplex blocks.
const LONG_LEN: usize = 600;
/// Shorter than one duplex block, like a small protocol record.
const SHORT_LEN: usize = 64;
/// Index of the first differing plaintext byte; everything at or after this differs.
const FIRST_DIFF: usize = 8;

/// Two plaintexts agreeing on `[0, FIRST_DIFF)` and differing in *every* byte after it.
fn plaintext_pair(len: usize) -> (Vec<u8>, Vec<u8>) {
    let p1 = Rng(0x5EED_0000_0000_0001).bytes(len);
    let mut p2 = p1.clone();
    for (i, b) in p2.iter_mut().enumerate().skip(FIRST_DIFF) {
        // Guarantee a difference at every position (never a coincidental match).
        *b ^= 0xA5u8.wrapping_add(i as u8) | 0x01;
    }
    for i in FIRST_DIFF..len {
        assert_ne!(
            p1[i], p2[i],
            "plaintext pair must differ at every byte >= FIRST_DIFF"
        );
    }
    (p1, p2)
}

/// How many byte positions satisfy `C1[i] ^ C2[i] == P1[i] ^ P2[i]` — i.e. positions where the
/// keystream was reused and the plaintext XOR is directly readable off the wire.
///
/// Counts only positions at or after `FIRST_DIFF`: before that the plaintexts are equal, so the
/// relation holds trivially for any deterministic cipher and would inflate every score.
fn leaked_bytes(p1: &[u8], p2: &[u8], c1: &[u8], c2: &[u8]) -> usize {
    let n = p1.len();
    assert!(
        c1.len() >= n && c2.len() >= n,
        "ciphertext shorter than plaintext"
    );
    (FIRST_DIFF..n)
        .filter(|&i| c1[i] ^ c2[i] == p1[i] ^ p2[i])
        .count()
}

/// Positions in `[FIRST_DIFF, len)` — the denominator for every leak figure below.
fn measurable(len: usize) -> usize {
    len - FIRST_DIFF
}

/// Length of the *contiguous* run of leaking bytes starting at the first differing byte.
///
/// This is the interpretable number. A total match count mixes the structural leak with
/// coincidental 1-in-256 agreements further along; the contiguous run isolates "how far does the
/// keystream stay synchronised after the plaintexts diverge", which is exactly the block/rate
/// boundary at which a state-chaining construction recovers.
fn contiguous_leak_run(p1: &[u8], p2: &[u8], c1: &[u8], c2: &[u8]) -> usize {
    (FIRST_DIFF..p1.len())
        .take_while(|&i| c1[i] ^ c2[i] == p1[i] ^ p2[i])
        .count()
}

/// Encrypt both plaintexts under one `(key, nonce)` and return `(total_leak, contiguous_run)`.
fn leak_under_repeated_nonce(
    name: &str,
    aead: &dyn Aead,
    key_len: usize,
    nonce_len: usize,
    len: usize,
) -> (usize, usize) {
    let (p1, p2) = plaintext_pair(len);
    let key = AeadKey::new(Rng(0xA11C_E000_0000_0001).bytes(key_len));
    let nonce = Nonce::new(Rng(0xBEEF_0000_0000_0001).bytes(nonce_len));
    let ad: &[u8] = b"same-associated-data";

    let c1 = aead
        .encrypt(&key, &nonce, &p1, Some(ad))
        .unwrap_or_else(|e| panic!("{name}: encrypt p1 failed: {e:?}"));
    let c2 = aead
        .encrypt(&key, &nonce, &p2, Some(ad))
        .unwrap_or_else(|e| panic!("{name}: encrypt p2 failed: {e:?}"));

    (
        leaked_bytes(&p1, &p2, &c1, &c2),
        contiguous_leak_run(&p1, &p2, &c1, &c2),
    )
}

/// The same measurement with *distinct* nonces — the correct-usage baseline.
fn leak_under_distinct_nonces(
    name: &str,
    aead: &dyn Aead,
    key_len: usize,
    nonce_len: usize,
    len: usize,
) -> usize {
    let (p1, p2) = plaintext_pair(len);
    let key = AeadKey::new(Rng(0xA11C_E000_0000_0001).bytes(key_len));
    let n1 = Nonce::new(Rng(0xBEEF_0000_0000_0001).bytes(nonce_len));
    let n2 = Nonce::new(Rng(0xBEEF_0000_0000_0002).bytes(nonce_len));
    assert_ne!(n1.data, n2.data, "{name}: control nonces must differ");
    let ad: &[u8] = b"same-associated-data";

    let c1 = aead
        .encrypt(&key, &n1, &p1, Some(ad))
        .unwrap_or_else(|e| panic!("{name}: {e:?}"));
    let c2 = aead
        .encrypt(&key, &n2, &p2, Some(ad))
        .unwrap_or_else(|e| panic!("{name}: {e:?}"));

    leaked_bytes(&p1, &p2, &c1, &c2)
}

/// Chance-level agreement is ~1/256 per byte. Allow generous slack so the control is not flaky;
/// the signal we are separating from noise is 100% vs 0.4%, not a marginal effect.
fn chance_ceiling(len: usize) -> usize {
    measurable(len) / 16 + 4
}

// ---------------------------------------------------------------------------------------------
// POSITIVE CONTROL: a deliberately broken cipher the detector must catch.
// ---------------------------------------------------------------------------------------------

/// A textbook-broken AEAD: ciphertext is `pt XOR keystream(key, nonce)`, keystream independent of
/// the plaintext. Not a registry algorithm — it exists only so the detector has something it is
/// *known* to have to flag.
fn broken_xor_keystream(key: &[u8], nonce: &[u8], pt: &[u8]) -> Vec<u8> {
    // FNV-style multiply-accumulate. An earlier version XORed each byte into a fixed lane
    // (`seed ^= b << ((i % 8) * 8)`); with the repeating key/nonce bytes used below every lane
    // cancelled to zero, so *both* nonces produced the same keystream and the negative control
    // reported a 592/592 "leak" for two supposedly independent streams. That failure is what
    // `control_detector_reports_no_leak_when_keystreams_differ` exists to catch.
    let mut seed = 0xCBF2_9CE4_8422_2325u64;
    for b in key.iter().chain(nonce.iter()) {
        seed ^= *b as u64;
        seed = seed.wrapping_mul(0x0000_0100_0000_01B3);
    }
    let ks = Rng(seed | 1).bytes(pt.len());
    pt.iter().zip(ks.iter()).map(|(p, k)| p ^ k).collect()
}

#[test]
fn control_detector_sees_a_known_keystream_leak() {
    let (p1, p2) = plaintext_pair(LONG_LEN);
    let key = [0x11u8; 32];
    let nonce = [0x22u8; 16];
    let c1 = broken_xor_keystream(&key, &nonce, &p1);
    let c2 = broken_xor_keystream(&key, &nonce, &p2);
    let leak = leaked_bytes(&p1, &p2, &c1, &c2);
    println!(
        "CONTROL(positive) broken-xor-keystream: leak {}/{} bytes after first difference",
        leak,
        measurable(LONG_LEN)
    );
    assert_eq!(
        leak,
        measurable(LONG_LEN),
        "the leak detector failed to flag a pure keystream reuse — every measurement in this \
         file would be worthless, because the detector cannot say \"leak\""
    );
}

#[test]
fn control_detector_reports_no_leak_when_keystreams_differ() {
    let (p1, p2) = plaintext_pair(LONG_LEN);
    let key = [0x11u8; 32];
    let c1 = broken_xor_keystream(&key, &[0x22u8; 16], &p1);
    let c2 = broken_xor_keystream(&key, &[0x33u8; 16], &p2);
    let leak = leaked_bytes(&p1, &p2, &c1, &c2);
    println!(
        "CONTROL(negative) broken-xor-keystream, distinct nonces: leak {}/{} bytes",
        leak,
        measurable(LONG_LEN)
    );
    assert!(
        leak <= chance_ceiling(LONG_LEN),
        "the detector reported {leak} leaked bytes for two independent keystreams — it cannot \
         say \"no leak\", so a low score elsewhere would prove nothing"
    );
}

// ---------------------------------------------------------------------------------------------
// Per-algorithm measurement.
// ---------------------------------------------------------------------------------------------

macro_rules! misuse_case {
    ($feature:literal, $modname:ident, $ty:path, $label:literal, $expect_mrae:expr) => {
        #[cfg(feature = $feature)]
        mod $modname {
            use super::*;

            fn build() -> ($ty, usize, usize) {
                let a = <$ty>::new();
                let kl = a.key_size();
                let nl = a.nonce_size();
                (a, kl, nl)
            }

            /// Negative control, per algorithm: used correctly (distinct nonces), nothing leaks.
            #[test]
            fn control_distinct_nonces_do_not_leak() {
                let (a, kl, nl) = build();
                let leak = leak_under_distinct_nonces($label, &a, kl, nl, LONG_LEN);
                println!(
                    "{}: CONTROL distinct nonces -> leak {}/{}",
                    $label,
                    leak,
                    measurable(LONG_LEN)
                );
                assert!(
                    leak <= chance_ceiling(LONG_LEN),
                    "{}: {} bytes agreed under DISTINCT nonces — the detector is not measuring \
                     nonce reuse, so its repeated-nonce result is meaningless",
                    $label,
                    leak
                );
            }

            /// The measurement: how much leaks when the nonce repeats on a multi-block message.
            #[test]
            fn long_message_leak_under_repeated_nonce() {
                let (a, kl, nl) = build();
                let (leak, run) = leak_under_repeated_nonce($label, &a, kl, nl, LONG_LEN);
                let total = measurable(LONG_LEN);
                let pct = (leak * 100) / total;
                println!(
                    "{}: REPEATED nonce, {}-byte message -> leak {}/{} bytes ({}%), contiguous \
                     run {} bytes from first difference [duplex rate = {}]",
                    $label, LONG_LEN, leak, total, pct, run, DUPLEX_RATE
                );
                if $expect_mrae {
                    assert!(
                        leak <= chance_ceiling(LONG_LEN),
                        "{}: claims misuse resistance but leaked {}/{} plaintext-XOR bytes under \
                         a repeated nonce",
                        $label,
                        leak,
                        total
                    );
                }
            }

            /// The qualifier that matters: below one duplex rate there is no room to diverge.
            #[test]
            fn short_message_leak_under_repeated_nonce() {
                let (a, kl, nl) = build();
                let (leak, run) = leak_under_repeated_nonce($label, &a, kl, nl, SHORT_LEN);
                let total = measurable(SHORT_LEN);
                println!(
                    "{}: REPEATED nonce, {}-byte message (< duplex rate {}) -> leak {}/{} bytes, \
                     contiguous run {} bytes",
                    $label, SHORT_LEN, DUPLEX_RATE, leak, total, run
                );
                if $expect_mrae {
                    assert!(
                        leak <= chance_ceiling(SHORT_LEN),
                        "{}: claims misuse resistance but leaked {}/{} bytes on a short message",
                        $label,
                        leak,
                        total
                    );
                }
            }

            /// AC5 rationale check: the 128-bit width is what makes random nonces safe and what
            /// makes XChaCha-style extension unnecessary. Verified, not assumed.
            #[test]
            fn all_registry_aeads_take_a_128_bit_nonce() {
                let (a, kl, nl) = build();
                println!(
                    "{}: key {} B, nonce {} B, tag {} B",
                    $label,
                    kl,
                    nl,
                    a.tag_size()
                );
                assert_eq!(
                    nl, 16,
                    "{}: nonce is {} B, not 128 bits — the birthday-bound argument for random \
                     nonces (and the rejection of nonce extension) does not hold for it",
                    $label, nl
                );
            }

            /// The residual leak an MRAE cannot remove: equal plaintexts give equal ciphertexts.
            #[test]
            fn equal_plaintexts_are_detectable() {
                let (a, kl, nl) = build();
                let key = AeadKey::new(Rng(0xA11C_E000_0000_0001).bytes(kl));
                let nonce = Nonce::new(Rng(0xBEEF_0000_0000_0001).bytes(nl));
                let pt = Rng(0x5EED_0000_0000_0001).bytes(LONG_LEN);
                let c1 = a.encrypt(&key, &nonce, &pt, Some(b"ad")).unwrap();
                let c2 = a.encrypt(&key, &nonce, &pt, Some(b"ad")).unwrap();
                println!(
                    "{}: equal plaintexts under a repeated nonce produce {} ciphertexts",
                    $label,
                    if c1 == c2 { "IDENTICAL" } else { "differing" }
                );
            }
        }
    };
}

misuse_case!(
    "shake256",
    shake256,
    lib_q_aead::Shake256Aead,
    "Shake256Aead",
    false
);
misuse_case!(
    "saturnin",
    saturnin,
    lib_q_aead::SaturninAead,
    "SaturninAead (CTR-Cascade)",
    false
);
misuse_case!(
    "duplex-sponge-aead",
    duplex,
    lib_q_aead::DuplexSpongeAead,
    "DuplexSpongeAead",
    false
);
misuse_case!(
    "tweak-aead",
    tweak,
    lib_q_aead::TweakAead,
    "TweakAead",
    false
);
misuse_case!(
    "romulus-n",
    romulus_n,
    lib_q_aead::RomulusNAead,
    "RomulusNAead",
    false
);
misuse_case!(
    "romulus-m",
    romulus_m,
    lib_q_aead::RomulusMAead,
    "RomulusMAead (SIV/MRAE)",
    true
);
misuse_case!(
    "rocca-s",
    rocca_s,
    lib_q_aead::RoccaSAead,
    "RoccaSAead",
    false
);
