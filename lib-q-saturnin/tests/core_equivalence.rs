//! The two Saturnin cores must agree wherever both are defined, and neither may hand-write a
//! constant schedule the specification says to derive.
//!
//! `lib-q-saturnin` carries two implementations of the Saturnin permutation: `SaturninCore`
//! (used by CTR-Cascade, QCB's tweakable block cipher, the stream cipher, the block cipher and
//! Short) and `SaturninBs32Core` (used by `SaturninHash`). There is only one Saturnin — the
//! designers' 16-bit reference and their bit-sliced implementation agree byte-for-byte — so any
//! disagreement between these two is a bug in one of them.
//!
//! This file exists because that disagreement was real and shipped. `core.rs` special-cased
//! `(rounds = 16, domain = 7 | 8)` with hardcoded tables copied from the bit-sliced code "for
//! hash compatibility". The tables were **transposed**: they stored the packed bs32 form
//! `(RC1 << 16) | RC0` flattened as `RC1[0], RC0[0], RC1[1], RC0[1], …`, while the round function
//! reads `rc[2i]` as RC0 and `rc[2i + 1]` as RC1. Those two configurations therefore computed a
//! permutation that is not Saturnin.
//!
//! Nothing shipped was wrong — `SaturninCore` is never deployed at a hash domain and
//! `SaturninBs32Core` is only ever used at exactly those two — so every KAT stayed green while
//! the defect sat in a public API. The gap was that no test compared the two cores, and no test
//! checked the constants against the rule that generates them. This is those two tests.
//!
//! Scope note: this file compares the cores **only** at the hash domains, because that is the
//! disagreement it was written for. It used to say a whole-grid comparison could not be written
//! yet, because `SaturninBs32Core`'s own constant generator was separately broken outside
//! `(16, 7)` / `(16, 8)` (its LFSR ran in a `u32` that never truncated to 16 bits, and
//! `!(x >> 15).wrapping_add(1)` does not parse as the intended two's-complement mask). That is
//! fixed; the whole-grid comparison — plus `SaturninBs32Core::decrypt_block`, which this file does
//! not exercise at all — now lives in `tests/bs32_lfsr_and_inverse.rs`.

#![cfg(feature = "alloc")]

use lib_q_saturnin::bs32_core::SaturninBs32Core;
use lib_q_saturnin::core::SaturninCore;

/// The configurations at which both cores are defined and must agree: Saturnin-Hash's two
/// domains, at the full 16 super-rounds.
const HASH_CONFIGS: [(usize, u8); 2] = [(16, 7), (16, 8)];

/// The round-constant LFSR from the Saturnin specification, written out here independently.
///
/// Deliberately *not* delegating to the crate's own generator, and deliberately not a pinned
/// table: a pinned table is precisely what went wrong, and a copy of the buggy one in a test
/// would have agreed with the bug. Two 16-bit shift registers with taps `0x2D` and `0x53`,
/// seeded from `domain + (rounds << 4) + 0xFE00`, clocked 16 times per super-round, emitting
/// `RC0` then `RC1`.
fn expected_round_constants(num_rounds: usize, domain: u8) -> Vec<u16> {
    let mut out = Vec::with_capacity(num_rounds * 2);
    let seed = (domain as u16)
        .wrapping_add((num_rounds as u16) << 4)
        .wrapping_add(0xFE00);
    let (mut x0, mut x1) = (seed, seed);

    for _ in 0..num_rounds {
        for _ in 0..16 {
            let mask0 = if (x0 >> 15) != 0 { 0xFFFF } else { 0x0000 };
            let mask1 = if (x1 >> 15) != 0 { 0xFFFF } else { 0x0000 };
            x0 = (x0 << 1) ^ (0x2D & mask0);
            x1 = (x1 << 1) ^ (0x53 & mask1);
        }
        out.push(x0);
        out.push(x1);
    }
    out
}

#[test]
fn the_two_cores_agree_at_the_hash_domains() {
    // Several unrelated inputs, so a pass cannot come from a degenerate state — an all-zero key
    // and block can agree under some wrong constant schedules.
    let inputs: [([u8; 32], [u8; 32]); 4] = [
        ([0x00; 32], [0x00; 32]),
        ([0xFF; 32], [0x00; 32]),
        ([0x5A; 32], [0x42; 32]),
        (
            std::array::from_fn(|i| i as u8),
            std::array::from_fn(|i| (255 - i) as u8),
        ),
    ];

    let mut mismatches: Vec<String> = Vec::new();
    for (rounds, domain) in HASH_CONFIGS {
        for (key, block) in &inputs {
            let mut a = *block;
            SaturninCore::new(rounds, domain)
                .expect("SaturninCore rejected a valid (rounds, domain)")
                .encrypt_block(key, &mut a)
                .expect("SaturninCore::encrypt_block failed");

            let mut b = *block;
            SaturninBs32Core::new(rounds, domain)
                .expect("SaturninBs32Core rejected a valid (rounds, domain)")
                .encrypt_block(key, &mut b)
                .expect("SaturninBs32Core::encrypt_block failed");

            if a != b {
                mismatches.push(format!(
                    "  (rounds={rounds}, domain={domain}) key={:02x?}…\n     \
                     SaturninCore     = {:02x?}…\n     SaturninBs32Core = {:02x?}…",
                    &key[..4],
                    &a[..8],
                    &b[..8],
                ));
            }
        }
    }

    assert!(
        mismatches.is_empty(),
        "the two Saturnin cores compute different permutations at {} of {} hash-domain \
         configurations.\nThere is only one Saturnin, so at least one of these is not it.\n{}",
        mismatches.len(),
        HASH_CONFIGS.len() * inputs.len(),
        mismatches.join("\n"),
    );
}

#[test]
fn core_constants_are_derived_not_hand_written() {
    // The property, not the symptom: every schedule the core produces must be the one the
    // specification's LFSR produces. A hand-written table is allowed to exist only if it agrees.
    let mut wrong: Vec<String> = Vec::new();

    for rounds in [10usize, 16] {
        for domain in 0u8..16 {
            let got = SaturninCore::new(rounds, domain)
                .expect("valid (rounds, domain)")
                .round_constants()
                .to_vec();
            let want = expected_round_constants(rounds, domain);
            if got != want {
                // Name the transposition explicitly when that is what it is — it is the failure
                // mode this test was written for, and it is invisible in a raw hex diff.
                let transposed = got.len() == want.len() &&
                    got.chunks_exact(2)
                        .zip(want.chunks_exact(2))
                        .all(|(g, w)| g[0] == w[1] && g[1] == w[0]);
                wrong.push(format!(
                    "  (rounds={rounds}, domain={domain}){}\n     got  {:04X?}…\n     want {:04X?}…",
                    if transposed {
                        "  <- RC0/RC1 TRANSPOSED in every super-round"
                    } else {
                        ""
                    },
                    &got[..4.min(got.len())],
                    &want[..4.min(want.len())],
                ));
            }
        }
    }

    assert!(
        wrong.is_empty(),
        "{} constant schedule(s) do not match the specification's LFSR:\n{}",
        wrong.len(),
        wrong.join("\n"),
    );
}
