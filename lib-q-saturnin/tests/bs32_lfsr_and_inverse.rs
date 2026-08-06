//! `SaturninBs32Core`'s round-constant LFSR and its decrypt datapath, checked against
//! independent models — never against the crate's own generator or a copy of it.
//!
//! `core_equivalence.rs` checks that `SaturninCore` and `SaturninBs32Core` agree at the two hash
//! domains `(16, 7)` / `(16, 8)`, and scopes itself to only those two. This file is the follow-up
//! it asks for: it widens the grid to non-hash-domain configurations, and adds
//! `SaturninBs32Core::decrypt_block`, which `core_equivalence.rs` does not touch at all.
//!
//! Both halves were red when this file was written, for independent reasons.
//!
//! *Constants.* `SaturninBs32Core`'s LFSR kept its shift-register state in a `u32` that was never
//! truncated back to the specification's 16 bits, and `!(x >> 15).wrapping_add(1)` does not parse
//! as the two's-complement mask the code meant to write (method-call precedence binds
//! `.wrapping_add(1)` before the `!`, giving `!((x >> 15) + 1)`). Every derived constant was
//! wrong at every `(rounds, domain)`; hardcoded `(16, 7)` / `(16, 8)` tables were the only reason
//! the shipped hash was right, and they are exactly why the two hash domains alone cannot witness
//! this bug — hence the grid.
//!
//! *Decrypt.* `decrypt_block` aliased the inverse S-box and inverse MDS to the **forward**
//! operations, on the false claim that each is its own inverse (Saturnin's own bit-sliced C ships
//! distinct `SBOX_INV` / `MDS_INV` circuits); it XORed the round constant into two registers where
//! encrypt only ever writes one; and its reversed `step_by(2)` loop dropped a super-round whenever
//! the round count was even. None of that depends on the constants being right, which is why
//! decrypt is also checked at `(16, 8)` — a configuration whose constants were correct all along.

#![cfg(feature = "alloc")]

use lib_q_saturnin::bs32_core::SaturninBs32Core;
use lib_q_saturnin::core::SaturninCore;

/// Grid of (super-rounds, domain) pairs covering hash domains, AEAD/short domains, an odd
/// round count (exercises the "one super-round left over" tail that a reversed `step_by(2)` loop
/// mishandles), and the boundary values 0/31/15.
const GRID: [(usize, u8); 10] = [
    (10, 1),
    (10, 6),
    (12, 3),
    (16, 6),
    (16, 7),
    (16, 8),
    (17, 9),
    (31, 15),
    (0, 0),
    (1, 0),
];

/// The round-constant LFSR from the Saturnin specification, written out independently here —
/// deliberately not delegating to `SaturninBs32Core`'s own generator (that would make this test
/// unable to fail), and deliberately not a pinned table copy-pasted from anywhere in-crate.
///
/// Two 16-bit shift registers with taps `0x2D` (RC0) and `0x53` (RC1), seeded from
/// `domain + (rounds << 4) + 0xFE00`, clocked 16 times per super-round, packed as
/// `(RC1 << 16) | RC0` per super-round.
fn expected_packed_round_constants(num_super_rounds: usize, domain: u8) -> Vec<u32> {
    let mut out = Vec::with_capacity(num_super_rounds);
    let seed = (domain as u16)
        .wrapping_add((num_super_rounds as u16) << 4)
        .wrapping_add(0xFE00);
    let (mut x0, mut x1) = (seed, seed);

    for _ in 0..num_super_rounds {
        for _ in 0..16 {
            let mask0: u16 = if (x0 >> 15) != 0 { 0xFFFF } else { 0x0000 };
            let mask1: u16 = if (x1 >> 15) != 0 { 0xFFFF } else { 0x0000 };
            x0 = (x0 << 1) ^ (0x2D & mask0);
            x1 = (x1 << 1) ^ (0x53 & mask1);
        }
        out.push(((x1 as u32) << 16) | (x0 as u32));
    }
    out
}

// The designers' own packed bit-sliced round-constant tables, quoted verbatim from the Saturnin
// NIST-LWC submission package. These are the ONLY pinned tables in this file: every value below
// appears character-for-character in the designers' C, at the cited file and symbol. Nothing here
// was derived by libQ, by this test, or by any tool of ours — a self-derived value dressed up as a
// reference vector is how the broken generator this file exists to catch survived in the first
// place. The submission ships packed u32 tables for exactly six (rounds, domain) pairs; there is
// no designer table for e.g. (10, 6) or (12, 3), so those pairs are covered by
// `expected_packed_round_constants` above (an independent from-spec model) and not pinned here.
//
// crypto_aead/saturninctrcascadev2/bs32/encrypt.c — `RC_10_1` .. `RC_10_5` (CTR-Cascade, R = 10,
// D = 1..5).
const RC_10_1: [u32; 10] = [
    0x4EB026C2, 0x90595303, 0xAA8FE632, 0xFE928A92, 0x4115A419, 0x93539532, 0x5DB1CC4E, 0x541515CA,
    0xBD1F55A8, 0x5A6E1A0D,
];
const RC_10_2: [u32; 10] = [
    0x4E4526B5, 0xA3565FF0, 0x0F8F20D8, 0x0B54BEE1, 0x7D1A6C9D, 0x17A6280A, 0xAA46C986, 0xC1199062,
    0x182C5CDE, 0xA00D53FE,
];
const RC_10_3: [u32; 10] = [
    0x4E162698, 0xB2535BA1, 0x6C8F9D65, 0x5816AD30, 0x691FD4FA, 0x6BF5BCF9, 0xF8EB3525, 0xB21DECFA,
    0x7B3DA417, 0xF62C94B4,
];
const RC_10_4: [u32; 10] = [
    0x4FAF265B, 0xC5484616, 0x45DCAD21, 0xE08BD607, 0x0504FDB8, 0x1E1F5257, 0x45FBC216, 0xEB529B1F,
    0x52194E32, 0x5498C018,
];
const RC_10_5: [u32; 10] = [
    0x4FFC2676, 0xD44D4247, 0x26DC109C, 0xB3C9C5D6, 0x110145DF, 0x624CC6A4, 0x17563EB5, 0x9856E787,
    0x3108B6FB, 0x02B90752,
];
// crypto_hash/saturninhashv2/bs32/hash.c — `RC_16_7`, `RC_16_8` (Saturnin-Hash, R = 16, D = 7/8).
// These are the two tables `bs32_core.rs` used to carry as a hardcoded ROM; pinning them here is
// what lets that ROM be deleted from the datapath without losing the designer-anchored check.
const RC_16_7: [u32; 16] = [
    0x3FBA180C, 0x563AB9AB, 0x125EA5EF, 0x859DA26C, 0xB8CF779B, 0x7D4DE793, 0x07EFB49F, 0x8D525306,
    0x1E08E6AB, 0x41729F87, 0x8C4AEF0A, 0x4AA0C9A7, 0xD93A95EF, 0xBB00D2AF, 0xB62C5BF0, 0x386D94D8,
];
const RC_16_8: [u32; 16] = [
    0x3C9B19A7, 0xA9098694, 0x23F878DA, 0xA7B647D3, 0x74FC9D78, 0xEACAAE11, 0x2F31A677, 0x4CC8C054,
    0x2F51CA05, 0x5268F195, 0x4F5B8A2B, 0xF614B4AC, 0xF1D95401, 0x764D2568, 0x6A493611, 0x8EEF9C3E,
];

#[test]
fn bs32_constants_match_independent_lfsr_model_over_the_grid() {
    let mut wrong: Vec<String> = Vec::new();

    for (rounds, domain) in GRID {
        let core = SaturninBs32Core::new(rounds, domain).expect("valid (rounds, domain)");
        let got = core.round_constants().to_vec();
        let want = expected_packed_round_constants(rounds, domain);
        if got != want {
            wrong.push(format!(
                "  (rounds={rounds}, domain={domain})\n     got  {:08X?}\n     want {:08X?}",
                &got[..got.len().min(4)],
                &want[..want.len().min(4)],
            ));
        }
    }

    assert!(
        wrong.is_empty(),
        "{} of {} grid configuration(s) diverge from the specification's LFSR:\n{}",
        wrong.len(),
        GRID.len(),
        wrong.join("\n"),
    );
}

#[test]
fn bs32_constants_match_designer_tables() {
    let cases: [(usize, u8, &[u32]); 7] = [
        (10, 1, &RC_10_1),
        (10, 2, &RC_10_2),
        (10, 3, &RC_10_3),
        (10, 4, &RC_10_4),
        (10, 5, &RC_10_5),
        (16, 7, &RC_16_7),
        (16, 8, &RC_16_8),
    ];

    let mut wrong: Vec<String> = Vec::new();
    for (rounds, domain, want) in cases {
        let got = SaturninBs32Core::new(rounds, domain).unwrap();
        if got.round_constants() != want {
            wrong.push(format!(
                "  RC_{rounds}_{domain}\n     got  {:08X?}\n     want {:08X?}",
                got.round_constants(),
                want,
            ));
        }
    }

    assert!(
        wrong.is_empty(),
        "{} of {} designer round-constant table(s) do not match what the crate derives:\n{}",
        wrong.len(),
        cases.len(),
        wrong.join("\n"),
    );
}

/// The from-spec model in this file is only a trustworthy oracle for the grid pairs the designers
/// never tabulated if it reproduces the ones they did. Check it directly, so a model that drifted
/// cannot quietly bless a wrong implementation that drifted the same way.
#[test]
fn the_from_spec_model_itself_reproduces_the_designer_tables() {
    assert_eq!(expected_packed_round_constants(10, 1), RC_10_1, "RC_10_1");
    assert_eq!(expected_packed_round_constants(10, 2), RC_10_2, "RC_10_2");
    assert_eq!(expected_packed_round_constants(10, 3), RC_10_3, "RC_10_3");
    assert_eq!(expected_packed_round_constants(10, 4), RC_10_4, "RC_10_4");
    assert_eq!(expected_packed_round_constants(10, 5), RC_10_5, "RC_10_5");
    assert_eq!(expected_packed_round_constants(16, 7), RC_16_7, "RC_16_7");
    assert_eq!(expected_packed_round_constants(16, 8), RC_16_8, "RC_16_8");
}

/// A handful of unrelated key/block pairs so a pass cannot come from a degenerate all-zero state.
fn sample_inputs() -> [([u8; 32], [u8; 32]); 4] {
    [
        ([0x00; 32], [0x00; 32]),
        ([0xFF; 32], [0x00; 32]),
        ([0x5A; 32], [0x42; 32]),
        (
            core::array::from_fn(|i| i as u8),
            core::array::from_fn(|i| (255 - i) as u8),
        ),
    ]
}

#[test]
fn bs32_encrypt_matches_scalar_core_over_the_grid() {
    let mut mismatches: Vec<String> = Vec::new();

    for (rounds, domain) in GRID {
        for (key, block) in sample_inputs() {
            let mut a = block;
            SaturninCore::new(rounds, domain)
                .expect("SaturninCore rejected a valid (rounds, domain)")
                .encrypt_block(&key, &mut a)
                .expect("SaturninCore::encrypt_block failed");

            let mut b = block;
            SaturninBs32Core::new(rounds, domain)
                .expect("SaturninBs32Core rejected a valid (rounds, domain)")
                .encrypt_block(&key, &mut b)
                .expect("SaturninBs32Core::encrypt_block failed");

            if a != b {
                mismatches.push(format!(
                    "  (rounds={rounds}, domain={domain}) key={:02x?}\n     \
                     SaturninCore     = {:02x?}\n     SaturninBs32Core = {:02x?}",
                    &key[..4],
                    &a[..8],
                    &b[..8],
                ));
            }
        }
    }

    assert!(
        mismatches.is_empty(),
        "the two Saturnin cores compute different permutations at {} configuration(s).\n\
         There is only one Saturnin.\n{}",
        mismatches.len(),
        mismatches.join("\n"),
    );
}

#[test]
fn bs32_decrypt_inverts_bs32_encrypt_over_the_grid() {
    let mut failures: Vec<String> = Vec::new();

    for (rounds, domain) in GRID {
        let core = SaturninBs32Core::new(rounds, domain).expect("valid (rounds, domain)");
        for (key, block) in sample_inputs() {
            let mut round_tripped = block;
            core.encrypt_block(&key, &mut round_tripped)
                .expect("encrypt_block failed");
            core.decrypt_block(&key, &mut round_tripped)
                .expect("decrypt_block failed");

            if round_tripped != block {
                failures.push(format!(
                    "  (rounds={rounds}, domain={domain}) key={:02x?}\n     \
                     original        = {:02x?}\n     decrypt(encrypt) = {:02x?}",
                    &key[..4],
                    &block[..8],
                    &round_tripped[..8],
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "bs32 decrypt_block did not invert encrypt_block at {} configuration(s):\n{}",
        failures.len(),
        failures.join("\n"),
    );
}

#[test]
fn bs32_decrypt_matches_scalar_core_decrypt_over_the_grid() {
    let mut mismatches: Vec<String> = Vec::new();

    for (rounds, domain) in GRID {
        for (key, block) in sample_inputs() {
            // Encrypt with the scalar core (already verified correct — see core_equivalence.rs
            // and the KAT-backed tests in kat_tests.rs) to get a ciphertext both decryptors should
            // be able to invert, since the two cores compute the same permutation.
            let mut ciphertext = block;
            SaturninCore::new(rounds, domain)
                .unwrap()
                .encrypt_block(&key, &mut ciphertext)
                .unwrap();

            let mut a = ciphertext;
            SaturninCore::new(rounds, domain)
                .unwrap()
                .decrypt_block(&key, &mut a)
                .unwrap();

            let mut b = ciphertext;
            SaturninBs32Core::new(rounds, domain)
                .unwrap()
                .decrypt_block(&key, &mut b)
                .unwrap();

            if a != b {
                mismatches.push(format!(
                    "  (rounds={rounds}, domain={domain}) key={:02x?}\n     \
                     SaturninCore::decrypt     = {:02x?}\n     \
                     SaturninBs32Core::decrypt = {:02x?}\n     (expected original block  = {:02x?})",
                    &key[..4],
                    &a[..8],
                    &b[..8],
                    &block[..8],
                ));
            }
        }
    }

    assert!(
        mismatches.is_empty(),
        "the two Saturnin cores' decrypt_block disagree at {} configuration(s):\n{}",
        mismatches.len(),
        mismatches.join("\n"),
    );
}
