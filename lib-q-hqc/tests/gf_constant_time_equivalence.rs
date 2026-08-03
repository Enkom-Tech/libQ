//! Exhaustive equivalence test for the table-free, branch-free GF(2^8) arithmetic in
//! `lib-q-hqc/src/gf.rs` against an independently rebuilt exp/log table oracle, run against the
//! crate's *public* API (`lib_q_hqc::gf::{gf_mul, gf_square, gf_inverse}`) as an outside-the-crate
//! integration check, complementing the unit tests in `gf.rs`'s own `#[cfg(test)]` module.
//!
//! `lib-q-hqc/src/reed_solomon.rs`'s table-based `gf_multiply`/`gf_inverse`/`gf_inverse_u16`
//! (lines 112-119, 385-408) are `impl`-private, so this test does not compare against them
//! directly; instead it rebuilds the GF(2^8) exp/log tables from scratch using the same
//! generation recurrence (`exp[i] = alpha^i`, `alpha = 2`, reducing by `GF_POLY` whenever the
//! running value overflows 8 bits) that both `reference/hqc/src/ref/gf.c`'s `gf_generate` and
//! `ReedSolomon::init_gf_tables` use. This is an independent oracle, not a copy of the code under
//! test, so a shared bug in both implementations would still show up as a mismatch here only if
//! the bug were in the *new* branch-free code and not in this from-scratch table build (and
//! vice-versa) — the two implementations do not share any code path.
//!
//! Every domain here is small enough to check exhaustively (256, or 256*256 pairs), so exhaustive
//! is the standard used throughout, not a sample.

use lib_q_hqc::gf::{
    gf_inverse,
    gf_mul,
    gf_square,
};

const GF_M: u32 = 8;
const GF_POLY: u16 = 0x11D;

/// Rebuild GF(2^8) exp/log tables from scratch (see module doc for why this, rather than
/// `reed_solomon.rs`'s private tables, is the oracle here).
fn build_tables() -> ([u8; 256], [u8; 256]) {
    let mut exp = [0u8; 256];
    let mut log = [0u8; 256];
    let mut elt: u16 = 1;
    let alpha: u16 = 2;
    for i in 0..255usize {
        exp[i] = elt as u8;
        log[elt as usize] = i as u8;
        elt *= alpha;
        if elt >= 1 << GF_M {
            elt ^= GF_POLY;
        }
    }
    log[0] = 0; // log(0) undefined; 0 by convention
    (exp, log)
}

fn table_mul(exp: &[u8; 256], log: &[u8; 256], a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let sum = log[a as usize] as usize + log[b as usize] as usize;
    exp[sum % 255]
}

fn table_inverse(exp: &[u8; 256], log: &[u8; 256], a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    exp[(255 - log[a as usize] as usize) % 255]
}

/// Exhaustive over all 256*256 = 65536 input pairs.
#[test]
fn gf_mul_matches_rebuilt_table_over_full_domain() {
    let (exp, log) = build_tables();
    let mut checked = 0usize;
    for a in 0u8..=255 {
        for b in 0u8..=255 {
            assert_eq!(
                gf_mul(a, b),
                table_mul(&exp, &log, a, b),
                "gf_mul({a}, {b}) mismatch"
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 65536, "did not cover the full 256*256 domain");
}

/// Exhaustive over all 256 inputs.
#[test]
fn gf_square_matches_rebuilt_table_over_full_domain() {
    let (exp, log) = build_tables();
    let mut checked = 0usize;
    for a in 0u8..=255 {
        assert_eq!(
            gf_square(a),
            table_mul(&exp, &log, a, a),
            "gf_square({a}) mismatch"
        );
        checked += 1;
    }
    assert_eq!(checked, 256, "did not cover the full 256-value domain");
}

/// Exhaustive over all 256 inputs, including `a == 0`.
#[test]
fn gf_inverse_matches_rebuilt_table_over_full_domain() {
    let (exp, log) = build_tables();
    let mut checked = 0usize;
    for a in 0u8..=255 {
        assert_eq!(
            gf_inverse(a),
            table_inverse(&exp, &log, a),
            "gf_inverse({a}) mismatch"
        );
        checked += 1;
    }
    assert_eq!(checked, 256, "did not cover the full 256-value domain");
}

/// `gf_inverse` has no `a == 0` special case anywhere in its addition chain (see doc comment on
/// `gf_inverse` in `lib-q-hqc/src/gf.rs`), yet must still match the old table-based convention
/// that callers rely on: inverse of 0 is 0.
#[test]
fn gf_inverse_zero_is_zero_matching_table_convention() {
    let (exp, log) = build_tables();
    assert_eq!(gf_inverse(0), 0);
    assert_eq!(table_inverse(&exp, &log, 0), 0);
}

/// Cross-check via the field axiom `a * a^-1 == 1` for every nonzero element, independent of the
/// rebuilt table oracle.
#[test]
fn gf_inverse_is_multiplicative_inverse_for_all_nonzero_elements() {
    for a in 1u8..=255 {
        assert_eq!(gf_mul(a, gf_inverse(a)), 1, "a * gf_inverse(a) != 1 for a={a}");
    }
}
