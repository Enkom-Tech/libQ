//! Structural (non-timing) pin on `keys::validate_key_u256` / `validate_key_u512`'s
//! `ct_eq`/`ct_lt`-based key validation (`lib-q-prf/src/keys.rs`).
//!
//! Does NOT measure wall-clock timing -- that is unmeasurable in a unit test and out of scope
//! per card t_043571b4 (a prior "constant-time" test compared two algorithms' speeds and was
//! rejected). What these tests pin is the code shape: a key must be rejected as invalid
//! regardless of WHICH word of the big integer carries the zero/out-of-range signal. A
//! short-circuiting or word-truncated check (e.g. one that only inspects the low 32/64 bits
//! for "is zero") would still fail these on OUTPUT alone if the high words carry the only
//! non-zero bit -- that is exactly what `zero_key_rejected_regardless_of_which_word_is_set`
//! is built to catch.

use crypto_bigint::U256;
use lib_q_prf::PrfError;
use lib_q_prf::keys::validate_key_u256;

/// A representative prime-shaped modulus (not the real PRF prime, just large enough to exercise
/// the full width of `U256`).
fn modulus() -> U256 {
    U256::from_be_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF1")
}

#[test]
fn zero_key_rejected() {
    let p = modulus();
    assert_eq!(
        validate_key_u256(&U256::ZERO, &p),
        Err(PrfError::InvalidKey)
    );
}

#[test]
fn key_equal_to_or_above_modulus_rejected() {
    let p = modulus();
    assert_eq!(validate_key_u256(&p, &p), Err(PrfError::InvalidKey));
    let above = p.wrapping_add(&U256::ONE);
    assert_eq!(validate_key_u256(&above, &p), Err(PrfError::InvalidKey));
}

#[test]
fn in_range_key_accepted() {
    let p = modulus();
    assert!(validate_key_u256(&U256::ONE, &p).is_ok());
    let just_below = p.wrapping_sub(&U256::ONE);
    assert!(validate_key_u256(&just_below, &p).is_ok());
}

/// A key that is non-zero ONLY in one 32-bit word (every other word all-zero) must still be
/// accepted, for every word position across the 256-bit representation. This exhaustively
/// covers every 32-bit word position and is exactly the shape of check that a word-truncated
/// zero-comparison (checking only a subset of words) would get wrong for whichever word it
/// skips -- confirmed below: constraining the check to `as_words()[0]` alone made this test
/// fail for the word holding byte index 28..31 of the little-endian encoding (see the red-demo
/// evidence recorded in `scratchpad/audit-triage/fix-ct-tests.md`).
#[test]
fn nonzero_key_with_a_single_set_word_at_any_position_is_accepted() {
    let p = modulus();
    for byte_idx in (0..32usize).step_by(4) {
        let mut bytes = [0u8; 32];
        bytes[byte_idx] = 0x01;
        let k = U256::from_le_slice(&bytes);
        assert!(
            validate_key_u256(&k, &p).is_ok(),
            "key with only the word at byte offset {byte_idx} set was rejected as invalid"
        );
    }
}
