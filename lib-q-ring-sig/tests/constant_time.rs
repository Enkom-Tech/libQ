//! Structural (non-timing) pin on `dualring_prf::dualring_prf_sign_u256`'s `ct_eq`-based key
//! match check (`lib-q-ring-sig/src/dualring_prf.rs`, lines ~159-160). Requires the
//! `pilot-insecure-prf-transcript` feature, which is what gates the `dualring_prf` module.
//!
//! Does NOT measure wall-clock timing -- that is unmeasurable in a unit test and out of scope
//! per card t_043571b4 (a prior "constant-time" test compared two algorithms' speeds and was
//! rejected). What these tests pin is the code shape: `dualring_prf_sign_u256` must reject a
//! caller-supplied `leg_key`/`gold_key` that mismatches the ring member's public encoding at
//! ANY bit position -- including the single low bit and the single high bit -- rather than a
//! check that only inspects a subset of the word (the class of regression fixed at ed104c2 for
//! seven `PartialEq` impls elsewhere in this repo, and the pattern the whole-word `ct_eq` here
//! is meant to prevent).
//!
//! SUSPECTED (not fixed here, out of scope for this lane): the two `ct_eq` outcomes at lines
//! 159-160 are combined with `bool::from(A) || bool::from(B)`, which short-circuits in Rust --
//! if the Legendre-key comparison already mismatches, the Gold-key `ct_eq` is never evaluated.
//! Both individual `ct_eq` calls are still whole-word constant-time comparisons (each one
//! resists a partial/prefix leak on its own operand, which is what the tests below pin), but the
//! two-key combination is not evaluated with equal work across both operands in every input
//! case. This is a finding for follow-up, not something this lane changes.

use lib_q_prf::{
    GoldKey256,
    GoldPrfParams256,
    LegendreKey256,
    LegendrePrfParams256,
    u256_to_le_bytes,
};
use lib_q_random::new_deterministic_rng;
use lib_q_ring_sig::dualring_prf::{
    DualringPrfError,
    DualringPrfMemberSecrets256,
    dualring_prf_sign_u256,
};

fn member_from_seed(seed: u8) -> (DualringPrfMemberSecrets256, LegendreKey256, GoldKey256) {
    let leg_p = LegendrePrfParams256::pilot();
    let gold_p = GoldPrfParams256::pilot();
    let leg = LegendreKey256::derive_from_seed(&[seed, 1, 2, 3], &leg_p).expect("leg");
    let gold = GoldKey256::derive_from_seed(&[seed, 4, 5, 6], &gold_p).expect("gold");
    let m = DualringPrfMemberSecrets256 {
        legendre_key_le: u256_to_le_bytes(leg.as_uint()),
        gold_key_le: u256_to_le_bytes(gold.as_uint()),
    };
    (m, leg, gold)
}

/// Sanity: the matching key for the ring member signs successfully.
#[test]
fn matching_keys_sign_ok() {
    let (m0, l0, g0) = member_from_seed(0xA1);
    let ring = [m0];
    let msg = b"constant-time-pin";
    let mut rng = new_deterministic_rng([0x10u8; 32]);
    assert!(dualring_prf_sign_u256(&mut rng, &ring, 0, &l0, &g0, msg).is_ok());
}

/// Flips every single bit of the caller's Legendre key (relative to the ring member's public
/// encoding) and confirms signing is rejected in every case -- including the low bit and the
/// high bit of the 256-bit encoding, which a comparison inspecting only a subset of the value
/// could silently accept.
#[test]
fn legendre_key_mismatch_rejected_at_every_bit_position() {
    let (m0, _l0, g0) = member_from_seed(0x01);
    let leg_p = LegendrePrfParams256::pilot();
    let ring = [m0.clone()];
    let msg = b"leg-mismatch";

    for bit in 0..256usize {
        let mut bytes = m0.legendre_key_le;
        bytes[bit / 8] ^= 1 << (bit % 8);
        let candidate = lib_q_prf::u256_from_le_bytes(&bytes);
        // Only exercise bit flips that still decode to a valid Legendre key under the pilot
        // modulus; an out-of-range encoding is rejected earlier (InvalidInput from
        // `LegendreKey256::from_uint`), which is a different code path than the ct_eq check
        // under test.
        let Ok(wrong_leg) = LegendreKey256::from_uint(candidate, &leg_p) else {
            continue;
        };
        let mut rng = new_deterministic_rng([0x20u8; 32]);
        let err = dualring_prf_sign_u256(&mut rng, &ring, 0, &wrong_leg, &g0, msg).unwrap_err();
        assert_eq!(
            err,
            DualringPrfError::InvalidInput,
            "legendre key mismatch at bit {bit} was not rejected"
        );
    }
}

/// Same as `legendre_key_mismatch_rejected_at_every_bit_position`, for the Gold key.
#[test]
fn gold_key_mismatch_rejected_at_every_bit_position() {
    let (m0, l0, _g0) = member_from_seed(0x02);
    let gold_p = GoldPrfParams256::pilot();
    let ring = [m0.clone()];
    let msg = b"gold-mismatch";

    for bit in 0..256usize {
        let mut bytes = m0.gold_key_le;
        bytes[bit / 8] ^= 1 << (bit % 8);
        let candidate = lib_q_prf::u256_from_le_bytes(&bytes);
        let Ok(wrong_gold) = GoldKey256::from_uint(candidate, &gold_p) else {
            continue;
        };
        let mut rng = new_deterministic_rng([0x21u8; 32]);
        let err = dualring_prf_sign_u256(&mut rng, &ring, 0, &l0, &wrong_gold, msg).unwrap_err();
        assert_eq!(
            err,
            DualringPrfError::InvalidInput,
            "gold key mismatch at bit {bit} was not rejected"
        );
    }
}
