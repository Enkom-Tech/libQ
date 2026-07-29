//! Known-answer coverage for the withdrawn scheme.
//!
//! **What this test used to do:** run a 3-of-5 ceremony, `aggregate` it, assert `verify`
//! returned `true`, assert `identify_abort` fingered a tampered partial, and assert
//! `proactive_refresh` rotated shares. Every one of those assertions certified behaviour that
//! provided no security: the `verify` assertion in particular would have passed just as
//! happily for a signature no participant ever produced.
//!
//! **What it does now:** asserts that each of those same entry points refuses. The historical
//! vectors under `tests/vectors/` have been replaced with a withdrawal notice — they described
//! a "valid" signature under a scheme whose verifier accepted anything, so republishing them as
//! known-good answers would be misleading. There is deliberately no replacement vector: a
//! withdrawn scheme has no correct answers to know.

mod common;

#[allow(deprecated)]
use lib_q_threshold_sig::{
    PROFILE_ENVELOPE_BUDGET_BYTES,
    ThresholdSigError,
    aggregate,
    encode_threshold_sig_wire_v1,
    identify_abort,
    proactive_refresh,
    setup,
    verify,
};

#[test]
#[allow(deprecated)]
fn kat_core_paths_all_refuse() {
    let profile = setup();
    let pk = common::inert_public_key();
    let message = b"kat-sign-verify-3-of-5";
    let commitments: Vec<_> = (1..=common::THRESHOLD)
        .map(common::inert_commitment)
        .collect();
    let partials: Vec<_> = (1..=common::THRESHOLD).map(common::inert_partial).collect();

    assert_eq!(
        aggregate(&profile, &pk, message, &commitments, &partials).err(),
        Some(ThresholdSigError::SchemeWithdrawn),
        "aggregate must refuse",
    );
    assert_eq!(
        verify(&profile, &pk, message, &common::inert_signature()).err(),
        Some(ThresholdSigError::SchemeWithdrawn),
        "verify must refuse — it must never certify a signature again",
    );
    assert_eq!(
        identify_abort(&profile, &pk, message, &commitments, &partials).err(),
        Some(ThresholdSigError::SchemeWithdrawn),
        "identify_abort must refuse",
    );

    let shares: Vec<_> = (1..=common::PARTIES).map(common::inert_share).collect();
    let mut rng = common::deterministic_rng(0x44);
    assert_eq!(
        proactive_refresh(&profile, &shares, &mut rng).err(),
        Some(ThresholdSigError::SchemeWithdrawn),
        "proactive_refresh must refuse",
    );
}

/// The envelope budget constant still governs the retained wire codec, so keep it pinned.
#[test]
fn envelope_budget_still_applies_to_the_retained_codec() {
    let profile = setup();
    let wire = encode_threshold_sig_wire_v1(&profile, &[0u8; 96], &[0u8; 128]).expect("encode");
    assert!(wire.len() <= PROFILE_ENVELOPE_BUDGET_BYTES);
}
