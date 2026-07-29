//! KAT regeneration — permanently disabled.
//!
//! **What this test used to do:** it was an `#[ignore]`d generator, run on demand, that drove a
//! 3-of-5 ceremony and wrote `tests/vectors/threshold-sig-pop-v1.json` plus a manifest. Those
//! files were then exported as this crate's published known-answer vectors.
//!
//! **What it does now:** nothing can be regenerated, because `aggregate` refuses. Rather than
//! leave a generator that silently produces nothing, this asserts the regeneration path is
//! closed, so anyone who reaches for it gets a clear failure instead of an empty result. It is
//! no longer `#[ignore]`d: the assertion is cheap and belongs in the normal run.

mod common;

#[allow(deprecated)]
use lib_q_threshold_sig::{
    ThresholdSigError,
    aggregate,
    setup,
};

#[test]
#[allow(deprecated)]
fn kat_regeneration_is_closed() {
    let profile = setup();
    let pk = common::inert_public_key();
    let commitments: Vec<_> = (1..=common::THRESHOLD)
        .map(common::inert_commitment)
        .collect();
    let partials: Vec<_> = (1..=common::THRESHOLD).map(common::inert_partial).collect();

    assert_eq!(
        aggregate(
            &profile,
            &pk,
            b"kat-regenerate-message",
            &commitments,
            &partials,
        )
        .err(),
        Some(ThresholdSigError::SchemeWithdrawn),
        "no vector can be regenerated for a withdrawn scheme",
    );
}

/// The shipped vector file must carry the withdrawal notice, not a signature blob.
#[test]
fn shipped_vector_file_is_a_withdrawal_notice() {
    let raw = include_str!("vectors/threshold-sig-pop-v1.json");
    assert!(
        raw.contains("WITHDRAWN"),
        "vector file must state the withdrawal: {raw}",
    );
    assert!(
        !raw.contains("wire_hex"),
        "vector file must not ship a signature blob: {raw}",
    );
}
