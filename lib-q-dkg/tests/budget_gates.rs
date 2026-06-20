//! Wire budget gates reject oversized payloads.

mod common;

use common::{
    PARTIES,
    THRESHOLD,
    det_rng,
};
use lib_q_dkg::{
    DkgError,
    WIRE_BUDGET_DKG_COMPLAINT_BYTES,
    WIRE_BUDGET_DKG_ROUND1_BYTES,
    decode_complaint,
    decode_round1_commitments,
    dkg_round1_commit,
    encode_round1_commitments,
    setup,
};

#[test]
fn round1_encode_within_budget() {
    let profile = setup();
    let mut rng = det_rng(0x31);
    let (_poly, comms) =
        dkg_round1_commit(&profile, PARTIES, THRESHOLD, 1, &mut rng).expect("round1");
    let wire = encode_round1_commitments(&comms).expect("encode");
    assert!(wire.len() <= WIRE_BUDGET_DKG_ROUND1_BYTES);
}

#[test]
fn oversized_round1_wire_rejected() {
    let oversized = vec![0u8; WIRE_BUDGET_DKG_ROUND1_BYTES + 1];
    let err = decode_round1_commitments(&oversized).expect_err("must reject");
    assert!(matches!(err, DkgError::BudgetExceeded { .. }));
}

#[test]
fn oversized_complaint_wire_rejected() {
    let oversized = vec![0u8; WIRE_BUDGET_DKG_COMPLAINT_BYTES + 1];
    // `Complaint` is not `Debug` (holds secret openings), so match instead of `expect_err`.
    match decode_complaint(&oversized) {
        Err(DkgError::BudgetExceeded { .. }) => {}
        Err(other) => panic!("wrong error: {other}"),
        Ok(_) => panic!("oversized complaint wire must be rejected"),
    }
}
