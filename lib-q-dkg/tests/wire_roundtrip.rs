//! Wire round-trip for the round-1 commitment broadcast and complaints.

mod common;

use common::{
    PARTIES,
    THRESHOLD,
    det_rng,
};
use lib_q_dkg::{
    decode_complaint,
    decode_round1_commitments,
    dkg_build_complaint,
    dkg_eval_share,
    dkg_round1_commit,
    encode_complaint,
    encode_round1_commitments,
    setup,
};

#[test]
fn round1_commitments_roundtrip() {
    let profile = setup();
    let mut rng = det_rng(0x21);
    let (_poly, comms) =
        dkg_round1_commit(&profile, PARTIES, THRESHOLD, 2, &mut rng).expect("round1");
    let wire = encode_round1_commitments(&comms).expect("encode");
    let decoded = decode_round1_commitments(&wire).expect("decode");
    assert_eq!(decoded, comms);
}

#[test]
fn complaint_roundtrip() {
    let profile = setup();
    let mut rng = det_rng(0x22);
    let (poly, _comms) =
        dkg_round1_commit(&profile, PARTIES, THRESHOLD, 3, &mut rng).expect("round1");
    let share = dkg_eval_share(&poly, 4, &mut rng).expect("eval");
    let complaint = dkg_build_complaint(3, 4, &share);
    let wire = encode_complaint(&complaint).expect("encode");
    let decoded = decode_complaint(&wire).expect("decode");
    assert_eq!(decoded.dealer, 3);
    assert_eq!(decoded.recipient, 4);
    assert_eq!(decoded.share.dealer, 3);
    assert_eq!(decoded.share.recipient, 4);
    assert_eq!(decoded.share.threshold, THRESHOLD);
}
