#![cfg(feature = "blind-pcs")]

use lib_q_blind_pcs::{
    blind_commit,
    blind_open,
    verify,
};

#[test]
fn demo_commit_open_verify_flow() {
    let message = b"demo polynomial bytes";
    let blind = b"demo blinding seed";

    let commitment = blind_commit(message, blind);
    let opening = blind_open(message, blind);

    assert!(verify(&commitment, &opening));
}

#[test]
fn verify_rejects_mismatched_opening() {
    let message = b"statement";
    let blind = b"blind";
    let commitment = blind_commit(message, blind);

    let tampered = blind_open(b"tampered", blind);
    assert!(!verify(&commitment, &tampered));
}
