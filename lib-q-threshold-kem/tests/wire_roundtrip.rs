mod common;

use lib_q_threshold_kem::{
    combine_decap,
    decode_threshold_kem_wire_v1,
    encap,
    encode_threshold_kem_wire_v1,
    partial_decap,
};

#[test]
fn wire_roundtrip() {
    let (profile, keygen) = common::deterministic_keygen(0x11);
    let mut rng = common::deterministic_rng(0x12);
    let enc = encap(&profile, &keygen.public_key, &mut rng).expect("encap");
    let partials = keygen
        .secret_shares
        .iter()
        .take(usize::from(common::THRESHOLD))
        .map(|share| partial_decap(share, &enc.ciphertext).expect("partial"))
        .collect::<Vec<_>>();
    let wire = encode_threshold_kem_wire_v1(&profile, &enc.ciphertext, &partials).expect("encode");
    let decoded = decode_threshold_kem_wire_v1(&profile, &wire).expect("decode");
    assert_eq!(decoded.ciphertext, enc.ciphertext);
    assert_eq!(decoded.shares, partials);

    let shared = combine_decap(
        &profile,
        &decoded.ciphertext,
        &decoded.shares,
        &keygen.public_key.share_verifiers,
        common::THRESHOLD,
    )
    .expect("combine");
    assert_eq!(shared, enc.shared_secret);
}
