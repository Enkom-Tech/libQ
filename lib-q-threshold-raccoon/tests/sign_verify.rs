//! Core sign/verify coverage. Run with `--release` (FS masking over `N = 1024`).

use lib_q_random::new_deterministic_rng;
use lib_q_threshold_raccoon::{
    combine_opening,
    decode_signature,
    encode_signature,
    keygen_shares,
    setup,
    sign,
    verify,
};

fn det(seed: u8) -> lib_q_random::LibQRng {
    new_deterministic_rng([seed; 32])
}

#[test]
fn keygen_sign_verify_and_subset_independence() {
    let profile = setup();
    let mut rng = det(0x01);
    let kg = keygen_shares(&profile, 3, 5, &mut rng).expect("keygen");
    let msg = b"threshold-raccoon";

    // Combine threshold {1,2,3} → sign → verify.
    let subset: Vec<_> = kg.secret_shares.iter().take(3).cloned().collect();
    let opening = combine_opening(&subset).expect("combine");
    let sig = sign(&mut rng, &kg.public_key, &opening, msg).expect("sign");
    assert!(verify(&kg.public_key, msg, &sig));
    assert!(
        !verify(&kg.public_key, b"wrong", &sig),
        "wrong message must fail"
    );

    // A DIFFERENT threshold subset reconstructs the same key and also signs+verifies.
    let subset2 = vec![
        kg.secret_shares[1].clone(),
        kg.secret_shares[3].clone(),
        kg.secret_shares[4].clone(),
    ];
    let opening2 = combine_opening(&subset2).expect("combine2");
    let sig2 = sign(&mut rng, &kg.public_key, &opening2, msg).expect("sign2");
    assert!(
        verify(&kg.public_key, msg, &sig2),
        "any threshold subset signs for the same key"
    );

    // Wire round-trip.
    let bytes = encode_signature(&sig).expect("encode");
    assert_eq!(decode_signature(&bytes).expect("decode"), sig);
}

#[test]
fn too_few_shares_rejected() {
    let profile = setup();
    let mut rng = det(0x02);
    let kg = keygen_shares(&profile, 3, 5, &mut rng).expect("keygen");
    let only_two: Vec<_> = kg.secret_shares.iter().take(2).cloned().collect();
    assert!(
        combine_opening(&only_two).is_err(),
        "sub-threshold combine must error"
    );
}
