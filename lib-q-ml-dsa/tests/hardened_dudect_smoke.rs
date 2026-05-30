#![cfg(all(feature = "hardened", feature = "mldsa44"))]

use lib_q_ml_dsa::constants::{
    KEY_GENERATION_RANDOMNESS_SIZE,
    SIGNING_RANDOMNESS_SIZE,
};
use lib_q_ml_dsa::ml_dsa_44::{
    MLDSA44Signature,
    generate_key_pair,
    sign,
    verify,
};
use lib_q_sca_test::dudect::timing_passes_loose;

#[test]
fn hardened_dudect_smoke_verify() {
    let kp = generate_key_pair([0x42u8; KEY_GENERATION_RANDOMNESS_SIZE]);
    let message = b"libq-hardened-ml-dsa-smoke";
    let sig = sign(
        &kp.signing_key,
        message,
        b"",
        [0x11u8; SIGNING_RANDOMNESS_SIZE],
    )
    .expect("sign");

    let mut valid = Vec::with_capacity(200);
    let mut invalid = Vec::with_capacity(200);
    for i in 0..100u8 {
        let start = std::time::Instant::now();
        let _ = verify(&kp.verification_key, message, b"", &sig);
        valid.push(start.elapsed().as_secs_f64());

        let mut bad = *sig.as_ref();
        bad[0] ^= i.wrapping_add(1);
        let bad_sig = MLDSA44Signature::new(bad);
        let start = std::time::Instant::now();
        let _ = verify(&kp.verification_key, message, b"", &bad_sig);
        invalid.push(start.elapsed().as_secs_f64());
    }
    let mut samples = valid;
    samples.extend(invalid);
    assert!(
        timing_passes_loose(6.0, &samples),
        "hardened ML-DSA verify timing smoke failed (loose gate)"
    );
}
