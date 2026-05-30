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
use lib_q_sca_test::sample_wall_times;

const SAMPLES: usize = 100;
const WARMUP: usize = 32;
/// Loose CI gate: wall-clock smoke only, not instrumented dudect.
const SMOKE_THRESHOLD: f64 = 6.0;

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

    for i in 0..WARMUP {
        let _ = verify(&kp.verification_key, message, b"", &sig);
        let mut bad = *sig.as_ref();
        bad[0] ^= i as u8;
        let _ = verify(
            &kp.verification_key,
            message,
            b"",
            &MLDSA44Signature::new(bad),
        );
    }

    let valid = sample_wall_times(
        || {
            let r = verify(&kp.verification_key, message, b"", &sig);
            std::hint::black_box(r);
        },
        SAMPLES,
    );

    let mut idx = 0u8;
    let invalid = sample_wall_times(
        || {
            idx = idx.wrapping_add(1);
            let mut bad = *sig.as_ref();
            bad[0] ^= idx;
            let bad_sig = MLDSA44Signature::new(bad);
            let r = verify(&kp.verification_key, message, b"", &bad_sig);
            std::hint::black_box(r);
        },
        SAMPLES,
    );

    let mut samples = valid;
    samples.extend(invalid);
    assert!(
        timing_passes_loose(SMOKE_THRESHOLD, &samples),
        "hardened ML-DSA verify timing smoke failed (loose gate)"
    );
}
