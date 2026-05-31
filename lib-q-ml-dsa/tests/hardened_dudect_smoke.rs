#![cfg(all(
    feature = "hardened",
    feature = "mldsa44",
    feature = "dudect-smoke-tests"
))]

use lib_q_ml_dsa::constants::{
    KEY_GENERATION_RANDOMNESS_SIZE,
    SIGNING_RANDOMNESS_SIZE,
};
use lib_q_ml_dsa::ml_dsa_44::{
    MLDSA44Signature,
    MLDSA44VerificationKey,
    generate_key_pair,
    sign,
    verify,
};
use lib_q_sca_test::dudect::timing_passes_loose;

const SMOKE_ITERS: u8 = 100;
const MAX_ATTEMPTS: usize = 5;
/// Loose CI gate: wall-clock smoke only, not instrumented dudect.
const SMOKE_THRESHOLD: f64 = 8.0;

fn collect_verify_timing_samples(
    vk: &MLDSA44VerificationKey,
    message: &[u8],
    sig: &MLDSA44Signature,
) -> Vec<f64> {
    let mut samples = Vec::with_capacity(SMOKE_ITERS as usize * 2);
    for i in 0..SMOKE_ITERS {
        let start = std::time::Instant::now();
        let r = verify(vk, message, b"", sig);
        let _ = std::hint::black_box(r);
        samples.push(start.elapsed().as_secs_f64());

        let mut bad = *sig.as_ref();
        bad[0] ^= i.wrapping_add(1);
        let bad_sig = MLDSA44Signature::new(bad);
        let start = std::time::Instant::now();
        let r = verify(vk, message, b"", &bad_sig);
        let _ = std::hint::black_box(r);
        samples.push(start.elapsed().as_secs_f64());
    }
    samples
}

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

    for attempt in 1..=MAX_ATTEMPTS {
        let samples = collect_verify_timing_samples(&kp.verification_key, message, &sig);
        if timing_passes_loose(SMOKE_THRESHOLD, &samples) {
            return;
        }
        eprintln!(
            "hardened ML-DSA verify timing smoke attempt {attempt}/{MAX_ATTEMPTS} exceeded loose gate"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    panic!(
        "hardened ML-DSA verify timing smoke failed after {MAX_ATTEMPTS} attempts (loose gate {SMOKE_THRESHOLD})"
    );
}
