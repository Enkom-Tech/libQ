#![cfg(all(
    feature = "hardened",
    feature = "mayo2",
    feature = "dudect-smoke-tests"
))]

//! Wall-clock timing-variance smoke for MAYO_2 signing: two fixed keys with
//! different secret material signing the same message must not show a large
//! timing separation. Loose CI gate, not instrumented dudect.

use lib_q_mayo::mayo_2::{
    SIGNING_RANDOMNESS_SIZE,
    generate_key_pair,
    sign,
};
use lib_q_sca_test::dudect::timing_passes_loose;

const SMOKE_ITERS: usize = 50;
const MAX_ATTEMPTS: usize = 5;
/// Loose CI gate: wall-clock smoke only, not instrumented dudect.
const SMOKE_THRESHOLD: f64 = 8.0;

fn collect_sign_timing_samples() -> Vec<f64> {
    let kp_a = generate_key_pair([0x42u8; 24]);
    let kp_b = generate_key_pair([0xA5u8; 24]);
    let message = b"libq-hardened-mayo-smoke";

    let mut samples = Vec::with_capacity(SMOKE_ITERS * 2);
    for i in 0..SMOKE_ITERS {
        let mut randomness = [0u8; SIGNING_RANDOMNESS_SIZE];
        randomness[0] = i as u8;

        let start = std::time::Instant::now();
        let r = sign(&kp_a.signing_key, message, randomness);
        let _ = std::hint::black_box(r);
        samples.push(start.elapsed().as_secs_f64());

        let start = std::time::Instant::now();
        let r = sign(&kp_b.signing_key, message, randomness);
        let _ = std::hint::black_box(r);
        samples.push(start.elapsed().as_secs_f64());
    }
    samples
}

#[test]
fn hardened_dudect_smoke_sign() {
    for attempt in 1..=MAX_ATTEMPTS {
        let samples = collect_sign_timing_samples();
        if timing_passes_loose(SMOKE_THRESHOLD, &samples) {
            return;
        }
        eprintln!(
            "hardened MAYO sign timing smoke attempt {attempt}/{MAX_ATTEMPTS} exceeded loose gate"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    panic!(
        "hardened MAYO sign timing smoke failed after {MAX_ATTEMPTS} attempts (loose gate {SMOKE_THRESHOLD})"
    );
}
