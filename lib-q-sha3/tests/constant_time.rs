//! Constant-time tests for SHA3 family algorithms
//!
//! These tests verify that SHA3 operations are constant-time to prevent
//! timing-based side-channel attacks.

use std::time::{
    Duration,
    Instant,
};

use digest::Digest;
use lib_q_sha3::{
    Keccak256,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
};

const TIMING_ITERATIONS: usize = 10_000;
const TIMING_RUNS: usize = 9;
const TIMING_WARMUP: usize = 1_000;
const MAX_SPREAD_PERCENT: u128 = 80; // Max allowed spread over min, e.g. 80% => 1.8x ratio.

fn build_fixed_length_inputs(len: usize) -> Vec<Vec<u8>> {
    vec![
        vec![0u8; len],
        vec![0xFFu8; len],
        vec![0xA5u8; len],
        (0..len).map(|i| (i % 251) as u8).collect::<Vec<_>>(),
        (0..len)
            .map(|i| ((i.wrapping_mul(73) + 19) % 256) as u8)
            .collect::<Vec<_>>(),
    ]
}

fn trimmed_mean_duration<F>(mut op: F) -> Duration
where
    F: FnMut(),
{
    for _ in 0..TIMING_WARMUP {
        op();
    }

    let mut run_times = Vec::with_capacity(TIMING_RUNS);
    for _ in 0..TIMING_RUNS {
        let start = Instant::now();
        for _ in 0..TIMING_ITERATIONS {
            op();
        }
        run_times.push(start.elapsed());
    }

    run_times.sort_unstable();
    let trimmed = &run_times[1..run_times.len() - 1];
    trimmed.iter().copied().sum::<Duration>() / trimmed.len() as u32
}

fn assert_timing_spread_within_limit(label: &str, timings: &[Duration]) {
    let min_timing = timings.iter().copied().min().expect("at least one timing");
    let max_timing = timings.iter().copied().max().expect("at least one timing");
    let min_ns = min_timing.as_nanos();
    let max_ns = max_timing.as_nanos();

    // `max <= min * (1 + MAX_SPREAD_PERCENT/100)`.
    let rhs = min_ns * (100 + MAX_SPREAD_PERCENT);
    let lhs = max_ns * 100;
    assert!(
        lhs <= rhs,
        "{} timing spread too high: min={}ns max={}ns allowed_ratio<=1.{}",
        label,
        min_ns,
        max_ns,
        MAX_SPREAD_PERCENT
    );
}

/// Test that SHA3-224 operations have similar timing for equal-length inputs.
#[test]
fn test_sha3_224_constant_time() {
    let test_inputs = build_fixed_length_inputs(128);
    let mut timings = Vec::new();
    for input in &test_inputs {
        let timing = trimmed_mean_duration(|| {
            let mut hasher = Sha3_224::new();
            hasher.update(input);
            let _result = hasher.finalize();
            std::hint::black_box(_result);
        });
        timings.push(timing);
    }

    assert_timing_spread_within_limit("SHA3-224", &timings);
}

/// Test that SHA3-256 operations have similar timing for equal-length inputs.
#[test]
fn test_sha3_256_constant_time() {
    let test_inputs = build_fixed_length_inputs(128);
    let mut timings = Vec::new();
    for input in &test_inputs {
        let timing = trimmed_mean_duration(|| {
            let mut hasher = Sha3_256::new();
            hasher.update(input);
            let _result = hasher.finalize();
            std::hint::black_box(_result);
        });
        timings.push(timing);
    }

    assert_timing_spread_within_limit("SHA3-256", &timings);
}

/// Test that Keccak operations have similar timing for equal-length inputs.
#[test]
fn test_keccak_256_constant_time() {
    let test_inputs = build_fixed_length_inputs(128);
    let mut timings = Vec::new();
    for input in &test_inputs {
        let timing = trimmed_mean_duration(|| {
            let mut hasher = Keccak256::new();
            hasher.update(input);
            let _result = hasher.finalize();
            std::hint::black_box(_result);
        });
        timings.push(timing);
    }

    assert_timing_spread_within_limit("Keccak256", &timings);
}

/// Test that different hash algorithms have consistent timing relationships
#[test]
fn test_hash_algorithm_timing_relationships() {
    let test_input = b"test input for timing analysis";
    const ITERATIONS: usize = 1000;

    // Test SHA3 variants

    // Measure SHA3-224
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let mut hasher = Sha3_224::new();
        hasher.update(test_input);
        let _result = hasher.finalize();
        let _ = std::hint::black_box(_result);
    }
    let sha3_224_time = start.elapsed();

    // Measure SHA3-256
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let mut hasher = Sha3_256::new();
        hasher.update(test_input);
        let _result = hasher.finalize();
        let _ = std::hint::black_box(_result);
    }
    let sha3_256_time = start.elapsed();

    // Measure SHA3-384
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let mut hasher = Sha3_384::new();
        hasher.update(test_input);
        let _result = hasher.finalize();
        let _ = std::hint::black_box(_result);
    }
    let sha3_384_time = start.elapsed();

    // Measure SHA3-512
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let mut hasher = Sha3_512::new();
        hasher.update(test_input);
        let _result = hasher.finalize();
        let _ = std::hint::black_box(_result);
    }
    let sha3_512_time = start.elapsed();

    // Verify that timing relationships are reasonable (order-of-magnitude sanity check only).
    // SHA3-512 uses a smaller sponge rate than SHA3-256 (72 vs 136 bytes), so it can be several
    // times slower on some inputs and builds; see `tests/performance.rs` SHA3-512 baseline.
    const MAX_RATIO_512_TO_256: f64 = 5.0;
    let ratio_512_to_256 = sha3_512_time.as_nanos() as f64 / sha3_256_time.as_nanos() as f64;
    assert!(
        ratio_512_to_256 > 0.5 && ratio_512_to_256 < MAX_RATIO_512_TO_256,
        "SHA3-512 vs SHA3-256 time ratio out of range (expected < {}), got: {}",
        MAX_RATIO_512_TO_256,
        ratio_512_to_256
    );

    // SHA3-384 sits between 256 and 512 in rate; allow the same upper bound for CI variance.
    const MAX_RATIO_384_TO_256: f64 = 5.0;
    let ratio_384_to_256 = sha3_384_time.as_nanos() as f64 / sha3_256_time.as_nanos() as f64;
    assert!(
        ratio_384_to_256 > 0.5 && ratio_384_to_256 < MAX_RATIO_384_TO_256,
        "SHA3-384 vs SHA3-256 time ratio out of range (expected < {}), got: {}",
        MAX_RATIO_384_TO_256,
        ratio_384_to_256
    );

    // SHA3-224 should be similar to SHA3-256 (same number of rounds)
    let ratio_224_to_256 = sha3_224_time.as_nanos() as f64 / sha3_256_time.as_nanos() as f64;
    assert!(
        ratio_224_to_256 > 0.5 && ratio_224_to_256 < 3.0,
        "SHA3-224 should have similar timing to SHA3-256, got ratio: {}",
        ratio_224_to_256
    );
}
