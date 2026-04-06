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
const TIMING_ATTEMPTS: usize = 3;
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

fn timing_spread_is_within_limit(timings: &[Duration]) -> bool {
    let min_timing = timings.iter().copied().min().expect("at least one timing");
    let max_timing = timings.iter().copied().max().expect("at least one timing");
    let min_ns = min_timing.as_nanos();
    let max_ns = max_timing.as_nanos();

    // `max <= min * (1 + MAX_SPREAD_PERCENT/100)`.
    let rhs = min_ns * (100 + MAX_SPREAD_PERCENT);
    let lhs = max_ns * 100;
    lhs <= rhs
}

fn assert_timing_spread_with_retries<F>(label: &str, mut collect_timings: F)
where
    F: FnMut() -> Vec<Duration>,
{
    let mut last_failure: Option<(u128, u128, Vec<u128>)> = None;

    for attempt in 1..=TIMING_ATTEMPTS {
        let timings = collect_timings();
        let min_ns = timings
            .iter()
            .copied()
            .min()
            .expect("at least one timing")
            .as_nanos();
        let max_ns = timings
            .iter()
            .copied()
            .max()
            .expect("at least one timing")
            .as_nanos();
        let timing_ns = timings
            .iter()
            .map(|duration| duration.as_nanos())
            .collect::<Vec<_>>();
        let ratio = max_ns as f64 / min_ns as f64;

        eprintln!(
            "{} timing attempt {}/{}: timings={:?} min={}ns max={}ns ratio={:.3}",
            label, attempt, TIMING_ATTEMPTS, timing_ns, min_ns, max_ns, ratio
        );

        if timing_spread_is_within_limit(&timings) {
            return;
        }

        last_failure = Some((min_ns, max_ns, timing_ns));
    }

    let (min_ns, max_ns, timing_ns) = last_failure.expect("at least one attempt");
    panic!(
        "{} timing spread too high after {} attempts: timings={:?} min={}ns max={}ns allowed_ratio<=1.{}",
        label, TIMING_ATTEMPTS, timing_ns, min_ns, max_ns, MAX_SPREAD_PERCENT
    );
}

/// Test that SHA3-224 operations have similar timing for equal-length inputs.
#[test]
fn test_sha3_224_constant_time() {
    let test_inputs = build_fixed_length_inputs(128);
    assert_timing_spread_with_retries("SHA3-224", || {
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
        timings
    });
}

/// Test that SHA3-256 operations have similar timing for equal-length inputs.
#[test]
fn test_sha3_256_constant_time() {
    let test_inputs = build_fixed_length_inputs(128);
    assert_timing_spread_with_retries("SHA3-256", || {
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
        timings
    });
}

/// Test that Keccak operations have similar timing for equal-length inputs.
#[test]
fn test_keccak_256_constant_time() {
    let test_inputs = build_fixed_length_inputs(128);
    assert_timing_spread_with_retries("Keccak256", || {
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
        timings
    });
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
