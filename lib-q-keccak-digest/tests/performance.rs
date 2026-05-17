//! Performance tests for Keccak fixed digests (moved from `lib-q-sha3`).

use std::time::{
    Duration,
    Instant,
};

use digest::Digest;
use lib_q_keccak_digest::Keccak256;
use lib_q_sha3::Sha3_256;

#[cfg(not(tarpaulin))]
const BASELINE_SHA3_256_NS: u64 = 220_000;

/// Test Keccak256 performance baseline
#[test]
#[cfg(not(tarpaulin))]
fn test_keccak256_performance() {
    let test_input = b"test input for Keccak256 performance analysis";
    const ITERATIONS: usize = 10000;

    for _ in 0..1000 {
        let mut hasher = Keccak256::new();
        hasher.update(test_input);
        let _result = hasher.finalize();
        std::hint::black_box(_result);
    }

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let mut hasher = Keccak256::new();
        hasher.update(test_input);
        let _result = hasher.finalize();
        std::hint::black_box(_result);
    }
    let total_time = start.elapsed();

    let avg_time_ns = total_time.as_nanos() / ITERATIONS as u128;

    assert!(
        avg_time_ns < BASELINE_SHA3_256_NS as u128,
        "Keccak256 too slow: {} ns per operation (baseline: {} ns)",
        avg_time_ns,
        BASELINE_SHA3_256_NS
    );
}

/// Test that Keccak256 and SHA3-256 have expected performance relationship
#[test]
fn test_algorithm_performance_relationships() {
    let test_input = b"test input for algorithm performance relationships";
    const ITERATIONS: usize = 10_000;
    const WARMUP: usize = 500;

    for _ in 0..WARMUP {
        let mut h = Sha3_256::new();
        h.update(test_input);
        std::hint::black_box(h.finalize());
        let mut h = Keccak256::new();
        h.update(test_input);
        std::hint::black_box(h.finalize());
    }

    let mut sha3_256_time = Duration::ZERO;
    let mut keccak256_time = Duration::ZERO;

    for _ in 0..ITERATIONS {
        let start = Instant::now();
        let mut hasher = Sha3_256::new();
        hasher.update(test_input);
        let _result = hasher.finalize();
        std::hint::black_box(_result);
        sha3_256_time += start.elapsed();

        let start = Instant::now();
        let mut hasher = Keccak256::new();
        hasher.update(test_input);
        let _result = hasher.finalize();
        std::hint::black_box(_result);
        keccak256_time += start.elapsed();
    }

    let ratio_keccak_to_256 = keccak256_time.as_nanos() as f64 / sha3_256_time.as_nanos() as f64;
    assert!(
        ratio_keccak_to_256 > 0.5 && ratio_keccak_to_256 < 2.0,
        "Keccak256 should have similar performance to SHA3-256, got ratio: {}",
        ratio_keccak_to_256
    );
}
