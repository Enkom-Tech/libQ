//! Performance tests for SHA3 family algorithms
//!
//! These tests verify performance characteristics and detect regressions.

use digest::Digest;
use lib_q_sha3::{Keccak256, Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use std::time::{Duration, Instant};

/// Performance baseline for SHA3-256 operations
const BASELINE_SHA3_256_NS: u64 = 100000; // 100 microseconds baseline (more realistic)

/// Test SHA3-256 performance baseline
#[test]
fn test_sha3_256_performance() {
    let test_input = b"test input for performance analysis";
    const ITERATIONS: usize = 10000;

    // Warm up
    for _ in 0..1000 {
        let mut hasher = Sha3_256::new();
        hasher.update(test_input);
        let _result = hasher.finalize();
        std::hint::black_box(_result);
    }

    // Measure performance
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let mut hasher = Sha3_256::new();
        hasher.update(test_input);
        let _result = hasher.finalize();
        std::hint::black_box(_result);
    }
    let total_time = start.elapsed();

    let avg_time_ns = total_time.as_nanos() / ITERATIONS as u128;

    // Performance should be within reasonable bounds
    assert!(
        avg_time_ns < BASELINE_SHA3_256_NS as u128,
        "SHA3-256 too slow: {} ns per operation (baseline: {} ns)",
        avg_time_ns,
        BASELINE_SHA3_256_NS
    );
}

/// Test SHA3-224 performance
#[test]
fn test_sha3_224_performance() {
    let test_input = b"test input for SHA3-224 performance analysis";
    const ITERATIONS: usize = 10000;

    // Warm up
    for _ in 0..1000 {
        let mut hasher = Sha3_224::new();
        hasher.update(test_input);
        let _result = hasher.finalize();
        std::hint::black_box(_result);
    }

    // Measure performance
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let mut hasher = Sha3_224::new();
        hasher.update(test_input);
        let _result = hasher.finalize();
        std::hint::black_box(_result);
    }
    let total_time = start.elapsed();

    let avg_time_ns = total_time.as_nanos() / ITERATIONS as u128;

    // SHA3-224 should be similar to SHA3-256 (same number of rounds)
    assert!(
        avg_time_ns < BASELINE_SHA3_256_NS as u128,
        "SHA3-224 too slow: {} ns per operation (baseline: {} ns)",
        avg_time_ns,
        BASELINE_SHA3_256_NS
    );
}

/// Test SHA3-384 performance
#[test]
fn test_sha3_384_performance() {
    let test_input = b"test input for SHA3-384 performance analysis";
    const ITERATIONS: usize = 10000;

    // Warm up
    for _ in 0..1000 {
        let mut hasher = Sha3_384::new();
        hasher.update(test_input);
        let _result = hasher.finalize();
        std::hint::black_box(_result);
    }

    // Measure performance
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let mut hasher = Sha3_384::new();
        hasher.update(test_input);
        let _result = hasher.finalize();
        std::hint::black_box(_result);
    }
    let total_time = start.elapsed();

    let avg_time_ns = total_time.as_nanos() / ITERATIONS as u128;

    // SHA3-384 should be slower than SHA3-256 due to more rounds
    assert!(
        avg_time_ns < (BASELINE_SHA3_256_NS * 2) as u128,
        "SHA3-384 too slow: {} ns per operation (baseline: {} ns)",
        avg_time_ns,
        BASELINE_SHA3_256_NS * 2
    );
}

/// Test SHA3-512 performance
#[test]
fn test_sha3_512_performance() {
    let test_input = b"test input for SHA3-512 performance analysis";
    const ITERATIONS: usize = 10000;

    // Warm up
    for _ in 0..1000 {
        let mut hasher = Sha3_512::new();
        hasher.update(test_input);
        let _result = hasher.finalize();
        std::hint::black_box(_result);
    }

    // Measure performance
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let mut hasher = Sha3_512::new();
        hasher.update(test_input);
        let _result = hasher.finalize();
        std::hint::black_box(_result);
    }
    let total_time = start.elapsed();

    let avg_time_ns = total_time.as_nanos() / ITERATIONS as u128;

    // SHA3-512 should be slower than SHA3-256 due to more rounds
    assert!(
        avg_time_ns < (BASELINE_SHA3_256_NS * 3) as u128,
        "SHA3-512 too slow: {} ns per operation (baseline: {} ns)",
        avg_time_ns,
        BASELINE_SHA3_256_NS * 3
    );
}

/// Test Keccak256 performance
#[test]
fn test_keccak256_performance() {
    let test_input = b"test input for Keccak256 performance analysis";
    const ITERATIONS: usize = 10000;

    // Warm up
    for _ in 0..1000 {
        let mut hasher = Keccak256::new();
        hasher.update(test_input);
        let _result = hasher.finalize();
        std::hint::black_box(_result);
    }

    // Measure performance
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let mut hasher = Keccak256::new();
        hasher.update(test_input);
        let _result = hasher.finalize();
        std::hint::black_box(_result);
    }
    let total_time = start.elapsed();

    let avg_time_ns = total_time.as_nanos() / ITERATIONS as u128;

    // Keccak256 should be similar to SHA3-256
    assert!(
        avg_time_ns < BASELINE_SHA3_256_NS as u128,
        "Keccak256 too slow: {} ns per operation (baseline: {} ns)",
        avg_time_ns,
        BASELINE_SHA3_256_NS
    );
}

/// Test performance scaling with input size
#[test]
fn test_performance_scaling() {
    const ITERATIONS: usize = 1000;

    let small_input = b"small input";
    let medium_input = &[0x42u8; 1000];
    let large_input = &[0x42u8; 10000];

    // Measure small input
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let mut hasher = Sha3_256::new();
        hasher.update(small_input);
        let _result = hasher.finalize();
        std::hint::black_box(_result);
    }
    let small_time = start.elapsed();

    // Measure medium input
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let mut hasher = Sha3_256::new();
        hasher.update(medium_input);
        let _result = hasher.finalize();
        std::hint::black_box(_result);
    }
    let medium_time = start.elapsed();

    // Measure large input
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let mut hasher = Sha3_256::new();
        hasher.update(large_input);
        let _result = hasher.finalize();
        std::hint::black_box(_result);
    }
    let large_time = start.elapsed();

    // Verify that performance scales reasonably with input size
    let small_to_medium_ratio = medium_time.as_nanos() as f64 / small_time.as_nanos() as f64;
    let medium_to_large_ratio = large_time.as_nanos() as f64 / medium_time.as_nanos() as f64;

    // Medium input should be slower than small input
    assert!(
        small_to_medium_ratio > 1.5,
        "Medium input should be slower than small input, got ratio: {}",
        small_to_medium_ratio
    );

    // Large input should be slower than medium input
    assert!(
        medium_to_large_ratio > 1.5,
        "Large input should be slower than medium input, got ratio: {}",
        medium_to_large_ratio
    );
}

/// Test performance consistency across multiple runs
#[test]
fn test_performance_consistency() {
    let test_input = b"test input for performance consistency";
    const ITERATIONS: usize = 1000;
    const RUNS: usize = 5;

    let mut run_times = Vec::new();

    for _run in 0..RUNS {
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let mut hasher = Sha3_256::new();
            hasher.update(test_input);
            let _result = hasher.finalize();
            std::hint::black_box(_result);
        }
        let total_time = start.elapsed();
        run_times.push(total_time);
    }

    // Calculate average and standard deviation
    let avg_time = run_times.iter().sum::<Duration>() / run_times.len() as u32;
    let variance = run_times
        .iter()
        .map(|&t| {
            let diff = if t > avg_time {
                t - avg_time
            } else {
                avg_time - t
            };
            diff.as_nanos() as f64 * diff.as_nanos() as f64
        })
        .sum::<f64>()
        / run_times.len() as f64;
    let std_dev = variance.sqrt();

    // Coefficient of variation should be less than 30%
    let cv = std_dev / avg_time.as_nanos() as f64;
    assert!(
        cv < 0.3,
        "Performance too inconsistent: coefficient of variation {} (expected < 0.3)",
        cv
    );
}

/// Test that different hash algorithms have expected performance relationships
#[test]
fn test_algorithm_performance_relationships() {
    let test_input = b"test input for algorithm performance relationships";
    const ITERATIONS: usize = 1000;

    // Measure SHA3-256
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let mut hasher = Sha3_256::new();
        hasher.update(test_input);
        let _result = hasher.finalize();
        std::hint::black_box(_result);
    }
    let sha3_256_time = start.elapsed();

    // Measure SHA3-512
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let mut hasher = Sha3_512::new();
        hasher.update(test_input);
        let _result = hasher.finalize();
        std::hint::black_box(_result);
    }
    let sha3_512_time = start.elapsed();

    // Measure Keccak256
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let mut hasher = Keccak256::new();
        hasher.update(test_input);
        let _result = hasher.finalize();
        std::hint::black_box(_result);
    }
    let keccak256_time = start.elapsed();

    // SHA3-512 should be similar to SHA3-256
    let ratio_512_to_256 = sha3_512_time.as_nanos() as f64 / sha3_256_time.as_nanos() as f64;
    assert!(
        ratio_512_to_256 > 0.5 && ratio_512_to_256 < 3.0, // More lenient requirement
        "SHA3-512 should have similar performance to SHA3-256, got ratio: {}",
        ratio_512_to_256
    );

    // Keccak256 should be similar to SHA3-256
    let ratio_keccak_to_256 = keccak256_time.as_nanos() as f64 / sha3_256_time.as_nanos() as f64;
    assert!(
        ratio_keccak_to_256 > 0.5 && ratio_keccak_to_256 < 2.0,
        "Keccak256 should have similar performance to SHA3-256, got ratio: {}",
        ratio_keccak_to_256
    );
}
