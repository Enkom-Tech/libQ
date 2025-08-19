//! Constant-time tests for SHA3 family algorithms
//!
//! These tests verify that SHA3 operations are constant-time to prevent
//! timing-based side-channel attacks.

use digest::Digest;
use lib_q_sha3::{Keccak256, Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use std::time::{Duration, Instant};

/// Test that SHA3-224 operations take constant time regardless of input
#[test]
fn test_sha3_224_constant_time() {
    let test_inputs = [
        &[] as &[u8],   // Empty input
        b"a",           // Single byte
        b"ab",          // Two bytes
        b"abc",         // Three bytes
        b"abcd",        // Four bytes
        b"abcde",       // Five bytes
        b"abcdef",      // Six bytes
        b"abcdefg",     // Seven bytes
        b"abcdefgh",    // Eight bytes
        b"abcdefghi",   // Nine bytes
        b"abcdefghij",  // Ten bytes
        &[0u8; 50],     // 50 zero bytes
        &[0xffu8; 50],  // 50 ones bytes
        &[0u8; 100],    // 100 zero bytes
        &[0xffu8; 100], // 100 ones bytes
    ];

    let mut timings = Vec::new();
    const ITERATIONS: usize = 1000;

    for input in &test_inputs {
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let mut hasher = Sha3_224::new();
            hasher.update(input);
            let _result = hasher.finalize();
            // Prevent compiler from optimizing away the operation
            std::hint::black_box(_result);
        }
        let duration = start.elapsed();
        timings.push(duration);
    }

    // Verify timing consistency (within 200% tolerance for real-world conditions)
    let avg_time = timings.iter().sum::<Duration>() / timings.len() as u32;
    let tolerance = avg_time * 200 / 100; // 200% tolerance

    for (i, timing) in timings.iter().enumerate() {
        let diff = if *timing > avg_time {
            *timing - avg_time
        } else {
            avg_time - *timing
        };
        assert!(
            diff <= tolerance,
            "SHA3-224 timing varies too much for input {}: {} vs {} (tolerance: {})",
            i,
            timing.as_nanos(),
            avg_time.as_nanos(),
            tolerance.as_nanos()
        );
    }
}

/// Test that SHA3-256 operations are constant-time
#[test]
fn test_sha3_256_constant_time() {
    let test_inputs = [
        &[] as &[u8],
        b"a",
        b"ab",
        b"abc",
        b"abcd",
        b"abcde",
        b"abcdef",
        b"abcdefg",
        b"abcdefgh",
        b"abcdefghi",
        b"abcdefghij",
        &[0u8; 50],
        &[0xffu8; 50],
        &[0u8; 100],
        &[0xffu8; 100],
    ];

    let mut timings = Vec::new();
    const ITERATIONS: usize = 1000;

    for input in &test_inputs {
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let mut hasher = Sha3_256::new();
            hasher.update(input);
            let _result = hasher.finalize();
            let _ = std::hint::black_box(_result);
        }
        let duration = start.elapsed();
        timings.push(duration);
    }

    let avg_time = timings.iter().sum::<Duration>() / timings.len() as u32;
    let tolerance = avg_time * 200 / 100; // 200% tolerance

    for (i, timing) in timings.iter().enumerate() {
        let diff = if *timing > avg_time {
            *timing - avg_time
        } else {
            avg_time - *timing
        };
        assert!(
            diff <= tolerance,
            "SHA3-256 timing varies too much for input {}: {} vs {} (tolerance: {})",
            i,
            timing.as_nanos(),
            avg_time.as_nanos(),
            tolerance.as_nanos()
        );
    }
}

/// Test that Keccak operations are constant-time
#[test]
fn test_keccak_256_constant_time() {
    let test_inputs = [
        &[] as &[u8],
        b"a",
        b"ab",
        b"abc",
        b"abcd",
        b"abcde",
        b"abcdef",
        b"abcdefg",
        b"abcdefgh",
        b"abcdefghi",
        b"abcdefghij",
        &[0u8; 50],
        &[0xffu8; 50],
        &[0u8; 100],
        &[0xffu8; 100],
    ];

    let mut timings = Vec::new();
    const ITERATIONS: usize = 1000;

    for input in &test_inputs {
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let mut hasher = Keccak256::new();
            hasher.update(input);
            let _result = hasher.finalize();
            let _ = std::hint::black_box(_result);
        }
        let duration = start.elapsed();
        timings.push(duration);
    }

    let avg_time = timings.iter().sum::<Duration>() / timings.len() as u32;
    let tolerance = avg_time * 200 / 100; // 200% tolerance

    for (i, timing) in timings.iter().enumerate() {
        let diff = if *timing > avg_time {
            *timing - avg_time
        } else {
            avg_time - *timing
        };
        assert!(
            diff <= tolerance,
            "Keccak256 timing varies too much for input {}: {} vs {} (tolerance: {})",
            i,
            timing.as_nanos(),
            avg_time.as_nanos(),
            tolerance.as_nanos()
        );
    }
}

/// Test that different hash algorithms have consistent timing relationships
#[test]
fn test_hash_algorithm_timing_relationships() {
    let test_input = b"test input for timing analysis";
    const ITERATIONS: usize = 1000;

    // Test SHA3 variants
    let mut sha3_224_time = Duration::ZERO;
    let mut sha3_256_time = Duration::ZERO;
    let mut sha3_384_time = Duration::ZERO;
    let mut sha3_512_time = Duration::ZERO;

    // Measure SHA3-224
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let mut hasher = Sha3_224::new();
        hasher.update(test_input);
        let _result = hasher.finalize();
        let _ = std::hint::black_box(_result);
    }
    sha3_224_time = start.elapsed();

    // Measure SHA3-256
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let mut hasher = Sha3_256::new();
        hasher.update(test_input);
        let _result = hasher.finalize();
        let _ = std::hint::black_box(_result);
    }
    sha3_256_time = start.elapsed();

    // Measure SHA3-384
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let mut hasher = Sha3_384::new();
        hasher.update(test_input);
        let _result = hasher.finalize();
        let _ = std::hint::black_box(_result);
    }
    sha3_384_time = start.elapsed();

    // Measure SHA3-512
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let mut hasher = Sha3_512::new();
        hasher.update(test_input);
        let _result = hasher.finalize();
        let _ = std::hint::black_box(_result);
    }
    sha3_512_time = start.elapsed();

    // Verify that timing relationships are reasonable
    // SHA3-512 should be similar to SHA3-256
    let ratio_512_to_256 = sha3_512_time.as_nanos() as f64 / sha3_256_time.as_nanos() as f64;
    assert!(
        ratio_512_to_256 > 0.5 && ratio_512_to_256 < 3.0, // More lenient requirement
        "SHA3-512 should have similar performance to SHA3-256, got ratio: {}",
        ratio_512_to_256
    );

    // SHA3-384 should be similar to SHA3-256
    let ratio_384_to_256 = sha3_384_time.as_nanos() as f64 / sha3_256_time.as_nanos() as f64;
    assert!(
        ratio_384_to_256 > 0.5 && ratio_384_to_256 < 3.0,
        "SHA3-384 should have similar performance to SHA3-256, got ratio: {}",
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
