//! Timing analysis tests for libQ
//!
//! These tests verify that cryptographic operations don't leak
//! information through timing side-channels.

use libq::*;
use std::time::{Duration, Instant};

/// Test that hash operations have consistent timing
#[test]
fn test_hash_timing_consistency() {
    let data1 = vec![0u8; 64];
    let data2 = vec![1u8; 64];
    let data3 = vec![0u8; 128];

    let hash_impl = HashAlgorithm::Shake256.create_hash();

    // Measure timing for different inputs
    let start1 = Instant::now();
    let _hash1 = hash_impl.hash(&data1).unwrap();
    let time1 = start1.elapsed();

    let start2 = Instant::now();
    let _hash2 = hash_impl.hash(&data2).unwrap();
    let time2 = start2.elapsed();

    let start3 = Instant::now();
    let _hash3 = hash_impl.hash(&data3).unwrap();
    let time3 = start3.elapsed();

    // Ensure the test doesn't take too long (timeout protection)
    let total_time = time1 + time2 + time3;
    assert!(
        total_time.as_millis() < 1000,
        "Hash timing test took too long: {total_time:?}"
    );

    // Timing should be reasonably consistent (within 10x)
    let max_time = time1.max(time2).max(time3);
    let min_time = time1.min(time2).min(time3);

    assert!(
        max_time.as_nanos() <= min_time.as_nanos() * 10,
        "Timing variation too large: min={min_time:?}, max={max_time:?}"
    );
}

/// Test that key comparison operations have consistent timing
#[test]
fn test_key_comparison_timing() {
    let key_data1 = utils::random_bytes(32).unwrap();
    let key_data2 = utils::random_bytes(32).unwrap();
    let key_data3 = key_data1.clone();

    let key1 = AeadKey::new(key_data1);
    let key2 = AeadKey::new(key_data2);
    let key3 = AeadKey::new(key_data3);

    // Measure timing for different comparisons
    let start1 = Instant::now();
    let _result1 = key1 == key2; // Different keys
    let time1 = start1.elapsed();

    let start2 = Instant::now();
    let _result2 = key1 == key3; // Same keys
    let time2 = start2.elapsed();

    // Timing should be consistent regardless of result
    let max_time = time1.max(time2);
    let min_time = time1.min(time2);

    assert!(
        max_time.as_nanos() <= min_time.as_nanos() * 5,
        "Key comparison timing variation too large: min={min_time:?}, max={max_time:?}"
    );
}

/// Test that random generation has consistent timing
#[test]
fn test_random_generation_timing() {
    // Measure timing for different sizes
    let start1 = Instant::now();
    let _bytes1 = utils::random_bytes(32).unwrap();
    let time1 = start1.elapsed();

    let start2 = Instant::now();
    let _bytes2 = utils::random_bytes(64).unwrap();
    let time2 = start2.elapsed();

    let start3 = Instant::now();
    let _bytes3 = utils::random_bytes(128).unwrap();
    let time3 = start3.elapsed();

    // Random generation can have significant timing variations due to entropy collection
    // We use a much more lenient threshold (100x) for random operations
    let max_time = time1.max(time2).max(time3);
    let min_time = time1.min(time2).min(time3);

    // Ensure the test doesn't take too long (timeout protection)
    let total_time = time1 + time2 + time3;
    assert!(
        total_time.as_millis() < 1000,
        "Random generation test took too long: {total_time:?}"
    );

    // Check that timing scales reasonably (not exponentially)
    assert!(
        max_time.as_nanos() <= min_time.as_nanos() * 100,
        "Random generation timing variation too large: min={min_time:?}, max={max_time:?}"
    );

    // Verify that larger sizes generally take more time (but not always due to entropy)
    if time3.as_nanos() > 0 && time1.as_nanos() > 0 {
        let ratio = time3.as_nanos() as f64 / time1.as_nanos() as f64;
        // Allow some variation but ensure it's not completely random
        assert!(
            ratio > 0.1,
            "Random generation timing seems completely random: ratio={ratio}"
        );
    }
}

/// Test that utility functions have consistent timing
#[test]
fn test_utility_function_timing() {
    let data1 = vec![0u8; 32];
    let data2 = vec![1u8; 32];
    let data3 = vec![0u8; 64];

    // Test constant-time comparison timing
    let start1 = Instant::now();
    let _result1 = utils::constant_time_compare(&data1, &data2); // Different
    let time1 = start1.elapsed();

    let start2 = Instant::now();
    let _result2 = utils::constant_time_compare(&data1, &data1); // Same
    let time2 = start2.elapsed();

    let start3 = Instant::now();
    let _result3 = utils::constant_time_compare(&data1, &data3); // Different size
    let time3 = start3.elapsed();

    // Timing should be consistent
    let max_time = time1.max(time2).max(time3);
    let min_time = time1.min(time2).min(time3);

    assert!(
        max_time.as_nanos() <= min_time.as_nanos() * 20,
        "Constant-time comparison timing variation too large: min={min_time:?}, max={max_time:?}"
    );
}

/// Test that validation operations have consistent timing
#[test]
fn test_validation_timing() {
    let valid_data = vec![0u8; 32];
    let invalid_data = vec![0u8; 31];
    let large_data = vec![0u8; 64];

    // Test validation timing
    let start1 = Instant::now();
    let _result1 = utils::validate_data_size(&valid_data, 32, 32); // Valid
    let time1 = start1.elapsed();

    let start2 = Instant::now();
    let _result2 = utils::validate_data_size(&invalid_data, 32, 32); // Invalid
    let time2 = start2.elapsed();

    let start3 = Instant::now();
    let _result3 = utils::validate_data_size(&large_data, 32, 32); // Invalid size
    let time3 = start3.elapsed();

    // Timing should be consistent regardless of validity
    let max_time = time1.max(time2).max(time3);
    let min_time = time1.min(time2).min(time3);

    assert!(
        max_time.as_nanos() <= min_time.as_nanos() * 50,
        "Validation timing variation too large: min={min_time:?}, max={max_time:?}"
    );
}

/// Test that memory operations have consistent timing
#[test]
fn test_memory_operation_timing() {
    let mut data1 = utils::random_bytes(32).unwrap();
    let mut data2 = utils::random_bytes(64).unwrap();
    let mut data3 = utils::random_bytes(128).unwrap();

    // Test zeroization timing
    let start1 = Instant::now();
    utils::secure_zeroize(&mut data1);
    let time1 = start1.elapsed();

    let start2 = Instant::now();
    utils::secure_zeroize(&mut data2);
    let time2 = start2.elapsed();

    let start3 = Instant::now();
    utils::secure_zeroize(&mut data3);
    let time3 = start3.elapsed();

    // Timing should scale reasonably with size
    let max_time = time1.max(time2).max(time3);
    let min_time = time1.min(time2).min(time3);

    assert!(
        max_time.as_nanos() <= min_time.as_nanos() * 10,
        "Memory operation timing variation too large: min={min_time:?}, max={max_time:?}"
    );
}

/// Test that error handling has consistent timing
#[test]
fn test_error_handling_timing() {
    let valid_key = utils::random_key(32).unwrap();
    let invalid_key = vec![0u8; 31];

    // Test key creation timing (success vs failure)
    let start1 = Instant::now();
    let _result1 = AeadKey::new(valid_key.clone());
    let time1 = start1.elapsed();

    let start2 = Instant::now();
    let _result2 = AeadKey::new(invalid_key.clone());
    let time2 = start2.elapsed();

    // Timing should be consistent regardless of success/failure
    let max_time = time1.max(time2);
    let min_time = time1.min(time2);

    assert!(
        max_time.as_nanos() <= min_time.as_nanos() * 5,
        "Error handling timing variation too large: min={min_time:?}, max={max_time:?}"
    );
}

/// Test that cryptographic primitives have consistent timing
#[test]
fn test_cryptographic_primitive_timing() {
    let data1 = vec![0u8; 64];
    let data2 = vec![1u8; 64];

    let hash_impl = HashAlgorithm::Shake256.create_hash();

    // Test hash timing with different inputs
    let start1 = Instant::now();
    let _hash1 = hash_impl.hash(&data1).unwrap();
    let time1 = start1.elapsed();

    let start2 = Instant::now();
    let _hash2 = hash_impl.hash(&data2).unwrap();
    let time2 = start2.elapsed();

    // Timing should be consistent
    let max_time = time1.max(time2);
    let min_time = time1.min(time2);

    assert!(
        max_time.as_nanos() <= min_time.as_nanos() * 50,
        "Cryptographic primitive timing variation too large: min={min_time:?}, max={max_time:?}"
    );
}

/// Test that operations don't have obvious timing patterns
#[test]
fn test_no_timing_patterns() {
    // Test that operations with different inputs don't have
    // obvious timing patterns that could leak information

    let inputs = vec![
        vec![0u8; 32],
        vec![1u8; 32],
        vec![0u8; 64],
        vec![1u8; 64],
        vec![0u8; 128],
        vec![1u8; 128],
    ];

    let hash_impl = HashAlgorithm::Shake256.create_hash();
    let mut timings = Vec::new();

    for input in inputs {
        let start = Instant::now();
        let _hash = hash_impl.hash(&input).unwrap();
        timings.push(start.elapsed());
    }

    // Check that timings don't have obvious patterns
    // (e.g., all even indices being faster than odd indices)
    let even_timings: Vec<Duration> = timings
        .iter()
        .enumerate()
        .filter(|(i, _)| i % 2 == 0)
        .map(|(_, &t)| t)
        .collect();

    let odd_timings: Vec<Duration> = timings
        .iter()
        .enumerate()
        .filter(|(i, _)| i % 2 == 1)
        .map(|(_, &t)| t)
        .collect();

    let even_avg = even_timings.iter().sum::<Duration>() / even_timings.len() as u32;
    let odd_avg = odd_timings.iter().sum::<Duration>() / odd_timings.len() as u32;

    // Average timings should be similar
    let max_avg = even_avg.max(odd_avg);
    let min_avg = even_avg.min(odd_avg);

    assert!(
        max_avg.as_nanos() <= min_avg.as_nanos() * 3,
        "Timing patterns detected: even_avg={even_avg:?}, odd_avg={odd_avg:?}"
    );
}
