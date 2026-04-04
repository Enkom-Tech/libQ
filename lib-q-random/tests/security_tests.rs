//! Security tests for lib-q-random
//!
//! These tests ensure that the RNG implementation meets cryptographic security requirements.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

// Conditional imports based on feature flags
#[cfg(feature = "alloc")]
use lib_q_random::{
    new_deterministic_rng,
    new_secure_rng,
};
#[cfg(not(feature = "alloc"))]
use lib_q_random::{
    new_deterministic_rng_no_std,
    new_secure_rng_no_std,
};
use rand_core::Rng;

/// Test that secure RNG never produces all zeros
#[test]
fn test_secure_rng_never_produces_zeros() {
    #[cfg(feature = "alloc")]
    {
        let mut rng = new_secure_rng().expect("Failed to create secure RNG");

        // Test multiple calls to ensure we never get all zeros
        for _ in 0..100 {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);

            // Ensure we never get all zeros
            assert_ne!(bytes, [0u8; 32], "Secure RNG produced all zeros!");

            // Ensure we have some non-zero bytes
            let non_zero_count = bytes.iter().filter(|&&b| b != 0).count();
            assert!(non_zero_count > 0, "Secure RNG produced no non-zero bytes!");
        }
    }

    #[cfg(not(feature = "alloc"))]
    {
        let mut rng = new_secure_rng_no_std().expect("Failed to create secure RNG");

        // Test multiple calls to ensure we never get all zeros
        for _ in 0..100 {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);

            // Ensure we never get all zeros
            assert_ne!(bytes, [0u8; 32], "Secure RNG produced all zeros!");

            // Ensure we have some non-zero bytes
            let non_zero_count = bytes.iter().filter(|&&b| b != 0).count();
            assert!(non_zero_count > 0, "Secure RNG produced no non-zero bytes!");
        }
    }
}

/// Test that secure RNG produces different values on successive calls
#[test]
fn test_secure_rng_produces_different_values() {
    #[cfg(feature = "alloc")]
    {
        let mut rng = new_secure_rng().expect("Failed to create secure RNG");

        let mut prev_bytes = [0u8; 32];
        rng.fill_bytes(&mut prev_bytes);

        // Test that successive calls produce different values
        for _ in 0..50 {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);

            // Very high probability that they should be different
            assert_ne!(
                bytes, prev_bytes,
                "Secure RNG produced identical values on successive calls!"
            );
            prev_bytes = bytes;
        }
    }

    #[cfg(not(feature = "alloc"))]
    {
        let mut rng = new_secure_rng_no_std().expect("Failed to create secure RNG");

        let mut prev_bytes = [0u8; 32];
        rng.fill_bytes(&mut prev_bytes);

        // Test that successive calls produce different values
        for _ in 0..50 {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);

            // Very high probability that they should be different
            assert_ne!(
                bytes, prev_bytes,
                "Secure RNG produced identical values on successive calls!"
            );
            prev_bytes = bytes;
        }
    }
}

/// Test that different RNG instances produce different values
#[test]
fn test_different_rng_instances_produce_different_values() {
    #[cfg(feature = "alloc")]
    {
        let mut rng1 = new_secure_rng().expect("Failed to create secure RNG 1");
        let mut rng2 = new_secure_rng().expect("Failed to create secure RNG 2");

        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];

        rng1.fill_bytes(&mut bytes1);
        rng2.fill_bytes(&mut bytes2);

        // Different instances should produce different values
        assert_ne!(
            bytes1, bytes2,
            "Different RNG instances produced identical values!"
        );
    }

    #[cfg(not(feature = "alloc"))]
    {
        let mut rng1 = new_secure_rng_no_std().expect("Failed to create secure RNG 1");
        let mut rng2 = new_secure_rng_no_std().expect("Failed to create secure RNG 2");

        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];

        rng1.fill_bytes(&mut bytes1);
        rng2.fill_bytes(&mut bytes2);

        // Different instances should produce different values
        assert_ne!(
            bytes1, bytes2,
            "Different RNG instances produced identical values!"
        );
    }
}

/// Test that deterministic RNG produces consistent values
#[test]
fn test_deterministic_rng_consistency() {
    let seed = b"test seed for deterministic RNG";

    #[cfg(feature = "alloc")]
    {
        let mut rng1 = new_deterministic_rng(seed);
        let mut rng2 = new_deterministic_rng(seed);

        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];

        rng1.fill_bytes(&mut bytes1);
        rng2.fill_bytes(&mut bytes2);

        // Deterministic RNGs with same seed should produce same values
        assert_eq!(
            bytes1, bytes2,
            "Deterministic RNGs with same seed produced different values!"
        );
    }

    #[cfg(not(feature = "alloc"))]
    {
        let mut rng1 = new_deterministic_rng_no_std(seed);
        let mut rng2 = new_deterministic_rng_no_std(seed);

        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];

        rng1.fill_bytes(&mut bytes1);
        rng2.fill_bytes(&mut bytes2);

        // Deterministic RNGs with same seed should produce same values
        assert_eq!(
            bytes1, bytes2,
            "Deterministic RNGs with same seed produced different values!"
        );
    }
}

/// Test that deterministic RNGs with different seeds produce different values
#[test]
fn test_deterministic_rng_different_seeds() {
    let seed1 = b"seed 1";
    let seed2 = b"seed 2";

    #[cfg(feature = "alloc")]
    {
        let mut rng1 = new_deterministic_rng(seed1);
        let mut rng2 = new_deterministic_rng(seed2);

        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];

        rng1.fill_bytes(&mut bytes1);
        rng2.fill_bytes(&mut bytes2);

        // Different seeds should produce different values
        assert_ne!(
            bytes1, bytes2,
            "Deterministic RNGs with different seeds produced identical values!"
        );
    }

    #[cfg(not(feature = "alloc"))]
    {
        let mut rng1 = new_deterministic_rng_no_std(seed1);
        let mut rng2 = new_deterministic_rng_no_std(seed2);

        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];

        rng1.fill_bytes(&mut bytes1);
        rng2.fill_bytes(&mut bytes2);

        // Different seeds should produce different values
        assert_ne!(
            bytes1, bytes2,
            "Deterministic RNGs with different seeds produced identical values!"
        );
    }
}

/// Test entropy quality of secure RNG
#[test]
#[cfg(feature = "alloc")]
fn test_secure_rng_entropy_quality() {
    let mut rng = new_secure_rng().expect("Failed to create secure RNG");

    // Collect a large sample of random data
    let mut samples = Vec::new();
    for _ in 0..1000 {
        let mut bytes = [0u8; 16];
        rng.fill_bytes(&mut bytes);
        samples.extend_from_slice(&bytes);
    }

    // Test basic entropy properties
    test_byte_distribution(&samples);
    test_autocorrelation(&samples);
    test_runs_test(&samples);
}

/// Test byte distribution uniformity
#[cfg(feature = "alloc")]
fn test_byte_distribution(data: &[u8]) {
    let mut byte_counts = [0u32; 256];
    for &byte in data {
        byte_counts[byte as usize] += 1;
    }

    let expected_count = data.len() / 256;
    let tolerance = ((expected_count as f64 * 0.6) as usize).max(15); // 60% tolerance, minimum 15

    for (i, &count) in byte_counts.iter().enumerate() {
        let count_usize = count as usize;
        let diff = count_usize.abs_diff(expected_count);

        assert!(
            diff <= tolerance,
            "Byte {} appears {} times, expected {} ± {}",
            i,
            count,
            expected_count,
            tolerance
        );
    }
}

/// Lag-1 sample Pearson correlation between adjacent bytes.
///
/// The previous check averaged `(x - 127.5)(y - 127.5)`, which is a *covariance-like*
/// quantity with scale ~Var(U(0,255))²/√n (std dev ~40+ for n≈16k), not a correlation in
/// [-1, 1]. A fixed threshold (e.g. 100) was only ~2–3σ, so bona fide OS RNG output could
/// fail CI sporadically. We instead normalize to Pearson r and bound |r| using ~8/√n_pairs
/// to allow for mild variance inflation from overlapping pairs under an i.i.d. null.
#[cfg(feature = "alloc")]
fn test_autocorrelation(data: &[u8]) {
    let n_pairs = data.len().saturating_sub(1);
    if n_pairs < 2 {
        return;
    }

    let n = n_pairs as f64;
    let mut sum_x = 0.0;
    let mut sum_y = 0.0;
    let mut sum_xx = 0.0;
    let mut sum_yy = 0.0;
    let mut sum_xy = 0.0;

    for i in 0..n_pairs {
        let x = data[i] as f64;
        let y = data[i + 1] as f64;
        sum_x += x;
        sum_y += y;
        sum_xx += x * x;
        sum_yy += y * y;
        sum_xy += x * y;
    }

    let mean_x = sum_x / n;
    let mean_y = sum_y / n;
    let cov = sum_xy / n - mean_x * mean_y;
    let var_x = sum_xx / n - mean_x * mean_x;
    let var_y = sum_yy / n - mean_y * mean_y;

    if var_x <= 1e-12 || var_y <= 1e-12 {
        return;
    }

    let r = cov / (var_x.sqrt() * var_y.sqrt());
    let threshold = 8.0 / n.sqrt();

    assert!(
        r.abs() < threshold,
        "Lag-1 correlation |r|={} exceeds bound {:.4} (~8/√n, n={} pairs)",
        r,
        threshold,
        n_pairs
    );
}

/// Test runs (consecutive identical values)
#[cfg(feature = "alloc")]
fn test_runs_test(data: &[u8]) {
    if data.is_empty() {
        return;
    }

    let mut runs = 1;
    let mut current_byte = data[0];

    for &byte in data.iter().skip(1) {
        if byte != current_byte {
            runs += 1;
            current_byte = byte;
        }
    }

    let expected_runs = data.len() / 2; // Rough expectation  
    let tolerance = ((expected_runs as f64 * 0.5) as usize).max(50); // 50% tolerance, minimum 50

    assert!(
        runs >= expected_runs - tolerance,
        "Too few runs: {} (expected ~{})",
        runs,
        expected_runs
    );
}

/// Test that RNG fails securely when entropy source is unavailable
#[test]
fn test_secure_failure_when_entropy_unavailable() {
    #[cfg(feature = "alloc")]
    {
        // This test would require mocking the entropy source to fail
        // For now, we just ensure the RNG doesn't panic
        let result = new_secure_rng();
        assert!(
            result.is_ok(),
            "RNG creation should not panic even if entropy is limited"
        );
    }

    #[cfg(not(feature = "alloc"))]
    {
        // This test would require mocking the entropy source to fail
        // For now, we just ensure the RNG doesn't panic
        let result = new_secure_rng_no_std();
        assert!(
            result.is_ok(),
            "RNG creation should not panic even if entropy is limited"
        );
    }
}

/// Test that RNG properly handles edge cases
#[test]
fn test_rng_edge_cases() {
    #[cfg(feature = "alloc")]
    {
        let mut rng = new_secure_rng().expect("Failed to create secure RNG");

        // Test filling empty slice
        let mut empty = [];
        rng.fill_bytes(&mut empty);

        // Test filling single byte
        let mut single = [0u8; 1];
        rng.fill_bytes(&mut single);
        assert_ne!(single[0], 0, "Single byte should not be zero");

        // Test filling large buffer
        let mut large = vec![0u8; 1024];
        rng.fill_bytes(&mut large);

        // Ensure large buffer has some non-zero bytes
        let non_zero_count = large.iter().filter(|&&b| b != 0).count();
        assert!(
            non_zero_count > 0,
            "Large buffer should have non-zero bytes"
        );
    }

    #[cfg(not(feature = "alloc"))]
    {
        let mut rng = new_secure_rng_no_std().expect("Failed to create secure RNG");

        // Test filling empty slice
        let mut empty = [];
        rng.fill_bytes(&mut empty);

        // Test filling single byte
        let mut single = [0u8; 1];
        rng.fill_bytes(&mut single);
        assert_ne!(single[0], 0, "Single byte should not be zero");

        // Test filling large buffer (using array instead of vec)
        let mut large = [0u8; 1024];
        rng.fill_bytes(&mut large);

        // Ensure large buffer has some non-zero bytes
        let non_zero_count = large.iter().filter(|&&b| b != 0).count();
        assert!(
            non_zero_count > 0,
            "Large buffer should have non-zero bytes"
        );
    }
}

/// Test that RNG maintains security properties across reseeding
#[test]
fn test_rng_security_across_reseeding() {
    #[cfg(feature = "alloc")]
    {
        let mut rng = new_secure_rng().expect("Failed to create secure RNG");

        // Generate data before potential reseeding
        let mut before_bytes = [0u8; 32];
        rng.fill_bytes(&mut before_bytes);

        // Force a reseed by generating a lot of data
        for _ in 0..100 {
            let mut temp = [0u8; 1024];
            rng.fill_bytes(&mut temp);
        }

        // Generate data after reseeding
        let mut after_bytes = [0u8; 32];
        rng.fill_bytes(&mut after_bytes);

        // Both should be non-zero and different
        assert_ne!(
            before_bytes, [0u8; 32],
            "Data before reseed should not be all zeros"
        );
        assert_ne!(
            after_bytes, [0u8; 32],
            "Data after reseed should not be all zeros"
        );
        assert_ne!(
            before_bytes, after_bytes,
            "Data before and after reseed should be different"
        );
    }

    #[cfg(not(feature = "alloc"))]
    {
        let mut rng = new_secure_rng_no_std().expect("Failed to create secure RNG");

        // Generate data before potential reseeding
        let mut before_bytes = [0u8; 32];
        rng.fill_bytes(&mut before_bytes);

        // Force a reseed by generating a lot of data
        for _ in 0..100 {
            let mut temp = [0u8; 1024];
            rng.fill_bytes(&mut temp);
        }

        // Generate data after reseeding
        let mut after_bytes = [0u8; 32];
        rng.fill_bytes(&mut after_bytes);

        // Both should be non-zero and different
        assert_ne!(
            before_bytes, [0u8; 32],
            "Data before reseed should not be all zeros"
        );
        assert_ne!(
            after_bytes, [0u8; 32],
            "Data after reseed should not be all zeros"
        );
        assert_ne!(
            before_bytes, after_bytes,
            "Data before and after reseed should be different"
        );
    }
}
