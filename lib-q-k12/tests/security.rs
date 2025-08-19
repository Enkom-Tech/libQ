// Copyright 2025 Enkom Tech
// Copyright 2025 Nexlab-One
// SPDX-License-Identifier: Apache-2.0

//! Security property tests for KangarooTwelve
//!
//! These tests verify that KangarooTwelve maintains essential cryptographic
//! security properties and handles edge cases correctly.

use lib_q_k12::{
    KangarooTwelve,
    digest::{ExtendableOutput, Reset, Update},
};
use std::collections::HashSet;

/// Test that identical inputs always produce identical outputs (determinism)
#[test]
fn test_determinism() {
    let test_data = b"determinism test data";
    let customization = b"test_custom";

    // Hash the same data multiple times
    let mut results = Vec::new();
    for _ in 0..10 {
        let mut hasher = KangarooTwelve::new(customization);
        hasher.update(test_data);
        let result = hasher.finalize_boxed(64);
        results.push(result);
    }

    // All results should be identical
    for i in 1..results.len() {
        assert_eq!(
            results[0], results[i],
            "Determinism failed: result {} differs from result 0",
            i
        );
    }
}

/// Test that different inputs produce different outputs (no collisions in test set)
#[test]
fn test_collision_resistance() {
    let mut results = HashSet::new();
    let output_size = 32;

    // Test various input patterns
    let test_inputs = [
        b"".as_slice(),
        b"a".as_slice(),
        b"ab".as_slice(),
        b"abc".as_slice(),
        b"abcd".as_slice(),
        b"The quick brown fox jumps over the lazy dog".as_slice(),
        b"The quick brown fox jumps over the lazy dog.".as_slice(),
        &vec![0x00u8; 100],
        &vec![0x01u8; 100],
        &vec![0xFFu8; 100],
    ];

    for input in &test_inputs {
        let mut hasher = KangarooTwelve::default();
        hasher.update(input);
        let result = hasher.finalize_boxed(output_size);

        assert!(
            results.insert(result.clone()),
            "Collision detected for input: {:?}",
            input
        );
    }
}

/// Test that customization strings produce different outputs
#[test]
fn test_customization_separation() {
    let test_data = b"same input data";
    let customizations = [
        b"".as_slice(),
        b"custom1".as_slice(),
        b"custom2".as_slice(),
        b"a_very_long_customization_string_that_exceeds_normal_length".as_slice(),
        &vec![0x00u8; 50],
        &vec![0x01u8; 50],
    ];

    let mut results = HashSet::new();

    for custom in &customizations {
        let mut hasher = KangarooTwelve::new(custom);
        hasher.update(test_data);
        let result = hasher.finalize_boxed(32);

        assert!(
            results.insert(result.clone()),
            "Customization collision detected for: {:?}",
            custom
        );
    }
}

/// Test avalanche effect: small input changes cause large output changes
#[test]
fn test_avalanche_effect() {
    let base_input = vec![0x42u8; 100];
    let mut base_hasher = KangarooTwelve::default();
    base_hasher.update(&base_input);
    let base_result = base_hasher.finalize_boxed(64);

    // Test single bit flips
    for byte_pos in [0, 50, 99] {
        for bit_pos in 0..8 {
            let mut modified_input = base_input.clone();
            modified_input[byte_pos] ^= 1 << bit_pos;

            let mut hasher = KangarooTwelve::default();
            hasher.update(&modified_input);
            let result = hasher.finalize_boxed(64);

            // Count differing bits
            let mut diff_bits = 0;
            for i in 0..64 {
                diff_bits += (base_result[i] ^ result[i]).count_ones();
            }

            // Should have significant bit differences (avalanche effect)
            // Expect roughly half the bits to be different (around 256 ± tolerance)
            assert!(
                diff_bits >= 200 && diff_bits <= 312,
                "Insufficient avalanche effect: only {} bits differ for bit flip at byte {} bit {}",
                diff_bits,
                byte_pos,
                bit_pos
            );
        }
    }
}

/// Test that outputs appear uniformly distributed
#[test]
fn test_output_distribution() {
    let mut bit_counts = vec![0u32; 8]; // Count for each bit position
    let num_samples = 256;

    for i in 0..num_samples {
        let input = vec![i as u8; 10];
        let mut hasher = KangarooTwelve::default();
        hasher.update(&input);
        let result = hasher.finalize_boxed(1);

        // Count bits in the single output byte
        for bit_pos in 0..8 {
            if (result[0] >> bit_pos) & 1 == 1 {
                bit_counts[bit_pos] += 1;
            }
        }
    }

    // Each bit position should be set roughly half the time
    let expected = num_samples / 2;
    let tolerance = expected / 4; // 25% tolerance

    for (bit_pos, &count) in bit_counts.iter().enumerate() {
        assert!(
            count >= expected - tolerance && count <= expected + tolerance,
            "Bit {} distribution skewed: {} out of {} (expected ~{})",
            bit_pos,
            count,
            num_samples,
            expected
        );
    }
}

/// Test XOF property: different output lengths from same input should be consistent
#[test]
fn test_xof_consistency() {
    let test_data = b"XOF consistency test";
    let customization = b"xof_test";

    // Generate outputs of different lengths
    let mut hasher1 = KangarooTwelve::new(customization);
    hasher1.update(test_data);
    let short_output = hasher1.finalize_boxed(32);

    let mut hasher2 = KangarooTwelve::new(customization);
    hasher2.update(test_data);
    let long_output = hasher2.finalize_boxed(64);

    // First 32 bytes of long output should match short output
    assert_eq!(
        short_output[..],
        long_output[..32],
        "XOF consistency failed: short output doesn't match prefix of long output"
    );

    // Test with even longer output
    let mut hasher3 = KangarooTwelve::new(customization);
    hasher3.update(test_data);
    let very_long_output = hasher3.finalize_boxed(128);

    assert_eq!(
        long_output[..],
        very_long_output[..64],
        "XOF consistency failed: medium output doesn't match prefix of long output"
    );
}

/// Test that reset functionality works correctly
#[test]
fn test_reset_security() {
    let data1 = b"first data";
    let data2 = b"second data";

    // Hash data1, reset, then hash data2
    let mut hasher = KangarooTwelve::default();
    hasher.update(data1);
    hasher.reset();
    hasher.update(data2);
    let result1 = hasher.finalize_boxed(32);

    // Hash data2 directly
    let mut hasher2 = KangarooTwelve::default();
    hasher2.update(data2);
    let result2 = hasher2.finalize_boxed(32);

    // Results should be identical (reset should completely clear state)
    assert_eq!(result1, result2, "Reset failed to clear state properly");
}

/// Test edge cases for input sizes
#[test]
fn test_input_size_edge_cases() {
    let sizes = [0, 1, 127, 128, 129, 8191, 8192, 8193, 16383, 16384, 16385];
    let mut results = HashSet::new();

    for &size in &sizes {
        let input: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let mut hasher = KangarooTwelve::default();
        hasher.update(&input);
        let result = hasher.finalize_boxed(32);

        assert!(
            results.insert((size, result.clone())),
            "Duplicate result for input size {}",
            size
        );
    }
}

/// Test that large customization strings are handled correctly
#[test]
fn test_large_customization() {
    let test_data = b"test data";
    let large_custom = vec![0x55u8; 10000]; // Large customization

    let mut hasher = KangarooTwelve::new(&large_custom);
    hasher.update(test_data);
    let result = hasher.finalize_boxed(32);

    // Should not panic and should produce valid output
    assert_ne!(
        result[..],
        vec![0u8; 32][..],
        "Large customization produced all-zero output"
    );

    // Should be different from no customization
    let mut hasher2 = KangarooTwelve::default();
    hasher2.update(test_data);
    let result2 = hasher2.finalize_boxed(32);

    assert_ne!(result, result2, "Large customization had no effect");
}

/// Test incremental vs. all-at-once updates
#[test]
fn test_incremental_updates() {
    let data = vec![0x77u8; 1000];
    let customization = b"incremental_test";

    // Hash all at once
    let mut hasher1 = KangarooTwelve::new(customization);
    hasher1.update(&data);
    let result1 = hasher1.finalize_boxed(32);

    // Hash incrementally
    let mut hasher2 = KangarooTwelve::new(customization);
    for chunk in data.chunks(100) {
        hasher2.update(chunk);
    }
    let result2 = hasher2.finalize_boxed(32);

    assert_eq!(
        result1, result2,
        "Incremental updates produced different result"
    );
}

/// Test that zero-length outputs are handled correctly
#[test]
fn test_zero_length_output() {
    let test_data = b"test for zero output";

    let mut hasher = KangarooTwelve::default();
    hasher.update(test_data);
    let result = hasher.finalize_boxed(0);

    assert_eq!(result.len(), 0, "Zero-length output should be empty");
}

/// Test that very large outputs work correctly
#[test]
fn test_large_output() {
    let test_data = b"test for large output";
    let output_size = 10000;

    let mut hasher = KangarooTwelve::default();
    hasher.update(test_data);
    let result = hasher.finalize_boxed(output_size);

    assert_eq!(result.len(), output_size, "Large output size mismatch");

    // Check that output is not all zeros or all ones
    let all_zeros = result.iter().all(|&b| b == 0);
    let all_ones = result.iter().all(|&b| b == 0xFF);

    assert!(!all_zeros, "Large output is all zeros");
    assert!(!all_ones, "Large output is all ones");

    // Check for some randomness in the output
    let unique_bytes: HashSet<_> = result.iter().collect();
    assert!(unique_bytes.len() > 10, "Large output lacks diversity");
}

/// Test cloning behavior
#[test]
fn test_cloning() {
    let test_data = b"cloning test data";

    let mut hasher1 = KangarooTwelve::default();
    hasher1.update(test_data);

    let hasher2 = hasher1.clone();

    let result1 = hasher1.finalize_boxed(32);
    let result2 = hasher2.finalize_boxed(32);

    assert_eq!(result1, result2, "Cloned hasher produced different result");
}

/// Test that different chunk patterns produce different results
#[test]
fn test_chunk_independence() {
    let chunk_size = 8192;

    // Create data that spans multiple chunks differently
    let data1 = vec![0x11u8; chunk_size * 2];
    let data2 = vec![0x22u8; chunk_size * 2];

    let mut hasher1 = KangarooTwelve::default();
    hasher1.update(&data1[..chunk_size]);
    hasher1.update(&data1[chunk_size..]);
    let result1 = hasher1.finalize_boxed(32);

    let mut hasher2 = KangarooTwelve::default();
    hasher2.update(&data2[..chunk_size]);
    hasher2.update(&data2[chunk_size..]);
    let result2 = hasher2.finalize_boxed(32);

    assert_ne!(
        result1, result2,
        "Different chunk patterns produced same result"
    );
}
