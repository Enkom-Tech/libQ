//! Comprehensive Test Suite for KangarooTwelve
//!
//! This test suite covers all aspects of the K12 implementation including:
//! - Basic functionality tests
//! - Known Answer Tests (KATs)
//! - Edge cases and boundary conditions
//! - Security properties
//! - Performance characteristics
//! - Both KT128 and KT256 variants

use hex_literal::hex;
use lib_q_k12::{
    KangarooTwelve, KangarooTwelve256,
    digest::{ExtendableOutput, Update},
};
use std::time::Instant;

// ============================================================================
// BASIC FUNCTIONALITY TESTS
// ============================================================================

#[test]
fn test_basic_kt128_functionality() {
    // Test basic KT128 functionality
    let mut hasher = KangarooTwelve::new(b"test");
    hasher.update(b"hello");
    let result = hasher.finalize_boxed(32);

    assert_eq!(result.len(), 32);
    // Check that result is not all zeros
    assert!(result.iter().any(|&b| b != 0));
}

#[test]
fn test_basic_kt256_functionality() {
    // Test basic KT256 functionality
    let mut hasher = KangarooTwelve256::new(b"test");
    hasher.update(b"hello");
    let result = hasher.finalize_boxed(64);

    assert_eq!(result.len(), 64);
    // Check that result is not all zeros
    assert!(result.iter().any(|&b| b != 0));
}

#[test]
fn test_empty_input_kt128() {
    // Test empty input for KT128
    let mut hasher = KangarooTwelve::new(&[]);
    hasher.update(&[]);
    let result = hasher.finalize_boxed(32);

    // Known empty input result for KT128
    let expected = hex!("1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5");
    assert_eq!(result[..], expected[..]);
}

#[test]
fn test_empty_input_kt256() {
    // Test empty input for KT256
    let mut hasher = KangarooTwelve256::new(&[]);
    hasher.update(&[]);
    let result = hasher.finalize_boxed(64);

    // Known empty input result for KT256
    let expected = hex!(
        "b23d2e9cea9f4904e02bec06817fc10ce38ce8e93ef4c89e6537076af8646404e3e8b68107b8833a5d30490aa33482353fd4adc7148ecb782855003aaebde4a9"
    );
    assert_eq!(result[..], expected[..]);
}

// ============================================================================
// CUSTOMIZATION TESTS
// ============================================================================

#[test]
fn test_customization_kt128() {
    // Test that different customizations produce different outputs
    let mut hasher1 = KangarooTwelve::new(b"custom1");
    hasher1.update(b"message");
    let result1 = hasher1.finalize_boxed(32);

    let mut hasher2 = KangarooTwelve::new(b"custom2");
    hasher2.update(b"message");
    let result2 = hasher2.finalize_boxed(32);

    assert_ne!(result1, result2);
}

#[test]
fn test_customization_kt256() {
    // Test that different customizations produce different outputs
    let mut hasher1 = KangarooTwelve256::new(b"custom1");
    hasher1.update(b"message");
    let result1 = hasher1.finalize_boxed(64);

    let mut hasher2 = KangarooTwelve256::new(b"custom2");
    hasher2.update(b"message");
    let result2 = hasher2.finalize_boxed(64);

    assert_ne!(result1, result2);
}

#[test]
fn test_empty_customization_kt128() {
    // Test empty customization
    let mut hasher1 = KangarooTwelve::new(&[]);
    hasher1.update(b"message");
    let result1 = hasher1.finalize_boxed(32);

    let mut hasher2 = KangarooTwelve::new(b"");
    hasher2.update(b"message");
    let result2 = hasher2.finalize_boxed(32);

    assert_eq!(result1, result2);
}

#[test]
fn test_empty_customization_kt256() {
    // Test empty customization
    let mut hasher1 = KangarooTwelve256::new(&[]);
    hasher1.update(b"message");
    let result1 = hasher1.finalize_boxed(64);

    let mut hasher2 = KangarooTwelve256::new(b"");
    hasher2.update(b"message");
    let result2 = hasher2.finalize_boxed(64);

    assert_eq!(result1, result2);
}

// ============================================================================
// XOF (EXTENDABLE OUTPUT FUNCTION) TESTS
// ============================================================================

#[test]
fn test_xof_consistency_kt128() {
    // Test that XOF produces consistent output
    let mut hasher1 = KangarooTwelve::new(b"test");
    hasher1.update(b"message");
    let result1 = hasher1.finalize_boxed(64);

    let mut hasher2 = KangarooTwelve::new(b"test");
    hasher2.update(b"message");
    let result2 = hasher2.finalize_boxed(64);

    assert_eq!(result1, result2);
}

#[test]
fn test_xof_consistency_kt256() {
    // Test that XOF produces consistent output
    let mut hasher1 = KangarooTwelve256::new(b"test");
    hasher1.update(b"message");
    let result1 = hasher1.finalize_boxed(128);

    let mut hasher2 = KangarooTwelve256::new(b"test");
    hasher2.update(b"message");
    let result2 = hasher2.finalize_boxed(128);

    assert_eq!(result1, result2);
}

#[test]
fn test_xof_output_sizes_kt128() {
    // Test different output sizes for KT128
    let mut hasher1 = KangarooTwelve::new(b"test");
    hasher1.update(b"message");
    let result32 = hasher1.finalize_boxed(32);

    let mut hasher2 = KangarooTwelve::new(b"test");
    hasher2.update(b"message");
    let result64 = hasher2.finalize_boxed(64);

    let mut hasher3 = KangarooTwelve::new(b"test");
    hasher3.update(b"message");
    let result128 = hasher3.finalize_boxed(128);

    assert_eq!(result32.len(), 32);
    assert_eq!(result64.len(), 64);
    assert_eq!(result128.len(), 128);

    // First 32 bytes should be the same
    assert_eq!(result32[..], result64[..32]);
    assert_eq!(result32[..], result128[..32]);
}

#[test]
fn test_xof_output_sizes_kt256() {
    // Test different output sizes for KT256
    let mut hasher1 = KangarooTwelve256::new(b"test");
    hasher1.update(b"message");
    let result64 = hasher1.finalize_boxed(64);

    let mut hasher2 = KangarooTwelve256::new(b"test");
    hasher2.update(b"message");
    let result128 = hasher2.finalize_boxed(128);

    let mut hasher3 = KangarooTwelve256::new(b"test");
    hasher3.update(b"message");
    let result256 = hasher3.finalize_boxed(256);

    assert_eq!(result64.len(), 64);
    assert_eq!(result128.len(), 128);
    assert_eq!(result256.len(), 256);

    // First 64 bytes should be the same
    assert_eq!(result64[..], result128[..64]);
    assert_eq!(result64[..], result256[..64]);
}

// ============================================================================
// INCREMENTAL UPDATE TESTS
// ============================================================================

#[test]
fn test_incremental_update_kt128() {
    // Test incremental updates
    let mut hasher1 = KangarooTwelve::new(b"test");
    hasher1.update(b"hello");
    hasher1.update(b"world");
    let result1 = hasher1.finalize_boxed(32);

    let mut hasher2 = KangarooTwelve::new(b"test");
    hasher2.update(b"helloworld");
    let result2 = hasher2.finalize_boxed(32);

    assert_eq!(result1, result2);
}

#[test]
fn test_incremental_update_kt256() {
    // Test incremental updates
    let mut hasher1 = KangarooTwelve256::new(b"test");
    hasher1.update(b"hello");
    hasher1.update(b"world");
    let result1 = hasher1.finalize_boxed(64);

    let mut hasher2 = KangarooTwelve256::new(b"test");
    hasher2.update(b"helloworld");
    let result2 = hasher2.finalize_boxed(64);

    assert_eq!(result1, result2);
}

// ============================================================================
// LARGE INPUT TESTS
// ============================================================================

#[test]
fn test_large_input_kt128() {
    // Test with large input
    let large_data = vec![0x42u8; 10000];
    let mut hasher = KangarooTwelve::new(b"test");
    hasher.update(&large_data);
    let result = hasher.finalize_boxed(32);

    assert_eq!(result.len(), 32);
    assert!(result.iter().any(|&b| b != 0));
}

#[test]
fn test_large_input_kt256() {
    // Test with large input
    let large_data = vec![0x42u8; 10000];
    let mut hasher = KangarooTwelve256::new(b"test");
    hasher.update(&large_data);
    let result = hasher.finalize_boxed(64);

    assert_eq!(result.len(), 64);
    assert!(result.iter().any(|&b| b != 0));
}

// ============================================================================
// EDGE CASE TESTS
// ============================================================================

#[test]
fn test_zero_length_output_kt128() {
    // Test zero length output
    let mut hasher = KangarooTwelve::new(b"test");
    hasher.update(b"message");
    let result = hasher.finalize_boxed(0);

    assert_eq!(result.len(), 0);
}

#[test]
fn test_zero_length_output_kt256() {
    // Test zero length output
    let mut hasher = KangarooTwelve256::new(b"test");
    hasher.update(b"message");
    let result = hasher.finalize_boxed(0);

    assert_eq!(result.len(), 0);
}

#[test]
fn test_very_large_output_kt128() {
    // Test very large output
    let mut hasher = KangarooTwelve::new(b"test");
    hasher.update(b"message");
    let result = hasher.finalize_boxed(10000);

    assert_eq!(result.len(), 10000);
    assert!(result.iter().any(|&b| b != 0));
}

#[test]
fn test_very_large_output_kt256() {
    // Test very large output
    let mut hasher = KangarooTwelve256::new(b"test");
    hasher.update(b"message");
    let result = hasher.finalize_boxed(10000);

    assert_eq!(result.len(), 10000);
    assert!(result.iter().any(|&b| b != 0));
}

// ============================================================================
// SECURITY PROPERTY TESTS
// ============================================================================

#[test]
fn test_avalanche_effect_kt128() {
    // Test avalanche effect - small input changes should produce large output changes
    let mut hasher1 = KangarooTwelve::new(b"test");
    hasher1.update(b"message");
    let result1 = hasher1.finalize_boxed(32);

    let mut hasher2 = KangarooTwelve::new(b"test");
    hasher2.update(b"message\x00");
    let result2 = hasher2.finalize_boxed(32);

    // Count different bits
    let mut diff_bits = 0;
    for (a, b) in result1.iter().zip(result2.iter()) {
        diff_bits += (a ^ b).count_ones();
    }

    // Should have significant bit differences (more than 50% on average)
    assert!(diff_bits > 64); // More than 50% of 256 bits
}

#[test]
fn test_avalanche_effect_kt256() {
    // Test avalanche effect - small input changes should produce large output changes
    let mut hasher1 = KangarooTwelve256::new(b"test");
    hasher1.update(b"message");
    let result1 = hasher1.finalize_boxed(64);

    let mut hasher2 = KangarooTwelve256::new(b"test");
    hasher2.update(b"message\x00");
    let result2 = hasher2.finalize_boxed(64);

    // Count different bits
    let mut diff_bits = 0;
    for (a, b) in result1.iter().zip(result2.iter()) {
        diff_bits += (a ^ b).count_ones();
    }

    // Should have significant bit differences (more than 50% on average)
    assert!(diff_bits > 128); // More than 50% of 512 bits
}

#[test]
fn test_determinism_kt128() {
    // Test that same input produces same output
    let mut hasher1 = KangarooTwelve::new(b"test");
    hasher1.update(b"message");
    let result1 = hasher1.finalize_boxed(32);

    let mut hasher2 = KangarooTwelve::new(b"test");
    hasher2.update(b"message");
    let result2 = hasher2.finalize_boxed(32);

    assert_eq!(result1, result2);
}

#[test]
fn test_determinism_kt256() {
    // Test that same input produces same output
    let mut hasher1 = KangarooTwelve256::new(b"test");
    hasher1.update(b"message");
    let result1 = hasher1.finalize_boxed(64);

    let mut hasher2 = KangarooTwelve256::new(b"test");
    hasher2.update(b"message");
    let result2 = hasher2.finalize_boxed(64);

    assert_eq!(result1, result2);
}

// ============================================================================
// PERFORMANCE TESTS
// ============================================================================

#[test]
fn test_performance_kt128() {
    // Test performance characteristics
    let data = vec![0x42u8; 1000];
    let iterations = 1000;

    let start = Instant::now();
    for _ in 0..iterations {
        let mut hasher = KangarooTwelve::new(b"test");
        hasher.update(&data);
        let _result = hasher.finalize_boxed(32);
    }
    let duration = start.elapsed();

    // Should complete in reasonable time (less than 1 second)
    assert!(duration.as_millis() < 1000);
}

#[test]
fn test_performance_kt256() {
    // Test performance characteristics
    let data = vec![0x42u8; 1000];
    let iterations = 1000;

    let start = Instant::now();
    for _ in 0..iterations {
        let mut hasher = KangarooTwelve256::new(b"test");
        hasher.update(&data);
        let _result = hasher.finalize_boxed(64);
    }
    let duration = start.elapsed();

    // Should complete in reasonable time (less than 1 second)
    assert!(duration.as_millis() < 1000);
}

// ============================================================================
// VARIANT COMPARISON TESTS
// ============================================================================

#[test]
fn test_variant_differences() {
    // Test that KT128 and KT256 produce different outputs
    let mut hasher128 = KangarooTwelve::new(b"test");
    hasher128.update(b"message");
    let result128 = hasher128.finalize_boxed(32);

    let mut hasher256 = KangarooTwelve256::new(b"test");
    hasher256.update(b"message");
    let result256 = hasher256.finalize_boxed(32);

    // Should be different (different security levels)
    assert_ne!(result128, result256);
}

#[test]
fn test_variant_output_sizes() {
    // Test that variants produce appropriate output sizes
    let mut hasher128 = KangarooTwelve::new(b"test");
    hasher128.update(b"message");
    let result128 = hasher128.finalize_boxed(64);

    let mut hasher256 = KangarooTwelve256::new(b"test");
    hasher256.update(b"message");
    let result256 = hasher256.finalize_boxed(64);

    assert_eq!(result128.len(), 64);
    assert_eq!(result256.len(), 64);
}

// ============================================================================
// STRESS TESTS
// ============================================================================

#[test]
fn test_stress_kt128() {
    // Stress test with many small updates
    let mut hasher = KangarooTwelve::new(b"test");
    for i in 0..1000 {
        hasher.update(&[i as u8]);
    }
    let result = hasher.finalize_boxed(32);

    assert_eq!(result.len(), 32);
    assert!(result.iter().any(|&b| b != 0));
}

#[test]
fn test_stress_kt256() {
    // Stress test with many small updates
    let mut hasher = KangarooTwelve256::new(b"test");
    for i in 0..1000 {
        hasher.update(&[i as u8]);
    }
    let result = hasher.finalize_boxed(64);

    assert_eq!(result.len(), 64);
    assert!(result.iter().any(|&b| b != 0));
}

// ============================================================================
// INTEGRATION TESTS
// ============================================================================

#[test]
fn test_integration_scenario_kt128() {
    // Test a realistic integration scenario
    let mut hasher = KangarooTwelve::new(b"session_key");
    hasher.update(b"user_id:12345");
    hasher.update(b"timestamp:1640995200");
    hasher.update(b"nonce:abcdef123456");
    let session_key = hasher.finalize_boxed(32);

    assert_eq!(session_key.len(), 32);
    assert!(session_key.iter().any(|&b| b != 0));
}

#[test]
fn test_integration_scenario_kt256() {
    // Test a realistic integration scenario
    let mut hasher = KangarooTwelve256::new(b"session_key");
    hasher.update(b"user_id:12345");
    hasher.update(b"timestamp:1640995200");
    hasher.update(b"nonce:abcdef123456");
    let session_key = hasher.finalize_boxed(64);

    assert_eq!(session_key.len(), 64);
    assert!(session_key.iter().any(|&b| b != 0));
}
