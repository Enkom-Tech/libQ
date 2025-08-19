//! Security tests for SHA3 family algorithms
//!
//! These tests verify security-critical properties including memory safety,
//! input validation, error handling, and cryptographic properties.

use digest::Digest;
use lib_q_sha3::{Keccak256, Sha3_224, Sha3_256, Sha3_384, Sha3_512};

/// Test that hash operations are deterministic
#[test]
fn test_hash_determinism() {
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
        &[0u8; 100],
        &[0xffu8; 100],
        &[0u8; 1000],
        &[0xffu8; 1000],
    ];

    for input in &test_inputs {
        // Test SHA3-224
        let mut hasher1 = Sha3_224::new();
        let mut hasher2 = Sha3_224::new();
        hasher1.update(input);
        hasher2.update(input);
        let result1 = hasher1.finalize();
        let result2 = hasher2.finalize();
        assert_eq!(
            result1, result2,
            "SHA3-224 should be deterministic for input"
        );

        // Test SHA3-256
        let mut hasher1 = Sha3_256::new();
        let mut hasher2 = Sha3_256::new();
        hasher1.update(input);
        hasher2.update(input);
        let result1 = hasher1.finalize();
        let result2 = hasher2.finalize();
        assert_eq!(
            result1, result2,
            "SHA3-256 should be deterministic for input"
        );

        // Test Keccak256
        let mut hasher1 = Keccak256::new();
        let mut hasher2 = Keccak256::new();
        hasher1.update(input);
        hasher2.update(input);
        let result1 = hasher1.finalize();
        let result2 = hasher2.finalize();
        assert_eq!(
            result1, result2,
            "Keccak256 should be deterministic for input"
        );
    }
}

/// Test avalanche effect - small input changes should produce large output changes
#[test]
fn test_avalanche_effect() {
    let base_input = b"test input for avalanche effect";
    let mut base_hasher = Sha3_256::new();
    base_hasher.update(base_input);
    let base_result = base_hasher.finalize();

    // Test single bit changes at different positions
    for i in 0..base_input.len() {
        for bit in 0..8 {
            let mut modified_input = base_input.to_vec();
            modified_input[i] ^= 1 << bit;

            let mut modified_hasher = Sha3_256::new();
            modified_hasher.update(&modified_input);
            let modified_result = modified_hasher.finalize();

            // Count different bits between results
            let mut diff_bits = 0;
            for (base_byte, modified_byte) in base_result.iter().zip(modified_result.iter()) {
                diff_bits += (base_byte ^ modified_byte).count_ones();
            }

            // At least 50% of bits should be different (avalanche effect)
            let total_bits = base_result.len() * 8;
            let diff_percentage = diff_bits as f64 / total_bits as f64;
            assert!(
                diff_percentage > 0.4,
                "Avalanche effect too weak: {}% bits changed (expected >40%)",
                diff_percentage * 100.0
            );
        }
    }
}

/// Test that different hash algorithms produce different outputs
#[test]
fn test_hash_algorithm_distinctness() {
    let test_input = b"test input for algorithm distinctness";

    let mut sha3_224_hasher = Sha3_224::new();
    let mut sha3_256_hasher = Sha3_256::new();
    let mut sha3_384_hasher = Sha3_384::new();
    let mut sha3_512_hasher = Sha3_512::new();
    let mut keccak256_hasher = Keccak256::new();

    sha3_224_hasher.update(test_input);
    sha3_256_hasher.update(test_input);
    sha3_384_hasher.update(test_input);
    sha3_512_hasher.update(test_input);
    keccak256_hasher.update(test_input);

    let sha3_224_result = sha3_224_hasher.finalize();
    let sha3_256_result = sha3_256_hasher.finalize();
    let sha3_384_result = sha3_384_hasher.finalize();
    let sha3_512_result = sha3_512_hasher.finalize();
    let keccak256_result = keccak256_hasher.finalize();

    // All results should be different (compare first 28 bytes for SHA3-224)
    assert_ne!(
        &sha3_224_result[..],
        &sha3_256_result[..28],
        "SHA3-224 and SHA3-256 should produce different outputs"
    );
    assert_ne!(
        &sha3_256_result[..],
        &sha3_384_result[..32],
        "SHA3-256 and SHA3-384 should produce different outputs"
    );
    assert_ne!(
        &sha3_384_result[..],
        &sha3_512_result[..48],
        "SHA3-384 and SHA3-512 should produce different outputs"
    );
    assert_ne!(
        &sha3_256_result[..],
        &keccak256_result[..],
        "SHA3-256 and Keccak256 should produce different outputs"
    );
}

/// Test that hash outputs have the correct length
#[test]
fn test_hash_output_lengths() {
    let test_input = b"test input for output length verification";

    let mut sha3_224_hasher = Sha3_224::new();
    let mut sha3_256_hasher = Sha3_256::new();
    let mut sha3_384_hasher = Sha3_384::new();
    let mut sha3_512_hasher = Sha3_512::new();
    let mut keccak256_hasher = Keccak256::new();

    sha3_224_hasher.update(test_input);
    sha3_256_hasher.update(test_input);
    sha3_384_hasher.update(test_input);
    sha3_512_hasher.update(test_input);
    keccak256_hasher.update(test_input);

    let sha3_224_result = sha3_224_hasher.finalize();
    let sha3_256_result = sha3_256_hasher.finalize();
    let sha3_384_result = sha3_384_hasher.finalize();
    let sha3_512_result = sha3_512_hasher.finalize();
    let keccak256_result = keccak256_hasher.finalize();

    assert_eq!(
        sha3_224_result.len(),
        28,
        "SHA3-224 should produce 224 bits (28 bytes)"
    );
    assert_eq!(
        sha3_256_result.len(),
        32,
        "SHA3-256 should produce 256 bits (32 bytes)"
    );
    assert_eq!(
        sha3_384_result.len(),
        48,
        "SHA3-384 should produce 384 bits (48 bytes)"
    );
    assert_eq!(
        sha3_512_result.len(),
        64,
        "SHA3-512 should produce 512 bits (64 bytes)"
    );
    assert_eq!(
        keccak256_result.len(),
        32,
        "Keccak256 should produce 256 bits (32 bytes)"
    );
}

/// Test that hash operations handle empty input correctly
#[test]
fn test_empty_input_handling() {
    let empty_input = b"";

    let mut sha3_224_hasher = Sha3_224::new();
    let mut sha3_256_hasher = Sha3_256::new();
    let mut sha3_384_hasher = Sha3_384::new();
    let mut sha3_512_hasher = Sha3_512::new();
    let mut keccak256_hasher = Keccak256::new();

    sha3_224_hasher.update(empty_input);
    sha3_256_hasher.update(empty_input);
    sha3_384_hasher.update(empty_input);
    sha3_512_hasher.update(empty_input);
    keccak256_hasher.update(empty_input);

    let sha3_224_result = sha3_224_hasher.finalize();
    let sha3_256_result = sha3_256_hasher.finalize();
    let sha3_384_result = sha3_384_hasher.finalize();
    let sha3_512_result = sha3_512_hasher.finalize();
    let keccak256_result = keccak256_hasher.finalize();

    // Empty input should not produce all-zero output
    assert!(
        !sha3_224_result.iter().all(|&x| x == 0),
        "SHA3-224 empty input should not produce all zeros"
    );
    assert!(
        !sha3_256_result.iter().all(|&x| x == 0),
        "SHA3-256 empty input should not produce all zeros"
    );
    assert!(
        !sha3_384_result.iter().all(|&x| x == 0),
        "SHA3-384 empty input should not produce all zeros"
    );
    assert!(
        !sha3_512_result.iter().all(|&x| x == 0),
        "SHA3-512 empty input should not produce all zeros"
    );
    assert!(
        !keccak256_result.iter().all(|&x| x == 0),
        "Keccak256 empty input should not produce all zeros"
    );
}

/// Test that hash operations handle large inputs correctly
#[test]
fn test_large_input_handling() {
    let large_input = vec![0x42u8; 1000000]; // 1MB input

    let mut sha3_224_hasher = Sha3_224::new();
    let mut sha3_256_hasher = Sha3_256::new();
    let mut sha3_384_hasher = Sha3_384::new();
    let mut sha3_512_hasher = Sha3_512::new();
    let mut keccak256_hasher = Keccak256::new();

    sha3_224_hasher.update(&large_input);
    sha3_256_hasher.update(&large_input);
    sha3_384_hasher.update(&large_input);
    sha3_512_hasher.update(&large_input);
    keccak256_hasher.update(&large_input);

    let sha3_224_result = sha3_224_hasher.finalize();
    let sha3_256_result = sha3_256_hasher.finalize();
    let sha3_384_result = sha3_384_hasher.finalize();
    let sha3_512_result = sha3_512_hasher.finalize();
    let keccak256_result = keccak256_hasher.finalize();

    // Large input should produce valid hash outputs
    assert_eq!(
        sha3_224_result.len(),
        28,
        "SHA3-224 large input should produce 28 bytes"
    );
    assert_eq!(
        sha3_256_result.len(),
        32,
        "SHA3-256 large input should produce 32 bytes"
    );
    assert_eq!(
        sha3_384_result.len(),
        48,
        "SHA3-384 large input should produce 48 bytes"
    );
    assert_eq!(
        sha3_512_result.len(),
        64,
        "SHA3-512 large input should produce 64 bytes"
    );
    assert_eq!(
        keccak256_result.len(),
        32,
        "Keccak256 large input should produce 32 bytes"
    );
}

/// Test that hash operations are idempotent (multiple updates produce same result)
#[test]
fn test_hash_idempotency() {
    let input1 = b"first part";
    let input2 = b"second part";
    let combined_input = b"first partsecond part";

    // Hash combined input
    let mut combined_hasher = Sha3_256::new();
    combined_hasher.update(combined_input);
    let combined_result = combined_hasher.finalize();

    // Hash parts separately
    let mut parts_hasher = Sha3_256::new();
    parts_hasher.update(input1);
    parts_hasher.update(input2);
    let parts_result = parts_hasher.finalize();

    // Results should be identical
    assert_eq!(
        combined_result, parts_result,
        "Hash should be idempotent for multiple updates"
    );
}

/// Test that hash operations handle repeated inputs correctly
#[test]
fn test_repeated_input_handling() {
    let input = b"test input";
    let repeated_input = b"test inputtest inputtest input";

    // Hash repeated input
    let mut repeated_hasher = Sha3_256::new();
    repeated_hasher.update(repeated_input);
    let repeated_result = repeated_hasher.finalize();

    // Hash input three times separately
    let mut separate_hasher = Sha3_256::new();
    separate_hasher.update(input);
    separate_hasher.update(input);
    separate_hasher.update(input);
    let separate_result = separate_hasher.finalize();

    // Results should be identical
    assert_eq!(
        repeated_result, separate_result,
        "Hash should handle repeated inputs correctly"
    );
}

/// Test that hash operations don't produce predictable patterns
#[test]
fn test_no_predictable_patterns() {
    let test_inputs = [
        &[] as &[u8],
        b"a",
        b"aa",
        b"aaa",
        b"aaaa",
        b"aaaaa",
        b"aaaaaa",
        b"aaaaaaa",
        b"aaaaaaaa",
        b"aaaaaaaaa",
        b"aaaaaaaaaa",
    ];

    let mut results = Vec::new();

    for input in &test_inputs {
        let mut hasher = Sha3_256::new();
        hasher.update(input);
        let result = hasher.finalize();
        results.push(result);
    }

    // Check that consecutive results are not identical
    for i in 1..results.len() {
        assert_ne!(
            results[i - 1],
            results[i],
            "Consecutive hash results should not be identical"
        );
    }

    // Check that results don't follow a simple pattern
    for i in 2..results.len() {
        let diff1 = results[i - 1]
            .iter()
            .zip(results[i - 2].iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<_>>();
        let diff2 = results[i]
            .iter()
            .zip(results[i - 1].iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<_>>();
        assert_ne!(
            diff1, diff2,
            "Hash differences should not follow a predictable pattern"
        );
    }
}
