//! Tests for HQC Reference Implementation in lib-q-random
//!
//! These tests verify that lib-q-random RNGs work correctly with HQC-style
//! polynomial and cryptographic operations using the reference implementation
//! in tests/common/hqc_reference.rs

// Import common test utilities
#[path = "common/mod.rs"]
mod common;

#[cfg(feature = "hqc")]
mod hqc_tests {
    use lib_q_random::LibQRng;

    use super::common::hqc_reference::*;

    /// Test polynomial multiplication in GF(2)
    #[test]
    fn test_polynomial_multiply() {
        let a = [0b1010u8, 0b0101]; // x^3 + x, x^2 + 1
        let b = [0b1100u8, 0b0011]; // x^3 + x^2, x + 1
        let mut result = [0u8; 4];

        let res = polynomial_multiply(&mut result, &a, &b);
        assert!(res.is_ok());

        // Verify result is not all zeros (should have some non-zero coefficients)
        assert!(result.iter().any(|&x| x != 0));
    }

    /// Test polynomial random weight generation
    #[test]
    fn test_polynomial_random_weight() {
        let mut rng = LibQRng::new_deterministic(&[42u8; 32]);
        let mut result = [0u8; 16];
        let weight = 5;

        let res = polynomial_random_weight(&mut result, weight, &mut rng);
        assert!(res.is_ok());

        // Count the number of set bits
        let mut bit_count = 0;
        for &byte in &result {
            bit_count += byte.count_ones();
        }

        // Should have approximately the requested weight
        assert!(bit_count <= (weight * 2) as u32); // Allow some variance
        assert!(bit_count > 0); // Should have at least some bits set
    }

    /// Test matrix-vector multiplication
    #[test]
    fn test_matrix_vector_multiply() {
        let matrix = vec![vec![1u8, 2, 3], vec![4u8, 5, 6], vec![7u8, 8, 9]];
        let vector = [1u8, 2, 3];
        let mut result = [0u8; 3];

        let res = matrix_vector_multiply(&mut result, &matrix, &vector);
        assert!(res.is_ok());

        // Verify result is not all zeros
        assert!(result.iter().any(|&x| x != 0));
    }

    /// Test tensor code encoding
    #[test]
    fn test_tensor_code_encode() {
        let message = [1u8, 2, 3, 4, 5];
        let mut codeword = [0u8; 10];

        let res = tensor_code_encode(&mut codeword, &message);
        assert!(res.is_ok());

        // Verify codeword is not all zeros
        assert!(codeword.iter().any(|&x| x != 0));
    }

    /// Test tensor code decoding
    #[test]
    fn test_tensor_code_decode() {
        let codeword = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut message = [0u8; 5];

        let res = tensor_code_decode(&mut message, &codeword);
        assert!(res.is_ok());

        // Verify message is not all zeros
        assert!(message.iter().any(|&x| x != 0));
    }

    /// Test round-trip encoding/decoding
    #[test]
    fn test_tensor_code_roundtrip() {
        let original_message = [1u8, 2, 3, 4, 5];
        let mut codeword = [0u8; 10];
        let mut decoded_message = [0u8; 5];

        // Encode
        let res1 = tensor_code_encode(&mut codeword, &original_message);
        assert!(res1.is_ok());

        // Decode
        let res2 = tensor_code_decode(&mut decoded_message, &codeword);
        assert!(res2.is_ok());

        // Should match original (for simple implementation)
        assert_eq!(original_message, decoded_message);
    }

    /// Test HQC key generation
    #[test]
    fn test_hqc_keygen() {
        let mut rng = LibQRng::new_deterministic(&[42u8; 32]);
        let mut public_key = [0u8; 100];
        let mut secret_key = [0u8; 100];

        let res = hqc_keygen(&mut public_key, &mut secret_key, &mut rng);
        assert!(res.is_ok());

        // Keys should not be all zeros
        assert!(public_key.iter().any(|&x| x != 0));
        assert!(secret_key.iter().any(|&x| x != 0));

        // Keys should be different
        assert_ne!(public_key, secret_key);
    }

    /// Test HQC encryption
    #[test]
    fn test_hqc_encrypt() {
        let mut rng = LibQRng::new_deterministic(&[42u8; 32]);
        let message = [1u8, 2, 3, 4, 5];
        let public_key = [1u8; 100];
        let mut ciphertext = [0u8; 200];

        let res = hqc_encrypt(&mut ciphertext, &message, &public_key, &mut rng);
        assert!(res.is_ok());

        // Ciphertext should not be all zeros
        assert!(ciphertext.iter().any(|&x| x != 0));
    }

    /// Test HQC decryption
    #[test]
    fn test_hqc_decrypt() {
        let ciphertext = [1u8, 2, 3, 4, 5];
        let secret_key = [5u8, 4, 3, 2, 1];
        let mut message = [0u8; 5];

        let res = hqc_decrypt(&mut message, &ciphertext, &secret_key);
        assert!(res.is_ok());

        // The simplified implementation XORs: ciphertext XOR secret_key
        // Expected: [1^5, 2^4, 3^3, 4^2, 5^1] = [4, 6, 0, 6, 4]
        assert_eq!(message, [4, 6, 0, 6, 4]);
    }

    /// Test deterministic behavior with same seeds
    #[test]
    fn test_deterministic_behavior() {
        let seed = [123u8; 32];

        // Test polynomial random weight
        let mut rng1 = LibQRng::new_deterministic(&seed);
        let mut rng2 = LibQRng::new_deterministic(&seed);

        let mut result1 = [0u8; 16];
        let mut result2 = [0u8; 16];

        let res1 = polynomial_random_weight(&mut result1, 5, &mut rng1);
        let res2 = polynomial_random_weight(&mut result2, 5, &mut rng2);

        assert!(res1.is_ok());
        assert!(res2.is_ok());
        assert_eq!(result1, result2);
    }

    /// Test error handling with invalid inputs
    #[test]
    fn test_error_handling() {
        let mut rng = LibQRng::new_deterministic(&[42u8; 32]);

        // Test with zero weight
        let mut result = [0u8; 16];
        let res = polynomial_random_weight(&mut result, 0, &mut rng);
        assert!(res.is_ok());

        // Test with weight larger than bit length
        let res = polynomial_random_weight(&mut result, 200, &mut rng);
        assert!(res.is_ok()); // Should handle gracefully

        // Test with empty arrays
        let empty = [];
        let mut empty_result = [];
        let res = polynomial_multiply(&mut empty_result, &empty, &empty);
        assert!(res.is_ok());
    }

    /// Test security properties
    #[test]
    fn test_security_properties() {
        // Test that different seeds produce different results
        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];

        let mut rng1 = LibQRng::new_deterministic(&seed1);
        let mut rng2 = LibQRng::new_deterministic(&seed2);

        let mut result1 = [0u8; 16];
        let mut result2 = [0u8; 16];

        let res1 = polynomial_random_weight(&mut result1, 5, &mut rng1);
        let res2 = polynomial_random_weight(&mut result2, 5, &mut rng2);

        assert!(res1.is_ok());
        assert!(res2.is_ok());
        assert_ne!(result1, result2);
    }

    /// Test performance with larger inputs
    #[test]
    fn test_performance_large_inputs() {
        let mut rng = LibQRng::new_deterministic(&[42u8; 32]);

        // Test with larger polynomial
        let mut result = [0u8; 256];
        let res = polynomial_random_weight(&mut result, 50, &mut rng);
        assert!(res.is_ok());

        // Test with larger matrix
        let matrix = vec![vec![1u8; 64]; 64];
        let vector = [1u8; 64];
        let mut result = [0u8; 64];

        let res = matrix_vector_multiply(&mut result, &matrix, &vector);
        assert!(res.is_ok());
    }

    /// Test edge cases
    #[test]
    fn test_edge_cases() {
        let mut rng = LibQRng::new_deterministic(&[42u8; 32]);

        // Test with single byte
        let mut result = [0u8; 1];
        let res = polynomial_random_weight(&mut result, 1, &mut rng);
        assert!(res.is_ok());

        // Test with maximum weight
        let mut result = [0u8; 8];
        let res = polynomial_random_weight(&mut result, 64, &mut rng);
        assert!(res.is_ok());

        // Test with mismatched sizes
        let a = [1u8, 2];
        let b = [3u8, 4, 5];
        let mut result = [0u8; 4];

        let res = polynomial_multiply(&mut result, &a, &b);
        assert!(res.is_ok());
    }
}
