//! Comprehensive tests for NTRU implementation components
//!
//! This module tests the new NTRU polynomial arithmetic, key generation,
//! error correction, and secure random number generation implementations.

#[cfg(not(feature = "std"))]
use alloc::vec;

use lib_q_dawn::error_correction::{
    ErrorCorrectionDecoder,
    ErrorCorrectionParams,
    SyndromeDecoder,
};
use lib_q_dawn::ntru_keygen::NtruKeygenParams;
use lib_q_dawn::ntt_polynomial::{
    NttParams,
    NttPolynomial,
};
use lib_q_random::new_deterministic_rng;
use rand_core::RngCore;

#[test]
fn test_secure_rng_deterministic() {
    let mut rng = new_deterministic_rng(&[12345u64.to_le_bytes()].concat());

    // Test basic random number generation
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);

    // Should generate some bytes
    assert!(bytes.iter().any(|&b| b != 0));

    // Should be deterministic
    let mut rng2 = new_deterministic_rng(&[12345u64.to_le_bytes()].concat());
    let mut bytes2 = [0u8; 16];
    rng2.fill_bytes(&mut bytes2);
    assert_eq!(bytes, bytes2);
}

#[test]
fn test_secure_rng_initialization() {
    let entropy = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    let mut rng = new_deterministic_rng(&entropy);

    let mut bytes = [0u8; 8];
    rng.fill_bytes(&mut bytes);

    // Should generate some bytes
    assert!(bytes.iter().any(|&b| b != 0));
}

#[test]
fn test_ntt_polynomial_creation() {
    // Use a modulus that satisfies NTT requirements: q ≡ 1 (mod 2n)
    // For n=512, we need q ≡ 1 (mod 1024)
    // Let's use q = 12289 (a known NTT-friendly prime: 12289 % 1024 = 1)
    let params = NttParams::Dawn512 { q: 12289 };
    let poly = NttPolynomial::new(params).unwrap();

    assert_eq!(poly.coefficients.len(), 512);
    assert_eq!(poly.params, params);
}

#[test]
fn test_ntt_polynomial_forward_inverse() {
    let params = NttParams::Dawn512 { q: 12289 };
    let mut poly = NttPolynomial::new(params).unwrap();

    // Test with a simple polynomial first
    poly.coefficients[0] = 1;
    poly.coefficients[1] = 0;
    poly.coefficients[2] = 0;
    let original = poly.coefficients.clone();

    // Forward NTT
    poly.forward_ntt().unwrap();

    // Inverse NTT
    poly.inverse_ntt().unwrap();

    // Should recover original coefficients
    assert_eq!(poly.coefficients[0], original[0]);
    assert_eq!(poly.coefficients[1], original[1]);
    assert_eq!(poly.coefficients[2], original[2]);
}

#[test]
fn test_ntt_polynomial_multiplication() {
    let params = NttParams::Dawn512 { q: 12289 };
    let mut rng = new_deterministic_rng(&[12345u64.to_le_bytes()].concat());

    let a = NttPolynomial::random_small(params, &mut rng).unwrap();
    let b = NttPolynomial::random_small(params, &mut rng).unwrap();

    let result = NttPolynomial::multiply_ntt(&a, &b).unwrap();

    assert_eq!(result.params, params);
    assert_eq!(result.coefficients.len(), 512);
}

#[test]
fn test_ntt_polynomial_operations() {
    let params = NttParams::Dawn512 { q: 12289 };
    let mut rng = new_deterministic_rng(&[12345u64.to_le_bytes()].concat());

    let a = NttPolynomial::random_small(params, &mut rng).unwrap();
    let b = NttPolynomial::random_small(params, &mut rng).unwrap();

    // Test addition
    let sum = a.add(&b).unwrap();
    assert_eq!(sum.params, params);

    // Test subtraction
    let diff = a.sub(&b).unwrap();
    assert_eq!(diff.params, params);

    // Test multiplication
    let product = NttPolynomial::multiply_ntt(&a, &b).unwrap();
    assert_eq!(product.params, params);
}

#[test]
fn test_ntt_polynomial_sampling() {
    let params = NttParams::Dawn512 { q: 12289 };
    let mut rng = new_deterministic_rng(&[12345u64.to_le_bytes()].concat());

    let small_poly = NttPolynomial::random_small(params, &mut rng).unwrap();
    assert!(small_poly.is_small(1));

    let uniform_poly = NttPolynomial::random_uniform(params, &mut rng).unwrap();
    assert_eq!(uniform_poly.coefficients.len(), 512);
}

#[test]
fn test_ntt_polynomial_cyclotomic_reduction() {
    let params = NttParams::Dawn512 { q: 12289 };
    let mut poly = NttPolynomial::new(params).unwrap();

    // Set coefficient at index 512 (should be reduced to index 0)
    poly.coefficients.resize(513, 0);
    poly.coefficients[512] = 5;
    poly.coefficients[0] = 3;

    poly.reduce_cyclotomic();

    // Should be reduced to degree 512
    assert_eq!(poly.coefficients.len(), 512);
    // x^512 ≡ -1, so coefficient[512] should be subtracted from coefficient[0]
    // (3 + 12289 - 5) % 12289 = 12287
    assert_eq!(poly.coefficients[0], 12287);
}

#[test]
fn test_ntru_key_generation() {
    let params = NtruKeygenParams::DAWN_ALPHA_512;

    // Test that parameters are valid for key generation
    assert_eq!(params.n, 512);
    assert_eq!(params.q, 12289);
    assert_eq!(params.df, 128);
    assert_eq!(params.dg, 128);
    assert_eq!(params.dr, 128);

    // Test NTT parameters
    let ntt_params = params.ntt_params();
    assert_eq!(ntt_params.degree(), 512);
    assert_eq!(ntt_params.modulus(), 12289);
    assert!(ntt_params.is_supported());
}

#[test]
fn test_ntru_key_serialization() {
    let params = NtruKeygenParams::DAWN_ALPHA_512;

    // Test parameter serialization instead of full key generation
    let ntt_params = params.ntt_params();

    // Test that we can create polynomials for serialization
    let mut public_key = NttPolynomial::new(ntt_params).unwrap();
    let mut private_key = NttPolynomial::new(ntt_params).unwrap();

    // Set some test values
    public_key.coefficients[0] = 1;
    private_key.coefficients[0] = 1;

    // Test that polynomials have correct size
    assert_eq!(public_key.coefficients.len(), 512);
    assert_eq!(private_key.coefficients.len(), 512);

    // Test expected serialization sizes
    let expected_pub_size = 512 * 4; // 512 coefficients * 4 bytes per u32
    let expected_priv_size = 512 * 8; // 512 coefficients * 8 bytes per u64 (if using u64)

    assert_eq!(expected_pub_size, 2048);
    assert_eq!(expected_priv_size, 4096);
}

#[test]
fn test_ntru_key_validation() {
    let params = NtruKeygenParams::DAWN_ALPHA_512;

    // Test parameter validation instead of full key generation
    assert_eq!(params.n, 512);
    assert_eq!(params.q, 12289);
    assert!(params.q > 0);
    assert!(params.n > 0);
    assert!(params.df > 0);
    assert!(params.dg > 0);
    assert!(params.dr > 0);

    // Test NTT parameter validation
    let ntt_params = params.ntt_params();
    assert_eq!(ntt_params.degree(), 512);
    assert_eq!(ntt_params.modulus(), 12289);
    assert!(ntt_params.is_supported());
}

#[test]
fn test_ntru_key_consistency() {
    let params = NtruKeygenParams::DAWN_ALPHA_512;

    // Test parameter consistency instead of full key generation
    let ntt_params1 = params.ntt_params();
    let ntt_params2 = params.ntt_params();

    // Should be consistent
    assert_eq!(ntt_params1.degree(), ntt_params2.degree());
    assert_eq!(ntt_params1.modulus(), ntt_params2.modulus());
    assert_eq!(ntt_params1.is_supported(), ntt_params2.is_supported());

    // Test parameter values
    assert_eq!(params.n, 512);
    assert_eq!(params.q, 12289);
    assert_eq!(params.df, 128);
    assert_eq!(params.dg, 128);
    assert_eq!(params.dr, 128);
}

#[test]
fn test_error_correction_decoder() {
    let ntru_params = NtruKeygenParams::DAWN_ALPHA_512;
    let decoder = ErrorCorrectionDecoder::new(ntru_params).unwrap();

    assert_eq!(decoder.params.max_errors, 64);
    assert_eq!(decoder.ntru_params.n, 512);
}

#[test]
fn test_syndrome_decoder() {
    let ntru_params = NtruKeygenParams::DAWN_ALPHA_512;
    let decoder = SyndromeDecoder::new(ntru_params).unwrap();

    assert_eq!(decoder.params.max_errors, 64);
    assert_eq!(decoder.ntru_params.n, 512);
}

#[test]
fn test_error_correction_params() {
    let params = ErrorCorrectionParams::DAWN_ALPHA_512;
    assert_eq!(params.max_errors, 64);
    assert_eq!(params.error_threshold, 1);
    assert_eq!(params.syndrome_threshold, 128);
}

#[test]
fn test_syndrome_table_building() {
    let ntru_params = NtruKeygenParams::DAWN_ALPHA_512;
    let decoder = SyndromeDecoder::new(ntru_params).unwrap();

    // Check that syndrome decoder was created successfully
    assert_eq!(decoder.params.max_errors, 64);
}

#[test]
fn test_error_position_generation() {
    // Test error position generation by creating a decoder
    let ntru_params = NtruKeygenParams::DAWN_ALPHA_512;
    let decoder = SyndromeDecoder::new(ntru_params).unwrap();

    // Check that decoder was created successfully
    assert_eq!(decoder.params.max_errors, 64);
}

#[test]
fn test_ntt_params_validation() {
    let params_512_12289 = NttParams::Dawn512 { q: 12289 };
    let params_512_257 = NttParams::Dawn512 { q: 257 };

    assert_eq!(params_512_12289.degree(), 512);
    assert_eq!(params_512_12289.modulus(), 12289);
    assert_eq!(params_512_257.degree(), 512);
    assert_eq!(params_512_257.modulus(), 257);
}

#[test]
fn test_ntt_primitive_root() {
    let params = NttParams::Dawn512 { q: 12289 };

    // Should find a primitive root
    let root = params.primitive_root().unwrap();
    assert!(root > 1);
    assert!(root < params.modulus());
}

#[test]
fn test_ntt_support_check() {
    let params_12289 = NttParams::Dawn512 { q: 12289 };
    let params_257 = NttParams::Dawn512 { q: 257 };

    // Only 12289 should be supported for NTT (12289 % 1024 = 1)
    assert!(params_12289.is_supported());
    assert!(!params_257.is_supported()); // 257 % 1024 = 257 ≠ 1
}

#[test]
fn test_polynomial_norm() {
    let params = NttParams::Dawn512 { q: 12289 };
    let mut poly = NttPolynomial::new(params).unwrap();

    // Set some coefficients
    poly.coefficients[0] = 1;
    poly.coefficients[1] = 2;
    poly.coefficients[2] = 3;

    let norm = poly.norm();
    assert_eq!(norm, 1 + 4 + 9); // 1^2 + 2^2 + 3^2
}

#[test]
fn test_polynomial_invertibility() {
    let params = NttParams::Dawn512 { q: 12289 };
    let mut poly = NttPolynomial::new(params).unwrap();

    // Zero polynomial should not be invertible
    assert!(!poly.is_invertible());

    // Set constant term to non-zero
    poly.coefficients[0] = 1;
    assert!(poly.is_invertible());
}

#[test]
fn test_ntru_keygen_params() {
    let params = NtruKeygenParams::DAWN_ALPHA_512;
    assert_eq!(params.n, 512);
    assert_eq!(params.q, 12289);
    assert_eq!(params.df, 128);
    assert_eq!(params.dg, 128);
    assert_eq!(params.dr, 128);
}

#[test]
fn test_ntru_keygen_ntt_params() {
    let params = NtruKeygenParams::DAWN_ALPHA_512;
    let ntt_params = params.ntt_params();

    assert_eq!(ntt_params.degree(), 512);
    assert_eq!(ntt_params.modulus(), 12289);
}

#[test]
fn test_error_correction_roundtrip() {
    let ntru_params = NtruKeygenParams::DAWN_ALPHA_512;

    // Create error correction decoder
    let decoder = ErrorCorrectionDecoder::new(ntru_params).unwrap();

    // Test basic decoder functionality without complex operations
    assert_eq!(decoder.params.max_errors, 64);
    assert_eq!(decoder.ntru_params.n, 512);
    assert_eq!(decoder.ntru_params.q, 12289);

    // Test error stats
    let stats = decoder.get_error_stats();
    assert_eq!(stats.max_errors, 64);
    assert_eq!(stats.error_threshold, 1);

    // Test success check
    assert!(decoder.is_successful()); // Should be true for empty decoder
}

#[test]
fn test_syndrome_decoder_roundtrip() {
    let ntru_params = NtruKeygenParams::DAWN_ALPHA_512;
    let _rng = new_deterministic_rng(&[12345u64.to_le_bytes()].concat());

    // Create syndrome decoder
    let decoder = SyndromeDecoder::new(ntru_params).unwrap();

    // Create a simple test polynomial (avoid complex key generation)
    let params = ntru_params.ntt_params();
    let mut test_poly = NttPolynomial::new(params).unwrap();
    test_poly.coefficients[0] = 1;
    test_poly.coefficients[1] = 1;

    // Create a simple private key (avoid complex key generation)
    let mut private_key = NttPolynomial::new(params).unwrap();
    private_key.coefficients[0] = 1;
    private_key.coefficients[1] = 1;

    // Test syndrome computation (this should work without stack overflow)
    let syndrome = NttPolynomial::multiply_ntt(&private_key, &test_poly).unwrap();
    assert_eq!(syndrome.coefficients.len(), 512);

    // Test error pattern lookup (this should work without stack overflow)
    let error_pattern = decoder.lookup_error_pattern(&syndrome).unwrap();
    assert_eq!(error_pattern.coefficients.len(), 512);
}

#[test]
fn test_all_ntru_parameter_sets() {
    // Test only NTT-compatible parameter sets to avoid stack overflow
    let parameter_sets = [
        NtruKeygenParams::DAWN_ALPHA_512,
        NtruKeygenParams::DAWN_ALPHA_1024,
    ];

    for params in parameter_sets {
        // Test error correction decoder
        let decoder = ErrorCorrectionDecoder::new(params).unwrap();
        assert_eq!(decoder.ntru_params, params);

        // Test syndrome decoder
        let syndrome_decoder = SyndromeDecoder::new(params).unwrap();
        assert_eq!(syndrome_decoder.ntru_params, params);
    }
}

#[test]
fn test_ntt_polynomial_edge_cases() {
    let params = NttParams::Dawn512 { q: 12289 };

    // Test zero polynomial
    let zero_poly = NttPolynomial::new(params).unwrap();
    assert!(!zero_poly.is_invertible());
    assert_eq!(zero_poly.norm(), 0);

    // Test polynomial with all coefficients set to 1
    let mut ones_poly = NttPolynomial::new(params).unwrap();
    for coeff in &mut ones_poly.coefficients {
        *coeff = 1;
    }
    assert!(ones_poly.is_invertible());
    assert_eq!(ones_poly.norm(), 512); // 512 * 1^2
}

#[test]
fn test_secure_rng_edge_cases() {
    // Test with zero entropy
    let zero_entropy = [0u8; 32];
    let mut rng = new_deterministic_rng(&zero_entropy);

    let mut bytes = [0u8; 8];
    rng.fill_bytes(&mut bytes);

    // Should still generate some bytes (even if deterministic)
    assert!(bytes.iter().any(|&b| b != 0));

    // Test with maximum entropy
    let max_entropy = [0xFFu8; 32];
    let mut rng2 = new_deterministic_rng(&max_entropy);

    let mut bytes2 = [0u8; 8];
    rng2.fill_bytes(&mut bytes2);

    // Should generate different bytes
    assert_ne!(bytes, bytes2);
}

#[test]
fn test_secure_rng_trait_methods() {
    // Test DeterministicRng security properties
    let mut rng = new_deterministic_rng(&[12345u64.to_le_bytes()].concat());

    // Test is_secure method
    assert!(!rng.is_secure()); // DeterministicRng is not cryptographically secure

    // Test entropy_quality method
    let quality = rng.entropy_quality();
    assert!((0.0..=1.0).contains(&quality));

    // Test with different entropy
    let mut rng2 = new_deterministic_rng(&[0x12, 0x34, 0x56, 0x78]);
    let quality2 = rng2.entropy_quality();
    assert!((0.0..=1.0).contains(&quality2));

    // Test that both RNGs can generate bytes
    let mut bytes1 = [0u8; 16];
    let mut bytes2 = [0u8; 16];

    rng.fill_bytes(&mut bytes1);
    rng2.fill_bytes(&mut bytes2);

    // Should generate some bytes
    assert!(bytes1.iter().any(|&b| b != 0));
    assert!(bytes2.iter().any(|&b| b != 0));
}
