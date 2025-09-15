//! Comprehensive tests for the new modular architecture
//!
//! This module tests the new modular architecture including providers,
//! security validation, and context management.

use lib_q_core::api::{
    Algorithm,
    AlgorithmCategory,
    CryptoProvider,
};
use lib_q_core::providers::LibQCryptoProvider;
use lib_q_core::security::SecurityValidator;
use lib_q_core::traits::{
    AeadKey,
    Nonce,
};

/// Test the main LibQCryptoProvider
#[cfg(feature = "std")]
#[test]
fn test_libq_crypto_provider() {
    let provider = LibQCryptoProvider::new();
    assert!(
        provider.is_ok(),
        "LibQCryptoProvider should be created successfully"
    );

    let provider = provider.unwrap();

    // Test that all operation providers are available
    assert!(provider.kem().is_some(), "KEM provider should be available");
    assert!(
        provider.signature().is_some(),
        "Signature provider should be available"
    );
    assert!(
        provider.hash().is_some(),
        "Hash provider should be available"
    );
    assert!(
        provider.aead().is_some(),
        "AEAD provider should be available"
    );
}

/// Test security validator creation and basic functionality
#[cfg(feature = "std")]
#[test]
fn test_security_validator() {
    let validator = SecurityValidator::new();
    assert!(
        validator.is_ok(),
        "SecurityValidator should be created successfully"
    );

    let validator = validator.unwrap();

    // Test algorithm category validation
    let result = validator.validate_algorithm_category(Algorithm::MlKem512, AlgorithmCategory::Kem);
    assert!(result.is_ok(), "Should accept correct algorithm category");

    let result =
        validator.validate_algorithm_category(Algorithm::MlKem512, AlgorithmCategory::Signature);
    assert!(
        result.is_err(),
        "Should reject incorrect algorithm category"
    );
}

/// Test key material validation
#[cfg(feature = "std")]
#[test]
fn test_key_material_validation() {
    let validator = SecurityValidator::new().unwrap();

    // Test valid key (use a more realistic key that passes entropy validation)
    let valid_key = vec![
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F,
        0x3C,
    ];
    let result = validator.validate_key_material(&valid_key);
    assert!(result.is_ok(), "Should accept valid key material");

    // Test zero key
    let zero_key = vec![0u8; 16];
    let result = validator.validate_key_material(&zero_key);
    assert!(result.is_err(), "Should reject zero key");

    // Test all-ones key
    let ones_key = vec![0xFFu8; 16];
    let result = validator.validate_key_material(&ones_key);
    assert!(result.is_err(), "Should reject all-ones key");

    // Test empty key
    let empty_key = vec![];
    let result = validator.validate_key_material(&empty_key);
    assert!(result.is_err(), "Should reject empty key");
}

/// Test message validation
#[cfg(feature = "std")]
#[test]
fn test_message_validation() {
    let validator = SecurityValidator::new().unwrap();

    // Test valid message
    let valid_message = vec![1u8; 1000];
    let result = validator.validate_message(&valid_message);
    assert!(result.is_ok(), "Should accept valid message size");

    // Test oversized message
    let oversized_message = vec![1u8; 2 * 1024 * 1024]; // 2MB
    let result = validator.validate_message(&oversized_message);
    assert!(result.is_err(), "Should reject oversized message");
}

/// Test nonce validation
#[cfg(feature = "std")]
#[test]
fn test_nonce_validation() {
    let validator = SecurityValidator::new().unwrap();

    // Test valid nonce
    let valid_nonce = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let result = validator.validate_nonce(&valid_nonce);
    assert!(result.is_ok(), "Should accept valid nonce");

    // Test wrong size nonce
    let wrong_size_nonce = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let result = validator.validate_nonce(&wrong_size_nonce);
    assert!(result.is_err(), "Should reject wrong size nonce");

    // Test zero nonce
    let zero_nonce = vec![0u8; 16];
    let result = validator.validate_nonce(&zero_nonce);
    assert!(result.is_err(), "Should reject zero nonce");
}

/// Test constant-time comparison
#[cfg(feature = "std")]
#[test]
fn test_constant_time_compare() {
    let validator = SecurityValidator::new().unwrap();

    // Test equal slices
    let a = vec![1, 2, 3, 4];
    let b = vec![1, 2, 3, 4];
    assert!(
        validator.constant_time_compare(&a, &b),
        "Should return true for equal slices"
    );

    // Test different slices
    let c = vec![1, 2, 3, 5];
    assert!(
        !validator.constant_time_compare(&a, &c),
        "Should return false for different slices"
    );

    // Test different length slices
    let d = vec![1, 2, 3];
    assert!(
        !validator.constant_time_compare(&a, &d),
        "Should return false for different length slices"
    );
}

/// Test KEM provider with unsupported algorithms
#[cfg(feature = "std")]
#[test]
fn test_kem_provider_unsupported_algorithm() {
    let provider = LibQCryptoProvider::new().unwrap();
    let kem_provider = provider.kem().unwrap();

    // Test unsupported algorithm
    let result = kem_provider.generate_keypair(Algorithm::Sha3_256, None);
    assert!(
        result.is_err(),
        "Should return error for unsupported algorithm"
    );

    if let Err(lib_q_core::error::Error::InvalidAlgorithm { .. }) = result {
        // Expected error type
    } else {
        panic!("Expected InvalidAlgorithm error");
    }
}

/// Test signature provider with unsupported algorithms
#[cfg(feature = "std")]
#[test]
fn test_signature_provider_unsupported_algorithm() {
    let provider = LibQCryptoProvider::new().unwrap();
    let sig_provider = provider.signature().unwrap();

    // Test unsupported algorithm
    let result = sig_provider.generate_keypair(Algorithm::Sha3_256, None);
    assert!(
        result.is_err(),
        "Should return error for unsupported algorithm"
    );

    if let Err(lib_q_core::error::Error::InvalidAlgorithm { .. }) = result {
        // Expected error type
    } else {
        panic!("Expected InvalidAlgorithm error");
    }
}

/// Test hash provider with unsupported algorithms
#[cfg(feature = "std")]
#[test]
fn test_hash_provider_unsupported_algorithm() {
    let provider = LibQCryptoProvider::new().unwrap();
    let hash_provider = provider.hash().unwrap();

    // Test unsupported algorithm
    let result = hash_provider.hash(Algorithm::MlKem512, b"test data");
    assert!(
        result.is_err(),
        "Should return error for unsupported algorithm"
    );

    if let Err(lib_q_core::error::Error::InvalidAlgorithm { .. }) = result {
        // Expected error type
    } else {
        panic!("Expected InvalidAlgorithm error");
    }
}

/// Test AEAD provider with unsupported algorithms
#[cfg(feature = "std")]
#[test]
fn test_aead_provider_unsupported_algorithm() {
    let provider = LibQCryptoProvider::new().unwrap();
    let aead_provider = provider.aead().unwrap();

    let key = AeadKey::new(vec![0u8; 32]);
    let nonce = Nonce::new(vec![0u8; 16]);

    // Test unsupported algorithm
    let result = aead_provider.encrypt(Algorithm::MlKem512, &key, &nonce, b"test", None);
    assert!(
        result.is_err(),
        "Should return error for unsupported algorithm"
    );

    if let Err(lib_q_core::error::Error::InvalidAlgorithm { .. }) = result {
        // Expected error type
    } else {
        panic!("Expected InvalidAlgorithm error");
    }
}

/// Test feature flag handling
#[cfg(feature = "std")]
#[test]
fn test_feature_flag_handling() {
    let provider = LibQCryptoProvider::new().unwrap();
    let kem_provider = provider.kem().unwrap();

    // Test ML-KEM without feature flag (should return NotImplemented with feature flag message)
    let result = kem_provider.generate_keypair(Algorithm::MlKem512, None);
    assert!(
        result.is_err(),
        "Should return error when feature flag is not enabled"
    );

    if let Err(lib_q_core::error::Error::NotImplemented { feature }) = result {
        assert!(
            feature.contains("ML-KEM implementations are provided by the main lib-q crate"),
            "Error should mention that implementations are provided by main lib-q crate"
        );
    } else {
        panic!("Expected NotImplemented error");
    }
}

/// Test provider pattern integration
#[cfg(feature = "std")]
#[test]
fn test_provider_pattern_integration() {
    let provider = LibQCryptoProvider::new().unwrap();

    // Test that the provider implements CryptoProvider trait
    assert!(provider.kem().is_some());
    assert!(provider.signature().is_some());
    assert!(provider.hash().is_some());
    assert!(provider.aead().is_some());

    // Test that we can get references to the operation providers
    let kem_ops = provider.kem().unwrap();
    let sig_ops = provider.signature().unwrap();
    let hash_ops = provider.hash().unwrap();
    let aead_ops = provider.aead().unwrap();

    // Test that the operation providers implement their respective traits
    // (This is tested by the fact that we can call methods on them)
    let _ = kem_ops.generate_keypair(Algorithm::MlKem512, None);
    let _ = sig_ops.generate_keypair(Algorithm::MlDsa65, None);
    let _ = hash_ops.hash(Algorithm::Sha3_256, b"test");
    let _ = aead_ops.encrypt(
        Algorithm::Saturnin,
        &AeadKey::new(vec![0u8; 32]),
        &Nonce::new(vec![0u8; 16]),
        b"test",
        None,
    );
}

/// Test security validation integration
#[cfg(feature = "std")]
#[test]
fn test_security_validation_integration() {
    let provider = LibQCryptoProvider::new().unwrap();
    let kem_provider = provider.kem().unwrap();

    // Test that security validation is integrated into operations
    // This should fail due to invalid algorithm category
    let result = kem_provider.generate_keypair(Algorithm::Sha3_256, None);
    assert!(result.is_err(), "Should fail due to security validation");

    // Test that proper error types are returned
    if let Err(lib_q_core::error::Error::InvalidAlgorithm { .. }) = result {
        // Expected error type from security validation
    } else {
        panic!("Expected InvalidAlgorithm error from security validation");
    }
}

/// Test error handling consistency
#[cfg(feature = "std")]
#[test]
fn test_error_handling_consistency() {
    let provider = LibQCryptoProvider::new().unwrap();
    let kem_provider = provider.kem().unwrap();

    // Test that all providers return consistent error types
    let kem_result = kem_provider.generate_keypair(Algorithm::Sha3_256, None);
    let sig_result = provider
        .signature()
        .unwrap()
        .generate_keypair(Algorithm::Sha3_256, None);
    let hash_result = provider.hash().unwrap().hash(Algorithm::MlKem512, b"test");

    // All should return InvalidAlgorithm errors
    assert!(matches!(
        kem_result,
        Err(lib_q_core::error::Error::InvalidAlgorithm { .. })
    ));
    assert!(matches!(
        sig_result,
        Err(lib_q_core::error::Error::InvalidAlgorithm { .. })
    ));
    assert!(matches!(
        hash_result,
        Err(lib_q_core::error::Error::InvalidAlgorithm { .. })
    ));
}

/// Test modular architecture benefits
#[cfg(feature = "std")]
#[test]
fn test_modular_architecture_benefits() {
    // Test that we can create individual components
    let validator = SecurityValidator::new().unwrap();
    let provider = LibQCryptoProvider::new().unwrap();

    // Test that components work independently
    let valid_key = vec![
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F,
        0x3C,
    ];
    assert!(validator.validate_key_material(&valid_key).is_ok());
    assert!(provider.kem().is_some());

    // Test that components can be used together
    let kem_provider = provider.kem().unwrap();
    let result = kem_provider.generate_keypair(Algorithm::MlKem512, None);
    // Should fail due to feature flag, but the integration should work
    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(lib_q_core::error::Error::NotImplemented { .. })
    ));
}
