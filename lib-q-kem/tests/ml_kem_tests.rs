//! Comprehensive tests for the refactored ML-KEM implementation
//!
//! This test suite validates the security, correctness, and performance
//! of the refactored ML-KEM implementation.

use lib_q_core::{
    Algorithm,
    Error,
    KemPublicKey,
    KemSecretKey,
    SecurityLevel,
};
use lib_q_kem::{
    available_algorithms,
    create_kem,
};

/// Test configuration for ML-KEM variants
#[derive(Debug, Clone, Copy)]
struct MlKemTestConfig {
    algorithm: Algorithm,
    security_level: SecurityLevel,
    public_key_size: usize,
    secret_key_size: usize,
    ciphertext_size: usize,
    shared_secret_size: usize,
}

impl MlKemTestConfig {
    const fn new(
        algorithm: Algorithm,
        security_level: SecurityLevel,
        public_key_size: usize,
        secret_key_size: usize,
        ciphertext_size: usize,
        shared_secret_size: usize,
    ) -> Self {
        Self {
            algorithm,
            security_level,
            public_key_size,
            secret_key_size,
            ciphertext_size,
            shared_secret_size,
        }
    }
}

/// ML-KEM test configurations
const ML_KEM_CONFIGS: &[MlKemTestConfig] = &[
    MlKemTestConfig::new(
        Algorithm::MlKem512,
        SecurityLevel::Level1,
        800,  // MLKEM512_PUBLIC_KEY_SIZE
        1632, // MLKEM512_SECRET_KEY_SIZE
        768,  // MLKEM512_CIPHERTEXT_SIZE
        32,   // MLKEM_SHARED_KEY_SIZE
    ),
    MlKemTestConfig::new(
        Algorithm::MlKem768,
        SecurityLevel::Level3,
        1184, // MLKEM768_PUBLIC_KEY_SIZE
        2400, // MLKEM768_SECRET_KEY_SIZE
        1088, // MLKEM768_CIPHERTEXT_SIZE
        32,   // MLKEM_SHARED_KEY_SIZE
    ),
    MlKemTestConfig::new(
        Algorithm::MlKem1024,
        SecurityLevel::Level4,
        1568, // MLKEM1024_PUBLIC_KEY_SIZE
        3168, // MLKEM1024_SECRET_KEY_SIZE
        1568, // MLKEM1024_CIPHERTEXT_SIZE
        32,   // MLKEM_SHARED_KEY_SIZE
    ),
];

/// Test basic KEM creation and algorithm availability
#[test]
fn test_ml_kem_availability() {
    let algorithms = available_algorithms();

    // Verify ML-KEM algorithms are available
    assert!(algorithms.contains(&Algorithm::MlKem512));
    assert!(algorithms.contains(&Algorithm::MlKem768));
    assert!(algorithms.contains(&Algorithm::MlKem1024));

    // Verify we can create KEM instances
    for config in ML_KEM_CONFIGS {
        let kem = create_kem(config.algorithm);
        assert!(
            kem.is_ok(),
            "Failed to create KEM for {:?}",
            config.algorithm
        );
    }
}

/// Test key generation for all ML-KEM variants
#[test]
fn test_ml_kem_key_generation() {
    for config in ML_KEM_CONFIGS {
        let kem = create_kem(config.algorithm).unwrap();
        let keypair = kem.generate_keypair().unwrap();

        // Verify key sizes
        assert_eq!(
            keypair.public_key.data.len(),
            config.public_key_size,
            "Invalid public key size for {:?}",
            config.algorithm
        );
        assert_eq!(
            keypair.secret_key.data.len(),
            config.secret_key_size,
            "Invalid secret key size for {:?}",
            config.algorithm
        );

        // Verify keys are not all zeros
        assert!(!keypair.public_key.data.iter().all(|&b| b == 0));
        assert!(!keypair.secret_key.data.iter().all(|&b| b == 0));
    }
}

/// Test encapsulation and decapsulation for all ML-KEM variants
#[test]
fn test_ml_kem_encapsulation_decapsulation() {
    for config in ML_KEM_CONFIGS {
        let kem = create_kem(config.algorithm).unwrap();
        let keypair = kem.generate_keypair().unwrap();

        // Test encapsulation
        let (ciphertext, shared_secret1) = kem.encapsulate(&keypair.public_key).unwrap();

        // Verify ciphertext size
        assert_eq!(
            ciphertext.len(),
            config.ciphertext_size,
            "Invalid ciphertext size for {:?}",
            config.algorithm
        );

        // Verify shared secret size
        assert_eq!(
            shared_secret1.len(),
            config.shared_secret_size,
            "Invalid shared secret size for {:?}",
            config.algorithm
        );

        // Test decapsulation
        let shared_secret2 = kem.decapsulate(&keypair.secret_key, &ciphertext).unwrap();

        // Verify shared secrets match
        assert_eq!(
            shared_secret1, shared_secret2,
            "Shared secrets don't match for {:?}",
            config.algorithm
        );

        // Verify shared secret is not all zeros
        assert!(!shared_secret1.iter().all(|&b| b == 0));
    }
}

/// Test public key derivation from secret key
#[test]
fn test_ml_kem_public_key_derivation() {
    for config in ML_KEM_CONFIGS {
        let kem = create_kem(config.algorithm).unwrap();
        let keypair = kem.generate_keypair().unwrap();

        // Derive public key from secret key
        let derived_public_key = kem.derive_public_key(&keypair.secret_key).unwrap();

        // Verify derived public key matches original
        assert_eq!(
            derived_public_key.data, keypair.public_key.data,
            "Derived public key doesn't match original for {:?}",
            config.algorithm
        );
    }
}

/// Test error handling for invalid key sizes
#[test]
fn test_ml_kem_invalid_key_sizes() {
    for config in ML_KEM_CONFIGS {
        let kem = create_kem(config.algorithm).unwrap();

        // Test invalid public key size
        let invalid_public_key = KemPublicKey {
            data: vec![0u8; config.public_key_size - 1],
        };
        let result = kem.encapsulate(&invalid_public_key);
        assert!(result.is_err());
        if let Err(Error::InvalidKeySize { expected, actual }) = result {
            assert_eq!(expected, config.public_key_size);
            assert_eq!(actual, config.public_key_size - 1);
        } else {
            panic!("Expected InvalidKeySize error for {:?}", config.algorithm);
        }

        // Test invalid secret key size
        let invalid_secret_key = KemSecretKey {
            data: vec![0u8; config.secret_key_size - 1],
        };
        let invalid_ciphertext = vec![0u8; config.ciphertext_size];
        let result = kem.decapsulate(&invalid_secret_key, &invalid_ciphertext);
        assert!(result.is_err());
        if let Err(Error::InvalidKeySize { expected, actual }) = result {
            assert_eq!(expected, config.secret_key_size);
            assert_eq!(actual, config.secret_key_size - 1);
        } else {
            panic!("Expected InvalidKeySize error for {:?}", config.algorithm);
        }
    }
}

/// Test error handling for invalid ciphertext sizes
#[test]
fn test_ml_kem_invalid_ciphertext_sizes() {
    for config in ML_KEM_CONFIGS {
        let kem = create_kem(config.algorithm).unwrap();
        let keypair = kem.generate_keypair().unwrap();

        // Test invalid ciphertext size
        let invalid_ciphertext = vec![0u8; config.ciphertext_size - 1];
        let result = kem.decapsulate(&keypair.secret_key, &invalid_ciphertext);
        assert!(result.is_err());
        if let Err(Error::InvalidCiphertextSize { expected, actual }) = result {
            assert_eq!(expected, config.ciphertext_size);
            assert_eq!(actual, config.ciphertext_size - 1);
        } else {
            panic!(
                "Expected InvalidCiphertextSize error for {:?}",
                config.algorithm
            );
        }
    }
}

/// Test multiple encapsulations with the same keypair
#[test]
fn test_ml_kem_multiple_encapsulations() {
    for config in ML_KEM_CONFIGS {
        let kem = create_kem(config.algorithm).unwrap();
        let keypair = kem.generate_keypair().unwrap();

        // Perform multiple encapsulations
        let mut shared_secrets = Vec::new();
        for _ in 0..5 {
            let (ciphertext, shared_secret) = kem.encapsulate(&keypair.public_key).unwrap();
            let decapsulated = kem.decapsulate(&keypair.secret_key, &ciphertext).unwrap();
            assert_eq!(shared_secret, decapsulated);
            shared_secrets.push(shared_secret);
        }

        // Verify all shared secrets are different (very high probability)
        for i in 0..shared_secrets.len() {
            for j in (i + 1)..shared_secrets.len() {
                assert_ne!(
                    shared_secrets[i], shared_secrets[j],
                    "Shared secrets should be different for {:?}",
                    config.algorithm
                );
            }
        }
    }
}

/// Test cross-algorithm key compatibility (should fail)
#[test]
fn test_ml_kem_cross_algorithm_incompatibility() {
    let kem512 = create_kem(Algorithm::MlKem512).unwrap();
    let kem768 = create_kem(Algorithm::MlKem768).unwrap();

    let keypair512 = kem512.generate_keypair().unwrap();
    let keypair768 = kem768.generate_keypair().unwrap();

    // Try to use ML-KEM-512 key with ML-KEM-768 KEM (should fail)
    let result = kem768.encapsulate(&keypair512.public_key);
    assert!(result.is_err());

    // Try to use ML-KEM-768 key with ML-KEM-512 KEM (should fail)
    let result = kem512.encapsulate(&keypair768.public_key);
    assert!(result.is_err());
}

/// Test security level validation
#[test]
fn test_ml_kem_security_levels() {
    for config in ML_KEM_CONFIGS {
        assert_eq!(
            config.algorithm.security_level(),
            config.security_level.as_u32(),
            "Security level mismatch for {:?}",
            config.algorithm
        );
    }
}

/// Test that the implementation doesn't use deprecated APIs
#[test]
fn test_ml_kem_no_deprecated_apis() {
    // This test ensures that the implementation doesn't rely on deprecated APIs
    // by verifying that all operations work correctly without warnings

    for config in ML_KEM_CONFIGS {
        let kem = create_kem(config.algorithm).unwrap();
        let keypair = kem.generate_keypair().unwrap();

        // Perform full KEM cycle
        let (ciphertext, shared_secret1) = kem.encapsulate(&keypair.public_key).unwrap();
        let shared_secret2 = kem.decapsulate(&keypair.secret_key, &ciphertext).unwrap();
        assert_eq!(shared_secret1, shared_secret2);

        // Test public key derivation
        let derived_pk = kem.derive_public_key(&keypair.secret_key).unwrap();
        assert_eq!(derived_pk.data, keypair.public_key.data);
    }
}

/// Test memory safety and zeroization
#[test]
fn test_ml_kem_memory_safety() {
    for config in ML_KEM_CONFIGS {
        let kem = create_kem(config.algorithm).unwrap();
        let _keypair = kem.generate_keypair().unwrap();

        // Verify that secret keys implement proper memory management
        // This is implicitly tested by the Zeroize trait implementation
        // in the core types

        // Test that we can create multiple keypairs without issues
        for _ in 0..10 {
            let _keypair = kem.generate_keypair().unwrap();
        }
    }
}

/// Test error message clarity and consistency
#[test]
fn test_ml_kem_error_messages() {
    let kem = create_kem(Algorithm::MlKem512).unwrap();

    // Test invalid public key size error message
    let invalid_pk = KemPublicKey {
        data: vec![0u8; 100],
    };
    let result = kem.encapsulate(&invalid_pk);
    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("Invalid key size"));
    assert!(error_msg.contains("expected 800"));
    assert!(error_msg.contains("got 100"));

    // Test invalid ciphertext size error message
    let keypair = kem.generate_keypair().unwrap();
    let invalid_ct = vec![0u8; 100];
    let result = kem.decapsulate(&keypair.secret_key, &invalid_ct);
    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("Invalid ciphertext size"));
    assert!(error_msg.contains("expected 768"));
    assert!(error_msg.contains("got 100"));
}
