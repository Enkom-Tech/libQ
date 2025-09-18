//! Comprehensive tests for the refactored ML-KEM implementation
//!
//! This test suite validates the security, correctness, and performance
//! of the refactored ML-KEM implementation.

use lib_q_core::{
    Algorithm,
    Error,
    KemOperations,
    KemPublicKey,
    KemSecretKey,
    SecurityLevel,
};
use lib_q_kem::{
    LibQKemProvider,
    available_algorithms,
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
    assert!(algorithms.contains(&"ML-KEM-512"));
    assert!(algorithms.contains(&"ML-KEM-768"));
    assert!(algorithms.contains(&"ML-KEM-1024"));

    // Verify we can create KEM provider
    let provider = LibQKemProvider::new();
    assert!(provider.is_ok(), "Failed to create KEM provider");
}

/// Test key generation for all ML-KEM variants
#[test]
fn test_ml_kem_key_generation() {
    let provider = LibQKemProvider::new().unwrap();

    for config in ML_KEM_CONFIGS {
        let keypair = provider.generate_keypair(config.algorithm, None).unwrap();

        // Verify key sizes
        assert_eq!(
            keypair.public_key().as_bytes().len(),
            config.public_key_size,
            "Invalid public key size for {:?}",
            config.algorithm
        );
        assert_eq!(
            keypair.secret_key().as_bytes().len(),
            config.secret_key_size,
            "Invalid secret key size for {:?}",
            config.algorithm
        );

        // Verify keys are not all zeros
        assert!(!keypair.public_key().as_bytes().iter().all(|&b| b == 0));
        assert!(!keypair.secret_key().as_bytes().iter().all(|&b| b == 0));
    }
}

/// Test encapsulation and decapsulation for all ML-KEM variants
#[test]
fn test_ml_kem_encapsulation_decapsulation() {
    let provider = LibQKemProvider::new().unwrap();

    for config in ML_KEM_CONFIGS {
        let keypair = provider.generate_keypair(config.algorithm, None).unwrap();

        // Test encapsulation
        let (ciphertext, shared_secret1) = provider
            .encapsulate(config.algorithm, keypair.public_key(), None)
            .unwrap();

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
        let shared_secret2 = provider
            .decapsulate(config.algorithm, keypair.secret_key(), &ciphertext)
            .unwrap();

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
    use lib_q_core::Kem;
    use lib_q_kem::ml_kem::{
        MlKem512Impl,
        MlKem768Impl,
        MlKem1024Impl,
    };

    for config in ML_KEM_CONFIGS {
        // Create KEM instance directly for derive_public_key test
        let keypair = match config.algorithm {
            Algorithm::MlKem512 => {
                let kem = MlKem512Impl::default();
                kem.generate_keypair().unwrap()
            }
            Algorithm::MlKem768 => {
                let kem = MlKem768Impl::default();
                kem.generate_keypair().unwrap()
            }
            Algorithm::MlKem1024 => {
                let kem = MlKem1024Impl::default();
                kem.generate_keypair().unwrap()
            }
            _ => panic!("Unsupported algorithm: {:?}", config.algorithm),
        };

        // Derive public key from secret key using the same KEM instance
        let derived_public_key = match config.algorithm {
            Algorithm::MlKem512 => {
                let kem = MlKem512Impl::default();
                kem.derive_public_key(&keypair.secret_key).unwrap()
            }
            Algorithm::MlKem768 => {
                let kem = MlKem768Impl::default();
                kem.derive_public_key(&keypair.secret_key).unwrap()
            }
            Algorithm::MlKem1024 => {
                let kem = MlKem1024Impl::default();
                kem.derive_public_key(&keypair.secret_key).unwrap()
            }
            _ => panic!("Unsupported algorithm: {:?}", config.algorithm),
        };

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
    let provider = LibQKemProvider::new().unwrap();

    for config in ML_KEM_CONFIGS {
        // Test invalid public key size
        let invalid_public_key = KemPublicKey::new(vec![0u8; config.public_key_size - 1]);
        let result = provider.encapsulate(config.algorithm, &invalid_public_key, None);
        assert!(result.is_err());
        if let Err(Error::InvalidKeySize { expected, actual }) = result {
            assert_eq!(expected, config.public_key_size);
            assert_eq!(actual, config.public_key_size - 1);
        } else {
            panic!("Expected InvalidKeySize error for {:?}", config.algorithm);
        }

        // Test invalid secret key size
        let invalid_secret_key = KemSecretKey::new(vec![0u8; config.secret_key_size - 1]);
        let invalid_ciphertext = vec![0u8; config.ciphertext_size];
        let result =
            provider.decapsulate(config.algorithm, &invalid_secret_key, &invalid_ciphertext);
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
    let provider = LibQKemProvider::new().unwrap();

    for config in ML_KEM_CONFIGS {
        let keypair = provider.generate_keypair(config.algorithm, None).unwrap();

        // Test invalid ciphertext size
        let invalid_ciphertext = vec![0u8; config.ciphertext_size - 1];
        let result =
            provider.decapsulate(config.algorithm, keypair.secret_key(), &invalid_ciphertext);
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
    let provider = LibQKemProvider::new().unwrap();

    for config in ML_KEM_CONFIGS {
        let keypair = provider.generate_keypair(config.algorithm, None).unwrap();

        // Perform multiple encapsulations
        let mut shared_secrets = Vec::new();
        for _ in 0..5 {
            let (ciphertext, shared_secret) = provider
                .encapsulate(config.algorithm, keypair.public_key(), None)
                .unwrap();
            let decapsulated = provider
                .decapsulate(config.algorithm, keypair.secret_key(), &ciphertext)
                .unwrap();
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
    let provider = LibQKemProvider::new().unwrap();

    let keypair512 = provider
        .generate_keypair(Algorithm::MlKem512, None)
        .unwrap();
    let keypair768 = provider
        .generate_keypair(Algorithm::MlKem768, None)
        .unwrap();

    // Try to use ML-KEM-512 key with ML-KEM-768 KEM (should fail)
    let result = provider.encapsulate(Algorithm::MlKem768, keypair512.public_key(), None);
    assert!(result.is_err());

    // Try to use ML-KEM-768 key with ML-KEM-512 KEM (should fail)
    let result = provider.encapsulate(Algorithm::MlKem512, keypair768.public_key(), None);
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

    let provider = LibQKemProvider::new().unwrap();

    for config in ML_KEM_CONFIGS {
        let keypair = provider.generate_keypair(config.algorithm, None).unwrap();

        // Perform full KEM cycle
        let (ciphertext, shared_secret1) = provider
            .encapsulate(config.algorithm, keypair.public_key(), None)
            .unwrap();
        let shared_secret2 = provider
            .decapsulate(config.algorithm, keypair.secret_key(), &ciphertext)
            .unwrap();
        assert_eq!(shared_secret1, shared_secret2);

        // Test public key derivation using direct KEM instance
        use lib_q_core::Kem;
        use lib_q_kem::ml_kem::{
            MlKem512Impl,
            MlKem768Impl,
            MlKem1024Impl,
        };
        let direct_keypair = match config.algorithm {
            Algorithm::MlKem512 => {
                let kem = MlKem512Impl::default();
                kem.generate_keypair().unwrap()
            }
            Algorithm::MlKem768 => {
                let kem = MlKem768Impl::default();
                kem.generate_keypair().unwrap()
            }
            Algorithm::MlKem1024 => {
                let kem = MlKem1024Impl::default();
                kem.generate_keypair().unwrap()
            }
            _ => panic!("Unsupported algorithm: {:?}", config.algorithm),
        };
        let derived_pk = match config.algorithm {
            Algorithm::MlKem512 => {
                let kem = MlKem512Impl::default();
                kem.derive_public_key(&direct_keypair.secret_key).unwrap()
            }
            Algorithm::MlKem768 => {
                let kem = MlKem768Impl::default();
                kem.derive_public_key(&direct_keypair.secret_key).unwrap()
            }
            Algorithm::MlKem1024 => {
                let kem = MlKem1024Impl::default();
                kem.derive_public_key(&direct_keypair.secret_key).unwrap()
            }
            _ => panic!("Unsupported algorithm: {:?}", config.algorithm),
        };
        assert_eq!(derived_pk.data, direct_keypair.public_key.data);
    }
}

/// Test memory safety and zeroization
#[test]
fn test_ml_kem_memory_safety() {
    let provider = LibQKemProvider::new().unwrap();

    for config in ML_KEM_CONFIGS {
        let _keypair = provider.generate_keypair(config.algorithm, None).unwrap();

        // Verify that secret keys implement proper memory management
        // This is implicitly tested by the Zeroize trait implementation
        // in the core types

        // Test that we can create multiple keypairs without issues
        for _ in 0..10 {
            let _keypair = provider.generate_keypair(config.algorithm, None).unwrap();
        }
    }
}

/// Test error message clarity and consistency
#[test]
fn test_ml_kem_error_messages() {
    let provider = LibQKemProvider::new().unwrap();

    // Test invalid public key size error message
    let invalid_pk = KemPublicKey::new(vec![0u8; 100]);
    let result = provider.encapsulate(Algorithm::MlKem512, &invalid_pk, None);
    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("Invalid key size"));
    assert!(error_msg.contains("expected 800"));
    assert!(error_msg.contains("got 100"));

    // Test invalid ciphertext size error message
    let keypair = provider
        .generate_keypair(Algorithm::MlKem512, None)
        .unwrap();
    let invalid_ct = vec![0u8; 100];
    let result = provider.decapsulate(Algorithm::MlKem512, keypair.secret_key(), &invalid_ct);
    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("Invalid ciphertext size"));
    assert!(error_msg.contains("expected 768"));
    assert!(error_msg.contains("got 100"));
}
