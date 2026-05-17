//! Integration tests for lib-q-aead
//!
//! These tests verify the complete AEAD functionality including the registry system,
//! algorithm implementations, and plugin architecture.

use lib_q_aead::*;
use lib_q_core::{
    AeadKey,
    Algorithm,
    AlgorithmCategory,
    Error,
    Nonce,
};

/// Generate a proper test key with good entropy (32 bytes; typical lib-q AEADs).
fn create_test_key() -> AeadKey {
    AeadKey::new(vec![
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF, 0x00,
    ])
}

/// Key material sized for the algorithm (Romulus uses 128-bit keys).
fn create_test_key_for(algorithm: Algorithm) -> AeadKey {
    match algorithm {
        Algorithm::RomulusN | Algorithm::RomulusM => AeadKey::new(vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ]),
        _ => create_test_key(),
    }
}

/// Second distinct key, same length as [`create_test_key_for`].
fn create_alt_test_key_for(algorithm: Algorithm) -> AeadKey {
    match algorithm {
        Algorithm::RomulusN | Algorithm::RomulusM => AeadKey::new(vec![
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00,
        ]),
        _ => AeadKey::new(vec![
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98,
            0x76, 0x54, 0x32, 0x10,
        ]),
    }
}

/// Generate a proper test nonce with good entropy
fn create_test_nonce() -> Nonce {
    Nonce::new(vec![
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ])
}

#[test]
fn test_available_algorithms() {
    let algorithms = available_algorithms();
    assert!(!algorithms.is_empty());

    // All returned algorithms should be AEAD algorithms
    for algorithm in algorithms {
        assert_eq!(algorithm.category(), AlgorithmCategory::Aead);
    }
}

#[test]
fn test_create_aead() {
    let algorithms = available_algorithms();

    for algorithm in algorithms {
        let aead = create_aead(algorithm);
        assert!(aead.is_ok(), "Failed to create AEAD for {:?}", algorithm);
    }
}

#[test]
fn test_invalid_algorithm() {
    // Try to create AEAD with non-AEAD algorithm
    let result = create_aead(Algorithm::MlKem512);
    assert!(result.is_err());

    if let Err(Error::InvalidAlgorithm { algorithm }) = result {
        assert!(algorithm.contains("not an AEAD algorithm"));
    } else {
        panic!("Expected InvalidAlgorithm error");
    }
}

#[test]
fn test_algorithm_availability() {
    let algorithms = available_algorithms();

    for algorithm in algorithms {
        assert!(is_algorithm_available(algorithm));
    }

    // Non-AEAD algorithms should not be available
    assert!(!is_algorithm_available(Algorithm::MlKem512));
}

#[test]
fn test_algorithm_metadata() {
    let algorithms = available_algorithms();

    for algorithm in algorithms {
        let metadata = get_algorithm_metadata(algorithm);
        assert!(metadata.is_some(), "No metadata for {:?}", algorithm);

        if let Some(meta) = metadata {
            assert_eq!(meta.algorithm, algorithm);
            assert!(meta.key_size > 0);
            assert!(meta.nonce_size > 0);
            assert!(meta.tag_size > 0);
        }
    }
}

#[test]
fn test_registry_functionality() {
    let registry = registry();

    // Test available algorithms
    let algorithms = registry.available_algorithms();
    assert!(!algorithms.is_empty());

    // Test algorithm creation
    for algorithm in &algorithms {
        let aead = registry.create_aead(*algorithm);
        assert!(aead.is_ok(), "Failed to create AEAD for {:?}", algorithm);
    }

    // Test metadata retrieval
    for algorithm in &algorithms {
        let metadata = registry.get_metadata(*algorithm);
        assert!(metadata.is_some(), "No metadata for {:?}", algorithm);
    }
}

#[test]
fn test_aead_encrypt_decrypt() {
    let algorithms = available_algorithms();

    for algorithm in algorithms {
        let aead = create_aead(algorithm).unwrap();

        // Test with different key and nonce values
        let key = create_test_key_for(algorithm);
        let nonce = create_test_nonce();
        let plaintext = b"Hello, World!";
        let associated_data = b"metadata";

        // Encrypt
        let ciphertext = aead.encrypt(&key, &nonce, plaintext, Some(associated_data.as_slice()));
        assert!(ciphertext.is_ok(), "Encryption failed for {:?}", algorithm);

        let ciphertext = ciphertext.unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + aead.tag_size());

        // Decrypt
        let decrypted = aead.decrypt(&key, &nonce, &ciphertext, Some(associated_data.as_slice()));
        assert!(decrypted.is_ok(), "Decryption failed for {:?}", algorithm);
        assert_eq!(decrypted.unwrap(), plaintext);
    }
}

#[test]
fn test_aead_authentication_failure() {
    let algorithms = available_algorithms();

    for algorithm in algorithms {
        let aead = create_aead(algorithm).unwrap();

        let key = create_test_key_for(algorithm);
        let nonce = create_test_nonce();
        let plaintext = b"Hello, World!";

        // Encrypt
        let ciphertext = aead.encrypt(&key, &nonce, plaintext, None).unwrap();

        // Tamper with ciphertext
        let mut tampered = ciphertext.clone();
        tampered[0] ^= 0xFF;

        // Decrypt should fail
        let result = aead.decrypt(&key, &nonce, &tampered, None);
        assert!(
            result.is_err(),
            "Authentication should fail for {:?}",
            algorithm
        );

        match result {
            Err(Error::VerificationFailed { operation }) => {
                assert!(operation.contains("AEAD tag verification"));
            }
            Err(Error::AuthenticationFailed { operation }) => {
                assert!(operation.contains("Tag verification failed"));
            }
            _ => {
                println!("Actual error: {:?}", result);
                panic!(
                    "Expected VerificationFailed or AuthenticationFailed error for {:?}",
                    algorithm
                );
            }
        }
    }
}

#[test]
fn test_aead_wrong_key() {
    let algorithms = available_algorithms();

    for algorithm in algorithms {
        let aead = create_aead(algorithm).unwrap();

        let key1 = create_test_key_for(algorithm);
        let key2 = create_alt_test_key_for(algorithm);
        let nonce = create_test_nonce();
        let plaintext = b"Hello, World!";

        // Encrypt with key1
        let ciphertext = aead.encrypt(&key1, &nonce, plaintext, None).unwrap();

        // Decrypt with key2 should fail
        let result = aead.decrypt(&key2, &nonce, &ciphertext, None);
        assert!(
            result.is_err(),
            "Decryption with wrong key should fail for {:?}",
            algorithm
        );
    }
}

#[test]
fn test_aead_wrong_nonce() {
    let algorithms = available_algorithms();

    for algorithm in algorithms {
        let aead = create_aead(algorithm).unwrap();

        let key = create_test_key_for(algorithm);
        let nonce1 = create_test_nonce();
        let nonce2 = Nonce::new(vec![
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00,
        ]);
        let plaintext = b"Hello, World!";

        // Encrypt with nonce1
        let ciphertext = aead.encrypt(&key, &nonce1, plaintext, None).unwrap();

        // Decrypt with nonce2 should fail
        let result = aead.decrypt(&key, &nonce2, &ciphertext, None);
        assert!(
            result.is_err(),
            "Decryption with wrong nonce should fail for {:?}",
            algorithm
        );
    }
}

#[test]
fn test_aead_empty_plaintext() {
    let algorithms = available_algorithms();

    for algorithm in algorithms {
        let aead = create_aead(algorithm).unwrap();

        let key = create_test_key_for(algorithm);
        let nonce = create_test_nonce();
        let plaintext = b"";

        // Encrypt empty plaintext
        let ciphertext = aead.encrypt(&key, &nonce, plaintext, None);
        assert!(
            ciphertext.is_ok(),
            "Empty plaintext encryption should work for {:?}",
            algorithm
        );

        let ciphertext = ciphertext.unwrap();
        assert_eq!(ciphertext.len(), aead.tag_size());

        // Decrypt should work
        let decrypted = aead.decrypt(&key, &nonce, &ciphertext, None);
        assert!(
            decrypted.is_ok(),
            "Empty plaintext decryption should work for {:?}",
            algorithm
        );
        assert_eq!(decrypted.unwrap(), plaintext);
    }
}

#[test]
fn test_aead_large_plaintext() {
    let algorithms = available_algorithms();

    for algorithm in algorithms {
        let aead = create_aead(algorithm).unwrap();

        let key = create_test_key_for(algorithm);
        let nonce = create_test_nonce();
        let plaintext = vec![0u8; 1024 * 1024]; // 1MB

        // Encrypt large plaintext
        let ciphertext = aead.encrypt(&key, &nonce, &plaintext, None);
        assert!(
            ciphertext.is_ok(),
            "Large plaintext encryption should work for {:?}",
            algorithm
        );

        let ciphertext = ciphertext.unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + aead.tag_size());

        // Decrypt should work
        let decrypted = aead.decrypt(&key, &nonce, &ciphertext, None);
        assert!(
            decrypted.is_ok(),
            "Large plaintext decryption should work for {:?}",
            algorithm
        );
        assert_eq!(decrypted.unwrap(), plaintext);
    }
}

#[test]
fn test_aead_associated_data() {
    let algorithms = available_algorithms();

    for algorithm in algorithms {
        let aead = create_aead(algorithm).unwrap();

        let key = create_test_key_for(algorithm);
        let nonce = create_test_nonce();
        let plaintext = b"Hello, World!";
        let associated_data = Some(b"important metadata".as_slice());

        // Encrypt with associated data
        let ciphertext = aead.encrypt(&key, &nonce, plaintext, associated_data);
        assert!(
            ciphertext.is_ok(),
            "Encryption with AD should work for {:?}",
            algorithm
        );

        let ciphertext = ciphertext.unwrap();

        // Decrypt with correct associated data should work
        let decrypted = aead.decrypt(&key, &nonce, &ciphertext, associated_data);
        assert!(
            decrypted.is_ok(),
            "Decryption with correct AD should work for {:?}",
            algorithm
        );
        assert_eq!(decrypted.unwrap(), plaintext);

        // Decrypt with wrong associated data should fail
        let wrong_ad = Some(b"wrong metadata".as_slice());
        let result = aead.decrypt(&key, &nonce, &ciphertext, wrong_ad);
        assert!(
            result.is_err(),
            "Decryption with wrong AD should fail for {:?}",
            algorithm
        );
    }
}

#[test]
fn test_aead_key_validation() {
    let algorithms = available_algorithms();

    for algorithm in algorithms {
        let aead = create_aead(algorithm).unwrap();

        let ks = aead.key_size();
        // Test valid key
        let key = AeadKey::new(vec![0u8; ks]);
        assert!(aead.validate_key(&key).is_ok());

        // Test invalid key size (pick a wrong length distinct from ks)
        let bad_len = if ks == 32 { 16usize } else { 32usize };
        let invalid_key = AeadKey::new(vec![0u8; bad_len]);
        assert!(aead.validate_key(&invalid_key).is_err());
    }
}

#[test]
fn test_aead_nonce_validation() {
    let algorithms = available_algorithms();

    for algorithm in algorithms {
        let aead = create_aead(algorithm).unwrap();

        // Test valid nonce
        let nonce = Nonce::new(vec![0u8; 16]);
        assert!(aead.validate_nonce(&nonce).is_ok());

        // Test invalid nonce size
        let invalid_nonce = Nonce::new(vec![0u8; 12]);
        assert!(aead.validate_nonce(&invalid_nonce).is_err());
    }
}

#[test]
fn test_aead_ciphertext_validation() {
    let algorithms = available_algorithms();

    for algorithm in algorithms {
        let aead = create_aead(algorithm).unwrap();

        // Test valid ciphertext size
        assert!(aead.validate_ciphertext_size(aead.tag_size()).is_ok());

        // Test invalid ciphertext size
        assert!(aead.validate_ciphertext_size(aead.tag_size() - 1).is_err());
    }
}

#[test]
fn test_aead_metadata() {
    let algorithms = available_algorithms();

    for algorithm in algorithms {
        let aead = create_aead(algorithm).unwrap();
        let metadata = aead.metadata();

        assert_eq!(metadata.algorithm, algorithm);
        assert!(metadata.key_size > 0);
        assert!(metadata.nonce_size > 0);
        assert!(metadata.tag_size > 0);
        assert!(metadata.security_level > 0);
        assert!(!metadata.name.is_empty());
        assert!(!metadata.description.is_empty());
    }
}

#[test]
fn test_aead_performance_tier() {
    let algorithms = available_algorithms();

    for algorithm in algorithms {
        let aead = create_aead(algorithm).unwrap();
        let metadata = aead.metadata();

        // All algorithms should have a valid performance tier
        let tier = metadata.performance_tier();
        assert!(matches!(
            tier,
            lib_q_aead::PerformanceTier::UltraSecure |
                lib_q_aead::PerformanceTier::Balanced |
                lib_q_aead::PerformanceTier::Performance |
                lib_q_aead::PerformanceTier::Hybrid
        ));
    }
}

#[test]
fn test_aead_security_level_suitability() {
    let algorithms = available_algorithms();

    for algorithm in algorithms {
        let aead = create_aead(algorithm).unwrap();
        let metadata = aead.metadata();

        // Test security level suitability
        assert!(metadata.is_suitable_for_security_level(1));
        assert!(metadata.is_suitable_for_security_level(metadata.security_level));

        if metadata.security_level < 5 {
            assert!(!metadata.is_suitable_for_security_level(metadata.security_level + 1));
        }
    }
}

#[test]
fn test_aead_total_overhead() {
    let algorithms = available_algorithms();

    for algorithm in algorithms {
        let aead = create_aead(algorithm).unwrap();
        let metadata = aead.metadata();

        // Total overhead should be nonce size + tag size
        let expected_overhead = metadata.nonce_size + metadata.tag_size;
        assert_eq!(metadata.total_overhead(), expected_overhead);
    }
}
