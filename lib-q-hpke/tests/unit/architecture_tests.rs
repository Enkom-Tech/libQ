//! Tests for the new modular architecture

use lib_q_hpke::security::*;
use lib_q_hpke::error::*;
use lib_q_hpke::types::*;
use lib_q_hpke::providers::*;

#[test]
fn test_security_policy_creation() {
    let policy = SecurityPolicy::default();
    assert!(policy.require_constant_time);
    assert!(policy.validate_key_material);
    assert!(policy.enforce_zero_key_rejection);
}

#[test]
fn test_security_policy_strict() {
    let policy = SecurityPolicy::strict();
    assert!(policy.require_constant_time);
    assert_eq!(policy.max_key_size, 32);
    assert_eq!(policy.max_nonce_size, 16);
}

#[test]
fn test_security_policy_permissive() {
    let policy = SecurityPolicy::permissive();
    assert!(!policy.require_constant_time);
    assert_eq!(policy.max_key_size, 128);
    assert_eq!(policy.max_nonce_size, 64);
}

#[test]
fn test_cryptographic_validator() {
    let validator = CryptographicValidator::with_default_policy();
    
    // Test key validation
    let key = vec![1u8; 32];
    assert!(validator.validate_aead_key(HpkeAead::Saturnin256, &key).is_ok());
    
    // Test nonce validation
    let nonce = vec![1u8; 16];
    assert!(validator.validate_aead_nonce(HpkeAead::Saturnin256, &nonce).is_ok());
}

#[test]
fn test_constant_time_operations() {
    let a = b"hello";
    let b = b"hello";
    let c = b"world";
    
    assert!(constant_time_eq(a, b));
    assert!(!constant_time_eq(a, c));
    
    assert_eq!(constant_time_select(1, 0xFF, 0x00), 0xFF);
    assert_eq!(constant_time_select(0, 0xFF, 0x00), 0x00);
}

#[test]
fn test_secure_memory() {
    let key = SecureKey::new(vec![1u8, 2u8, 3u8, 4u8]);
    assert_eq!(key.as_slice(), &[1u8, 2u8, 3u8, 4u8]);
    assert_eq!(key.len(), 4);
    assert!(!key.is_empty());
    
    let nonce = SecureNonce::new(vec![5u8, 6u8, 7u8, 8u8]);
    assert_eq!(nonce.as_slice(), &[5u8, 6u8, 7u8, 8u8]);
    assert_eq!(nonce.len(), 4);
    assert!(!nonce.is_empty());
    
    let mut buffer = SecureBuffer::new();
    buffer.push(1);
    buffer.push(2);
    assert_eq!(buffer.len(), 2);
    assert_eq!(buffer.as_slice(), &[1u8, 2u8]);
}

#[test]
fn test_prng() {
    let mut rng = SimpleRng::new();
    
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes).unwrap();
    
    // Check that we got some non-zero bytes
    assert!(bytes.iter().any(|&b| b != 0));
    
    let val1 = rng.next_u32().unwrap();
    let val2 = rng.next_u32().unwrap();
    
    // Very unlikely to be equal
    assert_ne!(val1, val2);
}

#[test]
fn test_enhanced_error_types() {
    let kem_error = HpkeError::kem_error(
        HpkeKem::MlKem512,
        KemOperation::KeyGeneration,
        "Test error",
    );
    
    match kem_error {
        HpkeError::KemError { algorithm, operation, cause } => {
            assert_eq!(algorithm, HpkeKem::MlKem512);
            assert_eq!(operation, KemOperation::KeyGeneration);
            assert_eq!(cause, "Test error");
        }
        _ => panic!("Expected KemError"),
    }
    
    let security_error = HpkeError::security_error(
        SecurityValidation::KeyLength,
        "Test error",
    );
    
    match security_error {
        HpkeError::SecurityError { validation, cause } => {
            assert_eq!(validation, SecurityValidation::KeyLength);
            assert_eq!(cause, "Test error");
        }
        _ => panic!("Expected SecurityError"),
    }
}

#[test]
fn test_provider_traits() {
    let provider = PostQuantumProvider::new();
    
    assert_eq!(provider.name(), "PostQuantumProvider");
    
    let algorithms = provider.supported_algorithms();
    
    // With default features enabled, we should have algorithm support
    // The exact algorithms depend on which features are enabled
    #[cfg(all(feature = "ml-kem", feature = "hash", feature = "saturnin"))]
    {
        // All algorithms should be supported with default features
        assert!(!algorithms.kems.is_empty(), "KEM algorithms should be supported with ml-kem feature");
        assert!(!algorithms.kdfs.is_empty(), "KDF algorithms should be supported with hash feature");
        assert!(!algorithms.aeads.is_empty(), "AEAD algorithms should be supported with saturnin feature");
        
        // Verify specific algorithms are present
        assert!(algorithms.kems.contains(&HpkeKem::MlKem512));
        assert!(algorithms.kems.contains(&HpkeKem::MlKem768));
        assert!(algorithms.kems.contains(&HpkeKem::MlKem1024));
        
        assert!(algorithms.kdfs.contains(&HpkeKdf::HkdfShake128));
        assert!(algorithms.kdfs.contains(&HpkeKdf::HkdfShake256));
        assert!(algorithms.kdfs.contains(&HpkeKdf::HkdfSha3_256));
        assert!(algorithms.kdfs.contains(&HpkeKdf::HkdfSha3_512));
        
        assert!(algorithms.aeads.contains(&HpkeAead::Saturnin256));
        assert!(algorithms.aeads.contains(&HpkeAead::Shake256));
        assert!(algorithms.aeads.contains(&HpkeAead::Export));
    }
    
    #[cfg(not(all(feature = "ml-kem", feature = "hash", feature = "saturnin")))]
    {
        // Without features, algorithms should be empty
        assert!(algorithms.kems.is_empty());
        assert!(algorithms.kdfs.is_empty());
        assert!(algorithms.aeads.is_empty());
    }
}

#[test]
fn test_supported_algorithms() {
    let algorithms = SupportedAlgorithms::new(
        vec![HpkeKem::MlKem512, HpkeKem::MlKem768],
        vec![HpkeKdf::HkdfShake256],
        vec![HpkeAead::Saturnin256],
    );
    
    assert!(algorithms.supports_kem(HpkeKem::MlKem512));
    assert!(algorithms.supports_kem(HpkeKem::MlKem768));
    assert!(!algorithms.supports_kem(HpkeKem::MlKem1024));
    
    assert!(algorithms.supports_kdf(HpkeKdf::HkdfShake256));
    assert!(!algorithms.supports_kdf(HpkeKdf::HkdfShake128));
    
    assert!(algorithms.supports_aead(HpkeAead::Saturnin256));
    assert!(!algorithms.supports_aead(HpkeAead::Shake256));
}

#[test]
fn test_error_macros() {
    let kem_error = kem_err!(HpkeKem::MlKem512, KemOperation::KeyGeneration, "Test");
    assert!(matches!(kem_error, HpkeError::KemError { .. }));
    
    let kdf_error = kdf_err!(HpkeKdf::HkdfShake256, KdfOperation::Extract, "Test");
    assert!(matches!(kdf_error, HpkeError::KdfError { .. }));
    
    let aead_error = aead_err!(HpkeAead::Saturnin256, AeadOperation::Seal, "Test");
    assert!(matches!(aead_error, HpkeError::AeadError { .. }));
    
    let security_error = security_err!(SecurityValidation::KeyLength, "Test");
    assert!(matches!(security_error, HpkeError::SecurityError { .. }));
    
    let protocol_error = protocol_err!(ProtocolStage::KeySchedule, "Test");
    assert!(matches!(protocol_error, HpkeError::ProtocolError { .. }));
}
