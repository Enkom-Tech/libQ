//! Unit tests for security utilities

use lib_q_hpke::security::*;
use lib_q_hpke::error::*;
use lib_q_hpke::types::*;

#[test]
fn test_security_policy_default() {
    let policy = SecurityPolicy::default();
    assert!(policy.require_constant_time);
    assert!(policy.validate_key_material);
    assert!(policy.enforce_zero_key_rejection);
    assert!(policy.strict_length_validation);
    assert!(policy.enable_side_channel_protection);
    assert_eq!(policy.max_key_size, 64);
    assert_eq!(policy.max_nonce_size, 32);
    assert_eq!(policy.max_ciphertext_size, 1024 * 1024);
}

#[test]
fn test_security_policy_strict() {
    let policy = SecurityPolicy::strict();
    assert!(policy.require_constant_time);
    assert!(policy.validate_key_material);
    assert!(policy.enforce_zero_key_rejection);
    assert!(policy.strict_length_validation);
    assert!(policy.enable_side_channel_protection);
    assert_eq!(policy.max_key_size, 32);
    assert_eq!(policy.max_nonce_size, 16);
    assert_eq!(policy.max_ciphertext_size, 64 * 1024);
}

#[test]
fn test_security_policy_permissive() {
    let policy = SecurityPolicy::permissive();
    assert!(!policy.require_constant_time);
    assert!(!policy.validate_key_material);
    assert!(!policy.enforce_zero_key_rejection);
    assert!(!policy.strict_length_validation);
    assert!(!policy.enable_side_channel_protection);
    assert_eq!(policy.max_key_size, 128);
    assert_eq!(policy.max_nonce_size, 64);
    assert_eq!(policy.max_ciphertext_size, 10 * 1024 * 1024);
}

#[test]
fn test_key_validation_success() {
    let policy = SecurityPolicy::default();
    let key = vec![1u8; 32];
    assert!(policy.validate_key(&key, 32).is_ok());
}

#[test]
fn test_key_validation_wrong_length() {
    let policy = SecurityPolicy::strict();
    let key = vec![1u8; 16];
    let result = policy.validate_key(&key, 32);
    assert!(result.is_err());
    
    if let Err(HpkeError::SecurityError { validation, .. }) = result {
        assert_eq!(validation, SecurityValidation::KeyLength);
    } else {
        panic!("Expected SecurityError");
    }
}

#[test]
fn test_key_validation_zero_key() {
    let policy = SecurityPolicy::default();
    let key = vec![0u8; 32];
    let result = policy.validate_key(&key, 32);
    assert!(result.is_err());
    
    if let Err(HpkeError::SecurityError { validation, .. }) = result {
        assert_eq!(validation, SecurityValidation::ZeroKeyRejection);
    } else {
        panic!("Expected SecurityError");
    }
}

#[test]
fn test_key_validation_too_large() {
    let policy = SecurityPolicy::strict();
    let key = vec![1u8; 64];
    let result = policy.validate_key(&key, 32);
    assert!(result.is_err());
    
    if let Err(HpkeError::SecurityError { validation, .. }) = result {
        assert_eq!(validation, SecurityValidation::KeyLength);
    } else {
        panic!("Expected SecurityError");
    }
}

#[test]
fn test_nonce_validation_success() {
    let policy = SecurityPolicy::default();
    let nonce = vec![1u8; 16];
    assert!(policy.validate_nonce(&nonce, 16).is_ok());
}

#[test]
fn test_nonce_validation_wrong_length() {
    let policy = SecurityPolicy::strict();
    let nonce = vec![1u8; 12];
    let result = policy.validate_nonce(&nonce, 16);
    assert!(result.is_err());
    
    if let Err(HpkeError::SecurityError { validation, .. }) = result {
        assert_eq!(validation, SecurityValidation::NonceLength);
    } else {
        panic!("Expected SecurityError");
    }
}

#[test]
fn test_ciphertext_validation_success() {
    let policy = SecurityPolicy::default();
    let ciphertext = vec![1u8; 1000];
    assert!(policy.validate_ciphertext(&ciphertext).is_ok());
}

#[test]
fn test_ciphertext_validation_too_large() {
    let policy = SecurityPolicy::strict();
    let ciphertext = vec![1u8; 100 * 1024]; // 100KB
    let result = policy.validate_ciphertext(&ciphertext);
    assert!(result.is_err());
    
    if let Err(HpkeError::SecurityError { validation, .. }) = result {
        assert_eq!(validation, SecurityValidation::CiphertextLength);
    } else {
        panic!("Expected SecurityError");
    }
}

#[test]
fn test_cryptographic_validator() {
    let validator = CryptographicValidator::with_default_policy();
    
    // Test KEM key validation
    let kem_key = vec![1u8; 32];
    assert!(validator.validate_kem_key(HpkeKem::MlKem512, &kem_key, false).is_ok());
    
    // Test AEAD key validation
    let aead_key = vec![1u8; 32];
    assert!(validator.validate_aead_key(HpkeAead::Saturnin256, &aead_key).is_ok());
    
    // Test AEAD nonce validation
    let nonce = vec![1u8; 16];
    assert!(validator.validate_aead_nonce(HpkeAead::Saturnin256, &nonce).is_ok());
    
    // Test ciphertext validation
    let ciphertext = vec![1u8; 100];
    assert!(validator.validate_ciphertext(&ciphertext).is_ok());
}

#[test]
fn test_input_sanitization() {
    let validator = CryptographicValidator::with_default_policy();
    
    // Test empty input
    let result = validator.validate_input_sanitization(&[], "test_input");
    assert!(result.is_err());
    
    if let Err(HpkeError::SecurityError { validation, .. }) = result {
        assert_eq!(validation, SecurityValidation::InputSanitization);
    } else {
        panic!("Expected SecurityError");
    }
    
    // Test valid input
    let input = vec![1u8; 100];
    assert!(validator.validate_input_sanitization(&input, "test_input").is_ok());
}

#[test]
fn test_global_security_policy() {
    // Test default policy
    let default_policy = get_default_security_policy();
    assert!(default_policy.require_constant_time);
    
    // Test strict policy
    let strict_policy = get_strict_security_policy();
    assert!(strict_policy.require_constant_time);
    assert_eq!(strict_policy.max_key_size, 32);
    
    // Test permissive policy
    let permissive_policy = get_permissive_security_policy();
    assert!(!permissive_policy.require_constant_time);
    assert_eq!(permissive_policy.max_key_size, 128);
}
