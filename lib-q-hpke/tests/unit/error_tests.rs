//! Unit tests for enhanced error types

use lib_q_hpke::error::*;
use lib_q_hpke::types::*;
use lib_q_hpke::{
    aead_err,
    kdf_err,
    kem_err,
    protocol_err,
    security_err,
};

#[test]
fn test_kem_error_creation() {
    let error = HpkeError::kem_error(HpkeKem::MlKem512, KemOperation::KeyGeneration, "Test error");

    match error {
        HpkeError::KemError {
            algorithm,
            operation,
            cause,
        } => {
            assert_eq!(algorithm, HpkeKem::MlKem512);
            assert_eq!(operation, KemOperation::KeyGeneration);
            assert_eq!(cause, "Test error");
        }
        _ => panic!("Expected KemError"),
    }
}

#[test]
fn test_kdf_error_creation() {
    let error = HpkeError::kdf_error(HpkeKdf::HkdfShake256, KdfOperation::Extract, "Test error");

    match error {
        HpkeError::KdfError {
            algorithm,
            operation,
            cause,
        } => {
            assert_eq!(algorithm, HpkeKdf::HkdfShake256);
            assert_eq!(operation, KdfOperation::Extract);
            assert_eq!(cause, "Test error");
        }
        _ => panic!("Expected KdfError"),
    }
}

#[test]
fn test_aead_error_creation() {
    let error = HpkeError::aead_error(HpkeAead::Saturnin256, AeadOperation::Seal, "Test error");

    match error {
        HpkeError::AeadError {
            algorithm,
            operation,
            cause,
        } => {
            assert_eq!(algorithm, HpkeAead::Saturnin256);
            assert_eq!(operation, AeadOperation::Seal);
            assert_eq!(cause, "Test error");
        }
        _ => panic!("Expected AeadError"),
    }
}

#[test]
fn test_security_error_creation() {
    let error = HpkeError::security_error(SecurityValidation::KeyLength, "Test error");

    match error {
        HpkeError::SecurityError { validation, cause } => {
            assert_eq!(validation, SecurityValidation::KeyLength);
            assert_eq!(cause, "Test error");
        }
        _ => panic!("Expected SecurityError"),
    }
}

#[test]
fn test_protocol_error_creation() {
    let error = HpkeError::protocol_error(ProtocolStage::KeySchedule, "Test error");

    match error {
        HpkeError::ProtocolError { stage, cause } => {
            assert_eq!(stage, ProtocolStage::KeySchedule);
            assert_eq!(cause, "Test error");
        }
        _ => panic!("Expected ProtocolError"),
    }
}

#[test]
fn test_invalid_input_error_creation() {
    let error = HpkeError::invalid_input("key", "invalid", "32 bytes");

    match error {
        HpkeError::InvalidInput {
            parameter,
            value,
            expected,
        } => {
            assert_eq!(parameter, "key");
            assert_eq!(value, "invalid");
            assert_eq!(expected, "32 bytes");
        }
        _ => panic!("Expected InvalidInput"),
    }
}

#[test]
fn test_feature_not_enabled_error_creation() {
    let error = HpkeError::feature_not_enabled("test_feature");

    match error {
        HpkeError::FeatureNotEnabled { feature } => {
            assert_eq!(feature, "test_feature");
        }
        _ => panic!("Expected FeatureNotEnabled"),
    }
}

#[test]
fn test_not_implemented_error_creation() {
    let error = HpkeError::not_implemented("test_feature");

    match error {
        HpkeError::NotImplemented { feature } => {
            assert_eq!(feature, "test_feature");
        }
        _ => panic!("Expected NotImplemented"),
    }
}

#[test]
fn test_error_display() {
    let error = HpkeError::kem_error(HpkeKem::MlKem512, KemOperation::KeyGeneration, "Test error");

    let display = format!("{}", error);
    assert!(display.contains("KEM error"));
    assert!(display.contains("MlKem512"));
    assert!(display.contains("KeyGeneration"));
    assert!(display.contains("Test error"));
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

#[test]
fn test_hpke_result_type() {
    let success: HpkeResult<u32> = Ok(42);
    assert!(matches!(success, Ok(42)));

    let error: HpkeResult<u32> = Err(HpkeError::CryptoError("Test".to_string()));
    assert!(error.is_err());
}
