//! Export-only AEAD implementation for HPKE
//!
//! This module implements the export-only AEAD mode as specified in RFC 9180.
//! Export-only mode is used for key derivation and does not provide encryption/decryption.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::error::{
    AeadOperation,
    HpkeError,
};
use crate::types::*;

/// Export-only AEAD implementation
///
/// This AEAD mode is used exclusively for key export operations and does not
/// provide encryption or decryption functionality. It always returns an error
/// for seal/open operations as these are not supported in export-only mode.
pub struct ExportOnlyAead;

impl Default for ExportOnlyAead {
    fn default() -> Self {
        Self::new()
    }
}

impl ExportOnlyAead {
    /// Create a new export-only AEAD implementation
    pub fn new() -> Self {
        Self
    }
}

impl crate::aead::traits::Aead for ExportOnlyAead {
    fn seal(
        &self,
        _key: &[u8],
        _nonce: &[u8],
        _aad: &[u8],
        _plaintext: &[u8],
    ) -> Result<Vec<u8>, HpkeError> {
        Err(HpkeError::aead_error(
            HpkeAead::Export,
            AeadOperation::Seal,
            "Export-only AEAD does not support encryption operations. Use export() method for key derivation.",
        ))
    }

    fn open(
        &self,
        _key: &[u8],
        _nonce: &[u8],
        _aad: &[u8],
        _ciphertext: &[u8],
    ) -> Result<Vec<u8>, HpkeError> {
        Err(HpkeError::aead_error(
            HpkeAead::Export,
            AeadOperation::Open,
            "Export-only AEAD does not support decryption operations. Use export() method for key derivation.",
        ))
    }
}

/// Create an export-only AEAD implementation
pub fn create_export_aead() -> Result<ExportOnlyAead, HpkeError> {
    Ok(ExportOnlyAead::new())
}

/// Check if export-only AEAD is available
pub fn is_export_available() -> bool {
    true // Export-only AEAD is always available
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;

    use super::*;
    use crate::aead::traits::Aead;

    #[test]
    fn test_export_availability() {
        assert!(is_export_available());
    }

    #[test]
    fn test_export_creation() {
        let _aead = ExportOnlyAead::new();
        // Should not panic
    }

    #[test]
    fn test_export_seal_returns_error() {
        let aead = ExportOnlyAead::new();
        let key = vec![1u8; 32];
        let nonce = vec![2u8; 16];
        let plaintext = b"test message";
        let aad = b"metadata";

        let result = aead.seal(&key, &nonce, aad, plaintext);
        assert!(result.is_err());

        if let Err(HpkeError::AeadError {
            algorithm,
            operation,
            ..
        }) = result
        {
            assert_eq!(algorithm, HpkeAead::Export);
            assert_eq!(operation, AeadOperation::Seal);
        } else {
            panic!("Expected AeadError");
        }
    }

    #[test]
    fn test_export_open_returns_error() {
        let aead = ExportOnlyAead::new();
        let key = vec![1u8; 32];
        let nonce = vec![2u8; 16];
        let ciphertext = vec![3u8; 32];
        let aad = b"metadata";

        let result = aead.open(&key, &nonce, aad, &ciphertext);
        assert!(result.is_err());

        if let Err(HpkeError::AeadError {
            algorithm,
            operation,
            ..
        }) = result
        {
            assert_eq!(algorithm, HpkeAead::Export);
            assert_eq!(operation, AeadOperation::Open);
        } else {
            panic!("Expected AeadError");
        }
    }

    #[test]
    fn test_export_error_messages() {
        let aead = ExportOnlyAead::new();
        let key = vec![1u8; 32];
        let nonce = vec![2u8; 16];
        let plaintext = b"test message";
        let aad = b"metadata";

        let seal_result = aead.seal(&key, &nonce, aad, plaintext);
        assert!(seal_result.is_err());

        let error_msg = seal_result.unwrap_err().to_string();
        assert!(error_msg.contains("Export-only AEAD does not support encryption operations"));
        assert!(error_msg.contains("Use export() method for key derivation"));

        let open_result = aead.open(&key, &nonce, aad, &[1u8; 32]);
        assert!(open_result.is_err());

        let error_msg = open_result.unwrap_err().to_string();
        assert!(error_msg.contains("Export-only AEAD does not support decryption operations"));
        assert!(error_msg.contains("Use export() method for key derivation"));
    }
}
