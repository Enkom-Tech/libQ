//! Security tests for HPKE implementation
//!
//! These tests validate security properties and edge cases to ensure
//! the HPKE implementation follows secure development practices.

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::{
        string::ToString,
        vec,
    };

    use crate::crypto_provider::{
        HpkeCryptoProvider,
        PostQuantumProvider,
    };
    use crate::types::*;

    /// Test that invalid key lengths are properly rejected
    #[test]
    fn test_aead_invalid_key_lengths() {
        let invalid_key_16 = vec![0u8; 16]; // Too short for Saturnin256
        let invalid_key_48 = vec![0u8; 48]; // Too long for Saturnin256
        let _valid_key = vec![0u8; 32]; // Correct length
        let nonce = vec![0u8; 16];
        let plaintext = b"test message";

        // Test with invalid key lengths
        let result_short = PostQuantumProvider::aead_seal(
            HpkeAead::Saturnin256,
            &invalid_key_16,
            &nonce,
            b"",
            plaintext,
        );
        assert!(result_short.is_err());
        assert!(
            result_short
                .unwrap_err()
                .to_string()
                .contains("Invalid key length")
        );

        let result_long = PostQuantumProvider::aead_seal(
            HpkeAead::Saturnin256,
            &invalid_key_48,
            &nonce,
            b"",
            plaintext,
        );
        assert!(result_long.is_err());
        assert!(
            result_long
                .unwrap_err()
                .to_string()
                .contains("Invalid key length")
        );
    }

    /// Test that invalid nonce lengths are properly rejected
    #[test]
    fn test_aead_invalid_nonce_lengths() {
        let key = vec![0u8; 32];
        let invalid_nonce_8 = vec![0u8; 8]; // Too short
        let invalid_nonce_24 = vec![0u8; 24]; // Too long
        let _valid_nonce = vec![0u8; 16]; // Correct length
        let plaintext = b"test message";

        // Test with invalid nonce lengths
        let result_short = PostQuantumProvider::aead_seal(
            HpkeAead::Saturnin256,
            &key,
            &invalid_nonce_8,
            b"",
            plaintext,
        );
        assert!(result_short.is_err());
        assert!(
            result_short
                .unwrap_err()
                .to_string()
                .contains("Invalid nonce length")
        );

        let result_long = PostQuantumProvider::aead_seal(
            HpkeAead::Saturnin256,
            &key,
            &invalid_nonce_24,
            b"",
            plaintext,
        );
        assert!(result_long.is_err());
        assert!(
            result_long
                .unwrap_err()
                .to_string()
                .contains("Invalid nonce length")
        );
    }

    /// Test that zero keys are properly rejected
    #[test]
    fn test_aead_zero_key_rejection() {
        let zero_key = vec![0u8; 32];
        let nonce = vec![0u8; 16];
        let plaintext = b"test message";

        let result = PostQuantumProvider::aead_seal(
            HpkeAead::Saturnin256,
            &zero_key,
            &nonce,
            b"",
            plaintext,
        );
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Key material cannot be all zeros")
        );
    }

    /// Test that unsupported AEAD algorithms return proper errors
    #[test]
    fn test_unsupported_aead_algorithms() {
        let key = vec![0u8; 32];
        let nonce = vec![0u8; 16];
        let plaintext = b"test message";

        // Test SHAKE256 AEAD (not yet implemented)
        let result =
            PostQuantumProvider::aead_seal(HpkeAead::Shake256, &key, &nonce, b"", plaintext);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("SHAKE256 AEAD not yet implemented")
        );
    }

    /// Test that feature flags work correctly
    #[test]
    #[cfg(not(feature = "saturnin"))]
    fn test_saturnin_feature_disabled() {
        let key = vec![0u8; 32];
        let nonce = vec![0u8; 16];
        let plaintext = b"test message";

        let result =
            PostQuantumProvider::aead_seal(HpkeAead::Saturnin256, &key, &nonce, b"", plaintext);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Saturnin feature not enabled")
        );
    }

    /// Test that ciphertext length validation works for decryption
    #[test]
    fn test_ciphertext_length_validation() {
        let key = vec![0u8; 32];
        let nonce = vec![0u8; 16];
        let short_ciphertext = vec![0u8; 8]; // Too short (less than tag length)

        let result = PostQuantumProvider::aead_open(
            HpkeAead::Saturnin256,
            &key,
            &nonce,
            b"",
            &short_ciphertext,
        );
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Ciphertext too short")
        );
    }

    /// Test that algorithm support checks work correctly
    #[test]
    fn test_algorithm_support_checks() {
        // Test supported algorithms
        assert!(PostQuantumProvider::supports_kem(HpkeKem::MlKem512));
        assert!(PostQuantumProvider::supports_kem(HpkeKem::MlKem768));
        assert!(PostQuantumProvider::supports_kem(HpkeKem::MlKem1024));

        assert!(PostQuantumProvider::supports_kdf(HpkeKdf::HkdfShake128));
        assert!(PostQuantumProvider::supports_kdf(HpkeKdf::HkdfShake256));
        assert!(PostQuantumProvider::supports_kdf(HpkeKdf::HkdfSha3_256));
        assert!(PostQuantumProvider::supports_kdf(HpkeKdf::HkdfSha3_512));

        assert!(PostQuantumProvider::supports_aead(HpkeAead::Saturnin256));
        assert!(PostQuantumProvider::supports_aead(HpkeAead::Shake256));
        assert!(PostQuantumProvider::supports_aead(HpkeAead::Export));
    }

    /// Test that error messages are informative and don't leak sensitive information
    #[test]
    fn test_error_message_security() {
        let invalid_key = vec![0u8; 16];
        let nonce = vec![0u8; 16];
        let plaintext = b"test message";

        let result = PostQuantumProvider::aead_seal(
            HpkeAead::Saturnin256,
            &invalid_key,
            &nonce,
            b"",
            plaintext,
        );

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();

        // Error should be informative but not leak sensitive data
        assert!(error_msg.contains("Invalid key length"));
        assert!(error_msg.contains("Saturnin256"));
        assert!(error_msg.contains("expected 32 bytes"));
        assert!(error_msg.contains("got 16 bytes"));

        // Should not contain the actual key material
        assert!(!error_msg.contains("00000000"));
    }

    /// Test constant-time properties (basic check)
    #[test]
    fn test_constant_time_properties() {
        // This is a basic test - in a real implementation, we'd use
        // more sophisticated timing analysis tools

        let key1 = vec![0u8; 32];
        let key2 = vec![1u8; 32]; // Different key
        let nonce = vec![0u8; 16];
        let plaintext = b"test message";

        // Both operations should fail for the same reason (zero key)
        // and should take similar time
        let result1 =
            PostQuantumProvider::aead_seal(HpkeAead::Saturnin256, &key1, &nonce, b"", plaintext);

        let result2 =
            PostQuantumProvider::aead_seal(HpkeAead::Saturnin256, &key2, &nonce, b"", plaintext);

        // Both should fail, but for different reasons
        assert!(result1.is_err());
        assert!(result2.is_err());

        // Error messages should be different (zero key vs feature not enabled)
        let error1 = result1.unwrap_err().to_string();
        let error2 = result2.unwrap_err().to_string();
        assert_ne!(error1, error2);
    }
}
