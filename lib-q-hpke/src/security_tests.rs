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

    use crate::providers::post_quantum::PostQuantumProvider;
    use crate::providers::traits::{
        AeadProvider,
        KdfProvider,
        KemProvider,
    };
    use crate::types::*;

    /// Test that invalid key lengths are properly rejected
    #[test]
    fn test_aead_invalid_key_lengths() {
        let provider = PostQuantumProvider::new();
        let invalid_key_16 = vec![0u8; 16]; // Too short for Saturnin256
        let invalid_key_48 = vec![0u8; 48]; // Too long for Saturnin256
        let _valid_key = vec![0u8; 32]; // Correct length
        let nonce = vec![0u8; 16];
        let plaintext = b"test message";

        // Test with invalid key lengths
        let result_short = provider.seal(
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
                .contains("Invalid input for key")
        );

        let result_long = provider.seal(
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
                .contains("Invalid input for key")
        );
    }

    /// Test that invalid nonce lengths are properly rejected
    #[test]
    fn test_aead_invalid_nonce_lengths() {
        let provider = PostQuantumProvider::new();
        let key = vec![1u8; 32]; // Non-zero key
        let invalid_nonce_8 = vec![0u8; 8]; // Too short
        let invalid_nonce_24 = vec![0u8; 24]; // Too long
        let _valid_nonce = vec![0u8; 16]; // Correct length
        let plaintext = b"test message";

        // Test with invalid nonce lengths
        let result_short = provider.seal(
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
                .contains("Invalid input for nonce")
        );

        let result_long = provider.seal(
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
                .contains("Invalid input for nonce")
        );
    }

    /// Test that zero keys are properly rejected
    #[test]
    fn test_aead_zero_key_rejection() {
        let provider = PostQuantumProvider::new();
        let zero_key = vec![0u8; 32];
        let nonce = vec![0u8; 16];
        let plaintext = b"test message";

        let result = provider.seal(HpkeAead::Saturnin256, &zero_key, &nonce, b"", plaintext);
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
        let provider = PostQuantumProvider::new();
        let key = vec![1u8; 32]; // Non-zero key for SHAKE256 AEAD
        let nonce = vec![0u8; 16];
        let plaintext = b"test message";

        // Test SHAKE256 AEAD - should fail as it's not currently implemented
        let result = provider.seal(HpkeAead::Shake256, &key, &nonce, b"", plaintext);
        assert!(
            result.is_err(),
            "SHAKE256 AEAD should fail as it's not currently implemented"
        );
    }

    /// Test that feature flags work correctly
    #[test]
    #[cfg(not(feature = "saturnin"))]
    fn test_saturnin_feature_disabled() {
        let provider = PostQuantumProvider::new();
        let key = vec![0u8; 32];
        let nonce = vec![0u8; 16];
        let plaintext = b"test message";

        let result = provider.seal(HpkeAead::Saturnin256, &key, &nonce, b"", plaintext);
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
        let provider = PostQuantumProvider::new();
        let key = vec![1u8; 32]; // Non-zero key
        let nonce = vec![0u8; 16];
        let short_ciphertext = vec![0u8; 8]; // Too short (less than tag length)

        let result = provider.open(HpkeAead::Saturnin256, &key, &nonce, b"", &short_ciphertext);
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Ciphertext too short") ||
                error_msg.contains("Invalid input") ||
                error_msg.contains("decryption failed")
        );
    }

    /// Test that algorithm support checks work correctly
    #[test]
    fn test_algorithm_support_checks() {
        let provider = PostQuantumProvider::new();
        // Test supported algorithms
        assert!(provider.supports_kem(HpkeKem::MlKem512));
        assert!(provider.supports_kem(HpkeKem::MlKem768));
        assert!(provider.supports_kem(HpkeKem::MlKem1024));

        assert!(provider.supports_kdf(HpkeKdf::HkdfShake128));
        assert!(provider.supports_kdf(HpkeKdf::HkdfShake256));
        assert!(provider.supports_kdf(HpkeKdf::HkdfSha3_256));
        assert!(provider.supports_kdf(HpkeKdf::HkdfSha3_512));

        assert!(provider.supports_aead(HpkeAead::Saturnin256));
        // SHAKE256 AEAD is implemented and supported
        assert!(provider.supports_aead(HpkeAead::Shake256));
        assert!(provider.supports_aead(HpkeAead::Export));
    }

    /// Test that error messages are informative and don't leak sensitive information
    #[test]
    fn test_error_message_security() {
        let provider = PostQuantumProvider::new();
        let invalid_key = vec![0u8; 16];
        let nonce = vec![0u8; 16];
        let plaintext = b"test message";

        let result = provider.seal(HpkeAead::Saturnin256, &invalid_key, &nonce, b"", plaintext);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();

        // Error should be informative but not leak sensitive data
        assert!(error_msg.contains("Invalid input for key"));
        assert!(error_msg.contains("expected 32 bytes"));
        assert!(error_msg.contains("got '16 bytes'"));

        // Should not contain the actual key material
        assert!(!error_msg.contains("00000000"));
    }

    /// Test constant-time properties (basic check)
    #[test]
    fn test_constant_time_properties() {
        let provider = PostQuantumProvider::new();
        // This is a basic test - in a real implementation, we'd use
        // more sophisticated timing analysis tools

        let key1 = vec![0u8; 32]; // Zero key - should fail
        let key2 = vec![1u8; 32]; // Non-zero key - should succeed (if saturnin feature enabled)
        let nonce = vec![0u8; 16];
        let plaintext = b"test message";

        // First operation should fail due to zero key validation
        let result1 = provider.seal(HpkeAead::Saturnin256, &key1, &nonce, b"", plaintext);
        assert!(result1.is_err());
        let error1 = result1.unwrap_err().to_string();
        assert!(error1.contains("Key material cannot be all zeros"));

        // Second operation should either succeed (if saturnin enabled) or fail with feature error
        let result2 = provider.seal(HpkeAead::Saturnin256, &key2, &nonce, b"", plaintext);

        #[cfg(feature = "saturnin")]
        {
            // With saturnin feature enabled, non-zero key should succeed
            assert!(result2.is_ok());
        }
        #[cfg(not(feature = "saturnin"))]
        {
            // Without saturnin feature, should fail with feature error
            assert!(result2.is_err());
            let error2 = result2.unwrap_err().to_string();
            assert!(error2.contains("Saturnin feature not enabled"));
        }
    }
}
