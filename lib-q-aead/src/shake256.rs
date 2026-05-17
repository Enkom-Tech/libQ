//! SHAKE256 AEAD Implementation
//!
//! This module provides a cryptographically secure SHAKE256-based AEAD implementation
//! using proper domain separation and authenticated encryption modes.
//!
//! # Layer A vs Layer B error mapping
//!
//! After inputs pass size and policy validation, the decrypt schedule derives keys, verifies
//! the tag (constant-time compare), always runs CTR decrypt, then applies
//! [`crate::security::constant_time::constant_time_zero`] on the candidate plaintext when the
//! tag is wrong. **Layer A** [`Aead::decrypt`] maps a bad tag to [`Error::AuthenticationFailed`].
//! **Layer B** [`AeadDecryptSemantic::decrypt_semantic`] maps the same condition to
//! [`DecryptSemanticOutcome::AuthenticationFailed`] inside [`Ok`]. Operational problems
//! (wrong key/nonce length, ciphertext too short for the tag, policy limits) remain [`Err`];
//! ciphertext-length checks that reject inputs before the tag split use [`Error::VerificationFailed`]
//! where historical tests expect that variant.

#[cfg(feature = "alloc")]
use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use lib_q_core::{
    Aead,
    AeadDecryptSemantic,
    AeadKey,
    Algorithm,
    DecryptSemanticOutcome,
    Error,
    Nonce,
    Result,
};
use lib_q_sha3::digest::{
    Update,
    XofReader,
};
use zeroize::Zeroizing;

// Plugin trait implementation
use crate::metadata::{
    AeadMetadata,
    AeadWithMetadata,
};
use crate::security::memory::secure_zero_slice;
use crate::security::stack_buffer::UninitStackBuffer;

/// SHAKE256 AEAD implementation with proper domain separation
pub struct Shake256Aead {
    metadata: &'static AeadMetadata,
}

impl Shake256Aead {
    /// Create a new SHAKE256 AEAD instance
    pub fn new() -> Self {
        Self {
            metadata: crate::metadata::get_metadata(Algorithm::Shake256Aead)
                .expect("SHAKE256 AEAD metadata not found"),
        }
    }

    /// Domain separation constants for different operations
    const DOMAIN_ENC_KEY: &'static [u8] = b"LIBQ-SHAKE256-AEAD-ENC-KEY";
    const DOMAIN_MAC_KEY: &'static [u8] = b"LIBQ-SHAKE256-AEAD-MAC-KEY";
    const DOMAIN_IV: &'static [u8] = b"LIBQ-SHAKE256-AEAD-IV";
    const DOMAIN_TAG: &'static [u8] = b"LIBQ-SHAKE256-AEAD-TAG";

    /// Derive encryption key using domain separation
    fn derive_encryption_key(
        &self,
        key: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>> {
        use lib_q_sha3::Shake256;
        use lib_q_sha3::digest::ExtendableOutput;

        let mut hasher = Shake256::default();
        hasher.update(Self::DOMAIN_ENC_KEY);
        hasher.update(key);
        hasher.update(nonce);
        hasher.update(associated_data);
        hasher.update(&(associated_data.len() as u64).to_le_bytes());

        let mut enc_key = Zeroizing::new([0u8; 32]);
        let mut reader = hasher.finalize_xof();
        reader.read(&mut enc_key[..]);
        Ok(enc_key)
    }

    /// Derive MAC key using domain separation
    fn derive_mac_key(
        &self,
        key: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>> {
        use lib_q_sha3::Shake256;
        use lib_q_sha3::digest::ExtendableOutput;

        let mut hasher = Shake256::default();
        hasher.update(Self::DOMAIN_MAC_KEY);
        hasher.update(key);
        hasher.update(nonce);
        hasher.update(associated_data);
        hasher.update(&(associated_data.len() as u64).to_le_bytes());

        let mut mac_key = Zeroizing::new([0u8; 32]);
        let mut reader = hasher.finalize_xof();
        reader.read(&mut mac_key[..]);
        Ok(mac_key)
    }

    /// Generate initialization vector using domain separation
    fn generate_iv(
        &self,
        key: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
    ) -> Result<Zeroizing<[u8; 16]>> {
        use lib_q_sha3::Shake256;
        use lib_q_sha3::digest::ExtendableOutput;

        let mut hasher = Shake256::default();
        hasher.update(Self::DOMAIN_IV);
        hasher.update(key);
        hasher.update(nonce);
        hasher.update(associated_data);
        hasher.update(&(associated_data.len() as u64).to_le_bytes());

        let mut iv = Zeroizing::new([0u8; 16]);
        let mut reader = hasher.finalize_xof();
        reader.read(&mut iv[..]);
        Ok(iv)
    }

    /// Generate authentication tag using domain separation
    fn generate_tag(
        &self,
        mac_key: &[u8],
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>> {
        use lib_q_sha3::Shake256;
        use lib_q_sha3::digest::ExtendableOutput;

        let mut hasher = Shake256::default();
        hasher.update(Self::DOMAIN_TAG);
        hasher.update(mac_key);
        hasher.update(associated_data);
        hasher.update(&(associated_data.len() as u64).to_le_bytes());
        hasher.update(ciphertext);
        hasher.update(&(ciphertext.len() as u64).to_le_bytes());

        let mut tag = Zeroizing::new([0u8; 32]);
        let mut reader = hasher.finalize_xof();
        reader.read(&mut tag[..]);
        Ok(tag)
    }

    /// Encrypt using CTR mode with SHAKE256
    fn ctr_encrypt(&self, enc_key: &[u8], iv: &[u8], plaintext: &mut [u8]) -> Result<()> {
        use lib_q_sha3::Shake256;
        use lib_q_sha3::digest::ExtendableOutput;

        // Generate keystream using SHAKE256
        let mut hasher = Shake256::default();
        hasher.update(enc_key);
        hasher.update(iv);
        hasher.update(&(plaintext.len() as u64).to_le_bytes());

        // Use uninitialized stack buffer: only the used keystream prefix is zeroed on drop
        // (avoids wiping the full 4096-byte backing store on every small message).
        if plaintext.len() <= 4096 {
            let mut keystream = UninitStackBuffer::<4096>::new();
            keystream
                .resize(plaintext.len())
                .map_err(|_| Error::BufferTooSmall {
                    capacity: keystream.capacity(),
                    requested: plaintext.len(),
                })?;
            let mut reader = hasher.finalize_xof();
            reader.read(keystream.as_mut_slice());

            // XOR with keystream
            for (i, byte) in plaintext.iter_mut().enumerate() {
                *byte ^= keystream.as_slice()[i];
            }
        } else {
            // Fall back to Vec for larger plaintexts
            let mut keystream = vec![0u8; plaintext.len()];
            let mut reader = hasher.finalize_xof();
            reader.read(&mut keystream);

            // XOR with keystream
            for (i, byte) in plaintext.iter_mut().enumerate() {
                *byte ^= keystream[i];
            }
            secure_zero_slice(&mut keystream);
        }

        Ok(())
    }

    /// Decrypt using CTR mode with SHAKE256
    fn ctr_decrypt(&self, enc_key: &[u8], iv: &[u8], ciphertext: &mut [u8]) -> Result<()> {
        // CTR decryption is the same as encryption
        self.ctr_encrypt(enc_key, iv, ciphertext)
    }

    /// Validate key material
    fn validate_key(&self, key: &AeadKey) -> Result<()> {
        // Use standard validation from AeadWithMetadata trait
        AeadWithMetadata::validate_key(self, key)
    }

    /// Validate nonce
    fn validate_nonce(&self, nonce: &Nonce) -> Result<()> {
        // Use standard validation from AeadWithMetadata trait
        AeadWithMetadata::validate_nonce(self, nonce)
    }

    /// Validate ciphertext size
    fn validate_ciphertext_size(&self, size: usize) -> Result<()> {
        // Use standard validation from AeadWithMetadata trait
        AeadWithMetadata::validate_ciphertext_size(self, size)
    }

    /// Internal encrypt implementation
    fn encrypt_internal(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        // Validate inputs using security modules
        self.validate_key(key)?;
        self.validate_nonce(nonce)?;
        crate::security::validation::validate_plaintext(plaintext)?;
        crate::security::validation::validate_key(key.as_bytes())?;
        crate::security::validation::validate_nonce(nonce.as_bytes())?;

        let associated_data = associated_data.unwrap_or(&[]);
        crate::security::validation::validate_associated_data(associated_data)?;

        // Use SHAKE256 for encryption with proper domain separation
        #[cfg(feature = "shake256")]
        {
            let mut key_staged = Zeroizing::new([0u8; 32]);
            key_staged.copy_from_slice(key.as_bytes());
            let mut nonce_staged = Zeroizing::new([0u8; 16]);
            nonce_staged.copy_from_slice(nonce.as_bytes());
            let kb = key_staged.as_slice();
            let nb = nonce_staged.as_slice();

            // Derive keys using domain separation
            let enc_key = self.derive_encryption_key(kb, nb, associated_data)?;
            let mac_key = self.derive_mac_key(kb, nb, associated_data)?;
            let iv = self.generate_iv(kb, nb, associated_data)?;

            // Encrypt plaintext
            let mut ciphertext = plaintext.to_vec();
            self.ctr_encrypt(enc_key.as_slice(), iv.as_slice(), &mut ciphertext)?;

            // Generate authentication tag
            let tag = self.generate_tag(mac_key.as_slice(), associated_data, &ciphertext)?;

            // Append tag to ciphertext
            ciphertext.extend_from_slice(tag.as_slice());

            Ok(ciphertext)
        }

        #[cfg(not(feature = "shake256"))]
        {
            Err(Error::NotImplemented {
                feature: "SHAKE256 AEAD implementation requires 'shake256' feature",
            })
        }
    }

    /// Shared decrypt body: same tag derive, CT compare, CTR decrypt, and `constant_time_zero`
    /// schedule as Layer A [`decrypt_internal`].
    fn decrypt_semantic_core(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<DecryptSemanticOutcome> {
        self.validate_key(key)?;
        self.validate_nonce(nonce)?;
        self.validate_ciphertext_size(ciphertext.len())?;
        crate::security::validation::validate_ciphertext(ciphertext)?;
        crate::security::validation::validate_key(key.as_bytes())?;
        crate::security::validation::validate_nonce(nonce.as_bytes())?;

        let associated_data = associated_data.unwrap_or(&[]);
        crate::security::validation::validate_associated_data(associated_data)?;

        #[cfg(feature = "shake256")]
        {
            let (ciphertext_data, tag) = ciphertext.split_at(ciphertext.len() - self.tag_size());

            let mut key_staged = Zeroizing::new([0u8; 32]);
            key_staged.copy_from_slice(key.as_bytes());
            let mut nonce_staged = Zeroizing::new([0u8; 16]);
            nonce_staged.copy_from_slice(nonce.as_bytes());
            let kb = key_staged.as_slice();
            let nb = nonce_staged.as_slice();

            let enc_key = self.derive_encryption_key(kb, nb, associated_data)?;
            let mac_key = self.derive_mac_key(kb, nb, associated_data)?;
            let iv = self.generate_iv(kb, nb, associated_data)?;

            let computed_tag =
                self.generate_tag(mac_key.as_slice(), associated_data, ciphertext_data)?;
            let tag_valid =
                crate::security::constant_time::constant_time_eq(tag, computed_tag.as_slice());

            let mut plaintext = ciphertext_data.to_vec();
            self.ctr_decrypt(enc_key.as_slice(), iv.as_slice(), &mut plaintext)?;

            crate::security::constant_time::constant_time_zero(!tag_valid, &mut plaintext);

            if tag_valid {
                Ok(DecryptSemanticOutcome::Success(Zeroizing::new(plaintext)))
            } else {
                Ok(DecryptSemanticOutcome::AuthenticationFailed)
            }
        }

        #[cfg(not(feature = "shake256"))]
        {
            Err(Error::NotImplemented {
                feature: "SHAKE256 AEAD implementation requires 'shake256' feature",
            })
        }
    }

    /// Internal decrypt implementation with constant-time execution
    fn decrypt_internal(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        match self.decrypt_semantic_core(key, nonce, ciphertext, associated_data)? {
            DecryptSemanticOutcome::Success(pt) => Ok(Vec::clone(&*pt)),
            DecryptSemanticOutcome::AuthenticationFailed => Err(Error::AuthenticationFailed {
                operation: "Tag verification failed".to_string(),
            }),
        }
    }
}

impl Aead for Shake256Aead {
    fn encrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.encrypt_internal(key, nonce, plaintext, associated_data)
    }

    fn decrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.decrypt_internal(key, nonce, ciphertext, associated_data)
    }
}

impl AeadDecryptSemantic for Shake256Aead {
    fn decrypt_semantic(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<DecryptSemanticOutcome> {
        self.decrypt_semantic_core(key, nonce, ciphertext, associated_data)
    }
}

impl AeadWithMetadata for Shake256Aead {
    fn metadata(&self) -> &'static AeadMetadata {
        self.metadata
    }
}

impl Default for Shake256Aead {
    fn default() -> Self {
        Self::new()
    }
}

// Implement the plugin trait using the macro
impl crate::plugin::AeadPlugin for Shake256Aead {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Shake256Aead
    }

    fn create(&self) -> Result<Box<dyn AeadWithMetadata>> {
        Ok(Box::new(Self::new()))
    }

    fn metadata(&self) -> &'static AeadMetadata {
        crate::metadata::get_metadata(Algorithm::Shake256Aead)
            .expect("Metadata not found for algorithm")
    }

    fn name(&self) -> &'static str {
        "SHAKE256 AEAD"
    }

    fn version(&self) -> &'static str {
        "1.0.0"
    }

    fn description(&self) -> &'static str {
        "SHAKE256-based AEAD construction using post-quantum hash function with proper domain separation"
    }
}

#[cfg(test)]
mod tests {
    use lib_q_core::{
        AeadDecryptSemantic,
        DecryptSemanticOutcome,
    };

    use super::*;

    /// Generate a proper test key with good entropy
    fn create_test_key() -> AeadKey {
        AeadKey::new(vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
            0xDD, 0xEE, 0xFF, 0x00,
        ])
    }

    /// Generate a proper test nonce with good entropy
    fn create_test_nonce() -> Nonce {
        Nonce::new(vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ])
    }

    /// Generate a different test key for wrong key tests
    fn create_test_key2() -> AeadKey {
        AeadKey::new(vec![
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98,
            0x76, 0x54, 0x32, 0x10,
        ])
    }

    /// Generate a different test nonce for wrong nonce tests
    fn create_test_nonce2() -> Nonce {
        Nonce::new(vec![
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00,
        ])
    }

    #[cfg(feature = "shake256")]
    #[test]
    fn test_shake256_decrypt_semantic_matches_decrypt() {
        let aead = Shake256Aead::new();
        let key = create_test_key();
        let nonce = create_test_nonce();
        let ad = b"metadata";
        let pt = b"semantic path";
        let ct = aead.encrypt(&key, &nonce, pt, Some(ad)).expect("encrypt");
        let layer_a = aead.decrypt(&key, &nonce, &ct, Some(ad)).expect("decrypt");
        match aead
            .decrypt_semantic(&key, &nonce, &ct, Some(ad))
            .expect("decrypt_semantic")
        {
            DecryptSemanticOutcome::Success(got) => {
                assert_eq!(got.as_slice(), layer_a.as_slice())
            }
            DecryptSemanticOutcome::AuthenticationFailed => {
                panic!("expected Success")
            }
        }
    }

    #[cfg(feature = "shake256")]
    #[test]
    fn test_shake256_decrypt_semantic_tampered_tag() {
        let aead = Shake256Aead::new();
        let key = create_test_key();
        let nonce = create_test_nonce();
        let mut ct = aead.encrypt(&key, &nonce, b"x", None).unwrap();
        *ct.last_mut().unwrap() ^= 1;
        let out = aead.decrypt_semantic(&key, &nonce, &ct, None).unwrap();
        assert_eq!(out, DecryptSemanticOutcome::AuthenticationFailed);
    }

    #[test]
    fn test_shake256_creation() {
        let aead = Shake256Aead::new();
        assert_eq!(aead.algorithm(), Algorithm::Shake256Aead);
        assert_eq!(aead.key_size(), 32);
        assert_eq!(aead.nonce_size(), 16);
        assert_eq!(aead.tag_size(), 32);
        assert_eq!(aead.security_level(), 1);
    }

    #[test]
    fn test_shake256_metadata() {
        let aead = Shake256Aead::new();
        let metadata = aead.metadata();

        assert_eq!(metadata.algorithm, Algorithm::Shake256Aead);
        assert_eq!(metadata.name, "SHAKE256-AEAD");
        assert_eq!(metadata.key_size, 32);
        assert_eq!(metadata.nonce_size, 16);
        assert_eq!(metadata.tag_size, 32);
        assert_eq!(metadata.security_level, 1);
    }

    #[test]
    fn test_shake256_validation() {
        let aead = Shake256Aead::new();

        // Test valid key
        let key = AeadKey::new(vec![0u8; 32]);
        assert!(aead.validate_key(&key).is_ok());

        // Test invalid key size
        let invalid_key = AeadKey::new(vec![0u8; 16]);
        assert!(aead.validate_key(&invalid_key).is_err());

        // Test valid nonce
        let nonce = Nonce::new(vec![0u8; 16]);
        assert!(aead.validate_nonce(&nonce).is_ok());

        // Test invalid nonce size
        let invalid_nonce = Nonce::new(vec![0u8; 12]);
        assert!(aead.validate_nonce(&invalid_nonce).is_err());
    }

    #[cfg(feature = "shake256")]
    #[test]
    fn test_shake256_encrypt_decrypt() {
        let aead = Shake256Aead::new();

        let key = create_test_key();
        let nonce = create_test_nonce();
        let plaintext = b"Hello, World!";
        let associated_data = b"metadata";

        // Encrypt
        let ciphertext = aead.encrypt(&key, &nonce, plaintext, Some(associated_data.as_slice()));
        assert!(ciphertext.is_ok());

        let ciphertext = ciphertext.unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + aead.tag_size());

        // Decrypt
        let decrypted = aead.decrypt(&key, &nonce, &ciphertext, Some(associated_data.as_slice()));
        assert!(decrypted.is_ok());
        assert_eq!(decrypted.unwrap(), plaintext);
    }

    #[cfg(feature = "shake256")]
    #[test]
    fn test_shake256_authentication_failure() {
        let aead = Shake256Aead::new();

        let key = create_test_key();
        let nonce = create_test_nonce();
        let plaintext = b"Hello, World!";

        // Encrypt
        let ciphertext = aead.encrypt(&key, &nonce, plaintext, None).unwrap();

        // Tamper with ciphertext
        let mut tampered = ciphertext.clone();
        tampered[0] ^= 0xFF;

        // Decrypt should fail
        let result = aead.decrypt(&key, &nonce, &tampered, None);
        assert!(result.is_err());

        if let Err(Error::AuthenticationFailed { operation }) = result {
            assert!(operation.contains("Tag verification failed"));
        } else {
            panic!("Expected AuthenticationFailed error");
        }
    }

    #[cfg(feature = "shake256")]
    #[test]
    fn test_shake256_wrong_key() {
        let aead = Shake256Aead::new();

        let key1 = create_test_key();
        let key2 = create_test_key2();
        let nonce = create_test_nonce();
        let plaintext = b"Hello, World!";

        // Encrypt with key1
        let ciphertext = aead.encrypt(&key1, &nonce, plaintext, None).unwrap();

        // Decrypt with key2 should fail
        let result = aead.decrypt(&key2, &nonce, &ciphertext, None);
        assert!(result.is_err());
    }

    #[cfg(feature = "shake256")]
    #[test]
    fn test_shake256_wrong_nonce() {
        let aead = Shake256Aead::new();

        let key = create_test_key();
        let nonce1 = create_test_nonce();
        let nonce2 = create_test_nonce2();
        let plaintext = b"Hello, World!";

        // Encrypt with nonce1
        let ciphertext = aead.encrypt(&key, &nonce1, plaintext, None).unwrap();

        // Decrypt with nonce2 should fail
        let result = aead.decrypt(&key, &nonce2, &ciphertext, None);
        assert!(result.is_err());
    }

    #[cfg(feature = "shake256")]
    #[test]
    fn test_shake256_empty_plaintext() {
        let aead = Shake256Aead::new();

        let key = create_test_key();
        let nonce = create_test_nonce();
        let plaintext = b"";

        // Encrypt empty plaintext
        let ciphertext = aead.encrypt(&key, &nonce, plaintext, None);
        assert!(ciphertext.is_ok());

        let ciphertext = ciphertext.unwrap();
        assert_eq!(ciphertext.len(), aead.tag_size());

        // Decrypt should work
        let decrypted = aead.decrypt(&key, &nonce, &ciphertext, None);
        assert!(decrypted.is_ok());
        assert_eq!(decrypted.unwrap(), plaintext);
    }

    #[cfg(feature = "shake256")]
    #[test]
    fn test_shake256_domain_separation() {
        let aead = Shake256Aead::new();

        let key = create_test_key();
        let nonce = create_test_nonce();
        let plaintext = b"Test message";

        // Encrypt with different associated data should produce different ciphertexts
        let ciphertext1 = aead.encrypt(&key, &nonce, plaintext, Some(b"ad1")).unwrap();
        let ciphertext2 = aead.encrypt(&key, &nonce, plaintext, Some(b"ad2")).unwrap();

        // Should be different due to domain separation
        assert_ne!(ciphertext1, ciphertext2);

        // Both should decrypt correctly with their respective AD
        let decrypted1 = aead
            .decrypt(&key, &nonce, &ciphertext1, Some(b"ad1"))
            .unwrap();
        let decrypted2 = aead
            .decrypt(&key, &nonce, &ciphertext2, Some(b"ad2"))
            .unwrap();

        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
    }

    #[cfg(feature = "shake256")]
    #[test]
    fn test_shake256_nonce_uniqueness() {
        let aead = Shake256Aead::new();

        let key = create_test_key();
        let plaintext = b"Test message";

        // Encrypt with different nonces should produce different ciphertexts
        let nonce1 = create_test_nonce();
        let nonce2 = create_test_nonce2();

        let ciphertext1 = aead.encrypt(&key, &nonce1, plaintext, None).unwrap();
        let ciphertext2 = aead.encrypt(&key, &nonce2, plaintext, None).unwrap();

        // Should be different due to nonce uniqueness
        assert_ne!(ciphertext1, ciphertext2);

        // Both should decrypt correctly with their respective nonces
        let decrypted1 = aead.decrypt(&key, &nonce1, &ciphertext1, None).unwrap();
        let decrypted2 = aead.decrypt(&key, &nonce2, &ciphertext2, None).unwrap();

        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
    }
}
