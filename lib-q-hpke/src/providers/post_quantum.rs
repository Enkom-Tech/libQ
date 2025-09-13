//! Post-quantum provider implementation

#[cfg(feature = "alloc")]
use alloc::boxed::Box;
#[cfg(feature = "alloc")]
use alloc::format;
#[cfg(feature = "alloc")]
use alloc::string::ToString;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use lib_q_aead::create_aead;
// Use lib-q abstractions instead of direct algorithm coupling
use lib_q_core::{
    Aead as CoreAead,
    Algorithm,
    Hash as CoreHash,
    Kem as CoreKem,
};
use lib_q_hash::create_hash;
use lib_q_kem::create_kem;

use crate::error::HpkeError;
use crate::kdf::hkdf::HkdfImpl;
use crate::providers::traits::*;
use crate::security::CryptoRng;
use crate::types::*;

/// Post-quantum provider implementation
pub struct PostQuantumProvider;

impl PostQuantumProvider {
    /// Create a new post-quantum provider
    pub fn new() -> Self {
        Self
    }

    /// Convert HPKE KEM to lib-q-core Algorithm
    fn hpke_kem_to_algorithm(kem: HpkeKem) -> Result<Algorithm, HpkeError> {
        match kem {
            HpkeKem::MlKem512 => Ok(Algorithm::MlKem512),
            HpkeKem::MlKem768 => Ok(Algorithm::MlKem768),
            HpkeKem::MlKem1024 => Ok(Algorithm::MlKem1024),
        }
    }

    /// Create a KEM instance using lib-q-kem abstraction
    fn create_kem_instance(kem: HpkeKem) -> Result<Box<dyn CoreKem>, HpkeError> {
        let algorithm = Self::hpke_kem_to_algorithm(kem)?;
        create_kem(algorithm)
            .map_err(|e| HpkeError::CryptoError(format!("Failed to create KEM instance: {}", e)))
    }

    /// Create hash instance using lib-q-hash abstraction
    fn create_hash_instance(kdf: HpkeKdf) -> Result<Box<dyn CoreHash>, HpkeError> {
        let algorithm_name = match kdf {
            HpkeKdf::HkdfShake128 => "shake128",
            HpkeKdf::HkdfShake256 => "shake256",
            HpkeKdf::HkdfSha3_256 => "sha3-256",
            HpkeKdf::HkdfSha3_512 => "sha3-512",
        };
        create_hash(algorithm_name)
            .map_err(|e| HpkeError::CryptoError(format!("Failed to create hash instance: {}", e)))
    }

    /// Create AEAD instance using lib-q-aead abstraction
    fn create_aead_instance(aead: HpkeAead) -> Result<Box<dyn CoreAead>, HpkeError> {
        let algorithm_name = match aead {
            HpkeAead::Saturnin256 => "saturnin",
            HpkeAead::Shake256 => "shake256", // This might need custom implementation
            HpkeAead::Export => return Err(HpkeError::not_implemented("Export-only AEAD")),
        };
        create_aead(algorithm_name)
            .map_err(|e| HpkeError::CryptoError(format!("Failed to create AEAD instance: {}", e)))
    }
}

impl KemProvider for PostQuantumProvider {
    type Error = HpkeError;

    fn generate_keypair(
        &self,
        kem: HpkeKem,
        _rng: &mut dyn CryptoRng,
    ) -> Result<(Vec<u8>, Vec<u8>), Self::Error> {
        let kem_impl = Self::create_kem_instance(kem)?;
        let keypair = kem_impl
            .generate_keypair()
            .map_err(|e| HpkeError::CryptoError(format!("KEM key generation failed: {}", e)))?;
        Ok((
            keypair.public_key().as_bytes().to_vec(),
            keypair.secret_key().as_bytes().to_vec(),
        ))
    }

    fn encapsulate(
        &self,
        kem: HpkeKem,
        public_key: &[u8],
        _rng: &mut dyn CryptoRng,
    ) -> Result<(Vec<u8>, Vec<u8>), Self::Error> {
        let kem_impl = Self::create_kem_instance(kem)?;
        let pk = lib_q_core::KemPublicKey::new(public_key.to_vec());
        kem_impl
            .encapsulate(&pk)
            .map_err(|e| HpkeError::CryptoError(format!("KEM encapsulation failed: {}", e)))
    }

    fn decapsulate(
        &self,
        kem: HpkeKem,
        secret_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        let kem_impl = Self::create_kem_instance(kem)?;
        let sk = lib_q_core::KemSecretKey::new(secret_key.to_vec());
        kem_impl
            .decapsulate(&sk, ciphertext)
            .map_err(|e| HpkeError::CryptoError(format!("KEM decapsulation failed: {}", e)))
    }

    fn validate_key(&self, kem: HpkeKem, key: &[u8], is_secret: bool) -> Result<(), Self::Error> {
        let expected_len = if is_secret {
            kem.secret_key_len()
        } else {
            kem.public_key_len()
        };

        if key.len() != expected_len {
            return Err(HpkeError::invalid_input(
                "key",
                format!("{} bytes", key.len()),
                format!("{} bytes", expected_len),
            ));
        }

        Ok(())
    }

    fn supports_kem(&self, kem: HpkeKem) -> bool {
        match kem {
            HpkeKem::MlKem512 | HpkeKem::MlKem768 | HpkeKem::MlKem1024 => {
                #[cfg(feature = "ml-kem")]
                {
                    crate::kem::ml_kem::is_ml_kem_available()
                }
                #[cfg(not(feature = "ml-kem"))]
                {
                    false
                }
            }
        }
    }

    fn auth_encapsulate(
        &self,
        kem: HpkeKem,
        sender_sk: &[u8],
        recipient_pk: &[u8],
        _rng: &mut dyn CryptoRng,
    ) -> Result<(Vec<u8>, Vec<u8>), Self::Error> {
        let kem_impl = Self::create_kem_instance(kem)?;

        // AuthEncap implementation according to RFC 9180 Section 5.1.3
        // For ML-KEM, AuthEncap provides sender authentication by:
        // 1. Deriving the sender's public key from the sender's secret key
        // 2. Using the sender's secret key to create an authenticated encapsulation
        // 3. The recipient can verify the sender's identity during AuthDecap

        // Validate sender secret key length
        let expected_sender_sk_len = kem.secret_key_len();
        if sender_sk.len() != expected_sender_sk_len {
            return Err(HpkeError::invalid_input(
                "sender_sk",
                format!("{} bytes", sender_sk.len()),
                format!("{} bytes", expected_sender_sk_len),
            ));
        }

        // Validate recipient public key length
        let expected_recipient_pk_len = kem.public_key_len();
        if recipient_pk.len() != expected_recipient_pk_len {
            return Err(HpkeError::invalid_input(
                "recipient_pk",
                format!("{} bytes", recipient_pk.len()),
                format!("{} bytes", expected_recipient_pk_len),
            ));
        }

        // Create sender secret key object
        let sender_sk_obj = lib_q_core::KemSecretKey::new(sender_sk.to_vec());

        // Derive sender's public key from secret key for authentication
        let sender_pk_obj = kem_impl.derive_public_key(&sender_sk_obj).map_err(|e| {
            HpkeError::CryptoError(format!("Failed to derive sender public key: {}", e))
        })?;

        // Create recipient public key object
        let recipient_pk_obj = lib_q_core::KemPublicKey::new(recipient_pk.to_vec());

        // Perform authenticated encapsulation
        // This creates an encapsulation that can only be decapsulated by someone
        // who knows the sender's secret key, providing cryptographic authentication
        let (encapsulated_key, shared_secret) = kem_impl
            .auth_encapsulate(&sender_sk_obj, &recipient_pk_obj)
            .map_err(|e| HpkeError::CryptoError(format!("AuthEncap failed: {}", e)))?;

        // Return both the encapsulated key and the shared secret
        Ok((encapsulated_key, shared_secret))
    }

    fn auth_decapsulate(
        &self,
        kem: HpkeKem,
        encapsulated_key: &[u8],
        recipient_sk: &[u8],
        sender_pk: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        let kem_impl = Self::create_kem_instance(kem)?;

        // AuthDecap implementation according to RFC 9180 Section 5.1.3
        // For ML-KEM, AuthDecap provides sender authentication verification by:
        // 1. Verifying that the encapsulated key was created by the claimed sender
        // 2. Using the recipient's secret key to decapsulate the shared secret
        // 3. Cryptographically verifying the sender's identity

        // Validate encapsulated key length
        let expected_enc_len = kem.enc_len();
        if encapsulated_key.len() != expected_enc_len {
            return Err(HpkeError::invalid_input(
                "encapsulated_key",
                format!("{} bytes", encapsulated_key.len()),
                format!("{} bytes", expected_enc_len),
            ));
        }

        // Validate recipient secret key length
        let expected_recipient_sk_len = kem.secret_key_len();
        if recipient_sk.len() != expected_recipient_sk_len {
            return Err(HpkeError::invalid_input(
                "recipient_sk",
                format!("{} bytes", recipient_sk.len()),
                format!("{} bytes", expected_recipient_sk_len),
            ));
        }

        // Validate sender public key length
        let expected_sender_pk_len = kem.public_key_len();
        if sender_pk.len() != expected_sender_pk_len {
            return Err(HpkeError::invalid_input(
                "sender_pk",
                format!("{} bytes", sender_pk.len()),
                format!("{} bytes", expected_sender_pk_len),
            ));
        }

        // Create key objects
        let recipient_sk_obj = lib_q_core::KemSecretKey::new(recipient_sk.to_vec());
        let sender_pk_obj = lib_q_core::KemPublicKey::new(sender_pk.to_vec());

        // Perform authenticated decapsulation
        // This verifies that the encapsulated key was created by the sender
        // and can only be decapsulated by the recipient
        let shared_secret = kem_impl
            .auth_decapsulate(&recipient_sk_obj, encapsulated_key, &sender_pk_obj)
            .map_err(|e| HpkeError::CryptoError(format!("AuthDecap failed: {}", e)))?;

        // The successful decapsulation provides cryptographic proof that:
        // 1. The sender has the correct secret key corresponding to sender_pk
        // 2. The recipient has the correct secret key
        // 3. The encapsulated key was created by the authenticated sender

        Ok(shared_secret)
    }
}

impl KdfProvider for PostQuantumProvider {
    type Error = HpkeError;

    fn extract(&self, kdf: HpkeKdf, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, Self::Error> {
        // Use the existing HKDF implementation which is already algorithm-agnostic
        // The HKDF implementation uses lib-q-hash internally
        let hkdf_impl = HkdfImpl::new(kdf);
        hkdf_impl.extract(salt, ikm)
    }

    fn expand(
        &self,
        kdf: HpkeKdf,
        prk: &[u8],
        info: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, Self::Error> {
        // Use the existing HKDF implementation which is already algorithm-agnostic
        // The HKDF implementation uses lib-q-hash internally
        let hkdf_impl = HkdfImpl::new(kdf);
        hkdf_impl.expand(prk, info, output_len)
    }

    fn supports_kdf(&self, kdf: HpkeKdf) -> bool {
        match kdf {
            HpkeKdf::HkdfShake128 |
            HpkeKdf::HkdfShake256 |
            HpkeKdf::HkdfSha3_256 |
            HpkeKdf::HkdfSha3_512 => {
                // Check if we can create a hash instance for this KDF
                Self::create_hash_instance(kdf).is_ok()
            }
        }
    }
}

impl AeadProvider for PostQuantumProvider {
    type Error = HpkeError;

    fn seal(
        &self,
        aead: HpkeAead,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        // Validate inputs
        <Self as AeadProvider>::validate_key(self, aead, key)?;
        self.validate_nonce(aead, nonce)?;

        match aead {
            HpkeAead::Export => {
                // Export mode: return plaintext as-is (no encryption)
                // This is used for key export functionality in HPKE
                Ok(plaintext.to_vec())
            }
            _ => {
                // Use lib-q-aead abstraction for AEAD operations
                let aead_impl = Self::create_aead_instance(aead)?;

                // Create key and nonce objects
                let aead_key = lib_q_core::AeadKey::new(key.to_vec());
                let aead_nonce = lib_q_core::Nonce::new(nonce.to_vec());

                // Perform encryption using the AEAD abstraction
                aead_impl
                    .encrypt(&aead_key, &aead_nonce, plaintext, Some(aad))
                    .map_err(|e| HpkeError::CryptoError(format!("AEAD encryption failed: {}", e)))
            }
        }
    }

    fn open(
        &self,
        aead: HpkeAead,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        // Validate inputs
        <Self as AeadProvider>::validate_key(self, aead, key)?;
        self.validate_nonce(aead, nonce)?;

        match aead {
            HpkeAead::Export => {
                // Export mode: return ciphertext as-is (no decryption)
                // This is used for key export functionality in HPKE
                Ok(ciphertext.to_vec())
            }
            _ => {
                // Use lib-q-aead abstraction for AEAD operations
                let aead_impl = Self::create_aead_instance(aead)?;

                // Create key and nonce objects
                let aead_key = lib_q_core::AeadKey::new(key.to_vec());
                let aead_nonce = lib_q_core::Nonce::new(nonce.to_vec());

                // Perform decryption using the AEAD abstraction
                aead_impl
                    .decrypt(&aead_key, &aead_nonce, ciphertext, Some(aad))
                    .map_err(|e| HpkeError::CryptoError(format!("AEAD decryption failed: {}", e)))
            }
        }
    }

    fn validate_key(&self, aead: HpkeAead, key: &[u8]) -> Result<(), Self::Error> {
        let expected_len = aead.key_len();
        if key.len() != expected_len {
            return Err(HpkeError::invalid_input(
                "key",
                format!("{} bytes", key.len()),
                format!("{} bytes", expected_len),
            ));
        }

        // Security check: reject zero keys
        if key.iter().all(|&b| b == 0) {
            return Err(HpkeError::CryptoError(
                "Key material cannot be all zeros".to_string(),
            ));
        }

        Ok(())
    }

    fn validate_nonce(&self, aead: HpkeAead, nonce: &[u8]) -> Result<(), Self::Error> {
        let expected_len = aead.nonce_len();
        if nonce.len() != expected_len {
            return Err(HpkeError::invalid_input(
                "nonce",
                format!("{} bytes", nonce.len()),
                format!("{} bytes", expected_len),
            ));
        }
        Ok(())
    }

    fn supports_aead(&self, aead: HpkeAead) -> bool {
        match aead {
            HpkeAead::Export => true, // Export mode is always supported (it's export-only)
            _ => Self::create_aead_instance(aead).is_ok(),
        }
    }
}

impl HpkeCryptoProvider for PostQuantumProvider {
    fn name(&self) -> &'static str {
        "PostQuantumProvider"
    }

    fn supported_algorithms(&self) -> SupportedAlgorithms {
        let mut kems = Vec::new();
        let mut kdfs = Vec::new();
        let mut aeads = Vec::new();

        // Check KEM support
        for kem in [HpkeKem::MlKem512, HpkeKem::MlKem768, HpkeKem::MlKem1024] {
            if self.supports_kem(kem) {
                kems.push(kem);
            }
        }

        // Check KDF support
        for kdf in [
            HpkeKdf::HkdfShake128,
            HpkeKdf::HkdfShake256,
            HpkeKdf::HkdfSha3_256,
            HpkeKdf::HkdfSha3_512,
        ] {
            if self.supports_kdf(kdf) {
                kdfs.push(kdf);
            }
        }

        // Check AEAD support
        for aead in [HpkeAead::Saturnin256, HpkeAead::Shake256, HpkeAead::Export] {
            if self.supports_aead(aead) {
                aeads.push(aead);
            }
        }

        SupportedAlgorithms::new(kems, kdfs, aeads)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider = PostQuantumProvider::new();
        assert_eq!(provider.name(), "PostQuantumProvider");
    }

    #[test]
    fn test_supported_algorithms() {
        let provider = PostQuantumProvider::new();
        let algorithms = provider.supported_algorithms();

        // Should have some supported algorithms
        assert!(
            !algorithms.kems.is_empty() ||
                !algorithms.kdfs.is_empty() ||
                !algorithms.aeads.is_empty()
        );
    }

    #[test]
    fn test_kem_support() {
        let provider = PostQuantumProvider::new();

        // Test ML-KEM support
        let ml_kem_512_supported = provider.supports_kem(HpkeKem::MlKem512);
        let ml_kem_768_supported = provider.supports_kem(HpkeKem::MlKem768);
        let ml_kem_1024_supported = provider.supports_kem(HpkeKem::MlKem1024);

        // All should have the same support status (based on ml-kem feature)
        assert_eq!(ml_kem_512_supported, ml_kem_768_supported);
        assert_eq!(ml_kem_768_supported, ml_kem_1024_supported);
    }

    #[test]
    fn test_kdf_support() {
        let provider = PostQuantumProvider::new();

        // Test KDF support
        let shake128_supported = provider.supports_kdf(HpkeKdf::HkdfShake128);
        let shake256_supported = provider.supports_kdf(HpkeKdf::HkdfShake256);
        let sha3_256_supported = provider.supports_kdf(HpkeKdf::HkdfSha3_256);
        let sha3_512_supported = provider.supports_kdf(HpkeKdf::HkdfSha3_512);

        // All should have the same support status (based on hash feature)
        assert_eq!(shake128_supported, shake256_supported);
        assert_eq!(shake256_supported, sha3_256_supported);
        assert_eq!(sha3_256_supported, sha3_512_supported);
    }

    #[test]
    fn test_aead_support() {
        let provider = PostQuantumProvider::new();

        // Test AEAD support
        let saturnin_supported = provider.supports_aead(HpkeAead::Saturnin256);
        let shake256_supported = provider.supports_aead(HpkeAead::Shake256);
        let export_supported = provider.supports_aead(HpkeAead::Export);

        // Export should always be supported
        assert!(export_supported);

        // Others depend on features
        #[cfg(feature = "saturnin")]
        assert!(saturnin_supported);
        #[cfg(not(feature = "saturnin"))]
        assert!(!saturnin_supported);

        // SHAKE256 AEAD is now implemented in lib-q-aead
        // This test reflects the current reality - SHAKE256 AEAD is supported
        assert!(
            shake256_supported,
            "SHAKE256 AEAD should be supported after migration to lib-q-aead"
        );
    }
}
