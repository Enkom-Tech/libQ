//! lib-Q Classical McEliece Provider Implementation
//!
//! This module provides the LibQCbKemProvider that implements the KemOperations
//! trait and routes Classical McEliece KEM operations to the appropriate algorithm
//! implementations with proper security validation.

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::{
    string::ToString,
    vec::Vec,
};

#[cfg(feature = "alloc")]
use lib_q_core::api::{
    Algorithm,
    CryptoProvider,
    KemOperations,
};
#[cfg(feature = "alloc")]
use lib_q_core::error::{
    Error,
    Result,
};
#[cfg(feature = "alloc")]
use lib_q_core::security::SecurityValidator;
#[cfg(feature = "alloc")]
use lib_q_core::traits::{
    KemKeypair,
    KemPublicKey,
    KemSecretKey,
};

// Import Classical McEliece implementations
#[cfg(feature = "alloc")]
use crate::{
    CRYPTO_BYTES,
    CRYPTO_CIPHERTEXTBYTES,
    CRYPTO_PUBLICKEYBYTES,
    CRYPTO_SECRETKEYBYTES,
    Ciphertext,
    PublicKey,
    SecretKey,
    decapsulate,
    encapsulate,
    keypair,
};

/// lib-Q Classical McEliece KEM provider implementation
///
/// This provider implements KEM operations for Classical McEliece, including key generation,
/// encapsulation, and decapsulation with proper security validation and algorithm routing.
#[cfg(feature = "alloc")]
#[derive(Clone)]
pub struct LibQCbKemProvider {
    security_validator: SecurityValidator,
}

#[cfg(feature = "alloc")]
impl core::fmt::Debug for LibQCbKemProvider {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LibQCbKemProvider")
            .field("security_validator", &"<SecurityValidator>")
            .finish()
    }
}

#[cfg(feature = "alloc")]
impl LibQCbKemProvider {
    /// Create a new Classical McEliece KEM provider
    ///
    /// # Returns
    ///
    /// A new instance of LibQCbKemProvider with security validation initialized.
    ///
    /// # Errors
    ///
    /// Returns an error if the security validator fails to initialize.
    pub fn new() -> Result<Self> {
        Ok(Self {
            security_validator: SecurityValidator::new()?,
        })
    }

    /// Get the security validator
    pub fn security_validator(&self) -> &SecurityValidator {
        &self.security_validator
    }

    /// Get mutable access to the security validator
    ///
    /// This method is provided for testing scenarios where entropy validation
    /// needs to be disabled for deterministic testing. Use with caution in production.
    pub fn security_validator_mut(&mut self) -> &mut SecurityValidator {
        &mut self.security_validator
    }
}

#[cfg(feature = "alloc")]
impl KemOperations for LibQCbKemProvider {
    fn generate_keypair(
        &self,
        algorithm: Algorithm,
        randomness: Option<&[u8]>,
    ) -> Result<KemKeypair> {
        // Validate algorithm category
        self.security_validator
            .validate_algorithm_category(algorithm, lib_q_core::api::AlgorithmCategory::Kem)?;

        // Validate randomness if provided
        if let Some(rng) = randomness {
            self.security_validator.validate_randomness(rng)?;
        }

        // Route to specific algorithm implementation
        match algorithm {
            // Classical McEliece algorithms
            Algorithm::CbKem348864 => self.generate_cb_kem_keypair(
                CRYPTO_PUBLICKEYBYTES,
                CRYPTO_SECRETKEYBYTES,
                randomness,
            ),
            Algorithm::CbKem460896 => self.generate_cb_kem_keypair(
                CRYPTO_PUBLICKEYBYTES,
                CRYPTO_SECRETKEYBYTES,
                randomness,
            ),
            Algorithm::CbKem6688128 => self.generate_cb_kem_keypair(
                CRYPTO_PUBLICKEYBYTES,
                CRYPTO_SECRETKEYBYTES,
                randomness,
            ),
            Algorithm::CbKem6960119 => self.generate_cb_kem_keypair(
                CRYPTO_PUBLICKEYBYTES,
                CRYPTO_SECRETKEYBYTES,
                randomness,
            ),
            Algorithm::CbKem8192128 => self.generate_cb_kem_keypair(
                CRYPTO_PUBLICKEYBYTES,
                CRYPTO_SECRETKEYBYTES,
                randomness,
            ),

            _ => Err(Error::InvalidAlgorithm {
                algorithm: "Algorithm not supported for Classical McEliece KEM operations",
            }),
        }
    }

    fn encapsulate(
        &self,
        algorithm: Algorithm,
        public_key: &KemPublicKey,
        randomness: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        // Validate algorithm category
        self.security_validator
            .validate_algorithm_category(algorithm, lib_q_core::api::AlgorithmCategory::Kem)?;

        // Validate public key size only (skip entropy validation for CB-KEM keys)
        self.security_validator
            .validate_key_size(algorithm, public_key.as_bytes(), false)?;

        // Validate randomness if provided
        if let Some(rng) = randomness {
            self.security_validator.validate_randomness(rng)?;
        }

        // Route to specific algorithm implementation
        match algorithm {
            // Classical McEliece algorithms
            Algorithm::CbKem348864 |
            Algorithm::CbKem460896 |
            Algorithm::CbKem6688128 |
            Algorithm::CbKem6960119 |
            Algorithm::CbKem8192128 => self.encapsulate_cb_kem(public_key, randomness),

            _ => Err(Error::InvalidAlgorithm {
                algorithm: "Algorithm not supported for Classical McEliece KEM operations",
            }),
        }
    }

    fn decapsulate(
        &self,
        algorithm: Algorithm,
        secret_key: &KemSecretKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        // Validate algorithm category
        self.security_validator
            .validate_algorithm_category(algorithm, lib_q_core::api::AlgorithmCategory::Kem)?;

        // Validate secret key size only (skip entropy validation for CB-KEM keys)
        self.security_validator
            .validate_key_size(algorithm, secret_key.as_bytes(), true)?;

        // Validate ciphertext
        self.security_validator
            .validate_ciphertext(algorithm, ciphertext)?;

        // Route to specific algorithm implementation
        match algorithm {
            // Classical McEliece algorithms
            Algorithm::CbKem348864 |
            Algorithm::CbKem460896 |
            Algorithm::CbKem6688128 |
            Algorithm::CbKem6960119 |
            Algorithm::CbKem8192128 => self.decapsulate_cb_kem(secret_key, ciphertext),

            _ => Err(Error::InvalidAlgorithm {
                algorithm: "Algorithm not supported for Classical McEliece KEM operations",
            }),
        }
    }

    fn derive_public_key(
        &self,
        _algorithm: Algorithm,
        _secret_key: &KemSecretKey,
    ) -> Result<KemPublicKey> {
        // Classical McEliece doesn't support public key derivation from secret key
        // The public key is generated independently during keypair generation
        Err(Error::UnsupportedOperation {
            operation: "Classical McEliece does not support public key derivation from secret key"
                .to_string(),
        })
    }
}

#[cfg(feature = "alloc")]
impl LibQCbKemProvider {
    /// Generate a Classical McEliece keypair
    fn generate_cb_kem_keypair(
        &self,
        public_key_size: usize,
        secret_key_size: usize,
        randomness: Option<&[u8]>,
    ) -> Result<KemKeypair> {
        // Validate key sizes
        if public_key_size != CRYPTO_PUBLICKEYBYTES {
            return Err(Error::InvalidKeySize {
                expected: CRYPTO_PUBLICKEYBYTES,
                actual: public_key_size,
            });
        }
        if secret_key_size != CRYPTO_SECRETKEYBYTES {
            return Err(Error::InvalidKeySize {
                expected: CRYPTO_SECRETKEYBYTES,
                actual: secret_key_size,
            });
        }

        // Create buffers for keys
        let mut public_key_buf = [0u8; CRYPTO_PUBLICKEYBYTES];
        let mut secret_key_buf = [0u8; CRYPTO_SECRETKEYBYTES];

        // Generate keypair using Classical McEliece
        let (public_key, secret_key) = if let Some(rng_bytes) = randomness {
            // Use provided randomness with deterministic RNG
            // Use local RNG implementation (non-blocking)
            {
                let mut rng = crate::LibQRng::new_deterministic_from_bytes(rng_bytes);
                keypair(&mut public_key_buf, &mut secret_key_buf, &mut rng)
            }
        } else {
            // Use secure system randomness with local RNG (non-blocking)
            {
                let mut rng = crate::LibQRng::new();
                keypair(&mut public_key_buf, &mut secret_key_buf, &mut rng)
            }
        };

        // Convert to libQ types
        let kem_public_key = KemPublicKey::new(public_key.as_array().to_vec());
        let kem_secret_key = KemSecretKey::new(secret_key.as_array().to_vec());

        Ok(KemKeypair::new(
            kem_public_key.as_bytes().to_vec(),
            kem_secret_key.as_bytes().to_vec(),
        ))
    }

    /// Encapsulate using Classical McEliece
    fn encapsulate_cb_kem(
        &self,
        public_key: &KemPublicKey,
        randomness: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        // Validate public key size
        if public_key.as_bytes().len() != CRYPTO_PUBLICKEYBYTES {
            return Err(Error::InvalidKeySize {
                expected: CRYPTO_PUBLICKEYBYTES,
                actual: public_key.as_bytes().len(),
            });
        }

        // Create public key from bytes
        let mut public_key_buf = [0u8; CRYPTO_PUBLICKEYBYTES];
        public_key_buf.copy_from_slice(public_key.as_bytes());
        let public_key = PublicKey::from(&mut public_key_buf);

        // Create shared secret buffer
        let mut shared_secret_buf = [0u8; CRYPTO_BYTES];

        // Encapsulate
        let (ciphertext, shared_secret) = if let Some(rng_bytes) = randomness {
            // Use provided randomness with deterministic RNG
            // Use local RNG implementation (non-blocking)
            {
                let mut rng = crate::LibQRng::new_deterministic_from_bytes(rng_bytes);
                encapsulate(&public_key, &mut shared_secret_buf, &mut rng)
            }
        } else {
            // Use secure system randomness with local RNG (non-blocking)
            {
                let mut rng = crate::LibQRng::new();
                encapsulate(&public_key, &mut shared_secret_buf, &mut rng)
            }
        };

        Ok((
            ciphertext.as_array().to_vec(),
            shared_secret.as_array().to_vec(),
        ))
    }

    /// Decapsulate using Classical McEliece
    fn decapsulate_cb_kem(&self, secret_key: &KemSecretKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Validate secret key size
        if secret_key.as_bytes().len() != CRYPTO_SECRETKEYBYTES {
            return Err(Error::InvalidKeySize {
                expected: CRYPTO_SECRETKEYBYTES,
                actual: secret_key.as_bytes().len(),
            });
        }

        // Validate ciphertext size
        if ciphertext.len() != CRYPTO_CIPHERTEXTBYTES {
            return Err(Error::InvalidCiphertextSize {
                expected: CRYPTO_CIPHERTEXTBYTES,
                actual: ciphertext.len(),
            });
        }

        // Create secret key from bytes
        let mut secret_key_buf = [0u8; CRYPTO_SECRETKEYBYTES];
        secret_key_buf.copy_from_slice(secret_key.as_bytes());
        let secret_key = SecretKey::from(&mut secret_key_buf);

        // Create ciphertext from bytes
        let mut ciphertext_buf = [0u8; CRYPTO_CIPHERTEXTBYTES];
        ciphertext_buf.copy_from_slice(ciphertext);
        let ciphertext = Ciphertext::from(ciphertext_buf);

        // Create shared secret buffer
        let mut shared_secret_buf = [0u8; CRYPTO_BYTES];

        // Decapsulate
        let shared_secret = decapsulate(&ciphertext, &secret_key, &mut shared_secret_buf);

        Ok(shared_secret.as_array().to_vec())
    }
}

#[cfg(feature = "alloc")]
impl CryptoProvider for LibQCbKemProvider {
    fn kem(&self) -> Option<&dyn KemOperations> {
        Some(self)
    }

    fn signature(&self) -> Option<&dyn lib_q_core::api::SignatureOperations> {
        None
    }

    fn hash(&self) -> Option<&dyn lib_q_core::api::HashOperations> {
        None
    }

    fn aead(&self) -> Option<&dyn lib_q_core::api::AeadOperations> {
        None
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    /// [`Algorithm`] that matches the single active `cbkem*` feature for this build (see `api.rs`).
    fn compiled_cb_kem_algorithm() -> Algorithm {
        #[cfg(any(feature = "cbkem348864", feature = "cbkem348864f"))]
        {
            Algorithm::CbKem348864
        }
        #[cfg(all(
            not(any(feature = "cbkem348864", feature = "cbkem348864f")),
            any(feature = "cbkem460896", feature = "cbkem460896f"),
        ))]
        {
            Algorithm::CbKem460896
        }
        #[cfg(all(
            not(any(
                feature = "cbkem348864",
                feature = "cbkem348864f",
                feature = "cbkem460896",
                feature = "cbkem460896f",
            )),
            any(feature = "cbkem6688128", feature = "cbkem6688128f"),
        ))]
        {
            Algorithm::CbKem6688128
        }
        #[cfg(all(
            not(any(
                feature = "cbkem348864",
                feature = "cbkem348864f",
                feature = "cbkem460896",
                feature = "cbkem460896f",
                feature = "cbkem6688128",
                feature = "cbkem6688128f",
            )),
            any(feature = "cbkem6960119", feature = "cbkem6960119f"),
        ))]
        {
            Algorithm::CbKem6960119
        }
        #[cfg(all(
            not(any(
                feature = "cbkem348864",
                feature = "cbkem348864f",
                feature = "cbkem460896",
                feature = "cbkem460896f",
                feature = "cbkem6688128",
                feature = "cbkem6688128f",
                feature = "cbkem6960119",
                feature = "cbkem6960119f",
            )),
            any(feature = "cbkem8192128", feature = "cbkem8192128f"),
        ))]
        {
            Algorithm::CbKem8192128
        }
    }

    #[test]
    fn test_provider_creation() {
        let provider = LibQCbKemProvider::new();
        assert!(provider.is_ok(), "Provider should be created successfully");
    }

    #[test]
    fn test_provider_security_validator() {
        let provider = LibQCbKemProvider::new().unwrap();
        let _validator = provider.security_validator();
        // Security validator should be accessible
    }

    #[test]
    fn test_provider_unsupported_algorithm() {
        let provider = LibQCbKemProvider::new().unwrap();
        let result = provider.generate_keypair(Algorithm::Sha3_256, None);
        assert!(
            result.is_err(),
            "Should return error for unsupported algorithm"
        );

        if let Err(Error::InvalidAlgorithm { .. }) = result {
            // Expected error type
        } else {
            panic!("Expected InvalidAlgorithm error");
        }
    }

    #[test]
    fn test_provider_algorithm_routing() {
        let provider = LibQCbKemProvider::new().unwrap();

        // Must match the compiled variant: this crate is built for exactly one `cbkem*` feature.
        let alg = compiled_cb_kem_algorithm();

        provider
            .security_validator()
            .validate_algorithm_category(alg, lib_q_core::api::AlgorithmCategory::Kem)
            .expect("compiled CB-KEM algorithm should be a KEM");

        // This crate is `#![no_std]` (the `std` feature is only a cfg knob), so we cannot spawn
        // a thread with a larger stack. Full `keypair()` for large-parameter variants overflows
        // the default test thread stack in debug builds; exercise it only for the smallest build.
        #[cfg(any(feature = "cbkem348864", feature = "cbkem348864f"))]
        {
            let result = provider.generate_keypair(alg, None);
            match result {
                Ok(_) => {}
                Err(Error::NotImplemented { .. }) => {}
                Err(Error::RandomGenerationFailed { .. }) => {}
                Err(e) => panic!("Unexpected error type: {:?}", e),
            }
        }
    }

    #[test]
    fn test_provider_full_kem_cycle() {
        #[cfg(feature = "std")]
        {
            let provider = LibQCbKemProvider::new().unwrap();

            let alg = compiled_cb_kem_algorithm();

            // Test full KEM cycle for the Classical McEliece variant in this build
            let keypair = provider.generate_keypair(alg, None).unwrap();

            // Test encapsulation
            let (ciphertext, shared_secret1) = provider
                .encapsulate(alg, &keypair.public_key, None)
                .unwrap();

            // Test decapsulation
            let shared_secret2 = provider
                .decapsulate(alg, &keypair.secret_key, &ciphertext)
                .unwrap();

            // Verify shared secrets match
            assert_eq!(
                shared_secret1, shared_secret2,
                "Shared secrets should match"
            );

            // Verify sizes are correct
            assert_eq!(
                ciphertext.len(),
                CRYPTO_CIPHERTEXTBYTES,
                "Classical McEliece ciphertext should be {} bytes",
                CRYPTO_CIPHERTEXTBYTES
            );
            assert_eq!(
                shared_secret1.len(),
                CRYPTO_BYTES,
                "Shared secret should be {} bytes",
                CRYPTO_BYTES
            );
        }
    }
}
