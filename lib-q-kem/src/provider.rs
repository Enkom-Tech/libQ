//! lib-Q KEM Provider Implementation
//!
//! This module provides the LibQKemProvider that implements the KemOperations
//! trait and routes KEM operations to the appropriate algorithm implementations
//! with proper security validation.

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

// Import Classical McEliece implementations
#[cfg(feature = "cb-kem")]
use lib_q_cb_kem::LibQCbKemProvider;
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
#[cfg(all(feature = "alloc", feature = "ml-kem"))]
use lib_q_core::traits::Kem;
#[cfg(feature = "alloc")]
use lib_q_core::traits::{
    KemKeypair,
    KemPublicKey,
    KemSecretKey,
};
// Import HQC implementations
#[cfg(feature = "hqc")]
use lib_q_hqc::LibQHqcProvider;

// Import algorithm implementations
#[cfg(feature = "ml-kem")]
use crate::ml_kem::{
    MlKem512Impl,
    MlKem768Impl,
    MlKem1024Impl,
};

/// lib-Q KEM provider implementation
///
/// This provider implements KEM operations for lib-Q, including key generation,
/// encapsulation, and decapsulation with proper security validation and algorithm routing.
#[cfg(feature = "alloc")]
#[derive(Clone)]
pub struct LibQKemProvider {
    security_validator: SecurityValidator,
}

#[cfg(feature = "alloc")]
impl core::fmt::Debug for LibQKemProvider {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LibQKemProvider")
            .field("security_validator", &"<SecurityValidator>")
            .finish()
    }
}

#[cfg(feature = "alloc")]
impl LibQKemProvider {
    /// Create a new KEM provider
    ///
    /// # Returns
    ///
    /// A new instance of LibQKemProvider with security validation initialized.
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
}

#[cfg(feature = "alloc")]
impl KemOperations for LibQKemProvider {
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
            // ML-KEM algorithms
            #[cfg(feature = "ml-kem")]
            Algorithm::MlKem512 => {
                let kem = MlKem512Impl::default();
                kem.generate_keypair()
            }
            #[cfg(feature = "ml-kem")]
            Algorithm::MlKem768 => {
                let kem = MlKem768Impl::default();
                kem.generate_keypair()
            }
            #[cfg(feature = "ml-kem")]
            Algorithm::MlKem1024 => {
                let kem = MlKem1024Impl::default();
                kem.generate_keypair()
            }

            // CB-KEM algorithms
            #[cfg(feature = "cb-kem")]
            Algorithm::CbKem348864 |
            Algorithm::CbKem460896 |
            Algorithm::CbKem6688128 |
            Algorithm::CbKem6960119 |
            Algorithm::CbKem8192128 => {
                let cb_kem_provider = LibQCbKemProvider::new()?;
                cb_kem_provider.generate_keypair(algorithm, randomness)
            }

            // HQC algorithms
            #[cfg(feature = "hqc")]
            Algorithm::Hqc128 | Algorithm::Hqc192 | Algorithm::Hqc256 => {
                let hqc_provider = LibQHqcProvider::new()?;
                hqc_provider.generate_keypair(algorithm, randomness)
            }

            // Handle missing feature flags
            #[cfg(not(feature = "ml-kem"))]
            Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024 => {
                Err(Error::NotImplemented {
                    feature: String::from("ML-KEM implementations require 'ml-kem' feature flag"),
                })
            }
            #[cfg(not(feature = "cb-kem"))]
            Algorithm::CbKem348864 |
            Algorithm::CbKem460896 |
            Algorithm::CbKem6688128 |
            Algorithm::CbKem6960119 |
            Algorithm::CbKem8192128 => Err(Error::NotImplemented {
                feature: String::from("CB-KEM implementations require 'cb-kem' feature flag"),
            }),
            #[cfg(not(feature = "hqc"))]
            Algorithm::Hqc128 | Algorithm::Hqc192 | Algorithm::Hqc256 => {
                Err(Error::NotImplemented {
                    feature: String::from("HQC implementations require 'hqc' feature flag"),
                })
            }
            _ => Err(Error::InvalidAlgorithm {
                algorithm: "Algorithm not supported for KEM operations",
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

        // Validate public key
        self.security_validator
            .validate_public_key(algorithm, public_key.as_bytes())?;

        // Validate randomness if provided
        if let Some(rng) = randomness {
            self.security_validator.validate_randomness(rng)?;
        }

        // Route to specific algorithm implementation
        match algorithm {
            // ML-KEM algorithms
            #[cfg(feature = "ml-kem")]
            Algorithm::MlKem512 => {
                let kem = MlKem512Impl::default();
                kem.encapsulate(public_key)
            }
            #[cfg(feature = "ml-kem")]
            Algorithm::MlKem768 => {
                let kem = MlKem768Impl::default();
                kem.encapsulate(public_key)
            }
            #[cfg(feature = "ml-kem")]
            Algorithm::MlKem1024 => {
                let kem = MlKem1024Impl::default();
                kem.encapsulate(public_key)
            }

            // CB-KEM algorithms
            #[cfg(feature = "cb-kem")]
            Algorithm::CbKem348864 |
            Algorithm::CbKem460896 |
            Algorithm::CbKem6688128 |
            Algorithm::CbKem6960119 |
            Algorithm::CbKem8192128 => {
                let cb_kem_provider = LibQCbKemProvider::new()?;
                cb_kem_provider.encapsulate(algorithm, public_key, randomness)
            }

            // HQC algorithms
            #[cfg(feature = "hqc")]
            Algorithm::Hqc128 | Algorithm::Hqc192 | Algorithm::Hqc256 => {
                let hqc_provider = LibQHqcProvider::new()?;
                hqc_provider.encapsulate(algorithm, public_key, randomness)
            }

            // Handle missing feature flags
            #[cfg(not(feature = "ml-kem"))]
            Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024 => {
                Err(Error::NotImplemented {
                    feature: String::from("ML-KEM implementations require 'ml-kem' feature flag"),
                })
            }
            #[cfg(not(feature = "cb-kem"))]
            Algorithm::CbKem348864 |
            Algorithm::CbKem460896 |
            Algorithm::CbKem6688128 |
            Algorithm::CbKem6960119 |
            Algorithm::CbKem8192128 => Err(Error::NotImplemented {
                feature: String::from("CB-KEM implementations require 'cb-kem' feature flag"),
            }),
            #[cfg(not(feature = "hqc"))]
            Algorithm::Hqc128 | Algorithm::Hqc192 | Algorithm::Hqc256 => {
                Err(Error::NotImplemented {
                    feature: String::from("HQC implementations require 'hqc' feature flag"),
                })
            }
            _ => Err(Error::InvalidAlgorithm {
                algorithm: "Algorithm not supported for KEM operations",
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

        // Validate secret key
        self.security_validator
            .validate_secret_key(algorithm, secret_key.as_bytes())?;

        // Validate ciphertext
        self.security_validator
            .validate_ciphertext(algorithm, ciphertext)?;

        // Route to specific algorithm implementation
        match algorithm {
            // ML-KEM algorithms
            #[cfg(feature = "ml-kem")]
            Algorithm::MlKem512 => {
                let kem = MlKem512Impl::default();
                kem.decapsulate(secret_key, ciphertext)
            }
            #[cfg(feature = "ml-kem")]
            Algorithm::MlKem768 => {
                let kem = MlKem768Impl::default();
                kem.decapsulate(secret_key, ciphertext)
            }
            #[cfg(feature = "ml-kem")]
            Algorithm::MlKem1024 => {
                let kem = MlKem1024Impl::default();
                kem.decapsulate(secret_key, ciphertext)
            }

            // CB-KEM algorithms
            #[cfg(feature = "cb-kem")]
            Algorithm::CbKem348864 |
            Algorithm::CbKem460896 |
            Algorithm::CbKem6688128 |
            Algorithm::CbKem6960119 |
            Algorithm::CbKem8192128 => {
                let cb_kem_provider = LibQCbKemProvider::new()?;
                cb_kem_provider.decapsulate(algorithm, secret_key, ciphertext)
            }

            // HQC algorithms
            #[cfg(feature = "hqc")]
            Algorithm::Hqc128 | Algorithm::Hqc192 | Algorithm::Hqc256 => {
                let hqc_provider = LibQHqcProvider::new()?;
                hqc_provider.decapsulate(algorithm, secret_key, ciphertext)
            }

            // Handle missing feature flags
            #[cfg(not(feature = "ml-kem"))]
            Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024 => {
                Err(Error::NotImplemented {
                    feature: String::from("ML-KEM implementations require 'ml-kem' feature flag"),
                })
            }
            #[cfg(not(feature = "cb-kem"))]
            Algorithm::CbKem348864 |
            Algorithm::CbKem460896 |
            Algorithm::CbKem6688128 |
            Algorithm::CbKem6960119 |
            Algorithm::CbKem8192128 => Err(Error::NotImplemented {
                feature: String::from("CB-KEM implementations require 'cb-kem' feature flag"),
            }),
            #[cfg(not(feature = "hqc"))]
            Algorithm::Hqc128 | Algorithm::Hqc192 | Algorithm::Hqc256 => {
                Err(Error::NotImplemented {
                    feature: String::from("HQC implementations require 'hqc' feature flag"),
                })
            }

            _ => Err(Error::InvalidAlgorithm {
                algorithm: "Algorithm not supported for KEM operations",
            }),
        }
    }

    fn derive_public_key(
        &self,
        algorithm: Algorithm,
        secret_key: &KemSecretKey,
    ) -> Result<KemPublicKey> {
        // Validate algorithm category
        self.security_validator
            .validate_algorithm_category(algorithm, lib_q_core::api::AlgorithmCategory::Kem)?;

        // Validate secret key
        self.security_validator
            .validate_secret_key(algorithm, secret_key.as_bytes())?;

        // Route to specific algorithm implementation
        match algorithm {
            // ML-KEM algorithms
            #[cfg(feature = "ml-kem")]
            Algorithm::MlKem512 => {
                let kem = MlKem512Impl::default();
                kem.derive_public_key(secret_key)
            }
            #[cfg(feature = "ml-kem")]
            Algorithm::MlKem768 => {
                let kem = MlKem768Impl::default();
                kem.derive_public_key(secret_key)
            }
            #[cfg(feature = "ml-kem")]
            Algorithm::MlKem1024 => {
                let kem = MlKem1024Impl::default();
                kem.derive_public_key(secret_key)
            }

            // CB-KEM algorithms
            #[cfg(feature = "cb-kem")]
            Algorithm::CbKem348864 |
            Algorithm::CbKem460896 |
            Algorithm::CbKem6688128 |
            Algorithm::CbKem6960119 |
            Algorithm::CbKem8192128 => {
                let cb_kem_provider = LibQCbKemProvider::new()?;
                cb_kem_provider.derive_public_key(algorithm, secret_key)
            }

            // HQC algorithms
            #[cfg(feature = "hqc")]
            Algorithm::Hqc128 | Algorithm::Hqc192 | Algorithm::Hqc256 => {
                let hqc_provider = LibQHqcProvider::new()?;
                hqc_provider.derive_public_key(algorithm, secret_key)
            }

            // Handle missing feature flags
            #[cfg(not(feature = "ml-kem"))]
            Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024 => {
                Err(Error::NotImplemented {
                    feature: String::from("ML-KEM implementations require 'ml-kem' feature flag"),
                })
            }
            #[cfg(not(feature = "cb-kem"))]
            Algorithm::CbKem348864 |
            Algorithm::CbKem460896 |
            Algorithm::CbKem6688128 |
            Algorithm::CbKem6960119 |
            Algorithm::CbKem8192128 => Err(Error::NotImplemented {
                feature: String::from("CB-KEM implementations require 'cb-kem' feature flag"),
            }),
            #[cfg(not(feature = "hqc"))]
            Algorithm::Hqc128 | Algorithm::Hqc192 | Algorithm::Hqc256 => {
                Err(Error::NotImplemented {
                    feature: String::from("HQC implementations require 'hqc' feature flag"),
                })
            }

            _ => Err(Error::InvalidAlgorithm {
                algorithm: "Algorithm not supported for KEM operations",
            }),
        }
    }
}

#[cfg(feature = "alloc")]
impl CryptoProvider for LibQKemProvider {
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

    #[test]
    fn test_provider_creation() {
        let provider = LibQKemProvider::new();
        assert!(provider.is_ok(), "Provider should be created successfully");
    }

    #[test]
    fn test_provider_security_validator() {
        let provider = LibQKemProvider::new().unwrap();
        let _validator = provider.security_validator();
        // Security validator should be accessible
    }

    #[test]
    fn test_provider_unsupported_algorithm() {
        let provider = LibQKemProvider::new().unwrap();
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
    fn test_provider_unsupported_algorithm_for_all_kem_operations() {
        let provider = LibQKemProvider::new().unwrap();
        let public_key = KemPublicKey::new(Vec::new());
        let secret_key = KemSecretKey::new(Vec::new());

        let encapsulate_result = provider.encapsulate(Algorithm::Sha3_256, &public_key, None);
        assert!(matches!(
            encapsulate_result,
            Err(Error::InvalidAlgorithm { .. })
        ));

        let decapsulate_result = provider.decapsulate(Algorithm::Sha3_256, &secret_key, &[]);
        assert!(matches!(
            decapsulate_result,
            Err(Error::InvalidAlgorithm { .. })
        ));

        let derive_result = provider.derive_public_key(Algorithm::Sha3_256, &secret_key);
        assert!(matches!(derive_result, Err(Error::InvalidAlgorithm { .. })));
    }

    #[test]
    fn test_provider_feature_flag_handling() {
        let _provider = LibQKemProvider::new().unwrap();

        // Test ML-KEM without feature flag
        #[cfg(not(feature = "ml-kem"))]
        {
            let result = _provider.generate_keypair(Algorithm::MlKem512, None);
            assert!(
                result.is_err(),
                "Should return error when feature flag is not enabled"
            );

            if let Err(Error::NotImplemented { feature }) = result {
                assert!(
                    feature.contains("ML-KEM implementations require 'ml-kem' feature flag"),
                    "Error should mention feature flag requirement"
                );
            } else {
                panic!("Expected NotImplemented error");
            }
        }
    }

    #[test]
    fn test_provider_algorithm_routing() {
        let _provider = LibQKemProvider::new().unwrap();

        // Test that algorithms are properly routed
        #[cfg(feature = "ml-kem")]
        {
            let result = _provider.generate_keypair(Algorithm::MlKem512, None);
            // Should either succeed or return NotImplemented (depending on std feature)
            match result {
                Ok(_) => {
                    // Success case - this is expected with std feature
                }
                Err(Error::NotImplemented { .. }) => {
                    // Expected when std feature is not available
                }
                Err(Error::RandomGenerationFailed { .. }) => {
                    // Expected when std feature is not available for randomness generation
                }
                Err(e) => {
                    panic!("Unexpected error type: {:?}", e);
                }
            }
        }
    }

    #[test]
    fn test_provider_full_kem_cycle() {
        #[cfg(feature = "ml-kem")]
        {
            let provider = LibQKemProvider::new().unwrap();

            // Test full KEM cycle for ML-KEM-512
            let keypair = provider
                .generate_keypair(Algorithm::MlKem512, None)
                .unwrap();

            // Test encapsulation
            let (ciphertext, shared_secret1) = provider
                .encapsulate(Algorithm::MlKem512, &keypair.public_key, None)
                .unwrap();

            // Test decapsulation
            let shared_secret2 = provider
                .decapsulate(Algorithm::MlKem512, &keypair.secret_key, &ciphertext)
                .unwrap();

            // Verify shared secrets match
            assert_eq!(
                shared_secret1, shared_secret2,
                "Shared secrets should match"
            );

            // Verify sizes are correct
            assert_eq!(
                ciphertext.len(),
                768,
                "ML-KEM-512 ciphertext should be 768 bytes"
            );
            assert_eq!(shared_secret1.len(), 32, "Shared secret should be 32 bytes");
        }
    }

    /// Analogous to `fn_dsa_round_trips_through_the_provider_at_every_parameter_set` in
    /// `lib-q-sig/src/provider.rs`: exercise every ML-KEM parameter set through the provider,
    /// not just ML-KEM-512, so a size-table drift on ML-KEM-768/1024 is caught here too.
    #[test]
    #[cfg(feature = "ml-kem")]
    fn ml_kem_round_trips_through_the_provider_at_every_parameter_set() {
        let provider = LibQKemProvider::new().unwrap();

        for algorithm in [
            Algorithm::MlKem512,
            Algorithm::MlKem768,
            Algorithm::MlKem1024,
        ] {
            let keypair = provider
                .generate_keypair(algorithm, None)
                .unwrap_or_else(|e| panic!("{algorithm:?} keygen failed: {e:?}"));

            let (ciphertext, shared_secret1) = provider
                .encapsulate(algorithm, &keypair.public_key, None)
                .unwrap_or_else(|e| panic!("{algorithm:?} encapsulate failed: {e:?}"));

            let shared_secret2 = provider
                .decapsulate(algorithm, &keypair.secret_key, &ciphertext)
                .unwrap_or_else(|e| panic!("{algorithm:?} decapsulate failed: {e:?}"));

            assert_eq!(
                shared_secret1, shared_secret2,
                "{algorithm:?}: shared secrets should match"
            );
        }
    }

    #[test]
    fn test_crypto_provider_trait_exposes_only_kem_operations() {
        let provider = LibQKemProvider::new().unwrap();
        let crypto_provider: &dyn CryptoProvider = &provider;
        assert!(crypto_provider.kem().is_some());
        assert!(crypto_provider.signature().is_none());
        assert!(crypto_provider.hash().is_none());
        assert!(crypto_provider.aead().is_none());
    }

    /// The `Debug` impl must identify the provider without ever printing validator internals —
    /// a provider dumped into a log line must not become a disclosure channel.
    #[test]
    fn debug_impl_names_the_provider_and_redacts_the_security_validator() {
        let provider = LibQKemProvider::new().unwrap();
        let rendered = alloc::format!("{provider:?}");
        assert!(
            rendered.contains("LibQKemProvider"),
            "Debug output should name the type, got: {rendered}"
        );
        assert!(
            rendered.contains("<SecurityValidator>"),
            "Debug output should redact the validator, got: {rendered}"
        );
    }

    /// `derive_public_key` had no success-path coverage at all: every existing test reached it
    /// only with an algorithm the category check rejects. Derivation must reproduce exactly the
    /// public key that `generate_keypair` returned, at every ML-KEM parameter set.
    #[test]
    #[cfg(feature = "ml-kem")]
    fn ml_kem_derive_public_key_reproduces_the_generated_public_key_at_every_parameter_set() {
        let provider = LibQKemProvider::new().unwrap();

        for algorithm in [
            Algorithm::MlKem512,
            Algorithm::MlKem768,
            Algorithm::MlKem1024,
        ] {
            let keypair = provider
                .generate_keypair(algorithm, None)
                .unwrap_or_else(|e| panic!("{algorithm:?} keygen failed: {e:?}"));

            let derived = provider
                .derive_public_key(algorithm, &keypair.secret_key)
                .unwrap_or_else(|e| panic!("{algorithm:?} derive_public_key failed: {e:?}"));

            assert_eq!(
                derived.as_bytes(),
                keypair.public_key.as_bytes(),
                "{algorithm:?}: derived public key should equal the generated one"
            );

            // A derived key must be usable: encapsulating against it must decapsulate correctly
            // under the original secret key.
            let (ciphertext, shared_secret1) = provider
                .encapsulate(algorithm, &derived, None)
                .unwrap_or_else(|e| panic!("{algorithm:?} encapsulate failed: {e:?}"));
            let shared_secret2 = provider
                .decapsulate(algorithm, &keypair.secret_key, &ciphertext)
                .unwrap_or_else(|e| panic!("{algorithm:?} decapsulate failed: {e:?}"));
            assert_eq!(
                shared_secret1, shared_secret2,
                "{algorithm:?}: derived public key should interoperate with the secret key"
            );
        }
    }

    /// 48-byte deterministic seed, mirroring `lib-q-kem/tests/hqc_tests.rs`: HQC encapsulation
    /// with OS entropy can sporadically mismatch on the large parameter sets, so the seeded
    /// path is the stable one to assert against.
    #[cfg(feature = "hqc")]
    const fn hqc_seed(base: u8, step: u8) -> [u8; 48] {
        let mut out = [0u8; 48];
        let mut i = 0usize;
        while i < 48 {
            out[i] = base.wrapping_add((i as u8).wrapping_mul(step));
            i += 1;
        }
        out
    }

    /// HQC was routed through `LibQKemProvider` by four separate match arms that no test ever
    /// entered — `hqc_tests.rs` drives `LibQHqcProvider` directly. Exercise the routing itself
    /// at every parameter set: a mis-routed arm (e.g. Hqc192 landing on Hqc128) would break the
    /// round trip here.
    #[test]
    #[cfg(feature = "hqc")]
    fn hqc_round_trips_through_the_provider_at_every_parameter_set() {
        let provider = LibQKemProvider::new().unwrap();

        for (algorithm, base) in [
            (Algorithm::Hqc128, 0x91u8),
            (Algorithm::Hqc192, 0x93),
            (Algorithm::Hqc256, 0x95),
        ] {
            let keygen_seed = hqc_seed(base, 3);
            let keypair = provider
                .generate_keypair(algorithm, Some(&keygen_seed))
                .unwrap_or_else(|e| panic!("{algorithm:?} keygen failed: {e:?}"));

            let derived = provider
                .derive_public_key(algorithm, &keypair.secret_key)
                .unwrap_or_else(|e| panic!("{algorithm:?} derive_public_key failed: {e:?}"));
            assert_eq!(
                derived.as_bytes(),
                keypair.public_key.as_bytes(),
                "{algorithm:?}: derived public key should equal the generated one"
            );

            // Step must not be 1: the security validator rejects sequential byte patterns as
            // low-entropy before the seed ever reaches HQC.
            let encaps_seed = hqc_seed(base ^ 0x20, 7);
            let (ciphertext, shared_secret1) = provider
                .encapsulate(algorithm, &keypair.public_key, Some(&encaps_seed))
                .unwrap_or_else(|e| panic!("{algorithm:?} encapsulate failed: {e:?}"));

            let shared_secret2 = provider
                .decapsulate(algorithm, &keypair.secret_key, &ciphertext)
                .unwrap_or_else(|e| panic!("{algorithm:?} decapsulate failed: {e:?}"));

            assert_eq!(
                shared_secret1, shared_secret2,
                "{algorithm:?}: shared secrets should match"
            );
            assert_eq!(
                shared_secret1.len(),
                32,
                "{algorithm:?}: HQC shared secret should be 32 bytes"
            );
        }
    }

    /// With `cb-kem` off, every CB-KEM algorithm must be rejected with a `NotImplemented` that
    /// names the missing feature — on ALL FOUR operations, not just keygen. Silently succeeding
    /// (or reporting a generic `InvalidAlgorithm`) would hide a build misconfiguration.
    #[test]
    #[cfg(not(feature = "cb-kem"))]
    fn cb_kem_algorithms_report_the_missing_feature_on_every_operation() {
        let provider = LibQKemProvider::new().unwrap();
        let public_key = KemPublicKey::new(Vec::new());
        let secret_key = KemSecretKey::new(Vec::new());

        for algorithm in [
            Algorithm::CbKem348864,
            Algorithm::CbKem460896,
            Algorithm::CbKem6688128,
            Algorithm::CbKem6960119,
            Algorithm::CbKem8192128,
        ] {
            let keygen = provider.generate_keypair(algorithm, None);
            match keygen {
                Err(Error::NotImplemented { ref feature }) => assert!(
                    feature.contains("cb-kem"),
                    "{algorithm:?}: keygen error should name the cb-kem feature, got {feature}"
                ),
                Err(other) => {
                    panic!("{algorithm:?}: expected NotImplemented from keygen, got {other:?}")
                }
                Ok(_) => panic!("{algorithm:?}: keygen must not succeed with cb-kem off"),
            }

            // The other three operations validate their key/ciphertext inputs BEFORE routing, so
            // an empty input is rejected by the validator rather than by the feature gate. That
            // is fine: what must never happen is a CB-KEM operation SUCCEEDING with the feature
            // off. (Presenting a correctly sized buffer to reach the gate itself was tried and
            // abandoned: the validator's entropy scan over a 261 KB CB-KEM key takes ~9 minutes
            // in a debug build, far past CI's 180 s coverage timeout.)
            assert!(
                provider.encapsulate(algorithm, &public_key, None).is_err(),
                "{algorithm:?}: encapsulate must fail with cb-kem off"
            );
            assert!(
                provider.decapsulate(algorithm, &secret_key, &[]).is_err(),
                "{algorithm:?}: decapsulate must fail with cb-kem off"
            );
            assert!(
                provider.derive_public_key(algorithm, &secret_key).is_err(),
                "{algorithm:?}: derive_public_key must fail with cb-kem off"
            );
        }
    }

    /// Caller-supplied randomness must go through the security validator before it reaches any
    /// algorithm implementation. A 16-byte seed is below the 32-byte floor and must be refused
    /// by both `generate_keypair` and `encapsulate` — accepting it would silently halve the
    /// entropy of a key or an encapsulation.
    #[test]
    #[cfg(feature = "ml-kem")]
    fn short_caller_supplied_randomness_is_rejected_before_the_algorithm_runs() {
        let provider = LibQKemProvider::new().unwrap();
        let short_randomness = [0x5Au8; 16];

        let keygen = provider.generate_keypair(Algorithm::MlKem512, Some(&short_randomness));
        assert!(
            matches!(keygen, Err(Error::InvalidKeySize { .. })),
            "16-byte randomness should be rejected by keygen with InvalidKeySize"
        );

        let keypair = provider
            .generate_keypair(Algorithm::MlKem512, None)
            .unwrap();
        let encapsulate = provider.encapsulate(
            Algorithm::MlKem512,
            &keypair.public_key,
            Some(&short_randomness),
        );
        assert!(
            matches!(encapsulate, Err(Error::InvalidKeySize { .. })),
            "16-byte randomness should be rejected by encapsulate, got {encapsulate:?}"
        );
    }

    /// Wrong-size inputs must be refused by the provider's validation layer rather than reaching
    /// the algorithm, where a length mismatch would be an out-of-bounds hazard.
    #[test]
    #[cfg(feature = "ml-kem")]
    fn wrong_size_keys_and_ciphertexts_are_rejected() {
        let provider = LibQKemProvider::new().unwrap();
        let keypair = provider
            .generate_keypair(Algorithm::MlKem512, None)
            .unwrap();

        // A public key one byte short of the ML-KEM-512 encoding.
        let mut truncated_pk = keypair.public_key.as_bytes().to_vec();
        truncated_pk.pop();
        let truncated_pk = KemPublicKey::new(truncated_pk);
        assert!(
            provider
                .encapsulate(Algorithm::MlKem512, &truncated_pk, None)
                .is_err(),
            "truncated public key should be rejected by encapsulate"
        );

        // A well-formed ciphertext for ML-KEM-512 is 768 bytes; 767 must not decapsulate.
        let short_ciphertext = [0u8; 767];
        assert!(
            provider
                .decapsulate(Algorithm::MlKem512, &keypair.secret_key, &short_ciphertext)
                .is_err(),
            "short ciphertext should be rejected by decapsulate"
        );

        // A secret key of the wrong length must not derive a public key.
        let truncated_sk = KemSecretKey::new(keypair.secret_key.as_bytes()[..16].to_vec());
        assert!(
            provider
                .derive_public_key(Algorithm::MlKem512, &truncated_sk)
                .is_err(),
            "truncated secret key should be rejected by derive_public_key"
        );
    }
}
