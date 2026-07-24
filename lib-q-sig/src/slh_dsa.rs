//! SLH-DSA (SPHINCS+) implementation for lib-Q
//!
//! This module provides integration between the lib-q-slh-dsa crate and the lib-q
//! provider pattern, implementing proper security validation and algorithm routing.
//!
//! ## Architecture
//!
//! This implementation follows the lib-q pattern for maximum flexibility:
//! - **Low-level API**: Functions accept randomness externally (no_std compatible)
//! - **High-level API**: Functions generate randomness when std is available
//! - **WASM Support**: JavaScript-compatible bindings for web environments
//! - **External randomness**: Required for key generation and signing operations
//!
//! ## Usage Examples
//!
//! ### With std (automatic randomness generation)
//! ```rust
//! # #[cfg(feature = "slh-dsa-std")]
//! # {
//! use lib_q_core::{
//!     Algorithm,
//!     Signature,
//! };
//! use lib_q_sig::slh_dsa::SlhDsa;
//!
//! let slh_dsa = SlhDsa::new();
//! let keypair = slh_dsa
//!     .generate_keypair_for_algorithm(
//!         Algorithm::SlhDsaShake256128fRobust,
//!         None,
//!     )
//!     .unwrap();
//! let signature = slh_dsa
//!     .sign_for_algorithm(
//!         Algorithm::SlhDsaShake256128fRobust,
//!         keypair.secret_key(),
//!         b"Hello, SLH-DSA!",
//!         None,
//!     )
//!     .unwrap();
//! let is_valid = slh_dsa
//!     .verify_for_algorithm(
//!         Algorithm::SlhDsaShake256128fRobust,
//!         keypair.public_key(),
//!         b"Hello, SLH-DSA!",
//!         &signature,
//!     )
//!     .unwrap();
//! assert!(is_valid);
//! # }
//! ```
//!
//! ### Without std (external randomness)
//! ```rust
//! # #[cfg(feature = "slh-dsa")]
//! # {
//! use lib_q_core::{Algorithm, Signature};
//! use lib_q_sig::slh_dsa::SlhDsa;
//!
//! let slh_dsa = SlhDsa::new();
//!
//! // Provide randomness externally
//! let key_randomness = [0u8; 48]; // Get from hardware RNG (48 bytes for Shake256128f)
//! let signing_randomness = [0u8; 16]; // Get from hardware RNG (size depends on parameter set)
//!
//! let keypair = slh_dsa.generate_keypair_with_randomness(
//!     Algorithm::SlhDsaShake256128fRobust,
//!     &key_randomness
//! ).unwrap();
//! let signature = slh_dsa.sign_with_randomness(
//!     Algorithm::SlhDsaShake256128fRobust,
//!     keypair.secret_key(),
//!     b"Hello, SLH-DSA!",
//!     &signing_randomness
//! ).unwrap();
//! let is_valid = slh_dsa.verify_for_algorithm(
//!     Algorithm::SlhDsaShake256128fRobust,
//!     keypair.public_key(),
//!     b"Hello, SLH-DSA!",
//!     &signature
//! ).unwrap();
//! assert!(is_valid);
//! # }
//! ```
//!
//! ### WASM (JavaScript) environment
//! ```javascript
//! import { SlhDsa, WasmSlhDsaKeyPair } from './pkg/lib_q_sig.js';
//!
//! const slhDsa = new SlhDsa();
//!
//! // Generate keypair
//! const keyRandomness = new Uint8Array(32);
//! const keypair = slhDsa.generate_keypair_wasm("SlhDsaShake256128fRobust", keyRandomness);
//!
//! // Sign message
//! const message = new TextEncoder().encode("Hello, WASM SLH-DSA!");
//! const signingRandomness = new Uint8Array(16);
//! const signature = slhDsa.sign_wasm(
//!     "SlhDsaShake256128fRobust",
//!     keypair.secret_key,
//!     message,
//!     signingRandomness
//! );
//!
//! // Verify signature
//! const isValid = slhDsa.verify_wasm(
//!     "SlhDsaShake256128fRobust",
//!     keypair.public_key,
//!     message,
//!     signature
//! );
//! console.log("Signature valid:", isValid);
//! ```
//!
//! ## Supported Parameter Sets
//!
//! - **SHA256-128f-Robust**: Level 1 security (128-bit)
//! - **SHA256-192f-Robust**: Level 3 security (192-bit)
//! - **SHA256-256f-Robust**: Level 5 security (256-bit)
//! - **SHAKE256-128f-Robust**: Level 1 security (128-bit)
//! - **SHAKE256-192f-Robust**: Level 3 security (192-bit)
//! - **SHAKE256-256f-Robust**: Level 5 security (256-bit)
//!
//! ## Feature Flags
//!
//! - `slh-dsa`: Basic SLH-DSA support (no_std compatible)
//! - `slh-dsa-std`: SLH-DSA with automatic randomness generation
//! - `slh-dsa-wasm`: SLH-DSA with WASM bindings
//! - `wasm`: General WASM support

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::{
    string::ToString,
    vec::Vec,
};

// Import ToString for lib-q-core compatibility (lib-q-core always has alloc enabled)
#[cfg(not(feature = "alloc"))]
extern crate alloc;
#[cfg(not(feature = "alloc"))]
use alloc::string::ToString;

#[cfg(feature = "wasm")]
use js_sys::Uint8Array;
use lib_q_core::api::Algorithm;
use lib_q_core::error::{
    Error,
    Result,
};
use lib_q_core::traits::{
    SigKeypair,
    SigPublicKey,
    SigSecretKey,
    Signature,
};
/// Maximum length of a FIPS-205 signing context, in bytes.
///
/// Re-exported so callers do not have to depend on `lib-q-slh-dsa` directly. See
/// [`lib_q_slh_dsa::lib_q_integration::SLH_DSA_CONTEXT_MAX_LEN`].
#[cfg(feature = "slh-dsa")]
pub use lib_q_slh_dsa::lib_q_integration::SLH_DSA_CONTEXT_MAX_LEN;
#[cfg(feature = "slh-dsa")]
use lib_q_slh_dsa::{
    ParameterSet,
    Sha2_128f,
    Sha2_192f,
    Sha2_256f,
    Shake128f,
    Shake192f,
    Shake256f,
    lib_q_integration::SlhDsaSignature,
};
#[cfg(feature = "slh-dsa-std")]
use rand_core::Rng;
// WASM support
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// SLH-DSA signature implementation wrapper
///
/// This struct provides the lib-Q Signature trait implementation for SLH-DSA,
/// routing operations to the appropriate parameter set based on the algorithm.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct SlhDsa;

impl SlhDsa {
    /// Create a new SLH-DSA instance
    pub fn new() -> Self {
        Self
    }

    /// Generate a keypair with external randomness (no_std compatible)
    ///
    /// This is the low-level API that accepts randomness externally,
    /// making it suitable for no_std environments where randomness
    /// must be provided by the caller (e.g., from hardware RNG).
    ///
    /// # Arguments
    /// * `algorithm` - The SLH-DSA algorithm variant
    /// * `randomness` - Cryptographically secure random bytes for key generation
    ///
    /// # Returns
    /// * `Result<SigKeypair>` - The generated keypair or an error
    ///
    /// # Example
    /// ```rust
    /// # #[cfg(feature = "slh-dsa")]
    /// # {
    /// use lib_q_core::Algorithm;
    /// use lib_q_sig::slh_dsa::SlhDsa;
    ///
    /// let slh_dsa = SlhDsa::new();
    /// let randomness = [0u8; 48]; // Get from hardware RNG (48 bytes for Shake256128f)
    /// let keypair = slh_dsa
    ///     .generate_keypair_with_randomness(
    ///         Algorithm::SlhDsaShake256128fRobust,
    ///         &randomness,
    ///     )
    ///     .unwrap();
    /// # }
    /// ```
    #[cfg(feature = "alloc")]
    pub fn generate_keypair_with_randomness(
        &self,
        algorithm: Algorithm,
        randomness: &[u8],
    ) -> Result<SigKeypair> {
        self.generate_keypair_for_algorithm(algorithm, Some(randomness))
    }

    /// Sign a message with external randomness (no_std compatible)
    ///
    /// This is the low-level API that accepts randomness externally,
    /// making it suitable for no_std environments where randomness
    /// must be provided by the caller (e.g., from hardware RNG).
    ///
    /// # Arguments
    /// * `algorithm` - The SLH-DSA algorithm variant
    /// * `secret_key` - The secret key for signing
    /// * `message` - The message to sign
    /// * `randomness` - Cryptographically secure random bytes for signing
    ///
    /// # Returns
    /// * `Result<Vec<u8>>` - The signature or an error
    ///
    /// # Example
    /// ```rust
    /// # #[cfg(feature = "slh-dsa")]
    /// # {
    /// use lib_q_core::Algorithm;
    /// use lib_q_sig::slh_dsa::SlhDsa;
    ///
    /// let slh_dsa = SlhDsa::new();
    /// let key_randomness = [0u8; 48]; // Get from hardware RNG (48 bytes for Shake256128f)
    /// let signing_randomness = [0u8; 16]; // Get from hardware RNG (size depends on parameter set)
    ///
    /// // Generate a keypair first
    /// let keypair = slh_dsa.generate_keypair_with_randomness(
    ///     Algorithm::SlhDsaShake256128fRobust,
    ///     &key_randomness
    /// ).unwrap();
    ///
    /// let signature = slh_dsa.sign_with_randomness(
    ///     Algorithm::SlhDsaShake256128fRobust,
    ///     keypair.secret_key(),
    ///     b"Hello, SLH-DSA!",
    ///     &signing_randomness
    /// ).unwrap();
    /// # }
    /// ```
    #[cfg(feature = "alloc")]
    pub fn sign_with_randomness(
        &self,
        algorithm: Algorithm,
        secret_key: &SigSecretKey,
        message: &[u8],
        randomness: &[u8],
    ) -> Result<Vec<u8>> {
        self.sign_for_algorithm(algorithm, secret_key, message, Some(randomness))
    }
}

impl Default for SlhDsa {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "alloc")]
impl Signature for SlhDsa {
    fn generate_keypair(&self) -> Result<SigKeypair> {
        // Default to SHAKE256-128f for key generation
        self.generate_keypair_for_algorithm(Algorithm::SlhDsaShake256128fRobust, None)
    }

    fn sign(&self, secret_key: &SigSecretKey, message: &[u8]) -> Result<Vec<u8>> {
        // Default to SHAKE256-128f for signing
        self.sign_for_algorithm(
            Algorithm::SlhDsaShake256128fRobust,
            secret_key,
            message,
            None,
        )
    }

    fn verify(&self, public_key: &SigPublicKey, message: &[u8], signature: &[u8]) -> Result<bool> {
        // Default to SHAKE256-128f for verification
        self.verify_for_algorithm(
            Algorithm::SlhDsaShake256128fRobust,
            public_key,
            message,
            signature,
        )
    }
}

impl SlhDsa {
    /// Generate a keypair for a specific SLH-DSA algorithm
    #[cfg(feature = "alloc")]
    pub fn generate_keypair_for_algorithm(
        &self,
        algorithm: Algorithm,
        randomness: Option<&[u8]>,
    ) -> Result<SigKeypair> {
        #[cfg(feature = "slh-dsa")]
        {
            // Validate algorithm is SLH-DSA
            if !matches!(
                algorithm,
                Algorithm::SlhDsaSha256128fRobust |
                    Algorithm::SlhDsaSha256192fRobust |
                    Algorithm::SlhDsaSha256256fRobust |
                    Algorithm::SlhDsaShake256128fRobust |
                    Algorithm::SlhDsaShake256192fRobust |
                    Algorithm::SlhDsaShake256256fRobust
            ) {
                return Err(Error::InvalidAlgorithm {
                    algorithm: "Algorithm is not an SLH-DSA algorithm",
                });
            }

            // Generate keypair based on algorithm
            let (public_key, secret_key) = match algorithm {
                Algorithm::SlhDsaSha256128fRobust => {
                    self.generate_keypair_impl::<Sha2_128f>(randomness)?
                }
                Algorithm::SlhDsaSha256192fRobust => {
                    self.generate_keypair_impl::<Sha2_192f>(randomness)?
                }
                Algorithm::SlhDsaSha256256fRobust => {
                    self.generate_keypair_impl::<Sha2_256f>(randomness)?
                }
                Algorithm::SlhDsaShake256128fRobust => {
                    self.generate_keypair_impl::<Shake128f>(randomness)?
                }
                Algorithm::SlhDsaShake256192fRobust => {
                    self.generate_keypair_impl::<Shake192f>(randomness)?
                }
                Algorithm::SlhDsaShake256256fRobust => {
                    self.generate_keypair_impl::<Shake256f>(randomness)?
                }
                _ => unreachable!(), // Already validated above
            };

            Ok(SigKeypair::new(public_key, secret_key))
        }
        #[cfg(not(feature = "slh-dsa"))]
        {
            Err(Error::NotImplemented {
                feature: "SLH-DSA implementation requires the 'slh-dsa' feature flag",
            })
        }
    }

    /// Sign a message for a specific SLH-DSA algorithm
    #[cfg(feature = "alloc")]
    pub fn sign_for_algorithm(
        &self,
        algorithm: Algorithm,
        secret_key: &SigSecretKey,
        message: &[u8],
        randomness: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.sign_for_algorithm_with_context(algorithm, secret_key, message, &[], randomness)
    }

    /// Sign a message under a FIPS-205 signing context, for a specific SLH-DSA algorithm.
    ///
    /// The `context` is domain-separation input bound into the signature: verification succeeds
    /// only when the verifier supplies the *same* context bytes. Pass `&[]` for the behaviour of
    /// [`Self::sign_for_algorithm`], which is what the context-free path already signs under —
    /// so existing signatures remain valid.
    ///
    /// # Errors
    ///
    /// Returns an error if `algorithm` is not an SLH-DSA algorithm, if `context` exceeds
    /// [`SLH_DSA_CONTEXT_MAX_LEN`] bytes, or if signing fails.
    pub fn sign_for_algorithm_with_context(
        &self,
        algorithm: Algorithm,
        secret_key: &SigSecretKey,
        message: &[u8],
        context: &[u8],
        randomness: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        #[cfg(feature = "slh-dsa")]
        {
            // Validate algorithm is SLH-DSA
            if !matches!(
                algorithm,
                Algorithm::SlhDsaSha256128fRobust |
                    Algorithm::SlhDsaSha256192fRobust |
                    Algorithm::SlhDsaSha256256fRobust |
                    Algorithm::SlhDsaShake256128fRobust |
                    Algorithm::SlhDsaShake256192fRobust |
                    Algorithm::SlhDsaShake256256fRobust
            ) {
                return Err(Error::InvalidAlgorithm {
                    algorithm: "Algorithm is not an SLH-DSA algorithm",
                });
            }

            // Sign based on algorithm
            match algorithm {
                Algorithm::SlhDsaSha256128fRobust => self
                    .sign_impl_with_context::<Sha2_128f>(secret_key, message, context, randomness),
                Algorithm::SlhDsaSha256192fRobust => self
                    .sign_impl_with_context::<Sha2_192f>(secret_key, message, context, randomness),
                Algorithm::SlhDsaSha256256fRobust => self
                    .sign_impl_with_context::<Sha2_256f>(secret_key, message, context, randomness),
                Algorithm::SlhDsaShake256128fRobust => self
                    .sign_impl_with_context::<Shake128f>(secret_key, message, context, randomness),
                Algorithm::SlhDsaShake256192fRobust => self
                    .sign_impl_with_context::<Shake192f>(secret_key, message, context, randomness),
                Algorithm::SlhDsaShake256256fRobust => self
                    .sign_impl_with_context::<Shake256f>(secret_key, message, context, randomness),
                _ => unreachable!(), // Already validated above
            }
        }
        #[cfg(not(feature = "slh-dsa"))]
        {
            Err(Error::NotImplemented {
                feature: "SLH-DSA implementation requires the 'slh-dsa' feature flag",
            })
        }
    }

    /// Verify a signature for a specific SLH-DSA algorithm
    pub fn verify_for_algorithm(
        &self,
        algorithm: Algorithm,
        public_key: &SigPublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        self.verify_for_algorithm_with_context(algorithm, public_key, message, &[], signature)
    }

    /// Verify a signature under a FIPS-205 signing context, for a specific SLH-DSA algorithm.
    ///
    /// Verification succeeds only when `context` matches the context the signature was produced
    /// under, byte for byte. Pass `&[]` for the behaviour of [`Self::verify_for_algorithm`].
    ///
    /// # Errors
    ///
    /// Returns an error if `algorithm` is not an SLH-DSA algorithm or if `context` exceeds
    /// [`SLH_DSA_CONTEXT_MAX_LEN`] bytes. An unrepresentable context is a caller bug, so it is a
    /// hard error rather than a `false` verdict.
    pub fn verify_for_algorithm_with_context(
        &self,
        algorithm: Algorithm,
        public_key: &SigPublicKey,
        message: &[u8],
        context: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        #[cfg(feature = "slh-dsa")]
        {
            // Validate algorithm is SLH-DSA
            if !matches!(
                algorithm,
                Algorithm::SlhDsaSha256128fRobust |
                    Algorithm::SlhDsaSha256192fRobust |
                    Algorithm::SlhDsaSha256256fRobust |
                    Algorithm::SlhDsaShake256128fRobust |
                    Algorithm::SlhDsaShake256192fRobust |
                    Algorithm::SlhDsaShake256256fRobust
            ) {
                return Err(Error::InvalidAlgorithm {
                    algorithm: "Algorithm is not an SLH-DSA algorithm",
                });
            }

            // Verify based on algorithm
            match algorithm {
                Algorithm::SlhDsaSha256128fRobust => self
                    .verify_impl_with_context::<Sha2_128f>(public_key, message, context, signature),
                Algorithm::SlhDsaSha256192fRobust => self
                    .verify_impl_with_context::<Sha2_192f>(public_key, message, context, signature),
                Algorithm::SlhDsaSha256256fRobust => self
                    .verify_impl_with_context::<Sha2_256f>(public_key, message, context, signature),
                Algorithm::SlhDsaShake256128fRobust => self
                    .verify_impl_with_context::<Shake128f>(public_key, message, context, signature),
                Algorithm::SlhDsaShake256192fRobust => self
                    .verify_impl_with_context::<Shake192f>(public_key, message, context, signature),
                Algorithm::SlhDsaShake256256fRobust => self
                    .verify_impl_with_context::<Shake256f>(public_key, message, context, signature),
                _ => unreachable!(), // Already validated above
            }
        }
        #[cfg(not(feature = "slh-dsa"))]
        {
            Err(Error::NotImplemented {
                feature: "SLH-DSA implementation requires the 'slh-dsa' feature flag",
            })
        }
    }

    #[cfg(all(feature = "slh-dsa", feature = "alloc"))]
    fn generate_keypair_impl<P: ParameterSet + 'static>(
        &self,
        randomness: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let slh_dsa = SlhDsaSignature::<P>::new();

        if let Some(rand) = randomness {
            // Use provided randomness
            let keypair = slh_dsa.generate_keypair_with_randomness(rand)?;
            Ok((
                keypair.public_key.as_bytes().to_vec(),
                keypair.secret_key.as_bytes().to_vec(),
            ))
        } else {
            // Use system RNG (requires std feature)
            #[cfg(feature = "slh-dsa-std")]
            {
                use lib_q_random::new_secure_rng;
                let mut rng = new_secure_rng().map_err(|_| Error::RandomGenerationFailed {
                    operation: "Failed to create secure RNG".to_string(),
                })?;

                // Generate randomness for key generation
                // SLH-DSA requires 3 * N bytes of randomness for key generation
                // We'll use a conservative size that works for all parameter sets
                let mut key_randomness = vec![0u8; 96]; // 32 * 3, works for all parameter sets
                rng.fill_bytes(&mut key_randomness);

                let keypair = slh_dsa.generate_keypair_with_randomness(&key_randomness)?;
                Ok((
                    keypair.public_key.as_bytes().to_vec(),
                    keypair.secret_key.as_bytes().to_vec(),
                ))
            }
            #[cfg(not(feature = "slh-dsa-std"))]
            {
                Err(Error::RandomGenerationFailed {
                    operation: "No randomness source available in no_std environment. Use generate_keypair_with_randomness() instead.".to_string(),
                })
            }
        }
    }

    #[cfg(all(feature = "slh-dsa", feature = "alloc"))]
    fn sign_impl_with_context<P: ParameterSet + 'static>(
        &self,
        secret_key: &SigSecretKey,
        message: &[u8],
        context: &[u8],
        randomness: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let slh_dsa = SlhDsaSignature::<P>::new();

        if let Some(rand) = randomness {
            // Use provided randomness
            slh_dsa.sign_with_randomness_and_context(secret_key, message, context, rand)
        } else {
            // Use system RNG (requires std feature)
            #[cfg(feature = "slh-dsa-std")]
            {
                use lib_q_random::new_secure_rng;
                let mut rng = new_secure_rng().map_err(|_| Error::RandomGenerationFailed {
                    operation: "Failed to create secure RNG".to_string(),
                })?;

                // Generate randomness for signing
                // SLH-DSA requires N bytes of randomness for signing
                // We'll use a conservative size that works for all parameter sets
                let mut signing_randomness = vec![0u8; 32]; // 32 bytes, works for all parameter sets
                rng.fill_bytes(&mut signing_randomness);

                slh_dsa.sign_with_randomness_and_context(
                    secret_key,
                    message,
                    context,
                    &signing_randomness,
                )
            }
            #[cfg(not(feature = "slh-dsa-std"))]
            {
                Err(Error::RandomGenerationFailed {
                    operation: "No randomness source available in no_std environment. Use sign_with_randomness() instead.".to_string(),
                })
            }
        }
    }

    #[cfg(all(feature = "slh-dsa", feature = "alloc"))]
    fn verify_impl_with_context<P: ParameterSet + 'static>(
        &self,
        public_key: &SigPublicKey,
        message: &[u8],
        context: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        let slh_dsa = SlhDsaSignature::<P>::new();
        slh_dsa.verify_with_context(public_key, message, context, signature)
    }

    #[cfg(all(feature = "slh-dsa", not(feature = "alloc")))]
    fn verify_impl_with_context<P: ParameterSet + 'static>(
        &self,
        _public_key: &SigPublicKey,
        _message: &[u8],
        _context: &[u8],
        _signature: &[u8],
    ) -> Result<bool> {
        Err(Error::NotImplemented {
            feature: "SLH-DSA verification requires alloc feature for no_std compatibility"
                .to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slh_dsa_creation() {
        let slh_dsa = SlhDsa::new();
        assert_eq!(slh_dsa, SlhDsa);
    }

    #[cfg(feature = "slh-dsa")]
    #[test]
    fn test_algorithm_validation() {
        let slh_dsa = SlhDsa::new();

        // Test valid SLH-DSA algorithms
        let valid_algorithms = [
            Algorithm::SlhDsaSha256128fRobust,
            Algorithm::SlhDsaSha256192fRobust,
            Algorithm::SlhDsaSha256256fRobust,
            Algorithm::SlhDsaShake256128fRobust,
            Algorithm::SlhDsaShake256192fRobust,
            Algorithm::SlhDsaShake256256fRobust,
        ];

        for algorithm in valid_algorithms {
            let result = slh_dsa.generate_keypair_for_algorithm(algorithm, None);
            // Should either succeed or fail with RandomGenerationFailed (no_std)
            assert!(result.is_ok() || matches!(result, Err(Error::RandomGenerationFailed { .. })));
        }

        // Test invalid algorithm
        let result = slh_dsa.generate_keypair_for_algorithm(Algorithm::MlDsa65, None);
        assert!(matches!(result, Err(Error::InvalidAlgorithm { .. })));
    }

    #[cfg(feature = "slh-dsa")]
    #[test]
    fn test_explicit_randomness_round_trip() {
        let slh_dsa = SlhDsa::new();
        let algorithm = Algorithm::SlhDsaShake256128fRobust;
        let message = b"slh-dsa explicit randomness test";
        // Shake256-128f requires 3*N bytes for keygen and N bytes for signing (N=16).
        let key_randomness = [11u8; 48];
        let signing_randomness = [23u8; 16];

        let keypair = slh_dsa
            .generate_keypair_with_randomness(algorithm, &key_randomness)
            .expect("key generation with explicit randomness should succeed");
        let signature = slh_dsa
            .sign_with_randomness(
                algorithm,
                keypair.secret_key(),
                message,
                &signing_randomness,
            )
            .expect("signing with explicit randomness should succeed");
        let is_valid = slh_dsa
            .verify_for_algorithm(algorithm, keypair.public_key(), message, &signature)
            .expect("verification should succeed");
        assert!(is_valid, "signature should verify for original message");
    }

    #[cfg(feature = "slh-dsa")]
    #[test]
    fn test_sign_and_verify_reject_non_slh_algorithm() {
        let slh_dsa = SlhDsa::new();
        let key_randomness = [5u8; 48];
        let signing_randomness = [9u8; 16];
        let keypair = slh_dsa
            .generate_keypair_with_randomness(Algorithm::SlhDsaShake256128fRobust, &key_randomness)
            .expect("explicit key generation should succeed");

        let sign_result = slh_dsa.sign_for_algorithm(
            Algorithm::MlDsa65,
            keypair.secret_key(),
            b"message",
            Some(&signing_randomness),
        );
        assert!(matches!(sign_result, Err(Error::InvalidAlgorithm { .. })));

        let verify_result = slh_dsa.verify_for_algorithm(
            Algorithm::MlDsa65,
            keypair.public_key(),
            b"message",
            b"signature",
        );
        assert!(matches!(verify_result, Err(Error::InvalidAlgorithm { .. })));
    }

    #[cfg(all(feature = "slh-dsa", feature = "slh-dsa-std"))]
    #[test]
    fn test_implicit_randomness_round_trip_with_std_rng() {
        let slh_dsa = SlhDsa::new();
        let algorithm = Algorithm::SlhDsaShake256128fRobust;
        let message = b"slh-dsa implicit randomness test";

        let keypair = slh_dsa
            .generate_keypair_for_algorithm(algorithm, None)
            .expect("key generation should use std RNG when slh-dsa-std is enabled");
        let signature = slh_dsa
            .sign_for_algorithm(algorithm, keypair.secret_key(), message, None)
            .expect("signing should use std RNG when slh-dsa-std is enabled");
        let is_valid = slh_dsa
            .verify_for_algorithm(algorithm, keypair.public_key(), message, &signature)
            .expect("verification should succeed");
        assert!(is_valid, "signature should verify for original message");
    }

    #[cfg(all(feature = "slh-dsa", not(feature = "slh-dsa-std")))]
    #[test]
    fn test_implicit_randomness_requires_std_feature() {
        let slh_dsa = SlhDsa::new();
        let algorithm = Algorithm::SlhDsaShake256128fRobust;

        let keypair_err = slh_dsa.generate_keypair_for_algorithm(algorithm, None);
        assert!(
            matches!(keypair_err, Err(Error::RandomGenerationFailed { .. })),
            "without slh-dsa-std, implicit keygen randomness should fail"
        );

        // A valid key is still needed to exercise the implicit-signing error path.
        let key_randomness = [7u8; 48];
        let keypair = slh_dsa
            .generate_keypair_with_randomness(algorithm, &key_randomness)
            .expect("explicit key generation should succeed");
        let sign_err = slh_dsa.sign_for_algorithm(algorithm, keypair.secret_key(), b"msg", None);
        assert!(
            matches!(sign_err, Err(Error::RandomGenerationFailed { .. })),
            "without slh-dsa-std, implicit signing randomness should fail"
        );
    }

    #[cfg(not(feature = "slh-dsa"))]
    #[test]
    fn test_feature_flag_required() {
        let slh_dsa = SlhDsa::new();
        let result =
            slh_dsa.generate_keypair_for_algorithm(Algorithm::SlhDsaShake256128fRobust, None);
        assert!(matches!(result, Err(Error::NotImplemented { .. })));
    }
}

// WASM bindings for SLH-DSA
#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl SlhDsa {
    /// Generate a keypair for WASM (JavaScript) environment
    ///
    /// # Arguments
    /// * `algorithm` - The algorithm name as a string
    /// * `randomness` - Optional randomness as Uint8Array
    ///
    /// # Returns
    /// * `Result<WasmSlhDsaKeyPair, JsValue>` - The keypair or error
    #[wasm_bindgen]
    pub fn generate_keypair_wasm(
        &self,
        algorithm: &str,
        randomness: Option<Uint8Array>,
    ) -> core::result::Result<WasmSlhDsaKeyPair, JsValue> {
        let algorithm = match algorithm {
            "SlhDsaSha256128fRobust" => Algorithm::SlhDsaSha256128fRobust,
            "SlhDsaSha256192fRobust" => Algorithm::SlhDsaSha256192fRobust,
            "SlhDsaSha256256fRobust" => Algorithm::SlhDsaSha256256fRobust,
            "SlhDsaShake256128fRobust" => Algorithm::SlhDsaShake256128fRobust,
            "SlhDsaShake256192fRobust" => Algorithm::SlhDsaShake256192fRobust,
            "SlhDsaShake256256fRobust" => Algorithm::SlhDsaShake256256fRobust,
            _ => return Err(JsValue::from_str("Invalid algorithm")),
        };

        let randomness_vec = randomness.map(|rand| rand.to_vec());
        let randomness_slice = randomness_vec.as_deref();

        let keypair = match self.generate_keypair_for_algorithm(algorithm, randomness_slice) {
            Ok(kp) => kp,
            Err(e) => return Err(JsValue::from_str(&e.to_string())),
        };

        Ok(WasmSlhDsaKeyPair::new(
            Uint8Array::from(keypair.public_key().as_bytes()),
            Uint8Array::from(keypair.secret_key().as_bytes()),
        ))
    }

    /// Sign a message in WASM (JavaScript) environment
    ///
    /// # Arguments
    /// * `algorithm` - The algorithm name as a string
    /// * `secret_key` - The secret key as Uint8Array
    /// * `message` - The message to sign as Uint8Array
    /// * `randomness` - Optional randomness as Uint8Array
    ///
    /// # Returns
    /// * `Result<Uint8Array, JsValue>` - The signature or error
    #[wasm_bindgen]
    pub fn sign_wasm(
        &self,
        algorithm: &str,
        secret_key: Uint8Array,
        message: Uint8Array,
        randomness: Option<Uint8Array>,
    ) -> core::result::Result<Uint8Array, JsValue> {
        let algorithm = match algorithm {
            "SlhDsaSha256128fRobust" => Algorithm::SlhDsaSha256128fRobust,
            "SlhDsaSha256192fRobust" => Algorithm::SlhDsaSha256192fRobust,
            "SlhDsaSha256256fRobust" => Algorithm::SlhDsaSha256256fRobust,
            "SlhDsaShake256128fRobust" => Algorithm::SlhDsaShake256128fRobust,
            "SlhDsaShake256192fRobust" => Algorithm::SlhDsaShake256192fRobust,
            "SlhDsaShake256256fRobust" => Algorithm::SlhDsaShake256256fRobust,
            _ => return Err(JsValue::from_str("Invalid algorithm")),
        };

        let secret_key = SigSecretKey::new(secret_key.to_vec());
        let message = message.to_vec();
        let randomness_vec = randomness.map(|rand| rand.to_vec());
        let randomness_slice = randomness_vec.as_deref();

        let signature =
            match self.sign_for_algorithm(algorithm, &secret_key, &message, randomness_slice) {
                Ok(sig) => sig,
                Err(e) => return Err(JsValue::from_str(&e.to_string())),
            };

        Ok(Uint8Array::from(signature.as_slice()))
    }

    /// Verify a signature in WASM (JavaScript) environment
    ///
    /// # Arguments
    /// * `algorithm` - The algorithm name as a string
    /// * `public_key` - The public key as Uint8Array
    /// * `message` - The message as Uint8Array
    /// * `signature` - The signature to verify as Uint8Array
    ///
    /// # Returns
    /// * `Result<bool, JsValue>` - Verification result or error
    #[wasm_bindgen]
    pub fn verify_wasm(
        &self,
        algorithm: &str,
        public_key: Uint8Array,
        message: Uint8Array,
        signature: Uint8Array,
    ) -> core::result::Result<bool, JsValue> {
        let algorithm = match algorithm {
            "SlhDsaSha256128fRobust" => Algorithm::SlhDsaSha256128fRobust,
            "SlhDsaSha256192fRobust" => Algorithm::SlhDsaSha256192fRobust,
            "SlhDsaSha256256fRobust" => Algorithm::SlhDsaSha256256fRobust,
            "SlhDsaShake256128fRobust" => Algorithm::SlhDsaShake256128fRobust,
            "SlhDsaShake256192fRobust" => Algorithm::SlhDsaShake256192fRobust,
            "SlhDsaShake256256fRobust" => Algorithm::SlhDsaShake256256fRobust,
            _ => return Err(JsValue::from_str("Invalid algorithm")),
        };

        let public_key = SigPublicKey::new(public_key.to_vec());
        let message = message.to_vec();
        let signature = signature.to_vec();

        let is_valid = match self.verify_for_algorithm(algorithm, &public_key, &message, &signature)
        {
            Ok(valid) => valid,
            Err(e) => return Err(JsValue::from_str(&e.to_string())),
        };

        Ok(is_valid)
    }

    /// Sign a message under a FIPS-205 signing context in a WASM (JavaScript) environment.
    ///
    /// This is the binding domain-separated signatures need; [`Self::sign_wasm`] remains the
    /// context-free entry point and is unchanged, so existing JavaScript callers are unaffected.
    ///
    /// # Errors
    ///
    /// Returns a `JsValue` error for an unknown algorithm, a context longer than
    /// [`SLH_DSA_CONTEXT_MAX_LEN`] bytes, or a signing failure.
    #[wasm_bindgen]
    pub fn sign_with_context_wasm(
        &self,
        algorithm: &str,
        secret_key: Uint8Array,
        message: Uint8Array,
        context: Uint8Array,
        randomness: Option<Uint8Array>,
    ) -> core::result::Result<Uint8Array, JsValue> {
        let algorithm = match Self::algorithm_from_wasm_name(algorithm) {
            Some(algorithm) => algorithm,
            None => return Err(JsValue::from_str("Invalid algorithm")),
        };

        let secret_key = SigSecretKey::new(secret_key.to_vec());
        let message = message.to_vec();
        let context = context.to_vec();
        let randomness_vec = randomness.map(|rand| rand.to_vec());
        let randomness_slice = randomness_vec.as_deref();

        let signature = self
            .sign_for_algorithm_with_context(
                algorithm,
                &secret_key,
                &message,
                &context,
                randomness_slice,
            )
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        Ok(Uint8Array::from(signature.as_slice()))
    }

    /// Verify a signature under a FIPS-205 signing context in a WASM (JavaScript) environment.
    ///
    /// Returns `false` unless `context` matches the context the signature was produced under,
    /// byte for byte. Pass an empty `context` for the behaviour of [`Self::verify_wasm`].
    ///
    /// # Errors
    ///
    /// Returns a `JsValue` error for an unknown algorithm or a context longer than
    /// [`SLH_DSA_CONTEXT_MAX_LEN`] bytes. A context mismatch is a `false` verdict, not an error.
    #[wasm_bindgen]
    pub fn verify_with_context_wasm(
        &self,
        algorithm: &str,
        public_key: Uint8Array,
        message: Uint8Array,
        context: Uint8Array,
        signature: Uint8Array,
    ) -> core::result::Result<bool, JsValue> {
        let algorithm = match Self::algorithm_from_wasm_name(algorithm) {
            Some(algorithm) => algorithm,
            None => return Err(JsValue::from_str("Invalid algorithm")),
        };

        let public_key = SigPublicKey::new(public_key.to_vec());
        let message = message.to_vec();
        let context = context.to_vec();
        let signature = signature.to_vec();

        self.verify_for_algorithm_with_context(
            algorithm,
            &public_key,
            &message,
            &context,
            &signature,
        )
        .map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

#[cfg(feature = "wasm")]
impl SlhDsa {
    /// Map the JavaScript algorithm name onto an [`Algorithm`].
    fn algorithm_from_wasm_name(algorithm: &str) -> Option<Algorithm> {
        match algorithm {
            "SlhDsaSha256128fRobust" => Some(Algorithm::SlhDsaSha256128fRobust),
            "SlhDsaSha256192fRobust" => Some(Algorithm::SlhDsaSha256192fRobust),
            "SlhDsaSha256256fRobust" => Some(Algorithm::SlhDsaSha256256fRobust),
            "SlhDsaShake256128fRobust" => Some(Algorithm::SlhDsaShake256128fRobust),
            "SlhDsaShake256192fRobust" => Some(Algorithm::SlhDsaShake256192fRobust),
            "SlhDsaShake256256fRobust" => Some(Algorithm::SlhDsaShake256256fRobust),
            _ => None,
        }
    }
}

/// WASM-compatible SLH-DSA key pair
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub struct WasmSlhDsaKeyPair {
    public_key: Uint8Array,
    secret_key: Uint8Array,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl WasmSlhDsaKeyPair {
    #[wasm_bindgen(constructor)]
    pub fn new(public_key: Uint8Array, secret_key: Uint8Array) -> WasmSlhDsaKeyPair {
        WasmSlhDsaKeyPair {
            public_key,
            secret_key,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Uint8Array {
        self.public_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn secret_key(&self) -> Uint8Array {
        self.secret_key.clone()
    }
}
