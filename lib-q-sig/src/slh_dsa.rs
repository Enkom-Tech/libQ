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
//! ```rust,ignore
//! use lib_q_core::{Algorithm, Signature};
//! use lib_q_sig::slh_dsa::SlhDsa;
//!
//! let slh_dsa = SlhDsa::new();
//! let keypair = slh_dsa.generate_keypair_for_algorithm(
//!     Algorithm::SlhDsaShake256128fRobust,
//!     None
//! ).unwrap();
//! let signature = slh_dsa.sign_for_algorithm(
//!     Algorithm::SlhDsaShake256128fRobust,
//!     keypair.secret_key(),
//!     b"Hello, SLH-DSA!",
//!     None
//! ).unwrap();
//! let is_valid = slh_dsa.verify_for_algorithm(
//!     Algorithm::SlhDsaShake256128fRobust,
//!     keypair.public_key(),
//!     b"Hello, SLH-DSA!",
//!     &signature
//! ).unwrap();
//! assert!(is_valid);
//! ```
//!
//! ### Without std (external randomness)
//! ```rust,ignore
//! use lib_q_core::{Algorithm, Signature};
//! use lib_q_sig::slh_dsa::SlhDsa;
//!
//! let slh_dsa = SlhDsa::new();
//!
//! // Provide randomness externally
//! let key_randomness = [0u8; 32]; // Get from hardware RNG
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
#[cfg(feature = "slh-dsa")]
use lib_q_slh_dsa::signature::{
    Keypair,
    RandomizedSigner,
};
#[cfg(feature = "slh-dsa")]
use lib_q_slh_dsa::{
    ParameterSet,
    Sha2_128f,
    Sha2_192f,
    Sha2_256f,
    Shake128f,
    Shake192f,
    Shake256f,
    Signature as SlhSignature,
    SigningKey,
    VerifyingKey,
};
#[cfg(feature = "slh-dsa")]
use rand_core::{
    CryptoRng,
    RngCore,
};
#[cfg(feature = "slh-dsa")]
use sha2::{
    Digest,
    Sha256,
};
// WASM support
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// SLH-DSA signature implementation wrapper
///
/// This struct provides the lib-Q Signature trait implementation for SLH-DSA,
/// routing operations to the appropriate parameter set based on the algorithm.
#[derive(Debug, PartialEq, Eq)]
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
    /// ```rust,ignore
    /// use lib_q_core::Algorithm;
    /// use lib_q_sig::slh_dsa::SlhDsa;
    ///
    /// let slh_dsa = SlhDsa::new();
    /// let randomness = [0u8; 32]; // Get from hardware RNG
    /// let keypair = slh_dsa.generate_keypair_with_randomness(
    ///     Algorithm::SlhDsaShake256128fRobust,
    ///     &randomness
    /// ).unwrap();
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
    /// ```rust,ignore
    /// use lib_q_core::{Algorithm, SigSecretKey};
    /// use lib_q_sig::slh_dsa::SlhDsa;
    ///
    /// let slh_dsa = SlhDsa::new();
    /// let randomness = [0u8; 16]; // Get from hardware RNG (size depends on parameter set)
    /// let signature = slh_dsa.sign_with_randomness(
    ///     Algorithm::SlhDsaShake256128fRobust,
    ///     &secret_key,
    ///     b"Hello, SLH-DSA!",
    ///     &randomness
    /// ).unwrap();
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
                Algorithm::SlhDsaSha256128fRobust => {
                    self.sign_impl::<Sha2_128f>(secret_key, message, randomness)
                }
                Algorithm::SlhDsaSha256192fRobust => {
                    self.sign_impl::<Sha2_192f>(secret_key, message, randomness)
                }
                Algorithm::SlhDsaSha256256fRobust => {
                    self.sign_impl::<Sha2_256f>(secret_key, message, randomness)
                }
                Algorithm::SlhDsaShake256128fRobust => {
                    self.sign_impl::<Shake128f>(secret_key, message, randomness)
                }
                Algorithm::SlhDsaShake256192fRobust => {
                    self.sign_impl::<Shake192f>(secret_key, message, randomness)
                }
                Algorithm::SlhDsaShake256256fRobust => {
                    self.sign_impl::<Shake256f>(secret_key, message, randomness)
                }
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
                Algorithm::SlhDsaSha256128fRobust => {
                    self.verify_impl::<Sha2_128f>(public_key, message, signature)
                }
                Algorithm::SlhDsaSha256192fRobust => {
                    self.verify_impl::<Sha2_192f>(public_key, message, signature)
                }
                Algorithm::SlhDsaSha256256fRobust => {
                    self.verify_impl::<Sha2_256f>(public_key, message, signature)
                }
                Algorithm::SlhDsaShake256128fRobust => {
                    self.verify_impl::<Shake128f>(public_key, message, signature)
                }
                Algorithm::SlhDsaShake256192fRobust => {
                    self.verify_impl::<Shake192f>(public_key, message, signature)
                }
                Algorithm::SlhDsaShake256256fRobust => {
                    self.verify_impl::<Shake256f>(public_key, message, signature)
                }
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
        // Create a deterministic RNG from randomness if provided, otherwise use system RNG
        if let Some(rand) = randomness {
            // For deterministic key generation, we'll use the provided randomness
            let mut rng = DeterministicRng::new(rand);
            let signing_key = SigningKey::<P>::new(&mut rng);
            let verifying_key = signing_key.verifying_key();

            // Serialize keys
            let public_key = verifying_key.to_bytes().to_vec();
            let secret_key = signing_key.to_bytes().to_vec();

            Ok((public_key, secret_key))
        } else {
            // Use system RNG (requires std feature)
            #[cfg(feature = "slh-dsa-std")]
            {
                use rand::rngs::ThreadRng;
                let mut rng = ThreadRng::default();
                let signing_key = SigningKey::<P>::new(&mut rng);
                let verifying_key = signing_key.verifying_key();

                // Serialize keys
                let public_key = verifying_key.to_bytes().to_vec();
                let secret_key = signing_key.to_bytes().to_vec();

                Ok((public_key, secret_key))
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
    fn sign_impl<P: ParameterSet + 'static>(
        &self,
        secret_key: &SigSecretKey,
        message: &[u8],
        randomness: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        // Deserialize signing key
        let signing_key =
            SigningKey::<P>::try_from(secret_key.as_bytes()).map_err(|_| Error::InvalidKey {
                key_type: "SLH-DSA signing key".to_string(),
                reason: "Failed to deserialize signing key".to_string(),
            })?;

        // Sign the message using RandomizedSigner trait for consistency
        let signature = if let Some(rand) = randomness {
            // Use provided randomness for deterministic signing
            // Create a deterministic RNG from the provided randomness
            let mut rng = DeterministicRng::new(rand);
            signing_key
                .try_sign_with_rng(&mut rng, message)
                .map_err(|_| Error::SigningFailed {
                    operation: "SLH-DSA signing failed".to_string(),
                })?
        } else {
            // Use system RNG for randomized signing (requires std feature)
            #[cfg(feature = "slh-dsa-std")]
            {
                use rand::rngs::ThreadRng;
                let mut rng = ThreadRng::default();
                signing_key
                    .try_sign_with_rng(&mut rng, message)
                    .map_err(|_| Error::SigningFailed {
                        operation: "SLH-DSA signing failed".to_string(),
                    })?
            }
            #[cfg(not(feature = "slh-dsa-std"))]
            {
                return Err(Error::RandomGenerationFailed {
                    operation: "No randomness source available in no_std environment. Use sign_with_randomness() instead.".to_string(),
                });
            }
        };

        Ok(signature.to_bytes().to_vec())
    }

    #[cfg(all(feature = "slh-dsa", feature = "alloc"))]
    fn verify_impl<P: ParameterSet + 'static>(
        &self,
        public_key: &SigPublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        // Deserialize verifying key
        let verifying_key =
            VerifyingKey::<P>::try_from(public_key.as_bytes()).map_err(|_| Error::InvalidKey {
                key_type: "SLH-DSA verifying key".to_string(),
                reason: "Failed to deserialize verifying key".to_string(),
            })?;

        // Deserialize signature
        let slh_signature =
            SlhSignature::<P>::try_from(signature).map_err(|_| Error::InvalidSignatureSize {
                expected: 0,
                actual: signature.len(),
            })?;

        // Verify the signature
        let result = verifying_key.try_verify_with_context(message, &[], &slh_signature);

        match result {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    #[cfg(all(feature = "slh-dsa", not(feature = "alloc")))]
    fn verify_impl<P: ParameterSet + 'static>(
        &self,
        _public_key: &SigPublicKey,
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<bool> {
        Err(Error::NotImplemented {
            feature: "SLH-DSA verification requires alloc feature for no_std compatibility"
                .to_string(),
        })
    }
}

/// Simple deterministic RNG for testing and deterministic key generation
#[cfg(all(feature = "slh-dsa", feature = "alloc"))]
struct DeterministicRng {
    seed: Vec<u8>,
    counter: u64,
}

#[cfg(all(feature = "slh-dsa", feature = "alloc"))]
impl DeterministicRng {
    fn new(seed: &[u8]) -> Self {
        Self {
            seed: seed.to_vec(),
            counter: 0,
        }
    }
}

#[cfg(all(feature = "slh-dsa", feature = "alloc"))]
impl RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(&self.seed);
        hasher.update(self.counter.to_be_bytes());
        let hash = hasher.finalize();

        self.counter += 1;

        u64::from_be_bytes([
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
        ])
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let value = self.next_u64();
            let bytes = value.to_be_bytes();
            let len = chunk.len().min(8);
            chunk[..len].copy_from_slice(&bytes[..len]);
        }
    }
}

#[cfg(all(feature = "slh-dsa", feature = "alloc"))]
impl CryptoRng for DeterministicRng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slh_dsa_creation() {
        let slh_dsa = SlhDsa::new();
        assert_eq!(slh_dsa, SlhDsa::default());
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
    ) -> Result<WasmSlhDsaKeyPair, JsValue> {
        let algorithm = match algorithm {
            "SlhDsaSha256128fRobust" => Algorithm::SlhDsaSha256128fRobust,
            "SlhDsaSha256192fRobust" => Algorithm::SlhDsaSha256192fRobust,
            "SlhDsaSha256256fRobust" => Algorithm::SlhDsaSha256256fRobust,
            "SlhDsaShake256128fRobust" => Algorithm::SlhDsaShake256128fRobust,
            "SlhDsaShake256192fRobust" => Algorithm::SlhDsaShake256192fRobust,
            "SlhDsaShake256256fRobust" => Algorithm::SlhDsaShake256256fRobust,
            _ => return Err(JsValue::from_str("Invalid algorithm")),
        };

        let randomness_slice = if let Some(rand) = randomness {
            Some(rand.to_vec().as_slice())
        } else {
            None
        };

        let keypair = self
            .generate_keypair_for_algorithm(algorithm, randomness_slice)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

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
    ) -> Result<Uint8Array, JsValue> {
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
        let randomness_slice = if let Some(rand) = randomness {
            Some(rand.to_vec().as_slice())
        } else {
            None
        };

        let signature = self
            .sign_for_algorithm(algorithm, &secret_key, &message, randomness_slice)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

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
    ) -> Result<bool, JsValue> {
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

        let is_valid = self
            .verify_for_algorithm(algorithm, &public_key, &message, &signature)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        Ok(is_valid)
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
