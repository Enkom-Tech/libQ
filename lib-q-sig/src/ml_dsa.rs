//! CRYSTALS-ML-DSA implementation
//!
//! ML-DSA (Module-Lattice Digital Signature Algorithm) is the new name for CRYSTALS-Dilithium
//! after standardization by NIST. This implementation integrates lib-q-ml-dsa
//! library with the lib-q signature interface.
//!
//! ## Architecture
//!
//! This implementation follows the lib-q pattern for no_std support:
//! - **Low-level API**: Functions accept randomness externally (no_std compatible)
//! - **High-level API**: Functions generate randomness when std is available
//! - **External randomness**: Required for key generation and signing operations
//! - **WASM Support**: JavaScript-compatible bindings for web environments
//!
//! ## Usage Examples
//!
//! ### With std (automatic randomness generation)
//! ```rust
//! # #[cfg(feature = "std")]
//! # {
//! use lib_q_core::Signature;
//! use lib_q_sig::ml_dsa::MlDsa;
//!
//! let ml_dsa = MlDsa::ml_dsa_65();
//! let keypair = ml_dsa.generate_keypair().unwrap();
//! let signature = ml_dsa
//!     .sign(keypair.secret_key(), b"Hello, ML-DSA!")
//!     .unwrap();
//! let is_valid = ml_dsa
//!     .verify(keypair.public_key(), b"Hello, ML-DSA!", &signature)
//!     .unwrap();
//! assert!(is_valid);
//! # }
//! ```
//!
//! ### Without std (external randomness)
//! ```rust
//! # #[cfg(feature = "ml-dsa")]
//! # {
//! use lib_q_core::Signature;
//! use lib_q_sig::ml_dsa::MlDsa;
//! use lib_q_ml_dsa::constants::{KEY_GENERATION_RANDOMNESS_SIZE, SIGNING_RANDOMNESS_SIZE};
//!
//! let ml_dsa = MlDsa::ml_dsa_65();
//!
//! // Provide randomness externally
//! let keypair_randomness = [0u8; KEY_GENERATION_RANDOMNESS_SIZE]; // Get from hardware RNG
//! let signing_randomness = [0u8; SIGNING_RANDOMNESS_SIZE]; // Get from hardware RNG
//!
//! let keypair = ml_dsa.generate_keypair_with_randomness(keypair_randomness).unwrap();
//! let signature = ml_dsa.sign_with_randomness(keypair.secret_key(), b"Hello, ML-DSA!", signing_randomness).unwrap();
//! let is_valid = ml_dsa.verify(keypair.public_key(), b"Hello, ML-DSA!", &signature).unwrap();
//! assert!(is_valid);
//! # }
//! ```
//!
//! ### WASM (JavaScript) Environment
//! ```rust
//! # #[cfg(feature = "wasm")]
//! # {
//! use js_sys::Uint8Array;
//! use lib_q_sig::ml_dsa::MlDsa;
//!
//! let ml_dsa = MlDsa::ml_dsa_65();
//!
//! // Generate keypair with optional randomness
//! let keypair = ml_dsa.generate_keypair_wasm(None).unwrap();
//!
//! // Sign message
//! let message = Uint8Array::from(&b"Hello, ML-DSA!"[..]);
//! let signature = ml_dsa
//!     .sign_wasm(keypair.secret_key(), message.clone(), None)
//!     .unwrap();
//!
//! // Verify signature
//! let is_valid = ml_dsa
//!     .verify_wasm(keypair.public_key(), message, signature)
//!     .unwrap();
//! assert!(is_valid);
//! # }
//! ```

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::string::ToString;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(feature = "wasm")]
use js_sys::Uint8Array;
use lib_q_core::{
    Result,
    SigKeypair,
    SigPublicKey,
    SigSecretKey,
    Signature,
};
use lib_q_ml_dsa::constants::{
    KEY_GENERATION_RANDOMNESS_SIZE,
    SIGNING_RANDOMNESS_SIZE,
};
use lib_q_ml_dsa::types::*;
use lib_q_ml_dsa::{
    ml_dsa_44,
    ml_dsa_65,
    ml_dsa_87,
};
// WASM support
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

/// CRYSTALS-ML-DSA signature implementation
///
/// This implementation provides both high-level (std) and low-level (no_std) APIs
/// following the lib-q architecture pattern for maximum flexibility.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct MlDsa {
    /// The specific ML-DSA variant (44, 65, or 87)
    variant: MlDsaVariant,
}

// ML-DSA key and signature sizes (in bytes)
const MLDSA44_VERIFICATION_KEY_SIZE: usize = 1312;
const MLDSA44_SIGNING_KEY_SIZE: usize = 2560;
const MLDSA44_SIGNATURE_SIZE: usize = 2420;

const MLDSA65_VERIFICATION_KEY_SIZE: usize = 1952;
const MLDSA65_SIGNING_KEY_SIZE: usize = 4032;
const MLDSA65_SIGNATURE_SIZE: usize = 3309;

const MLDSA87_VERIFICATION_KEY_SIZE: usize = 2592;
const MLDSA87_SIGNING_KEY_SIZE: usize = 4896;
const MLDSA87_SIGNATURE_SIZE: usize = 4627;

/// Maximum length of a FIPS-204 signing context, in bytes.
///
/// FIPS 204 encodes the context as a single length byte followed by its bytes, so a context
/// longer than this cannot be represented. Passing a longer context to any `*_with_context`
/// API is rejected with [`Error::InvalidAssociatedDataSize`](lib_q_core::Error::InvalidAssociatedDataSize).
pub const ML_DSA_CONTEXT_MAX_LEN: usize = 255;

#[inline]
fn validate_context(context: &[u8]) -> Result<()> {
    if context.len() > ML_DSA_CONTEXT_MAX_LEN {
        return Err(lib_q_core::Error::InvalidAssociatedDataSize {
            max: ML_DSA_CONTEXT_MAX_LEN,
            actual: context.len(),
        });
    }
    Ok(())
}

/// ML-DSA variants with their parameter sets
#[derive(Debug, Clone, Copy)]
pub enum MlDsaVariant {
    /// ML-DSA-44: Level 1 security (128-bit)
    MlDsa44,
    /// ML-DSA-65: Level 3 security (192-bit)
    MlDsa65,
    /// ML-DSA-87: Level 4 security (256-bit)
    MlDsa87,
}

impl MlDsa {
    /// Create a new ML-DSA instance with the specified variant
    pub fn new(variant: MlDsaVariant) -> Self {
        Self { variant }
    }

    /// Create ML-DSA-44 instance (Level 1 security)
    pub fn ml_dsa_44() -> Self {
        Self::new(MlDsaVariant::MlDsa44)
    }

    /// Create ML-DSA-65 instance (Level 3 security)
    pub fn ml_dsa_65() -> Self {
        Self::new(MlDsaVariant::MlDsa65)
    }

    /// Create ML-DSA-87 instance (Level 4 security)
    pub fn ml_dsa_87() -> Self {
        Self::new(MlDsaVariant::MlDsa87)
    }

    /// Generate keypair with provided randomness (no_std compatible)
    ///
    /// This is the low-level API that accepts randomness externally,
    /// making it suitable for no_std environments where randomness
    /// must be provided by the caller (e.g., from hardware RNG).
    ///
    /// # Arguments
    /// * `randomness` - Cryptographically secure random bytes for key generation
    ///
    /// # Returns
    /// * `Result<SigKeypair>` - The generated keypair or an error
    ///
    /// # Example
    /// ```rust
    /// use lib_q_sig::ml_dsa::MlDsa;
    /// use lib_q_ml_dsa::constants::KEY_GENERATION_RANDOMNESS_SIZE;
    ///
    /// let ml_dsa = MlDsa::ml_dsa_65();
    /// let randomness = [0u8; KEY_GENERATION_RANDOMNESS_SIZE]; // Get from hardware RNG
    /// let keypair = ml_dsa.generate_keypair_with_randomness(randomness).unwrap();
    /// ```
    pub fn generate_keypair_with_randomness(
        &self,
        randomness: [u8; KEY_GENERATION_RANDOMNESS_SIZE],
    ) -> Result<SigKeypair> {
        // Generate keypair using the appropriate ML-DSA variant
        let keypair = match self.variant {
            MlDsaVariant::MlDsa44 => {
                let mut kp = ml_dsa_44::portable::generate_key_pair(randomness);
                let pair = SigKeypair::new(
                    kp.verification_key.as_slice().to_vec(),
                    kp.signing_key.as_slice().to_vec(),
                );
                kp.signing_key.as_mut_slice().zeroize();
                pair
            }
            MlDsaVariant::MlDsa65 => {
                let mut kp = ml_dsa_65::portable::generate_key_pair(randomness);
                let pair = SigKeypair::new(
                    kp.verification_key.as_slice().to_vec(),
                    kp.signing_key.as_slice().to_vec(),
                );
                kp.signing_key.as_mut_slice().zeroize();
                pair
            }
            MlDsaVariant::MlDsa87 => {
                let mut kp = ml_dsa_87::portable::generate_key_pair(randomness);
                let pair = SigKeypair::new(
                    kp.verification_key.as_slice().to_vec(),
                    kp.signing_key.as_slice().to_vec(),
                );
                kp.signing_key.as_mut_slice().zeroize();
                pair
            }
        };

        Ok(keypair)
    }

    /// Sign a message with provided randomness (no_std compatible)
    ///
    /// This is the low-level API that accepts randomness externally,
    /// making it suitable for no_std environments where randomness
    /// must be provided by the caller (e.g., from hardware RNG).
    ///
    /// # Arguments
    /// * `secret_key` - The secret key for signing
    /// * `message` - The message to sign
    /// * `randomness` - Cryptographically secure random bytes for signing
    ///
    /// # Returns
    /// * `Result<Vec<u8>>` - The signature or an error
    ///
    /// # Example
    /// ```rust
    /// use lib_q_core::SigSecretKey;
    /// use lib_q_ml_dsa::constants::SIGNING_RANDOMNESS_SIZE;
    /// use lib_q_sig::ml_dsa::MlDsa;
    ///
    /// let ml_dsa = MlDsa::ml_dsa_65();
    /// let randomness = [0u8; SIGNING_RANDOMNESS_SIZE]; // Get from hardware RNG
    /// let secret_key_bytes = vec![0u8; 4032]; // ML-DSA-65 secret key size
    /// let secret_key = SigSecretKey::new(secret_key_bytes);
    /// let message = b"Hello, ML-DSA!";
    /// let signature = ml_dsa
    ///     .sign_with_randomness(&secret_key, message, randomness)
    ///     .unwrap();
    /// ```
    #[cfg(feature = "alloc")]
    pub fn sign_with_randomness(
        &self,
        secret_key: &SigSecretKey,
        message: &[u8],
        randomness: [u8; SIGNING_RANDOMNESS_SIZE],
    ) -> Result<Vec<u8>> {
        self.sign_with_randomness_and_context(secret_key, message, &[], randomness)
    }

    /// Sign a message under a FIPS-204 signing context, with provided randomness.
    ///
    /// The `context` is domain separation input bound into the signature: verification only
    /// succeeds when the verifier supplies the *same* context bytes. Pass `&[]` for the
    /// context-free behaviour of [`Self::sign_with_randomness`].
    ///
    /// # Arguments
    /// * `secret_key` - The secret key for signing
    /// * `message` - The message to sign
    /// * `context` - The signing context (at most [`ML_DSA_CONTEXT_MAX_LEN`] bytes)
    /// * `randomness` - Cryptographically secure random bytes for signing
    ///
    /// # Example
    /// ```rust
    /// use lib_q_core::SigSecretKey;
    /// use lib_q_ml_dsa::constants::SIGNING_RANDOMNESS_SIZE;
    /// use lib_q_sig::ml_dsa::MlDsa;
    ///
    /// let ml_dsa = MlDsa::ml_dsa_65();
    /// let randomness = [0u8; SIGNING_RANDOMNESS_SIZE];
    /// let secret_key = SigSecretKey::new(vec![0u8; 4032]);
    /// let signature = ml_dsa
    ///     .sign_with_randomness_and_context(
    ///         &secret_key,
    ///         b"msg",
    ///         b"example.org/v0",
    ///         randomness,
    ///     )
    ///     .unwrap();
    /// ```
    #[cfg(feature = "alloc")]
    pub fn sign_with_randomness_and_context(
        &self,
        secret_key: &SigSecretKey,
        message: &[u8],
        context: &[u8],
        randomness: [u8; SIGNING_RANDOMNESS_SIZE],
    ) -> Result<Vec<u8>> {
        validate_context(context)?;

        // Validate secret key size for the specific variant
        let expected_sk_size = match self.variant {
            MlDsaVariant::MlDsa44 => MLDSA44_SIGNING_KEY_SIZE,
            MlDsaVariant::MlDsa65 => MLDSA65_SIGNING_KEY_SIZE,
            MlDsaVariant::MlDsa87 => MLDSA87_SIGNING_KEY_SIZE,
        };

        if secret_key.as_bytes().len() != expected_sk_size {
            return Err(lib_q_core::Error::InvalidKeySize {
                expected: expected_sk_size,
                actual: secret_key.as_bytes().len(),
            });
        }

        // Perform signing using the appropriate ML-DSA variant
        let signature = match self.variant {
            MlDsaVariant::MlDsa44 => {
                let mut signing_key = MLDSASigningKey::zero();
                signing_key
                    .as_mut_slice()
                    .copy_from_slice(secret_key.as_bytes());

                let sig_result =
                    ml_dsa_44::portable::sign(&signing_key, message, context, randomness);
                signing_key.as_mut_slice().zeroize();
                sig_result
                    .map(|signature| signature.as_slice().to_vec())
                    .map_err(|_| lib_q_core::Error::SigningFailed {
                        operation: "ml-dsa-44 signing".to_string(),
                    })?
            }
            MlDsaVariant::MlDsa65 => {
                let mut signing_key = MLDSASigningKey::zero();
                signing_key
                    .as_mut_slice()
                    .copy_from_slice(secret_key.as_bytes());

                let sig_result =
                    ml_dsa_65::portable::sign(&signing_key, message, context, randomness);
                signing_key.as_mut_slice().zeroize();
                sig_result
                    .map(|signature| signature.as_slice().to_vec())
                    .map_err(|_| lib_q_core::Error::SigningFailed {
                        operation: "ml-dsa-65 signing".to_string(),
                    })?
            }
            MlDsaVariant::MlDsa87 => {
                let mut signing_key = MLDSASigningKey::zero();
                signing_key
                    .as_mut_slice()
                    .copy_from_slice(secret_key.as_bytes());

                let sig_result =
                    ml_dsa_87::portable::sign(&signing_key, message, context, randomness);
                signing_key.as_mut_slice().zeroize();
                sig_result
                    .map(|signature| signature.as_slice().to_vec())
                    .map_err(|_| lib_q_core::Error::SigningFailed {
                        operation: "ml-dsa-87 signing".to_string(),
                    })?
            }
        };

        Ok(signature)
    }

    #[cfg(not(feature = "alloc"))]
    pub fn sign_with_randomness(
        &self,
        _secret_key: &SigSecretKey,
        _message: &[u8],
        _randomness: [u8; SIGNING_RANDOMNESS_SIZE],
    ) -> Result<&'static [u8]> {
        Err(lib_q_core::Error::RandomGenerationFailed {
            operation: "ml-dsa signing requires alloc feature".to_string(),
        })
    }

    #[cfg(not(feature = "alloc"))]
    pub fn sign_with_randomness_and_context(
        &self,
        _secret_key: &SigSecretKey,
        _message: &[u8],
        _context: &[u8],
        _randomness: [u8; SIGNING_RANDOMNESS_SIZE],
    ) -> Result<&'static [u8]> {
        Err(lib_q_core::Error::RandomGenerationFailed {
            operation: "ml-dsa signing requires alloc feature".to_string(),
        })
    }

    /// Sign a message under a FIPS-204 signing context, drawing randomness from the system RNG.
    ///
    /// This is the context-taking counterpart of [`Signature::sign`]. Pass `&[]` for the
    /// context-free behaviour.
    ///
    /// # Errors
    /// Returns [`InvalidAssociatedDataSize`](lib_q_core::Error::InvalidAssociatedDataSize) if
    /// `context` exceeds [`ML_DSA_CONTEXT_MAX_LEN`] bytes.
    #[cfg(feature = "alloc")]
    #[allow(unused_variables)]
    pub fn sign_with_context(
        &self,
        secret_key: &SigSecretKey,
        message: &[u8],
        context: &[u8],
    ) -> Result<Vec<u8>> {
        #[cfg(feature = "std")]
        {
            use lib_q_core::Utils;

            let randomness = Utils::random_bytes(SIGNING_RANDOMNESS_SIZE).map_err(|_| {
                lib_q_core::Error::RandomGenerationFailed {
                    operation: "ml-dsa signing".to_string(),
                }
            })?;

            let randomness_len = randomness.len();
            let randomness_array: [u8; SIGNING_RANDOMNESS_SIZE] =
                randomness
                    .try_into()
                    .map_err(|_| lib_q_core::Error::InvalidKeySize {
                        expected: SIGNING_RANDOMNESS_SIZE,
                        actual: randomness_len,
                    })?;

            self.sign_with_randomness_and_context(secret_key, message, context, randomness_array)
        }

        #[cfg(not(feature = "std"))]
        {
            Err(lib_q_core::Error::RandomGenerationFailed {
                operation: "ml-dsa signing requires std feature or external randomness".to_string(),
            })
        }
    }

    /// Verify a signature under a FIPS-204 signing context.
    ///
    /// Verification succeeds only when `context` matches the context the signature was
    /// produced under, byte for byte. Pass `&[]` for the context-free behaviour of
    /// [`Signature::verify`].
    ///
    /// `signature` must equal the fixed ML-DSA serialized length for this variant. Shorter or
    /// longer inputs are rejected with
    /// [`InvalidSignatureSize`](lib_q_core::Error::InvalidSignatureSize) rather than padded or
    /// truncated.
    ///
    /// # Errors
    /// Returns [`InvalidAssociatedDataSize`](lib_q_core::Error::InvalidAssociatedDataSize) if
    /// `context` exceeds [`ML_DSA_CONTEXT_MAX_LEN`] bytes. Note that this is a hard error, not
    /// a `false` verdict: an unrepresentable context is a caller bug, not a bad signature.
    pub fn verify_with_context(
        &self,
        public_key: &SigPublicKey,
        message: &[u8],
        context: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        use lib_q_ml_dsa::types::{
            MLDSASignature,
            MLDSAVerificationKey,
        };

        validate_context(context)?;

        // Convert public key bytes to ML-DSA verification key
        let public_key_bytes = public_key.as_bytes();
        let expected_vk_size = match self.variant {
            MlDsaVariant::MlDsa44 => MLDSA44_VERIFICATION_KEY_SIZE,
            MlDsaVariant::MlDsa65 => MLDSA65_VERIFICATION_KEY_SIZE,
            MlDsaVariant::MlDsa87 => MLDSA87_VERIFICATION_KEY_SIZE,
        };

        // Validate public key size first
        if public_key_bytes.len() != expected_vk_size {
            return Err(lib_q_core::Error::InvalidKeySize {
                expected: expected_vk_size,
                actual: public_key_bytes.len(),
            });
        }

        let expected_sig_size = match self.variant {
            MlDsaVariant::MlDsa44 => MLDSA44_SIGNATURE_SIZE,
            MlDsaVariant::MlDsa65 => MLDSA65_SIGNATURE_SIZE,
            MlDsaVariant::MlDsa87 => MLDSA87_SIGNATURE_SIZE,
        };
        if signature.len() != expected_sig_size {
            return Err(lib_q_core::Error::InvalidSignatureSize {
                expected: expected_sig_size,
                actual: signature.len(),
            });
        }

        // Create verification key and verify for the specific variant
        let result = match self.variant {
            MlDsaVariant::MlDsa44 => {
                let mut vk_bytes = [0u8; MLDSA44_VERIFICATION_KEY_SIZE];
                vk_bytes.copy_from_slice(public_key_bytes);
                let verification_key = MLDSAVerificationKey::new(vk_bytes);

                let mut sig_bytes = [0u8; MLDSA44_SIGNATURE_SIZE];
                sig_bytes.copy_from_slice(signature);
                let ml_dsa_signature = MLDSASignature::new(sig_bytes);

                ml_dsa_44::portable::verify(&verification_key, message, context, &ml_dsa_signature)
                    .is_ok()
            }
            MlDsaVariant::MlDsa65 => {
                let mut vk_bytes = [0u8; MLDSA65_VERIFICATION_KEY_SIZE];
                vk_bytes.copy_from_slice(public_key_bytes);
                let verification_key = MLDSAVerificationKey::new(vk_bytes);

                let mut sig_bytes = [0u8; MLDSA65_SIGNATURE_SIZE];
                sig_bytes.copy_from_slice(signature);
                let ml_dsa_signature = MLDSASignature::new(sig_bytes);

                ml_dsa_65::portable::verify(&verification_key, message, context, &ml_dsa_signature)
                    .is_ok()
            }
            MlDsaVariant::MlDsa87 => {
                let mut vk_bytes = [0u8; MLDSA87_VERIFICATION_KEY_SIZE];
                vk_bytes.copy_from_slice(public_key_bytes);
                let verification_key = MLDSAVerificationKey::new(vk_bytes);

                let mut sig_bytes = [0u8; MLDSA87_SIGNATURE_SIZE];
                sig_bytes.copy_from_slice(signature);
                let ml_dsa_signature = MLDSASignature::new(sig_bytes);

                ml_dsa_87::portable::verify(&verification_key, message, context, &ml_dsa_signature)
                    .is_ok()
            }
        };

        Ok(result)
    }
}

impl Default for MlDsa {
    fn default() -> Self {
        Self::ml_dsa_65() // Default to ML-DSA-65 for 192-bit security
    }
}

impl Signature for MlDsa {
    fn generate_keypair(&self) -> Result<SigKeypair> {
        #[cfg(feature = "std")]
        {
            use lib_q_core::Utils;

            // Generate cryptographically secure random seed
            let seed = Utils::random_bytes(KEY_GENERATION_RANDOMNESS_SIZE).map_err(|_| {
                lib_q_core::Error::RandomGenerationFailed {
                    operation: "ml-dsa key generation".to_string(),
                }
            })?;

            let seed_len = seed.len();
            let seed_array: [u8; KEY_GENERATION_RANDOMNESS_SIZE] =
                seed.try_into()
                    .map_err(|_| lib_q_core::Error::InvalidKeySize {
                        expected: KEY_GENERATION_RANDOMNESS_SIZE,
                        actual: seed_len,
                    })?;

            self.generate_keypair_with_randomness(seed_array)
        }

        #[cfg(not(feature = "std"))]
        {
            // In no_std mode, return error - key generation requires randomness
            Err(lib_q_core::Error::RandomGenerationFailed {
                operation: "ml-dsa key generation requires std feature or external randomness"
                    .to_string(),
            })
        }
    }

    #[cfg(feature = "alloc")]
    #[allow(unused_variables)]
    fn sign(&self, secret_key: &SigSecretKey, message: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "std")]
        {
            use lib_q_core::Utils;

            // Generate cryptographically secure random seed for signing
            let randomness = Utils::random_bytes(SIGNING_RANDOMNESS_SIZE).map_err(|_| {
                lib_q_core::Error::RandomGenerationFailed {
                    operation: "ml-dsa signing".to_string(),
                }
            })?;

            let randomness_len = randomness.len();
            let randomness_array: [u8; SIGNING_RANDOMNESS_SIZE] =
                randomness
                    .try_into()
                    .map_err(|_| lib_q_core::Error::InvalidKeySize {
                        expected: SIGNING_RANDOMNESS_SIZE,
                        actual: randomness_len,
                    })?;

            self.sign_with_randomness(secret_key, message, randomness_array)
        }

        #[cfg(not(feature = "std"))]
        {
            // In no_std mode, return error - signing requires randomness
            Err(lib_q_core::Error::RandomGenerationFailed {
                operation: "ml-dsa signing requires std feature or external randomness".to_string(),
            })
        }
    }

    #[cfg(not(feature = "alloc"))]
    fn sign(&self, _secret_key: &SigSecretKey, _message: &[u8]) -> Result<Vec<u8>> {
        // In no_std mode without alloc, we cannot return Vec<u8>
        // This is a limitation of the trait definition - it should return &'static [u8] in no_std mode
        // For now, we return an error indicating that external randomness is required
        Err(lib_q_core::Error::RandomGenerationFailed {
            operation: "ml-dsa signing requires alloc feature or external randomness".to_string(),
        })
    }

    /// `signature` must equal the fixed ML-DSA serialized length for this variant. Shorter or longer
    /// inputs must not be padded or truncated; they are rejected with [`InvalidSignatureSize`](lib_q_core::Error::InvalidSignatureSize).
    fn verify(&self, public_key: &SigPublicKey, message: &[u8], signature: &[u8]) -> Result<bool> {
        // Empty context: see [`MlDsa::verify_with_context`] for the context-bound form.
        self.verify_with_context(public_key, message, &[], signature)
    }
}

#[cfg(test)]
mod tests {
    use lib_q_core::{
        SigPublicKey,
        SigSecretKey,
    };

    use super::*;

    #[test]
    fn test_ml_dsa_variants() {
        // Test that all variants can be created
        let ml_dsa_44 = MlDsa::ml_dsa_44();
        let ml_dsa_65 = MlDsa::ml_dsa_65();
        let ml_dsa_87 = MlDsa::ml_dsa_87();

        assert!(matches!(ml_dsa_44.variant, MlDsaVariant::MlDsa44));
        assert!(matches!(ml_dsa_65.variant, MlDsaVariant::MlDsa65));
        assert!(matches!(ml_dsa_87.variant, MlDsaVariant::MlDsa87));
    }

    #[test]
    fn test_ml_dsa_keypair_sizes() {
        // Test that keypair sizes are correct for each variant
        let ml_dsa_44 = MlDsa::ml_dsa_44();
        let ml_dsa_65 = MlDsa::ml_dsa_65();
        let ml_dsa_87 = MlDsa::ml_dsa_87();

        // Test key generation with provided randomness (no_std compatible)
        let test_randomness = [0u8; KEY_GENERATION_RANDOMNESS_SIZE];

        let keypair_44 = ml_dsa_44
            .generate_keypair_with_randomness(test_randomness)
            .unwrap();
        let keypair_65 = ml_dsa_65
            .generate_keypair_with_randomness(test_randomness)
            .unwrap();
        let keypair_87 = ml_dsa_87
            .generate_keypair_with_randomness(test_randomness)
            .unwrap();

        // Verify public key sizes
        assert_eq!(
            keypair_44.public_key().as_bytes().len(),
            MLDSA44_VERIFICATION_KEY_SIZE
        );
        assert_eq!(
            keypair_65.public_key().as_bytes().len(),
            MLDSA65_VERIFICATION_KEY_SIZE
        );
        assert_eq!(
            keypair_87.public_key().as_bytes().len(),
            MLDSA87_VERIFICATION_KEY_SIZE
        );

        // Verify secret key sizes
        assert_eq!(
            keypair_44.secret_key().as_bytes().len(),
            MLDSA44_SIGNING_KEY_SIZE
        );
        assert_eq!(
            keypair_65.secret_key().as_bytes().len(),
            MLDSA65_SIGNING_KEY_SIZE
        );
        assert_eq!(
            keypair_87.secret_key().as_bytes().len(),
            MLDSA87_SIGNING_KEY_SIZE
        );
    }

    #[test]
    fn test_ml_dsa_signing_sizes() {
        // Test that signature sizes are correct for each variant
        let ml_dsa_65 = MlDsa::ml_dsa_65();

        // Test signature generation with provided randomness (no_std compatible)
        let test_randomness = [0u8; KEY_GENERATION_RANDOMNESS_SIZE];
        let signing_randomness = [0u8; SIGNING_RANDOMNESS_SIZE];

        let keypair = ml_dsa_65
            .generate_keypair_with_randomness(test_randomness)
            .unwrap();
        let message = b"Hello, ML-DSA!";
        let signature = ml_dsa_65
            .sign_with_randomness(keypair.secret_key(), message, signing_randomness)
            .unwrap();

        // Verify signature size
        assert_eq!(signature.len(), MLDSA65_SIGNATURE_SIZE);

        // Verify signature
        let is_valid = ml_dsa_65
            .verify(keypair.public_key(), message, &signature)
            .unwrap();
        assert!(is_valid);
    }

    #[test]
    fn sign_with_randomness_rejects_wrong_secret_key_length() {
        let dsa44 = MlDsa::ml_dsa_44();
        let bad = SigSecretKey::new(vec![0u8; 8]);
        let r = dsa44.sign_with_randomness(&bad, b"m", [0u8; SIGNING_RANDOMNESS_SIZE]);
        assert!(matches!(r, Err(lib_q_core::Error::InvalidKeySize { .. })));

        let dsa65 = MlDsa::ml_dsa_65();
        let kp44 = dsa44
            .generate_keypair_with_randomness([9u8; KEY_GENERATION_RANDOMNESS_SIZE])
            .unwrap();
        let r = dsa65.sign_with_randomness(kp44.secret_key(), b"m", [0u8; SIGNING_RANDOMNESS_SIZE]);
        assert!(matches!(r, Err(lib_q_core::Error::InvalidKeySize { .. })));
    }

    #[test]
    fn verify_rejects_bad_public_key_and_signature_sizes() {
        let dsa = MlDsa::ml_dsa_65();
        let kp = dsa
            .generate_keypair_with_randomness([3u8; KEY_GENERATION_RANDOMNESS_SIZE])
            .unwrap();
        let sig = dsa
            .sign_with_randomness(kp.secret_key(), b"x", [4u8; SIGNING_RANDOMNESS_SIZE])
            .unwrap();
        assert!(matches!(
            dsa.verify(&SigPublicKey::new(vec![0u8; 4]), b"x", &sig),
            Err(lib_q_core::Error::InvalidKeySize { .. })
        ));
        assert!(matches!(
            dsa.verify(kp.public_key(), b"x", &[0u8; 8]),
            Err(lib_q_core::Error::InvalidSignatureSize { .. })
        ));
    }
}

#[test]
fn test_default_variant() {
    let default_ml_dsa = MlDsa::default();
    assert!(matches!(default_ml_dsa.variant, MlDsaVariant::MlDsa65));
}

#[cfg(feature = "std")]
#[test]
fn test_keypair_generation() {
    let ml_dsa = MlDsa::ml_dsa_65();
    let keypair = ml_dsa.generate_keypair().unwrap();

    assert!(!keypair.public_key().as_bytes().is_empty());
    assert!(!keypair.secret_key().as_bytes().is_empty());
}

#[cfg(feature = "std")]
#[test]
fn test_sign_and_verify() {
    let ml_dsa = MlDsa::ml_dsa_65();
    let keypair = ml_dsa.generate_keypair().unwrap();

    let message = b"Hello, ML-DSA!";
    let signature = ml_dsa.sign(keypair.secret_key(), message).unwrap();

    let is_valid = ml_dsa
        .verify(keypair.public_key(), message, &signature)
        .unwrap();
    assert!(is_valid);
}

#[cfg(feature = "std")]
#[test]
fn test_invalid_signature() {
    let ml_dsa = MlDsa::ml_dsa_65();
    let keypair = ml_dsa.generate_keypair().unwrap();

    let message = b"Hello, ML-DSA!";
    let wrong_message = b"Goodbye, ML-DSA!";
    let signature = ml_dsa.sign(keypair.secret_key(), message).unwrap();

    let is_valid = ml_dsa
        .verify(keypair.public_key(), wrong_message, &signature)
        .unwrap();
    assert!(!is_valid);
}

// WASM bindings for ML-DSA
#[cfg(feature = "wasm")]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl MlDsa {
    /// Generate a keypair for WASM (JavaScript) environment
    ///
    /// # Arguments
    /// * `randomness` - Optional randomness as Uint8Array
    ///
    /// # Returns
    /// * `Result<WasmMlDsaKeyPair, JsValue>` - The keypair or error
    #[wasm_bindgen]
    pub fn generate_keypair_wasm(
        &self,
        randomness: Option<Uint8Array>,
    ) -> core::result::Result<WasmMlDsaKeyPair, JsValue> {
        let randomness_array = if let Some(rand) = randomness {
            let rand_vec = rand.to_vec();
            if rand_vec.len() != KEY_GENERATION_RANDOMNESS_SIZE {
                return Err(JsValue::from_str("Invalid randomness size"));
            }
            let mut array = [0u8; KEY_GENERATION_RANDOMNESS_SIZE];
            array.copy_from_slice(&rand_vec);
            Some(array)
        } else {
            None
        };

        let keypair = if let Some(rand) = randomness_array {
            self.generate_keypair_with_randomness(rand)
                .map_err(|e| JsValue::from_str(&e.to_string()))?
        } else {
            self.generate_keypair()
                .map_err(|e| JsValue::from_str(&e.to_string()))?
        };

        Ok(WasmMlDsaKeyPair::new(
            Uint8Array::from(keypair.public_key().as_bytes()),
            Uint8Array::from(keypair.secret_key().as_bytes()),
        ))
    }

    /// Sign a message in WASM (JavaScript) environment
    ///
    /// # Arguments
    /// * `secret_key` - The secret key as Uint8Array
    /// * `message` - The message to sign as Uint8Array
    /// * `randomness` - Optional randomness as Uint8Array
    ///
    /// # Returns
    /// * `Result<Uint8Array, JsValue>` - The signature or error
    #[wasm_bindgen]
    pub fn sign_wasm(
        &self,
        secret_key: Uint8Array,
        message: Uint8Array,
        randomness: Option<Uint8Array>,
    ) -> core::result::Result<Uint8Array, JsValue> {
        let secret_key = SigSecretKey::new(secret_key.to_vec());
        let message = message.to_vec();
        let randomness_array = if let Some(rand) = randomness {
            let rand_vec = rand.to_vec();
            if rand_vec.len() != SIGNING_RANDOMNESS_SIZE {
                return Err(JsValue::from_str("Invalid randomness size"));
            }
            let mut array = [0u8; SIGNING_RANDOMNESS_SIZE];
            array.copy_from_slice(&rand_vec);
            Some(array)
        } else {
            None
        };

        let signature: Vec<u8> = if let Some(rand) = randomness_array {
            self.sign_with_randomness(&secret_key, &message, rand)
                .map_err(|e| JsValue::from_str(&e.to_string()))?
        } else {
            #[cfg(feature = "std")]
            {
                self.sign(&secret_key, &message)
                    .map_err(|e| JsValue::from_str(&e.to_string()))?
            }
            #[cfg(not(feature = "std"))]
            {
                return Err(JsValue::from_str(
                    "Randomness required for signing in no_std mode",
                ));
            }
        };

        Ok(Uint8Array::from(signature.as_slice()))
    }

    /// Verify a signature in WASM (JavaScript) environment
    ///
    /// # Arguments
    /// * `public_key` - The public key as Uint8Array
    /// * `message` - The message as Uint8Array
    /// * `signature` - The signature to verify as Uint8Array
    ///
    /// # Returns
    /// * `Result<bool, JsValue>` - Verification result or error
    #[wasm_bindgen]
    pub fn verify_wasm(
        &self,
        public_key: Uint8Array,
        message: Uint8Array,
        signature: Uint8Array,
    ) -> core::result::Result<bool, JsValue> {
        let public_key = SigPublicKey::new(public_key.to_vec());
        let message = message.to_vec();
        let signature = signature.to_vec();

        let is_valid = self
            .verify(&public_key, &message, &signature)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        Ok(is_valid)
    }

    /// Sign a message under a FIPS-204 signing context in a WASM (JavaScript) environment
    ///
    /// The signature produced here verifies **only** under the same `context` bytes — use
    /// [`Self::verify_with_context_wasm`]. This is the binding GIP-style domain-separated
    /// signatures (e.g. `wapp.sh/entitlement-v0`) need; [`Self::sign_wasm`] remains the
    /// empty-context path.
    ///
    /// # Arguments
    /// * `secret_key` - The secret key as Uint8Array
    /// * `message` - The message to sign as Uint8Array
    /// * `context` - The signing context as Uint8Array (at most 255 bytes)
    /// * `randomness` - Optional randomness as Uint8Array
    ///
    /// # Returns
    /// * `Result<Uint8Array, JsValue>` - The signature or error
    #[wasm_bindgen]
    pub fn sign_with_context_wasm(
        &self,
        secret_key: Uint8Array,
        message: Uint8Array,
        context: Uint8Array,
        randomness: Option<Uint8Array>,
    ) -> core::result::Result<Uint8Array, JsValue> {
        let secret_key = SigSecretKey::new(secret_key.to_vec());
        let message = message.to_vec();
        let context = context.to_vec();
        let randomness_array = if let Some(rand) = randomness {
            let rand_vec = rand.to_vec();
            if rand_vec.len() != SIGNING_RANDOMNESS_SIZE {
                return Err(JsValue::from_str("Invalid randomness size"));
            }
            let mut array = [0u8; SIGNING_RANDOMNESS_SIZE];
            array.copy_from_slice(&rand_vec);
            Some(array)
        } else {
            None
        };

        let signature: Vec<u8> = if let Some(rand) = randomness_array {
            self.sign_with_randomness_and_context(&secret_key, &message, &context, rand)
                .map_err(|e| JsValue::from_str(&e.to_string()))?
        } else {
            #[cfg(feature = "std")]
            {
                self.sign_with_context(&secret_key, &message, &context)
                    .map_err(|e| JsValue::from_str(&e.to_string()))?
            }
            #[cfg(not(feature = "std"))]
            {
                return Err(JsValue::from_str(
                    "Randomness required for signing in no_std mode",
                ));
            }
        };

        Ok(Uint8Array::from(signature.as_slice()))
    }

    /// Verify a signature under a FIPS-204 signing context in a WASM (JavaScript) environment
    ///
    /// Returns `false` unless `context` matches the context the signature was produced under,
    /// byte for byte. Pass an empty `context` for the behaviour of [`Self::verify_wasm`].
    ///
    /// # Arguments
    /// * `public_key` - The public key as Uint8Array
    /// * `message` - The message as Uint8Array
    /// * `context` - The signing context as Uint8Array (at most 255 bytes)
    /// * `signature` - The signature to verify as Uint8Array
    ///
    /// # Returns
    /// * `Result<bool, JsValue>` - Verification result or error
    #[wasm_bindgen]
    pub fn verify_with_context_wasm(
        &self,
        public_key: Uint8Array,
        message: Uint8Array,
        context: Uint8Array,
        signature: Uint8Array,
    ) -> core::result::Result<bool, JsValue> {
        let public_key = SigPublicKey::new(public_key.to_vec());
        let message = message.to_vec();
        let context = context.to_vec();
        let signature = signature.to_vec();

        let is_valid = self
            .verify_with_context(&public_key, &message, &context, &signature)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        Ok(is_valid)
    }
}

/// WASM-compatible ML-DSA key pair
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub struct WasmMlDsaKeyPair {
    public_key: Uint8Array,
    secret_key: Uint8Array,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl WasmMlDsaKeyPair {
    #[wasm_bindgen(constructor)]
    pub fn new(public_key: Uint8Array, secret_key: Uint8Array) -> WasmMlDsaKeyPair {
        WasmMlDsaKeyPair {
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
