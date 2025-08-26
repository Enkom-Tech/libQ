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
//!
//! ## Usage Examples
//!
//! ### With std (automatic randomness generation)
//! ```rust,ignore
//! // This example requires the std feature to be enabled
//! use lib_q_core::Signature;
//! use lib_q_sig::ml_dsa::MlDsa;
//!
//! let ml_dsa = MlDsa::ml_dsa_65();
//! let keypair = ml_dsa.generate_keypair().unwrap();
//! let signature = ml_dsa.sign(keypair.secret_key(), b"Hello, ML-DSA!").unwrap();
//! let is_valid = ml_dsa.verify(keypair.public_key(), b"Hello, ML-DSA!", &signature).unwrap();
//! assert!(is_valid);
//! ```
//!
//! ### Without std (external randomness)
//! ```rust
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
//! ```

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::{
    string::ToString,
    vec::Vec,
};
#[cfg(not(feature = "alloc"))]
use alloc::{
    string::ToString,
    vec::Vec,
};

use lib_q_core::{
    Result,
    SigKeypair,
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

/// CRYSTALS-ML-DSA signature implementation
///
/// This implementation provides both high-level (std) and low-level (no_std) APIs
/// following the lib-q architecture pattern for maximum flexibility.
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
                let kp = ml_dsa_44::portable::generate_key_pair(randomness);
                SigKeypair::new(
                    kp.verification_key.as_slice().to_vec(),
                    kp.signing_key.as_slice().to_vec(),
                )
            }
            MlDsaVariant::MlDsa65 => {
                let kp = ml_dsa_65::portable::generate_key_pair(randomness);
                SigKeypair::new(
                    kp.verification_key.as_slice().to_vec(),
                    kp.signing_key.as_slice().to_vec(),
                )
            }
            MlDsaVariant::MlDsa87 => {
                let kp = ml_dsa_87::portable::generate_key_pair(randomness);
                SigKeypair::new(
                    kp.verification_key.as_slice().to_vec(),
                    kp.signing_key.as_slice().to_vec(),
                )
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
        secret_key: &lib_q_core::SigSecretKey,
        message: &[u8],
        randomness: [u8; SIGNING_RANDOMNESS_SIZE],
    ) -> Result<Vec<u8>> {
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
                let mut sk_bytes = [0u8; MLDSA44_SIGNING_KEY_SIZE];
                sk_bytes.copy_from_slice(secret_key.as_bytes());
                let signing_key = MLDSASigningKey::new(sk_bytes);

                let signature = ml_dsa_44::portable::sign(
                    &signing_key,
                    message,
                    &[], // empty context
                    randomness,
                )
                .map_err(|_| lib_q_core::Error::SigningFailed {
                    operation: "ml-dsa-44 signing".to_string(),
                })?;

                signature.as_slice().to_vec()
            }
            MlDsaVariant::MlDsa65 => {
                let mut sk_bytes = [0u8; MLDSA65_SIGNING_KEY_SIZE];
                sk_bytes.copy_from_slice(secret_key.as_bytes());
                let signing_key = MLDSASigningKey::new(sk_bytes);

                let signature = ml_dsa_65::portable::sign(
                    &signing_key,
                    message,
                    &[], // empty context
                    randomness,
                )
                .map_err(|_| lib_q_core::Error::SigningFailed {
                    operation: "ml-dsa-65 signing".to_string(),
                })?;

                signature.as_slice().to_vec()
            }
            MlDsaVariant::MlDsa87 => {
                let mut sk_bytes = [0u8; MLDSA87_SIGNING_KEY_SIZE];
                sk_bytes.copy_from_slice(secret_key.as_bytes());
                let signing_key = MLDSASigningKey::new(sk_bytes);

                let signature = ml_dsa_87::portable::sign(
                    &signing_key,
                    message,
                    &[], // empty context
                    randomness,
                )
                .map_err(|_| lib_q_core::Error::SigningFailed {
                    operation: "ml-dsa-87 signing".to_string(),
                })?;

                signature.as_slice().to_vec()
            }
        };

        Ok(signature)
    }

    #[cfg(not(feature = "alloc"))]
    pub fn sign_with_randomness(
        &self,
        _secret_key: &lib_q_core::SigSecretKey,
        _message: &[u8],
        _randomness: [u8; SIGNING_RANDOMNESS_SIZE],
    ) -> Result<&'static [u8]> {
        Err(lib_q_core::Error::RandomGenerationFailed {
            operation: "ml-dsa signing requires alloc feature".to_string(),
        })
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
            #[cfg(feature = "alloc")]
            {
                Err(lib_q_core::Error::RandomGenerationFailed {
                    operation: "ml-dsa key generation requires std feature or external randomness"
                        .to_string(),
                })
            }
            #[cfg(not(feature = "alloc"))]
            {
                Err(lib_q_core::Error::RandomGenerationFailed {
                    operation: "ml-dsa key generation requires std feature or external randomness"
                        .to_string(),
                })
            }
        }
    }

    #[cfg(feature = "alloc")]
    fn sign(&self, secret_key: &lib_q_core::SigSecretKey, message: &[u8]) -> Result<Vec<u8>> {
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
            #[cfg(feature = "alloc")]
            {
                Err(lib_q_core::Error::RandomGenerationFailed {
                    operation: "ml-dsa signing requires std feature or external randomness"
                        .to_string(),
                })
            }
            #[cfg(not(feature = "alloc"))]
            {
                Err(lib_q_core::Error::RandomGenerationFailed {
                    operation: "ml-dsa signing requires std feature or external randomness",
                })
            }
        }
    }

    #[cfg(not(feature = "alloc"))]
    fn sign(&self, _secret_key: &lib_q_core::SigSecretKey, _message: &[u8]) -> Result<Vec<u8>> {
        // In no_std mode without alloc, we cannot return Vec<u8>
        // This is a limitation of the trait definition - it should return &'static [u8] in no_std mode
        // For now, we return an error indicating that external randomness is required
        Err(lib_q_core::Error::RandomGenerationFailed {
            operation: "ml-dsa signing requires alloc feature or external randomness".to_string(),
        })
    }

    fn verify(
        &self,
        public_key: &lib_q_core::SigPublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        use lib_q_ml_dsa::types::{
            MLDSASignature,
            MLDSAVerificationKey,
        };

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

        // Create verification key and verify for the specific variant
        let result = match self.variant {
            MlDsaVariant::MlDsa44 => {
                let mut vk_bytes = [0u8; MLDSA44_VERIFICATION_KEY_SIZE];
                vk_bytes.copy_from_slice(public_key_bytes);
                let verification_key = MLDSAVerificationKey::new(vk_bytes);

                let mut sig_bytes = [0u8; MLDSA44_SIGNATURE_SIZE];
                sig_bytes[..signature.len().min(MLDSA44_SIGNATURE_SIZE)].copy_from_slice(signature);
                let ml_dsa_signature = MLDSASignature::new(sig_bytes);

                ml_dsa_44::portable::verify(
                    &verification_key,
                    message,
                    &[], // empty context
                    &ml_dsa_signature,
                )
                .is_ok()
            }
            MlDsaVariant::MlDsa65 => {
                let mut vk_bytes = [0u8; MLDSA65_VERIFICATION_KEY_SIZE];
                vk_bytes.copy_from_slice(public_key_bytes);
                let verification_key = MLDSAVerificationKey::new(vk_bytes);

                let mut sig_bytes = [0u8; MLDSA65_SIGNATURE_SIZE];
                sig_bytes[..signature.len().min(MLDSA65_SIGNATURE_SIZE)].copy_from_slice(signature);
                let ml_dsa_signature = MLDSASignature::new(sig_bytes);

                ml_dsa_65::portable::verify(
                    &verification_key,
                    message,
                    &[], // empty context
                    &ml_dsa_signature,
                )
                .is_ok()
            }
            MlDsaVariant::MlDsa87 => {
                let mut vk_bytes = [0u8; MLDSA87_VERIFICATION_KEY_SIZE];
                vk_bytes.copy_from_slice(public_key_bytes);
                let verification_key = MLDSAVerificationKey::new(vk_bytes);

                let mut sig_bytes = [0u8; MLDSA87_SIGNATURE_SIZE];
                sig_bytes[..signature.len().min(MLDSA87_SIGNATURE_SIZE)].copy_from_slice(signature);
                let ml_dsa_signature = MLDSASignature::new(sig_bytes);

                ml_dsa_87::portable::verify(
                    &verification_key,
                    message,
                    &[], // empty context
                    &ml_dsa_signature,
                )
                .is_ok()
            }
        };

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
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
