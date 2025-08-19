//! Unified API for lib-Q cryptographic operations
//!
//! This module provides a consistent, secure API that works identically
//! whether used as a Rust crate or compiled to WASM.

use crate::{error::Result, traits::*};
use core::marker::PhantomData;

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

#[cfg(any(feature = "getrandom", feature = "rand"))]
use rand_core::RngCore;

#[cfg(feature = "ml-kem")]
use lib_q_ml_kem::{
    Ciphertext,
    Decapsulate,
    Encapsulate,
    EncodedSizeUser,
    KemCore,
    MLKEM512_CIPHERTEXT_SIZE,
    // ML-KEM size constants for validation
    MLKEM512_PUBLIC_KEY_SIZE,
    MLKEM512_SECRET_KEY_SIZE,
    MLKEM768_CIPHERTEXT_SIZE,
    MLKEM768_PUBLIC_KEY_SIZE,
    MLKEM768_SECRET_KEY_SIZE,
    MLKEM1024_CIPHERTEXT_SIZE,
    MLKEM1024_PUBLIC_KEY_SIZE,
    MLKEM1024_SECRET_KEY_SIZE,
    MlKem512,
    MlKem768,
    MlKem1024,
};

#[cfg(feature = "ml-kem")]
use lib_q_ml_kem::array::Array;

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// Algorithm identifiers for cryptographic operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum Algorithm {
    // KEM algorithms
    MlKem512,
    MlKem768,
    MlKem1024,
    McEliece348864,
    McEliece460896,
    McEliece6688128,
    McEliece6960119,
    McEliece8192128,
    Hqc128,
    Hqc192,
    Hqc256,

    // Signature algorithms
    Dilithium2,
    Dilithium3,
    Dilithium5,
    Falcon512,
    Falcon1024,
    SphincsSha256128fRobust,
    SphincsSha256192fRobust,
    SphincsSha256256fRobust,
    SphincsShake256128fRobust,
    SphincsShake256192fRobust,
    SphincsShake256256fRobust,

    // Hash algorithms
    Shake128,
    Shake256,
    CShake128,
    CShake256,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Kmac128,
    Kmac256,
    TupleHash128,
    TupleHash256,
    ParallelHash128,
    ParallelHash256,
}

impl Algorithm {
    /// Get the security level for this algorithm
    pub fn security_level(&self) -> u32 {
        match self {
            // Level 1 (128-bit security)
            Algorithm::MlKem512 => 1,
            Algorithm::McEliece348864 => 1,
            Algorithm::Hqc128 => 1,
            Algorithm::Dilithium2 => 1,
            Algorithm::Falcon512 => 1,
            Algorithm::SphincsSha256128fRobust => 1,
            Algorithm::SphincsShake256128fRobust => 1,

            // Level 3 (192-bit security)
            Algorithm::MlKem768 => 3,
            Algorithm::McEliece460896 => 3,
            Algorithm::Hqc192 => 3,
            Algorithm::Dilithium3 => 3,
            Algorithm::Falcon1024 => 3,
            Algorithm::SphincsSha256192fRobust => 3,
            Algorithm::SphincsShake256192fRobust => 3,

            // Level 4 (256-bit security)
            Algorithm::MlKem1024 => 4,
            Algorithm::McEliece6688128 => 4,
            Algorithm::McEliece6960119 => 4,
            Algorithm::Hqc256 => 4,
            Algorithm::Dilithium5 => 4,
            Algorithm::SphincsSha256256fRobust => 4,
            Algorithm::SphincsShake256256fRobust => 4,

            // Level 5 (256-bit security, higher performance)
            Algorithm::McEliece8192128 => 5,

            // Hash algorithms don't have security levels
            Algorithm::Shake128
            | Algorithm::Shake256
            | Algorithm::CShake128
            | Algorithm::CShake256
            | Algorithm::Sha3_224
            | Algorithm::Sha3_256
            | Algorithm::Sha3_384
            | Algorithm::Sha3_512
            | Algorithm::Kmac128
            | Algorithm::Kmac256
            | Algorithm::TupleHash128
            | Algorithm::TupleHash256
            | Algorithm::ParallelHash128
            | Algorithm::ParallelHash256 => 0,
        }
    }

    /// Get the algorithm category
    pub fn category(&self) -> AlgorithmCategory {
        match self {
            Algorithm::MlKem512
            | Algorithm::MlKem768
            | Algorithm::MlKem1024
            | Algorithm::McEliece348864
            | Algorithm::McEliece460896
            | Algorithm::McEliece6688128
            | Algorithm::McEliece6960119
            | Algorithm::McEliece8192128
            | Algorithm::Hqc128
            | Algorithm::Hqc192
            | Algorithm::Hqc256 => AlgorithmCategory::Kem,

            Algorithm::Dilithium2
            | Algorithm::Dilithium3
            | Algorithm::Dilithium5
            | Algorithm::Falcon512
            | Algorithm::Falcon1024
            | Algorithm::SphincsSha256128fRobust
            | Algorithm::SphincsSha256192fRobust
            | Algorithm::SphincsSha256256fRobust
            | Algorithm::SphincsShake256128fRobust
            | Algorithm::SphincsShake256192fRobust
            | Algorithm::SphincsShake256256fRobust => AlgorithmCategory::Signature,

            Algorithm::Shake128
            | Algorithm::Shake256
            | Algorithm::CShake128
            | Algorithm::CShake256
            | Algorithm::Sha3_224
            | Algorithm::Sha3_256
            | Algorithm::Sha3_384
            | Algorithm::Sha3_512
            | Algorithm::Kmac128
            | Algorithm::Kmac256
            | Algorithm::TupleHash128
            | Algorithm::TupleHash256
            | Algorithm::ParallelHash128
            | Algorithm::ParallelHash256 => AlgorithmCategory::Hash,
        }
    }
}

/// Algorithm categories
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum AlgorithmCategory {
    Kem,
    Signature,
    Hash,
}

/// Security levels for cryptographic algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum SecurityLevel {
    Level1 = 1, // 128-bit security
    Level3 = 3, // 192-bit security
    Level4 = 4, // 256-bit security
    Level5 = 5, // 256-bit security (higher performance)
}

impl SecurityLevel {
    /// Convert from u32 to SecurityLevel
    pub fn from_u32(level: u32) -> Option<Self> {
        match level {
            1 => Some(SecurityLevel::Level1),
            3 => Some(SecurityLevel::Level3),
            4 => Some(SecurityLevel::Level4),
            5 => Some(SecurityLevel::Level5),
            _ => None,
        }
    }

    /// Convert to u32
    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

/// Secure context for cryptographic operations
///
/// This provides a safe, zero-cost abstraction that ensures proper
/// initialization and cleanup of cryptographic operations.
pub struct Context<T> {
    _phantom: PhantomData<T>,
    initialized: bool,
}

impl<T> Context<T> {
    /// Create a new uninitialized context
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
            initialized: false,
        }
    }

    /// Initialize the context
    pub fn init(&mut self) -> Result<()> {
        if self.initialized {
            return Ok(());
        }
        self.initialized = true;
        Ok(())
    }

    /// Check if the context is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl<T> Default for Context<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// KEM context for key encapsulation operations
pub struct KemContext {
    inner: Context<Self>,
}

impl KemContext {
    /// Create a new KEM context
    pub fn new() -> Self {
        Self {
            inner: Context::new(),
        }
    }

    /// Generate a keypair for the specified algorithm
    pub fn generate_keypair(&mut self, algorithm: Algorithm) -> Result<KemKeypair> {
        if !self.inner.is_initialized() {
            self.inner.init()?;
        }

        // Validate algorithm category
        if algorithm.category() != AlgorithmCategory::Kem {
            #[cfg(feature = "alloc")]
            return Err(crate::error::Error::InvalidAlgorithm {
                algorithm: format!("{algorithm:?} is not a KEM algorithm"),
            });
            #[cfg(not(feature = "alloc"))]
            return Err(crate::error::Error::InvalidAlgorithm {
                algorithm: "algorithm is not a KEM algorithm",
            });
        }

        #[cfg(feature = "ml-kem")]
        {
            // Use real ML-KEM implementation for supported algorithms
            match algorithm {
                Algorithm::MlKem512 => {
                    let mut rng = rand::rng();
                    let (dk, ek) = <MlKem512 as KemCore>::generate(&mut rng);

                    #[cfg(feature = "alloc")]
                    {
                        // Convert ML-KEM arrays to Vec<u8> using proper conversion
                        let public_key = ek.as_bytes().as_slice().to_vec();
                        let secret_key = dk.as_bytes().as_slice().to_vec();

                        // Validate key sizes for security
                        if public_key.len() != MLKEM512_PUBLIC_KEY_SIZE {
                            return Err(crate::error::Error::InternalError {
                                operation: String::from("ml-kem-512 key generation"),
                                details: String::from("Invalid public key size"),
                            });
                        }
                        if secret_key.len() != MLKEM512_SECRET_KEY_SIZE {
                            return Err(crate::error::Error::InternalError {
                                operation: String::from("ml-kem-512 key generation"),
                                details: String::from("Invalid secret key size"),
                            });
                        }

                        Ok(KemKeypair::new(public_key, secret_key))
                    }
                    #[cfg(not(feature = "alloc"))]
                    {
                        // In no_std mode, we need to handle this differently
                        // For now, return an error indicating alloc is required for ML-KEM
                        Err(crate::error::Error::MemoryAllocationFailed {
                            operation: "ml-kem key generation",
                        })
                    }
                }
                Algorithm::MlKem768 => {
                    let mut rng = rand::rng();
                    let (dk, ek) = <MlKem768 as KemCore>::generate(&mut rng);

                    #[cfg(feature = "alloc")]
                    {
                        // Convert ML-KEM arrays to Vec<u8> using proper conversion
                        let public_key = ek.as_bytes().as_slice().to_vec();
                        let secret_key = dk.as_bytes().as_slice().to_vec();

                        // Validate key sizes for security
                        if public_key.len() != MLKEM768_PUBLIC_KEY_SIZE {
                            return Err(crate::error::Error::InternalError {
                                operation: String::from("ml-kem-768 key generation"),
                                details: String::from("Invalid public key size"),
                            });
                        }
                        if secret_key.len() != MLKEM768_SECRET_KEY_SIZE {
                            return Err(crate::error::Error::InternalError {
                                operation: String::from("ml-kem-768 key generation"),
                                details: String::from("Invalid secret key size"),
                            });
                        }

                        Ok(KemKeypair::new(public_key, secret_key))
                    }
                    #[cfg(not(feature = "alloc"))]
                    {
                        Err(crate::error::Error::MemoryAllocationFailed {
                            operation: "ml-kem key generation",
                        })
                    }
                }
                Algorithm::MlKem1024 => {
                    let mut rng = rand::rng();
                    let (dk, ek) = <MlKem1024 as KemCore>::generate(&mut rng);

                    #[cfg(feature = "alloc")]
                    {
                        // Convert ML-KEM arrays to Vec<u8> using proper conversion
                        let public_key = ek.as_bytes().as_slice().to_vec();
                        let secret_key = dk.as_bytes().as_slice().to_vec();

                        // Validate key sizes for security
                        if public_key.len() != MLKEM1024_PUBLIC_KEY_SIZE {
                            return Err(crate::error::Error::InternalError {
                                operation: String::from("ml-kem-1024 key generation"),
                                details: String::from("Invalid public key size"),
                            });
                        }
                        if secret_key.len() != MLKEM1024_SECRET_KEY_SIZE {
                            return Err(crate::error::Error::InternalError {
                                operation: String::from("ml-kem-1024 key generation"),
                                details: String::from("Invalid secret key size"),
                            });
                        }

                        Ok(KemKeypair::new(public_key, secret_key))
                    }
                    #[cfg(not(feature = "alloc"))]
                    {
                        Err(crate::error::Error::MemoryAllocationFailed {
                            operation: "ml-kem key generation",
                        })
                    }
                }
                _ => {
                    // Fallback to placeholder for other algorithms
                    let key_size = match algorithm {
                        Algorithm::MlKem512 => 800,
                        Algorithm::MlKem768 => 1184,
                        Algorithm::MlKem1024 => 1568,
                        Algorithm::McEliece348864 => 261120,
                        Algorithm::McEliece460896 => 1357824,
                        Algorithm::McEliece6688128 => 1044992,
                        Algorithm::McEliece6960119 => 1047319,
                        Algorithm::McEliece8192128 => 1357824,
                        Algorithm::Hqc128 => 2249,
                        Algorithm::Hqc192 => 4522,
                        Algorithm::Hqc256 => 9027,
                        _ => 1024, // Default size for other algorithms
                    };

                    #[cfg(feature = "alloc")]
                    {
                        let public_key = vec![0u8; key_size];
                        let secret_key = vec![0u8; key_size];
                        Ok(KemKeypair::new(public_key, secret_key))
                    }
                    #[cfg(not(feature = "alloc"))]
                    {
                        // In no_std mode, return static data
                        static PLACEHOLDER_KEY: [u8; 1024] = [0u8; 1024];
                        Ok(KemKeypair::new(
                            &PLACEHOLDER_KEY[..key_size.min(1024)],
                            &PLACEHOLDER_KEY[..key_size.min(1024)],
                        ))
                    }
                }
            }
        }

        #[cfg(not(feature = "ml-kem"))]
        {
            // Fallback to placeholder implementation when ML-KEM is not available
            let key_size = match algorithm {
                Algorithm::MlKem512 => 800,
                Algorithm::MlKem768 => 1184,
                Algorithm::MlKem1024 => 1568,
                Algorithm::McEliece348864 => 261120,
                Algorithm::McEliece460896 => 1357824,
                Algorithm::McEliece6688128 => 1044992,
                Algorithm::McEliece6960119 => 1047319,
                Algorithm::McEliece8192128 => 1357824,
                Algorithm::Hqc128 => 2249,
                Algorithm::Hqc192 => 4522,
                Algorithm::Hqc256 => 9027,
                _ => 1024, // Default size for other algorithms
            };

            #[cfg(feature = "alloc")]
            {
                let public_key = vec![0u8; key_size];
                let secret_key = vec![0u8; key_size];
                Ok(KemKeypair::new(public_key, secret_key))
            }
            #[cfg(not(feature = "alloc"))]
            {
                // In no_std mode, return static data
                static PLACEHOLDER_KEY: [u8; 1024] = [0u8; 1024];
                Ok(KemKeypair::new(
                    &PLACEHOLDER_KEY[..key_size.min(1024)],
                    &PLACEHOLDER_KEY[..key_size.min(1024)],
                ))
            }
        }
    }

    /// Encapsulate a shared secret using the given public key
    #[cfg(feature = "alloc")]
    pub fn encapsulate(
        &self,
        algorithm: Algorithm,
        public_key: &KemPublicKey,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        if !self.inner.is_initialized() {
            return Err(crate::error::Error::InvalidState {
                operation: String::from("encapsulate"),
                reason: String::from("Context not initialized"),
            });
        }

        #[cfg(feature = "ml-kem")]
        {
            // Use real ML-KEM implementation for supported algorithms
            match algorithm {
                Algorithm::MlKem512 => {
                    // Validate input size for security
                    if public_key.as_bytes().len() != MLKEM512_PUBLIC_KEY_SIZE {
                        return Err(crate::error::Error::InvalidKeySize {
                            expected: MLKEM512_PUBLIC_KEY_SIZE,
                            actual: public_key.as_bytes().len(),
                        });
                    }

                    // Convert Vec<u8> to ML-KEM Array with proper error handling
                    let encoded_key = Array::try_from(public_key.as_bytes()).map_err(|_| {
                        crate::error::Error::InternalError {
                            operation: String::from("ml-kem-512 encapsulation"),
                            details: String::from("Invalid public key format"),
                        }
                    })?;

                    // Reconstruct the encapsulation key from bytes
                    let ek = <MlKem512 as KemCore>::EncapsulationKey::from_bytes(&encoded_key);

                    let mut rng = rand::rng();
                    let (ciphertext, shared_secret) = ek.encapsulate(&mut rng).map_err(|_| {
                        crate::error::Error::EncryptionFailed {
                            operation: String::from("ml-kem-512 encapsulation"),
                        }
                    })?;

                    // Convert ML-KEM arrays back to Vec<u8>
                    Ok((
                        shared_secret.as_slice().to_vec(),
                        ciphertext.as_slice().to_vec(),
                    ))
                }
                Algorithm::MlKem768 => {
                    // Validate input size for security
                    if public_key.as_bytes().len() != MLKEM768_PUBLIC_KEY_SIZE {
                        return Err(crate::error::Error::InvalidKeySize {
                            expected: MLKEM768_PUBLIC_KEY_SIZE,
                            actual: public_key.as_bytes().len(),
                        });
                    }

                    // Convert Vec<u8> to ML-KEM Array with proper error handling
                    let encoded_key = Array::try_from(public_key.as_bytes()).map_err(|_| {
                        crate::error::Error::InternalError {
                            operation: String::from("ml-kem-768 encapsulation"),
                            details: String::from("Invalid public key format"),
                        }
                    })?;

                    let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(&encoded_key);

                    let mut rng = rand::rng();
                    let (ciphertext, shared_secret) = ek.encapsulate(&mut rng).map_err(|_| {
                        crate::error::Error::EncryptionFailed {
                            operation: String::from("ml-kem-768 encapsulation"),
                        }
                    })?;

                    // Convert ML-KEM arrays back to Vec<u8>
                    Ok((
                        shared_secret.as_slice().to_vec(),
                        ciphertext.as_slice().to_vec(),
                    ))
                }
                Algorithm::MlKem1024 => {
                    // Validate input size for security
                    if public_key.as_bytes().len() != MLKEM1024_PUBLIC_KEY_SIZE {
                        return Err(crate::error::Error::InvalidKeySize {
                            expected: MLKEM1024_PUBLIC_KEY_SIZE,
                            actual: public_key.as_bytes().len(),
                        });
                    }

                    // Convert Vec<u8> to ML-KEM Array with proper error handling
                    let encoded_key = Array::try_from(public_key.as_bytes()).map_err(|_| {
                        crate::error::Error::InternalError {
                            operation: String::from("ml-kem-1024 encapsulation"),
                            details: String::from("Invalid public key format"),
                        }
                    })?;

                    let ek = <MlKem1024 as KemCore>::EncapsulationKey::from_bytes(&encoded_key);

                    let mut rng = rand::rng();
                    let (ciphertext, shared_secret) = ek.encapsulate(&mut rng).map_err(|_| {
                        crate::error::Error::EncryptionFailed {
                            operation: String::from("ml-kem-1024 encapsulation"),
                        }
                    })?;

                    // Convert ML-KEM arrays back to Vec<u8>
                    Ok((
                        shared_secret.as_slice().to_vec(),
                        ciphertext.as_slice().to_vec(),
                    ))
                }
                _ => {
                    // Fallback to placeholder for other algorithms
                    let shared_secret = vec![0u8; 32];
                    let ciphertext = vec![0u8; public_key.as_bytes().len()];
                    Ok((shared_secret, ciphertext))
                }
            }
        }

        #[cfg(not(feature = "ml-kem"))]
        {
            // Fallback to placeholder implementation when ML-KEM is not available
            let shared_secret = vec![0u8; 32];
            let ciphertext = vec![0u8; public_key.as_bytes().len()];
            Ok((shared_secret, ciphertext))
        }
    }

    #[cfg(not(feature = "alloc"))]
    pub fn encapsulate(
        &self,
        _algorithm: Algorithm,
        public_key: &KemPublicKey,
    ) -> Result<(&'static [u8], &'static [u8])> {
        if !self.inner.is_initialized() {
            return Err(crate::error::Error::InvalidState {
                operation: "encapsulate",
                reason: "Context not initialized",
            });
        }

        // TODO: Implement actual encapsulation
        static SHARED_SECRET: [u8; 32] = [0u8; 32];
        static CIPHERTEXT: [u8; 1024] = [0u8; 1024];

        Ok((
            &SHARED_SECRET,
            &CIPHERTEXT[..public_key.as_bytes().len().min(1024)],
        ))
    }

    /// Decapsulate a shared secret using the given secret key and ciphertext
    #[cfg(feature = "alloc")]
    pub fn decapsulate(
        &self,
        algorithm: Algorithm,
        secret_key: &KemSecretKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        if !self.inner.is_initialized() {
            return Err(crate::error::Error::InvalidState {
                operation: String::from("decapsulate"),
                reason: String::from("Context not initialized"),
            });
        }

        #[cfg(feature = "ml-kem")]
        {
            // Use real ML-KEM implementation for supported algorithms
            match algorithm {
                Algorithm::MlKem512 => {
                    // Validate input sizes for security
                    if secret_key.as_bytes().len() != MLKEM512_SECRET_KEY_SIZE {
                        return Err(crate::error::Error::InvalidKeySize {
                            expected: MLKEM512_SECRET_KEY_SIZE,
                            actual: secret_key.as_bytes().len(),
                        });
                    }
                    if ciphertext.len() != MLKEM512_CIPHERTEXT_SIZE {
                        return Err(crate::error::Error::InvalidCiphertextSize {
                            expected: MLKEM512_CIPHERTEXT_SIZE,
                            actual: ciphertext.len(),
                        });
                    }

                    // Convert Vec<u8> to ML-KEM Array with proper error handling
                    let encoded_dk = Array::try_from(secret_key.as_bytes()).map_err(|_| {
                        crate::error::Error::InternalError {
                            operation: String::from("ml-kem-512 decapsulation"),
                            details: String::from("Invalid secret key format"),
                        }
                    })?;

                    // Reconstruct the decapsulation key and ciphertext from bytes
                    let dk = <MlKem512 as KemCore>::DecapsulationKey::from_bytes(&encoded_dk);
                    let ct = Ciphertext::<MlKem512>::try_from(ciphertext).map_err(|_| {
                        crate::error::Error::InvalidCiphertextSize {
                            expected: MLKEM512_CIPHERTEXT_SIZE,
                            actual: ciphertext.len(),
                        }
                    })?;

                    let shared_secret =
                        dk.decapsulate(&ct)
                            .map_err(|_| crate::error::Error::DecryptionFailed {
                                operation: String::from("ml-kem-512 decapsulation"),
                            })?;

                    // Convert ML-KEM array back to Vec<u8>
                    Ok(shared_secret.as_slice().to_vec())
                }
                Algorithm::MlKem768 => {
                    // Validate input sizes for security
                    if secret_key.as_bytes().len() != MLKEM768_SECRET_KEY_SIZE {
                        return Err(crate::error::Error::InvalidKeySize {
                            expected: MLKEM768_SECRET_KEY_SIZE,
                            actual: secret_key.as_bytes().len(),
                        });
                    }
                    if ciphertext.len() != MLKEM768_CIPHERTEXT_SIZE {
                        return Err(crate::error::Error::InvalidCiphertextSize {
                            expected: MLKEM768_CIPHERTEXT_SIZE,
                            actual: ciphertext.len(),
                        });
                    }

                    // Convert Vec<u8> to ML-KEM Array with proper error handling
                    let encoded_dk = Array::try_from(secret_key.as_bytes()).map_err(|_| {
                        crate::error::Error::InternalError {
                            operation: String::from("ml-kem-768 decapsulation"),
                            details: String::from("Invalid secret key format"),
                        }
                    })?;

                    let dk = <MlKem768 as KemCore>::DecapsulationKey::from_bytes(&encoded_dk);
                    let ct = Ciphertext::<MlKem768>::try_from(ciphertext).map_err(|_| {
                        crate::error::Error::InvalidCiphertextSize {
                            expected: MLKEM768_CIPHERTEXT_SIZE,
                            actual: ciphertext.len(),
                        }
                    })?;

                    let shared_secret =
                        dk.decapsulate(&ct)
                            .map_err(|_| crate::error::Error::DecryptionFailed {
                                operation: String::from("ml-kem-768 decapsulation"),
                            })?;

                    // Convert ML-KEM array back to Vec<u8>
                    Ok(shared_secret.as_slice().to_vec())
                }
                Algorithm::MlKem1024 => {
                    // Validate input sizes for security
                    if secret_key.as_bytes().len() != MLKEM1024_SECRET_KEY_SIZE {
                        return Err(crate::error::Error::InvalidKeySize {
                            expected: MLKEM1024_SECRET_KEY_SIZE,
                            actual: secret_key.as_bytes().len(),
                        });
                    }
                    if ciphertext.len() != MLKEM1024_CIPHERTEXT_SIZE {
                        return Err(crate::error::Error::InvalidCiphertextSize {
                            expected: MLKEM1024_CIPHERTEXT_SIZE,
                            actual: ciphertext.len(),
                        });
                    }

                    // Convert Vec<u8> to ML-KEM Array with proper error handling
                    let encoded_dk = Array::try_from(secret_key.as_bytes()).map_err(|_| {
                        crate::error::Error::InternalError {
                            operation: String::from("ml-kem-1024 decapsulation"),
                            details: String::from("Invalid secret key format"),
                        }
                    })?;

                    let dk = <MlKem1024 as KemCore>::DecapsulationKey::from_bytes(&encoded_dk);
                    let ct = Ciphertext::<MlKem1024>::try_from(ciphertext).map_err(|_| {
                        crate::error::Error::InvalidCiphertextSize {
                            expected: MLKEM1024_CIPHERTEXT_SIZE,
                            actual: ciphertext.len(),
                        }
                    })?;

                    let shared_secret =
                        dk.decapsulate(&ct)
                            .map_err(|_| crate::error::Error::DecryptionFailed {
                                operation: String::from("ml-kem-1024 decapsulation"),
                            })?;

                    // Convert ML-KEM array back to Vec<u8>
                    Ok(shared_secret.as_slice().to_vec())
                }
                _ => {
                    // Fallback to placeholder for other algorithms
                    Ok(vec![0u8; 32])
                }
            }
        }

        #[cfg(not(feature = "ml-kem"))]
        {
            // Fallback to placeholder implementation when ML-KEM is not available
            Ok(vec![0u8; 32])
        }
    }

    #[cfg(not(feature = "alloc"))]
    pub fn decapsulate(
        &self,
        _algorithm: Algorithm,
        _secret_key: &KemSecretKey,
        _ciphertext: &[u8],
    ) -> Result<&'static [u8]> {
        if !self.inner.is_initialized() {
            return Err(crate::error::Error::InvalidState {
                operation: "decapsulate",
                reason: "Context not initialized",
            });
        }

        // TODO: Implement actual decapsulation
        static SHARED_SECRET: [u8; 32] = [0u8; 32];
        Ok(&SHARED_SECRET)
    }
}

impl Default for KemContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Signature context for digital signature operations
pub struct SignatureContext {
    inner: Context<Self>,
}

impl SignatureContext {
    /// Create a new signature context
    pub fn new() -> Self {
        Self {
            inner: Context::new(),
        }
    }

    /// Generate a keypair for the specified algorithm
    pub fn generate_keypair(&mut self, algorithm: Algorithm) -> Result<SigKeypair> {
        if !self.inner.is_initialized() {
            self.inner.init()?;
        }

        // Validate algorithm category
        if algorithm.category() != AlgorithmCategory::Signature {
            #[cfg(feature = "alloc")]
            return Err(crate::error::Error::InvalidAlgorithm {
                algorithm: format!("{algorithm:?} is not a signature algorithm"),
            });
            #[cfg(not(feature = "alloc"))]
            return Err(crate::error::Error::InvalidAlgorithm {
                algorithm: "algorithm is not a signature algorithm",
            });
        }

        // TODO: Implement actual key generation based on algorithm
        let key_size = match algorithm {
            Algorithm::MlKem512 => 1312,
            Algorithm::MlKem768 => 1952,
            Algorithm::MlKem1024 => 2592,
            Algorithm::Dilithium2 => 1312,
            Algorithm::Dilithium3 => 1952,
            Algorithm::Dilithium5 => 2592,
            Algorithm::Falcon512 => 1024,
            Algorithm::Falcon1024 => 2048,
            Algorithm::SphincsSha256128fRobust => 8080,
            Algorithm::SphincsSha256192fRobust => 16224,
            Algorithm::SphincsSha256256fRobust => 29792,
            Algorithm::SphincsShake256128fRobust => 8080,
            Algorithm::SphincsShake256192fRobust => 16224,
            Algorithm::SphincsShake256256fRobust => 29792,
            _ => 1024, // Default size for other algorithms
        };

        #[cfg(feature = "alloc")]
        {
            let public_key = vec![0u8; key_size];
            let secret_key = vec![0u8; key_size];
            Ok(SigKeypair::new(public_key, secret_key))
        }
        #[cfg(not(feature = "alloc"))]
        {
            // In no_std mode, return static data
            static PLACEHOLDER_KEY: [u8; 1024] = [0u8; 1024];
            Ok(SigKeypair::new(
                &PLACEHOLDER_KEY[..key_size.min(1024)],
                &PLACEHOLDER_KEY[..key_size.min(1024)],
            ))
        }
    }

    /// Sign a message using the given secret key
    #[cfg(feature = "alloc")]
    pub fn sign(
        &self,
        _algorithm: Algorithm,
        _secret_key: &SigSecretKey,
        _message: &[u8],
    ) -> Result<Vec<u8>> {
        if !self.inner.is_initialized() {
            return Err(crate::error::Error::InvalidState {
                operation: String::from("sign"),
                reason: String::from("Context not initialized"),
            });
        }

        // TODO: Implement actual signing
        let signature_size = match _algorithm {
            Algorithm::MlKem512 => 1312,
            Algorithm::MlKem768 => 1952,
            Algorithm::MlKem1024 => 2592,
            Algorithm::Dilithium2 => 2420,
            Algorithm::Dilithium3 => 3293,
            Algorithm::Dilithium5 => 4595,
            Algorithm::Falcon512 => 690,
            Algorithm::Falcon1024 => 1330,
            Algorithm::SphincsSha256128fRobust => 8080,
            Algorithm::SphincsSha256192fRobust => 16224,
            Algorithm::SphincsSha256256fRobust => 29792,
            Algorithm::SphincsShake256128fRobust => 8080,
            Algorithm::SphincsShake256192fRobust => 16224,
            Algorithm::SphincsShake256256fRobust => 29792,
            _ => 1024, // Default size for other algorithms
        };

        Ok(vec![0u8; signature_size])
    }

    #[cfg(not(feature = "alloc"))]
    pub fn sign(
        &self,
        _algorithm: Algorithm,
        _secret_key: &SigSecretKey,
        _message: &[u8],
    ) -> Result<&'static [u8]> {
        if !self.inner.is_initialized() {
            return Err(crate::error::Error::InvalidState {
                operation: "sign",
                reason: "Context not initialized",
            });
        }

        // TODO: Implement actual signing
        static SIGNATURE: [u8; 1024] = [0u8; 1024];
        Ok(&SIGNATURE)
    }

    /// Verify a signature using the given public key
    pub fn verify(
        &self,
        _algorithm: Algorithm,
        _public_key: &SigPublicKey,
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<bool> {
        if !self.inner.is_initialized() {
            #[cfg(feature = "alloc")]
            return Err(crate::error::Error::InvalidState {
                operation: String::from("verify"),
                reason: String::from("Context not initialized"),
            });
            #[cfg(not(feature = "alloc"))]
            return Err(crate::error::Error::InvalidState {
                operation: "verify",
                reason: "Context not initialized",
            });
        }

        // TODO: Implement actual verification
        Ok(true) // Placeholder
    }
}

impl Default for SignatureContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash context for hash operations
pub struct HashContext {
    inner: Context<Self>,
}

impl HashContext {
    /// Create a new hash context
    pub fn new() -> Self {
        Self {
            inner: Context::new(),
        }
    }

    /// Hash data using the specified algorithm
    #[cfg(feature = "alloc")]
    pub fn hash(&mut self, algorithm: Algorithm, _data: &[u8]) -> Result<Vec<u8>> {
        if !self.inner.is_initialized() {
            self.inner.init()?;
        }

        // Validate algorithm category
        if algorithm.category() != AlgorithmCategory::Hash {
            return Err(crate::error::Error::InvalidAlgorithm {
                algorithm: format!("{algorithm:?} is not a hash algorithm"),
            });
        }

        // TODO: Implement actual hashing
        // This should delegate to the hash crate implementations
        let output_size = match algorithm {
            Algorithm::Shake128 => 16,
            Algorithm::Shake256 => 32,
            Algorithm::CShake128 => 16,
            Algorithm::CShake256 => 32,
            _ => 32, // Default size for other algorithms
        };

        Ok(vec![0u8; output_size])
    }

    #[cfg(not(feature = "alloc"))]
    pub fn hash(&mut self, algorithm: Algorithm, _data: &[u8]) -> Result<&'static [u8]> {
        if !self.inner.is_initialized() {
            self.inner.init()?;
        }

        // Validate algorithm category
        if algorithm.category() != AlgorithmCategory::Hash {
            return Err(crate::error::Error::InvalidAlgorithm {
                algorithm: "algorithm is not a hash algorithm",
            });
        }

        // TODO: Implement actual hashing
        static HASH_16: [u8; 16] = [0u8; 16];
        static HASH_32: [u8; 32] = [0u8; 32];

        match algorithm {
            Algorithm::Shake128 | Algorithm::CShake128 => Ok(&HASH_16),
            _ => Ok(&HASH_32),
        }
    }
}

impl Default for HashContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Utility functions that work consistently across platforms
pub struct Utils;

impl Utils {
    /// Generate cryptographically secure random bytes
    ///
    /// This function works in both std and no_std environments:
    /// - In std environments with the "rand" feature: Uses rand::thread_rng()
    /// - In no_std environments with the "getrandom" feature: Uses getrandom directly
    /// - In no_std environments without getrandom: Returns an error
    #[cfg(feature = "rand")]
    pub fn random_bytes(length: usize) -> Result<Vec<u8>> {
        if length == 0 {
            return Err(crate::error::Error::InvalidMessageSize { max: 0, actual: 0 });
        }

        const MAX_RANDOM_SIZE: usize = 1024 * 1024; // 1MB limit
        if length > MAX_RANDOM_SIZE {
            return Err(crate::error::Error::InvalidMessageSize {
                max: MAX_RANDOM_SIZE,
                actual: length,
            });
        }

        let mut bytes = vec![0u8; length];

        // Use rand for cryptographically secure random generation
        let mut rng = rand::rng();
        rng.fill_bytes(&mut bytes);

        Ok(bytes)
    }

    #[cfg(all(feature = "getrandom", not(feature = "rand")))]
    #[cfg(feature = "alloc")]
    pub fn random_bytes(length: usize) -> Result<Vec<u8>> {
        if length == 0 {
            return Err(crate::error::Error::InvalidMessageSize { max: 0, actual: 0 });
        }

        const MAX_RANDOM_SIZE: usize = 1024 * 1024; // 1MB limit
        if length > MAX_RANDOM_SIZE {
            return Err(crate::error::Error::InvalidMessageSize {
                max: MAX_RANDOM_SIZE,
                actual: length,
            });
        }

        let mut bytes = vec![0u8; length];

        // Use getrandom for no_std environments
        // Note: This requires the getrandom crate to be properly configured
        // for the target platform (e.g., wasm_js for WASM targets)
        getrandom::getrandom(&mut bytes).map_err(|_| {
            crate::error::Error::RandomGenerationFailed {
                operation: String::from("random_bytes"),
            }
        })?;

        Ok(bytes)
    }

    #[cfg(all(feature = "getrandom", not(feature = "rand")))]
    #[cfg(not(feature = "alloc"))]
    pub fn random_bytes(length: usize) -> Result<&'static [u8]> {
        if length == 0 {
            return Err(crate::error::Error::InvalidMessageSize { max: 0, actual: 0 });
        }

        const MAX_RANDOM_SIZE: usize = 1024; // Limit for no_std without alloc
        if length > MAX_RANDOM_SIZE {
            return Err(crate::error::Error::InvalidMessageSize {
                max: MAX_RANDOM_SIZE,
                actual: length,
            });
        }

        // For no_std without alloc, we need to handle platform-specific RNG
        // This provides a graceful fallback for platforms where getrandom is not available
        #[cfg(target_arch = "wasm32")]
        {
            // For WASM targets, getrandom might not be available
            return Err(crate::error::Error::RandomGenerationFailed {
                operation: "random_bytes",
            });
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            // For native targets, getrandom might not be available in this configuration
            // Note: This is a simplified approach - in production, you'd want proper platform detection
            return Err(crate::error::Error::RandomGenerationFailed {
                operation: "random_bytes",
            });
        }
    }

    #[cfg(not(any(feature = "rand", feature = "getrandom")))]
    #[cfg(feature = "alloc")]
    pub fn random_bytes(_length: usize) -> Result<Vec<u8>> {
        Err(crate::error::Error::RandomGenerationFailed {
            operation: String::from("random_bytes"),
        })
    }

    #[cfg(not(any(feature = "rand", feature = "getrandom")))]
    #[cfg(not(feature = "alloc"))]
    pub fn random_bytes(_length: usize) -> Result<&'static [u8]> {
        Err(crate::error::Error::RandomGenerationFailed {
            operation: "random_bytes",
        })
    }

    /// Convert bytes to hex string
    #[cfg(feature = "alloc")]
    pub fn bytes_to_hex(bytes: &[u8]) -> String {
        let mut hex = String::new();
        for &byte in bytes {
            hex.push_str(&format!("{:02x}", byte));
        }
        hex
    }

    #[cfg(not(feature = "alloc"))]
    pub fn bytes_to_hex(_bytes: &[u8]) -> &'static str {
        "hex conversion not available in no_std without alloc"
    }

    /// Convert hex string to bytes
    #[cfg(feature = "alloc")]
    pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
        let hex = hex.trim();

        if !hex.len().is_multiple_of(2) {
            return Err(crate::error::Error::InvalidMessageSize {
                max: 0,
                actual: hex.len(),
            });
        }

        let mut bytes = Vec::with_capacity(hex.len() / 2);
        for i in (0..hex.len()).step_by(2) {
            let byte = u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| crate::error::Error::InvalidMessageSize { max: 0, actual: i })?;
            bytes.push(byte);
        }

        Ok(bytes)
    }

    #[cfg(not(feature = "alloc"))]
    pub fn hex_to_bytes(_hex: &str) -> Result<&'static [u8]> {
        Err(crate::error::Error::MemoryAllocationFailed {
            operation: "hex_to_bytes",
        })
    }

    /// Constant-time comparison of two byte slices
    pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        let mut result = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            result |= x ^ y;
        }
        result == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_security_levels() {
        assert_eq!(Algorithm::MlKem512.security_level(), 1);
        assert_eq!(Algorithm::MlKem768.security_level(), 3);
        assert_eq!(Algorithm::MlKem1024.security_level(), 4);
        assert_eq!(Algorithm::Dilithium2.security_level(), 1);
        assert_eq!(Algorithm::Dilithium3.security_level(), 3);
        assert_eq!(Algorithm::Dilithium5.security_level(), 4);
    }

    #[test]
    fn test_algorithm_categories() {
        assert_eq!(Algorithm::MlKem512.category(), AlgorithmCategory::Kem);
        assert_eq!(
            Algorithm::Dilithium2.category(),
            AlgorithmCategory::Signature
        );
        assert_eq!(Algorithm::Shake256.category(), AlgorithmCategory::Hash);
    }

    #[test]
    fn test_kem_context() {
        let mut ctx = KemContext::new();
        let keypair = ctx.generate_keypair(Algorithm::MlKem512).unwrap();
        assert!(!keypair.public_key().as_bytes().is_empty());
        assert!(!keypair.secret_key().as_bytes().is_empty());
    }

    #[test]
    fn test_signature_context() {
        let mut ctx = SignatureContext::new();
        let keypair = ctx.generate_keypair(Algorithm::Dilithium2).unwrap();
        assert!(!keypair.public_key().as_bytes().is_empty());
        assert!(!keypair.secret_key().as_bytes().is_empty());
    }

    #[test]
    fn test_hash_context() {
        let mut ctx = HashContext::new();
        let hash = ctx.hash(Algorithm::Shake256, b"test").unwrap();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_utils() {
        #[cfg(feature = "getrandom")]
        {
            let bytes = Utils::random_bytes(32).unwrap();
            assert_eq!(bytes.len(), 32);
        }

        #[cfg(feature = "alloc")]
        {
            let hex = Utils::bytes_to_hex(&[0x01, 0x23, 0x45, 0x67]);
            assert_eq!(hex, "01234567");

            let decoded = Utils::hex_to_bytes(&hex).unwrap();
            assert_eq!(decoded, vec![0x01, 0x23, 0x45, 0x67]);
        }
    }

    #[test]
    fn test_random_bytes_generation() {
        // Test that random_bytes generates different values
        let bytes1 = Utils::random_bytes(32).expect("Should generate random bytes");
        let bytes2 = Utils::random_bytes(32).expect("Should generate random bytes");

        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);

        // Verify that we get different bytes on subsequent calls
        // (This test has a very small probability of failure, but it's acceptable for testing)
        assert_ne!(
            bytes1, bytes2,
            "Random bytes should be different on subsequent calls"
        );

        // Test that all bytes are not zero (very unlikely with proper RNG)
        let all_zero1 = bytes1.iter().all(|&b| b == 0);
        let all_zero2 = bytes2.iter().all(|&b| b == 0);

        assert!(!all_zero1, "Random bytes should not all be zero");
        assert!(!all_zero2, "Random bytes should not all be zero");
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(Utils::constant_time_compare(b"hello", b"hello"));
        assert!(!Utils::constant_time_compare(b"hello", b"world"));
        assert!(!Utils::constant_time_compare(b"hello", b"hell"));
    }
}
