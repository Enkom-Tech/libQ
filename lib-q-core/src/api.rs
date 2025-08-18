//! Unified API for lib-Q cryptographic operations
//!
//! This module provides a consistent, secure API that works identically
//! whether used as a Rust crate or compiled to WASM.

use crate::{error::Result, traits::*};
use core::marker::PhantomData;
use rand::RngCore;

/// Algorithm identifiers for cryptographic operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    // KEM algorithms
    Kyber512,
    Kyber768,
    Kyber1024,
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
            Algorithm::Kyber512 => 1,
            Algorithm::McEliece348864 => 1,
            Algorithm::Hqc128 => 1,
            Algorithm::Dilithium2 => 1,
            Algorithm::Falcon512 => 1,
            Algorithm::SphincsSha256128fRobust => 1,
            Algorithm::SphincsShake256128fRobust => 1,

            // Level 3 (192-bit security)
            Algorithm::Kyber768 => 3,
            Algorithm::McEliece460896 => 3,
            Algorithm::Hqc192 => 3,
            Algorithm::Dilithium3 => 3,
            Algorithm::Falcon1024 => 3,
            Algorithm::SphincsSha256192fRobust => 3,
            Algorithm::SphincsShake256192fRobust => 3,

            // Level 4 (256-bit security)
            Algorithm::Kyber1024 => 4,
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
            Algorithm::Kyber512
            | Algorithm::Kyber768
            | Algorithm::Kyber1024
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
pub enum AlgorithmCategory {
    Kem,
    Signature,
    Hash,
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
            return Err(crate::error::Error::InvalidAlgorithm {
                algorithm: format!("{algorithm:?} is not a KEM algorithm"),
            });
        }

        // TODO: Implement actual key generation based on algorithm
        // For now, return placeholder
        let key_size = match algorithm {
            Algorithm::Kyber512 => 800,
            Algorithm::Kyber768 => 1184,
            Algorithm::Kyber1024 => 1568,
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

        let public_key = vec![0u8; key_size];
        let secret_key = vec![0u8; key_size];

        Ok(KemKeypair::new(public_key, secret_key))
    }

    /// Encapsulate a shared secret using the given public key
    pub fn encapsulate(
        &self,
        _algorithm: Algorithm,
        public_key: &KemPublicKey,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        if !self.inner.is_initialized() {
            return Err(crate::error::Error::InvalidState {
                operation: "encapsulate".to_string(),
                reason: "Context not initialized".to_string(),
            });
        }

        // TODO: Implement actual encapsulation
        let shared_secret = vec![0u8; 32];
        let ciphertext = vec![0u8; public_key.as_bytes().len()];

        Ok((shared_secret, ciphertext))
    }

    /// Decapsulate a shared secret using the given secret key and ciphertext
    pub fn decapsulate(
        &self,
        _algorithm: Algorithm,
        _secret_key: &KemSecretKey,
        _ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        if !self.inner.is_initialized() {
            return Err(crate::error::Error::InvalidState {
                operation: "decapsulate".to_string(),
                reason: "Context not initialized".to_string(),
            });
        }

        // TODO: Implement actual decapsulation
        Ok(vec![0u8; 32])
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
            return Err(crate::error::Error::InvalidAlgorithm {
                algorithm: format!("{algorithm:?} is not a signature algorithm"),
            });
        }

        // TODO: Implement actual key generation based on algorithm
        let key_size = match algorithm {
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

        let public_key = vec![0u8; key_size];
        let secret_key = vec![0u8; key_size];

        Ok(SigKeypair::new(public_key, secret_key))
    }

    /// Sign a message using the given secret key
    pub fn sign(
        &self,
        _algorithm: Algorithm,
        _secret_key: &SigSecretKey,
        _message: &[u8],
    ) -> Result<Vec<u8>> {
        if !self.inner.is_initialized() {
            return Err(crate::error::Error::InvalidState {
                operation: "sign".to_string(),
                reason: "Context not initialized".to_string(),
            });
        }

        // TODO: Implement actual signing
        let signature_size = match _algorithm {
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

    /// Verify a signature using the given public key
    pub fn verify(
        &self,
        _algorithm: Algorithm,
        _public_key: &SigPublicKey,
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<bool> {
        if !self.inner.is_initialized() {
            return Err(crate::error::Error::InvalidState {
                operation: "verify".to_string(),
                reason: "Context not initialized".to_string(),
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
        let mut rng = rand::rng();
        rng.fill_bytes(&mut bytes);
        Ok(bytes)
    }

    /// Convert bytes to hex string
    pub fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Convert hex string to bytes
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
        assert_eq!(Algorithm::Kyber512.security_level(), 1);
        assert_eq!(Algorithm::Kyber768.security_level(), 3);
        assert_eq!(Algorithm::Kyber1024.security_level(), 4);
        assert_eq!(Algorithm::Dilithium2.security_level(), 1);
        assert_eq!(Algorithm::Dilithium3.security_level(), 3);
        assert_eq!(Algorithm::Dilithium5.security_level(), 4);
    }

    #[test]
    fn test_algorithm_categories() {
        assert_eq!(Algorithm::Kyber512.category(), AlgorithmCategory::Kem);
        assert_eq!(
            Algorithm::Dilithium2.category(),
            AlgorithmCategory::Signature
        );
        assert_eq!(Algorithm::Shake256.category(), AlgorithmCategory::Hash);
    }

    #[test]
    fn test_kem_context() {
        let mut ctx = KemContext::new();
        let keypair = ctx.generate_keypair(Algorithm::Kyber512).unwrap();
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
        let bytes = Utils::random_bytes(32).unwrap();
        assert_eq!(bytes.len(), 32);

        let hex = Utils::bytes_to_hex(&[0x01, 0x23, 0x45, 0x67]);
        assert_eq!(hex, "01234567");

        let decoded = Utils::hex_to_bytes(&hex).unwrap();
        assert_eq!(decoded, vec![0x01, 0x23, 0x45, 0x67]);
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(Utils::constant_time_compare(b"hello", b"hello"));
        assert!(!Utils::constant_time_compare(b"hello", b"world"));
        assert!(!Utils::constant_time_compare(b"hello", b"hell"));
    }
}
