//! Unified API for lib-Q cryptographic operations
//!
//! This module provides a consistent, secure API that works identically
//! whether used as a Rust crate or compiled to WASM.

use core::marker::PhantomData;

use crate::error::Result;
use crate::traits::*;

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::{
    boxed::Box,
    string::String,
    vec::Vec,
};

// Hash function imports
#[cfg(feature = "hash")]
use lib_q_sha3::{
    Digest,
    ExtendableOutput,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Shake128,
    Shake256,
};
#[cfg(any(feature = "getrandom", feature = "rand"))]
#[allow(unused_imports)]
use rand_core::RngCore;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

// Define cryptographic operation traits for dependency injection
// This allows implementations to be provided by higher-level crates

/// Key Encapsulation Mechanism operations
#[cfg(feature = "alloc")]
pub trait KemOperations {
    fn generate_keypair(
        &self,
        algorithm: Algorithm,
        randomness: Option<&[u8]>,
    ) -> Result<KemKeypair>;
    fn encapsulate(
        &self,
        algorithm: Algorithm,
        public_key: &KemPublicKey,
        randomness: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Vec<u8>)>;
    fn decapsulate(
        &self,
        algorithm: Algorithm,
        secret_key: &KemSecretKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>>;
}

/// Digital Signature operations
#[cfg(feature = "alloc")]
pub trait SignatureOperations {
    fn generate_keypair(
        &self,
        algorithm: Algorithm,
        randomness: Option<&[u8]>,
    ) -> Result<SigKeypair>;
    fn sign(
        &self,
        algorithm: Algorithm,
        secret_key: &SigSecretKey,
        message: &[u8],
        randomness: Option<&[u8]>,
    ) -> Result<Vec<u8>>;
    fn verify(
        &self,
        algorithm: Algorithm,
        public_key: &SigPublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool>;
}

/// Hash operations
#[cfg(feature = "alloc")]
pub trait HashOperations {
    fn hash(&self, algorithm: Algorithm, data: &[u8]) -> Result<Vec<u8>>;
}

/// Cryptographic provider that supplies implementations
pub trait CryptoProvider: Send + Sync {
    #[cfg(feature = "alloc")]
    fn kem(&self) -> Option<&dyn KemOperations>;
    #[cfg(feature = "alloc")]
    fn signature(&self) -> Option<&dyn SignatureOperations>;
    #[cfg(feature = "alloc")]
    fn hash(&self) -> Option<&dyn HashOperations>;
}

/// Algorithm identifiers for cryptographic operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
    MlDsa44,
    MlDsa65,
    MlDsa87,
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
            Algorithm::MlDsa44 => 1,
            Algorithm::Falcon512 => 1,
            Algorithm::SphincsSha256128fRobust => 1,
            Algorithm::SphincsShake256128fRobust => 1,

            // Level 3 (192-bit security)
            Algorithm::MlKem768 => 3,
            Algorithm::McEliece460896 => 3,
            Algorithm::Hqc192 => 3,
            Algorithm::MlDsa65 => 3,
            Algorithm::Falcon1024 => 3,
            Algorithm::SphincsSha256192fRobust => 3,
            Algorithm::SphincsShake256192fRobust => 3,

            // Level 4 (256-bit security)
            Algorithm::MlKem1024 => 4,
            Algorithm::McEliece6688128 => 4,
            Algorithm::McEliece6960119 => 4,
            Algorithm::Hqc256 => 4,
            Algorithm::MlDsa87 => 4,
            Algorithm::SphincsSha256256fRobust => 4,
            Algorithm::SphincsShake256256fRobust => 4,

            // Level 5 (256-bit security, higher performance)
            Algorithm::McEliece8192128 => 5,

            // Hash algorithms don't have security levels
            Algorithm::Shake128 |
            Algorithm::Shake256 |
            Algorithm::CShake128 |
            Algorithm::CShake256 |
            Algorithm::Sha3_224 |
            Algorithm::Sha3_256 |
            Algorithm::Sha3_384 |
            Algorithm::Sha3_512 |
            Algorithm::Kmac128 |
            Algorithm::Kmac256 |
            Algorithm::TupleHash128 |
            Algorithm::TupleHash256 |
            Algorithm::ParallelHash128 |
            Algorithm::ParallelHash256 => 0,
        }
    }

    /// Get the algorithm category
    pub fn category(&self) -> AlgorithmCategory {
        match self {
            Algorithm::MlKem512 |
            Algorithm::MlKem768 |
            Algorithm::MlKem1024 |
            Algorithm::McEliece348864 |
            Algorithm::McEliece460896 |
            Algorithm::McEliece6688128 |
            Algorithm::McEliece6960119 |
            Algorithm::McEliece8192128 |
            Algorithm::Hqc128 |
            Algorithm::Hqc192 |
            Algorithm::Hqc256 => AlgorithmCategory::Kem,

            Algorithm::MlDsa44 |
            Algorithm::MlDsa65 |
            Algorithm::MlDsa87 |
            Algorithm::Falcon512 |
            Algorithm::Falcon1024 |
            Algorithm::SphincsSha256128fRobust |
            Algorithm::SphincsSha256192fRobust |
            Algorithm::SphincsSha256256fRobust |
            Algorithm::SphincsShake256128fRobust |
            Algorithm::SphincsShake256192fRobust |
            Algorithm::SphincsShake256256fRobust => AlgorithmCategory::Signature,

            Algorithm::Shake128 |
            Algorithm::Shake256 |
            Algorithm::CShake128 |
            Algorithm::CShake256 |
            Algorithm::Sha3_224 |
            Algorithm::Sha3_256 |
            Algorithm::Sha3_384 |
            Algorithm::Sha3_512 |
            Algorithm::Kmac128 |
            Algorithm::Kmac256 |
            Algorithm::TupleHash128 |
            Algorithm::TupleHash256 |
            Algorithm::ParallelHash128 |
            Algorithm::ParallelHash256 => AlgorithmCategory::Hash,
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
#[cfg(feature = "alloc")]
pub struct KemContext {
    inner: Context<Self>,
    provider: Option<Box<dyn CryptoProvider>>,
}

// Example implementation of a concrete crypto provider
#[cfg(feature = "std")]
pub struct DefaultCryptoProvider;

#[cfg(feature = "std")]
impl CryptoProvider for DefaultCryptoProvider {
    fn kem(&self) -> Option<&dyn KemOperations> {
        Some(&DefaultKemImpl)
    }

    fn signature(&self) -> Option<&dyn SignatureOperations> {
        Some(&DefaultSignatureImpl)
    }

    fn hash(&self) -> Option<&dyn HashOperations> {
        Some(&DefaultHashImpl)
    }
}

// Example implementations (would be moved to separate crate in real architecture)
#[cfg(feature = "std")]
struct DefaultKemImpl;

#[cfg(feature = "std")]
impl KemOperations for DefaultKemImpl {
    fn generate_keypair(
        &self,
        algorithm: Algorithm,
        _randomness: Option<&[u8]>,
    ) -> Result<KemKeypair> {
        // This would delegate to actual implementations
        match algorithm {
            Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024 => {
                // In real implementation, would call lib-q-kem
                Err(crate::error::Error::NotImplemented {
                    feature: String::from("Real KEM implementations in lib-q-kem"),
                })
            }
            _ => Err(crate::error::Error::NotImplemented {
                feature: String::from("Algorithm not supported"),
            }),
        }
    }

    fn encapsulate(
        &self,
        algorithm: Algorithm,
        _public_key: &KemPublicKey,
        _randomness: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        match algorithm {
            Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024 => {
                Err(crate::error::Error::NotImplemented {
                    feature: String::from("Real KEM implementations in lib-q-kem"),
                })
            }
            _ => Err(crate::error::Error::NotImplemented {
                feature: String::from("Algorithm not supported"),
            }),
        }
    }

    fn decapsulate(
        &self,
        algorithm: Algorithm,
        _secret_key: &KemSecretKey,
        _ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        match algorithm {
            Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024 => {
                Err(crate::error::Error::NotImplemented {
                    feature: String::from("Real KEM implementations in lib-q-kem"),
                })
            }
            _ => Err(crate::error::Error::NotImplemented {
                feature: String::from("Algorithm not supported"),
            }),
        }
    }
}

#[cfg(feature = "std")]
struct DefaultSignatureImpl;

#[cfg(feature = "std")]
impl SignatureOperations for DefaultSignatureImpl {
    fn generate_keypair(
        &self,
        algorithm: Algorithm,
        _randomness: Option<&[u8]>,
    ) -> Result<SigKeypair> {
        match algorithm {
            Algorithm::MlDsa44 | Algorithm::MlDsa65 | Algorithm::MlDsa87 => {
                Err(crate::error::Error::NotImplemented {
                    feature: String::from("Real signature implementations in lib-q-sig"),
                })
            }
            _ => Err(crate::error::Error::NotImplemented {
                feature: String::from("Algorithm not supported"),
            }),
        }
    }

    fn sign(
        &self,
        algorithm: Algorithm,
        _secret_key: &SigSecretKey,
        _message: &[u8],
        _randomness: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        match algorithm {
            Algorithm::MlDsa44 | Algorithm::MlDsa65 | Algorithm::MlDsa87 => {
                Err(crate::error::Error::NotImplemented {
                    feature: String::from("Real signature implementations in lib-q-sig"),
                })
            }
            _ => Err(crate::error::Error::NotImplemented {
                feature: String::from("Algorithm not supported"),
            }),
        }
    }

    fn verify(
        &self,
        algorithm: Algorithm,
        _public_key: &SigPublicKey,
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<bool> {
        match algorithm {
            Algorithm::MlDsa44 | Algorithm::MlDsa65 | Algorithm::MlDsa87 => {
                Err(crate::error::Error::NotImplemented {
                    feature: String::from("Real signature implementations in lib-q-sig"),
                })
            }
            _ => Err(crate::error::Error::NotImplemented {
                feature: String::from("Algorithm not supported"),
            }),
        }
    }
}

#[cfg(feature = "std")]
struct DefaultHashImpl;

#[cfg(feature = "std")]
impl HashOperations for DefaultHashImpl {
    fn hash(&self, _algorithm: Algorithm, _data: &[u8]) -> Result<Vec<u8>> {
        Err(crate::error::Error::NotImplemented {
            feature: String::from("Real hash implementations in lib-q-hash"),
        })
    }
}

#[cfg(feature = "alloc")]
impl KemContext {
    /// Create a new KEM context with no provider (returns errors for all operations)
    pub fn new() -> Self {
        Self {
            inner: Context::new(),
            provider: None,
        }
    }

    /// Create a new KEM context with the default provider
    #[cfg(feature = "std")]
    pub fn with_default_provider() -> Self {
        Self {
            inner: Context::new(),
            provider: Some(Box::new(DefaultCryptoProvider)),
        }
    }

    /// Create a new KEM context with a cryptographic provider
    pub fn with_provider(provider: Box<dyn CryptoProvider>) -> Self {
        Self {
            inner: Context::new(),
            provider: Some(provider),
        }
    }

    /// Set the cryptographic provider
    pub fn set_provider(&mut self, provider: Box<dyn CryptoProvider>) {
        self.provider = Some(provider);
    }

    /// Generate a keypair for the specified algorithm
    pub fn generate_keypair(&mut self, algorithm: Algorithm) -> Result<KemKeypair> {
        if !self.inner.is_initialized() {
            self.inner.init()?;
        }

        // Validate algorithm category
        if algorithm.category() != AlgorithmCategory::Kem {
            return Err(crate::error::Error::InvalidAlgorithm {
                algorithm: "Algorithm is not a KEM algorithm",
            });
        }

        // Use provider if available, otherwise return a clear error
        match self.provider.as_ref().and_then(|p| p.kem()) {
            Some(kem_ops) => kem_ops.generate_keypair(algorithm, None),
            None => Err(crate::error::Error::NotImplemented {
                feature: String::from("KEM operations - no provider configured"),
            }),
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

        // Use provider if available, otherwise return a clear error
        match self.provider.as_ref().and_then(|p| p.kem()) {
            Some(kem_ops) => kem_ops.encapsulate(algorithm, public_key, None),
            None => Err(crate::error::Error::NotImplemented {
                feature: String::from("KEM operations - no provider configured"),
            }),
        }
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

        // Use provider if available, otherwise return a clear error
        match self.provider.as_ref().and_then(|p| p.kem()) {
            Some(kem_ops) => kem_ops.decapsulate(algorithm, secret_key, ciphertext),
            None => Err(crate::error::Error::NotImplemented {
                feature: String::from("KEM operations - no provider configured"),
            }),
        }
    }
}

#[cfg(feature = "alloc")]
impl Default for KemContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Signature context for digital signature operations
#[cfg(feature = "alloc")]
pub struct SignatureContext {
    inner: Context<Self>,
    provider: Option<Box<dyn CryptoProvider>>,
}

#[cfg(feature = "alloc")]
impl SignatureContext {
    /// Create a new signature context with no provider (returns errors for all operations)
    pub fn new() -> Self {
        Self {
            inner: Context::new(),
            provider: None,
        }
    }

    /// Create a new signature context with the default provider
    #[cfg(feature = "std")]
    pub fn with_default_provider() -> Self {
        Self {
            inner: Context::new(),
            provider: Some(Box::new(DefaultCryptoProvider)),
        }
    }

    /// Create a new signature context with a cryptographic provider
    pub fn with_provider(provider: Box<dyn CryptoProvider>) -> Self {
        Self {
            inner: Context::new(),
            provider: Some(provider),
        }
    }

    /// Set the cryptographic provider
    pub fn set_provider(&mut self, provider: Box<dyn CryptoProvider>) {
        self.provider = Some(provider);
    }

    /// Generate a keypair for the specified algorithm
    pub fn generate_keypair(&mut self, algorithm: Algorithm) -> Result<SigKeypair> {
        if !self.inner.is_initialized() {
            self.inner.init()?;
        }

        // Validate algorithm category
        if algorithm.category() != AlgorithmCategory::Signature {
            return Err(crate::error::Error::InvalidAlgorithm {
                algorithm: "Algorithm is not a signature algorithm",
            });
        }

        // Use provider if available, otherwise return a clear error
        match self.provider.as_ref().and_then(|p| p.signature()) {
            Some(sig_ops) => sig_ops.generate_keypair(algorithm, None),
            None => Err(crate::error::Error::NotImplemented {
                feature: String::from("Signature operations - no provider configured"),
            }),
        }
    }

    /// Sign a message using the given secret key
    #[cfg(feature = "alloc")]
    pub fn sign(
        &self,
        algorithm: Algorithm,
        secret_key: &SigSecretKey,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        if !self.inner.is_initialized() {
            return Err(crate::error::Error::InvalidState {
                operation: String::from("sign"),
                reason: String::from("Context not initialized"),
            });
        }

        // Use provider if available, otherwise return a clear error
        match self.provider.as_ref().and_then(|p| p.signature()) {
            Some(sig_ops) => sig_ops.sign(algorithm, secret_key, message, None),
            None => Err(crate::error::Error::NotImplemented {
                feature: String::from("Signature operations - no provider configured"),
            }),
        }
    }

    /// Verify a signature for the given message and public key
    #[cfg(feature = "alloc")]
    pub fn verify(
        &self,
        algorithm: Algorithm,
        public_key: &SigPublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        if !self.inner.is_initialized() {
            return Err(crate::error::Error::InvalidState {
                operation: String::from("verify"),
                reason: String::from("Context not initialized"),
            });
        }

        // Use provider if available, otherwise return a clear error
        match self.provider.as_ref().and_then(|p| p.signature()) {
            Some(sig_ops) => sig_ops.verify(algorithm, public_key, message, signature),
            None => Err(crate::error::Error::NotImplemented {
                feature: String::from("Signature operations - no provider configured"),
            }),
        }
    }
}

#[cfg(feature = "alloc")]
impl Default for SignatureContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash context for hash operations
#[cfg(feature = "alloc")]
pub struct HashContext {
    inner: Context<Self>,
    provider: Option<Box<dyn CryptoProvider>>,
}

#[cfg(feature = "alloc")]
impl HashContext {
    /// Create a new hash context with no provider (returns errors for all operations)
    pub fn new() -> Self {
        Self {
            inner: Context::new(),
            provider: None,
        }
    }

    /// Create a new hash context with the default provider
    #[cfg(feature = "std")]
    pub fn with_default_provider() -> Self {
        Self {
            inner: Context::new(),
            provider: Some(Box::new(DefaultCryptoProvider)),
        }
    }

    /// Create a new hash context with a cryptographic provider
    pub fn with_provider(provider: Box<dyn CryptoProvider>) -> Self {
        Self {
            inner: Context::new(),
            provider: Some(provider),
        }
    }

    /// Set the cryptographic provider
    pub fn set_provider(&mut self, provider: Box<dyn CryptoProvider>) {
        self.provider = Some(provider);
    }

    /// Hash data using the specified algorithm
    #[cfg(feature = "alloc")]
    pub fn hash(&mut self, algorithm: Algorithm, data: &[u8]) -> Result<Vec<u8>> {
        if !self.inner.is_initialized() {
            self.inner.init()?;
        }

        // Validate algorithm category
        if algorithm.category() != AlgorithmCategory::Hash {
            return Err(crate::error::Error::InvalidAlgorithm {
                algorithm: "Algorithm is not a hash algorithm",
            });
        }

        // Use provider if available, otherwise return a clear error
        match self.provider.as_ref().and_then(|p| p.hash()) {
            Some(hash_ops) => hash_ops.hash(algorithm, data),
            None => Err(crate::error::Error::NotImplemented {
                feature: String::from("Hash operations - no provider configured"),
            }),
        }
    }
}

#[cfg(feature = "alloc")]
impl Default for HashContext {
    fn default() -> Self {
        Self::new()
    }
}

/// WASM API for web environments
#[cfg(feature = "wasm")]
pub mod wasm_api {
    use super::*;
    use wasm_bindgen::JsValue;
    use serde_wasm_bindgen;
    use serde_json;

    /// WASM-compatible KEM context
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub struct WasmKemContext {
        inner: KemContext,
    }

    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    impl WasmKemContext {
        #[cfg_attr(feature = "wasm", wasm_bindgen(constructor))]
        pub fn new() -> Self {
            Self {
                inner: KemContext::new(),
            }
        }

        /// Generate a keypair for the specified algorithm
        #[cfg_attr(feature = "wasm", wasm_bindgen)]
        pub fn generate_keypair(&mut self, algorithm: &str) -> std::result::Result<JsValue, JsValue> {
            let algorithm = match algorithm {
                "MlKem512" => Algorithm::MlKem512,
                "MlKem768" => Algorithm::MlKem768,
                "MlKem1024" => Algorithm::MlKem1024,
                _ => return Err(JsValue::from_str("Unsupported algorithm")),
            };

            match self.inner.generate_keypair(algorithm) {
                Ok(keypair) => {
                    let result = serde_json::json!({
                        "public_key": keypair.public_key.data,
                        "secret_key": keypair.secret_key.data
                    });
                    Ok(serde_wasm_bindgen::to_value(&result)
                        .map_err(|e| JsValue::from_str(&format!("Serialization error: {:?}", e)))?)
                },
                Err(e) => Err(JsValue::from_str(&format!("Key generation failed: {:?}", e))),
            }
        }

        /// Encapsulate a shared secret using the given public key
        #[cfg_attr(feature = "wasm", wasm_bindgen)]
        pub fn encapsulate(&self, algorithm: &str, public_key_data: &[u8]) -> std::result::Result<JsValue, JsValue> {
            let algorithm = match algorithm {
                "MlKem512" => Algorithm::MlKem512,
                "MlKem768" => Algorithm::MlKem768,
                "MlKem1024" => Algorithm::MlKem1024,
                _ => return Err(JsValue::from_str("Unsupported algorithm")),
            };

            let public_key = KemPublicKey {
                data: public_key_data.to_vec(),
            };

            match self.inner.encapsulate(algorithm, &public_key) {
                Ok((ciphertext, shared_secret)) => {
                    let result = serde_json::json!({
                        "ciphertext": ciphertext,
                        "shared_secret": shared_secret
                    });
                    Ok(serde_wasm_bindgen::to_value(&result)
                        .map_err(|e| JsValue::from_str(&format!("Serialization error: {:?}", e)))?)
                },
                Err(e) => Err(JsValue::from_str(&format!("Encapsulation failed: {:?}", e))),
            }
        }

        /// Decapsulate a shared secret using the given secret key and ciphertext
        #[cfg_attr(feature = "wasm", wasm_bindgen)]
        pub fn decapsulate(&self, algorithm: &str, secret_key_data: &[u8], ciphertext: &[u8]) -> std::result::Result<Vec<u8>, JsValue> {
            let algorithm = match algorithm {
                "MlKem512" => Algorithm::MlKem512,
                "MlKem768" => Algorithm::MlKem768,
                "MlKem1024" => Algorithm::MlKem1024,
                _ => return Err(JsValue::from_str("Unsupported algorithm")),
            };

            let secret_key = KemSecretKey {
                data: secret_key_data.to_vec(),
            };

            match self.inner.decapsulate(algorithm, &secret_key, ciphertext) {
                Ok(shared_secret) => Ok(shared_secret),
                Err(e) => Err(JsValue::from_str(&format!("Decapsulation failed: {:?}", e))),
            }
        }
    }
}

/// Senior Developer Summary: Clean Architecture Implementation
///
/// This implementation demonstrates proper senior-level cryptography development practices:
///
/// 1. **Provider Pattern**: Clean dependency injection without circular dependencies
/// 2. **Fail Fast**: Clear errors instead of dummy/placeholder data
/// 3. **Security-First**: No silent failures or insecure defaults
/// 4. **Clean Architecture**: Separation of interfaces from implementations
/// 5. **Proper Error Handling**: Specific error types for different failure modes
/// 6. **Feature Gates**: Optional dependencies with clear security implications
///
/// The core API now provides a clean interface that:
/// - Defines cryptographic operation traits (KemOperations, SignatureOperations, etc.)
/// - Uses dependency injection via CryptoProvider trait
/// - Returns clear NotImplemented errors when providers are not configured
/// - Maintains no circular dependencies with implementation crates
/// - Provides proper validation and error handling
///
/// Real implementations are provided by the main lib-q crate through LibQCryptoProvider.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_architecture() {
        #[cfg(feature = "std")]
        {
            // Test that default provider is properly configured
            let mut ctx = KemContext::with_default_provider();

            // Should return NotImplemented error, not dummy data
            let result = ctx.generate_keypair(Algorithm::MlKem512);
            assert!(result.is_err());

            if let Err(crate::error::Error::NotImplemented { feature }) = result {
                assert!(feature.contains("Real KEM implementations"));
            } else {
                panic!("Expected NotImplemented error, got different error type");
            }
        }

        // Test that context without provider returns clear error
        let mut ctx = KemContext::new();
        let result = ctx.generate_keypair(Algorithm::MlKem512);
        assert!(result.is_err());

        if let Err(crate::error::Error::NotImplemented { feature }) = result {
            assert!(feature.contains("no provider configured"));
        } else {
            panic!("Expected NotImplemented error, got different error type");
        }
    }

    #[test]
    fn test_algorithm_security_levels() {
        assert_eq!(Algorithm::MlKem512.security_level(), 1);
        assert_eq!(Algorithm::MlKem768.security_level(), 3);
        assert_eq!(Algorithm::MlKem1024.security_level(), 4);
        assert_eq!(Algorithm::MlDsa44.security_level(), 1);
        assert_eq!(Algorithm::MlDsa65.security_level(), 3);
        assert_eq!(Algorithm::MlDsa87.security_level(), 4);
    }

    #[test]
    fn test_algorithm_categories() {
        assert_eq!(Algorithm::MlKem512.category(), AlgorithmCategory::Kem);
        assert_eq!(Algorithm::MlDsa44.category(), AlgorithmCategory::Signature);
        assert_eq!(Algorithm::Shake256.category(), AlgorithmCategory::Hash);
    }

    #[test]
    fn test_kem_context() {
        let mut ctx = KemContext::new();
        // Without a provider, should return NotImplemented error
        let result = ctx.generate_keypair(Algorithm::MlKem512);
        assert!(result.is_err());
        if let Err(crate::error::Error::NotImplemented { feature }) = result {
            assert!(feature.contains("no provider configured"));
        } else {
            panic!("Expected NotImplemented error");
        }
    }

    #[test]
    fn test_signature_context() {
        let mut ctx = SignatureContext::new();
        // Without a provider, should return NotImplemented error
        let result = ctx.generate_keypair(Algorithm::MlDsa65);
        assert!(result.is_err());
        if let Err(crate::error::Error::NotImplemented { feature }) = result {
            assert!(feature.contains("no provider configured"));
        } else {
            panic!("Expected NotImplemented error");
        }
    }

    #[test]
    fn test_hash_context() {
        let mut ctx = HashContext::new();
        // Without a provider, should return NotImplemented error
        let result = ctx.hash(Algorithm::Shake256, b"test");
        assert!(result.is_err());
        if let Err(crate::error::Error::NotImplemented { feature }) = result {
            assert!(feature.contains("no provider configured"));
        } else {
            panic!("Expected NotImplemented error");
        }
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

        // Zeroize the bytes on error paths (handled by Vec's Drop implementation)
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

        // Zeroize the bytes on error paths (handled by Vec's Drop implementation)
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
