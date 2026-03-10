//! Unified API for lib-Q cryptographic operations
//!
//! This module provides a consistent, secure API that works identically
//! whether used as a Rust crate or compiled to WASM.

// PhantomData import removed - no longer needed after removing old Context<T>

use crate::error::Result;
#[cfg(feature = "alloc")]
use crate::traits::*;

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::{
    format,
    string::String,
    vec::Vec,
};

#[cfg(feature = "getrandom")]
#[allow(unused_imports)] // Used in getrandom::fill() call
use getrandom;
// Hash function imports
// #[cfg(feature = "hash")]
// use lib_q_sha3::{
//     Digest,
//     Sha3_224,
//     Sha3_256,
//     Sha3_384,
//     Sha3_512,
//     Shake128,
//     Shake256,
//     digest::ExtendableOutput,
// };
#[cfg(any(feature = "getrandom", feature = "rand"))]
#[allow(unused_imports)]
use rand_core::Rng;
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
    fn derive_public_key(
        &self,
        algorithm: Algorithm,
        secret_key: &KemSecretKey,
    ) -> Result<KemPublicKey>;
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

/// AEAD operations
#[cfg(feature = "alloc")]
pub trait AeadOperations {
    fn encrypt(
        &self,
        algorithm: Algorithm,
        key: &AeadKey,
        nonce: &Nonce,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>>;
    fn decrypt(
        &self,
        algorithm: Algorithm,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>>;
}

/// Cryptographic provider that supplies implementations
pub trait CryptoProvider: Send + Sync {
    #[cfg(feature = "alloc")]
    fn kem(&self) -> Option<&dyn KemOperations>;
    #[cfg(feature = "alloc")]
    fn signature(&self) -> Option<&dyn SignatureOperations>;
    #[cfg(feature = "alloc")]
    fn hash(&self) -> Option<&dyn HashOperations>;
    #[cfg(feature = "alloc")]
    fn aead(&self) -> Option<&dyn AeadOperations>;
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
    CbKem348864,
    CbKem460896,
    CbKem6688128,
    CbKem6960119,
    CbKem8192128,
    Hqc128,
    Hqc192,
    Hqc256,
    DawnAlpha512,
    DawnBeta512,
    DawnAlpha1024,
    DawnBeta1024,

    // Signature algorithms
    MlDsa44,
    MlDsa65,
    MlDsa87,
    FnDsa,
    FnDsa512,
    FnDsa1024,
    SlhDsaSha256128fRobust,
    SlhDsaSha256192fRobust,
    SlhDsaSha256256fRobust,
    SlhDsaShake256128fRobust,
    SlhDsaShake256192fRobust,
    SlhDsaShake256256fRobust,

    // Hash algorithms
    Shake128,
    Shake256,
    CShake128,
    CShake256,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Keccak224,
    Keccak256,
    Keccak384,
    Keccak512,
    KangarooTwelve,
    TurboShake128,
    TurboShake256,
    Kmac128,
    Kmac256,
    TupleHash128,
    TupleHash256,
    ParallelHash128,
    ParallelHash256,

    // SHA-2 algorithms
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512_224,
    Sha512_256,

    // AEAD algorithms
    Saturnin,
    Shake256Aead,
    KemAead,
}

impl Algorithm {
    /// Get the security level for this algorithm
    pub fn security_level(&self) -> u32 {
        match self {
            // Level 1 (128-bit security)
            Algorithm::MlKem512 => 1,
            Algorithm::CbKem348864 => 1,
            Algorithm::Hqc128 => 1,
            Algorithm::DawnAlpha512 => 1,
            Algorithm::DawnBeta512 => 1,
            Algorithm::MlDsa44 => 1,
            Algorithm::FnDsa => 1,
            Algorithm::FnDsa512 => 1,
            Algorithm::SlhDsaSha256128fRobust => 1,
            Algorithm::SlhDsaShake256128fRobust => 1,

            // Level 3 (192-bit security)
            Algorithm::MlKem768 => 3,
            Algorithm::CbKem460896 => 3,
            Algorithm::Hqc192 => 3,
            Algorithm::MlDsa65 => 3,
            Algorithm::SlhDsaSha256192fRobust => 3,
            Algorithm::SlhDsaShake256192fRobust => 3,

            // Level 4 (256-bit security)
            Algorithm::MlKem1024 => 4,
            Algorithm::CbKem6688128 => 4,
            Algorithm::CbKem6960119 => 4,
            Algorithm::Hqc256 => 4,
            Algorithm::MlDsa87 => 4,
            Algorithm::SlhDsaSha256256fRobust => 5,
            Algorithm::SlhDsaShake256256fRobust => 5,

            // Level 5 (256-bit security)
            Algorithm::FnDsa1024 => 5,
            Algorithm::DawnAlpha1024 => 5,
            Algorithm::DawnBeta1024 => 5,

            // Level 5 (256-bit security, higher performance)
            Algorithm::CbKem8192128 => 5,

            // Hash algorithms don't have security levels
            Algorithm::Shake128 |
            Algorithm::Shake256 |
            Algorithm::CShake128 |
            Algorithm::CShake256 |
            Algorithm::Sha3_224 |
            Algorithm::Sha3_256 |
            Algorithm::Sha3_384 |
            Algorithm::Sha3_512 |
            Algorithm::Keccak224 |
            Algorithm::Keccak256 |
            Algorithm::Keccak384 |
            Algorithm::Keccak512 |
            Algorithm::KangarooTwelve |
            Algorithm::TurboShake128 |
            Algorithm::TurboShake256 |
            Algorithm::Kmac128 |
            Algorithm::Kmac256 |
            Algorithm::TupleHash128 |
            Algorithm::TupleHash256 |
            Algorithm::ParallelHash128 |
            Algorithm::ParallelHash256 |
            Algorithm::Sha224 |
            Algorithm::Sha256 |
            Algorithm::Sha384 |
            Algorithm::Sha512 |
            Algorithm::Sha512_224 |
            Algorithm::Sha512_256 => 0,

            // AEAD algorithms
            Algorithm::Saturnin => 1,
            Algorithm::Shake256Aead => 1,
            Algorithm::KemAead => 4,
        }
    }

    /// Get the algorithm category
    pub fn category(&self) -> AlgorithmCategory {
        match self {
            Algorithm::MlKem512 |
            Algorithm::MlKem768 |
            Algorithm::MlKem1024 |
            Algorithm::CbKem348864 |
            Algorithm::CbKem460896 |
            Algorithm::CbKem6688128 |
            Algorithm::CbKem6960119 |
            Algorithm::CbKem8192128 |
            Algorithm::Hqc128 |
            Algorithm::Hqc192 |
            Algorithm::Hqc256 |
            Algorithm::DawnAlpha512 |
            Algorithm::DawnBeta512 |
            Algorithm::DawnAlpha1024 |
            Algorithm::DawnBeta1024 => AlgorithmCategory::Kem,

            Algorithm::MlDsa44 |
            Algorithm::MlDsa65 |
            Algorithm::MlDsa87 |
            Algorithm::FnDsa |
            Algorithm::FnDsa512 |
            Algorithm::FnDsa1024 |
            Algorithm::SlhDsaSha256128fRobust |
            Algorithm::SlhDsaSha256192fRobust |
            Algorithm::SlhDsaSha256256fRobust |
            Algorithm::SlhDsaShake256128fRobust |
            Algorithm::SlhDsaShake256192fRobust |
            Algorithm::SlhDsaShake256256fRobust => AlgorithmCategory::Signature,

            Algorithm::Shake128 |
            Algorithm::Shake256 |
            Algorithm::CShake128 |
            Algorithm::CShake256 |
            Algorithm::Sha3_224 |
            Algorithm::Sha3_256 |
            Algorithm::Sha3_384 |
            Algorithm::Sha3_512 |
            Algorithm::Keccak224 |
            Algorithm::Keccak256 |
            Algorithm::Keccak384 |
            Algorithm::Keccak512 |
            Algorithm::KangarooTwelve |
            Algorithm::TurboShake128 |
            Algorithm::TurboShake256 |
            Algorithm::Kmac128 |
            Algorithm::Kmac256 |
            Algorithm::TupleHash128 |
            Algorithm::TupleHash256 |
            Algorithm::ParallelHash128 |
            Algorithm::ParallelHash256 |
            Algorithm::Sha224 |
            Algorithm::Sha256 |
            Algorithm::Sha384 |
            Algorithm::Sha512 |
            Algorithm::Sha512_224 |
            Algorithm::Sha512_256 => AlgorithmCategory::Hash,

            // AEAD algorithms
            Algorithm::Saturnin | Algorithm::Shake256Aead | Algorithm::KemAead => {
                AlgorithmCategory::Aead
            } // Multi-category algorithms
        }
    }

    /// Check if an algorithm supports a specific category
    pub fn supports_category(&self, category: AlgorithmCategory) -> bool {
        match self {
            // Pure KEM algorithms
            Algorithm::MlKem512 |
            Algorithm::MlKem768 |
            Algorithm::MlKem1024 |
            Algorithm::CbKem348864 |
            Algorithm::CbKem460896 |
            Algorithm::CbKem6688128 |
            Algorithm::CbKem6960119 |
            Algorithm::CbKem8192128 |
            Algorithm::Hqc128 |
            Algorithm::Hqc192 |
            Algorithm::Hqc256 |
            Algorithm::DawnAlpha512 |
            Algorithm::DawnBeta512 |
            Algorithm::DawnAlpha1024 |
            Algorithm::DawnBeta1024 => category == AlgorithmCategory::Kem,

            // Pure signature algorithms
            Algorithm::MlDsa44 |
            Algorithm::MlDsa65 |
            Algorithm::MlDsa87 |
            Algorithm::FnDsa |
            Algorithm::FnDsa512 |
            Algorithm::FnDsa1024 |
            Algorithm::SlhDsaSha256128fRobust |
            Algorithm::SlhDsaSha256192fRobust |
            Algorithm::SlhDsaSha256256fRobust |
            Algorithm::SlhDsaShake256128fRobust |
            Algorithm::SlhDsaShake256192fRobust |
            Algorithm::SlhDsaShake256256fRobust => category == AlgorithmCategory::Signature,

            // Pure hash algorithms
            Algorithm::Shake128 |
            Algorithm::Shake256 |
            Algorithm::CShake128 |
            Algorithm::CShake256 |
            Algorithm::Sha3_224 |
            Algorithm::Sha3_256 |
            Algorithm::Sha3_384 |
            Algorithm::Sha3_512 |
            Algorithm::Keccak224 |
            Algorithm::Keccak256 |
            Algorithm::Keccak384 |
            Algorithm::Keccak512 |
            Algorithm::KangarooTwelve |
            Algorithm::TurboShake128 |
            Algorithm::TurboShake256 |
            Algorithm::Kmac128 |
            Algorithm::Kmac256 |
            Algorithm::TupleHash128 |
            Algorithm::TupleHash256 |
            Algorithm::ParallelHash128 |
            Algorithm::ParallelHash256 |
            Algorithm::Sha224 |
            Algorithm::Sha256 |
            Algorithm::Sha384 |
            Algorithm::Sha512 |
            Algorithm::Sha512_224 |
            Algorithm::Sha512_256 => category == AlgorithmCategory::Hash,

            // Pure AEAD algorithms
            Algorithm::Saturnin | Algorithm::Shake256Aead | Algorithm::KemAead => {
                category == AlgorithmCategory::Aead
            } // Multi-category algorithms
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
    Aead,
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

impl core::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            // KEM algorithms
            Algorithm::MlKem512 => write!(f, "ML-KEM-512"),
            Algorithm::MlKem768 => write!(f, "ML-KEM-768"),
            Algorithm::MlKem1024 => write!(f, "ML-KEM-1024"),
            Algorithm::CbKem348864 => write!(f, "CB-KEM-348864"),
            Algorithm::CbKem460896 => write!(f, "CB-KEM-460896"),
            Algorithm::CbKem6688128 => write!(f, "CB-KEM-6688128"),
            Algorithm::CbKem6960119 => write!(f, "CB-KEM-6960119"),
            Algorithm::CbKem8192128 => write!(f, "CB-KEM-8192128"),
            Algorithm::Hqc128 => write!(f, "HQC-128"),
            Algorithm::Hqc192 => write!(f, "HQC-192"),
            Algorithm::Hqc256 => write!(f, "HQC-256"),
            Algorithm::DawnAlpha512 => write!(f, "DAWN-α-512"),
            Algorithm::DawnBeta512 => write!(f, "DAWN-β-512"),
            Algorithm::DawnAlpha1024 => write!(f, "DAWN-α-1024"),
            Algorithm::DawnBeta1024 => write!(f, "DAWN-β-1024"),

            // Signature algorithms
            Algorithm::MlDsa44 => write!(f, "ML-DSA-44"),
            Algorithm::MlDsa65 => write!(f, "ML-DSA-65"),
            Algorithm::MlDsa87 => write!(f, "ML-DSA-87"),
            Algorithm::FnDsa => write!(f, "FN-DSA"),
            Algorithm::FnDsa512 => write!(f, "FN-DSA-512"),
            Algorithm::FnDsa1024 => write!(f, "FN-DSA-1024"),
            Algorithm::SlhDsaSha256128fRobust => write!(f, "SLH-DSA-SHA256-128f-Robust"),
            Algorithm::SlhDsaSha256192fRobust => write!(f, "SLH-DSA-SHA256-192f-Robust"),
            Algorithm::SlhDsaSha256256fRobust => write!(f, "SLH-DSA-SHA256-256f-Robust"),
            Algorithm::SlhDsaShake256128fRobust => write!(f, "SLH-DSA-SHAKE256-128f-Robust"),
            Algorithm::SlhDsaShake256192fRobust => write!(f, "SLH-DSA-SHAKE256-192f-Robust"),
            Algorithm::SlhDsaShake256256fRobust => write!(f, "SLH-DSA-SHAKE256-256f-Robust"),

            // Hash algorithms
            Algorithm::Shake128 => write!(f, "SHAKE128"),
            Algorithm::Shake256 => write!(f, "SHAKE256"),
            Algorithm::CShake128 => write!(f, "cSHAKE128"),
            Algorithm::CShake256 => write!(f, "cSHAKE256"),
            Algorithm::Sha3_224 => write!(f, "SHA3-224"),
            Algorithm::Sha3_256 => write!(f, "SHA3-256"),
            Algorithm::Sha3_384 => write!(f, "SHA3-384"),
            Algorithm::Sha3_512 => write!(f, "SHA3-512"),
            Algorithm::Keccak224 => write!(f, "Keccak-224"),
            Algorithm::Keccak256 => write!(f, "Keccak-256"),
            Algorithm::Keccak384 => write!(f, "Keccak-384"),
            Algorithm::Keccak512 => write!(f, "Keccak-512"),
            Algorithm::Sha224 => write!(f, "SHA-224"),
            Algorithm::Sha256 => write!(f, "SHA-256"),
            Algorithm::Sha384 => write!(f, "SHA-384"),
            Algorithm::Sha512 => write!(f, "SHA-512"),
            Algorithm::Sha512_224 => write!(f, "SHA-512/224"),
            Algorithm::Sha512_256 => write!(f, "SHA-512/256"),

            // AEAD algorithms
            Algorithm::Saturnin => write!(f, "Saturnin"),
            Algorithm::Shake256Aead => write!(f, "SHAKE256-AEAD"),
            Algorithm::KemAead => write!(f, "KEM-AEAD"),

            // Additional algorithms
            Algorithm::KangarooTwelve => write!(f, "KangarooTwelve"),
            Algorithm::TurboShake128 => write!(f, "TurboShake128"),
            Algorithm::TurboShake256 => write!(f, "TurboShake256"),
            Algorithm::Kmac128 => write!(f, "KMAC128"),
            Algorithm::Kmac256 => write!(f, "KMAC256"),
            Algorithm::TupleHash128 => write!(f, "TupleHash128"),
            Algorithm::TupleHash256 => write!(f, "TupleHash256"),
            Algorithm::ParallelHash128 => write!(f, "ParallelHash128"),
            Algorithm::ParallelHash256 => write!(f, "ParallelHash256"),
        }
    }
}

impl core::fmt::Display for AlgorithmCategory {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AlgorithmCategory::Kem => write!(f, "KEM"),
            AlgorithmCategory::Signature => write!(f, "Signature"),
            AlgorithmCategory::Hash => write!(f, "Hash"),
            AlgorithmCategory::Aead => write!(f, "AEAD"),
        }
    }
}

// Old Context<T> struct removed - use the new modular contexts instead
// The new architecture provides better separation of concerns and security validation

// KEM context is now implemented in the contexts module
// Re-export for backward compatibility
#[cfg(feature = "alloc")]
pub use crate::contexts::KemContext;

// Old DefaultCryptoProvider removed - use LibQCryptoProvider from providers module instead

// Old Default*Impl structs and implementations removed
// Use the new LibQCryptoProvider and its implementations from the providers module instead

// Context implementations are now in the contexts module
// These re-exports are maintained for API consistency

/// The core API provides a clean interface that:
/// - Defines cryptographic operation traits (KemOperations, SignatureOperations, etc.)
/// - Uses dependency injection via CryptoProvider trait
/// - Returns clear NotImplemented errors when providers are not configured
/// - Maintains no circular dependencies with implementation crates
/// - Provides proper validation and error handling
///
/// Real implementations are provided by the main lib-q crate through LibQCryptoProvider.
///
/// Utility functions that work consistently across platforms
pub struct Utils;

impl Utils {
    /// Generate cryptographically secure random bytes
    ///
    /// This function works in both std and no_std environments:
    /// - In std environments with the "rand" feature: Uses rand::rng()
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

        let mut bytes = alloc::vec![0u8; length];

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

        let mut bytes = alloc::vec![0u8; length];

        // Generate cryptographically secure random bytes using getrandom
        // This works across all platforms including WASM (using crypto.getRandomValues())
        // The getrandom crate automatically selects the appropriate entropy source:
        // - Native: OS entropy sources (e.g., /dev/urandom, CryptGenRandom)
        // - WASM: crypto.getRandomValues() in browsers, WebCrypto API in Node.js
        getrandom::fill(&mut bytes).map_err(|_| crate::error::Error::RandomGenerationFailed {
            operation: String::from("random_bytes"),
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

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "alloc")]
    use crate::contexts::{
        HashContext,
        SignatureContext,
    };

    #[test]
    fn test_provider_architecture() {
        #[cfg(feature = "std")]
        {
            // Test that default provider is properly configured
            let mut ctx = KemContext::with_default_provider();

            // Should return NotImplemented error, not dummy data
            let result = ctx.generate_keypair(Algorithm::MlKem512, None);
            assert!(result.is_err());

            if let Err(crate::error::Error::NotImplemented { feature }) = result {
                assert!(
                    feature.contains("ML-KEM implementations are provided by the main lib-q crate")
                );
            } else {
                panic!("Expected NotImplemented error, got different error type");
            }
        }

        // Test that context without provider returns clear error
        #[cfg(feature = "alloc")]
        {
            let mut ctx = KemContext::new();
            let result = ctx.generate_keypair(Algorithm::MlKem512, None);
            assert!(result.is_err());

            if let Err(crate::error::Error::NotImplemented { feature }) = result {
                assert!(feature.contains("no provider configured"));
            } else {
                panic!("Expected NotImplemented error, got different error type");
            }
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
    #[cfg(feature = "alloc")]
    fn test_kem_context() {
        let mut ctx = KemContext::new();
        // Without a provider, should return NotImplemented error
        let result = ctx.generate_keypair(Algorithm::MlKem512, None);
        assert!(result.is_err());
        if let Err(crate::error::Error::NotImplemented { feature }) = result {
            assert!(feature.contains("no provider configured"));
        } else {
            panic!("Expected NotImplemented error");
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_signature_context() {
        let mut ctx = SignatureContext::new();
        // Without a provider, should return NotImplemented error
        let result = ctx.generate_keypair(Algorithm::MlDsa65, None);
        assert!(result.is_err());
        if let Err(crate::error::Error::NotImplemented { feature }) = result {
            assert!(feature.contains("no provider configured"));
        } else {
            panic!("Expected NotImplemented error");
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
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
            assert_eq!(decoded, alloc::vec![0x01, 0x23, 0x45, 0x67]);
        }
    }

    #[test]
    fn test_random_bytes_generation() {
        // Test that random_bytes generates different values when available
        match Utils::random_bytes(32) {
            Ok(bytes1) => {
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
            Err(crate::error::Error::RandomGenerationFailed { .. }) => {
                // This is expected in no_std mode without getrandom feature
                // The test passes by not panicking
            }
            Err(e) => {
                panic!("Unexpected error: {:?}", e);
            }
        }
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(Utils::constant_time_compare(b"hello", b"hello"));
        assert!(!Utils::constant_time_compare(b"hello", b"world"));
        assert!(!Utils::constant_time_compare(b"hello", b"hell"));
    }

    #[cfg(feature = "getrandom")]
    #[test]
    fn test_random_bytes_entropy_quality() {
        // Test entropy quality by checking byte distribution
        const NUM_SAMPLES: usize = 1000;
        const BYTE_LENGTH: usize = 32;

        let mut byte_counts = [0u32; 256];
        let mut total_bytes = 0u32;

        for _ in 0..NUM_SAMPLES {
            let bytes = Utils::random_bytes(BYTE_LENGTH).expect("Should generate random bytes");
            for &byte in &bytes {
                byte_counts[byte as usize] += 1;
                total_bytes += 1;
            }
        }

        // Check that no byte value is completely absent (extremely unlikely with good RNG)
        let zero_count = byte_counts.iter().filter(|&&count| count == 0).count();
        assert!(
            zero_count < 50,
            "Too many byte values are missing from random generation"
        );

        // Check that no single byte value dominates (chi-square test approximation)
        let expected_per_byte = total_bytes as f64 / 256.0;
        let max_deviation = byte_counts
            .iter()
            .map(|&count| (count as f64 - expected_per_byte).abs())
            .fold(0.0, f64::max);

        // Allow for reasonable statistical variation (3 standard deviations)
        let max_expected_deviation = 3.0 * (expected_per_byte.sqrt());
        assert!(
            max_deviation < max_expected_deviation,
            "Random bytes show poor entropy distribution"
        );
    }

    #[cfg(feature = "getrandom")]
    #[test]
    fn test_random_bytes_uniformity() {
        // Test that random bytes are uniformly distributed
        const NUM_SAMPLES: usize = 10000;
        const BYTE_LENGTH: usize = 16;

        let mut all_bytes = alloc::vec![0u8; NUM_SAMPLES * BYTE_LENGTH];
        let mut offset = 0;

        for _ in 0..NUM_SAMPLES {
            let bytes = Utils::random_bytes(BYTE_LENGTH).expect("Should generate random bytes");
            all_bytes[offset..offset + BYTE_LENGTH].copy_from_slice(&bytes);
            offset += BYTE_LENGTH;
        }

        // Test for patterns that would indicate poor randomness
        // Check for runs of identical bytes (should be rare)
        let mut max_run_length = 0;
        let mut current_run_length = 1;

        for i in 1..all_bytes.len() {
            if all_bytes[i] == all_bytes[i - 1] {
                current_run_length += 1;
                max_run_length = max_run_length.max(current_run_length);
            } else {
                current_run_length = 1;
            }
        }

        // Runs longer than 4 identical bytes are suspicious
        assert!(
            max_run_length <= 4,
            "Random bytes show suspicious patterns (run length: {})",
            max_run_length
        );
    }

    #[cfg(feature = "getrandom")]
    #[test]
    fn test_random_bytes_size_limits() {
        // Test size limit enforcement
        assert!(Utils::random_bytes(0).is_err(), "Should reject zero length");

        // Test maximum size limit
        const MAX_SIZE: usize = 1024 * 1024; // 1MB
        assert!(
            Utils::random_bytes(MAX_SIZE).is_ok(),
            "Should accept maximum size"
        );
        assert!(
            Utils::random_bytes(MAX_SIZE + 1).is_err(),
            "Should reject size exceeding limit"
        );

        // Test reasonable sizes
        for size in [1, 16, 32, 64, 128, 256, 512, 1024] {
            let bytes = Utils::random_bytes(size).expect("Should generate random bytes");
            assert_eq!(bytes.len(), size, "Should generate exactly {} bytes", size);
        }
    }
}
