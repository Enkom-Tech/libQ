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
pub use lib_q_types::{
    Algorithm,
    AlgorithmCategory,
    SecurityLevel,
};
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
use subtle::ConstantTimeEq;

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
/// - Returns [`ProviderNotConfigured`](crate::error::Error::ProviderNotConfigured) when no provider is set on a context
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
        // This provides a graceful fallback for platforms where getrandom is not available.
        // WASM builds should enable the root crate's `wasm` or `wasm_js` feature so that
        // lib-q-core/wasm_getrandom is enabled and getrandom works (this path is then avoided).
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
        a.ct_eq(b).into()
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

            // Stub core provider: NotImplemented if configured, or ProviderNotConfigured if init failed
            let result = ctx.generate_keypair(Algorithm::MlKem512, None);
            assert!(result.is_err());

            match result {
                Err(crate::error::Error::NotImplemented { feature }) => {
                    assert!(
                        feature.contains(
                            "ML-KEM implementations are provided by the main lib-q crate"
                        )
                    );
                }
                Err(crate::error::Error::ProviderNotConfigured { operation }) => {
                    assert_eq!(operation, "KEM");
                }
                _ => panic!("Expected NotImplemented or ProviderNotConfigured"),
            }
        }

        // Test that context without provider returns clear error
        #[cfg(feature = "alloc")]
        {
            let mut ctx = KemContext::new();
            let result = ctx.generate_keypair(Algorithm::MlKem512, None);
            assert!(result.is_err());

            if let Err(crate::error::Error::ProviderNotConfigured { operation }) = result {
                assert_eq!(operation, "KEM");
            } else {
                panic!("Expected ProviderNotConfigured error, got different error type");
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
        let result = ctx.generate_keypair(Algorithm::MlKem512, None);
        assert!(result.is_err());
        if let Err(crate::error::Error::ProviderNotConfigured { operation }) = result {
            assert_eq!(operation, "KEM");
        } else {
            panic!("Expected ProviderNotConfigured error");
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_signature_context() {
        let mut ctx = SignatureContext::new();
        let result = ctx.generate_keypair(Algorithm::MlDsa65, None);
        assert!(result.is_err());
        if let Err(crate::error::Error::ProviderNotConfigured { operation }) = result {
            assert_eq!(operation, "signature");
        } else {
            panic!("Expected ProviderNotConfigured error");
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_hash_context() {
        let mut ctx = HashContext::new();
        let result = ctx.hash(Algorithm::Shake256, b"test");
        assert!(result.is_err());
        if let Err(crate::error::Error::ProviderNotConfigured { operation }) = result {
            assert_eq!(operation, "hash");
        } else {
            panic!("Expected ProviderNotConfigured error");
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

        // Chi-square goodness-of-fit test for uniform byte distribution (χ² with ν=255).
        // Wilson-Hilferty approximation converts χ² to z; reject if z > 5 (false positive ~2.9e-7).
        let expected_per_byte = total_bytes as f64 / 256.0;
        let chi_sq: f64 = byte_counts
            .iter()
            .map(|&count| {
                let d = count as f64 - expected_per_byte;
                d * d / expected_per_byte
            })
            .sum();
        const NU: f64 = 255.0;
        let z =
            ((chi_sq / NU).powf(1.0 / 3.0) - (1.0 - 2.0 / (9.0 * NU))) / (2.0 / (9.0 * NU)).sqrt();
        assert!(
            z <= 5.0,
            "Random bytes show poor entropy distribution (chi-square z = {})",
            z
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
