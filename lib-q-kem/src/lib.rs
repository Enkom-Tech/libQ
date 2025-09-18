//! lib-Q KEM - Post-quantum Key Encapsulation Mechanisms
//!
//! This crate provides implementations of post-quantum key encapsulation mechanisms
//! following the lib-Q architecture with proper security validation and provider pattern integration.
//!
//! ## Architecture
//!
//! This implementation follows the lib-Q provider pattern:
//! - **Provider Pattern**: Implements `KemOperations` trait for integration with lib-q-core
//! - **Security Validation**: Comprehensive input validation and security checks
//! - **Algorithm Support**: Full support for NIST-approved KEM algorithms
//! - **Memory Safety**: Automatic zeroization of sensitive data
//! - **no_std Support**: Works in constrained environments
//!
//! ## Supported Algorithms
//!
//! - **ML-KEM**: CRYSTALS-ML-KEM (Levels 1, 3, 4)
//! - **DAWN**: DAWN KEM (Level 1) - Coming soon
//! - **RCPKC**: RCPKC KEM (Level 4) - Coming soon
//!
//! ## Feature Support
//!
//! All KEM algorithms support:
//! - **no_std**: Works in constrained environments with external randomness
//! - **WASM**: JavaScript-compatible bindings for web environments
//! - **Security validation**: Comprehensive input validation and security checks
//! - **Memory safety**: Automatic zeroization of sensitive data
//!
//! ## Usage
//!
//! ### With std (automatic randomness)
//! ```rust,ignore
//! use lib_q_core::{Algorithm, KemContext, create_kem_context};
//! use lib_q_kem::LibQKemProvider;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create KEM context with provider
//!     let mut ctx = create_kem_context();
//!     ctx.set_provider(Box::new(LibQKemProvider::new()?));
//!
//!     // Generate keypair (requires std feature for automatic randomness)
//!     let keypair = ctx.generate_keypair(Algorithm::MlKem512, None)?;
//!
//!     // Encapsulate shared secret
//!     let (ciphertext, shared_secret) = ctx.encapsulate(Algorithm::MlKem512, &keypair.public_key, None)?;
//!
//!     // Decapsulate shared secret
//!     let decapsulated_secret = ctx.decapsulate(Algorithm::MlKem512, &keypair.secret_key, &ciphertext)?;
//!     assert_eq!(shared_secret, decapsulated_secret);
//!     Ok(())
//! }
//! ```
//!
//! ### Without std (external randomness)
//! ```rust,ignore
//! use lib_q_core::{Algorithm, KemContext, create_kem_context};
//! use lib_q_kem::LibQKemProvider;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create KEM context with provider
//!     let mut ctx = create_kem_context();
//!     ctx.set_provider(Box::new(LibQKemProvider::new()?));
//!
//!     // Provide randomness externally (required in no_std environments)
//!     let key_randomness = [0u8; 32]; // Get from hardware RNG
//!
//!     // Generate keypair with external randomness
//!     let keypair = ctx.generate_keypair(Algorithm::MlKem512, Some(&key_randomness))?;
//!
//!     // Encapsulate shared secret
//!     let (ciphertext, shared_secret) = ctx.encapsulate(Algorithm::MlKem512, &keypair.public_key, None)?;
//!
//!     // Decapsulate shared secret
//!     let decapsulated_secret = ctx.decapsulate(Algorithm::MlKem512, &keypair.secret_key, &ciphertext)?;
//!     assert_eq!(shared_secret, decapsulated_secret);
//!     Ok(())
//! }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![deny(unused_qualifications)]

#[cfg(not(feature = "std"))]
extern crate alloc;

// Re-export core types for public use
pub use lib_q_core::{
    Algorithm,
    AlgorithmCategory,
    Error,
    Kem,
    KemContext,
    KemKeypair,
    KemOperations,
    KemPublicKey,
    KemSecretKey,
    Result,
};

// Provider implementation
pub mod provider;

// Algorithm implementations
#[cfg(feature = "ml-kem")]
pub mod ml_kem;

/// DAWN KEM implementation
#[cfg(feature = "dawn")]
pub use lib_q_dawn::DawnKem as DawnImpl;
/// RCPKC KEM implementation
#[cfg(feature = "rcpkc")]
pub use lib_q_rcpkc::RcpkcKem as RcpkcImpl;
// Re-export provider
#[cfg(feature = "alloc")]
pub use provider::LibQKemProvider;

/// Get available KEM algorithms with proper NIST naming
#[cfg(feature = "std")]
pub fn available_algorithms() -> Vec<&'static str> {
    let mut algorithms = Vec::new();

    #[cfg(feature = "ml-kem")]
    {
        algorithms.extend(["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]);
    }

    #[cfg(feature = "dawn")]
    {
        algorithms.extend(["DAWN"]);
    }

    #[cfg(feature = "rcpkc")]
    {
        algorithms.extend(["RCPKC"]);
    }

    algorithms
}

/// Get available KEM algorithms (no_std version)
#[cfg(not(feature = "std"))]
pub fn available_algorithms() -> &'static [&'static str] {
    &[
        #[cfg(feature = "ml-kem")]
        "ML-KEM-512",
        #[cfg(feature = "ml-kem")]
        "ML-KEM-768",
        #[cfg(feature = "ml-kem")]
        "ML-KEM-1024",
        #[cfg(feature = "dawn")]
        "DAWN",
        #[cfg(feature = "rcpkc")]
        "RCPKC",
    ]
}

/// Create a KEM instance by algorithm name (legacy compatibility)
#[cfg(feature = "std")]
pub fn create_kem(algorithm: &str) -> Result<Box<dyn Kem>> {
    match algorithm {
        #[cfg(feature = "ml-kem")]
        "ml-kem-512" | "ML-KEM-512" => Ok(Box::new(ml_kem::MlKem512Impl::default())),
        #[cfg(feature = "ml-kem")]
        "ml-kem-768" | "ML-KEM-768" => Ok(Box::new(ml_kem::MlKem768Impl::default())),
        #[cfg(feature = "ml-kem")]
        "ml-kem-1024" | "ML-KEM-1024" => Ok(Box::new(ml_kem::MlKem1024Impl::default())),

        #[cfg(feature = "dawn")]
        "dawn" | "DAWN" => Ok(Box::new(DawnImpl::default())),

        #[cfg(feature = "rcpkc")]
        "rcpkc" | "RCPKC" => Ok(Box::new(RcpkcImpl::default())),

        _ => Err(Error::InvalidAlgorithm {
            algorithm: "Unknown algorithm",
        }),
    }
}

/// Create a KEM context for the specified algorithm
pub fn create_kem_context(algorithm: Algorithm) -> Result<KemContext> {
    // Validate that this is a KEM algorithm
    if algorithm.category() != AlgorithmCategory::Kem {
        return Err(Error::InvalidAlgorithm {
            algorithm: "Algorithm is not a KEM algorithm",
        });
    }

    Ok(KemContext::new())
}

/// WASM-friendly wrapper for KEM operations
#[cfg(feature = "wasm")]
pub mod wasm {
    use alloc::string::ToString;
    use alloc::vec::Vec;

    use lib_q_core::{
        Algorithm,
        KemKeypair,
        KemPublicKey,
        KemSecretKey,
    };
    #[allow(unused_imports)]
    use wasm_bindgen::{
        JsError,
        prelude::*,
    };

    use super::*;

    /// Generate a keypair for the specified algorithm (WASM)
    #[wasm_bindgen]
    pub fn generate_keypair(algorithm: Algorithm) -> core::result::Result<KemKeypair, JsError> {
        let provider = LibQKemProvider::new().map_err(|e| JsError::new(&e.to_string()))?;
        provider
            .generate_keypair(algorithm, None)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Encapsulate a shared secret (WASM)
    #[wasm_bindgen]
    pub fn encapsulate(
        algorithm: Algorithm,
        public_key: &KemPublicKey,
    ) -> core::result::Result<EncapsulationResult, JsError> {
        let provider = LibQKemProvider::new().map_err(|e| JsError::new(&e.to_string()))?;
        let (ciphertext, shared_secret) = provider
            .encapsulate(algorithm, public_key, None)
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(EncapsulationResult::new(ciphertext, shared_secret))
    }

    /// Decapsulate a shared secret (WASM)
    #[wasm_bindgen]
    pub fn decapsulate(
        algorithm: Algorithm,
        secret_key: &KemSecretKey,
        ciphertext: &[u8],
    ) -> core::result::Result<Vec<u8>, JsError> {
        let provider = LibQKemProvider::new().map_err(|e| JsError::new(&e.to_string()))?;
        provider
            .decapsulate(algorithm, secret_key, ciphertext)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Result of encapsulation operation for WASM
    #[wasm_bindgen]
    pub struct EncapsulationResult {
        #[wasm_bindgen(skip)]
        ciphertext: Vec<u8>,
        #[wasm_bindgen(skip)]
        shared_secret: Vec<u8>,
    }

    #[wasm_bindgen]
    impl EncapsulationResult {
        #[wasm_bindgen(constructor)]
        pub fn new(ciphertext: Vec<u8>, shared_secret: Vec<u8>) -> Self {
            Self {
                ciphertext,
                shared_secret,
            }
        }

        #[wasm_bindgen(getter)]
        pub fn ciphertext(&self) -> Vec<u8> {
            self.ciphertext.clone()
        }

        #[wasm_bindgen(getter)]
        pub fn shared_secret(&self) -> Vec<u8> {
            self.shared_secret.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_available_algorithms() {
        let algorithms = available_algorithms();
        // Should have algorithms if features are enabled
        #[cfg(any(feature = "ml-kem", feature = "dawn", feature = "rcpkc"))]
        assert!(
            !algorithms.is_empty(),
            "Should have at least one algorithm when features are enabled"
        );
    }

    #[test]
    fn test_create_kem_context() {
        // Test that context creation works for valid KEM algorithms
        let result = create_kem_context(Algorithm::MlKem512);
        assert!(
            result.is_ok(),
            "Context creation should succeed for valid KEM algorithm"
        );

        // The context itself doesn't have providers - those are set up by the main lib-q crate
        // This test just verifies the basic context creation and structure
        let mut ctx = result.unwrap();

        // Without a provider, keypair generation should return NotImplemented
        let keypair_result = ctx.generate_keypair(Algorithm::MlKem512, None);
        assert!(
            keypair_result.is_err(),
            "Keypair generation should fail without provider"
        );
        if let Err(err) = keypair_result {
            assert!(matches!(err, Error::NotImplemented { .. }));
        }
    }

    #[test]
    fn test_create_kem_context_invalid_algorithm() {
        let result = create_kem_context(Algorithm::MlDsa65);
        assert!(result.is_err());
    }

    #[test]
    fn test_provider_creation() {
        let provider = LibQKemProvider::new();
        assert!(provider.is_ok(), "Provider should be created successfully");
    }

    #[test]
    fn test_provider_algorithm_support() {
        let provider = LibQKemProvider::new().unwrap();

        // Test ML-KEM algorithms
        #[cfg(feature = "ml-kem")]
        {
            let result = provider.generate_keypair(Algorithm::MlKem512, None);
            // Should either succeed or return NotImplemented (depending on feature flags)
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

        // Test unsupported algorithm
        let result = provider.generate_keypair(Algorithm::Sha3_256, None);
        assert!(result.is_err());
        if let Err(Error::InvalidAlgorithm { .. }) = result {
            // Expected error type
        } else {
            panic!("Expected InvalidAlgorithm error for non-KEM algorithm");
        }
    }

    #[test]
    fn test_algorithm_naming_consistency() {
        let algorithms = available_algorithms();

        // Check that algorithm names follow NIST conventions
        for algorithm in algorithms {
            assert!(
                algorithm.starts_with("ML-KEM-") ||
                    algorithm.starts_with("DAWN") ||
                    algorithm.starts_with("RCPKC"),
                "Algorithm name '{}' should follow NIST naming conventions",
                algorithm
            );
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_legacy_compatibility() {
        #[cfg(feature = "ml-kem")]
        {
            // Test legacy algorithm names still work
            let result = create_kem("ml-kem-512");
            assert!(result.is_ok(), "Legacy 'ml-kem-512' name should work");

            let result = create_kem("ML-KEM-512");
            assert!(result.is_ok(), "NIST 'ML-KEM-512' name should work");
        }
    }
}
