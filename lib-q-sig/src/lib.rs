//! lib-Q SIG - Post-quantum Digital Signatures
//!
//! This crate provides implementations of post-quantum digital signature schemes
//! following the lib-Q architecture with proper security validation and provider pattern integration.
//!
//! ## Architecture
//!
//! This implementation follows the lib-Q provider pattern:
//! - **Provider Pattern**: Implements `SignatureOperations` trait for integration with lib-q-core
//! - **Security Validation**: Comprehensive input validation and security checks using `SecurityValidator`
//! - **Algorithm Support**: Full support for NIST-approved signature algorithms
//! - **Memory Safety**: Automatic zeroization of sensitive data with secure memory management
//! - **no_std Support**: Works in constrained environments with external randomness
//! - **Context Integration**: Seamless integration with `SignatureContext` for unified API
//!
//! ## Supported Algorithms
//!
//! - **ML-DSA**: CRYSTALS-ML-DSA (Levels 1, 3, 4)
//!   - ML-DSA-44: Level 1 security (128-bit)
//!   - ML-DSA-65: Level 3 security (192-bit)
//!   - ML-DSA-87: Level 4 security (256-bit)
//! - **FN-DSA**: FIPS 206 FN-DSA (Levels 1, 5)
//!   - FN-DSA: Level 1 security (128-bit)
//!   - FN-DSA-512: Level 1 security (128-bit)
//!   - FN-DSA-1024: Level 5 security (256-bit)
//! - **SLH-DSA**: SPHINCS+ (Levels 1, 3, 5)
//!   - SLH-DSA-SHA256-128f-Robust: Level 1 security (128-bit)
//!   - SLH-DSA-SHA256-192f-Robust: Level 3 security (192-bit)
//!   - SLH-DSA-SHA256-256f-Robust: Level 5 security (256-bit)
//!   - SLH-DSA-SHAKE256-128f-Robust: Level 1 security (128-bit)
//!   - SLH-DSA-SHAKE256-192f-Robust: Level 3 security (192-bit)
//!   - SLH-DSA-SHAKE256-256f-Robust: Level 5 security (256-bit)
//!
//! ## Feature Support
//!
//! All signature algorithms support:
//! - **no_std**: Works in constrained environments with external randomness
//! - **WASM**: JavaScript-compatible bindings for web environments
//! - **Security validation**: Comprehensive input validation and security checks
//! - **Memory safety**: Automatic zeroization of sensitive data
//! - **Provider integration**: Full integration with lib-q-core provider system
//!
//! ## Usage
//!
//! ### With std (automatic randomness)
//! ```rust,ignore
//! use lib_q_core::{Algorithm, SignatureContext, create_signature_context};
//! use lib_q_sig::LibQSignatureProvider;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create signature context with provider
//!     let mut ctx = create_signature_context();
//!     ctx.set_provider(Box::new(LibQSignatureProvider::new()?));
//!
//!     // Generate keypair (requires std feature for automatic randomness)
//!     let keypair = ctx.generate_keypair(Algorithm::MlDsa65, None)?;
//!
//!     // Sign message
//!     let message = b"Hello, lib-Q!";
//!     let signature = ctx.sign(Algorithm::MlDsa65, keypair.secret_key(), message, None)?;
//!
//!     // Verify signature
//!     let is_valid = ctx.verify(Algorithm::MlDsa65, keypair.public_key(), message, &signature)?;
//!     assert!(is_valid);
//!     Ok(())
//! }
//! ```
//!
//! ### Without std (external randomness)
//! ```rust,ignore
//! use lib_q_core::{Algorithm, SignatureContext, create_signature_context};
//! use lib_q_sig::LibQSignatureProvider;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create signature context with provider
//!     let mut ctx = create_signature_context();
//!     ctx.set_provider(Box::new(LibQSignatureProvider::new()?));
//!
//!     // Provide randomness externally (required in no_std environments)
//!     let key_randomness = [0u8; 32]; // Get from hardware RNG
//!     let signing_randomness = [0u8; 32]; // Get from hardware RNG
//!
//!     // Generate keypair with external randomness
//!     let keypair = ctx.generate_keypair(Algorithm::MlDsa65, Some(&key_randomness))?;
//!
//!     // Sign message with external randomness
//!     let message = b"Hello, lib-Q!";
//!     let signature = ctx.sign(Algorithm::MlDsa65, keypair.secret_key(), message, Some(&signing_randomness))?;
//!
//!     // Verify signature
//!     let is_valid = ctx.verify(Algorithm::MlDsa65, keypair.public_key(), message, &signature)?;
//!     assert!(is_valid);
//!     Ok(())
//! }
//! ```
//!
//! ### WASM (JavaScript) Environment
//! ```rust,ignore
//! use lib_q_sig::ml_dsa::MlDsa;
//! use js_sys::Uint8Array;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create ML-DSA instance
//!     let ml_dsa = MlDsa::ml_dsa_65();
//!
//!     // Generate keypair (with optional randomness)
//!     let keypair = ml_dsa.generate_keypair_wasm(None)?;
//!
//!     // Sign message
//!     let message = Uint8Array::from(b"Hello, WASM!");
//!     let signature = ml_dsa.sign_wasm(keypair.secret_key(), message, None)?;
//!
//!     // Verify signature
//!     let is_valid = ml_dsa.verify_wasm(keypair.public_key(), message, signature)?;
//!     assert!(is_valid);
//!     Ok(())
//! }
//! ```
//!
//! ## Provider Pattern Integration
//!
//! The `LibQSignatureProvider` implements the `SignatureOperations` trait and integrates
//! seamlessly with the lib-q-core provider system:
//!
//! ```rust,ignore
//! use lib_q_core::{Algorithm, SignatureContext, create_signature_context};
//! use lib_q_sig::LibQSignatureProvider;
//!
//! // Create provider and integrate with context
//! let provider = LibQSignatureProvider::new()?;
//! let mut ctx = create_signature_context();
//! ctx.set_provider(Box::new(provider));
//!
//! // All operations go through the provider with security validation
//! let keypair = ctx.generate_keypair(Algorithm::MlDsa65, None)?;
//! let signature = ctx.sign(Algorithm::MlDsa65, keypair.secret_key(), b"message", None)?;
//! let is_valid = ctx.verify(Algorithm::MlDsa65, keypair.public_key(), b"message", &signature)?;
//! ```
//!
//! ## Security Features
//!
//! The implementation includes comprehensive security measures:
//!
//! - **Input Validation**: All inputs are validated for correctness and security
//! - **Memory Safety**: Sensitive data is automatically zeroized after use
//! - **Algorithm Validation**: Only NIST-approved algorithms are supported
//! - **Key Size Validation**: Keys are validated against expected sizes for each algorithm
//! - **Randomness Validation**: Randomness inputs are validated for quality and size
//! - **Error Handling**: Secure error messages that don't leak sensitive information
//!
//! ## Feature Flags
//!
//! - `ml-dsa`: Enable ML-DSA signature algorithms
//! - `fn-dsa`: Enable FN-DSA signature algorithms  
//! - `slh-dsa`: Enable SLH-DSA signature algorithms
//! - `std`: Enable standard library features (automatic randomness generation)
//! - `alloc`: Enable heap allocation (required for most operations)
//! - `wasm`: Enable WebAssembly bindings for JavaScript environments

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
    Result,
    SigKeypair,
    SigPublicKey,
    SigSecretKey,
    Signature,
    SignatureContext,
    SignatureOperations,
};

// Provider implementation
pub mod provider;

// Algorithm implementations
#[cfg(feature = "ml-dsa")]
pub mod ml_dsa;

#[cfg(feature = "fn-dsa")]
pub mod fn_dsa;

#[cfg(feature = "slh-dsa")]
pub mod slh_dsa;

// Re-export provider
#[cfg(feature = "alloc")]
pub use provider::LibQSignatureProvider;

/// Get available signature algorithms with proper NIST naming
#[cfg(feature = "std")]
pub fn available_algorithms() -> Vec<&'static str> {
    let mut algorithms = Vec::new();

    #[cfg(feature = "ml-dsa")]
    {
        algorithms.extend(["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]);
    }

    #[cfg(feature = "fn-dsa")]
    {
        algorithms.extend(["FN-DSA", "FN-DSA-512", "FN-DSA-1024"]);
    }

    #[cfg(feature = "slh-dsa")]
    {
        algorithms.extend([
            "SLH-DSA-SHA256-128f-Robust",
            "SLH-DSA-SHA256-192f-Robust",
            "SLH-DSA-SHA256-256f-Robust",
            "SLH-DSA-SHAKE256-128f-Robust",
            "SLH-DSA-SHAKE256-192f-Robust",
            "SLH-DSA-SHAKE256-256f-Robust",
        ]);
    }

    algorithms
}

/// Get available signature algorithms (no_std version)
#[cfg(not(feature = "std"))]
pub fn available_algorithms() -> &'static [&'static str] {
    &[
        #[cfg(feature = "ml-dsa")]
        "ML-DSA-44",
        #[cfg(feature = "ml-dsa")]
        "ML-DSA-65",
        #[cfg(feature = "ml-dsa")]
        "ML-DSA-87",
        #[cfg(feature = "fn-dsa")]
        "FN-DSA",
        #[cfg(feature = "fn-dsa")]
        "FN-DSA-512",
        #[cfg(feature = "fn-dsa")]
        "FN-DSA-1024",
        #[cfg(feature = "slh-dsa")]
        "SLH-DSA-SHA256-128f-Robust",
        #[cfg(feature = "slh-dsa")]
        "SLH-DSA-SHA256-192f-Robust",
        #[cfg(feature = "slh-dsa")]
        "SLH-DSA-SHA256-256f-Robust",
        #[cfg(feature = "slh-dsa")]
        "SLH-DSA-SHAKE256-128f-Robust",
        #[cfg(feature = "slh-dsa")]
        "SLH-DSA-SHAKE256-192f-Robust",
        #[cfg(feature = "slh-dsa")]
        "SLH-DSA-SHAKE256-256f-Robust",
    ]
}

/// Create a signature instance by algorithm name (legacy compatibility)
#[cfg(feature = "std")]
pub fn create_signature(algorithm: &str) -> Result<Box<dyn Signature>> {
    match algorithm {
        #[cfg(feature = "ml-dsa")]
        "ml-dsa" | "mldsa65" | "ML-DSA-65" => Ok(Box::new(ml_dsa::MlDsa::ml_dsa_65())),
        #[cfg(feature = "ml-dsa")]
        "mldsa44" | "ML-DSA-44" => Ok(Box::new(ml_dsa::MlDsa::ml_dsa_44())),
        #[cfg(feature = "ml-dsa")]
        "mldsa87" | "ML-DSA-87" => Ok(Box::new(ml_dsa::MlDsa::ml_dsa_87())),

        #[cfg(feature = "fn-dsa")]
        "fn-dsa" | "FN-DSA" => Ok(Box::new(fn_dsa::FnDsa::level1())),
        #[cfg(feature = "fn-dsa")]
        "fn-dsa-512" | "FN-DSA-512" => Ok(Box::new(fn_dsa::FnDsa512::new())),
        #[cfg(feature = "fn-dsa")]
        "fn-dsa-1024" | "FN-DSA-1024" => Ok(Box::new(fn_dsa::FnDsa1024::new())),

        #[cfg(feature = "slh-dsa")]
        "slh-dsa" | "SLH-DSA-SHA256-128f-Robust" => Ok(Box::new(slh_dsa::SlhDsa::new())),

        _ => Err(Error::InvalidAlgorithm {
            algorithm: "Unknown algorithm",
        }),
    }
}

/// Create a signature context for the specified algorithm
pub fn create_signature_context(algorithm: Algorithm) -> Result<SignatureContext> {
    // Validate that this is a signature algorithm
    if algorithm.category() != AlgorithmCategory::Signature {
        return Err(Error::InvalidAlgorithm {
            algorithm: "Algorithm is not a signature algorithm",
        });
    }

    Ok(SignatureContext::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_available_algorithms() {
        let algorithms = available_algorithms();
        // Should have algorithms if features are enabled
        #[cfg(any(feature = "ml-dsa", feature = "fn-dsa", feature = "slh-dsa"))]
        assert!(
            !algorithms.is_empty(),
            "Should have at least one algorithm when features are enabled"
        );
    }

    #[test]
    fn test_create_signature_context() {
        // Test that context creation works for valid signature algorithms
        let result = create_signature_context(Algorithm::MlDsa65);
        assert!(
            result.is_ok(),
            "Context creation should succeed for valid signature algorithm"
        );

        // The context itself doesn't have providers - those are set up by the main lib-q crate
        // This test just verifies the basic context creation and structure
        let mut ctx = result.unwrap();

        // Without a provider, keypair generation should return NotImplemented
        let keypair_result = ctx.generate_keypair(Algorithm::MlDsa65, None);
        assert!(
            keypair_result.is_err(),
            "Keypair generation should fail without provider"
        );
        if let Err(err) = keypair_result {
            assert!(matches!(err, Error::NotImplemented { .. }));
        }
    }

    #[test]
    fn test_create_signature_context_invalid_algorithm() {
        let result = create_signature_context(Algorithm::MlKem512);
        assert!(result.is_err());
    }

    #[test]
    fn test_provider_creation() {
        let provider = LibQSignatureProvider::new();
        assert!(provider.is_ok(), "Provider should be created successfully");
    }

    #[test]
    fn test_provider_algorithm_support() {
        let provider = LibQSignatureProvider::new().unwrap();

        // Test ML-DSA algorithms
        #[cfg(feature = "ml-dsa")]
        {
            let result = provider.generate_keypair(Algorithm::MlDsa65, None);
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
            panic!("Expected InvalidAlgorithm error for non-signature algorithm");
        }
    }

    #[test]
    fn test_algorithm_naming_consistency() {
        let algorithms = available_algorithms();

        // Check that algorithm names follow NIST conventions
        for algorithm in algorithms {
            assert!(
                algorithm.starts_with("ML-DSA-") ||
                    algorithm.starts_with("FN-DSA") ||
                    algorithm.starts_with("SLH-DSA-"),
                "Algorithm name '{}' should follow NIST naming conventions",
                algorithm
            );
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_legacy_compatibility() {
        #[cfg(feature = "ml-dsa")]
        {
            // Test legacy algorithm names still work
            let result = create_signature("ml-dsa");
            assert!(result.is_ok(), "Legacy 'ml-dsa' name should work");

            let result = create_signature("mldsa65");
            assert!(result.is_ok(), "Legacy 'mldsa65' name should work");

            // Test new NIST names work
            let result = create_signature("ML-DSA-65");
            assert!(result.is_ok(), "NIST 'ML-DSA-65' name should work");
        }
    }
}
