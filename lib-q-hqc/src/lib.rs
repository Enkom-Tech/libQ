//! lib-Q HQC - Post-quantum Hamming Quasi-Cyclic Key Encapsulation Mechanism
//!
//! This crate provides implementations of the HQC (Hamming Quasi-Cyclic) KEM
//! following the lib-Q architecture with proper security validation and provider pattern integration.
//!
//! ## Architecture
//!
//! This implementation follows the lib-Q provider pattern:
//! - **Provider Pattern**: Implements `KemOperations` trait for integration with lib-q-core
//! - **Security Validation**: Comprehensive input validation and security checks
//! - **Algorithm Support**: Full support for NIST-approved HQC algorithms
//! - **Memory Safety**: Automatic zeroization of sensitive data
//! - **no_std Support**: Works in constrained environments
//!
//! ## Supported Algorithms
//!
//! - **HQC-128**: Security Level 1 (128-bit security)
//! - **HQC-192**: Security Level 3 (192-bit security)  
//! - **HQC-256**: Security Level 5 (256-bit security)
//!
//! ## Feature Support
//!
//! All HQC algorithms support:
//! - **no_std**: Works in constrained environments with external randomness
//! - **WASM**: JavaScript-compatible bindings for web environments
//! - **Security validation**: Comprehensive input validation and security checks
//! - **Memory safety**: Automatic zeroization of sensitive data
//!
//! ## Usage
//!
//! ### With libQ Integration
//! ```rust,ignore
//! use lib_q_core::{Algorithm, KemContext, create_kem_context};
//! use lib_q_hqc::LibQHqcProvider;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create KEM context with HQC provider
//!     let mut ctx = create_kem_context();
//!     ctx.set_provider(Box::new(LibQHqcProvider::new()?));
//!
//!     // Generate keypair (requires std feature for automatic randomness)
//!     let keypair = ctx.generate_keypair(Algorithm::Hqc128, None)?;
//!
//!     // Encapsulate shared secret
//!     let (ciphertext, shared_secret) = ctx.encapsulate(Algorithm::Hqc128, &keypair.public_key, None)?;
//!
//!     // Decapsulate shared secret
//!     let decapsulated_secret = ctx.decapsulate(Algorithm::Hqc128, &keypair.secret_key, &ciphertext)?;
//!     assert_eq!(shared_secret, decapsulated_secret);
//!     Ok(())
//! }
//! ```
//!
//! ### Direct Usage (no_std compatible)
//! ```rust,ignore
//! use lib_q_hqc::{Hqc128, KemCore, Encapsulate, Decapsulate};
//! use lib_q_random::LibQRng;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create deterministic RNG for testing (use hardware RNG in production)
//!     let mut rng = LibQRng::new_deterministic(&[42u8; 32]);
//!
//!     // Generate keypair
//!     let (dk, ek) = Hqc128::generate(&mut rng);
//!
//!     // Encapsulate shared secret
//!     let (ct, k_send) = ek.encapsulate(&mut rng).unwrap();
//!
//!     // Decapsulate shared secret
//!     let k_recv = dk.decapsulate(&ct).unwrap();
//!     assert_eq!(k_send, k_recv);
//!     Ok(())
//! }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![deny(unused_qualifications)]

#[cfg(feature = "alloc")]
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

// Core modules - Correct Implementation
pub mod concatenated_code;
pub mod error;
pub mod field;
pub mod hqc_correct;
pub mod hqc_kem;
pub mod hqc_pke;
pub mod params_correct;
pub mod reed_muller;
pub mod reed_solomon;
pub mod shake256_prng;

// AES-CTR-DRBG for KAT compatibility
#[cfg(feature = "aes-drbg")]
pub mod aes_ctr_drbg;

// BearSSL AES-CTR-DRBG for exact KAT compatibility
#[cfg(feature = "bearssl-aes")]
pub mod bearssl_aes_ctr_drbg;

// Pure Rust BearSSL AES implementation
#[cfg(feature = "bearssl-aes")]
pub mod bearssl_aes_pure;

// Dual-mode DRBG diagnostics for interoperability testing
#[cfg(all(
    feature = "aes-drbg",
    feature = "bearssl-aes",
    feature = "debug-drbg-interop"
))]
pub mod drbg_diagnostic;

// Internal implementation details
pub mod internal;

// SIMD optimizations
pub mod simd;

// KAT-compatible PRNG for test compliance
pub mod kat_prng;

// Provider implementation
#[cfg(feature = "alloc")]
pub mod provider;

// Re-export main types - Correct Implementation
pub use error::HqcError;
pub use hqc_correct::*;
pub use params_correct::*;
// Re-export provider
#[cfg(feature = "alloc")]
pub use provider::LibQHqcProvider;

/// Get available HQC algorithms with proper NIST naming
#[cfg(feature = "std")]
pub fn available_algorithms() -> Vec<&'static str> {
    let mut algorithms = Vec::new();

    #[cfg(feature = "hqc128")]
    {
        algorithms.push("HQC-128");
    }

    #[cfg(feature = "hqc192")]
    {
        algorithms.push("HQC-192");
    }

    #[cfg(feature = "hqc256")]
    {
        algorithms.push("HQC-256");
    }

    algorithms
}

/// Get available HQC algorithms (no_std version)
#[cfg(not(feature = "std"))]
pub fn available_algorithms() -> &'static [&'static str] {
    &[
        #[cfg(feature = "hqc128")]
        "HQC-128",
        #[cfg(feature = "hqc192")]
        "HQC-192",
        #[cfg(feature = "hqc256")]
        "HQC-256",
    ]
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

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    #[test]
    fn test_available_algorithms() {
        let algorithms = available_algorithms();

        // Test that we get the expected algorithms based on enabled features
        #[cfg(feature = "hqc128")]
        {
            assert!(
                algorithms.contains(&"HQC-128"),
                "HQC-128 should be available when hqc128 feature is enabled"
            );
        }

        #[cfg(feature = "hqc192")]
        {
            assert!(
                algorithms.contains(&"HQC-192"),
                "HQC-192 should be available when hqc192 feature is enabled"
            );
        }

        #[cfg(feature = "hqc256")]
        {
            assert!(
                algorithms.contains(&"HQC-256"),
                "HQC-256 should be available when hqc256 feature is enabled"
            );
        }

        // Test that we have at least one algorithm when any features are enabled
        #[cfg(any(feature = "hqc128", feature = "hqc192", feature = "hqc256"))]
        assert!(
            !algorithms.is_empty(),
            "Should have at least one algorithm when features are enabled"
        );

        // Test that we have no algorithms when no features are enabled
        #[cfg(not(any(feature = "hqc128", feature = "hqc192", feature = "hqc256")))]
        assert!(
            algorithms.is_empty(),
            "Should have no algorithms when no features are enabled"
        );
    }

    #[test]
    fn test_create_kem_context() {
        // Test that context creation works for valid KEM algorithms
        let result = create_kem_context(Algorithm::Hqc128);
        assert!(
            result.is_ok(),
            "Context creation should succeed for valid KEM algorithm"
        );

        // The context itself doesn't have providers - those are set up by the main lib-q crate
        // This test just verifies the basic context creation and structure
        let mut ctx = result.unwrap();

        // Without a provider, keypair generation should return NotImplemented
        let keypair_result = ctx.generate_keypair(Algorithm::Hqc128, None);
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
    fn test_algorithm_naming_consistency() {
        let algorithms = available_algorithms();

        // Check that algorithm names follow NIST conventions
        for algorithm in algorithms {
            assert!(
                algorithm.starts_with("HQC-"),
                "Algorithm name '{}' should follow NIST naming conventions",
                algorithm
            );
        }
    }
}
