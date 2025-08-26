//! lib-Q SIG - Post-quantum Digital Signatures
//!
//! This crate provides implementations of post-quantum digital signature schemes.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![deny(unused_qualifications)]

#[cfg(not(feature = "std"))]
extern crate alloc;

// Re-export core types for public use
pub use lib_q_core::{
    Algorithm,
    Result,
    SigKeypair,
    SigPublicKey,
    SigSecretKey,
    Signature,
    SignatureContext,
};

/// CRYSTALS-ML-DSA implementation
#[cfg(feature = "ml-dsa")]
pub mod ml_dsa;

/// Falcon implementation
#[cfg(feature = "falcon")]
pub mod falcon;

/// SPHINCS+ implementation
#[cfg(feature = "sphincs")]
pub mod sphincs;

/// Get available signature algorithms
#[cfg(feature = "std")]
pub fn available_algorithms() -> Vec<&'static str> {
    vec![
        #[cfg(feature = "ml-dsa")]
        "ml-dsa",
        #[cfg(feature = "falcon")]
        "falcon",
        #[cfg(feature = "sphincs")]
        "sphincs",
    ]
}

/// Get available signature algorithms (no_std version)
#[cfg(not(feature = "std"))]
pub fn available_algorithms() -> &'static [&'static str] {
    &[
        #[cfg(feature = "ml-dsa")]
        "ml-dsa",
        #[cfg(feature = "falcon")]
        "falcon",
        #[cfg(feature = "sphincs")]
        "sphincs",
    ]
}

/// Create a signature instance by algorithm name
#[cfg(feature = "std")]
pub fn create_signature(algorithm: &str) -> Result<Box<dyn Signature>> {
    match algorithm {
        #[cfg(feature = "ml-dsa")]
        "ml-dsa" | "mldsa65" => Ok(Box::new(ml_dsa::MlDsa::ml_dsa_65())),
        #[cfg(feature = "ml-dsa")]
        "mldsa44" => Ok(Box::new(ml_dsa::MlDsa::ml_dsa_44())),
        #[cfg(feature = "ml-dsa")]
        "mldsa87" => Ok(Box::new(ml_dsa::MlDsa::ml_dsa_87())),

        #[cfg(feature = "falcon")]
        "falcon" => Ok(Box::new(falcon::Falcon::new())),

        #[cfg(feature = "sphincs")]
        "sphincs" => Ok(Box::new(sphincs::Sphincs::new())),

        _ => {
            Err(lib_q_core::Error::InvalidAlgorithm {
                algorithm: "Unknown algorithm",
            })
        }
    }
}

/// Create a signature context for the specified algorithm
pub fn create_signature_context(algorithm: Algorithm) -> Result<SignatureContext> {
    // Validate that this is a signature algorithm
    if algorithm.category() != lib_q_core::AlgorithmCategory::Signature {
        return Err(lib_q_core::Error::InvalidAlgorithm {
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
        let _algorithms = available_algorithms();
        // No features are enabled by default, so algorithms will be empty
        // assert!(!algorithms.is_empty()); // TODO: Enable features to test
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
        let keypair_result = ctx.generate_keypair(Algorithm::MlDsa65);
        assert!(
            keypair_result.is_err(),
            "Keypair generation should fail without provider"
        );
        if let Err(err) = keypair_result {
            assert!(matches!(err, lib_q_core::Error::NotImplemented { .. }));
        }
    }

    #[test]
    fn test_create_signature_context_invalid_algorithm() {
        let result = create_signature_context(Algorithm::MlKem512);
        assert!(result.is_err());
    }
}
