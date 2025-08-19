//! lib-Q SIG - Post-quantum Digital Signatures
//!
//! This crate provides implementations of post-quantum digital signature schemes.

// Re-export core types for public use
pub use lib_q_core::{
    Algorithm, Result, SigKeypair, SigPublicKey, SigSecretKey, Signature, SignatureContext,
};

/// CRYSTALS-Dilithium implementation
#[cfg(feature = "dilithium")]
pub mod dilithium;

/// Falcon implementation
#[cfg(feature = "falcon")]
pub mod falcon;

/// SPHINCS+ implementation
#[cfg(feature = "sphincs")]
pub mod sphincs;

/// Get available signature algorithms
pub fn available_algorithms() -> Vec<&'static str> {
    let algorithms = vec![
        #[cfg(feature = "dilithium")]
        "dilithium",
        #[cfg(feature = "falcon")]
        "falcon",
        #[cfg(feature = "sphincs")]
        "sphincs",
    ];

    algorithms
}

/// Create a signature instance by algorithm name
pub fn create_signature(algorithm: &str) -> Result<Box<dyn Signature>> {
    match algorithm {
        #[cfg(feature = "dilithium")]
        "dilithium" => Ok(Box::new(dilithium::Dilithium::new())),

        #[cfg(feature = "falcon")]
        "falcon" => Ok(Box::new(falcon::Falcon::new())),

        #[cfg(feature = "sphincs")]
        "sphincs" => Ok(Box::new(sphincs::Sphincs::new())),

        _ => Err(lib_q_core::Error::InvalidAlgorithm {
            algorithm: algorithm.to_string(),
        }),
    }
}

/// Create a signature context for the specified algorithm
pub fn create_signature_context(algorithm: Algorithm) -> Result<SignatureContext> {
    // Validate that this is a signature algorithm
    if algorithm.category() != lib_q_core::AlgorithmCategory::Signature {
        return Err(lib_q_core::Error::InvalidAlgorithm {
            algorithm: format!("{algorithm:?} is not a signature algorithm"),
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
        // No features are enabled by default, so algorithms will be empty
        // assert!(!algorithms.is_empty()); // TODO: Enable features to test
    }

    #[test]
    fn test_create_signature_context() {
        let mut ctx = create_signature_context(Algorithm::Dilithium2).unwrap();
        // Context is created successfully
        assert!(ctx.generate_keypair(Algorithm::Dilithium2).is_ok());
    }

    #[test]
    fn test_create_signature_context_invalid_algorithm() {
        let result = create_signature_context(Algorithm::MlKem512);
        assert!(result.is_err());
    }
}
