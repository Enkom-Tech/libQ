//! lib-Q KEM - Post-quantum Key Encapsulation Mechanisms
//!
//! This crate provides implementations of post-quantum key encapsulation mechanisms.

// Re-export core types for public use
pub use lib_q_core::{Algorithm, Kem, KemContext, KemKeypair, KemPublicKey, KemSecretKey, Result};

/// CRYSTALS-Kyber implementation
#[cfg(feature = "kyber")]
pub mod kyber;

/// Classic McEliece implementation
#[cfg(feature = "mceliece")]
pub mod mceliece;

/// HQC implementation
#[cfg(feature = "hqc")]
pub mod hqc;

/// Get available KEM algorithms
#[allow(clippy::vec_init_then_push)]
pub fn available_algorithms() -> Vec<&'static str> {
    let mut algorithms = vec![];

    #[cfg(feature = "kyber")]
    algorithms.push("kyber");

    #[cfg(feature = "mceliece")]
    algorithms.push("mceliece");

    #[cfg(feature = "hqc")]
    algorithms.push("hqc");

    algorithms
}

/// Create a KEM instance by algorithm name
pub fn create_kem(algorithm: &str) -> Result<Box<dyn Kem>> {
    match algorithm {
        #[cfg(feature = "kyber")]
        "kyber" => Ok(Box::new(kyber::Kyber::new())),

        #[cfg(feature = "mceliece")]
        "mceliece" => Ok(Box::new(mceliece::McEliece::new())),

        #[cfg(feature = "hqc")]
        "hqc" => Ok(Box::new(hqc::Hqc::new())),

        _ => Err(lib_q_core::Error::InvalidAlgorithm {
            algorithm: algorithm.to_string(),
        }),
    }
}

/// Create a KEM context for the specified algorithm
pub fn create_kem_context(algorithm: Algorithm) -> Result<KemContext> {
    // Validate that this is a KEM algorithm
    if algorithm.category() != lib_q_core::AlgorithmCategory::Kem {
        return Err(lib_q_core::Error::InvalidAlgorithm {
            algorithm: format!("{algorithm:?} is not a KEM algorithm"),
        });
    }

    Ok(KemContext::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_available_algorithms() {
        let algorithms = available_algorithms();
        assert!(!algorithms.is_empty());
    }

    #[test]
    fn test_create_kem_context() {
        let mut ctx = create_kem_context(Algorithm::Kyber512).unwrap();
        // Context is created successfully
        assert!(ctx.generate_keypair(Algorithm::Kyber512).is_ok());
    }

    #[test]
    fn test_create_kem_context_invalid_algorithm() {
        let result = create_kem_context(Algorithm::Dilithium2);
        assert!(result.is_err());
    }
}
