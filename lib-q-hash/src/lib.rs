//! lib-Q HASH - Post-quantum Hash Functions
//!
//! This crate provides implementations of post-quantum hash functions.

// Re-export core types for public use
pub use lib_q_core::{Algorithm, Hash, HashContext, Result};

/// SHAKE256 implementation
#[cfg(feature = "shake256")]
pub mod shake256;

/// SHAKE128 implementation
#[cfg(feature = "shake128")]
pub mod shake128;

/// cSHAKE256 implementation
#[cfg(feature = "cshake256")]
pub mod cshake256;

/// Hash algorithm types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHAKE256
    Shake256,
    /// SHAKE128
    Shake128,
    /// cSHAKE256
    CShake256,
}

impl HashAlgorithm {
    /// Get the output size for this algorithm
    pub fn output_size(&self) -> usize {
        match self {
            HashAlgorithm::Shake256 => 32,
            HashAlgorithm::Shake128 => 16,
            HashAlgorithm::CShake256 => 32,
        }
    }
}

/// Get available hash algorithms
#[allow(clippy::vec_init_then_push)]
pub fn available_algorithms() -> Vec<&'static str> {
    let mut algorithms = vec![];

    #[cfg(feature = "shake256")]
    algorithms.push("shake256");

    #[cfg(feature = "shake128")]
    algorithms.push("shake128");

    #[cfg(feature = "cshake256")]
    algorithms.push("cshake256");

    algorithms
}

/// Create a hash instance by algorithm name
pub fn create_hash(algorithm: &str) -> Result<Box<dyn Hash>> {
    match algorithm {
        #[cfg(feature = "shake256")]
        "shake256" => Ok(Box::new(shake256::Shake256::new())),

        #[cfg(feature = "shake128")]
        "shake128" => Ok(Box::new(shake128::Shake128::new())),

        #[cfg(feature = "cshake256")]
        "cshake256" => Ok(Box::new(cshake256::CShake256::new())),

        _ => Err(lib_q_core::Error::InvalidAlgorithm {
            algorithm: algorithm.to_string(),
        }),
    }
}

/// Create a hash context for the specified algorithm
pub fn create_hash_context(algorithm: Algorithm) -> Result<HashContext> {
    // Validate that this is a hash algorithm
    if algorithm.category() != lib_q_core::AlgorithmCategory::Hash {
        return Err(lib_q_core::Error::InvalidAlgorithm {
            algorithm: format!("{algorithm:?} is not a hash algorithm"),
        });
    }

    Ok(HashContext::new())
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
    fn test_hash_algorithm_output_sizes() {
        assert_eq!(HashAlgorithm::Shake256.output_size(), 32);
        assert_eq!(HashAlgorithm::Shake128.output_size(), 16);
        assert_eq!(HashAlgorithm::CShake256.output_size(), 32);
    }

    #[test]
    fn test_create_hash_context() {
        let mut ctx = create_hash_context(Algorithm::Shake256).unwrap();
        // Context is created successfully
        assert!(ctx.hash(Algorithm::Shake256, b"test").is_ok());
    }

    #[test]
    fn test_create_hash_context_invalid_algorithm() {
        let result = create_hash_context(Algorithm::Kyber512);
        assert!(result.is_err());
    }
}
