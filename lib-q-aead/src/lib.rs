//! lib-Q AEAD - Post-quantum Authenticated Encryption
//!
//! This crate provides implementations of post-quantum authenticated encryption.

// Re-export core types for public use
pub use lib_q_core::{Aead, AeadKey, Nonce, Result};

/// KEM-based AEAD construction
// pub mod kem_aead; // TODO: Implement

/// Get available AEAD algorithms
pub fn available_algorithms() -> Vec<&'static str> {
    let mut algorithms = Vec::new();
    // algorithms.push("kem-aead"); // TODO: Implement
    algorithms
}

/// Create an AEAD instance by algorithm name
pub fn create_aead(algorithm: &str) -> Result<Box<dyn Aead>> {
    match algorithm {
        // "kem-aead" => Ok(Box::new(kem_aead::KemAead::new())), // TODO: Implement
        _ => Err(lib_q_core::Error::InvalidAlgorithm { algorithm: algorithm.to_string() }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_available_algorithms() {
        let algorithms = available_algorithms();
        // assert!(!algorithms.is_empty()); // TODO: Implement algorithms
    }

    #[test]
    fn test_create_aead() {
        // let algorithm = available_algorithms()[0]; // TODO: Implement algorithms
        // assert!(create_aead(algorithm).is_ok());
    }
}
