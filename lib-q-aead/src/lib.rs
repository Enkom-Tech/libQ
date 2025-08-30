//! lib-Q AEAD - Post-quantum Authenticated Encryption
//!
//! This crate provides implementations of post-quantum authenticated encryption.

// Re-export core types for public use
pub use lib_q_core::{
    Aead,
    AeadKey,
    Nonce,
    Result,
};

/// KEM-based AEAD construction
// pub mod kem_aead; // TODO: Implement
/// Get available AEAD algorithms
pub fn available_algorithms() -> Vec<&'static str> {
    // algorithms.push("kem-aead"); // TODO: Implement
    Vec::new()
}

/// Create an AEAD instance by algorithm name
pub fn create_aead(_algorithm: &str) -> Result<Box<dyn Aead>> {
    // "kem-aead" => Ok(Box::new(kem_aead::KemAead::new())), // TODO: Implement
    Err(lib_q_core::Error::InvalidAlgorithm {
        algorithm: "Unknown AEAD algorithm",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_available_algorithms() {
        let _algorithms = available_algorithms();
        // assert!(!algorithms.is_empty()); // TODO: Implement algorithms
    }

    #[test]
    fn test_create_aead() {
        // let algorithm = available_algorithms()[0]; // TODO: Implement algorithms
        // assert!(create_aead(algorithm).is_ok());
    }
}
