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
// Re-export algorithm implementations
#[cfg(feature = "saturnin")]
pub use lib_q_saturnin::SaturninAead;

/// KEM-based AEAD construction
// pub mod kem_aead; // TODO: Implement
/// Get available AEAD algorithms
#[allow(clippy::vec_init_then_push)] // Can't use vec![] due to feature-gated content
pub fn available_algorithms() -> Vec<&'static str> {
    #[allow(unused_mut)] // mut is needed for algorithms.push() in feature-gated code
    let mut algorithms = Vec::new();

    #[cfg(feature = "saturnin")]
    algorithms.push("saturnin");

    // algorithms.push("kem-aead"); // TODO: Implement
    algorithms
}

/// Create an AEAD instance by algorithm name
pub fn create_aead(algorithm: &str) -> Result<Box<dyn Aead>> {
    match algorithm {
        #[cfg(feature = "saturnin")]
        "saturnin" => Ok(Box::new(SaturninAead::new())),
        // "kem-aead" => Ok(Box::new(kem_aead::KemAead::new())), // TODO: Implement
        _ => Err(lib_q_core::Error::InvalidAlgorithm {
            algorithm: "Unknown AEAD algorithm",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_available_algorithms() {
        let _algorithms = available_algorithms();
        // Should include saturnin if feature is enabled
        #[cfg(feature = "saturnin")]
        assert!(_algorithms.contains(&"saturnin"));
    }

    #[test]
    fn test_create_aead() {
        #[cfg(feature = "saturnin")]
        {
            let aead = create_aead("saturnin");
            assert!(aead.is_ok());
        }

        let invalid = create_aead("invalid");
        assert!(invalid.is_err());
    }
}
