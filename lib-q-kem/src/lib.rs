//! lib-Q KEM - Post-quantum Key Encapsulation Mechanisms
//!
//! This crate provides implementations of post-quantum key encapsulation mechanisms.

// Re-export core types for public use
pub use lib_q_core::{Kem, KemKeypair, KemPublicKey, KemSecretKey, Result};

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
pub fn available_algorithms() -> Vec<&'static str> {
    let mut algorithms = Vec::new();
    
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
        
        _ => Err(lib_q_core::Error::InvalidAlgorithm { algorithm: algorithm.to_string() }),
    }
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
    fn test_create_kem() {
        // Test with a valid algorithm if any features are enabled
        if !available_algorithms().is_empty() {
            let algorithm = available_algorithms()[0];
            assert!(create_kem(algorithm).is_ok());
        }
    }
}
