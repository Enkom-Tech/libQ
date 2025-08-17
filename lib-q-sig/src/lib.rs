//! lib-Q SIG - Post-quantum Digital Signatures
//!
//! This crate provides implementations of post-quantum digital signature schemes.

// Re-export core types for public use
pub use lib_q_core::{Signature, SigKeypair, SigPublicKey, SigSecretKey, Result};

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
    let mut algorithms = Vec::new();
    
    #[cfg(feature = "dilithium")]
    algorithms.push("dilithium");
    
    #[cfg(feature = "falcon")]
    algorithms.push("falcon");
    
    #[cfg(feature = "sphincs")]
    algorithms.push("sphincs");
    
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
    fn test_create_signature() {
        // Test with a valid algorithm if any features are enabled
        if !available_algorithms().is_empty() {
            let algorithm = available_algorithms()[0];
            assert!(create_signature(algorithm).is_ok());
        }
    }
}
