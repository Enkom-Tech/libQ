//! lib-Q Core - Common types and traits for post-quantum cryptography
//!
//! This crate provides the foundational types, traits, and error handling
//! used across all lib-Q crates.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![deny(unused_qualifications)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod algorithm_registry;
pub mod api;
pub mod error;
pub mod traits;
pub mod wasm_common;

// New modular architecture
#[cfg(feature = "alloc")]
pub mod contexts;
#[cfg(feature = "alloc")]
pub mod providers;
#[cfg(feature = "alloc")]
pub mod security;

// WASM bindings
#[cfg(feature = "wasm")]
pub mod wasm;

// Re-exports
pub use algorithm_registry::*;
pub use api::*;
#[cfg(feature = "alloc")]
pub use contexts::{
    AeadContext,
    HashContext,
    KemContext,
    SignatureContext,
};
pub use error::{
    Error,
    Result,
};
// Re-export new modular components
#[cfg(feature = "alloc")]
pub use providers::LibQCryptoProvider;
#[cfg(feature = "alloc")]
pub use security::SecurityValidator;
pub use traits::*;
#[cfg(feature = "wasm")]
pub use wasm::*;

// Constants
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize the core library
pub fn init() -> Result<()> {
    Ok(())
}

/// Get library version information
pub fn version() -> &'static str {
    VERSION
}

/// Create a new hash context
#[cfg(feature = "alloc")]
pub fn create_hash_context() -> HashContext {
    HashContext::new()
}

/// Create a new KEM context
#[cfg(feature = "alloc")]
pub fn create_kem_context() -> KemContext {
    KemContext::new()
}

/// Create a new signature context
#[cfg(feature = "alloc")]
pub fn create_signature_context() -> SignatureContext {
    SignatureContext::new()
}

/// Create a new AEAD context
#[cfg(feature = "alloc")]
pub fn create_aead_context() -> AeadContext {
    AeadContext::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        assert!(init().is_ok());
    }

    #[test]
    fn test_version() {
        assert!(!version().is_empty());
        assert_eq!(version(), VERSION);
    }

    #[test]
    fn test_no_std_compatibility() {
        #[cfg(not(feature = "std"))]
        use alloc::string::ToString;

        // Test that core functionality works in no_std mode
        let error = Error::InvalidKeySize {
            expected: 32,
            actual: 16,
        };
        assert_eq!(error.to_string(), "Invalid key size: expected 32, got 16");

        // Test that we can create basic structures
        #[cfg(feature = "alloc")]
        {
            let public_key = KemPublicKey::new(vec![1, 2, 3, 4]);
            assert_eq!(public_key.as_bytes(), &[1, 2, 3, 4]);

            let secret_key = KemSecretKey::new(vec![5, 6, 7, 8]);
            assert_eq!(secret_key.as_bytes(), &[5, 6, 7, 8]);
        }
    }
}
