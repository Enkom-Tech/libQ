//! lib-Q Core - Common types and traits for post-quantum cryptography
//!
//! This crate provides the foundational types, traits, and error handling
//! used across all lib-Q crates.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod algorithm_registry;
pub mod api;
pub mod error;
pub mod traits;
pub mod wasm_common;

// Re-exports
pub use algorithm_registry::*;
pub use api::*;
pub use error::{Error, Result};
pub use traits::*;

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
        // Test that core functionality works in no_std mode
        let error = Error::InvalidKeySize {
            expected: 32,
            actual: 16,
        };
        assert_eq!(error.to_string(), "Invalid key size: expected 32, got 16");

        // Test that we can create basic structures
        let public_key = KemPublicKey::new(vec![1, 2, 3, 4]);
        assert_eq!(public_key.as_bytes(), &[1, 2, 3, 4]);

        let secret_key = KemSecretKey::new(vec![5, 6, 7, 8]);
        assert_eq!(secret_key.as_bytes(), &[5, 6, 7, 8]);
    }
}
