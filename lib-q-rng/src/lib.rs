//! # lib-q-rng: Secure Random Number Generation for libQ
//!
//! This crate provides a comprehensive, secure random number generation system
//! designed specifically for post-quantum cryptography applications in the libQ ecosystem.
//!
//! ## Features
//!
//! - **Cryptographically Secure**: Uses OS entropy sources and hardware RNGs when available
//! - **Multiple Providers**: Support for OS, deterministic, and hardware entropy sources
//! - **Entropy Validation**: Comprehensive entropy quality assessment and validation
//! - **no_std Support**: Works in constrained environments without standard library
//! - **WASM Compatible**: Full support for WebAssembly and browser environments
//! - **Zero-Copy**: Efficient memory usage with minimal allocations
//! - **Thread-Safe**: Safe for use in multi-threaded environments
//! - **Extensible**: Plugin architecture for custom entropy sources
//!
//! ## Quick Start
//!
//! ```rust
//! use lib_q_rng::{
//!     EntropySource,
//!     LibQRng,
//!     RngProvider,
//! };
//! use rand_core::RngCore;
//!
//! // Create a secure RNG for production use
//! let mut rng = LibQRng::new_secure().unwrap();
//!
//! // Generate random bytes
//! let mut bytes = [0u8; 32];
//! rng.fill_bytes(&mut bytes);
//!
//! // Create a deterministic RNG for testing
//! let mut test_rng = LibQRng::new_deterministic(&[1, 2, 3, 4]);
//! ```
//!
//! ## Architecture
//!
//! The crate is organized into several key components:
//!
//! - **Core Traits**: Define the interface for RNG providers and entropy sources
//! - **Providers**: Implement different RNG strategies (OS, deterministic, hardware)
//! - **Validation**: Entropy quality assessment and security validation
//! - **Factory**: RNG creation and configuration management
//!
//! ## Security Considerations
//!
//! - All RNGs are cryptographically secure by default
//! - Entropy validation ensures sufficient randomness
//! - Secure memory clearing prevents key material leakage
//! - Constant-time operations prevent timing attacks
//! - Comprehensive error handling prevents fallback to weak randomness

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs, clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

#[cfg(feature = "alloc")]
extern crate alloc;

// Core modules
pub mod entropy;
pub mod error;
pub mod provider;
pub mod traits;
pub mod validation;

// Re-export main types
pub use error::{
    Error,
    Result,
};
#[cfg(feature = "alloc")]
pub use provider::LibQRng;
#[cfg(feature = "alloc")]
pub use traits::RngProvider;
pub use traits::{
    EntropySource,
    SecureRng,
};
// Re-export validation types
pub use validation::{
    EntropyQuality,
    EntropyValidator,
};

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Minimum entropy bits required for cryptographic operations
pub const MIN_ENTROPY_BITS: usize = 128;

/// Maximum entropy bits for validation
pub const MAX_ENTROPY_BITS: usize = 4096;

/// Default entropy buffer size
pub const DEFAULT_ENTROPY_SIZE: usize = 32;

/// Create a new secure RNG instance
///
/// This function creates a cryptographically secure RNG using the best available
/// entropy source for the current platform.
///
/// # Errors
///
/// Returns an error if no secure entropy source is available.
///
/// # Examples
///
/// ```rust
/// use lib_q_rng::new_secure_rng;
/// use rand_core::RngCore;
///
/// let mut rng = new_secure_rng().unwrap();
/// let mut bytes = [0u8; 32];
/// rng.fill_bytes(&mut bytes);
/// ```
#[cfg(feature = "alloc")]
pub fn new_secure_rng() -> Result<LibQRng> {
    LibQRng::new_secure()
}

/// Create a new deterministic RNG instance
///
/// This function creates a deterministic RNG suitable for testing and
/// reproducible operations. **NOT CRYPTOGRAPHICALLY SECURE**.
///
/// # Arguments
///
/// * `seed` - The seed value for deterministic generation
///
/// # Examples
///
/// ```rust
/// use lib_q_rng::new_deterministic_rng;
/// use rand_core::RngCore;
///
/// let mut rng = new_deterministic_rng(&[1, 2, 3, 4]);
/// let mut bytes = [0u8; 32];
/// rng.fill_bytes(&mut bytes);
/// ```
#[cfg(feature = "alloc")]
pub fn new_deterministic_rng(seed: &[u8]) -> LibQRng {
    LibQRng::new_deterministic(seed)
}

/// Create a new RNG with custom entropy source
///
/// This function allows creating an RNG with a custom entropy source,
/// useful for specialized applications or testing.
///
/// # Arguments
///
/// * `entropy_source` - Custom entropy source implementation
///
/// # Examples
///
/// ```rust
/// use lib_q_rng::{
///     EntropySource,
///     new_custom_rng,
/// };
/// use rand_core::RngCore;
///
/// struct MyEntropySource;
/// impl EntropySource for MyEntropySource {
///     fn get_entropy(
///         &mut self,
///         dest: &mut [u8],
///     ) -> Result<(), lib_q_rng::Error> {
///         // Implementation details...
///         Ok(())
///     }
/// }
///
/// let mut rng = new_custom_rng(MyEntropySource);
/// ```
#[cfg(feature = "alloc")]
pub fn new_custom_rng<T: EntropySource + 'static>(entropy_source: T) -> LibQRng {
    LibQRng::new_custom(entropy_source)
}

#[cfg(test)]
mod tests {
    use rand_core::RngCore;

    use super::*;

    #[test]
    fn test_version_constant() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_constants() {
        assert!(MIN_ENTROPY_BITS >= 128);
        assert!(MAX_ENTROPY_BITS > MIN_ENTROPY_BITS);
        assert!(DEFAULT_ENTROPY_SIZE > 0);
    }

    #[test]
    fn test_deterministic_rng_creation() {
        let seed = [1, 2, 3, 4, 5, 6, 7, 8];
        let rng = new_deterministic_rng(&seed);
        assert!(rng.is_deterministic());
    }

    #[test]
    fn test_deterministic_rng_consistency() {
        let seed = [42u8; 16];
        let mut rng1 = new_deterministic_rng(&seed);
        let mut rng2 = new_deterministic_rng(&seed);

        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];

        rng1.fill_bytes(&mut bytes1);
        rng2.fill_bytes(&mut bytes2);

        assert_eq!(bytes1, bytes2);
    }
}
