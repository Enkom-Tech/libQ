#![allow(
    clippy::uninlined_format_args,
    clippy::must_use_candidate,
    clippy::cast_precision_loss,
    clippy::cast_lossless,
    clippy::manual_clamp,
    clippy::unused_self,
    clippy::unnecessary_wraps,
    clippy::struct_excessive_bools,
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::similar_names
)]

//! # lib-q-random: Secure Random Number Generation for libQ
//!
//! This crate provides a comprehensive, secure random number generation system
//! designed specifically for post-quantum cryptography applications in the libQ ecosystem.
//!
//! ## Features
//!
//! - **Cryptographically Secure**: Uses OS entropy sources and hardware RNGs when available
//! - **Multiple Providers**: Support for OS, deterministic, and hardware entropy sources
//! - **Entropy Validation**: Comprehensive entropy quality assessment and validation
//! - **`no_std` Support**: Works in constrained environments without standard library
//! - **WASM Compatible**: Full support for `WebAssembly` and browser environments
//! - **Zero-Copy**: Efficient memory usage with minimal allocations
//! - **Thread-Safe**: Safe for use in multi-threaded environments
//! - **Extensible**: Plugin architecture for custom entropy sources
//! - **Custom Entropy Sources**: Secure callback-based system for plugging in custom entropy sources in `no_std` and WASM environments
//!
//! ## Quick Start
//!
//! ### With std/alloc features
//! ```rust
//! #[cfg(feature = "alloc")]
//! {
//!     use lib_q_random::{
//!         EntropySource,
//!         LibQRng,
//!         RngProvider,
//!     };
//!     use rand_core::Rng;
//!
//!     // Create a secure RNG for production use
//!     let mut rng = LibQRng::new_secure().unwrap();
//!
//!     // Generate random bytes
//!     let mut bytes = [0u8; 32];
//!     rng.fill_bytes(&mut bytes);
//!
//!     // Create a deterministic RNG for testing
//!     let mut test_rng = LibQRng::new_deterministic(&[1, 2, 3, 4]);
//! }
//! ```
//!
//! ### Custom Entropy Sources (`no_std`/WASM)
//! ```rust
//! #[cfg(feature = "custom-entropy")]
//! {
//!     use lib_q_random::{
//!         custom_entropy::{CustomEntropySource, EntropyContext, EntropyQuality, CustomEntropyConfig},
//!         register_custom_entropy_source, unregister_custom_entropy_source,
//!         new_secure_rng
//!     };
//!     use rand_core::Rng;
//!
//!     // Define your custom entropy callback
//!     unsafe extern "C" fn my_entropy_callback(dest: *mut u8, len: usize, _context: *mut u8) -> i32 {
//!         // Fill dest with len bytes of entropy from your source
//!         for i in 0..len {
//!             unsafe {
//!                 *dest.add(i) = (i as u8).wrapping_add(42); // Example entropy source
//!             }
//!         }
//!         0
//!     }
//!
//!     // Create and register the custom entropy source
//!     let context = EntropyContext::empty();
//!     let config = CustomEntropyConfig::default();
//!     let source = CustomEntropySource {
//!         callback: my_entropy_callback,
//!         context,
//!         quality: EntropyQuality::Hardware,
//!         config,
//!         source_id: "my_hardware_rng",
//!     };
//!
//!     // Register the source (must remain valid for the lifetime of usage)
//!     unsafe {
//!         register_custom_entropy_source(&source);
//!     }
//!
//!     // Now create RNGs that will use your custom entropy source
//!     let mut rng = new_secure_rng().unwrap();
//!     let mut bytes = [0u8; 32];
//!     rng.fill_bytes(&mut bytes);
//!
//!     // Clean up when done
//!     unregister_custom_entropy_source();
//! }
//! ```
//!
//! ### With `no_std` features
//! ```rust
//! #[cfg(not(feature = "alloc"))]
//! {
//!     use lib_q_random::{
//!         new_deterministic_rng_no_std,
//!         new_secure_rng_no_std,
//!     };
//!     use rand_core::Rng;
//!
//!     // Create a secure RNG for production use
//!     let mut rng = new_secure_rng_no_std().unwrap();
//!
//!     // Generate random bytes
//!     let mut bytes = [0u8; 32];
//!     rng.fill_bytes(&mut bytes);
//!
//!     // Create a deterministic RNG for testing
//!     let mut test_rng = new_deterministic_rng_no_std(&[1, 2, 3, 4]);
//! }
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

// Enable alloc crate when not using std or when alloc feature is enabled
#[cfg(any(not(feature = "std"), feature = "alloc"))]
extern crate alloc;

// Core modules
pub mod entropy;
pub mod error;
pub mod provider;
pub mod traits;
pub mod validation;

// Specialized RNG implementations for different algorithms
pub mod secure_fallback;
pub mod specialized;

// no_std RNG implementation
#[cfg(any(not(feature = "std"), feature = "no_std"))]
pub mod no_std_rng;

// Deterministic RNG for STARK/ZKP use
pub mod deterministic_rng;
pub use deterministic_rng::DeterministicRng;

// Custom entropy source system for no_std/WASM environments
#[cfg(feature = "custom-entropy")]
pub mod custom_entropy;

// Re-export main types
pub use error::{
    Error,
    Result,
};
#[cfg(feature = "alloc")]
pub use provider::LibQRng;
// Re-export specialized implementations
#[cfg(feature = "classical-mceliece")]
pub use specialized::ClassicalMcElieceRng;
#[cfg(feature = "fn-dsa")]
pub use specialized::FnDsaRng;
#[cfg(feature = "hpke")]
pub use specialized::KangarooTwelveRng;
#[cfg(feature = "alloc")]
pub use traits::RngProvider;
pub use traits::{
    EntropySource,
    SecureRng,
    SecurityLevel,
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

/// Fill `dest` with cryptographically secure bytes from the OS entropy source.
///
/// Requires the `getrandom` feature. Returns `Err` if that feature is absent
/// rather than silently producing weak output.
///
/// # Errors
///
/// Returns [`Error::FeatureNotAvailable`] when the `getrandom` feature is not
/// enabled. Returns [`Error::EntropySourceUnavailable`] when getrandom fails.
pub fn fill_entropy(dest: &mut [u8]) -> Result<()> {
    #[cfg(feature = "getrandom")]
    {
        getrandom::fill(dest).map_err(|_| Error::EntropySourceUnavailable {
            source: "system",
            context: Some("getrandom failed"),
        })
    }
    #[cfg(not(feature = "getrandom"))]
    {
        let _ = dest;
        Err(Error::FeatureNotAvailable {
            feature: "secure entropy",
            required_features: &["getrandom"],
        })
    }
}

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
/// use lib_q_random::new_secure_rng;
/// use rand_core::Rng;
///
/// let mut rng = new_secure_rng().unwrap();
/// let mut bytes = [0u8; 32];
/// rng.fill_bytes(&mut bytes);
/// ```
#[cfg(feature = "alloc")]
pub fn new_secure_rng() -> Result<LibQRng> {
    LibQRng::new_secure()
}

/// Create a new secure RNG instance for `no_std` environments
///
/// This function creates a cryptographically secure RNG that works in `no_std`
/// environments using getrandom for entropy.
///
/// # Errors
///
/// Returns an error if getrandom is not available or fails to initialize.
///
/// # Examples
///
/// ```rust,no_run
/// use lib_q_random::new_secure_rng_no_std;
/// use rand_core::Rng;
///
/// let mut rng = new_secure_rng_no_std().unwrap();
/// let mut bytes = [0u8; 32];
/// rng.fill_bytes(&mut bytes);
/// ```
#[cfg(not(feature = "alloc"))]
pub fn new_secure_rng_no_std() -> Result<no_std_rng::NoStdRng> {
    no_std_rng::NoStdRng::new()
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
/// use lib_q_random::new_deterministic_rng;
/// use rand_core::Rng;
///
/// let mut rng = new_deterministic_rng(&[1, 2, 3, 4]);
/// let mut bytes = [0u8; 32];
/// rng.fill_bytes(&mut bytes);
/// ```
#[cfg(feature = "alloc")]
#[must_use]
pub fn new_deterministic_rng(seed: &[u8]) -> LibQRng {
    LibQRng::new_deterministic(seed)
}

/// Create a new deterministic RNG instance for `no_std` environments
///
/// This function creates a deterministic RNG suitable for testing and
/// reproducible operations in `no_std` environments. **NOT CRYPTOGRAPHICALLY SECURE**.
///
/// # Arguments
///
/// * `seed` - The seed value for deterministic generation
///
/// # Examples
///
/// ```rust,no_run
/// use lib_q_random::new_deterministic_rng_no_std;
/// use rand_core::Rng;
///
/// let mut rng = new_deterministic_rng_no_std(&[1, 2, 3, 4]);
/// let mut bytes = [0u8; 32];
/// rng.fill_bytes(&mut bytes);
/// ```
#[cfg(not(feature = "alloc"))]
#[must_use]
pub fn new_deterministic_rng_no_std(seed: &[u8]) -> no_std_rng::NoStdRng {
    no_std_rng::NoStdRng::new_deterministic(seed)
}

/// Register a custom entropy source for the current thread
///
/// This function allows developers to register a custom entropy source that will
/// be used by `NoStdRng` when generating random bytes. The entropy source must
/// remain valid for the lifetime of the registration.
///
/// # Arguments
///
/// * `source` - The custom entropy source to register
///
/// # Safety
///
/// The `source` must remain valid for the lifetime of the registration.
/// The caller is responsible for ensuring the source is not dropped
/// while registered.
///
/// # Examples
///
/// ```rust,no_run
/// use lib_q_random::custom_entropy::{
///     CustomEntropyConfig,
///     CustomEntropySource,
///     EntropyContext,
///     EntropyQuality,
/// };
/// use lib_q_random::{
///     register_custom_entropy_source,
///     unregister_custom_entropy_source,
/// };
/// use rand_core::Rng;
///
/// // Define a custom entropy callback
/// unsafe extern "C" fn my_entropy_callback(
///     dest: *mut u8,
///     len: usize,
///     _context: *mut u8,
/// ) -> i32 {
///     // Fill dest with len bytes of entropy
///     // Return 0 on success, non-zero on failure
///     0
/// }
///
/// // Create and register the entropy source
/// let context = EntropyContext::empty();
/// let config = CustomEntropyConfig::default();
/// let source = unsafe {
///     CustomEntropySource::new(
///         my_entropy_callback,
///         context,
///         EntropyQuality::User,
///         config,
///         "my_custom_source",
///     )
/// };
///
/// unsafe {
///     register_custom_entropy_source(&source);
/// }
///
/// // Now NoStdRng will use the custom entropy source
/// // (In no_std environments, use new_secure_rng_no_std())
/// // let mut rng = new_secure_rng_no_std().unwrap();
/// // let mut bytes = [0u8; 32];
/// // rng.fill_bytes(&mut bytes);
///
/// // Clean up
/// unregister_custom_entropy_source();
/// ```
#[cfg(feature = "custom-entropy")]
pub unsafe fn register_custom_entropy_source(source: *const custom_entropy::CustomEntropySource) {
    unsafe { custom_entropy::register_custom_entropy_source(source) };
}

/// Unregister the current custom entropy source
///
/// This function removes the currently registered custom entropy source,
/// causing `NoStdRng` to fall back to the default entropy source (getrandom).
#[cfg(feature = "custom-entropy")]
pub fn unregister_custom_entropy_source() {
    custom_entropy::unregister_custom_entropy_source();
}

/// Check if a custom entropy source is currently registered
///
/// # Returns
///
/// Returns `true` if a custom entropy source is registered, `false` otherwise.
#[cfg(feature = "custom-entropy")]
#[must_use]
pub fn has_custom_entropy_source() -> bool {
    custom_entropy::has_custom_entropy_source()
}

/// Get information about the currently registered entropy source
///
/// # Returns
///
/// Returns a tuple of (`source_id`, quality) if a source is registered.
#[cfg(feature = "custom-entropy")]
#[must_use]
pub fn get_custom_entropy_source_info() -> Option<(&'static str, custom_entropy::EntropyQuality)> {
    custom_entropy::get_entropy_source_info()
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
/// use lib_q_random::{
///     EntropySource,
///     new_custom_rng,
/// };
/// use rand_core::Rng;
///
/// struct MyEntropySource;
/// impl EntropySource for MyEntropySource {
///     fn get_entropy(
///         &mut self,
///         dest: &mut [u8],
///     ) -> Result<(), lib_q_random::Error> {
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
    #[cfg(not(feature = "alloc"))]
    use rand_core::Rng;

    use super::*;

    #[test]
    fn test_version_constant() {
        // VERSION is a non-empty string constant
        #[allow(clippy::const_is_empty)]
        {
            assert!(!VERSION.is_empty());
        }
    }

    #[test]
    fn test_constants() {
        // Test that constants have reasonable values
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(MIN_ENTROPY_BITS >= 128);
            assert!(MAX_ENTROPY_BITS > MIN_ENTROPY_BITS);
            assert!(DEFAULT_ENTROPY_SIZE > 0);
        }
    }

    #[test]
    #[cfg(not(feature = "alloc"))]
    fn test_deterministic_rng_creation() {
        let seed = [1, 2, 3, 4, 5, 6, 7, 8];
        let rng = new_deterministic_rng_no_std(&seed);
        assert!(rng.is_deterministic());
    }

    #[test]
    #[cfg(not(feature = "alloc"))]
    fn test_deterministic_rng_consistency() {
        let seed = [42u8; 16];
        let mut rng1 = new_deterministic_rng_no_std(&seed);
        let mut rng2 = new_deterministic_rng_no_std(&seed);

        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];

        rng1.fill_bytes(&mut bytes1);
        rng2.fill_bytes(&mut bytes2);

        assert_eq!(bytes1, bytes2);
    }
}
