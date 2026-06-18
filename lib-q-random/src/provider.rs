// Allow clippy warnings in provider code
// These are legitimate patterns for API design
#![allow(clippy::must_use_candidate)]

//! RNG provider implementations
//!
//! This module provides the main RNG provider implementation and factory
//! for creating and managing RNG instances with different characteristics.

#[cfg(feature = "alloc")]
use alloc::{
    boxed::Box,
    vec,
};
#[cfg(feature = "alloc")]
use core::fmt;

#[cfg(feature = "alloc")]
use rand_core::{
    TryCryptoRng,
    TryRng,
};

#[cfg(feature = "alloc")]
use crate::Result;
#[cfg(feature = "alloc")]
use crate::traits::{
    EntropySource,
    ProviderCapabilities,
    RngConfig,
    RngProvider,
    SecureRng,
    SecurityLevel,
};
#[cfg(feature = "alloc")]
use crate::validation::EntropyValidator;

/// Main libQ random number generator
///
/// This is the primary RNG implementation for the libQ ecosystem, providing
/// a unified interface for secure random number generation across different
/// platforms and use cases.
#[cfg(feature = "alloc")]
pub struct LibQRng {
    /// Entropy source for random data
    entropy_source: Box<dyn EntropySource>,
    /// Entropy validator for quality assessment
    validator: EntropyValidator,
    /// Security level of this RNG
    security_level: SecurityLevel,
    /// Whether this RNG is deterministic
    deterministic: bool,
    /// Reseed counter for security
    reseed_counter: u32,
    /// Bytes generated since last reseed
    bytes_generated: usize,
    /// Reseed interval in bytes
    reseed_interval: Option<usize>,
}

#[cfg(feature = "alloc")]
impl LibQRng {
    /// Create a new secure RNG using the best available entropy source
    ///
    /// This method creates a cryptographically secure RNG using the highest
    /// quality entropy source available on the current platform.
    ///
    /// # Errors
    ///
    /// Returns an error if no secure entropy source is available.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use lib_q_random::LibQRng;
    /// use rand_core::Rng;
    ///
    /// let mut rng = LibQRng::new_secure().unwrap();
    /// let mut bytes = [0u8; 32];
    /// rng.fill_bytes(&mut bytes);
    /// ```
    pub fn new_secure() -> Result<Self> {
        let entropy_source = crate::entropy::EntropySourceFactory::create_best_available()?;
        // Use relaxed validation settings for real-world entropy sources
        let validator = EntropyValidator::with_settings(
            64,    // min_entropy_bits: 64 bits minimum (8 bytes)
            8192,  // max_entropy_bits: 8KB maximum
            0.3,   // quality_threshold: More realistic threshold
            false, // strict_mode: Disabled for real-world usage
        );

        Ok(Self {
            entropy_source,
            validator,
            security_level: SecurityLevel::CryptographicallySecure,
            deterministic: false,
            reseed_counter: 0,
            bytes_generated: 0,
            reseed_interval: Some(1024 * 1024), // 1MB reseed interval
        })
    }

    /// Create a new deterministic RNG for testing
    ///
    /// Initializes a **KT128** (`KangarooTwelve`) XOF byte stream from a **256-bit** seed.
    /// Suitable for KATs and regression
    /// tests. **Unpredictability is only as strong as the seed**: this is not a
    /// substitute for [`Self::new_secure`] in production.
    ///
    /// # Arguments
    ///
    /// * `seed` - 32-byte seed; must be chosen explicitly for tests
    ///
    /// # Examples
    ///
    /// ```rust
    /// use lib_q_random::LibQRng;
    /// use rand_core::Rng;
    ///
    /// let mut rng = LibQRng::new_deterministic([1; 32]);
    /// let mut bytes = [0u8; 32];
    /// rng.fill_bytes(&mut bytes);
    /// ```
    pub fn new_deterministic(seed: [u8; 32]) -> Self {
        let entropy_source =
            crate::entropy::EntropySourceFactory::create_deterministic_entropy(seed);
        // Deterministic RNGs don't need strict validation since they're not cryptographically secure
        let validator = EntropyValidator::with_settings(
            32,    // min_entropy_bits: Lower threshold for deterministic
            1024,  // max_entropy_bits: Smaller limit
            0.1,   // quality_threshold: Very low threshold since it's deterministic
            false, // strict_mode: Disabled
        );

        Self {
            entropy_source,
            validator,
            security_level: SecurityLevel::Deterministic,
            deterministic: true,
            reseed_counter: 0,
            bytes_generated: 0,
            reseed_interval: None, // No reseeding for deterministic RNGs
        }
    }

    /// Create a deterministic RNG from a `u64` test seed (`SplitMix64` → KT128).
    pub fn new_deterministic_from_u64(seed: u64) -> Self {
        let entropy_source =
            crate::entropy::EntropySourceFactory::create_deterministic_entropy_from_u64(seed);
        let validator = EntropyValidator::with_settings(32, 1024, 0.1, false);

        Self {
            entropy_source,
            validator,
            security_level: SecurityLevel::Deterministic,
            deterministic: true,
            reseed_counter: 0,
            bytes_generated: 0,
            reseed_interval: None,
        }
    }

    /// Create a deterministic RNG using Saturnin CTR keystream (`deterministic-saturnin` feature).
    ///
    /// Requires `alloc`. Uses domain [`crate::kt128_expander::DOMAIN_LIBQ_DET_SATURNIN`] for the CTR nonce.
    ///
    /// # Errors
    ///
    /// Returns an error if Saturnin keystream generation fails.
    #[cfg(feature = "deterministic-saturnin")]
    pub fn new_deterministic_saturnin(seed: [u8; 32]) -> Result<Self> {
        let entropy_source = alloc::boxed::Box::new(
            crate::saturnin_det::SaturninDeterministicEntropySource::new(seed)?,
        );
        let validator = EntropyValidator::with_settings(32, 1024, 0.1, false);
        Ok(Self {
            entropy_source,
            validator,
            security_level: SecurityLevel::Deterministic,
            deterministic: true,
            reseed_counter: 0,
            bytes_generated: 0,
            reseed_interval: None,
        })
    }

    /// Create a new RNG with NIST AES256-CTR-DRBG for KAT test compatibility
    ///
    /// This method creates an RNG using the NIST AES256-CTR-DRBG algorithm,
    /// which is required for compatibility with NIST KAT test vectors.
    ///
    /// # Arguments
    ///
    /// * `entropy_input` - 48-byte entropy input for DRBG initialization
    ///
    /// # Examples
    ///
    /// ```rust
    /// use lib_q_random::LibQRng;
    /// use rand_core::Rng;
    ///
    /// let entropy_input = [0u8; 48]; // 48-byte seed
    /// let mut rng = LibQRng::new_nist_drbg(entropy_input);
    /// let mut bytes = [0u8; 32];
    /// rng.fill_bytes(&mut bytes);
    /// ```
    #[cfg(feature = "nist-drbg")]
    pub fn new_nist_drbg(entropy_input: [u8; 48]) -> Self {
        let entropy_source =
            crate::entropy::EntropySourceFactory::create_nist_drbg_entropy(entropy_input);
        // NIST DRBG provides high quality entropy
        let validator = EntropyValidator::with_settings(
            256,  // min_entropy_bits: High threshold for NIST DRBG
            4096, // max_entropy_bits: Higher limit
            0.9,  // quality_threshold: High threshold for NIST DRBG
            true, // strict_mode: Enabled for NIST DRBG
        );

        Self {
            entropy_source,
            validator,
            security_level: SecurityLevel::CryptographicallySecure,
            deterministic: true, // NIST DRBG is deterministic but cryptographically secure
            reseed_counter: 0,
            bytes_generated: 0,
            reseed_interval: Some(1_000_000), // NIST recommendation
        }
    }

    /// Create a new RNG with a custom entropy source
    ///
    /// This method allows creating an RNG with a custom entropy source,
    /// useful for specialized applications or testing.
    ///
    /// # Arguments
    ///
    /// * `entropy_source` - Custom entropy source implementation
    ///
    /// # Examples
    ///
    /// ```rust
    /// use lib_q_random::LibQRng;
    /// use lib_q_random::entropy::UserEntropySource;
    /// use rand_core::Rng;
    ///
    /// let entropy_data = vec![1, 2, 3, 4, 5, 6, 7, 8];
    /// let entropy_source = UserEntropySource::new(entropy_data);
    /// let mut rng = LibQRng::new_custom(entropy_source);
    /// ```
    pub fn new_custom<T: EntropySource + 'static>(entropy_source: T) -> Self {
        let entropy_source = Box::new(entropy_source);
        // Use appropriate validator settings based on entropy source type
        let validator = match entropy_source.source_type() {
            crate::traits::EntropySourceType::Hardware => {
                EntropyValidator::with_settings(64, 8192, 0.4, false)
            }
            crate::traits::EntropySourceType::OperatingSystem => {
                EntropyValidator::with_settings(64, 8192, 0.3, false)
            }
            _ => EntropyValidator::with_settings(64, 8192, 0.3, false),
        };

        // Determine security level based on entropy source type
        let security_level = match entropy_source.source_type() {
            crate::traits::EntropySourceType::Hardware => SecurityLevel::Hardware,
            crate::traits::EntropySourceType::OperatingSystem => {
                SecurityLevel::CryptographicallySecure
            }
            crate::traits::EntropySourceType::Deterministic
            | crate::traits::EntropySourceType::User => SecurityLevel::Deterministic,
        };

        let deterministic =
            entropy_source.source_type() == crate::traits::EntropySourceType::Deterministic;

        Self {
            entropy_source,
            validator,
            security_level,
            deterministic,
            reseed_counter: 0,
            bytes_generated: 0,
            reseed_interval: if deterministic {
                None
            } else {
                Some(1024 * 1024)
            },
        }
    }

    /// Create a new RNG with custom configuration
    ///
    /// This method allows creating an RNG with specific configuration
    /// parameters for specialized use cases.
    ///
    /// # Arguments
    ///
    /// * `config` - RNG configuration parameters
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid or if the RNG
    /// cannot be created with the specified parameters.
    pub fn with_config(config: &RngConfig) -> Result<Self> {
        let entropy_source = if let Some(_source) = &config.entropy_source {
            // We can't move out of a reference, so we need to create a new one
            // This is a limitation of the current design
            crate::entropy::EntropySourceFactory::create_best_available()?
        } else {
            crate::entropy::EntropySourceFactory::create_best_available()?
        };

        // Use appropriate validator settings based on security level
        let validator = match config.security_level {
            SecurityLevel::Hardware => EntropyValidator::with_settings(64, 8192, 0.4, false),
            SecurityLevel::CryptographicallySecure => {
                EntropyValidator::with_settings(64, 8192, 0.3, false)
            }
            SecurityLevel::Deterministic => EntropyValidator::with_settings(32, 1024, 0.1, false),
            SecurityLevel::Software => EntropyValidator::with_settings(64, 8192, 0.3, false),
        };
        let deterministic =
            entropy_source.source_type() == crate::traits::EntropySourceType::Deterministic;

        Ok(Self {
            entropy_source,
            validator,
            security_level: config.security_level,
            deterministic,
            reseed_counter: 0,
            bytes_generated: 0,
            reseed_interval: config.reseed_interval,
        })
    }

    /// Check if this RNG is deterministic
    pub fn is_deterministic(&self) -> bool {
        self.deterministic
    }

    /// Get the security level of this RNG
    pub fn security_level(&self) -> SecurityLevel {
        self.security_level
    }

    /// Get the entropy source name
    pub fn entropy_source_name(&self) -> &'static str {
        self.entropy_source.name()
    }

    /// Get the entropy source type
    pub fn entropy_source_type(&self) -> crate::traits::EntropySourceType {
        self.entropy_source.source_type()
    }

    /// Get the reseed counter
    pub fn reseed_counter(&self) -> u32 {
        self.reseed_counter
    }

    /// Get the bytes generated since last reseed
    pub fn bytes_generated(&self) -> usize {
        self.bytes_generated
    }

    /// Check if this RNG is cryptographically secure
    pub fn is_secure(&self) -> bool {
        self.security_level == SecurityLevel::CryptographicallySecure
    }

    /// Get the entropy quality estimate (0.0 to 1.0)
    pub fn entropy_quality(&self) -> f64 {
        match self.security_level {
            SecurityLevel::CryptographicallySecure => 1.0,
            SecurityLevel::Deterministic => 0.0,
            SecurityLevel::Hardware => 0.95,
            SecurityLevel::Software => 0.8,
        }
    }

    /// Check if reseeding is needed
    fn needs_reseed(&self) -> bool {
        if let Some(interval) = self.reseed_interval {
            self.bytes_generated >= interval
        } else {
            false
        }
    }

    /// Perform reseeding if needed
    fn reseed_if_needed(&mut self) -> Result<()> {
        if self.needs_reseed() {
            self.reseed()?;
        }
        Ok(())
    }
}

#[cfg(feature = "alloc")]
impl SecureRng for LibQRng {
    fn fill_bytes_secure(&mut self, dest: &mut [u8]) -> Result<()> {
        // Check if reseeding is needed
        self.reseed_if_needed()?;

        // Get entropy from the source
        self.entropy_source.get_entropy(dest)?;

        // Validate entropy quality if not deterministic
        if !self.deterministic {
            // Only validate if we have enough data
            if dest.len() >= 8 {
                self.validator.validate_entropy(dest)?;
            }
        }

        // Update counters
        self.bytes_generated += dest.len();

        Ok(())
    }

    fn next_u32_secure(&mut self) -> Result<u32> {
        let mut bytes = [0u8; 4];
        self.fill_bytes_secure(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn next_u64_secure(&mut self) -> Result<u64> {
        let mut bytes = [0u8; 8];
        self.fill_bytes_secure(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn initialize(&mut self, entropy: &[u8]) -> Result<()> {
        // For deterministic RNGs, we can reinitialize with new seed
        if self.deterministic {
            let seed: [u8; 32] = entropy.try_into().map_err(|_| {
                crate::Error::invalid_configuration(
                    "deterministic seed",
                    "exactly 32 bytes",
                    "slice length is not 32",
                )
            })?;
            let new_source =
                crate::entropy::EntropySourceFactory::create_deterministic_entropy(seed);
            self.entropy_source = new_source;
            self.reseed_counter = 0;
            self.bytes_generated = 0;
        }
        // For secure RNGs, we can't reinitialize with user entropy
        // as it would compromise security
        Ok(())
    }

    fn is_secure(&self) -> bool {
        !self.deterministic
    }

    fn entropy_quality(&self) -> f64 {
        self.entropy_source.quality()
    }

    fn security_level(&self) -> SecurityLevel {
        self.security_level
    }

    fn reseed(&mut self) -> Result<()> {
        if self.deterministic {
            return Ok(()); // No reseeding for deterministic RNGs
        }

        // For secure RNGs, reseeding is handled by the entropy source
        // We just update our counters
        self.reseed_counter = self.reseed_counter.wrapping_add(1);
        self.bytes_generated = 0;

        Ok(())
    }

    fn state_size(&self) -> usize {
        // This is an estimate - the actual state size depends on the entropy source
        64
    }

    fn reseed_interval(&self) -> Option<usize> {
        self.reseed_interval
    }
}

#[cfg(feature = "alloc")]
impl TryRng for LibQRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        match self.next_u32_secure() {
            Ok(value) => Ok(value),
            Err(_) => rng_abort(),
        }
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        match self.next_u64_secure() {
            Ok(value) => Ok(value),
            Err(_) => rng_abort(),
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), Self::Error> {
        match self.fill_bytes_secure(dest) {
            Ok(()) => Ok(()),
            Err(_) => rng_abort(),
        }
    }
}

/// Hard stop on unrecoverable entropy failure (avoids `panic!` / `eprintln!` for strict Clippy).
// `clippy::panic` is denied in non-test builds (see `lib.rs` lint config),
// but the `no_std` branch of this abort path has no `std::process::abort`
// alternative, so `panic!` is the only way out. Allow it on the function so
// the attribute targets an item rather than a macro invocation.
#[cfg(feature = "alloc")]
#[inline(never)]
#[allow(clippy::panic)]
fn rng_abort() -> ! {
    #[cfg(feature = "std")]
    std::process::abort();
    #[cfg(not(feature = "std"))]
    panic!("CRITICAL SECURITY FAILURE: RNG entropy unavailable");
}

#[cfg(feature = "alloc")]
impl TryCryptoRng for LibQRng {}

#[cfg(feature = "alloc")]
impl LibQRng {
    /// Fill a slice with random values of any integer type
    ///
    /// This method provides a convenient way to fill slices of different integer types
    /// with random values, handling the byte conversion internally.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use lib_q_random::LibQRng;
    ///
    /// let mut rng = LibQRng::new_secure().unwrap();
    /// let mut u16_array = [0u16; 10];
    /// rng.fill(&mut u16_array);
    /// ```
    pub fn fill<T>(&mut self, dest: &mut [T])
    where
        T: Copy + Default,
    {
        if dest.is_empty() {
            return;
        }

        // Calculate the number of bytes needed
        let size = core::mem::size_of::<T>();
        if size == 0 {
            return;
        }
        let total_bytes = core::mem::size_of_val(dest);

        // Create a temporary byte buffer
        let mut bytes = vec![0u8; total_bytes];

        // Entropy failure must never yield predictable output; abort like the
        // infallible `RngCore` path instead of returning the zeroed buffer.
        if self.fill_bytes_secure(&mut bytes).is_err() {
            rng_abort();
        }

        // Convert bytes back to the target type
        for (i, chunk) in bytes.chunks_exact(size).enumerate() {
            if i < dest.len() {
                // This is safe because we're copying the exact number of bytes
                // that the type occupies in memory
                unsafe {
                    let ptr = dest.as_mut_ptr().add(i).cast::<u8>();
                    core::ptr::copy_nonoverlapping(chunk.as_ptr(), ptr, size);
                }
            }
        }
    }
}

// LibQRng implements rand_core::Rng and TryCryptoRng, so CryptoRng and Rng
// are provided by rand_core blanket impls. The signature crate uses rand_core
// and will see these implementations when using the same rand_core version.

#[cfg(feature = "alloc")]
impl fmt::Display for LibQRng {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LibQRng(security_level: {}, entropy_source: {}, deterministic: {}, reseed_counter: {})",
            self.security_level,
            self.entropy_source.name(),
            self.deterministic,
            self.reseed_counter
        )
    }
}

/// RNG provider factory
///
/// This factory provides convenient methods for creating RNG instances
/// with different characteristics and configurations.
pub struct LibQRngProvider;

impl LibQRngProvider {
    /// Create a new RNG provider
    pub fn new() -> Self {
        Self
    }
}

#[cfg(feature = "alloc")]
impl RngProvider for LibQRngProvider {
    fn create_rng(&self, config: &RngConfig) -> Result<Box<dyn SecureRng>> {
        let rng = LibQRng::with_config(config)?;
        Ok(Box::new(rng))
    }

    fn name(&self) -> &'static str {
        "libQ RNG Provider"
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            secure: true,
            deterministic: true,
            hardware: true,
            reseeding: true,
            custom_entropy: true,
            no_std: true,
            wasm: true,
        }
    }

    fn supports_config(&self, config: &RngConfig) -> bool {
        // We support all configurations
        let _ = config;
        true
    }

    fn priority(&self) -> u32 {
        100 // High priority as the main provider
    }
}

impl Default for LibQRngProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #[cfg(all(not(feature = "std"), feature = "alloc"))]
    use alloc::format;

    #[cfg(feature = "alloc")]
    use rand_core::Rng;

    #[cfg(feature = "alloc")]
    use super::*;

    #[test]
    #[cfg(feature = "alloc")]
    fn test_libq_rng_deterministic_creation() {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let rng = LibQRng::new_deterministic(seed);
        assert!(rng.is_deterministic());
        assert_eq!(rng.security_level(), SecurityLevel::Deterministic);
        assert!(!rng.is_secure());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_libq_rng_deterministic_consistency() {
        let seed = [42u8; 32];
        let mut rng1 = LibQRng::new_deterministic(seed);
        let mut rng2 = LibQRng::new_deterministic(seed);

        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];

        rng1.fill_bytes(&mut bytes1);
        rng2.fill_bytes(&mut bytes2);

        assert_eq!(bytes1, bytes2);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_libq_rng_deterministic_golden_zero_seed() {
        use crate::kt128_expander::Kt128Expander;

        let expected = crate::kt128_expander::KT128_DET_GOLDEN_ZERO_SEED_64;
        let mut rng = LibQRng::new_deterministic([0u8; 32]);
        let mut out = [0u8; 64];
        rng.fill_bytes(&mut out);
        let mut direct = Kt128Expander::from_det_seed_32([0u8; 32]);
        let mut expected_direct = [0u8; 64];
        direct.fill_bytes(&mut expected_direct);
        assert_eq!(out, expected);
        assert_eq!(out, expected_direct);
    }

    /// Regression: deterministic RNG must use the full 256-bit seed (KT128), not a
    /// collapsed 64-bit state where distant seed bytes could be ignored.
    #[test]
    #[cfg(feature = "alloc")]
    fn test_libq_rng_deterministic_seeds_differ_in_final_byte_yield_different_streams() {
        let seed_a = [0u8; 32];
        let mut seed_b = [0u8; 32];
        seed_b[31] = 1;

        let mut rng_a = LibQRng::new_deterministic(seed_a);
        let mut rng_b = LibQRng::new_deterministic(seed_b);

        let mut out_a = [0u8; 64];
        let mut out_b = [0u8; 64];
        rng_a.fill_bytes(&mut out_a);
        rng_b.fill_bytes(&mut out_b);

        assert_ne!(
            out_a, out_b,
            "KT128 streams from different 32-byte keys must diverge immediately"
        );
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_libq_rng_custom_creation() {
        let entropy_data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let entropy_source = crate::entropy::UserEntropySource::new(entropy_data);
        let rng = LibQRng::new_custom(entropy_source);
        assert!(!rng.is_deterministic());
        assert_eq!(rng.security_level(), SecurityLevel::CryptographicallySecure);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_libq_rng_config_creation() {
        let config = RngConfig::default();
        let rng = LibQRng::with_config(&config);
        assert!(rng.is_ok());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_libq_rng_provider_creation() {
        let provider = LibQRngProvider::new();
        assert_eq!(provider.name(), "libQ RNG Provider");
        assert_eq!(provider.priority(), 100);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_libq_rng_provider_capabilities() {
        let provider = LibQRngProvider::new();
        let caps = provider.capabilities();
        assert!(caps.secure);
        assert!(caps.deterministic);
        assert!(caps.hardware);
        assert!(caps.reseeding);
        assert!(caps.custom_entropy);
        assert!(caps.no_std);
        assert!(caps.wasm);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_libq_rng_provider_create_rng() {
        let provider = LibQRngProvider::new();
        let config = RngConfig::default();
        let rng = provider.create_rng(&config);
        assert!(rng.is_ok());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_libq_rng_reseed_counter() {
        let mut seed = [0u8; 32];
        seed[..4].copy_from_slice(&[1, 2, 3, 4]);
        let rng = LibQRng::new_deterministic(seed);
        assert_eq!(rng.reseed_counter(), 0);
        assert_eq!(rng.bytes_generated(), 0);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_libq_rng_entropy_source_info() {
        let mut seed = [0u8; 32];
        seed[..4].copy_from_slice(&[1, 2, 3, 4]);
        let rng = LibQRng::new_deterministic(seed);
        assert!(!rng.entropy_source_name().is_empty());
        assert_eq!(
            rng.entropy_source_type(),
            crate::traits::EntropySourceType::Deterministic
        );
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_libq_rng_display() {
        let mut seed = [0u8; 32];
        seed[..4].copy_from_slice(&[1, 2, 3, 4]);
        let rng = LibQRng::new_deterministic(seed);
        let display = format!("{rng}");
        assert!(display.contains("LibQRng"));
        assert!(display.contains("Deterministic"));
    }
}
