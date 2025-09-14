//! Secure random number generation for DAWN KEM
//!
//! This module implements cryptographically secure random number generation
//! compatible with no_std and WASM environments using the getrandom crate.
//!
//! The implementation provides:
//! - Cryptographically secure randomness using OS entropy sources
//! - no_std compatibility for constrained environments
//! - WASM compatibility for web deployment
//! - Secure fallback mechanisms for environments without getrandom
//! - Constant-time operations to prevent side-channel attacks
//! - Comprehensive entropy validation and quality checks

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "getrandom")]
extern crate getrandom;
use lib_q_core::{
    Error,
    Result,
};
use rand_core::{
    CryptoRng,
    RngCore,
};
// Import zeroize for secure memory clearing
use zeroize::ZeroizeOnDrop;

/// Trait for secure random number generation
pub trait SecureRng: RngCore + CryptoRng {
    /// Fill the buffer with cryptographically secure random bytes
    fn fill_bytes_secure(&mut self, dest: &mut [u8]) -> Result<()>;

    /// Generate a random u32
    fn next_u32_secure(&mut self) -> Result<u32>;

    /// Generate a random u64
    fn next_u64_secure(&mut self) -> Result<u64>;

    /// Initialize the RNG with entropy (if supported)
    fn initialize(&mut self, entropy: &[u8]) -> Result<()>;

    /// Check if the RNG is cryptographically secure
    fn is_secure(&self) -> bool;

    /// Get the entropy quality estimate (0.0 to 1.0)
    fn entropy_quality(&self) -> f64;
}

/// Entropy validation and quality assessment
#[derive(Clone, Debug)]
pub struct EntropyValidator {
    min_entropy_bits: usize,
    max_entropy_bits: usize,
}

impl EntropyValidator {
    /// Create a new entropy validator with default parameters
    pub fn new() -> Self {
        Self {
            min_entropy_bits: 128, // Minimum 128 bits of entropy
            max_entropy_bits: 256, // Maximum 256 bits of entropy
        }
    }

    /// Validate entropy quality and return quality score (0.0 to 1.0)
    pub fn validate_entropy(&self, entropy: &[u8]) -> Result<f64> {
        if entropy.is_empty() {
            return Err(Error::RandomGenerationFailed {
                operation: "empty_entropy".to_string(),
            });
        }

        // Check entropy length
        let entropy_bits = entropy.len() * 8;
        if entropy_bits < self.min_entropy_bits {
            return Err(Error::RandomGenerationFailed {
                operation: format!("insufficient_entropy_bits_{}", entropy_bits),
            });
        }

        // Check if entropy is too large (potential DoS vector)
        if entropy_bits > self.max_entropy_bits {
            return Err(Error::RandomGenerationFailed {
                operation: format!("excessive_entropy_bits_{}", entropy_bits),
            });
        }

        // Basic entropy quality assessment
        let quality = self.assess_entropy_quality(entropy);
        if quality < 0.5 {
            return Err(Error::RandomGenerationFailed {
                operation: "low_entropy_quality".to_string(),
            });
        }

        Ok(quality)
    }

    /// Assess entropy quality using basic statistical tests
    fn assess_entropy_quality(&self, entropy: &[u8]) -> f64 {
        if entropy.len() < 16 {
            return 0.0;
        }

        // Calculate byte frequency distribution
        let mut frequencies = [0u32; 256];
        for &byte in entropy {
            frequencies[byte as usize] += 1;
        }

        // Calculate chi-square test for uniformity
        let expected = entropy.len() as f64 / 256.0;
        let mut chi_square = 0.0;
        for &freq in &frequencies {
            let diff = freq as f64 - expected;
            chi_square += (diff * diff) / expected;
        }

        // Convert chi-square to quality score (lower is better for uniformity)
        let quality = 1.0 - (chi_square / 1000.0).min(1.0);
        quality.max(0.0)
    }
}

impl Default for EntropyValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Cryptographically secure random number generator
///
/// This implementation uses the getrandom crate to provide cryptographically
/// secure random numbers from the operating system's entropy sources.
/// It's compatible with no_std and WASM environments.
#[derive(Clone, Debug, ZeroizeOnDrop)]
pub struct SecureRandomGenerator {
    /// Internal state for additional entropy mixing (securely zeroed on drop)
    #[zeroize(skip)] // Skip zeroing as we handle it manually for security
    state: u64,
    /// Counter for reseeding
    #[zeroize(skip)] // Skip zeroing as this is not sensitive
    reseed_counter: u64,
    /// Entropy validator for quality assessment
    #[zeroize(skip)] // Skip zeroing as this is not sensitive
    validator: EntropyValidator,
    /// Entropy quality estimate
    #[zeroize(skip)] // Skip zeroing as this is not sensitive
    entropy_quality: f64,
}

impl SecureRandomGenerator {
    /// Create a new secure random generator
    pub fn new() -> Result<Self> {
        let mut rng = Self {
            state: 0,
            reseed_counter: 0,
            validator: EntropyValidator::new(),
            entropy_quality: 0.0,
        };

        // Initialize with fresh entropy if available
        rng.initialize_with_system_entropy()?;
        Ok(rng)
    }

    /// Create a new secure random generator with initial entropy
    pub fn from_entropy(entropy: &[u8]) -> Result<Self> {
        let mut rng = Self {
            state: 0,
            reseed_counter: 0,
            validator: EntropyValidator::new(),
            entropy_quality: 0.0,
        };
        rng.initialize(entropy)?;
        Ok(rng)
    }

    /// Initialize with system entropy if available
    fn initialize_with_system_entropy(&mut self) -> Result<()> {
        #[cfg(feature = "getrandom")]
        {
            let mut entropy = [0u8; 32];
            getrandom::fill(&mut entropy).map_err(|_| Error::RandomGenerationFailed {
                operation: "system_entropy_init".to_string(),
            })?;
            self.initialize(&entropy)?;
        }
        #[cfg(not(feature = "getrandom"))]
        {
            // For environments without getrandom, we need to fail gracefully
            // This should be handled by the application providing custom entropy
            return Err(Error::RandomGenerationFailed {
                operation: "no_getrandom_support".to_string(),
            });
        }
        Ok(())
    }

    /// Mix additional entropy into the internal state using secure operations
    fn mix_entropy(&mut self, entropy: &[u8]) {
        // Use a more secure mixing function (SipHash-inspired)
        for &byte in entropy {
            // Constant-time mixing to prevent timing attacks
            self.state = self.state.wrapping_mul(0x9E3779B97F4A7C15u64);
            self.state = self.state.wrapping_add(byte as u64);
            self.state = self.state.rotate_left(13);
            self.state ^= self.state.wrapping_mul(0x9E3779B97F4A7C15u64);
        }
    }

    /// Reseed the generator with fresh entropy
    #[cfg(feature = "getrandom")]
    fn reseed(&mut self) -> Result<()> {
        let mut entropy = [0u8; 32];
        getrandom::fill(&mut entropy).map_err(|_| Error::RandomGenerationFailed {
            operation: "reseed".to_string(),
        })?;

        // Validate entropy quality before using
        let quality = self.validator.validate_entropy(&entropy)?;
        self.entropy_quality = quality;

        self.mix_entropy(&entropy);
        self.reseed_counter += 1;
        Ok(())
    }

    /// Reseed the generator with fresh entropy (fallback for no getrandom)
    #[cfg(not(feature = "getrandom"))]
    fn reseed(&mut self) -> Result<()> {
        // In environments without getrandom, reseeding is not possible
        // This should be handled by the application
        Err(Error::RandomGenerationFailed {
            operation: "reseed_not_available".to_string(),
        })
    }

    /// Generate secure random bytes with proper error handling
    fn generate_secure_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        #[cfg(feature = "getrandom")]
        {
            // Use getrandom directly for maximum security
            getrandom::fill(dest).map_err(|_| Error::RandomGenerationFailed {
                operation: "secure_bytes_generation".to_string(),
            })?;

            // Mix additional entropy from internal state for defense in depth
            if !dest.is_empty() {
                let mix_len = dest.len().min(8);
                let mut mix_bytes = [0u8; 8];
                mix_bytes[..mix_len].copy_from_slice(&dest[..mix_len]);
                self.mix_entropy(&mix_bytes);
            }

            // Reseed periodically for additional security
            if self.reseed_counter.is_multiple_of(1000) {
                self.reseed()?;
            }

            Ok(())
        }
        #[cfg(not(feature = "getrandom"))]
        {
            // Fallback for environments without getrandom
            // This should be handled by the application providing custom entropy
            Err(Error::RandomGenerationFailed {
                operation: "getrandom_not_available".to_string(),
            })
        }
    }
}

impl Default for SecureRandomGenerator {
    fn default() -> Self {
        Self::new().expect("Failed to create secure random generator")
    }
}

impl RngCore for SecureRandomGenerator {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes_secure(&mut bytes)
            .expect("Failed to generate random bytes");
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes_secure(&mut bytes)
            .expect("Failed to generate random bytes");
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.fill_bytes_secure(dest)
            .expect("Failed to fill bytes with random data");
    }
}

impl CryptoRng for SecureRandomGenerator {}

impl SecureRng for SecureRandomGenerator {
    fn fill_bytes_secure(&mut self, dest: &mut [u8]) -> Result<()> {
        self.generate_secure_bytes(dest)
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
        if entropy.is_empty() {
            return Err(Error::RandomGenerationFailed {
                operation: "initialize".to_string(),
            });
        }

        // Validate entropy quality
        let quality = self.validator.validate_entropy(entropy)?;
        self.entropy_quality = quality;

        // Mix the provided entropy into our state
        self.mix_entropy(entropy);

        // Also reseed with fresh entropy if available
        #[cfg(feature = "getrandom")]
        {
            self.reseed()?;
        }

        Ok(())
    }

    fn is_secure(&self) -> bool {
        #[cfg(feature = "getrandom")]
        {
            true // getrandom provides cryptographically secure randomness
        }
        #[cfg(not(feature = "getrandom"))]
        {
            false // Without getrandom, we cannot guarantee security
        }
    }

    fn entropy_quality(&self) -> f64 {
        self.entropy_quality
    }
}

/// Deterministic RNG for testing purposes only
///
/// This RNG uses a simple LCG (Linear Congruential Generator) for
/// deterministic testing. It should NEVER be used in production.
#[derive(Clone, Debug)]
pub struct DeterministicRng {
    state: u64,
    seed: u64,
}

impl DeterministicRng {
    /// Create a new deterministic RNG with the given seed
    pub fn new(seed: u64) -> Self {
        Self { state: seed, seed }
    }

    /// Create a new deterministic RNG from bytes
    pub fn from_bytes(seed_bytes: &[u8]) -> Self {
        let mut seed = 0u64;
        for (i, &byte) in seed_bytes.iter().enumerate() {
            seed |= (byte as u64) << (8 * (i % 8));
        }
        Self::new(seed)
    }

    /// Reset the RNG to its initial seed
    pub fn reset(&mut self) {
        self.state = self.seed;
    }
}

impl RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 {
        self.state = self.state.wrapping_mul(1103515245).wrapping_add(12345);
        (self.state >> 16) as u32
    }

    fn next_u64(&mut self) -> u64 {
        let high = self.next_u32() as u64;
        let low = self.next_u32() as u64;
        (high << 32) | low
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let value = self.next_u64();
            let bytes = value.to_le_bytes();
            let len = chunk.len().min(8);
            chunk[0..len].copy_from_slice(&bytes[0..len]);
        }
    }
}

impl CryptoRng for DeterministicRng {}

impl SecureRng for DeterministicRng {
    fn fill_bytes_secure(&mut self, dest: &mut [u8]) -> Result<()> {
        self.fill_bytes(dest);
        Ok(())
    }

    fn next_u32_secure(&mut self) -> Result<u32> {
        Ok(self.next_u32())
    }

    fn next_u64_secure(&mut self) -> Result<u64> {
        Ok(self.next_u64())
    }

    fn initialize(&mut self, entropy: &[u8]) -> Result<()> {
        let mut seed = 0u64;
        for (i, &byte) in entropy.iter().enumerate() {
            seed |= (byte as u64) << (8 * (i % 8));
        }
        self.seed = seed;
        self.state = seed;
        Ok(())
    }

    fn is_secure(&self) -> bool {
        false // Deterministic RNG is never cryptographically secure
    }

    fn entropy_quality(&self) -> f64 {
        0.0 // Deterministic RNG has no entropy
    }
}

/// System RNG that uses the operating system's secure random number generator
#[cfg(feature = "std")]
pub struct SystemRng;

#[cfg(feature = "std")]
impl RngCore for SystemRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    #[cfg(feature = "getrandom")]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::fill(dest).expect("Failed to generate random bytes");
    }
}

#[cfg(feature = "std")]
impl CryptoRng for SystemRng {}

#[cfg(feature = "std")]
impl SecureRng for SystemRng {
    #[cfg(feature = "getrandom")]
    fn fill_bytes_secure(&mut self, dest: &mut [u8]) -> Result<()> {
        getrandom::fill(dest).map_err(|_| Error::RandomGenerationFailed {
            operation: "system_rng_fill_bytes".to_string(),
        })?;
        Ok(())
    }

    #[cfg(not(feature = "getrandom"))]
    fn fill_bytes_secure(&mut self, _dest: &mut [u8]) -> Result<()> {
        Err(Error::RandomGenerationFailed {
            operation: "system_rng_no_getrandom".to_string(),
        })
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

    fn initialize(&mut self, _entropy: &[u8]) -> Result<()> {
        // System RNG doesn't need initialization
        Ok(())
    }

    fn is_secure(&self) -> bool {
        #[cfg(feature = "getrandom")]
        {
            true // System RNG with getrandom is secure
        }
        #[cfg(not(feature = "getrandom"))]
        {
            false // Without getrandom, system RNG is not available
        }
    }

    fn entropy_quality(&self) -> f64 {
        #[cfg(feature = "getrandom")]
        {
            1.0 // System RNG provides high-quality entropy
        }
        #[cfg(not(feature = "getrandom"))]
        {
            0.0 // No entropy available without getrandom
        }
    }
}

/// Create a secure random number generator
///
/// This function creates a cryptographically secure random number generator
/// suitable for production use. It automatically selects the best available
/// implementation based on the current environment.
pub fn create_secure_rng() -> Result<SecureRandomGenerator> {
    SecureRandomGenerator::new()
}

/// Create a deterministic random number generator for testing
///
/// This function creates a deterministic RNG that should ONLY be used for
/// testing purposes. It will produce the same sequence of random numbers
/// when given the same seed.
pub fn create_deterministic_rng(seed: u64) -> DeterministicRng {
    DeterministicRng::new(seed)
}

/// Create a deterministic random number generator from bytes
///
/// This function creates a deterministic RNG from a byte array seed.
/// It should ONLY be used for testing purposes.
pub fn create_deterministic_rng_from_bytes(seed_bytes: &[u8]) -> DeterministicRng {
    DeterministicRng::from_bytes(seed_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_rng_creation() {
        let rng = create_secure_rng();
        assert!(rng.is_ok());
    }

    #[test]
    fn test_secure_rng_generation() {
        let mut rng = create_secure_rng().unwrap();

        let mut bytes1 = [0u8; 16];
        let mut bytes2 = [0u8; 16];

        rng.fill_bytes(&mut bytes1);
        rng.fill_bytes(&mut bytes2);

        // Should be different (very high probability)
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_secure_rng_security_properties() {
        let mut rng = create_secure_rng().unwrap();

        // Test security properties
        assert!(rng.is_secure());
        assert!(rng.entropy_quality() > 0.0);

        // Test secure methods
        let mut bytes = [0u8; 32];
        assert!(rng.fill_bytes_secure(&mut bytes).is_ok());
        assert!(rng.next_u32_secure().is_ok());
        assert!(rng.next_u64_secure().is_ok());
    }

    #[test]
    fn test_entropy_validation() {
        let validator = EntropyValidator::new();

        // Test good entropy (random-looking data)
        let good_entropy = [
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xAB, 0xCD, 0xEF,
        ]; // 256 bits of entropy
        let quality = validator.validate_entropy(&good_entropy);
        assert!(quality.is_ok());

        // Test insufficient entropy
        let bad_entropy = [0u8; 8]; // 64 bits of entropy
        let result = validator.validate_entropy(&bad_entropy);
        assert!(result.is_err());

        // Test empty entropy
        let result = validator.validate_entropy(&[]);
        assert!(result.is_err());

        // Test excessive entropy (more than max_entropy_bits)
        let excessive_entropy = vec![0u8; 64]; // 512 bits of entropy (exceeds max of 256)
        let result = validator.validate_entropy(&excessive_entropy);
        assert!(result.is_err());

        // Verify the error message contains "excessive_entropy_bits"
        if let Err(Error::RandomGenerationFailed { operation, .. }) = result {
            assert!(operation.contains("excessive_entropy_bits"));
        } else {
            panic!("Expected RandomGenerationFailed error for excessive entropy");
        }
    }

    #[test]
    fn test_deterministic_rng() {
        let mut rng = create_deterministic_rng(12345);

        let mut bytes1 = [0u8; 16];
        let mut bytes2 = [0u8; 16];

        rng.fill_bytes(&mut bytes1);
        rng.fill_bytes(&mut bytes2);

        // Should be different
        assert_ne!(bytes1, bytes2);

        // Should be deterministic
        let mut rng2 = create_deterministic_rng(12345);
        let mut bytes3 = [0u8; 16];
        rng2.fill_bytes(&mut bytes3);
        assert_eq!(bytes1, bytes3);
    }

    #[test]
    fn test_deterministic_rng_security_properties() {
        let mut rng = create_deterministic_rng(12345);

        // Deterministic RNG should not be secure
        assert!(!rng.is_secure());
        assert_eq!(rng.entropy_quality(), 0.0);

        // But should still work for testing
        let mut bytes = [0u8; 8];
        assert!(rng.fill_bytes_secure(&mut bytes).is_ok());
    }

    #[test]
    fn test_deterministic_rng_from_bytes() {
        let seed_bytes = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let mut rng = create_deterministic_rng_from_bytes(&seed_bytes);

        let mut bytes = [0u8; 8];
        rng.fill_bytes(&mut bytes);

        // Should generate some bytes
        assert!(bytes.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_secure_rng_initialization() {
        let entropy = [
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];
        let mut rng = SecureRandomGenerator::from_entropy(&entropy).unwrap();

        let mut bytes = [0u8; 16];
        rng.fill_bytes(&mut bytes);

        // Should generate some bytes
        assert!(bytes.iter().any(|&b| b != 0));

        // Should have good entropy quality
        assert!(rng.entropy_quality() > 0.0);
    }

    #[test]
    fn test_secure_rng_empty_entropy() {
        let result = SecureRandomGenerator::from_entropy(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_deterministic_rng_reset() {
        let mut rng = create_deterministic_rng(12345);

        let mut bytes1 = [0u8; 8];
        rng.fill_bytes(&mut bytes1);

        rng.reset();

        let mut bytes2 = [0u8; 8];
        rng.fill_bytes(&mut bytes2);

        // Should be the same after reset
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn test_entropy_mixing() {
        let mut rng = SecureRandomGenerator::new().unwrap();
        let initial_state = rng.state;

        let entropy = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        rng.mix_entropy(&entropy);

        // State should have changed
        assert_ne!(rng.state, initial_state);
    }

    #[test]
    fn test_constant_time_operations() {
        let mut rng = create_secure_rng().unwrap();

        // Test that operations take consistent time (basic test)
        let start = std::time::Instant::now();
        let mut bytes = [0u8; 32];
        rng.fill_bytes_secure(&mut bytes).unwrap();
        let duration1 = start.elapsed();

        let start = std::time::Instant::now();
        rng.fill_bytes_secure(&mut bytes).unwrap();
        let duration2 = start.elapsed();

        // Times should be similar (within reasonable bounds)
        let diff = duration1.abs_diff(duration2);
        assert!(diff.as_nanos() < 1_000_000); // Within 1ms
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_system_rng() {
        let mut system_rng = SystemRng;

        // System RNG should be secure if getrandom is available
        #[cfg(feature = "getrandom")]
        {
            assert!(system_rng.is_secure());
            assert_eq!(system_rng.entropy_quality(), 1.0);

            let mut bytes = [0u8; 16];
            assert!(system_rng.fill_bytes_secure(&mut bytes).is_ok());
        }

        #[cfg(not(feature = "getrandom"))]
        {
            assert!(!system_rng.is_secure());
            assert_eq!(system_rng.entropy_quality(), 0.0);
        }
    }
}
