//! Random Number Generation for ML-DSA
//!
//! This module provides secure and deterministic random number generation
//! for ML-DSA operations, integrating with lib-q-random for proper
//! cryptographic security and test reproducibility.

#[cfg(feature = "random")]
use lib_q_random::{
    LibQRng,
    Result,
    SecureRng,
};

#[cfg(not(feature = "random"))]
type Result<T> = core::result::Result<T, &'static str>;

/// ML-DSA Random Number Generator
///
/// This provides a unified interface for random number generation in ML-DSA,
/// supporting both secure production use and deterministic testing.
pub struct MLDsaRng {
    #[cfg(feature = "random")]
    rng: LibQRng,
    #[cfg(not(feature = "random"))]
    fallback_seed: u64,
}

impl MLDsaRng {
    /// Create a new secure RNG for production use
    ///
    /// This uses the best available entropy source and is cryptographically secure.
    /// Should be used for key generation, signing, and other production operations.
    ///
    /// # Errors
    ///
    /// Returns an error if no secure entropy source is available.
    #[cfg(feature = "random")]
    pub fn new_secure() -> Result<Self> {
        let rng = LibQRng::new_secure()?;
        Ok(Self { rng })
    }

    /// Create a new deterministic RNG for testing
    ///
    /// This creates a deterministic RNG that will produce the same sequence
    /// of random values for the same seed. **NOT CRYPTOGRAPHICALLY SECURE**.
    ///
    /// # Arguments
    ///
    /// * `seed` - The seed value for deterministic generation
    #[cfg(feature = "random")]
    pub fn new_deterministic(seed: &[u8]) -> Self {
        let rng = LibQRng::new_deterministic(seed);
        Self { rng }
    }

    /// Create a new NIST DRBG RNG for KAT test compatibility
    ///
    /// This creates an RNG using NIST AES256-CTR-DRBG for compatibility
    /// with NIST Known Answer Tests.
    ///
    /// # Arguments
    ///
    /// * `entropy_input` - 48-byte entropy input for DRBG initialization
    #[cfg(all(feature = "random", feature = "nist-drbg"))]
    pub fn new_nist_drbg(entropy_input: [u8; 48]) -> Self {
        let rng = LibQRng::new_nist_drbg(entropy_input);
        Self { rng }
    }

    /// Fallback implementation when random feature is disabled
    #[cfg(not(feature = "random"))]
    pub fn new_secure() -> Result<Self> {
        // Use system time as fallback seed (not cryptographically secure)
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        Ok(Self {
            fallback_seed: seed,
        })
    }

    /// Fallback deterministic implementation
    #[cfg(not(feature = "random"))]
    pub fn new_deterministic(seed: &[u8]) -> Self {
        let mut seed_value = 0u64;
        for (i, &byte) in seed.iter().enumerate() {
            seed_value ^= (byte as u64) << ((i % 8) * 8);
        }
        Self {
            fallback_seed: seed_value,
        }
    }

    /// Fill a buffer with random bytes
    ///
    /// # Arguments
    ///
    /// * `dest` - Buffer to fill with random bytes
    ///
    /// # Errors
    ///
    /// Returns an error if random generation fails
    #[cfg(feature = "random")]
    pub fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        self.rng.fill_bytes_secure(dest)?;
        Ok(())
    }

    /// Fallback fill_bytes implementation
    #[cfg(not(feature = "random"))]
    pub fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        // Simple LCG fallback (NOT cryptographically secure)
        for byte in dest.iter_mut() {
            self.fallback_seed = self
                .fallback_seed
                .wrapping_mul(1103515245)
                .wrapping_add(12345);
            *byte = (self.fallback_seed >> 24) as u8;
        }
        Ok(())
    }

    /// Generate a random u32 value
    #[cfg(feature = "random")]
    pub fn next_u32(&mut self) -> Result<u32> {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Fallback u32 generation
    #[cfg(not(feature = "random"))]
    pub fn next_u32(&mut self) -> Result<u32> {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Generate a random u64 value
    #[cfg(feature = "random")]
    pub fn next_u64(&mut self) -> Result<u64> {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Fallback u64 generation
    #[cfg(not(feature = "random"))]
    pub fn next_u64(&mut self) -> Result<u64> {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Check if this RNG is deterministic
    #[cfg(feature = "random")]
    pub fn is_deterministic(&self) -> bool {
        self.rng.is_deterministic()
    }

    /// Fallback deterministic check
    #[cfg(not(feature = "random"))]
    pub fn is_deterministic(&self) -> bool {
        true // Fallback is always deterministic
    }
}

/// Global RNG instance for ML-DSA operations
///
/// This provides a thread-local RNG that can be used throughout the ML-DSA
/// implementation for consistent random number generation.
pub struct GlobalRng;

impl GlobalRng {
    /// Get or create a thread-local secure RNG
    #[cfg(feature = "random")]
    pub fn get_secure() -> Result<MLDsaRng> {
        MLDsaRng::new_secure()
    }

    /// Get or create a thread-local deterministic RNG
    #[cfg(feature = "random")]
    pub fn get_deterministic(seed: &[u8]) -> MLDsaRng {
        MLDsaRng::new_deterministic(seed)
    }

    /// Fallback secure RNG
    #[cfg(not(feature = "random"))]
    pub fn get_secure() -> Result<MLDsaRng> {
        MLDsaRng::new_secure()
    }

    /// Fallback deterministic RNG
    #[cfg(not(feature = "random"))]
    pub fn get_deterministic(seed: &[u8]) -> MLDsaRng {
        MLDsaRng::new_deterministic(seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_rng_consistency() {
        let seed = b"test_seed_12345";
        let mut rng1 = MLDsaRng::new_deterministic(seed);
        let mut rng2 = MLDsaRng::new_deterministic(seed);

        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];

        rng1.fill_bytes(&mut bytes1).unwrap();
        rng2.fill_bytes(&mut bytes2).unwrap();

        assert_eq!(
            bytes1, bytes2,
            "Deterministic RNG should produce identical outputs"
        );
    }

    #[test]
    fn test_rng_deterministic_flag() {
        let seed = b"test_seed";
        let rng = MLDsaRng::new_deterministic(seed);
        assert!(
            rng.is_deterministic(),
            "Deterministic RNG should report as deterministic"
        );
    }

    #[test]
    fn test_rng_generates_different_values() {
        let mut rng = MLDsaRng::new_deterministic(b"seed1");
        let val1 = rng.next_u32().unwrap();
        let val2 = rng.next_u32().unwrap();

        // Very unlikely to be equal (but not impossible)
        // This is more of a sanity check
        assert_ne!(val1, val2, "RNG should generate different values");
    }

    #[test]
    fn test_entropy_quality_no_duplicates() {
        // Test that consecutive entropy calls never produce identical output
        let mut rng = MLDsaRng::new_secure().expect("Secure RNG should be available in tests");

        let mut prev_bytes = [0u8; 32];
        rng.fill_bytes(&mut prev_bytes)
            .expect("RNG should not fail");

        // Test 100 consecutive calls - none should be identical
        for i in 0..100 {
            let mut current_bytes = [0u8; 32];
            rng.fill_bytes(&mut current_bytes)
                .expect("RNG should not fail");

            assert_ne!(
                prev_bytes, current_bytes,
                "Consecutive entropy call {} produced identical output - entropy source may be compromised",
                i
            );

            prev_bytes = current_bytes;
        }
    }

    #[test]
    fn test_entropy_quality_distribution() {
        // Test that entropy has reasonable distribution (not all zeros or all ones)
        let mut rng = MLDsaRng::new_secure().expect("Secure RNG should be available in tests");

        let mut total_bytes = 0u32;
        let mut zero_bytes = 0u32;
        let mut max_bytes = 0u32;

        // Collect statistics over 1000 bytes
        for _ in 0..1000 {
            let mut bytes = [0u8; 1];
            rng.fill_bytes(&mut bytes).expect("RNG should not fail");

            total_bytes += 1;
            if bytes[0] == 0 {
                zero_bytes += 1;
            }
            if bytes[0] == 0xFF {
                max_bytes += 1;
            }
        }

        // Check that we don't have pathological distributions
        let zero_ratio = zero_bytes as f32 / total_bytes as f32;
        let max_ratio = max_bytes as f32 / total_bytes as f32;

        // Should not have more than 10% zeros or 0xFF bytes (pathological)
        assert!(
            zero_ratio < 0.1,
            "Too many zero bytes: {}% (entropy source may be biased)",
            zero_ratio * 100.0
        );

        assert!(
            max_ratio < 0.1,
            "Too many 0xFF bytes: {}% (entropy source may be biased)",
            max_ratio * 100.0
        );
    }

    #[test]
    fn test_deterministic_vs_secure_different() {
        // Test that deterministic and secure RNGs produce different outputs
        let seed = b"test_seed_for_comparison";

        let mut det_rng = MLDsaRng::new_deterministic(seed);
        let mut secure_rng =
            MLDsaRng::new_secure().expect("Secure RNG should be available in tests");

        let mut det_bytes = [0u8; 32];
        let mut secure_bytes = [0u8; 32];

        det_rng
            .fill_bytes(&mut det_bytes)
            .expect("RNG should not fail");
        secure_rng
            .fill_bytes(&mut secure_bytes)
            .expect("RNG should not fail");

        // They should be different (very high probability)
        assert_ne!(
            det_bytes, secure_bytes,
            "Deterministic and secure RNGs should produce different outputs"
        );
    }

    #[test]
    fn test_different_seeds_produce_different_outputs() {
        // Test that different seeds produce different outputs
        let seed1 = b"seed_one_12345";
        let seed2 = b"seed_two_67890";

        let mut rng1 = MLDsaRng::new_deterministic(seed1);
        let mut rng2 = MLDsaRng::new_deterministic(seed2);

        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];

        rng1.fill_bytes(&mut bytes1).expect("RNG should not fail");
        rng2.fill_bytes(&mut bytes2).expect("RNG should not fail");

        assert_ne!(
            bytes1, bytes2,
            "Different seeds should produce different outputs"
        );
    }

    #[test]
    fn test_rng_state_isolation() {
        // Test that RNG instances don't interfere with each other
        let seed = b"isolation_test_seed";

        let mut rng1 = MLDsaRng::new_deterministic(seed);
        let mut rng2 = MLDsaRng::new_deterministic(seed);

        // Generate some bytes from rng1
        let mut bytes1 = [0u8; 16];
        rng1.fill_bytes(&mut bytes1).expect("RNG should not fail");

        // Generate bytes from rng2 - should be identical to rng1's first output
        let mut bytes2 = [0u8; 16];
        rng2.fill_bytes(&mut bytes2).expect("RNG should not fail");

        assert_eq!(
            bytes1, bytes2,
            "Identical RNG instances should produce identical outputs"
        );

        // Continue with rng1
        let mut bytes1_cont = [0u8; 16];
        rng1.fill_bytes(&mut bytes1_cont)
            .expect("RNG should not fail");

        // Continue with rng2
        let mut bytes2_cont = [0u8; 16];
        rng2.fill_bytes(&mut bytes2_cont)
            .expect("RNG should not fail");

        assert_eq!(
            bytes1_cont, bytes2_cont,
            "RNG instances should maintain independent state"
        );
    }

    #[test]
    fn test_entropy_source_availability() {
        // Test that secure RNG can be created (entropy source is available)
        let rng = MLDsaRng::new_secure();
        assert!(
            rng.is_ok(),
            "Secure RNG should be available - entropy source may be unavailable"
        );

        let rng = rng.unwrap();
        assert!(
            !rng.is_deterministic(),
            "Secure RNG should not be deterministic"
        );
    }
}
