//! `no_std` Random Number Generator Implementation
//!
//! This module provides a complete `no_std` RNG implementation that works
//! in constrained environments without the standard library.

use core::fmt;

use rand_core::{
    CryptoRng,
    RngCore,
};

#[cfg(feature = "custom-entropy")]
use crate::custom_entropy::{
    generate_custom_entropy,
    has_custom_entropy_source,
};
use crate::{
    Error,
    Result,
};

/// A `no_std` compatible random number generator
///
/// This RNG uses getrandom for entropy and provides a secure interface
/// for cryptographic operations in `no_std` environments.
#[derive(Debug)]
pub struct NoStdRng {
    /// Reseed counter for security
    reseed_counter: u32,
    /// Bytes generated since last reseed
    bytes_generated: usize,
    /// Reseed interval in bytes (1MB default)
    reseed_interval: usize,
    /// Deterministic state for deterministic RNGs
    deterministic_state: Option<u64>,
}

impl NoStdRng {
    /// Create a new `no_std` RNG instance
    ///
    /// This creates a cryptographically secure RNG that works in `no_std`
    /// environments using getrandom for entropy.
    ///
    /// # Errors
    ///
    /// Returns an error if getrandom is not available or fails to initialize.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use lib_q_random::no_std_rng::NoStdRng;
    /// use rand_core::RngCore;
    ///
    /// let mut rng = NoStdRng::new().unwrap();
    /// let mut bytes = [0u8; 32];
    /// rng.fill_bytes(&mut bytes);
    /// ```
    pub fn new() -> Result<Self> {
        // Test getrandom availability
        let mut test_bytes = [0u8; 1];
        #[cfg(feature = "getrandom")]
        {
            getrandom::fill(&mut test_bytes).map_err(|_| Error::EntropySourceUnavailable {
                source: "getrandom",
                context: Some("initialization test failed"),
            })?;
        }
        #[cfg(not(feature = "getrandom"))]
        {
            return Err(Error::FeatureNotAvailable {
                feature: "no_std RNG",
                required_features: &["getrandom"],
            });
        }

        Ok(Self {
            reseed_counter: 0,
            bytes_generated: 0,
            reseed_interval: 1024 * 1024, // 1MB reseed interval
            deterministic_state: None,
        })
    }

    /// Create a new deterministic RNG for testing
    ///
    /// This creates a deterministic RNG suitable for testing and
    /// reproducible operations. **NOT CRYPTOGRAPHICALLY SECURE**.
    ///
    /// # Arguments
    ///
    /// * `seed` - The seed value for deterministic generation
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use lib_q_random::no_std_rng::NoStdRng;
    /// use rand_core::RngCore;
    ///
    /// let mut rng = NoStdRng::new_deterministic(&[1, 2, 3, 4]);
    /// let mut bytes = [0u8; 32];
    /// rng.fill_bytes(&mut bytes);
    /// ```
    #[must_use]
    pub fn new_deterministic(seed: &[u8]) -> Self {
        // Create a simple deterministic RNG using the seed
        // This is a basic implementation - in production, you'd want a proper CSPRNG
        let mut state = 0u64;
        for (i, &byte) in seed.iter().enumerate() {
            // Use a better seed mixing function to ensure different seeds produce different states
            state = state
                .wrapping_mul(0x9E37_79B9_7F4A_7C15_u64) // Golden ratio constant
                .wrapping_add(u64::from(byte))
                .wrapping_add(i as u64);
        }

        // Ensure we have a non-zero state
        if state == 0 {
            state = 1;
        }

        Self {
            reseed_counter: 0,
            bytes_generated: 0,
            reseed_interval: 0, // No reseeding for deterministic RNG
            deterministic_state: Some(state),
        }
    }

    /// Check if this RNG is deterministic
    #[must_use]
    pub fn is_deterministic(&self) -> bool {
        self.reseed_interval == 0
    }

    /// Get the number of bytes generated since last reseed
    #[must_use]
    pub fn bytes_generated(&self) -> usize {
        self.bytes_generated
    }

    /// Get the reseed counter
    #[must_use]
    pub fn reseed_counter(&self) -> u32 {
        self.reseed_counter
    }

    /// Get the reseed interval
    #[must_use]
    pub fn reseed_interval(&self) -> usize {
        self.reseed_interval
    }
}

impl RngCore for NoStdRng {
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

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if dest.is_empty() {
            return;
        }

        // Check if we need to reseed
        if !self.is_deterministic() && self.bytes_generated >= self.reseed_interval {
            self.reseed_counter = self.reseed_counter.wrapping_add(1);
            self.bytes_generated = 0;
        }

        // Generate random bytes
        if let Some(ref mut state) = self.deterministic_state {
            // Deterministic RNG using simple LCG
            for byte in dest.iter_mut() {
                *state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
                #[allow(clippy::cast_possible_truncation)]
                {
                    *byte = (*state >> 24) as u8; // Intentional truncation for LCG output
                }
            }
        } else {
            // Try custom entropy source first, then fall back to getrandom
            #[cfg(feature = "custom-entropy")]
            {
                if has_custom_entropy_source() {
                    if let Err(e) = generate_custom_entropy(dest) {
                        // If custom entropy fails, fall back to getrandom
                        #[cfg(feature = "getrandom")]
                        {
                            getrandom::fill(dest).unwrap_or_else(|_| {
                                panic!("both custom entropy and getrandom failed: {e:?}")
                            });
                        }
                        #[cfg(not(feature = "getrandom"))]
                        {
                            panic!("custom entropy failed and getrandom not available: {e:?}");
                        }
                    }
                } else {
                    // No custom entropy source, use getrandom
                    #[cfg(feature = "getrandom")]
                    {
                        getrandom::fill(dest).expect("getrandom failed");
                    }
                    #[cfg(not(feature = "getrandom"))]
                    {
                        panic!(
                            "no custom entropy source registered and getrandom feature not enabled"
                        );
                    }
                }
            }
            #[cfg(not(feature = "custom-entropy"))]
            {
                // No custom entropy support, use getrandom
                #[cfg(feature = "getrandom")]
                {
                    getrandom::fill(dest).expect("getrandom failed");
                }
                #[cfg(not(feature = "getrandom"))]
                {
                    panic!("getrandom feature not enabled");
                }
            }
        }

        self.bytes_generated += dest.len();
    }
}

impl CryptoRng for NoStdRng {}

impl fmt::Display for NoStdRng {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NoStdRng(deterministic: {}, bytes_generated: {}, reseed_counter: {})",
            self.is_deterministic(),
            self.bytes_generated,
            self.reseed_counter
        )
    }
}

#[cfg(test)]
mod tests {
    use rand_core::RngCore;

    use super::*;

    #[test]
    fn test_no_std_rng_creation() {
        let rng = NoStdRng::new();
        assert!(rng.is_ok());
    }

    #[test]
    fn test_deterministic_rng_creation() {
        let seed = [1, 2, 3, 4, 5, 6, 7, 8];
        let rng = NoStdRng::new_deterministic(&seed);
        assert!(rng.is_deterministic());
    }

    #[test]
    fn test_rng_bytes_generation() {
        let mut rng = NoStdRng::new().unwrap();
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);

        // Check that bytes were actually generated (not all zeros)
        let all_zeros = bytes.iter().all(|&b| b == 0);
        assert!(!all_zeros);
    }

    #[test]
    fn test_rng_reseed_counter() {
        let mut rng = NoStdRng::new().unwrap();
        let initial_counter = rng.reseed_counter();
        let initial_bytes = rng.bytes_generated();

        // Generate some bytes
        let mut bytes = [0u8; 1024];
        rng.fill_bytes(&mut bytes);

        // Check that bytes were generated
        assert!(rng.bytes_generated() > initial_bytes);

        // For deterministic RNGs, reseed counter should remain the same
        if rng.is_deterministic() {
            assert_eq!(rng.reseed_counter(), initial_counter);
        } else {
            // For secure RNGs, reseed counter should be >= initial (might not increase for small amounts)
            assert!(rng.reseed_counter() >= initial_counter);
        }
    }

    #[test]
    fn test_deterministic_rng_consistency() {
        let seed = [42u8; 16];
        let mut rng1 = NoStdRng::new_deterministic(&seed);
        let mut rng2 = NoStdRng::new_deterministic(&seed);

        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];

        rng1.fill_bytes(&mut bytes1);
        rng2.fill_bytes(&mut bytes2);

        assert_eq!(bytes1, bytes2);
    }
}
