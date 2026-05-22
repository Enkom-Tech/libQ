//! `no_std` Random Number Generator Implementation
//!
//! This module provides a complete `no_std` RNG implementation that works
//! in constrained environments without the standard library.

use core::fmt;

use rand_core::{
    TryCryptoRng,
    TryRng,
};

#[cfg(feature = "custom-entropy")]
use crate::custom_entropy::{
    generate_custom_entropy,
    has_custom_entropy_source,
};
use crate::kt128_expander::Kt128Expander;
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
    /// KT128 expander when constructed with [`Self::new_deterministic`]
    deterministic_rng: Option<Kt128Expander>,
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
    /// use rand_core::Rng;
    ///
    /// let mut rng = NoStdRng::new().unwrap();
    /// let mut bytes = [0u8; 32];
    /// rng.fill_bytes(&mut bytes);
    /// ```
    pub fn new() -> Result<Self> {
        #[cfg(feature = "getrandom")]
        {
            // Test getrandom availability
            let mut test_bytes = [0u8; 1];
            getrandom::fill(&mut test_bytes).map_err(|_| Error::EntropySourceUnavailable {
                source: "getrandom",
                context: Some("initialization test failed"),
            })?;

            Ok(Self {
                reseed_counter: 0,
                bytes_generated: 0,
                reseed_interval: 1024 * 1024, // 1MB reseed interval
                deterministic_rng: None,
            })
        }
        #[cfg(not(feature = "getrandom"))]
        {
            Err(Error::FeatureNotAvailable {
                feature: "no_std RNG",
                required_features: &["getrandom"],
            })
        }
    }

    /// Create a new deterministic RNG for testing
    ///
    /// This builds a KT128 XOF byte stream from a **256-bit** seed
    /// ([`Kt128Expander`] / [`crate::kt128_expander::DOMAIN_LIBQ_DET_RNG`])
    /// in libQ). Output is reproducible and suitable for KATs and benchmarks.
    ///
    /// **Security**: Unpredictability is **entirely** bounded by the secrecy of
    /// `seed`. This is **not** a substitute for [`Self::new`]: anyone who knows or
    /// guesses the seed knows the full stream. Do not use for production keys or
    /// secrets unless the seed itself is high-entropy and handled as key material.
    ///
    /// # Arguments
    ///
    /// * `seed` - 32-byte seed; distinct seeds produce unrelated streams
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use lib_q_random::no_std_rng::NoStdRng;
    /// use rand_core::Rng;
    ///
    /// let mut rng = NoStdRng::new_deterministic([1; 32]);
    /// let mut bytes = [0u8; 32];
    /// rng.fill_bytes(&mut bytes);
    /// ```
    #[must_use]
    pub fn new_deterministic(seed: [u8; 32]) -> Self {
        Self {
            reseed_counter: 0,
            bytes_generated: 0,
            reseed_interval: 0, // No reseeding for deterministic RNG
            deterministic_rng: Some(Kt128Expander::from_det_seed_32(seed)),
        }
    }

    /// Same as [`Self::new_deterministic`] but seeds via `SplitMix64` → KT128.
    #[must_use]
    pub fn new_deterministic_from_u64(seed: u64) -> Self {
        Self {
            reseed_counter: 0,
            bytes_generated: 0,
            reseed_interval: 0,
            deterministic_rng: Some(Kt128Expander::from_det_u64(seed)),
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

impl TryRng for NoStdRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), Self::Error> {
        if dest.is_empty() {
            return Ok(());
        }

        // Check if we need to reseed
        if !self.is_deterministic() && self.bytes_generated >= self.reseed_interval {
            self.reseed_counter = self.reseed_counter.wrapping_add(1);
            self.bytes_generated = 0;
        }

        // Generate random bytes
        if let Some(ref mut expander) = self.deterministic_rng {
            expander.fill_bytes(dest);
        } else {
            #[cfg(feature = "custom-entropy")]
            {
                if has_custom_entropy_source() {
                    if let Err(e) = generate_custom_entropy(dest) {
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
        Ok(())
    }
}

impl TryCryptoRng for NoStdRng {}

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
    use rand_core::Rng;

    use super::*;

    #[cfg(feature = "getrandom")]
    #[test]
    fn test_no_std_rng_creation() {
        let rng = NoStdRng::new();
        assert!(rng.is_ok());
    }

    #[test]
    fn test_deterministic_rng_creation() {
        let seed = [1u8; 32];
        let rng = NoStdRng::new_deterministic(seed);
        assert!(rng.is_deterministic());
    }

    #[cfg(feature = "getrandom")]
    #[test]
    fn test_rng_bytes_generation() {
        let mut rng = NoStdRng::new().unwrap();
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);

        // Check that bytes were actually generated (not all zeros)
        let all_zeros = bytes.iter().all(|&b| b == 0);
        assert!(!all_zeros);
    }

    #[cfg(feature = "getrandom")]
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
        let seed = [42u8; 32];
        let mut rng1 = NoStdRng::new_deterministic(seed);
        let mut rng2 = NoStdRng::new_deterministic(seed);

        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];

        rng1.fill_bytes(&mut bytes1);
        rng2.fill_bytes(&mut bytes2);

        assert_eq!(bytes1, bytes2);
    }

    /// Regression: deterministic RNG must use the full 256-bit seed (KT128), not a
    /// collapsed 64-bit state where distant seed bytes could be ignored.
    #[test]
    fn test_deterministic_seeds_differ_in_final_byte_yield_different_streams() {
        let seed_a = [0u8; 32];
        let mut seed_b = [0u8; 32];
        seed_b[31] = 1;

        let mut rng_a = NoStdRng::new_deterministic(seed_a);
        let mut rng_b = NoStdRng::new_deterministic(seed_b);

        let mut out_a = [0u8; 64];
        let mut out_b = [0u8; 64];
        rng_a.fill_bytes(&mut out_a);
        rng_b.fill_bytes(&mut out_b);

        assert_ne!(
            out_a, out_b,
            "KT128 streams from different 32-byte keys must diverge immediately"
        );
    }
}
