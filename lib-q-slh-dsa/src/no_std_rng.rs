//! no_std Random Number Generator for SLH-DSA
//!
//! This module provides no_std compatible RNG functionality for SLH-DSA
//! when the standard library is not available.

use rand_core::{
    Rng,
    TryCryptoRng,
    TryRng,
};

// Use a simple error type for no_std
#[derive(Debug)]
pub enum NoStdError {
    InvalidInput,
    RngFailed,
}

/// A no_std compatible random number generator for SLH-DSA
///
/// This RNG uses lib-q-random for entropy and provides a secure interface
/// for cryptographic operations in no_std environments.
#[derive(Debug)]
pub struct SlhDsaNoStdRng {
    /// Internal RNG from lib-q-random
    inner: lib_q_random::no_std_rng::NoStdRng,
}

impl SlhDsaNoStdRng {
    /// Create a new no_std RNG instance
    ///
    /// This creates a cryptographically secure RNG that works in no_std
    /// environments using lib-q-random for entropy.
    ///
    /// # Errors
    ///
    /// Returns an error if lib-q-random is not available or fails to initialize.
    pub fn new() -> Result<Self, NoStdError> {
        let inner = lib_q_random::no_std_rng::NoStdRng::new().map_err(|_| NoStdError::RngFailed)?;

        Ok(Self { inner })
    }

    /// Create a new deterministic RNG for testing
    ///
    /// This creates a deterministic RNG suitable for testing and
    /// reproducible operations. **NOT CRYPTOGRAPHICALLY SECURE**.
    ///
    /// # Arguments
    ///
    /// * `seed` - The seed value for deterministic generation
    #[must_use]
    pub fn new_deterministic(seed: &[u8]) -> Self {
        let inner = lib_q_random::no_std_rng::NoStdRng::new_deterministic(seed);
        Self { inner }
    }

    /// Check if this RNG is deterministic
    #[must_use]
    pub fn is_deterministic(&self) -> bool {
        self.inner.is_deterministic()
    }

    /// Get the number of bytes generated since last reseed
    #[must_use]
    pub fn bytes_generated(&self) -> usize {
        self.inner.bytes_generated()
    }

    /// Get the reseed counter
    #[must_use]
    pub fn reseed_counter(&self) -> u32 {
        self.inner.reseed_counter()
    }
}

impl TryRng for SlhDsaNoStdRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        Ok(self.inner.next_u32())
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        Ok(self.inner.next_u64())
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), Self::Error> {
        self.inner.fill_bytes(dest);
        Ok(())
    }
}

impl TryCryptoRng for SlhDsaNoStdRng {}

#[cfg(test)]
mod tests {
    use rand_core::Rng;

    use super::*;

    #[test]
    fn test_no_std_rng_creation() {
        let rng = SlhDsaNoStdRng::new();
        assert!(rng.is_ok());
    }

    #[test]
    fn test_deterministic_rng_creation() {
        let seed = [1, 2, 3, 4, 5, 6, 7, 8];
        let rng = SlhDsaNoStdRng::new_deterministic(&seed);
        assert!(rng.is_deterministic());
    }

    #[test]
    fn test_rng_bytes_generation() {
        let mut rng = SlhDsaNoStdRng::new().unwrap();
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);

        // Check that bytes were actually generated (not all zeros)
        let all_zeros = bytes.iter().all(|&b| b == 0);
        assert!(!all_zeros);
    }

    #[test]
    fn test_deterministic_rng_consistency() {
        let seed = [42u8; 16];
        let mut rng1 = SlhDsaNoStdRng::new_deterministic(&seed);
        let mut rng2 = SlhDsaNoStdRng::new_deterministic(&seed);

        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];

        rng1.fill_bytes(&mut bytes1);
        rng2.fill_bytes(&mut bytes2);

        assert_eq!(bytes1, bytes2);
    }
}
