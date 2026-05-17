//! Test RNG for security module testing
//!
//! This module provides a deterministic RNG for testing purposes.

use rand_chacha::ChaCha20Rng;
use rand_core::{
    Rng,
    SeedableRng,
};

use crate::error::HpkeError;
use crate::security::CryptoRng;

/// Deterministic test RNG for reproducible testing
pub struct TestRng {
    inner: ChaCha20Rng,
}

impl TestRng {
    /// Create a new test RNG with default seed
    pub fn new() -> Self {
        Self::with_seed(12345)
    }

    /// Create a new test RNG with specific seed
    pub fn with_seed(seed: u64) -> Self {
        let mut expanded = [0u8; 32];
        expanded[0..8].copy_from_slice(&seed.to_le_bytes());
        Self {
            inner: ChaCha20Rng::from_seed(expanded),
        }
    }
}

impl CryptoRng for TestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), HpkeError> {
        self.inner.fill_bytes(dest);
        Ok(())
    }

    fn next_u32(&mut self) -> Result<u32, HpkeError> {
        Ok(self.inner.next_u32())
    }

    fn next_u64(&mut self) -> Result<u64, HpkeError> {
        Ok(self.inner.next_u64())
    }
}

impl Default for TestRng {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_test_rng_deterministic() {
        let mut rng1 = TestRng::with_seed(42);
        let mut rng2 = TestRng::with_seed(42);

        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];

        let _ = rng1.fill_bytes(&mut bytes1);
        let _ = rng2.fill_bytes(&mut bytes2);

        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn test_test_rng_different_seeds() {
        let mut rng1 = TestRng::with_seed(42);
        let mut rng2 = TestRng::with_seed(43);

        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];

        let _ = rng1.fill_bytes(&mut bytes1);
        let _ = rng2.fill_bytes(&mut bytes2);

        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_test_rng_fill_bytes() {
        let mut rng = TestRng::new();
        let mut bytes = [0u8; 100];

        let _ = rng.fill_bytes(&mut bytes);

        // Should not be all zeros
        assert!(bytes.iter().any(|&b| b != 0));
    }
}
