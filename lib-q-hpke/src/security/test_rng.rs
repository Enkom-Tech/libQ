//! Test RNG for security module testing
//!
//! This module provides a deterministic RNG for testing purposes.

use lib_q_random::kt128_expander::Kt128Expander;

use crate::error::HpkeError;
use crate::security::CryptoRng;

/// Deterministic test RNG for reproducible testing (KT128 / [`lib_q_random`]).
pub struct TestRng {
    expander: Kt128Expander,
}

impl TestRng {
    /// Create a new test RNG with default seed
    pub fn new() -> Self {
        Self::with_seed(12345)
    }

    /// Create a new test RNG with specific seed (SplitMix64 → KT128, lib-Q DET domain).
    pub fn with_seed(seed: u64) -> Self {
        Self {
            expander: Kt128Expander::from_det_u64(seed),
        }
    }
}

impl CryptoRng for TestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), HpkeError> {
        self.expander.fill_bytes(dest);
        Ok(())
    }

    fn next_u32(&mut self) -> Result<u32, HpkeError> {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn next_u64(&mut self) -> Result<u64, HpkeError> {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
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

        assert!(bytes.iter().any(|&b| b != 0));
    }
}
