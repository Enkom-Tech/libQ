//! Test RNG for security module testing
//!
//! This module provides a deterministic RNG for testing purposes.

use crate::error::HpkeError;
use crate::security::CryptoRng;

/// Deterministic test RNG for reproducible testing
pub struct TestRng {
    state: u64,
}

impl TestRng {
    /// Create a new test RNG with default seed
    pub fn new() -> Self {
        Self::with_seed(12345)
    }

    /// Create a new test RNG with specific seed
    pub fn with_seed(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Generate next pseudo-random u64
    fn next_u64_internal(&mut self) -> u64 {
        // Simple linear congruential generator
        self.state = self.state.wrapping_mul(1103515245).wrapping_add(12345);
        self.state
    }
}

impl CryptoRng for TestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), HpkeError> {
        for chunk in dest.chunks_mut(8) {
            let random_u64 = self.next_u64_internal();
            let bytes = random_u64.to_le_bytes();

            for (i, &byte) in bytes.iter().enumerate() {
                if i < chunk.len() {
                    chunk[i] = byte;
                }
            }
        }
        Ok(())
    }

    fn next_u32(&mut self) -> Result<u32, HpkeError> {
        Ok(self.next_u64()? as u32)
    }

    fn next_u64(&mut self) -> Result<u64, HpkeError> {
        Ok(self.next_u64_internal())
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
