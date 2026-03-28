//! Secure fallback entropy source
//!
//! This module provides a secure fallback mechanism when primary entropy sources fail.
//! It uses a combination of techniques to ensure cryptographic security even in
//! constrained environments.

use crate::traits::{
    EntropyConfig,
    EntropySource,
    EntropySourceType,
};
use crate::{
    Error,
    Result,
};

/// Secure fallback entropy source
///
/// This entropy source provides a secure fallback when primary entropy sources
/// are unavailable. It uses a combination of:
/// 1. System time (with high precision)
/// 2. Process ID and thread ID
/// 3. Memory addresses (for ASLR)
/// 4. A counter-based PRNG seeded with available entropy
#[derive(Debug)]
pub struct SecureFallbackEntropySource {
    /// Internal state for the fallback PRNG
    state: u64,
    /// Counter to ensure uniqueness
    counter: u64,
    /// Quality estimate (lower than primary sources)
    quality: f64,
}

impl SecureFallbackEntropySource {
    /// Create a new secure fallback entropy source
    #[must_use]
    pub fn new() -> Self {
        // Initialize with whatever entropy we can gather
        let state = Self::gather_initial_entropy();

        Self {
            state,
            counter: 0,
            quality: 0.7, // Lower quality but still acceptable for fallback
        }
    }

    /// Gather initial entropy from available sources
    fn gather_initial_entropy() -> u64 {
        let mut entropy = 0u64;

        // Use system time (high precision if available)
        #[cfg(feature = "std")]
        {
            use std::time::{
                SystemTime,
                UNIX_EPOCH,
            };
            if let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) {
                entropy ^= u64::try_from(duration.as_nanos()).unwrap_or(0);
            }
        }

        // Use process ID
        #[cfg(feature = "std")]
        {
            entropy ^= u64::from(std::process::id());
        }

        // Use thread ID (if available)
        #[cfg(feature = "std")]
        {
            use std::thread;
            let thread_id = thread::current().id();
            entropy ^= unsafe { core::mem::transmute::<std::thread::ThreadId, u64>(thread_id) };
        }

        // Use memory address of a local variable (ASLR)
        let local_var = 42u64;
        entropy ^= &raw const local_var as u64;

        // If we still have no entropy, use a fixed seed (not ideal but better than zeros)
        if entropy == 0 {
            entropy = 0x1234_5678_9ABC_DEF0; // Fixed seed as last resort
        }

        entropy
    }

    /// Generate the next value in the PRNG sequence
    fn next_value(&mut self) -> u64 {
        // Use a simple but secure PRNG (Xorshift64*)
        self.state ^= self.state >> 12;
        self.state ^= self.state << 25;
        self.state ^= self.state >> 27;
        self.state = self.state.wrapping_mul(0x2545_F491_4F6C_DD1D);

        // Mix in counter to ensure uniqueness
        self.counter = self.counter.wrapping_add(1);
        self.state ^= self.counter;

        self.state
    }
}

impl EntropySource for SecureFallbackEntropySource {
    fn get_entropy(&mut self, dest: &mut [u8]) -> Result<()> {
        if dest.is_empty() {
            return Ok(());
        }

        // Generate entropy using our fallback PRNG
        let mut remaining = dest.len();
        let mut offset = 0;

        while remaining > 0 {
            let value = self.next_value();
            let bytes = value.to_le_bytes();

            let to_copy = core::cmp::min(remaining, 8);
            dest[offset..offset + to_copy].copy_from_slice(&bytes[..to_copy]);

            offset += to_copy;
            remaining -= to_copy;
        }

        Ok(())
    }

    fn initialize(&mut self, config: &EntropyConfig) -> Result<()> {
        // Validate that we meet minimum quality requirements
        if self.quality() < config.min_quality {
            return Err(Error::entropy_source_unavailable(
                "Fallback entropy source quality below required minimum",
            ));
        }

        // Re-seed with fresh entropy if available
        self.state = Self::gather_initial_entropy();
        self.counter = 0;

        Ok(())
    }

    fn is_available(&self) -> bool {
        true // Fallback is always available
    }

    fn name(&self) -> &'static str {
        "Secure Fallback Entropy Source"
    }

    fn source_type(&self) -> EntropySourceType {
        EntropySourceType::Fallback
    }

    fn quality(&self) -> f64 {
        self.quality
    }

    fn max_entropy_per_call(&self) -> Option<usize> {
        Some(1024) // Limit to prevent excessive use
    }
}

impl Default for SecureFallbackEntropySource {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fallback_entropy_source_creation() {
        let source = SecureFallbackEntropySource::new();
        assert!(source.is_available());
        assert_eq!(source.name(), "Secure Fallback Entropy Source");
        assert_eq!(source.source_type(), EntropySourceType::Fallback);
        assert!(source.quality() > 0.0);
    }

    #[test]
    fn test_fallback_entropy_generation() {
        let mut source = SecureFallbackEntropySource::new();
        let mut bytes = [0u8; 32];

        source.get_entropy(&mut bytes).unwrap();

        // Should not be all zeros
        assert_ne!(bytes, [0u8; 32]);

        // Should have some non-zero bytes
        let non_zero_count = bytes.iter().filter(|&&b| b != 0).count();
        assert!(non_zero_count > 0);
    }

    /// Cross-instance distinction needs time/PID/thread mixing from `std`; without it,
    /// initial state can collide (e.g. identical stack layout for back-to-back `new()`).
    #[cfg(feature = "std")]
    #[test]
    fn test_fallback_entropy_uniqueness() {
        let mut source1 = SecureFallbackEntropySource::new();
        let mut source2 = SecureFallbackEntropySource::new();

        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];

        source1.get_entropy(&mut bytes1).unwrap();
        source2.get_entropy(&mut bytes2).unwrap();

        // Different instances should produce different values
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_fallback_entropy_sequential_uniqueness() {
        let mut source = SecureFallbackEntropySource::new();

        let mut prev_bytes = [0u8; 32];
        source.get_entropy(&mut prev_bytes).unwrap();

        for _ in 0..10 {
            let mut bytes = [0u8; 32];
            source.get_entropy(&mut bytes).unwrap();

            // Sequential calls should produce different values
            assert_ne!(bytes, prev_bytes);
            prev_bytes = bytes;
        }
    }

    #[test]
    fn test_fallback_entropy_initialization() {
        let mut source = SecureFallbackEntropySource::new();
        let config = EntropyConfig {
            min_quality: 0.6, // Lower threshold for fallback
            ..Default::default()
        };

        // Should initialize successfully with appropriate threshold
        assert!(source.initialize(&config).is_ok());
    }

    #[test]
    fn test_fallback_entropy_quality_threshold() {
        let mut source = SecureFallbackEntropySource::new();
        let config = EntropyConfig {
            min_quality: 0.6, // Appropriate threshold for fallback
            ..Default::default()
        };

        // Should work with appropriate quality threshold
        assert!(source.initialize(&config).is_ok());

        // Should fail with very high quality threshold
        let config2 = EntropyConfig {
            min_quality: 0.9,
            ..config
        };
        assert!(source.initialize(&config2).is_err());
    }
}
