//! Cryptographic random number generation utilities

#[cfg(feature = "hash")]
use alloc::format;

#[cfg(feature = "alloc")]
use crate::error::HpkeError;

/// Trait for cryptographic random number generation
pub trait CryptoRng {
    /// Fill a buffer with random bytes
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), HpkeError>;

    /// Generate a random u32
    fn next_u32(&mut self) -> Result<u32, HpkeError>;

    /// Generate a random u64
    fn next_u64(&mut self) -> Result<u64, HpkeError>;
}

// Use the unified Kt128Rng (KangarooTwelve KT128) from lib-q-random
pub use lib_q_random::Kt128Rng;

// Implement HPKE-specific CryptoRng trait for Kt128Rng
#[cfg(feature = "hash")]
impl CryptoRng for Kt128Rng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), HpkeError> {
        use rand_core::Rng;
        Rng::fill_bytes(self, dest);
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

/// Alternative: KMAC-based RNG (excellent for HPKE integration)
///
/// This uses KMAC256 which is already used in HPKE's KDF, providing
/// consistency across the protocol.
#[cfg(feature = "hash")]
pub struct KmacRng {
    counter: u64,
    buffer: [u8; 32],
    position: usize,
}

#[cfg(feature = "hash")]
impl KmacRng {
    /// Create a new KMAC-based RNG with system entropy
    pub fn new() -> Result<Self, HpkeError> {
        let mut seed = [0u8; 32];
        lib_q_random::fill_entropy(&mut seed)
            .map_err(|e| HpkeError::CryptoError(alloc::format!("Entropy unavailable: {}", e)))?;
        Self::from_seed(&seed)
    }

    /// Create a new KMAC-based RNG with explicit seed.
    ///
    /// Returns an error if fixed-length KMAC output cannot be produced (for example, if the
    /// requested output length exceeds the implementation cap).
    pub fn from_seed(seed: &[u8]) -> Result<Self, HpkeError> {
        let kmac = lib_q_hash::Kmac256::new(seed, b"HPKE-RNG");
        let mut buffer = [0u8; 32];
        kmac.finalize(&mut buffer).ok_or_else(|| {
            HpkeError::CryptoError(format!(
                "KMAC256 finalize rejected {}-byte output (implementation output cap)",
                buffer.len()
            ))
        })?;

        Ok(Self {
            counter: 0,
            buffer,
            position: 0,
        })
    }

    /// Generate next block of random data
    fn next_block(&mut self) -> Result<(), HpkeError> {
        let mut kmac = lib_q_hash::Kmac256::new(&self.buffer, b"HPKE-RNG");
        kmac.update(&self.counter.to_le_bytes());
        kmac.finalize(&mut self.buffer).ok_or_else(|| {
            HpkeError::CryptoError(format!(
                "KMAC256 finalize rejected {}-byte output (implementation output cap)",
                self.buffer.len()
            ))
        })?;
        self.counter = self.counter.wrapping_add(1);
        self.position = 0;
        Ok(())
    }
}

#[cfg(feature = "hash")]
impl CryptoRng for KmacRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), HpkeError> {
        let mut remaining = dest.len();
        let mut offset = 0;

        while remaining > 0 {
            if self.position >= self.buffer.len() {
                self.next_block()?;
            }

            let available = self.buffer.len() - self.position;
            let to_copy = core::cmp::min(remaining, available);

            dest[offset..offset + to_copy]
                .copy_from_slice(&self.buffer[self.position..self.position + to_copy]);

            self.position += to_copy;
            offset += to_copy;
            remaining -= to_copy;
        }

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

/// Simple PRNG implementation for testing
pub struct SimpleRng {
    counter: u64,
}

impl Default for SimpleRng {
    fn default() -> Self {
        Self::new()
    }
}

impl SimpleRng {
    /// Create a new simple PRNG
    pub fn new() -> Self {
        Self { counter: 0 }
    }

    /// Create a new simple PRNG with seed
    pub fn from_seed(seed: u64) -> Self {
        Self { counter: seed }
    }
}

impl CryptoRng for SimpleRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), HpkeError> {
        for byte in dest.iter_mut() {
            *byte = (self.counter as u8).wrapping_add(0x42);
            self.counter = self.counter.wrapping_add(1);
        }
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

/// Cryptographic RNG backed by [`fill_random_bytes`] (OS / platform entropy via `lib-q-random`).
///
/// This is the default RNG for [`crate::HpkeContext`] production paths (setup and single-shot seal).
#[derive(Clone, Copy, Debug, Default)]
pub struct EntropyCryptoRng;

impl CryptoRng for EntropyCryptoRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), HpkeError> {
        fill_random_bytes(dest)
    }

    fn next_u32(&mut self) -> Result<u32, HpkeError> {
        random_u32()
    }

    fn next_u64(&mut self) -> Result<u64, HpkeError> {
        random_u64()
    }
}

/// Fill a buffer with random bytes using system entropy.
///
/// Uses lib-q-random's entropy source. Returns an error if secure entropy
/// is not available (e.g. when the `getrandom` feature is disabled).
pub fn fill_random_bytes(dest: &mut [u8]) -> Result<(), HpkeError> {
    lib_q_random::fill_entropy(dest)
        .map_err(|e| HpkeError::CryptoError(alloc::format!("Entropy unavailable: {}", e)))
}

/// Generate a random u32 using system entropy
pub fn random_u32() -> Result<u32, HpkeError> {
    let mut bytes = [0u8; 4];
    fill_random_bytes(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

/// Generate a random u64 using system entropy
pub fn random_u64() -> Result<u64, HpkeError> {
    let mut bytes = [0u8; 8];
    fill_random_bytes(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_rng() {
        let mut rng = SimpleRng::new();

        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes).unwrap();

        // Check that we got some non-zero bytes
        assert!(bytes.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_rng_determinism() {
        let mut rng1 = SimpleRng::from_seed(42);
        let mut rng2 = SimpleRng::from_seed(42);

        let val1 = rng1.next_u32().unwrap();
        let val2 = rng2.next_u32().unwrap();

        assert_eq!(val1, val2);
    }

    #[test]
    fn test_fill_random_bytes() {
        let mut bytes = [0u8; 32];
        fill_random_bytes(&mut bytes).unwrap();

        // Check that we got some non-zero bytes
        assert!(bytes.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_random_u32() {
        let mut rng = SimpleRng::new();
        let val1 = rng.next_u32().unwrap();
        let val2 = rng.next_u32().unwrap();

        // Very unlikely to be equal
        assert_ne!(val1, val2);
    }

    #[test]
    fn test_random_u64() {
        let mut rng = SimpleRng::new();
        let val1 = rng.next_u64().unwrap();
        let val2 = rng.next_u64().unwrap();

        // Very unlikely to be equal
        assert_ne!(val1, val2);
    }

    #[test]
    fn test_simple_rng_fill_bytes_pattern() {
        let mut rng = SimpleRng::from_seed(0);
        let mut bytes = [0u8; 4];
        rng.fill_bytes(&mut bytes).unwrap();
        assert_eq!(bytes, [0x42, 0x43, 0x44, 0x45]);
    }

    #[test]
    fn test_simple_rng_from_seed_u64_output() {
        let mut rng = SimpleRng::from_seed(2);
        let value = rng.next_u64().unwrap();
        assert_eq!(
            value,
            u64::from_le_bytes([0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B])
        );
    }

    #[cfg(feature = "hash")]
    #[test]
    fn test_kmac_rng_from_seed_is_deterministic() {
        let mut rng1 = KmacRng::from_seed(b"deterministic-seed").unwrap();
        let mut rng2 = KmacRng::from_seed(b"deterministic-seed").unwrap();
        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];
        rng1.fill_bytes(&mut out1).unwrap();
        rng2.fill_bytes(&mut out2).unwrap();
        assert_eq!(out1, out2);
    }

    #[cfg(feature = "hash")]
    #[test]
    fn test_kmac_rng_next_u32_and_u64_progress() {
        let mut rng = KmacRng::from_seed(b"another-seed").unwrap();
        let a = rng.next_u32().unwrap();
        let b = rng.next_u32().unwrap();
        let c = rng.next_u64().unwrap();
        assert_ne!(a, b);
        assert_ne!(c, 0);
    }
}
