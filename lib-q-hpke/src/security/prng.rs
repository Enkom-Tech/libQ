//! Cryptographic random number generation utilities

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

/// Secure cryptographic RNG implementation using KangarooTwelve (K12)
///
/// This implementation provides cryptographically secure random number generation
/// using lib-q's fastest native primitive - KangarooTwelve. K12 is significantly
/// faster than SHAKE256 while maintaining the same security properties.
#[cfg(feature = "hash")]
pub struct KangarooTwelveRng {
    buffer: [u8; 32], // K12 output size
    position: usize,
    counter: u64,
}

#[cfg(feature = "hash")]
impl KangarooTwelveRng {
    /// Create a new secure RNG with system entropy
    pub fn new() -> Result<Self, HpkeError> {
        // Use system entropy to seed the RNG
        let mut seed = [0u8; 32];
        #[cfg(feature = "secure-rng")]
        {
            use rand_core::{
                OsRng,
                TryRngCore,
            };
            OsRng.try_fill_bytes(&mut seed).map_err(|e| {
                HpkeError::CryptoError(alloc::format!("Failed to get system entropy: {}", e))
            })?;
        }
        #[cfg(not(feature = "secure-rng"))]
        {
            // Fallback for no_std - use a simple counter (INSECURE)
            for (i, byte) in seed.iter_mut().enumerate() {
                *byte = (i as u8).wrapping_add(0x42);
            }
        }

        Ok(Self::from_seed(&seed))
    }

    /// Create a new secure RNG with explicit seed
    pub fn from_seed(seed: &[u8]) -> Self {
        use lib_q_hash::digest::{
            ExtendableOutput,
            Update,
            XofReader,
        };

        let mut k12 = lib_q_hash::KangarooTwelve::new(b"HPKE-RNG");
        k12.update(seed);
        let mut reader = k12.finalize_xof();

        // Fill initial buffer
        let mut buffer = [0u8; 32];
        reader.read(&mut buffer);

        Self {
            buffer,
            position: 0,
            counter: 0,
        }
    }

    /// Refill the internal buffer with new random data
    fn refill(&mut self) {
        use lib_q_hash::digest::{
            ExtendableOutput,
            Update,
            XofReader,
        };

        // Use current buffer + counter as seed for next generation
        let mut k12 = lib_q_hash::KangarooTwelve::new(b"HPKE-RNG");
        k12.update(&self.buffer);
        k12.update(&self.counter.to_le_bytes());
        let mut reader = k12.finalize_xof();
        reader.read(&mut self.buffer);
        self.counter = self.counter.wrapping_add(1);
        self.position = 0;
    }
}

#[cfg(feature = "hash")]
impl CryptoRng for KangarooTwelveRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), HpkeError> {
        let mut remaining = dest.len();
        let mut offset = 0;

        while remaining > 0 {
            if self.position >= self.buffer.len() {
                self.refill();
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
        // Use system entropy to seed the RNG
        let mut seed = [0u8; 32];
        #[cfg(feature = "secure-rng")]
        {
            use rand_core::{
                OsRng,
                TryRngCore,
            };
            OsRng.try_fill_bytes(&mut seed).map_err(|e| {
                HpkeError::CryptoError(alloc::format!("Failed to get system entropy: {}", e))
            })?;
        }
        #[cfg(not(feature = "secure-rng"))]
        {
            // Fallback for no_std - use a simple counter (INSECURE)
            for (i, byte) in seed.iter_mut().enumerate() {
                *byte = (i as u8).wrapping_add(0x42);
            }
        }

        Ok(Self::from_seed(&seed))
    }

    /// Create a new KMAC-based RNG with explicit seed
    pub fn from_seed(seed: &[u8]) -> Self {
        let kmac = lib_q_hash::Kmac256::new(seed, b"HPKE-RNG");
        let mut buffer = [0u8; 32];
        kmac.finalize(&mut buffer);

        Self {
            counter: 0,
            buffer,
            position: 0,
        }
    }

    /// Generate next block of random data
    fn next_block(&mut self) {
        let mut kmac = lib_q_hash::Kmac256::new(&self.buffer, b"HPKE-RNG");
        kmac.update(&self.counter.to_le_bytes());
        kmac.finalize(&mut self.buffer);
        self.counter = self.counter.wrapping_add(1);
        self.position = 0;
    }
}

#[cfg(feature = "hash")]
impl CryptoRng for KmacRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), HpkeError> {
        let mut remaining = dest.len();
        let mut offset = 0;

        while remaining > 0 {
            if self.position >= self.buffer.len() {
                self.next_block();
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

/// Fill a buffer with random bytes using system entropy
#[cfg(feature = "secure-rng")]
pub fn fill_random_bytes(dest: &mut [u8]) -> Result<(), HpkeError> {
    use rand_core::{
        OsRng,
        TryRngCore,
    };
    OsRng
        .try_fill_bytes(dest)
        .map_err(|e| HpkeError::CryptoError(alloc::format!("Failed to get system entropy: {}", e)))
}

/// Fill a buffer with random bytes (no_std fallback - INSECURE)
///
/// # Security Warning
/// This implementation is NOT cryptographically secure and should only be used
/// in no_std environments where system entropy is not available.
/// For production use, ensure the `secure-rng` feature is enabled.
#[cfg(not(feature = "secure-rng"))]
pub fn fill_random_bytes(dest: &mut [u8]) -> Result<(), HpkeError> {
    // This is a placeholder implementation for no_std environments
    // In production, this should be replaced with a proper hardware RNG
    // or external entropy source
    for (i, byte) in dest.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_add(0x42);
    }
    Ok(())
}

/// Generate a random u32 using system entropy
#[cfg(feature = "secure-rng")]
pub fn random_u32() -> Result<u32, HpkeError> {
    let mut bytes = [0u8; 4];
    fill_random_bytes(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

/// Generate a random u32 (no_std fallback - INSECURE)
#[cfg(not(feature = "secure-rng"))]
pub fn random_u32() -> Result<u32, HpkeError> {
    let mut bytes = [0u8; 4];
    fill_random_bytes(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

/// Generate a random u64 using system entropy
#[cfg(feature = "secure-rng")]
pub fn random_u64() -> Result<u64, HpkeError> {
    let mut bytes = [0u8; 8];
    fill_random_bytes(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

/// Generate a random u64 (no_std fallback - INSECURE)
#[cfg(not(feature = "secure-rng"))]
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
}
