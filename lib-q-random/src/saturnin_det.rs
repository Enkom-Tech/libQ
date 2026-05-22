//! Saturnin CTR deterministic byte expansion (optional `deterministic-saturnin` feature).

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use lib_q_saturnin::SaturninStream;

use crate::Result;
use crate::kt128_expander::DOMAIN_LIBQ_DET_SATURNIN;

const NONCE_LEN: usize = 16;
const KEY_LEN: usize = 32;
const CHUNK: usize = 4096;

/// Deterministic Saturnin CTR keystream expander for testing.
pub struct SaturninDetExpander {
    key: [u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    keystream: Vec<u8>,
    position: usize,
    counter: u64,
}

impl SaturninDetExpander {
    /// Build from a 32-byte seed (used directly as the Saturnin key).
    ///
    /// # Errors
    ///
    /// Returns an error if keystream generation fails.
    pub fn from_seed_32(seed: [u8; 32]) -> Result<Self> {
        let mut nonce = [0u8; NONCE_LEN];
        let domain = DOMAIN_LIBQ_DET_SATURNIN;
        let copy_len = core::cmp::min(NONCE_LEN, domain.len());
        nonce[..copy_len].copy_from_slice(&domain[..copy_len]);

        let stream = SaturninStream::new();
        let keystream = stream
            .generate_keystream(&seed, &nonce, CHUNK)
            .map_err(|_| crate::Error::platform_rng_failed("saturnin"))?;

        Ok(Self {
            key: seed,
            nonce,
            keystream: keystream.to_vec(),
            position: 0,
            counter: 0,
        })
    }

    fn refill(&mut self) -> Result<()> {
        self.counter = self.counter.wrapping_add(1);
        let mut nonce = self.nonce;
        nonce[8..16].copy_from_slice(&self.counter.to_le_bytes());
        let stream = SaturninStream::new();
        let chunk = stream
            .generate_keystream(&self.key, &nonce, CHUNK)
            .map_err(|_| crate::Error::platform_rng_failed("saturnin"))?;
        self.keystream = chunk.to_vec();
        self.position = 0;
        Ok(())
    }

    /// Fill `dest` with deterministic keystream bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if keystream refill fails.
    pub fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        let mut remaining = dest.len();
        let mut offset = 0;
        while remaining > 0 {
            if self.position >= self.keystream.len() {
                self.refill()?;
            }
            let available = self.keystream.len() - self.position;
            let to_copy = core::cmp::min(remaining, available);
            dest[offset..offset + to_copy]
                .copy_from_slice(&self.keystream[self.position..self.position + to_copy]);
            self.position += to_copy;
            offset += to_copy;
            remaining -= to_copy;
        }
        Ok(())
    }
}

/// Entropy source adapter for [`SaturninDetExpander`].
#[cfg(feature = "alloc")]
pub struct SaturninDeterministicEntropySource {
    expander: SaturninDetExpander,
    quality: f64,
}

#[cfg(feature = "alloc")]
impl SaturninDeterministicEntropySource {
    /// Create a Saturnin CTR-backed deterministic entropy source.
    ///
    /// # Errors
    ///
    /// Returns an error if Saturnin keystream initialization fails.
    pub fn new(seed: [u8; 32]) -> Result<Self> {
        Ok(Self {
            expander: SaturninDetExpander::from_seed_32(seed)?,
            quality: 0.0,
        })
    }
}

#[cfg(feature = "alloc")]
impl crate::traits::EntropySource for SaturninDeterministicEntropySource {
    fn get_entropy(&mut self, dest: &mut [u8]) -> Result<()> {
        self.expander.fill_bytes(dest)
    }

    fn initialize(&mut self, config: &crate::traits::EntropyConfig) -> Result<()> {
        let _ = config;
        Ok(())
    }

    fn is_available(&self) -> bool {
        true
    }

    fn quality(&self) -> f64 {
        self.quality
    }

    fn name(&self) -> &'static str {
        "Saturnin Deterministic Entropy Source"
    }

    fn source_type(&self) -> crate::traits::EntropySourceType {
        crate::traits::EntropySourceType::Deterministic
    }

    fn max_entropy_per_call(&self) -> Option<usize> {
        None
    }
}

#[cfg(all(test, feature = "deterministic-saturnin"))]
mod tests {
    use super::*;
    use crate::kt128_expander::Kt128Expander;

    #[test]
    fn saturnin_det_differs_from_kt128_det() {
        let seed = [3u8; 32];
        let mut sat = SaturninDetExpander::from_seed_32(seed).expect("saturnin");
        let mut kt = Kt128Expander::from_det_seed_32(seed);
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        sat.fill_bytes(&mut a).expect("fill");
        kt.fill_bytes(&mut b);
        assert_ne!(a, b);
    }
}
