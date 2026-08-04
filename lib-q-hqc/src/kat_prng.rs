//! KAT (Known Answer Test) compatible PRNG implementation
//!
//! This module provides a PRNG implementation that matches the reference HQC
//! implementation's behavior for KAT tests. The reference implementation uses
//! SHAKE-256 XOF with domain separation for random number generation.

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec;

#[cfg(feature = "random")]
use lib_q_random::traits::EntropySource;
use rand_core::{
    TryCryptoRng,
    TryRng,
};

/// SHAKE-256 based PRNG that matches the reference HQC implementation
///
/// This PRNG uses SHAKE-256 XOF with domain=0 (HQC_PRNG_DOMAIN) to generate
/// deterministic random bytes, matching the reference implementation's behavior.
pub struct Shake256KatPrng {
    xof: crate::internal::shake256::Shake256Xof,
}

impl Shake256KatPrng {
    /// Create a new SHAKE-256 KAT-compatible PRNG
    ///
    /// # Arguments
    /// * `seed` - 48-byte seed (entropy input)
    ///
    /// # Returns
    /// A new SHAKE-256 PRNG initialized matching reference prng_init exactly:
    /// 1. Absorb entropy_input (seed)
    /// 2. Absorb personalization_string (empty)
    /// 3. Absorb domain byte (HQC_PRNG_DOMAIN = 0)
    /// 4. Finalize
    pub fn new(seed: &[u8; 48]) -> Self {
        let mut xof = crate::internal::shake256::Shake256Xof::new();

        // Match reference prng_init exactly:
        // shake256_inc_absorb(&shake256_prng_ctx, entropy_input, enlen);
        xof.absorb(seed).expect("SHAKE256 absorb seed failed");

        // shake256_inc_absorb(&shake256_prng_ctx, personalization_string, perlen);
        // Even for empty personalization string, we must call absorb to match reference
        xof.absorb(&[])
            .expect("SHAKE256 absorb personalization failed");

        // shake256_inc_absorb(&shake256_prng_ctx, &domain, 1);
        const HQC_PRNG_DOMAIN: u8 = 0;
        xof.absorb(&[HQC_PRNG_DOMAIN])
            .expect("SHAKE256 absorb domain failed");

        // shake256_inc_finalize(&shake256_prng_ctx);
        xof.finalize_absorb().expect("SHAKE256 finalize failed");

        Self { xof }
    }

    /// Skip a specified number of bytes from the PRNG output
    pub fn skip(&mut self, count: usize) {
        let mut tmp = vec![0u8; count];
        self.xof.squeeze(&mut tmp).expect("SHAKE256 squeeze failed");
    }
}

impl TryRng for Shake256KatPrng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.xof.squeeze(dest).expect("SHAKE256 squeeze failed");
        Ok(())
    }
}

impl TryCryptoRng for Shake256KatPrng {}

/// KAT-compatible PRNG that matches reference implementation behavior
///
/// This PRNG is specifically designed to pass KAT tests by matching the exact
/// behavior of the reference HQC implementation, which returns the first 32 bytes
/// of the entropy input directly for the first call.
pub struct KatPrng {
    entropy_input: [u8; 48],
    bytes_consumed: usize,
}

impl KatPrng {
    /// Create a new KAT-compatible PRNG
    ///
    /// # Arguments
    /// * `entropy_input` - 48-byte entropy input
    ///
    /// # Returns
    /// A new KAT-compatible PRNG
    pub fn new(entropy_input: [u8; 48]) -> Self {
        Self {
            entropy_input,
            bytes_consumed: 0,
        }
    }
}

#[cfg(feature = "random")]
impl EntropySource for KatPrng {
    fn get_entropy(&mut self, dest: &mut [u8]) -> lib_q_random::Result<()> {
        let remaining = self.entropy_input.len() - self.bytes_consumed;
        let to_copy = dest.len().min(remaining);

        if to_copy > 0 {
            dest[..to_copy].copy_from_slice(
                &self.entropy_input[self.bytes_consumed..self.bytes_consumed + to_copy],
            );
            self.bytes_consumed += to_copy;
        }

        // Fill remaining bytes with zeros if needed
        if to_copy < dest.len() {
            dest[to_copy..].fill(0);
        }

        Ok(())
    }
}

impl TryRng for KatPrng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        #[cfg(feature = "random")]
        {
            self.get_entropy(dest)
                .expect("KAT PRNG entropy generation failed");
        }
        #[cfg(not(feature = "random"))]
        {
            // For no_std builds without random feature, just copy from entropy input
            let remaining = self.entropy_input.len() - self.bytes_consumed;
            let to_copy = dest.len().min(remaining);

            if to_copy > 0 {
                dest[..to_copy].copy_from_slice(
                    &self.entropy_input[self.bytes_consumed..self.bytes_consumed + to_copy],
                );
                self.bytes_consumed += to_copy;
            }

            // Fill remaining bytes with zeros if needed
            if to_copy < dest.len() {
                dest[to_copy..].fill(0);
            }
        }
        Ok(())
    }
}

impl TryCryptoRng for KatPrng {}

/// Create a KAT-compatible PRNG RNG
///
/// # Arguments
/// * `entropy_input` - 48-byte entropy input
///
/// # Returns
/// A KAT-compatible PRNG that implements Rng
pub fn create_kat_prng_rng(entropy_input: [u8; 48]) -> KatPrng {
    KatPrng::new(entropy_input)
}

#[cfg(test)]
mod tests {
    use rand_core::Rng;

    use super::*;

    #[test]
    fn test_kat_prng_matches_reference() {
        // KAT test seed (48 bytes)
        let seed = hex::decode("9EF877FDDBE8891C6E4E79EAF022E563DEFACA6B152161B9A423E8FE96A403E774B2D352CF74C934069C9DE74757F505").unwrap();
        let mut entropy_input = [0u8; 48];
        entropy_input.copy_from_slice(&seed);

        let mut rng = create_kat_prng_rng(entropy_input);

        // Get 32 bytes (seed_kem) - should match first 32 bytes of input
        let mut seed_kem = [0u8; 32];
        rng.fill_bytes(&mut seed_kem);

        // Expected from reference (first 32 bytes of entropy input)
        let expected =
            hex::decode("9ef877fddbe8891c6e4e79eaf022e563defaca6b152161b9a423e8fe96a403e7")
                .unwrap();

        assert_eq!(
            &seed_kem[..],
            &expected[..],
            "KAT PRNG output doesn't match reference implementation"
        );
    }

    #[test]
    fn test_kat_prng_deterministic() {
        let seed = [0x42u8; 48];
        let mut rng1 = create_kat_prng_rng(seed);
        let mut rng2 = create_kat_prng_rng(seed);

        let mut output1 = [0u8; 32];
        let mut output2 = [0u8; 32];

        rng1.fill_bytes(&mut output1);
        rng2.fill_bytes(&mut output2);

        assert_eq!(output1, output2, "KAT PRNG is not deterministic");
    }

    /// `Shake256KatPrng` has no callers anywhere else in the crate under default features
    /// (`grep -rn "Shake256KatPrng" lib-q-hqc/src lib-q-hqc/tests` outside this file returns
    /// nothing) -- it is exercised here directly as a regression pin on its own public API,
    /// not through any production call site.
    #[test]
    fn test_shake256_kat_prng_deterministic_and_try_rng() {
        let seed = [0x11u8; 48];
        let mut rng1 = Shake256KatPrng::new(&seed);
        let mut rng2 = Shake256KatPrng::new(&seed);

        let a = rng1.try_next_u32().unwrap();
        let b = rng2.try_next_u32().unwrap();
        assert_eq!(a, b, "same seed must give the same try_next_u32 output");

        let a64 = rng1.try_next_u64().unwrap();
        let b64 = rng2.try_next_u64().unwrap();
        assert_eq!(a64, b64, "same seed must give the same try_next_u64 output");

        let mut buf_a = [0u8; 10];
        let mut buf_b = [0u8; 10];
        rng1.try_fill_bytes(&mut buf_a).unwrap();
        rng2.try_fill_bytes(&mut buf_b).unwrap();
        assert_eq!(buf_a, buf_b);
    }

    #[test]
    fn test_shake256_kat_prng_skip_advances_stream() {
        let seed = [0x22u8; 48];

        let mut skipped = Shake256KatPrng::new(&seed);
        skipped.skip(16);
        let after_skip = skipped.try_next_u32().unwrap();

        let mut unskipped = Shake256KatPrng::new(&seed);
        let mut discard = [0u8; 16];
        unskipped.try_fill_bytes(&mut discard).unwrap();
        let after_manual_discard = unskipped.try_next_u32().unwrap();

        assert_eq!(
            after_skip, after_manual_discard,
            "skip(n) must be equivalent to discarding n bytes via try_fill_bytes"
        );
    }

    /// `KatPrng::try_next_u32`/`try_next_u64` (as opposed to `try_fill_bytes`, exercised by the
    /// other tests here via `Rng::fill_bytes`) -- called directly so their own bodies run.
    #[test]
    fn test_kat_prng_try_next_u32_and_u64() {
        let seed = [0x33u8; 48];
        let mut rng_a = create_kat_prng_rng(seed);
        let mut rng_b = create_kat_prng_rng(seed);

        let u32_a = rng_a.try_next_u32().unwrap();
        let mut raw = [0u8; 4];
        rng_b.fill_bytes(&mut raw);
        assert_eq!(u32_a, u32::from_le_bytes(raw));

        let mut rng_c = create_kat_prng_rng(seed);
        let mut discard = [0u8; 4];
        rng_c.fill_bytes(&mut discard);
        let u64_c = rng_c.try_next_u64().unwrap();

        let mut rng_d = create_kat_prng_rng(seed);
        let mut discard_d = [0u8; 4];
        rng_d.fill_bytes(&mut discard_d);
        let mut raw8 = [0u8; 8];
        rng_d.fill_bytes(&mut raw8);
        assert_eq!(u64_c, u64::from_le_bytes(raw8));
    }

    #[test]
    fn test_kat_prng_exhausts_entropy() {
        let seed = [0x42u8; 48];
        let mut rng = create_kat_prng_rng(seed);

        // First 32 bytes should match first 32 bytes of seed
        let mut first_32 = [0u8; 32];
        rng.fill_bytes(&mut first_32);
        assert_eq!(&first_32[..], &seed[..32]);

        // Next 16 bytes should match next 16 bytes of seed
        let mut next_16 = [0u8; 16];
        rng.fill_bytes(&mut next_16);
        assert_eq!(&next_16[..], &seed[32..48]);

        // After exhausting entropy, should return zeros
        let mut zeros = [0u8; 32];
        rng.fill_bytes(&mut zeros);
        assert_eq!(zeros, [0u8; 32]);
    }
}
