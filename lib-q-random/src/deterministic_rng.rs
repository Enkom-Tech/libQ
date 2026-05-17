//! Lightweight deterministic RNG for STARK/ZKP testing.
//!
//! NOT cryptographically secure. Use only for deterministic test vectors,
//! hiding commitment salt, and other non-security-critical randomness.

use core::convert::Infallible;

use rand_core::{
    SeedableRng,
    TryRng,
};

/// Deterministic xorshift64 RNG.
///
/// Satisfies `rand_core::RngCore + SeedableRng + Clone` with no alloc.
/// Used in STARK/ZKP as the `R` type parameter for `MerkleTreeHidingMmcs`
/// and `HidingFriPcs`.
#[derive(Clone, Copy, Debug)]
pub struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    /// Create from a `u64` seed (mirrors `SmallRng::seed_from_u64`).
    #[must_use]
    pub fn seed_from_u64(seed: u64) -> Self {
        // splitmix64 initializer so seed=0 still gives a non-zero state
        let mut s = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        s = (s ^ (s >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        s = (s ^ (s >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        s ^= s >> 31;
        Self {
            state: if s == 0 { 1 } else { s },
        }
    }

    #[inline]
    fn next_u64_inner(&mut self) -> u64 {
        // xorshift64
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
}

impl TryRng for DeterministicRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok((self.next_u64_inner() & 0xFFFF_FFFF) as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.next_u64_inner())
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        let mut i = 0;
        while i < dest.len() {
            let u = self.next_u64_inner().to_le_bytes();
            let n = (dest.len() - i).min(8);
            dest[i..i + n].copy_from_slice(&u[..n]);
            i += n;
        }
        Ok(())
    }
}

impl SeedableRng for DeterministicRng {
    type Seed = [u8; 8];

    fn from_seed(seed: Self::Seed) -> Self {
        Self::seed_from_u64(u64::from_le_bytes(seed))
    }
}
