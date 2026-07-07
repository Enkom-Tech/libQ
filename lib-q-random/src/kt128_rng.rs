//! Cryptographic KT128-backed RNG for STARK/ZKP hiding randomness.
//!
//! Unlike [`crate::deterministic_rng::DeterministicRng`] (a 64-bit xorshift64, explicitly NOT
//! cryptographically secure), this RNG expands a **256-bit seed** through `KangarooTwelve`
//! ([`Kt128Expander`]) — a SHA3-family XOF — so its output stream is cryptographically
//! pseudorandom and **not** linearly invertible from observed outputs (e.g. the salts a hiding
//! Merkle commitment reveals).
//!
//! It satisfies the SAME trait surface as `DeterministicRng` (`rand_core::TryRng` +
//! `SeedableRng` + `Clone`), so it is a drop-in for the `R` type parameter of
//! `MerkleTreeHidingMmcs` / `HidingFriPcs`. Use it (seeded from a CSPRNG) for the hiding
//! salts and blinding polynomials of zero-knowledge STARK proofs.

use core::convert::Infallible;

use rand_core::{
    SeedableRng,
    TryCryptoRng,
    TryRng,
};

use crate::kt128_expander::Kt128Expander;

/// Cryptographic RNG: a [`Kt128Expander`] (`KangarooTwelve` XOF) exposed as a seedable,
/// cloneable `rand_core` RNG. 256-bit seed; cryptographically pseudorandom output.
#[derive(Clone, Debug)]
pub struct Kt128Rng {
    expander: Kt128Expander,
}

impl Kt128Rng {
    /// Create from a 256-bit seed (the seed MUST be fresh CSPRNG entropy for hiding use).
    #[must_use]
    pub fn from_seed_bytes(seed: [u8; 32]) -> Self {
        Self {
            expander: Kt128Expander::from_det_seed_32(seed),
        }
    }

    /// Create from a `u64` seed (`SplitMix64` → KT128). **Only 64 bits of seed entropy** — for
    /// deterministic tests, NOT for production hiding. Use [`Self::from_seed_bytes`] there.
    #[must_use]
    pub fn from_u64(seed: u64) -> Self {
        Self {
            expander: Kt128Expander::from_det_u64(seed),
        }
    }
}

impl TryRng for Kt128Rng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.expander.fill_bytes(&mut b);
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.expander.fill_bytes(&mut b);
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.expander.fill_bytes(dest);
        Ok(())
    }
}

impl SeedableRng for Kt128Rng {
    type Seed = [u8; 32];

    fn from_seed(seed: Self::Seed) -> Self {
        Self::from_seed_bytes(seed)
    }
}

// KangarooTwelve is a cryptographically secure XOF, so its output stream is a CSPRNG: mark
// `Kt128Rng` accordingly. This lets it satisfy `CryptoRng` bounds (e.g. FN-DSA seeded keygen/sign
// for reproducible KAT vectors). Seed-entropy adequacy is the caller's responsibility, as with any
// CSPRNG — use `from_seed_bytes` (256-bit seed) for production, `from_u64` only for tests.
impl TryCryptoRng for Kt128Rng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_same_seed_distinct_for_different() {
        let mut a = Kt128Rng::from_seed_bytes([7u8; 32]);
        let mut b = Kt128Rng::from_seed_bytes([7u8; 32]);
        let mut c = Kt128Rng::from_seed_bytes([8u8; 32]);
        let (mut xa, mut xb, mut xc) = ([0u8; 64], [0u8; 64], [0u8; 64]);
        a.try_fill_bytes(&mut xa).unwrap();
        b.try_fill_bytes(&mut xb).unwrap();
        c.try_fill_bytes(&mut xc).unwrap();
        assert_eq!(xa, xb, "same seed ⇒ same stream");
        assert_ne!(xa, xc, "different seed ⇒ different stream");
    }

    #[test]
    fn clone_resumes_same_stream() {
        let mut a = Kt128Rng::from_u64(123);
        let mut pre = [0u8; 16];
        a.try_fill_bytes(&mut pre).unwrap();
        let mut b = a.clone();
        let (mut xa, mut xb) = ([0u8; 32], [0u8; 32]);
        a.try_fill_bytes(&mut xa).unwrap();
        b.try_fill_bytes(&mut xb).unwrap();
        assert_eq!(xa, xb, "clone must resume the identical stream position");
    }
}
