//! Centralised entropy source for hardened ML-KEM internals (feature `hardened`).
//!
//! This is the **single location** in `lib-q-ml-kem` that calls `getrandom` directly.
//! All other hardened-path code obtains OS randomness through [`OsRngFill`].
//!
//! # Failure policy
//!
//! Masking randomness that silently degrades to a constant defeats the countermeasure entirely
//! (e.g. `r = 1` means no blinding; a stuck Fisher–Yates means no shuffle). If the OS CSPRNG is
//! unavailable while `hardened` is active, the system is in an unrecoverable insecure state.
//! [`OsRngFill`] therefore **panics** on `getrandom` failure rather than returning a fallback.

use rand_core::{
    Infallible,
    TryRng,
};

/// Infallible [`rand_core::Rng`] adapter backed by the OS CSPRNG.
///
/// Constructed inline at call sites within the hardened decapsulation path. Constructing a new
/// instance is zero-cost; it holds no state.
pub(crate) struct OsRngFill;

impl TryRng for OsRngFill {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::fill(dest)
            .expect("OS CSPRNG unavailable: hardened masking requires a live entropy source");
        Ok(())
    }
}

/// Fisher–Yates shuffle of `0..k` into `perm[..k]`.
///
/// Caller supplies a buffer with `perm.len() >= k`. ML-KEM uses `k ≤ 4` (vector dimension).
#[allow(clippy::needless_range_loop, clippy::integer_division_remainder_used)]
pub(crate) fn shuffle_indices<R: rand_core::Rng>(rng: &mut R, k: usize, perm: &mut [usize]) {
    for i in 0..k {
        perm[i] = i;
    }
    for i in (1..k).rev() {
        let mut buf = [0u8; 8];
        rng.fill_bytes(&mut buf);
        // `usize` is 32-bit on wasm32; reduce via u64 so the same RNG bytes work on all targets.
        let j = usize::try_from(u64::from_le_bytes(buf) % (i as u64 + 1))
            .expect("shuffle index fits in usize (k <= 4)");
        perm.swap(i, j);
    }
}
