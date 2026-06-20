//! Buffered RNG adapter.
//!
//! The lattice samplers draw randomness in tiny chunks (a `u64` at a time per rejection step):
//! a single DKG round pulls many thousands of small draws. Routing each through the underlying
//! CSPRNG's per-call path dominates runtime. [`BufRng`] wraps any [`Rng`], refilling a block buffer
//! with one bulk `fill_bytes` and serving small reads from it — same byte stream, far fewer calls.

use core::convert::Infallible;

use rand_core::{
    Rng,
    TryCryptoRng,
    TryRng,
};

/// Refill block size (bytes).
const CAP: usize = 8192;

/// Buffered wrapper over a mutable reference to an [`Rng`]. Implements `Rng + CryptoRng` (via the
/// `TryRng`/`TryCryptoRng` blanket impls), so it is a drop-in for the samplers' `R: CryptoRng + Rng`.
pub struct BufRng<'a, R: Rng> {
    inner: &'a mut R,
    buf: [u8; CAP],
    pos: usize,
}

impl<'a, R: Rng> BufRng<'a, R> {
    /// Wrap `inner`. The buffer is filled lazily on first use.
    pub fn new(inner: &'a mut R) -> Self {
        Self {
            inner,
            buf: [0u8; CAP],
            pos: CAP, // force a refill on first read
        }
    }

    #[inline]
    fn fill(&mut self, dest: &mut [u8]) {
        let mut filled = 0;
        while filled < dest.len() {
            if self.pos == CAP {
                self.inner.fill_bytes(&mut self.buf);
                self.pos = 0;
            }
            let avail = CAP - self.pos;
            let take = (dest.len() - filled).min(avail);
            dest[filled..filled + take].copy_from_slice(&self.buf[self.pos..self.pos + take]);
            self.pos += take;
            filled += take;
        }
    }
}

impl<R: Rng> TryRng for BufRng<'_, R> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.fill(&mut b);
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.fill(&mut b);
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.fill(dest);
        Ok(())
    }
}

impl<R: Rng> TryCryptoRng for BufRng<'_, R> {}
