//! KT128 (`KangarooTwelve`) deterministic byte expansion for test and KAT RNGs.
//!
//! Uses RFC 9861 KT128 as an XOF with explicit domain separation labels.

use lib_q_k12::Kt128;
use lib_q_k12::digest::{
    ExtendableOutput,
    Update,
    XofReader,
};

/// Domain label for general lib-Q deterministic RNG (`new_deterministic`, etc.).
pub const DOMAIN_LIBQ_DET_RNG: &[u8] = b"libQ-DET-RNG-v1";

/// Domain label for HPKE [`crate::Kt128Rng`] (unchanged from prior inline implementation).
pub const DOMAIN_HPKE_RNG: &[u8] = b"HPKE-RNG";

/// Domain label for optional Saturnin CTR deterministic path.
#[cfg(feature = "deterministic-saturnin")]
pub const DOMAIN_LIBQ_DET_SATURNIN: &[u8] = b"libQ-DET-SATURNIN-v1";

/// Expand a 256-bit seed (and optional domain) into an arbitrary-length byte stream via KT128.
#[derive(Clone, Debug)]
pub struct Kt128Expander {
    domain: &'static [u8],
    buffer: [u8; 32],
    position: usize,
    counter: u64,
}

impl Kt128Expander {
    /// Create an expander from a 32-byte seed and domain label.
    #[must_use]
    pub fn from_seed_32(domain: &'static [u8], seed: [u8; 32]) -> Self {
        Self::from_seed(domain, &seed)
    }

    /// Create an expander from variable-length seed material and a domain label.
    #[must_use]
    pub fn from_seed(domain: &'static [u8], seed: &[u8]) -> Self {
        let mut k12 = Kt128::new(domain);
        k12.update(seed);
        let mut reader = k12.finalize_xof();
        let mut buffer = [0u8; 32];
        reader.read(&mut buffer);
        Self {
            domain,
            buffer,
            position: 0,
            counter: 0,
        }
    }

    /// Create an expander using [`DOMAIN_LIBQ_DET_RNG`] and a 32-byte seed.
    #[must_use]
    pub fn from_det_seed_32(seed: [u8; 32]) -> Self {
        Self::from_seed_32(DOMAIN_LIBQ_DET_RNG, seed)
    }

    /// Create an expander using [`DOMAIN_LIBQ_DET_RNG`] and SplitMix64-expanded `u64` seed material.
    #[must_use]
    pub fn from_det_u64(seed: u64) -> Self {
        Self::from_seed_32(DOMAIN_LIBQ_DET_RNG, seed_32_from_u64(seed))
    }

    /// Refill the internal 32-byte buffer from the chained KT128 XOF step.
    pub fn refill(&mut self) {
        let mut k12 = Kt128::new(self.domain);
        k12.update(&self.buffer);
        k12.update(&self.counter.to_le_bytes());
        let mut reader = k12.finalize_xof();
        reader.read(&mut self.buffer);
        self.counter = self.counter.wrapping_add(1);
        self.position = 0;
    }

    /// Fill `dest` with deterministic pseudorandom bytes.
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
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
    }
}

/// SplitMix64-style expansion of a `u64` test seed into 32 bytes (four mixing rounds).
#[must_use]
pub fn seed_32_from_u64(seed: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut s = seed;
    for chunk in out.chunks_mut(8) {
        s = splitmix64_step(s);
        chunk.copy_from_slice(&s.to_le_bytes());
    }
    out
}

#[inline]
fn splitmix64_step(mut s: u64) -> u64 {
    s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
    s = (s ^ (s >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    s = (s ^ (s >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    let out = s ^ (s >> 31);
    if out == 0 { 1 } else { out }
}

/// `DOMAIN_LIBQ_DET_RNG` + `[0u8; 32]` → first 64 output bytes.
pub const KT128_DET_GOLDEN_ZERO_SEED_64: [u8; 64] = [
    221, 250, 174, 112, 192, 10, 162, 130, 180, 58, 67, 124, 118, 240, 140, 65, 32, 215, 8, 34,
    140, 63, 13, 205, 241, 229, 59, 9, 57, 190, 20, 124, 197, 138, 246, 213, 80, 155, 64, 77, 70,
    54, 191, 17, 7, 229, 73, 226, 157, 172, 235, 183, 104, 145, 73, 150, 229, 58, 50, 22, 40, 119,
    178, 69,
];

/// `from_det_u64(0x0123_4567_89ab_cdef)` → first 64 output bytes.
pub const KT128_DET_GOLDEN_U64_SEED_64: [u8; 64] = [
    252, 181, 230, 112, 248, 141, 49, 132, 104, 217, 21, 202, 22, 213, 11, 151, 255, 181, 150, 56,
    230, 170, 210, 70, 45, 58, 246, 36, 221, 142, 143, 69, 198, 102, 112, 157, 221, 138, 218, 8,
    136, 45, 198, 171, 31, 205, 147, 64, 120, 114, 35, 21, 207, 61, 174, 238, 179, 102, 189, 172,
    16, 254, 132, 2,
];

// Golden vectors are generated in `tests/data/kt128_det_rng_v1.json` and asserted in integration tests.
// Unit tests compare live output against values captured from this implementation (see `gen_kt128_goldens` test).

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_separation_same_seed() {
        let seed = [7u8; 32];
        let mut det = Kt128Expander::from_seed_32(DOMAIN_LIBQ_DET_RNG, seed);
        let mut hpke = Kt128Expander::from_seed_32(DOMAIN_HPKE_RNG, seed);
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        det.fill_bytes(&mut a);
        hpke.fill_bytes(&mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn test_u64_differs_from_raw_32_byte_seed() {
        let seed_u64 = 0x0123_4567_89AB_CDEF_u64;
        let mut from_u64 = Kt128Expander::from_det_u64(seed_u64);
        let mut from_bytes = Kt128Expander::from_det_seed_32(seed_32_from_u64(seed_u64));
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        from_u64.fill_bytes(&mut a);
        from_bytes.fill_bytes(&mut b);
        assert_eq!(a, b);
        let mut wrong = Kt128Expander::from_det_seed_32({
            let mut s = [0u8; 32];
            s[..8].copy_from_slice(&seed_u64.to_le_bytes());
            s
        });
        let mut c = [0u8; 64];
        wrong.fill_bytes(&mut c);
        assert_ne!(a, c);
    }

    #[test]
    fn test_deterministic_repeatability() {
        let seed = [1u8; 32];
        let mut e1 = Kt128Expander::from_det_seed_32(seed);
        let mut e2 = Kt128Expander::from_det_seed_32(seed);
        let mut out1 = [0u8; 128];
        let mut out2 = [0u8; 128];
        e1.fill_bytes(&mut out1);
        e2.fill_bytes(&mut out2);
        assert_eq!(out1, out2);
    }

    /// Golden bytes for `DOMAIN_LIBQ_DET_RNG` + zero seed (first 64 output bytes).
    #[test]
    fn test_golden_zero_seed_64_bytes() {
        let mut expander = Kt128Expander::from_det_seed_32([0u8; 32]);
        let mut out = [0u8; 64];
        expander.fill_bytes(&mut out);
        assert_eq!(out, KT128_DET_GOLDEN_ZERO_SEED_64);
    }

    /// Golden bytes for `from_det_u64(0x0123_4567_89ab_cdef)` (first 64 output bytes).
    #[test]
    fn test_golden_u64_seed_64_bytes() {
        let mut expander = Kt128Expander::from_det_u64(0x0123_4567_89AB_CDEF);
        let mut out = [0u8; 64];
        expander.fill_bytes(&mut out);
        assert_eq!(out, KT128_DET_GOLDEN_U64_SEED_64);
    }

    /// One-shot helper to print committed goldens (run with `--ignored --nocapture` after changing expansion).
    #[test]
    #[ignore = "manual: cargo test gen_kt128_goldens -- --ignored --nocapture -p lib-q-random"]
    fn gen_kt128_goldens() {
        let mut z = Kt128Expander::from_det_seed_32([0u8; 32]);
        let mut zu = [0u8; 64];
        z.fill_bytes(&mut zu);
        let mut u = Kt128Expander::from_det_u64(0x0123_4567_89AB_CDEF);
        let mut uu = [0u8; 64];
        u.fill_bytes(&mut uu);
        println!("zero_seed_64 = {zu:?}");
        println!("u64_seed_64 = {uu:?}");
    }
}
