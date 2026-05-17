//! Unbiased uniform sampling in \(\mathbb{Z}_q\) for word-oriented RNGs.
//!
//! [`try_uniform_coeff_mod_q_from_u32`] and [`sample_uniform_coeff_mod_q`] implement the same
//! rejection rule as ML-DSA coefficient expansion ([`crate::expand`]): discard outputs that would
//! induce modular bias. Here the domain is full `u32` words: accept only
//! `r < floor(2^32/q)*q`, then map with `r % q`.

use rand_core::{
    CryptoRng,
    Rng,
};

use crate::constants::FIELD_MODULUS;

/// Largest multiple of `q` strictly below `2^32`, i.e. `floor(2^32/q)*q`.
///
/// Returns `0` if `q == 0` (invalid modulus; callers should not use such `q`).
#[inline]
#[must_use]
pub fn uniform_mod_u32_rejection_threshold(q: u32) -> u64 {
    let q_u64 = u64::from(q);
    if q_u64 == 0 {
        return 0;
    }
    ((1u64 << 32) / q_u64) * q_u64
}

/// Maps a single `u32` word to a uniform residue in `[0, q)` when it lies below
/// [`uniform_mod_u32_rejection_threshold`]; otherwise returns [`None`] (caller should draw another
/// word). Returns [`None`] if `q == 0`.
#[inline]
#[must_use]
pub fn try_uniform_coeff_mod_q_from_u32(q: u32, word: u32) -> Option<i32> {
    if q == 0 {
        return None;
    }
    let q_u64 = u64::from(q);
    let r = u64::from(word);
    let threshold = uniform_mod_u32_rejection_threshold(q);
    (r < threshold).then_some((r % q_u64) as i32)
}

/// Draws uniform coefficients in `[0, q)` using rejection on [`Rng::next_u32`].
///
/// # Panics
///
/// Panics if `q == 0`.
#[inline]
pub fn sample_uniform_coeff_mod_q<R: Rng + CryptoRng>(rng: &mut R, q: u32) -> i32 {
    assert!(q > 0, "sample_uniform_coeff_mod_q: q must be non-zero");
    let q_u64 = u64::from(q);
    let threshold = uniform_mod_u32_rejection_threshold(q);
    loop {
        let r = u64::from(rng.next_u32());
        if r < threshold {
            return (r % q_u64) as i32;
        }
    }
}

/// Uniform coefficient in `[0, q)` for the ML-DSA / shared ring modulus [`FIELD_MODULUS`].
#[inline]
pub fn sample_uniform_field_coefficient<R: Rng + CryptoRng>(rng: &mut R) -> i32 {
    sample_uniform_coeff_mod_q(rng, FIELD_MODULUS as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejection_threshold_matches_remainder_identity() {
        let q = FIELD_MODULUS as u64;
        let threshold = uniform_mod_u32_rejection_threshold(FIELD_MODULUS as u32);
        assert!(threshold <= 1u64 << 32);
        assert_eq!((1u64 << 32) % q, (1u64 << 32) - threshold);
    }

    #[test]
    fn try_from_u32_accepts_high_boundary() {
        let q = FIELD_MODULUS as u32;
        let th = uniform_mod_u32_rejection_threshold(q);
        assert!(try_uniform_coeff_mod_q_from_u32(q, (th - 1) as u32).is_some());
        assert!(try_uniform_coeff_mod_q_from_u32(q, th as u32).is_none());
    }
}
