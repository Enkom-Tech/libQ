//! Side-channel oriented hooks (Cargo feature `hardened`).
//!
//! # Scope
//!
//! - Constant-time infinity-norm screening via [`lib_q_ring::polys_norm_within_bound`].
//! - First-order additive witness masking before `c·wit` ring multiplies
//!   ([`crate::sigma::secrets::MaskedWitness`]).
//! - Fixed-iteration rejection loops: every attempt runs norm screen + verification; the first
//!   accepting transcript is merged with [`ct_select_polys`] (no early return on success).
//!
//! # Rejection-attempt counts
//!
//! Hardened provers always execute exactly `max_attempts` loop iterations. Wall-clock time is
//! therefore independent of which attempt first satisfies the norm and verification checks.

#![cfg(feature = "hardened")]

/// Reduced fixed-iteration budget for unit and smoke tests (production profiles use 512).
pub const TEST_FIXED_PROVE_ATTEMPTS: usize = 32;

/// Errors from [`new_secure_rng`] / [`LibQRng::new_secure`].
pub use lib_q_random::Error as SecureRngError;
/// Workspace secure RNG (OS / platform CSPRNG via [`lib-q-random`](../../lib-q-random)).
pub use lib_q_random::LibQRng;
/// Secure RNG constructor used by hardened integrations and CI smoke tests.
pub use lib_q_random::new_secure_rng;
use lib_q_ring::Poly;
use subtle::{
    Choice,
    ConditionallySelectable,
};

use crate::util::module_norm_within_bound;

/// Returns `1` when `z` satisfies the configured infinity-norm abort bound.
#[must_use]
pub(crate) fn response_within_bound(z: &[Poly], z_inf_bound: i32) -> Choice {
    module_norm_within_bound(z, z_inf_bound)
}

/// Combine norm and verification success without short-circuiting the norm branch.
#[must_use]
pub(crate) fn accept_transcript(within_bound: Choice, verify_ok: bool) -> Choice {
    let verify_choice = Choice::from(u8::from(verify_ok));
    within_bound & verify_choice
}

/// `1` iff this attempt should be recorded as the first accept (prior attempts all rejected).
#[must_use]
pub(crate) fn first_accept_take(accept: Choice, seen_accept: Choice) -> Choice {
    accept & !seen_accept
}

/// OR-accumulate whether any attempt has accepted so far.
#[must_use]
pub(crate) fn fold_accept_seen(seen_accept: Choice, accept: Choice) -> Choice {
    seen_accept | accept
}

/// Constant-time coefficient merge: `dst = cond ? src : dst` per coefficient.
pub(crate) fn ct_select_poly(dst: &mut Poly, src: &Poly, cond: Choice) {
    for (d, s) in dst.coeffs.iter_mut().zip(src.coeffs.iter()) {
        *d = i32::conditional_select(d, s, cond);
    }
}

/// [`ct_select_poly`] on equal-length polynomial slices.
pub(crate) fn ct_select_polys(dst: &mut [Poly], src: &[Poly], cond: Choice) {
    debug_assert_eq!(dst.len(), src.len());
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        ct_select_poly(d, s, cond);
    }
}

#[cfg(test)]
mod tests {
    use lib_q_ring::Poly;

    use super::*;

    #[test]
    fn first_accept_take_selects_only_initial_success() {
        let accept = Choice::from(1u8);
        let seen = Choice::from(0u8);
        assert!(bool::from(first_accept_take(accept, seen)));

        let seen = Choice::from(1u8);
        assert!(!bool::from(first_accept_take(accept, seen)));
    }

    #[test]
    fn ct_select_poly_overwrites_on_cond() {
        let mut dst = Poly::zero();
        dst.coeffs[0] = 11;
        let mut src = Poly::zero();
        src.coeffs[0] = 42;
        ct_select_poly(&mut dst, &src, Choice::from(1u8));
        assert_eq!(dst.coeffs[0], 42);
        ct_select_poly(&mut dst, &src, Choice::from(0u8));
        assert_eq!(dst.coeffs[0], 42);
    }

    #[test]
    fn hardened_secure_rng_is_available() {
        use rand_core::Rng;

        let mut rng = new_secure_rng().expect("secure rng for hardened stack");
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        assert!(buf.iter().any(|&b| b != 0));
    }
}
