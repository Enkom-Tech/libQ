//! Field arithmetic in \(\mathbb{F}_p\) using Montgomery form ([`crypto_bigint::modular::MontyForm`]).
//!
//! Public-modulus operations may use [`MontyParams::new_vartime`]. Secret-dependent paths use
//! [`MontyForm`] operations from `crypto-bigint`, which are intended to be constant-time with
//! respect to the **values**, not the modulus bit length (see upstream docs on `exponent_bits`).

use crypto_bigint::Uint;
use crypto_bigint::modular::MontyForm;
use subtle::{
    Choice,
    ConditionallySelectable,
    ConstantTimeEq,
};

use crate::error::PrfError;

/// Map `y = a^{(p-1)/2} mod p` to a conventional Legendre symbol in `{-1,0,1}`.
///
/// For odd prime `p`, `y` is always `0`, `1`, or `p-1`. Any other residue is mapped to
/// [`PrfError::InvalidParam`] (should not occur for prime `p`).
pub fn legendre_symbol_residue<const LIMBS: usize>(
    y: &Uint<LIMBS>,
    p: &Uint<LIMBS>,
) -> Result<i8, PrfError> {
    let zero = y.ct_eq(&Uint::ZERO);
    let one = y.ct_eq(&Uint::ONE);
    let pm1 = p.wrapping_sub(&Uint::ONE);
    let neg_one = y.ct_eq(&pm1);

    let ok = zero | one | neg_one;
    if !bool::from(ok) {
        return Err(PrfError::InvalidParam);
    }

    let mut out = 0i8;
    out = i8::conditional_select(&out, &0, zero);
    out = i8::conditional_select(&out, &1, one & !zero);
    out = i8::conditional_select(&out, &-1, neg_one & !zero & !one);
    Ok(out)
}

/// Legendre symbol \(\left(\frac{a}{p}\right)\) via Euler's criterion, for `a` in Montgomery form.
pub fn legendre_symbol_monty<const LIMBS: usize>(a: &MontyForm<LIMBS>) -> Result<i8, PrfError> {
    let p = *a.params().modulus().as_ref();
    let pm1 = p.wrapping_sub(&Uint::ONE);
    let half = pm1.shr(1);
    let y = a.pow(&half).retrieve();
    legendre_symbol_residue(&y, &p)
}

/// `lhs + rhs` in \(\mathbb{F}_p\).
#[must_use]
pub fn fp_add<const LIMBS: usize>(
    lhs: MontyForm<LIMBS>,
    rhs: &MontyForm<LIMBS>,
) -> MontyForm<LIMBS> {
    lhs.add(rhs)
}

/// `lhs * rhs` in \(\mathbb{F}_p\).
#[must_use]
pub fn fp_mul<const LIMBS: usize>(
    lhs: &MontyForm<LIMBS>,
    rhs: &MontyForm<LIMBS>,
) -> MontyForm<LIMBS> {
    lhs.mul(rhs)
}

/// `base^exp` in \(\mathbb{F}_p\) (Montgomery ladder; `exp` bit length may leak via timing).
#[must_use]
pub fn fp_pow<const LIMBS: usize, const E: usize>(
    base: &MontyForm<LIMBS>,
    exp: &Uint<E>,
) -> MontyForm<LIMBS> {
    base.pow(exp)
}

/// Encode `x mod p` as [`MontyForm`].
#[must_use]
pub fn to_monty<const LIMBS: usize>(
    x: &Uint<LIMBS>,
    params: crypto_bigint::modular::MontyParams<LIMBS>,
) -> MontyForm<LIMBS> {
    MontyForm::new(x, params)
}

/// Reduce comparison `x == 0 (mod p)` on representatives in `[0,p)`.
#[must_use]
pub fn uint_ct_eq_zero<const LIMBS: usize>(x: &Uint<LIMBS>) -> Choice {
    x.ct_eq(&Uint::ZERO)
}
