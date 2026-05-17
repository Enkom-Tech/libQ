//! Legendre PRF: \(L_K(x) = \left(\frac{x+K}{p}\right)\).

use crypto_bigint::{
    NonZero,
    U256,
    U512,
};
use zeroize::{
    Zeroize,
    ZeroizeOnDrop,
};

use crate::error::PrfError;
use crate::field::{
    fp_add,
    legendre_symbol_monty,
    to_monty,
    uint_ct_eq_zero,
};
use crate::keys::{
    validate_key_u256,
    validate_key_u512,
};
use crate::params::{
    LegendrePrfParams256,
    LegendrePrfParams512,
};

/// Secret key `K` for the Legendre PRF (pilot: [`U256`] field).
///
/// Invariant: `k` is a reduced field element in `[1, p)` for the modulus `p`
/// carried in [`LegendrePrfParams256`]. Keys are only constructible via
/// [`LegendreKey256::from_uint`] or [`LegendreKey256::derive_from_seed`]; use
/// [`LegendreKey256::as_uint`] for read-only access. Evaluation APIs assume this
/// invariant and do not re-validate on each call.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct LegendreKey256 {
    k: U256,
}

/// Secret key for the 512-bit pilot field.
///
/// Same invariant as [`LegendreKey256`], with [`LegendrePrfParams512`].
/// Construct only via [`LegendreKey512::from_uint`] / [`LegendreKey512::derive_from_seed`];
/// read the scalar with [`LegendreKey512::as_uint`].
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct LegendreKey512 {
    k: U512,
}

impl LegendreKey256 {
    /// Construct from a reduced field element.
    pub fn from_uint(k: U256, params: &LegendrePrfParams256) -> Result<Self, PrfError> {
        validate_key_u256(&k, &params.p.get())?;
        Ok(Self { k })
    }

    /// Domain-separated expansion: `SHAKE256("lib-q-prf/leg-k256/v1" ‖ seed) → k mod p`.
    pub fn derive_from_seed(seed: &[u8], params: &LegendrePrfParams256) -> Result<Self, PrfError> {
        let k =
            crate::shake::shake256_to_field_u256(seed, b"lib-q-prf/leg-k256/v1", &params.p.get())?;
        Self::from_uint(k, params)
    }

    /// Borrow the key as a reduced field element in `[1, p)` (see type invariant).
    #[inline]
    #[must_use]
    pub fn as_uint(&self) -> &U256 {
        &self.k
    }
}

impl LegendreKey512 {
    pub fn from_uint(k: U512, params: &LegendrePrfParams512) -> Result<Self, PrfError> {
        validate_key_u512(&k, &params.p)?;
        Ok(Self { k })
    }

    pub fn derive_from_seed(seed: &[u8], params: &LegendrePrfParams512) -> Result<Self, PrfError> {
        let k = crate::shake::shake256_to_field_u512(seed, b"lib-q-prf/leg-k512/v1", &params.p)?;
        Self::from_uint(k, params)
    }

    /// Borrow the key as a reduced field element in `[1, p)` (see type invariant).
    #[inline]
    #[must_use]
    pub fn as_uint(&self) -> &U512 {
        &self.k
    }
}

/// Reduce `x` modulo `p` (public vartime on modulus) and evaluate the Legendre PRF.
///
/// Assumes `key` satisfies the [`LegendreKey256`] invariant (validated when the key
/// is built via [`LegendreKey256::from_uint`] / [`LegendreKey256::derive_from_seed`]).
pub fn legendre_prf_u256(
    key: &LegendreKey256,
    x: &U256,
    params: &LegendrePrfParams256,
) -> Result<i8, PrfError> {
    let xm = to_monty(&x.rem_vartime(&params.p), &params.monty);
    let km = to_monty(&key.k, &params.monty);
    let sum = fp_add(xm, &km);
    let zero_sum = uint_ct_eq_zero(&sum.retrieve());
    if bool::from(zero_sum) {
        return Err(PrfError::ZeroInput);
    }
    legendre_symbol_monty(&sum)
}

/// 512-bit field variant.
///
/// Assumes `key` satisfies the [`LegendreKey512`] invariant (see [`LegendreKey512::from_uint`]).
pub fn legendre_prf_u512(
    key: &LegendreKey512,
    x: &U512,
    params: &LegendrePrfParams512,
) -> Result<i8, PrfError> {
    let nz = NonZero::new(params.p)
        .into_option()
        .ok_or(PrfError::InvalidParam)?;
    let xm = to_monty(&x.rem_vartime(&nz), &params.monty);
    let km = to_monty(&key.k, &params.monty);
    let sum = fp_add(xm, &km);
    let zero_sum = uint_ct_eq_zero(&sum.retrieve());
    if bool::from(zero_sum) {
        return Err(PrfError::ZeroInput);
    }
    legendre_symbol_monty(&sum)
}

/// Reference Legendre symbol via Euler: `pow(x+k, (p-1)/2, p)` on **canonical** residues (test / KAT).
#[cfg(test)]
pub fn legendre_symbol_euler_u256(x_plus_k: &U256, params: &LegendrePrfParams256) -> i8 {
    let p = params.p.get();
    let e = p.wrapping_sub(&U256::ONE).shr(1);
    let reduced = x_plus_k.rem_vartime(&params.p);
    let m = to_monty(&reduced, &params.monty);
    let y = m.pow(&e).retrieve();
    crate::field::legendre_symbol_residue(&y, &p).expect("prime field")
}
