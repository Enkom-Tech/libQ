//! Shared validation for PRF secret keys represented as field scalars.
//!
//! Legendre and Gold PRFs require the same invariant on `k`: a non-zero reduced
//! residue strictly below the prime modulus `p` (equivalently `k ∈ [1, p)`).
//!
//! Callers building custom key material or cross-checking serialized scalars may use
//! [`validate_key_u256`] and [`validate_key_u512`] directly; opaque key types in
//! [`crate::legendre`] and [`crate::gold`] already apply these checks in their constructors.

use crypto_bigint::{
    CtEq,
    CtLt,
    U256,
    U512,
};

use crate::error::PrfError;

/// Ensure `k` lies in `[1, p)` (non-zero and strictly less than `p`).
#[inline]
pub fn validate_key_u256(k: &U256, p: &U256) -> Result<(), PrfError> {
    let zero = k.ct_eq(&U256::ZERO);
    let lt_p = k.ct_lt(p);
    if bool::from(zero | !lt_p) {
        return Err(PrfError::InvalidKey);
    }
    Ok(())
}

/// Same invariant as [`validate_key_u256`] for the 512-bit pilot modulus.
#[inline]
pub fn validate_key_u512(k: &U512, p: &U512) -> Result<(), PrfError> {
    let zero = k.ct_eq(&U512::ZERO);
    let lt_p = k.ct_lt(p);
    if bool::from(zero | !lt_p) {
        return Err(PrfError::InvalidKey);
    }
    Ok(())
}
