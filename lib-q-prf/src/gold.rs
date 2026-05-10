//! Gold (power-residue) PRF: \(\mathrm{Gold}_k(x) = (k+x)^g \bmod p\).

use crypto_bigint::{
    CtEq,
    CtLt,
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
    fp_pow,
    to_monty,
};
use crate::params::{
    GoldPrfParams256,
    GoldPrfParams512,
};

/// Secret key `k` for the Gold PRF (pilot: [`U256`] field).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct GoldKey256 {
    pub k: U256,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct GoldKey512 {
    pub k: U512,
}

fn validate_key_u256(k: &U256, p: &U256) -> Result<(), PrfError> {
    let zero = k.ct_eq(&U256::ZERO);
    let lt_p = k.ct_lt(p);
    if bool::from(zero | !lt_p) {
        return Err(PrfError::InvalidKey);
    }
    Ok(())
}

fn validate_key_u512(k: &U512, p: &U512) -> Result<(), PrfError> {
    let zero = k.ct_eq(&U512::ZERO);
    let lt_p = k.ct_lt(p);
    if bool::from(zero | !lt_p) {
        return Err(PrfError::InvalidKey);
    }
    Ok(())
}

impl GoldKey256 {
    pub fn from_uint(k: U256, params: &GoldPrfParams256) -> Result<Self, PrfError> {
        validate_key_u256(&k, &params.p)?;
        Ok(Self { k })
    }

    pub fn derive_from_seed(seed: &[u8], params: &GoldPrfParams256) -> Result<Self, PrfError> {
        let k = crate::shake::shake256_to_field_u256(seed, b"lib-q-prf/gold-k256/v1", &params.p)?;
        Self::from_uint(k, params)
    }
}

impl GoldKey512 {
    pub fn from_uint(k: U512, params: &GoldPrfParams512) -> Result<Self, PrfError> {
        validate_key_u512(&k, &params.p)?;
        Ok(Self { k })
    }

    pub fn derive_from_seed(seed: &[u8], params: &GoldPrfParams512) -> Result<Self, PrfError> {
        let k = crate::shake::shake256_to_field_u512(seed, b"lib-q-prf/gold-k512/v1", &params.p)?;
        Self::from_uint(k, params)
    }
}

/// Evaluate Gold PRF; returns canonical residue in little-endian bytes.
pub fn gold_prf_u256(
    key: &GoldKey256,
    x: &U256,
    params: &GoldPrfParams256,
) -> Result<[u8; 32], PrfError> {
    validate_key_u256(&key.k, &params.p)?;
    let nz = NonZero::new(params.p)
        .into_option()
        .ok_or(PrfError::InvalidParam)?;
    let xr = x.rem_vartime(&nz);
    let xm = to_monty(&xr, &params.monty);
    let km = to_monty(&key.k, &params.monty);
    let sum = fp_add(xm, &km);
    let out_m = fp_pow(&sum, &params.g);
    Ok(out_m.retrieve().to_le_bytes().into())
}

pub fn gold_prf_u512(
    key: &GoldKey512,
    x: &U512,
    params: &GoldPrfParams512,
) -> Result<[u8; 64], PrfError> {
    validate_key_u512(&key.k, &params.p)?;
    let nz = NonZero::new(params.p)
        .into_option()
        .ok_or(PrfError::InvalidParam)?;
    let xr = x.rem_vartime(&nz);
    let xm = to_monty(&xr, &params.monty);
    let km = to_monty(&key.k, &params.monty);
    let sum = fp_add(xm, &km);
    let out_m = fp_pow(&sum, &params.g);
    Ok(out_m.retrieve().to_le_bytes().into())
}
