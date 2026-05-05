//! SHAKE256 helpers for domain-separated key derivation.

use crypto_bigint::{
    NonZero,
    U256,
    U512,
};
use lib_q_sha3::{
    ExtendableOutput,
    Update,
    XofReader,
};
use subtle::ConstantTimeEq;

use crate::error::PrfError;

/// Expand XOF output until we obtain a non-zero field element `< p` (rejection sampling).
pub fn shake256_to_field_u256(seed: &[u8], label: &[u8], p: &U256) -> Result<U256, PrfError> {
    let nz_p = NonZero::new(*p)
        .into_option()
        .ok_or(PrfError::InvalidParam)?;
    let mut ctr: u32 = 0;
    loop {
        let mut h = lib_q_sha3::Shake256::default();
        h.update(label);
        h.update(&(ctr as u64).to_le_bytes());
        h.update(seed);
        let mut wide = [0u8; 64];
        let mut r = h.finalize_xof();
        XofReader::read(&mut r, &mut wide);
        let candidate = U256::from_le_slice(&wide[..32]);
        let reduced = candidate.rem_vartime(&nz_p);
        if !bool::from(reduced.ct_eq(&U256::ZERO)) {
            return Ok(reduced);
        }
        ctr = ctr.wrapping_add(1);
        if ctr > 1024 {
            return Err(PrfError::InvalidParam);
        }
    }
}

/// Same for [`U512`] / 64-byte absorb.
pub fn shake256_to_field_u512(seed: &[u8], label: &[u8], p: &U512) -> Result<U512, PrfError> {
    let nz_p = NonZero::new(*p)
        .into_option()
        .ok_or(PrfError::InvalidParam)?;
    let mut ctr: u32 = 0;
    loop {
        let mut h = lib_q_sha3::Shake256::default();
        h.update(label);
        h.update(&(ctr as u64).to_le_bytes());
        h.update(seed);
        let mut wide = [0u8; 128];
        let mut r = h.finalize_xof();
        XofReader::read(&mut r, &mut wide);
        let candidate = U512::from_le_slice(&wide[..64]);
        let reduced = candidate.rem_vartime(&nz_p);
        if !bool::from(reduced.ct_eq(&U512::ZERO)) {
            return Ok(reduced);
        }
        ctr = ctr.wrapping_add(1);
        if ctr > 1024 {
            return Err(PrfError::InvalidParam);
        }
    }
}
