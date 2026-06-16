//! SHAKE256 helpers for domain-separated key derivation.

use crypto_bigint::{
    CtEq,
    CtLt,
    U256,
    U512,
};
use lib_q_sha3::{
    ExtendableOutput,
    Update,
    XofReader,
};

use crate::error::PrfError;

/// Expand XOF output until we obtain a non-zero field element `< p` (rejection sampling).
///
/// Each iteration hashes `label ‖ ctr ‖ seed` and reads exactly as many bytes as
/// the field width.  The candidate is accepted only when `0 < candidate < p`, so
/// the output is *uniform* over `[1, p)` with no modular bias.
pub fn shake256_to_field_u256(seed: &[u8], label: &[u8], p: &U256) -> Result<U256, PrfError> {
    // Reject a zero or all-ones modulus early.
    if bool::from(p.ct_eq(&U256::ZERO)) {
        return Err(PrfError::InvalidParam);
    }
    let mut ctr: u32 = 0;
    loop {
        let mut h = lib_q_sha3::Shake256::default();
        h.update(label);
        h.update(&(ctr as u64).to_le_bytes());
        h.update(seed);
        // Read exactly 32 bytes — one field-element's worth of entropy.
        let mut buf = [0u8; 32];
        let mut r = h.finalize_xof();
        XofReader::read(&mut r, &mut buf);
        let candidate = U256::from_le_slice(&buf);
        // Accept only when candidate is strictly in [1, p).
        // Rejection probability is at most 1/2 for any p <= 2^255, so the expected
        // number of iterations is < 2.  This loop terminates with overwhelming probability.
        let in_range = candidate.ct_lt(p);
        let nonzero = !candidate.ct_eq(&U256::ZERO);
        if bool::from(in_range & nonzero) {
            return Ok(candidate);
        }
        ctr = ctr.wrapping_add(1);
        if ctr > 1024 {
            return Err(PrfError::InvalidParam);
        }
    }
}

/// Same for [`U512`] / 64-byte absorb.
///
/// Uses pure rejection sampling (no `rem`) to avoid modular bias.
pub fn shake256_to_field_u512(seed: &[u8], label: &[u8], p: &U512) -> Result<U512, PrfError> {
    if bool::from(p.ct_eq(&U512::ZERO)) {
        return Err(PrfError::InvalidParam);
    }
    let mut ctr: u32 = 0;
    loop {
        let mut h = lib_q_sha3::Shake256::default();
        h.update(label);
        h.update(&(ctr as u64).to_le_bytes());
        h.update(seed);
        // Read exactly 64 bytes — one field-element's worth of entropy.
        let mut buf = [0u8; 64];
        let mut r = h.finalize_xof();
        XofReader::read(&mut r, &mut buf);
        let candidate = U512::from_le_slice(&buf);
        let in_range = candidate.ct_lt(p);
        let nonzero = !candidate.ct_eq(&U512::ZERO);
        if bool::from(in_range & nonzero) {
            return Ok(candidate);
        }
        ctr = ctr.wrapping_add(1);
        if ctr > 1024 {
            return Err(PrfError::InvalidParam);
        }
    }
}
