//! Minimal deterministic serialization (big-endian `u32` length prefixes + coefficient bytes).

use alloc::vec::Vec;

use lib_q_ring::Poly;
use lib_q_ring::constants::{
    COEFFICIENTS_IN_RING_ELEMENT,
    FIELD_MODULUS,
};

use crate::error::VerifyError;

fn push_i32_le(buf: &mut Vec<u8>, v: i32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

/// Append [`write_module_vec`] encoding of `v` to `buf` without an intermediate allocation.
pub(crate) fn append_module_vec(buf: &mut Vec<u8>, v: &[Poly]) {
    buf.extend_from_slice(&(v.len() as u32).to_le_bytes());
    for p in v {
        for &c in &p.coeffs {
            push_i32_le(buf, c);
        }
    }
}

/// Serialize a module vector (polynomial count + flattened coefficients).
pub fn write_module_vec(v: &[Poly]) -> Vec<u8> {
    let mut out = Vec::new();
    append_module_vec(&mut out, v);
    out
}

/// Parse [`write_module_vec`] output.
pub fn read_module_vec(data: &[u8]) -> Result<Vec<Poly>, VerifyError> {
    if data.len() < 4 {
        return Err(VerifyError::InvalidFormat);
    }
    let n = u32::from_le_bytes(
        data[0..4]
            .try_into()
            .map_err(|_| VerifyError::InvalidFormat)?,
    ) as usize;
    // Use checked arithmetic for the required byte length so a hostile `n` cannot overflow
    // `usize` and wrap to a small `need` that passes the length check (#7).
    let need = n
        .checked_mul(COEFFICIENTS_IN_RING_ELEMENT)
        .and_then(|v| v.checked_mul(4))
        .and_then(|v| v.checked_add(4))
        .ok_or(VerifyError::InvalidFormat)?;
    if data.len() < need {
        return Err(VerifyError::InvalidFormat);
    }
    let mut out = Vec::with_capacity(n);
    let mut off = 4;
    for _ in 0..n {
        let mut coeffs = [0i32; COEFFICIENTS_IN_RING_ELEMENT];
        for c in &mut coeffs {
            let v = i32::from_le_bytes(
                data[off..off + 4]
                    .try_into()
                    .map_err(|_| VerifyError::InvalidFormat)?,
            );
            // Range-check decoded coefficients (#7). This serializer preserves signed values
            // (callers may store either canonical `[0, q)` or centered `(-q, q)` representatives),
            // so we reject any coefficient whose magnitude reaches the modulus: a valid reduced or
            // centered representative always satisfies `|v| < q`. This stops out-of-range garbage
            // from entering ring arithmetic. Trust assumption: within `(-q, q)` both canonical and
            // centered encodings are accepted; canonicalization (if required) happens downstream.
            if v <= -FIELD_MODULUS || v >= FIELD_MODULUS {
                return Err(VerifyError::InvalidFormat);
            }
            *c = v;
            off += 4;
        }
        out.push(Poly::from_coeffs(coeffs));
    }
    Ok(out)
}
