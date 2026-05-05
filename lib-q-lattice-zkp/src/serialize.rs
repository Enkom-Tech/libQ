//! Minimal deterministic serialization (big-endian `u32` length prefixes + coefficient bytes).

use alloc::vec::Vec;

use lib_q_ring::Poly;
use lib_q_ring::constants::COEFFICIENTS_IN_RING_ELEMENT;

use crate::error::VerifyError;

fn push_i32_le(buf: &mut Vec<u8>, v: i32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

/// Serialize a module vector (polynomial count + flattened coefficients).
pub fn write_module_vec(v: &[Poly]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(v.len() as u32).to_le_bytes());
    for p in v {
        for &c in &p.coeffs {
            push_i32_le(&mut out, c);
        }
    }
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
    let need = 4 + n * COEFFICIENTS_IN_RING_ELEMENT * 4;
    if data.len() < need {
        return Err(VerifyError::InvalidFormat);
    }
    let mut out = Vec::with_capacity(n);
    let mut off = 4;
    for _ in 0..n {
        let mut coeffs = [0i32; COEFFICIENTS_IN_RING_ELEMENT];
        for c in &mut coeffs {
            *c = i32::from_le_bytes(
                data[off..off + 4]
                    .try_into()
                    .map_err(|_| VerifyError::InvalidFormat)?,
            );
            off += 4;
        }
        out.push(Poly::from_coeffs(coeffs));
    }
    Ok(out)
}
