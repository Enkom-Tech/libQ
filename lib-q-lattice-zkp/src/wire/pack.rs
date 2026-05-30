//! Compact polynomial packing for `lattice_zkp_wire_v0`.

use alloc::vec::Vec;

use lib_q_ring::Poly;
use lib_q_ring::constants::COEFFICIENTS_IN_RING_ELEMENT;
use lib_q_ring::encoding::{
    simple_bit_pack,
    simple_bit_pack_len,
    simple_bit_unpack,
};

use crate::error::VerifyError;
use crate::profile::RQ_COEFF_PACK_BITS;

/// Canonical unsigned representative in `[0, q)`.
#[must_use]
pub fn coeff_to_unsigned(c: i32, modulus: i32) -> i32 {
    let q = modulus as i64;
    let mut v = c as i64 % q;
    if v < 0 {
        v += q;
    }
    v as i32
}

/// Map signed `c` in `[-bound, bound]` to unsigned bias code.
pub fn signed_to_bias(c: i32, bound: i32) -> Result<u32, VerifyError> {
    if c < -bound || c > bound {
        return Err(VerifyError::Rejected);
    }
    Ok((c + bound) as u32)
}

/// Inverse of [`signed_to_bias`].
#[must_use]
pub fn bias_to_signed(code: u32, bound: i32) -> i32 {
    code as i32 - bound
}

/// Pack one `R_q` polynomial (coefficients reduced mod `q`, `RQ_COEFF_PACK_BITS` each).
pub fn pack_rq_poly(poly: &Poly, modulus: i32, out: &mut Vec<u8>) -> Result<(), VerifyError> {
    let len = simple_bit_pack_len(usize::from(RQ_COEFF_PACK_BITS));
    let start = out.len();
    out.resize(start + len, 0);
    let mut unsigned = [0i32; COEFFICIENTS_IN_RING_ELEMENT];
    for (u, &c) in unsigned.iter_mut().zip(poly.coeffs.iter()) {
        *u = coeff_to_unsigned(c, modulus);
    }
    simple_bit_pack(RQ_COEFF_PACK_BITS, &unsigned, &mut out[start..start + len]);
    Ok(())
}

/// Unpack one `R_q` polynomial.
pub fn unpack_rq_poly(data: &[u8], modulus: i32) -> Result<(Poly, usize), VerifyError> {
    let len = simple_bit_pack_len(usize::from(RQ_COEFF_PACK_BITS));
    if data.len() < len {
        return Err(VerifyError::InvalidFormat);
    }
    let mut coeffs = [0i32; COEFFICIENTS_IN_RING_ELEMENT];
    simple_bit_unpack(RQ_COEFF_PACK_BITS, &data[..len], &mut coeffs);
    for c in &mut coeffs {
        if *c < 0 || *c >= modulus {
            return Err(VerifyError::InvalidFormat);
        }
    }
    Ok((Poly::from_coeffs(coeffs), len))
}

/// Pack bounded signed response polynomial.
pub fn pack_bounded_z_poly(
    poly: &Poly,
    bound: i32,
    pack_bits: u8,
    out: &mut Vec<u8>,
) -> Result<(), VerifyError> {
    let len = simple_bit_pack_len(usize::from(pack_bits));
    let start = out.len();
    out.resize(start + len, 0);
    let mut unsigned = [0i32; COEFFICIENTS_IN_RING_ELEMENT];
    for (u, &c) in unsigned.iter_mut().zip(poly.coeffs.iter()) {
        *u = signed_to_bias(c, bound)? as i32;
    }
    simple_bit_pack(pack_bits, &unsigned, &mut out[start..start + len]);
    Ok(())
}

/// Unpack bounded signed response polynomial.
pub fn unpack_bounded_z_poly(
    data: &[u8],
    bound: i32,
    pack_bits: u8,
) -> Result<(Poly, usize), VerifyError> {
    let len = simple_bit_pack_len(usize::from(pack_bits));
    if data.len() < len {
        return Err(VerifyError::InvalidFormat);
    }
    let mut unsigned = [0i32; COEFFICIENTS_IN_RING_ELEMENT];
    simple_bit_unpack(pack_bits, &data[..len], &mut unsigned);
    let max_code = (1u32 << pack_bits).saturating_sub(1);
    let mut coeffs = [0i32; COEFFICIENTS_IN_RING_ELEMENT];
    for (c, &u) in coeffs.iter_mut().zip(unsigned.iter()) {
        if u < 0 || (u as u32) > max_code {
            return Err(VerifyError::InvalidFormat);
        }
        *c = bias_to_signed(u as u32, bound);
        if *c < -bound || *c > bound {
            return Err(VerifyError::Rejected);
        }
    }
    Ok((Poly::from_coeffs(coeffs), len))
}

/// Pack a module vector of `R_q` polynomials.
pub fn pack_rq_module(polys: &[Poly], modulus: i32, out: &mut Vec<u8>) -> Result<(), VerifyError> {
    let n = polys.len();
    if n > u16::MAX as usize {
        return Err(VerifyError::InvalidFormat);
    }
    out.extend_from_slice(&(n as u16).to_le_bytes());
    for p in polys {
        pack_rq_poly(p, modulus, out)?;
    }
    Ok(())
}

/// Unpack a module vector of `R_q` polynomials.
pub fn unpack_rq_module(data: &[u8], modulus: i32) -> Result<(Vec<Poly>, usize), VerifyError> {
    if data.len() < 2 {
        return Err(VerifyError::InvalidFormat);
    }
    let n = u16::from_le_bytes([data[0], data[1]]) as usize;
    let mut off = 2;
    let mut polys = Vec::with_capacity(n);
    for _ in 0..n {
        let (p, consumed) = unpack_rq_poly(&data[off..], modulus)?;
        polys.push(p);
        off = off.saturating_add(consumed);
        if off > data.len() {
            return Err(VerifyError::InvalidFormat);
        }
    }
    Ok((polys, off))
}

/// Pack bounded `z` module vector.
pub fn pack_z_module(
    polys: &[Poly],
    bound: i32,
    pack_bits: u8,
    out: &mut Vec<u8>,
) -> Result<(), VerifyError> {
    let n = polys.len();
    if n > u16::MAX as usize {
        return Err(VerifyError::InvalidFormat);
    }
    out.extend_from_slice(&(n as u16).to_le_bytes());
    for p in polys {
        pack_bounded_z_poly(p, bound, pack_bits, out)?;
    }
    Ok(())
}

/// Unpack bounded `z` module vector.
pub fn unpack_z_module(
    data: &[u8],
    bound: i32,
    pack_bits: u8,
) -> Result<(Vec<Poly>, usize), VerifyError> {
    if data.len() < 2 {
        return Err(VerifyError::InvalidFormat);
    }
    let n = u16::from_le_bytes([data[0], data[1]]) as usize;
    let mut off = 2;
    let mut polys = Vec::with_capacity(n);
    for _ in 0..n {
        let (p, consumed) = unpack_bounded_z_poly(&data[off..], bound, pack_bits)?;
        polys.push(p);
        off = off.saturating_add(consumed);
        if off > data.len() {
            return Err(VerifyError::InvalidFormat);
        }
    }
    Ok((polys, off))
}
