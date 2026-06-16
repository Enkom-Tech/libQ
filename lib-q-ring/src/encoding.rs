//! FIPS 204-style bit packing for bounded unsigned coefficient vectors.

use crate::constants::COEFFICIENTS_IN_RING_ELEMENT;

/// Byte length for [`simple_bit_pack`] / [`simple_bit_unpack`] with `w` bits per coefficient.
#[must_use]
pub const fn simple_bit_pack_len(w: usize) -> usize {
    (COEFFICIENTS_IN_RING_ELEMENT * w).div_ceil(8)
}

/// Pack 256 coefficients, each using `w` bits, least-significant bit first within each coefficient,
/// coefficients in order `0 … 255`, bit stream little-endian across bytes (FIPS 204 “SimpleBitPack”).
///
/// # Panics
///
/// If any coefficient is outside `[0, 2^w)`.
pub fn simple_bit_pack(w: u8, coeffs: &[i32; COEFFICIENTS_IN_RING_ELEMENT], out: &mut [u8]) {
    let w = usize::from(w);
    assert_eq!(out.len(), simple_bit_pack_len(w), "output length mismatch");
    let max = 1i32.checked_shl(w as u32).expect("w too large");
    out.fill(0);
    let mut bit_idx = 0usize;
    for &c in coeffs {
        assert!(c >= 0 && c < max, "coefficient out of range for w={w}");
        let u = c as u32;
        for b in 0..w {
            let bit = (u >> b) & 1;
            let byte_i = bit_idx / 8;
            let bit_in_byte = bit_idx % 8;
            out[byte_i] |= (bit as u8) << bit_in_byte;
            bit_idx += 1;
        }
    }
}

/// Inverse of [`simple_bit_pack`].
///
/// # Panics
///
/// If `data` is shorter than [`simple_bit_pack_len`]`(w)`.
pub fn simple_bit_unpack(w: u8, data: &[u8], out: &mut [i32; COEFFICIENTS_IN_RING_ELEMENT]) {
    let w = usize::from(w);
    let need = simple_bit_pack_len(w);
    assert!(data.len() >= need, "input too short");
    // Use a u64 intermediate so that w == 32 produces a mask of all-ones (u32::MAX)
    // without overflowing a u32 shift.
    let mask = ((1u64 << w).wrapping_sub(1)) as u32;
    let mut bit_idx = 0usize;
    for o in out.iter_mut() {
        let mut v = 0u32;
        for b in 0..w {
            let byte_i = bit_idx / 8;
            let bit_in_byte = bit_idx % 8;
            let bit = ((data[byte_i] >> bit_in_byte) & 1) as u32;
            v |= bit << b;
            bit_idx += 1;
        }
        *o = (v & mask) as i32;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_pack_roundtrip_w4_w6_w20() {
        for w in [4u8, 6, 10, 20] {
            let mut coeffs = [0i32; COEFFICIENTS_IN_RING_ELEMENT];
            for (i, c) in coeffs.iter_mut().enumerate() {
                *c = (i % (1 << (w as usize))) as i32;
            }
            let len = simple_bit_pack_len(w as usize);
            let mut buf = [0u8; 800];
            simple_bit_pack(w, &coeffs, &mut buf[..len]);
            let mut back = [0i32; COEFFICIENTS_IN_RING_ELEMENT];
            simple_bit_unpack(w, &buf[..len], &mut back);
            assert_eq!(coeffs, back);
        }
    }
}
