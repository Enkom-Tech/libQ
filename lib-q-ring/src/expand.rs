//! ExpandA (FIPS 204, Algorithm 34) — SHAKE128 rejection sampling per matrix entry.

use alloc::vec::Vec;

use lib_q_sha3::{
    ExtendableOutput,
    Shake128,
    Update,
    XofReader,
};

use crate::constants::{
    COEFFICIENTS_IN_RING_ELEMENT,
    FIELD_MODULUS,
    SHAKE128_BLOCK_SIZE,
    SHAKE128_FIVE_BLOCKS_SIZE,
};
use crate::poly::{
    NttPoly,
    Poly,
};

#[inline]
fn generate_domain_separator((row, column): (u8, u8)) -> u16 {
    (column as u16) | ((row as u16) << 8)
}

/// Domain-separated seed for matrix position `(row, col)` (ML-DSA `add_domain_separator`).
#[must_use]
pub fn add_domain_separator(slice: &[u8], indices: (u8, u8)) -> [u8; 34] {
    let mut out = [0u8; 34];
    out[0..slice.len()].copy_from_slice(slice);
    let domain_separator = generate_domain_separator(indices);
    out[32] = domain_separator as u8;
    out[33] = (domain_separator >> 8) as u8;
    out
}

/// Portable rejection sampling: interpret `randomness` as 24-byte chunks of 3-byte little-endian values `< q`.
fn rejection_sample_less_than_field_modulus(randomness: &[u8], out: &mut [i32]) -> usize {
    let mut sampled = 0;
    for i in 0..randomness.len() / 3 {
        let b0 = randomness[i * 3] as i32;
        let b1 = randomness[i * 3 + 1] as i32;
        let b2 = randomness[i * 3 + 2] as i32;
        let coefficient = ((b2 << 16) | (b1 << 8) | b0) & 0x007F_FFFF;
        if coefficient < FIELD_MODULUS && sampled < out.len() {
            out[sampled] = coefficient;
            sampled += 1;
        }
    }
    sampled
}

fn rejection_sample_fill_poly(
    randomness: &[u8],
    sampled_coefficients: &mut usize,
    tmp: &mut [i32; 263],
) -> bool {
    let mut done = false;
    for random_bytes in randomness.chunks_exact(24) {
        if !done {
            let n = rejection_sample_less_than_field_modulus(
                random_bytes,
                &mut tmp[*sampled_coefficients..],
            );
            *sampled_coefficients += n;
            if *sampled_coefficients >= COEFFICIENTS_IN_RING_ELEMENT {
                done = true;
            }
        }
    }
    done
}

/// Sample one matrix polynomial in the same representation as `lib-q-ml-dsa` after `matrix_flat`
/// (coefficient layout, **not** additionally NTT-transformed).
fn sample_matrix_polynomial(seed: &[u8], row: u8, col: u8) -> Poly {
    let domain = add_domain_separator(seed, (row, col));
    let mut hasher = Shake128::default();
    hasher.update(&domain);
    let mut reader = hasher.finalize_xof();

    let mut rand_stack = [0u8; SHAKE128_FIVE_BLOCKS_SIZE];
    reader.read(&mut rand_stack);

    let mut tmp = [0i32; 263];
    let mut sampled = 0usize;
    let mut done = rejection_sample_fill_poly(&rand_stack, &mut sampled, &mut tmp);

    while !done {
        let mut block = [0u8; SHAKE128_BLOCK_SIZE];
        reader.read(&mut block);
        done = rejection_sample_fill_poly(&block, &mut sampled, &mut tmp);
    }

    let mut coeffs = [0i32; COEFFICIENTS_IN_RING_ELEMENT];
    coeffs.copy_from_slice(&tmp[..COEFFICIENTS_IN_RING_ELEMENT]);
    Poly::from_coeffs(coeffs)
}

/// Expand the public matrix `A` (dimensions `rows × cols`) from seed `ρ` (FIPS 204 ExpandA).
///
/// Returns a row-major vector of [`NttPoly`] entries in the **NTT domain** used internally by
/// ML-DSA (`NTT` of each uniformly sampled time-domain polynomial).
#[must_use]
pub fn expand_a_from_seed(seed: &[u8; 32], rows: usize, cols: usize) -> Vec<NttPoly> {
    let mut out = Vec::with_capacity(rows * cols);
    for idx in 0..rows * cols {
        let r = (idx / cols) as u8;
        let c = (idx % cols) as u8;
        let p = sample_matrix_polynomial(seed, r, c);
        out.push(p.to_ntt());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_one_cell_ntt_matches_explicit_ntt() {
        let seed = [7u8; 32];
        let p = sample_matrix_polynomial(&seed, 1, 2);
        let from_expand = expand_a_from_seed(&seed, 3, 4);
        // Row-major: row 1, column 2, width 4 → linear index 6.
        let idx = 6;
        assert_eq!(from_expand[idx], p.to_ntt());
    }
}
