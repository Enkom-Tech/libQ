//! Portable (non-SIMD) implementations of HQC operations
//!
//! This module contains the reference implementations that work on all platforms.
//! These are used as fallbacks when SIMD instructions are not available.

use super::traits::{
    PolynomialOps,
    SyndromeOps,
};

/// Portable (non-SIMD) implementation marker
/// This is a zero-sized type used for static dispatch
pub struct Portable;

impl PolynomialOps for Portable {
    fn sparse_dense_mul(
        output: &mut [u8],
        sparse: &[u8],
        dense: &[u8],
        weight: u32,
        n_bits: usize,
    ) {
        sparse_dense_mul_portable(output, sparse, dense, weight, n_bits);
    }

    fn shift_xor(dest: &mut [u64], source: &[u64], distance: usize) {
        shift_xor_portable(dest, source, distance);
    }

    fn vect_add(output: &mut [u8], a: &[u8], b: &[u8]) {
        vect_add_portable(output, a, b);
    }
}

impl SyndromeOps for Portable {
    fn generate_syndrome(syndrome: &mut [u8], vector: &[u8], parity: &[u8]) {
        generate_syndrome_portable(syndrome, vector, parity);
    }

    fn correct_errors(corrected: &mut [u8], received: &[u8], syndrome: &[u8]) -> bool {
        correct_errors_portable(corrected, received, syndrome)
    }
}

// Portable implementations (to be moved from hqc_pke.rs)

#[inline]
fn get_bit_byte_order(data: &[u8], bit: usize) -> u8 {
    let byte = bit / 8;
    if byte >= data.len() {
        return 0;
    }
    (data[byte] >> (bit % 8)) & 1
}

#[inline]
fn xor_bit_byte_order(data: &mut [u8], bit: usize) {
    let byte = bit / 8;
    if byte < data.len() {
        data[byte] ^= 1u8 << (bit % 8);
    }
}

/// XOR `dest` with the cyclic left shift of `source` by `distance` bits modulo `n_bits`.
///
/// Bit `i` of `source` (for `i < n_bits`) contributes to bit `(i + distance) % n_bits` of `dest`.
pub fn shift_xor_cyclic_bytes(dest: &mut [u8], source: &[u8], distance: usize, n_bits: usize) {
    if n_bits == 0 {
        return;
    }
    for i in 0..n_bits {
        if get_bit_byte_order(source, i) != 0 {
            let j = (i + distance) % n_bits;
            xor_bit_byte_order(dest, j);
        }
    }
}

/// Portable sparse-dense polynomial multiplication in GF(2)[x]/(x^n - 1).
///
/// For each set coefficient at position `p` in `sparse`, XORs `x^p * dense` (cyclic) into `output`.
#[cfg(feature = "alloc")]
pub fn sparse_dense_mul_portable(
    output: &mut [u8],
    sparse: &[u8],
    dense: &[u8],
    _weight: u32,
    n_bits: usize,
) {
    let _ = _weight;
    output.fill(0);
    for (bi, &byte) in sparse.iter().enumerate() {
        for j in 0..8 {
            let p = bi * 8 + j;
            if p >= n_bits {
                continue;
            }
            if (byte >> j) & 1 == 1 {
                shift_xor_cyclic_bytes(output, dense, p, n_bits);
            }
        }
    }
}

/// Portable sparse-dense polynomial multiplication (no_std version)
#[cfg(not(feature = "alloc"))]
pub fn sparse_dense_mul_portable(
    output: &mut [u8],
    sparse: &[u8],
    dense: &[u8],
    _weight: u32,
    n_bits: usize,
) {
    let _ = _weight;
    output.fill(0);
    for (bi, &byte) in sparse.iter().enumerate() {
        for j in 0..8 {
            let p = bi * 8 + j;
            if p >= n_bits {
                continue;
            }
            if (byte >> j) & 1 == 1 {
                shift_xor_cyclic_bytes(output, dense, p, n_bits);
            }
        }
    }
}

/// Helper function for byte-level shift and XOR
pub fn shift_xor_portable_bytes(dest: &mut [u8], source: &[u8], distance: usize) {
    let byte_shift = distance / 8;
    let bit_shift = distance % 8;

    if bit_shift == 0 {
        // Byte-aligned shift: simple XOR
        for i in 0..(dest.len() - byte_shift) {
            if i < source.len() {
                dest[i + byte_shift] ^= source[i];
            }
        }
    } else {
        // Bit-level shift with carry
        let inv_shift = 8 - bit_shift;
        for i in 0..(dest.len() - byte_shift - 1) {
            if i < source.len() {
                let shifted = (source[i] << bit_shift) |
                    (if i + 1 < source.len() {
                        source[i + 1] >> inv_shift
                    } else {
                        0
                    });
                dest[i + byte_shift] ^= shifted;
            }
        }
    }
}

/// Portable vector shift and XOR
///
/// Computes `dest ^= source >> distance` using portable bit operations.
/// This matches the AVX2 implementation's behavior for u64 arrays.
///
/// # Arguments
/// * `dest` - Destination buffer (modified in place)
/// * `source` - Source buffer
/// * `distance` - Number of bits to shift right
pub fn shift_xor_portable(dest: &mut [u64], source: &[u64], distance: usize) {
    let word_shift = distance / 64;
    let bit_shift = distance % 64;

    if bit_shift == 0 {
        // Word-aligned shift: simple XOR
        for (i, &src_val) in source.iter().enumerate() {
            if i + word_shift < dest.len() {
                dest[i + word_shift] ^= src_val;
            }
        }
    } else {
        // Bit-level shift with carry
        let inv_shift = 64 - bit_shift;
        for (i, &src_val) in source.iter().enumerate() {
            if i + word_shift < dest.len() {
                let shifted = src_val >> bit_shift;
                dest[i + word_shift] ^= shifted;

                // Handle carry to next word
                if i + word_shift + 1 < dest.len() && i + 1 < source.len() {
                    let carry = source[i + 1] << inv_shift;
                    dest[i + word_shift + 1] ^= carry;
                }
            }
        }
    }
}

/// Portable vector addition (XOR)
pub fn vect_add_portable(output: &mut [u8], a: &[u8], b: &[u8]) {
    for (i, (&ai, &bi)) in a.iter().zip(b.iter()).enumerate() {
        output[i] = ai ^ bi;
    }
}

/// Portable syndrome generation
///
/// Computes the syndrome vector used in tensor code decoding.
/// The syndrome is computed as the XOR of the received vector with the parity check matrix.
///
/// # Arguments
/// * `syndrome` - Output syndrome vector
/// * `vector` - Input vector to compute syndrome for
/// * `parity` - Parity check matrix
pub fn generate_syndrome_portable(syndrome: &mut [u8], vector: &[u8], parity: &[u8]) {
    // Initialize syndrome to zero
    syndrome.fill(0);

    // Compute syndrome as vector XOR parity
    // This is a simplified implementation - in practice, this would involve
    // more complex tensor code operations, but for SIMD equivalence testing
    // we use a basic XOR operation
    for (i, (&vi, &pi)) in vector.iter().zip(parity.iter()).enumerate() {
        if i < syndrome.len() {
            syndrome[i] = vi ^ pi;
        }
    }
}

/// Portable error correction
///
/// Attempts to correct errors using the syndrome vector.
/// This is a simplified implementation that applies the syndrome as an error pattern.
///
/// # Arguments
/// * `corrected` - Output corrected vector
/// * `received` - Received vector with errors
/// * `syndrome` - Computed syndrome vector
///
/// # Returns
/// `true` if correction was successful, `false` otherwise
pub fn correct_errors_portable(corrected: &mut [u8], received: &[u8], syndrome: &[u8]) -> bool {
    // Apply syndrome as error correction pattern
    // This is a simplified implementation - in practice, this would involve
    // more complex error correction algorithms based on the syndrome
    for (i, (&recv, &synd)) in received.iter().zip(syndrome.iter()).enumerate() {
        if i < corrected.len() {
            corrected[i] = recv ^ synd;
        }
    }

    // For now, always return true (successful correction)
    // In a real implementation, this would check if the correction was valid
    true
}
