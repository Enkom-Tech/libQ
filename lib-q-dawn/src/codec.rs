//! Lossless bit-packed encoding for DAWN polynomials (public key and ciphertext).

/// Bits per coefficient for public/secret key (full modulus range).
/// ceil(log2(q)) for q in [1, 2^32).
pub fn pk_bits_per_coeff(q: u32) -> usize {
    if q <= 1 {
        return 1;
    }
    (32 - (q - 1).leading_zeros()) as usize
}

/// Bits per coefficient for compressed ciphertext (values in [0, (q+d_c/2)/d_c]).
pub fn ct_bits_per_coeff(q: u32, d_c: u32) -> usize {
    let max_ct = (q + d_c / 2) / d_c;
    if max_ct == 0 {
        return 1;
    }
    (32 - max_ct.leading_zeros()) as usize
}

/// Pack `n` unsigned integers, each fitting in `bits` bits, into a byte vector.
/// Total output length = ceil(n * bits / 8) bytes.
pub fn pack_bits(values: &[u32], bits: usize) -> Vec<u8> {
    let total_bits = values.len() * bits;
    let mut out = vec![0u8; total_bits.div_ceil(8)];
    let mut bit_pos = 0usize;
    for &v in values {
        for b in 0..bits {
            if ((v >> b) & 1) == 1 {
                out[bit_pos / 8] |= 1 << (bit_pos % 8);
            }
            bit_pos += 1;
        }
    }
    out
}

/// Unpack bytes into `n` unsigned integers, each `bits` bits wide.
pub fn unpack_bits(bytes: &[u8], n: usize, bits: usize) -> Vec<u32> {
    let mut out = vec![0u32; n];
    let mask = (1u32 << bits).wrapping_sub(1);
    let mut bit_pos = 0usize;
    for slot in out.iter_mut() {
        let mut v = 0u32;
        for b in 0..bits {
            let byte_idx = bit_pos / 8;
            let bit_idx = bit_pos % 8;
            if byte_idx < bytes.len() && ((bytes[byte_idx] >> bit_idx) & 1) == 1 {
                v |= 1 << b;
            }
            bit_pos += 1;
        }
        *slot = v & mask;
    }
    out
}
