//! AVX2 kernels for Saturnin helpers.

use alloc::vec;
use alloc::vec::Vec;
use core::arch::x86_64::{
    __m256i,
    _mm256_and_si256,
    _mm256_loadu_si256,
    _mm256_or_si256,
    _mm256_set_epi32,
    _mm256_set1_epi16,
    _mm256_set1_epi32,
    _mm256_slli_epi16,
    _mm256_slli_epi32,
    _mm256_srli_epi16,
    _mm256_srli_epi32,
    _mm256_storeu_si256,
    _mm256_xor_si256,
};

use lib_q_core::{
    Error,
    Result,
};

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn v_xor(a: __m256i, b: __m256i) -> __m256i {
    _mm256_xor_si256(a, b)
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn v_and(a: __m256i, b: __m256i) -> __m256i {
    _mm256_and_si256(a, b)
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn v_or(a: __m256i, b: __m256i) -> __m256i {
    _mm256_or_si256(a, b)
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn v_rol16(x: __m256i) -> __m256i {
    // 16-bit rotate within each 32-bit lane.
    let l = _mm256_slli_epi32(x, 16);
    let r = _mm256_srli_epi32(x, 16);
    _mm256_or_si256(l, r)
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn v_set1(v: u32) -> __m256i {
    _mm256_set1_epi32(v as i32)
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn load_words(words: &[u32; 8]) -> __m256i {
    _mm256_set_epi32(
        words[7] as i32,
        words[6] as i32,
        words[5] as i32,
        words[4] as i32,
        words[3] as i32,
        words[2] as i32,
        words[1] as i32,
        words[0] as i32,
    )
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn store_words(v: __m256i) -> [u32; 8] {
    let mut out = [0u32; 8];
    // SAFETY: out has exactly 32 bytes and unaligned store is allowed.
    unsafe {
        _mm256_storeu_si256(out.as_mut_ptr().cast::<__m256i>(), v);
    }
    out
}

/// AVX2 XOR for one 32-byte block.
///
/// # Safety
///
/// Caller must ensure AVX2 is available on the executing CPU before calling.
/// Input and output pointers must be valid for 32-byte reads/writes.
#[target_feature(enable = "avx2")]
pub unsafe fn xor_blocks_32(a: &[u8; 32], b: &[u8; 32], result: &mut [u8; 32]) {
    // SAFETY: AVX2 target feature is enabled by function contract.
    let va = unsafe { _mm256_loadu_si256(a.as_ptr().cast::<__m256i>()) };
    // SAFETY: AVX2 target feature is enabled by function contract.
    let vb = unsafe { _mm256_loadu_si256(b.as_ptr().cast::<__m256i>()) };
    // SAFETY: AVX2 target feature is enabled by function contract.
    let vr = _mm256_xor_si256(va, vb);
    // SAFETY: result points to 32 bytes and unaligned store is allowed.
    unsafe {
        _mm256_storeu_si256(result.as_mut_ptr().cast::<__m256i>(), vr);
    }
}

#[target_feature(enable = "avx2")]
unsafe fn decode_blocks8(blocks: &[[u8; 32]; 8]) -> [__m256i; 8] {
    let mut words = [[0u32; 8]; 8];

    for lane in 0..8 {
        let src = &blocks[lane];
        words[0][lane] = (src[0] as u32) |
            ((src[1] as u32) << 8) |
            ((src[16] as u32) << 16) |
            ((src[17] as u32) << 24);
        words[1][lane] = (src[2] as u32) |
            ((src[3] as u32) << 8) |
            ((src[18] as u32) << 16) |
            ((src[19] as u32) << 24);
        words[2][lane] = (src[4] as u32) |
            ((src[5] as u32) << 8) |
            ((src[20] as u32) << 16) |
            ((src[21] as u32) << 24);
        words[3][lane] = (src[6] as u32) |
            ((src[7] as u32) << 8) |
            ((src[22] as u32) << 16) |
            ((src[23] as u32) << 24);
        words[4][lane] = (src[8] as u32) |
            ((src[9] as u32) << 8) |
            ((src[24] as u32) << 16) |
            ((src[25] as u32) << 24);
        words[5][lane] = (src[10] as u32) |
            ((src[11] as u32) << 8) |
            ((src[26] as u32) << 16) |
            ((src[27] as u32) << 24);
        words[6][lane] = (src[12] as u32) |
            ((src[13] as u32) << 8) |
            ((src[28] as u32) << 16) |
            ((src[29] as u32) << 24);
        words[7][lane] = (src[14] as u32) |
            ((src[15] as u32) << 8) |
            ((src[30] as u32) << 16) |
            ((src[31] as u32) << 24);
    }

    [
        unsafe { load_words(&words[0]) },
        unsafe { load_words(&words[1]) },
        unsafe { load_words(&words[2]) },
        unsafe { load_words(&words[3]) },
        unsafe { load_words(&words[4]) },
        unsafe { load_words(&words[5]) },
        unsafe { load_words(&words[6]) },
        unsafe { load_words(&words[7]) },
    ]
}

#[target_feature(enable = "avx2")]
unsafe fn encode_blocks8(q: &[__m256i; 8], blocks: &mut [[u8; 32]; 8]) {
    let mut words = [[0u32; 8]; 8];
    for i in 0..8 {
        words[i] = unsafe { store_words(q[i]) };
    }

    for lane in 0..8 {
        let dst = &mut blocks[lane];
        let w0 = words[0][lane];
        let w1 = words[1][lane];
        let w2 = words[2][lane];
        let w3 = words[3][lane];
        let w4 = words[4][lane];
        let w5 = words[5][lane];
        let w6 = words[6][lane];
        let w7 = words[7][lane];

        dst[0] = w0 as u8;
        dst[1] = (w0 >> 8) as u8;
        dst[16] = (w0 >> 16) as u8;
        dst[17] = (w0 >> 24) as u8;

        dst[2] = w1 as u8;
        dst[3] = (w1 >> 8) as u8;
        dst[18] = (w1 >> 16) as u8;
        dst[19] = (w1 >> 24) as u8;

        dst[4] = w2 as u8;
        dst[5] = (w2 >> 8) as u8;
        dst[20] = (w2 >> 16) as u8;
        dst[21] = (w2 >> 24) as u8;

        dst[6] = w3 as u8;
        dst[7] = (w3 >> 8) as u8;
        dst[22] = (w3 >> 16) as u8;
        dst[23] = (w3 >> 24) as u8;

        dst[8] = w4 as u8;
        dst[9] = (w4 >> 8) as u8;
        dst[24] = (w4 >> 16) as u8;
        dst[25] = (w4 >> 24) as u8;

        dst[10] = w5 as u8;
        dst[11] = (w5 >> 8) as u8;
        dst[26] = (w5 >> 16) as u8;
        dst[27] = (w5 >> 24) as u8;

        dst[12] = w6 as u8;
        dst[13] = (w6 >> 8) as u8;
        dst[28] = (w6 >> 16) as u8;
        dst[29] = (w6 >> 24) as u8;

        dst[14] = w7 as u8;
        dst[15] = (w7 >> 8) as u8;
        dst[30] = (w7 >> 16) as u8;
        dst[31] = (w7 >> 24) as u8;
    }
}

#[target_feature(enable = "avx2")]
unsafe fn apply_sbox(q: &mut [__m256i; 8]) {
    let mut a = q[0];
    let mut b = q[1];
    let mut c = q[2];
    let mut d = q[3];
    a = unsafe { v_xor(a, v_and(b, c)) };
    b = unsafe { v_xor(b, v_or(a, d)) };
    d = unsafe { v_xor(d, v_or(b, c)) };
    c = unsafe { v_xor(c, v_and(b, d)) };
    b = unsafe { v_xor(b, v_or(a, c)) };
    a = unsafe { v_xor(a, v_or(b, d)) };
    q[0] = b;
    q[1] = c;
    q[2] = d;
    q[3] = a;

    let mut a = q[4];
    let mut b = q[5];
    let mut c = q[6];
    let mut d = q[7];
    a = unsafe { v_xor(a, v_and(b, c)) };
    b = unsafe { v_xor(b, v_or(a, d)) };
    d = unsafe { v_xor(d, v_or(b, c)) };
    c = unsafe { v_xor(c, v_and(b, d)) };
    b = unsafe { v_xor(b, v_or(a, c)) };
    a = unsafe { v_xor(a, v_or(b, d)) };
    q[4] = d;
    q[5] = b;
    q[6] = a;
    q[7] = c;
}

#[target_feature(enable = "avx2")]
unsafe fn mul_column_4_7(q: &mut [__m256i; 8]) {
    let tmp = q[4];
    q[4] = q[5];
    q[5] = q[6];
    q[6] = q[7];
    q[7] = unsafe { v_xor(tmp, q[4]) };
}

#[target_feature(enable = "avx2")]
unsafe fn mul_column_0_3(q: &mut [__m256i; 8]) {
    let tmp = q[0];
    q[0] = q[1];
    q[1] = q[2];
    q[2] = q[3];
    q[3] = unsafe { v_xor(tmp, q[0]) };
}

#[target_feature(enable = "avx2")]
unsafe fn apply_mds(q: &mut [__m256i; 8]) {
    q[0] = unsafe { v_xor(q[0], q[4]) };
    q[1] = unsafe { v_xor(q[1], q[5]) };
    q[2] = unsafe { v_xor(q[2], q[6]) };
    q[3] = unsafe { v_xor(q[3], q[7]) };

    unsafe { mul_column_4_7(q) };

    q[4] = unsafe { v_xor(q[4], v_rol16(q[0])) };
    q[5] = unsafe { v_xor(q[5], v_rol16(q[1])) };
    q[6] = unsafe { v_xor(q[6], v_rol16(q[2])) };
    q[7] = unsafe { v_xor(q[7], v_rol16(q[3])) };

    unsafe { mul_column_0_3(q) };
    unsafe { mul_column_0_3(q) };

    q[0] = unsafe { v_xor(q[0], q[4]) };
    q[1] = unsafe { v_xor(q[1], q[5]) };
    q[2] = unsafe { v_xor(q[2], q[6]) };
    q[3] = unsafe { v_xor(q[3], q[7]) };

    q[4] = unsafe { v_xor(q[4], v_rol16(q[0])) };
    q[5] = unsafe { v_xor(q[5], v_rol16(q[1])) };
    q[6] = unsafe { v_xor(q[6], v_rol16(q[2])) };
    q[7] = unsafe { v_xor(q[7], v_rol16(q[3])) };
}

#[target_feature(enable = "avx2")]
unsafe fn apply_shift_rows_slice(q: &mut [__m256i; 8]) {
    let mffff = unsafe { v_set1(0x0000_FFFF) };
    let m3333 = unsafe { v_set1(0x3333_0000) };
    let m7777_low = unsafe { v_set1(0x0000_7777) };
    let m1111_low = unsafe { v_set1(0x0000_1111) };
    let m1111_hi = unsafe { v_set1(0x1111_0000) };
    let m7777_hi = unsafe { v_set1(0x7777_0000) };

    for qi in q.iter_mut().take(4) {
        let x = *qi;
        let low = unsafe { v_and(x, mffff) };
        let a = unsafe { _mm256_slli_epi32(v_and(x, m3333), 2) };
        let b = unsafe { v_and(_mm256_srli_epi32(x, 2), m3333) };
        *qi = unsafe { v_or(low, v_or(a, b)) };
    }

    for qi in q.iter_mut().take(8).skip(4) {
        let x = *qi;
        let a = unsafe { _mm256_slli_epi32(v_and(x, m7777_low), 1) };
        let b = unsafe { v_and(_mm256_srli_epi32(x, 3), m1111_low) };
        let c = unsafe { _mm256_slli_epi32(v_and(x, m1111_hi), 3) };
        let d = unsafe { v_and(_mm256_srli_epi32(x, 1), m7777_hi) };
        *qi = unsafe { v_or(v_or(a, b), v_or(c, d)) };
    }
}

#[target_feature(enable = "avx2")]
unsafe fn apply_shift_rows_slice_inv(q: &mut [__m256i; 8]) {
    let mffff = unsafe { v_set1(0x0000_FFFF) };
    let m3333 = unsafe { v_set1(0x3333_0000) };
    let m1111_low = unsafe { v_set1(0x0000_1111) };
    let m7777_low = unsafe { v_set1(0x0000_7777) };
    let m7777_hi = unsafe { v_set1(0x7777_0000) };
    let m1111_hi = unsafe { v_set1(0x1111_0000) };

    for qi in q.iter_mut().take(4) {
        let x = *qi;
        let low = unsafe { v_and(x, mffff) };
        let a = unsafe { _mm256_slli_epi32(v_and(x, m3333), 2) };
        let b = unsafe { v_and(_mm256_srli_epi32(x, 2), m3333) };
        *qi = unsafe { v_or(low, v_or(a, b)) };
    }

    for qi in q.iter_mut().take(8).skip(4) {
        let x = *qi;
        let a = unsafe { _mm256_slli_epi32(v_and(x, m1111_low), 3) };
        let b = unsafe { v_and(_mm256_srli_epi32(x, 1), m7777_low) };
        let c = unsafe { _mm256_slli_epi32(v_and(x, m7777_hi), 1) };
        let d = unsafe { v_and(_mm256_srli_epi32(x, 3), m1111_hi) };
        *qi = unsafe { v_or(v_or(a, b), v_or(c, d)) };
    }
}

#[target_feature(enable = "avx2")]
unsafe fn apply_shift_rows_sheet(q: &mut [__m256i; 8]) {
    let mffff = unsafe { v_set1(0x0000_FFFF) };
    let m00ff = unsafe { v_set1(0x00FF_0000) };
    let m0fff_low = unsafe { v_set1(0x0000_0FFF) };
    let m000f_low = unsafe { v_set1(0x0000_000F) };
    let m000f_hi = unsafe { v_set1(0x000F_0000) };
    let m0fff_hi = unsafe { v_set1(0x0FFF_0000) };

    for qi in q.iter_mut().take(4) {
        let x = *qi;
        let low = unsafe { v_and(x, mffff) };
        let a = unsafe { _mm256_slli_epi32(v_and(x, m00ff), 8) };
        let b = unsafe { v_and(_mm256_srli_epi32(x, 8), m00ff) };
        *qi = unsafe { v_or(low, v_or(a, b)) };
    }

    for qi in q.iter_mut().take(8).skip(4) {
        let x = *qi;
        let a = unsafe { _mm256_slli_epi32(v_and(x, m0fff_low), 4) };
        let b = unsafe { v_and(_mm256_srli_epi32(x, 12), m000f_low) };
        let c = unsafe { _mm256_slli_epi32(v_and(x, m000f_hi), 12) };
        let d = unsafe { v_and(_mm256_srli_epi32(x, 4), m0fff_hi) };
        *qi = unsafe { v_or(v_or(a, b), v_or(c, d)) };
    }
}

#[target_feature(enable = "avx2")]
unsafe fn apply_shift_rows_sheet_inv(q: &mut [__m256i; 8]) {
    let mffff = unsafe { v_set1(0x0000_FFFF) };
    let m00ff = unsafe { v_set1(0x00FF_0000) };
    let m000f_low = unsafe { v_set1(0x0000_000F) };
    let m0fff_low = unsafe { v_set1(0x0000_0FFF) };
    let m0fff_hi = unsafe { v_set1(0x0FFF_0000) };
    let m000f_hi = unsafe { v_set1(0x000F_0000) };

    for qi in q.iter_mut().take(4) {
        let x = *qi;
        let low = unsafe { v_and(x, mffff) };
        let a = unsafe { _mm256_slli_epi32(v_and(x, m00ff), 8) };
        let b = unsafe { v_and(_mm256_srli_epi32(x, 8), m00ff) };
        *qi = unsafe { v_or(low, v_or(a, b)) };
    }

    for qi in q.iter_mut().take(8).skip(4) {
        let x = *qi;
        let a = unsafe { _mm256_slli_epi32(v_and(x, m000f_low), 12) };
        let b = unsafe { v_and(_mm256_srli_epi32(x, 4), m0fff_low) };
        let c = unsafe { _mm256_slli_epi32(v_and(x, m0fff_hi), 4) };
        let d = unsafe { v_and(_mm256_srli_epi32(x, 12), m000f_hi) };
        *qi = unsafe { v_or(v_or(a, b), v_or(c, d)) };
    }
}

fn round_constants(num_super_rounds: usize, domain: u8) -> Vec<u32> {
    if num_super_rounds == 16 {
        match domain {
            7 => {
                return vec![
                    0x3FBA180C, 0x563AB9AB, 0x125EA5EF, 0x859DA26C, 0xB8CF779B, 0x7D4DE793,
                    0x07EFB49F, 0x8D525306, 0x1E08E6AB, 0x41729F87, 0x8C4AEF0A, 0x4AA0C9A7,
                    0xD93A95EF, 0xBB00D2AF, 0xB62C5BF0, 0x386D94D8,
                ];
            }
            8 => {
                return vec![
                    0x3C9B19A7, 0xA9098694, 0x23F878DA, 0xA7B647D3, 0x74FC9D78, 0xEACAAE11,
                    0x2F31A677, 0x4CC8C054, 0x2F51CA05, 0x5268F195, 0x4F5B8A2B, 0xF614B4AC,
                    0xF1D95401, 0x764D2568, 0x6A493611, 0x8EEF9C3E,
                ];
            }
            _ => {}
        }
    }

    let mut out = Vec::with_capacity(num_super_rounds);
    let mut x0 = (domain as u32)
        .wrapping_add((num_super_rounds as u32) << 4)
        .wrapping_add(0xFE00);
    let mut x1 = x0;
    for _ in 0..num_super_rounds {
        for _ in 0..16 {
            x0 = (x0 << 1) ^ (0x2D & (!(x0 >> 15).wrapping_add(1)));
            x1 = (x1 << 1) ^ (0x53 & (!(x1 >> 15).wrapping_add(1)));
        }
        out.push((x1 << 16) | x0);
    }
    out
}

#[inline]
#[target_feature(enable = "avx2")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn v16_set1(v: u16) -> __m256i {
    _mm256_set1_epi16(v as i16)
}

#[inline]
#[target_feature(enable = "avx2")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn rol16_4(x: __m256i) -> __m256i {
    _mm256_or_si256(_mm256_slli_epi16(x, 4), _mm256_srli_epi16(x, 12))
}

#[inline]
#[target_feature(enable = "avx2")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn rol16_8(x: __m256i) -> __m256i {
    _mm256_or_si256(_mm256_slli_epi16(x, 8), _mm256_srli_epi16(x, 8))
}

#[inline]
#[target_feature(enable = "avx2")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn rol16_12(x: __m256i) -> __m256i {
    _mm256_or_si256(_mm256_slli_epi16(x, 12), _mm256_srli_epi16(x, 4))
}

/// Decode eight 32-byte blocks into sixteen SIMD words.
///
/// Lane model (must match scalar `SaturninCore` semantics exactly):
/// - SIMD register index `w` corresponds to scalar state word `state[w]`.
/// - Lower 8 lanes hold blocks 0..7, upper 8 lanes are zero.
/// - Each word is little-endian `u16` (`block[2*w] | block[2*w+1] << 8`).
#[target_feature(enable = "avx2")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn decode_blocks8_core(blocks: &[[u8; 32]; 8]) -> [__m256i; 16] {
    let mut out = [_mm256_set1_epi16(0); 16];
    for (word, out_word) in out.iter_mut().enumerate() {
        let mut lanes = [0u16; 16];
        for lane in 0..8 {
            let offset = word * 2;
            lanes[lane] = (blocks[lane][offset] as u16) | ((blocks[lane][offset + 1] as u16) << 8);
        }
        *out_word = _mm256_loadu_si256(lanes.as_ptr().cast::<__m256i>());
    }
    out
}

#[target_feature(enable = "avx2")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn encode_blocks8_core(words: &[__m256i; 16], blocks: &mut [[u8; 32]; 8]) {
    for (word, simd_word) in words.iter().enumerate() {
        let mut lanes = [0u16; 16];
        _mm256_storeu_si256(lanes.as_mut_ptr().cast::<__m256i>(), *simd_word);
        for lane in 0..8 {
            let offset = word * 2;
            blocks[lane][offset] = lanes[lane] as u8;
            blocks[lane][offset + 1] = (lanes[lane] >> 8) as u8;
        }
    }
}

#[target_feature(enable = "avx2")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn apply_sbox_core(q: &mut [__m256i; 16]) {
    for base in [0usize, 8usize] {
        let mut a0 = q[base];
        let mut b0 = q[base + 1];
        let mut c0 = q[base + 2];
        let mut d0 = q[base + 3];
        let mut a1 = q[base + 4];
        let mut b1 = q[base + 5];
        let mut c1 = q[base + 6];
        let mut d1 = q[base + 7];

        a0 = v_xor(a0, v_and(b0, c0));
        b0 = v_xor(b0, v_or(a0, d0));
        d0 = v_xor(d0, v_or(b0, c0));
        c0 = v_xor(c0, v_and(b0, d0));
        b0 = v_xor(b0, v_or(a0, c0));
        a0 = v_xor(a0, v_or(b0, d0));

        a1 = v_xor(a1, v_and(b1, c1));
        b1 = v_xor(b1, v_or(a1, d1));
        d1 = v_xor(d1, v_or(b1, c1));
        c1 = v_xor(c1, v_and(b1, d1));
        b1 = v_xor(b1, v_or(a1, c1));
        a1 = v_xor(a1, v_or(b1, d1));

        q[base] = b0;
        q[base + 1] = c0;
        q[base + 2] = d0;
        q[base + 3] = a0;
        q[base + 4] = d1;
        q[base + 5] = b1;
        q[base + 6] = a1;
        q[base + 7] = c1;
    }
}

#[inline]
#[target_feature(enable = "avx2")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn mul_col_core(q: &mut [__m256i; 16], a: usize, b: usize, c: usize, d: usize) {
    let tmp = q[a];
    q[a] = q[b];
    q[b] = q[c];
    q[c] = q[d];
    q[d] = v_xor(tmp, q[a]);
}

#[target_feature(enable = "avx2")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn apply_mds_core(q: &mut [__m256i; 16]) {
    q[8] = v_xor(q[8], q[12]);
    q[9] = v_xor(q[9], q[13]);
    q[10] = v_xor(q[10], q[14]);
    q[11] = v_xor(q[11], q[15]);
    q[0] = v_xor(q[0], q[4]);
    q[1] = v_xor(q[1], q[5]);
    q[2] = v_xor(q[2], q[6]);
    q[3] = v_xor(q[3], q[7]);

    mul_col_core(q, 4, 5, 6, 7);
    mul_col_core(q, 12, 13, 14, 15);

    q[4] = v_xor(q[4], q[8]);
    q[5] = v_xor(q[5], q[9]);
    q[6] = v_xor(q[6], q[10]);
    q[7] = v_xor(q[7], q[11]);
    q[12] = v_xor(q[12], q[0]);
    q[13] = v_xor(q[13], q[1]);
    q[14] = v_xor(q[14], q[2]);
    q[15] = v_xor(q[15], q[3]);

    mul_col_core(q, 0, 1, 2, 3);
    mul_col_core(q, 0, 1, 2, 3);
    mul_col_core(q, 8, 9, 10, 11);
    mul_col_core(q, 8, 9, 10, 11);

    q[8] = v_xor(q[8], q[12]);
    q[9] = v_xor(q[9], q[13]);
    q[10] = v_xor(q[10], q[14]);
    q[11] = v_xor(q[11], q[15]);
    q[0] = v_xor(q[0], q[4]);
    q[1] = v_xor(q[1], q[5]);
    q[2] = v_xor(q[2], q[6]);
    q[3] = v_xor(q[3], q[7]);
    q[4] = v_xor(q[4], q[8]);
    q[5] = v_xor(q[5], q[9]);
    q[6] = v_xor(q[6], q[10]);
    q[7] = v_xor(q[7], q[11]);
    q[12] = v_xor(q[12], q[0]);
    q[13] = v_xor(q[13], q[1]);
    q[14] = v_xor(q[14], q[2]);
    q[15] = v_xor(q[15], q[3]);
}

#[target_feature(enable = "avx2")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn apply_shift_rows_slice_core(q: &mut [__m256i; 16]) {
    let m7777 = v16_set1(0x7777);
    let m8888 = v16_set1(0x8888);
    let m3333 = v16_set1(0x3333);
    let mcccc = v16_set1(0xCCCC);
    let m1111 = v16_set1(0x1111);
    let meeee = v16_set1(0xEEEE);

    for i in 0..4 {
        let x4 = q[4 + i];
        let x8 = q[8 + i];
        let xc = q[12 + i];
        q[4 + i] = v_or(
            _mm256_slli_epi16(v_and(x4, m7777), 1),
            _mm256_srli_epi16(v_and(x4, m8888), 3),
        );
        q[8 + i] = v_or(
            _mm256_slli_epi16(v_and(x8, m3333), 2),
            _mm256_srli_epi16(v_and(x8, mcccc), 2),
        );
        q[12 + i] = v_or(
            _mm256_slli_epi16(v_and(xc, m1111), 3),
            _mm256_srli_epi16(v_and(xc, meeee), 1),
        );
    }
}

#[target_feature(enable = "avx2")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn apply_shift_rows_slice_inv_core(q: &mut [__m256i; 16]) {
    let m7777 = v16_set1(0x7777);
    let m8888 = v16_set1(0x8888);
    let m3333 = v16_set1(0x3333);
    let mcccc = v16_set1(0xCCCC);
    let m1111 = v16_set1(0x1111);
    let meeee = v16_set1(0xEEEE);

    for i in 0..4 {
        let x4 = q[4 + i];
        let x8 = q[8 + i];
        let xc = q[12 + i];
        q[4 + i] = v_or(
            _mm256_slli_epi16(v_and(x4, m1111), 3),
            _mm256_srli_epi16(v_and(x4, meeee), 1),
        );
        q[8 + i] = v_or(
            _mm256_slli_epi16(v_and(x8, m3333), 2),
            _mm256_srli_epi16(v_and(x8, mcccc), 2),
        );
        q[12 + i] = v_or(
            _mm256_slli_epi16(v_and(xc, m7777), 1),
            _mm256_srli_epi16(v_and(xc, m8888), 3),
        );
    }
}

#[target_feature(enable = "avx2")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn apply_shift_rows_sheet_core(q: &mut [__m256i; 16]) {
    for i in 0..4 {
        q[4 + i] = rol16_4(q[4 + i]);
        q[8 + i] = rol16_8(q[8 + i]); // rotate_right(8) == rotate_left(8)
        q[12 + i] = rol16_12(q[12 + i]); // rotate_right(4)
    }
}

#[target_feature(enable = "avx2")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn apply_shift_rows_sheet_inv_core(q: &mut [__m256i; 16]) {
    for i in 0..4 {
        q[4 + i] = rol16_12(q[4 + i]); // rotate_right(4)
        q[8 + i] = rol16_8(q[8 + i]); // rotate_right(8)
        q[12 + i] = rol16_4(q[12 + i]); // rotate_left(4)
    }
}

/// Encrypts eight Saturnin-bs32 blocks in parallel.
///
/// This kernel is intended for throughput-oriented callers where multiple independent
/// blocks share the same `(num_super_rounds, domain, key)` parameters.
///
/// # Safety
///
/// Caller must ensure AVX2 is available on the executing CPU before calling.
/// The `blocks` buffer must contain exactly eight mutable 32-byte blocks.
#[target_feature(enable = "avx2")]
pub unsafe fn encrypt_blocks8(
    num_super_rounds: usize,
    domain: u8,
    key: &[u8; 32],
    blocks: &mut [[u8; 32]; 8],
) -> Result<()> {
    if num_super_rounds > 31 {
        return Err(Error::InvalidAlgorithm {
            algorithm: "Number of super-rounds must be <= 31",
        });
    }
    if domain > 15 {
        return Err(Error::InvalidAlgorithm {
            algorithm: "Domain must be <= 15",
        });
    }

    let mut keybuf = [0u32; 16];
    for i in 0..8 {
        let w = (key[i << 1] as u32) |
            ((key[(i << 1) + 1] as u32) << 8) |
            ((key[(i << 1) + 16] as u32) << 16) |
            ((key[(i << 1) + 17] as u32) << 24);
        keybuf[i] = w;
        keybuf[i + 8] = ((w & 0x001F001F) << 11) | ((w >> 5) & 0x07FF07FF);
    }

    let rc = round_constants(num_super_rounds, domain);
    let mut q = unsafe { decode_blocks8(blocks) };

    for i in 0..8 {
        q[i] = unsafe { v_xor(q[i], v_set1(keybuf[i])) };
    }

    for i in (0..num_super_rounds).step_by(2) {
        unsafe { apply_sbox(&mut q) };
        unsafe { apply_mds(&mut q) };

        unsafe { apply_sbox(&mut q) };
        unsafe { apply_shift_rows_slice(&mut q) };
        unsafe { apply_mds(&mut q) };
        unsafe { apply_shift_rows_slice_inv(&mut q) };
        q[0] = unsafe { v_xor(q[0], v_set1(rc[i])) };
        for j in 0..8 {
            q[j] = unsafe { v_xor(q[j], v_set1(keybuf[j + 8])) };
        }

        if i + 1 < num_super_rounds {
            unsafe { apply_sbox(&mut q) };
            unsafe { apply_mds(&mut q) };

            unsafe { apply_sbox(&mut q) };
            unsafe { apply_shift_rows_sheet(&mut q) };
            unsafe { apply_mds(&mut q) };
            unsafe { apply_shift_rows_sheet_inv(&mut q) };
            q[0] = unsafe { v_xor(q[0], v_set1(rc[i + 1])) };
            for j in 0..8 {
                q[j] = unsafe { v_xor(q[j], v_set1(keybuf[j])) };
            }
        }
    }

    unsafe { encode_blocks8(&q, blocks) };
    Ok(())
}

/// Encrypt eight blocks with semantics equivalent to `SaturninCore::encrypt_block`.
///
/// This kernel is intended for domain-1 CTR batching and must remain byte-for-byte
/// equivalent to the scalar core for all supported `(num_rounds, domain)` pairs.
///
/// # Safety
///
/// Caller must ensure AVX2 is available on the executing CPU before calling.
#[target_feature(enable = "avx2")]
#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn encrypt_blocks8_core(
    num_rounds: usize,
    domain: u8,
    key: &[u8; 32],
    blocks: &mut [[u8; 32]; 8],
) -> Result<()> {
    if num_rounds > 31 {
        return Err(Error::InvalidAlgorithm {
            algorithm: "Number of rounds must be <= 31",
        });
    }
    if domain > 15 {
        return Err(Error::InvalidAlgorithm {
            algorithm: "Domain must be <= 15",
        });
    }

    let core = crate::core::SaturninCore::new(num_rounds, domain)?;
    let rc = core.round_constants();
    let mut key_vec = [_mm256_set1_epi16(0); 16];
    let mut key_rot_vec = [_mm256_set1_epi16(0); 16];
    for i in 0..16 {
        let kw = (key[i * 2] as u16) | ((key[i * 2 + 1] as u16) << 8);
        key_vec[i] = v16_set1(kw);
        key_rot_vec[i] = v16_set1(kw.rotate_right(5));
    }

    let mut q = decode_blocks8_core(blocks);
    for i in 0..16 {
        q[i] = v_xor(q[i], key_vec[i]);
    }

    for round in 0..num_rounds {
        apply_sbox_core(&mut q);
        apply_mds_core(&mut q);
        apply_sbox_core(&mut q);

        if (round & 1) == 0 {
            apply_shift_rows_slice_core(&mut q);
            apply_mds_core(&mut q);
            apply_shift_rows_slice_inv_core(&mut q);
            q[0] = v_xor(q[0], v16_set1(rc[round * 2]));
            q[8] = v_xor(q[8], v16_set1(rc[round * 2 + 1]));
            for i in 0..16 {
                q[i] = v_xor(q[i], key_rot_vec[i]);
            }
        } else {
            apply_shift_rows_sheet_core(&mut q);
            apply_mds_core(&mut q);
            apply_shift_rows_sheet_inv_core(&mut q);
            q[0] = v_xor(q[0], v16_set1(rc[round * 2]));
            q[8] = v_xor(q[8], v16_set1(rc[round * 2 + 1]));
            for i in 0..16 {
                q[i] = v_xor(q[i], key_vec[i]);
            }
        }
    }

    encode_blocks8_core(&q, blocks);
    Ok(())
}
