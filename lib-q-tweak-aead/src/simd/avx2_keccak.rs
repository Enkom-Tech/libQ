//! Four-way parallel Keccak-f[1600] over `__m256i` lanes (AVX2).
#![allow(unsafe_code)]
#![allow(unsafe_op_in_unsafe_fn)]

use core::arch::x86_64::*;

const PLEN: usize = 25;

#[rustfmt::skip]
const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];
#[rustfmt::skip]
const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];
#[allow(clippy::unreadable_literal)]
const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

#[inline(always)]
unsafe fn rotl64x4(v: __m256i, n: u32) -> __m256i {
    macro_rules! ro {
        ($k:literal) => {
            _mm256_or_si256(_mm256_slli_epi64(v, $k), _mm256_srli_epi64(v, 64 - $k))
        };
    }
    match n {
        1 => ro!(1),
        2 => ro!(2),
        3 => ro!(3),
        6 => ro!(6),
        8 => ro!(8),
        10 => ro!(10),
        14 => ro!(14),
        15 => ro!(15),
        18 => ro!(18),
        20 => ro!(20),
        21 => ro!(21),
        25 => ro!(25),
        27 => ro!(27),
        28 => ro!(28),
        36 => ro!(36),
        39 => ro!(39),
        41 => ro!(41),
        43 => ro!(43),
        44 => ro!(44),
        45 => ro!(45),
        55 => ro!(55),
        56 => ro!(56),
        61 => ro!(61),
        62 => ro!(62),
        _ => core::hint::unreachable_unchecked(),
    }
}

/// 24-round Keccak-f[1600] on four interleaved states (`state[w]` holds lane `j` = word `w` of instance `j`).
///
/// # Safety
///
/// The CPU must support AVX2.
#[target_feature(enable = "avx2")]
pub unsafe fn f1600_x4(state: &mut [__m256i; PLEN]) {
    for &rc in &RC {
        let mut c = [_mm256_setzero_si256(); 5];
        for x in 0..5usize {
            for y in 0..5usize {
                c[x] = _mm256_xor_si256(c[x], state[5 * y + x]);
            }
        }
        let mut d = [_mm256_setzero_si256(); 5];
        for x in 0..5usize {
            d[x] = _mm256_xor_si256(c[(x + 4) % 5], rotl64x4(c[(x + 1) % 5], 1));
        }
        for x in 0..5usize {
            for y in 0..5usize {
                state[5 * y + x] = _mm256_xor_si256(state[5 * y + x], d[x]);
            }
        }
        let mut last = state[1];
        for i in 0..24 {
            let dest = PI[i];
            let tmp = state[dest];
            state[dest] = rotl64x4(last, RHO[i]);
            last = tmp;
        }
        for y in 0..5usize {
            let row = 5 * y;
            let arr = [
                state[row],
                state[row + 1],
                state[row + 2],
                state[row + 3],
                state[row + 4],
            ];
            for x in 0..5usize {
                state[row + x] = _mm256_xor_si256(
                    arr[x],
                    _mm256_andnot_si256(arr[(x + 1) % 5], arr[(x + 2) % 5]),
                );
            }
        }
        state[0] = _mm256_xor_si256(state[0], _mm256_set1_epi64x(rc as i64));
    }
}

/// Pack four `[u64; 25]` states into interleaved vectors (lane `k` = instance `k`).
///
/// # Safety
///
/// The CPU must support AVX2.
#[target_feature(enable = "avx2")]
pub unsafe fn transpose_to_x4(states: &[[u64; PLEN]; 4], out: &mut [__m256i; PLEN]) {
    for w in 0..PLEN {
        out[w] = _mm256_set_epi64x(
            states[3][w] as i64,
            states[2][w] as i64,
            states[1][w] as i64,
            states[0][w] as i64,
        );
    }
}

/// Unpack interleaved vectors into four scalar Keccak states.
///
/// # Safety
///
/// The CPU must support AVX2.
#[target_feature(enable = "avx2")]
pub unsafe fn transpose_from_x4(v: &[__m256i; PLEN], out: &mut [[u64; PLEN]; 4]) {
    let mut lane = [0u64; 4];
    for w in 0..PLEN {
        _mm256_storeu_si256(lane.as_mut_ptr() as *mut __m256i, v[w]);
        for j in 0..4 {
            out[j][w] = lane[j];
        }
    }
}
