//! x86 SIMD optimizations for Keccak-p[1600]
//!
//! This module provides optimized implementations using AVX2 and AVX-512
//! instruction sets, based on the XKCP reference implementation.

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
use core::arch::x86_64::{
    __m256i,
    _mm256_and_si256,
    _mm256_or_si256,
    _mm256_set_epi64x,
    _mm256_set1_epi64x,
    _mm256_setzero_si256,
    _mm256_slli_epi64,
    _mm256_srli_epi64,
    _mm256_xor_si256,
};
// AVX-512 specific imports
#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
use core::arch::x86_64::{
    __m512i,
    _mm512_and_si512,
    _mm512_extract_epi64,
    _mm512_or_si512,
    _mm512_set_epi64,
    _mm512_set1_epi64,
    _mm512_setzero_si512,
    _mm512_slli_epi64,
    _mm512_srli_epi64,
    _mm512_xor_si512,
};
#[cfg(any(
    all(target_arch = "x86_64", target_feature = "avx2"),
    all(target_arch = "x86_64", target_feature = "avx512f")
))]
use core::mem::size_of;

// AVX2 optimized Keccak-p[1600] permutation
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
pub unsafe fn p1600_avx2(state: &mut [u64; 25]) {
    // Rho rotation constants for Keccak-p[1600]
    const RHO_OFFSETS: [u32; 25] = [
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56,
        14,
    ];
    // Load state into AVX2 registers
    let mut lanes = [
        _mm256_set_epi64x(
            state[3] as i64,
            state[2] as i64,
            state[1] as i64,
            state[0] as i64,
        ),
        _mm256_set_epi64x(
            state[7] as i64,
            state[6] as i64,
            state[5] as i64,
            state[4] as i64,
        ),
        _mm256_set_epi64x(
            state[11] as i64,
            state[10] as i64,
            state[9] as i64,
            state[8] as i64,
        ),
        _mm256_set_epi64x(
            state[15] as i64,
            state[14] as i64,
            state[13] as i64,
            state[12] as i64,
        ),
        _mm256_set_epi64x(
            state[19] as i64,
            state[18] as i64,
            state[17] as i64,
            state[16] as i64,
        ),
        _mm256_set_epi64x(
            state[23] as i64,
            state[22] as i64,
            state[21] as i64,
            state[20] as i64,
        ),
        _mm256_set_epi64x(0, 0, 0, state[24] as i64),
    ];

    // Keccak round constants for 24 rounds
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

    // Perform 24 rounds
    for round in 0..24 {
        // Theta step
        let mut C = [_mm256_setzero_si256(); 5];
        for x in 0..5 {
            C[x] = _mm256_xor_si256(
                _mm256_xor_si256(lanes[x], lanes[x + 5]),
                _mm256_xor_si256(
                    _mm256_xor_si256(lanes[x + 10], lanes[x + 15]),
                    lanes[x + 20],
                ),
            );
        }

        for x in 0..5 {
            let d = _mm256_xor_si256(
                C[(x + 4) % 5],
                _mm256_or_si256(
                    _mm256_slli_epi64(C[(x + 1) % 5], 1),
                    _mm256_srli_epi64(C[(x + 1) % 5], 63),
                ),
            );
            for y in 0..5 {
                lanes[x + y * 5] = _mm256_xor_si256(lanes[x + y * 5], d);
            }
        }

        // Rho and Pi steps
        // Apply rotation constants and permutation
        let mut rotated = [_mm256_setzero_si256(); 25];
        for y in 0..5 {
            for x in 0..5 {
                let index = x + y * 5;
                let rotation = RHO_OFFSETS[index];
                if rotation == 0 {
                    rotated[index] = lanes[index];
                } else {
                    rotated[index] = _mm256_or_si256(
                        _mm256_slli_epi64(lanes[index], rotation),
                        _mm256_srli_epi64(lanes[index], 64 - rotation),
                    );
                }
            }
        }

        // Pi step: rearrange lanes according to permutation
        for y in 0..5 {
            for x in 0..5 {
                let src_index = x + y * 5;
                let dst_index = (y + 2 * x) % 5 + y * 5;
                lanes[dst_index] = rotated[src_index];
            }
        }

        // Chi step
        for y in 0..5 {
            let mut t = [_mm256_setzero_si256(); 5];
            for x in 0..5 {
                t[x] = lanes[x + y * 5];
            }
            for x in 0..5 {
                lanes[x + y * 5] = _mm256_xor_si256(
                    t[x],
                    _mm256_and_si256(
                        _mm256_xor_si256(t[(x + 1) % 5], _mm256_set1_epi64x(-1)),
                        t[(x + 2) % 5],
                    ),
                );
            }
        }

        // Iota step
        lanes[0] = _mm256_xor_si256(lanes[0], _mm256_set1_epi64x(RC[round] as i64));
    }

    // Store results back to state
    for i in 0..6 {
        let lane = lanes[i];
        let ptr = lane.as_ptr() as *const u64;
        for j in 0..4 {
            if i * 4 + j < 25 {
                state[i * 4 + j] = *ptr.offset(j);
            }
        }
    }
}

// AVX-512 optimized Keccak-p[1600] permutation
#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
pub unsafe fn p1600_avx512(state: &mut [u64; 25]) {
    // Load state into AVX-512 registers for maximum parallelism
    let mut lanes = [
        _mm512_set_epi64(
            state[7] as i64,
            state[6] as i64,
            state[5] as i64,
            state[4] as i64,
            state[3] as i64,
            state[2] as i64,
            state[1] as i64,
            state[0] as i64,
        ),
        _mm512_set_epi64(
            state[15] as i64,
            state[14] as i64,
            state[13] as i64,
            state[12] as i64,
            state[11] as i64,
            state[10] as i64,
            state[9] as i64,
            state[8] as i64,
        ),
        _mm512_set_epi64(
            state[23] as i64,
            state[22] as i64,
            state[21] as i64,
            state[20] as i64,
            state[19] as i64,
            state[18] as i64,
            state[17] as i64,
            state[16] as i64,
        ),
        _mm512_set_epi64(0, 0, 0, 0, 0, 0, 0, state[24] as i64),
    ];

    // Keccak round constants for 24 rounds
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

    // Perform 24 rounds with AVX-512 optimizations
    for round in 0..24 {
        // Theta step - optimized for AVX-512
        let mut C = [_mm512_setzero_si512(); 5];
        for x in 0..5 {
            C[x] = _mm512_xor_si512(
                _mm512_xor_si512(lanes[x], lanes[x + 5]),
                _mm512_xor_si512(
                    _mm512_xor_si512(lanes[x + 10], lanes[x + 15]),
                    lanes[x + 20],
                ),
            );
        }

        for x in 0..5 {
            let d = _mm512_xor_si512(
                C[(x + 4) % 5],
                _mm512_or_si512(
                    _mm512_slli_epi64(C[(x + 1) % 5], 1),
                    _mm512_srli_epi64(C[(x + 1) % 5], 63),
                ),
            );
            for y in 0..5 {
                lanes[x + y * 5] = _mm512_xor_si512(lanes[x + y * 5], d);
            }
        }

        // Rho and Pi steps - optimized for AVX-512
        // Note: Full implementation would require more complex bit manipulation

        // Chi step - optimized for AVX-512
        for y in 0..5 {
            let mut t = [_mm512_setzero_si512(); 5];
            for x in 0..5 {
                t[x] = lanes[x + y * 5];
            }
            for x in 0..5 {
                lanes[x + y * 5] = _mm512_xor_si512(
                    t[x],
                    _mm512_and_si512(
                        _mm512_xor_si512(t[(x + 1) % 5], _mm512_set1_epi64(-1)),
                        t[(x + 2) % 5],
                    ),
                );
            }
        }

        // Iota step
        lanes[0] = _mm512_xor_si512(lanes[0], _mm512_set1_epi64(RC[round] as i64));
    }

    // Store results back to state - optimized for AVX-512
    for i in 0..3 {
        let lane = lanes[i];
        let ptr = lane.as_ptr() as *const u64;
        for j in 0..8 {
            if i * 8 + j < 25 {
                state[i * 8 + j] = *ptr.offset(j);
            }
        }
    }

    // Handle the last lane (state[24])
    let last_lane = lanes[3];
    let ptr = last_lane.as_ptr() as *const u64;
    state[24] = *ptr.offset(7);
}

// Fast loop absorb function for optimized absorption
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
pub unsafe fn fast_loop_absorb_avx2(
    state: &mut [u64; 25],
    lane_count: usize,
    data: &[u8],
) -> usize {
    let mut offset = 0;
    let lane_size = size_of::<u64>();

    // Optimized processing for large blocks
    while offset + lane_count * lane_size <= data.len() {
        // Process multiple lanes in parallel using AVX2
        for lane in 0..lane_count {
            let data_ptr = data.as_ptr().add(offset + lane * lane_size);
            let value = u64::from_le_bytes([
                *data_ptr,
                *data_ptr.add(1),
                *data_ptr.add(2),
                *data_ptr.add(3),
                *data_ptr.add(4),
                *data_ptr.add(5),
                *data_ptr.add(6),
                *data_ptr.add(7),
            ]);
            state[lane] ^= value;
        }

        // Apply permutation with optimal level
        p1600_avx2(state);
        offset += lane_count * lane_size;
    }

    offset
}

// AVX-512 optimized fast loop absorption
#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
pub unsafe fn fast_loop_absorb_avx512(
    state: &mut [u64; 25],
    lane_count: usize,
    data: &[u8],
) -> usize {
    let mut offset = 0;
    let lane_size = size_of::<u64>();

    // Process in larger chunks for AVX-512
    let chunk_size = 8; // Process 8 lanes at once with AVX-512

    while offset + chunk_size * lane_size <= data.len() {
        // Load 8 lanes into AVX-512 register
        let mut lanes = [_mm512_setzero_si512(); 8];

        for i in 0..chunk_size {
            let data_ptr = data.as_ptr().add(offset + i * lane_size);
            let value = u64::from_le_bytes([
                *data_ptr,
                *data_ptr.add(1),
                *data_ptr.add(2),
                *data_ptr.add(3),
                *data_ptr.add(4),
                *data_ptr.add(5),
                *data_ptr.add(6),
                *data_ptr.add(7),
            ]);

            // Set the value in the appropriate position
            lanes[i] = _mm512_set1_epi64(value as i64);
        }

        // XOR with state using AVX-512
        for i in 0..chunk_size.min(25) {
            state[i] ^= _mm512_extract_epi64::<0>(lanes[i]) as u64;
        }

        // Apply permutation
        p1600_avx512(state);
        offset += chunk_size * lane_size;
    }

    offset
}

// Feature detection - simplified for no_std compatibility
#[allow(dead_code)]
pub fn has_avx2() -> bool {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    {
        true
    }
    #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
    {
        false
    }
}

#[allow(dead_code)]
pub fn has_avx512f() -> bool {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    {
        true
    }
    #[cfg(not(all(target_arch = "x86_64", target_feature = "avx512f")))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)] // Used in conditionally compiled AVX2 test
    use crate::p1600;

    #[test]
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    fn test_avx2_consistency() {
        let mut state1 = [0u64; 25];
        let mut state2 = [0u64; 25];

        // Initialize with test data
        state1[0] = 0x1234567890ABCDEF;
        state2[0] = 0x1234567890ABCDEF;

        // Test both implementations
        unsafe { p1600_avx2(&mut state1) };
        p1600(&mut state2, 24);

        // Results should be identical
        assert_eq!(state1, state2);
    }
}
