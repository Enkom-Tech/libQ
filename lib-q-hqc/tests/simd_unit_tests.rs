//! Unit tests for individual SIMD operations

mod simd_debug_utils;

#[cfg(all(test, feature = "simd-avx2", target_arch = "x86_64"))]
mod tests {
    use super::simd_debug_utils::debug::*;

    #[test]
    fn test_shift_xor_zero_distance() {
        let source = vec![0xDEADBEEF12345678u64; 8];
        verify_shift_xor(&source, 0).expect("Zero distance failed");
    }

    #[test]
    fn test_shift_xor_byte_aligned() {
        // Test distances: 8, 16, 24, 32, 64 bits
        for distance in [8, 16, 24, 32, 64] {
            let source = vec![0xFFFFFFFFFFFFFFFFu64; 8];
            verify_shift_xor(&source, distance)
                .unwrap_or_else(|_| panic!("Byte-aligned {} failed", distance));
        }
    }

    #[test]
    fn test_shift_xor_bit_aligned() {
        // Test non-byte-aligned: 1, 3, 5, 7, 9, 15 bits
        for distance in [1, 3, 5, 7, 9, 15] {
            let source = vec![0xAAAAAAAAAAAAAAAAu64; 8];
            verify_shift_xor(&source, distance)
                .unwrap_or_else(|_| panic!("Bit-aligned {} failed", distance));
        }
    }

    #[test]
    fn test_sparse_dense_mul_single_position() {
        let sparse = vec![0x01u8; 16]; // Single bit set
        let dense = vec![0xFFu8; 16];
        verify_sparse_dense_mul(&sparse, &dense, 1).expect("Single position failed");
    }

    #[test]
    fn test_sparse_dense_mul_multiple_positions() {
        let sparse = vec![0xABu8; 32]; // Multiple bits
        let dense = vec![0xCDu8; 32];
        verify_sparse_dense_mul(&sparse, &dense, 10).expect("Multiple positions failed");
    }
}
