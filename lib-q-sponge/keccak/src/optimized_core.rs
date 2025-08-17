//! Optimized core implementations for Keccak-p[1600]
//!
//! This module provides high-performance implementations with proper feature gating
//! and security considerations. All optimizations are optional and fall back to
//! secure reference implementations when not available.

use core::mem::size_of;

use crate::keccak_p;

/// Platform-specific optimization selector
///
/// This enum allows runtime selection of the best available optimization
/// while maintaining security guarantees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptimizationLevel {
    /// Reference implementation (always available)
    Reference,
    /// Basic SIMD optimizations (AVX2, ARMv8)
    Basic,
    /// Advanced SIMD optimizations (AVX-512, parallel processing)
    Advanced,
    /// Maximum performance (all available optimizations)
    Maximum,
}

impl OptimizationLevel {
    /// Returns the best available optimization level for the current platform
    pub fn best_available() -> Self {
        #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
        {
            Self::Maximum
        }
        #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
        {
            Self::Advanced
        }
        #[cfg(all(target_arch = "aarch64", target_feature = "sha3"))]
        {
            Self::Basic
        }
        #[cfg(not(any(
            all(target_arch = "x86_64", target_feature = "avx2"),
            all(target_arch = "aarch64", target_feature = "sha3")
        )))]
        {
            Self::Reference
        }
    }

    /// Check if this optimization level is available on the current platform
    pub fn is_available(self) -> bool {
        match self {
            Self::Reference => true,
            Self::Basic => {
                #[cfg(any(
                    all(target_arch = "x86_64", target_feature = "avx2"),
                    all(target_arch = "aarch64", target_feature = "sha3")
                ))]
                {
                    true
                }
                #[cfg(not(any(
                    all(target_arch = "x86_64", target_feature = "avx2"),
                    all(target_arch = "aarch64", target_feature = "sha3")
                )))]
                {
                    false
                }
            }
            Self::Advanced => {
                #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
                {
                    true
                }
                #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
                {
                    false
                }
            }
            Self::Maximum => {
                #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
                {
                    true
                }
                #[cfg(not(all(target_arch = "x86_64", target_feature = "avx512f")))]
                {
                    false
                }
            }
        }
    }
}

/// Optimized Keccak-p[1600] permutation with automatic optimization selection
///
/// This function automatically selects the best available optimization
/// while maintaining cryptographic security guarantees.
pub fn p1600_optimized(state: &mut [u64; 25], level: OptimizationLevel) {
    match level {
        OptimizationLevel::Reference => {
            keccak_p(state, 24);
        }
        OptimizationLevel::Basic => {
            #[cfg(all(target_arch = "aarch64", target_feature = "sha3"))]
            {
                unsafe { crate::armv8::p1600(state) };
            }
            #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
            {
                unsafe { crate::x86::p1600_avx2(state) };
            }
            #[cfg(not(any(
                all(target_arch = "aarch64", target_feature = "sha3"),
                all(target_arch = "x86_64", target_feature = "avx2")
            )))]
            {
                keccak_p(state, 24);
            }
        }
        OptimizationLevel::Advanced => {
            #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
            {
                unsafe { crate::x86::p1600_avx2(state) };
            }
            #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
            {
                keccak_p(state, 24);
            }
        }
        OptimizationLevel::Maximum => {
            #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
            {
                unsafe { crate::x86::p1600_avx512(state) };
            }
            #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
            {
                unsafe { crate::x86::p1600_avx2(state) };
            }
            #[cfg(not(all(
                target_arch = "x86_64",
                any(target_feature = "avx2", target_feature = "avx512f")
            )))]
            {
                keccak_p(state, 24);
            }
        }
    }
}

/// Fast loop absorption with automatic optimization selection
///
/// This function provides optimized absorption for large data blocks
/// while maintaining security guarantees.
pub fn fast_loop_absorb_optimized(
    state: &mut [u64; 25],
    data: &[u8],
    level: OptimizationLevel,
) -> usize {
    match level {
        OptimizationLevel::Reference => fast_loop_absorb_reference(state, data),
        OptimizationLevel::Basic => {
            #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
            {
                unsafe { crate::x86::fast_loop_absorb_avx2(state, 1, data) }
            }
            #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
            {
                fast_loop_absorb_reference(state, data)
            }
        }
        OptimizationLevel::Advanced => {
            #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
            {
                unsafe { crate::x86::fast_loop_absorb_avx2(state, 4, data) }
            }
            #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
            {
                fast_loop_absorb_reference(state, data)
            }
        }
        OptimizationLevel::Maximum => {
            #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
            {
                unsafe { crate::x86::fast_loop_absorb_avx2(state, 8, data) }
            }
            #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
            {
                unsafe { crate::x86::fast_loop_absorb_avx2(state, 4, data) }
            }
            #[cfg(not(all(
                target_arch = "x86_64",
                any(target_feature = "avx2", target_feature = "avx512f")
            )))]
            {
                fast_loop_absorb_reference(state, data)
            }
        }
    }
}

/// Reference implementation of fast loop absorption
///
/// This is the secure fallback implementation that is always available.
fn fast_loop_absorb_reference(state: &mut [u64; 25], data: &[u8]) -> usize {
    let mut offset = 0;
    let lane_size = size_of::<u64>();

    while offset + lane_size <= data.len() {
        let value = u64::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        state[0] ^= value;

        // Apply permutation
        keccak_p(state, 24);
        offset += lane_size;
    }

    offset
}

/// Parallel processing interface for batch operations
///
/// This module provides parallel processing capabilities for batch hashing
/// operations, similar to XKCP's times2, times4, times8 implementations.
#[cfg(feature = "simd")]
pub mod parallel {
    use super::*;
    use crate::advanced_simd;

    /// Process multiple Keccak states in parallel
    ///
    /// This function processes multiple Keccak states simultaneously,
    /// providing significant performance improvements for batch operations.
    pub fn p1600_parallel(states: &mut [[u64; 25]], level: OptimizationLevel) {
        match level {
            OptimizationLevel::Reference => {
                // Process sequentially
                for state in states.iter_mut() {
                    keccak_p(state, 24);
                }
            }
            OptimizationLevel::Basic => {
                // Process in pairs if possible
                for chunk in states.chunks_mut(2) {
                    if chunk.len() == 2 {
                        advanced_simd::parallel::p1600_parallel_2x(&mut [chunk[0], chunk[1]]);
                    } else {
                        keccak_p(&mut chunk[0], 24);
                    }
                }
            }
            OptimizationLevel::Advanced => {
                // Process in groups of 4
                for chunk in states.chunks_mut(4) {
                    match chunk.len() {
                        4 => advanced_simd::parallel::p1600_parallel_4x(&mut [
                            chunk[0], chunk[1], chunk[2], chunk[3],
                        ]),
                        3 => {
                            advanced_simd::parallel::p1600_parallel_2x(&mut [chunk[0], chunk[1]]);
                            keccak_p(&mut chunk[2], 24);
                        }
                        2 => advanced_simd::parallel::p1600_parallel_2x(&mut [chunk[0], chunk[1]]),
                        1 => keccak_p(&mut chunk[0], 24),
                        _ => unreachable!(),
                    }
                }
            }
            OptimizationLevel::Maximum => {
                // Process in groups of 8
                for chunk in states.chunks_mut(8) {
                    match chunk.len() {
                        8 => advanced_simd::parallel::p1600_parallel_8x(&mut [
                            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6],
                            chunk[7],
                        ]),
                        7 => {
                            advanced_simd::parallel::p1600_parallel_4x(&mut [
                                chunk[0], chunk[1], chunk[2], chunk[3],
                            ]);
                            advanced_simd::parallel::p1600_parallel_2x(&mut [chunk[4], chunk[5]]);
                            keccak_p(&mut chunk[6], 24);
                        }
                        6 => {
                            advanced_simd::parallel::p1600_parallel_4x(&mut [
                                chunk[0], chunk[1], chunk[2], chunk[3],
                            ]);
                            advanced_simd::parallel::p1600_parallel_2x(&mut [chunk[4], chunk[5]]);
                        }
                        5 => {
                            advanced_simd::parallel::p1600_parallel_4x(&mut [
                                chunk[0], chunk[1], chunk[2], chunk[3],
                            ]);
                            keccak_p(&mut chunk[4], 24);
                        }
                        4 => advanced_simd::parallel::p1600_parallel_4x(&mut [
                            chunk[0], chunk[1], chunk[2], chunk[3],
                        ]),
                        3 => {
                            advanced_simd::parallel::p1600_parallel_2x(&mut [chunk[0], chunk[1]]);
                            keccak_p(&mut chunk[2], 24);
                        }
                        2 => advanced_simd::parallel::p1600_parallel_2x(&mut [chunk[0], chunk[1]]),
                        1 => keccak_p(&mut chunk[0], 24),
                        _ => unreachable!(),
                    }
                }
            }
        }
    }

    /// Fast parallel absorption for large data blocks
    ///
    /// This function provides optimized absorption for large data blocks
    /// using parallel processing techniques.
    pub fn fast_loop_absorb_parallel(
        states: &mut [[u64; 25]],
        data: &[u8],
        level: OptimizationLevel,
    ) -> usize {
        match level {
            OptimizationLevel::Reference => {
                // Process sequentially
                let mut min_offset = usize::MAX;
                for state in states.iter_mut() {
                    let offset = fast_loop_absorb_reference(state, data);
                    min_offset = min_offset.min(offset);
                }
                min_offset
            }
            OptimizationLevel::Basic => {
                // Process in pairs
                let mut min_offset = usize::MAX;
                for chunk in states.chunks_mut(2) {
                    if chunk.len() == 2 {
                        let offset =
                            advanced_simd::fast_loop_absorb_advanced(&mut chunk[0], data, 2);
                        min_offset = min_offset.min(offset);
                    } else {
                        let offset = fast_loop_absorb_reference(&mut chunk[0], data);
                        min_offset = min_offset.min(offset);
                    }
                }
                min_offset
            }
            OptimizationLevel::Advanced => {
                // Process in groups of 4
                let mut min_offset = usize::MAX;
                for chunk in states.chunks_mut(4) {
                    match chunk.len() {
                        4 => {
                            let offset =
                                advanced_simd::fast_loop_absorb_advanced(&mut chunk[0], data, 4);
                            min_offset = min_offset.min(offset);
                        }
                        _ => {
                            for state in chunk.iter_mut() {
                                let offset = fast_loop_absorb_reference(state, data);
                                min_offset = min_offset.min(offset);
                            }
                        }
                    }
                }
                min_offset
            }
            OptimizationLevel::Maximum => {
                // Process in groups of 8
                let mut min_offset = usize::MAX;
                for chunk in states.chunks_mut(8) {
                    match chunk.len() {
                        8 => {
                            let offset =
                                advanced_simd::fast_loop_absorb_advanced(&mut chunk[0], data, 8);
                            min_offset = min_offset.min(offset);
                        }
                        _ => {
                            for state in chunk.iter_mut() {
                                let offset = fast_loop_absorb_reference(state, data);
                                min_offset = min_offset.min(offset);
                            }
                        }
                    }
                }
                min_offset
            }
        }
    }

    /// Multi-threaded parallel processing for large workloads
    ///
    /// This function uses multiple threads to process Keccak states in parallel,
    /// providing significant performance improvements for large workloads.
    #[cfg(all(feature = "multithreading", feature = "std"))]
    pub fn p1600_multithreaded(
        states: &[Vec<u64>],
        level: OptimizationLevel,
    ) -> Result<Vec<Vec<u64>>, Box<dyn std::error::Error + Send + Sync>> {
        use crate::multithreading::{process_keccak_states_global, ThreadingConfig};

        // Use global thread pool if available, otherwise create a temporary one
        if let Ok(results) = process_keccak_states_global(states, level) {
            Ok(results)
        } else {
            // Fallback to sequential processing
            let mut results = Vec::with_capacity(states.len());
            for state in states {
                let mut result_state = state.clone();
                // Convert Vec<u64> to [u64; 25] for keccak_p
                if result_state.len() == 25 {
                    let mut state_array = [0u64; 25];
                    state_array.copy_from_slice(&result_state);
                    match level {
                        OptimizationLevel::Reference => {
                            keccak_p(&mut state_array, 24);
                        }
                        OptimizationLevel::Basic => {
                            #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
                            unsafe {
                                crate::x86::p1600_avx2(&mut state_array);
                            }
                            #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
                            {
                                keccak_p(&mut state_array, 24);
                            }
                        }
                        OptimizationLevel::Advanced => {
                            #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
                            unsafe {
                                crate::x86::p1600_avx2(&mut state_array);
                            }
                            #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
                            {
                                keccak_p(&mut state_array, 24);
                            }
                        }
                        OptimizationLevel::Maximum => {
                            #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
                            unsafe {
                                crate::x86::p1600_avx512(&mut state_array);
                            }
                            #[cfg(all(
                                target_arch = "x86_64",
                                target_feature = "avx2",
                                not(target_feature = "avx512f")
                            ))]
                            unsafe {
                                crate::x86::p1600_avx2(&mut state_array);
                            }
                            #[cfg(not(all(
                                target_arch = "x86_64",
                                any(target_feature = "avx2", target_feature = "avx512f")
                            )))]
                            {
                                keccak_p(&mut state_array, 24);
                            }
                        }
                    }
                    result_state = state_array.to_vec();
                }
                results.push(result_state);
            }
            Ok(results)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_optimization_level_availability() {
        // Reference should always be available
        assert!(OptimizationLevel::Reference.is_available());

        // Check that best_available returns a valid level
        let best = OptimizationLevel::best_available();
        assert!(best.is_available());
    }

    #[test]
    fn test_p1600_optimized_consistency() {
        let mut state1 = [0u64; 25];
        let mut state2 = [0u64; 25];

        // Initialize with test data
        state1[0] = 0x1234567890abcdef;
        state2[0] = 0x1234567890abcdef;

        // Test both implementations
        p1600_optimized(&mut state1, OptimizationLevel::Reference);
        keccak_p(&mut state2, 24);

        // Results should be identical
        assert_eq!(state1, state2);
    }

    #[test]
    fn test_fast_loop_absorb_optimized() {
        let mut state = [0u64; 25];
        let data = b"Hello, World! This is a test message for optimized absorption.";

        let offset = fast_loop_absorb_optimized(&mut state, data, OptimizationLevel::Reference);

        // Verify some data was processed
        assert!(offset > 0);
        assert_ne!(state[0], 0);
    }

    #[test]
    #[cfg(feature = "simd")]
    fn test_parallel_processing() {
        let mut states = [[0u64; 25], [0u64; 25], [0u64; 25], [0u64; 25]];

        // Initialize with test data
        for (i, state) in states.iter_mut().enumerate() {
            state[0] = 0x1234567890abcdef + i as u64;
        }

        // Test parallel processing
        parallel::p1600_parallel(&mut states, OptimizationLevel::Basic);

        // Verify all states changed
        for (i, state) in states.iter().enumerate() {
            assert_ne!(state[0], 0x1234567890abcdef + i as u64);
        }
    }
}
