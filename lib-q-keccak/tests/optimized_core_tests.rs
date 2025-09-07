//! Comprehensive tests for the optimized core Keccak functions
//!
//! These tests ensure complete coverage of the optimization-specific functionality
//! in lib-q-keccak.

use lib_q_keccak::{
    OptimizationLevel,
    fast_loop_absorb_optimized,
    p1600_optimized,
};

#[test]
fn test_optimization_level_best_available() {
    let best = OptimizationLevel::best_available();
    assert!(best.is_available());
}

#[test]
fn test_optimization_level_is_available() {
    // Reference should always be available
    assert!(OptimizationLevel::Reference.is_available());

    // Other levels depend on platform/features, but should at least not panic
    let _ = OptimizationLevel::Basic.is_available();
    let _ = OptimizationLevel::Advanced.is_available();
    let _ = OptimizationLevel::Maximum.is_available();
}

#[test]
fn test_p1600_optimized_reference() {
    // Create two identical states
    let mut state1 = [0u64; 25];
    let mut state2 = [0u64; 25];

    // Initialize with test data
    state1[0] = 0x1234567890ABCDEF;
    state2[0] = 0x1234567890ABCDEF;

    // Apply permutation using reference implementation
    lib_q_keccak::keccak_p(&mut state1, 24);

    // Apply permutation using optimized implementation with Reference level
    p1600_optimized(&mut state2, OptimizationLevel::Reference);

    // Results should be identical
    assert_eq!(state1, state2);
}

#[test]
fn test_p1600_optimized_all_levels() {
    // Test all available optimization levels
    for level in &[
        OptimizationLevel::Reference,
        OptimizationLevel::Basic,
        OptimizationLevel::Advanced,
        OptimizationLevel::Maximum,
    ] {
        if !level.is_available() {
            // Skip unavailable levels
            continue;
        }

        let mut state = [0u64; 25];
        state[0] = 0x1234567890ABCDEF;

        // Apply permutation with the current level
        p1600_optimized(&mut state, *level);

        // Verify it performed some transformation
        assert_ne!(state[0], 0x1234567890ABCDEF);

        // The state should not be all zeros
        assert!(state.iter().any(|&x| x != 0));
    }
}

#[test]
fn test_fast_loop_absorb_optimized_reference() {
    // Create a state and test data
    let mut state = [0u64; 25];
    let data = b"This is test data for the fast loop absorption function";

    // Process using reference level
    let offset = fast_loop_absorb_optimized(&mut state, data, OptimizationLevel::Reference);

    // Verify absorption worked
    assert!(offset > 0);
    assert_ne!(state[0], 0);
}

#[test]
fn test_fast_loop_absorb_optimized_all_levels() {
    // Test all available optimization levels
    for level in &[
        OptimizationLevel::Reference,
        OptimizationLevel::Basic,
        OptimizationLevel::Advanced,
        OptimizationLevel::Maximum,
    ] {
        if !level.is_available() {
            // Skip unavailable levels
            continue;
        }

        let mut state = [0u64; 25];
        let data = b"This is test data for fast loop absorption testing with different optimization levels";

        // Apply absorption with the current level
        let offset = fast_loop_absorb_optimized(&mut state, data, *level);

        // Verify some data was processed
        assert!(offset > 0);

        // Verify state changed
        assert_ne!(state[0], 0);
    }
}

#[test]
fn test_fast_loop_absorb_empty_data() {
    // Test with empty data
    let mut state = [0u64; 25];
    let data = b"";

    // Process empty data
    let offset = fast_loop_absorb_optimized(&mut state, data, OptimizationLevel::Reference);

    // Verify no bytes were processed
    assert_eq!(offset, 0);

    // State should remain unchanged
    assert_eq!(state[0], 0);
}

#[test]
fn test_fast_loop_absorb_small_data() {
    // Test with data smaller than a lane
    let mut state = [0u64; 25];
    let data = b"1234567"; // 7 bytes, less than 8-byte lane

    // Process small data
    let offset = fast_loop_absorb_optimized(&mut state, data, OptimizationLevel::Reference);

    // Verify no bytes were processed (since they don't form a complete lane)
    assert_eq!(offset, 0);
}

#[test]
fn test_fast_loop_absorb_exact_lane_size() {
    // Test with data exactly one lane in size
    let mut state = [0u64; 25];
    let data = b"12345678"; // 8 bytes, exactly one lane

    // Process one lane
    let offset = fast_loop_absorb_optimized(&mut state, data, OptimizationLevel::Reference);

    // Verify one lane (8 bytes) was processed
    assert_eq!(offset, 8);

    // State should have changed
    assert_ne!(state, [0u64; 25]);
}

#[test]
fn test_fast_loop_absorb_multiple_lanes() {
    // Test with data containing multiple complete lanes
    let mut state = [0u64; 25];
    let data = b"1234567812345678123456781234567812345678"; // 40 bytes, 5 complete lanes

    // Process multiple lanes
    let offset = fast_loop_absorb_optimized(&mut state, data, OptimizationLevel::Reference);

    // Verify all 5 lanes (40 bytes) were processed
    assert_eq!(offset, 40);

    // State should have changed
    assert_ne!(state, [0u64; 25]);
}

#[test]
fn test_fast_loop_absorb_partial_lanes() {
    // Test with data containing complete lanes plus a partial lane
    let mut state = [0u64; 25];
    let data = b"1234567812345678123"; // 19 bytes: 2 complete lanes (16 bytes) + 3 partial bytes

    // Process data
    let offset = fast_loop_absorb_optimized(&mut state, data, OptimizationLevel::Reference);

    // Verify only complete lanes (16 bytes) were processed
    assert_eq!(offset, 16);

    // State should have changed
    assert_ne!(state, [0u64; 25]);
}

#[cfg(feature = "simd")]
mod simd_tests {
    use lib_q_keccak::OptimizationLevel;
    use lib_q_keccak::parallel::p1600_parallel;

    #[test]
    fn test_parallel_processing_reference() {
        // Create multiple states
        let mut states = [[0u64; 25]; 4];

        // Initialize with test data
        for (i, state) in states.iter_mut().enumerate() {
            state[0] = 0x1234567890ABCDEF + i as u64;
        }

        // Store original values for comparison
        let original_values: Vec<u64> = states.iter().map(|s| s[0]).collect();

        // Process states in parallel using reference level
        p1600_parallel(&mut states, OptimizationLevel::Reference);

        // Verify each state was processed
        for (i, state) in states.iter().enumerate() {
            assert_ne!(state[0], original_values[i]);
        }
    }

    #[test]
    fn test_parallel_processing_all_levels() {
        // Test all available optimization levels
        for level in &[
            OptimizationLevel::Reference,
            OptimizationLevel::Basic,
            OptimizationLevel::Advanced,
            OptimizationLevel::Maximum,
        ] {
            if !level.is_available() {
                // Skip unavailable levels
                continue;
            }

            // Create multiple states
            let mut states = [[0u64; 25]; 8];

            // Initialize with test data
            for (i, state) in states.iter_mut().enumerate() {
                state[0] = 0x1234567890ABCDEF + i as u64;
            }

            // Store original values for comparison
            let original_values: Vec<u64> = states.iter().map(|s| s[0]).collect();

            // Process states in parallel using the current level
            p1600_parallel(&mut states, *level);

            // Verify each state was processed
            for (i, state) in states.iter().enumerate() {
                assert_ne!(state[0], original_values[i]);
            }
        }
    }

    #[test]
    fn test_parallel_processing_different_sizes() {
        // Test processing with different numbers of states

        // Process one state
        let mut states1 = [[0u64; 25]; 1];
        states1[0][0] = 0x1234567890ABCDEF;
        p1600_parallel(&mut states1, OptimizationLevel::Reference);
        assert_ne!(states1[0][0], 0x1234567890ABCDEF);

        // Process two states
        let mut states2 = [[0u64; 25]; 2];
        states2[0][0] = 0x1234567890ABCDEF;
        states2[1][0] = 0xFEDCBA0987654321;
        p1600_parallel(&mut states2, OptimizationLevel::Reference);
        assert_ne!(states2[0][0], 0x1234567890ABCDEF);
        assert_ne!(states2[1][0], 0xFEDCBA0987654321);

        // Process three states
        let mut states3 = [[0u64; 25]; 3];
        for (i, state) in states3.iter_mut().enumerate() {
            state[0] = 0x1234567890ABCDEF + i as u64;
        }
        p1600_parallel(&mut states3, OptimizationLevel::Reference);
        for (i, state) in states3.iter().enumerate() {
            assert_ne!(state[0], 0x1234567890ABCDEF + i as u64);
        }

        // Process seven states (odd number)
        let mut states7 = [[0u64; 25]; 7];
        for (i, state) in states7.iter_mut().enumerate() {
            state[0] = 0x1234567890ABCDEF + i as u64;
        }
        p1600_parallel(&mut states7, OptimizationLevel::Reference);
        for (i, state) in states7.iter().enumerate() {
            assert_ne!(state[0], 0x1234567890ABCDEF + i as u64);
        }
    }
}

#[cfg(all(feature = "simd", feature = "multithreading"))]
mod multithreading_tests {
    use lib_q_keccak::OptimizationLevel;
    use lib_q_keccak::parallel::p1600_multithreaded;

    #[test]
    fn test_multithreaded_processing() {
        // Create multiple states
        let states = [[0u64; 25]; 4];

        // Initialize with test data
        let mut states = states;
        for (i, state) in states.iter_mut().enumerate() {
            state[0] = 0x1234567890ABCDEF + i as u64;
        }

        // Store original values for comparison
        let original_values: Vec<u64> = states.iter().map(|s| s[0]).collect();

        // Process states using multithreaded implementation
        let result = p1600_multithreaded(&states, OptimizationLevel::Reference);

        // Check the operation succeeded
        assert!(result.is_ok());

        // Get the processed states
        let processed_states = result.unwrap();

        // Verify each state was processed
        for (i, state) in processed_states.iter().enumerate() {
            assert_ne!(state[0], original_values[i]);
        }
    }
}
