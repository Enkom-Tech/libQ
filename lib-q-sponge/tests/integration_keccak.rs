//! Integration tests for Keccak re-exports from lib-q-sponge

use lib_q_sponge::{
    detection, f1600, f200, f400, f800, fast_loop_absorb_optimized, p1600, p1600_optimized,
    OptimizationLevel,
};

#[test]
fn test_keccak_f1600_permutation() {
    // Test that the Keccak-f[1600] permutation is accessible and functional
    let mut state = [0u64; 25];

    // Initialize with some test data
    state[0] = 0x1234567890abcdef;
    state[1] = 0xfedcba0987654321;

    // Apply permutation
    f1600(&mut state);

    // Verify that the state has changed (permutation was applied)
    assert_ne!(state[0], 0x1234567890abcdef);
    assert_ne!(state[1], 0xfedcba0987654321);

    // Verify that the state is not all zeros (permutation produced meaningful output)
    let all_zeros = state.iter().all(|&x| x == 0);
    assert!(
        !all_zeros,
        "Keccak permutation should not produce all zeros"
    );
}

#[test]
fn test_keccak_f800_permutation() {
    // Test that the Keccak-f[800] permutation is accessible and functional
    let mut state = [0u32; 25];

    // Initialize with some test data
    state[0] = 0x12345678;
    state[1] = 0x87654321;

    // Apply permutation
    f800(&mut state);

    // Verify that the state has changed
    assert_ne!(state[0], 0x12345678);
    assert_ne!(state[1], 0x87654321);
}

#[test]
fn test_keccak_f400_permutation() {
    // Test that the Keccak-f[400] permutation is accessible and functional
    let mut state = [0u16; 25];

    // Initialize with some test data
    state[0] = 0x1234;
    state[1] = 0x4321;

    // Apply permutation
    f400(&mut state);

    // Verify that the state has changed
    assert_ne!(state[0], 0x1234);
    assert_ne!(state[1], 0x4321);
}

#[test]
fn test_keccak_f200_permutation() {
    // Test that the Keccak-f[200] permutation is accessible and functional
    let mut state = [0u8; 25];

    // Initialize with some test data
    state[0] = 0x12;
    state[1] = 0x21;

    // Apply permutation
    f200(&mut state);

    // Verify that the state has changed
    assert_ne!(state[0], 0x12);
    assert_ne!(state[1], 0x21);
}

#[test]
fn test_keccak_p1600_reduced_rounds() {
    // Test Keccak-p[1600] with reduced rounds
    let mut state = [0u64; 25];

    // Initialize with test data
    state[0] = 0xdeadbeefcafebabe;

    // Apply permutation with reduced rounds
    p1600(&mut state, 12);

    // Verify permutation was applied
    assert_ne!(state[0], 0xdeadbeefcafebabe);
}

#[test]
fn test_keccak_consistency() {
    // Test that the same input produces the same output
    let mut state1 = [0u64; 25];
    let mut state2 = [0u64; 25];

    // Initialize both states identically
    state1[0] = 0x1234567890abcdef;
    state2[0] = 0x1234567890abcdef;

    // Apply the same permutation to both
    f1600(&mut state1);
    f1600(&mut state2);

    // Verify they produce identical results
    assert_eq!(state1, state2, "Keccak permutation should be deterministic");
}

#[test]
fn test_keccak_zero_input() {
    // Test that zero input produces non-zero output (avalanche effect)
    let mut state = [0u64; 25];

    // Apply permutation to zero state
    f1600(&mut state);

    // Verify that the output is not all zeros
    let all_zeros = state.iter().all(|&x| x == 0);
    assert!(
        !all_zeros,
        "Keccak permutation should produce non-zero output from zero input"
    );
}

#[test]
fn test_keccak_avalanche_effect() {
    // Test that small changes in input produce large changes in output
    let mut state1 = [0u64; 25];
    let mut state2 = [0u64; 25];

    // Initialize states with minimal difference
    state1[0] = 0x1234567890abcdef;
    state2[0] = 0x1234567890abcdee; // Only 1 bit different

    // Apply permutation to both
    f1600(&mut state1);
    f1600(&mut state2);

    // Count how many bits are different in the output
    let mut diff_count = 0;
    for i in 0..25 {
        diff_count += (state1[i] ^ state2[i]).count_ones();
    }

    // Verify avalanche effect (should be around 50% of bits different)
    let total_bits = 25 * 64;
    let diff_percentage = (diff_count as f64) / (total_bits as f64);

    // Allow some tolerance (between 30% and 70% different bits)
    assert!(
        diff_percentage > 0.3 && diff_percentage < 0.7,
        "Avalanche effect not observed: {:.1}% bits different",
        diff_percentage * 100.0
    );
}

#[test]
fn test_optimization_levels_availability() {
    // Test that optimization levels are properly detected
    let report = detection::detect_available_features();
    assert!(
        !report.summary().is_empty(),
        "Feature detection should work"
    );

    let best_level = OptimizationLevel::best_available();
    assert!(
        best_level.is_available(),
        "Best available level should be available"
    );
}

#[test]
fn test_optimized_permutation_consistency() {
    // Test that optimized permutations produce the same results as reference
    let mut state_ref = [0u64; 25];
    let mut state_opt = [0u64; 25];

    // Initialize with test data
    state_ref[0] = 0x1234567890abcdef;
    state_opt[0] = 0x1234567890abcdef;

    // Apply reference permutation
    p1600(&mut state_ref, 24);

    // Apply optimized permutation
    p1600_optimized(&mut state_opt, OptimizationLevel::Reference);

    // Results should be identical
    assert_eq!(
        state_ref, state_opt,
        "Optimized permutation should match reference"
    );
}

#[test]
fn test_optimized_permutation_all_levels() {
    // Test all available optimization levels
    let test_data = 0x1234567890abcdefu64;

    for level in [
        OptimizationLevel::Reference,
        OptimizationLevel::Basic,
        OptimizationLevel::Advanced,
        OptimizationLevel::Maximum,
    ] {
        if level.is_available() {
            let mut state = [0u64; 25];
            state[0] = test_data;

            p1600_optimized(&mut state, level);

            // Verify permutation was applied
            assert_ne!(state[0], test_data, "Permutation should change state");

            // Verify non-zero output
            let all_zeros = state.iter().all(|&x| x == 0);
            assert!(!all_zeros, "Permutation should not produce all zeros");
        }
    }
}

#[test]
fn test_fast_loop_absorption() {
    // Test fast loop absorption functionality
    let mut state = [0u64; 25];
    let data = b"This is test data for fast loop absorption testing";

    let offset = fast_loop_absorb_optimized(&mut state, data, OptimizationLevel::Reference);

    // Verify some data was processed
    assert!(offset > 0, "Should process some data");
    assert_ne!(state[0], 0, "State should change after absorption");
}

#[test]
fn test_optimization_feature_detection() {
    // Test that feature detection works correctly
    let report = detection::detect_available_features();

    // Basic feature detection should always work
    assert!(
        report.x86_64 || report.aarch64,
        "Should detect some architecture"
    );

    // Get recommended level
    let recommended = report.recommended_optimization_level();
    assert!(
        recommended.is_available(),
        "Recommended level should be available"
    );
}
