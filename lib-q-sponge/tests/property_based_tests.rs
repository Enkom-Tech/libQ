//! Property-based tests for sponge functions
//!
//! These tests verify important cryptographic properties using property-based testing.

extern crate proptest;
extern crate quickcheck;

use lib_q_sponge::{
    OptimizationLevel,
    State as AsconState,
    f1600,
    p1600_optimized,
};
use proptest::prelude::*;

proptest! {
    // Test that Keccak-f[1600] has the avalanche effect property
    // (changing one bit of input should change about half of the output bits)
    #[test]
    fn keccak_avalanche_effect(
        x0 in any::<u64>(),
        x1 in any::<u64>(),
        x2 in any::<u64>(),
        x3 in any::<u64>()
    ) {
        // Create two nearly identical states (differ by one bit)
        let mut state1 = [0u64; 25];
        let mut state2 = [0u64; 25];

        // Fill with random values
        state1[0] = x0;
        state1[1] = x1;
        state1[2] = x2;
        state1[3] = x3;

        // Copy values to state2
        state2[0] = x0;
        state2[1] = x1;
        state2[2] = x2;
        state2[3] = x3;

        // Flip a single bit in state2
        state2[0] ^= 1;

        // Apply permutation to both
        f1600(&mut state1);
        f1600(&mut state2);

        // Count how many bits differ
        let mut diff_count = 0;
        for i in 0..25 {
            diff_count += (state1[i] ^ state2[i]).count_ones();
        }

        // Total number of bits
        let total_bits = 25 * 64;

        // Calculate percentage of different bits
        let diff_percentage = diff_count as f64 / total_bits as f64;

        // With avalanche effect, should be around 50% different
        // We use a wide range to avoid flaky tests
        prop_assert!(diff_percentage > 0.3 && diff_percentage < 0.7);
    }

    // Test that Ascon permutation has the avalanche effect
    #[test]
    fn ascon_avalanche_effect(
        x0 in any::<u64>(),
        x1 in any::<u64>(),
        x2 in any::<u64>()
    ) {
        // Create two nearly identical states (differ by one bit)
        let mut state1 = AsconState::new(x0, x1, x2, 0, 0);
        let mut state2 = AsconState::new(x0 ^ 1, x1, x2, 0, 0); // Flip the LSB

        // Apply permutation to both
        state1.permute_12();
        state2.permute_12();

        // Get byte representations
        let bytes1 = state1.as_bytes();
        let bytes2 = state2.as_bytes();

        // Count how many bits differ
        let mut diff_count = 0;
        for i in 0..40 {
            diff_count += (bytes1[i] ^ bytes2[i]).count_ones();
        }

        // Total number of bits
        let total_bits = 40 * 8;

        // Calculate percentage of different bits
        let diff_percentage = diff_count as f64 / total_bits as f64;

        // With avalanche effect, should be around 50% different
        // We use a wide range to avoid flaky tests
        prop_assert!(diff_percentage > 0.3 && diff_percentage < 0.7);
    }

    // Test that different optimization levels produce the same output
    #[test]
    fn keccak_optimization_consistency(
        x0 in any::<u64>(),
        x1 in any::<u64>(),
        x2 in any::<u64>(),
        x3 in any::<u64>()
    ) {
        // Skip test if optimization levels aren't available
        if !OptimizationLevel::Basic.is_available() {
            return Ok(());
        }

        // Create reference state
        let mut state_ref = [0u64; 25];
        state_ref[0] = x0;
        state_ref[1] = x1;
        state_ref[2] = x2;
        state_ref[3] = x3;

        // Create optimized state with same values
        let mut state_opt = [0u64; 25];
        state_opt[0] = x0;
        state_opt[1] = x1;
        state_opt[2] = x2;
        state_opt[3] = x3;

        // Apply permutations
        f1600(&mut state_ref);
        p1600_optimized(&mut state_opt, OptimizationLevel::Basic);

        // Results should be identical
        prop_assert_eq!(state_ref, state_opt);
    }

    // Test that Ascon-p with 12 rounds is not reversible by 12 more rounds
    // This ensures cryptographic strength
    #[test]
    fn ascon_permutation_not_self_inverse(
        x0 in any::<u64>(),
        x1 in any::<u64>(),
        x2 in any::<u64>(),
        x3 in any::<u64>(),
        x4 in any::<u64>()
    ) {
        // Create original state
        let mut state = AsconState::new(x0, x1, x2, x3, x4);
        let original = state;

        // Apply permutation twice
        state.permute_12();
        state.permute_12();

        // States should be different (not an involution)
        prop_assert_ne!(state[0], original[0]);
        prop_assert_ne!(state[1], original[1]);
        prop_assert_ne!(state[2], original[2]);
        prop_assert_ne!(state[3], original[3]);
        prop_assert_ne!(state[4], original[4]);
    }

    // Test that Keccak is not self-inverse
    #[test]
    fn keccak_not_self_inverse(
        x0 in any::<u64>(),
        x1 in any::<u64>(),
        x2 in any::<u64>()
    ) {
        // Create state
        let mut state = [0u64; 25];
        state[0] = x0;
        state[1] = x1;
        state[2] = x2;

        // Save original
        let original = state;

        // Apply permutation twice
        f1600(&mut state);
        f1600(&mut state);

        // Should be different from original (not an involution)
        prop_assert_ne!(state, original);
    }
}

quickcheck::quickcheck! {
    // Test that Keccak permutation is deterministic
    fn keccak_deterministic(x0: u64, x1: u64, x2: u64) -> bool {
        let mut state1 = [0u64; 25];
        let mut state2 = [0u64; 25];

        state1[0] = x0;
        state1[1] = x1;
        state1[2] = x2;

        state2[0] = x0;
        state2[1] = x1;
        state2[2] = x2;

        f1600(&mut state1);
        f1600(&mut state2);

        state1 == state2
    }

    // Test that Ascon permutation is deterministic
    fn ascon_deterministic(x0: u64, x1: u64, x2: u64) -> bool {
        let mut state1 = AsconState::new(x0, x1, x2, 0, 0);
        let mut state2 = AsconState::new(x0, x1, x2, 0, 0);

        state1.permute_12();
        state2.permute_12();

        // Check equality of all state words
        state1[0] == state2[0] &&
            state1[1] == state2[1] &&
            state1[2] == state2[2] &&
            state1[3] == state2[3] &&
            state1[4] == state2[4]
    }

    // Test that Keccak permutation with different rounds produce different outputs
    fn keccak_round_count_matters(x0: u64, x1: u64) -> bool {
        let mut state1 = [0u64; 25];
        let mut state2 = [0u64; 25];

        state1[0] = x0;
        state1[1] = x1;

        state2[0] = x0;
        state2[1] = x1;

        // Apply permutation with different rounds
        lib_q_sponge::keccak_p(&mut state1, 12);
        lib_q_sponge::keccak_p(&mut state2, 24);

        // Outputs should be different
        state1 != state2
    }

    // Test that Ascon permutations with different rounds produce different outputs
    fn ascon_round_count_matters(x0: u64, x1: u64) -> bool {
        let mut state1 = AsconState::new(x0, x1, 0, 0, 0);
        let mut state2 = AsconState::new(x0, x1, 0, 0, 0);

        // Apply permutation with different rounds
        state1.permute_6();
        state2.permute_12();

        // Outputs should be different
        state1[0] != state2[0] || state1[1] != state2[1] ||
            state1[2] != state2[2] || state1[3] != state2[3] ||
            state1[4] != state2[4]
    }
}
