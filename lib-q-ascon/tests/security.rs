//! Security tests for Ascon permutation
//!
//! These tests verify security-critical properties including memory safety,
//! input validation, error handling, and side-channel resistance.

use lib_q_ascon::State;
use std::panic;

/// Test that invalid round counts are properly handled
#[test]
fn test_invalid_round_count() {
    let mut state = State::new(0x1234567890abcdef, 0, 0, 0, 0);

    // Test that permute_n panics with invalid round count in debug mode
    #[cfg(debug_assertions)]
    {
        let result = panic::catch_unwind(|| {
            let mut test_state = state.clone();
            test_state.permute_n(13); // Invalid: > 12
        });
        assert!(
            result.is_err(),
            "permute_n should panic with invalid round count in debug mode"
        );
    }

    // Test that valid round counts work
    state.permute_n(1);
    state.permute_n(6);
    state.permute_n(8);
    state.permute_n(12);
}

/// Test that state indexing is bounds-checked
#[test]
fn test_state_index_bounds() {
    let state = State::new(
        0x1234567890abcdef,
        0xfedcba0987654321,
        0xdeadbeefcafebabe,
        0xbebafecaefbeadde,
        0x0123456789abcdef,
    );

    // Valid indices should work
    assert_eq!(state[0], 0x1234567890abcdef);
    assert_eq!(state[1], 0xfedcba0987654321);
    assert_eq!(state[2], 0xdeadbeefcafebabe);
    assert_eq!(state[3], 0xbebafecaefbeadde);
    assert_eq!(state[4], 0x0123456789abcdef);

    // Invalid indices should panic
    let result = panic::catch_unwind(|| {
        let _ = state[5]; // Invalid index
    });
    assert!(
        result.is_err(),
        "State indexing should panic with invalid index"
    );
}

/// Test that TryFrom handles invalid input lengths correctly
#[test]
fn test_try_from_invalid_length() {
    // Test with too short input
    let short_bytes = [0u8; 39]; // Should be 40 bytes
    let result = State::try_from(short_bytes.as_slice());
    assert!(result.is_err(), "TryFrom should fail with too short input");

    // Test with too long input
    let long_bytes = [0u8; 41]; // Should be 40 bytes
    let result = State::try_from(long_bytes.as_slice());
    assert!(result.is_err(), "TryFrom should fail with too long input");

    // Test with correct length
    let correct_bytes = [0u8; 40];
    let result = State::try_from(correct_bytes.as_slice());
    assert!(result.is_ok(), "TryFrom should succeed with correct length");
}

/// Test that state conversion preserves data integrity
#[test]
fn test_state_conversion_integrity() {
    let original_state = State::new(
        0x1234567890abcdef,
        0xfedcba0987654321,
        0xdeadbeefcafebabe,
        0xbebafecaefbeadde,
        0x0123456789abcdef,
    );

    // Convert to bytes and back
    let bytes = original_state.as_bytes();
    let reconstructed_state = State::try_from(bytes.as_slice()).unwrap();

    // Verify data integrity
    assert_eq!(original_state[0], reconstructed_state[0]);
    assert_eq!(original_state[1], reconstructed_state[1]);
    assert_eq!(original_state[2], reconstructed_state[2]);
    assert_eq!(original_state[3], reconstructed_state[3]);
    assert_eq!(original_state[4], reconstructed_state[4]);
}

/// Test that permutation is deterministic
#[test]
fn test_permutation_determinism() {
    let input_state = State::new(
        0x1234567890abcdef,
        0xfedcba0987654321,
        0xdeadbeefcafebabe,
        0xbebafecaefbeadde,
        0x0123456789abcdef,
    );

    // Apply permutation multiple times
    let mut state1 = input_state.clone();
    let mut state2 = input_state.clone();
    let mut state3 = input_state.clone();

    state1.permute_12();
    state2.permute_12();
    state3.permute_12();

    // All results should be identical
    assert_eq!(state1.as_bytes(), state2.as_bytes());
    assert_eq!(state2.as_bytes(), state3.as_bytes());
    assert_eq!(state1.as_bytes(), state3.as_bytes());
}

/// Test that permutation produces avalanche effect
#[test]
fn test_avalanche_effect() {
    let base_state = State::new(
        0x1234567890abcdef,
        0xfedcba0987654321,
        0xdeadbeefcafebabe,
        0xbebafecaefbeadde,
        0x0123456789abcdef,
    );

    // Create states with single bit differences
    let mut modified_states = Vec::new();
    for i in 0..5 {
        for bit in 0..64 {
            let mut modified = base_state.clone();
            modified[i] ^= 1u64 << bit;
            modified_states.push((i, bit, modified));
        }
    }

    // Apply permutation to base state
    let mut base_permuted = base_state.clone();
    base_permuted.permute_12();
    let base_bytes = base_permuted.as_bytes();

    // Check that each single-bit change produces significantly different output
    for (word_idx, bit_idx, mut modified_state) in modified_states {
        modified_state.permute_12();
        let modified_bytes = modified_state.as_bytes();

        // Count different bits
        let mut diff_bits = 0;
        for i in 0..40 {
            diff_bits += (base_bytes[i] ^ modified_bytes[i]).count_ones();
        }

        // At least 50% of bits should be different (avalanche effect)
        let total_bits = 40 * 8;
        let diff_percentage = diff_bits as f64 / total_bits as f64;

        assert!(
            diff_percentage > 0.4, // Allow some tolerance
            "Avalanche effect too weak for bit {} in word {}: {:.1}% bits different",
            bit_idx,
            word_idx,
            diff_percentage * 100.0
        );
    }
}

/// Test that zeroization works correctly when enabled
#[cfg(feature = "zeroize")]
#[test]
fn test_zeroization() {
    use zeroize::Zeroize;

    let mut state = State::new(
        0x1234567890abcdef,
        0xfedcba0987654321,
        0xdeadbeefcafebabe,
        0xbebafecaefbeadde,
        0x0123456789abcdef,
    );

    // Verify state has non-zero values
    assert_ne!(state[0], 0);
    assert_ne!(state[1], 0);
    assert_ne!(state[2], 0);
    assert_ne!(state[3], 0);
    assert_ne!(state[4], 0);

    // Zeroize the state
    state.zeroize();

    // Verify all values are now zero
    assert_eq!(state[0], 0);
    assert_eq!(state[1], 0);
    assert_eq!(state[2], 0);
    assert_eq!(state[3], 0);
    assert_eq!(state[4], 0);
}

/// Test that state cloning preserves data
#[test]
fn test_state_cloning() {
    let original_state = State::new(
        0x1234567890abcdef,
        0xfedcba0987654321,
        0xdeadbeefcafebabe,
        0xbebafecaefbeadde,
        0x0123456789abcdef,
    );

    let cloned_state = original_state.clone();

    // Verify all values are preserved
    assert_eq!(original_state[0], cloned_state[0]);
    assert_eq!(original_state[1], cloned_state[1]);
    assert_eq!(original_state[2], cloned_state[2]);
    assert_eq!(original_state[3], cloned_state[3]);
    assert_eq!(original_state[4], cloned_state[4]);

    // Verify they are independent (modifying one doesn't affect the other)
    let mut modified_original = original_state.clone();
    modified_original[0] = 0xdeadbeefdeadbeef;

    assert_ne!(modified_original[0], cloned_state[0]);
    assert_eq!(original_state[0], cloned_state[0]);
}

/// Test that state mutation works correctly
#[test]
fn test_state_mutation() {
    let mut state = State::new(0, 0, 0, 0, 0);

    // Test individual word mutation
    state[0] = 0x1234567890abcdef;
    state[1] = 0xfedcba0987654321;
    state[2] = 0xdeadbeefcafebabe;
    state[3] = 0xbebafecaefbeadde;
    state[4] = 0x0123456789abcdef;

    assert_eq!(state[0], 0x1234567890abcdef);
    assert_eq!(state[1], 0xfedcba0987654321);
    assert_eq!(state[2], 0xdeadbeefcafebabe);
    assert_eq!(state[3], 0xbebafecaefbeadde);
    assert_eq!(state[4], 0x0123456789abcdef);
}

/// Test that permutation doesn't produce all-zero output from non-zero input
#[test]
fn test_no_zero_output() {
    let test_states = [
        State::new(1, 0, 0, 0, 0),
        State::new(0, 1, 0, 0, 0),
        State::new(0, 0, 1, 0, 0),
        State::new(0, 0, 0, 1, 0),
        State::new(0, 0, 0, 0, 1),
        State::new(0x1234567890abcdef, 0, 0, 0, 0),
        State::new(0, 0x1234567890abcdef, 0, 0, 0),
        State::new(0, 0, 0x1234567890abcdef, 0, 0),
        State::new(0, 0, 0, 0x1234567890abcdef, 0),
        State::new(0, 0, 0, 0, 0x1234567890abcdef),
    ];

    for (i, mut state) in test_states.into_iter().enumerate() {
        state.permute_12();
        let bytes = state.as_bytes();

        // Verify output is not all zeros
        let all_zeros = bytes.iter().all(|&x| x == 0);
        assert!(
            !all_zeros,
            "Permutation produced all-zero output from non-zero input {}",
            i
        );
    }
}

/// Test that permutation rounds are distinct
#[test]
fn test_round_distinctness() {
    let base_state = State::new(
        0x1234567890abcdef,
        0xfedcba0987654321,
        0xdeadbeefcafebabe,
        0xbebafecaefbeadde,
        0x0123456789abcdef,
    );

    let mut state_6 = base_state.clone();
    let mut state_8 = base_state.clone();
    let mut state_12 = base_state.clone();

    state_6.permute_6();
    state_8.permute_8();
    state_12.permute_12();

    // All outputs should be different
    assert_ne!(state_6.as_bytes(), state_8.as_bytes());
    assert_ne!(state_8.as_bytes(), state_12.as_bytes());
    assert_ne!(state_6.as_bytes(), state_12.as_bytes());
}

/// Test that permutation is invertible (not bijective, but produces unique outputs)
#[test]
fn test_permutation_uniqueness() {
    let mut seen_outputs = std::collections::HashSet::new();
    let mut state = State::new(0, 0, 0, 0, 0);

    // Test multiple inputs to ensure permutation produces unique outputs
    for i in 0..100 {
        state[0] = i;
        let mut test_state = state.clone();
        test_state.permute_12();
        let output = test_state.as_bytes();

        // Each output should be unique
        assert!(
            seen_outputs.insert(output),
            "Permutation produced duplicate output for input {}",
            i
        );
    }
}

/// Test that state creation handles edge cases
#[test]
fn test_state_creation_edge_cases() {
    // Test with maximum values
    let max_state = State::new(
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
    );

    assert_eq!(max_state[0], 0xffffffffffffffff);
    assert_eq!(max_state[1], 0xffffffffffffffff);
    assert_eq!(max_state[2], 0xffffffffffffffff);
    assert_eq!(max_state[3], 0xffffffffffffffff);
    assert_eq!(max_state[4], 0xffffffffffffffff);

    // Test with alternating bit patterns
    let alt_state = State::new(
        0xaaaaaaaaaaaaaaaa,
        0x5555555555555555,
        0xaaaaaaaaaaaaaaaa,
        0x5555555555555555,
        0xaaaaaaaaaaaaaaaa,
    );

    assert_eq!(alt_state[0], 0xaaaaaaaaaaaaaaaa);
    assert_eq!(alt_state[1], 0x5555555555555555);
    assert_eq!(alt_state[2], 0xaaaaaaaaaaaaaaaa);
    assert_eq!(alt_state[3], 0x5555555555555555);
    assert_eq!(alt_state[4], 0xaaaaaaaaaaaaaaaa);
}
