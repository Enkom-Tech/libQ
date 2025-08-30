//! Integration tests for Ascon re-exports from lib-q-sponge

use lib_q_sponge::State;

#[test]
fn test_ascon_permutation_12() {
    // Test that the Ascon permutation with 12 rounds is accessible and functional
    let mut state = State::new(0x1234567890ABCDEF, 0xFEDCBA0987654321, 0, 0, 0);

    // Apply permutation
    state.permute_12();

    // Verify that the state has changed (permutation was applied)
    let bytes = state.as_bytes();
    assert_ne!(bytes[0..8], 0x1234567890ABCDEFu64.to_le_bytes());
    assert_ne!(bytes[8..16], 0xFEDCBA0987654321u64.to_le_bytes());

    // Verify that the state is not all zeros (permutation produced meaningful output)
    let all_zeros = bytes.iter().all(|&x| x == 0);
    assert!(!all_zeros, "Ascon permutation should not produce all zeros");
}

#[test]
fn test_ascon_permute_8() {
    // Test that the Ascon permutation with 8 rounds is accessible and functional
    let mut state = State::new(0xDEADBEEFCAFEBABE, 0xBEBAFECAEFBEADDE, 0, 0, 0);

    // Apply permutation
    state.permute_8();

    // Verify that the state has changed
    let bytes = state.as_bytes();
    assert_ne!(bytes[0..8], 0xDEADBEEFCAFEBABEu64.to_le_bytes());
    assert_ne!(bytes[8..16], 0xBEBAFECAEFBEADDEu64.to_le_bytes());
}

#[test]
fn test_ascon_permute_6() {
    // Test that the Ascon permutation with 6 rounds is accessible and functional
    let mut state = State::new(0x1234567890ABCDEF, 0, 0, 0, 0);

    // Apply permutation
    state.permute_6();

    // Verify that the state has changed
    let bytes = state.as_bytes();
    assert_ne!(bytes[0..8], 0x1234567890ABCDEFu64.to_le_bytes());
}

#[test]
fn test_ascon_consistency() {
    // Test that the same input produces the same output
    let mut state1 = State::new(0x1234567890ABCDEF, 0, 0, 0, 0);
    let mut state2 = State::new(0x1234567890ABCDEF, 0, 0, 0, 0);

    // Apply the same permutation to both
    state1.permute_12();
    state2.permute_12();

    // Verify they produce identical results
    assert_eq!(
        state1.as_bytes(),
        state2.as_bytes(),
        "Ascon permutation should be deterministic"
    );
}

#[test]
fn test_ascon_zero_input() {
    // Test that zero input produces non-zero output (avalanche effect)
    let mut state = State::new(0, 0, 0, 0, 0);

    // Apply permutation to zero state
    state.permute_12();

    // Verify that the output is not all zeros
    let all_zeros = state.as_bytes().iter().all(|&x| x == 0);
    assert!(
        !all_zeros,
        "Ascon permutation should produce non-zero output from zero input"
    );
}

#[test]
fn test_ascon_avalanche_effect() {
    // Test that small changes in input produce large changes in output
    let mut state1 = State::new(0x1234567890ABCDEF, 0, 0, 0, 0);
    let mut state2 = State::new(0x1234567890ABCDEE, 0, 0, 0, 0); // Only 1 bit different

    // Apply permutation to both
    state1.permute_12();
    state2.permute_12();

    // Count how many bits are different in the output
    let bytes1 = state1.as_bytes();
    let bytes2 = state2.as_bytes();
    let mut diff_count = 0;
    for i in 0..40 {
        diff_count += (bytes1[i] ^ bytes2[i]).count_ones();
    }

    // Verify avalanche effect (should be around 50% of bits different)
    let total_bits = 40 * 8;
    let diff_percentage = (diff_count as f64) / (total_bits as f64);

    // Allow some tolerance (between 30% and 70% different bits)
    assert!(
        diff_percentage > 0.3 && diff_percentage < 0.7,
        "Avalanche effect not observed: {:.1}% bits different",
        diff_percentage * 100.0
    );
}

#[test]
fn test_ascon_round_differences() {
    // Test that different round counts produce different outputs
    let mut state_6 = State::new(0x1234567890ABCDEF, 0, 0, 0, 0);
    let mut state_8 = State::new(0x1234567890ABCDEF, 0, 0, 0, 0);
    let mut state_12 = State::new(0x1234567890ABCDEF, 0, 0, 0, 0);

    // Apply different permutations
    state_6.permute_6();
    state_8.permute_8();
    state_12.permute_12();

    // Verify they produce different results
    assert_ne!(
        state_6.as_bytes(),
        state_8.as_bytes(),
        "6-round and 8-round permutations should differ"
    );
    assert_ne!(
        state_8.as_bytes(),
        state_12.as_bytes(),
        "8-round and 12-round permutations should differ"
    );
    assert_ne!(
        state_6.as_bytes(),
        state_12.as_bytes(),
        "6-round and 12-round permutations should differ"
    );
}

#[test]
fn test_ascon_full_state() {
    // Test permutation with all state words initialized
    let mut state = State::new(
        0x1234567890ABCDEF,
        0xFEDCBA0987654321,
        0xDEADBEEFCAFEBABE,
        0xBEBAFECAEFBEADDE,
        0x0123456789ABCDEF,
    );

    // Apply permutation
    state.permute_12();

    // Verify all state words changed
    let bytes = state.as_bytes();
    assert_ne!(bytes[0..8], 0x1234567890ABCDEFu64.to_le_bytes());
    assert_ne!(bytes[8..16], 0xFEDCBA0987654321u64.to_le_bytes());
    assert_ne!(bytes[16..24], 0xDEADBEEFCAFEBABEu64.to_le_bytes());
    assert_ne!(bytes[24..32], 0xBEBAFECAEFBEADDEu64.to_le_bytes());
    assert_ne!(bytes[32..40], 0x0123456789ABCDEFu64.to_le_bytes());
}
