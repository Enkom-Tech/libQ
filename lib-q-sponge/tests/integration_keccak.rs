//! Integration tests for Keccak re-exports from lib-q-sponge

use lib_q_sponge::{f1600, f200, f400, f800, p1600};

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
