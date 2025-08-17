//! Integration tests for cross-sponge functionality in lib-q-sponge

use lib_q_sponge::{f1600, State};

#[test]
fn test_cross_sponge_availability() {
    // Test that both Keccak and Ascon functions are available in the same crate
    let mut keccak_state = [0u64; 25];
    let mut ascon_state = State::new(0x1234567890abcdef, 0, 0, 0, 0);

    // Both should be accessible
    f1600(&mut keccak_state);
    ascon_state.permute_12();

    // Verify both produced non-zero output
    let keccak_non_zero = keccak_state.iter().any(|&x| x != 0);
    let ascon_non_zero = ascon_state.as_bytes().iter().any(|&x| x != 0);

    assert!(keccak_non_zero, "Keccak should produce non-zero output");
    assert!(ascon_non_zero, "Ascon should produce non-zero output");
}

#[test]
fn test_sponge_consistency_across_imports() {
    // Test that the same sponge functions produce consistent results
    // regardless of how they're imported

    // Test Keccak consistency
    let mut state1 = [0u64; 25];
    let mut state2 = [0u64; 25];

    state1[0] = 0x1234567890abcdef;
    state2[0] = 0x1234567890abcdef;

    f1600(&mut state1);
    f1600(&mut state2);

    assert_eq!(state1, state2, "Keccak should be consistent");

    // Test Ascon consistency
    let mut ascon1 = State::new(0x1234567890abcdef, 0, 0, 0, 0);
    let mut ascon2 = State::new(0x1234567890abcdef, 0, 0, 0, 0);

    ascon1.permute_12();
    ascon2.permute_12();

    assert_eq!(
        ascon1.as_bytes(),
        ascon2.as_bytes(),
        "Ascon should be consistent"
    );
}

#[test]
fn test_sponge_avalanche_comparison() {
    // Test that both sponges exhibit proper avalanche effect
    // This verifies they're both functioning as cryptographic primitives

    // Keccak avalanche test
    let mut keccak1 = [0u64; 25];
    let mut keccak2 = [0u64; 25];

    keccak1[0] = 0x1234567890abcdef;
    keccak2[0] = 0x1234567890abcdee; // 1 bit different

    f1600(&mut keccak1);
    f1600(&mut keccak2);

    let keccak_diff = keccak1
        .iter()
        .zip(keccak2.iter())
        .map(|(a, b)| (a ^ b).count_ones())
        .sum::<u32>();

    // Ascon avalanche test
    let mut ascon1 = State::new(0x1234567890abcdef, 0, 0, 0, 0);
    let mut ascon2 = State::new(0x1234567890abcdee, 0, 0, 0, 0); // 1 bit different

    ascon1.permute_12();
    ascon2.permute_12();

    let ascon_bytes1 = ascon1.as_bytes();
    let ascon_bytes2 = ascon2.as_bytes();
    let ascon_diff = ascon_bytes1
        .iter()
        .zip(ascon_bytes2.iter())
        .map(|(a, b)| (a ^ b).count_ones())
        .sum::<u32>();

    // Both should show significant differences (avalanche effect)
    let keccak_total_bits = 25 * 64;
    let ascon_total_bits = 40 * 8;

    let keccak_diff_percentage = (keccak_diff as f64) / (keccak_total_bits as f64);
    let ascon_diff_percentage = (ascon_diff as f64) / (ascon_total_bits as f64);

    // Both should show avalanche effect (30-70% different bits)
    assert!(
        keccak_diff_percentage > 0.3 && keccak_diff_percentage < 0.7,
        "Keccak avalanche effect: {:.1}% bits different",
        keccak_diff_percentage * 100.0
    );

    assert!(
        ascon_diff_percentage > 0.3 && ascon_diff_percentage < 0.7,
        "Ascon avalanche effect: {:.1}% bits different",
        ascon_diff_percentage * 100.0
    );
}

#[test]
fn test_sponge_zero_input_behavior() {
    // Test that both sponges handle zero input correctly
    // (produce non-zero output from zero input)

    // Keccak zero input test
    let mut keccak_state = [0u64; 25];
    f1600(&mut keccak_state);

    let keccak_non_zero = keccak_state.iter().any(|&x| x != 0);
    assert!(
        keccak_non_zero,
        "Keccak should produce non-zero output from zero input"
    );

    // Ascon zero input test
    let mut ascon_state = State::new(0, 0, 0, 0, 0);
    ascon_state.permute_12();

    let ascon_non_zero = ascon_state.as_bytes().iter().any(|&x| x != 0);
    assert!(
        ascon_non_zero,
        "Ascon should produce non-zero output from zero input"
    );
}

#[test]
fn test_sponge_deterministic_behavior() {
    // Test that both sponges are deterministic
    // (same input always produces same output)

    // Keccak deterministic test
    let mut keccak1 = [0u64; 25];
    let mut keccak2 = [0u64; 25];

    keccak1[0] = 0xdeadbeefcafebabe;
    keccak2[0] = 0xdeadbeefcafebabe;

    f1600(&mut keccak1);
    f1600(&mut keccak2);

    assert_eq!(keccak1, keccak2, "Keccak should be deterministic");

    // Ascon deterministic test
    let mut ascon1 = State::new(0xdeadbeefcafebabe, 0, 0, 0, 0);
    let mut ascon2 = State::new(0xdeadbeefcafebabe, 0, 0, 0, 0);

    ascon1.permute_12();
    ascon2.permute_12();

    assert_eq!(
        ascon1.as_bytes(),
        ascon2.as_bytes(),
        "Ascon should be deterministic"
    );
}

#[test]
fn test_sponge_state_independence() {
    // Test that different sponge instances don't interfere with each other
    // This verifies proper encapsulation

    // Create multiple instances of each sponge with different initial values
    let mut keccak1 = [0u64; 25];
    let mut keccak2 = [0u64; 25];
    let mut ascon1 = State::new(0x1234567890abcdef, 0, 0, 0, 0);
    let mut ascon2 = State::new(0xfedcba0987654321, 0, 0, 0, 0);

    // Initialize Keccak states with different values
    keccak1[0] = 0x1234567890abcdef;
    keccak2[0] = 0xfedcba0987654321;

    // Apply permutations
    f1600(&mut keccak1);
    f1600(&mut keccak2);
    ascon1.permute_12();
    ascon2.permute_12();

    // Verify they produced different outputs (due to different inputs)
    assert_ne!(
        keccak1, keccak2,
        "Different Keccak inputs should produce different outputs"
    );
    assert_ne!(
        ascon1.as_bytes(),
        ascon2.as_bytes(),
        "Different Ascon inputs should produce different outputs"
    );

    // Verify they both produced non-zero outputs
    let keccak1_non_zero = keccak1.iter().any(|&x| x != 0);
    let keccak2_non_zero = keccak2.iter().any(|&x| x != 0);
    let ascon1_non_zero = ascon1.as_bytes().iter().any(|&x| x != 0);
    let ascon2_non_zero = ascon2.as_bytes().iter().any(|&x| x != 0);

    assert!(keccak1_non_zero, "Keccak1 should produce non-zero output");
    assert!(keccak2_non_zero, "Keccak2 should produce non-zero output");
    assert!(ascon1_non_zero, "Ascon1 should produce non-zero output");
    assert!(ascon2_non_zero, "Ascon2 should produce non-zero output");
}
