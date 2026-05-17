//! SHAKE256 PRNG KAT (Known Answer Test) validation
//!
//! This module validates that our SHAKE256 PRNG implementation produces correct
//! XOF output matching the reference HQC specification exactly.
//!
//! The PRNG follows the reference HQC prng_init sequence:
//!   1. SHAKE256 absorb(entropy_input)     -- 48 bytes
//!   2. SHAKE256 absorb(personalization)   -- 0 bytes (empty)
//!   3. SHAKE256 absorb(domain=0x00)       -- 1 byte
//!   4. SHAKE256 finalize
//!   5. SHAKE256 squeeze(output)
//!
//! Expected values verified independently via Python hashlib.shake_256.

use lib_q_hqc::shake256_prng::create_shake256_prng_rng;
use rand_core::Rng;

/// SHAKE256 XOF output for KAT seed from HQC-1 test vector.
/// Input: SHAKE256(seed || 0x00), squeeze 32 bytes.
/// Verified against Python hashlib.shake_256.
#[test]
fn test_shake256_prng_reference_compatibility() {
    let seed = hex::decode("9EF877FDDBE8891C6E4E79EAF022E563DEFACA6B152161B9A423E8FE96A403E774B2D352CF74C934069C9DE74757F505").unwrap();
    let mut entropy_input = [0u8; 48];
    entropy_input.copy_from_slice(&seed);

    let mut rng = create_shake256_prng_rng(entropy_input);

    let mut seed_kem = [0u8; 32];
    rng.fill_bytes(&mut seed_kem);

    let expected =
        hex::decode("cefc0d60050e04c3171859e54ba888d2f670e22ebe926b0b307a65264fbc08f8").unwrap();

    assert_eq!(
        &seed_kem[..],
        &expected[..],
        "SHAKE256 PRNG output doesn't match expected XOF output"
    );
}

/// Multiple test vectors with correct SHAKE256 XOF expected output.
/// Each expected value is SHAKE256(seed || 0x00) squeezed to 32 bytes,
/// verified against Python hashlib.shake_256.
#[test]
fn test_shake256_prng_multiple_vectors() {
    let test_vectors = [
        (
            "9EF877FDDBE8891C6E4E79EAF022E563DEFACA6B152161B9A423E8FE96A403E774B2D352CF74C934069C9DE74757F505",
            "cefc0d60050e04c3171859e54ba888d2f670e22ebe926b0b307a65264fbc08f8",
        ),
        (
            "A1B2C3D4E5F6789012345678901234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF123456",
            "93cd9e206af68ec0b150c7c696568daa83717e14ef14b50298969df66434e789",
        ),
        (
            "FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321",
            "05c2dcfecc2686acfc28f815f3558092f4c6a4ff634c313053381a8fd06e9f97",
        ),
    ];

    for (i, (seed_hex, expected_hex)) in test_vectors.iter().enumerate() {
        let seed = hex::decode(seed_hex).unwrap();
        let mut entropy_input = [0u8; 48];
        entropy_input.copy_from_slice(&seed);

        let mut rng = create_shake256_prng_rng(entropy_input);
        let mut seed_kem = [0u8; 32];
        rng.fill_bytes(&mut seed_kem);

        let expected = hex::decode(expected_hex).unwrap();

        assert_eq!(
            &seed_kem[..],
            &expected[..],
            "Vector {}: SHAKE256 PRNG output doesn't match expected",
            i + 1
        );
    }
}

/// Test that the PRNG produces consistent output for the same input
#[test]
fn test_shake256_prng_deterministic() {
    let seed = hex::decode("9EF877FDDBE8891C6E4E79EAF022E563DEFACA6B152161B9A423E8FE96A403E774B2D352CF74C934069C9DE74757F505").unwrap();
    let mut entropy_input = [0u8; 48];
    entropy_input.copy_from_slice(&seed);

    // Create two PRNG instances with the same seed
    let mut rng1 = create_shake256_prng_rng(entropy_input);
    let mut rng2 = create_shake256_prng_rng(entropy_input);

    // Generate 100 bytes from each
    let mut output1 = [0u8; 100];
    let mut output2 = [0u8; 100];

    rng1.fill_bytes(&mut output1);
    rng2.fill_bytes(&mut output2);

    // Outputs should be identical
    assert_eq!(output1, output2, "SHAKE256 PRNG is not deterministic");
}

/// Test that different seeds produce different outputs
#[test]
fn test_shake256_prng_different_seeds() {
    let seed1 = hex::decode("9EF877FDDBE8891C6E4E79EAF022E563DEFACA6B152161B9A423E8FE96A403E774B2D352CF74C934069C9DE74757F505").unwrap();
    let seed2 = hex::decode("A1B2C3D4E5F6789012345678901234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF123456").unwrap();

    let mut entropy_input1 = [0u8; 48];
    let mut entropy_input2 = [0u8; 48];
    entropy_input1.copy_from_slice(&seed1);
    entropy_input2.copy_from_slice(&seed2);

    let mut rng1 = create_shake256_prng_rng(entropy_input1);
    let mut rng2 = create_shake256_prng_rng(entropy_input2);

    let mut output1 = [0u8; 32];
    let mut output2 = [0u8; 32];

    rng1.fill_bytes(&mut output1);
    rng2.fill_bytes(&mut output2);

    // Outputs should be different
    assert_ne!(
        output1, output2,
        "Different seeds produced identical outputs"
    );
}

/// Validate consecutive squeeze blocks produce correct XOF stream.
#[test]
fn test_shake256_xof_intermediate_states() {
    let seed = hex::decode("9EF877FDDBE8891C6E4E79EAF022E563DEFACA6B152161B9A423E8FE96A403E774B2D352CF74C934069C9DE74757F505").unwrap();
    let mut entropy_input = [0u8; 48];
    entropy_input.copy_from_slice(&seed);

    let mut rng = create_shake256_prng_rng(entropy_input);

    let mut block1 = [0u8; 32];
    let mut block2 = [0u8; 32];

    rng.fill_bytes(&mut block1);
    rng.fill_bytes(&mut block2);

    assert!(block1.iter().any(|&x| x != 0), "First block is all zeros");
    assert!(block2.iter().any(|&x| x != 0), "Second block is all zeros");
    assert_ne!(block1, block2, "Consecutive blocks are identical");

    let expected_block1 =
        hex::decode("cefc0d60050e04c3171859e54ba888d2f670e22ebe926b0b307a65264fbc08f8").unwrap();
    let expected_block2 =
        hex::decode("3deca12f8963918f537c67f2571fffde4bb80684d826860c7515ce86e35571f5").unwrap();

    assert_eq!(
        &block1[..],
        &expected_block1[..],
        "First block doesn't match expected XOF output"
    );
    assert_eq!(
        &block2[..],
        &expected_block2[..],
        "Second block doesn't match expected XOF output"
    );
}

/// Test edge cases and error conditions
#[test]
fn test_shake256_prng_edge_cases() {
    // Test with all-zero seed
    let zero_seed = [0u8; 48];
    let mut rng = create_shake256_prng_rng(zero_seed);
    let mut output = [0u8; 32];
    rng.fill_bytes(&mut output);

    // Should produce non-zero output (SHAKE256 should hash the zeros)
    assert!(
        output.iter().any(|&x| x != 0),
        "All-zero seed produced all-zero output"
    );

    // Test with all-ones seed
    let ones_seed = [0xFFu8; 48];
    let mut rng = create_shake256_prng_rng(ones_seed);
    let mut output = [0u8; 32];
    rng.fill_bytes(&mut output);

    // Should produce non-zero output
    assert!(
        output.iter().any(|&x| x != 0),
        "All-ones seed produced all-zero output"
    );

    // Test that different edge cases produce different outputs
    let mut rng_zero = create_shake256_prng_rng([0u8; 48]);
    let mut rng_ones = create_shake256_prng_rng([0xFFu8; 48]);

    let mut output_zero = [0u8; 32];
    let mut output_ones = [0u8; 32];

    rng_zero.fill_bytes(&mut output_zero);
    rng_ones.fill_bytes(&mut output_ones);

    assert_ne!(
        output_zero, output_ones,
        "Zero and ones seeds produced identical outputs"
    );
}
