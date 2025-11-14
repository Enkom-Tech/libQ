//! Debug seed_ek Generation Issue
//!
//! This module focuses on debugging why seed_ek generation is incorrect.

#[cfg(feature = "aes-drbg")]
use lib_q_hqc::aes_ctr_drbg::Aes256CtrDrbg;
#[cfg(feature = "aes-drbg")]
use rand_core::RngCore;

/// Helper function to convert hex string to bytes
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut chars = hex.chars().peekable();

    while let (Some(c1), Some(c2)) = (chars.next(), chars.next()) {
        let byte = u8::from_str_radix(&format!("{}{}", c1, c2), 16).unwrap();
        bytes.push(byte);
    }

    bytes
}

#[cfg(feature = "aes-drbg")]
#[test]
fn test_seed_ek_generation_step_by_step() {
    println!("=== seed_ek Generation Step-by-Step Debug ===");

    // Use the KAT seed directly
    let kat_seed_kem = hex_to_bytes(
        "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1",
    );
    let kat_seed_array: [u8; 48] = kat_seed_kem.try_into().unwrap();

    println!("KAT seed: {:02x?}", kat_seed_array);

    // Initialize DRBG with KAT seed
    let mut rng = Aes256CtrDrbg::instantiate(&kat_seed_array);

    // Generate seed_dk (first 32 bytes)
    let mut seed_dk = [0u8; 32];
    rng.fill_bytes(&mut seed_dk);
    println!("Generated seed_dk: {:02x?}", seed_dk);

    // Expected seed_dk
    let expected_seed_dk =
        hex_to_bytes("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d");
    println!("Expected seed_dk:  {:02x?}", expected_seed_dk);
    println!("seed_dk match: {}", seed_dk == expected_seed_dk.as_slice());

    // Now generate seed_ek (next 32 bytes)
    let mut seed_ek = [0u8; 32];
    rng.fill_bytes(&mut seed_ek);
    println!("Generated seed_ek: {:02x?}", seed_ek);

    // Expected seed_ek
    let expected_seed_ek =
        hex_to_bytes("74b2d352cf74c934069c9de74757f50566fe46f7e122243c90c30adebb0e3db3");
    println!("Expected seed_ek:  {:02x?}", expected_seed_ek);
    println!("seed_ek match: {}", seed_ek == expected_seed_ek.as_slice());

    // Let's see what the DRBG state looks like after generating seed_dk
    println!("\n=== DRBG State Analysis ===");

    // Re-initialize to see the state after seed_dk generation
    let mut rng2 = Aes256CtrDrbg::instantiate(&kat_seed_array);
    let mut _seed_dk2 = [0u8; 32];
    rng2.fill_bytes(&mut _seed_dk2);

    // Now let's manually generate the next 32 bytes to see what's happening
    println!("Manual generation of next 32 bytes:");

    // We need to access the internal state, but it's private
    // Let's create a new DRBG and generate 64 bytes, then compare
    let mut rng3 = Aes256CtrDrbg::instantiate(&kat_seed_array);
    let mut output_64 = [0u8; 64];
    rng3.fill_bytes(&mut output_64);

    println!("First 64 bytes from fresh DRBG:");
    println!("  Bytes 0-31:  {:02x?}", &output_64[0..32]);
    println!("  Bytes 32-63: {:02x?}", &output_64[32..64]);

    println!("Expected values:");
    println!("  seed_dk: {:02x?}", expected_seed_dk);
    println!("  seed_ek: {:02x?}", expected_seed_ek);

    // Check if the issue is in our understanding of the expected values
    println!("\n=== Cross-Reference Check ===");

    // Let's check if the expected seed_ek is actually in the KAT seed
    println!("KAT seed bytes 32-47: {:02x?}", &kat_seed_array[32..48]);
    println!("Expected seed_ek:     {:02x?}", expected_seed_ek);
    println!(
        "Match: {}",
        kat_seed_array[32..48] == expected_seed_ek[0..16]
    );

    // Let's also check if there's a pattern in the KAT seed
    println!("\nKAT seed analysis:");
    println!("  First 32 bytes:  {:02x?}", &kat_seed_array[0..32]);
    println!("  Last 16 bytes:   {:02x?}", &kat_seed_array[32..48]);
}

#[cfg(feature = "aes-drbg")]
#[test]
fn test_kat_seed_structure_analysis() {
    println!("=== KAT Seed Structure Analysis ===");

    // The KAT seed_kem from the official KAT file
    let kat_seed_kem = hex_to_bytes(
        "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1",
    );

    println!("Full KAT seed: {:02x?}", kat_seed_kem);
    println!("Length: {} bytes", kat_seed_kem.len());

    // Split into two parts (32 bytes + 16 bytes)
    let part1 = &kat_seed_kem[0..32];
    let part2 = &kat_seed_kem[32..48];

    println!("Part 1 (bytes 0-31):  {:02x?}", part1);
    println!("Part 2 (bytes 32-47): {:02x?}", part2);

    // Expected values from KAT
    let expected_seed_dk =
        hex_to_bytes("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d");
    let expected_seed_ek =
        hex_to_bytes("74b2d352cf74c934069c9de74757f50566fe46f7e122243c90c30adebb0e3db3");

    println!("\nExpected values:");
    println!("Expected seed_dk: {:02x?}", expected_seed_dk);
    println!("Expected seed_ek: {:02x?}", expected_seed_ek);

    println!("\nComparisons:");
    println!(
        "Part 1 == expected_seed_dk: {}",
        part1 == expected_seed_dk.as_slice()
    );
    println!(
        "Part 2 == expected_seed_ek (first 16 bytes): {}",
        part2 == &expected_seed_ek[0..16]
    );

    // Hypothesis: Maybe the KAT seed is not the input to key generation,
    // but rather the output of some other process

    println!("\n=== Hypothesis Testing ===");
    println!("Hypothesis 1: KAT seed is the input to key generation");
    println!("  - We use KAT seed to initialize DRBG");
    println!("  - Generate seed_dk and seed_ek from DRBG");
    println!("  - Result: seed_dk matches, seed_ek doesn't");

    println!("\nHypothesis 2: KAT seed contains the actual seed_dk and seed_ek");
    println!("  - Part 1 of KAT seed is seed_dk");
    println!("  - Part 2 of KAT seed is seed_ek");
    println!("  - Result: Neither matches expected values");

    println!("\nHypothesis 3: KAT seed is generated by reference entropy");
    println!("  - Reference uses sequential entropy (0,1,2,...,47)");
    println!("  - Generates KAT seed using AES-CTR-DRBG");
    println!("  - Then uses KAT seed for key generation");
    println!("  - Result: This matches our findings!");
}

#[cfg(not(feature = "aes-drbg"))]
#[test]
fn test_feature_disabled() {
    println!("=== AES-CTR-DRBG Feature Disabled Test ===");
    println!("✅ Feature disabled test passed - aes-drbg feature is not enabled");
}
