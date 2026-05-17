//! Debug State Transitions for AES256-CTR-DRBG
//!
//! This module contains detailed diagnostic tests to understand the exact
//! state transitions and identify where our implementation diverges from
//! the reference implementation.

#[cfg(feature = "aes-drbg")]
use lib_q_hqc::aes_ctr_drbg::Aes256CtrDrbg;
#[cfg(feature = "aes-drbg")]
use rand_core::Rng;

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
fn test_reference_sequence_analysis() {
    println!("=== Reference Implementation Sequence Analysis ===");

    // Based on the reference implementation analysis:
    // 1. randombytes_init() calls AES256_CTR_DRBG_Update() once
    // 2. randombytes() generates blocks, then calls AES256_CTR_DRBG_Update() at the END
    // 3. The key insight: CTR_DRBG_Update is called AFTER generating all requested bytes

    println!("Reference Implementation Flow:");
    println!("1. randombytes_init(entropy_input, NULL, security_strength)");
    println!("   - Copies entropy_input to seed_material[48]");
    println!("   - Sets Key[32] = 0, V[16] = 0");
    println!("   - Calls AES256_CTR_DRBG_Update(seed_material, Key, V)");
    println!("   - Sets reseed_counter = 1");

    println!("\n2. randombytes(x, xlen) - generates xlen bytes");
    println!("   - For each 16-byte block needed:");
    println!("     a. Increment V (rightmost byte first)");
    println!("     b. AES256_ECB(Key, V, block)");
    println!("     c. Copy block to output");
    println!("   - AFTER generating all bytes:");
    println!("     d. AES256_CTR_DRBG_Update(NULL, Key, V)");
    println!("     e. reseed_counter++");

    println!("\n3. Key insight: CTR_DRBG_Update happens AFTER the generate call completes");
    println!("   This means the state update affects the NEXT call, not the current one!");
}

#[cfg(feature = "aes-drbg")]
#[test]
fn test_single_vs_multiple_calls() {
    println!("=== Single vs Multiple Calls Analysis ===");

    // Use the KAT seed
    let kat_seed = hex_to_bytes(
        "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1",
    );
    let kat_seed_array: [u8; 48] = kat_seed.try_into().unwrap();

    println!("KAT seed: {:02x?}", kat_seed_array);

    // Test 1: Single call generating 64 bytes
    let mut rng1 = Aes256CtrDrbg::instantiate(&kat_seed_array);
    let mut output_64 = [0u8; 64];
    rng1.fill_bytes(&mut output_64);

    println!("\nSingle call (64 bytes):");
    println!("  Bytes 0-31:  {:02x?}", &output_64[0..32]);
    println!("  Bytes 32-63: {:02x?}", &output_64[32..64]);

    // Test 2: Two separate calls of 32 bytes each
    let mut rng2 = Aes256CtrDrbg::instantiate(&kat_seed_array);
    let mut output1 = [0u8; 32];
    let mut output2 = [0u8; 32];
    rng2.fill_bytes(&mut output1);
    rng2.fill_bytes(&mut output2);

    println!("\nTwo separate calls (32 + 32 bytes):");
    println!("  First call:  {:02x?}", output1);
    println!("  Second call: {:02x?}", output2);

    // Compare
    println!("\nComparison:");
    println!("  First 32 bytes match: {}", output1 == output_64[0..32]);
    println!("  Second 32 bytes match: {}", output2 == output_64[32..64]);

    if output1 == output_64[0..32] && output2 == output_64[32..64] {
        println!("✅ Single call and multiple calls produce identical output");
    } else {
        println!("❌ Single call and multiple calls produce different output");
        println!("  This suggests our state management between calls is incorrect");
    }

    // Expected values from KAT
    let expected_seed_dk =
        hex_to_bytes("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d");
    let expected_seed_ek =
        hex_to_bytes("74b2d352cf74c934069c9de74757f50566fe46f7e122243c90c30adebb0e3db3");

    println!("\nExpected KAT values:");
    println!("  seed_dk: {:02x?}", expected_seed_dk);
    println!("  seed_ek: {:02x?}", expected_seed_ek);

    println!("\nKAT comparison:");
    println!(
        "  seed_dk match: {}",
        output1 == expected_seed_dk.as_slice()
    );
    println!(
        "  seed_ek match: {}",
        output2 == expected_seed_ek.as_slice()
    );
}

#[cfg(feature = "aes-drbg")]
#[test]
fn test_reference_behavior_simulation() {
    println!("=== Reference Behavior Simulation ===");

    // Simulate the exact reference behavior
    let kat_seed = hex_to_bytes(
        "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1",
    );
    let kat_seed_array: [u8; 48] = kat_seed.try_into().unwrap();

    println!("Simulating reference randombytes() behavior:");

    // Step 1: Initialize (equivalent to randombytes_init)
    let mut rng = Aes256CtrDrbg::instantiate(&kat_seed_array);

    // Step 2: Generate first 32 bytes (equivalent to first randombytes call)
    println!("\nStep 1: Generate first 32 bytes (seed_dk)");
    let mut seed_dk = [0u8; 32];
    rng.fill_bytes(&mut seed_dk);
    println!("  Generated: {:02x?}", seed_dk);

    // Expected seed_dk
    let expected_seed_dk =
        hex_to_bytes("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d");
    println!("  Expected:  {:02x?}", expected_seed_dk);
    println!("  Match: {}", seed_dk == expected_seed_dk.as_slice());

    // Step 3: Generate second 32 bytes (equivalent to second randombytes call)
    println!("\nStep 2: Generate second 32 bytes (seed_ek)");
    let mut seed_ek = [0u8; 32];
    rng.fill_bytes(&mut seed_ek);
    println!("  Generated: {:02x?}", seed_ek);

    // Expected seed_ek
    let expected_seed_ek =
        hex_to_bytes("74b2d352cf74c934069c9de74757f50566fe46f7e122243c90c30adebb0e3db3");
    println!("  Expected:  {:02x?}", expected_seed_ek);
    println!("  Match: {}", seed_ek == expected_seed_ek.as_slice());

    // Analysis
    if seed_dk == expected_seed_dk.as_slice() && seed_ek == expected_seed_ek.as_slice() {
        println!("\n✅ Perfect match with reference behavior!");
    } else {
        println!("\n❌ Divergence from reference behavior");
        if seed_dk != expected_seed_dk.as_slice() {
            println!("  seed_dk generation is incorrect");
        }
        if seed_ek != expected_seed_ek.as_slice() {
            println!("  seed_ek generation is incorrect");
        }
    }
}

#[cfg(feature = "aes-drbg")]
#[test]
fn test_counter_increment_behavior() {
    println!("=== Counter Increment Behavior Test ===");

    // Test the counter increment behavior to ensure it matches reference
    let mut v = [0u8; 16];

    println!("Testing counter increment (rightmost byte first):");

    // Test basic increment
    v[15] = 0x00;
    Aes256CtrDrbg::increment_counter(&mut v);
    println!("  0x00 -> {:02x?}", v);
    assert_eq!(v[15], 0x01);

    // Test overflow
    v[15] = 0xFF;
    Aes256CtrDrbg::increment_counter(&mut v);
    println!("  0xFF -> {:02x?}", v);
    assert_eq!(v[15], 0x00);
    assert_eq!(v[14], 0x01);

    // Test multiple overflow
    v = [0xFFu8; 16];
    Aes256CtrDrbg::increment_counter(&mut v);
    println!("  All 0xFF -> {:02x?}", v);
    assert_eq!(v, [0u8; 16]);

    println!("✅ Counter increment behavior is correct");
}

#[cfg(not(feature = "aes-drbg"))]
#[test]
fn test_feature_disabled() {
    println!("=== AES-CTR-DRBG Feature Disabled Test ===");
    println!("✅ Feature disabled test passed - aes-drbg feature is not enabled");
}
