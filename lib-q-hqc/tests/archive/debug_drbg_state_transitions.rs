//! Debug DRBG State Transitions
//!
//! This module focuses on debugging the exact state transitions in our AES-CTR-DRBG
//! to understand why seed_ek generation differs from the reference.

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
fn test_drbg_state_transitions() {
    println!("=== DRBG State Transition Analysis ===");

    // Use the KAT seed directly
    let kat_seed_kem = hex_to_bytes(
        "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1",
    );
    let kat_seed_array: [u8; 48] = kat_seed_kem.try_into().unwrap();

    println!("KAT seed: {:02x?}", kat_seed_array);

    // Expected values
    let expected_seed_dk =
        hex_to_bytes("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d");
    let expected_seed_ek =
        hex_to_bytes("74b2d352cf74c934069c9de74757f50566fe46f7e122243c90c30adebb0e3db3");

    println!("Expected seed_dk: {:02x?}", expected_seed_dk);
    println!("Expected seed_ek: {:02x?}", expected_seed_ek);

    // Test 1: Generate 64 bytes in one call
    println!("\n=== Test 1: Generate 64 bytes in one call ===");
    let mut rng1 = Aes256CtrDrbg::instantiate(&kat_seed_array);
    let mut output_64 = [0u8; 64];
    rng1.fill_bytes(&mut output_64);

    println!("Generated 64 bytes:");
    println!("  Bytes 0-31:  {:02x?}", &output_64[0..32]);
    println!("  Bytes 32-63: {:02x?}", &output_64[32..64]);

    let seed_dk_match = &output_64[0..32] == expected_seed_dk.as_slice();
    let seed_ek_match = &output_64[32..64] == expected_seed_ek.as_slice();

    println!("seed_dk match: {}", seed_dk_match);
    println!("seed_ek match: {}", seed_ek_match);

    // Test 2: Generate 32 bytes, then another 32 bytes
    println!("\n=== Test 2: Generate 32 bytes, then another 32 bytes ===");
    let mut rng2 = Aes256CtrDrbg::instantiate(&kat_seed_array);
    let mut seed_dk = [0u8; 32];
    let mut seed_ek = [0u8; 32];

    rng2.fill_bytes(&mut seed_dk);
    rng2.fill_bytes(&mut seed_ek);

    println!("Generated seed_dk: {:02x?}", seed_dk);
    println!("Generated seed_ek: {:02x?}", seed_ek);

    let seed_dk_match2 = seed_dk == expected_seed_dk.as_slice();
    let seed_ek_match2 = seed_ek == expected_seed_ek.as_slice();

    println!("seed_dk match: {}", seed_dk_match2);
    println!("seed_ek match: {}", seed_ek_match2);

    // Test 3: Generate 16 bytes at a time
    println!("\n=== Test 3: Generate 16 bytes at a time ===");
    let mut rng3 = Aes256CtrDrbg::instantiate(&kat_seed_array);
    let mut output_16x4 = [0u8; 64];

    for i in 0..4 {
        let start = i * 16;
        let end = start + 16;
        rng3.fill_bytes(&mut output_16x4[start..end]);
        println!("  Block {}: {:02x?}", i, &output_16x4[start..end]);
    }

    let seed_dk_match3 = &output_16x4[0..32] == expected_seed_dk.as_slice();
    let seed_ek_match3 = &output_16x4[32..64] == expected_seed_ek.as_slice();

    println!("seed_dk match: {}", seed_dk_match3);
    println!("seed_ek match: {}", seed_ek_match3);

    // Test 4: Generate 1 byte at a time
    println!("\n=== Test 4: Generate 1 byte at a time ===");
    let mut rng4 = Aes256CtrDrbg::instantiate(&kat_seed_array);
    let mut output_1x64 = [0u8; 64];

    for i in 0..64 {
        rng4.fill_bytes(&mut output_1x64[i..i + 1]);
    }

    let seed_dk_match4 = &output_1x64[0..32] == expected_seed_dk.as_slice();
    let seed_ek_match4 = &output_1x64[32..64] == expected_seed_ek.as_slice();

    println!("seed_dk match: {}", seed_dk_match4);
    println!("seed_ek match: {}", seed_ek_match4);

    // Summary
    println!("\n=== Summary ===");
    println!(
        "Test 1 (64 bytes): seed_dk={}, seed_ek={}",
        seed_dk_match, seed_ek_match
    );
    println!(
        "Test 2 (32+32):   seed_dk={}, seed_ek={}",
        seed_dk_match2, seed_ek_match2
    );
    println!(
        "Test 3 (16x4):    seed_dk={}, seed_ek={}",
        seed_dk_match3, seed_ek_match3
    );
    println!(
        "Test 4 (1x64):    seed_dk={}, seed_ek={}",
        seed_dk_match4, seed_ek_match4
    );

    // All tests should produce the same result
    assert_eq!(seed_dk_match, seed_dk_match2);
    assert_eq!(seed_dk_match2, seed_dk_match3);
    assert_eq!(seed_dk_match3, seed_dk_match4);

    assert_eq!(seed_ek_match, seed_ek_match2);
    assert_eq!(seed_ek_match2, seed_ek_match3);
    assert_eq!(seed_ek_match3, seed_ek_match4);
}

#[cfg(feature = "aes-drbg")]
#[test]
fn test_drbg_counter_behavior() {
    println!("=== DRBG Counter Behavior Analysis ===");

    // Use the KAT seed directly
    let kat_seed_kem = hex_to_bytes(
        "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1",
    );
    let kat_seed_array: [u8; 48] = kat_seed_kem.try_into().unwrap();

    // Expected values
    let expected_seed_dk =
        hex_to_bytes("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d");
    let expected_seed_ek =
        hex_to_bytes("74b2d352cf74c934069c9de74757f50566fe46f7e122243c90c30adebb0e3db3");

    // Let's manually trace through what should happen
    println!("Manual counter trace:");

    // Initialize DRBG
    let mut rng = Aes256CtrDrbg::instantiate(&kat_seed_array);

    // The initial state should be:
    // key = derived from seed_material via CTR_DRBG_Update
    // v = derived from seed_material via CTR_DRBG_Update
    // reseed_counter = 1

    println!("Initial state after instantiate:");
    println!("  reseed_counter should be: 1");

    // Generate first 32 bytes (seed_dk)
    let mut seed_dk = [0u8; 32];
    rng.fill_bytes(&mut seed_dk);

    println!("After generating seed_dk:");
    println!("  reseed_counter should be: 2");
    println!("  Generated: {:02x?}", seed_dk);
    println!("  Expected:  {:02x?}", expected_seed_dk);
    println!("  Match: {}", seed_dk == expected_seed_dk.as_slice());

    // Generate second 32 bytes (seed_ek)
    let mut seed_ek = [0u8; 32];
    rng.fill_bytes(&mut seed_ek);

    println!("After generating seed_ek:");
    println!("  reseed_counter should be: 3");
    println!("  Generated: {:02x?}", seed_ek);
    println!("  Expected:  {:02x?}", expected_seed_ek);
    println!("  Match: {}", seed_ek == expected_seed_ek.as_slice());
}

#[cfg(not(feature = "aes-drbg"))]
#[test]
fn test_feature_disabled() {
    println!("=== AES-CTR-DRBG Feature Disabled Test ===");
    println!("✅ Feature disabled test passed - aes-drbg feature is not enabled");
}
