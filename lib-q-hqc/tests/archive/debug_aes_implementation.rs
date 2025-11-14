//! Debug AES Implementation for KAT Compatibility
//!
//! This module contains tests to debug our AES-256-ECB implementation
//! and compare it with the reference OpenSSL implementation.

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
fn test_aes_ecb_known_vectors() {
    println!("=== AES-256-ECB Known Test Vectors ===");

    // Test with known AES-256-ECB test vectors
    // These are from NIST AES test vectors

    // Test vector 1: All zeros
    let key1 = [0u8; 32];
    let input1 = [0u8; 16];
    let expected1 = hex_to_bytes("dc95c078a2408989ad48a21492842087");

    let result1 = Aes256CtrDrbg::aes256_ecb(&key1, &input1);
    println!("Test 1 - All zeros:");
    println!("  Key: {:02x?}", key1);
    println!("  Input: {:02x?}", input1);
    println!("  Expected: {:02x?}", expected1);
    println!("  Got: {:02x?}", result1);

    if result1 == expected1.as_slice() {
        println!("  ✅ PASS");
    } else {
        println!("  ❌ FAIL");
    }

    // Test vector 2: Known key and input
    let key2 = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let input2 = hex_to_bytes("00112233445566778899aabbccddeeff");
    let expected2 = hex_to_bytes("8ea2b7ca516745bfeafc49904b496089");

    let result2 = Aes256CtrDrbg::aes256_ecb(
        &key2.clone().try_into().unwrap(),
        &input2.clone().try_into().unwrap(),
    );
    println!("Test 2 - Known vectors:");
    println!("  Key: {:02x?}", key2);
    println!("  Input: {:02x?}", input2);
    println!("  Expected: {:02x?}", expected2);
    println!("  Got: {:02x?}", result2);

    if result2 == expected2.as_slice() {
        println!("  ✅ PASS");
    } else {
        println!("  ❌ FAIL");
    }
}

#[cfg(feature = "aes-drbg")]
#[test]
fn test_ctr_drbg_step_by_step() {
    println!("=== CTR-DRBG Step-by-Step Debug ===");

    // Use the same entropy input as the reference implementation
    let mut entropy = [0u8; 48];
    for (i, byte) in entropy.iter_mut().enumerate() {
        *byte = i as u8;
    }

    println!("Entropy input: {:02x?}", entropy);

    // Step 1: Initial state
    let mut key = [0u8; 32];
    let mut v = [0u8; 16];

    println!("Initial state:");
    println!("  Key: {:02x?}", key);
    println!("  V: {:02x?}", v);

    // Step 2: First CTR_DRBG_Update
    println!("\nStep 2: CTR_DRBG_Update with entropy");

    // Generate 3 blocks using AES-256-ECB
    let mut temp = [0u8; 48];

    for i in 0..3 {
        // Increment V
        Aes256CtrDrbg::increment_counter(&mut v);
        println!("  Block {} - V after increment: {:02x?}", i, v);

        // AES-256-ECB(Key, V) -> temp[i*16..(i+1)*16]
        let block = Aes256CtrDrbg::aes256_ecb(&key, &v);
        println!("  Block {} - AES output: {:02x?}", i, block);

        temp[i * 16..(i + 1) * 16].copy_from_slice(&block);
    }

    println!("  Temp before XOR: {:02x?}", temp);

    // XOR with provided_data
    for i in 0..48 {
        temp[i] ^= entropy[i];
    }

    println!("  Temp after XOR: {:02x?}", temp);

    // Update Key and V
    key.copy_from_slice(&temp[..32]);
    v.copy_from_slice(&temp[32..48]);

    println!("  New Key: {:02x?}", key);
    println!("  New V: {:02x?}", v);

    // Step 3: Generate first 32 bytes (seed_dk)
    println!("\nStep 3: Generate first 32 bytes (seed_dk)");

    let mut seed_dk = [0u8; 32];
    let mut offset = 0;

    while offset < 32 {
        // Increment V
        Aes256CtrDrbg::increment_counter(&mut v);
        println!("  Generate block {} - V: {:02x?}", offset / 16, v);

        // Generate block using AES-256-ECB
        let block = Aes256CtrDrbg::aes256_ecb(&key, &v);
        println!(
            "  Generate block {} - AES output: {:02x?}",
            offset / 16,
            block
        );

        // Copy to output
        let to_copy = core::cmp::min(16, 32 - offset);
        seed_dk[offset..offset + to_copy].copy_from_slice(&block[..to_copy]);
        offset += to_copy;
    }

    println!("  Generated seed_dk: {:02x?}", seed_dk);

    // Step 4: Generate next 32 bytes (seed_ek)
    println!("\nStep 4: Generate next 32 bytes (seed_ek)");

    let mut seed_ek = [0u8; 32];
    offset = 0;

    while offset < 32 {
        // Increment V
        Aes256CtrDrbg::increment_counter(&mut v);
        println!("  Generate block {} - V: {:02x?}", (offset + 32) / 16, v);

        // Generate block using AES-256-ECB
        let block = Aes256CtrDrbg::aes256_ecb(&key, &v);
        println!(
            "  Generate block {} - AES output: {:02x?}",
            (offset + 32) / 16,
            block
        );

        // Copy to output
        let to_copy = core::cmp::min(16, 32 - offset);
        seed_ek[offset..offset + to_copy].copy_from_slice(&block[..to_copy]);
        offset += to_copy;
    }

    println!("  Generated seed_ek: {:02x?}", seed_ek);

    // Expected values from KAT
    let expected_seed_dk =
        hex_to_bytes("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d");
    let expected_seed_ek =
        hex_to_bytes("74b2d352cf74c934069c9de74757f50566fe46f7e122243c90c30adebb0e3db3");

    println!("\nComparison with expected KAT values:");
    println!("  Expected seed_dk: {:02x?}", expected_seed_dk);
    println!("  Our seed_dk:      {:02x?}", seed_dk);
    println!("  Match: {}", seed_dk == expected_seed_dk.as_slice());

    println!("  Expected seed_ek: {:02x?}", expected_seed_ek);
    println!("  Our seed_ek:      {:02x?}", seed_ek);
    println!("  Match: {}", seed_ek == expected_seed_ek.as_slice());
}

#[cfg(feature = "aes-drbg")]
#[test]
fn test_reference_entropy_sequence() {
    println!("=== Reference Entropy Sequence Test ===");

    // This is the exact entropy sequence used by the reference implementation
    let mut entropy = [0u8; 48];
    for (i, byte) in entropy.iter_mut().enumerate() {
        *byte = i as u8;
    }

    println!("Reference entropy: {:02x?}", entropy);

    let mut rng = Aes256CtrDrbg::instantiate(&entropy);

    // Generate the first 64 bytes (seed_dk + seed_ek)
    let mut output = [0u8; 64];
    rng.fill_bytes(&mut output);

    println!("Generated output: {:02x?}", output);

    // Expected output from reference implementation
    // This should match the reference's randombytes() output
    let expected_output = hex_to_bytes(
        "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d74b2d352cf74c934069c9de74757f50566fe46f7e122243c90c30adebb0e3db3",
    );

    println!("Expected output: {:02x?}", expected_output);

    if output == expected_output.as_slice() {
        println!("✅ Output matches reference exactly!");
    } else {
        println!("❌ Output differs from reference");

        // Find differences
        for i in 0..output.len() {
            if output[i] != expected_output[i] {
                println!(
                    "  Diff at byte {}: got={:02x}, expected={:02x}",
                    i, output[i], expected_output[i]
                );
            }
        }
    }
}

#[cfg(feature = "aes-drbg")]
#[test]
fn test_counter_increment_behavior() {
    println!("=== Counter Increment Behavior Test ===");

    // Test counter increment with known values
    let mut v = [0u8; 16];

    println!("Testing counter increment:");

    for i in 0..10 {
        println!("  Step {}: V = {:02x?}", i, v);
        Aes256CtrDrbg::increment_counter(&mut v);
    }

    // Test overflow behavior
    println!("\nTesting overflow behavior:");
    v = [0xFFu8; 16]; // All 0xff
    println!("  Before overflow: V = {:02x?}", v);
    Aes256CtrDrbg::increment_counter(&mut v);
    println!("  After overflow:  V = {:02x?}", v);

    // Test specific overflow case
    v = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF,
    ];
    println!("  Before single overflow: V = {:02x?}", v);
    Aes256CtrDrbg::increment_counter(&mut v);
    println!("  After single overflow:  V = {:02x?}", v);
}

#[cfg(not(feature = "aes-drbg"))]
#[test]
fn test_feature_disabled() {
    println!("=== AES-CTR-DRBG Feature Disabled Test ===");
    println!("✅ Feature disabled test passed - aes-drbg feature is not enabled");
}
