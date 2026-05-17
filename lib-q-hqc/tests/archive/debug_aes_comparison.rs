//! Debug AES Comparison
//!
//! This module compares our AES-256-ECB implementation with known test vectors
//! to identify any differences from the reference OpenSSL implementation.

#[cfg(feature = "aes-drbg")]
use lib_q_hqc::aes_ctr_drbg::Aes256CtrDrbg;

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

    // Test vector 3: Another known vector
    let key3 = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7158809cf4f3c");
    let input3 = hex_to_bytes("3243f6a8885a308d313198a2e0370734");
    let expected3 = hex_to_bytes("3925841d02dc09fbd1185ff7953a0a43");

    let result3 = Aes256CtrDrbg::aes256_ecb(
        &key3.clone().try_into().unwrap(),
        &input3.clone().try_into().unwrap(),
    );
    println!("Test 3 - Another known vector:");
    println!("  Key: {:02x?}", key3);
    println!("  Input: {:02x?}", input3);
    println!("  Expected: {:02x?}", expected3);
    println!("  Got: {:02x?}", result3);

    if result3 == expected3.as_slice() {
        println!("  ✅ PASS");
    } else {
        println!("  ❌ FAIL");
    }

    // Assertions
    assert_eq!(result1, expected1.as_slice(), "Test vector 1 must pass");
    assert_eq!(result2, expected2.as_slice(), "Test vector 2 must pass");
    assert_eq!(result3, expected3.as_slice(), "Test vector 3 must pass");
}

#[cfg(feature = "aes-drbg")]
#[test]
fn test_aes_ecb_with_kat_seed() {
    println!("=== AES-256-ECB with KAT Seed ===");

    // Use the KAT seed as input to see what our AES produces
    let kat_seed = hex_to_bytes(
        "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1",
    );
    let kat_seed_array: [u8; 48] = kat_seed.try_into().unwrap();

    // Split into key (first 32 bytes) and input (last 16 bytes)
    let key = &kat_seed_array[0..32];
    let input = &kat_seed_array[32..48];

    println!("KAT seed: {:02x?}", kat_seed_array);
    println!("Key (first 32 bytes): {:02x?}", key);
    println!("Input (last 16 bytes): {:02x?}", input);

    let result = Aes256CtrDrbg::aes256_ecb(&key.try_into().unwrap(), &input.try_into().unwrap());

    println!("AES-256-ECB result: {:02x?}", result);

    // This is just for debugging - we don't have expected values for this
    println!("✅ AES-256-ECB computation completed");
}

#[cfg(not(feature = "aes-drbg"))]
#[test]
fn test_feature_disabled() {
    println!("=== AES-CTR-DRBG Feature Disabled Test ===");
    println!("✅ Feature disabled test passed - aes-drbg feature is not enabled");
}
