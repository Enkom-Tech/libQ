//! AES Implementation Verification
//!
//! This module verifies our AES-256-ECB implementation against known test vectors
//! to identify any differences from OpenSSL's implementation.

#[cfg(feature = "aes-drbg")]
use lib_q_hqc::aes_ctr_drbg::Aes256CtrDrbg;

/// Helper function to print hex with label
#[allow(dead_code)]
fn print_hex(label: &str, data: &[u8]) {
    println!("{}: {:02x?}", label, data);
}

#[cfg(feature = "aes-drbg")]
#[test]
fn test_aes_known_vectors() {
    println!("=== AES-256-ECB Known Test Vectors ===");

    // Test Vector 1: All zeros
    let key1 = [0u8; 32];
    let input1 = [0u8; 16];
    let output1 = Aes256CtrDrbg::aes256_ecb(&key1, &input1);
    print_hex("AES(zeros, zeros)", &output1);

    // Expected output for all zeros (from NIST test vectors)
    // Note: This is a placeholder - we need to verify with actual NIST vectors
    let expected1 = [
        0xDC, 0x95, 0xC0, 0x78, 0xA2, 0x40, 0x89, 0x89, 0xAD, 0x48, 0xA2, 0x14, 0x92, 0x84, 0x20,
        0x87,
    ];
    println!("Expected: {:02x?}", expected1);
    println!("Matches: {}", output1 == expected1);

    // Test Vector 2: Simple pattern
    let key2 = [0x01u8; 32];
    let input2 = [0x02u8; 16];
    let output2 = Aes256CtrDrbg::aes256_ecb(&key2, &input2);
    print_hex("AES(0x01, 0x02)", &output2);

    // Test Vector 3: Different pattern
    let key3 = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F,
    ];
    let input3 = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];
    let output3 = Aes256CtrDrbg::aes256_ecb(&key3, &input3);
    print_hex("AES(pattern, pattern)", &output3);

    // Expected output for this test vector
    let expected3 = [
        0x8E, 0xA2, 0xB7, 0xCA, 0x51, 0x67, 0x45, 0xBF, 0xEA, 0xFC, 0x49, 0x90, 0x4B, 0x49, 0x60,
        0x89,
    ];
    println!("Expected: {:02x?}", expected3);
    println!("Matches: {}", output3 == expected3);
}

#[cfg(feature = "aes-drbg")]
#[test]
fn test_drbg_aes_sequence() {
    println!("=== DRBG AES Sequence Test ===");

    // Test the exact sequence that would be used in DRBG
    let key = [
        0x7C, 0x99, 0x35, 0xA0, 0xB0, 0x76, 0x94, 0xAA, 0x0C, 0x6D, 0x10, 0xE4, 0xDB, 0x6B, 0x1A,
        0xDD, 0x2F, 0xD8, 0x1A, 0x25, 0xCC, 0xB1, 0x48, 0x03, 0x2D, 0xCD, 0x73, 0x99, 0x36, 0x73,
        0x7F, 0x2D,
    ];

    // This is the key that would be used after generating seed_dk
    print_hex("DRBG Key (after seed_dk)", &key);

    // Test with different counter values
    let mut counter = [0u8; 16];

    // First block (would generate first 16 bytes of seed_ek)
    let output1 = Aes256CtrDrbg::aes256_ecb(&key, &counter);
    print_hex("AES(Key, Counter=0)", &output1);

    // Increment counter
    Aes256CtrDrbg::increment_counter(&mut counter);
    let output2 = Aes256CtrDrbg::aes256_ecb(&key, &counter);
    print_hex("AES(Key, Counter=1)", &output2);

    // This should give us the first 32 bytes of seed_ek
    let mut seed_ek_first_32 = [0u8; 32];
    seed_ek_first_32[0..16].copy_from_slice(&output1);
    seed_ek_first_32[16..32].copy_from_slice(&output2);

    print_hex("First 32 bytes of seed_ek", &seed_ek_first_32);

    // Expected first 32 bytes of seed_ek
    let expected_seed_ek = [
        0x74, 0xB2, 0xD3, 0x52, 0xCF, 0x74, 0xC9, 0x34, 0x06, 0x9C, 0x9D, 0xE7, 0x47, 0x57, 0xF5,
        0x05, 0x66, 0xFE, 0x46, 0xF7, 0xE1, 0x22, 0x24, 0x3C, 0x90, 0xC3, 0x0A, 0xDE, 0xBB, 0x0E,
        0x3D, 0xB3,
    ];

    println!("Expected seed_ek: {:02x?}", expected_seed_ek);
    println!(
        "First 32 bytes match: {}",
        seed_ek_first_32 == expected_seed_ek
    );

    // The issue might be that we're not using the correct counter value
    // Let's check what counter value we should be using
    println!("\n=== Counter Analysis ===");
    println!("The issue might be in the counter value used for seed_ek generation");
    println!("We need to determine what counter value the reference uses");
}

#[cfg(feature = "aes-drbg")]
#[test]
fn test_counter_sequence() {
    println!("=== Counter Sequence Analysis ===");

    // Let's trace the exact counter sequence that should happen
    let mut counter = [0u8; 16];

    println!("Initial counter: {:02x?}", counter);

    // Simulate the counter increments that would happen during seed_dk generation
    // seed_dk is 32 bytes = 2 blocks, so counter should increment twice
    Aes256CtrDrbg::increment_counter(&mut counter);
    println!("After first increment: {:02x?}", counter);

    Aes256CtrDrbg::increment_counter(&mut counter);
    println!("After second increment: {:02x?}", counter);

    // Now this should be the counter value used for seed_ek generation
    println!("Counter value for seed_ek generation: {:02x?}", counter);

    // Test AES with this counter value
    let key = [
        0x7C, 0x99, 0x35, 0xA0, 0xB0, 0x76, 0x94, 0xAA, 0x0C, 0x6D, 0x10, 0xE4, 0xDB, 0x6B, 0x1A,
        0xDD, 0x2F, 0xD8, 0x1A, 0x25, 0xCC, 0xB1, 0x48, 0x03, 0x2D, 0xCD, 0x73, 0x99, 0x36, 0x73,
        0x7F, 0x2D,
    ];

    let output1 = Aes256CtrDrbg::aes256_ecb(&key, &counter);
    print_hex("AES(Key, Counter for seed_ek)", &output1);

    Aes256CtrDrbg::increment_counter(&mut counter);
    let output2 = Aes256CtrDrbg::aes256_ecb(&key, &counter);
    print_hex("AES(Key, Counter+1 for seed_ek)", &output2);

    // Combine the outputs
    let mut seed_ek = [0u8; 32];
    seed_ek[0..16].copy_from_slice(&output1);
    seed_ek[16..32].copy_from_slice(&output2);

    print_hex("Generated seed_ek", &seed_ek);

    // Expected seed_ek
    let expected_seed_ek = [
        0x74, 0xB2, 0xD3, 0x52, 0xCF, 0x74, 0xC9, 0x34, 0x06, 0x9C, 0x9D, 0xE7, 0x47, 0x57, 0xF5,
        0x05, 0x66, 0xFE, 0x46, 0xF7, 0xE1, 0x22, 0x24, 0x3C, 0x90, 0xC3, 0x0A, 0xDE, 0xBB, 0x0E,
        0x3D, 0xB3,
    ];

    println!("Expected seed_ek: {:02x?}", expected_seed_ek);
    println!("Matches: {}", seed_ek == expected_seed_ek);
}
