//! Debug AES Implementation in Detail
//!
//! This module debugs our AES implementation to understand why it produces different results.

#[cfg(feature = "aes-drbg")]
use lib_q_hqc::aes_ctr_drbg::Aes256CtrDrbg;
#[cfg(feature = "aes-drbg")]
use rand_core::RngCore;

/// Helper function to print hex with label
fn print_hex(label: &str, data: &[u8]) {
    println!("{}: {:02x?}", label, data);
}

#[cfg(feature = "aes-drbg")]
#[test]
fn test_aes_with_drbg_values() {
    println!("=== AES Test with DRBG Values ===");

    // Test with the exact key and counter values that would be used in the DRBG
    let key = [
        0x7C, 0x99, 0x35, 0xA0, 0xB0, 0x76, 0x94, 0xAA, 0x0C, 0x6D, 0x10, 0xE4, 0xDB, 0x6B, 0x1A,
        0xDD, 0x2F, 0xD8, 0x1A, 0x25, 0xCC, 0xB1, 0x48, 0x03, 0x2D, 0xCD, 0x73, 0x99, 0x36, 0x73,
        0x7F, 0x2D,
    ];

    let counter = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02,
    ];

    print_hex("Key", &key);
    print_hex("Counter", &counter);

    let output = Aes256CtrDrbg::aes256_ecb(&key, &counter);
    print_hex("AES Output", &output);

    // Expected first block of seed_ek
    let expected_first_block = [
        0x74, 0xB2, 0xD3, 0x52, 0xCF, 0x74, 0xC9, 0x34, 0x06, 0x9C, 0x9D, 0xE7, 0x47, 0x57, 0xF5,
        0x05,
    ];

    print_hex("Expected first block", &expected_first_block);
    println!("First block matches: {}", output == expected_first_block);

    // Test with counter + 1
    let mut counter_plus_1 = counter;
    Aes256CtrDrbg::increment_counter(&mut counter_plus_1);
    print_hex("Counter + 1", &counter_plus_1);

    let output2 = Aes256CtrDrbg::aes256_ecb(&key, &counter_plus_1);
    print_hex("AES Output (counter + 1)", &output2);

    // Expected second block of seed_ek
    let expected_second_block = [
        0x66, 0xFE, 0x46, 0xF7, 0xE1, 0x22, 0x24, 0x3C, 0x90, 0xC3, 0x0A, 0xDE, 0xBB, 0x0E, 0x3D,
        0xB3,
    ];

    print_hex("Expected second block", &expected_second_block);
    println!("Second block matches: {}", output2 == expected_second_block);

    // The issue is clear: our AES implementation produces different output
    // than what's expected for the same key and counter values
    println!("\n=== Analysis ===");
    println!("Our AES implementation produces different output than expected");
    println!("This suggests that either:");
    println!("1. The key or counter values we're using are incorrect");
    println!("2. Our AES implementation differs from OpenSSL");
    println!("3. There's an endianness or byte order issue");
}

#[cfg(feature = "aes-drbg")]
#[test]
fn test_aes_with_simple_values() {
    println!("=== AES Test with Simple Values ===");

    // Test with simple values to verify our AES implementation
    let key = [0x01u8; 32];
    let input = [0x02u8; 16];

    let output = Aes256CtrDrbg::aes256_ecb(&key, &input);
    print_hex("AES(0x01, 0x02)", &output);

    // Test with zeros
    let key_zeros = [0u8; 32];
    let input_zeros = [0u8; 16];

    let output_zeros = Aes256CtrDrbg::aes256_ecb(&key_zeros, &input_zeros);
    print_hex("AES(zeros, zeros)", &output_zeros);

    // Test with a known pattern
    let key_pattern = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F,
    ];
    let input_pattern = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];

    let output_pattern = Aes256CtrDrbg::aes256_ecb(&key_pattern, &input_pattern);
    print_hex("AES(pattern, pattern)", &output_pattern);

    // Expected output for the pattern test
    let expected_pattern = [
        0x8E, 0xA2, 0xB7, 0xCA, 0x51, 0x67, 0x45, 0xBF, 0xEA, 0xFC, 0x49, 0x90, 0x4B, 0x49, 0x60,
        0x89,
    ];

    print_hex("Expected pattern", &expected_pattern);
    println!("Pattern matches: {}", output_pattern == expected_pattern);
}

#[cfg(feature = "aes-drbg")]
#[test]
fn test_drbg_key_derivation() {
    println!("=== DRBG Key Derivation Test ===");

    // Let's trace how the DRBG key is derived
    // The key should be derived from the KAT seed through the DRBG initialization

    let kat_seed = [
        0x06, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE, 0x04, 0xEF, 0x7A,
        0x25, 0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79, 0xD0, 0x9D, 0x86, 0xDC, 0x9A, 0xBC,
        0xFD, 0xE7, 0x05, 0x6A, 0x8C, 0x26, 0x6F, 0x9E, 0xF9, 0x7E, 0xD0, 0x85, 0x41, 0xDB, 0xD2,
        0xE1, 0xFF, 0xA1,
    ];

    print_hex("KAT seed", &kat_seed);

    // Initialize DRBG with KAT seed
    let mut rng = Aes256CtrDrbg::instantiate(&kat_seed);

    // Generate seed_dk
    let mut seed_dk = [0u8; 32];
    rng.fill_bytes(&mut seed_dk);

    print_hex("Generated seed_dk", &seed_dk);

    // The key insight: after generating seed_dk, the DRBG state should be updated
    // The key that would be used for seed_ek generation should be the updated key
    // from the DRBG state, not the original key

    // Let's see what happens if we generate seed_ek
    let mut seed_ek = [0u8; 32];
    rng.fill_bytes(&mut seed_ek);

    print_hex("Generated seed_ek", &seed_ek);

    // Expected seed_ek
    let expected_seed_ek = [
        0x74, 0xB2, 0xD3, 0x52, 0xCF, 0x74, 0xC9, 0x34, 0x06, 0x9C, 0x9D, 0xE7, 0x47, 0x57, 0xF5,
        0x05, 0x66, 0xFE, 0x46, 0xF7, 0xE1, 0x22, 0x24, 0x3C, 0x90, 0xC3, 0x0A, 0xDE, 0xBB, 0x0E,
        0x3D, 0xB3,
    ];

    println!("seed_ek matches expected: {}", seed_ek == expected_seed_ek);

    // The issue is that our DRBG state management is not producing
    // the same result as the reference implementation
    // This suggests that the problem is in our CTR_DRBG_Update implementation
    // or in how we manage the DRBG state between calls
}
