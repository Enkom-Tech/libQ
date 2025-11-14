//! Debug DRBG Exact Flow
//!
//! This module debugs the exact flow of the DRBG to understand where the discrepancy occurs.

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
fn test_exact_reference_flow() {
    println!("=== Exact Reference Flow Debug ===");

    // Step 1: Initialize entropy_input with [0, 1, 2, ..., 47]
    let mut entropy_input = [0u8; 48];
    for (i, byte) in entropy_input.iter_mut().enumerate() {
        *byte = i as u8;
    }
    print_hex("Entropy input", &entropy_input);

    // Step 2: Initialize DRBG with entropy (randombytes_init)
    let mut rng1 = Aes256CtrDrbg::instantiate(&entropy_input);
    println!("DRBG initialized with entropy");

    // Step 3: Generate KAT seed (randombytes(seed, 48))
    let mut kat_seed = [0u8; 48];
    rng1.fill_bytes(&mut kat_seed);
    print_hex("Generated KAT seed", &kat_seed);

    // Expected KAT seed
    let expected_kat_seed = [
        0x06, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE, 0x04, 0xEF, 0x7A,
        0x25, 0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79, 0xD0, 0x9D, 0x86, 0xDC, 0x9A, 0xBC,
        0xFD, 0xE7, 0x05, 0x6A, 0x8C, 0x26, 0x6F, 0x9E, 0xF9, 0x7E, 0xD0, 0x85, 0x41, 0xDB, 0xD2,
        0xE1, 0xFF, 0xA1,
    ];

    println!("KAT seed matches: {}", kat_seed == expected_kat_seed);

    // Step 4: Re-initialize DRBG with KAT seed (randombytes_init(seed, NULL, 256))
    let mut rng2 = Aes256CtrDrbg::instantiate(&kat_seed);
    println!("DRBG re-initialized with KAT seed");

    // Step 5: Generate seed_dk (randombytes(seed_dk, 32))
    let mut seed_dk = [0u8; 32];
    rng2.fill_bytes(&mut seed_dk);
    print_hex("Generated seed_dk", &seed_dk);

    // Expected seed_dk
    let expected_seed_dk = [
        0x7C, 0x99, 0x35, 0xA0, 0xB0, 0x76, 0x94, 0xAA, 0x0C, 0x6D, 0x10, 0xE4, 0xDB, 0x6B, 0x1A,
        0xDD, 0x2F, 0xD8, 0x1A, 0x25, 0xCC, 0xB1, 0x48, 0x03, 0x2D, 0xCD, 0x73, 0x99, 0x36, 0x73,
        0x7F, 0x2D,
    ];

    println!("seed_dk matches: {}", seed_dk == expected_seed_dk);

    // Step 6: Generate seed_ek (randombytes(seed_ek, 32))
    let mut seed_ek = [0u8; 32];
    rng2.fill_bytes(&mut seed_ek);
    print_hex("Generated seed_ek", &seed_ek);

    // Expected seed_ek
    let expected_seed_ek = [
        0x74, 0xB2, 0xD3, 0x52, 0xCF, 0x74, 0xC9, 0x34, 0x06, 0x9C, 0x9D, 0xE7, 0x47, 0x57, 0xF5,
        0x05, 0x66, 0xFE, 0x46, 0xF7, 0xE1, 0x22, 0x24, 0x3C, 0x90, 0xC3, 0x0A, 0xDE, 0xBB, 0x0E,
        0x3D, 0xB3,
    ];

    println!("seed_ek matches: {}", seed_ek == expected_seed_ek);

    // Now let's analyze what might be different
    println!("\n=== Analysis ===");
    println!("The issue is that seed_ek doesn't match the expected value");
    println!("This suggests that either:");
    println!("1. Our AES implementation differs from OpenSSL");
    println!("2. Our DRBG state management differs from the reference");
    println!("3. There's a subtle difference in the counter handling");

    // Let's check if the issue is in the AES implementation by testing with the exact values
    // that would be used in the DRBG
    println!("\n=== AES Implementation Test ===");

    // The key that should be used after generating seed_dk
    let drbg_key = [
        0x7C, 0x99, 0x35, 0xA0, 0xB0, 0x76, 0x94, 0xAA, 0x0C, 0x6D, 0x10, 0xE4, 0xDB, 0x6B, 0x1A,
        0xDD, 0x2F, 0xD8, 0x1A, 0x25, 0xCC, 0xB1, 0x48, 0x03, 0x2D, 0xCD, 0x73, 0x99, 0x36, 0x73,
        0x7F, 0x2D,
    ];

    // The counter that should be used for seed_ek generation
    // After generating seed_dk (32 bytes = 2 blocks), the counter should be incremented twice
    let mut counter = [0u8; 16];
    Aes256CtrDrbg::increment_counter(&mut counter); // First block of seed_dk
    Aes256CtrDrbg::increment_counter(&mut counter); // Second block of seed_dk

    print_hex("DRBG Key (after seed_dk)", &drbg_key);
    print_hex("Counter (after seed_dk)", &counter);

    // Generate the first block of seed_ek
    let block1 = Aes256CtrDrbg::aes256_ecb(&drbg_key, &counter);
    print_hex("First block of seed_ek", &block1);

    // Increment counter for second block
    Aes256CtrDrbg::increment_counter(&mut counter);
    let block2 = Aes256CtrDrbg::aes256_ecb(&drbg_key, &counter);
    print_hex("Second block of seed_ek", &block2);

    // Combine the blocks
    let mut manual_seed_ek = [0u8; 32];
    manual_seed_ek[0..16].copy_from_slice(&block1);
    manual_seed_ek[16..32].copy_from_slice(&block2);

    print_hex("Manual seed_ek", &manual_seed_ek);
    print_hex("Expected seed_ek", &expected_seed_ek);

    println!(
        "Manual seed_ek matches expected: {}",
        manual_seed_ek == expected_seed_ek
    );
    println!(
        "Manual seed_ek matches DRBG output: {}",
        manual_seed_ek == seed_ek
    );

    // This test will help us understand if the issue is in the AES implementation
    // or in the DRBG state management
}

#[cfg(feature = "aes-drbg")]
#[test]
fn test_drbg_state_after_seed_dk() {
    println!("=== DRBG State After seed_dk Generation ===");

    // Initialize with KAT seed
    let kat_seed = [
        0x06, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE, 0x04, 0xEF, 0x7A,
        0x25, 0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79, 0xD0, 0x9D, 0x86, 0xDC, 0x9A, 0xBC,
        0xFD, 0xE7, 0x05, 0x6A, 0x8C, 0x26, 0x6F, 0x9E, 0xF9, 0x7E, 0xD0, 0x85, 0x41, 0xDB, 0xD2,
        0xE1, 0xFF, 0xA1,
    ];

    let mut rng = Aes256CtrDrbg::instantiate(&kat_seed);

    // Generate seed_dk
    let mut seed_dk = [0u8; 32];
    rng.fill_bytes(&mut seed_dk);

    print_hex("Generated seed_dk", &seed_dk);

    // Now, what should the DRBG state be after generating seed_dk?
    // The reference implementation would have:
    // 1. Generated 32 bytes (2 blocks) for seed_dk
    // 2. Called CTR_DRBG_Update(NULL, Key, V)
    // 3. Incremented reseed_counter

    // The key insight is that the DRBG state (Key, V) should be updated
    // after generating seed_dk, and this updated state should be used
    // for generating seed_ek

    // Let's see what our implementation produces for seed_ek
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

    // The issue is clear: our DRBG state management is not producing
    // the same result as the reference implementation
}
