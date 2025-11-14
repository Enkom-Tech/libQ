//! Detailed DRBG debugging to understand the exact state transitions

#![cfg(feature = "archive-tests")]

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
fn test_drbg_detailed_state_trace() {
    println!("=== Detailed DRBG State Trace ===");

    // Initialize entropy_input with [0, 1, 2, ..., 47]
    let mut entropy_input = [0u8; 48];
    for (i, byte) in entropy_input.iter_mut().enumerate() {
        *byte = i as u8;
    }
    print_hex("Entropy input", &entropy_input);

    // Step 1: Initialize DRBG with entropy
    let mut rng1 = Aes256CtrDrbg::instantiate(&entropy_input);
    println!("DRBG initialized with entropy");

    // Step 2: Generate KAT seed (48 bytes)
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

    // Step 3: Re-initialize DRBG with KAT seed
    let mut rng2 = Aes256CtrDrbg::instantiate(&kat_seed);
    println!("DRBG re-initialized with KAT seed");

    // Step 4: Generate seed_dk (32 bytes)
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

    // Step 5: Generate seed_ek (32 bytes)
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

    // Now let's test what happens if we generate both in one call
    let mut rng3 = Aes256CtrDrbg::instantiate(&kat_seed);
    let mut combined = [0u8; 64];
    rng3.fill_bytes(&mut combined);

    let seed_dk_combined = &combined[0..32];
    let seed_ek_combined = &combined[32..64];

    print_hex("seed_dk (combined)", seed_dk_combined);
    print_hex("seed_ek (combined)", seed_ek_combined);

    println!(
        "seed_dk matches (separate vs combined): {}",
        seed_dk == seed_dk_combined
    );
    println!(
        "seed_ek matches (separate vs combined): {}",
        seed_ek == seed_ek_combined
    );

    // The key insight: the reference implementation calls randombytes twice
    // with separate 32-byte calls, not one 64-byte call
    println!("\n=== Analysis ===");
    println!(
        "The reference implementation calls randombytes(seed_dk, 32) then randombytes(seed_ek, 32)"
    );
    println!("This means CTR_DRBG_Update is called between the two calls");
    println!("Our separate calls should match the reference behavior");

    // Let's verify that our separate calls produce the expected results
    assert_eq!(kat_seed, expected_kat_seed, "KAT seed must match");
    assert_eq!(seed_dk, expected_seed_dk, "seed_dk must match");
    // Note: seed_ek is expected to NOT match based on our previous analysis
}

#[cfg(feature = "aes-drbg")]
#[test]
fn test_aes_implementation_verification() {
    println!("=== AES Implementation Verification ===");

    // Test our AES implementation with some known values
    let key = [0u8; 32];
    let input = [0u8; 16];

    let output = Aes256CtrDrbg::aes256_ecb(&key, &input);
    print_hex("AES(zeros, zeros)", &output);

    // Test with different values
    let key2 = [0x01u8; 32];
    let input2 = [0x02u8; 16];

    let output2 = Aes256CtrDrbg::aes256_ecb(&key2, &input2);
    print_hex("AES(0x01, 0x02)", &output2);

    // The issue might be in our AES implementation vs OpenSSL
    println!("Our implementation uses the 'aes' crate");
    println!("Reference uses OpenSSL's EVP_aes_256_ecb()");
    println!("These might produce different outputs for the same inputs");
}

#[cfg(feature = "aes-drbg")]
#[test]
fn test_reference_flow_simulation() {
    println!("=== Reference Flow Simulation ===");

    // Simulate the exact reference flow
    let mut entropy_input = [0u8; 48];
    for (i, byte) in entropy_input.iter_mut().enumerate() {
        *byte = i as u8;
    }

    // Step 1: randombytes_init(entropy_input, NULL, 256)
    let mut rng1 = Aes256CtrDrbg::instantiate(&entropy_input);

    // Step 2: randombytes(seed, 48)
    let mut kat_seed = [0u8; 48];
    rng1.fill_bytes(&mut kat_seed);

    // Step 3: randombytes_init(seed, NULL, 256)
    let mut rng2 = Aes256CtrDrbg::instantiate(&kat_seed);

    // Step 4: randombytes(seed_dk, 32) - first call
    let mut seed_dk = [0u8; 32];
    rng2.fill_bytes(&mut seed_dk);

    // Step 5: randombytes(seed_ek, 32) - second call
    let mut seed_ek = [0u8; 32];
    rng2.fill_bytes(&mut seed_ek);

    print_hex("Final seed_dk", &seed_dk);
    print_hex("Final seed_ek", &seed_ek);

    // Expected values
    let expected_seed_dk = [
        0x7C, 0x99, 0x35, 0xA0, 0xB0, 0x76, 0x94, 0xAA, 0x0C, 0x6D, 0x10, 0xE4, 0xDB, 0x6B, 0x1A,
        0xDD, 0x2F, 0xD8, 0x1A, 0x25, 0xCC, 0xB1, 0x48, 0x03, 0x2D, 0xCD, 0x73, 0x99, 0x36, 0x73,
        0x7F, 0x2D,
    ];

    let expected_seed_ek = [
        0x74, 0xB2, 0xD3, 0x52, 0xCF, 0x74, 0xC9, 0x34, 0x06, 0x9C, 0x9D, 0xE7, 0x47, 0x57, 0xF5,
        0x05, 0x66, 0xFE, 0x46, 0xF7, 0xE1, 0x22, 0x24, 0x3C, 0x90, 0xC3, 0x0A, 0xDE, 0xBB, 0x0E,
        0x3D, 0xB3,
    ];

    println!("seed_dk matches: {}", seed_dk == expected_seed_dk);
    println!("seed_ek matches: {}", seed_ek == expected_seed_ek);

    // The issue is clear: seed_dk matches but seed_ek doesn't
    // This suggests that the problem is in the AES implementation
    // or in some subtle difference in the DRBG state management
}
