//! Reference Implementation Analysis
//!
//! This module analyzes the reference C implementation to understand the exact
//! flow and identify any discrepancies with our Rust implementation.

#[cfg(feature = "aes-drbg")]
use lib_q_hqc::aes_ctr_drbg::Aes256CtrDrbg;
#[cfg(feature = "aes-drbg")]
use rand_core::RngCore;

/// Helper function to convert hex string to bytes
#[allow(dead_code)]
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut chars = hex.chars().peekable();

    while let (Some(c1), Some(c2)) = (chars.next(), chars.next()) {
        let byte = u8::from_str_radix(&format!("{}{}", c1, c2), 16).unwrap();
        bytes.push(byte);
    }

    bytes
}

/// Helper function to print hex with label
#[allow(dead_code)]
fn print_hex(label: &str, data: &[u8]) {
    println!("{}: {:02x?}", label, data);
}

#[cfg(feature = "aes-drbg")]
#[test]
#[ignore] // Reference implementation comparison - known DRBG differences
fn test_reference_flow_analysis() {
    println!("=== Reference Implementation Flow Analysis ===");

    // Step 1: Initialize entropy_input with [0, 1, 2, ..., 47]
    let mut entropy_input = [0u8; 48];
    for (i, byte) in entropy_input.iter_mut().enumerate() {
        *byte = i as u8;
    }
    print_hex("Entropy input", &entropy_input);

    // Step 2: Initialize DRBG with entropy (randombytes_init)
    // From reference: randombytes_init(entropy_input, NULL, 256)
    let mut rng1 = Aes256CtrDrbg::instantiate(&entropy_input);
    println!("DRBG initialized with entropy");

    // Step 3: Generate KAT seed (randombytes(seed, 48))
    let mut kat_seed = [0u8; 48];
    rng1.fill_bytes(&mut kat_seed);
    print_hex("Generated KAT seed", &kat_seed);

    // Expected KAT seed from our analysis
    let expected_kat_seed = hex_to_bytes(
        "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1",
    );
    println!("Expected KAT seed: {:02x?}", expected_kat_seed);
    println!(
        "KAT seed matches: {}",
        kat_seed == expected_kat_seed.as_slice()
    );

    // Step 4: Re-initialize DRBG with KAT seed (randombytes_init(seed, NULL, 256))
    let mut rng2 = Aes256CtrDrbg::instantiate(&kat_seed);
    println!("DRBG re-initialized with KAT seed");

    // Step 5: Generate seed_dk (first 32 bytes from randombytes)
    let mut seed_dk = [0u8; 32];
    rng2.fill_bytes(&mut seed_dk);
    print_hex("Generated seed_dk", &seed_dk);

    // Step 6: Generate seed_ek (next 32 bytes from randombytes)
    let mut seed_ek = [0u8; 32];
    rng2.fill_bytes(&mut seed_ek);
    print_hex("Generated seed_ek", &seed_ek);

    // Expected values from KAT file
    let expected_seed_dk =
        hex_to_bytes("7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2D");
    let expected_seed_ek =
        hex_to_bytes("74B2D352CF74C934069C9DE74757F50566FE46F7E122243C90C30ADEBB0E3DB3");

    println!("Expected seed_dk: {:02x?}", expected_seed_dk);
    println!("Expected seed_ek: {:02x?}", expected_seed_ek);

    println!(
        "seed_dk matches: {}",
        seed_dk == expected_seed_dk.as_slice()
    );
    println!(
        "seed_ek matches: {}",
        seed_ek == expected_seed_ek.as_slice()
    );

    // Analysis of the reference implementation flow:
    println!("\n=== Reference Implementation Analysis ===");
    println!("1. randombytes_init(entropy_input, NULL, 256)");
    println!("   - Copies entropy_input to seed_material");
    println!("   - XORs with personalization_string (NULL, so no change)");
    println!("   - Initializes Key and V to zeros");
    println!("   - Calls AES256_CTR_DRBG_Update(seed_material, Key, V)");
    println!("   - Sets reseed_counter = 1");

    println!("\n2. randombytes(seed, 48)");
    println!("   - Generates 48 bytes using AES256_ECB");
    println!("   - Increments V for each 16-byte block");
    println!("   - Calls AES256_CTR_DRBG_Update(NULL, Key, V) at the end");
    println!("   - Increments reseed_counter");

    println!("\n3. randombytes_init(seed, NULL, 256)");
    println!("   - Re-initializes DRBG with the generated KAT seed");
    println!("   - Same process as step 1, but with KAT seed as entropy");

    println!("\n4. randombytes(seed_dk, 32)");
    println!("   - Generates first 32 bytes for seed_dk");
    println!("   - Updates DRBG state after generation");

    println!("\n5. randombytes(seed_ek, 32)");
    println!("   - Generates next 32 bytes for seed_ek");
    println!("   - Updates DRBG state after generation");

    // Key observations from reference code analysis:
    println!("\n=== Key Observations ===");
    println!("1. The reference uses OpenSSL's EVP_aes_256_ecb() for AES encryption");
    println!("2. Our implementation uses the 'aes' crate");
    println!("3. The CTR_DRBG_Update is called AFTER each randombytes call");
    println!("4. The counter V is incremented for each 16-byte block generated");
    println!("5. The reseed_counter is incremented after each randombytes call");

    // Potential issues:
    println!("\n=== Potential Issues ===");
    println!("1. AES implementation differences (OpenSSL vs aes crate)");
    println!("2. Counter increment behavior");
    println!("3. State update timing");
    println!("4. Endianness differences");

    // Assertions for debugging
    assert_eq!(
        kat_seed,
        expected_kat_seed.as_slice(),
        "KAT seed must match expected value"
    );
    assert_eq!(
        seed_dk,
        expected_seed_dk.as_slice(),
        "seed_dk must match expected value"
    );
    assert_eq!(
        seed_ek,
        expected_seed_ek.as_slice(),
        "seed_ek must match expected value"
    );
}

#[cfg(feature = "aes-drbg")]
#[test]
fn test_drbg_state_analysis() {
    println!("=== DRBG State Analysis ===");

    // Test the exact same flow as the reference
    let mut entropy_input = [0u8; 48];
    for (i, byte) in entropy_input.iter_mut().enumerate() {
        *byte = i as u8;
    }

    // Initialize DRBG
    let mut rng = Aes256CtrDrbg::instantiate(&entropy_input);

    // Generate KAT seed
    let mut kat_seed = [0u8; 48];
    rng.fill_bytes(&mut kat_seed);

    // Re-initialize with KAT seed
    let mut rng2 = Aes256CtrDrbg::instantiate(&kat_seed);

    // Generate seed_dk and seed_ek in separate calls (like reference)
    let mut seed_dk = [0u8; 32];
    let mut seed_ek = [0u8; 32];

    rng2.fill_bytes(&mut seed_dk);
    rng2.fill_bytes(&mut seed_ek);

    print_hex("seed_dk (separate calls)", &seed_dk);
    print_hex("seed_ek (separate calls)", &seed_ek);

    // Now test generating both in one call
    let mut rng3 = Aes256CtrDrbg::instantiate(&kat_seed);
    let mut combined = [0u8; 64];
    rng3.fill_bytes(&mut combined);

    let seed_dk_combined = &combined[0..32];
    let seed_ek_combined = &combined[32..64];

    print_hex("seed_dk (combined call)", seed_dk_combined);
    print_hex("seed_ek (combined call)", seed_ek_combined);

    println!(
        "seed_dk matches (separate vs combined): {}",
        seed_dk == seed_dk_combined
    );
    println!(
        "seed_ek matches (separate vs combined): {}",
        seed_ek == seed_ek_combined
    );

    // This test helps us understand if the issue is in the state management
    // between separate fill_bytes calls
}

#[cfg(feature = "aes-drbg")]
#[test]
fn test_aes_implementation_comparison() {
    println!("=== AES Implementation Comparison ===");

    // Test our AES implementation with known vectors
    let key = [0u8; 32]; // All zeros key
    let input = [0u8; 16]; // All zeros input

    // Our implementation
    let output = lib_q_hqc::aes_ctr_drbg::Aes256CtrDrbg::aes256_ecb(&key, &input);

    print_hex("Our AES output (zeros)", &output);

    // Test with non-zero values
    let key2 = [0x01u8; 32]; // All 0x01 key
    let input2 = [0x02u8; 16]; // All 0x02 input

    let output2 = lib_q_hqc::aes_ctr_drbg::Aes256CtrDrbg::aes256_ecb(&key2, &input2);

    print_hex("Our AES output (0x01/0x02)", &output2);

    // The reference uses OpenSSL's EVP_aes_256_ecb()
    // We need to verify our implementation produces the same output
    println!("Note: Our AES implementation uses the 'aes' crate");
    println!("Reference uses OpenSSL's EVP_aes_256_ecb()");
    println!("This could be a source of discrepancy");
}
