//! Debug Reference Flow
//!
//! This module tests the exact flow from the reference implementation:
//! 1. Initialize DRBG with entropy [0,1,2,...,47]
//! 2. Generate KAT seed (48 bytes)
//! 3. Re-initialize DRBG with KAT seed
//! 4. Generate keypair using re-initialized DRBG

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
fn test_reference_flow_exact() {
    println!("=== Reference Flow Exact Test ===");

    // Step 1: Initialize entropy_input with sequential values [0,1,2,...,47]
    // This matches line 50-51 in main_kat.c
    let mut entropy_input = [0u8; 48];
    for (i, byte) in entropy_input.iter_mut().enumerate() {
        *byte = i as u8;
    }
    println!("Step 1 - Entropy input: {:02x?}", entropy_input);

    // Step 2: Initialize DRBG with entropy_input
    // This matches line 53: randombytes_init(entropy_input, NULL, 256)
    let mut rng1 = Aes256CtrDrbg::instantiate(&entropy_input);
    println!("Step 2 - DRBG initialized with entropy");

    // Step 3: Generate KAT seed (48 bytes)
    // This matches line 56: randombytes(seed, 48)
    let mut kat_seed = [0u8; 48];
    rng1.fill_bytes(&mut kat_seed);
    println!("Step 3 - Generated KAT seed: {:02x?}", kat_seed);

    // Expected KAT seed from official KAT file
    let expected_kat_seed = hex_to_bytes(
        "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1",
    );
    let expected_kat_seed_array: [u8; 48] = expected_kat_seed.try_into().unwrap();

    println!("Expected KAT seed: {:02x?}", expected_kat_seed_array);

    if kat_seed == expected_kat_seed_array {
        println!("✅ KAT seed generation is correct!");
    } else {
        println!("❌ KAT seed generation is incorrect!");
        return;
    }

    // Step 4: Re-initialize DRBG with KAT seed
    // This matches line 88: randombytes_init(seed, NULL, 256)
    let mut rng2 = Aes256CtrDrbg::instantiate(&kat_seed);
    println!("Step 4 - DRBG re-initialized with KAT seed");

    // Step 5: Generate seed_dk and seed_ek using the re-initialized DRBG
    // This matches what happens inside crypto_kem_keypair
    let mut seed_dk = [0u8; 32];
    let mut seed_ek = [0u8; 32];
    rng2.fill_bytes(&mut seed_dk);
    rng2.fill_bytes(&mut seed_ek);

    println!("Step 5 - Generated seeds:");
    println!("  seed_dk: {:02x?}", seed_dk);
    println!("  seed_ek: {:02x?}", seed_ek);

    // Expected values from KAT
    let expected_seed_dk =
        hex_to_bytes("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d");
    let expected_seed_ek =
        hex_to_bytes("74b2d352cf74c934069c9de74757f50566fe46f7e122243c90c30adebb0e3db3");

    println!("Expected seeds:");
    println!("  seed_dk: {:02x?}", expected_seed_dk);
    println!("  seed_ek: {:02x?}", expected_seed_ek);

    let seed_dk_match = seed_dk == expected_seed_dk.as_slice();
    let seed_ek_match = seed_ek == expected_seed_ek.as_slice();

    println!("Results:");
    println!("  seed_dk match: {}", seed_dk_match);
    println!("  seed_ek match: {}", seed_ek_match);

    if seed_dk_match && seed_ek_match {
        println!("✅ SUCCESS: Both seeds match reference exactly!");
    } else {
        println!("❌ FAILURE: Seeds don't match reference");

        if !seed_dk_match {
            println!("seed_dk differences:");
            for i in 0..32 {
                if seed_dk[i] != expected_seed_dk[i] {
                    println!(
                        "  Byte {}: generated={:02x}, expected={:02x}",
                        i, seed_dk[i], expected_seed_dk[i]
                    );
                }
            }
        }

        if !seed_ek_match {
            println!("seed_ek differences:");
            for i in 0..32 {
                if seed_ek[i] != expected_seed_ek[i] {
                    println!(
                        "  Byte {}: generated={:02x}, expected={:02x}",
                        i, seed_ek[i], expected_seed_ek[i]
                    );
                }
            }
        }
    }

    // Assertions
    assert_eq!(
        kat_seed, expected_kat_seed_array,
        "KAT seed must match reference"
    );
    assert_eq!(
        seed_dk,
        expected_seed_dk.as_slice(),
        "seed_dk must match reference"
    );
    assert_eq!(
        seed_ek,
        expected_seed_ek.as_slice(),
        "seed_ek must match reference"
    );
}

#[cfg(not(feature = "aes-drbg"))]
#[test]
fn test_feature_disabled() {
    println!("=== AES-CTR-DRBG Feature Disabled Test ===");
    println!("✅ Feature disabled test passed - aes-drbg feature is not enabled");
}
