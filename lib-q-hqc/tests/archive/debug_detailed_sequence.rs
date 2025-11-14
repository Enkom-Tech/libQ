//! Debug Detailed Sequence Analysis
//!
//! This module provides detailed analysis of the exact sequence of operations
//! to understand where our implementation diverges from the reference.

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
fn test_manual_step_by_step() {
    println!("=== Manual Step-by-Step Analysis ===");

    // Let's manually implement the reference sequence step by step
    let kat_seed = hex_to_bytes(
        "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1",
    );
    let kat_seed_array: [u8; 48] = kat_seed.try_into().unwrap();

    println!("KAT seed: {:02x?}", kat_seed_array);

    // Step 1: Initialize DRBG (equivalent to randombytes_init)
    let mut rng = Aes256CtrDrbg::instantiate(&kat_seed_array);

    // Step 2: Generate first 32 bytes (equivalent to first randombytes call)
    println!("\n=== First randombytes call (32 bytes) ===");
    let mut seed_dk = [0u8; 32];
    rng.fill_bytes(&mut seed_dk);
    println!("Generated seed_dk: {:02x?}", seed_dk);

    // Expected seed_dk
    let expected_seed_dk =
        hex_to_bytes("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d");
    println!("Expected seed_dk:  {:02x?}", expected_seed_dk);
    println!("seed_dk match: {}", seed_dk == expected_seed_dk.as_slice());

    // Step 3: Generate second 32 bytes (equivalent to second randombytes call)
    println!("\n=== Second randombytes call (32 bytes) ===");
    let mut seed_ek = [0u8; 32];
    rng.fill_bytes(&mut seed_ek);
    println!("Generated seed_ek: {:02x?}", seed_ek);

    // Expected seed_ek
    let expected_seed_ek =
        hex_to_bytes("74b2d352cf74c934069c9de74757f50566fe46f7e122243c90c30adebb0e3db3");
    println!("Expected seed_ek:  {:02x?}", expected_seed_ek);
    println!("seed_ek match: {}", seed_ek == expected_seed_ek.as_slice());

    // Let's also test what happens if we generate 64 bytes in a single call
    println!("\n=== Single randombytes call (64 bytes) ===");
    let mut rng2 = Aes256CtrDrbg::instantiate(&kat_seed_array);
    let mut output_64 = [0u8; 64];
    rng2.fill_bytes(&mut output_64);

    println!("Single call output:");
    println!("  Bytes 0-31:  {:02x?}", &output_64[0..32]);
    println!("  Bytes 32-63: {:02x?}", &output_64[32..64]);

    println!("\nComparison:");
    println!(
        "  First 32 bytes match: {}",
        &output_64[0..32] == expected_seed_dk.as_slice()
    );
    println!(
        "  Second 32 bytes match: {}",
        &output_64[32..64] == expected_seed_ek.as_slice()
    );

    // Analysis
    if seed_dk == expected_seed_dk.as_slice() && seed_ek == expected_seed_ek.as_slice() {
        println!("\n✅ Perfect match with expected KAT values!");
    } else {
        println!("\n❌ Still not matching expected KAT values");

        // Let's see if the issue is in our understanding of the expected values
        println!("\n=== Alternative Analysis ===");
        println!("Maybe the expected values are wrong? Let's check:");

        // What if the KAT seed itself contains the expected values?
        println!("KAT seed first 32 bytes:  {:02x?}", &kat_seed_array[0..32]);
        println!("KAT seed second 32 bytes: {:02x?}", &kat_seed_array[32..48]);

        println!("Are the expected values in the KAT seed?");
        println!(
            "  seed_dk in KAT seed: {}",
            &kat_seed_array[0..32] == expected_seed_dk.as_slice()
        );
        println!(
            "  seed_ek in KAT seed: {}",
            kat_seed_array[32..48] == expected_seed_ek[0..16]
        );
    }
}

#[cfg(feature = "aes-drbg")]
#[test]
fn test_hypothesis_verification() {
    println!("=== Hypothesis Verification ===");

    // Hypothesis: Maybe the reference implementation doesn't use the KAT seed directly
    // but rather generates it from some other entropy source

    println!("Hypothesis 1: KAT seed is generated from reference entropy");
    let mut reference_entropy = [0u8; 48];
    for (i, byte) in reference_entropy.iter_mut().enumerate() {
        *byte = i as u8;
    }

    let mut rng = Aes256CtrDrbg::instantiate(&reference_entropy);
    let mut generated_kat_seed = [0u8; 48];
    rng.fill_bytes(&mut generated_kat_seed);

    let expected_kat_seed = hex_to_bytes(
        "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1",
    );
    let expected_kat_seed_array: [u8; 48] = expected_kat_seed.try_into().unwrap();

    println!("Generated KAT seed: {:02x?}", generated_kat_seed);
    println!("Expected KAT seed:  {:02x?}", expected_kat_seed_array);
    println!(
        "KAT seed match: {}",
        generated_kat_seed == expected_kat_seed_array
    );

    if generated_kat_seed == expected_kat_seed_array {
        println!("✅ Hypothesis 1 confirmed: KAT seed is generated from reference entropy");

        // Now let's use this generated seed for key generation
        println!("\n=== Using Generated KAT Seed for Key Generation ===");
        let mut rng2 = Aes256CtrDrbg::instantiate(&generated_kat_seed);

        let mut seed_dk = [0u8; 32];
        let mut seed_ek = [0u8; 32];
        rng2.fill_bytes(&mut seed_dk);
        rng2.fill_bytes(&mut seed_ek);

        let expected_seed_dk =
            hex_to_bytes("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d");
        let expected_seed_ek =
            hex_to_bytes("74b2d352cf74c934069c9de74757f50566fe46f7e122243c90c30adebb0e3db3");

        println!("Generated seed_dk: {:02x?}", seed_dk);
        println!("Expected seed_dk:  {:02x?}", expected_seed_dk);
        println!("seed_dk match: {}", seed_dk == expected_seed_dk.as_slice());

        println!("Generated seed_ek: {:02x?}", seed_ek);
        println!("Expected seed_ek:  {:02x?}", expected_seed_ek);
        println!("seed_ek match: {}", seed_ek == expected_seed_ek.as_slice());

        if seed_dk == expected_seed_dk.as_slice() && seed_ek == expected_seed_ek.as_slice() {
            println!("✅ SUCCESS: Using generated KAT seed produces correct key generation!");
        } else {
            println!("❌ Still not matching even with generated KAT seed");
        }
    } else {
        println!("❌ Hypothesis 1 rejected: KAT seed is not generated from reference entropy");
    }
}

#[cfg(not(feature = "aes-drbg"))]
#[test]
fn test_feature_disabled() {
    println!("=== AES-CTR-DRBG Feature Disabled Test ===");
    println!("✅ Feature disabled test passed - aes-drbg feature is not enabled");
}
