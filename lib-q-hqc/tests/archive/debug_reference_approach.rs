//! Debug Reference Implementation Approach
//!
//! This module contains tests to understand how the reference implementation
//! actually generates the KAT values.

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
fn test_kat_seed_is_generated_output() {
    println!("=== KAT Seed Analysis ===");

    // The KAT seed_kem from the official KAT file
    let kat_seed_kem = hex_to_bytes(
        "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1",
    );

    println!("KAT seed_kem: {:02x?}", kat_seed_kem);

    // The reference implementation uses this entropy input
    let mut entropy = [0u8; 48];
    for (i, byte) in entropy.iter_mut().enumerate() {
        *byte = i as u8;
    }

    println!("Reference entropy: {:02x?}", entropy);

    // Our AES-CTR-DRBG generates this output
    let mut rng = Aes256CtrDrbg::instantiate(&entropy);
    let mut output = [0u8; 48];
    rng.fill_bytes(&mut output);

    println!("Our generated output: {:02x?}", output);

    // Check if our output matches the KAT seed
    if output == kat_seed_kem.as_slice() {
        println!("✅ Our AES-CTR-DRBG generates the KAT seed exactly!");
    } else {
        println!("❌ Our output differs from KAT seed");

        // Check if the first 32 bytes match
        if output[..32] == kat_seed_kem[..32] {
            println!("✅ First 32 bytes match KAT seed_kem exactly!");
            println!("  This suggests the reference uses our approach for seed generation");
        } else {
            println!("❌ First 32 bytes don't match");
        }
    }
}

#[cfg(feature = "aes-drbg")]
#[test]
fn test_reference_entropy_vs_kat_seed() {
    println!("=== Reference Entropy vs KAT Seed Analysis ===");

    // The reference implementation's entropy input (sequential bytes 0-47)
    let mut reference_entropy = [0u8; 48];
    for (i, byte) in reference_entropy.iter_mut().enumerate() {
        *byte = i as u8;
    }

    // The KAT seed_kem from the official KAT file
    let kat_seed_kem = hex_to_bytes(
        "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1",
    );

    println!("Reference entropy: {:02x?}", reference_entropy);
    println!("KAT seed_kem:      {:02x?}", kat_seed_kem);

    // Hypothesis: The reference implementation generates the KAT seed using AES-CTR-DRBG
    // with the sequential entropy input, and then uses that seed for key generation

    let mut rng = Aes256CtrDrbg::instantiate(&reference_entropy);
    let mut generated_seed = [0u8; 48];
    rng.fill_bytes(&mut generated_seed);

    println!("Generated seed:    {:02x?}", generated_seed);

    if generated_seed == kat_seed_kem.as_slice() {
        println!("✅ CONFIRMED: Reference generates KAT seed using AES-CTR-DRBG!");
        println!("  This means our implementation is correct for seed generation");
        println!("  The issue must be in how we use the generated seed for key generation");
    } else {
        println!("❌ Generated seed doesn't match KAT seed");
        println!("  This suggests our AES-CTR-DRBG implementation differs from reference");
    }
}

#[cfg(feature = "aes-drbg")]
#[test]
fn test_kat_seed_usage_in_keygen() {
    println!("=== KAT Seed Usage in Key Generation ===");

    // The KAT seed_kem from the official KAT file
    let kat_seed_kem = hex_to_bytes(
        "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1",
    );
    let kat_seed_array: [u8; 48] = kat_seed_kem.try_into().unwrap();

    println!("Using KAT seed directly: {:02x?}", kat_seed_array);

    // Now use this seed for key generation (this is what the reference does)
    let mut rng = Aes256CtrDrbg::instantiate(&kat_seed_array);

    // Generate seed_dk and seed_ek
    let mut seed_dk = [0u8; 32];
    let mut seed_ek = [0u8; 32];
    rng.fill_bytes(&mut seed_dk);
    rng.fill_bytes(&mut seed_ek);

    println!("Generated seed_dk: {:02x?}", seed_dk);
    println!("Generated seed_ek: {:02x?}", seed_ek);

    // Expected values from KAT
    let expected_seed_dk =
        hex_to_bytes("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d");
    let expected_seed_ek =
        hex_to_bytes("74b2d352cf74c934069c9de74757f50566fe46f7e122243c90c30adebb0e3db3");

    println!("Expected seed_dk:  {:02x?}", expected_seed_dk);
    println!("Expected seed_ek:  {:02x?}", expected_seed_ek);

    if seed_dk == expected_seed_dk.as_slice() && seed_ek == expected_seed_ek.as_slice() {
        println!("✅ SUCCESS: Using KAT seed directly produces correct key generation seeds!");
        println!("  This confirms our AES-CTR-DRBG implementation is correct");
        println!("  The issue was in our test setup, not the implementation");
    } else {
        println!("❌ Still not matching expected values");
        println!(
            "  seed_dk match: {}",
            seed_dk == expected_seed_dk.as_slice()
        );
        println!(
            "  seed_ek match: {}",
            seed_ek == expected_seed_ek.as_slice()
        );
    }
}

#[cfg(not(feature = "aes-drbg"))]
#[test]
fn test_feature_disabled() {
    println!("=== AES-CTR-DRBG Feature Disabled Test ===");
    println!("✅ Feature disabled test passed - aes-drbg feature is not enabled");
}
