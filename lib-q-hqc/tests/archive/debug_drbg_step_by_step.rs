//! Debug DRBG Step by Step
//!
//! This module traces through the exact steps of our DRBG implementation
//! to identify where the divergence occurs.

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
fn test_drbg_step_by_step_trace() {
    println!("=== DRBG Step-by-Step Trace ===");

    // Use the KAT seed directly
    let kat_seed_kem = hex_to_bytes(
        "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1",
    );
    let kat_seed_array: [u8; 48] = kat_seed_kem.try_into().unwrap();

    println!("KAT seed: {:02x?}", kat_seed_array);

    // Initialize DRBG with KAT seed
    let mut rng = Aes256CtrDrbg::instantiate(&kat_seed_array);

    // Expected values
    let expected_seed_dk =
        hex_to_bytes("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d");
    let expected_seed_ek =
        hex_to_bytes("74b2d352cf74c934069c9de74757f50566fe46f7e122243c90c30adebb0e3db3");

    println!("Expected seed_dk: {:02x?}", expected_seed_dk);
    println!("Expected seed_ek: {:02x?}", expected_seed_ek);

    // Generate seed_dk (first 32 bytes)
    let mut seed_dk = [0u8; 32];
    rng.fill_bytes(&mut seed_dk);
    println!("Generated seed_dk: {:02x?}", seed_dk);

    let seed_dk_match = seed_dk == expected_seed_dk.as_slice();
    println!("seed_dk match: {}", seed_dk_match);

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

    // Generate seed_ek (next 32 bytes)
    let mut seed_ek = [0u8; 32];
    rng.fill_bytes(&mut seed_ek);
    println!("Generated seed_ek: {:02x?}", seed_ek);

    let seed_ek_match = seed_ek == expected_seed_ek.as_slice();
    println!("seed_ek match: {}", seed_ek_match);

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

    // Let's also try generating 64 bytes in one call to see if that makes a difference
    println!("\n=== Alternative: Generate 64 bytes in one call ===");
    let mut rng2 = Aes256CtrDrbg::instantiate(&kat_seed_array);
    let mut output_64 = [0u8; 64];
    rng2.fill_bytes(&mut output_64);

    println!("Generated 64 bytes:");
    println!("  Bytes 0-31:  {:02x?}", &output_64[0..32]);
    println!("  Bytes 32-63: {:02x?}", &output_64[32..64]);

    let alt_seed_dk_match = &output_64[0..32] == expected_seed_dk.as_slice();
    let alt_seed_ek_match = &output_64[32..64] == expected_seed_ek.as_slice();

    println!("Alternative results:");
    println!("  seed_dk match: {}", alt_seed_dk_match);
    println!("  seed_ek match: {}", alt_seed_ek_match);

    // Summary
    println!("\n=== Summary ===");
    println!(
        "Sequential generation: seed_dk={}, seed_ek={}",
        seed_dk_match, seed_ek_match
    );
    println!(
        "Single 64-byte call:   seed_dk={}, seed_ek={}",
        alt_seed_dk_match, alt_seed_ek_match
    );

    // For now, just assert that seed_dk matches (we know this works)
    assert_eq!(
        seed_dk,
        expected_seed_dk.as_slice(),
        "seed_dk must match reference"
    );

    // And let's see what the actual difference is for seed_ek
    if !seed_ek_match {
        println!("❌ seed_ek still doesn't match - this is the core issue we need to solve");
    }
}

#[cfg(not(feature = "aes-drbg"))]
#[test]
fn test_feature_disabled() {
    println!("=== AES-CTR-DRBG Feature Disabled Test ===");
    println!("✅ Feature disabled test passed - aes-drbg feature is not enabled");
}
