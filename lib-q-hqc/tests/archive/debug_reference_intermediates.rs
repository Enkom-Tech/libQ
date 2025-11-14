//! Debug Reference Intermediates
//!
//! This module compares our implementation with the intermediate values
//! from the reference implementation's intermediate values file.

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
fn test_reference_intermediate_seeds() {
    println!("=== Reference Intermediate Seeds Analysis ===");

    // From the reference intermediate values file:
    // sk_seed: 530f8afbc74536b9a963b4f1c4cb738bcea7403d4d606b6e074ec5d3baf39d18726003ca37a62a74
    // pk_seed: 99b77ab3eb4e18e85ea5b9affa1d68b2d223dee20d1f855fd1a8222b31b53cb5c7328f685f90545c

    let reference_sk_seed_hex =
        "530f8afbc74536b9a963b4f1c4cb738bcea7403d4d606b6e074ec5d3baf39d18726003ca37a62a74";
    let reference_pk_seed_hex =
        "99b77ab3eb4e18e85ea5b9affa1d68b2d223dee20d1f855fd1a8222b31b53cb5c7328f685f90545c";

    let reference_sk_seed = hex_to_bytes(reference_sk_seed_hex);
    let reference_pk_seed = hex_to_bytes(reference_pk_seed_hex);

    println!("Reference sk_seed: {:02x?}", reference_sk_seed);
    println!("Reference pk_seed: {:02x?}", reference_pk_seed);

    // Expected values from KAT (what we've been trying to match):
    let expected_seed_dk =
        hex_to_bytes("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d");
    let expected_seed_ek =
        hex_to_bytes("74b2d352cf74c934069c9de74757f50566fe46f7e122243c90c30adebb0e3db3");

    println!("Expected seed_dk: {:02x?}", expected_seed_dk);
    println!("Expected seed_ek: {:02x?}", expected_seed_ek);

    // Compare
    println!("\n=== Comparison ===");
    println!(
        "sk_seed == seed_dk: {}",
        reference_sk_seed == expected_seed_dk
    );
    println!(
        "pk_seed == seed_ek: {}",
        reference_pk_seed == expected_seed_ek
    );

    if reference_sk_seed != expected_seed_dk {
        println!("sk_seed differences:");
        for i in 0..reference_sk_seed.len().min(expected_seed_dk.len()) {
            if reference_sk_seed[i] != expected_seed_dk[i] {
                println!(
                    "  Byte {}: reference={:02x}, expected={:02x}",
                    i, reference_sk_seed[i], expected_seed_dk[i]
                );
            }
        }
    }

    if reference_pk_seed != expected_seed_ek {
        println!("pk_seed differences:");
        for i in 0..reference_pk_seed.len().min(expected_seed_ek.len()) {
            if reference_pk_seed[i] != expected_seed_ek[i] {
                println!(
                    "  Byte {}: reference={:02x}, expected={:02x}",
                    i, reference_pk_seed[i], expected_seed_ek[i]
                );
            }
        }
    }

    // Now let's see what our implementation produces
    println!("\n=== Our Implementation ===");
    let kat_seed_kem = hex_to_bytes(
        "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1",
    );
    let kat_seed_array: [u8; 48] = kat_seed_kem.try_into().unwrap();

    let mut rng = Aes256CtrDrbg::instantiate(&kat_seed_array);
    let mut our_seed_dk = [0u8; 32];
    let mut our_seed_ek = [0u8; 32];
    rng.fill_bytes(&mut our_seed_dk);
    rng.fill_bytes(&mut our_seed_ek);

    println!("Our seed_dk: {:02x?}", our_seed_dk);
    println!("Our seed_ek: {:02x?}", our_seed_ek);

    println!("\n=== Final Comparison ===");
    println!(
        "Our seed_dk == Reference sk_seed: {}",
        our_seed_dk == reference_sk_seed.as_slice()
    );
    println!(
        "Our seed_ek == Reference pk_seed: {}",
        our_seed_ek == reference_pk_seed.as_slice()
    );
    println!(
        "Our seed_dk == Expected seed_dk: {}",
        our_seed_dk == expected_seed_dk.as_slice()
    );
    println!(
        "Our seed_ek == Expected seed_ek: {}",
        our_seed_ek == expected_seed_ek.as_slice()
    );

    // The key insight: if our implementation matches the reference intermediate values,
    // then the "expected" values from the KAT file might be wrong or from a different source
    if our_seed_dk == reference_sk_seed.as_slice() && our_seed_ek == reference_pk_seed.as_slice() {
        println!("✅ SUCCESS: Our implementation matches the reference intermediate values!");
        println!(
            "This suggests that the 'expected' values from the KAT file are incorrect or from a different source."
        );
    } else {
        println!("❌ Our implementation still doesn't match the reference intermediate values");
    }
}

#[cfg(not(feature = "aes-drbg"))]
#[test]
fn test_feature_disabled() {
    println!("=== AES-CTR-DRBG Feature Disabled Test ===");
    println!("✅ Feature disabled test passed - aes-drbg feature is not enabled");
}
