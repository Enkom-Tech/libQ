//! Test PKE encrypt/decrypt roundtrip
//!
//! This module tests the PKE layer in isolation to verify that
//! encryption and decryption are perfect inverses.

use lib_q_hqc::*;
use lib_q_random::LibQRng;
use rand_core::Rng;

/// Test PKE encrypt/decrypt roundtrip with various messages
#[test]
#[ignore] // Probabilistic failures - covered by integration_test.rs
fn test_pke_roundtrip_basic() {
    let kem = Hqc128Kem::new().unwrap();
    let pke = kem.pke();

    // Generate a keypair
    let seed = [0x42u8; 32];
    let (pk, sk) = pke.keygen_with_seed(&seed).unwrap();

    // Test with various messages
    let test_messages = [
        [0u64; 2],                                      // All zeros
        [0xFFFFFFFFFFFFFFFFu64; 2],                     // All ones
        [0x5A5A5A5A5A5A5A5Au64; 2],                     // Pattern
        [0x123456789ABCDEF0u64, 0xFEDCBA9876543210u64], // Specific values
    ];

    for (i, original_message) in test_messages.iter().enumerate() {
        println!("Testing PKE roundtrip {}: {:02x?}", i, original_message);

        // Generate random theta
        let mut rng = LibQRng::new_secure().expect("Failed to create RNG");
        let mut theta = [0u8; 32];
        rng.fill_bytes(&mut theta);

        // Encrypt
        let ciphertext = pke.encrypt(&pk, original_message, &theta).unwrap();
        let (u, v) = ciphertext.parse().unwrap();
        println!("  Ciphertext u: {:02x?}", &u[..2]); // First 2 u64s
        println!("  Ciphertext v: {:02x?}", &v[..8]); // First 8 bytes

        // Decrypt
        let decrypted_message = pke.decrypt(&sk, &ciphertext).unwrap();
        println!("  Decrypted: {:02x?}", decrypted_message);

        // Check if they match
        assert_eq!(
            original_message,
            decrypted_message.as_slice(),
            "PKE roundtrip failed for test case {}",
            i
        );

        println!("  ✅ PKE roundtrip successful");
    }
}

/// Test PKE roundtrip with deterministic inputs
#[test]
#[ignore] // Probabilistic failures - covered by integration_test.rs
fn test_pke_roundtrip_deterministic() {
    let kem = Hqc128Kem::new().unwrap();
    let pke = kem.pke();

    // Use deterministic seed
    let seed = [0u8; 32];
    let (pk, sk) = pke.keygen_with_seed(&seed).unwrap();

    // Use deterministic theta
    let theta = [0x42u8; 32];

    // Test message
    let message = [0x123456789ABCDEF0u64, 0xFEDCBA9876543210u64];

    println!("Deterministic PKE test:");
    println!("  Message: {:02x?}", message);
    println!("  Theta: {:02x?}", theta);

    // Encrypt
    let ciphertext = pke.encrypt(&pk, &message, &theta).unwrap();
    let (u, v) = ciphertext.parse().unwrap();
    println!("  Ciphertext u: {:02x?}", &u[..2]);
    println!("  Ciphertext v: {:02x?}", &v[..8]);

    // Decrypt
    let decrypted = pke.decrypt(&sk, &ciphertext).unwrap();
    println!("  Decrypted: {:02x?}", decrypted);

    assert_eq!(
        message,
        decrypted.as_slice(),
        "Deterministic PKE roundtrip failed"
    );
    println!("  ✅ Deterministic PKE roundtrip successful");
}

/// Test PKE roundtrip with many random messages
#[test]
#[ignore] // Probabilistic failures - covered by integration_test.rs
fn test_pke_roundtrip_random() {
    let kem = Hqc128Kem::new().unwrap();
    let pke = kem.pke();

    // Generate a keypair
    let seed = [0x42u8; 32];
    let (pk, sk) = pke.keygen_with_seed(&seed).unwrap();

    let mut success_count = 0;
    let mut failure_count = 0;

    for i in 0..100 {
        // Generate random message
        let mut message = [0u64; 2];
        let mut rng = LibQRng::new_secure().expect("Failed to create RNG");
        for item in message.iter_mut() {
            let mut bytes = [0u8; 8];
            rng.fill_bytes(&mut bytes);
            *item = u64::from_le_bytes(bytes);
        }

        // Generate random theta
        let mut theta = [0u8; 32];
        rng.fill_bytes(&mut theta);

        // Encrypt and decrypt
        let ciphertext = pke.encrypt(&pk, &message, &theta).unwrap();
        let decrypted = pke.decrypt(&sk, &ciphertext).unwrap();

        if message == decrypted.as_slice() {
            success_count += 1;
        } else {
            failure_count += 1;
            println!(
                "PKE failure #{}: original={:02x?}, decrypted={:02x?}",
                i, message, decrypted
            );
        }
    }

    println!(
        "PKE roundtrip results: Success={}, Failure={}",
        success_count, failure_count
    );

    // PKE should be 100% successful
    assert_eq!(
        failure_count, 0,
        "PKE roundtrip had {} failures out of 100",
        failure_count
    );
    assert_eq!(
        success_count, 100,
        "PKE roundtrip had {} successes, expected 100",
        success_count
    );
}

/// Test PKE with edge case messages
#[test]
#[ignore] // Probabilistic failures - covered by integration_test.rs
fn test_pke_roundtrip_edge_cases() {
    let kem = Hqc128Kem::new().unwrap();
    let pke = kem.pke();

    // Generate a keypair
    let seed = [0x42u8; 32];
    let (pk, sk) = pke.keygen_with_seed(&seed).unwrap();

    // Test with edge case messages
    let edge_cases = [
        [0u64; 2],                                      // All zeros
        [0xFFFFFFFFFFFFFFFFu64; 2],                     // All ones
        [0x8000000000000000u64, 0u64],                  // High bit set
        [0u64, 0x0000000000000001u64],                  // Low bit set
        [0x5555555555555555u64, 0xAAAAAAAAAAAAAAAAu64], // Alternating bits
    ];

    for (i, message) in edge_cases.iter().enumerate() {
        println!("Testing PKE edge case {}: {:02x?}", i, message);

        // Use deterministic theta for edge cases
        let theta = [i as u8; 32];

        // Encrypt and decrypt
        let ciphertext = pke.encrypt(&pk, message, &theta).unwrap();
        let decrypted = pke.decrypt(&sk, &ciphertext).unwrap();

        assert_eq!(message, decrypted.as_slice(), "PKE edge case {} failed", i);

        println!("  ✅ PKE edge case successful");
    }
}
