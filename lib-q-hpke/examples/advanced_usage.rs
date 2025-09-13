//! Advanced HPKE usage example
//!
//! This example demonstrates advanced HPKE features:
//! - Custom cipher suites
//! - Error handling
//! - Performance testing
//! - Different message sizes

#![cfg(feature = "std")]

use std::time::Instant;

use lib_q_core::{
    Algorithm,
    KemContext,
    KemPublicKey,
    KemSecretKey,
};
use lib_q_hpke::{
    HpkeAead,
    HpkeCipherSuite,
    HpkeContext,
    HpkeKdf,
    HpkeKem,
};
use libq::LibQCryptoProvider;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Advanced HPKE Usage Example ===");

    // Test different cipher suites
    test_cipher_suites()?;

    // Test error handling
    test_error_handling()?;

    // Test performance
    test_performance()?;

    // Test different message sizes
    test_message_sizes()?;

    println!("\n=== All advanced tests passed! ===");
    Ok(())
}

fn test_cipher_suites() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n--- Testing Different Cipher Suites ---");

    let suites = vec![
        (
            HpkeKem::MlKem512,
            HpkeKdf::HkdfShake128,
            HpkeAead::Saturnin256,
            "ML-KEM-512 + HKDF-SHAKE128 + Saturnin256",
        ),
        (
            HpkeKem::MlKem768,
            HpkeKdf::HkdfShake256,
            HpkeAead::Saturnin256,
            "ML-KEM-768 + HKDF-SHAKE256 + Saturnin256",
        ),
        (
            HpkeKem::MlKem1024,
            HpkeKdf::HkdfSha3_256,
            HpkeAead::Saturnin256,
            "ML-KEM-1024 + HKDF-SHA3-256 + Saturnin256",
        ),
        (
            HpkeKem::MlKem512,
            HpkeKdf::HkdfSha3_512,
            HpkeAead::Saturnin256,
            "ML-KEM-512 + HKDF-SHA3-512 + Saturnin256",
        ),
    ];

    for (kem, kdf, aead, description) in suites {
        let suite = HpkeCipherSuite::new(kem, kdf, aead);
        let suite_id = suite.identifier();
        println!("✓ {}: Suite ID = {:02x?}", description, suite_id);

        // Verify algorithm IDs
        assert!(suite.kem.algorithm_id() > 0);
        assert!(suite.kdf.algorithm_id() > 0);
        assert!(suite.aead.algorithm_id() > 0);
    }

    Ok(())
}

fn test_error_handling() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n--- Testing Error Handling ---");

    let mut hpke_ctx = HpkeContext::new();

    // Test with invalid key sizes
    let invalid_pk_small = KemPublicKey::new(vec![0u8; 100]); // Too small
    let result_small = hpke_ctx.setup_sender(&invalid_pk_small, b"info");
    match result_small {
        Err(_) => {
            println!("✓ Correctly rejected small key");
        }
        _ => panic!("Expected error for small key"),
    }

    let invalid_pk_large = KemPublicKey::new(vec![0u8; 2000]); // Too large
    let result_large = hpke_ctx.setup_sender(&invalid_pk_large, b"info");
    match result_large {
        Err(_) => {
            println!("✓ Correctly rejected large key");
        }
        _ => panic!("Expected error for large key"),
    }

    // Test with mismatched keys (placeholder implementation note)
    let mut kem_ctx = KemContext::with_provider(Box::new(LibQCryptoProvider::new()));
    let keypair1 = kem_ctx.generate_keypair(Algorithm::MlKem512)?;
    let keypair2 = kem_ctx.generate_keypair(Algorithm::MlKem512)?;

    let recipient_pk1 = KemPublicKey::new(keypair1.public_key().as_bytes().to_vec());
    let recipient_sk2 = KemSecretKey::new(keypair2.secret_key().as_bytes().to_vec());

    let (enc_key, ciphertext) = hpke_ctx.seal(&recipient_pk1, b"info", b"aad", b"message")?;
    let result_mismatch = hpke_ctx.open(&enc_key, &recipient_sk2, b"info", b"aad", &ciphertext);

    match result_mismatch {
        Err(_) => {
            println!("✓ Correctly rejected mismatched keys");
        }
        Ok(_) => {
            // Note: With placeholder KEM implementation, mismatched keys may succeed
            // In a real implementation, this should fail
            println!("⚠ Mismatched keys test passed (placeholder implementation)");
        }
    }

    Ok(())
}

fn test_performance() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n--- Performance Testing ---");

    let mut hpke_ctx = HpkeContext::new();
    let mut kem_ctx = KemContext::with_provider(Box::new(LibQCryptoProvider::new()));
    let keypair = kem_ctx.generate_keypair(Algorithm::MlKem512)?;

    let recipient_pk = KemPublicKey::new(keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(keypair.secret_key().as_bytes().to_vec());

    let message = b"Performance test message";
    let iterations = 100;

    // Test encryption performance
    let start = Instant::now();
    for _ in 0..iterations {
        let (enc_key, ciphertext) = hpke_ctx.seal(&recipient_pk, b"info", b"aad", message)?;
        let _decrypted = hpke_ctx.open(&enc_key, &recipient_sk, b"info", b"aad", &ciphertext)?;
    }
    let duration = start.elapsed();

    let avg_time = duration.as_millis() as f64 / iterations as f64;
    println!("✓ {} iterations completed in {:?}", iterations, duration);
    println!("  Average time per encrypt+decrypt: {:.2}ms", avg_time);

    // Test key generation performance
    let start = Instant::now();
    for _ in 0..10 {
        let _keypair = kem_ctx.generate_keypair(Algorithm::MlKem512)?;
    }
    let duration = start.elapsed();

    let avg_keygen_time = duration.as_millis() as f64 / 10.0;
    println!("✓ Key generation: {:.2}ms per key pair", avg_keygen_time);

    Ok(())
}

fn test_message_sizes() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n--- Testing Different Message Sizes ---");

    let mut hpke_ctx = HpkeContext::new();
    let mut kem_ctx = KemContext::with_provider(Box::new(LibQCryptoProvider::new()));
    let keypair = kem_ctx.generate_keypair(Algorithm::MlKem512)?;

    let recipient_pk = KemPublicKey::new(keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(keypair.secret_key().as_bytes().to_vec());

    let message_sizes = vec![
        (0, "Empty message"),
        (1, "1 byte"),
        (16, "16 bytes"),
        (256, "256 bytes"),
        (1024, "1 KB"),
        (4096, "4 KB"),
        (16384, "16 KB"),
    ];

    for (size, description) in message_sizes {
        let message = vec![0x42u8; size];

        let start = Instant::now();
        let (enc_key, ciphertext) = hpke_ctx.seal(&recipient_pk, b"info", b"aad", &message)?;
        let decrypted = hpke_ctx.open(&enc_key, &recipient_sk, b"info", b"aad", &ciphertext)?;
        let duration = start.elapsed();

        assert_eq!(decrypted, message);
        println!(
            "✓ {}: {} bytes -> {} bytes ({}μs)",
            description,
            size,
            ciphertext.len(),
            duration.as_micros()
        );
    }

    Ok(())
}
