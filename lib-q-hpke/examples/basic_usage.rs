//! Basic HPKE usage example
//!
//! This example demonstrates the most common HPKE operations:
//! - Key generation
//! - Single-shot encryption/decryption
//! - Context-based operations
//! - Key export

#![cfg(feature = "std")]

use lib_q_core::{
    Algorithm,
    KemContext,
    KemPublicKey,
    KemSecretKey,
};
use lib_q_hpke::HpkeContext;
use lib_q_kem::LibQKemProvider;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Basic HPKE Usage Example ===");

    // Create HPKE context with provider
    let provider = Box::new(LibQKemProvider::new()?);
    let mut hpke_ctx = HpkeContext::with_provider(provider);
    println!("✓ Created HPKE context");

    // Generate recipient key pair
    let mut kem_ctx = KemContext::with_provider(Box::new(LibQKemProvider::new()?));
    let keypair = kem_ctx.generate_keypair(Algorithm::MlKem512, None)?;
    println!("✓ Generated ML-KEM-512 key pair");

    let recipient_pk = KemPublicKey::new(keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(keypair.secret_key().as_bytes().to_vec());
    println!("✓ Created HPKE key objects");

    // Single-shot encryption/decryption
    println!("\n--- Single-shot Operations ---");
    let message = b"Hello, HPKE! This is a secret message.";
    println!("Original message: {}", String::from_utf8_lossy(message));

    let (encapsulated_key, ciphertext) = hpke_ctx.seal(
        &recipient_pk,
        b"application-info",
        b"additional-data",
        message,
    )?;
    println!("✓ Encrypted message");
    println!("  Encapsulated key size: {} bytes", encapsulated_key.len());
    println!("  Ciphertext size: {} bytes", ciphertext.len());

    let decrypted = hpke_ctx.open(
        &encapsulated_key,
        &recipient_sk,
        b"application-info",
        b"additional-data",
        &ciphertext,
    )?;
    println!("✓ Decrypted message");
    println!("Decrypted message: {}", String::from_utf8_lossy(&decrypted));

    assert_eq!(decrypted, message);
    println!("✓ Verification: Original and decrypted messages match");

    // Context-based operations
    println!("\n--- Context-based Operations ---");
    let mut sender_ctx = hpke_ctx.setup_sender(&recipient_pk, b"session-info")?;
    println!("✓ Setup sender context");

    // Encrypt multiple messages with the same context
    let messages = vec![
        b"First message in session".as_slice(),
        b"Second message in session".as_slice(),
        b"Third message in session".as_slice(),
    ];

    for (i, msg) in messages.iter().enumerate() {
        let ciphertext = sender_ctx.seal(b"aad", msg)?;
        println!("✓ Encrypted message {} ({} bytes)", i + 1, ciphertext.len());
    }

    // Key export
    println!("\n--- Key Export ---");
    let exported_key = sender_ctx.export(b"key-context", 32)?;
    println!("✓ Exported 32-byte key material");
    println!("  Key: {:02x?}", exported_key);

    // Test with different key sizes
    println!("\n--- Different Key Sizes ---");
    let algorithms = vec![
        (Algorithm::MlKem512, "ML-KEM-512"),
        (Algorithm::MlKem768, "ML-KEM-768"),
        (Algorithm::MlKem1024, "ML-KEM-1024"),
    ];

    for (algorithm, name) in algorithms {
        let keypair = kem_ctx.generate_keypair(algorithm, None)?;
        let pk = KemPublicKey::new(keypair.public_key().as_bytes().to_vec());
        let sk = KemSecretKey::new(keypair.secret_key().as_bytes().to_vec());

        let (enc_key, ciphertext) = hpke_ctx.seal(&pk, b"info", b"aad", b"test")?;
        let decrypted = hpke_ctx.open(&enc_key, &sk, b"info", b"aad", &ciphertext)?;

        println!(
            "✓ {}: PK={} bytes, CT={} bytes",
            name,
            keypair.public_key().as_bytes().len(),
            enc_key.len()
        );
        assert_eq!(decrypted, b"test");
    }

    println!("\n=== All tests passed! ===");
    Ok(())
}
