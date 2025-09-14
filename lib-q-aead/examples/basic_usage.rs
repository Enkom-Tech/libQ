//! Basic Usage Example for lib-q-aead
//!
//! This example demonstrates basic encryption and decryption operations
//! using the SHAKE256 AEAD implementation.

use lib_q_aead::security::validation::{
    validate_key,
    validate_nonce,
};
use lib_q_aead::{
    AeadKey,
    Algorithm,
    Nonce,
    create_aead,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("lib-q-aead Basic Usage Example");
    println!("==============================");

    // Create an AEAD instance
    let aead = create_aead(Algorithm::Shake256Aead)
        .map_err(|e| format!("Failed to create AEAD: {}", e))?;

    println!("✓ Created SHAKE256 AEAD instance");

    // Generate secure key and nonce (in practice, use proper random generation)
    let key_data = vec![
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF, 0x00,
    ];

    let nonce_data = vec![
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];

    // Validate key and nonce
    validate_key(&key_data)?;
    validate_nonce(&nonce_data)?;

    let key = AeadKey::new(key_data);
    let nonce = Nonce::new(nonce_data);

    println!("✓ Generated and validated key and nonce");

    // Data to encrypt
    let plaintext = b"Hello, World! This is a test message for lib-q-aead.";
    let associated_data = b"metadata: example usage";

    println!("Plaintext: {}", String::from_utf8_lossy(plaintext));
    println!(
        "Associated Data: {}",
        String::from_utf8_lossy(associated_data)
    );

    // Encrypt
    let ciphertext = aead
        .encrypt(&key, &nonce, plaintext, Some(associated_data))
        .map_err(|e| format!("Encryption failed: {}", e))?;

    println!("✓ Encryption successful");
    println!("Ciphertext length: {} bytes", ciphertext.len());
    println!("Ciphertext (hex): {}", hex::encode(&ciphertext));

    // Decrypt
    let decrypted = aead
        .decrypt(&key, &nonce, &ciphertext, Some(associated_data))
        .map_err(|e| format!("Decryption failed: {}", e))?;

    println!("✓ Decryption successful");
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));

    // Verify
    if decrypted == plaintext {
        println!("✓ Verification successful - data integrity maintained");
    } else {
        return Err("Verification failed - data corruption detected".into());
    }

    // Demonstrate authentication failure
    println!("\nTesting authentication failure...");
    let mut tampered_ciphertext = ciphertext.clone();
    tampered_ciphertext[0] ^= 0xFF; // Tamper with first byte

    let tampered_result = aead.decrypt(&key, &nonce, &tampered_ciphertext, Some(associated_data));
    match tampered_result {
        Ok(_) => return Err("Authentication should have failed but didn't".into()),
        Err(_) => println!("✓ Authentication correctly rejected tampered data"),
    }

    // Demonstrate wrong key
    println!("\nTesting wrong key...");
    let wrong_key_data = vec![0xFF; 32];
    let wrong_key = AeadKey::new(wrong_key_data);

    let wrong_key_result = aead.decrypt(&wrong_key, &nonce, &ciphertext, Some(associated_data));
    match wrong_key_result {
        Ok(_) => return Err("Wrong key should have failed but didn't".into()),
        Err(_) => println!("✓ Wrong key correctly rejected"),
    }

    // Demonstrate wrong nonce
    println!("\nTesting wrong nonce...");
    let wrong_nonce_data = vec![0xFF; 16];
    let wrong_nonce = Nonce::new(wrong_nonce_data);

    let wrong_nonce_result = aead.decrypt(&key, &wrong_nonce, &ciphertext, Some(associated_data));
    match wrong_nonce_result {
        Ok(_) => return Err("Wrong nonce should have failed but didn't".into()),
        Err(_) => println!("✓ Wrong nonce correctly rejected"),
    }

    println!("\n🎉 All tests passed! lib-q-aead is working correctly.");
    Ok(())
}
