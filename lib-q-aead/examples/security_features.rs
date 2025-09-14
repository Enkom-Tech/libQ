//! Security Features Example for lib-q-aead
//!
//! This example demonstrates advanced security features including
//! timing attack protection, constant-time operations, and secure memory handling.

use std::time::Instant;

use lib_q_aead::security::constant_time::constant_time_eq;
use lib_q_aead::security::memory::secure_zero_slice;
use lib_q_aead::security::timing::{
    TimingProtection,
    protect_timing,
};
use lib_q_aead::security::validation::{
    validate_key,
    validate_nonce,
};
use lib_q_aead::security::{
    SecurityConfig,
    SecurityContext,
};
use lib_q_aead::{
    AeadKey,
    Algorithm,
    Nonce,
    create_aead,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("lib-q-aead Security Features Example");
    println!("====================================");

    // Create AEAD instance
    let aead = create_aead(Algorithm::Shake256Aead)
        .map_err(|e| format!("Failed to create AEAD: {}", e))?;

    // Generate test data
    let key_data = vec![
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF, 0x00,
    ];

    let nonce_data = vec![
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];

    let key = AeadKey::new(key_data);
    let nonce = Nonce::new(nonce_data);
    let plaintext = b"Secure message with timing protection";
    let associated_data = b"security metadata";

    println!("✓ Created AEAD instance and test data");

    // 1. Timing Attack Protection
    println!("\n1. Timing Attack Protection");
    println!("---------------------------");

    // Demonstrate timing protection
    let timing_protection = TimingProtection::strict();

    let start = Instant::now();
    let ciphertext = timing_protection
        .protect(|| aead.encrypt(&key, &nonce, plaintext, Some(associated_data)))?;
    let protected_time = start.elapsed();

    println!("✓ Encryption with timing protection: {:?}", protected_time);

    // Decrypt with timing protection
    let start = Instant::now();
    let decrypted = timing_protection
        .protect(|| aead.decrypt(&key, &nonce, &ciphertext, Some(associated_data)))?;
    let protected_decrypt_time = start.elapsed();

    // Verify the decryption was successful
    assert_eq!(decrypted, plaintext);

    println!(
        "✓ Decryption with timing protection: {:?}",
        protected_decrypt_time
    );

    // 2. Global Timing Protection
    println!("\n2. Global Timing Protection");
    println!("----------------------------");

    let start = Instant::now();
    let result = protect_timing(|| aead.decrypt(&key, &nonce, &ciphertext, Some(associated_data)))?;
    let global_protected_time = start.elapsed();

    println!("✓ Global timing protection: {:?}", global_protected_time);
    assert_eq!(result, plaintext);

    // 3. Security Context
    println!("\n3. Security Context");
    println!("-------------------");

    let security_config = SecurityConfig::strict();
    let security_ctx = SecurityContext::with_config(security_config);

    println!("✓ Security context created with strict configuration");
    println!(
        "  - Constant time operations: {}",
        security_ctx.constant_time_enabled()
    );
    println!(
        "  - Side channel protection: {}",
        security_ctx.side_channel_protection_enabled()
    );
    println!(
        "  - Secure memory: {}",
        security_ctx.secure_memory_enabled()
    );

    // 4. Constant-Time Operations
    println!("\n4. Constant-Time Operations");
    println!("---------------------------");

    let tag1 = vec![0x01, 0x02, 0x03, 0x04];
    let tag2 = vec![0x01, 0x02, 0x03, 0x04];
    let tag3 = vec![0x01, 0x02, 0x03, 0x05];

    let is_equal = constant_time_eq(&tag1, &tag2);
    let is_different = constant_time_eq(&tag1, &tag3);

    println!("✓ Constant-time comparison results:");
    println!("  - tag1 == tag2: {}", is_equal);
    println!("  - tag1 == tag3: {}", is_different);

    // 5. Input Validation
    println!("\n5. Input Validation");
    println!("-------------------");

    // Test valid inputs
    validate_key(key.as_bytes())?;
    validate_nonce(nonce.as_bytes())?;
    println!("✓ Valid key and nonce passed validation");

    // Test invalid inputs
    let zero_key = vec![0u8; 32];
    let all_ones_key = vec![0xFFu8; 32];
    let repeated_key = vec![0xABu8; 32];

    println!("✓ Testing invalid key rejection:");

    match validate_key(&zero_key) {
        Ok(_) => println!("  ❌ Zero key should have been rejected"),
        Err(_) => println!("  ✓ Zero key correctly rejected"),
    }

    match validate_key(&all_ones_key) {
        Ok(_) => println!("  ❌ All-ones key should have been rejected"),
        Err(_) => println!("  ✓ All-ones key correctly rejected"),
    }

    match validate_key(&repeated_key) {
        Ok(_) => println!("  ❌ Repeated pattern key should have been rejected"),
        Err(_) => println!("  ✓ Repeated pattern key correctly rejected"),
    }

    // 6. Secure Memory Handling
    println!("\n6. Secure Memory Handling");
    println!("-------------------------");

    let mut sensitive_data = vec![0x42u8; 64];
    println!("✓ Created sensitive data: {} bytes", sensitive_data.len());

    // Securely zero the data
    secure_zero_slice(&mut sensitive_data);

    // Verify it's zeroed
    let is_zeroed = sensitive_data.iter().all(|&b| b == 0);
    println!("✓ Sensitive data securely zeroed: {}", is_zeroed);

    // 7. Performance with Security Features
    println!("\n7. Performance with Security Features");
    println!("-------------------------------------");

    let iterations = 1000;
    let mut total_time = std::time::Duration::new(0, 0);

    for _ in 0..iterations {
        let start = Instant::now();
        let _ = protect_timing(|| aead.encrypt(&key, &nonce, plaintext, Some(associated_data)))?;
        total_time += start.elapsed();
    }

    let avg_time = total_time / iterations as u32;
    println!(
        "✓ Average time per operation ({} iterations): {:?}",
        iterations, avg_time
    );
    println!(
        "  - Operations per second: {:.0}",
        1_000_000_000.0 / avg_time.as_nanos() as f64
    );

    // 8. Security Configuration Comparison
    println!("\n8. Security Configuration Comparison");
    println!("------------------------------------");

    let configs = [
        ("Permissive", SecurityConfig::permissive()),
        ("Balanced", SecurityConfig::balanced()),
        ("Strict", SecurityConfig::strict()),
    ];

    for (name, config) in configs.iter() {
        let ctx = SecurityContext::with_config(*config);
        println!("✓ {} Configuration:", name);
        println!("  - Constant time: {}", ctx.constant_time_enabled());
        println!(
            "  - Side channel protection: {}",
            ctx.side_channel_protection_enabled()
        );
        println!("  - Secure memory: {}", ctx.secure_memory_enabled());
        println!("  - Timing protection: {}", ctx.timing_protection_enabled());
    }

    println!("\n🎉 All security features demonstrated successfully!");
    println!("lib-q-aead provides comprehensive security protection for your applications.");

    Ok(())
}
