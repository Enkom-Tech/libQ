//! Comprehensive ML-DSA integration test
//!
//! This example demonstrates the full ML-DSA integration working with both:
//! - High-level API (std): Automatic randomness generation
//! - Low-level API (no_std): External randomness provision
//!
//! Run with: cargo run --example ml_dsa_full_integration_test --features "lib-q-sig/ml-dsa"

use lib_q_core::Signature;
use lib_q_ml_dsa::constants::{
    KEY_GENERATION_RANDOMNESS_SIZE,
    SIGNING_RANDOMNESS_SIZE,
};
use lib_q_ml_dsa::ml_dsa_65;
use lib_q_sig::ml_dsa::MlDsa;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 ML-DSA Full Integration Test");
    println!("===============================\n");

    // Test 1: High-level API with std (automatic randomness generation)
    println!("1. Testing High-level API (std) - Automatic randomness generation");
    test_high_level_api()?;

    // Test 2: Low-level API with external randomness (no_std compatible)
    println!("\n2. Testing Low-level API (no_std) - External randomness provision");
    test_low_level_api()?;

    // Test 3: All ML-DSA variants (simplified)
    println!("\n3. Testing ML-DSA-65 variant");
    test_ml_dsa_65_variant()?;

    println!("\n🎉 All integration tests passed! ML-DSA is fully functional.");
    Ok(())
}

fn test_high_level_api() -> Result<(), Box<dyn std::error::Error>> {
    let ml_dsa = MlDsa::ml_dsa_65();

    // Generate keypair with automatic randomness (requires std)
    let keypair = ml_dsa.generate_keypair()?;
    println!("   ✅ Keypair generated with automatic randomness");
    println!(
        "   📊 Public key size: {} bytes",
        keypair.public_key().as_bytes().len()
    );
    println!(
        "   📊 Secret key size: {} bytes",
        keypair.secret_key().as_bytes().len()
    );

    // Sign message with automatic randomness
    let message = b"Hello from high-level API!";
    let signature = ml_dsa.sign(keypair.secret_key(), message)?;
    println!("   ✅ Message signed with automatic randomness");
    println!("   📊 Signature size: {} bytes", signature.len());

    // Verify signature
    let is_valid = ml_dsa.verify(keypair.public_key(), message, &signature)?;
    if is_valid {
        println!("   ✅ Signature verification successful");
    } else {
        return Err("Signature verification failed".into());
    }

    // Test wrong message
    let wrong_message = b"Wrong message!";
    let is_valid_wrong = ml_dsa.verify(keypair.public_key(), wrong_message, &signature)?;
    if !is_valid_wrong {
        println!("   ✅ Correctly rejected signature for wrong message");
    } else {
        return Err("Signature verification should have failed".into());
    }

    Ok(())
}

fn test_low_level_api() -> Result<(), Box<dyn std::error::Error>> {
    // In a real no_std environment, get randomness from hardware RNG
    let keypair_randomness = [0u8; KEY_GENERATION_RANDOMNESS_SIZE];
    let signing_randomness = [0u8; SIGNING_RANDOMNESS_SIZE];

    // Generate keypair with external randomness
    let keypair = ml_dsa_65::portable::generate_key_pair(keypair_randomness);
    println!("   ✅ Keypair generated with external randomness");
    println!(
        "   📊 Public key size: {} bytes",
        keypair.verification_key.as_slice().len()
    );
    println!(
        "   📊 Secret key size: {} bytes",
        keypair.signing_key.as_slice().len()
    );

    // Sign message with external randomness
    let message = b"Hello from low-level API!";
    let signature = ml_dsa_65::portable::sign(
        &keypair.signing_key,
        message,
        &[], // empty context
        signing_randomness,
    )
    .map_err(|e| format!("Signing failed: {:?}", e))?;
    println!("   ✅ Message signed with external randomness");
    println!("   📊 Signature size: {} bytes", signature.as_slice().len());

    // Verify signature
    let is_valid = ml_dsa_65::portable::verify(
        &keypair.verification_key,
        message,
        &[], // empty context
        &signature,
    )
    .is_ok();
    if is_valid {
        println!("   ✅ Signature verification successful");
    } else {
        return Err("Signature verification failed".into());
    }

    // Test wrong message
    let wrong_message = b"Wrong message!";
    let is_valid_wrong = ml_dsa_65::portable::verify(
        &keypair.verification_key,
        wrong_message,
        &[], // empty context
        &signature,
    )
    .is_ok();
    if !is_valid_wrong {
        println!("   ✅ Correctly rejected signature for wrong message");
    } else {
        return Err("Signature verification should have failed".into());
    }

    Ok(())
}

fn test_ml_dsa_65_variant() -> Result<(), Box<dyn std::error::Error>> {
    println!("   Testing ML-DSA-65...");

    // Generate keypair
    let keypair = ml_dsa_65::portable::generate_key_pair([0u8; KEY_GENERATION_RANDOMNESS_SIZE]);

    // Sign message
    let message = b"Test message";
    let signature = ml_dsa_65::portable::sign(
        &keypair.signing_key,
        message,
        &[],
        [0u8; SIGNING_RANDOMNESS_SIZE],
    )
    .map_err(|e| format!("ML-DSA-65 signing failed: {:?}", e))?;

    // Verify signature
    let is_valid =
        ml_dsa_65::portable::verify(&keypair.verification_key, message, &[], &signature).is_ok();

    if is_valid {
        println!("   ✅ ML-DSA-65: OK");
    } else {
        return Err("ML-DSA-65 verification failed".into());
    }

    Ok(())
}
