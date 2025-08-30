//! Example demonstrating ML-DSA usage in no_std environments
//!
//! This example shows how to use ML-DSA without std by providing randomness externally
//!
//! Run with: cargo run --example ml_dsa_no_std_example --features "lib-q-sig/ml-dsa"

use lib_q_ml_dsa::constants::{
    KEY_GENERATION_RANDOMNESS_SIZE,
    SIGNING_RANDOMNESS_SIZE,
};
use lib_q_ml_dsa::ml_dsa_65;

// In a real no_std environment, you would get randomness from:
// - Hardware random number generator
// - External entropy source
// - Deterministic seed (for testing only)
fn get_randomness() -> [u8; KEY_GENERATION_RANDOMNESS_SIZE] {
    // WARNING: This is for demonstration only!
    // In production, use a proper cryptographically secure random source
    [0u8; KEY_GENERATION_RANDOMNESS_SIZE]
}

fn get_signing_randomness() -> [u8; SIGNING_RANDOMNESS_SIZE] {
    // WARNING: This is for demonstration only!
    // In production, use a proper cryptographically secure random source
    [0u8; SIGNING_RANDOMNESS_SIZE]
}

fn main() {
    // Step 1: Generate keypair with external randomness
    let keypair_randomness = get_randomness();
    let keypair = ml_dsa_65::portable::generate_key_pair(keypair_randomness);

    println!("✅ Keypair generated successfully");
    println!(
        "Public key size: {} bytes",
        keypair.verification_key.as_slice().len()
    );
    println!(
        "Secret key size: {} bytes",
        keypair.signing_key.as_slice().len()
    );

    // Step 2: Sign a message with external randomness
    let message = b"Hello, no_std ML-DSA!";
    let signing_randomness = get_signing_randomness();

    let signature = ml_dsa_65::portable::sign(
        &keypair.signing_key,
        message,
        &[], // empty context
        signing_randomness,
    )
    .expect("Signing failed");

    println!("✅ Message signed successfully");
    println!("Signature size: {} bytes", signature.as_slice().len());

    // Step 3: Verify the signature
    let is_valid = ml_dsa_65::portable::verify(
        &keypair.verification_key,
        message,
        &[], // empty context
        &signature,
    )
    .is_ok();

    if is_valid {
        println!("✅ Signature verification successful");
    } else {
        println!("❌ Signature verification failed");
    }

    // Step 4: Demonstrate that verification fails with wrong message
    let wrong_message = b"Wrong message!";
    let is_valid_wrong = ml_dsa_65::portable::verify(
        &keypair.verification_key,
        wrong_message,
        &[], // empty context
        &signature,
    )
    .is_ok();

    if !is_valid_wrong {
        println!("✅ Correctly rejected signature for wrong message");
    } else {
        println!("❌ Incorrectly accepted signature for wrong message");
    }
}
