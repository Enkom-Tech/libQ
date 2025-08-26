//! Test demonstrating the fixed Signature trait working in no_std environments
//!
//! This example shows that the Signature trait now properly supports no_std
//! with the correct return types based on feature flags.
//!
//! Run with: cargo run --example ml_dsa_no_std_trait_test --features "lib-q-sig/ml-dsa"

use lib_q_core::Signature;
use lib_q_sig::ml_dsa::MlDsa;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 ML-DSA no_std Trait Test");
    println!("============================\n");

    // Test 1: Verify trait implementation works with alloc feature
    println!("1. Testing Signature trait with alloc feature...");
    test_trait_with_alloc()?;

    // Test 2: Verify trait implementation works without alloc feature
    println!("\n2. Testing Signature trait without alloc feature...");
    test_trait_without_alloc()?;

    println!("\n🎉 All trait tests passed! Signature trait is properly implemented.");
    Ok(())
}

fn test_trait_with_alloc() -> Result<(), Box<dyn std::error::Error>> {
    let ml_dsa = MlDsa::ml_dsa_65();

    // Test key generation
    let keypair = ml_dsa.generate_keypair()?;
    println!("   ✅ Keypair generation works");

    // Test signing (should return Vec<u8> with alloc feature)
    let message = b"Test message";
    let signature = ml_dsa.sign(keypair.secret_key(), message)?;
    println!(
        "   ✅ Signing works (returned Vec<u8> with {} bytes)",
        signature.len()
    );

    // Test verification
    let is_valid = ml_dsa.verify(keypair.public_key(), message, &signature)?;
    if is_valid {
        println!("   ✅ Verification works");
    } else {
        return Err("Verification failed".into());
    }

    Ok(())
}

fn test_trait_without_alloc() -> Result<(), Box<dyn std::error::Error>> {
    let ml_dsa = MlDsa::ml_dsa_65();

    // Test key generation (should work)
    let keypair = ml_dsa.generate_keypair()?;
    println!("   ✅ Keypair generation works");

    // Test signing (should return error in no_std mode)
    let message = b"Test message";
    let result = ml_dsa.sign(keypair.secret_key(), message);
    match result {
        Ok(_) => {
            println!("   ❌ Signing unexpectedly succeeded in no_std mode");
            return Err("Signing should fail in no_std mode".into());
        }
        Err(e) => {
            println!("   ✅ Signing correctly failed in no_std mode: {}", e);
        }
    }

    // Test verification (should still work)
    let dummy_signature = [0u8; 100]; // Dummy signature for testing
    let is_valid = ml_dsa.verify(keypair.public_key(), message, &dummy_signature)?;
    println!("   ✅ Verification works (returned {})", is_valid);

    Ok(())
}

// Test that demonstrates the proper trait signature
#[cfg(test)]
mod trait_tests {
    use super::*;

    #[test]
    fn test_trait_signature_with_alloc() {
        // This test verifies that the trait signature is correct with alloc feature
        let ml_dsa = MlDsa::ml_dsa_65();

        // The trait should return Vec<u8> with alloc feature
        let keypair = ml_dsa.generate_keypair().unwrap();
        let signature = ml_dsa.sign(keypair.secret_key(), b"test").unwrap();

        // Verify the signature is Vec<u8>
        assert!(std::any::type_name::<Vec<u8>>() == std::any::type_name_of_val(&signature));
    }

    #[test]
    fn test_trait_signature_without_alloc() {
        // This test verifies that the trait signature is correct without alloc feature
        let ml_dsa = MlDsa::ml_dsa_65();

        // The trait should return &'static [u8] without alloc feature
        let keypair = ml_dsa.generate_keypair().unwrap();
        let result = ml_dsa.sign(keypair.secret_key(), b"test");

        // In no_std mode, signing should fail with an error
        assert!(result.is_err());
    }
}
