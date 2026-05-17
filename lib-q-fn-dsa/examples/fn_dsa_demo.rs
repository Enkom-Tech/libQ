//! FN-DSA Integration Demo
//!
//! This example demonstrates the complete integration of FN-DSA into the libQ
//! cryptographic library, showing how to use FN-DSA for post-quantum digital signatures.

#![allow(clippy::print_stdout, clippy::print_stderr)]

use lib_q_fn_dsa::*;

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    println!("🔐 FN-DSA Integration Demo");
    println!("========================\n");

    // Demonstrate FN-DSA Level 1 (128-bit security)
    println!("📊 FN-DSA Level 1 (128-bit security)");
    println!("------------------------------------");
    demo_fn_dsa_level1()?;

    println!();

    // Demonstrate FN-DSA Level 5 (256-bit security)
    println!("📊 FN-DSA Level 5 (256-bit security)");
    println!("------------------------------------");
    demo_fn_dsa_level5()?;

    println!();

    // Demonstrate generic FN-DSA usage
    println!("📊 Generic FN-DSA Usage");
    println!("----------------------");
    demo_generic_fn_dsa()?;

    println!();

    // Demonstrate SigKeypair functionality
    println!("🔑 SigKeypair Functionality Demo");
    println!("--------------------------------");
    demo_sig_keypair_functionality()?;

    println!();

    // Demonstrate security features
    println!("🛡️ Security Features Demo");
    println!("------------------------");
    demo_security_features()?;

    println!("\n✅ All demonstrations completed successfully!");

    Ok(())
}

fn demo_fn_dsa_level1() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let fn_dsa = FnDsa512::new();

    println!("• Security Level: {:?}", fn_dsa.security_level());
    println!("• Logn value: {}", fn_dsa.logn());

    // Generate keypair
    let keypair = fn_dsa.generate_keypair()?;
    println!("• Generated keypair successfully");

    // Display key sizes
    let (sign_size, vrfy_size, sig_size) = fn_dsa.security_level().key_sizes();
    println!("• Sign key size: {} bytes", sign_size);
    println!("• Verify key size: {} bytes", vrfy_size);
    println!("• Signature size: {} bytes", sig_size);

    // Sign and verify a message
    let message = b"Hello, FN-DSA Level 1!";
    let signature = fn_dsa.sign(&keypair.secret_key, message)?;
    println!("• Signed message successfully");

    let is_valid = fn_dsa.verify(&keypair.public_key, message, &signature)?;
    println!(
        "• Signature verification: {}",
        if is_valid { "✅ Valid" } else { "❌ Invalid" }
    );

    Ok(())
}

fn demo_fn_dsa_level5() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let fn_dsa = FnDsa1024::new();

    println!("• Security Level: {:?}", fn_dsa.security_level());
    println!("• Logn value: {}", fn_dsa.logn());

    // Generate keypair
    let keypair = fn_dsa.generate_keypair()?;
    println!("• Generated keypair successfully");

    // Display key sizes
    let (sign_size, vrfy_size, sig_size) = fn_dsa.security_level().key_sizes();
    println!("• Sign key size: {} bytes", sign_size);
    println!("• Verify key size: {} bytes", vrfy_size);
    println!("• Signature size: {} bytes", sig_size);

    // Sign and verify a message
    let message = b"Hello, FN-DSA Level 5!";
    let signature = fn_dsa.sign(&keypair.secret_key, message)?;
    println!("• Signed message successfully");

    let is_valid = fn_dsa.verify(&keypair.public_key, message, &signature)?;
    println!(
        "• Signature verification: {}",
        if is_valid { "✅ Valid" } else { "❌ Invalid" }
    );

    Ok(())
}

fn demo_generic_fn_dsa() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Create FN-DSA instances with different security levels
    let fn_dsa1 = FnDsa::level1();
    let fn_dsa5 = FnDsa::level5();

    println!("• Created FN-DSA Level 1: {:?}", fn_dsa1.security_level());
    println!("• Created FN-DSA Level 5: {:?}", fn_dsa5.security_level());

    // Demonstrate key generation for both levels
    let keypair1 = fn_dsa1.generate_keypair()?;
    let keypair5 = fn_dsa5.generate_keypair()?;

    println!("• Generated keypairs for both security levels");

    // Sign messages with both instances
    let message1 = b"Message for Level 1";
    let message5 = b"Message for Level 5";

    let sig1 = fn_dsa1.sign(&keypair1.secret_key, message1)?;
    let sig5 = fn_dsa5.sign(&keypair5.secret_key, message5)?;

    println!("• Signed messages with both instances");

    // Verify signatures
    let valid1 = fn_dsa1.verify(&keypair1.public_key, message1, &sig1)?;
    let valid5 = fn_dsa5.verify(&keypair5.public_key, message5, &sig5)?;

    println!(
        "• Level 1 verification: {}",
        if valid1 { "✅ Valid" } else { "❌ Invalid" }
    );
    println!(
        "• Level 5 verification: {}",
        if valid5 { "✅ Valid" } else { "❌ Invalid" }
    );

    Ok(())
}

fn demo_sig_keypair_functionality() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let fn_dsa = FnDsa512::new();

    // Generate a keypair
    let keypair = fn_dsa.generate_keypair()?;
    println!("• Generated SigKeypair successfully");

    // Demonstrate keypair access methods
    let public_key = keypair.public_key();
    let secret_key = keypair.secret_key();
    println!("• Accessed public and secret keys via keypair methods");

    // Show key sizes
    println!("• Public key size: {} bytes", public_key.as_bytes().len());
    println!("• Secret key size: {} bytes", secret_key.as_bytes().len());

    // Demonstrate keypair reconstruction
    let public_key_bytes = public_key.as_bytes().to_vec();
    let secret_key_bytes = secret_key.as_bytes().to_vec();
    let reconstructed_keypair = lib_q_core::SigKeypair::new(public_key_bytes, secret_key_bytes);
    println!("• Reconstructed SigKeypair from individual key bytes");

    // Test that both keypairs work identically
    let message = b"Test message for keypair functionality";

    // Sign with original keypair
    let signature1 = fn_dsa.sign(keypair.secret_key(), message)?;
    let valid1 = fn_dsa.verify(keypair.public_key(), message, &signature1)?;

    // Sign with reconstructed keypair
    let signature2 = fn_dsa.sign(reconstructed_keypair.secret_key(), message)?;
    let valid2 = fn_dsa.verify(reconstructed_keypair.public_key(), message, &signature2)?;

    println!(
        "• Original keypair verification: {}",
        if valid1 { "✅ Valid" } else { "❌ Invalid" }
    );
    println!(
        "• Reconstructed keypair verification: {}",
        if valid2 { "✅ Valid" } else { "❌ Invalid" }
    );

    // Test cross-verification (original public key should verify reconstructed signature)
    let cross_valid = fn_dsa.verify(keypair.public_key(), message, &signature2)?;
    println!(
        "• Cross-verification (original pub key + reconstructed sig): {}",
        if cross_valid {
            "✅ Valid"
        } else {
            "❌ Invalid"
        }
    );

    // Demonstrate keypair uniqueness
    let keypair2 = fn_dsa.generate_keypair()?;
    let different_public = keypair.public_key().as_bytes() != keypair2.public_key().as_bytes();
    let different_secret = keypair.secret_key().as_bytes() != keypair2.secret_key().as_bytes();
    println!(
        "• Keypair uniqueness: {}",
        if different_public && different_secret {
            "✅ Each keypair is unique"
        } else {
            "❌ Keypairs are identical"
        }
    );

    Ok(())
}

fn demo_security_features() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let fn_dsa = FnDsa512::new();
    let keypair = fn_dsa.generate_keypair()?;

    // Test signature uniqueness
    let message = b"Security test message";
    let sig1 = fn_dsa.sign(&keypair.secret_key, message)?;
    let sig2 = fn_dsa.sign(&keypair.secret_key, message)?;

    println!(
        "• Signature uniqueness: {}",
        if sig1 != sig2 {
            "✅ Signatures are unique"
        } else {
            "❌ Signatures are identical"
        }
    );

    // Test message tampering detection
    let tampered_message = b"Tampered message";
    let is_valid = fn_dsa.verify(&keypair.public_key, tampered_message, &sig1)?;
    println!(
        "• Tampering detection: {}",
        if !is_valid {
            "✅ Tampering detected"
        } else {
            "❌ Tampering not detected"
        }
    );

    // Test empty message handling
    let empty_sig = fn_dsa.sign(&keypair.secret_key, b"")?;
    let empty_valid = fn_dsa.verify(&keypair.public_key, b"", &empty_sig)?;
    println!(
        "• Empty message support: {}",
        if empty_valid {
            "✅ Empty messages supported"
        } else {
            "❌ Empty messages not supported"
        }
    );

    // Test large message handling
    let large_message = vec![0u8; 1024 * 1024]; // 1MB message
    let large_sig = fn_dsa.sign(&keypair.secret_key, &large_message)?;
    let large_valid = fn_dsa.verify(&keypair.public_key, &large_message, &large_sig)?;
    println!(
        "• Large message support: {}",
        if large_valid {
            "✅ Large messages supported"
        } else {
            "❌ Large messages not supported"
        }
    );

    Ok(())
}
