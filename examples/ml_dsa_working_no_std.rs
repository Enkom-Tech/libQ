//! Working example demonstrating ML-DSA usage in no_std environments
//!
//! This example shows how to use ML-DSA without std by using the low-level API directly,
//! bypassing the flawed trait definition in lib-q-core.

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 ML-DSA no_std Example");
    println!("========================\n");

    // Step 1: Generate keypair with external randomness
    println!("1. Generating keypair with external randomness...");
    let keypair_randomness = get_randomness();
    let keypair = ml_dsa_65::portable::generate_key_pair(keypair_randomness);

    println!("   ✅ Keypair generated successfully");
    println!(
        "   📊 Public key size: {} bytes",
        keypair.verification_key.as_slice().len()
    );
    println!(
        "   📊 Secret key size: {} bytes",
        keypair.signing_key.as_slice().len()
    );

    // Step 2: Sign a message with external randomness
    println!("\n2. Signing message with external randomness...");
    let message = b"Hello, no_std ML-DSA!";
    let signing_randomness = get_signing_randomness();

    let signature = ml_dsa_65::portable::sign(
        &keypair.signing_key,
        message,
        &[], // empty context
        signing_randomness,
    )
    .expect("Signing failed");

    println!("   ✅ Message signed successfully");
    println!("   📊 Signature size: {} bytes", signature.as_slice().len());
    println!("   📝 Message: {}", String::from_utf8_lossy(message));

    // Step 3: Verify the signature
    println!("\n3. Verifying signature...");
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
        println!("   ❌ Signature verification failed");
        return Err("Signature verification failed".into());
    }

    // Step 4: Demonstrate that verification fails with wrong message
    println!("\n4. Testing signature verification with wrong message...");
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
        println!("   ❌ Incorrectly accepted signature for wrong message");
        return Err("Signature verification should have failed".into());
    }

    // Step 5: Test all ML-DSA variants
    println!("\n5. Testing all ML-DSA variants...");
    test_all_variants()?;

    println!("\n🎉 All tests passed! ML-DSA no_std implementation is working correctly.");
    Ok(())
}

fn test_all_variants() -> Result<(), Box<dyn std::error::Error>> {
    use lib_q_ml_dsa::{
        ml_dsa_44,
        ml_dsa_87,
    };

    // Test ML-DSA-44
    println!("   Testing ML-DSA-44...");
    let keypair_44 = ml_dsa_44::portable::generate_key_pair([0u8; KEY_GENERATION_RANDOMNESS_SIZE]);
    let signature_44 = ml_dsa_44::portable::sign(
        &keypair_44.signing_key,
        b"Test message",
        &[],
        [0u8; SIGNING_RANDOMNESS_SIZE],
    )
    .map_err(|e| format!("ML-DSA-44 signing failed: {:?}", e))?;
    let valid_44 = ml_dsa_44::portable::verify(
        &keypair_44.verification_key,
        b"Test message",
        &[],
        &signature_44,
    )
    .is_ok();
    assert!(valid_44, "ML-DSA-44 verification failed");
    println!("   ✅ ML-DSA-44: OK");

    // Test ML-DSA-65 (already tested above)
    println!("   ✅ ML-DSA-65: OK");

    // Test ML-DSA-87
    println!("   Testing ML-DSA-87...");
    let keypair_87 = ml_dsa_87::portable::generate_key_pair([0u8; KEY_GENERATION_RANDOMNESS_SIZE]);
    let signature_87 = ml_dsa_87::portable::sign(
        &keypair_87.signing_key,
        b"Test message",
        &[],
        [0u8; SIGNING_RANDOMNESS_SIZE],
    )
    .map_err(|e| format!("ML-DSA-87 signing failed: {:?}", e))?;
    let valid_87 = ml_dsa_87::portable::verify(
        &keypair_87.verification_key,
        b"Test message",
        &[],
        &signature_87,
    )
    .is_ok();
    assert!(valid_87, "ML-DSA-87 verification failed");
    println!("   ✅ ML-DSA-87: OK");

    Ok(())
}

// Example of how to implement a proper hardware RNG for embedded systems
// This is a demonstration of how you would implement hardware RNG in a real embedded system
#[allow(dead_code)]
mod embedded_example {
    use lib_q_ml_dsa::constants::{
        KEY_GENERATION_RANDOMNESS_SIZE,
        SIGNING_RANDOMNESS_SIZE,
    };
    use lib_q_ml_dsa::ml_dsa_65;

    // Hardware RNG implementation for embedded systems
    pub struct HardwareRng;

    impl HardwareRng {
        pub fn new() -> Self {
            Self
        }

        pub fn get_random_bytes(&self, dest: &mut [u8]) {
            // Implementation depends on the specific hardware
            // This could be:
            // - TRNG (True Random Number Generator)
            // - DRBG (Deterministic Random Bit Generator)
            // - External entropy source
            for byte in dest.iter_mut() {
                *byte = self.read_hardware_entropy();
            }
        }

        fn read_hardware_entropy(&self) -> u8 {
            // Read from hardware entropy source
            // This is platform-specific
            // For example, on ARM Cortex-M:
            // unsafe { core::ptr::read_volatile(0x4000_0000 as *const u8) }
            0 // Placeholder
        }
    }

    pub fn embedded_ml_dsa_example() -> Result<(), Box<dyn std::error::Error>> {
        let rng = HardwareRng::new();

        // Generate randomness for key generation
        let mut keypair_randomness = [0u8; KEY_GENERATION_RANDOMNESS_SIZE];
        rng.get_random_bytes(&mut keypair_randomness);

        // Generate keypair
        let keypair = ml_dsa_65::portable::generate_key_pair(keypair_randomness);

        // Generate randomness for signing
        let mut signing_randomness = [0u8; SIGNING_RANDOMNESS_SIZE];
        rng.get_random_bytes(&mut signing_randomness);

        // Sign message
        let message = b"Secure message from embedded device";
        let signature = ml_dsa_65::portable::sign(
            &keypair.signing_key,
            message,
            &[], // empty context
            signing_randomness,
        )
        .map_err(|e| format!("Signing failed: {:?}", e))?;

        // Verify signature
        let is_valid = ml_dsa_65::portable::verify(
            &keypair.verification_key,
            message,
            &[], // empty context
            &signature,
        )
        .is_ok();

        if is_valid {
            println!("✅ Embedded ML-DSA verification successful");
        } else {
            println!("❌ Embedded ML-DSA verification failed");
        }

        Ok(())
    }
}
