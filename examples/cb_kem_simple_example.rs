//! Simple CB-KEM Example for lib-Q
//!
//! This is a minimal example to test CB-KEM functionality without hanging.
//!
//! Run: `cargo run -p lib-q-examples --example cb_kem_simple_example` (package default enables `cb-kem`).

#[cfg(feature = "cb-kem")]
use lib_q_cb_kem::LibQCbKemProvider;
#[cfg(feature = "cb-kem")]
use lib_q_core::{
    Algorithm,
    KemOperations,
};

fn main() {
    #[cfg(not(feature = "cb-kem"))]
    {
        println!("❌ CB-KEM feature not enabled!");
        println!("Enable the package `cb-kem` feature (on by default), e.g.:");
        println!("  cargo run -p lib-q-examples --example cb_kem_simple_example --features cb-kem");
    }

    #[cfg(feature = "cb-kem")]
    {
        println!("=== Simple CB-KEM Test ===\n");

        // Create CB-KEM provider with entropy validation disabled for testing
        let mut provider = match LibQCbKemProvider::new() {
            Ok(p) => {
                println!("✅ CB-KEM Provider created successfully");
                p
            }
            Err(e) => {
                println!("❌ Failed to create CB-KEM provider: {e:?}");
                return;
            }
        };

        // For this example, we'll use deterministic randomness for reproducible testing
        // In production, you should use None for randomness to get secure system entropy
        println!("   Note: Using deterministic randomness for reproducible testing");
        println!("   In production, use None for randomness parameter to get secure entropy");

        // For testing with deterministic randomness, disable entropy validation
        // This allows deterministic seeds to pass validation
        provider
            .security_validator_mut()
            .entropy_validator_mut()
            .set_entropy_validation(false);

        // Generate keypair with deterministic randomness
        println!("1. Generating Keypair...");
        let deterministic_seed = b"cb_kem_test_seed_2024_secure_randomness_for_testing_purposes_only_abcdefghijklmnopqrstuvwxyz1234567890";
        let keypair =
            match provider.generate_keypair(Algorithm::CbKem348864, Some(deterministic_seed)) {
                Ok(kp) => {
                    println!("   ✅ Keypair generated successfully");
                    println!("   Public Key Size: {} bytes", kp.public_key.data.len());
                    println!("   Secret Key Size: {} bytes", kp.secret_key.data.len());
                    kp
                }
                Err(e) => {
                    println!("   ❌ Keypair generation failed: {e:?}");
                    return;
                }
            };

        // Test encapsulation with deterministic randomness to avoid hanging
        println!("2. Testing Encapsulation...");
        println!("   (Using deterministic randomness to avoid hanging)");

        let deterministic_seed = b"cb_kem_test_seed_2024_secure_randomness_for_testing_purposes_only_abcdefghijklmnopqrstuvwxyz1234567890";
        let start = std::time::Instant::now();
        let (ciphertext, shared_secret) = match provider.encapsulate(
            Algorithm::CbKem348864,
            &keypair.public_key,
            Some(deterministic_seed),
        ) {
            Ok((ct, ss)) => {
                let elapsed = start.elapsed();
                println!("   ✅ Encapsulation successful in {:?}", elapsed);
                println!("   Ciphertext Size: {} bytes", ct.len());
                println!("   Shared Secret Size: {} bytes", ss.len());
                (ct, ss)
            }
            Err(e) => {
                let elapsed = start.elapsed();
                println!("   ❌ Encapsulation failed after {:?}: {e:?}", elapsed);
                return;
            }
        };

        // Test decapsulation
        println!("3. Testing Decapsulation...");
        let start = std::time::Instant::now();
        let recovered_secret =
            match provider.decapsulate(Algorithm::CbKem348864, &keypair.secret_key, &ciphertext) {
                Ok(ss) => {
                    let elapsed = start.elapsed();
                    println!("   ✅ Decapsulation successful in {:?}", elapsed);
                    println!("   Recovered Secret Size: {} bytes", ss.len());
                    ss
                }
                Err(e) => {
                    let elapsed = start.elapsed();
                    println!("   ❌ Decapsulation failed after {:?}: {e:?}", elapsed);
                    return;
                }
            };

        // Verify shared secrets match
        println!("4. Verification:");
        if shared_secret == recovered_secret {
            println!("   ✅ Shared secrets match! KEM cycle successful");
        } else {
            println!("   ❌ Shared secrets don't match! KEM cycle failed");
            return;
        }

        println!("\n=== Simple CB-KEM Test Complete ===");
        println!("🔐 CB-KEM is working correctly!");
    }
}
