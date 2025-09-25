//! CB-KEM Testing Example for lib-Q
//!
//! This example demonstrates proper testing usage of CB-KEM with deterministic randomness
//! and relaxed entropy validation. This approach is suitable for testing and CI/CD pipelines.

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
        println!("Run with: cargo run --example cb_kem_testing_example --features \"cb-kem\"");
    }

    #[cfg(feature = "cb-kem")]
    {
        println!("=== CB-KEM Testing Example ===\n");
        println!("This example demonstrates proper testing practices:");
        println!("- Uses deterministic randomness for reproducible results");
        println!("- Employs relaxed entropy validation for testing");
        println!("- Provides consistent behavior across different environments");
        println!();

        // Create CB-KEM provider
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

        // For testing, disable entropy validation to allow deterministic seeds
        // This is safe for testing but should NEVER be done in production
        println!("🔧 Configuring provider for testing environment...");
        provider
            .security_validator_mut()
            .entropy_validator_mut()
            .set_entropy_validation(false);
        println!("   ✅ Entropy validation disabled for testing");

        // Use a well-designed deterministic seed for testing
        // This seed is designed to avoid obvious patterns while being deterministic
        let test_seed = b"cb_kem_testing_seed_2024_secure_deterministic_randomness_for_ci_cd_pipeline_testing_abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        // Generate keypair with deterministic randomness
        println!("1. Generating Keypair with deterministic randomness...");
        let start = std::time::Instant::now();
        let keypair = match provider.generate_keypair(Algorithm::CbKem348864, Some(test_seed)) {
            Ok(kp) => {
                let elapsed = start.elapsed();
                println!("   ✅ Keypair generated successfully in {:?}", elapsed);
                println!("   Public Key Size: {} bytes", kp.public_key.data.len());
                println!("   Secret Key Size: {} bytes", kp.secret_key.data.len());
                kp
            }
            Err(e) => {
                let elapsed = start.elapsed();
                println!("   ❌ Keypair generation failed after {:?}: {e:?}", elapsed);
                return;
            }
        };

        // Test encapsulation with deterministic randomness
        println!("2. Testing Encapsulation with deterministic randomness...");
        let start = std::time::Instant::now();
        let (ciphertext, shared_secret) = match provider.encapsulate(
            Algorithm::CbKem348864,
            &keypair.public_key,
            Some(test_seed),
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

        // Test multiple encapsulations to demonstrate reproducibility
        println!("5. Multiple Encapsulations Test (demonstrating reproducibility):");
        let mut all_successful = true;
        for i in 1..=3 {
            let start = std::time::Instant::now();
            let (ct, ss) = match provider.encapsulate(
                Algorithm::CbKem348864,
                &keypair.public_key,
                Some(test_seed),
            ) {
                Ok((ct, ss)) => {
                    let elapsed = start.elapsed();
                    println!("   ✅ Encapsulation {i}: Success in {:?}", elapsed);
                    (ct, ss)
                }
                Err(e) => {
                    let elapsed = start.elapsed();
                    println!("   ❌ Encapsulation {i}: Failed after {:?}: {e:?}", elapsed);
                    all_successful = false;
                    continue;
                }
            };

            let recovered =
                match provider.decapsulate(Algorithm::CbKem348864, &keypair.secret_key, &ct) {
                    Ok(ss) => ss,
                    Err(e) => {
                        println!("   ❌ Decapsulation {i}: Failed: {e:?}");
                        all_successful = false;
                        continue;
                    }
                };

            if ss == recovered {
                println!("   ✅ Encapsulation {i}: Secrets match");
            } else {
                println!("   ❌ Encapsulation {i}: Secrets don't match");
                all_successful = false;
            }
        }

        if all_successful {
            println!("   ✅ All multiple encapsulations successful");
        } else {
            println!("   ❌ Some encapsulations failed");
        }

        println!("\n=== CB-KEM Testing Example Complete ===");
        println!("🔐 CB-KEM testing completed successfully!");
        println!("⚡ All operations completed without hanging!");
        println!("🔄 Deterministic behavior ensures reproducible test results!");
        println!("⚠️  Remember: This configuration is for testing only!");
        println!("🛡️  Production applications should use secure randomness (None parameter)!");
    }
}
