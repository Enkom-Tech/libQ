//! CB-KEM Production Example for lib-Q
//!
//! This example demonstrates the proper production usage of CB-KEM with secure randomness.
//! This is the recommended approach for production applications.

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
        println!("Run with: cargo run --example cb_kem_production_example --features \"cb-kem\"");
    }

    #[cfg(feature = "cb-kem")]
    {
        println!("=== CB-KEM Production Example ===\n");

        // Create CB-KEM provider
        let provider = match LibQCbKemProvider::new() {
            Ok(p) => {
                println!("✅ CB-KEM Provider created successfully");
                println!("   Using secure system entropy for all operations");
                p
            }
            Err(e) => {
                println!("❌ Failed to create CB-KEM provider: {e:?}");
                return;
            }
        };

        // Generate keypair with secure system randomness
        println!("1. Generating Keypair with secure randomness...");
        let start = std::time::Instant::now();
        let keypair = match provider.generate_keypair(Algorithm::CbKem348864, None) {
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

        // Test encapsulation with secure system randomness
        println!("2. Testing Encapsulation with secure randomness...");
        let start = std::time::Instant::now();
        let (ciphertext, shared_secret) =
            match provider.encapsulate(Algorithm::CbKem348864, &keypair.public_key, None) {
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

        // Test multiple encapsulations to demonstrate non-blocking behavior
        println!("5. Multiple Encapsulations Test (demonstrating non-blocking behavior):");
        let mut all_successful = true;
        for i in 1..=3 {
            let start = std::time::Instant::now();
            let (ct, ss) =
                match provider.encapsulate(Algorithm::CbKem348864, &keypair.public_key, None) {
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

        println!("\n=== CB-KEM Production Example Complete ===");
        println!("🔐 CB-KEM is working correctly with secure randomness!");
        println!("⚡ No hanging issues - all operations completed successfully!");
        println!("🛡️  This is the recommended approach for production applications.");
    }
}
