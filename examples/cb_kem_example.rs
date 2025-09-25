//! CB-KEM Example for lib-Q
//!
//! This example demonstrates the usage of Classical McEliece CB-KEM with SHA3 hash function.
//! This is the default implementation using SHAKE256.

#[cfg(feature = "cb-kem")]
use lib_q_cb_kem::LibQCbKemProvider;
#[cfg(feature = "cb-kem")]
use lib_q_core::{
    Algorithm,
    KemOperations,
};

#[cfg(feature = "cb-kem")]
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    #[cfg(not(feature = "cb-kem"))]
    {
        println!("❌ CB-KEM feature not enabled!");
        println!("Run with: cargo run --example cb_kem_example --features \"cb-kem\"");
    }

    #[cfg(feature = "cb-kem")]
    {
        println!("=== lib-Q CB-KEM Example (SHA3) ===\n");

        // Create CB-KEM provider
        let provider = match LibQCbKemProvider::new() {
            Ok(p) => {
                println!("✅ CB-KEM Provider created successfully");
                println!("   Hash Function: SHAKE256 (SHA3)");
                println!("   Algorithm: CB-KEM-348864");
                p
            }
            Err(e) => {
                println!("❌ Failed to create CB-KEM provider: {e:?}");
                return;
            }
        };
        println!();

        // Generate keypair
        println!("1. Generating Keypair:");
        let keypair = match provider.generate_keypair(Algorithm::CbKem348864, None) {
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
        println!();

        // Encapsulate (generate shared secret and ciphertext)
        println!("2. Encapsulation (Generate Shared Secret):");
        let (ciphertext, shared_secret) =
            match provider.encapsulate(Algorithm::CbKem348864, &keypair.public_key, None) {
                Ok((ct, ss)) => {
                    println!("   ✅ Encapsulation successful");
                    println!("   Ciphertext Size: {} bytes", ct.len());
                    println!("   Shared Secret Size: {} bytes", ss.len());
                    println!(
                        "   Ciphertext (first 32 bytes): {}",
                        bytes_to_hex(&ct[..32.min(ct.len())])
                    );
                    println!(
                        "   Shared Secret (first 16 bytes): {}",
                        bytes_to_hex(&ss[..16.min(ss.len())])
                    );
                    (ct, ss)
                }
                Err(e) => {
                    println!("   ❌ Encapsulation failed: {e:?}");
                    return;
                }
            };
        println!();

        // Decapsulate (recover shared secret using secret key)
        println!("3. Decapsulation (Recover Shared Secret):");
        let recovered_secret =
            match provider.decapsulate(Algorithm::CbKem348864, &keypair.secret_key, &ciphertext) {
                Ok(ss) => {
                    println!("   ✅ Decapsulation successful");
                    println!("   Recovered Secret Size: {} bytes", ss.len());
                    println!(
                        "   Recovered Secret (first 16 bytes): {}",
                        bytes_to_hex(&ss[..16.min(ss.len())])
                    );
                    ss
                }
                Err(e) => {
                    println!("   ❌ Decapsulation failed: {e:?}");
                    return;
                }
            };
        println!();

        // Verify shared secrets match
        println!("4. Verification:");
        if shared_secret == recovered_secret {
            println!("   ✅ Shared secrets match! KEM cycle successful");
        } else {
            println!("   ❌ Shared secrets don't match! KEM cycle failed");
            return;
        }
        println!();

        // Test multiple encapsulations
        println!("5. Multiple Encapsulations Test:");
        let mut all_secrets_match = true;
        for i in 1..=3 {
            let (ct, ss) =
                match provider.encapsulate(Algorithm::CbKem348864, &keypair.public_key, None) {
                    Ok((ct, ss)) => (ct, ss),
                    Err(e) => {
                        println!("   ❌ Encapsulation {i} failed: {e:?}");
                        all_secrets_match = false;
                        continue;
                    }
                };

            let recovered =
                match provider.decapsulate(Algorithm::CbKem348864, &keypair.secret_key, &ct) {
                    Ok(ss) => ss,
                    Err(e) => {
                        println!("   ❌ Decapsulation {i} failed: {e:?}");
                        all_secrets_match = false;
                        continue;
                    }
                };

            if ss == recovered {
                println!("   ✅ Encapsulation {i}: Secrets match");
            } else {
                println!("   ❌ Encapsulation {i}: Secrets don't match");
                all_secrets_match = false;
            }
        }

        if all_secrets_match {
            println!("   ✅ All multiple encapsulations successful");
        } else {
            println!("   ❌ Some encapsulations failed");
        }
        println!();

        // Test different algorithms (if available)
        println!("6. Algorithm Support Test:");
        let algorithms = [
            Algorithm::CbKem348864,
            Algorithm::CbKem460896,
            Algorithm::CbKem6688128,
            Algorithm::CbKem6960119,
            Algorithm::CbKem8192128,
        ];

        for alg in algorithms {
            match provider.generate_keypair(alg, None) {
                Ok(kp) => {
                    println!(
                        "   ✅ {alg:?}: Supported (PK: {} bytes, SK: {} bytes)",
                        kp.public_key.data.len(),
                        kp.secret_key.data.len()
                    );
                }
                Err(_) => {
                    println!("   ❌ {alg:?}: Not supported or not compiled");
                }
            }
        }
        println!();

        println!("=== CB-KEM Example Complete ===");
        println!("🔐 Classical McEliece CB-KEM with SHA3 is working correctly!");
    }
}
