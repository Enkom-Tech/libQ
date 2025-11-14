//! DRBG Interoperability Test Suite
//!
//! This module provides comprehensive testing for DRBG interoperability between
//! the Rust AES and BearSSL AES implementations.

#[cfg(all(
    feature = "aes-drbg",
    feature = "bearssl-aes",
    feature = "debug-drbg-interop"
))]
use lib_q_hqc::aes_ctr_drbg::Aes256CtrDrbg;
#[cfg(all(
    feature = "aes-drbg",
    feature = "bearssl-aes",
    feature = "debug-drbg-interop"
))]
use lib_q_hqc::bearssl_aes_ctr_drbg::BearSslAes256CtrDrbg;
#[cfg(all(
    feature = "aes-drbg",
    feature = "bearssl-aes",
    feature = "debug-drbg-interop"
))]
use lib_q_hqc::drbg_diagnostic::DualModeDrbg;
#[cfg(all(
    feature = "aes-drbg",
    feature = "bearssl-aes",
    feature = "debug-drbg-interop"
))]
use lib_q_hqc::hqc_pke::HqcPke;
#[cfg(all(
    feature = "aes-drbg",
    feature = "bearssl-aes",
    feature = "debug-drbg-interop"
))]
use lib_q_hqc::params_correct::Hqc1Params;
#[cfg(all(
    feature = "aes-drbg",
    feature = "bearssl-aes",
    feature = "debug-drbg-interop"
))]
use rand_core::RngCore;

#[cfg(all(
    feature = "aes-drbg",
    feature = "bearssl-aes",
    feature = "debug-drbg-interop"
))]
#[test]
fn test_drbg_interop_with_logging() {
    println!("=== DRBG Interoperability Test with Diagnostic Logging ===");

    let kat_seed = [
        0x06, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE, 0x04, 0xEF, 0x7A,
        0x25, 0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79, 0xD0, 0x9D, 0x86, 0xDC, 0x9A, 0xBC,
        0xFD, 0xE7, 0x05, 0x6A, 0x8C, 0x26, 0x6F, 0x9E, 0xF9, 0x7E, 0xD0, 0x85, 0x41, 0xDB, 0xD2,
        0xE1, 0xFF, 0xA1,
    ];

    // Create dual-mode DRBG for diagnostic logging
    let bearssl_rng = BearSslAes256CtrDrbg::instantiate(&kat_seed);
    let rust_rng = Aes256CtrDrbg::instantiate(&kat_seed);
    let mut dual_rng = DualModeDrbg::new(bearssl_rng, rust_rng);

    // Generate multiple outputs to capture differences
    let mut outputs = Vec::new();
    for i in 0..5 {
        let mut output = [0u8; 32];
        dual_rng.fill_bytes(&mut output);
        outputs.push(output);
        println!("Generated output #{}: {:02x?}", i + 1, output);
    }

    // Print diagnostic logs
    println!("\n=== Diagnostic Logs ===");
    for log in dual_rng.get_logs() {
        println!("{}", log);
    }

    // Check if any differences were logged
    let has_differences = !dual_rng.get_logs().is_empty();
    println!("\n=== Summary ===");
    println!("Differences detected: {}", has_differences);

    if has_differences {
        println!("❌ DRBG implementations produce different output");
        println!("This confirms the interoperability issue identified in previous analysis");
    } else {
        println!("✅ DRBG implementations produce identical output");
    }
}

#[cfg(all(
    feature = "aes-drbg",
    feature = "bearssl-aes",
    feature = "debug-drbg-interop"
))]
#[test]
fn test_internal_state_divergence() {
    println!("=== Internal State Divergence Test ===");

    let kat_seed = [
        0x06, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE, 0x04, 0xEF, 0x7A,
        0x25, 0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79, 0xD0, 0x9D, 0x86, 0xDC, 0x9A, 0xBC,
        0xFD, 0xE7, 0x05, 0x6A, 0x8C, 0x26, 0x6F, 0x9E, 0xF9, 0x7E, 0xD0, 0x85, 0x41, 0xDB, 0xD2,
        0xE1, 0xFF, 0xA1,
    ];

    // Test with different output sizes to see state divergence patterns
    let sizes = [16, 32, 48, 64, 128];

    for size in sizes {
        println!("\n--- Testing {} byte output ---", size);

        let bearssl_rng = BearSslAes256CtrDrbg::instantiate(&kat_seed);
        let rust_rng = Aes256CtrDrbg::instantiate(&kat_seed);
        let mut dual_rng = DualModeDrbg::new(bearssl_rng, rust_rng);

        let mut output = vec![0u8; size];
        dual_rng.fill_bytes(&mut output);

        println!("Output: {:02x?}", &output[..core::cmp::min(16, size)]);

        // Check for differences in this generation
        let logs = dual_rng.get_logs();
        if !logs.is_empty() {
            println!("State divergence detected:");
            for log in logs {
                println!("  {}", log);
            }
        } else {
            println!("No state divergence detected");
        }
    }
}

#[cfg(all(
    feature = "aes-drbg",
    feature = "bearssl-aes",
    feature = "debug-drbg-interop"
))]
#[test]
fn test_ctr_drbg_update_differences() {
    println!("=== CTR_DRBG_Update Differences Analysis ===");

    let kat_seed = [
        0x06, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE, 0x04, 0xEF, 0x7A,
        0x25, 0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79, 0xD0, 0x9D, 0x86, 0xDC, 0x9A, 0xBC,
        0xFD, 0xE7, 0x05, 0x6A, 0x8C, 0x26, 0x6F, 0x9E, 0xF9, 0x7E, 0xD0, 0x85, 0x41, 0xDB, 0xD2,
        0xE1, 0xFF, 0xA1,
    ];

    // Test sequential generations to analyze state update patterns
    let bearssl_rng = BearSslAes256CtrDrbg::instantiate(&kat_seed);
    let rust_rng = Aes256CtrDrbg::instantiate(&kat_seed);
    let mut dual_rng = DualModeDrbg::new(bearssl_rng, rust_rng);

    println!("Testing sequential 32-byte generations:");

    for i in 0..10 {
        let mut output = [0u8; 32];
        dual_rng.fill_bytes(&mut output);

        let logs = dual_rng.get_logs();
        if !logs.is_empty() {
            println!("Generation #{}: Divergence detected", i + 1);
            for log in logs {
                println!("  {}", log);
            }
            break; // Stop at first divergence
        } else {
            println!("Generation #{}: No divergence", i + 1);
        }
    }
}

#[cfg(all(
    feature = "aes-drbg",
    feature = "bearssl-aes",
    feature = "debug-drbg-interop"
))]
#[test]
fn test_kat_seed_compatibility() {
    println!("=== KAT Seed Compatibility Test ===");

    // Test with the exact KAT seed from the official test vectors
    let kat_seed = [
        0x06, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE, 0x04, 0xEF, 0x7A,
        0x25, 0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79, 0xD0, 0x9D, 0x86, 0xDC, 0x9A, 0xBC,
        0xFD, 0xE7, 0x05, 0x6A, 0x8C, 0x26, 0x6F, 0x9E, 0xF9, 0x7E, 0xD0, 0x85, 0x41, 0xDB, 0xD2,
        0xE1, 0xFF, 0xA1,
    ];

    // Expected values from KAT (first two 32-byte generations)
    let expected_seed_dk = [
        0x7C, 0x99, 0x35, 0xA0, 0xB0, 0x76, 0x94, 0xAA, 0x0C, 0x6D, 0x10, 0xE4, 0xDB, 0x6B, 0x1A,
        0xDD, 0x2F, 0xD8, 0x1A, 0x25, 0xCC, 0xB1, 0x48, 0x03, 0x2D, 0xCD, 0x73, 0x99, 0x36, 0x73,
        0x7F, 0x2D,
    ];
    let expected_seed_ek = [
        0x74, 0xB2, 0xD3, 0x52, 0xCF, 0x74, 0xC9, 0x34, 0x06, 0x9C, 0x9D, 0xE7, 0x47, 0x57, 0xF5,
        0x05, 0x66, 0xFE, 0x46, 0xF7, 0xE1, 0x22, 0x24, 0x3C, 0x90, 0xC3, 0x0A, 0xDE, 0xBB, 0x0E,
        0x3D, 0xB3,
    ];

    let bearssl_rng = BearSslAes256CtrDrbg::instantiate(&kat_seed);
    let rust_rng = Aes256CtrDrbg::instantiate(&kat_seed);
    let mut dual_rng = DualModeDrbg::new(bearssl_rng, rust_rng);

    // Generate first 32 bytes (seed_dk)
    let mut seed_dk = [0u8; 32];
    dual_rng.fill_bytes(&mut seed_dk);

    // Generate second 32 bytes (seed_ek)
    let mut seed_ek = [0u8; 32];
    dual_rng.fill_bytes(&mut seed_ek);

    println!("Generated seed_dk: {:02x?}", seed_dk);
    println!("Expected seed_dk:  {:02x?}", expected_seed_dk);
    println!("seed_dk matches:   {}", seed_dk == expected_seed_dk);

    println!("\nGenerated seed_ek: {:02x?}", seed_ek);
    println!("Expected seed_ek:  {:02x?}", expected_seed_ek);
    println!("seed_ek matches:   {}", seed_ek == expected_seed_ek);

    // Print diagnostic logs
    println!("\n=== Diagnostic Logs ===");
    for log in dual_rng.get_logs() {
        println!("{}", log);
    }

    // Analysis
    println!("\n=== Analysis ===");
    if seed_dk == expected_seed_dk && seed_ek == expected_seed_ek {
        println!("✅ Both implementations match KAT exactly");
    } else if seed_dk == expected_seed_dk {
        println!("⚠️  seed_dk matches KAT, but seed_ek does not");
        println!("   This confirms the issue identified in previous analysis");
    } else {
        println!("❌ Neither seed_dk nor seed_ek matches KAT");
        println!("   This indicates a fundamental DRBG implementation difference");
    }
}

#[cfg(all(
    feature = "aes-drbg",
    feature = "bearssl-aes",
    feature = "debug-drbg-interop"
))]
#[test]
fn test_hqc_keygen_with_diagnostic_mode() {
    println!("=== HQC Keygen with Diagnostic Mode ===");

    let kat_seed = [
        0x06, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE, 0x04, 0xEF, 0x7A,
        0x25, 0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79, 0xD0, 0x9D, 0x86, 0xDC, 0x9A, 0xBC,
        0xFD, 0xE7, 0x05, 0x6A, 0x8C, 0x26, 0x6F, 0x9E, 0xF9, 0x7E, 0xD0, 0x85, 0x41, 0xDB, 0xD2,
        0xE1, 0xFF, 0xA1,
    ];

    let pke = HqcPke::<Hqc1Params>::new().unwrap();

    // Generate keypair using diagnostic mode
    let (pk, sk) = pke.keygen_with_seed(&kat_seed).unwrap();

    println!("Generated public key: {:02x?}", &pk.as_bytes()[..16]);
    println!("Generated secret key: {:02x?}", &sk.data[..16]);

    // Note: The actual diagnostic logs would be captured by the DualModeDrbg
    // inside the keygen_with_seed call, but we can't access them directly here
    // since they're internal to the DRBG wrapper.

    println!("✅ Key generation completed with diagnostic mode");
    println!("   (Diagnostic logs are captured internally by DualModeDrbg)");
}

#[cfg(all(
    feature = "aes-drbg",
    feature = "bearssl-aes",
    feature = "debug-drbg-interop"
))]
#[test]
fn test_block_boundary_handling() {
    println!("=== Block Boundary Handling Test ===");

    let kat_seed = [
        0x06, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE, 0x04, 0xEF, 0x7A,
        0x25, 0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79, 0xD0, 0x9D, 0x86, 0xDC, 0x9A, 0xBC,
        0xFD, 0xE7, 0x05, 0x6A, 0x8C, 0x26, 0x6F, 0x9E, 0xF9, 0x7E, 0xD0, 0x85, 0x41, 0xDB, 0xD2,
        0xE1, 0xFF, 0xA1,
    ];

    // Test various sizes that cross AES block boundaries (16 bytes)
    let test_sizes = [1, 15, 16, 17, 31, 32, 33, 47, 48, 49, 63, 64, 65];

    for size in test_sizes {
        println!(
            "\n--- Testing {} byte output (block boundary: {}) ---",
            size,
            size % 16 == 0
        );

        let bearssl_rng = BearSslAes256CtrDrbg::instantiate(&kat_seed);
        let rust_rng = Aes256CtrDrbg::instantiate(&kat_seed);
        let mut dual_rng = DualModeDrbg::new(bearssl_rng, rust_rng);

        let mut output = vec![0u8; size];
        dual_rng.fill_bytes(&mut output);

        let logs = dual_rng.get_logs();
        if !logs.is_empty() {
            println!("Block boundary divergence detected:");
            for log in logs {
                println!("  {}", log);
            }
        } else {
            println!("No block boundary divergence");
        }
    }
}

#[cfg(all(
    feature = "aes-drbg",
    feature = "bearssl-aes",
    feature = "debug-drbg-interop"
))]
#[test]
fn test_multiple_seed_variations() {
    println!("=== Multiple Seed Variations Test ===");

    let test_seeds = [
        // KAT seed
        [
            0x06, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE, 0x04, 0xEF,
            0x7A, 0x25, 0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79, 0xD0, 0x9D, 0x86, 0xDC,
            0x9A, 0xBC, 0xFD, 0xE7, 0x05, 0x6A, 0x8C, 0x26, 0x6F, 0x9E, 0xF9, 0x7E, 0xD0, 0x85,
            0x41, 0xDB, 0xD2, 0xE1, 0xFF, 0xA1,
        ],
        // All zeros
        [0u8; 48],
        // All ones
        [0xFFu8; 48],
        // Sequential
        (0..48)
            .map(|i| i as u8)
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap(),
    ];

    for (i, seed) in test_seeds.iter().enumerate() {
        println!("\n--- Seed Variation #{} ---", i + 1);

        let bearssl_rng = BearSslAes256CtrDrbg::instantiate(seed);
        let rust_rng = Aes256CtrDrbg::instantiate(seed);
        let mut dual_rng = DualModeDrbg::new(bearssl_rng, rust_rng);

        let mut output = [0u8; 32];
        dual_rng.fill_bytes(&mut output);

        let logs = dual_rng.get_logs();
        if !logs.is_empty() {
            println!("Divergence detected for seed variation #{}:", i + 1);
            for log in logs {
                println!("  {}", log);
            }
        } else {
            println!("No divergence for seed variation #{}", i + 1);
        }
    }
}
