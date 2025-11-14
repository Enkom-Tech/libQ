#[cfg(all(feature = "aes-drbg", feature = "bearssl-aes"))]
use lib_q_hqc::aes_ctr_drbg::Aes256CtrDrbg;
#[cfg(all(feature = "aes-drbg", feature = "bearssl-aes"))]
use lib_q_hqc::bearssl_aes_ctr_drbg::BearSslAes256CtrDrbg;
// Diagnostic mode tests
#[cfg(all(
    feature = "aes-drbg",
    feature = "bearssl-aes",
    feature = "debug-drbg-interop"
))]
use lib_q_hqc::drbg_diagnostic::DualModeDrbg;
#[cfg(all(feature = "aes-drbg", feature = "bearssl-aes"))]
use rand_core::RngCore;

#[cfg(all(feature = "aes-drbg", feature = "bearssl-aes"))]
#[test]
fn test_drbg_output_equivalence() {
    println!("=== DRBG Output Equivalence Test ===\n");

    // Test with multiple seeds
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

    for (seed_idx, seed) in test_seeds.iter().enumerate() {
        println!("Testing seed set {}", seed_idx + 1);

        let mut rust_rng = Aes256CtrDrbg::instantiate(seed);
        let mut bearssl_rng = BearSslAes256CtrDrbg::instantiate(seed);

        // Test various output sizes
        for size in &[16, 32, 48, 64, 128, 256] {
            let mut rust_output = vec![0u8; *size];
            let mut bearssl_output = vec![0u8; *size];

            rust_rng.fill_bytes(&mut rust_output);
            bearssl_rng.fill_bytes(&mut bearssl_output);

            assert_eq!(
                rust_output, bearssl_output,
                "DRBG outputs must match for seed {} size {}",
                seed_idx, size
            );
        }

        println!("  ✅ Seed {} passed all sizes\n", seed_idx + 1);
    }

    println!("✅ All DRBG equivalence tests passed");
}

#[cfg(all(feature = "aes-drbg", feature = "bearssl-aes"))]
#[test]
fn test_drbg_state_equivalence() {
    println!("=== DRBG State Equivalence Test ===\n");

    let seed = [
        0x06, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE, 0x04, 0xEF, 0x7A,
        0x25, 0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79, 0xD0, 0x9D, 0x86, 0xDC, 0x9A, 0xBC,
        0xFD, 0xE7, 0x05, 0x6A, 0x8C, 0x26, 0x6F, 0x9E, 0xF9, 0x7E, 0xD0, 0x85, 0x41, 0xDB, 0xD2,
        0xE1, 0xFF, 0xA1,
    ];

    let mut rust_rng = Aes256CtrDrbg::instantiate(&seed);
    let mut bearssl_rng = BearSslAes256CtrDrbg::instantiate(&seed);

    // Generate multiple outputs from same instance
    for i in 0..10 {
        let mut rust_output = [0u8; 32];
        let mut bearssl_output = [0u8; 32];

        rust_rng.fill_bytes(&mut rust_output);
        bearssl_rng.fill_bytes(&mut bearssl_output);

        assert_eq!(
            rust_output, bearssl_output,
            "Generation {} outputs must match",
            i
        );
    }

    println!("✅ DRBG state equivalence test passed");
}

#[cfg(all(feature = "aes-drbg", feature = "bearssl-aes"))]
#[test]
fn test_drbg_partial_blocks_equivalence() {
    println!("=== DRBG Partial Blocks Equivalence Test ===\n");

    let seed = [
        0x06, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE, 0x04, 0xEF, 0x7A,
        0x25, 0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79, 0xD0, 0x9D, 0x86, 0xDC, 0x9A, 0xBC,
        0xFD, 0xE7, 0x05, 0x6A, 0x8C, 0x26, 0x6F, 0x9E, 0xF9, 0x7E, 0xD0, 0x85, 0x41, 0xDB, 0xD2,
        0xE1, 0xFF, 0xA1,
    ];

    let mut rust_rng = Aes256CtrDrbg::instantiate(&seed);
    let mut bearssl_rng = BearSslAes256CtrDrbg::instantiate(&seed);

    // Test non-16-byte-aligned sizes
    for size in &[1, 7, 15, 17, 23, 31, 33] {
        let mut rust_output = vec![0u8; *size];
        let mut bearssl_output = vec![0u8; *size];

        rust_rng.fill_bytes(&mut rust_output);
        bearssl_rng.fill_bytes(&mut bearssl_output);

        assert_eq!(
            rust_output, bearssl_output,
            "Partial block size {} must match",
            size
        );
    }

    println!("✅ DRBG partial blocks equivalence test passed");
}

#[cfg(all(feature = "aes-drbg", feature = "bearssl-aes"))]
#[test]
fn test_edge_cases() {
    println!("=== DRBG Edge Cases Test ===\n");

    // Empty output
    let seed = [0x06u8; 48];
    let mut rust_rng = Aes256CtrDrbg::instantiate(&seed);
    let mut bearssl_rng = BearSslAes256CtrDrbg::instantiate(&seed);

    let mut rust_empty = [];
    let mut bearssl_empty = [];
    rust_rng.fill_bytes(&mut rust_empty);
    bearssl_rng.fill_bytes(&mut bearssl_empty);

    // Very large output
    let mut rust_large = vec![0u8; 10000];
    let mut bearssl_large = vec![0u8; 10000];
    rust_rng.fill_bytes(&mut rust_large);
    bearssl_rng.fill_bytes(&mut bearssl_large);

    assert_eq!(rust_large, bearssl_large, "Large outputs must match");

    println!("✅ DRBG edge cases test passed");
}

#[cfg(all(
    feature = "aes-drbg",
    feature = "bearssl-aes",
    feature = "debug-drbg-interop"
))]
#[test]
fn test_with_diagnostic_logging() {
    println!("=== DRBG Equivalence Test with Diagnostic Logging ===");

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

    // Test multiple output sizes
    let sizes = [16, 32, 48, 64];
    for size in sizes {
        let mut output = vec![0u8; size];
        dual_rng.fill_bytes(&mut output);
        println!(
            "Generated {} bytes: {:02x?}",
            size,
            &output[..core::cmp::min(16, size)]
        );
    }

    // Print diagnostic logs
    println!("\n=== Diagnostic Logs ===");
    for log in dual_rng.get_logs() {
        println!("{}", log);
    }

    let has_differences = !dual_rng.get_logs().is_empty();
    println!("\n=== Summary ===");
    println!("Differences detected: {}", has_differences);

    if has_differences {
        println!("❌ DRBG implementations produce different output");
    } else {
        println!("✅ DRBG implementations produce identical output");
    }
}
