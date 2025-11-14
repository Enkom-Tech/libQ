#[cfg(feature = "aes-drbg")]
use lib_q_hqc::aes_ctr_drbg::Aes256CtrDrbg;
#[cfg(feature = "bearssl-aes")]
use lib_q_hqc::bearssl_aes_ctr_drbg::BearSslAes256CtrDrbg;
use rand_core::RngCore;

#[cfg(feature = "aes-drbg")]
#[test]
fn test_rust_block_by_block_comparison() {
    let kat_seed = [
        0x06, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE, 0x04, 0xEF, 0x7A,
        0x25, 0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79, 0xD0, 0x9D, 0x86, 0xDC, 0x9A, 0xBC,
        0xFD, 0xE7, 0x05, 0x6A, 0x8C, 0x26, 0x6F, 0x9E, 0xF9, 0x7E, 0xD0, 0x85, 0x41, 0xDB, 0xD2,
        0xE1, 0xFF, 0xA1,
    ];

    let mut rng = Aes256CtrDrbg::instantiate(&kat_seed);

    println!("=== Rust Block-by-Block Comparison ===");
    println!("Initial state: {}", rng.debug_state());

    // Generate blocks one at a time
    let mut all_blocks = Vec::new();

    for i in 0..4 {
        // 4 blocks total (64 bytes)
        let mut block = [0u8; 16];
        rng.fill_bytes(&mut block);
        all_blocks.push(block);

        println!("Block {}: {:02x?}", i, block);
        println!("State after block {}: {}", i, rng.debug_state());
    }

    // Expected blocks from KAT
    let expected_blocks = [
        // Block 0 (bytes 0-15 of seed_dk)
        [
            0x7C, 0x99, 0x35, 0xA0, 0xB0, 0x76, 0x94, 0xAA, 0x0C, 0x6D, 0x10, 0xE4, 0xDB, 0x6B,
            0x1A, 0xDD,
        ],
        // Block 1 (bytes 16-31 of seed_dk)
        [
            0x2F, 0xD8, 0x1A, 0x25, 0xCC, 0xB1, 0x48, 0x03, 0x2D, 0xCD, 0x73, 0x99, 0x36, 0x73,
            0x7F, 0x2D,
        ],
        // Block 2 (bytes 0-15 of seed_ek)
        [
            0x74, 0xB2, 0xD3, 0x52, 0xCF, 0x74, 0xC9, 0x34, 0x06, 0x9C, 0x9D, 0xE7, 0x47, 0x57,
            0xF5, 0x05,
        ],
        // Block 3 (bytes 16-31 of seed_ek)
        [
            0x66, 0xFE, 0x46, 0xF7, 0xE1, 0x22, 0x24, 0x3C, 0x90, 0xC3, 0x0A, 0xDE, 0xBB, 0x0E,
            0x3D, 0xB3,
        ],
    ];

    println!("\n=== Comparison ===");
    for (i, (generated, expected)) in all_blocks.iter().zip(expected_blocks.iter()).enumerate() {
        let matches = generated == expected;
        println!("Block {}: Match = {}", i, matches);
        if !matches {
            println!("  Generated: {:02x?}", generated);
            println!("  Expected:  {:02x?}", expected);
            println!(
                "  Difference: {:02x?}",
                generated
                    .iter()
                    .zip(expected.iter())
                    .map(|(a, b)| a ^ b)
                    .collect::<Vec<_>>()
            );
        }
    }
}

#[cfg(feature = "bearssl-aes")]
#[test]
fn test_bearssl_block_by_block_comparison() {
    let kat_seed = [
        0x06, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE, 0x04, 0xEF, 0x7A,
        0x25, 0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79, 0xD0, 0x9D, 0x86, 0xDC, 0x9A, 0xBC,
        0xFD, 0xE7, 0x05, 0x6A, 0x8C, 0x26, 0x6F, 0x9E, 0xF9, 0x7E, 0xD0, 0x85, 0x41, 0xDB, 0xD2,
        0xE1, 0xFF, 0xA1,
    ];

    let mut rng = BearSslAes256CtrDrbg::instantiate(&kat_seed);

    println!("=== BearSSL Block-by-Block Comparison ===");
    println!("Initial state: {}", rng.debug_state());

    // Generate blocks one at a time
    let mut all_blocks = Vec::new();

    for i in 0..4 {
        // 4 blocks total (64 bytes)
        let mut block = [0u8; 16];
        rng.fill_bytes(&mut block);
        all_blocks.push(block);

        println!("Block {}: {:02x?}", i, block);
        println!("State after block {}: {}", i, rng.debug_state());
    }

    // Expected blocks from KAT
    let expected_blocks = [
        // Block 0 (bytes 0-15 of seed_dk)
        [
            0x7C, 0x99, 0x35, 0xA0, 0xB0, 0x76, 0x94, 0xAA, 0x0C, 0x6D, 0x10, 0xE4, 0xDB, 0x6B,
            0x1A, 0xDD,
        ],
        // Block 1 (bytes 16-31 of seed_dk)
        [
            0x2F, 0xD8, 0x1A, 0x25, 0xCC, 0xB1, 0x48, 0x03, 0x2D, 0xCD, 0x73, 0x99, 0x36, 0x73,
            0x7F, 0x2D,
        ],
        // Block 2 (bytes 0-15 of seed_ek)
        [
            0x74, 0xB2, 0xD3, 0x52, 0xCF, 0x74, 0xC9, 0x34, 0x06, 0x9C, 0x9D, 0xE7, 0x47, 0x57,
            0xF5, 0x05,
        ],
        // Block 3 (bytes 16-31 of seed_ek)
        [
            0x66, 0xFE, 0x46, 0xF7, 0xE1, 0x22, 0x24, 0x3C, 0x90, 0xC3, 0x0A, 0xDE, 0xBB, 0x0E,
            0x3D, 0xB3,
        ],
    ];

    println!("\n=== Comparison ===");
    for (i, (generated, expected)) in all_blocks.iter().zip(expected_blocks.iter()).enumerate() {
        let matches = generated == expected;
        println!("Block {}: Match = {}", i, matches);
        if !matches {
            println!("  Generated: {:02x?}", generated);
            println!("  Expected:  {:02x?}", expected);
            println!(
                "  Difference: {:02x?}",
                generated
                    .iter()
                    .zip(expected.iter())
                    .map(|(a, b)| a ^ b)
                    .collect::<Vec<_>>()
            );
        }
    }
}
