//! Debug DRBG Step-by-Step Analysis
//!
//! This test traces through the DRBG instantiation and first output generation
//! to identify where our implementation diverges from the reference.

#[cfg(feature = "bearssl-aes")]
use lib_q_hqc::bearssl_aes_ctr_drbg::BearSslAes256CtrDrbg;
#[cfg(feature = "bearssl-aes")]
use lib_q_hqc::bearssl_aes_pure::Aes256CtxPure;
#[cfg(feature = "bearssl-aes")]
use rand_core::RngCore;

/// Helper to print hex with label
fn print_hex(label: &str, data: &[u8]) {
    println!("{}: {:02x?}", label, data);
}

#[cfg(feature = "bearssl-aes")]
#[test]
fn test_drbg_instantiate_step_by_step() {
    println!("=== DRBG Instantiate Step-by-Step Debug ===");

    // KAT seed from test
    let seed_48: [u8; 48] = [
        0x9E, 0xF8, 0x77, 0xFD, 0xDB, 0xE8, 0x89, 0x1C, 0x6E, 0x4E, 0x79, 0xEA, 0xF0, 0x22, 0xE5,
        0x63, 0xDE, 0xFA, 0xCA, 0x6B, 0x15, 0x21, 0x61, 0xB9, 0xA4, 0x23, 0xE8, 0xFE, 0x96, 0xA4,
        0x03, 0xE7, 0x74, 0xB2, 0xD3, 0x52, 0xCF, 0x74, 0xC9, 0x34, 0x06, 0x9C, 0x9D, 0xE7, 0x47,
        0x57, 0xF5, 0x05,
    ];

    print_hex("Seed (entropy_input)", &seed_48);

    // Step 1: Initialize Key and V to zeros
    let mut key = [0u8; 32];
    let mut v = [0u8; 16];
    print_hex("Initial Key (should be all zeros)", &key);
    print_hex("Initial V (should be all zeros)", &v);

    // Step 2: Simulate ctr_drbg_update manually to see intermediate values
    println!("\n=== Simulating ctr_drbg_update ===");
    let mut temp = [0u8; 48];

    // Generate 48 bytes using AES-256-ECB (3 blocks)
    for i in 0..3 {
        // Increment V
        BearSslAes256CtrDrbg::increment_counter(&mut v);
        print_hex(&format!("V after increment #{}", i + 1), &v);

        // Encrypt V with Key
        let aes_ctx = Aes256CtxPure::new(&key);
        let encrypted = aes_ctx.encrypt_block(&v);
        temp[i * 16..(i + 1) * 16].copy_from_slice(&encrypted);
        print_hex(&format!("AES(Key, V) block #{}", i + 1), &encrypted);
    }

    print_hex("temp before XOR", &temp);

    // XOR with provided_data
    for i in 0..48 {
        temp[i] ^= seed_48[i];
    }
    print_hex("temp after XOR with seed", &temp);

    // Update Key and V
    key.copy_from_slice(&temp[..32]);
    v.copy_from_slice(&temp[32..48]);
    print_hex("Key after update", &key);
    print_hex("V after update", &v);

    // Now create DRBG and compare
    println!("\n=== Comparing with actual DRBG instantiate ===");
    let drbg = BearSslAes256CtrDrbg::instantiate(&seed_48);
    let drbg_state = drbg.debug_state();
    println!("DRBG state after instantiate:\n{}", drbg_state);
}

#[cfg(feature = "bearssl-aes")]
#[test]
fn test_drbg_first_output_step_by_step() {
    println!("=== DRBG First Output Step-by-Step Debug ===");

    // KAT seed
    let seed_48: [u8; 48] = [
        0x9E, 0xF8, 0x77, 0xFD, 0xDB, 0xE8, 0x89, 0x1C, 0x6E, 0x4E, 0x79, 0xEA, 0xF0, 0x22, 0xE5,
        0x63, 0xDE, 0xFA, 0xCA, 0x6B, 0x15, 0x21, 0x61, 0xB9, 0xA4, 0x23, 0xE8, 0xFE, 0x96, 0xA4,
        0x03, 0xE7, 0x74, 0xB2, 0xD3, 0x52, 0xCF, 0x74, 0xC9, 0x34, 0x06, 0x9C, 0x9D, 0xE7, 0x47,
        0x57, 0xF5, 0x05,
    ];

    let mut drbg = BearSslAes256CtrDrbg::instantiate(&seed_48);
    println!("DRBG state after instantiate:");
    println!("{}", drbg.debug_state());

    // Expected seed_dk from reference
    let expected_seed_dk: [u8; 32] = [
        0x12, 0xDA, 0xF0, 0x31, 0xBD, 0xC7, 0xFC, 0x59, 0x2E, 0x00, 0x03, 0xA2, 0x1E, 0xEF, 0xA9,
        0xA1, 0x01, 0x95, 0x39, 0xAB, 0xCC, 0xC8, 0xF6, 0x70, 0x75, 0x94, 0x7C, 0xBF, 0xEA, 0xAC,
        0x98, 0xC5,
    ];

    println!("\n=== Manually computing first output block ===");

    // Get the Key and V after instantiate (we need to access internal state)
    // For now, let's manually recreate the state
    let mut key = [0u8; 32];
    let mut v = [0u8; 16];

    // Simulate instantiate
    let mut temp = [0u8; 48];
    for i in 0..3 {
        BearSslAes256CtrDrbg::increment_counter(&mut v);
        let aes_ctx = Aes256CtxPure::new(&key);
        let encrypted = aes_ctx.encrypt_block(&v);
        temp[i * 16..(i + 1) * 16].copy_from_slice(&encrypted);
    }
    for i in 0..48 {
        temp[i] ^= seed_48[i];
    }
    key.copy_from_slice(&temp[..32]);
    v.copy_from_slice(&temp[32..48]);

    print_hex("Key after instantiate", &key);
    print_hex("V after instantiate", &v);

    // Now compute first output block manually
    println!("\n=== Computing first 16 bytes ===");
    let mut v_first = v;
    BearSslAes256CtrDrbg::increment_counter(&mut v_first);
    print_hex("V after first increment", &v_first);

    let aes_ctx = Aes256CtxPure::new(&key);
    let first_block = aes_ctx.encrypt_block(&v_first);
    print_hex("First AES block", &first_block);
    print_hex(
        "Expected first 16 bytes of seed_dk",
        &expected_seed_dk[..16],
    );

    println!("\n=== Computing second 16 bytes ===");
    BearSslAes256CtrDrbg::increment_counter(&mut v_first);
    print_hex("V after second increment", &v_first);

    let second_block = aes_ctx.encrypt_block(&v_first);
    print_hex("Second AES block", &second_block);
    print_hex(
        "Expected second 16 bytes of seed_dk",
        &expected_seed_dk[16..],
    );

    // Now call fill_bytes and compare
    println!("\n=== Comparing with actual fill_bytes ===");
    let mut output = [0u8; 32];
    drbg.fill_bytes(&mut output);

    print_hex("Actual output (seed_dk)", &output);
    print_hex("Expected seed_dk", &expected_seed_dk);

    println!("\nFirst byte comparison:");
    println!("  Actual[0] = 0x{:02x}", output[0]);
    println!("  Expected[0] = 0x{:02x}", expected_seed_dk[0]);
    println!("  Match: {}", output[0] == expected_seed_dk[0]);

    if output != expected_seed_dk {
        println!("\n❌ Output does NOT match expected!");
        println!(
            "First differing byte at index: {}",
            output
                .iter()
                .zip(expected_seed_dk.iter())
                .position(|(a, e)| a != e)
                .unwrap_or(32)
        );
    } else {
        println!("\n✅ Output matches expected!");
    }
}
