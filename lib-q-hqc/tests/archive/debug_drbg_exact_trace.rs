//! Exact trace of DRBG to find the bug

#[cfg(feature = "bearssl-aes")]
use lib_q_hqc::bearssl_aes_ctr_drbg::BearSslAes256CtrDrbg;
#[cfg(feature = "bearssl-aes")]
use lib_q_hqc::bearssl_aes_pure::Aes256CtxPure;
#[cfg(feature = "bearssl-aes")]
use rand_core::Rng;

#[cfg(feature = "bearssl-aes")]
#[test]
fn test_exact_drbg_trace() {
    println!("=== Exact DRBG Trace ===");

    let seed_48: [u8; 48] = [
        0x9E, 0xF8, 0x77, 0xFD, 0xDB, 0xE8, 0x89, 0x1C, 0x6E, 0x4E, 0x79, 0xEA, 0xF0, 0x22, 0xE5,
        0x63, 0xDE, 0xFA, 0xCA, 0x6B, 0x15, 0x21, 0x61, 0xB9, 0xA4, 0x23, 0xE8, 0xFE, 0x96, 0xA4,
        0x03, 0xE7, 0x74, 0xB2, 0xD3, 0x52, 0xCF, 0x74, 0xC9, 0x34, 0x06, 0x9C, 0x9D, 0xE7, 0x47,
        0x57, 0xF5, 0x05,
    ];

    // Expected output
    let expected_seed_dk: [u8; 32] = [
        0x12, 0xDA, 0xF0, 0x31, 0xBD, 0xC7, 0xFC, 0x59, 0x2E, 0x00, 0x03, 0xA2, 0x1E, 0xEF, 0xA9,
        0xA1, 0x01, 0x95, 0x39, 0xAB, 0xCC, 0xC8, 0xF6, 0x70, 0x75, 0x94, 0x7C, 0xBF, 0xEA, 0xAC,
        0x98, 0xC5,
    ];

    // Step 1: Instantiate
    println!("Step 1: Instantiate DRBG");
    let mut key = [0u8; 32];
    let mut v = [0u8; 16];

    // Simulate ctr_drbg_update
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

    println!("Key after instantiate: {:02x?}", key);
    println!("V after instantiate:   {:02x?}", v);

    // Step 2: First fill_bytes(32) - manually compute
    println!("\nStep 2: Compute first 32 bytes manually");
    let mut output_manual = [0u8; 32];
    let mut v_work = v;

    // First block
    BearSslAes256CtrDrbg::increment_counter(&mut v_work);
    println!("V after increment #1: {:02x?}", v_work);
    let aes_ctx = Aes256CtxPure::new(&key);
    let block1 = aes_ctx.encrypt_block(&v_work);
    output_manual[..16].copy_from_slice(&block1);
    println!("First block: {:02x?}", block1);
    println!("Expected first 16: {:02x?}", &expected_seed_dk[..16]);

    // Second block
    BearSslAes256CtrDrbg::increment_counter(&mut v_work);
    println!("V after increment #2: {:02x?}", v_work);
    let block2 = aes_ctx.encrypt_block(&v_work);
    output_manual[16..].copy_from_slice(&block2);
    println!("Second block: {:02x?}", block2);
    println!("Expected second 16: {:02x?}", &expected_seed_dk[16..]);

    println!("\nManual output: {:02x?}", output_manual);
    println!("Expected:     {:02x?}", expected_seed_dk);
    println!("Match: {}", output_manual == expected_seed_dk);

    // Step 3: Compare with actual DRBG
    println!("\nStep 3: Compare with actual DRBG");
    let mut drbg = BearSslAes256CtrDrbg::instantiate(&seed_48);
    let mut output_drbg = [0u8; 32];
    drbg.fill_bytes(&mut output_drbg);

    println!("DRBG output: {:02x?}", output_drbg);
    println!("Match: {}", output_drbg == expected_seed_dk);
    println!("Manual == DRBG: {}", output_manual == output_drbg);
}
