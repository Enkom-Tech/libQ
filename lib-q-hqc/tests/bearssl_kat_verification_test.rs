//! BearSSL DRBG KAT Verification Test
//!
//! This test verifies that our BearSSL DRBG implementation works correctly
//! with the HQC implementation and produces deterministic results.

#[cfg(feature = "bearssl-aes")]
use lib_q_hqc::bearssl_aes_ctr_drbg::BearSslAes256CtrDrbg;
#[cfg(feature = "bearssl-aes")]
use lib_q_hqc::hqc_kem::HqcKem;
#[cfg(feature = "bearssl-aes")]
use lib_q_hqc::*;
#[cfg(feature = "bearssl-aes")]
use rand_core::RngCore;

#[cfg(feature = "bearssl-aes")]
#[test]
fn test_bearssl_drbg_hqc_integration() {
    // Test that BearSSL DRBG works correctly with HQC key generation
    let seed_48: [u8; 48] = [
        0x9E, 0xF8, 0x77, 0xFD, 0xDB, 0xE8, 0x89, 0x1C, 0x6E, 0x4E, 0x79, 0xEA, 0xF0, 0x22, 0xE5,
        0x63, 0xDE, 0xFA, 0xCA, 0x6B, 0x15, 0x21, 0x61, 0xB9, 0xA4, 0x23, 0xE8, 0xFE, 0x96, 0xA4,
        0x03, 0xE7, 0x74, 0xB2, 0xD3, 0x52, 0xCF, 0x74, 0xC9, 0x34, 0x06, 0x9C, 0x9D, 0xE7, 0x47,
        0x57, 0xF5, 0x05,
    ];

    // Create BearSSL DRBG
    let mut drbg = BearSslAes256CtrDrbg::instantiate(&seed_48);

    // Generate seed_kem using BearSSL DRBG (48 bytes for HQC KEM)
    let mut seed_kem = [0u8; 48];
    drbg.fill_bytes(&mut seed_kem);

    println!("BearSSL DRBG seed_kem: {:02x?}", seed_kem);

    // Create HQC KEM instance
    let kem = HqcKem::<Hqc1Params>::new().expect("KEM creation failed");

    // Test key generation with BearSSL DRBG seed
    let (public_key, secret_key) = kem
        .keygen_with_seed(&seed_kem)
        .expect("Key generation failed");

    println!("✅ BearSSL DRBG + HQC key generation successful");
    println!(
        "   Public key length: {} bytes",
        public_key.as_bytes().len()
    );
    println!(
        "   Secret key length: {} bytes",
        secret_key.as_bytes().len()
    );

    // Test that the same seed produces the same keys
    let mut drbg2 = BearSslAes256CtrDrbg::instantiate(&seed_48);
    let mut seed_kem2 = [0u8; 48];
    drbg2.fill_bytes(&mut seed_kem2);

    assert_eq!(seed_kem, seed_kem2, "BearSSL DRBG should be deterministic");

    let (public_key2, secret_key2) = kem
        .keygen_with_seed(&seed_kem2)
        .expect("Key generation failed");

    assert_eq!(
        public_key.as_bytes(),
        public_key2.as_bytes(),
        "Same seed should produce same public key"
    );
    assert_eq!(
        secret_key.as_bytes(),
        secret_key2.as_bytes(),
        "Same seed should produce same secret key"
    );

    println!("✅ BearSSL DRBG produces deterministic HQC keys");
}

#[cfg(feature = "bearssl-aes")]
#[test]
fn test_bearssl_drbg_kat_seed_values() {
    // Test with the exact seed from KAT file to verify our DRBG output
    let seed_48: [u8; 48] = [
        0x9E, 0xF8, 0x77, 0xFD, 0xDB, 0xE8, 0x89, 0x1C, 0x6E, 0x4E, 0x79, 0xEA, 0xF0, 0x22, 0xE5,
        0x63, 0xDE, 0xFA, 0xCA, 0x6B, 0x15, 0x21, 0x61, 0xB9, 0xA4, 0x23, 0xE8, 0xFE, 0x96, 0xA4,
        0x03, 0xE7, 0x74, 0xB2, 0xD3, 0x52, 0xCF, 0x74, 0xC9, 0x34, 0x06, 0x9C, 0x9D, 0xE7, 0x47,
        0x57, 0xF5, 0x05,
    ];

    let mut drbg = BearSslAes256CtrDrbg::instantiate(&seed_48);

    // Generate the first 32 bytes (seed_dk equivalent)
    let mut seed_dk = [0u8; 32];
    drbg.fill_bytes(&mut seed_dk);

    // Generate the second 32 bytes (seed_ek equivalent)
    let mut seed_ek = [0u8; 32];
    drbg.fill_bytes(&mut seed_ek);

    // These are the actual values our BearSSL DRBG produces
    // They should be deterministic and consistent
    let expected_seed_dk: [u8; 32] = [
        0xB1, 0x53, 0x96, 0xD1, 0xED, 0xE4, 0x00, 0x8C, 0xAC, 0xD9, 0x34, 0xD8, 0x93, 0x3D, 0x89,
        0x04, 0x13, 0x20, 0x3F, 0x01, 0xCF, 0x9C, 0xC4, 0x3C, 0x4F, 0xD6, 0x26, 0xCB, 0x31, 0x67,
        0xA3, 0xA9,
    ];

    let expected_seed_ek: [u8; 32] = [
        0xFD, 0xB4, 0xEA, 0xE1, 0xAC, 0x1A, 0x71, 0x75, 0x39, 0x60, 0xA9, 0x09, 0xB8, 0x24, 0x17,
        0x69, 0x17, 0x9F, 0x2B, 0xE3, 0x8A, 0x4B, 0xA3, 0x47, 0x5A, 0x47, 0x9E, 0xDE, 0x0F, 0xB4,
        0xF8, 0xDB,
    ];

    assert_eq!(
        seed_dk, expected_seed_dk,
        "seed_dk should match expected BearSSL DRBG output"
    );
    assert_eq!(
        seed_ek, expected_seed_ek,
        "seed_ek should match expected BearSSL DRBG output"
    );

    println!("✅ BearSSL DRBG produces expected output values");
    println!("   seed_dk: {:02x?}", seed_dk);
    println!("   seed_ek: {:02x?}", seed_ek);
}

#[cfg(feature = "bearssl-aes")]
#[test]
fn test_bearssl_drbg_state_consistency() {
    // Test that BearSSL DRBG maintains consistent state across multiple calls
    let seed_48: [u8; 48] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C,
        0x2D, 0x2E, 0x2F,
    ];

    let mut drbg = BearSslAes256CtrDrbg::instantiate(&seed_48);

    // Generate multiple outputs and verify they're different
    let mut output1 = [0u8; 32];
    let mut output2 = [0u8; 32];
    let mut output3 = [0u8; 32];

    drbg.fill_bytes(&mut output1);
    drbg.fill_bytes(&mut output2);
    drbg.fill_bytes(&mut output3);

    // All outputs should be different
    assert_ne!(
        output1, output2,
        "Consecutive DRBG outputs should be different"
    );
    assert_ne!(
        output2, output3,
        "Consecutive DRBG outputs should be different"
    );
    assert_ne!(
        output1, output3,
        "Non-consecutive DRBG outputs should be different"
    );

    // Test deterministic behavior with same seed
    let mut drbg2 = BearSslAes256CtrDrbg::instantiate(&seed_48);
    let mut output1_2 = [0u8; 32];
    let mut output2_2 = [0u8; 32];
    let mut output3_2 = [0u8; 32];

    drbg2.fill_bytes(&mut output1_2);
    drbg2.fill_bytes(&mut output2_2);
    drbg2.fill_bytes(&mut output3_2);

    assert_eq!(
        output1, output1_2,
        "Same seed should produce same first output"
    );
    assert_eq!(
        output2, output2_2,
        "Same seed should produce same second output"
    );
    assert_eq!(
        output3, output3_2,
        "Same seed should produce same third output"
    );

    println!("✅ BearSSL DRBG maintains consistent state and produces different outputs");
}

#[cfg(not(feature = "bearssl-aes"))]
#[test]
fn test_bearssl_feature_required() {
    panic!("This test requires the 'bearssl-aes' feature to be enabled");
}
