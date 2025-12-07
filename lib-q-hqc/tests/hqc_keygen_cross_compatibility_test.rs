// Diagnostic mode tests
#[cfg(all(
    feature = "aes-drbg",
    feature = "bearssl-aes",
    feature = "debug-drbg-interop"
))]
#[cfg(all(feature = "aes-drbg", feature = "bearssl-aes"))]
use lib_q_hqc::hqc_pke::HqcPke;
#[cfg(all(feature = "aes-drbg", feature = "bearssl-aes"))]
use lib_q_hqc::params_correct::{
    Hqc1Params,
    HqcParams,
};

#[cfg(all(feature = "aes-drbg", feature = "bearssl-aes"))]
#[test]
fn test_keygen_produces_identical_keys() {
    println!("=== Keygen Identity Test ===\n");

    let pke = HqcPke::<Hqc1Params>::new().unwrap();
    let seed = [
        0x06, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE, 0x04, 0xEF, 0x7A,
        0x25, 0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79, 0xD0, 0x9D, 0x86, 0xDC, 0x9A, 0xBC,
        0xFD, 0xE7, 0x05, 0x6A, 0x8C, 0x26, 0x6F, 0x9E, 0xF9, 0x7E, 0xD0, 0x85, 0x41, 0xDB, 0xD2,
        0xE1, 0xFF, 0xA1,
    ];

    // Generate keys twice with same seed - should produce identical keys
    // regardless of which DRBG backend is active
    let (pk1, sk1) = pke.keygen_with_seed(&seed).unwrap();
    let (pk2, sk2) = pke.keygen_with_seed(&seed).unwrap();

    assert_eq!(pk1.as_bytes(), pk2.as_bytes(), "Public keys must match");
    assert_eq!(sk1.data, sk2.data, "Secret keys must match");

    println!("✅ Same seed produces identical keys");
}

#[cfg(all(
    feature = "aes-drbg",
    feature = "bearssl-aes",
    feature = "debug-drbg-interop"
))]
#[test]
fn test_keygen_with_diagnostic_logging() {
    println!("=== Keygen with Diagnostic Logging ===");

    let pke = HqcPke::<Hqc1Params>::new().unwrap();
    let seed = [
        0x06, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE, 0x04, 0xEF, 0x7A,
        0x25, 0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79, 0xD0, 0x9D, 0x86, 0xDC, 0x9A, 0xBC,
        0xFD, 0xE7, 0x05, 0x6A, 0x8C, 0x26, 0x6F, 0x9E, 0xF9, 0x7E, 0xD0, 0x85, 0x41, 0xDB, 0xD2,
        0xE1, 0xFF, 0xA1,
    ];

    // Generate keypair using diagnostic mode
    let (pk, sk) = pke.keygen_with_seed(&seed).unwrap();

    println!("Generated public key: {:02x?}", &pk.as_bytes()[..16]);
    println!("Generated secret key: {:02x?}", &sk.data[..16]);

    // Note: The actual diagnostic logs would be captured by the DualModeDrbg
    // inside the keygen_with_seed call, but we can't access them directly here
    // since they're internal to the DRBG wrapper.

    println!("✅ Key generation completed with diagnostic mode");
    println!("   (Diagnostic logs are captured internally by DualModeDrbg)");
}
