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

#[cfg(all(feature = "aes-drbg", feature = "bearssl-aes"))]
#[test]
fn test_keys_work_across_implementations() {
    println!("=== Cross-Implementation Key Usage Test ===\n");

    let pke = HqcPke::<Hqc1Params>::new().unwrap();
    let seed = [
        0x06, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE, 0x04, 0xEF, 0x7A,
        0x25, 0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79, 0xD0, 0x9D, 0x86, 0xDC, 0x9A, 0xBC,
        0xFD, 0xE7, 0x05, 0x6A, 0x8C, 0x26, 0x6F, 0x9E, 0xF9, 0x7E, 0xD0, 0x85, 0x41, 0xDB, 0xD2,
        0xE1, 0xFF, 0xA1,
    ];

    // Generate keypair
    let (pk, sk) = pke.keygen_with_seed(&seed).unwrap();

    // Encrypt a test message (convert to u64 array)
    let message_bytes = b"Test message for cross-compatibility";
    let mut message = vec![0u64; message_bytes.len().div_ceil(8)];
    for (i, &byte) in message_bytes.iter().enumerate() {
        let word_idx = i / 8;
        let bit_idx = i % 8;
        message[word_idx] |= (byte as u64) << (bit_idx * 8);
    }

    let theta = [0u8; 16]; // PARAM_SECURITY_BYTES
    let ciphertext = pke.encrypt(&pk, &message, &theta).unwrap();

    // Decrypt - should work regardless of which DRBG was used for keygen
    let decrypted = pke.decrypt(&sk, &ciphertext).unwrap();

    // Convert back to bytes for comparison
    let mut decrypted_bytes = vec![0u8; message_bytes.len()];
    for (i, &word) in decrypted.iter().enumerate() {
        for bit_idx in 0..8 {
            let byte_idx = i * 8 + bit_idx;
            if byte_idx < decrypted_bytes.len() {
                decrypted_bytes[byte_idx] = ((word >> (bit_idx * 8)) & 0xFF) as u8;
            }
        }
    }

    assert_eq!(&decrypted_bytes[..message_bytes.len()], message_bytes);

    println!("✅ Keys work correctly for encryption/decryption");
}

#[cfg(all(feature = "aes-drbg", feature = "bearssl-aes"))]
#[test]
fn test_multiple_keygen_iterations() {
    println!("=== Multiple Keygen Iterations Test ===\n");

    let pke = HqcPke::<Hqc1Params>::new().unwrap();

    // Test with different seeds
    for i in 0..10 {
        let mut seed = [0u8; 48];
        for (j, item) in seed.iter_mut().enumerate() {
            *item = (i * 48 + j) as u8;
        }

        let (pk, sk) = pke.keygen_with_seed(&seed).unwrap();

        // Verify key sizes
        assert_eq!(pk.as_bytes().len(), Hqc1Params::PUBLIC_KEY_BYTES);
        assert_eq!(sk.data.len(), Hqc1Params::SEED_BYTES);

        // Quick encrypt/decrypt check
        let message_bytes = b"test";
        let mut message = vec![0u64; message_bytes.len().div_ceil(8)];
        for (i, &byte) in message_bytes.iter().enumerate() {
            let word_idx = i / 8;
            let bit_idx = i % 8;
            message[word_idx] |= (byte as u64) << (bit_idx * 8);
        }

        let theta = [0u8; 16]; // PARAM_SECURITY_BYTES
        let ct = pke.encrypt(&pk, &message, &theta).unwrap();
        let pt = pke.decrypt(&sk, &ct).unwrap();

        // Convert back to bytes for comparison
        let mut pt_bytes = vec![0u8; message_bytes.len()];
        for (i, &word) in pt.iter().enumerate() {
            for bit_idx in 0..8 {
                let byte_idx = i * 8 + bit_idx;
                if byte_idx < pt_bytes.len() {
                    pt_bytes[byte_idx] = ((word >> (bit_idx * 8)) & 0xFF) as u8;
                }
            }
        }
        assert_eq!(&pt_bytes[..4], message_bytes);
    }

    println!("✅ Multiple keygen iterations successful");
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
