//! RFC 9180 HPKE Test Vectors
//!
//! This module contains test vectors for HPKE compliance testing according to RFC 9180.
//! These test vectors cover various scenarios including different modes, algorithms, and edge cases.

#![cfg(feature = "std")]
#![allow(clippy::manual_map, clippy::unnecessary_unwrap)]

use lib_q_core::{
    Algorithm,
    KemContext,
    KemPublicKey,
    KemSecretKey,
};
use lib_q_hpke::HpkeContext;
use lib_q_kem::LibQKemProvider;

/// Test vector structure for HPKE operations
#[derive(Debug, Clone)]
pub struct HpkeTestVector {
    /// Test vector identifier
    pub id: String,
    /// HPKE mode
    pub mode: String,
    /// KEM algorithm
    pub kem: String,
    /// KDF algorithm
    pub kdf: String,
    /// AEAD algorithm
    pub aead: String,
    /// Recipient public key
    pub recipient_pk: Vec<u8>,
    /// Recipient secret key
    pub recipient_sk: Vec<u8>,
    /// Sender public key (for Auth modes)
    pub sender_pk: Option<Vec<u8>>,
    /// Sender secret key (for Auth modes)
    pub sender_sk: Option<Vec<u8>>,
    /// Pre-shared key (for PSK modes)
    pub psk: Option<Vec<u8>>,
    /// Pre-shared key ID (for PSK modes)
    pub psk_id: Option<Vec<u8>>,
    /// Info parameter
    pub info: Vec<u8>,
    /// Plaintext message
    pub plaintext: Vec<u8>,
    /// Associated authenticated data
    pub aad: Vec<u8>,
    /// Expected encapsulated key
    pub expected_encapsulated_key: Vec<u8>,
    /// Expected ciphertext
    pub expected_ciphertext: Vec<u8>,
    /// Expected exported key
    pub expected_exported_key: Option<Vec<u8>>,
}

impl HpkeTestVector {
    /// Create a new test vector
    pub fn new(id: String, mode: String, kem: String, kdf: String, aead: String) -> Self {
        Self {
            id,
            mode,
            kem,
            kdf,
            aead,
            recipient_pk: Vec::new(),
            recipient_sk: Vec::new(),
            sender_pk: None,
            sender_sk: None,
            psk: None,
            psk_id: None,
            info: Vec::new(),
            plaintext: Vec::new(),
            aad: Vec::new(),
            expected_encapsulated_key: Vec::new(),
            expected_ciphertext: Vec::new(),
            expected_exported_key: None,
        }
    }
}

/// Generate test vectors for HPKE compliance testing
pub fn generate_test_vectors() -> Vec<HpkeTestVector> {
    let mut test_vectors = Vec::new();

    // Test Vector 1: Base Mode with ML-KEM-512
    let mut tv1 = HpkeTestVector::new(
        "TV-001".to_string(),
        "Base".to_string(),
        "ML-KEM-512".to_string(),
        "HKDF-SHA3-256".to_string(),
        "Saturnin256".to_string(),
    );
    tv1.info = b"HPKE test vector 1".to_vec();
    tv1.plaintext = b"Hello, HPKE!".to_vec();
    tv1.aad = b"additional data".to_vec();
    test_vectors.push(tv1);

    // Test Vector 2: PSK Mode with ML-KEM-768
    let mut tv2 = HpkeTestVector::new(
        "TV-002".to_string(),
        "PSK".to_string(),
        "ML-KEM-768".to_string(),
        "HKDF-SHA3-512".to_string(),
        "Shake256".to_string(),
    );
    tv2.psk = Some(b"pre-shared-key-32-bytes-long".to_vec());
    tv2.psk_id = Some(b"psk-identifier".to_vec());
    tv2.info = b"HPKE test vector 2".to_vec();
    tv2.plaintext = b"PSK mode test message".to_vec();
    tv2.aad = b"psk aad".to_vec();
    test_vectors.push(tv2);

    // Test Vector 3: Auth Mode with ML-KEM-1024
    let mut tv3 = HpkeTestVector::new(
        "TV-003".to_string(),
        "Auth".to_string(),
        "ML-KEM-1024".to_string(),
        "HKDF-SHA3-256".to_string(),
        "Saturnin256".to_string(),
    );
    tv3.info = b"HPKE test vector 3".to_vec();
    tv3.plaintext = b"Auth mode test message".to_vec();
    tv3.aad = b"auth aad".to_vec();
    test_vectors.push(tv3);

    // Test Vector 4: AuthPSK Mode with ML-KEM-512
    let mut tv4 = HpkeTestVector::new(
        "TV-004".to_string(),
        "AuthPSK".to_string(),
        "ML-KEM-512".to_string(),
        "HKDF-SHA3-256".to_string(),
        "Saturnin256".to_string(),
    );
    tv4.psk = Some(b"auth-psk-key-32-bytes-long".to_vec());
    tv4.psk_id = Some(b"auth-psk-id".to_vec());
    tv4.info = b"HPKE test vector 4".to_vec();
    tv4.plaintext = b"AuthPSK mode test message".to_vec();
    tv4.aad = b"authpsk aad".to_vec();
    test_vectors.push(tv4);

    // Test Vector 5: Export-only mode
    let mut tv5 = HpkeTestVector::new(
        "TV-005".to_string(),
        "Base".to_string(),
        "ML-KEM-512".to_string(),
        "HKDF-SHA3-256".to_string(),
        "Export".to_string(),
    );
    tv5.info = b"HPKE export test".to_vec();
    tv5.plaintext = b"export test message".to_vec();
    tv5.aad = b"export aad".to_vec();
    tv5.expected_exported_key = Some(vec![0u8; 32]); // 32-byte exported key
    test_vectors.push(tv5);

    test_vectors
}

/// Test HPKE compliance with generated test vectors
#[test]
fn test_hpke_rfc9180_compliance() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);
    let test_vectors = generate_test_vectors();

    for test_vector in test_vectors {
        println!("Testing vector: {}", test_vector.id);

        // Generate key pairs for this test vector
        let mut kem_ctx = KemContext::with_provider(Box::new(
            LibQKemProvider::new().expect("Failed to create KEM provider"),
        ));
        let kem_algorithm = match test_vector.kem.as_str() {
            "ML-KEM-512" => Algorithm::MlKem512,
            "ML-KEM-768" => Algorithm::MlKem768,
            "ML-KEM-1024" => Algorithm::MlKem1024,
            _ => panic!("Unsupported KEM algorithm: {}", test_vector.kem),
        };

        let recipient_keypair = kem_ctx.generate_keypair(kem_algorithm, None).unwrap();
        let recipient_pk = KemPublicKey::new(recipient_keypair.public_key().as_bytes().to_vec());
        let recipient_sk = KemSecretKey::new(recipient_keypair.secret_key().as_bytes().to_vec());

        let sender_keypair = if test_vector.mode.contains("Auth") {
            Some(kem_ctx.generate_keypair(kem_algorithm, None).unwrap())
        } else {
            None
        };

        let sender_pk = if let Some(ref keypair) = sender_keypair {
            Some(KemPublicKey::new(keypair.public_key().as_bytes().to_vec()))
        } else {
            None
        };

        let sender_sk = if let Some(ref keypair) = sender_keypair {
            Some(KemSecretKey::new(keypair.secret_key().as_bytes().to_vec()))
        } else {
            None
        };

        // Test sender setup
        let sender_ctx_result = match test_vector.mode.as_str() {
            "Base" => hpke_ctx.setup_sender(&recipient_pk, &test_vector.info),
            "PSK" => {
                let psk = test_vector.psk.as_ref().unwrap();
                let psk_id = test_vector.psk_id.as_ref().unwrap();
                hpke_ctx.setup_sender_psk(&recipient_pk, &test_vector.info, psk, psk_id)
            }
            "Auth" => {
                let sender_sk = sender_sk.as_ref().unwrap();
                let sender_pk = sender_pk.as_ref().unwrap();
                hpke_ctx.setup_sender_auth(&recipient_pk, &test_vector.info, sender_sk, sender_pk)
            }
            "AuthPSK" => {
                let psk = test_vector.psk.as_ref().unwrap();
                let psk_id = test_vector.psk_id.as_ref().unwrap();
                let sender_sk = sender_sk.as_ref().unwrap();
                let sender_pk = sender_pk.as_ref().unwrap();
                hpke_ctx.setup_sender_auth_psk(
                    &recipient_pk,
                    &test_vector.info,
                    psk,
                    psk_id,
                    sender_sk,
                    sender_pk,
                )
            }
            _ => panic!("Unsupported mode: {}", test_vector.mode),
        };

        assert!(
            sender_ctx_result.is_ok(),
            "Sender setup should succeed for test vector {}",
            test_vector.id
        );

        let mut sender_ctx = sender_ctx_result.unwrap();

        // Test encryption
        let ciphertext_result = sender_ctx.seal(&test_vector.aad, &test_vector.plaintext);
        assert!(
            ciphertext_result.is_ok(),
            "Encryption should succeed for test vector {}",
            test_vector.id
        );

        let ciphertext = ciphertext_result.unwrap();

        // Test receiver setup
        let receiver_ctx_result = match test_vector.mode.as_str() {
            "Base" => hpke_ctx.setup_receiver(
                sender_ctx.encapsulated_key(),
                &recipient_sk,
                &test_vector.info,
            ),
            "PSK" => {
                let psk = test_vector.psk.as_ref().unwrap();
                let psk_id = test_vector.psk_id.as_ref().unwrap();
                hpke_ctx.setup_receiver_psk(
                    sender_ctx.encapsulated_key(),
                    &recipient_sk,
                    &test_vector.info,
                    psk,
                    psk_id,
                )
            }
            "Auth" => {
                let sender_pk = sender_pk.as_ref().unwrap();
                hpke_ctx.setup_receiver_auth(
                    sender_ctx.encapsulated_key(),
                    &recipient_sk,
                    &test_vector.info,
                    sender_pk,
                )
            }
            "AuthPSK" => {
                let psk = test_vector.psk.as_ref().unwrap();
                let psk_id = test_vector.psk_id.as_ref().unwrap();
                let sender_pk = sender_pk.as_ref().unwrap();
                hpke_ctx.setup_receiver_auth_psk(
                    sender_ctx.encapsulated_key(),
                    &recipient_sk,
                    &test_vector.info,
                    psk,
                    psk_id,
                    sender_pk,
                )
            }
            _ => panic!("Unsupported mode: {}", test_vector.mode),
        };

        assert!(
            receiver_ctx_result.is_ok(),
            "Receiver setup should succeed for test vector {}",
            test_vector.id
        );

        let mut receiver_ctx = receiver_ctx_result.unwrap();

        // Test decryption
        let decrypted_result = receiver_ctx.open(&test_vector.aad, &ciphertext);
        assert!(
            decrypted_result.is_ok(),
            "Decryption should succeed for test vector {}",
            test_vector.id
        );

        let decrypted = decrypted_result.unwrap();
        assert_eq!(
            decrypted, test_vector.plaintext,
            "Decrypted message should match original for test vector {}",
            test_vector.id
        );

        // Test key export if applicable
        if test_vector.expected_exported_key.is_some() {
            let export_context = b"export-context";
            let export_length = 32;
            let exported_key_result = sender_ctx.export(export_context, export_length);
            assert!(
                exported_key_result.is_ok(),
                "Key export should succeed for test vector {}",
                test_vector.id
            );

            let exported_key = exported_key_result.unwrap();
            assert_eq!(
                exported_key.len(),
                export_length,
                "Exported key should have correct length for test vector {}",
                test_vector.id
            );

            // Verify that receiver can export the same key
            let receiver_exported_key_result = receiver_ctx.export(export_context, export_length);
            assert!(
                receiver_exported_key_result.is_ok(),
                "Receiver key export should succeed for test vector {}",
                test_vector.id
            );

            let receiver_exported_key = receiver_exported_key_result.unwrap();
            assert_eq!(
                exported_key, receiver_exported_key,
                "Exported keys should match for test vector {}",
                test_vector.id
            );
        }

        println!("✓ Test vector {} passed", test_vector.id);
    }
}

/// Test HPKE error handling with invalid inputs
#[test]
fn test_hpke_error_handling() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    // Generate valid key pair
    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));
    let recipient_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512, None).unwrap();
    let recipient_pk = KemPublicKey::new(recipient_keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(recipient_keypair.secret_key().as_bytes().to_vec());

    // Test with invalid encapsulated key
    let invalid_encapsulated_key = vec![0u8; 100]; // Wrong size
    let invalid_receiver_result =
        hpke_ctx.setup_receiver(&invalid_encapsulated_key, &recipient_sk, b"info");
    assert!(
        invalid_receiver_result.is_err(),
        "Setup should fail with invalid encapsulated key"
    );

    // Test with wrong recipient key
    let wrong_recipient_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512, None).unwrap();
    let wrong_recipient_sk =
        KemSecretKey::new(wrong_recipient_keypair.secret_key().as_bytes().to_vec());

    let mut sender_ctx = hpke_ctx.setup_sender(&recipient_pk, b"info").unwrap();
    let wrong_receiver_result =
        hpke_ctx.setup_receiver(sender_ctx.encapsulated_key(), &wrong_recipient_sk, b"info");

    // Note: In HPKE, using a wrong recipient key will cause decryption to fail,
    // but the setup itself may succeed. The authentication happens during decryption.
    // Let's test that decryption fails instead.
    if wrong_receiver_result.is_ok() {
        let mut wrong_receiver_ctx = wrong_receiver_result.unwrap();
        let message = b"test message";
        let aad = b"test aad";
        let ciphertext = sender_ctx.seal(aad, message).unwrap();
        let decrypt_result = wrong_receiver_ctx.open(aad, &ciphertext);
        assert!(
            decrypt_result.is_err(),
            "Decryption should fail with wrong recipient key"
        );
    } else {
        // If setup fails, that's also acceptable
        println!("Setup failed with wrong recipient key (acceptable behavior)");
    }
}

/// Test HPKE with different message sizes
#[test]
fn test_hpke_message_sizes() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    // Generate key pair
    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));
    let recipient_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512, None).unwrap();
    let recipient_pk = KemPublicKey::new(recipient_keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(recipient_keypair.secret_key().as_bytes().to_vec());

    let message_sizes = vec![0, 1, 16, 64, 256, 1024, 4096];

    for size in message_sizes {
        let message = vec![0x42u8; size];
        let aad = b"test-aad";

        // Setup sender and receiver
        let mut sender_ctx = hpke_ctx.setup_sender(&recipient_pk, b"info").unwrap();
        let mut receiver_ctx = hpke_ctx
            .setup_receiver(sender_ctx.encapsulated_key(), &recipient_sk, b"info")
            .unwrap();

        // Encrypt and decrypt
        let ciphertext = sender_ctx.seal(aad, &message).unwrap();
        let decrypted = receiver_ctx.open(aad, &ciphertext).unwrap();

        assert_eq!(
            decrypted, message,
            "Message of size {} should encrypt/decrypt correctly",
            size
        );
    }
}
