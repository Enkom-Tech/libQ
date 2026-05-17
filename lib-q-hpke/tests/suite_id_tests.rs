#![cfg(feature = "std")]

use std::sync::Arc;

use lib_q_hpke::providers::post_quantum::PostQuantumProvider;
use lib_q_hpke::providers::traits::HpkeCryptoProvider;
use lib_q_hpke::{
    HpkeAead,
    HpkeCipherSuite,
    HpkeKdf,
    HpkeKem,
    HpkeMode,
    hpke_core,
};

/// Test vectors for suite ID construction
mod test_vectors {

    /// Expected suite ID for ML-KEM-512, HKDF-SHAKE256, Saturnin256
    pub const SUITE_ID_MLKEM512_SHAKE256_SATURNIN256: &[u8] = &[
        b'H', b'P', b'K', b'E', // "HPKE" prefix
        0x00, 0x22, // ML-KEM-512 (0x0022)
        0x00, 0x05, // HKDF-SHAKE256 (0x0005)
        0x00, 0x04, // Saturnin256 (0x0004)
    ];

    /// Expected suite ID for ML-KEM-768, HKDF-SHA3-256, Saturnin256
    pub const SUITE_ID_MLKEM768_SHA3_256_SATURNIN256: &[u8] = &[
        b'H', b'P', b'K', b'E', // "HPKE" prefix
        0x00, 0x23, // ML-KEM-768 (0x0023)
        0x00, 0x06, // HKDF-SHA3-256 (0x0006)
        0x00, 0x04, // Saturnin256 (0x0004)
    ];

    /// Expected suite ID for ML-KEM-1024, HKDF-SHA3-512, Saturnin256
    pub const SUITE_ID_MLKEM1024_SHA3_512_SATURNIN256: &[u8] = &[
        b'H', b'P', b'K', b'E', // "HPKE" prefix
        0x00, 0x24, // ML-KEM-1024 (0x0024)
        0x00, 0x07, // HKDF-SHA3-512 (0x0007)
        0x00, 0x04, // Saturnin256 (0x0004)
    ];
}

/// Test suite ID construction with different cipher suites
#[test]
fn test_suite_id_construction() {
    // Test ML-KEM-512, HKDF-SHAKE256, Saturnin256
    let cipher_suite = HpkeCipherSuite::new(
        HpkeKem::MlKem512,
        HpkeKdf::HkdfShake256,
        HpkeAead::Saturnin256,
    );
    let suite_id =
        hpke_core::create_suite_id(&cipher_suite).expect("Suite ID creation should work");
    assert_eq!(
        suite_id,
        test_vectors::SUITE_ID_MLKEM512_SHAKE256_SATURNIN256
    );

    // Test ML-KEM-768, HKDF-SHA3-256, Saturnin256
    let cipher_suite = HpkeCipherSuite::new(
        HpkeKem::MlKem768,
        HpkeKdf::HkdfSha3_256,
        HpkeAead::Saturnin256,
    );
    let suite_id =
        hpke_core::create_suite_id(&cipher_suite).expect("Suite ID creation should work");
    assert_eq!(
        suite_id,
        test_vectors::SUITE_ID_MLKEM768_SHA3_256_SATURNIN256
    );

    // Test ML-KEM-1024, HKDF-SHA3-512, Saturnin256
    let cipher_suite = HpkeCipherSuite::new(
        HpkeKem::MlKem1024,
        HpkeKdf::HkdfSha3_512,
        HpkeAead::Saturnin256,
    );
    let suite_id =
        hpke_core::create_suite_id(&cipher_suite).expect("Suite ID creation should work");
    assert_eq!(
        suite_id,
        test_vectors::SUITE_ID_MLKEM1024_SHA3_512_SATURNIN256
    );
}

/// Test suite ID construction with all KEM variants
#[test]
fn test_suite_id_all_kems() {
    let kems = [HpkeKem::MlKem512, HpkeKem::MlKem768, HpkeKem::MlKem1024];
    let expected_ids = [0x0022u16, 0x0023u16, 0x0024u16];

    for (kem, expected_id) in kems.iter().zip(expected_ids.iter()) {
        let cipher_suite = HpkeCipherSuite::new(*kem, HpkeKdf::HkdfShake256, HpkeAead::Saturnin256);
        let suite_id =
            hpke_core::create_suite_id(&cipher_suite).expect("Suite ID creation should work");

        // Check that the KEM ID is in the correct position (bytes 4-5)
        let kem_id_bytes = &suite_id[4..6];
        let kem_id = u16::from_be_bytes([kem_id_bytes[0], kem_id_bytes[1]]);
        assert_eq!(kem_id, *expected_id, "KEM ID mismatch for {:?}", kem);
    }
}

/// Test suite ID construction with all KDF variants
#[test]
fn test_suite_id_all_kdfs() {
    let kdfs = [
        HpkeKdf::HkdfShake128,
        HpkeKdf::HkdfShake256,
        HpkeKdf::HkdfSha3_256,
        HpkeKdf::HkdfSha3_512,
    ];
    let expected_ids = [0x0004u16, 0x0005u16, 0x0006u16, 0x0007u16];

    for (kdf, expected_id) in kdfs.iter().zip(expected_ids.iter()) {
        let cipher_suite = HpkeCipherSuite::new(HpkeKem::MlKem512, *kdf, HpkeAead::Saturnin256);
        let suite_id =
            hpke_core::create_suite_id(&cipher_suite).expect("Suite ID creation should work");

        // Check that the KDF ID is in the correct position (bytes 6-7)
        let kdf_id_bytes = &suite_id[6..8];
        let kdf_id = u16::from_be_bytes([kdf_id_bytes[0], kdf_id_bytes[1]]);
        assert_eq!(kdf_id, *expected_id, "KDF ID mismatch for {:?}", kdf);
    }
}

/// Test suite ID construction with all AEAD variants
#[test]
fn test_suite_id_all_aeads() {
    let aeads = [
        HpkeAead::Saturnin256,
        HpkeAead::Shake256,
        HpkeAead::DuplexSpongeAead,
    ];
    let expected_ids = [0x0004u16, 0x0005u16, 0x0006u16];

    for (aead, expected_id) in aeads.iter().zip(expected_ids.iter()) {
        let cipher_suite = HpkeCipherSuite::new(HpkeKem::MlKem512, HpkeKdf::HkdfShake256, *aead);
        let suite_id =
            hpke_core::create_suite_id(&cipher_suite).expect("Suite ID creation should work");

        // Check that the AEAD ID is in the correct position (bytes 8-9)
        let aead_id_bytes = &suite_id[8..10];
        let aead_id = u16::from_be_bytes([aead_id_bytes[0], aead_id_bytes[1]]);
        assert_eq!(aead_id, *expected_id, "AEAD ID mismatch for {:?}", aead);
    }
}

/// Test suite ID format compliance with RFC 9180
#[test]
fn test_suite_id_rfc_compliance() {
    let cipher_suite = HpkeCipherSuite::new(
        HpkeKem::MlKem512,
        HpkeKdf::HkdfShake256,
        HpkeAead::Saturnin256,
    );
    let suite_id =
        hpke_core::create_suite_id(&cipher_suite).expect("Suite ID creation should work");

    // RFC 9180 Section 4: Suite ID should start with "HPKE"
    assert_eq!(
        &suite_id[0..4],
        b"HPKE",
        "Suite ID should start with 'HPKE'"
    );

    // Suite ID should be exactly 10 bytes: 4 (HPKE) + 2 (KEM) + 2 (KDF) + 2 (AEAD)
    assert_eq!(suite_id.len(), 10, "Suite ID should be exactly 10 bytes");

    // All algorithm IDs should be valid (non-zero)
    let kem_id = u16::from_be_bytes([suite_id[4], suite_id[5]]);
    let kdf_id = u16::from_be_bytes([suite_id[6], suite_id[7]]);
    let aead_id = u16::from_be_bytes([suite_id[8], suite_id[9]]);

    assert_ne!(kem_id, 0, "KEM ID should not be zero");
    assert_ne!(kdf_id, 0, "KDF ID should not be zero");
    assert_ne!(aead_id, 0, "AEAD ID should not be zero");
}

/// Test key schedule with different cipher suites
#[test]
fn test_key_schedule_with_different_cipher_suites() {
    use lib_q_hpke::providers::post_quantum::PostQuantumProvider;

    let shared_secret = b"test_shared_secret_32_bytes_long!";
    let info = b"test_info";

    // Test with ML-KEM-512, HKDF-SHAKE256, Saturnin256
    let cipher_suite1 = HpkeCipherSuite::new(
        HpkeKem::MlKem512,
        HpkeKdf::HkdfShake256,
        HpkeAead::Saturnin256,
    );
    let provider = PostQuantumProvider::new();
    let result1 = hpke_core::key_schedule(
        HpkeMode::Base,
        shared_secret,
        info,
        None,
        None,
        &cipher_suite1,
        &provider,
    )
    .expect("Key schedule should work");

    // Test with ML-KEM-768, HKDF-SHA3-256, Saturnin256
    let cipher_suite2 = HpkeCipherSuite::new(
        HpkeKem::MlKem768,
        HpkeKdf::HkdfSha3_256,
        HpkeAead::Saturnin256,
    );
    let result2 = hpke_core::key_schedule(
        HpkeMode::Base,
        shared_secret,
        info,
        None,
        None,
        &cipher_suite2,
        &provider,
    )
    .expect("Key schedule should work");

    // Results should be different due to different cipher suites
    assert_ne!(
        result1.key, result2.key,
        "Keys should be different for different cipher suites"
    );
    assert_ne!(
        result1.nonce, result2.nonce,
        "Nonces should be different for different cipher suites"
    );
    assert_ne!(
        result1.exporter_secret, result2.exporter_secret,
        "Exporter secrets should be different for different cipher suites"
    );
}

/// Test key schedule determinism with same cipher suite
#[test]
fn test_key_schedule_determinism() {
    use lib_q_hpke::providers::post_quantum::PostQuantumProvider;

    let shared_secret = b"test_shared_secret_32_bytes_long!";
    let info = b"test_info";
    let cipher_suite = HpkeCipherSuite::new(
        HpkeKem::MlKem512,
        HpkeKdf::HkdfShake256,
        HpkeAead::Saturnin256,
    );

    // Run key schedule twice with same parameters
    let provider = PostQuantumProvider::new();
    let result1 = hpke_core::key_schedule(
        HpkeMode::Base,
        shared_secret,
        info,
        None,
        None,
        &cipher_suite,
        &provider,
    )
    .expect("Key schedule should work");

    let result2 = hpke_core::key_schedule(
        HpkeMode::Base,
        shared_secret,
        info,
        None,
        None,
        &cipher_suite,
        &provider,
    )
    .expect("Key schedule should work");

    // Results should be identical
    assert_eq!(
        result1.key, result2.key,
        "Keys should be identical for same parameters"
    );
    assert_eq!(
        result1.nonce, result2.nonce,
        "Nonces should be identical for same parameters"
    );
    assert_eq!(
        result1.exporter_secret, result2.exporter_secret,
        "Exporter secrets should be identical for same parameters"
    );
}

/// Export-only AEAD: RFC 9180 key schedule uses N_key = N_nonce = 0 (no payload key material).
#[test]
fn test_key_schedule_export_aead_zero_key_and_nonce() {
    use lib_q_hpke::providers::post_quantum::PostQuantumProvider;

    let shared_secret = b"test_shared_secret_32_bytes_long!";
    let info = b"test_info";
    let cipher_suite =
        HpkeCipherSuite::new(HpkeKem::MlKem512, HpkeKdf::HkdfSha3_256, HpkeAead::Export);
    let provider = PostQuantumProvider::new();
    let schedule = hpke_core::key_schedule(
        HpkeMode::Base,
        shared_secret,
        info,
        None,
        None,
        &cipher_suite,
        &provider,
    )
    .expect("Key schedule should work for Export AEAD");

    assert!(
        schedule.key.is_empty(),
        "Export suite must derive zero-length AEAD key"
    );
    assert!(
        schedule.nonce.is_empty(),
        "Export suite must derive zero-length base nonce"
    );
    assert_eq!(schedule.exporter_secret.len(), 32);
}

/// Test setup_sender with different cipher suites
#[test]
fn test_setup_sender_with_cipher_suite() {
    use lib_q_core::KemContext;

    // Create a test key pair
    let mut kem_ctx = KemContext::with_provider(Box::new(
        lib_q_kem::LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));
    let keypair = kem_ctx
        .generate_keypair(lib_q_core::Algorithm::MlKem512, None)
        .expect("Key generation should work");
    let recipient_pk = lib_q_core::KemPublicKey::new(keypair.public_key().as_bytes().to_vec());

    let info = b"test_info";
    let cipher_suite = HpkeCipherSuite::new(
        HpkeKem::MlKem512,
        HpkeKdf::HkdfShake256,
        HpkeAead::Saturnin256,
    );

    let mut kem_ctx_for_setup = KemContext::new();
    let hpke_crypto: Arc<dyn HpkeCryptoProvider + Send + Sync> =
        Arc::new(PostQuantumProvider::new());
    let mut rng = lib_q_hpke::security::prng::SimpleRng::new();
    let result = hpke_core::setup_sender(
        &mut kem_ctx_for_setup,
        &recipient_pk,
        info,
        &cipher_suite,
        hpke_crypto.as_ref(),
        &mut rng,
        hpke_crypto.clone(),
    )
    .expect("Setup sender should work");

    // Verify that the context was created successfully
    assert!(!result.key.is_empty(), "Key should not be empty");
    assert!(!result.nonce.is_empty(), "Nonce should not be empty");
    assert!(
        !result.exporter_secret.is_empty(),
        "Exporter secret should not be empty"
    );
}

/// Test setup_receiver with different cipher suites
#[test]
fn test_setup_receiver_with_cipher_suite() {
    use lib_q_core::KemContext;

    // Create a test key pair
    let mut kem_ctx = KemContext::with_provider(Box::new(
        lib_q_kem::LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));
    let keypair = kem_ctx
        .generate_keypair(lib_q_core::Algorithm::MlKem512, None)
        .expect("Key generation should work");
    let recipient_sk = lib_q_core::KemSecretKey::new(keypair.secret_key().as_bytes().to_vec());

    // Create a dummy encapsulated key (in real usage, this would come from sender)
    let encapsulated_key = vec![0u8; 768]; // ML-KEM-512 encapsulated key size
    let info = b"test_info";
    let cipher_suite = HpkeCipherSuite::new(
        HpkeKem::MlKem512,
        HpkeKdf::HkdfShake256,
        HpkeAead::Saturnin256,
    );

    let mut kem_ctx_for_setup = KemContext::new();
    let hpke_crypto: Arc<dyn HpkeCryptoProvider + Send + Sync> =
        Arc::new(PostQuantumProvider::new());
    let result = hpke_core::setup_receiver(
        &mut kem_ctx_for_setup,
        &encapsulated_key,
        &recipient_sk,
        info,
        &cipher_suite,
        hpke_crypto.as_ref(),
        hpke_crypto.clone(),
    )
    .expect("Setup receiver should work");

    // Verify that the context was created successfully
    assert!(!result.key.is_empty(), "Key should not be empty");
    assert!(!result.nonce.is_empty(), "Nonce should not be empty");
    assert!(
        !result.exporter_secret.is_empty(),
        "Exporter secret should not be empty"
    );
}

/// Test error handling for invalid cipher suite combinations
#[test]
fn test_invalid_cipher_suite_combinations() {
    // Test with Export-only AEAD (should be handled gracefully)
    let cipher_suite =
        HpkeCipherSuite::new(HpkeKem::MlKem512, HpkeKdf::HkdfShake256, HpkeAead::Export);

    // This should work for suite ID creation
    let suite_id =
        hpke_core::create_suite_id(&cipher_suite).expect("Suite ID creation should work");
    assert_eq!(
        suite_id.len(),
        10,
        "Suite ID should be created even for Export AEAD"
    );

    // Check that Export AEAD ID (0xFFFF) is correctly placed
    let aead_id_bytes = &suite_id[8..10];
    let aead_id = u16::from_be_bytes([aead_id_bytes[0], aead_id_bytes[1]]);
    assert_eq!(aead_id, 0xFFFF, "Export AEAD ID should be 0xFFFF");
}
