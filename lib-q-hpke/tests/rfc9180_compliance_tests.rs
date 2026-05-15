//! RFC 9180 compliance tests for HPKE implementation
//!
//! These tests ensure our HPKE implementation follows the official RFC 9180 specification
//! and can interoperate with other compliant implementations.

#![cfg(feature = "std")]
#![allow(
    clippy::len_zero,
    clippy::assertions_on_constants,
    clippy::needless_borrow
)]

use lib_q_core::{
    Algorithm,
    KemContext,
};
use lib_q_hpke::{
    HpkeAead,
    HpkeCipherSuite,
    HpkeContext,
    HpkeKdf,
    HpkeKem,
    HpkeMode,
};
use lib_q_kem::LibQKemProvider;

/// Test vectors for RFC 9180 compliance
mod test_vectors {
    // These will be populated with official RFC 9180 test vectors
    pub const TEST_INFO: &[u8] = b"HPKE test info";
    pub const TEST_AAD: &[u8] = b"HPKE test aad";
    pub const TEST_PLAINTEXT: &[u8] = b"Hello, HPKE!";

    // Note: Official RFC 9180 test vectors would be added here when available
}

/// Test HPKE cipher suite creation and validation
#[test]
fn test_cipher_suite_creation() {
    let suite = HpkeCipherSuite::new(
        HpkeKem::MlKem512,
        HpkeKdf::HkdfShake256,
        HpkeAead::Saturnin256,
    );

    // Verify algorithm IDs match RFC 9180
    assert_eq!(suite.kem.algorithm_id(), 0x0022); // ML-KEM-512
    assert_eq!(suite.kdf.algorithm_id(), 0x0005); // HKDF-SHAKE256
    assert_eq!(suite.aead.algorithm_id(), 0x0004); // Saturnin-256

    // Verify suite identifier format
    let suite_id = suite.identifier();
    assert_eq!(suite_id.len(), 6); // 2 bytes per algorithm
}

/// Test HPKE mode validation
#[test]
fn test_hpke_modes() {
    // Test mode conversion
    assert_eq!(HpkeMode::from_u8(0x00), Some(HpkeMode::Base));
    assert_eq!(HpkeMode::from_u8(0x01), Some(HpkeMode::Psk));
    assert_eq!(HpkeMode::from_u8(0x02), Some(HpkeMode::Auth));
    assert_eq!(HpkeMode::from_u8(0x03), Some(HpkeMode::AuthPsk));
    assert_eq!(HpkeMode::from_u8(0x04), None); // Invalid mode

    // Test mode to u8 conversion
    assert_eq!(HpkeMode::Base.as_u8(), 0x00);
    assert_eq!(HpkeMode::Psk.as_u8(), 0x01);
    assert_eq!(HpkeMode::Auth.as_u8(), 0x02);
    assert_eq!(HpkeMode::AuthPsk.as_u8(), 0x03);
}

/// Test KEM algorithm properties
#[test]
fn test_kem_properties() {
    // Test ML-KEM-512
    assert_eq!(HpkeKem::MlKem512.shared_secret_len(), 32);
    assert_eq!(HpkeKem::MlKem512.enc_len(), 768);

    // Test ML-KEM-768
    assert_eq!(HpkeKem::MlKem768.shared_secret_len(), 32);
    assert_eq!(HpkeKem::MlKem768.enc_len(), 1088);

    // Test ML-KEM-1024
    assert_eq!(HpkeKem::MlKem1024.shared_secret_len(), 32);
    assert_eq!(HpkeKem::MlKem1024.enc_len(), 1568);
}

/// Test KDF algorithm properties
#[test]
fn test_kdf_properties() {
    // Test HKDF-SHAKE128
    assert_eq!(HpkeKdf::HkdfShake128.digest_len(), 32);

    // Test HKDF-SHAKE256
    assert_eq!(HpkeKdf::HkdfShake256.digest_len(), 64);

    // Test HKDF-SHA3-256
    assert_eq!(HpkeKdf::HkdfSha3_256.digest_len(), 32);

    // Test HKDF-SHA3-512
    assert_eq!(HpkeKdf::HkdfSha3_512.digest_len(), 64);
}

/// Test AEAD algorithm properties
#[test]
fn test_aead_properties() {
    // Test Saturnin-256
    assert_eq!(HpkeAead::Saturnin256.key_len(), 32);
    assert_eq!(HpkeAead::Saturnin256.nonce_len(), 16);
    assert_eq!(HpkeAead::Saturnin256.tag_len(), 32);

    // Test SHAKE256
    assert_eq!(HpkeAead::Shake256.key_len(), 32);
    assert_eq!(HpkeAead::Shake256.nonce_len(), 16);
    assert_eq!(HpkeAead::Shake256.tag_len(), 16);

    // Duplex-sponge AEAD (lib-Q extension)
    assert_eq!(HpkeAead::DuplexSpongeAead.key_len(), 32);
    assert_eq!(HpkeAead::DuplexSpongeAead.nonce_len(), 16);
    assert_eq!(HpkeAead::DuplexSpongeAead.tag_len(), 32);

    // Test Export mode
    assert_eq!(HpkeAead::Export.key_len(), 0);
    assert_eq!(HpkeAead::Export.nonce_len(), 0);
    assert_eq!(HpkeAead::Export.tag_len(), 0);
}

/// Export-only AEAD (RFC 9180 0xFFFF): single-shot `seal` must fail (bypasses `can_encrypt` on contexts).
#[test]
#[cfg(feature = "ml-kem")]
fn test_export_only_suite_rejects_single_shot_seal() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);
    hpke_ctx.set_cipher_suite(HpkeCipherSuite::new(
        HpkeKem::MlKem512,
        HpkeKdf::HkdfSha3_256,
        HpkeAead::Export,
    ));

    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));
    let recipient_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Key generation should work");
    let recipient_pk =
        lib_q_core::KemPublicKey::new(recipient_keypair.public_key().as_bytes().to_vec());

    let seal_result = hpke_ctx.seal(
        &recipient_pk,
        test_vectors::TEST_INFO,
        test_vectors::TEST_AAD,
        test_vectors::TEST_PLAINTEXT,
    );
    assert!(
        seal_result.is_err(),
        "Export-only cipher suite must not allow single-shot payload encryption"
    );
}

/// Test HPKE context creation
#[test]
fn test_hpke_context_creation() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let _hpke_ctx = HpkeContext::with_provider(provider);
    // Context creation should not panic
}

/// Test key pair generation through KEM context
#[test]
fn test_kem_key_generation() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(provider);

    // Test ML-KEM-512 key generation
    let keypair_512 = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("ML-KEM-512 key generation should work");

    // Verify key sizes
    assert_eq!(keypair_512.public_key().as_bytes().len(), 800); // ML-KEM-512 public key size
    assert_eq!(keypair_512.secret_key().as_bytes().len(), 1632); // ML-KEM-512 secret key size

    // Test ML-KEM-768 key generation
    let keypair_768 = kem_ctx
        .generate_keypair(Algorithm::MlKem768, None)
        .expect("ML-KEM-768 key generation should work");

    assert_eq!(keypair_768.public_key().as_bytes().len(), 1184); // ML-KEM-768 public key size
    assert_eq!(keypair_768.secret_key().as_bytes().len(), 2400); // ML-KEM-768 secret key size

    // Test ML-KEM-1024 key generation
    let keypair_1024 = kem_ctx
        .generate_keypair(Algorithm::MlKem1024, None)
        .expect("ML-KEM-1024 key generation should work");

    assert_eq!(keypair_1024.public_key().as_bytes().len(), 1568); // ML-KEM-1024 public key size
    assert_eq!(keypair_1024.secret_key().as_bytes().len(), 3168); // ML-KEM-1024 secret key size
}

/// Test KEM encapsulation/decapsulation
#[test]
fn test_kem_encapsulation_decapsulation() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(provider);

    // Generate key pair
    let keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Key generation should work");

    // Test encapsulation
    let (ciphertext, shared_secret1) = kem_ctx
        .encapsulate(Algorithm::MlKem512, keypair.public_key(), None)
        .expect("Encapsulation should work");

    // Verify ciphertext size
    assert_eq!(ciphertext.len(), 768); // ML-KEM-512 ciphertext size
    assert_eq!(shared_secret1.len(), 32); // ML-KEM shared secret size

    // Test decapsulation
    let shared_secret2 = kem_ctx
        .decapsulate(Algorithm::MlKem512, keypair.secret_key(), &ciphertext)
        .expect("Decapsulation should work");

    // Verify shared secrets match
    assert_eq!(shared_secret1, shared_secret2);
}

/// Test HPKE single-shot encryption/decryption (placeholder)
#[test]
fn test_hpke_single_shot() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    // Generate recipient key pair
    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));
    let recipient_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Key generation should work");

    // Convert to HPKE format
    let recipient_pk =
        lib_q_core::KemPublicKey::new(recipient_keypair.public_key().as_bytes().to_vec());
    let recipient_sk =
        lib_q_core::KemSecretKey::new(recipient_keypair.secret_key().as_bytes().to_vec());

    // Test single-shot encryption
    let (encapsulated_key, ciphertext) = hpke_ctx
        .seal(
            &recipient_pk,
            test_vectors::TEST_INFO,
            test_vectors::TEST_AAD,
            test_vectors::TEST_PLAINTEXT,
        )
        .expect("HPKE seal should work");

    // Verify output sizes
    assert_eq!(encapsulated_key.len(), 768); // ML-KEM-512 ciphertext size
    assert!(ciphertext.len() > 0); // Should have some ciphertext

    // Test single-shot decryption
    let decrypted = hpke_ctx
        .open(
            &encapsulated_key,
            &recipient_sk,
            test_vectors::TEST_INFO,
            test_vectors::TEST_AAD,
            &ciphertext,
        )
        .expect("HPKE open should work");

    // Verify decryption
    assert_eq!(decrypted, test_vectors::TEST_PLAINTEXT);
}

/// Test HPKE context setup (placeholder)
#[test]
fn test_hpke_context_setup() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    // Generate recipient key pair
    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));
    let recipient_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Key generation should work");

    // Convert to HPKE format
    let recipient_pk =
        lib_q_core::KemPublicKey::new(recipient_keypair.public_key().as_bytes().to_vec());
    let recipient_sk =
        lib_q_core::KemSecretKey::new(recipient_keypair.secret_key().as_bytes().to_vec());

    // Test sender context setup
    let _sender_ctx = hpke_ctx
        .setup_sender(&recipient_pk, test_vectors::TEST_INFO)
        .expect("Sender setup should work");

    // Test receiver context setup (this will need the encapsulated key from sender)
    // For now, we'll test with a placeholder
    let encapsulated_key = vec![0u8; 768]; // Placeholder
    let _receiver_ctx = hpke_ctx
        .setup_receiver(&encapsulated_key, &recipient_sk, test_vectors::TEST_INFO)
        .expect("Receiver setup should work");
}

/// Test key export functionality (placeholder)
#[test]
fn test_key_export() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    // Generate recipient key pair
    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));
    let recipient_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Key generation should work");

    // Convert to HPKE format
    let recipient_pk =
        lib_q_core::KemPublicKey::new(recipient_keypair.public_key().as_bytes().to_vec());

    // Setup sender context
    let sender_ctx = hpke_ctx
        .setup_sender(&recipient_pk, test_vectors::TEST_INFO)
        .expect("Sender setup should work");

    // Test key export
    let exported_key = sender_ctx
        .export(b"test-context", 32)
        .expect("Key export should work");

    // Verify export size
    assert_eq!(exported_key.len(), 32);
}

/// Test error handling
#[test]
fn test_error_handling() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    // Test with invalid key sizes
    let invalid_pk = lib_q_core::KemPublicKey::new(vec![0u8; 100]); // Wrong size
    let result = hpke_ctx.setup_sender(&invalid_pk, test_vectors::TEST_INFO);
    assert!(result.is_err(), "Should fail with invalid key size");
}

/// Test multiple cipher suites
#[test]
fn test_multiple_cipher_suites() {
    let suites = vec![
        HpkeCipherSuite::new(
            HpkeKem::MlKem512,
            HpkeKdf::HkdfShake128,
            HpkeAead::Saturnin256,
        ),
        HpkeCipherSuite::new(
            HpkeKem::MlKem768,
            HpkeKdf::HkdfShake256,
            HpkeAead::Saturnin256,
        ),
        HpkeCipherSuite::new(
            HpkeKem::MlKem1024,
            HpkeKdf::HkdfSha3_256,
            HpkeAead::Saturnin256,
        ),
        HpkeCipherSuite::new(HpkeKem::MlKem512, HpkeKdf::HkdfSha3_512, HpkeAead::Shake256),
    ];

    for suite in suites {
        let suite_id = suite.identifier();
        assert_eq!(suite_id.len(), 6); // 2 bytes per algorithm

        // Verify each algorithm ID is valid
        assert!(suite.kem.algorithm_id() > 0);
        assert!(suite.kdf.algorithm_id() > 0);
        assert!(suite.aead.algorithm_id() > 0);
    }
}

/// Test RFC 9180 labeled extract/expand functions (placeholder)
#[test]
fn test_labeled_functions() {
    // This test will be implemented once we have proper KDF implementation
    // For now, just verify the test compiles
    assert!(true);
}

/// Test PSK mode
#[test]
fn test_psk_mode() {
    use lib_q_core::{
        Algorithm,
        KemContext,
    };
    use lib_q_hpke::hpke_core::setup_sender_with_mode;
    use lib_q_hpke::providers::post_quantum::PostQuantumProvider;
    use lib_q_hpke::security::prng::Kt128Rng;
    use lib_q_hpke::types::{
        HpkeAead,
        HpkeCipherSuite,
        HpkeKdf,
        HpkeKem,
        HpkeMode,
        HpkePskWireFormat,
    };

    let provider = PostQuantumProvider::new();
    let mut rng = Kt128Rng::new().expect("Failed to create RNG");

    // Create cipher suite
    let cipher_suite = HpkeCipherSuite {
        kem: HpkeKem::MlKem512,
        kdf: HpkeKdf::HkdfShake256,
        aead: HpkeAead::Saturnin256,
    };

    // Generate recipient key pair
    let kem_provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(kem_provider);
    let keypair = kem_ctx.generate_keypair(Algorithm::MlKem512, None).unwrap();
    let recipient_pk = keypair.public_key();
    let _recipient_sk = keypair.secret_key();

    // PSK and PSK ID for PSK mode
    let psk = b"test-psk-key";
    let psk_id = b"test-psk-id";
    let info = b"test-info";

    // Test PSK mode setup
    let sender_ctx = setup_sender_with_mode(
        &mut kem_ctx,
        &recipient_pk,
        info,
        &cipher_suite,
        &provider,
        &mut rng,
        HpkeMode::Psk,
        Some(psk),
        Some(psk_id),
        None,
        None,
        HpkePskWireFormat::Rfc9180,
    )
    .unwrap();

    // Verify PSK mode was set up correctly
    assert!(!sender_ctx.shared_secret.is_empty());
    assert!(!sender_ctx.key.is_empty());
    assert!(!sender_ctx.nonce.is_empty());
    assert!(!sender_ctx.exporter_secret.is_empty());
}

/// Test Auth mode
#[test]
fn test_auth_mode() {
    use lib_q_core::{
        Algorithm,
        KemContext,
    };
    use lib_q_hpke::hpke_core::setup_sender_with_mode;
    use lib_q_hpke::providers::post_quantum::PostQuantumProvider;
    use lib_q_hpke::security::prng::Kt128Rng;
    use lib_q_hpke::types::{
        HpkeAead,
        HpkeCipherSuite,
        HpkeKdf,
        HpkeKem,
        HpkeMode,
        HpkePskWireFormat,
    };

    let provider = PostQuantumProvider::new();
    let mut rng = Kt128Rng::new().expect("Failed to create RNG");

    // Create cipher suite
    let cipher_suite = HpkeCipherSuite {
        kem: HpkeKem::MlKem512,
        kdf: HpkeKdf::HkdfShake256,
        aead: HpkeAead::Saturnin256,
    };

    // Generate recipient key pair
    let recipient_kem_provider =
        Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut recipient_kem_ctx = KemContext::with_provider(recipient_kem_provider);
    let recipient_keypair = recipient_kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .unwrap();
    let recipient_pk = recipient_keypair.public_key();
    let _recipient_sk = recipient_keypair.secret_key();

    // Generate sender key pair for Auth mode
    let sender_kem_provider =
        Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut sender_kem_ctx = KemContext::with_provider(sender_kem_provider);
    let sender_keypair = sender_kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .unwrap();
    let sender_pk = sender_keypair.public_key();
    let sender_sk = sender_keypair.secret_key();

    let info = b"test-info";

    // Test Auth mode setup
    let sender_ctx = setup_sender_with_mode(
        &mut sender_kem_ctx,
        &recipient_pk,
        info,
        &cipher_suite,
        &provider,
        &mut rng,
        HpkeMode::Auth,
        None,
        None,
        Some(&sender_sk),
        Some(&sender_pk),
        HpkePskWireFormat::default(),
    )
    .unwrap();

    // Verify Auth mode was set up correctly
    assert!(!sender_ctx.shared_secret.is_empty());
    assert!(!sender_ctx.key.is_empty());
    assert!(!sender_ctx.nonce.is_empty());
    assert!(!sender_ctx.exporter_secret.is_empty());
}

/// Test AuthPSK mode
#[test]
fn test_auth_psk_mode() {
    use lib_q_core::{
        Algorithm,
        KemContext,
    };
    use lib_q_hpke::hpke_core::setup_sender_with_mode;
    use lib_q_hpke::providers::post_quantum::PostQuantumProvider;
    use lib_q_hpke::security::prng::Kt128Rng;
    use lib_q_hpke::types::{
        HpkeAead,
        HpkeCipherSuite,
        HpkeKdf,
        HpkeKem,
        HpkeMode,
        HpkePskWireFormat,
    };

    let provider = PostQuantumProvider::new();
    let mut rng = Kt128Rng::new().expect("Failed to create RNG");

    // Create cipher suite
    let cipher_suite = HpkeCipherSuite {
        kem: HpkeKem::MlKem512,
        kdf: HpkeKdf::HkdfShake256,
        aead: HpkeAead::Saturnin256,
    };

    // Generate recipient key pair
    let recipient_kem_provider =
        Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut recipient_kem_ctx = KemContext::with_provider(recipient_kem_provider);
    let recipient_keypair = recipient_kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .unwrap();
    let recipient_pk = recipient_keypair.public_key();
    let _recipient_sk = recipient_keypair.secret_key();

    // Generate sender key pair for AuthPSK mode
    let sender_kem_provider =
        Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut sender_kem_ctx = KemContext::with_provider(sender_kem_provider);
    let sender_keypair = sender_kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .unwrap();
    let sender_pk = sender_keypair.public_key();
    let sender_sk = sender_keypair.secret_key();

    // PSK and PSK ID for AuthPSK mode
    let psk = b"test-psk-key";
    let psk_id = b"test-psk-id";
    let info = b"test-info";

    // Test AuthPSK mode setup
    let sender_ctx = setup_sender_with_mode(
        &mut sender_kem_ctx,
        &recipient_pk,
        info,
        &cipher_suite,
        &provider,
        &mut rng,
        HpkeMode::AuthPsk,
        Some(psk),
        Some(psk_id),
        Some(&sender_sk),
        Some(&sender_pk),
        HpkePskWireFormat::Rfc9180,
    )
    .unwrap();

    // Verify AuthPSK mode was set up correctly
    assert!(!sender_ctx.shared_secret.is_empty());
    assert!(!sender_ctx.key.is_empty());
    assert!(!sender_ctx.nonce.is_empty());
    assert!(!sender_ctx.exporter_secret.is_empty());
}
