#![allow(clippy::expect_fun_call, clippy::too_many_arguments)]

use lib_q_core::{
    KemContext,
    KemPublicKey,
    KemSecretKey,
};
use lib_q_hpke::hpke_core::{
    open_with_mode,
    seal_with_mode,
};
use lib_q_hpke::providers::KemProvider;
use lib_q_hpke::providers::post_quantum::PostQuantumProvider;
use lib_q_hpke::security::prng::Kt128Rng;
use lib_q_hpke::types::{
    HpkeAead,
    HpkeCipherSuite,
    HpkeKdf,
    HpkeKem,
    HpkeMode,
};
use lib_q_kem::LibQKemProvider;

/// Test that HPKE works with different KEM algorithms
#[test]
fn test_hpke_with_different_kem_algorithms() {
    let provider = PostQuantumProvider::new();
    let mut rng = Kt128Rng::new().expect("Failed to create RNG");

    // Test with ML-KEM-512
    test_kem_algorithm(&provider, &mut rng, HpkeKem::MlKem512, "ML-KEM-512");

    // Test with ML-KEM-768
    test_kem_algorithm(&provider, &mut rng, HpkeKem::MlKem768, "ML-KEM-768");

    // Test with ML-KEM-1024
    test_kem_algorithm(&provider, &mut rng, HpkeKem::MlKem1024, "ML-KEM-1024");
}

fn test_kem_algorithm(
    provider: &PostQuantumProvider,
    rng: &mut Kt128Rng,
    kem: HpkeKem,
    kem_name: &str,
) {
    println!("Testing HPKE with {}", kem_name);

    // Create cipher suite with the specified KEM
    let cipher_suite = HpkeCipherSuite {
        kem,
        kdf: HpkeKdf::HkdfShake256,
        aead: HpkeAead::Saturnin256,
    };

    // Generate keypair using the provider
    let (public_key_bytes, secret_key_bytes) = provider
        .generate_keypair(kem, rng)
        .expect(&format!("Failed to generate keypair for {}", kem_name));

    let recipient_pk = KemPublicKey::new(public_key_bytes);
    let recipient_sk = KemSecretKey::new(secret_key_bytes);

    // Test data
    let info = b"test info";
    let aad = b"test aad";
    let plaintext = b"Hello, post-quantum world!";

    // Test Base mode
    test_hpke_mode(
        provider,
        rng,
        &cipher_suite,
        &recipient_pk,
        &recipient_sk,
        info,
        aad,
        plaintext,
        HpkeMode::Base,
        None,
        None,
        None,
        None,
        &format!("{} Base mode", kem_name),
    );

    // Test PSK mode
    let psk = b"test-psk";
    let psk_id = b"test-psk-id";
    test_hpke_mode(
        provider,
        rng,
        &cipher_suite,
        &recipient_pk,
        &recipient_sk,
        info,
        aad,
        plaintext,
        HpkeMode::Psk,
        Some(psk),
        Some(psk_id),
        None,
        None,
        &format!("{} PSK mode", kem_name),
    );

    // Test Auth mode
    let (sender_pk_bytes, sender_sk_bytes) = provider.generate_keypair(kem, rng).expect(&format!(
        "Failed to generate sender keypair for {}",
        kem_name
    ));
    let sender_pk = KemPublicKey::new(sender_pk_bytes);
    let sender_sk = KemSecretKey::new(sender_sk_bytes);

    test_hpke_mode(
        provider,
        rng,
        &cipher_suite,
        &recipient_pk,
        &recipient_sk,
        info,
        aad,
        plaintext,
        HpkeMode::Auth,
        None,
        None,
        Some(&sender_sk),
        Some(&sender_pk),
        &format!("{} Auth mode", kem_name),
    );

    // Test AuthPSK mode
    test_hpke_mode(
        provider,
        rng,
        &cipher_suite,
        &recipient_pk,
        &recipient_sk,
        info,
        aad,
        plaintext,
        HpkeMode::AuthPsk,
        Some(psk),
        Some(psk_id),
        Some(&sender_sk),
        Some(&sender_pk),
        &format!("{} AuthPSK mode", kem_name),
    );
}

fn test_hpke_mode(
    provider: &PostQuantumProvider,
    rng: &mut Kt128Rng,
    cipher_suite: &HpkeCipherSuite,
    recipient_pk: &KemPublicKey,
    recipient_sk: &KemSecretKey,
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    mode: HpkeMode,
    psk: Option<&[u8]>,
    psk_id: Option<&[u8]>,
    sender_sk: Option<&KemSecretKey>,
    sender_pk: Option<&KemPublicKey>,
    test_name: &str,
) {
    println!("  Testing {}", test_name);

    // Create KEM context with provider
    let kem_provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(kem_provider);

    // Encrypt
    let (encapsulated_key, ciphertext) = seal_with_mode(
        &mut kem_ctx,
        recipient_pk,
        info,
        aad,
        plaintext,
        cipher_suite,
        provider,
        rng,
        mode,
        psk,
        psk_id,
        sender_sk,
        sender_pk,
    )
    .expect(&format!("Failed to encrypt in {}", test_name));

    // Verify encapsulated key is not empty
    assert!(
        !encapsulated_key.is_empty(),
        "Encapsulated key should not be empty in {}",
        test_name
    );

    // Verify ciphertext is not empty and different from plaintext
    assert!(
        !ciphertext.is_empty(),
        "Ciphertext should not be empty in {}",
        test_name
    );
    assert_ne!(
        ciphertext, plaintext,
        "Ciphertext should be different from plaintext in {}",
        test_name
    );

    // Decrypt
    let kem_provider_decrypt =
        Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx_decrypt = KemContext::with_provider(kem_provider_decrypt);
    let decrypted = open_with_mode(
        &mut kem_ctx_decrypt,
        &encapsulated_key,
        recipient_sk,
        info,
        aad,
        &ciphertext,
        cipher_suite,
        provider,
        mode,
        psk,
        psk_id,
        sender_pk,
    )
    .expect(&format!("Failed to decrypt in {}", test_name));

    // Verify decryption
    assert_eq!(
        decrypted, plaintext,
        "Decrypted text should match plaintext in {}",
        test_name
    );

    println!("    ✓ {} passed", test_name);
}

/// Test that HPKE works with different KDF algorithms
#[test]
fn test_hpke_with_different_kdf_algorithms() {
    let provider = PostQuantumProvider::new();
    let mut rng = Kt128Rng::new().expect("Failed to create RNG");

    let kems = [HpkeKem::MlKem512, HpkeKem::MlKem768, HpkeKem::MlKem1024];
    let kdfs = [
        HpkeKdf::HkdfShake128,
        HpkeKdf::HkdfShake256,
        HpkeKdf::HkdfSha3_256,
        HpkeKdf::HkdfSha3_512,
    ];

    for kem in &kems {
        for kdf in &kdfs {
            let cipher_suite = HpkeCipherSuite {
                kem: *kem,
                kdf: *kdf,
                aead: HpkeAead::Saturnin256,
            };

            // Generate keypair
            let (public_key_bytes, secret_key_bytes) = provider
                .generate_keypair(*kem, &mut rng)
                .expect("Failed to generate keypair");

            let recipient_pk = KemPublicKey::new(public_key_bytes);
            let recipient_sk = KemSecretKey::new(secret_key_bytes);

            // Test data
            let info = b"test info";
            let aad = b"test aad";
            let plaintext = b"Hello, post-quantum world!";

            // Test encryption/decryption
            let kem_provider =
                Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
            let mut kem_ctx = KemContext::with_provider(kem_provider);
            let (encapsulated_key, ciphertext) = seal_with_mode(
                &mut kem_ctx,
                &recipient_pk,
                info,
                aad,
                plaintext,
                &cipher_suite,
                &provider,
                &mut rng,
                HpkeMode::Base,
                None,
                None,
                None,
                None,
            )
            .expect("Failed to encrypt");

            let kem_provider_decrypt =
                Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
            let mut kem_ctx_decrypt = KemContext::with_provider(kem_provider_decrypt);
            let decrypted = open_with_mode(
                &mut kem_ctx_decrypt,
                &encapsulated_key,
                &recipient_sk,
                info,
                aad,
                &ciphertext,
                &cipher_suite,
                &provider,
                HpkeMode::Base,
                None,
                None,
                None,
            )
            .expect("Failed to decrypt");

            assert_eq!(
                decrypted, plaintext,
                "Decryption failed for KEM {:?} with KDF {:?}",
                kem, kdf
            );
        }
    }
}

/// Test that HPKE works with different AEAD algorithms
#[test]
fn test_hpke_with_different_aead_algorithms() {
    let provider = PostQuantumProvider::new();
    let mut rng = Kt128Rng::new().expect("Failed to create RNG");

    let kems = [HpkeKem::MlKem512, HpkeKem::MlKem768, HpkeKem::MlKem1024];
    let aeads = [HpkeAead::Saturnin256];

    for kem in &kems {
        for aead in &aeads {
            let cipher_suite = HpkeCipherSuite {
                kem: *kem,
                kdf: HpkeKdf::HkdfShake256,
                aead: *aead,
            };

            // Generate keypair
            let (public_key_bytes, secret_key_bytes) = provider
                .generate_keypair(*kem, &mut rng)
                .expect("Failed to generate keypair");

            let recipient_pk = KemPublicKey::new(public_key_bytes);
            let recipient_sk = KemSecretKey::new(secret_key_bytes);

            // Test data
            let info = b"test info";
            let aad = b"test aad";
            let plaintext = b"Hello, post-quantum world!";

            // Test encryption/decryption
            let kem_provider =
                Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
            let mut kem_ctx = KemContext::with_provider(kem_provider);
            let (encapsulated_key, ciphertext) = seal_with_mode(
                &mut kem_ctx,
                &recipient_pk,
                info,
                aad,
                plaintext,
                &cipher_suite,
                &provider,
                &mut rng,
                HpkeMode::Base,
                None,
                None,
                None,
                None,
            )
            .expect("Failed to encrypt");

            let kem_provider_decrypt =
                Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
            let mut kem_ctx_decrypt = KemContext::with_provider(kem_provider_decrypt);
            let decrypted = open_with_mode(
                &mut kem_ctx_decrypt,
                &encapsulated_key,
                &recipient_sk,
                info,
                aad,
                &ciphertext,
                &cipher_suite,
                &provider,
                HpkeMode::Base,
                None,
                None,
                None,
            )
            .expect("Failed to decrypt");

            assert_eq!(
                decrypted, plaintext,
                "Decryption failed for KEM {:?} with AEAD {:?}",
                kem, aead
            );
        }
    }
}

/// Test cross-algorithm compatibility
#[test]
fn test_cross_algorithm_compatibility() {
    let provider = PostQuantumProvider::new();
    let mut rng = Kt128Rng::new().expect("Failed to create RNG");

    // Test that different KEM algorithms produce different key sizes
    let kem_512_keypair = provider
        .generate_keypair(HpkeKem::MlKem512, &mut rng)
        .expect("Failed to generate ML-KEM-512 keypair");

    let kem_768_keypair = provider
        .generate_keypair(HpkeKem::MlKem768, &mut rng)
        .expect("Failed to generate ML-KEM-768 keypair");

    let kem_1024_keypair = provider
        .generate_keypair(HpkeKem::MlKem1024, &mut rng)
        .expect("Failed to generate ML-KEM-1024 keypair");

    // Verify different key sizes
    assert_ne!(
        kem_512_keypair.0.len(),
        kem_768_keypair.0.len(),
        "ML-KEM-512 and ML-KEM-768 should have different public key sizes"
    );
    assert_ne!(
        kem_768_keypair.0.len(),
        kem_1024_keypair.0.len(),
        "ML-KEM-768 and ML-KEM-1024 should have different public key sizes"
    );
    assert_ne!(
        kem_512_keypair.0.len(),
        kem_1024_keypair.0.len(),
        "ML-KEM-512 and ML-KEM-1024 should have different public key sizes"
    );

    // Verify different secret key sizes
    assert_ne!(
        kem_512_keypair.1.len(),
        kem_768_keypair.1.len(),
        "ML-KEM-512 and ML-KEM-768 should have different secret key sizes"
    );
    assert_ne!(
        kem_768_keypair.1.len(),
        kem_1024_keypair.1.len(),
        "ML-KEM-768 and ML-KEM-1024 should have different secret key sizes"
    );
    assert_ne!(
        kem_512_keypair.1.len(),
        kem_1024_keypair.1.len(),
        "ML-KEM-512 and ML-KEM-1024 should have different secret key sizes"
    );

    println!("✓ Cross-algorithm compatibility test passed");
}

/// Test that the provider correctly handles different KEM algorithms
#[test]
fn test_provider_kem_algorithm_handling() {
    let provider = PostQuantumProvider::new();
    let mut rng = Kt128Rng::new().expect("Failed to create RNG");

    let kems = [HpkeKem::MlKem512, HpkeKem::MlKem768, HpkeKem::MlKem1024];

    for kem in &kems {
        // Test key generation
        let (public_key_bytes, secret_key_bytes) = provider
            .generate_keypair(*kem, &mut rng)
            .expect(&format!("Failed to generate keypair for {:?}", kem));

        let recipient_pk = KemPublicKey::new(public_key_bytes);
        let recipient_sk = KemSecretKey::new(secret_key_bytes);

        // Test encapsulation
        let (encapsulated_key, shared_secret) = provider
            .encapsulate(*kem, recipient_pk.as_bytes(), &mut rng)
            .expect(&format!("Failed to encapsulate for {:?}", kem));

        // Test decapsulation
        let decapsulated_secret = provider
            .decapsulate(*kem, recipient_sk.as_bytes(), &encapsulated_key)
            .expect(&format!("Failed to decapsulate for {:?}", kem));

        // Verify shared secrets match
        assert_eq!(
            shared_secret, decapsulated_secret,
            "Shared secrets should match for {:?}",
            kem
        );

        // Verify encapsulated key is not empty
        assert!(
            !encapsulated_key.is_empty(),
            "Encapsulated key should not be empty for {:?}",
            kem
        );

        // Verify shared secret is not empty
        assert!(
            !shared_secret.is_empty(),
            "Shared secret should not be empty for {:?}",
            kem
        );

        println!("✓ Provider correctly handles {:?}", kem);
    }
}
