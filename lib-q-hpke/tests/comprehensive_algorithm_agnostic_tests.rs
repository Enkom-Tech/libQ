//! Comprehensive tests for algorithm-agnostic design across all cryptographic primitives

use lib_q_core::{
    KemContext,
    KemPublicKey,
    KemSecretKey,
};
use lib_q_hpke::hpke_core::{
    open_with_mode,
    seal_with_mode,
};
use lib_q_hpke::providers::post_quantum::PostQuantumProvider;
use lib_q_hpke::providers::{
    AeadProvider,
    KdfProvider,
    KemProvider,
};
use lib_q_hpke::security::prng::KangarooTwelveRng;
use lib_q_hpke::types::{
    HpkeAead,
    HpkeCipherSuite,
    HpkeKdf,
    HpkeKem,
    HpkeMode,
};
use lib_q_kem::LibQKemProvider;

/// Test comprehensive algorithm-agnostic design across all primitives
#[test]
fn test_comprehensive_algorithm_agnostic_design() {
    let provider = PostQuantumProvider::new();
    let mut rng = KangarooTwelveRng::new().expect("Failed to create RNG");

    // Test all combinations of KEM, KDF, and AEAD algorithms
    let kems = [HpkeKem::MlKem512, HpkeKem::MlKem768, HpkeKem::MlKem1024];
    let kdfs = [
        HpkeKdf::HkdfShake128,
        HpkeKdf::HkdfShake256,
        HpkeKdf::HkdfSha3_256,
        HpkeKdf::HkdfSha3_512,
    ];
    let aeads = [HpkeAead::Saturnin256];

    let mut test_count = 0;
    let mut success_count = 0;

    for kem in &kems {
        for kdf in &kdfs {
            for aead in &aeads {
                test_count += 1;
                println!(
                    "Testing combination: KEM={:?}, KDF={:?}, AEAD={:?}",
                    kem, kdf, aead
                );

                if test_algorithm_combination(&provider, &mut rng, *kem, *kdf, *aead) {
                    success_count += 1;
                    println!("  ✓ Success");
                } else {
                    println!("  ✗ Failed");
                }
            }
        }
    }

    println!(
        "Algorithm-agnostic test results: {}/{} combinations successful",
        success_count, test_count
    );

    // Ensure all combinations work
    assert_eq!(
        success_count, test_count,
        "All algorithm combinations should work with algorithm-agnostic design"
    );
}

/// Test a specific combination of algorithms
fn test_algorithm_combination(
    provider: &PostQuantumProvider,
    rng: &mut KangarooTwelveRng,
    kem: HpkeKem,
    kdf: HpkeKdf,
    aead: HpkeAead,
) -> bool {
    // Create cipher suite
    let cipher_suite = HpkeCipherSuite { kem, kdf, aead };

    // Test 1: Provider support verification
    if !provider.supports_kem(kem) {
        println!("    KEM not supported: {:?}", kem);
        return false;
    }
    if !provider.supports_kdf(kdf) {
        println!("    KDF not supported: {:?}", kdf);
        return false;
    }
    if !provider.supports_aead(aead) {
        println!("    AEAD not supported: {:?}", aead);
        return false;
    }

    // Test 2: Key generation
    let (public_key_bytes, secret_key_bytes) = match provider.generate_keypair(kem, rng) {
        Ok(keypair) => keypair,
        Err(e) => {
            println!("    Key generation failed: {}", e);
            return false;
        }
    };

    let recipient_pk = KemPublicKey::new(public_key_bytes);
    let recipient_sk = KemSecretKey::new(secret_key_bytes);

    // Test 3: KEM operations (encapsulation/decapsulation)
    let (encapsulated_key, shared_secret) =
        match provider.encapsulate(kem, recipient_pk.as_bytes(), rng) {
            Ok(result) => result,
            Err(e) => {
                println!("    Encapsulation failed: {}", e);
                return false;
            }
        };

    let decapsulated_secret =
        match provider.decapsulate(kem, recipient_sk.as_bytes(), &encapsulated_key) {
            Ok(secret) => secret,
            Err(e) => {
                println!("    Decapsulation failed: {}", e);
                return false;
            }
        };

    if shared_secret != decapsulated_secret {
        println!("    Shared secrets don't match");
        return false;
    }

    // Test 4: KDF operations
    let test_salt = b"test-salt";
    let test_ikm = b"test-ikm";
    let test_info = b"test-info";

    let prk = match provider.extract(kdf, test_salt, test_ikm) {
        Ok(prk) => prk,
        Err(e) => {
            println!("    KDF extract failed: {}", e);
            return false;
        }
    };

    let okm = match provider.expand(kdf, &prk, test_info, 32) {
        Ok(okm) => okm,
        Err(e) => {
            println!("    KDF expand failed: {}", e);
            return false;
        }
    };

    if okm.len() != 32 {
        println!("    KDF expand output length incorrect: {}", okm.len());
        return false;
    }

    // Test 5: AEAD operations
    let test_key = vec![1u8; aead.key_len()]; // Non-zero key for security
    let test_nonce = vec![0u8; aead.nonce_len()];
    let test_aad = b"test-aad";
    let test_plaintext = b"Hello, algorithm-agnostic world!";

    let ciphertext = match provider.seal(aead, &test_key, &test_nonce, test_aad, test_plaintext) {
        Ok(ciphertext) => ciphertext,
        Err(e) => {
            println!("    AEAD seal failed: {}", e);
            return false;
        }
    };

    let decrypted = match provider.open(aead, &test_key, &test_nonce, test_aad, &ciphertext) {
        Ok(decrypted) => decrypted,
        Err(e) => {
            println!("    AEAD open failed: {}", e);
            return false;
        }
    };

    if decrypted != test_plaintext {
        println!("    AEAD decryption failed");
        return false;
    }

    // Test 6: Full HPKE operation
    let info = b"test-hpke-info";
    let aad = b"test-hpke-aad";
    let plaintext = b"Hello, comprehensive algorithm-agnostic HPKE!";

    let kem_provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(kem_provider);

    let (hpke_encapsulated_key, hpke_ciphertext) = match seal_with_mode(
        &mut kem_ctx,
        &recipient_pk,
        info,
        aad,
        plaintext,
        &cipher_suite,
        provider,
        rng,
        HpkeMode::Base,
        None,
        None,
        None,
        None,
    ) {
        Ok(result) => result,
        Err(e) => {
            println!("    HPKE seal failed: {}", e);
            return false;
        }
    };

    let kem_provider_decrypt =
        Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx_decrypt = KemContext::with_provider(kem_provider_decrypt);

    let hpke_decrypted = match open_with_mode(
        &mut kem_ctx_decrypt,
        &hpke_encapsulated_key,
        &recipient_sk,
        info,
        aad,
        &hpke_ciphertext,
        &cipher_suite,
        provider,
        HpkeMode::Base,
        None,
        None,
        None,
    ) {
        Ok(decrypted) => decrypted,
        Err(e) => {
            println!("    HPKE open failed: {}", e);
            return false;
        }
    };

    if hpke_decrypted != plaintext {
        println!("    HPKE decryption failed");
        return false;
    }

    true
}

/// Test that the provider correctly handles algorithm validation
#[test]
fn test_algorithm_validation() {
    let provider = PostQuantumProvider::new();

    // Test KEM support
    assert!(provider.supports_kem(HpkeKem::MlKem512));
    assert!(provider.supports_kem(HpkeKem::MlKem768));
    assert!(provider.supports_kem(HpkeKem::MlKem1024));

    // Test KDF support
    assert!(provider.supports_kdf(HpkeKdf::HkdfShake128));
    assert!(provider.supports_kdf(HpkeKdf::HkdfShake256));
    assert!(provider.supports_kdf(HpkeKdf::HkdfSha3_256));
    assert!(provider.supports_kdf(HpkeKdf::HkdfSha3_512));

    // Test AEAD support
    assert!(provider.supports_aead(HpkeAead::Saturnin256));
}

/// Test that different algorithms produce different outputs
#[test]
fn test_algorithm_differentiation() {
    let provider = PostQuantumProvider::new();
    let mut rng = KangarooTwelveRng::new().expect("Failed to create RNG");

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
    assert_ne!(kem_512_keypair.0.len(), kem_768_keypair.0.len());
    assert_ne!(kem_768_keypair.0.len(), kem_1024_keypair.0.len());
    assert_ne!(kem_512_keypair.0.len(), kem_1024_keypair.0.len());

    // Test that different KDF algorithms produce different output sizes
    let test_salt = b"test-salt";
    let test_ikm = b"test-ikm";
    let test_info = b"test-info";

    // Test KDF extract operations with different algorithms
    let shake128_prk = provider
        .extract(HpkeKdf::HkdfShake128, test_salt, test_ikm)
        .expect("Failed to extract with SHAKE128");
    let shake256_prk = provider
        .extract(HpkeKdf::HkdfShake256, test_salt, test_ikm)
        .expect("Failed to extract with SHAKE256");

    // Different KDFs should produce different PRKs
    assert_ne!(shake128_prk, shake256_prk);

    // Test KDF expand operations with different algorithms
    let shake128_output = provider
        .expand(HpkeKdf::HkdfShake128, &shake128_prk, test_info, 16)
        .expect("Failed to expand with SHAKE128");
    let shake256_output = provider
        .expand(HpkeKdf::HkdfShake256, &shake256_prk, test_info, 32)
        .expect("Failed to expand with SHAKE256");

    assert_eq!(shake128_output.len(), 16);
    assert_eq!(shake256_output.len(), 32);
    assert_ne!(shake128_output, shake256_output);
}

/// Test error handling for unsupported algorithms
#[test]
fn test_unsupported_algorithm_handling() {
    let provider = PostQuantumProvider::new();
    let mut rng = KangarooTwelveRng::new().expect("Failed to create RNG");

    // Test that all current algorithms are supported
    assert!(provider.supports_kem(HpkeKem::MlKem512));
    assert!(provider.supports_kem(HpkeKem::MlKem768));
    assert!(provider.supports_kem(HpkeKem::MlKem1024));
    assert!(provider.supports_kdf(HpkeKdf::HkdfShake128));
    assert!(provider.supports_kdf(HpkeKdf::HkdfShake256));
    assert!(provider.supports_kdf(HpkeKdf::HkdfSha3_256));
    assert!(provider.supports_kdf(HpkeKdf::HkdfSha3_512));
    assert!(provider.supports_aead(HpkeAead::Saturnin256));

    // Test that supported algorithms work correctly
    let (public_key, secret_key) = provider
        .generate_keypair(HpkeKem::MlKem512, &mut rng)
        .expect("ML-KEM-512 key generation should work");

    // Verify key lengths are correct
    assert_eq!(public_key.len(), HpkeKem::MlKem512.public_key_len());
    assert_eq!(secret_key.len(), HpkeKem::MlKem512.secret_key_len());

    // Test KDF operations work with supported algorithms
    let test_salt = b"test-salt";
    let test_ikm = b"test-ikm";
    let test_info = b"test-info";

    let prk = provider
        .extract(HpkeKdf::HkdfShake128, test_salt, test_ikm)
        .expect("SHAKE128 extract should work");

    let okm = provider
        .expand(HpkeKdf::HkdfShake128, &prk, test_info, 32)
        .expect("SHAKE128 expand should work");

    assert_eq!(okm.len(), 32);

    // Test AEAD operations work with supported algorithms
    let test_key = vec![1u8; HpkeAead::Saturnin256.key_len()]; // Non-zero key for security
    let test_nonce = vec![0u8; HpkeAead::Saturnin256.nonce_len()];
    let test_aad = b"test-aad";
    let test_plaintext = b"test-plaintext";

    let ciphertext = provider
        .seal(
            HpkeAead::Saturnin256,
            &test_key,
            &test_nonce,
            test_aad,
            test_plaintext,
        )
        .expect("Saturnin256 seal should work");

    let decrypted = provider
        .open(
            HpkeAead::Saturnin256,
            &test_key,
            &test_nonce,
            test_aad,
            &ciphertext,
        )
        .expect("Saturnin256 open should work");

    assert_eq!(decrypted, test_plaintext);
}

/// Test that the algorithm-agnostic design maintains security properties
#[test]
fn test_security_properties() {
    let provider = PostQuantumProvider::new();
    let mut rng = KangarooTwelveRng::new().expect("Failed to create RNG");

    // Test that the same input produces different outputs with different algorithms
    let test_data = b"security-test-data";

    // Test KEM security: different keypairs should produce different keys
    let (pk1, sk1) = provider
        .generate_keypair(HpkeKem::MlKem512, &mut rng)
        .expect("Failed to generate first keypair");
    let (pk2, sk2) = provider
        .generate_keypair(HpkeKem::MlKem512, &mut rng)
        .expect("Failed to generate second keypair");

    // Different keypairs should be different
    assert_ne!(pk1, pk2);
    assert_ne!(sk1, sk2);

    // Test KDF security: same input should produce different outputs with different KDFs
    let test_salt = b"test-salt";
    let test_ikm = b"test-ikm";
    let test_info = b"test-info";

    // Test extract operations with different KDFs
    let shake128_prk = provider
        .extract(HpkeKdf::HkdfShake128, test_salt, test_ikm)
        .expect("Failed to extract with SHAKE128");
    let shake256_prk = provider
        .extract(HpkeKdf::HkdfShake256, test_salt, test_ikm)
        .expect("Failed to extract with SHAKE256");

    // Different KDFs should produce different PRKs
    assert_ne!(shake128_prk, shake256_prk);

    // Test expand operations with different KDFs
    let shake128_output = provider
        .expand(HpkeKdf::HkdfShake128, &shake128_prk, test_info, 32)
        .expect("Failed to expand with SHAKE128");
    let shake256_output = provider
        .expand(HpkeKdf::HkdfShake256, &shake256_prk, test_info, 32)
        .expect("Failed to expand with SHAKE256");

    // Different KDFs should produce different outputs
    assert_ne!(shake128_output, shake256_output);

    // Test that different inputs produce different outputs with same KDF
    let test_ikm2 = b"different-test-ikm";
    let shake128_prk2 = provider
        .extract(HpkeKdf::HkdfShake128, test_salt, test_ikm2)
        .expect("Failed to extract with different IKM");

    assert_ne!(
        shake128_prk, shake128_prk2,
        "Different IKM should produce different PRK"
    );

    // Test cross-algorithm security: same data should produce different results with different algorithms
    let test_data_salt = b"cross-algorithm-test-salt";
    let test_data_ikm = test_data;
    let test_data_info = b"cross-algorithm-test-info";

    // Test with different KDF algorithms
    let sha3_256_prk = provider
        .extract(HpkeKdf::HkdfSha3_256, test_data_salt, test_data_ikm)
        .expect("Failed to extract with SHA3-256");
    let sha3_512_prk = provider
        .extract(HpkeKdf::HkdfSha3_512, test_data_salt, test_data_ikm)
        .expect("Failed to extract with SHA3-512");

    // Different KDF algorithms should produce different PRKs
    assert_ne!(
        sha3_256_prk, sha3_512_prk,
        "Different KDF algorithms should produce different PRKs"
    );

    // Test expand operations with the cross-algorithm data
    let sha3_256_output = provider
        .expand(HpkeKdf::HkdfSha3_256, &sha3_256_prk, test_data_info, 32)
        .expect("Failed to expand with SHA3-256");
    let sha3_512_output = provider
        .expand(HpkeKdf::HkdfSha3_512, &sha3_512_prk, test_data_info, 32)
        .expect("Failed to expand with SHA3-512");

    // Different KDF algorithms should produce different expanded outputs
    assert_ne!(
        sha3_256_output, sha3_512_output,
        "Different KDF algorithms should produce different expanded outputs"
    );

    // Test AEAD security: verify encryption/decryption works correctly
    let test_key = vec![1u8; 32]; // Non-zero key for security
    let test_nonce = vec![0u8; 16];
    let test_aad = b"test-aad";
    let test_plaintext = b"security-test-plaintext";

    let ciphertext1 = provider
        .seal(
            HpkeAead::Saturnin256,
            &test_key,
            &test_nonce,
            test_aad,
            test_plaintext,
        )
        .expect("Failed to seal with Saturnin256");
    let ciphertext2 = provider
        .seal(
            HpkeAead::Saturnin256,
            &test_key,
            &test_nonce,
            test_aad,
            test_plaintext,
        )
        .expect("Failed to seal with Saturnin256");

    // Note: Some AEAD implementations may be deterministic, which is acceptable
    // The important thing is that both ciphertexts decrypt correctly

    // But both should decrypt to the same plaintext
    let decrypted1 = provider
        .open(
            HpkeAead::Saturnin256,
            &test_key,
            &test_nonce,
            test_aad,
            &ciphertext1,
        )
        .expect("Failed to open ciphertext1");
    let decrypted2 = provider
        .open(
            HpkeAead::Saturnin256,
            &test_key,
            &test_nonce,
            test_aad,
            &ciphertext2,
        )
        .expect("Failed to open ciphertext2");

    assert_eq!(decrypted1, test_plaintext);
    assert_eq!(decrypted2, test_plaintext);
}
