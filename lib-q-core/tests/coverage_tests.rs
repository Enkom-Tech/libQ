// Additional tests to improve coverage for lib-q-core

use lib_q_core::algorithm_registry::AlgorithmRegistry;
use lib_q_core::contexts::{
    AeadContext,
    KemContext,
    SignatureContext,
};
use lib_q_core::error::{
    Error,
    supported_security_levels,
};
use lib_q_core::security::SecurityConstants;
use lib_q_core::traits::{
    AeadKey,
    KemKeypair,
    KemPublicKey,
    KemSecretKey,
    Nonce,
    SigKeypair,
    SigPublicKey,
    SigSecretKey,
};
use lib_q_core::{
    Algorithm,
    AlgorithmCategory,
    SecurityValidator,
    Utils,
    algorithms_by_category,
    create_hash_context,
    create_kem_context,
    create_signature_context,
    supported_algorithms,
};

#[test]
fn test_algorithm_registry_coverage() {
    let registry = AlgorithmRegistry::new();

    // Test algorithm lookup
    let algorithm = Algorithm::MlKem512;
    assert!(registry.get_metadata(&algorithm).is_some());

    // Test algorithm categories
    assert_eq!(AlgorithmCategory::Kem as u32, 0);
    assert_eq!(AlgorithmCategory::Signature as u32, 1);

    // Test algorithms by category
    let kem_algorithms = registry.algorithms_by_category(AlgorithmCategory::Kem);
    assert!(!kem_algorithms.is_empty());

    let level_1 = registry.algorithms_by_security_level(1);
    assert!(level_1.contains(&Algorithm::MlKem512));

    let global = supported_algorithms();
    assert!(!global.is_empty());
    let hashes = algorithms_by_category(AlgorithmCategory::Hash);
    assert!(!hashes.is_empty());
}

#[test]
fn test_error_coverage() {
    let err = Error::InvalidAlgorithm { algorithm: "test" };
    let _display = format!("{}", err);
    let _debug = format!("{:?}", err);

    // Test error conversion
    let result: core::result::Result<(), Error> =
        Err(Error::InvalidAlgorithm { algorithm: "test" });
    assert!(result.is_err());
}

#[test]
fn test_error_not_implemented_and_provider_display() {
    let e = Error::NotImplemented {
        feature: "unit-test-feature".to_string(),
    };
    assert!(!format!("{}", e).is_empty());
    let e2 = Error::ProviderNotConfigured {
        operation: "aead_encrypt".to_string(),
    };
    assert!(!format!("{}", e2).is_empty());
}

/// Exercise public factory helpers, context error paths, and security constant accessors.
#[cfg(feature = "std")]
#[test]
fn test_factories_contexts_and_security_constants() {
    let mut hash_ctx = create_hash_context();
    assert!(!hash_ctx.is_initialized());
    let wrong_cat = hash_ctx.hash(Algorithm::MlKem512, b"payload");
    assert!(wrong_cat.is_err());
    assert!(hash_ctx.is_initialized());

    let kem_idle = create_kem_context();
    assert!(!kem_idle.is_initialized());

    let kem = KemContext::new();
    let pk = KemPublicKey::new(vec![0u8; 32]);
    let enc_uninit = kem.encapsulate(Algorithm::MlKem512, &pk, None);
    assert!(matches!(
        enc_uninit,
        Err(Error::InvalidState { operation, .. }) if operation == "encapsulate"
    ));

    let mut kem_init = KemContext::new();
    let _ = kem_init.generate_keypair(Algorithm::MlKem512, None);
    let wrong_alg = kem_init.encapsulate(Algorithm::Sha3_256, &pk, None);
    assert!(matches!(wrong_alg, Err(Error::InvalidAlgorithm { .. })));

    let sig = create_signature_context();
    let sk = SigSecretKey::new(vec![0x2Bu8; 32]);
    let sign_uninit = sig.sign(Algorithm::MlDsa65, &sk, b"msg", None);
    assert!(matches!(
        sign_uninit,
        Err(Error::InvalidState { operation, .. }) if operation == "sign"
    ));

    let mut sig_ctx = SignatureContext::new();
    let _ = sig_ctx.generate_keypair(Algorithm::MlDsa65, None);
    let pk_sig = SigPublicKey::new(vec![1u8; 32]);
    let verify_wrong = sig_ctx.verify(Algorithm::Sha3_256, &pk_sig, b"m", b"s");
    assert!(matches!(verify_wrong, Err(Error::InvalidAlgorithm { .. })));

    let constants = SecurityConstants::new();
    assert!(constants.max_message_size() >= 1024);
    assert_eq!(constants.standard_nonce_size(), 16);
    assert!(constants.min_randomness_size() >= 32);
    assert!(
        constants
            .get_expected_key_size(Algorithm::MlKem768, true)
            .is_ok()
    );
    assert!(
        constants
            .get_expected_key_size(Algorithm::Sha3_256, false)
            .is_err()
    );
}

/// Exercise every Display arm for coverage (std implies alloc in this crate).
#[cfg(feature = "std")]
#[test]
fn test_error_display_all_variants() {
    use std::error::Error as StdError;

    let check = |e: Error| {
        let s = format!("{e}");
        assert!(!s.is_empty(), "empty Display for {e:?}");
        assert!(StdError::source(&e).is_none());
    };

    check(Error::InvalidKeySize {
        expected: 32,
        actual: 16,
    });
    check(Error::InvalidSignatureSize {
        expected: 64,
        actual: 8,
    });
    check(Error::InvalidNonceSize {
        expected: 12,
        actual: 8,
    });
    check(Error::InvalidMessageSize {
        max: 100,
        actual: 200,
    });
    check(Error::InvalidCiphertextSize {
        expected: 32,
        actual: 10,
    });
    check(Error::InvalidPlaintextSize {
        expected: 16,
        actual: 4,
    });
    check(Error::InvalidAssociatedDataSize {
        max: 64,
        actual: 128,
    });
    check(Error::InvalidTagSize {
        expected: 16,
        actual: 8,
    });
    check(Error::InvalidHashSize {
        expected: 32,
        actual: 16,
    });
    check(Error::InvalidAlgorithm {
        algorithm: "test-alg",
    });
    check(Error::InvalidSecurityLevel {
        level: 99,
        supported: vec![1, 3, 4, 5],
    });
    check(Error::VerificationFailed {
        operation: "verify".to_string(),
    });
    check(Error::EncryptionFailed {
        operation: "enc".to_string(),
    });
    check(Error::DecryptionFailed {
        operation: "dec".to_string(),
    });
    check(Error::KeyGenerationFailed {
        operation: "kg".to_string(),
    });
    check(Error::RandomGenerationFailed {
        operation: "rng".to_string(),
    });
    check(Error::SigningFailed {
        operation: "sign".to_string(),
    });
    check(Error::MemoryAllocationFailed {
        operation: "alloc".to_string(),
    });
    check(Error::InternalError {
        operation: "op".to_string(),
        details: "detail".to_string(),
    });
    check(Error::NotImplemented {
        feature: "feat".to_string(),
    });
    check(Error::UnsupportedOperation {
        operation: "unsupported".to_string(),
    });
    check(Error::ProviderNotConfigured {
        operation: "AEAD".to_string(),
    });
    check(Error::InvalidState {
        operation: "decrypt".to_string(),
        reason: "Context not initialized".to_string(),
    });
    check(Error::PluginDependencyError {
        plugin: "p".to_string(),
        dependency: "d".to_string(),
        required_version: "1.0".to_string(),
        available_version: Some("0.9".to_string()),
    });
    check(Error::PluginDependencyError {
        plugin: "p".to_string(),
        dependency: "d".to_string(),
        required_version: "1.0".to_string(),
        available_version: None,
    });
    check(Error::PluginVersionIncompatible {
        plugin: "p".to_string(),
        required_version: "2.0".to_string(),
        available_version: "1.0".to_string(),
    });
    check(Error::InvalidKeyFormat);
    check(Error::InvalidKey {
        key_type: "public key".to_string(),
        reason: "bad".to_string(),
    });
    check(Error::UnsupportedAlgorithm {
        algorithm: "legacy".to_string(),
    });
    check(Error::AuthenticationFailed {
        operation: "auth".to_string(),
    });
    check(Error::InvalidRandomnessSize {
        expected: 32,
        actual: 4,
    });
}

/// Hit remaining SecurityConstants match arms (CB-KEM, SLH-DSA) and Default.
#[cfg(feature = "std")]
#[test]
fn test_security_constants_extended_algorithms() {
    let c = SecurityConstants::default();
    assert_eq!(c.max_message_size(), 1024 * 1024);

    let kem_algorithms = [
        Algorithm::MlKem512,
        Algorithm::MlKem768,
        Algorithm::MlKem1024,
        Algorithm::CbKem348864,
        Algorithm::CbKem460896,
        Algorithm::CbKem6688128,
        Algorithm::CbKem6960119,
        Algorithm::CbKem8192128,
        Algorithm::Hqc128,
        Algorithm::Hqc192,
        Algorithm::Hqc256,
    ];
    for a in kem_algorithms {
        let pk = c.get_expected_key_size(a, false).unwrap();
        let sk = c.get_expected_key_size(a, true).unwrap();
        assert!(pk > 0 && sk > 0);
        let ct = c.get_expected_ciphertext_size(a).unwrap();
        assert!(ct > 0);
    }

    let sig_algorithms = [
        Algorithm::MlDsa44,
        Algorithm::MlDsa65,
        Algorithm::MlDsa87,
        Algorithm::FnDsa,
        Algorithm::FnDsa512,
        Algorithm::FnDsa1024,
        Algorithm::SlhDsaSha256128fRobust,
        Algorithm::SlhDsaSha256192fRobust,
        Algorithm::SlhDsaSha256256fRobust,
        Algorithm::SlhDsaShake256128fRobust,
        Algorithm::SlhDsaShake256192fRobust,
        Algorithm::SlhDsaShake256256fRobust,
    ];
    for a in sig_algorithms {
        assert!(c.get_expected_signature_size(a).unwrap() > 0);
    }

    assert!(c.get_expected_ciphertext_size(Algorithm::Sha3_256).is_err());
    assert!(c.get_expected_signature_size(Algorithm::MlKem512).is_err());
}

/// More SecurityValidator branches: key/ciphertext/signature/randomness and entropy accessors.
#[cfg(feature = "std")]
#[test]
fn test_security_validator_extended() {
    fn pseudo_key_bytes(len: usize, seed: u32) -> Vec<u8> {
        (0..len)
            .map(|i| {
                let x = (i as u32).wrapping_add(seed);
                (x.wrapping_mul(0x9E37_79B9) ^ (x << 13) ^ (x >> 7)) as u8
            })
            .collect()
    }

    let mut v = SecurityValidator::new().unwrap();
    let _ = v.entropy_validator();
    let _ = v.entropy_validator_mut();

    let good = vec![
        0x1Au8, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x81, 0x92, 0xA3, 0xB4, 0xC5, 0xD6, 0xE7, 0xF8,
        0x09,
    ];
    let pk_ml_kem = pseudo_key_bytes(800, 0xC0FFEE);
    let sk_ml_kem = pseudo_key_bytes(1632, 0xBEEF);
    assert!(
        v.validate_public_key(Algorithm::MlKem512, &pk_ml_kem)
            .is_ok()
    );
    assert!(
        v.validate_secret_key(Algorithm::MlKem512, &sk_ml_kem)
            .is_ok()
    );

    assert!(v.validate_public_key(Algorithm::MlKem512, &good).is_err());
    assert!(
        v.validate_secret_key(Algorithm::MlKem512, &[0x4Du8; 100])
            .is_err()
    );

    assert!(matches!(
        v.validate_ciphertext(Algorithm::MlKem512, &[]),
        Err(Error::InvalidCiphertextSize { actual: 0, .. })
    ));
    let wrong_ct = vec![0u8; 10];
    assert!(
        v.validate_ciphertext(Algorithm::MlKem512, &wrong_ct)
            .is_err()
    );
    let ok_ct = vec![0u8; 768];
    assert!(v.validate_ciphertext(Algorithm::MlKem512, &ok_ct).is_ok());

    assert!(matches!(
        v.validate_signature(Algorithm::MlDsa65, &[]),
        Err(Error::InvalidSignatureSize { actual: 0, .. })
    ));
    let wrong_sig = vec![0u8; 10];
    assert!(
        v.validate_signature(Algorithm::MlDsa65, &wrong_sig)
            .is_err()
    );
    let ok_sig = vec![0u8; 3309];
    assert!(v.validate_signature(Algorithm::MlDsa65, &ok_sig).is_ok());

    assert!(v.validate_randomness(&[0u8; 16]).is_err());
    let mut rnd = pseudo_key_bytes(32, 0x51A6);
    assert!(v.validate_randomness(&rnd).is_ok());
    rnd.fill(0);
    assert!(v.validate_randomness(&rnd).is_err());
}

/// AeadContext paths: wrong category, missing provider, decrypt before init.
#[cfg(feature = "std")]
#[test]
fn test_aead_context_coverage_paths() {
    let key = AeadKey::new(vec![0u8; 32]);
    let nonce = Nonce::new((1u8..=16).collect::<Vec<_>>());

    let mut ctx = AeadContext::new();
    let r = ctx.encrypt(Algorithm::MlKem512, &key, &nonce, b"pt", None);
    assert!(matches!(r, Err(Error::InvalidAlgorithm { .. })));

    let r = ctx.encrypt(Algorithm::Saturnin, &key, &nonce, b"pt", None);
    assert!(matches!(r, Err(Error::ProviderNotConfigured { .. })));

    let ctx_uninit = AeadContext::new();
    let d = ctx_uninit.decrypt(Algorithm::Saturnin, &key, &nonce, b"ct", None);
    assert!(matches!(d, Err(Error::InvalidState { .. })));
}

fn pseudo_key_bytes(len: usize, seed: u32) -> Vec<u8> {
    (0..len)
        .map(|i| {
            let x = (i as u32).wrapping_add(seed);
            (x.wrapping_mul(0x9E37_79B9) ^ (x << 13) ^ (x >> 7)) as u8
        })
        .collect()
}

/// Utils::hex_to_bytes / bytes_to_hex, supported_security_levels, keypair helpers, zeroize hooks.
#[cfg(feature = "std")]
#[test]
fn test_utils_traits_and_security_levels_vec() {
    assert_eq!(Utils::bytes_to_hex(&[0xAB, 0xCD]), "abcd");
    assert!(matches!(
        Utils::hex_to_bytes("123"),
        Err(Error::InvalidMessageSize { .. })
    ));
    assert!(Utils::hex_to_bytes("g0").is_err());
    assert_eq!(Utils::hex_to_bytes("00ff").unwrap(), vec![0, 255]);

    let levels = supported_security_levels();
    assert!(levels.contains(&1));

    let kp = KemKeypair::new(pseudo_key_bytes(800, 0xA1), pseudo_key_bytes(1632, 0xA2));
    assert_eq!(kp.public_key().as_bytes().len(), 800);
    assert_eq!(kp.secret_key().as_bytes().len(), 1632);

    let sp = SigKeypair::new(pseudo_key_bytes(1952, 0xB1), pseudo_key_bytes(4032, 0xB2));
    assert_eq!(sp.public_key().as_bytes().len(), 1952);
    assert_eq!(sp.secret_key().as_bytes().len(), 4032);

    let mut ksk = KemSecretKey::new(pseudo_key_bytes(32, 0xC1));
    zeroize::Zeroize::zeroize(&mut ksk);
    let mut ssk = SigSecretKey::new(pseudo_key_bytes(32, 0xC2));
    zeroize::Zeroize::zeroize(&mut ssk);
    let mut ak = AeadKey::new(pseudo_key_bytes(32, 0xC3));
    zeroize::Zeroize::zeroize(&mut ak);
}

/// Extra provider operation shapes (success and error) for hash / AEAD / KEM / signature.
#[cfg(feature = "std")]
#[test]
fn test_libq_provider_operation_paths() {
    use lib_q_core::CryptoProvider;
    use lib_q_core::providers::LibQCryptoProvider;
    use lib_q_core::traits::SigPublicKey as SPK;

    let provider = LibQCryptoProvider::new().unwrap();
    let _ = provider.kem_provider();
    let _ = provider.signature_provider();
    let _ = provider.hash_provider();
    let _ = provider.aead_provider();

    let kem = provider.kem().unwrap();
    let pk = KemPublicKey::new(pseudo_key_bytes(800, 0x10));
    assert!(matches!(
        kem.encapsulate(Algorithm::MlKem512, &pk, None),
        Err(Error::NotImplemented { .. })
    ));
    let sk = KemSecretKey::new(pseudo_key_bytes(1632, 0x11));
    let ct = vec![0u8; 768];
    assert!(matches!(
        kem.decapsulate(Algorithm::MlKem512, &sk, &ct),
        Err(Error::NotImplemented { .. })
    ));
    assert!(matches!(
        kem.derive_public_key(Algorithm::MlKem512, &sk),
        Err(Error::NotImplemented { .. })
    ));
    assert!(matches!(
        kem.generate_keypair(Algorithm::MlKem512, None),
        Err(Error::NotImplemented { .. })
    ));
    assert!(kem.generate_keypair(Algorithm::Sha3_256, None).is_err());

    let sig = provider.signature().unwrap();
    let pk_sig = SPK::new(pseudo_key_bytes(1952, 0x20));
    assert!(matches!(
        sig.verify(
            Algorithm::MlDsa65,
            &pk_sig,
            b"m",
            &pseudo_key_bytes(3309, 0x21)
        ),
        Err(Error::NotImplemented { .. })
    ));
    let skey = SigSecretKey::new(pseudo_key_bytes(4032, 0x22));
    assert!(matches!(
        sig.sign(Algorithm::MlDsa65, &skey, b"msg", None),
        Err(Error::NotImplemented { .. })
    ));
    assert!(matches!(
        sig.generate_keypair(Algorithm::MlDsa65, None),
        Err(Error::NotImplemented { .. })
    ));

    let hp = provider.hash().unwrap();
    let _ = hp.hash(Algorithm::Sha3_256, b"data");
    for alg in [
        Algorithm::Shake128,
        Algorithm::CShake128,
        Algorithm::Kmac128,
        Algorithm::TupleHash128,
        Algorithm::ParallelHash128,
        Algorithm::Keccak256,
        Algorithm::KangarooTwelve,
        Algorithm::TurboShake128,
    ] {
        assert!(matches!(
            hp.hash(alg, b"x"),
            Err(Error::NotImplemented { .. })
        ));
    }

    let ap = provider.aead().unwrap();
    let key = AeadKey::new(pseudo_key_bytes(32, 0x30));
    let nonce = Nonce::new(pseudo_key_bytes(16, 0x31));
    assert!(matches!(
        ap.encrypt(Algorithm::Saturnin, &key, &nonce, b"pt", None),
        Err(Error::NotImplemented { .. })
    ));
}
