// Additional tests to improve coverage for lib-q-core

use lib_q_core::algorithm_registry::AlgorithmRegistry;
use lib_q_core::contexts::{
    KemContext,
    SignatureContext,
};
use lib_q_core::error::Error;
use lib_q_core::security::SecurityConstants;
use lib_q_core::traits::{
    KemPublicKey,
    SigPublicKey,
    SigSecretKey,
};
use lib_q_core::{
    Algorithm,
    AlgorithmCategory,
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
