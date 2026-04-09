//! Integration tests for Classical McEliece KEM with libQ

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use lib_q_cb_kem::LibQCbKemProvider;
#[cfg(feature = "alloc")]
use lib_q_core::api::{
    Algorithm,
    KemOperations,
};

#[cfg(feature = "alloc")]
fn compiled_cb_kem_algorithm() -> Algorithm {
    #[cfg(any(feature = "cbkem348864", feature = "cbkem348864f"))]
    {
        Algorithm::CbKem348864
    }
    #[cfg(all(
        not(any(feature = "cbkem348864", feature = "cbkem348864f")),
        any(feature = "cbkem460896", feature = "cbkem460896f"),
    ))]
    {
        Algorithm::CbKem460896
    }
    #[cfg(all(
        not(any(
            feature = "cbkem348864",
            feature = "cbkem348864f",
            feature = "cbkem460896",
            feature = "cbkem460896f",
        )),
        any(feature = "cbkem6688128", feature = "cbkem6688128f"),
    ))]
    {
        Algorithm::CbKem6688128
    }
    #[cfg(all(
        not(any(
            feature = "cbkem348864",
            feature = "cbkem348864f",
            feature = "cbkem460896",
            feature = "cbkem460896f",
            feature = "cbkem6688128",
            feature = "cbkem6688128f",
        )),
        any(feature = "cbkem6960119", feature = "cbkem6960119f"),
    ))]
    {
        Algorithm::CbKem6960119
    }
    #[cfg(all(
        not(any(
            feature = "cbkem348864",
            feature = "cbkem348864f",
            feature = "cbkem460896",
            feature = "cbkem460896f",
            feature = "cbkem6688128",
            feature = "cbkem6688128f",
            feature = "cbkem6960119",
            feature = "cbkem6960119f",
        )),
        any(feature = "cbkem8192128", feature = "cbkem8192128f"),
    ))]
    {
        Algorithm::CbKem8192128
    }
}

#[cfg(feature = "alloc")]
#[test]
fn test_cb_kem_provider_creation() {
    let provider = LibQCbKemProvider::new();
    assert!(provider.is_ok(), "Provider should be created successfully");
}

#[cfg(feature = "alloc")]
#[test]
fn test_cb_kem_algorithm_support() {
    let provider = LibQCbKemProvider::new().unwrap();

    let alg = compiled_cb_kem_algorithm();
    provider
        .security_validator()
        .validate_algorithm_category(alg, lib_q_core::api::AlgorithmCategory::Kem)
        .expect("compiled CB-KEM algorithm should be a KEM");

    #[cfg(any(feature = "cbkem348864", feature = "cbkem348864f"))]
    {
        let result = provider.generate_keypair(alg, None);
        match result {
            Ok(_) => {}
            Err(lib_q_core::Error::NotImplemented { .. }) => {}
            Err(lib_q_core::Error::RandomGenerationFailed { .. }) => {}
            Err(e) => panic!("Unexpected error type: {:?}", e),
        }
    }
}

#[cfg(feature = "alloc")]
#[test]
fn test_cb_kem_unsupported_algorithm() {
    let provider = LibQCbKemProvider::new().unwrap();
    let result = provider.generate_keypair(Algorithm::Sha3_256, None);
    assert!(
        result.is_err(),
        "Should return error for unsupported algorithm"
    );

    if let Err(lib_q_core::Error::InvalidAlgorithm { .. }) = result {
        // Expected error type
    } else {
        panic!("Expected InvalidAlgorithm error");
    }
}

#[cfg(all(
    feature = "alloc",
    any(feature = "cbkem348864", feature = "cbkem348864f")
))]
#[test]
fn test_cb_kem_full_cycle() {
    let provider = LibQCbKemProvider::new().unwrap();

    let alg = compiled_cb_kem_algorithm();

    let keypair = provider.generate_keypair(alg, None).unwrap();

    let (ciphertext, shared_secret1) = provider
        .encapsulate(alg, &keypair.public_key, None)
        .unwrap();

    let shared_secret2 = provider
        .decapsulate(alg, &keypair.secret_key, &ciphertext)
        .unwrap();

    assert_eq!(
        shared_secret1, shared_secret2,
        "Shared secrets should match"
    );

    provider
        .security_validator()
        .validate_ciphertext(alg, &ciphertext)
        .expect("ciphertext length must match algorithm");
    assert_eq!(shared_secret1.len(), 32, "Shared secret should be 32 bytes");
}
