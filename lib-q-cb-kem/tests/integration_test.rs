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
#[test]
fn test_cb_kem_provider_creation() {
    let provider = LibQCbKemProvider::new();
    assert!(provider.is_ok(), "Provider should be created successfully");
}

#[cfg(feature = "alloc")]
#[test]
fn test_cb_kem_algorithm_support() {
    let provider = LibQCbKemProvider::new().unwrap();

    // Test that Classical McEliece algorithms are supported
    let result = provider.generate_keypair(Algorithm::CbKem348864, None);
    // Should either succeed or return NotImplemented (depending on std feature)
    match result {
        Ok(_) => {
            // Success case - this is expected with std feature
        }
        Err(lib_q_core::Error::NotImplemented { .. }) => {
            // Expected when std feature is not available
        }
        Err(lib_q_core::Error::RandomGenerationFailed { .. }) => {
            // Expected when std feature is not available for randomness generation
        }
        Err(e) => {
            panic!("Unexpected error type: {:?}", e);
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

#[cfg(all(feature = "alloc", feature = "std"))]
#[test]
fn test_cb_kem_full_cycle() {
    let provider = LibQCbKemProvider::new().unwrap();

    // Test full KEM cycle for Classical McEliece
    let keypair = provider
        .generate_keypair(Algorithm::CbKem348864, None)
        .unwrap();

    // Test encapsulation
    let (ciphertext, shared_secret1) = provider
        .encapsulate(Algorithm::CbKem348864, &keypair.public_key, None)
        .unwrap();

    // Test decapsulation
    let shared_secret2 = provider
        .decapsulate(Algorithm::CbKem348864, &keypair.secret_key, &ciphertext)
        .unwrap();

    // Verify shared secrets match
    assert_eq!(
        shared_secret1, shared_secret2,
        "Shared secrets should match"
    );

    // Verify sizes are correct
    assert_eq!(
        ciphertext.len(),
        96, // CRYPTO_CIPHERTEXTBYTES for mceliece348864
        "Classical McEliece ciphertext should be 96 bytes"
    );
    assert_eq!(shared_secret1.len(), 32, "Shared secret should be 32 bytes");
}
