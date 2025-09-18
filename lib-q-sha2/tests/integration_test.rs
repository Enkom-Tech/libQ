use lib_q_core::Algorithm;
use lib_q_core::api::HashOperations;
use lib_q_sha2::{
    Sha2HashProvider,
    sha224,
    sha256,
    sha384,
    sha512,
    sha512_224,
    sha512_256,
};

#[test]
fn test_sha2_provider_integration() {
    // Test that the SHA2 provider can be created
    let provider = Sha2HashProvider::new().expect("Failed to create SHA2 provider");

    // Test data
    let test_data = b"Hello, lib-Q SHA2 integration test!";

    // Test SHA-224
    let hash224 = provider
        .hash(Algorithm::Sha224, test_data)
        .expect("SHA-224 hash failed");
    assert_eq!(hash224.len(), 28); // SHA-224 produces 28 bytes

    // Test SHA-256
    let hash256 = provider
        .hash(Algorithm::Sha256, test_data)
        .expect("SHA-256 hash failed");
    assert_eq!(hash256.len(), 32); // SHA-256 produces 32 bytes

    // Test SHA-384
    let hash384 = provider
        .hash(Algorithm::Sha384, test_data)
        .expect("SHA-384 hash failed");
    assert_eq!(hash384.len(), 48); // SHA-384 produces 48 bytes

    // Test SHA-512
    let hash512 = provider
        .hash(Algorithm::Sha512, test_data)
        .expect("SHA-512 hash failed");
    assert_eq!(hash512.len(), 64); // SHA-512 produces 64 bytes

    // Test SHA-512/224
    let hash512_224 = provider
        .hash(Algorithm::Sha512_224, test_data)
        .expect("SHA-512/224 hash failed");
    assert_eq!(hash512_224.len(), 28); // SHA-512/224 produces 28 bytes

    // Test SHA-512/256
    let hash512_256 = provider
        .hash(Algorithm::Sha512_256, test_data)
        .expect("SHA-512/256 hash failed");
    assert_eq!(hash512_256.len(), 32); // SHA-512/256 produces 32 bytes
}

#[test]
fn test_sha2_convenience_functions() {
    let test_data = b"Hello, lib-Q SHA2 convenience functions test!";

    // Test convenience functions produce correct output sizes
    let hash224 = sha224(test_data);
    assert_eq!(hash224.len(), 28);

    let hash256 = sha256(test_data);
    assert_eq!(hash256.len(), 32);

    let hash384 = sha384(test_data);
    assert_eq!(hash384.len(), 48);

    let hash512 = sha512(test_data);
    assert_eq!(hash512.len(), 64);

    let hash512_224 = sha512_224(test_data);
    assert_eq!(hash512_224.len(), 28);

    let hash512_256 = sha512_256(test_data);
    assert_eq!(hash512_256.len(), 32);
}

#[test]
fn test_sha2_consistency() {
    let test_data = b"Consistency test data";

    // Test that provider and convenience functions produce the same results
    let provider = Sha2HashProvider::new().expect("Failed to create SHA2 provider");

    let provider_hash256 = provider
        .hash(Algorithm::Sha256, test_data)
        .expect("Provider hash failed");
    let convenience_hash256 = sha256(test_data);

    assert_eq!(provider_hash256, convenience_hash256.to_vec());

    let provider_hash512 = provider
        .hash(Algorithm::Sha512, test_data)
        .expect("Provider hash failed");
    let convenience_hash512 = sha512(test_data);

    assert_eq!(provider_hash512, convenience_hash512.to_vec());
}

#[test]
fn test_sha2_empty_input() {
    let provider = Sha2HashProvider::new().expect("Failed to create SHA2 provider");
    let empty_data = b"";

    // Test that empty input works correctly
    let hash256 = provider
        .hash(Algorithm::Sha256, empty_data)
        .expect("Empty input hash failed");
    assert_eq!(hash256.len(), 32);

    // Test convenience function with empty input
    let convenience_hash256 = sha256(empty_data);
    assert_eq!(convenience_hash256.len(), 32);
}

#[test]
fn test_sha2_large_input() {
    let provider = Sha2HashProvider::new().expect("Failed to create SHA2 provider");

    // Test with larger input (1MB)
    let large_data = vec![0x42u8; 1024 * 1024];

    let hash256 = provider
        .hash(Algorithm::Sha256, &large_data)
        .expect("Large input hash failed");
    assert_eq!(hash256.len(), 32);

    let convenience_hash256 = sha256(&large_data);
    assert_eq!(convenience_hash256.len(), 32);

    // Verify they produce the same result
    assert_eq!(hash256, convenience_hash256.to_vec());
}
