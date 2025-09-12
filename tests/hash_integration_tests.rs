use libq::{
    Algorithm,
    create_hash_context,
};

#[test]
fn test_new_hash_algorithms() {
    // Test the newly added hash algorithms
    let mut hash_ctx = create_hash_context();
    let test_data = b"Hello, libQ!";

    // Test KangarooTwelve
    let kt_result = hash_ctx.hash(Algorithm::KangarooTwelve, test_data);
    assert!(kt_result.is_ok(), "KangarooTwelve should work");
    let kt_hash = kt_result.unwrap();
    assert_eq!(
        kt_hash.len(),
        32,
        "KangarooTwelve should produce 32-byte output"
    );

    // Test Keccak algorithms
    let keccak224_result = hash_ctx.hash(Algorithm::Keccak224, test_data);
    assert!(keccak224_result.is_ok(), "Keccak-224 should work");
    let keccak224_hash = keccak224_result.unwrap();
    assert_eq!(
        keccak224_hash.len(),
        28,
        "Keccak-224 should produce 28-byte output"
    );

    let keccak256_result = hash_ctx.hash(Algorithm::Keccak256, test_data);
    assert!(keccak256_result.is_ok(), "Keccak-256 should work");
    let keccak256_hash = keccak256_result.unwrap();
    assert_eq!(
        keccak256_hash.len(),
        32,
        "Keccak-256 should produce 32-byte output"
    );

    let keccak384_result = hash_ctx.hash(Algorithm::Keccak384, test_data);
    assert!(keccak384_result.is_ok(), "Keccak-384 should work");
    let keccak384_hash = keccak384_result.unwrap();
    assert_eq!(
        keccak384_hash.len(),
        48,
        "Keccak-384 should produce 48-byte output"
    );

    let keccak512_result = hash_ctx.hash(Algorithm::Keccak512, test_data);
    assert!(keccak512_result.is_ok(), "Keccak-512 should work");
    let keccak512_hash = keccak512_result.unwrap();
    assert_eq!(
        keccak512_hash.len(),
        64,
        "Keccak-512 should produce 64-byte output"
    );

    // Test TurboShake algorithms
    let turboshake128_result = hash_ctx.hash(Algorithm::TurboShake128, test_data);
    assert!(turboshake128_result.is_ok(), "TurboShake128 should work");
    let turboshake128_hash = turboshake128_result.unwrap();
    assert_eq!(
        turboshake128_hash.len(),
        16,
        "TurboShake128 should produce 16-byte output"
    );

    let turboshake256_result = hash_ctx.hash(Algorithm::TurboShake256, test_data);
    assert!(turboshake256_result.is_ok(), "TurboShake256 should work");
    let turboshake256_hash = turboshake256_result.unwrap();
    assert_eq!(
        turboshake256_hash.len(),
        32,
        "TurboShake256 should produce 32-byte output"
    );

    // Verify different algorithms produce different outputs
    assert_ne!(
        keccak224_hash, keccak256_hash,
        "Different Keccak variants should produce different outputs"
    );
    assert_ne!(
        turboshake128_hash, turboshake256_hash,
        "Different TurboShake variants should produce different outputs"
    );
}

#[test]
fn test_all_hash_algorithms_available() {
    // Test that all hash algorithms are properly registered and available
    let mut hash_ctx = create_hash_context();
    let test_data = b"Test data for algorithm availability";

    // Test all hash algorithms to ensure they're properly integrated
    let algorithms = [
        Algorithm::Shake128,
        Algorithm::Shake256,
        Algorithm::CShake128,
        Algorithm::CShake256,
        Algorithm::Sha3_224,
        Algorithm::Sha3_256,
        Algorithm::Sha3_384,
        Algorithm::Sha3_512,
        Algorithm::Keccak224,
        Algorithm::Keccak256,
        Algorithm::Keccak384,
        Algorithm::Keccak512,
        Algorithm::KangarooTwelve,
        Algorithm::TurboShake128,
        Algorithm::TurboShake256,
        Algorithm::Kmac128,
        Algorithm::Kmac256,
        Algorithm::TupleHash128,
        Algorithm::TupleHash256,
        Algorithm::ParallelHash128,
        Algorithm::ParallelHash256,
    ];

    for algorithm in algorithms {
        let result = hash_ctx.hash(algorithm, test_data);
        assert!(result.is_ok(), "Algorithm {:?} should work", algorithm);

        // Verify the result is not empty
        let hash = result.unwrap();
        assert!(
            !hash.is_empty(),
            "Algorithm {:?} should produce non-empty output",
            algorithm
        );

        // Verify the output size is reasonable (hash algorithms should produce non-empty output)
        assert!(
            hash.len() > 0,
            "Algorithm {:?} should produce output with length > 0",
            algorithm
        );
    }
}
