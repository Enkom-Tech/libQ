use libq::{
    Algorithm,
    create_hash_context,
};

#[test]
fn test_new_hash_algorithms() {
    // Test the newly added hash algorithms
    let mut hash_ctx = create_hash_context();
    let test_data = b"Hello, libQ!";

    // Test KangarooTwelve - should return NotImplemented with current architecture
    let kt_result = hash_ctx.hash(Algorithm::KangarooTwelve, test_data);
    assert!(
        kt_result.is_err(),
        "KangarooTwelve should return NotImplemented error with current architecture"
    );

    if let Err(libq::Error::NotImplemented { feature }) = kt_result {
        assert!(feature.contains("Hash operations - no provider configured"));
    } else {
        panic!("Expected NotImplemented error for KangarooTwelve");
    }

    // Test Keccak algorithms - should return NotImplemented with current architecture
    let keccak224_result = hash_ctx.hash(Algorithm::Keccak224, test_data);
    assert!(
        keccak224_result.is_err(),
        "Keccak-224 should return NotImplemented error"
    );

    if let Err(libq::Error::NotImplemented { feature }) = keccak224_result {
        assert!(feature.contains("Hash operations - no provider configured"));
    } else {
        panic!("Expected NotImplemented error for Keccak-224");
    }

    let keccak256_result = hash_ctx.hash(Algorithm::Keccak256, test_data);
    assert!(
        keccak256_result.is_err(),
        "Keccak-256 should return NotImplemented error"
    );

    if let Err(libq::Error::NotImplemented { feature }) = keccak256_result {
        assert!(feature.contains("Hash operations - no provider configured"));
    } else {
        panic!("Expected NotImplemented error for Keccak-256");
    }

    let keccak384_result = hash_ctx.hash(Algorithm::Keccak384, test_data);
    assert!(
        keccak384_result.is_err(),
        "Keccak-384 should return NotImplemented error"
    );

    if let Err(libq::Error::NotImplemented { feature }) = keccak384_result {
        assert!(feature.contains("Hash operations - no provider configured"));
    } else {
        panic!("Expected NotImplemented error for Keccak-384");
    }

    let keccak512_result = hash_ctx.hash(Algorithm::Keccak512, test_data);
    assert!(
        keccak512_result.is_err(),
        "Keccak-512 should return NotImplemented error"
    );

    if let Err(libq::Error::NotImplemented { feature }) = keccak512_result {
        assert!(feature.contains("Hash operations - no provider configured"));
    } else {
        panic!("Expected NotImplemented error for Keccak-512");
    }

    // Test TurboShake algorithms - should return NotImplemented with current architecture
    let turboshake128_result = hash_ctx.hash(Algorithm::TurboShake128, test_data);
    assert!(
        turboshake128_result.is_err(),
        "TurboShake128 should return NotImplemented error"
    );

    if let Err(libq::Error::NotImplemented { feature }) = turboshake128_result {
        assert!(feature.contains("Hash operations - no provider configured"));
    } else {
        panic!("Expected NotImplemented error for TurboShake128");
    }

    let turboshake256_result = hash_ctx.hash(Algorithm::TurboShake256, test_data);
    assert!(
        turboshake256_result.is_err(),
        "TurboShake256 should return NotImplemented error"
    );

    if let Err(libq::Error::NotImplemented { feature }) = turboshake256_result {
        assert!(feature.contains("Hash operations - no provider configured"));
    } else {
        panic!("Expected NotImplemented error for TurboShake256");
    }
}

#[test]
fn test_all_hash_algorithms_available() {
    // Test that all hash algorithms are properly registered and return appropriate errors
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
        assert!(
            result.is_err(),
            "Algorithm {:?} should return NotImplemented error with current architecture",
            algorithm
        );

        // Verify the error is NotImplemented
        if let Err(libq::Error::NotImplemented { feature }) = result {
            assert!(
                feature.contains("Hash operations - no provider configured"),
                "Algorithm {:?} should return appropriate NotImplemented error message",
                algorithm
            );
        } else {
            panic!(
                "Algorithm {:?} should return NotImplemented error, got different error type",
                algorithm
            );
        }
    }
}
