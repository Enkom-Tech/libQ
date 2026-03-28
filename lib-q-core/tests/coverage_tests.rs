// Additional tests to improve coverage for lib-q-core

use lib_q_core::algorithm_registry::AlgorithmRegistry;
use lib_q_core::error::Error;
use lib_q_core::{
    Algorithm,
    AlgorithmCategory,
    algorithms_by_category,
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
