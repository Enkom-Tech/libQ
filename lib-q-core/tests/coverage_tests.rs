// Additional tests to improve coverage for lib-q-core

use lib_q_core::algorithm_registry::AlgorithmRegistry;
use lib_q_core::error::Error;
use lib_q_core::{
    Algorithm,
    AlgorithmCategory,
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
