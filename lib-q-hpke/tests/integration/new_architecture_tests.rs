//! Integration tests for the new HPKE architecture

use lib_q_hpke::{
    security::*,
    error::*,
    types::*,
    providers::*,
    integration::*,
    benchmarking::*,
};

#[test]
fn test_integration_layer_compilation() {
    // Test that the integration layer compiles and basic types work
    let bridge = LibQProviderBridge::new();
    assert_eq!(bridge.name(), "LibQProviderBridge");
    
    let algorithms = bridge.supported_algorithms();
    assert!(algorithms.supports_aead(HpkeAead::Export));
    assert!(!algorithms.supports_aead(HpkeAead::Saturnin256));
}

#[test]
fn test_error_conversion() {
    // Test error conversion between HPKE and lib-q-core
    let hpke_error = HpkeError::kem_error(
        HpkeKem::MlKem512,
        KemOperation::KeyGeneration,
        "Test error",
    );
    
    let libq_error: lib_q_core::Error = hpke_error.into();
    match libq_error {
        lib_q_core::Error::InternalError { operation, details } => {
            assert!(operation.contains("KEM"));
            assert!(operation.contains("KeyGeneration"));
            assert_eq!(details, "Test error");
        }
        _ => panic!("Expected InternalError"),
    }
}

#[test]
fn test_type_adapters() {
    // Test algorithm type conversions
    let kem = HpkeKem::MlKem512;
    let algorithm = AlgorithmAdapter::kem_to_algorithm(kem);
    assert_eq!(algorithm, lib_q_core::Algorithm::MlKem512);
    
    let converted_kem = AlgorithmAdapter::algorithm_to_kem(algorithm);
    assert_eq!(converted_kem, Some(kem));
    
    let kdf = HpkeKdf::HkdfShake256;
    let kdf_algorithm = AlgorithmAdapter::kdf_to_algorithm(kdf);
    assert_eq!(kdf_algorithm, lib_q_core::Algorithm::Shake256);
    
    let aead = HpkeAead::Saturnin256;
    let aead_algorithm = AlgorithmAdapter::aead_to_algorithm(aead);
    assert_eq!(aead_algorithm, Some(lib_q_core::Algorithm::Saturnin256));
}

#[test]
fn test_cipher_suite_adapter() {
    // Test cipher suite creation
    let default_suite = CipherSuiteAdapter::default();
    assert_eq!(default_suite.kem, HpkeKem::MlKem512);
    assert_eq!(default_suite.kdf, HpkeKdf::HkdfShake256);
    assert_eq!(default_suite.aead, HpkeAead::Saturnin256);
    
    // Test cipher suite from algorithms
    let suite = CipherSuiteAdapter::from_algorithms(
        lib_q_core::Algorithm::MlKem768,
        lib_q_core::Algorithm::Shake256,
        lib_q_core::Algorithm::Saturnin256,
    ).unwrap();
    
    assert_eq!(suite.kem, HpkeKem::MlKem768);
    assert_eq!(suite.kdf, HpkeKdf::HkdfShake256);
    assert_eq!(suite.aead, HpkeAead::Saturnin256);
}

#[test]
fn test_performance_metrics() {
    // Test performance metrics creation
    let metrics = PerformanceMetrics::new(
        OperationType::KemKeyGeneration,
        AlgorithmType::MlKem512,
        1000000, // 1ms in nanoseconds
        1024,    // 1KB memory usage
        100,     // 100 iterations
        0.95,    // 95% success rate
    );
    
    assert_eq!(metrics.operation, OperationType::KemKeyGeneration);
    assert_eq!(metrics.algorithm, AlgorithmType::MlKem512);
    assert_eq!(metrics.avg_execution_time_ns(), 10000.0); // 10μs per operation
    assert_eq!(metrics.throughput_ops_per_sec(), 100000.0); // 100k ops/sec
    assert_eq!(metrics.memory_efficiency_bytes_per_op(), 10.24); // ~10 bytes per op
}

#[test]
fn test_metrics_collector() {
    // Test metrics collection
    let mut collector = MetricsCollector::new();
    assert!(collector.is_empty());
    
    let metrics1 = PerformanceMetrics::new(
        OperationType::KemKeyGeneration,
        AlgorithmType::MlKem512,
        1000000,
        1024,
        100,
        0.95,
    );
    
    let metrics2 = PerformanceMetrics::new(
        OperationType::KemKeyGeneration,
        AlgorithmType::MlKem768,
        2000000,
        2048,
        50,
        0.90,
    );
    
    collector.add_metrics(metrics1);
    collector.add_metrics(metrics2);
    
    assert_eq!(collector.len(), 2);
    
    let kem_gen_metrics = collector.get_metrics_for_operation(OperationType::KemKeyGeneration);
    assert_eq!(kem_gen_metrics.len(), 2);
    
    let ml_kem_512_metrics = collector.get_metrics_for_algorithm(AlgorithmType::MlKem512);
    assert_eq!(ml_kem_512_metrics.len(), 1);
    
    let avg_metrics = collector.get_average_metrics_for_operation(OperationType::KemKeyGeneration);
    assert!(avg_metrics.is_some());
    let avg = avg_metrics.unwrap();
    assert_eq!(avg.iterations, 150); // 100 + 50
    assert_eq!(avg.execution_time_ns, 3000000); // 1ms + 2ms
}

#[test]
fn test_performance_profiler() {
    // Test performance profiling
    let mut profiler = PerformanceProfiler::new();
    
    // Test single operation profiling
    let result = profiler.profile_function(
        OperationType::KemKeyGeneration,
        AlgorithmType::MlKem512,
        1,
        || {
            // Simulate some work
            std::thread::sleep(std::time::Duration::from_micros(100));
            Ok::<(), HpkeError>(())
        },
    );
    
    assert!(result.is_ok());
    let (_, metrics) = result.unwrap();
    assert_eq!(metrics.operation, OperationType::KemKeyGeneration);
    assert_eq!(metrics.algorithm, AlgorithmType::MlKem512);
    assert_eq!(metrics.iterations, 1);
    assert_eq!(metrics.success_rate, 1.0);
    assert!(metrics.execution_time_ns > 0);
}

#[test]
fn test_performance_reporter() {
    // Test performance reporting
    let mut reporter = PerformanceReporter::new();
    
    let metrics = PerformanceMetrics::new(
        OperationType::KemKeyGeneration,
        AlgorithmType::MlKem512,
        1000000,
        1024,
        100,
        0.95,
    );
    
    reporter.add_metrics(metrics);
    
    // Test text report generation
    let text_report = reporter.generate_text_report();
    assert!(text_report.contains("HPKE Performance Report"));
    assert!(text_report.contains("KemKeyGeneration"));
    assert!(text_report.contains("MlKem512"));
    
    // Test CSV report generation
    let csv_report = reporter.generate_csv_report();
    assert!(csv_report.contains("Operation,Algorithm"));
    assert!(csv_report.contains("KemKeyGeneration"));
    
    // Test JSON report generation
    let json_report = reporter.generate_json_report();
    assert!(json_report.contains("\"summary\""));
    assert!(json_report.contains("\"operations\""));
    assert!(json_report.contains("KemKeyGeneration"));
}

#[test]
fn test_performance_comparator() {
    // Test performance comparison
    let mut comparator = PerformanceComparator::new();
    
    // Create baseline metrics
    let mut baseline_collector = MetricsCollector::new();
    let baseline_metrics = PerformanceMetrics::new(
        OperationType::KemKeyGeneration,
        AlgorithmType::MlKem512,
        2000000, // 2ms
        1024,
        100,
        0.95,
    );
    baseline_collector.add_metrics(baseline_metrics);
    comparator.set_baseline(baseline_collector);
    
    // Create current metrics
    let mut current_collector = MetricsCollector::new();
    let current_metrics = PerformanceMetrics::new(
        OperationType::KemKeyGeneration,
        AlgorithmType::MlKem512,
        1000000, // 1ms (50% improvement)
        1024,
        100,
        0.95,
    );
    current_collector.add_metrics(current_metrics);
    comparator.set_current(current_collector);
    
    // Generate comparison report
    let comparison_report = comparator.compare();
    assert!(comparison_report.contains("Performance Comparison Report"));
    assert!(comparison_report.contains("Time improvement"));
    assert!(comparison_report.contains("Throughput improvement"));
}

#[test]
fn test_algorithm_type_conversions() {
    // Test HPKE type to AlgorithmType conversions
    let kem = HpkeKem::MlKem512;
    let algorithm_type: AlgorithmType = kem.into();
    assert_eq!(algorithm_type, AlgorithmType::MlKem512);
    
    let kdf = HpkeKdf::HkdfShake256;
    let algorithm_type: AlgorithmType = kdf.into();
    assert_eq!(algorithm_type, AlgorithmType::HkdfShake256);
    
    let aead = HpkeAead::Saturnin256;
    let algorithm_type: AlgorithmType = aead.into();
    assert_eq!(algorithm_type, AlgorithmType::Saturnin256);
}

#[test]
fn test_security_policy_integration() {
    // Test security policy integration
    let policy = SecurityPolicy::strict();
    let validator = CryptographicValidator::new(policy);
    
    // Test key validation
    let key = vec![1u8; 32];
    assert!(validator.validate_aead_key(HpkeAead::Saturnin256, &key).is_ok());
    
    // Test nonce validation
    let nonce = vec![1u8; 16];
    assert!(validator.validate_aead_nonce(HpkeAead::Saturnin256, &nonce).is_ok());
    
    // Test invalid key length
    let invalid_key = vec![1u8; 16]; // Wrong length for Saturnin256
    assert!(validator.validate_aead_key(HpkeAead::Saturnin256, &invalid_key).is_err());
}

#[test]
fn test_secure_memory_integration() {
    // Test secure memory integration
    let key = SecureKey::new(vec![1u8, 2u8, 3u8, 4u8]);
    assert_eq!(key.as_slice(), &[1u8, 2u8, 3u8, 4u8]);
    assert_eq!(key.len(), 4);
    
    let nonce = SecureNonce::new(vec![5u8, 6u8, 7u8, 8u8]);
    assert_eq!(nonce.as_slice(), &[5u8, 6u8, 7u8, 8u8]);
    assert_eq!(nonce.len(), 4);
    
    let mut buffer = SecureBuffer::new();
    buffer.push(1);
    buffer.push(2);
    assert_eq!(buffer.len(), 2);
    assert_eq!(buffer.as_slice(), &[1u8, 2u8]);
}

#[test]
fn test_constant_time_operations_integration() {
    // Test constant-time operations integration
    let a = b"hello";
    let b = b"hello";
    let c = b"world";
    
    assert!(constant_time_eq(a, b));
    assert!(!constant_time_eq(a, c));
    
    assert_eq!(constant_time_select(1, 0xFF, 0x00), 0xFF);
    assert_eq!(constant_time_select(0, 0xFF, 0x00), 0x00);
    
    // Test constant-time copy
    let mut dst = [0u8; 4];
    let src = [1u8, 2u8, 3u8, 4u8];
    constant_time_copy(1, &mut dst, &src);
    assert_eq!(dst, src);
    
    constant_time_copy(0, &mut dst, &[5u8, 6u8, 7u8, 8u8]);
    assert_eq!(dst, src); // Should be unchanged
}
