//! Integration tests for HPKE provider wiring, errors, benchmarking, and security helpers.

use lib_q_hpke::benchmarking::*;
use lib_q_hpke::error::*;
use lib_q_hpke::providers::*;
use lib_q_hpke::security::*;
use lib_q_hpke::types::*;

#[test]
fn test_post_quantum_provider_smoke() {
    let provider = PostQuantumProvider::new();
    assert_eq!(provider.name(), "PostQuantumProvider");

    let algorithms = provider.supported_algorithms();
    assert!(algorithms.supports_aead(HpkeAead::Export));
    #[cfg(feature = "saturnin")]
    assert!(algorithms.supports_aead(HpkeAead::Saturnin256));
}

#[test]
fn test_error_conversion() {
    let hpke_error =
        HpkeError::kem_error(HpkeKem::MlKem512, KemOperation::KeyGeneration, "Test error");

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
fn test_performance_metrics() {
    let metrics = PerformanceMetrics::new(
        OperationType::KemKeyGeneration,
        AlgorithmType::MlKem512,
        1_000_000,
        1024,
        100,
        0.95,
    );

    assert_eq!(metrics.operation, OperationType::KemKeyGeneration);
    assert_eq!(metrics.algorithm, AlgorithmType::MlKem512);
    assert_eq!(metrics.avg_execution_time_ns(), 10_000.0);
    assert_eq!(metrics.throughput_ops_per_sec(), 100_000.0);
    assert_eq!(metrics.memory_efficiency_bytes_per_op(), 10.24);
}

#[test]
fn test_metrics_collector() {
    let mut collector = MetricsCollector::new();
    assert!(collector.is_empty());

    let metrics1 = PerformanceMetrics::new(
        OperationType::KemKeyGeneration,
        AlgorithmType::MlKem512,
        1_000_000,
        1024,
        100,
        0.95,
    );

    let metrics2 = PerformanceMetrics::new(
        OperationType::KemKeyGeneration,
        AlgorithmType::MlKem768,
        2_000_000,
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
    assert_eq!(avg.iterations, 150);
    assert_eq!(avg.execution_time_ns, 3_000_000);
}

#[test]
fn test_performance_profiler() {
    let mut profiler = PerformanceProfiler::new();

    let result = profiler.profile_function(
        OperationType::KemKeyGeneration,
        AlgorithmType::MlKem512,
        1,
        || {
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
    let mut reporter = PerformanceReporter::new();

    let metrics = PerformanceMetrics::new(
        OperationType::KemKeyGeneration,
        AlgorithmType::MlKem512,
        1_000_000,
        1024,
        100,
        0.95,
    );

    reporter.add_metrics(metrics);

    let text_report = reporter.generate_text_report();
    assert!(text_report.contains("HPKE Performance Report"));
    assert!(text_report.contains("KemKeyGeneration"));
    assert!(text_report.contains("MlKem512"));

    let csv_report = reporter.generate_csv_report();
    assert!(csv_report.contains("Operation,Algorithm"));
    assert!(csv_report.contains("KemKeyGeneration"));

    let json_report = reporter.generate_json_report();
    assert!(json_report.contains("\"summary\""));
    assert!(json_report.contains("\"operations\""));
    assert!(json_report.contains("KemKeyGeneration"));
}

#[test]
fn test_performance_comparator() {
    let mut comparator = PerformanceComparator::new();

    let mut baseline_collector = MetricsCollector::new();
    let baseline_metrics = PerformanceMetrics::new(
        OperationType::KemKeyGeneration,
        AlgorithmType::MlKem512,
        2_000_000,
        1024,
        100,
        0.95,
    );
    baseline_collector.add_metrics(baseline_metrics);
    comparator.set_baseline(baseline_collector);

    let mut current_collector = MetricsCollector::new();
    let current_metrics = PerformanceMetrics::new(
        OperationType::KemKeyGeneration,
        AlgorithmType::MlKem512,
        1_000_000,
        1024,
        100,
        0.95,
    );
    current_collector.add_metrics(current_metrics);
    comparator.set_current(current_collector);

    let comparison_report = comparator.compare();
    assert!(comparison_report.contains("Performance Comparison Report"));
    assert!(comparison_report.contains("Time improvement"));
    assert!(comparison_report.contains("Throughput improvement"));
}

#[test]
fn test_algorithm_type_conversions() {
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
    let policy = SecurityPolicy::strict();
    let validator = CryptographicValidator::new(policy);

    let key = vec![1u8; 32];
    assert!(
        validator
            .validate_aead_key(HpkeAead::Saturnin256, &key)
            .is_ok()
    );

    let nonce = vec![1u8; 16];
    assert!(
        validator
            .validate_aead_nonce(HpkeAead::Saturnin256, &nonce)
            .is_ok()
    );

    let invalid_key = vec![1u8; 16];
    assert!(
        validator
            .validate_aead_key(HpkeAead::Saturnin256, &invalid_key)
            .is_err()
    );
}

#[test]
fn test_secure_memory_integration() {
    let key = SecureKey::new(vec![1u8; 32], KeyType::AeadKey).unwrap();
    assert_eq!(key.as_bytes(), &[1u8; 32]);
    assert_eq!(key.len(), 32);

    let nonce = SecureBytes::new(vec![5u8, 6u8, 7u8, 8u8]);
    assert_eq!(nonce.as_bytes(), &[5u8, 6u8, 7u8, 8u8]);
    assert_eq!(nonce.len(), 4);

    let mut buffer = SecureBytes::with_capacity(8);
    buffer.extend_from_slice(&[1u8, 2u8]);
    assert_eq!(buffer.len(), 2);
    assert_eq!(buffer.as_bytes(), &[1u8, 2u8]);
}

#[test]
fn test_constant_time_operations_integration() {
    let a = b"hello";
    let b = b"hello";
    let c = b"world";

    assert!(constant_time_eq(a, b));
    assert!(!constant_time_eq(a, c));

    assert_eq!(constant_time_select(true, 0xFF, 0x00), 0xFF);
    assert_eq!(constant_time_select(false, 0xFF, 0x00), 0x00);

    let mut dst = [0u8; 4];
    let src = [1u8, 2u8, 3u8, 4u8];
    constant_time_copy(true, &src, &mut dst);
    assert_eq!(dst, src);

    constant_time_copy(false, &[5u8, 6u8, 7u8, 8u8], &mut dst);
    assert_eq!(dst, src);
}
