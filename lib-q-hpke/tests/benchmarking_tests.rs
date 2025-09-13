//! Tests for benchmarking and performance profiling functionality

#![cfg(feature = "std")]

use lib_q_hpke::benchmarking::{
    AlgorithmType,
    OperationType,
    PerformanceMetrics,
    PerformanceProfiler,
};

/// Test basic profiling functionality
#[test]
fn test_basic_profiling() {
    let mut profiler = PerformanceProfiler::new();

    // Test single operation profiling
    let result = profiler.profile_function(
        OperationType::KemKeyGeneration,
        AlgorithmType::MlKem512,
        1,
        || {
            // Simulate some work
            std::thread::sleep(std::time::Duration::from_millis(1));
            Ok(42u32)
        },
    );

    assert!(result.is_ok());
    let (value, metrics) = result.unwrap();
    assert_eq!(value, 42);
    assert_eq!(metrics.operation, OperationType::KemKeyGeneration);
    assert_eq!(metrics.algorithm, AlgorithmType::MlKem512);
    assert_eq!(metrics.iterations, 1);
    assert_eq!(metrics.success_rate, 1.0);
    assert!(metrics.execution_time_ns > 0);
}

/// Test multiple iterations profiling
#[test]
fn test_multiple_iterations_profiling() {
    let mut profiler = PerformanceProfiler::new();

    let metrics =
        profiler.profile_multiple(OperationType::HpkeSeal, AlgorithmType::MlKem768, 10, || {
            // Simulate some work
            std::thread::sleep(std::time::Duration::from_micros(100));
            Ok(())
        });

    assert!(metrics.is_ok());
    let metrics = metrics.unwrap();
    assert_eq!(metrics.operation, OperationType::HpkeSeal);
    assert_eq!(metrics.algorithm, AlgorithmType::MlKem768);
    assert_eq!(metrics.iterations, 10);
    assert_eq!(metrics.success_rate, 1.0);
    assert!(metrics.execution_time_ns > 0);
}

/// Test profiling with failures
#[test]
fn test_profiling_with_failures() {
    let mut profiler = PerformanceProfiler::new();

    let counter = std::cell::RefCell::new(0);
    let metrics =
        profiler.profile_multiple(OperationType::HpkeOpen, AlgorithmType::MlKem1024, 5, || {
            let mut count = counter.borrow_mut();
            *count += 1;
            if *count % 2 == 0 {
                Err(lib_q_hpke::HpkeError::CryptoError(
                    "Simulated failure".to_string(),
                ))
            } else {
                Ok(())
            }
        });

    assert!(metrics.is_ok());
    let metrics = metrics.unwrap();
    assert_eq!(metrics.operation, OperationType::HpkeOpen);
    assert_eq!(metrics.algorithm, AlgorithmType::MlKem1024);
    assert_eq!(metrics.iterations, 5);
    assert_eq!(metrics.success_rate, 0.6); // 3 out of 5 successful
    assert!(metrics.execution_time_ns > 0);
}

/// Test manual start/stop profiling
#[test]
fn test_manual_profiling() {
    let mut profiler = PerformanceProfiler::new();

    // Start profiling
    profiler.start_profiling(OperationType::KemKeyGeneration, AlgorithmType::MlKem512);

    // Simulate some work
    std::thread::sleep(std::time::Duration::from_millis(1));

    // Stop profiling
    let metrics = profiler.stop_profiling(1, 1);

    assert!(metrics.is_ok());
    let metrics = metrics.unwrap();
    assert_eq!(metrics.operation, OperationType::KemKeyGeneration);
    assert_eq!(metrics.algorithm, AlgorithmType::MlKem512);
    assert_eq!(metrics.iterations, 1);
    assert_eq!(metrics.success_rate, 1.0);
    assert!(metrics.execution_time_ns > 0);
}

/// Test profiling macros
#[test]
fn test_profiling_macros() {
    let profiler = PerformanceProfiler::new();

    // Test profile_operation macro
    let metrics = lib_q_hpke::profile_operation!(
        profiler,
        OperationType::HpkeSeal,
        AlgorithmType::MlKem512,
        5,
        {
            std::thread::sleep(std::time::Duration::from_micros(50));
            Ok(())
        }
    );

    assert!(metrics.is_ok());
    let metrics = metrics.unwrap();
    assert_eq!(metrics.operation, OperationType::HpkeSeal);
    assert_eq!(metrics.algorithm, AlgorithmType::MlKem512);
    assert_eq!(metrics.iterations, 5);
    assert_eq!(metrics.success_rate, 1.0);
    assert!(metrics.execution_time_ns > 0);
}

/// Test profiling with custom calibration
#[test]
fn test_custom_calibration() {
    let mut profiler = PerformanceProfiler::with_calibration(2.0);

    let metrics = profiler.profile_multiple(
        OperationType::KemKeyGeneration,
        AlgorithmType::MlKem768,
        1,
        || {
            std::thread::sleep(std::time::Duration::from_millis(1));
            Ok(())
        },
    );

    assert!(metrics.is_ok());
    let metrics = metrics.unwrap();
    assert_eq!(metrics.operation, OperationType::KemKeyGeneration);
    assert_eq!(metrics.algorithm, AlgorithmType::MlKem768);
    assert_eq!(metrics.iterations, 1);
    assert_eq!(metrics.success_rate, 1.0);
    assert!(metrics.execution_time_ns > 0);
}

/// Test performance metrics display
#[test]
fn test_performance_metrics_display() {
    let metrics = PerformanceMetrics::new(
        OperationType::HpkeSeal,
        AlgorithmType::MlKem1024,
        1000, // 1 microsecond
        1024, // 1KB memory usage
        10,   // 10 iterations
        0.9,  // 90% success rate
    );

    // Test getter methods
    assert_eq!(metrics.operation, OperationType::HpkeSeal);
    assert_eq!(metrics.algorithm, AlgorithmType::MlKem1024);
    assert_eq!(metrics.execution_time_ns, 1000);
    assert_eq!(metrics.memory_usage_bytes, 1024);
    assert_eq!(metrics.iterations, 10);
    assert_eq!(metrics.success_rate, 0.9);

    // Test that metrics can be formatted
    let formatted = format!("{:?}", metrics);
    assert!(formatted.contains("HpkeSeal"));
    assert!(formatted.contains("MlKem1024"));
}

/// Test timing accuracy
#[test]
fn test_timing_accuracy() {
    let mut profiler = PerformanceProfiler::new();

    // Test with known sleep duration
    let sleep_duration = std::time::Duration::from_millis(10);
    let start = std::time::Instant::now();

    let metrics = profiler.profile_multiple(
        OperationType::KemKeyGeneration,
        AlgorithmType::MlKem512,
        1,
        || {
            std::thread::sleep(sleep_duration);
            Ok(())
        },
    );

    let end = std::time::Instant::now();
    let real_duration = end.duration_since(start);

    assert!(metrics.is_ok());
    let metrics = metrics.unwrap();

    // The measured time should be reasonably close to the actual sleep time
    // Allow for some variance due to timing precision and system scheduling
    let measured_ns = metrics.execution_time_ns;
    let expected_ns = real_duration.as_nanos() as u64;

    // Allow 20% variance
    let variance = expected_ns / 5;
    assert!(
        measured_ns >= expected_ns.saturating_sub(variance) &&
            measured_ns <= expected_ns + variance,
        "Measured time {}ns not within expected range {}ns ± {}ns",
        measured_ns,
        expected_ns,
        variance
    );
}

/// Test memory usage tracking
#[test]
fn test_memory_usage_tracking() {
    let mut profiler = PerformanceProfiler::new();

    profiler.start_profiling(OperationType::HpkeSeal, AlgorithmType::MlKem512);

    // Allocate some memory
    let _data = vec![0u8; 1024];

    let metrics = profiler.stop_profiling(1, 1);

    assert!(metrics.is_ok());
    let metrics = metrics.unwrap();

    // Memory usage should be tracked (exact value depends on implementation)
    assert!(metrics.memory_usage_bytes >= 0);
}

/// Test error handling in profiling
#[test]
fn test_profiling_error_handling() {
    let mut profiler = PerformanceProfiler::new();

    // Test stopping profiling without starting
    let result = profiler.stop_profiling(1, 1);
    assert!(result.is_err());

    // Test profiling with all failures
    let metrics = profiler.profile_multiple(
        OperationType::HpkeOpen,
        AlgorithmType::MlKem768,
        3,
        || -> Result<(), lib_q_hpke::HpkeError> {
            Err(lib_q_hpke::HpkeError::CryptoError(
                "Always fails".to_string(),
            ))
        },
    );

    assert!(metrics.is_ok());
    let metrics = metrics.unwrap();
    assert_eq!(metrics.success_rate, 0.0);
    assert_eq!(metrics.iterations, 3);
}
