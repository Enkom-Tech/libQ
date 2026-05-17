//! Comprehensive tests for the feature configuration functionality
//!
//! These tests ensure complete coverage of the feature detection and configuration
//! capabilities in lib-q-keccak.

use lib_q_keccak::{
    FeatureConfig,
    OptimizationLevel,
    detection,
    get_global_config,
    reset_global_config,
    set_global_config,
};

#[test]
fn test_feature_config_new() {
    let config = FeatureConfig::new();
    assert!(config.optimization_level.is_available());
    assert!(config.enable_parallel);
    assert!(config.enable_advanced_simd);
    assert!(config.enable_platform_optimizations);
}

#[test]
fn test_feature_config_with_optimization_level() {
    let config = FeatureConfig::with_optimization_level(OptimizationLevel::Reference);
    assert_eq!(config.optimization_level, OptimizationLevel::Reference);
    assert!(config.enable_parallel);
    assert!(config.enable_advanced_simd);
    assert!(config.enable_platform_optimizations);
}

#[test]
fn test_feature_config_compatibility_optimized() {
    let config = FeatureConfig::compatibility_optimized();
    assert_eq!(config.optimization_level, OptimizationLevel::Basic);
    assert!(!config.enable_parallel);
    assert!(!config.enable_advanced_simd);
    assert!(config.enable_platform_optimizations);
}

#[test]
fn test_parallel_available() {
    // Test when enabled
    let config = FeatureConfig {
        enable_parallel: true,
        optimization_level: OptimizationLevel::Advanced,
        ..Default::default()
    };

    // Check if it's consistent with the configuration
    assert_eq!(
        config.parallel_available(),
        cfg!(all(feature = "simd", keccak_portable_simd)) &&
            config.optimization_level != OptimizationLevel::Reference
    );

    // Test when disabled by optimization level
    let config_ref = FeatureConfig {
        enable_parallel: true,
        optimization_level: OptimizationLevel::Reference,
        ..Default::default()
    };
    assert!(!config_ref.parallel_available());

    // Test when explicitly disabled
    let config_disabled = FeatureConfig {
        enable_parallel: false,
        optimization_level: OptimizationLevel::Advanced,
        ..Default::default()
    };
    assert!(!config_disabled.parallel_available());
}

#[test]
fn test_advanced_simd_available() {
    // Test when enabled
    let config = FeatureConfig {
        enable_advanced_simd: true,
        optimization_level: OptimizationLevel::Advanced,
        ..Default::default()
    };

    // Check if it's consistent with the configuration
    assert_eq!(
        config.advanced_simd_available(),
        cfg!(all(feature = "simd", keccak_portable_simd)) &&
            config.optimization_level != OptimizationLevel::Reference
    );

    // Test when disabled by optimization level
    let config_ref = FeatureConfig {
        enable_advanced_simd: true,
        optimization_level: OptimizationLevel::Reference,
        ..Default::default()
    };
    assert!(!config_ref.advanced_simd_available());

    // Test when explicitly disabled
    let config_disabled = FeatureConfig {
        enable_advanced_simd: false,
        optimization_level: OptimizationLevel::Advanced,
        ..Default::default()
    };
    assert!(!config_disabled.advanced_simd_available());
}

#[test]
fn test_platform_optimizations_available() {
    // Test when enabled
    let config = FeatureConfig {
        enable_platform_optimizations: true,
        optimization_level: OptimizationLevel::Advanced,
        ..Default::default()
    };
    assert!(config.platform_optimizations_available());

    // Test when disabled by optimization level
    let config_ref = FeatureConfig {
        enable_platform_optimizations: true,
        optimization_level: OptimizationLevel::Reference,
        ..Default::default()
    };
    assert!(!config_ref.platform_optimizations_available());

    // Test when explicitly disabled
    let config_disabled = FeatureConfig {
        enable_platform_optimizations: false,
        optimization_level: OptimizationLevel::Advanced,
        ..Default::default()
    };
    assert!(!config_disabled.platform_optimizations_available());
}

#[test]
fn test_effective_optimization_level() {
    // Test normal case
    let config = FeatureConfig {
        optimization_level: OptimizationLevel::Advanced,
        enable_platform_optimizations: true,
        enable_advanced_simd: true,
        ..Default::default()
    };
    assert_eq!(
        config.effective_optimization_level(),
        OptimizationLevel::Advanced
    );

    // Test when platform optimizations are disabled
    let config_no_platform = FeatureConfig {
        optimization_level: OptimizationLevel::Advanced,
        enable_platform_optimizations: false,
        enable_advanced_simd: true,
        ..Default::default()
    };
    assert_eq!(
        config_no_platform.effective_optimization_level(),
        OptimizationLevel::Reference
    );

    // Test when advanced SIMD is disabled but max optimization is selected
    let config_no_simd = FeatureConfig {
        optimization_level: OptimizationLevel::Maximum,
        enable_platform_optimizations: true,
        enable_advanced_simd: false,
        ..Default::default()
    };
    assert_eq!(
        config_no_simd.effective_optimization_level(),
        OptimizationLevel::Advanced
    );

    // Ensure other cases work as expected
    let config_basic = FeatureConfig {
        optimization_level: OptimizationLevel::Basic,
        enable_platform_optimizations: true,
        enable_advanced_simd: true,
        ..Default::default()
    };
    assert_eq!(
        config_basic.effective_optimization_level(),
        OptimizationLevel::Basic
    );
}

#[test]
fn test_description() {
    // Test all features enabled
    let config = FeatureConfig {
        enable_platform_optimizations: true,
        enable_parallel: true,
        enable_advanced_simd: true,
        optimization_level: OptimizationLevel::Maximum,
    };

    // Check description is consistent with availability
    let description = config.description();
    assert!(!description.is_empty());

    // Test with just platform optimizations
    let config_platform_only = FeatureConfig {
        enable_platform_optimizations: true,
        enable_parallel: false,
        enable_advanced_simd: false,
        optimization_level: OptimizationLevel::Basic,
    };
    assert_eq!(
        config_platform_only.description(),
        "basic optimization with platform features"
    );

    // Test with no optimizations
    let config_no_optimizations = FeatureConfig {
        enable_platform_optimizations: false,
        enable_parallel: false,
        enable_advanced_simd: false,
        optimization_level: OptimizationLevel::Reference,
    };
    assert_eq!(
        config_no_optimizations.description(),
        "reference implementation"
    );

    // Test with platform and parallel
    let config_platform_parallel = FeatureConfig {
        enable_platform_optimizations: true,
        enable_parallel: true,
        enable_advanced_simd: false,
        optimization_level: OptimizationLevel::Advanced,
    };

    // The exact string may depend on runtime detection
    assert!(
        config_platform_parallel.description().contains("parallel") ||
            config_platform_parallel.description().contains("platform")
    );
}

#[test]
fn test_global_config_set_get_reset() {
    // Save original config to restore it later
    let original_config = get_global_config();

    // Test setting custom config
    let test_config = FeatureConfig::security_optimized();
    set_global_config(test_config.clone());

    // Verify it was set correctly
    let retrieved = get_global_config();
    assert_eq!(retrieved.optimization_level, test_config.optimization_level);
    assert_eq!(retrieved.enable_parallel, test_config.enable_parallel);
    assert_eq!(
        retrieved.enable_advanced_simd,
        test_config.enable_advanced_simd
    );
    assert_eq!(
        retrieved.enable_platform_optimizations,
        test_config.enable_platform_optimizations
    );

    // Test resetting to default
    reset_global_config();
    let default = get_global_config();
    assert_eq!(
        default.optimization_level,
        OptimizationLevel::best_available()
    );

    // Restore original config
    set_global_config(original_config.clone());
}

#[test]
#[cfg(feature = "std")]
fn test_global_config_concurrent_access() {
    use std::sync::{
        Arc,
        Barrier,
    };
    use std::thread;

    const THREADS: usize = 8;
    const ITERATIONS: usize = 1_000;

    // Start from a known baseline and restore at the end.
    let original_config = get_global_config();
    reset_global_config();

    let start_barrier = Arc::new(Barrier::new(THREADS + 1));
    let mut handles = Vec::with_capacity(THREADS);

    for thread_id in 0..THREADS {
        let start_barrier = Arc::clone(&start_barrier);
        handles.push(thread::spawn(move || {
            start_barrier.wait();

            for i in 0..ITERATIONS {
                let config = if (thread_id + i) % 2 == 0 {
                    FeatureConfig::performance_optimized()
                } else {
                    FeatureConfig::security_optimized()
                };

                set_global_config(config.clone());
                let observed = get_global_config();

                // We cannot assert identity under races, but every observed
                // value must be a valid full config snapshot.
                assert!(matches!(
                    observed.optimization_level,
                    OptimizationLevel::Reference |
                        OptimizationLevel::Basic |
                        OptimizationLevel::Advanced |
                        OptimizationLevel::Maximum
                ));

                if (thread_id + i) % 17 == 0 {
                    reset_global_config();
                    let snapshot = get_global_config();
                    assert!(matches!(
                        snapshot.optimization_level,
                        OptimizationLevel::Reference |
                            OptimizationLevel::Basic |
                            OptimizationLevel::Advanced |
                            OptimizationLevel::Maximum
                    ));
                }
            }
        }));
    }

    // Release all workers at once to maximize lock contention.
    start_barrier.wait();
    for handle in handles {
        handle.join().expect("worker thread should not panic");
    }

    // API remains usable after concurrent pressure.
    set_global_config(original_config.clone());
    let restored = get_global_config();
    assert_eq!(
        restored.optimization_level,
        original_config.optimization_level
    );
    assert_eq!(restored.enable_parallel, original_config.enable_parallel);
    assert_eq!(
        restored.enable_advanced_simd,
        original_config.enable_advanced_simd
    );
    assert_eq!(
        restored.enable_platform_optimizations,
        original_config.enable_platform_optimizations
    );
}

#[test]
fn test_feature_report_summary() {
    let report = detection::detect_available_features();

    // Check that summary is non-empty and contains expected content
    let summary = report.summary();
    assert!(!summary.is_empty());

    // Test that the summary is consistent with detected features
    if report.avx512f {
        assert!(summary.contains("AVX-512"));
    }

    if report.avx2 {
        assert!(summary.contains("AVX2"));
    }

    if report.x86_64 {
        assert!(summary.contains("x86_64"));
    }

    if report.aarch64 {
        assert!(summary.contains("AArch64"));
    }

    if !report.x86_64 &&
        !report.aarch64 &&
        !report.avx2 &&
        !report.avx512f &&
        !report.sha3_intrinsics &&
        !report.simd_support
    {
        assert_eq!(summary, "No special features available");
    }
}

#[test]
fn test_feature_report_recommended_level() {
    let report = detection::detect_available_features();
    let recommended = report.recommended_optimization_level();

    // Test that the recommended level is consistent with detected features
    if report.avx512f && OptimizationLevel::Maximum.is_available() {
        assert_eq!(recommended, OptimizationLevel::Maximum);
    } else if report.avx2 && OptimizationLevel::Advanced.is_available() {
        assert_eq!(recommended, OptimizationLevel::Advanced);
    } else if report.sha3_intrinsics && OptimizationLevel::Basic.is_available() {
        assert_eq!(recommended, OptimizationLevel::Basic);
    } else {
        assert_eq!(recommended, OptimizationLevel::Reference);
    }

    // Verify the recommended level is actually available
    assert!(recommended.is_available());
}

#[test]
fn test_best_available_optimization() {
    let best = detection::best_available_optimization();
    assert!(best.is_available());
}

#[test]
fn test_is_optimization_available() {
    // Reference implementation should always be available
    assert!(detection::is_optimization_available(
        OptimizationLevel::Reference
    ));

    // Check all other levels - results depend on the platform
    // But the function should at least not panic
    for level in &[
        OptimizationLevel::Basic,
        OptimizationLevel::Advanced,
        OptimizationLevel::Maximum,
    ] {
        let _ = detection::is_optimization_available(*level);
    }
}
