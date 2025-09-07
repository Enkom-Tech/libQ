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
    let mut config = FeatureConfig::default();

    // Test when enabled
    config.enable_parallel = true;
    config.optimization_level = OptimizationLevel::Advanced;

    // Check if it's consistent with the configuration
    assert_eq!(
        config.parallel_available(),
        cfg!(feature = "simd") && config.optimization_level != OptimizationLevel::Reference
    );

    // Test when disabled by optimization level
    config.optimization_level = OptimizationLevel::Reference;
    assert!(!config.parallel_available());

    // Test when explicitly disabled
    config.enable_parallel = false;
    config.optimization_level = OptimizationLevel::Advanced;
    assert!(!config.parallel_available());
}

#[test]
fn test_advanced_simd_available() {
    let mut config = FeatureConfig::default();

    // Test when enabled
    config.enable_advanced_simd = true;
    config.optimization_level = OptimizationLevel::Advanced;

    // Check if it's consistent with the configuration
    assert_eq!(
        config.advanced_simd_available(),
        cfg!(feature = "simd") && config.optimization_level != OptimizationLevel::Reference
    );

    // Test when disabled by optimization level
    config.optimization_level = OptimizationLevel::Reference;
    assert!(!config.advanced_simd_available());

    // Test when explicitly disabled
    config.enable_advanced_simd = false;
    config.optimization_level = OptimizationLevel::Advanced;
    assert!(!config.advanced_simd_available());
}

#[test]
fn test_platform_optimizations_available() {
    let mut config = FeatureConfig::default();

    // Test when enabled
    config.enable_platform_optimizations = true;
    config.optimization_level = OptimizationLevel::Advanced;
    assert!(config.platform_optimizations_available());

    // Test when disabled by optimization level
    config.optimization_level = OptimizationLevel::Reference;
    assert!(!config.platform_optimizations_available());

    // Test when explicitly disabled
    config.enable_platform_optimizations = false;
    config.optimization_level = OptimizationLevel::Advanced;
    assert!(!config.platform_optimizations_available());
}

#[test]
fn test_effective_optimization_level() {
    let mut config = FeatureConfig::default();

    // Test normal case
    config.optimization_level = OptimizationLevel::Advanced;
    config.enable_platform_optimizations = true;
    config.enable_advanced_simd = true;
    assert_eq!(
        config.effective_optimization_level(),
        OptimizationLevel::Advanced
    );

    // Test when platform optimizations are disabled
    config.enable_platform_optimizations = false;
    assert_eq!(
        config.effective_optimization_level(),
        OptimizationLevel::Reference
    );

    // Test when advanced SIMD is disabled but max optimization is selected
    config.enable_platform_optimizations = true;
    config.enable_advanced_simd = false;
    config.optimization_level = OptimizationLevel::Maximum;
    assert_eq!(
        config.effective_optimization_level(),
        OptimizationLevel::Advanced
    );

    // Ensure other cases work as expected
    config.optimization_level = OptimizationLevel::Basic;
    assert_eq!(
        config.effective_optimization_level(),
        OptimizationLevel::Basic
    );
}

#[test]
fn test_description() {
    let mut config = FeatureConfig::default();

    // Test all features enabled
    config.enable_platform_optimizations = true;
    config.enable_parallel = true;
    config.enable_advanced_simd = true;

    // Check description is consistent with availability
    let description = config.description();
    assert!(!description.is_empty());

    // Test with just platform optimizations
    config.enable_parallel = false;
    config.enable_advanced_simd = false;
    assert_eq!(
        config.description(),
        "basic optimization with platform features"
    );

    // Test with no optimizations
    config.enable_platform_optimizations = false;
    assert_eq!(config.description(), "reference implementation");

    // Test with platform and parallel
    config.enable_platform_optimizations = true;
    config.enable_parallel = true;
    config.enable_advanced_simd = false;

    // The exact string may depend on runtime detection
    assert!(config.description().contains("parallel") || config.description().contains("platform"));
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
    set_global_config(original_config);
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
