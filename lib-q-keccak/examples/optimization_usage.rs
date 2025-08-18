//! Example: High-Impact Optimization Usage with Feature-Based Nightly Rust
//!
//! This example demonstrates how to use the high-impact optimizations
//! available in the keccak crate, including x86 SIMD optimizations,
//! parallel processing, and advanced optimizations.

use lib_q_keccak::{
    detection, fast_loop_absorb_optimized, get_global_config, p1600_optimized, set_global_config,
    FeatureConfig, OptimizationLevel,
};

#[cfg(feature = "simd")]
use lib_q_keccak::parallel;

fn main() {
    println!("=== Keccak High-Impact Optimization Example ===\n");

    // 1. Feature Detection
    println!("1. Hardware Feature Detection:");
    let report = detection::detect_available_features();
    println!("   {}", report.summary());
    println!(
        "   Recommended optimization level: {:?}",
        report.recommended_optimization_level()
    );
    println!();

    // 2. Basic Usage with Automatic Optimization
    println!("2. Basic Usage with Automatic Optimization:");
    let mut state = [0u64; 25];
    state[0] = 0x1234567890abcdef;

    // Use the best available optimization automatically
    let best_level = OptimizationLevel::best_available();
    println!("   Using optimization level: {:?}", best_level);

    p1600_optimized(&mut state, best_level);
    println!("   State[0] after permutation: 0x{:016x}", state[0]);
    println!();

    // 3. Feature Configuration Examples
    println!("3. Feature Configuration Examples:");

    // Security-optimized configuration
    let security_config = FeatureConfig::security_optimized();
    println!("   Security-optimized: {}", security_config.description());

    // Performance-optimized configuration
    let performance_config = FeatureConfig::performance_optimized();
    println!(
        "   Performance-optimized: {}",
        performance_config.description()
    );

    // Compatibility-optimized configuration
    let compatibility_config = FeatureConfig::compatibility_optimized();
    println!(
        "   Compatibility-optimized: {}",
        compatibility_config.description()
    );
    println!();

    // 4. Global Configuration
    println!("4. Global Configuration:");
    set_global_config(FeatureConfig::performance_optimized());
    let current_config = get_global_config();
    println!("   Current global config: {}", current_config.description());
    println!();

    // 5. Fast Loop Absorption
    println!("5. Fast Loop Absorption:");
    let initial_state = [0u64; 25];
    let data = b"This is a test message for fast loop absorption. It should be processed efficiently using optimized implementations.";

    for level in [
        OptimizationLevel::Reference,
        OptimizationLevel::Basic,
        OptimizationLevel::Advanced,
        OptimizationLevel::Maximum,
    ] {
        if level.is_available() {
            let mut test_state = initial_state;
            let offset = fast_loop_absorb_optimized(&mut test_state, data, level);
            println!(
                "   {:?}: processed {} bytes, state[0] = 0x{:016x}",
                level, offset, test_state[0]
            );
        } else {
            println!("   {:?}: not available on this platform", level);
        }
    }
    println!();

    // 6. Parallel Processing (if available)
    #[cfg(feature = "simd")]
    {
        println!("6. Parallel Processing:");
        let mut states = vec![[0u64; 25]; 8];

        // Initialize states with different values
        for (i, state) in states.iter_mut().enumerate() {
            state[0] = 0x1234567890abcdef + i as u64;
        }

        // Process in parallel
        parallel::p1600_parallel(&mut states, OptimizationLevel::Advanced);

        println!("   Processed {} states in parallel", states.len());
        for (i, state) in states.iter().enumerate() {
            println!("   State[{}][0] = 0x{:016x}", i, state[0]);
        }
        println!();
    }

    // 7. Performance Comparison
    println!("7. Performance Comparison:");
    let test_data = vec![0x42u8; 1024 * 1024]; // 1MB of data
    let mut state = [0u64; 25];

    for level in [
        OptimizationLevel::Reference,
        OptimizationLevel::Basic,
        OptimizationLevel::Advanced,
        OptimizationLevel::Maximum,
    ] {
        if level.is_available() {
            let start = std::time::Instant::now();
            let offset = fast_loop_absorb_optimized(&mut state, &test_data, level);
            let duration = start.elapsed();

            println!(
                "   {:?}: processed {} bytes in {:?} ({:.2} MB/s)",
                level,
                offset,
                duration,
                (offset as f64 / 1024.0 / 1024.0) / duration.as_secs_f64()
            );
        }
    }
    println!();

    // 8. Nightly Features Usage
    println!("8. Nightly Features Usage:");

    #[cfg(feature = "simd")]
    {
        println!("   SIMD features enabled: ✓");
        println!("   Portable SIMD available: ✓");
    }

    #[cfg(not(feature = "simd"))]
    {
        println!("   SIMD features disabled: use --features simd to enable");
    }

    #[cfg(feature = "nightly")]
    {
        println!("   Nightly features enabled: ✓");
        println!("   Advanced optimizations available: ✓");
    }

    #[cfg(not(feature = "nightly"))]
    {
        println!("   Nightly features disabled: use --features nightly to enable");
    }
    println!();

    // 9. Configuration Recommendations
    println!("9. Configuration Recommendations:");
    let report = detection::detect_available_features();

    if report.avx512f {
        println!("   ✓ AVX-512 detected: Use OptimizationLevel::Maximum for best performance");
    } else if report.avx2 {
        println!("   ✓ AVX2 detected: Use OptimizationLevel::Advanced for good performance");
    } else if report.sha3_intrinsics {
        println!(
            "   ✓ SHA3 intrinsics detected: Use OptimizationLevel::Basic for ARM optimization"
        );
    } else {
        println!("   ⚠ No special hardware detected: Using reference implementation");
    }

    if report.simd_support {
        println!("   ✓ SIMD support available: Enable parallel processing for batch operations");
    }

    if report.nightly_features {
        println!("   ✓ Nightly features available: Enable advanced optimizations");
    }
    println!();

    println!("=== Example Complete ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_detection() {
        let report = detection::detect_available_features();
        assert!(report.summary().len() > 0);
    }

    #[test]
    fn test_optimization_levels() {
        let mut state = [0u64; 25];
        state[0] = 0x1234567890abcdef;

        for level in [
            OptimizationLevel::Reference,
            OptimizationLevel::Basic,
            OptimizationLevel::Advanced,
            OptimizationLevel::Maximum,
        ] {
            if level.is_available() {
                let mut test_state = state;
                p1600_optimized(&mut test_state, level);
                assert_ne!(test_state[0], state[0]); // State should change
            }
        }
    }

    #[test]
    fn test_fast_loop_absorption() {
        let mut state = [0u64; 25];
        let data = b"Test data for absorption";

        let offset = fast_loop_absorb_optimized(&mut state, data, OptimizationLevel::Reference);
        assert!(offset > 0);
        assert_ne!(state[0], 0);
    }

    #[test]
    #[cfg(feature = "simd")]
    fn test_parallel_processing() {
        let mut states = vec![[0u64; 25]; 4];

        // Initialize states
        for (i, state) in states.iter_mut().enumerate() {
            state[0] = 0x1234567890abcdef + i as u64;
        }

        // Process in parallel
        parallel::p1600_parallel(&mut states, OptimizationLevel::Basic);

        // Verify all states changed
        for (i, state) in states.iter().enumerate() {
            assert_ne!(state[0], 0x1234567890abcdef + i as u64);
        }
    }
}
