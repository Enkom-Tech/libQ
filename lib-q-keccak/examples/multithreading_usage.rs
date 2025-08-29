//! Multi-threading usage example for Keccak operations
//!
//! This example demonstrates how to use the multi-threading capabilities
//! for cryptographic operations, following secure development practices.
//!
//! Run with: cargo run --example multithreading_usage --features multithreading

#[cfg(feature = "multithreading")]
use std::time::Instant;

#[cfg(feature = "multithreading")]
use lib_q_keccak::{
    CryptoThreadPool,
    OptimizationLevel,
    ThreadingConfig,
    init_global_thread_pool,
    p1600_multithreaded,
    process_keccak_states_global,
};

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(feature = "multithreading")]
    {
        println!("=== lib-Q Multi-threading Example ===\n");

        // Example 1: Basic multi-threading configuration
        println!("1. Basic Multi-threading Configuration");
        println!("=====================================");

        let config = ThreadingConfig::default();
        println!(
            "Default config: {} threads, min work size: {} bytes",
            config.num_threads, config.min_work_size
        );

        let security_config = ThreadingConfig::security_optimized();
        println!(
            "Security config: {} threads (single-threaded for maximum security)",
            security_config.num_threads
        );

        let performance_config = ThreadingConfig::performance_optimized();
        println!(
            "Performance config: {} threads, min work size: {} bytes",
            performance_config.num_threads, performance_config.min_work_size
        );

        let balanced_config = ThreadingConfig::balanced();
        println!(
            "Balanced config: {} threads, min work size: {} bytes",
            balanced_config.num_threads, balanced_config.min_work_size
        );
        println!();

        // Example 2: Initialize global thread pool
        println!("2. Global Thread Pool Initialization");
        println!("====================================");

        init_global_thread_pool(balanced_config.clone());
        println!("Global thread pool initialized with balanced configuration");
        println!();

        // Example 3: Process small workload (sequential fallback)
        println!("3. Small Workload Processing (Sequential Fallback)");
        println!("==================================================");

        let small_states: Vec<[u64; 25]> = vec![[0u64; 25]; 10]; // Small workload
        let start = Instant::now();

        let results = process_keccak_states_global(&small_states, OptimizationLevel::Reference)?;
        let duration = start.elapsed();

        println!(
            "Processed {} states in {:?} (sequential mode due to small workload)",
            small_states.len(),
            duration
        );
        println!("Results: {} processed states", results.len());
        println!();

        // Example 4: Process large workload (multi-threaded)
        println!("4. Large Workload Processing (Multi-threaded)");
        println!("=============================================");

        let large_states: Vec<[u64; 25]> = vec![[0u64; 25]; 10000]; // Large workload
        let start = Instant::now();

        let results = process_keccak_states_global(&large_states, OptimizationLevel::Maximum)?;
        let duration = start.elapsed();

        println!(
            "Processed {} states in {:?} (multi-threaded mode)",
            large_states.len(),
            duration
        );
        println!("Results: {} processed states", results.len());
        println!();

        // Example 5: Custom thread pool with different configurations
        println!("5. Custom Thread Pool with Different Configurations");
        println!("===================================================");

        // Security-optimized pool
        let security_pool = CryptoThreadPool::new(ThreadingConfig::security_optimized());
        let security_states: Vec<[u64; 25]> = vec![[0u64; 25]; 1000];
        let start = Instant::now();

        let _security_results =
            security_pool.process_keccak_states(&security_states, OptimizationLevel::Reference)?;
        let security_duration = start.elapsed();

        println!(
            "Security pool: {} states in {:?} (single-threaded)",
            security_states.len(),
            security_duration
        );

        // Performance-optimized pool
        let performance_pool = CryptoThreadPool::new(ThreadingConfig::performance_optimized());
        let performance_states: Vec<[u64; 25]> = vec![[0u64; 25]; 1000];
        let start = Instant::now();

        let _performance_results = performance_pool
            .process_keccak_states(&performance_states, OptimizationLevel::Maximum)?;
        let performance_duration = start.elapsed();

        println!(
            "Performance pool: {} states in {:?} (multi-threaded)",
            performance_states.len(),
            performance_duration
        );
        println!();

        // Example 6: Direct multi-threading function usage
        println!("6. Direct Multi-threading Function Usage");
        println!("========================================");

        let direct_states: Vec<[u64; 25]> = vec![[0u64; 25]; 5000];
        let start = Instant::now();

        let direct_results = p1600_multithreaded(&direct_states, OptimizationLevel::Advanced)?;
        let direct_duration = start.elapsed();

        println!(
            "Direct function: {} states in {:?}",
            direct_states.len(),
            direct_duration
        );
        println!("Results: {} processed states", direct_results.len());
        println!();

        // Example 7: Performance comparison
        println!("7. Performance Comparison");
        println!("=========================");

        let test_states: Vec<[u64; 25]> = vec![[0u64; 25]; 5000];

        // Sequential processing
        let start = Instant::now();
        let sequential_pool = CryptoThreadPool::new(ThreadingConfig::security_optimized());
        let _sequential_results =
            sequential_pool.process_keccak_states(&test_states, OptimizationLevel::Reference)?;
        let sequential_duration = start.elapsed();

        // Multi-threaded processing
        let start = Instant::now();
        let _multi_results =
            process_keccak_states_global(&test_states, OptimizationLevel::Maximum)?;
        let multi_duration = start.elapsed();

        println!("Sequential: {:?}", sequential_duration);
        println!("Multi-threaded: {:?}", multi_duration);

        if multi_duration < sequential_duration {
            let speedup = sequential_duration.as_nanos() as f64 / multi_duration.as_nanos() as f64;
            println!("Speedup: {:.2}x", speedup);
        } else {
            println!("Sequential processing was faster (likely due to overhead)");
        }
        println!();

        // Example 8: Error handling and graceful degradation
        println!("8. Error Handling and Graceful Degradation");
        println!("===========================================");

        // Test with invalid configuration (should fall back to sequential)
        let invalid_config = ThreadingConfig {
            num_threads: 0, // Invalid: no threads
            min_work_size: 100,
            max_work_per_thread: 1000,
            timeout: std::time::Duration::from_secs(5),
            enable_affinity: false,
            affinity_strategy: lib_q_keccak::AffinityStrategy::Disabled,
        };

        let fallback_pool = CryptoThreadPool::new(invalid_config);
        let fallback_states: Vec<[u64; 25]> = vec![[0u64; 25]; 100];
        let start = Instant::now();

        match fallback_pool.process_keccak_states(&fallback_states, OptimizationLevel::Reference) {
            Ok(results) => {
                let duration = start.elapsed();
                println!(
                    "Fallback successful: {} states in {:?} (sequential fallback)",
                    fallback_states.len(),
                    duration
                );
                println!("Results: {} processed states", results.len());
            }
            Err(e) => {
                println!("Fallback failed: {}", e);
            }
        }
        println!();

        println!("=== Multi-threading Example Complete ===");
        println!("All operations completed successfully!");
    }

    #[cfg(not(feature = "multithreading"))]
    {
        println!("Multi-threading feature not enabled.");
        println!("Enable with: cargo run --example multithreading_usage --features multithreading");
        println!();
        println!("This example demonstrates:");
        println!("- Thread-safe cryptographic operations");
        println!("- Configurable thread pools for different use cases");
        println!("- Performance vs. security trade-offs");
        println!("- Graceful fallback to sequential processing");
        println!("- Error handling and timeout management");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multithreading_example() {
        // Test that the example runs without errors
        assert!(main().is_ok());
    }

    #[cfg(feature = "multithreading")]
    #[test]
    fn test_threading_configurations() {
        let default_config = ThreadingConfig::default();
        assert!(default_config.num_threads > 0);

        let security_config = ThreadingConfig::security_optimized();
        assert_eq!(security_config.num_threads, 1);

        let performance_config = ThreadingConfig::performance_optimized();
        assert!(performance_config.num_threads > 0);
    }

    #[cfg(feature = "multithreading")]
    #[test]
    fn test_thread_pool_creation() {
        let config = ThreadingConfig::balanced();
        let pool = CryptoThreadPool::new(config);

        let states: Vec<[u64; 25]> = vec![[0u64; 25]; 10];
        let results = pool.process_keccak_states(&states, OptimizationLevel::Reference);
        assert!(results.is_ok());
    }
}
