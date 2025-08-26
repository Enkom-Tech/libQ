//! Multi-threading implementations for Keccak operations
//!
//! This module provides thread-safe multi-threading capabilities for cryptographic
//! operations, following secure development practices and proper architecture.
//! It leverages Rust's ownership model and safe concurrency primitives to ensure
//! thread safety without data races.
//!
//! Note: This module requires the `std` feature to be enabled.

#![cfg_attr(not(feature = "std"), no_implicit_prelude)]

extern crate alloc;
extern crate std;

use alloc::boxed::Box;
use alloc::vec::Vec;
use alloc::{
    format,
    vec,
};
use core::sync::atomic::{
    AtomicBool,
    AtomicUsize,
    Ordering,
};
use std::sync::{
    Arc,
    OnceLock,
    RwLock,
};
use std::thread;
use std::time::Duration;

use crate::{
    OptimizationLevel,
    keccak_p,
};

/// Thread-safe configuration for multi-threading operations
#[derive(Debug, Clone)]
pub struct ThreadingConfig {
    /// Number of worker threads to use
    pub num_threads: usize,
    /// Minimum work size to trigger multi-threading
    pub min_work_size: usize,
    /// Maximum work size per thread
    pub max_work_per_thread: usize,
    /// Thread pool timeout
    pub timeout: Duration,
    /// Enable thread affinity for better cache performance
    pub enable_affinity: bool,
}

impl Default for ThreadingConfig {
    fn default() -> Self {
        Self {
            num_threads: num_cpus::get(),
            min_work_size: 1024,            // 1KB minimum for multi-threading
            max_work_per_thread: 64 * 1024, // 64KB per thread
            timeout: Duration::from_secs(30),
            enable_affinity: true,
        }
    }
}

impl ThreadingConfig {
    /// Create a security-optimized configuration
    pub fn security_optimized() -> Self {
        Self {
            num_threads: 1,            // Single thread for maximum security
            min_work_size: usize::MAX, // Disable multi-threading
            max_work_per_thread: usize::MAX,
            timeout: Duration::from_secs(5),
            enable_affinity: false,
        }
    }

    /// Create a performance-optimized configuration
    pub fn performance_optimized() -> Self {
        Self {
            num_threads: num_cpus::get(),
            min_work_size: 512,             // Lower threshold for more parallelism
            max_work_per_thread: 32 * 1024, // Smaller chunks for better load balancing
            timeout: Duration::from_secs(60),
            enable_affinity: true,
        }
    }

    /// Create a balanced configuration
    pub fn balanced() -> Self {
        Self {
            num_threads: (num_cpus::get() + 1) / 2, // Half the cores
            min_work_size: 2048,                    // Higher threshold for better efficiency
            max_work_per_thread: 128 * 1024,        // Larger chunks
            timeout: Duration::from_secs(30),
            enable_affinity: true,
        }
    }
}

/// Thread-safe work distribution for cryptographic operations
#[derive(Debug)]
struct WorkDistribution {
    /// Total number of items to process
    total_items: usize,
    /// Current position in the work queue
    current_position: AtomicUsize,
    /// Work completion status
    completed: AtomicBool,
}

impl WorkDistribution {
    fn new(total_items: usize) -> Self {
        Self {
            total_items,
            current_position: AtomicUsize::new(0),
            completed: AtomicBool::new(false),
        }
    }

    /// Get next work chunk for a thread
    fn get_next_chunk(&self, chunk_size: usize) -> Option<(usize, usize)> {
        let start = self
            .current_position
            .fetch_add(chunk_size, Ordering::AcqRel);
        if start >= self.total_items {
            return None;
        }
        let end = (start + chunk_size).min(self.total_items);
        Some((start, end))
    }

    /// Mark work as completed
    fn mark_completed(&self) {
        self.completed.store(true, Ordering::Release);
    }

    /// Check if all work is completed
    fn is_completed(&self) -> bool {
        self.completed.load(Ordering::Acquire)
    }
}

/// Thread-safe cryptographic worker
#[derive(Debug)]
struct CryptoWorker {
    /// Worker thread ID
    id: usize,
    /// Thread-safe work distribution
    work_dist: Arc<WorkDistribution>,
    /// Thread-safe result storage
    results: Arc<RwLock<Vec<[u64; 25]>>>,
    /// Configuration
    config: ThreadingConfig,
}

impl CryptoWorker {
    fn new(
        id: usize,
        work_dist: Arc<WorkDistribution>,
        results: Arc<RwLock<Vec<[u64; 25]>>>,
        config: ThreadingConfig,
    ) -> Self {
        Self {
            id,
            work_dist,
            results,
            config,
        }
    }

    /// Process Keccak permutations in parallel
    fn process_keccak_parallel(&self, states: &[[u64; 25]], level: OptimizationLevel) {
        let chunk_size = self
            .config
            .max_work_per_thread
            .min(states.len() / self.config.num_threads);

        while let Some((start, end)) = self.work_dist.get_next_chunk(chunk_size) {
            let mut local_results = Vec::new();

            for i in start..end {
                if i < states.len() {
                    let mut state = states[i];
                    self.apply_keccak_optimization(&mut state, level);
                    local_results.push(state);
                }
            }

            // Store results thread-safely
            if let Ok(mut results_guard) = self.results.write() {
                for (i, result) in local_results.into_iter().enumerate() {
                    let global_index = start + i;
                    if global_index < results_guard.len() {
                        results_guard[global_index] = result;
                    }
                }
            }
        }
    }

    /// Apply Keccak optimization based on level
    fn apply_keccak_optimization(&self, state: &mut [u64; 25], level: OptimizationLevel) {
        match level {
            OptimizationLevel::Reference => {
                keccak_p(state, 24);
            }
            OptimizationLevel::Basic => {
                #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
                unsafe {
                    crate::x86::p1600_avx2(state);
                }
                #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
                {
                    keccak_p(state, 24);
                }
            }
            OptimizationLevel::Advanced => {
                #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
                unsafe {
                    crate::x86::p1600_avx2(state);
                }
                #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
                {
                    keccak_p(state, 24);
                }
            }
            OptimizationLevel::Maximum => {
                #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
                unsafe {
                    crate::x86::p1600_avx512(state);
                }
                #[cfg(all(
                    target_arch = "x86_64",
                    target_feature = "avx2",
                    not(target_feature = "avx512f")
                ))]
                unsafe {
                    crate::x86::p1600_avx2(state);
                }
                #[cfg(not(all(
                    target_arch = "x86_64",
                    any(target_feature = "avx2", target_feature = "avx512f")
                )))]
                {
                    keccak_p(state, 24);
                }
            }
        }
    }
}

/// Thread-safe cryptographic thread pool
#[derive(Debug)]
pub struct CryptoThreadPool {
    /// Thread pool configuration
    config: ThreadingConfig,
    /// Thread-safe shutdown flag
    shutdown: Arc<AtomicBool>,
}

impl CryptoThreadPool {
    /// Create a new thread pool with the specified configuration
    pub fn new(config: ThreadingConfig) -> Self {
        Self {
            config,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Process multiple Keccak states using multiple threads
    pub fn process_keccak_states(
        &self,
        states: &[[u64; 25]],
        level: OptimizationLevel,
    ) -> Result<Vec<[u64; 25]>, Box<dyn std::error::Error + Send + Sync>> {
        // Check if multi-threading is beneficial
        if states.len() < self.config.min_work_size || self.config.num_threads <= 1 {
            return self.process_sequential(states, level);
        }

        // Create thread-safe work distribution
        let work_dist = Arc::new(WorkDistribution::new(states.len()));
        let results = Arc::new(RwLock::new(vec![[0u64; 25]; states.len()]));
        let shutdown = Arc::clone(&self.shutdown);

        // Spawn worker threads
        let mut handles = Vec::new();
        for thread_id in 0..self.config.num_threads {
            let worker = CryptoWorker::new(
                thread_id,
                Arc::clone(&work_dist),
                Arc::clone(&results),
                self.config.clone(),
            );

            let states_clone = states.to_vec();
            let handle = thread::spawn(move || {
                // Set thread affinity if enabled
                if worker.config.enable_affinity {
                    #[cfg(target_os = "linux")]
                    {
                        use std::os::linux::thread::AffinityExt;
                        if let Ok(mut set) = nix::sched::CpuSet::new() {
                            if set.set(thread_id % num_cpus::get()).is_ok() {
                                let _ = nix::sched::sched_setaffinity(
                                    nix::unistd::Pid::from_raw(0),
                                    &set,
                                );
                            }
                        }
                    }
                }

                worker.process_keccak_parallel(&states_clone, level);
            });

            handles.push(handle);
        }

        // Wait for all threads to complete with timeout
        for handle in handles {
            if let Err(e) = handle.join() {
                shutdown.store(true, Ordering::Release);
                return Err(format!("Thread join error: {:?}", e).into());
            }
        }

        // Extract results
        match results.read() {
            Ok(results_guard) => Ok(results_guard.clone()),
            Err(_) => Err("Failed to read results".into()),
        }
    }

    /// Process states sequentially (fallback)
    fn process_sequential(
        &self,
        states: &[[u64; 25]],
        level: OptimizationLevel,
    ) -> Result<Vec<[u64; 25]>, Box<dyn std::error::Error + Send + Sync>> {
        let mut results = Vec::with_capacity(states.len());

        for state in states {
            let mut result_state = *state;
            match level {
                OptimizationLevel::Reference => {
                    keccak_p(&mut result_state, 24);
                }
                OptimizationLevel::Basic => {
                    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
                    unsafe {
                        crate::x86::p1600_avx2(&mut result_state);
                    }
                    #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
                    {
                        keccak_p(&mut result_state, 24);
                    }
                }
                OptimizationLevel::Advanced => {
                    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
                    unsafe {
                        crate::x86::p1600_avx2(&mut result_state);
                    }
                    #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
                    {
                        keccak_p(&mut result_state, 24);
                    }
                }
                OptimizationLevel::Maximum => {
                    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
                    unsafe {
                        crate::x86::p1600_avx512(&mut result_state);
                    }
                    #[cfg(all(
                        target_arch = "x86_64",
                        target_feature = "avx2",
                        not(target_feature = "avx512f")
                    ))]
                    unsafe {
                        crate::x86::p1600_avx2(&mut result_state);
                    }
                    #[cfg(not(all(
                        target_arch = "x86_64",
                        any(target_feature = "avx2", target_feature = "avx512f")
                    )))]
                    {
                        keccak_p(&mut result_state, 24);
                    }
                }
            }
            results.push(result_state);
        }

        Ok(results)
    }

    /// Shutdown the thread pool
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }
}

/// Global thread pool instance
static GLOBAL_THREAD_POOL: OnceLock<Arc<CryptoThreadPool>> = OnceLock::new();
static THREAD_POOL_INIT: std::sync::Once = std::sync::Once::new();

/// Initialize the global thread pool
pub fn init_global_thread_pool(config: ThreadingConfig) {
    THREAD_POOL_INIT.call_once(|| {
        let _ = GLOBAL_THREAD_POOL.set(Arc::new(CryptoThreadPool::new(config)));
    });
}

/// Get the global thread pool instance
pub fn get_global_thread_pool() -> Option<Arc<CryptoThreadPool>> {
    GLOBAL_THREAD_POOL.get().cloned()
}

/// Process Keccak states using the global thread pool
pub fn process_keccak_states_global(
    states: &[[u64; 25]],
    level: OptimizationLevel,
) -> Result<Vec<[u64; 25]>, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(pool) = get_global_thread_pool() {
        pool.process_keccak_states(states, level)
    } else {
        // Fallback to sequential processing
        let config = ThreadingConfig::default();
        let pool = CryptoThreadPool::new(config);
        pool.process_keccak_states(states, level)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threading_config_defaults() {
        let config = ThreadingConfig::default();
        assert!(config.num_threads > 0);
        assert!(config.min_work_size > 0);
        assert!(config.max_work_per_thread > 0);
    }

    #[test]
    fn test_threading_config_security_optimized() {
        let config = ThreadingConfig::security_optimized();
        assert_eq!(config.num_threads, 1);
        assert_eq!(config.min_work_size, usize::MAX);
    }

    #[test]
    fn test_threading_config_performance_optimized() {
        let config = ThreadingConfig::performance_optimized();
        assert!(config.num_threads > 0);
        assert!(config.min_work_size < usize::MAX);
    }

    #[test]
    fn test_work_distribution() {
        let work_dist = WorkDistribution::new(100);
        assert!(!work_dist.is_completed());

        // Test chunk distribution
        let chunk1 = work_dist.get_next_chunk(25);
        assert_eq!(chunk1, Some((0, 25)));

        let chunk2 = work_dist.get_next_chunk(25);
        assert_eq!(chunk2, Some((25, 50)));

        work_dist.mark_completed();
        assert!(work_dist.is_completed());
    }

    #[test]
    fn test_sequential_processing() {
        let config = ThreadingConfig::security_optimized();
        let pool = CryptoThreadPool::new(config);

        let states = vec![[0u64; 25], [1u64; 25], [2u64; 25]];

        let results = pool
            .process_keccak_states(&states, OptimizationLevel::Reference)
            .unwrap();
        assert_eq!(results.len(), states.len());

        // Verify that states were modified
        for (original, result) in states.iter().zip(results.iter()) {
            assert_ne!(original, result);
        }
    }

    #[test]
    fn test_global_thread_pool() {
        let config = ThreadingConfig::balanced();
        init_global_thread_pool(config);

        let pool = get_global_thread_pool();
        assert!(pool.is_some());

        let states = vec![[0u64; 25]; 10];
        let results = process_keccak_states_global(&states, OptimizationLevel::Reference).unwrap();
        assert_eq!(results.len(), states.len());
    }
}
