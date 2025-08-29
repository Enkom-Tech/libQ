//! Multi-threading implementations for Keccak operations
//!
//! This module provides thread-safe multi-threading capabilities for cryptographic
//! operations, following secure development practices and proper architecture.
//! It leverages Rust's ownership model and safe concurrency primitives to ensure
//! thread safety without data races.
//!
//! Note: This module requires the `std` feature to be enabled.

#![cfg_attr(not(feature = "std"), no_implicit_prelude)]

// Core is always available
extern crate core;

// Std and alloc are required for multithreading
#[cfg(feature = "std")]
extern crate std;

#[cfg(any(feature = "std", feature = "alloc"))]
extern crate alloc;

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

/// Cross-platform thread affinity implementation
/// Sets thread affinity to a specific CPU core for optimal cache performance
#[cfg(feature = "thread-affinity")]
fn set_thread_affinity(thread_id: usize, strategy: AffinityStrategy) {
    use std::sync::OnceLock;

    // Early return if affinity is disabled
    if matches!(strategy, AffinityStrategy::Disabled) {
        return;
    }

    // Cache the number of available CPUs to avoid repeated system calls
    static CPU_COUNT: OnceLock<usize> = OnceLock::new();

    let cpu_count = CPU_COUNT.get_or_init(|| {
        core_affinity::get_core_ids()
            .map(|ids| ids.len())
            .unwrap_or_else(num_cpus::get)
    });

    if *cpu_count == 0 {
        return; // No CPUs available, skip affinity setting
    }

    // Calculate target CPU based on strategy
    let target_cpu = match strategy {
        AffinityStrategy::Disabled => return,
        AffinityStrategy::Spread => {
            // Distribute threads across all available cores
            thread_id % *cpu_count
        }
        AffinityStrategy::Compact => {
            // Group threads on fewer cores for better cache sharing
            let active_cores = cpu_count.div_ceil(2); // Use roughly half the cores
            thread_id % active_cores
        }
        AffinityStrategy::Custom => {
            // For now, fall back to spread strategy
            thread_id % *cpu_count
        }
    };

    // Get the core ID for the target CPU
    if let Some(core_ids) = core_affinity::get_core_ids() &&
        let Some(core_id) = core_ids.get(target_cpu)
    {
        // Attempt to set thread affinity - ignore errors gracefully
        // This is a performance optimization, so we don't fail on errors
        let _ = core_affinity::set_for_current(*core_id);
    }
}

/// Fallback implementation for systems without thread affinity support
#[cfg(not(feature = "thread-affinity"))]
fn set_thread_affinity(_thread_id: usize, _strategy: AffinityStrategy) {
    // No-op implementation for systems without thread affinity support
}

/// Thread affinity strategy for optimizing cache performance
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AffinityStrategy {
    /// Disable thread affinity completely
    Disabled,
    /// Spread threads across all available CPU cores
    Spread,
    /// Group threads on fewer cores for better cache sharing
    Compact,
    /// Custom affinity pattern (future extension)
    Custom,
}

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
    /// Thread affinity strategy
    pub affinity_strategy: AffinityStrategy,
}

impl Default for ThreadingConfig {
    fn default() -> Self {
        Self {
            num_threads: num_cpus::get(),
            min_work_size: 1024,            // 1KB minimum for multi-threading
            max_work_per_thread: 64 * 1024, // 64KB per thread
            timeout: Duration::from_secs(30),
            enable_affinity: true,
            affinity_strategy: AffinityStrategy::Spread,
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
            affinity_strategy: AffinityStrategy::Disabled,
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
            affinity_strategy: AffinityStrategy::Spread,
        }
    }

    /// Create a balanced configuration
    pub fn balanced() -> Self {
        Self {
            num_threads: num_cpus::get().div_ceil(2), // Half the cores
            min_work_size: 2048,                      // Higher threshold for better efficiency
            max_work_per_thread: 128 * 1024,          // Larger chunks
            timeout: Duration::from_secs(30),
            enable_affinity: true,
            affinity_strategy: AffinityStrategy::Compact,
        }
    }
}

/// Worker statistics for monitoring and debugging
#[derive(Debug, Clone)]
pub struct WorkerStats {
    /// Unique worker thread identifier
    pub worker_id: usize,
    /// Number of work items processed by this worker
    pub work_items_processed: usize,
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
    /// Number of items completed
    completed_count: AtomicUsize,
}

impl WorkDistribution {
    fn new(total_items: usize) -> Self {
        Self {
            total_items,
            current_position: AtomicUsize::new(0),
            completed: AtomicBool::new(false),
            completed_count: AtomicUsize::new(0),
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

    /// Increment the completed work count
    fn increment_completed(&self, count: usize) {
        self.completed_count.fetch_add(count, Ordering::AcqRel);
    }

    /// Check if all work has been completed
    fn is_all_work_completed(&self) -> bool {
        self.completed_count.load(Ordering::Acquire) >= self.total_items
    }

    /// Check if all work is completed (primarily for testing/monitoring)
    #[allow(dead_code)] // Used in tests and available for monitoring
    fn is_completed(&self) -> bool {
        self.completed.load(Ordering::Acquire)
    }
}

/// Thread-safe cryptographic worker
#[derive(Debug)]
struct CryptoWorker {
    /// Worker thread ID
    #[allow(dead_code)] // Used in tests and available for monitoring
    id: usize,
    /// Thread-safe work distribution
    work_dist: Arc<WorkDistribution>,
    /// Thread-safe result storage
    results: Arc<RwLock<Vec<[u64; 25]>>>,
    /// Configuration
    config: ThreadingConfig,
}

impl CryptoWorker {
    /// Get worker statistics for monitoring and debugging
    #[allow(dead_code)] // Used in tests and available for production monitoring
    pub fn get_stats(&self) -> WorkerStats {
        WorkerStats {
            worker_id: self.id,
            work_items_processed: self.work_dist.completed_count.load(Ordering::Acquire),
        }
    }

    /// Get worker identifier for thread management and monitoring
    #[allow(dead_code)] // Used in tests and available for production monitoring
    pub fn get_worker_id(&self) -> usize {
        self.id
    }

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

            // Worker ID available via get_worker_id() for monitoring

            for i in start..end {
                if i < states.len() {
                    let mut state = states[i];
                    self.apply_keccak_optimization(&mut state, level);
                    local_results.push(state);
                }
            }

            // Store results thread-safely with bounds checking
            if let Ok(mut results_guard) = self.results.write() {
                let results_len = results_guard.len();
                let mut valid_results = 0;

                for (i, result) in local_results.iter().enumerate() {
                    let global_index = start + i;
                    if global_index < results_len && global_index < states.len() {
                        results_guard[global_index] = *result;
                        valid_results += 1;
                    }
                }

                // Increment completed count only for valid results
                if valid_results > 0 {
                    self.work_dist.increment_completed(valid_results);
                }
            }
        }

        // Worker completion statistics available via get_stats()
        // Use worker.get_stats() for monitoring in production code
    }

    /// Apply Keccak optimization based on level
    fn apply_keccak_optimization(&self, state: &mut [u64; 25], level: OptimizationLevel) {
        match level {
            OptimizationLevel::Reference => {
                keccak_p(state, 24);
            }
            OptimizationLevel::Basic => {
                #[cfg(all(target_arch = "x86_64", feature = "asm", target_feature = "avx2"))]
                unsafe {
                    crate::x86::p1600_avx2(state);
                }
                #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
                {
                    keccak_p(state, 24);
                }
            }
            OptimizationLevel::Advanced => {
                #[cfg(all(target_arch = "x86_64", feature = "asm", target_feature = "avx2"))]
                unsafe {
                    crate::x86::p1600_avx2(state);
                }
                #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
                {
                    keccak_p(state, 24);
                }
            }
            OptimizationLevel::Maximum => {
                #[cfg(all(target_arch = "x86_64", feature = "asm", target_feature = "avx512f"))]
                unsafe {
                    crate::x86::p1600_avx512(state);
                }
                #[cfg(all(
                    target_arch = "x86_64",
                    feature = "asm",
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
                // Set thread affinity for optimal cache performance
                if worker.config.enable_affinity {
                    set_thread_affinity(thread_id, worker.config.affinity_strategy);
                }

                worker.process_keccak_parallel(&states_clone, level);
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            if let Err(e) = handle.join() {
                shutdown.store(true, Ordering::Release);
                return Err(format!("Thread join error: {:?}", e).into());
            }
        }

        // Mark work as completed
        work_dist.mark_completed();

        // Robust completion verification with timeout protection
        let max_retries = 100; // Prevent infinite waiting
        let mut retries = 0;

        while !work_dist.is_all_work_completed() && retries < max_retries {
            // Brief yield to allow threads to complete
            thread::yield_now();
            retries += 1;

            // Check for completion every few iterations to reduce overhead
            if retries % 10 == 0 {
                let completed = work_dist.completed_count.load(Ordering::Acquire);
                if completed >= work_dist.total_items {
                    break;
                }
            }
        }

        // Final verification
        if !work_dist.is_all_work_completed() {
            let completed = work_dist.completed_count.load(Ordering::Acquire);
            return Err(format!(
                "Incomplete processing after timeout: {} of {} items completed",
                completed, work_dist.total_items
            )
            .into());
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
                    #[cfg(all(target_arch = "x86_64", feature = "asm", target_feature = "avx2"))]
                    unsafe {
                        crate::x86::p1600_avx2(&mut result_state);
                    }
                    #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
                    {
                        keccak_p(&mut result_state, 24);
                    }
                }
                OptimizationLevel::Advanced => {
                    #[cfg(all(target_arch = "x86_64", feature = "asm", target_feature = "avx2"))]
                    unsafe {
                        crate::x86::p1600_avx2(&mut result_state);
                    }
                    #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
                    {
                        keccak_p(&mut result_state, 24);
                    }
                }
                OptimizationLevel::Maximum => {
                    #[cfg(all(
                        target_arch = "x86_64",
                        feature = "asm",
                        target_feature = "avx512f"
                    ))]
                    unsafe {
                        crate::x86::p1600_avx512(&mut result_state);
                    }
                    #[cfg(all(
                        target_arch = "x86_64",
                        feature = "asm",
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
        assert_eq!(config.affinity_strategy, AffinityStrategy::Spread);
        assert!(config.enable_affinity);
    }

    #[test]
    fn test_threading_config_security_optimized() {
        let config = ThreadingConfig::security_optimized();
        assert_eq!(config.num_threads, 1);
        assert_eq!(config.min_work_size, usize::MAX);
        assert_eq!(config.affinity_strategy, AffinityStrategy::Disabled);
        assert!(!config.enable_affinity);
    }

    #[test]
    fn test_threading_config_performance_optimized() {
        let config = ThreadingConfig::performance_optimized();
        assert!(config.num_threads > 0);
        assert!(config.min_work_size < usize::MAX);
        assert_eq!(config.affinity_strategy, AffinityStrategy::Spread);
        assert!(config.enable_affinity);
    }

    #[test]
    fn test_threading_config_balanced() {
        let config = ThreadingConfig::balanced();
        assert!(config.num_threads > 0);
        assert!(config.min_work_size > 0);
        assert_eq!(config.affinity_strategy, AffinityStrategy::Compact);
        assert!(config.enable_affinity);
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
    fn test_worker_id_and_stats() {
        let work_dist = Arc::new(WorkDistribution::new(10));
        let results = Arc::new(RwLock::new(vec![[0u64; 25]; 10]));
        let config = ThreadingConfig::default();

        // Create worker with specific ID
        let worker = CryptoWorker::new(42, Arc::clone(&work_dist), Arc::clone(&results), config);

        // Test worker ID retrieval
        assert_eq!(worker.get_worker_id(), 42);

        // Test initial stats
        let stats = worker.get_stats();
        assert_eq!(stats.worker_id, 42);
        assert_eq!(stats.work_items_processed, 0);

        // Worker ID and stats are properly accessible for monitoring
    }

    #[test]
    fn test_sequential_processing() {
        let config = ThreadingConfig::security_optimized();
        let pool = CryptoThreadPool::new(config);

        let states = vec![[0u64; 25], [1u64; 25], [2u64; 25]];

        let results = pool
            .process_keccak_states(&states, OptimizationLevel::Reference)
            .expect("Failed to process Keccak states in thread pool");
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
        let results = process_keccak_states_global(&states, OptimizationLevel::Reference)
            .expect("Failed to process Keccak states with global thread pool");
        assert_eq!(results.len(), states.len());
    }
}
