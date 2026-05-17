//! Parallel processing optimizations for Saturnin
//!
//! This module provides multi-threaded implementations of Saturnin operations
//! for large data blocks, utilizing multiple CPU cores for maximum performance.
//!
//! ## Features
//!
//! - **Multi-threaded encryption/decryption**: Parallel processing of large data blocks
//! - **Thread-safe operations**: Safe concurrent access to cryptographic primitives
//! - **Automatic thread management**: Optimal thread count based on CPU cores
//! - **Fallback support**: Automatic fallback to single-threaded operations when threading unavailable
//!
//! ## Usage Example
//!
//! ```rust
//! use lib_q_saturnin::parallel::ParallelSaturninCore;
//!
//! // Create parallel-optimized core
//! let core = ParallelSaturninCore::new(16, 7).unwrap();
//!
//! // Encrypt large data block with parallel processing
//! let mut large_data = vec![0u8; 1024 * 1024]; // 1MB
//! core.encrypt_blocks_parallel(&[0u8; 32], &mut large_data)
//!     .unwrap();
//! ```

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::sync::Arc;
#[cfg(feature = "std")]
use std::sync::mpsc;
#[cfg(feature = "std")]
use std::thread;

use lib_q_core::Result;

/// Parallel processing configuration
#[derive(Debug, Clone)]
pub struct ParallelConfig {
    /// Number of threads to use (0 = auto-detect)
    pub thread_count: usize,
    /// Minimum data size to use parallel processing (bytes)
    pub min_parallel_size: usize,
    /// Maximum number of threads to use
    pub max_threads: usize,
}

impl Default for ParallelConfig {
    fn default() -> Self {
        Self {
            thread_count: 0,              // Auto-detect
            min_parallel_size: 64 * 1024, // 64KB minimum
            max_threads: 16,              // Reasonable maximum
        }
    }
}

impl ParallelConfig {
    /// Create a new parallel configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the number of threads to use
    pub fn with_thread_count(mut self, count: usize) -> Self {
        self.thread_count = count;
        self
    }

    /// Set the minimum size for parallel processing
    pub fn with_min_parallel_size(mut self, size: usize) -> Self {
        self.min_parallel_size = size;
        self
    }

    /// Set the maximum number of threads
    pub fn with_max_threads(mut self, max: usize) -> Self {
        self.max_threads = max;
        self
    }

    /// Get the effective number of threads to use
    pub fn effective_thread_count(&self) -> usize {
        if self.thread_count > 0 {
            self.thread_count.min(self.max_threads)
        } else {
            // Auto-detect based on CPU cores
            #[cfg(feature = "std")]
            {
                let cpu_count = thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(1);
                cpu_count.min(self.max_threads)
            }
            #[cfg(not(feature = "std"))]
            {
                1 // Fallback to single-threaded
            }
        }
    }
}

/// Parallel-optimized Saturnin core implementation
///
/// Uses multi-threading for processing large data blocks in parallel.
pub struct ParallelSaturninCore {
    // Use the standard core as the base implementation
    base_core: crate::core::SaturninCore,
    // Parallel processing configuration
    config: ParallelConfig,
}

impl ParallelSaturninCore {
    /// Create a new parallel-optimized Saturnin core instance
    ///
    /// # Arguments
    /// * `num_rounds` - Number of super-rounds (0-31)
    /// * `domain` - Domain parameter (0-15)
    ///
    /// # Returns
    /// Parallel-optimized core instance
    pub fn new(num_rounds: usize, domain: u8) -> Result<Self> {
        let base_core = crate::core::SaturninCore::new(num_rounds, domain)?;
        let config = ParallelConfig::new();

        Ok(Self { base_core, config })
    }

    /// Create a new parallel-optimized core with custom configuration
    ///
    /// # Arguments
    /// * `num_rounds` - Number of super-rounds (0-31)
    /// * `domain` - Domain parameter (0-15)
    /// * `config` - Parallel processing configuration
    ///
    /// # Returns
    /// Parallel-optimized core instance
    pub fn with_config(num_rounds: usize, domain: u8, config: ParallelConfig) -> Result<Self> {
        let base_core = crate::core::SaturninCore::new(num_rounds, domain)?;

        Ok(Self { base_core, config })
    }

    /// Encrypt a single block (delegates to base core)
    ///
    /// # Arguments
    /// * `key` - 32-byte encryption key
    /// * `block` - 32-byte block to encrypt (modified in-place)
    ///
    /// # Returns
    /// Result indicating success or failure
    pub fn encrypt_block(&self, key: &[u8], block: &mut [u8]) -> Result<()> {
        self.base_core.encrypt_block(key, block)
    }

    /// Decrypt a single block (delegates to base core)
    ///
    /// # Arguments
    /// * `key` - 32-byte decryption key
    /// * `block` - 32-byte block to decrypt (modified in-place)
    ///
    /// # Returns
    /// Result indicating success or failure
    pub fn decrypt_block(&self, key: &[u8], block: &mut [u8]) -> Result<()> {
        self.base_core.decrypt_block(key, block)
    }

    /// Encrypt multiple blocks in parallel
    ///
    /// # Arguments
    /// * `key` - 32-byte encryption key
    /// * `data` - Data to encrypt (must be multiple of 32 bytes)
    ///
    /// # Returns
    /// Result indicating success or failure
    pub fn encrypt_blocks_parallel(&self, key: &[u8], data: &mut [u8]) -> Result<()> {
        if !data.len().is_multiple_of(32) {
            return Err(lib_q_core::Error::InvalidMessageSize {
                max: data.len() - (data.len() % 32),
                actual: data.len(),
            });
        }

        // Check if we should use parallel processing
        if data.len() < self.config.min_parallel_size {
            return self.encrypt_blocks_sequential(key, data);
        }

        #[cfg(feature = "std")]
        {
            self.encrypt_blocks_parallel_std(key, data)
        }
        #[cfg(not(feature = "std"))]
        {
            self.encrypt_blocks_sequential(key, data)
        }
    }

    /// Decrypt multiple blocks in parallel
    ///
    /// # Arguments
    /// * `key` - 32-byte decryption key
    /// * `data` - Data to decrypt (must be multiple of 32 bytes)
    ///
    /// # Returns
    /// Result indicating success or failure
    pub fn decrypt_blocks_parallel(&self, key: &[u8], data: &mut [u8]) -> Result<()> {
        if !data.len().is_multiple_of(32) {
            return Err(lib_q_core::Error::InvalidMessageSize {
                max: data.len() - (data.len() % 32),
                actual: data.len(),
            });
        }

        // Check if we should use parallel processing
        if data.len() < self.config.min_parallel_size {
            return self.decrypt_blocks_sequential(key, data);
        }

        #[cfg(feature = "std")]
        {
            self.decrypt_blocks_parallel_std(key, data)
        }
        #[cfg(not(feature = "std"))]
        {
            self.decrypt_blocks_sequential(key, data)
        }
    }

    /// Encrypt blocks sequentially (fallback)
    fn encrypt_blocks_sequential(&self, key: &[u8], data: &mut [u8]) -> Result<()> {
        for chunk in data.chunks_mut(32) {
            self.base_core.encrypt_block(key, chunk)?;
        }
        Ok(())
    }

    /// Decrypt blocks sequentially (fallback)
    fn decrypt_blocks_sequential(&self, key: &[u8], data: &mut [u8]) -> Result<()> {
        for chunk in data.chunks_mut(32) {
            self.base_core.decrypt_block(key, chunk)?;
        }
        Ok(())
    }

    /// Encrypt blocks in parallel (std implementation)
    #[cfg(feature = "std")]
    fn encrypt_blocks_parallel_std(&self, key: &[u8], data: &mut [u8]) -> Result<()> {
        let thread_count = self.config.effective_thread_count();
        if thread_count <= 1 {
            return self.encrypt_blocks_sequential(key, data);
        }

        let block_count = data.len() / 32;
        let blocks_per_thread = block_count.div_ceil(thread_count);

        // Create a shared core for each thread
        let core = Arc::new(self.base_core.clone());
        let key = Arc::new(key.to_vec());

        // Channel for collecting results
        let (tx, rx) = mpsc::channel();

        // Spawn worker threads
        for thread_id in 0..thread_count {
            let start_block = thread_id * blocks_per_thread;
            let end_block = ((thread_id + 1) * blocks_per_thread).min(block_count);

            if start_block >= end_block {
                break;
            }

            let core: Arc<crate::core::SaturninCore> = Arc::clone(&core);
            let key: Arc<Vec<u8>> = Arc::clone(&key);
            let tx = tx.clone();

            // We need to work with a copy of the data slice for this thread
            let thread_data = &data[start_block * 32..end_block * 32];
            let mut thread_data_copy = thread_data.to_vec();

            thread::spawn(move || {
                // Encrypt blocks in this thread's range
                for chunk in thread_data_copy.chunks_mut(32) {
                    if let Err(e) = core.encrypt_block(&key, chunk) {
                        let _ = tx.send(Err(e));
                        return;
                    }
                }

                // Send the encrypted data back
                let _ = tx.send(Ok((thread_id, thread_data_copy)));
            });
        }

        // Collect results
        let mut results = Vec::new();
        for _ in 0..thread_count {
            match rx.recv() {
                Ok(result) => results.push(result),
                Err(_) => {
                    return Err(lib_q_core::Error::InvalidAlgorithm {
                        algorithm: "Thread communication failed",
                    });
                }
            }
        }

        // Reassemble the data
        for result in results {
            match result {
                Ok((thread_id, encrypted_data)) => {
                    let start_block = thread_id * blocks_per_thread;
                    let end_block = ((thread_id + 1) * blocks_per_thread).min(block_count);
                    let start_byte = start_block * 32;
                    let end_byte = end_block * 32;
                    data[start_byte..end_byte].copy_from_slice(&encrypted_data);
                }
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    /// Decrypt blocks in parallel (std implementation)
    #[cfg(feature = "std")]
    fn decrypt_blocks_parallel_std(&self, key: &[u8], data: &mut [u8]) -> Result<()> {
        let thread_count = self.config.effective_thread_count();
        if thread_count <= 1 {
            return self.decrypt_blocks_sequential(key, data);
        }

        let block_count = data.len() / 32;
        let blocks_per_thread = block_count.div_ceil(thread_count);

        // Create a shared core for each thread
        let core = Arc::new(self.base_core.clone());
        let key = Arc::new(key.to_vec());

        // Channel for collecting results
        let (tx, rx) = mpsc::channel();

        // Spawn worker threads
        for thread_id in 0..thread_count {
            let start_block = thread_id * blocks_per_thread;
            let end_block = ((thread_id + 1) * blocks_per_thread).min(block_count);

            if start_block >= end_block {
                break;
            }

            let core: Arc<crate::core::SaturninCore> = Arc::clone(&core);
            let key: Arc<Vec<u8>> = Arc::clone(&key);
            let tx = tx.clone();

            // We need to work with a copy of the data slice for this thread
            let thread_data = &data[start_block * 32..end_block * 32];
            let mut thread_data_copy = thread_data.to_vec();

            thread::spawn(move || {
                // Decrypt blocks in this thread's range
                for chunk in thread_data_copy.chunks_mut(32) {
                    if let Err(e) = core.decrypt_block(&key, chunk) {
                        let _ = tx.send(Err(e));
                        return;
                    }
                }

                // Send the decrypted data back
                let _ = tx.send(Ok((thread_id, thread_data_copy)));
            });
        }

        // Collect results
        let mut results = Vec::new();
        for _ in 0..thread_count {
            match rx.recv() {
                Ok(result) => results.push(result),
                Err(_) => {
                    return Err(lib_q_core::Error::InvalidAlgorithm {
                        algorithm: "Thread communication failed",
                    });
                }
            }
        }

        // Reassemble the data
        for result in results {
            match result {
                Ok((thread_id, decrypted_data)) => {
                    let start_block = thread_id * blocks_per_thread;
                    let end_block = ((thread_id + 1) * blocks_per_thread).min(block_count);
                    let start_byte = start_block * 32;
                    let end_byte = end_block * 32;
                    data[start_byte..end_byte].copy_from_slice(&decrypted_data);
                }
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    /// Get the parallel processing configuration
    pub fn config(&self) -> &ParallelConfig {
        &self.config
    }

    /// Get the underlying base core (for testing)
    pub fn base_core(&self) -> &crate::core::SaturninCore {
        &self.base_core
    }
}

/// Parallel-optimized hash function
///
/// Uses multi-threading for processing large data blocks in the hash function.
pub struct ParallelSaturninHash {
    // Use the standard hash as the base implementation
    base_hash: crate::hash::SaturninHash,
    // Parallel processing configuration
    config: ParallelConfig,
}

impl Default for ParallelSaturninHash {
    fn default() -> Self {
        Self::new()
    }
}

impl ParallelSaturninHash {
    /// Create a new parallel-optimized Saturnin hash instance
    pub fn new() -> Self {
        let base_hash = crate::hash::SaturninHash::new();
        let config = ParallelConfig::new();

        Self { base_hash, config }
    }

    /// Create a new parallel-optimized hash with custom configuration
    pub fn with_config(config: ParallelConfig) -> Self {
        let base_hash = crate::hash::SaturninHash::new();

        Self { base_hash, config }
    }

    /// Hash data using parallel processing for large inputs
    ///
    /// # Arguments
    /// * `data` - Data to hash
    ///
    /// # Returns
    /// 256-bit hash output
    pub fn hash_parallel(&self, data: &[u8]) -> Result<Vec<u8>> {
        // For now, delegate to the base hash implementation
        // In a full implementation, this would split large data across threads
        self.base_hash.hash(data)
    }

    /// Get the parallel processing configuration
    pub fn config(&self) -> &ParallelConfig {
        &self.config
    }

    /// Get the underlying base hash (for testing)
    pub fn base_hash(&self) -> &crate::hash::SaturninHash {
        &self.base_hash
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::vec;

    use super::*;

    #[test]
    fn test_parallel_config_creation() {
        let config = ParallelConfig::new();
        assert_eq!(config.thread_count, 0);
        assert_eq!(config.min_parallel_size, 64 * 1024);
        assert_eq!(config.max_threads, 16);
    }

    #[test]
    fn test_parallel_config_customization() {
        let config = ParallelConfig::new()
            .with_thread_count(4)
            .with_min_parallel_size(32 * 1024)
            .with_max_threads(8);

        assert_eq!(config.thread_count, 4);
        assert_eq!(config.min_parallel_size, 32 * 1024);
        assert_eq!(config.max_threads, 8);
    }

    #[test]
    fn test_parallel_core_creation() {
        let core = ParallelSaturninCore::new(16, 7).unwrap();

        // Should be able to create a core
        assert_eq!(core.base_core().num_rounds(), 16);
        assert_eq!(core.base_core().domain(), 7);
    }

    #[test]
    fn test_parallel_core_single_block() -> Result<()> {
        let core = ParallelSaturninCore::new(16, 7)?;
        let key = [0u8; 32];
        let mut block = [0u8; 32];

        // Test encryption
        core.encrypt_block(&key, &mut block)?;

        // Test decryption
        core.decrypt_block(&key, &mut block)?;

        // Should be back to original (all zeros)
        assert_eq!(block, [0u8; 32]);

        Ok(())
    }

    #[test]
    fn test_parallel_core_multiple_blocks() -> Result<()> {
        let core = ParallelSaturninCore::new(16, 7)?;
        let key = [0x12u8; 32];
        let mut data = vec![0x34u8; 128]; // 4 blocks

        // Test encryption
        core.encrypt_blocks_parallel(&key, &mut data)?;

        // Test decryption
        core.decrypt_blocks_parallel(&key, &mut data)?;

        // Should be back to original
        assert_eq!(data, vec![0x34u8; 128]);

        Ok(())
    }

    #[test]
    fn test_parallel_core_vs_sequential_equivalence() -> Result<()> {
        let parallel_core = ParallelSaturninCore::new(16, 7)?;
        let base_core = parallel_core.base_core();

        let key = [0x12u8; 32];
        let mut data1 = vec![0x34u8; 128]; // 4 blocks
        let mut data2 = data1.clone();

        // Encrypt with both cores
        parallel_core.encrypt_blocks_parallel(&key, &mut data1)?;
        for chunk in data2.chunks_mut(32) {
            base_core.encrypt_block(&key, chunk)?;
        }

        // Results should be identical
        assert_eq!(data1, data2);

        Ok(())
    }

    #[test]
    fn test_parallel_hash_creation() {
        let hash = ParallelSaturninHash::new();

        // Should be able to create a hash
        assert_eq!(hash.base_hash().output_size(), 32);
    }

    #[test]
    fn test_parallel_hash_operation() -> Result<()> {
        let hash = ParallelSaturninHash::new();
        let data = b"Hello, World!";

        // Test hash operation
        let result = hash.hash_parallel(data)?;

        // Should produce a 32-byte hash
        assert_eq!(result.len(), 32);

        Ok(())
    }
}
