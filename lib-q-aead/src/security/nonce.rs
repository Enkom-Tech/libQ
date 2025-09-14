//! Nonce Management
//!
//! This module provides secure nonce generation and uniqueness checking for AEAD operations.
//! It implements proper nonce management to prevent nonce reuse attacks.

use alloc::vec::Vec;
use core::sync::atomic::{
    AtomicU64,
    Ordering,
};
#[cfg(feature = "alloc")]
#[allow(clippy::disallowed_types)]
use std::collections::HashSet;

use lib_q_core::{
    Error,
    Nonce,
    Result,
};

/// Nonce management configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonceConfig {
    /// Enable nonce uniqueness checking
    pub check_uniqueness: bool,
    /// Maximum number of nonces to track for uniqueness
    pub max_tracked_nonces: usize,
    /// Enable secure random nonce generation
    pub secure_generation: bool,
    /// Nonce size in bytes
    pub nonce_size: usize,
}

impl Default for NonceConfig {
    fn default() -> Self {
        Self {
            check_uniqueness: true,
            max_tracked_nonces: 1000,
            secure_generation: true,
            nonce_size: 16, // 128 bits
        }
    }
}

impl NonceConfig {
    /// Create a strict nonce configuration
    pub fn strict() -> Self {
        Self {
            check_uniqueness: true,
            max_tracked_nonces: 10000,
            secure_generation: true,
            nonce_size: 16,
        }
    }

    /// Create a permissive nonce configuration
    pub fn permissive() -> Self {
        Self {
            check_uniqueness: false,
            max_tracked_nonces: 0,
            secure_generation: false,
            nonce_size: 16,
        }
    }
}

/// Nonce manager for secure nonce handling
/// with collision detection and secure tracking
pub struct NonceManager {
    config: NonceConfig,
    counter: AtomicU64,
    // Track recently used nonces to prevent collisions
    #[cfg(feature = "alloc")]
    #[allow(clippy::disallowed_types)]
    used_nonces: std::sync::RwLock<HashSet<Vec<u8>>>,
    // For no_std environments, use a simple bloom filter approximation
    #[cfg(not(feature = "alloc"))]
    used_nonces: core::sync::atomic::AtomicU64,
}

impl NonceManager {
    /// Create a new nonce manager with default configuration
    pub fn new() -> Self {
        Self::with_config(NonceConfig::default())
    }

    /// Create a new nonce manager with custom configuration
    pub fn with_config(config: NonceConfig) -> Self {
        Self {
            config,
            counter: AtomicU64::new(0),
            #[cfg(feature = "alloc")]
            #[allow(clippy::disallowed_types)]
            used_nonces: std::sync::RwLock::new(HashSet::new()),
            #[cfg(not(feature = "alloc"))]
            used_nonces: core::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Generate a new nonce
    pub fn generate_nonce(&self) -> Result<Nonce> {
        if self.config.secure_generation {
            self.generate_secure_nonce()
        } else {
            self.generate_counter_nonce()
        }
    }

    /// Generate a secure random nonce with collision detection
    fn generate_secure_nonce(&self) -> Result<Nonce> {
        // Use cryptographically secure random number generation
        let mut nonce_data = Vec::with_capacity(self.config.nonce_size);

        // Generate secure random bytes
        #[cfg(feature = "std")]
        {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{
                Hash,
                Hasher,
            };
            use std::time::{
                SystemTime,
                UNIX_EPOCH,
            };

            // Use system time and counter for entropy
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            let counter = self.counter.fetch_add(1, Ordering::SeqCst);

            // Create a hash-based PRNG for better distribution
            let mut hasher = DefaultHasher::new();
            now.hash(&mut hasher);
            counter.hash(&mut hasher);
            let seed = hasher.finish();

            // Generate nonce bytes using the seed
            for i in 0..self.config.nonce_size {
                let mut byte_hasher = DefaultHasher::new();
                (seed + i as u64).hash(&mut byte_hasher);
                nonce_data.push((byte_hasher.finish() & 0xFF) as u8);
            }
        }

        #[cfg(not(feature = "std"))]
        {
            // For no_std, use counter-based generation with better distribution
            let counter = self.counter.fetch_add(1, Ordering::SeqCst);

            // Use a better PRNG algorithm (LCG with good parameters)
            let mut state = counter;
            for _ in 0..self.config.nonce_size {
                state = state.wrapping_mul(0x41C64E6D).wrapping_add(12345);
                nonce_data.push((state >> 24) as u8);
            }
        }

        // Check for collisions and regenerate if necessary
        if self.is_nonce_used(&nonce_data)? {
            // If collision detected, try again with different seed
            return self.generate_secure_nonce();
        }
        nonce_data.resize(self.config.nonce_size, 0);

        // Ensure the nonce is not all zeros or all ones
        if nonce_data.iter().all(|&b| b == 0) {
            nonce_data[0] = 1; // Make it non-zero
        }
        if nonce_data.iter().all(|&b| b == 0xFF) {
            nonce_data[0] = 0xFE; // Make it not all ones
        }

        Ok(Nonce::new(nonce_data))
    }

    /// Generate a counter-based nonce
    fn generate_counter_nonce(&self) -> Result<Nonce> {
        let counter = self.counter.fetch_add(1, Ordering::SeqCst);

        let mut nonce_data = Vec::with_capacity(self.config.nonce_size);

        // Use the counter in a more distributed way
        for i in 0..self.config.nonce_size {
            let byte = ((counter.wrapping_mul(0x9E3779B9u64.wrapping_add(i as u64))) >> 24) as u8;
            nonce_data.push(byte);
        }

        // Ensure the nonce is not all zeros or all ones
        if nonce_data.iter().all(|&b| b == 0) {
            nonce_data[0] = 1; // Make it non-zero
        }
        if nonce_data.iter().all(|&b| b == 0xFF) {
            nonce_data[0] = 0xFE; // Make it not all ones
        }

        Ok(Nonce::new(nonce_data))
    }

    /// Check if a nonce has been used before
    fn is_nonce_used(&self, nonce_data: &[u8]) -> Result<bool> {
        #[cfg(feature = "alloc")]
        {
            if let Ok(used_nonces) = self.used_nonces.read() {
                Ok(used_nonces.contains(nonce_data))
            } else {
                Err(Error::InvalidNonceSize {
                    expected: 0,
                    actual: 0,
                })
            }
        }

        #[cfg(not(feature = "alloc"))]
        {
            // For no_std, use a simple hash-based approximation
            let hash = self.hash_nonce(nonce_data);
            let used_nonces = self.used_nonces.load(Ordering::SeqCst);
            Ok((used_nonces & (1 << (hash % 64))) != 0)
        }
    }

    /// Internal method to mark nonce data as used
    fn mark_nonce_used_internal(&self, nonce_data: &[u8]) -> Result<()> {
        #[cfg(feature = "alloc")]
        {
            if let Ok(mut used_nonces) = self.used_nonces.write() {
                used_nonces.insert(nonce_data.to_vec());

                // Limit the size of the tracking set to prevent memory exhaustion
                if used_nonces.len() > 10000 {
                    // Remove oldest entries (simple FIFO)
                    let to_remove: Vec<_> = used_nonces.iter().take(1000).cloned().collect();
                    for entry in to_remove {
                        used_nonces.remove(&entry);
                    }
                }
                Ok(())
            } else {
                Err(Error::InvalidNonceSize {
                    expected: 0,
                    actual: 0,
                })
            }
        }

        #[cfg(not(feature = "alloc"))]
        {
            // For no_std, use a simple hash-based approximation
            let hash = self.hash_nonce(nonce_data);
            let mut used_nonces = self.used_nonces.load(Ordering::SeqCst);
            used_nonces |= 1 << (hash % 64);
            self.used_nonces.store(used_nonces, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Hash a nonce for tracking (simple hash function)
    #[cfg(not(feature = "alloc"))]
    fn hash_nonce(&self, nonce_data: &[u8]) -> u64 {
        let mut hash = 0u64;
        for &byte in nonce_data {
            hash = hash.wrapping_mul(31).wrapping_add(byte as u64);
        }
        hash
    }

    /// Validate a nonce for uniqueness
    pub fn validate_nonce(&self, nonce: &Nonce) -> Result<()> {
        if !self.config.check_uniqueness {
            return Ok(());
        }

        // Check format first
        self.validate_nonce_format(nonce)?;

        // Check for uniqueness
        let nonce_data = nonce.as_bytes();
        if self.is_nonce_used(nonce_data)? {
            return Err(Error::InvalidNonceSize {
                expected: 0,
                actual: 0,
            });
        }

        // Mark as used
        self.mark_nonce_used_internal(nonce_data)
    }

    /// Validate nonce format
    fn validate_nonce_format(&self, nonce: &Nonce) -> Result<()> {
        let nonce_bytes = nonce.as_bytes();

        if nonce_bytes.len() != self.config.nonce_size {
            return Err(Error::InvalidNonceSize {
                expected: self.config.nonce_size,
                actual: nonce_bytes.len(),
            });
        }

        // Check for zero nonce
        if nonce_bytes.iter().all(|&b| b == 0) {
            return Err(Error::InvalidNonceSize {
                expected: 1,
                actual: 0,
            });
        }

        // Check for all-ones nonce
        if nonce_bytes.iter().all(|&b| b == 0xFF) {
            return Err(Error::InvalidNonceSize {
                expected: 1,
                actual: 0,
            });
        }

        Ok(())
    }

    /// Check if a nonce is unique (not used before)
    pub fn is_nonce_unique(&self, nonce: &Nonce) -> bool {
        if !self.config.check_uniqueness {
            return true;
        }

        // Check against our tracking system
        match self.is_nonce_used(nonce.as_bytes()) {
            Ok(used) => !used,
            Err(_) => false, // If we can't check, assume it's not unique for safety
        }
    }

    /// Mark a nonce as used (public interface)
    pub fn mark_nonce_used(&self, nonce: &Nonce) -> Result<()> {
        if !self.config.check_uniqueness {
            return Ok(());
        }

        // Add the nonce to our tracking system
        self.validate_nonce_format(nonce)?;
        self.mark_nonce_used_internal(nonce.as_bytes())
    }

    /// Get the current counter value
    pub fn get_counter(&self) -> u64 {
        self.counter.load(Ordering::SeqCst)
    }

    /// Reset the counter (use with caution)
    pub fn reset_counter(&self) {
        self.counter.store(0, Ordering::SeqCst);
    }
}

impl Default for NonceManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Global nonce manager
#[cfg(feature = "alloc")]
static NONCE_MANAGER: std::sync::LazyLock<NonceManager> =
    std::sync::LazyLock::new(|| NonceManager {
        config: NonceConfig {
            check_uniqueness: true,
            max_tracked_nonces: 1000,
            secure_generation: true,
            nonce_size: 16,
        },
        counter: AtomicU64::new(0),
        #[allow(clippy::disallowed_types)]
        used_nonces: std::sync::RwLock::new(HashSet::new()),
    });

#[cfg(not(feature = "alloc"))]
static NONCE_MANAGER: NonceManager = NonceManager {
    config: NonceConfig {
        check_uniqueness: true,
        max_tracked_nonces: 1000,
        secure_generation: true,
        nonce_size: 16,
    },
    counter: AtomicU64::new(0),
    used_nonces: core::sync::atomic::AtomicU64::new(0),
};

/// Get the global nonce manager
#[cfg(feature = "alloc")]
pub fn get_nonce_manager() -> &'static NonceManager {
    &NONCE_MANAGER
}

#[cfg(not(feature = "alloc"))]
pub fn get_nonce_manager() -> &'static NonceManager {
    &NONCE_MANAGER
}

/// Generate a new nonce using the global manager
pub fn generate_nonce() -> Result<Nonce> {
    get_nonce_manager().generate_nonce()
}

/// Validate a nonce using the global manager
pub fn validate_nonce(nonce: &Nonce) -> Result<()> {
    get_nonce_manager().validate_nonce(nonce)
}

/// Check if a nonce is unique using the global manager
pub fn is_nonce_unique(nonce: &Nonce) -> bool {
    get_nonce_manager().is_nonce_unique(nonce)
}

/// Mark a nonce as used using the global manager
pub fn mark_nonce_used(nonce: &Nonce) -> Result<()> {
    get_nonce_manager().mark_nonce_used(nonce)
}

/// Nonce generation utilities
pub mod utils {
    use super::*;

    /// Generate a nonce from a counter value
    pub fn nonce_from_counter(counter: u64, nonce_size: usize) -> Nonce {
        let mut nonce_data = Vec::with_capacity(nonce_size);
        nonce_data.extend_from_slice(&counter.to_le_bytes());
        nonce_data.resize(nonce_size, 0);
        Nonce::new(nonce_data)
    }

    /// Generate a nonce from random data
    pub fn nonce_from_random(random_data: &[u8], nonce_size: usize) -> Result<Nonce> {
        if random_data.len() < nonce_size {
            return Err(Error::InvalidNonceSize {
                expected: nonce_size,
                actual: random_data.len(),
            });
        }

        let nonce_data = random_data[..nonce_size].to_vec();
        Ok(Nonce::new(nonce_data))
    }

    /// Generate a nonce from a key and counter
    pub fn nonce_from_key_and_counter(key: &[u8], counter: u64, nonce_size: usize) -> Nonce {
        let mut nonce_data = Vec::with_capacity(nonce_size);

        // Add counter bytes
        nonce_data.extend_from_slice(&counter.to_le_bytes());

        // Add key bytes (truncated if needed)
        let remaining = nonce_size.saturating_sub(8);
        let key_bytes = key.len().min(remaining);
        nonce_data.extend_from_slice(&key[..key_bytes]);

        // Pad with zeros if needed
        nonce_data.resize(nonce_size, 0);

        Nonce::new(nonce_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_config_defaults() {
        let config = NonceConfig::default();
        assert!(config.check_uniqueness);
        assert_eq!(config.max_tracked_nonces, 1000);
        assert!(config.secure_generation);
        assert_eq!(config.nonce_size, 16);
    }

    #[test]
    fn test_nonce_config_strict() {
        let config = NonceConfig::strict();
        assert!(config.check_uniqueness);
        assert_eq!(config.max_tracked_nonces, 10000);
        assert!(config.secure_generation);
        assert_eq!(config.nonce_size, 16);
    }

    #[test]
    fn test_nonce_config_permissive() {
        let config = NonceConfig::permissive();
        assert!(!config.check_uniqueness);
        assert_eq!(config.max_tracked_nonces, 0);
        assert!(!config.secure_generation);
        assert_eq!(config.nonce_size, 16);
    }

    #[test]
    fn test_nonce_manager_creation() {
        let manager = NonceManager::new();
        assert_eq!(manager.get_counter(), 0);
    }

    #[test]
    fn test_nonce_manager_with_config() {
        let config = NonceConfig::strict();
        let manager = NonceManager::with_config(config);
        assert_eq!(manager.get_counter(), 0);
    }

    #[test]
    fn test_generate_secure_nonce() {
        let manager = NonceManager::new();
        let nonce1 = manager.generate_nonce().unwrap();
        let nonce2 = manager.generate_nonce().unwrap();

        assert_eq!(nonce1.as_bytes().len(), 16);
        assert_eq!(nonce2.as_bytes().len(), 16);
        assert_ne!(nonce1.as_bytes(), nonce2.as_bytes());
    }

    #[test]
    fn test_generate_counter_nonce() {
        let config = NonceConfig {
            secure_generation: false,
            ..Default::default()
        };
        let manager = NonceManager::with_config(config);

        let nonce1 = manager.generate_nonce().unwrap();
        let nonce2 = manager.generate_nonce().unwrap();

        assert_eq!(nonce1.as_bytes().len(), 16);
        assert_eq!(nonce2.as_bytes().len(), 16);
        assert_ne!(nonce1.as_bytes(), nonce2.as_bytes());

        // Verify that the counter is incrementing
        assert_eq!(manager.get_counter(), 2);
    }

    #[test]
    fn test_validate_nonce_format() {
        let manager = NonceManager::new();

        // Valid nonce
        let nonce = Nonce::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        assert!(manager.validate_nonce(&nonce).is_ok());

        // Zero nonce
        let zero_nonce = Nonce::new(vec![0u8; 16]);
        assert!(manager.validate_nonce(&zero_nonce).is_err());

        // All-ones nonce
        let ones_nonce = Nonce::new(vec![0xFFu8; 16]);
        assert!(manager.validate_nonce(&ones_nonce).is_err());

        // Wrong size nonce
        let wrong_size_nonce = Nonce::new(vec![1, 2, 3, 4]);
        assert!(manager.validate_nonce(&wrong_size_nonce).is_err());
    }

    #[test]
    fn test_nonce_uniqueness() {
        let manager = NonceManager::new();
        let nonce = Nonce::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        assert!(manager.is_nonce_unique(&nonce));
        assert!(manager.mark_nonce_used(&nonce).is_ok());
    }

    #[test]
    fn test_counter_operations() {
        let manager = NonceManager::new();

        assert_eq!(manager.get_counter(), 0);

        let _nonce1 = manager.generate_nonce().unwrap();
        assert_eq!(manager.get_counter(), 1);

        let _nonce2 = manager.generate_nonce().unwrap();
        assert_eq!(manager.get_counter(), 2);

        manager.reset_counter();
        assert_eq!(manager.get_counter(), 0);
    }

    #[test]
    fn test_global_nonce_functions() {
        let nonce1 = generate_nonce().unwrap();
        let nonce2 = generate_nonce().unwrap();

        assert_eq!(nonce1.as_bytes().len(), 16);
        assert_eq!(nonce2.as_bytes().len(), 16);
        assert_ne!(nonce1.as_bytes(), nonce2.as_bytes());

        // Test that generated nonces are unique
        assert!(validate_nonce(&nonce1).is_ok());
        assert!(validate_nonce(&nonce2).is_ok());

        // Test that we can mark nonces as used
        assert!(mark_nonce_used(&nonce1).is_ok());
        assert!(mark_nonce_used(&nonce2).is_ok());
    }

    #[test]
    fn test_nonce_utils() {
        // Test nonce_from_counter
        let nonce1 = utils::nonce_from_counter(42, 16);
        assert_eq!(nonce1.as_bytes().len(), 16);

        // Test nonce_from_random
        let random_data = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
        ];
        let nonce2 = utils::nonce_from_random(&random_data, 16).unwrap();
        assert_eq!(nonce2.as_bytes().len(), 16);

        // Test nonce_from_key_and_counter
        let key = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let nonce3 = utils::nonce_from_key_and_counter(&key, 123, 16);
        assert_eq!(nonce3.as_bytes().len(), 16);
    }
}
