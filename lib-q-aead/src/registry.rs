//! AEAD Algorithm Registry
//!
//! This module provides a flexible registry system for AEAD algorithms that allows
//! dynamic registration and creation of algorithm instances.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
#[cfg(feature = "alloc")]
use alloc::string::ToString;
use alloc::vec::Vec;
#[cfg(feature = "std")]
use core::hash::Hasher;

/// Custom hasher for Algorithm to ensure consistent hashing
/// This provides deterministic hashing for Algorithm keys
/// Available for future HashMap usage when security requirements allow
#[cfg(feature = "std")]
#[derive(Default)]
#[allow(dead_code)] // Reserved for future HashMap implementation
struct AlgorithmHasher {
    state: u64,
}

#[cfg(feature = "std")]
impl Hasher for AlgorithmHasher {
    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.state = self.state.wrapping_mul(31).wrapping_add(byte as u64);
        }
    }

    fn finish(&self) -> u64 {
        self.state
    }
}

/// Type alias for algorithm storage
/// Uses BTreeMap for consistent cross-platform behavior and security
/// AlgorithmHasher is available for future HashMap usage if needed
type AlgorithmHashMap = BTreeMap<Algorithm, AeadConstructor>;
#[cfg(not(feature = "std"))]
use core::cell::RefCell;
#[cfg(feature = "std")]
use std::sync::RwLock;

use lib_q_core::{
    Algorithm,
    AlgorithmCategory,
    Error,
    Result,
};

use crate::AeadWithMetadata;
use crate::metadata::AeadMetadata;
use crate::plugin::AeadPlugin;

/// Constructor function type for creating AEAD instances
pub type AeadConstructor = Box<dyn Fn() -> Result<Box<dyn AeadWithMetadata>> + Send + Sync>;

/// Registry for AEAD algorithms
pub struct AeadRegistry {
    #[cfg(feature = "std")]
    constructors: RwLock<AlgorithmHashMap>,
    #[cfg(not(feature = "std"))]
    constructors: RefCell<AlgorithmHashMap>,
    #[cfg(feature = "std")]
    plugins: RwLock<Vec<Box<dyn AeadPlugin>>>,
    #[cfg(not(feature = "std"))]
    plugins: RefCell<Vec<Box<dyn AeadPlugin>>>,
    metadata: BTreeMap<Algorithm, &'static AeadMetadata>,
}

// Make AeadRegistry Sync for WASM targets
unsafe impl Sync for AeadRegistry {}

impl AeadRegistry {
    /// Create a new AEAD registry
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "std")]
            constructors: RwLock::new(AlgorithmHashMap::new()),
            #[cfg(not(feature = "std"))]
            constructors: RefCell::new(AlgorithmHashMap::new()),
            #[cfg(feature = "std")]
            plugins: RwLock::new(Vec::new()),
            #[cfg(not(feature = "std"))]
            plugins: RefCell::new(Vec::new()),
            metadata: Self::create_metadata_map(),
        }
    }

    /// Create the metadata map for all known algorithms
    fn create_metadata_map() -> BTreeMap<Algorithm, &'static AeadMetadata> {
        let mut metadata = BTreeMap::new();

        // Saturnin metadata
        metadata.insert(Algorithm::Saturnin, &AeadMetadata {
            algorithm: Algorithm::Saturnin,
            key_size: 32,
            nonce_size: 16,
            tag_size: 32,
            security_level: 1,
            name: "Saturnin",
            description: "Lightweight post-quantum symmetric algorithm suite for IoT and constrained devices",
        });

        // SHAKE256 AEAD metadata
        metadata.insert(
            Algorithm::Shake256Aead,
            &AeadMetadata {
                algorithm: Algorithm::Shake256Aead,
                key_size: 32,
                nonce_size: 16,
                tag_size: 32,
                security_level: 1,
                name: "SHAKE256-AEAD",
                description: "SHAKE256-based AEAD construction using post-quantum hash function",
            },
        );

        // KEM AEAD metadata
        metadata.insert(Algorithm::KemAead, &AeadMetadata {
            algorithm: Algorithm::KemAead,
            key_size: 32,
            nonce_size: 16,
            tag_size: 32,
            security_level: 4,
            name: "KEM-AEAD",
            description: "KEM-based AEAD construction combining post-quantum KEM with symmetric encryption",
        });

        metadata
    }

    /// Register an algorithm constructor
    pub fn register_algorithm<F>(&self, algorithm: Algorithm, constructor: F) -> Result<()>
    where
        F: Fn() -> Result<Box<dyn AeadWithMetadata>> + Send + Sync + 'static,
    {
        // Validate algorithm category
        if algorithm.category() != AlgorithmCategory::Aead {
            return Err(Error::InvalidAlgorithm {
                algorithm: "Algorithm is not an AEAD algorithm",
            });
        }

        #[cfg(feature = "std")]
        {
            let mut constructors = self.constructors.write().map_err(|_| Error::InvalidState {
                operation: "register_algorithm".to_string(),
                reason: "Failed to acquire write lock".to_string(),
            })?;
            constructors.insert(algorithm, Box::new(constructor));
        }
        #[cfg(not(feature = "std"))]
        {
            let mut constructors = self.constructors.borrow_mut();
            constructors.insert(algorithm, Box::new(constructor));
        }
        Ok(())
    }

    /// Register a plugin
    pub fn register_plugin(&self, plugin: Box<dyn AeadPlugin>) -> Result<()> {
        #[cfg(feature = "std")]
        {
            let mut plugins = self.plugins.write().map_err(|_| Error::InvalidState {
                operation: "register_plugin".to_string(),
                reason: "Failed to acquire write lock".to_string(),
            })?;
            plugins.push(plugin);
        }
        #[cfg(not(feature = "std"))]
        {
            let mut plugins = self.plugins.borrow_mut();
            plugins.push(plugin);
        }
        Ok(())
    }

    /// Create an AEAD instance for the specified algorithm
    pub fn create_aead(&self, algorithm: Algorithm) -> Result<Box<dyn AeadWithMetadata>> {
        // First try direct constructors
        #[cfg(feature = "std")]
        {
            let constructors = self.constructors.read().map_err(|_| Error::InvalidState {
                operation: "create_aead".to_string(),
                reason: "Failed to acquire read lock".to_string(),
            })?;
            if let Some(constructor) = constructors.get(&algorithm) {
                return constructor();
            }
        }
        #[cfg(not(feature = "std"))]
        {
            let constructors = self.constructors.borrow();
            if let Some(constructor) = constructors.get(&algorithm) {
                return constructor();
            }
        }

        // Then try plugins
        #[cfg(feature = "std")]
        {
            let plugins = self.plugins.read().map_err(|_| Error::InvalidState {
                operation: "create_aead".to_string(),
                reason: "Failed to acquire read lock".to_string(),
            })?;
            for plugin in plugins.iter() {
                if plugin.algorithm() == algorithm {
                    return plugin.create();
                }
            }
        }
        #[cfg(not(feature = "std"))]
        {
            let plugins = self.plugins.borrow();
            for plugin in plugins.iter() {
                if plugin.algorithm() == algorithm {
                    return plugin.create();
                }
            }
        }

        Err(Error::UnsupportedAlgorithm {
            algorithm: "Algorithm not registered".to_string(),
        })
    }

    /// Get available algorithms
    pub fn available_algorithms(&self) -> Vec<Algorithm> {
        let mut algorithms = Vec::new();

        // Add algorithms from constructors
        #[cfg(feature = "std")]
        {
            if let Ok(constructors) = self.constructors.read() {
                algorithms.extend(constructors.keys().copied());
            }
        }
        #[cfg(not(feature = "std"))]
        {
            let constructors = self.constructors.borrow();
            algorithms.extend(constructors.keys().copied());
        }

        // Add algorithms from plugins
        #[cfg(feature = "std")]
        {
            if let Ok(plugins) = self.plugins.read() {
                for plugin in plugins.iter() {
                    let algorithm = plugin.algorithm();
                    if !algorithms.contains(&algorithm) {
                        algorithms.push(algorithm);
                    }
                }
            }
        }
        #[cfg(not(feature = "std"))]
        {
            let plugins = self.plugins.borrow();
            for plugin in plugins.iter() {
                let algorithm = plugin.algorithm();
                if !algorithms.contains(&algorithm) {
                    algorithms.push(algorithm);
                }
            }
        }

        algorithms.sort();
        algorithms
    }

    /// Check if an algorithm is available
    pub fn is_available(&self, algorithm: Algorithm) -> bool {
        // Check constructors
        #[cfg(feature = "std")]
        {
            if let Ok(constructors) = self.constructors.read() &&
                constructors.contains_key(&algorithm)
            {
                return true;
            }
        }
        #[cfg(not(feature = "std"))]
        {
            let constructors = self.constructors.borrow();
            if constructors.contains_key(&algorithm) {
                return true;
            }
        }

        // Check plugins
        #[cfg(feature = "std")]
        {
            if let Ok(plugins) = self.plugins.read() {
                for plugin in plugins.iter() {
                    if plugin.algorithm() == algorithm {
                        return true;
                    }
                }
            }
        }
        #[cfg(not(feature = "std"))]
        {
            let plugins = self.plugins.borrow();
            for plugin in plugins.iter() {
                if plugin.algorithm() == algorithm {
                    return true;
                }
            }
        }

        false
    }

    /// Get algorithm metadata
    pub fn get_metadata(&self, algorithm: Algorithm) -> Option<&'static AeadMetadata> {
        self.metadata.get(&algorithm).copied()
    }

    /// Get all registered algorithms with their metadata
    pub fn get_all_metadata(&self) -> Vec<&'static AeadMetadata> {
        let available = self.available_algorithms();
        available
            .iter()
            .filter_map(|&algorithm| self.get_metadata(algorithm))
            .collect()
    }
}

impl Default for AeadRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use lib_q_core::{
        Aead,
        AeadKey,
        Nonce,
    };

    use super::*;

    // Mock AEAD implementation for testing
    struct MockAead {
        algorithm: Algorithm,
    }

    impl Aead for MockAead {
        fn encrypt(
            &self,
            _key: &AeadKey,
            _nonce: &Nonce,
            _plaintext: &[u8],
            _associated_data: Option<&[u8]>,
        ) -> Result<Vec<u8>> {
            Ok(alloc::vec![1, 2, 3, 4])
        }

        fn decrypt(
            &self,
            _key: &AeadKey,
            _nonce: &Nonce,
            _ciphertext: &[u8],
            _associated_data: Option<&[u8]>,
        ) -> Result<Vec<u8>> {
            Ok(alloc::vec![5, 6, 7, 8])
        }
    }

    impl AeadWithMetadata for MockAead {
        fn metadata(&self) -> &'static AeadMetadata {
            crate::metadata::get_metadata(self.algorithm).expect("Metadata not found")
        }
    }

    #[test]
    fn test_registry_creation() {
        let registry = AeadRegistry::new();
        assert!(registry.available_algorithms().is_empty());
    }

    #[test]
    fn test_algorithm_registration() {
        let registry = AeadRegistry::new();

        let result = registry.register_algorithm(Algorithm::Saturnin, || {
            Ok(Box::new(MockAead {
                algorithm: Algorithm::Saturnin,
            }) as Box<dyn AeadWithMetadata>)
        });

        assert!(result.is_ok());
        assert!(registry.is_available(Algorithm::Saturnin));
        assert!(
            registry
                .available_algorithms()
                .contains(&Algorithm::Saturnin)
        );
    }

    #[test]
    fn test_algorithm_creation() {
        let registry = AeadRegistry::new();

        registry
            .register_algorithm(Algorithm::Saturnin, || {
                Ok(Box::new(MockAead {
                    algorithm: Algorithm::Saturnin,
                }) as Box<dyn AeadWithMetadata>)
            })
            .unwrap();

        let aead = registry.create_aead(Algorithm::Saturnin);
        assert!(aead.is_ok());
    }

    #[test]
    fn test_invalid_algorithm_registration() {
        let registry = AeadRegistry::new();

        let result = registry.register_algorithm(Algorithm::MlKem512, || {
            Ok(Box::new(MockAead {
                algorithm: Algorithm::MlKem512,
            }) as Box<dyn AeadWithMetadata>)
        });

        assert!(result.is_err());
        if let Err(Error::InvalidAlgorithm { algorithm }) = result {
            assert!(algorithm.contains("not an AEAD algorithm"));
        } else {
            panic!("Expected InvalidAlgorithm error");
        }
    }

    #[test]
    fn test_metadata_retrieval() {
        let registry = AeadRegistry::new();

        let metadata = registry.get_metadata(Algorithm::Saturnin);
        assert!(metadata.is_some());

        if let Some(meta) = metadata {
            assert_eq!(meta.algorithm, Algorithm::Saturnin);
            assert_eq!(meta.name, "Saturnin");
            assert!(meta.key_size > 0);
            assert!(meta.nonce_size > 0);
            assert!(meta.tag_size > 0);
        }
    }

    #[test]
    fn test_unsupported_algorithm() {
        let registry = AeadRegistry::new();

        let result = registry.create_aead(Algorithm::Shake256Aead);
        assert!(result.is_err());

        if let Err(Error::UnsupportedAlgorithm { algorithm }) = result {
            assert!(algorithm.contains("not registered"));
        } else {
            panic!("Expected UnsupportedAlgorithm error");
        }
    }
}
