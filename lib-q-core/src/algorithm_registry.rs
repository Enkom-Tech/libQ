//! Algorithm registry for lib-Q
//!
//! This module provides a centralized registry of all supported algorithms,
//! eliminating the need for manual enumeration and providing better maintainability.

use crate::{Algorithm, AlgorithmCategory, Result};
use std::collections::HashMap;

/// Algorithm metadata
#[derive(Debug, Clone)]
pub struct AlgorithmMetadata {
    pub algorithm: Algorithm,
    pub category: AlgorithmCategory,
    pub security_level: u32,
    pub name: &'static str,
    pub description: &'static str,
    pub enabled: bool,
}

/// Central registry of all algorithms
pub struct AlgorithmRegistry {
    algorithms: HashMap<Algorithm, AlgorithmMetadata>,
}

impl AlgorithmRegistry {
    /// Create a new algorithm registry
    pub fn new() -> Self {
        let mut registry = Self {
            algorithms: HashMap::new(),
        };
        registry.register_all();
        registry
    }

    /// Register all supported algorithms
    fn register_all(&mut self) {
        // KEM algorithms
        self.register(AlgorithmMetadata {
            algorithm: Algorithm::MlKem512,
            category: AlgorithmCategory::Kem,
            security_level: 1,
            name: "ML-KEM-512",
            description: "CRYSTALS-ML-KEM Level 1 (128-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::MlKem768,
            category: AlgorithmCategory::Kem,
            security_level: 3,
            name: "ML-KEM-768",
            description: "CRYSTALS-ML-KEM Level 3 (192-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::MlKem1024,
            category: AlgorithmCategory::Kem,
            security_level: 4,
            name: "ML-KEM-1024",
            description: "CRYSTALS-ML-KEM Level 4 (256-bit security)",
            enabled: true,
        });

        // McEliece algorithms
        self.register(AlgorithmMetadata {
            algorithm: Algorithm::McEliece348864,
            category: AlgorithmCategory::Kem,
            security_level: 1,
            name: "Classic McEliece 348864",
            description: "Classic McEliece Level 1 (128-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::McEliece460896,
            category: AlgorithmCategory::Kem,
            security_level: 3,
            name: "Classic McEliece 460896",
            description: "Classic McEliece Level 3 (192-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::McEliece6688128,
            category: AlgorithmCategory::Kem,
            security_level: 4,
            name: "Classic McEliece 6688128",
            description: "Classic McEliece Level 4 (256-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::McEliece6960119,
            category: AlgorithmCategory::Kem,
            security_level: 4,
            name: "Classic McEliece 6960119",
            description: "Classic McEliece Level 4 (256-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::McEliece8192128,
            category: AlgorithmCategory::Kem,
            security_level: 5,
            name: "Classic McEliece 8192128",
            description: "Classic McEliece Level 5 (256-bit security, higher performance)",
            enabled: true,
        });

        // HQC algorithms
        self.register(AlgorithmMetadata {
            algorithm: Algorithm::Hqc128,
            category: AlgorithmCategory::Kem,
            security_level: 1,
            name: "HQC-128",
            description: "HQC Level 1 (128-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::Hqc192,
            category: AlgorithmCategory::Kem,
            security_level: 3,
            name: "HQC-192",
            description: "HQC Level 3 (192-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::Hqc256,
            category: AlgorithmCategory::Kem,
            security_level: 4,
            name: "HQC-256",
            description: "HQC Level 4 (256-bit security)",
            enabled: true,
        });

        // Signature algorithms
        self.register(AlgorithmMetadata {
            algorithm: Algorithm::Dilithium2,
            category: AlgorithmCategory::Signature,
            security_level: 1,
            name: "Dilithium2",
            description: "CRYSTALS-Dilithium Level 1 (128-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::Dilithium3,
            category: AlgorithmCategory::Signature,
            security_level: 3,
            name: "Dilithium3",
            description: "CRYSTALS-Dilithium Level 3 (192-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::Dilithium5,
            category: AlgorithmCategory::Signature,
            security_level: 4,
            name: "Dilithium5",
            description: "CRYSTALS-Dilithium Level 4 (256-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::Falcon512,
            category: AlgorithmCategory::Signature,
            security_level: 1,
            name: "Falcon-512",
            description: "Falcon Level 1 (128-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::Falcon1024,
            category: AlgorithmCategory::Signature,
            security_level: 3,
            name: "Falcon-1024",
            description: "Falcon Level 3 (192-bit security)",
            enabled: true,
        });

        // SPHINCS+ algorithms
        self.register(AlgorithmMetadata {
            algorithm: Algorithm::SphincsSha256128fRobust,
            category: AlgorithmCategory::Signature,
            security_level: 1,
            name: "SPHINCS+-SHA256-128f-Robust",
            description: "SPHINCS+ SHA256 Level 1 (128-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::SphincsSha256192fRobust,
            category: AlgorithmCategory::Signature,
            security_level: 3,
            name: "SPHINCS+-SHA256-192f-Robust",
            description: "SPHINCS+ SHA256 Level 3 (192-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::SphincsSha256256fRobust,
            category: AlgorithmCategory::Signature,
            security_level: 4,
            name: "SPHINCS+-SHA256-256f-Robust",
            description: "SPHINCS+ SHA256 Level 4 (256-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::SphincsShake256128fRobust,
            category: AlgorithmCategory::Signature,
            security_level: 1,
            name: "SPHINCS+-SHAKE256-128f-Robust",
            description: "SPHINCS+ SHAKE256 Level 1 (128-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::SphincsShake256192fRobust,
            category: AlgorithmCategory::Signature,
            security_level: 3,
            name: "SPHINCS+-SHAKE256-192f-Robust",
            description: "SPHINCS+ SHAKE256 Level 3 (192-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::SphincsShake256256fRobust,
            category: AlgorithmCategory::Signature,
            security_level: 4,
            name: "SPHINCS+-SHAKE256-256f-Robust",
            description: "SPHINCS+ SHAKE256 Level 4 (256-bit security)",
            enabled: true,
        });

        // Hash algorithms
        self.register(AlgorithmMetadata {
            algorithm: Algorithm::Shake128,
            category: AlgorithmCategory::Hash,
            security_level: 0,
            name: "SHAKE128",
            description: "SHAKE128 hash function",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::Shake256,
            category: AlgorithmCategory::Hash,
            security_level: 0,
            name: "SHAKE256",
            description: "SHAKE256 hash function",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::CShake128,
            category: AlgorithmCategory::Hash,
            security_level: 0,
            name: "cSHAKE128",
            description: "cSHAKE128 customizable hash function",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::CShake256,
            category: AlgorithmCategory::Hash,
            security_level: 0,
            name: "cSHAKE256",
            description: "cSHAKE256 customizable hash function",
            enabled: true,
        });

        // SHA-3 algorithms
        self.register(AlgorithmMetadata {
            algorithm: Algorithm::Sha3_224,
            category: AlgorithmCategory::Hash,
            security_level: 0,
            name: "SHA3-224",
            description: "SHA3-224 hash function",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::Sha3_256,
            category: AlgorithmCategory::Hash,
            security_level: 0,
            name: "SHA3-256",
            description: "SHA3-256 hash function",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::Sha3_384,
            category: AlgorithmCategory::Hash,
            security_level: 0,
            name: "SHA3-384",
            description: "SHA3-384 hash function",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::Sha3_512,
            category: AlgorithmCategory::Hash,
            security_level: 0,
            name: "SHA3-512",
            description: "SHA3-512 hash function",
            enabled: true,
        });

        // KMAC algorithms
        self.register(AlgorithmMetadata {
            algorithm: Algorithm::Kmac128,
            category: AlgorithmCategory::Hash,
            security_level: 0,
            name: "KMAC128",
            description: "KMAC128 keyed hash function",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::Kmac256,
            category: AlgorithmCategory::Hash,
            security_level: 0,
            name: "KMAC256",
            description: "KMAC256 keyed hash function",
            enabled: true,
        });

        // TupleHash algorithms
        self.register(AlgorithmMetadata {
            algorithm: Algorithm::TupleHash128,
            category: AlgorithmCategory::Hash,
            security_level: 0,
            name: "TupleHash128",
            description: "TupleHash128 tuple hashing",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::TupleHash256,
            category: AlgorithmCategory::Hash,
            security_level: 0,
            name: "TupleHash256",
            description: "TupleHash256 tuple hashing",
            enabled: true,
        });

        // ParallelHash algorithms
        self.register(AlgorithmMetadata {
            algorithm: Algorithm::ParallelHash128,
            category: AlgorithmCategory::Hash,
            security_level: 0,
            name: "ParallelHash128",
            description: "ParallelHash128 parallel hashing",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::ParallelHash256,
            category: AlgorithmCategory::Hash,
            security_level: 0,
            name: "ParallelHash256",
            description: "ParallelHash256 parallel hashing",
            enabled: true,
        });
    }

    /// Register an algorithm
    fn register(&mut self, metadata: AlgorithmMetadata) {
        self.algorithms.insert(metadata.algorithm.clone(), metadata);
    }

    /// Get all supported algorithms
    pub fn supported_algorithms(&self) -> Vec<Algorithm> {
        self.algorithms
            .values()
            .filter(|meta| meta.enabled)
            .map(|meta| meta.algorithm.clone())
            .collect()
    }

    /// Get algorithms by category
    pub fn algorithms_by_category(&self, category: AlgorithmCategory) -> Vec<Algorithm> {
        self.algorithms
            .values()
            .filter(|meta| meta.enabled && meta.category == category)
            .map(|meta| meta.algorithm.clone())
            .collect()
    }

    /// Get algorithms by security level
    pub fn algorithms_by_security_level(&self, level: u32) -> Vec<Algorithm> {
        self.algorithms
            .values()
            .filter(|meta| meta.enabled && meta.security_level == level)
            .map(|meta| meta.algorithm.clone())
            .collect()
    }

    /// Get algorithm metadata
    pub fn get_metadata(&self, algorithm: &Algorithm) -> Option<&AlgorithmMetadata> {
        self.algorithms.get(algorithm)
    }

    /// Check if algorithm is enabled
    pub fn is_enabled(&self, algorithm: &Algorithm) -> bool {
        self.algorithms
            .get(algorithm)
            .map(|meta| meta.enabled)
            .unwrap_or(false)
    }

    /// Enable/disable an algorithm
    pub fn set_enabled(&mut self, algorithm: Algorithm, enabled: bool) -> Result<()> {
        if let Some(metadata) = self.algorithms.get_mut(&algorithm) {
            metadata.enabled = enabled;
            Ok(())
        } else {
            Err(crate::Error::UnsupportedAlgorithm {
                algorithm: format!("{:?}", algorithm),
            })
        }
    }
}

impl Default for AlgorithmRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// Global algorithm registry instance
lazy_static::lazy_static! {
    static ref REGISTRY: AlgorithmRegistry = AlgorithmRegistry::new();
}

/// Get the global algorithm registry
pub fn registry() -> &'static AlgorithmRegistry {
    &REGISTRY
}

/// Get all supported algorithms
pub fn supported_algorithms() -> Vec<Algorithm> {
    registry().supported_algorithms()
}

/// Get algorithms by category
pub fn algorithms_by_category(category: AlgorithmCategory) -> Vec<Algorithm> {
    registry().algorithms_by_category(category)
}

/// Get algorithms by security level
pub fn algorithms_by_security_level(level: u32) -> Vec<Algorithm> {
    registry().algorithms_by_security_level(level)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_registry() {
        let registry = AlgorithmRegistry::new();

        // Test that we have algorithms
        let algorithms = registry.supported_algorithms();
        assert!(!algorithms.is_empty());

        // Test category filtering
        let kem_algorithms = registry.algorithms_by_category(AlgorithmCategory::Kem);
        assert!(!kem_algorithms.is_empty());

        // Test security level filtering
        let level1_algorithms = registry.algorithms_by_security_level(1);
        assert!(!level1_algorithms.is_empty());

        // Test metadata retrieval
        let metadata = registry.get_metadata(&Algorithm::MlKem512);
        assert!(metadata.is_some());
        assert_eq!(metadata.unwrap().name, "ML-KEM-512");
    }

    #[test]
    fn test_global_registry() {
        let algorithms = supported_algorithms();
        assert!(!algorithms.is_empty());

        let kem_algorithms = algorithms_by_category(AlgorithmCategory::Kem);
        assert!(!kem_algorithms.is_empty());
    }
}
