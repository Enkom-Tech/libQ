//! Algorithm registry for lib-Q
//!
//! This module provides a centralized registry of all supported algorithms,
//! eliminating the need for manual enumeration and providing better maintainability.

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap as HashMap;
#[cfg(feature = "alloc")]
use alloc::string::ToString;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "std")]
#[allow(clippy::disallowed_types)]
use std::collections::HashMap;

use crate::{
    Algorithm,
    AlgorithmCategory,
    Result,
};

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
    #[allow(clippy::disallowed_types)]
    algorithms: HashMap<Algorithm, AlgorithmMetadata>,
}

impl AlgorithmRegistry {
    /// Create a new algorithm registry
    pub fn new() -> Self {
        let mut registry = Self {
            #[allow(clippy::disallowed_types)]
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

        // CB-KEM algorithms
        self.register(AlgorithmMetadata {
            algorithm: Algorithm::CbKem348864,
            category: AlgorithmCategory::Kem,
            security_level: 1,
            name: "CB-KEM 348864",
            description: "CB-KEM Level 1 (128-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::CbKem460896,
            category: AlgorithmCategory::Kem,
            security_level: 3,
            name: "CB-KEM 460896",
            description: "CB-KEM Level 3 (192-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::CbKem6688128,
            category: AlgorithmCategory::Kem,
            security_level: 4,
            name: "CB-KEM 6688128",
            description: "CB-KEM Level 4 (256-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::CbKem6960119,
            category: AlgorithmCategory::Kem,
            security_level: 4,
            name: "CB-KEM 6960119",
            description: "CB-KEM Level 4 (256-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::CbKem8192128,
            category: AlgorithmCategory::Kem,
            security_level: 5,
            name: "CB-KEM 8192128",
            description: "CB-KEM Level 5 (256-bit security, higher performance)",
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

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::Dawn,
            category: AlgorithmCategory::Kem,
            security_level: 1,
            name: "DAWN",
            description: "DAWN - NTRU-based encryption with double encoding for smaller/faster ciphertexts",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::Rcpkc,
            category: AlgorithmCategory::Kem,
            security_level: 4,
            name: "RCPKC",
            description: "RCPKC - Randomized Concatenated Public Key Cryptography for enhanced security",
            enabled: true,
        });

        // Signature algorithms
        self.register(AlgorithmMetadata {
            algorithm: Algorithm::MlDsa44,
            category: AlgorithmCategory::Signature,
            security_level: 1,
            name: "MlDsa44",
            description: "ML-DSA Level 1 (128-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::MlDsa65,
            category: AlgorithmCategory::Signature,
            security_level: 3,
            name: "MlDsa65",
            description: "ML-DSA Level 3 (192-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::MlDsa87,
            category: AlgorithmCategory::Signature,
            security_level: 4,
            name: "MlDsa87",
            description: "ML-DSA Level 4 (256-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::FnDsa,
            category: AlgorithmCategory::Signature,
            security_level: 1,
            name: "FN-DSA",
            description: "FN-DSA (FIPS 206) - Fast Fourier Transform over NTRU-Lattice-Based Digital Signature Algorithm",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::FnDsa512,
            category: AlgorithmCategory::Signature,
            security_level: 1,
            name: "FN-DSA-512",
            description: "FN-DSA Level 1 (128-bit security) - n=512",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::FnDsa1024,
            category: AlgorithmCategory::Signature,
            security_level: 5,
            name: "FN-DSA-1024",
            description: "FN-DSA Level 5 (256-bit security) - n=1024",
            enabled: true,
        });

        // SLH-DSA algorithms
        self.register(AlgorithmMetadata {
            algorithm: Algorithm::SlhDsaSha256128fRobust,
            category: AlgorithmCategory::Signature,
            security_level: 1,
            name: "SLH-DSA-SHA256-128f-Robust",
            description: "SLH-DSA SHA256 Level 1 (128-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::SlhDsaSha256192fRobust,
            category: AlgorithmCategory::Signature,
            security_level: 3,
            name: "SLH-DSA-SHA256-192f-Robust",
            description: "SLH-DSA SHA256 Level 3 (192-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::SlhDsaSha256256fRobust,
            category: AlgorithmCategory::Signature,
            security_level: 4,
            name: "SLH-DSA-SHA256-256f-Robust",
            description: "SLH-DSA SHA256 Level 4 (256-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::SlhDsaShake256128fRobust,
            category: AlgorithmCategory::Signature,
            security_level: 1,
            name: "SLH-DSA-SHAKE256-128f-Robust",
            description: "SLH-DSA SHAKE256 Level 1 (128-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::SlhDsaShake256192fRobust,
            category: AlgorithmCategory::Signature,
            security_level: 3,
            name: "SLH-DSA-SHAKE256-192f-Robust",
            description: "SLH-DSA SHAKE256 Level 3 (192-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::SlhDsaShake256256fRobust,
            category: AlgorithmCategory::Signature,
            security_level: 4,
            name: "SLH-DSA-SHAKE256-256f-Robust",
            description: "SLH-DSA SHAKE256 Level 4 (256-bit security)",
            enabled: true,
        });

        // ML-DSA algorithms
        self.register(AlgorithmMetadata {
            algorithm: Algorithm::MlDsa44,
            category: AlgorithmCategory::Signature,
            security_level: 1,
            name: "ML-DSA-44",
            description: "CRYSTALS-ML-DSA Level 1 (128-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::MlDsa65,
            category: AlgorithmCategory::Signature,
            security_level: 3,
            name: "ML-DSA-65",
            description: "CRYSTALS-ML-DSA Level 3 (192-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::MlDsa87,
            category: AlgorithmCategory::Signature,
            security_level: 4,
            name: "ML-DSA-87",
            description: "CRYSTALS-ML-DSA Level 4 (256-bit security)",
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

        // Keccak algorithms
        self.register(AlgorithmMetadata {
            algorithm: Algorithm::Keccak224,
            category: AlgorithmCategory::Hash,
            security_level: 0,
            name: "Keccak-224",
            description: "Keccak-224 hash function",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::Keccak256,
            category: AlgorithmCategory::Hash,
            security_level: 0,
            name: "Keccak-256",
            description: "Keccak-256 hash function",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::Keccak384,
            category: AlgorithmCategory::Hash,
            security_level: 0,
            name: "Keccak-384",
            description: "Keccak-384 hash function",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::Keccak512,
            category: AlgorithmCategory::Hash,
            security_level: 0,
            name: "Keccak-512",
            description: "Keccak-512 hash function",
            enabled: true,
        });

        // KangarooTwelve algorithm
        self.register(AlgorithmMetadata {
            algorithm: Algorithm::KangarooTwelve,
            category: AlgorithmCategory::Hash,
            security_level: 0,
            name: "KangarooTwelve",
            description: "KangarooTwelve hash function (KT128 variant)",
            enabled: true,
        });

        // SHA-2 algorithms
        self.register(AlgorithmMetadata {
            algorithm: Algorithm::Sha224,
            category: AlgorithmCategory::Hash,
            security_level: 0,
            name: "SHA-224",
            description: "SHA-224 hash function",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::Sha256,
            category: AlgorithmCategory::Hash,
            security_level: 0,
            name: "SHA-256",
            description: "SHA-256 hash function",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::Sha384,
            category: AlgorithmCategory::Hash,
            security_level: 0,
            name: "SHA-384",
            description: "SHA-384 hash function",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::Sha512,
            category: AlgorithmCategory::Hash,
            security_level: 0,
            name: "SHA-512",
            description: "SHA-512 hash function",
            enabled: true,
        });

        // TurboSHAKE algorithms
        self.register(AlgorithmMetadata {
            algorithm: Algorithm::TurboShake128,
            category: AlgorithmCategory::Hash,
            security_level: 0,
            name: "TurboSHAKE128",
            description: "TurboSHAKE128 extendable-output function",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::TurboShake256,
            category: AlgorithmCategory::Hash,
            security_level: 0,
            name: "TurboSHAKE256",
            description: "TurboSHAKE256 extendable-output function",
            enabled: true,
        });

        // AEAD algorithms
        self.register(AlgorithmMetadata {
            algorithm: Algorithm::Saturnin,
            category: AlgorithmCategory::Aead,
            security_level: 1,
            name: "Saturnin",
            description: "Saturnin - Lightweight post-quantum symmetric algorithm suite for IoT and constrained devices",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::Shake256Aead,
            category: AlgorithmCategory::Aead,
            security_level: 1,
            name: "SHAKE256-AEAD",
            description: "SHAKE256-based AEAD construction using post-quantum hash function",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::KemAead,
            category: AlgorithmCategory::Aead,
            security_level: 4,
            name: "KEM-AEAD",
            description: "KEM-based AEAD construction combining post-quantum KEM with symmetric encryption",
            enabled: true,
        });
    }

    /// Register an algorithm
    fn register(&mut self, metadata: AlgorithmMetadata) {
        self.algorithms.insert(metadata.algorithm, metadata);
    }

    /// Get all supported algorithms
    #[cfg(feature = "alloc")]
    pub fn supported_algorithms(&self) -> Vec<Algorithm> {
        self.algorithms
            .values()
            .filter(|meta| meta.enabled)
            .map(|meta| meta.algorithm)
            .collect()
    }

    #[cfg(not(feature = "alloc"))]
    pub fn supported_algorithms(&self) -> &'static [Algorithm] {
        // In no_std mode, return a static slice of enabled algorithms
        static ALGORITHMS: &[Algorithm] = &[
            Algorithm::MlKem512,
            Algorithm::MlKem768,
            Algorithm::MlKem1024,
            Algorithm::MlDsa44,
            Algorithm::MlDsa65,
            Algorithm::MlDsa87,
            Algorithm::FnDsa,
            Algorithm::FnDsa512,
            Algorithm::FnDsa1024,
        ];
        ALGORITHMS
    }

    /// Get algorithms by category
    #[cfg(feature = "alloc")]
    pub fn algorithms_by_category(&self, category: AlgorithmCategory) -> Vec<Algorithm> {
        self.algorithms
            .values()
            .filter(|meta| meta.enabled && meta.category == category)
            .map(|meta| meta.algorithm)
            .collect()
    }

    #[cfg(not(feature = "alloc"))]
    pub fn algorithms_by_category(&self, category: AlgorithmCategory) -> &'static [Algorithm] {
        // In no_std mode, return a static slice based on category
        match category {
            AlgorithmCategory::Kem => &[
                Algorithm::MlKem512,
                Algorithm::MlKem768,
                Algorithm::MlKem1024,
            ],
            AlgorithmCategory::Signature => &[
                Algorithm::MlDsa44,
                Algorithm::MlDsa65,
                Algorithm::MlDsa87,
                Algorithm::FnDsa,
                Algorithm::FnDsa512,
                Algorithm::FnDsa1024,
            ],
            AlgorithmCategory::Hash => &[
                Algorithm::Sha224,
                Algorithm::Sha256,
                Algorithm::Sha384,
                Algorithm::Sha512,
            ],
            AlgorithmCategory::Aead => &[
                Algorithm::Saturnin,
                Algorithm::Shake256Aead,
                Algorithm::KemAead,
            ],
        }
    }

    /// Get algorithms by security level
    #[cfg(feature = "alloc")]
    pub fn algorithms_by_security_level(&self, level: u32) -> Vec<Algorithm> {
        self.algorithms
            .values()
            .filter(|meta| meta.enabled && meta.security_level == level)
            .map(|meta| meta.algorithm)
            .collect()
    }

    #[cfg(not(feature = "alloc"))]
    pub fn algorithms_by_security_level(&self, level: u32) -> &'static [Algorithm] {
        // In no_std mode, return a static slice based on security level
        match level {
            1 => &[
                Algorithm::MlKem512,
                Algorithm::MlDsa44,
                Algorithm::FnDsa,
                Algorithm::FnDsa512,
                Algorithm::Saturnin,
                Algorithm::Shake256Aead,
            ],
            3 => &[Algorithm::MlKem768, Algorithm::MlDsa65],
            4 => &[Algorithm::MlKem1024, Algorithm::MlDsa87, Algorithm::KemAead],
            5 => &[Algorithm::FnDsa1024],
            _ => &[],
        }
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
            #[cfg(feature = "alloc")]
            {
                Err(crate::Error::UnsupportedAlgorithm {
                    algorithm: "unsupported algorithm".to_string(),
                })
            }
            #[cfg(not(feature = "alloc"))]
            {
                Err(crate::Error::UnsupportedAlgorithm {
                    algorithm: "unsupported algorithm",
                })
            }
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
#[cfg(feature = "alloc")]
pub fn supported_algorithms() -> Vec<Algorithm> {
    registry().supported_algorithms()
}

#[cfg(not(feature = "alloc"))]
pub fn supported_algorithms() -> &'static [Algorithm] {
    registry().supported_algorithms()
}

/// Get algorithms by category
#[cfg(feature = "alloc")]
pub fn algorithms_by_category(category: AlgorithmCategory) -> Vec<Algorithm> {
    registry().algorithms_by_category(category)
}

#[cfg(not(feature = "alloc"))]
pub fn algorithms_by_category(category: AlgorithmCategory) -> &'static [Algorithm] {
    registry().algorithms_by_category(category)
}

/// Get algorithms by security level
#[cfg(feature = "alloc")]
pub fn algorithms_by_security_level(level: u32) -> Vec<Algorithm> {
    registry().algorithms_by_security_level(level)
}

#[cfg(not(feature = "alloc"))]
pub fn algorithms_by_security_level(level: u32) -> &'static [Algorithm] {
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
