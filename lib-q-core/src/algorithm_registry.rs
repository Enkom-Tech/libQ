//! Algorithm registry for lib-Q
//!
//! This module provides a centralized registry of all supported algorithms,
//! eliminating the need for manual enumeration and providing better maintainability.

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::collections::BTreeMap as HashMap;
#[cfg(feature = "alloc")]
use alloc::string::ToString;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "std")]
#[allow(clippy::disallowed_types)]
use std::collections::HashMap;

#[cfg(any(feature = "std", feature = "alloc"))]
use crate::Result;
use crate::{
    Algorithm,
    AlgorithmCategory,
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
#[cfg(any(feature = "std", feature = "alloc"))]
pub struct AlgorithmRegistry {
    #[allow(clippy::disallowed_types)]
    algorithms: HashMap<Algorithm, AlgorithmMetadata>,
}

#[cfg(any(feature = "std", feature = "alloc"))]
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
            security_level: 5,
            name: "ML-KEM-1024",
            description: "CRYSTALS-ML-KEM Level 5 (256-bit security)",
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
            security_level: 5,
            name: "CB-KEM 6688128",
            description: "CB-KEM Level 5 (256-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::CbKem6960119,
            category: AlgorithmCategory::Kem,
            security_level: 5,
            name: "CB-KEM 6960119",
            description: "CB-KEM Level 5 (256-bit security)",
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
            security_level: 5,
            name: "HQC-256",
            description: "HQC Level 5 (256-bit security)",
            enabled: true,
        });

        // Signature algorithms
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
            security_level: 5,
            name: "ML-DSA-87",
            description: "CRYSTALS-ML-DSA Level 5 (256-bit security)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::FnDsa,
            category: AlgorithmCategory::Signature,
            security_level: 1,
            name: "FN-DSA",
            description: "FN-DSA (NIST-selected; FIPS 206 not yet published) - Fast Fourier Transform over NTRU-Lattice-Based Digital Signature Algorithm",
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
            security_level: 5,
            name: "SLH-DSA-SHA256-256f-Robust",
            description: "SLH-DSA SHA256 Level 5 (256-bit security)",
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
            security_level: 5,
            name: "SLH-DSA-SHAKE256-256f-Robust",
            description: "SLH-DSA SHAKE256 Level 5 (256-bit security)",
            enabled: true,
        });

        // Reserved diversity signature: registered but DISABLED. FAEST (VOLE-in-the-Head) rests on
        // symmetric-only assumptions — a hedge against a structured-lattice break of ML-DSA. Large
        // and slow vs ML-DSA, so never a default; activate only on a lattice-cryptanalysis event.
        // Identifier only (no implementation). Supersedes Picnic. See lib-q-sig/docs/FAEST_EVALUATION.md.
        self.register(AlgorithmMetadata {
            algorithm: Algorithm::FaestReserved,
            category: AlgorithmCategory::Signature,
            security_level: 3,
            name: "FAEST-Reserved",
            description: "RESERVED FAEST/VOLE-in-the-Head diversity signature (symmetric assumptions); disabled — activate only on a lattice-cryptanalysis event",
            enabled: false,
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

        // RFC 9861 KangarooTwelve instances
        self.register(AlgorithmMetadata {
            algorithm: Algorithm::Kt128,
            category: AlgorithmCategory::Hash,
            security_level: 0,
            name: "KT128",
            description: "KangarooTwelve with TurboSHAKE128 (RFC 9861)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::Kt256,
            category: AlgorithmCategory::Hash,
            security_level: 0,
            name: "KT256",
            description: "KangarooTwelve with TurboSHAKE256 (RFC 9861)",
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

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::Sha512_224,
            category: AlgorithmCategory::Hash,
            security_level: 0,
            name: "SHA-512/224",
            description: "SHA-512/224 hash function (truncated)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::Sha512_256,
            category: AlgorithmCategory::Hash,
            security_level: 0,
            name: "SHA-512/256",
            description: "SHA-512/256 hash function (truncated)",
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
            algorithm: Algorithm::DuplexSpongeAead,
            category: AlgorithmCategory::Aead,
            security_level: 4,
            name: "Duplex-Sponge-AEAD",
            description: "Keccak-f[1600] duplex-sponge authenticated encryption (SHA-3 family permutation)",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::TweakAead,
            category: AlgorithmCategory::Aead,
            security_level: 4,
            name: "Tweak-AEAD",
            description: "Parallel tweakable-block CTR AEAD over Keccak-f[1600] with independent 32-byte blocks",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::RomulusN,
            category: AlgorithmCategory::Aead,
            security_level: 1,
            name: "Romulus-N",
            description: "Romulus-N nonce-based AEAD (SKINNY-128-384+), LWC v1.3",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::RomulusM,
            category: AlgorithmCategory::Aead,
            security_level: 1,
            name: "Romulus-M",
            description: "Romulus-M misuse-resistant AEAD (SKINNY-128-384+), LWC v1.3",
            enabled: true,
        });

        self.register(AlgorithmMetadata {
            algorithm: Algorithm::RoccaS,
            category: AlgorithmCategory::Aead,
            security_level: 1,
            name: "Rocca-S",
            description: "Rocca-S high-throughput AES-round AEAD (IETF draft-nakano-rocca-s); 256-bit key/tag, 128-bit nonce",
            enabled: true,
        });

        // Privacy-oriented protocol identifiers (implementations: lib-q-lattice-zkp, lib-q-ring-sig)
        self.register(AlgorithmMetadata {
            algorithm: Algorithm::LatticeRingSignature,
            category: AlgorithmCategory::PrivacyProtocol,
            security_level: 3,
            name: "Lattice federation ring signature",
            description: "Federation ring-style opening proofs over Ajtai commitments (lib-q-ring-sig)",
            enabled: true,
        });
        self.register(AlgorithmMetadata {
            algorithm: Algorithm::LatticeBlindIssuance,
            category: AlgorithmCategory::PrivacyProtocol,
            security_level: 3,
            name: "Lattice blind issuance",
            description: "CRS blind issuance plumbing and issuer attestation (lib-q-lattice-zkp/blind)",
            enabled: true,
        });
        self.register(AlgorithmMetadata {
            algorithm: Algorithm::LatticeAnonymousToken,
            category: AlgorithmCategory::PrivacyProtocol,
            security_level: 3,
            name: "Lattice anonymous token",
            description: "Commitment-backed anonymous token and spending proof (lib-q-lattice-zkp/token)",
            enabled: true,
        });
        self.register(AlgorithmMetadata {
            algorithm: Algorithm::LatticeNullifierRegistry,
            category: AlgorithmCategory::PrivacyProtocol,
            security_level: 3,
            name: "Lattice nullifier registry",
            description: "SHAKE256 nullifier binding for Sybil-evidence style proofs (lib-q-lattice-zkp/sigma/uniqueness)",
            enabled: true,
        });
        self.register(AlgorithmMetadata {
            algorithm: Algorithm::LatticeWitnessNullifier,
            category: AlgorithmCategory::PrivacyProtocol,
            security_level: 3,
            name: "Lattice witness nullifier",
            description: "Witness-derived SHAKE256 nullifier and opening binding (lib-q-lattice-zkp/sigma/uniqueness)",
            enabled: true,
        });
        self.register(AlgorithmMetadata {
            algorithm: Algorithm::LatticeDualRingLb,
            category: AlgorithmCategory::PrivacyProtocol,
            security_level: 3,
            name: "Lattice DualRing-LB pilot",
            description: "DualRing-LB (CCS 2021 Alg. 3) aggregated opening verify over Ajtai ring (lib-q-ring-sig/dualring_lb)",
            enabled: true,
        });
        self.register(AlgorithmMetadata {
            algorithm: Algorithm::MixOnionRouting,
            category: AlgorithmCategory::PrivacyProtocol,
            security_level: 3,
            name: "Mix-layer onion routing",
            description: "ML-KEM-768 layered encapsulation with Saturnin AEAD per hop",
            enabled: true,
        });
        self.register(AlgorithmMetadata {
            algorithm: Algorithm::SessionResumptionBinding,
            category: AlgorithmCategory::PrivacyProtocol,
            security_level: 3,
            name: "Session resumption binding",
            description: "SHAKE256 session token and stateless retry-cookie derivation",
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
                Algorithm::Sha512_224,
                Algorithm::Sha512_256,
            ],
            AlgorithmCategory::Aead => &[
                Algorithm::Saturnin,
                Algorithm::Shake256Aead,
                Algorithm::DuplexSpongeAead,
                Algorithm::TweakAead,
                Algorithm::RomulusN,
                Algorithm::RomulusM,
            ],
            AlgorithmCategory::PrivacyProtocol => &[
                Algorithm::LatticeRingSignature,
                Algorithm::LatticeBlindIssuance,
                Algorithm::LatticeAnonymousToken,
                Algorithm::LatticeNullifierRegistry,
                Algorithm::LatticeWitnessNullifier,
                Algorithm::LatticeDualRingLb,
                Algorithm::MixOnionRouting,
                Algorithm::SessionResumptionBinding,
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
                Algorithm::RomulusN,
                Algorithm::RomulusM,
            ],
            3 => &[
                Algorithm::MlKem768,
                Algorithm::MlDsa65,
                Algorithm::LatticeRingSignature,
                Algorithm::LatticeBlindIssuance,
                Algorithm::LatticeAnonymousToken,
                Algorithm::LatticeNullifierRegistry,
                Algorithm::LatticeWitnessNullifier,
                Algorithm::LatticeDualRingLb,
                Algorithm::MixOnionRouting,
                Algorithm::SessionResumptionBinding,
            ],
            4 => &[Algorithm::DuplexSpongeAead, Algorithm::TweakAead],
            5 => &[
                Algorithm::MlKem1024,
                Algorithm::MlDsa87,
                Algorithm::FnDsa1024,
            ],
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

#[cfg(any(feature = "std", feature = "alloc"))]
impl Default for AlgorithmRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// Global algorithm registry instance
// Note: AlgorithmRegistry requires alloc (uses HashMap/BTreeMap)
#[cfg(all(feature = "alloc", feature = "std"))]
static REGISTRY: once_cell::sync::Lazy<AlgorithmRegistry> =
    once_cell::sync::Lazy::new(AlgorithmRegistry::new);

#[cfg(all(feature = "alloc", not(feature = "std"), feature = "spin"))]
static REGISTRY: spin::Once<AlgorithmRegistry> = spin::Once::new();

/// Get the global algorithm registry
/// Requires alloc feature (registry uses HashMap/BTreeMap internally)
#[cfg(all(feature = "alloc", feature = "std"))]
pub fn registry() -> &'static AlgorithmRegistry {
    &REGISTRY
}

#[cfg(all(feature = "alloc", not(feature = "std"), feature = "spin"))]
pub fn registry() -> &'static AlgorithmRegistry {
    REGISTRY.call_once(AlgorithmRegistry::new)
}

// registry() is not available in no_alloc mode
// Use supported_algorithms() etc. which return static slices directly

/// Get all supported algorithms
#[cfg(all(feature = "alloc", any(feature = "std", feature = "spin")))]
pub fn supported_algorithms() -> Vec<Algorithm> {
    registry().supported_algorithms()
}

#[cfg(all(feature = "alloc", not(any(feature = "std", feature = "spin"))))]
pub fn supported_algorithms() -> Vec<Algorithm> {
    AlgorithmRegistry::new().supported_algorithms()
}

#[cfg(not(feature = "alloc"))]
pub fn supported_algorithms() -> &'static [Algorithm] {
    // In no_alloc mode, return static slice directly without using registry
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
#[cfg(all(feature = "alloc", any(feature = "std", feature = "spin")))]
pub fn algorithms_by_category(category: AlgorithmCategory) -> Vec<Algorithm> {
    registry().algorithms_by_category(category)
}

#[cfg(all(feature = "alloc", not(any(feature = "std", feature = "spin"))))]
pub fn algorithms_by_category(category: AlgorithmCategory) -> Vec<Algorithm> {
    AlgorithmRegistry::new().algorithms_by_category(category)
}

#[cfg(not(feature = "alloc"))]
pub fn algorithms_by_category(category: AlgorithmCategory) -> &'static [Algorithm] {
    // In no_alloc mode, return static slice directly without using registry
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
            Algorithm::DuplexSpongeAead,
            Algorithm::TweakAead,
            Algorithm::RomulusN,
            Algorithm::RomulusM,
        ],
        AlgorithmCategory::PrivacyProtocol => &[
            Algorithm::LatticeRingSignature,
            Algorithm::LatticeBlindIssuance,
            Algorithm::LatticeAnonymousToken,
            Algorithm::LatticeNullifierRegistry,
            Algorithm::LatticeWitnessNullifier,
            Algorithm::LatticeDualRingLb,
            Algorithm::MixOnionRouting,
            Algorithm::SessionResumptionBinding,
        ],
    }
}

/// Get algorithms by security level
#[cfg(all(feature = "alloc", any(feature = "std", feature = "spin")))]
pub fn algorithms_by_security_level(level: u32) -> Vec<Algorithm> {
    registry().algorithms_by_security_level(level)
}

#[cfg(all(feature = "alloc", not(any(feature = "std", feature = "spin"))))]
pub fn algorithms_by_security_level(level: u32) -> Vec<Algorithm> {
    AlgorithmRegistry::new().algorithms_by_security_level(level)
}

#[cfg(not(feature = "alloc"))]
pub fn algorithms_by_security_level(level: u32) -> &'static [Algorithm] {
    // In no_alloc mode, return static slice directly without using registry
    match level {
        1 => &[
            Algorithm::MlKem512,
            Algorithm::MlDsa44,
            Algorithm::FnDsa,
            Algorithm::FnDsa512,
            Algorithm::Saturnin,
            Algorithm::Shake256Aead,
            Algorithm::RomulusN,
            Algorithm::RomulusM,
        ],
        3 => &[
            Algorithm::MlKem768,
            Algorithm::MlDsa65,
            Algorithm::LatticeRingSignature,
            Algorithm::LatticeBlindIssuance,
            Algorithm::LatticeAnonymousToken,
            Algorithm::LatticeNullifierRegistry,
            Algorithm::LatticeWitnessNullifier,
            Algorithm::LatticeDualRingLb,
            Algorithm::MixOnionRouting,
            Algorithm::SessionResumptionBinding,
        ],
        4 => &[Algorithm::DuplexSpongeAead, Algorithm::TweakAead],
        5 => &[
            Algorithm::MlKem1024,
            Algorithm::MlDsa87,
            Algorithm::FnDsa1024,
        ],
        _ => &[],
    }
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

    /// Regression test for card t_e3457ac8: `security_level` must track each
    /// algorithm's own NIST PQC security category, not an ad-hoc ordinal that
    /// happens to coincide with it for most entries. Every value below is
    /// sourced from the algorithm's own specification:
    ///
    /// - ML-KEM-512/768/1024: FIPS 203 (Categories 1/3/5)
    /// - ML-DSA-65/87: FIPS 204 (Categories 3/5) — ML-DSA-44 is intentionally
    ///   excluded: FIPS 204 claims Category 2 for it but permits a documented
    ///   fallback to Category 1 with a weaker RBG, so the correct registered
    ///   value is genuinely ambiguous without knowing which RBG posture this
    ///   crate assumes (see card t_e3457ac8 follow-up notes).
    /// - FN-DSA-512/1024 (Falcon): Categories 1/5
    /// - SLH-DSA SHA256/SHAKE256 -128f/-192f/-256f: FIPS 205 Table (Categories
    ///   1/3/5; confirmed via reference/fips205/NIST.FIPS.205.pdf sections
    ///   11.2.1 "SLH-DSA Using SHA2 for Security Category 1" and 11.2.2
    ///   "...for Security Categories 3 and 5")
    /// - CB-KEM 348864/460896/6688128/6960119/8192128: Classic McEliece spec
    ///   (Categories 1/3/5/5/5 — all three "128"-suffixed parameter sets are
    ///   Category 5)
    /// - HQC-128/192/256: HQC v5.0.0 spec Table 5 "Parameter sets for HQC"
    ///   (reference/hqc-avx2/hqc_specifications_2025_08_22.pdf) — HQC-1/3/5
    ///   map directly to NIST-1/3/5
    ///
    /// A future entry registered at the wrong level will fail this test as
    /// soon as it's added to the table below alongside its registration.
    #[test]
    fn test_security_levels_match_documented_nist_category() {
        let registry = AlgorithmRegistry::new();

        let expected: &[(Algorithm, u32)] = &[
            (Algorithm::MlKem512, 1),
            (Algorithm::MlKem768, 3),
            (Algorithm::MlKem1024, 5),
            (Algorithm::CbKem348864, 1),
            (Algorithm::CbKem460896, 3),
            (Algorithm::CbKem6688128, 5),
            (Algorithm::CbKem6960119, 5),
            (Algorithm::CbKem8192128, 5),
            (Algorithm::Hqc128, 1),
            (Algorithm::Hqc192, 3),
            (Algorithm::Hqc256, 5),
            (Algorithm::MlDsa65, 3),
            (Algorithm::MlDsa87, 5),
            (Algorithm::FnDsa, 1),
            (Algorithm::FnDsa512, 1),
            (Algorithm::FnDsa1024, 5),
            (Algorithm::SlhDsaSha256128fRobust, 1),
            (Algorithm::SlhDsaSha256192fRobust, 3),
            (Algorithm::SlhDsaSha256256fRobust, 5),
            (Algorithm::SlhDsaShake256128fRobust, 1),
            (Algorithm::SlhDsaShake256192fRobust, 3),
            (Algorithm::SlhDsaShake256256fRobust, 5),
        ];

        for (algorithm, expected_level) in expected {
            let metadata = registry
                .get_metadata(algorithm)
                .unwrap_or_else(|| panic!("{algorithm:?} missing from registry"));
            assert_eq!(
                metadata.security_level, *expected_level,
                "{algorithm:?} is registered at security_level {}, but its spec claims NIST \
                 Category {expected_level}",
                metadata.security_level
            );
        }
    }

    /// The security level is stored in more than one place, and that duplication -- not the
    /// arithmetic -- is what let the wrong values survive: this registry's table, its three
    /// hand-written no_std static-slice copies, and an entirely separate hardcoded `match` in
    /// `lib_q_types::Algorithm::security_level`. Fixing one copy left the others disagreeing,
    /// silently, because nothing compared them.
    ///
    /// The test above pins the registry against the specifications. This one pins the copies
    /// against EACH OTHER, so a future edit to one of them cannot drift. It walks whatever the
    /// registry reports as supported rather than a hand-written list, so an algorithm added
    /// later is covered without anyone remembering to extend this test.
    #[test]
    fn registry_and_types_agree_on_every_security_level() {
        let registry = AlgorithmRegistry::new();
        let algorithms = registry.supported_algorithms();
        assert!(
            !algorithms.is_empty(),
            "supported_algorithms() is empty, so this test would pass while checking nothing"
        );

        let mut checked = 0usize;
        for algorithm in algorithms.iter() {
            let Some(metadata) = registry.get_metadata(algorithm) else {
                continue;
            };
            // Hashes and other entries that carry no category are registered at 0; skip them
            // rather than assert a level they do not claim.
            if metadata.security_level == 0 {
                continue;
            }
            assert_eq!(
                metadata.security_level,
                algorithm.security_level(),
                "{algorithm:?}: the registry says security_level {}, but \
                 lib_q_types::Algorithm::security_level() says {}. These are duplicate copies of \
                 one table and must be changed together.",
                metadata.security_level,
                algorithm.security_level()
            );
            checked += 1;
        }

        assert!(
            checked > 0,
            "no algorithm carried a non-zero security level, so nothing was actually compared"
        );
    }
}
