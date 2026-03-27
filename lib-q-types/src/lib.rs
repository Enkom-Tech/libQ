//! Shared algorithm identifiers and categories for lib-Q.
//!
//! This crate is the lowest dependency layer: implementation crates can depend on
//! `lib-q-types` for `Algorithm` / `AlgorithmCategory` without pulling in `lib-q-core`.
#![no_std]
#![deny(unsafe_code)]
#![deny(unused_qualifications)]

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// Algorithm identifiers for cryptographic operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum Algorithm {
    // KEM algorithms
    MlKem512,
    MlKem768,
    MlKem1024,
    CbKem348864,
    CbKem460896,
    CbKem6688128,
    CbKem6960119,
    CbKem8192128,
    Hqc128,
    Hqc192,
    Hqc256,
    DawnAlpha512,
    DawnBeta512,
    DawnAlpha1024,
    DawnBeta1024,

    // Signature algorithms
    MlDsa44,
    MlDsa65,
    MlDsa87,
    FnDsa,
    FnDsa512,
    FnDsa1024,
    SlhDsaSha256128fRobust,
    SlhDsaSha256192fRobust,
    SlhDsaSha256256fRobust,
    SlhDsaShake256128fRobust,
    SlhDsaShake256192fRobust,
    SlhDsaShake256256fRobust,

    // Hash algorithms
    Shake128,
    Shake256,
    CShake128,
    CShake256,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Keccak224,
    Keccak256,
    Keccak384,
    Keccak512,
    KangarooTwelve,
    TurboShake128,
    TurboShake256,
    Kmac128,
    Kmac256,
    TupleHash128,
    TupleHash256,
    ParallelHash128,
    ParallelHash256,

    // SHA-2 algorithms
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512_224,
    Sha512_256,

    // AEAD algorithms
    Saturnin,
    Shake256Aead,
    KemAead,
    DuplexSpongeAead,
    TweakAead,
}

impl Algorithm {
    /// Get the security level for this algorithm
    pub fn security_level(&self) -> u32 {
        match self {
            // Level 1 (128-bit security)
            Algorithm::MlKem512 => 1,
            Algorithm::CbKem348864 => 1,
            Algorithm::Hqc128 => 1,
            Algorithm::DawnAlpha512 => 1,
            Algorithm::DawnBeta512 => 1,
            Algorithm::MlDsa44 => 1,
            Algorithm::FnDsa => 1,
            Algorithm::FnDsa512 => 1,
            Algorithm::SlhDsaSha256128fRobust => 1,
            Algorithm::SlhDsaShake256128fRobust => 1,

            // Level 3 (192-bit security)
            Algorithm::MlKem768 => 3,
            Algorithm::CbKem460896 => 3,
            Algorithm::Hqc192 => 3,
            Algorithm::MlDsa65 => 3,
            Algorithm::SlhDsaSha256192fRobust => 3,
            Algorithm::SlhDsaShake256192fRobust => 3,

            // Level 4 (256-bit security)
            Algorithm::MlKem1024 => 4,
            Algorithm::CbKem6688128 => 4,
            Algorithm::CbKem6960119 => 4,
            Algorithm::Hqc256 => 4,
            Algorithm::MlDsa87 => 4,
            Algorithm::SlhDsaSha256256fRobust => 5,
            Algorithm::SlhDsaShake256256fRobust => 5,

            // Level 5 (256-bit security)
            Algorithm::FnDsa1024 => 5,
            Algorithm::DawnAlpha1024 => 5,
            Algorithm::DawnBeta1024 => 5,

            // Level 5 (256-bit security, higher performance)
            Algorithm::CbKem8192128 => 5,

            // Hash algorithms don't have security levels
            Algorithm::Shake128 |
            Algorithm::Shake256 |
            Algorithm::CShake128 |
            Algorithm::CShake256 |
            Algorithm::Sha3_224 |
            Algorithm::Sha3_256 |
            Algorithm::Sha3_384 |
            Algorithm::Sha3_512 |
            Algorithm::Keccak224 |
            Algorithm::Keccak256 |
            Algorithm::Keccak384 |
            Algorithm::Keccak512 |
            Algorithm::KangarooTwelve |
            Algorithm::TurboShake128 |
            Algorithm::TurboShake256 |
            Algorithm::Kmac128 |
            Algorithm::Kmac256 |
            Algorithm::TupleHash128 |
            Algorithm::TupleHash256 |
            Algorithm::ParallelHash128 |
            Algorithm::ParallelHash256 |
            Algorithm::Sha224 |
            Algorithm::Sha256 |
            Algorithm::Sha384 |
            Algorithm::Sha512 |
            Algorithm::Sha512_224 |
            Algorithm::Sha512_256 => 0,

            // AEAD algorithms
            Algorithm::Saturnin => 1,
            Algorithm::Shake256Aead => 1,
            Algorithm::KemAead => 4,
            Algorithm::DuplexSpongeAead => 4,
            Algorithm::TweakAead => 4,
        }
    }

    /// Get the algorithm category
    pub fn category(&self) -> AlgorithmCategory {
        match self {
            Algorithm::MlKem512 |
            Algorithm::MlKem768 |
            Algorithm::MlKem1024 |
            Algorithm::CbKem348864 |
            Algorithm::CbKem460896 |
            Algorithm::CbKem6688128 |
            Algorithm::CbKem6960119 |
            Algorithm::CbKem8192128 |
            Algorithm::Hqc128 |
            Algorithm::Hqc192 |
            Algorithm::Hqc256 |
            Algorithm::DawnAlpha512 |
            Algorithm::DawnBeta512 |
            Algorithm::DawnAlpha1024 |
            Algorithm::DawnBeta1024 => AlgorithmCategory::Kem,

            Algorithm::MlDsa44 |
            Algorithm::MlDsa65 |
            Algorithm::MlDsa87 |
            Algorithm::FnDsa |
            Algorithm::FnDsa512 |
            Algorithm::FnDsa1024 |
            Algorithm::SlhDsaSha256128fRobust |
            Algorithm::SlhDsaSha256192fRobust |
            Algorithm::SlhDsaSha256256fRobust |
            Algorithm::SlhDsaShake256128fRobust |
            Algorithm::SlhDsaShake256192fRobust |
            Algorithm::SlhDsaShake256256fRobust => AlgorithmCategory::Signature,

            Algorithm::Shake128 |
            Algorithm::Shake256 |
            Algorithm::CShake128 |
            Algorithm::CShake256 |
            Algorithm::Sha3_224 |
            Algorithm::Sha3_256 |
            Algorithm::Sha3_384 |
            Algorithm::Sha3_512 |
            Algorithm::Keccak224 |
            Algorithm::Keccak256 |
            Algorithm::Keccak384 |
            Algorithm::Keccak512 |
            Algorithm::KangarooTwelve |
            Algorithm::TurboShake128 |
            Algorithm::TurboShake256 |
            Algorithm::Kmac128 |
            Algorithm::Kmac256 |
            Algorithm::TupleHash128 |
            Algorithm::TupleHash256 |
            Algorithm::ParallelHash128 |
            Algorithm::ParallelHash256 |
            Algorithm::Sha224 |
            Algorithm::Sha256 |
            Algorithm::Sha384 |
            Algorithm::Sha512 |
            Algorithm::Sha512_224 |
            Algorithm::Sha512_256 => AlgorithmCategory::Hash,

            // AEAD algorithms
            Algorithm::Saturnin |
            Algorithm::Shake256Aead |
            Algorithm::KemAead |
            Algorithm::DuplexSpongeAead |
            Algorithm::TweakAead => AlgorithmCategory::Aead, // Multi-category algorithms
        }
    }

    /// Check if an algorithm supports a specific category
    pub fn supports_category(&self, category: AlgorithmCategory) -> bool {
        match self {
            // Pure KEM algorithms
            Algorithm::MlKem512 |
            Algorithm::MlKem768 |
            Algorithm::MlKem1024 |
            Algorithm::CbKem348864 |
            Algorithm::CbKem460896 |
            Algorithm::CbKem6688128 |
            Algorithm::CbKem6960119 |
            Algorithm::CbKem8192128 |
            Algorithm::Hqc128 |
            Algorithm::Hqc192 |
            Algorithm::Hqc256 |
            Algorithm::DawnAlpha512 |
            Algorithm::DawnBeta512 |
            Algorithm::DawnAlpha1024 |
            Algorithm::DawnBeta1024 => category == AlgorithmCategory::Kem,

            // Pure signature algorithms
            Algorithm::MlDsa44 |
            Algorithm::MlDsa65 |
            Algorithm::MlDsa87 |
            Algorithm::FnDsa |
            Algorithm::FnDsa512 |
            Algorithm::FnDsa1024 |
            Algorithm::SlhDsaSha256128fRobust |
            Algorithm::SlhDsaSha256192fRobust |
            Algorithm::SlhDsaSha256256fRobust |
            Algorithm::SlhDsaShake256128fRobust |
            Algorithm::SlhDsaShake256192fRobust |
            Algorithm::SlhDsaShake256256fRobust => category == AlgorithmCategory::Signature,

            // Pure hash algorithms
            Algorithm::Shake128 |
            Algorithm::Shake256 |
            Algorithm::CShake128 |
            Algorithm::CShake256 |
            Algorithm::Sha3_224 |
            Algorithm::Sha3_256 |
            Algorithm::Sha3_384 |
            Algorithm::Sha3_512 |
            Algorithm::Keccak224 |
            Algorithm::Keccak256 |
            Algorithm::Keccak384 |
            Algorithm::Keccak512 |
            Algorithm::KangarooTwelve |
            Algorithm::TurboShake128 |
            Algorithm::TurboShake256 |
            Algorithm::Kmac128 |
            Algorithm::Kmac256 |
            Algorithm::TupleHash128 |
            Algorithm::TupleHash256 |
            Algorithm::ParallelHash128 |
            Algorithm::ParallelHash256 |
            Algorithm::Sha224 |
            Algorithm::Sha256 |
            Algorithm::Sha384 |
            Algorithm::Sha512 |
            Algorithm::Sha512_224 |
            Algorithm::Sha512_256 => category == AlgorithmCategory::Hash,

            // Pure AEAD algorithms
            Algorithm::Saturnin |
            Algorithm::Shake256Aead |
            Algorithm::KemAead |
            Algorithm::DuplexSpongeAead |
            Algorithm::TweakAead => category == AlgorithmCategory::Aead, // Multi-category algorithms
        }
    }
}

/// Algorithm categories
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum AlgorithmCategory {
    Kem,
    Signature,
    Hash,
    Aead,
}

/// Security levels for cryptographic algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum SecurityLevel {
    Level1 = 1, // 128-bit security
    Level3 = 3, // 192-bit security
    Level4 = 4, // 256-bit security
    Level5 = 5, // 256-bit security (higher performance)
}

impl SecurityLevel {
    /// Convert from u32 to SecurityLevel
    pub fn from_u32(level: u32) -> Option<Self> {
        match level {
            1 => Some(SecurityLevel::Level1),
            3 => Some(SecurityLevel::Level3),
            4 => Some(SecurityLevel::Level4),
            5 => Some(SecurityLevel::Level5),
            _ => None,
        }
    }

    /// Convert to u32
    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

impl core::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            // KEM algorithms
            Algorithm::MlKem512 => write!(f, "ML-KEM-512"),
            Algorithm::MlKem768 => write!(f, "ML-KEM-768"),
            Algorithm::MlKem1024 => write!(f, "ML-KEM-1024"),
            Algorithm::CbKem348864 => write!(f, "CB-KEM-348864"),
            Algorithm::CbKem460896 => write!(f, "CB-KEM-460896"),
            Algorithm::CbKem6688128 => write!(f, "CB-KEM-6688128"),
            Algorithm::CbKem6960119 => write!(f, "CB-KEM-6960119"),
            Algorithm::CbKem8192128 => write!(f, "CB-KEM-8192128"),
            Algorithm::Hqc128 => write!(f, "HQC-128"),
            Algorithm::Hqc192 => write!(f, "HQC-192"),
            Algorithm::Hqc256 => write!(f, "HQC-256"),
            Algorithm::DawnAlpha512 => write!(f, "DAWN-α-512"),
            Algorithm::DawnBeta512 => write!(f, "DAWN-β-512"),
            Algorithm::DawnAlpha1024 => write!(f, "DAWN-α-1024"),
            Algorithm::DawnBeta1024 => write!(f, "DAWN-β-1024"),

            // Signature algorithms
            Algorithm::MlDsa44 => write!(f, "ML-DSA-44"),
            Algorithm::MlDsa65 => write!(f, "ML-DSA-65"),
            Algorithm::MlDsa87 => write!(f, "ML-DSA-87"),
            Algorithm::FnDsa => write!(f, "FN-DSA"),
            Algorithm::FnDsa512 => write!(f, "FN-DSA-512"),
            Algorithm::FnDsa1024 => write!(f, "FN-DSA-1024"),
            Algorithm::SlhDsaSha256128fRobust => write!(f, "SLH-DSA-SHA256-128f-Robust"),
            Algorithm::SlhDsaSha256192fRobust => write!(f, "SLH-DSA-SHA256-192f-Robust"),
            Algorithm::SlhDsaSha256256fRobust => write!(f, "SLH-DSA-SHA256-256f-Robust"),
            Algorithm::SlhDsaShake256128fRobust => write!(f, "SLH-DSA-SHAKE256-128f-Robust"),
            Algorithm::SlhDsaShake256192fRobust => write!(f, "SLH-DSA-SHAKE256-192f-Robust"),
            Algorithm::SlhDsaShake256256fRobust => write!(f, "SLH-DSA-SHAKE256-256f-Robust"),

            // Hash algorithms
            Algorithm::Shake128 => write!(f, "SHAKE128"),
            Algorithm::Shake256 => write!(f, "SHAKE256"),
            Algorithm::CShake128 => write!(f, "cSHAKE128"),
            Algorithm::CShake256 => write!(f, "cSHAKE256"),
            Algorithm::Sha3_224 => write!(f, "SHA3-224"),
            Algorithm::Sha3_256 => write!(f, "SHA3-256"),
            Algorithm::Sha3_384 => write!(f, "SHA3-384"),
            Algorithm::Sha3_512 => write!(f, "SHA3-512"),
            Algorithm::Keccak224 => write!(f, "Keccak-224"),
            Algorithm::Keccak256 => write!(f, "Keccak-256"),
            Algorithm::Keccak384 => write!(f, "Keccak-384"),
            Algorithm::Keccak512 => write!(f, "Keccak-512"),
            Algorithm::Sha224 => write!(f, "SHA-224"),
            Algorithm::Sha256 => write!(f, "SHA-256"),
            Algorithm::Sha384 => write!(f, "SHA-384"),
            Algorithm::Sha512 => write!(f, "SHA-512"),
            Algorithm::Sha512_224 => write!(f, "SHA-512/224"),
            Algorithm::Sha512_256 => write!(f, "SHA-512/256"),

            // AEAD algorithms
            Algorithm::Saturnin => write!(f, "Saturnin"),
            Algorithm::Shake256Aead => write!(f, "SHAKE256-AEAD"),
            Algorithm::KemAead => write!(f, "KEM-AEAD"),
            Algorithm::DuplexSpongeAead => write!(f, "Duplex-Sponge-AEAD"),
            Algorithm::TweakAead => write!(f, "Tweak-AEAD"),

            // Additional algorithms
            Algorithm::KangarooTwelve => write!(f, "KangarooTwelve"),
            Algorithm::TurboShake128 => write!(f, "TurboShake128"),
            Algorithm::TurboShake256 => write!(f, "TurboShake256"),
            Algorithm::Kmac128 => write!(f, "KMAC128"),
            Algorithm::Kmac256 => write!(f, "KMAC256"),
            Algorithm::TupleHash128 => write!(f, "TupleHash128"),
            Algorithm::TupleHash256 => write!(f, "TupleHash256"),
            Algorithm::ParallelHash128 => write!(f, "ParallelHash128"),
            Algorithm::ParallelHash256 => write!(f, "ParallelHash256"),
        }
    }
}

impl core::fmt::Display for AlgorithmCategory {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AlgorithmCategory::Kem => write!(f, "KEM"),
            AlgorithmCategory::Signature => write!(f, "Signature"),
            AlgorithmCategory::Hash => write!(f, "Hash"),
            AlgorithmCategory::Aead => write!(f, "AEAD"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_categories() {
        assert_eq!(Algorithm::MlKem512.category(), AlgorithmCategory::Kem);
        assert_eq!(Algorithm::Shake256Aead.category(), AlgorithmCategory::Aead);
    }
}
