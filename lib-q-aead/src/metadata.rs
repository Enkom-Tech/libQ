//! AEAD Algorithm Metadata
//!
//! This module provides metadata structures for AEAD algorithms, including
//! key sizes, nonce sizes, tag sizes, and other algorithm properties.

use lib_q_core::{
    Aead,
    AeadKey,
    Algorithm,
    Nonce,
    Result,
};

/// Performance tier for AEAD algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PerformanceTier {
    /// Ultra-secure tier with maximum security
    UltraSecure,
    /// Balanced tier with good security and performance
    Balanced,
    /// Performance tier optimized for speed
    Performance,
    /// Hybrid tier with algorithm diversity
    Hybrid,
}

/// Metadata for AEAD algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AeadMetadata {
    /// The algorithm identifier
    pub algorithm: Algorithm,
    /// Key size in bytes
    pub key_size: usize,
    /// Nonce size in bytes
    pub nonce_size: usize,
    /// Authentication tag size in bytes
    pub tag_size: usize,
    /// Security level (1, 3, 4, 5)
    pub security_level: u32,
    /// Human-readable algorithm name
    pub name: &'static str,
    /// Algorithm description
    pub description: &'static str,
}

impl AeadMetadata {
    /// Create new metadata
    pub const fn new(
        algorithm: Algorithm,
        key_size: usize,
        nonce_size: usize,
        tag_size: usize,
        security_level: u32,
        name: &'static str,
        description: &'static str,
    ) -> Self {
        Self {
            algorithm,
            key_size,
            nonce_size,
            tag_size,
            security_level,
            name,
            description,
        }
    }

    /// Get the performance tier for this algorithm
    pub fn performance_tier(&self) -> PerformanceTier {
        match self.security_level {
            1 => PerformanceTier::Performance,
            3 => PerformanceTier::Balanced,
            4 => PerformanceTier::UltraSecure,
            5 => PerformanceTier::Hybrid,
            _ => PerformanceTier::Balanced,
        }
    }

    /// Check if this algorithm is suitable for the given security level
    pub fn is_suitable_for_security_level(&self, required_level: u32) -> bool {
        self.security_level >= required_level
    }

    /// Get the total overhead (nonce + tag) for this algorithm
    pub fn total_overhead(&self) -> usize {
        self.nonce_size + self.tag_size
    }

    /// Validate key size
    pub fn validate_key_size(&self, key_size: usize) -> bool {
        key_size == self.key_size
    }

    /// Validate nonce size
    pub fn validate_nonce_size(&self, nonce_size: usize) -> bool {
        nonce_size == self.nonce_size
    }

    /// Validate tag size
    pub fn validate_tag_size(&self, tag_size: usize) -> bool {
        tag_size == self.tag_size
    }
}

/// Trait for AEAD implementations that provide metadata
pub trait AeadWithMetadata: Aead {
    /// Get the algorithm metadata
    fn metadata(&self) -> &'static AeadMetadata;

    /// Get the algorithm identifier
    fn algorithm(&self) -> Algorithm {
        self.metadata().algorithm
    }

    /// Get the key size in bytes
    fn key_size(&self) -> usize {
        self.metadata().key_size
    }

    /// Get the nonce size in bytes
    fn nonce_size(&self) -> usize {
        self.metadata().nonce_size
    }

    /// Get the tag size in bytes
    fn tag_size(&self) -> usize {
        self.metadata().tag_size
    }

    /// Get the security level
    fn security_level(&self) -> u32 {
        self.metadata().security_level
    }

    /// Get the algorithm name
    fn algorithm_name(&self) -> &'static str {
        self.metadata().name
    }

    /// Get the algorithm description
    fn algorithm_description(&self) -> &'static str {
        self.metadata().description
    }

    /// Validate key size
    fn validate_key(&self, key: &AeadKey) -> Result<()> {
        if !self.metadata().validate_key_size(key.as_bytes().len()) {
            return Err(lib_q_core::Error::InvalidKeySize {
                expected: self.key_size(),
                actual: key.as_bytes().len(),
            });
        }
        Ok(())
    }

    /// Validate nonce size
    fn validate_nonce(&self, nonce: &Nonce) -> Result<()> {
        if !self.metadata().validate_nonce_size(nonce.as_bytes().len()) {
            return Err(lib_q_core::Error::InvalidNonceSize {
                expected: self.nonce_size(),
                actual: nonce.as_bytes().len(),
            });
        }
        Ok(())
    }

    /// Validate ciphertext size (must be at least tag size)
    fn validate_ciphertext_size(&self, ciphertext_size: usize) -> Result<()> {
        if ciphertext_size < self.tag_size() {
            return Err(lib_q_core::Error::InvalidCiphertextSize {
                expected: self.tag_size(),
                actual: ciphertext_size,
            });
        }
        Ok(())
    }
}

/// Helper function to get metadata for an algorithm
pub fn get_metadata(algorithm: Algorithm) -> Option<&'static AeadMetadata> {
    // Use static metadata to avoid lifetime issues
    static SATURNIN_METADATA: AeadMetadata = AeadMetadata::new(
        Algorithm::Saturnin,
        32, // 256-bit key
        16, // 128-bit nonce
        32, // 256-bit tag
        1,  // Level 1 security
        "Saturnin",
        "Lightweight post-quantum symmetric algorithm suite for IoT and constrained devices",
    );

    static SHAKE256_METADATA: AeadMetadata = AeadMetadata::new(
        Algorithm::Shake256Aead,
        32, // 256-bit key
        16, // 128-bit nonce
        32, // 256-bit tag
        1,  // Level 1 security
        "SHAKE256-AEAD",
        "SHAKE256-based AEAD construction using post-quantum hash function",
    );

    static DUPLEX_SPONGE_AEAD_METADATA: AeadMetadata = AeadMetadata::new(
        Algorithm::DuplexSpongeAead,
        32,
        16,
        32,
        4,
        "Duplex-Sponge-AEAD",
        "Keccak-f[1600] duplex-sponge authenticated encryption",
    );

    static TWEAK_AEAD_METADATA: AeadMetadata = AeadMetadata::new(
        Algorithm::TweakAead,
        32,
        16,
        32,
        4,
        "Tweak-AEAD",
        "Parallel tweakable-block CTR AEAD over Keccak-f[1600]",
    );

    static ROMULUS_N_METADATA: AeadMetadata = AeadMetadata::new(
        Algorithm::RomulusN,
        16,
        16,
        16,
        1,
        "Romulus-N",
        "Romulus-N nonce-based AEAD (SKINNY-128-384+), LWC v1.3",
    );

    static ROMULUS_M_METADATA: AeadMetadata = AeadMetadata::new(
        Algorithm::RomulusM,
        16,
        16,
        16,
        1,
        "Romulus-M",
        "Romulus-M misuse-resistant AEAD (SKINNY-128-384+), LWC v1.3",
    );

    match algorithm {
        Algorithm::Saturnin => Some(&SATURNIN_METADATA),
        Algorithm::Shake256Aead => Some(&SHAKE256_METADATA),
        Algorithm::DuplexSpongeAead => Some(&DUPLEX_SPONGE_AEAD_METADATA),
        Algorithm::TweakAead => Some(&TWEAK_AEAD_METADATA),
        Algorithm::RomulusN => Some(&ROMULUS_N_METADATA),
        Algorithm::RomulusM => Some(&ROMULUS_M_METADATA),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_creation() {
        let metadata = AeadMetadata::new(
            Algorithm::Saturnin,
            32,
            16,
            32,
            1,
            "Saturnin",
            "Test algorithm",
        );

        assert_eq!(metadata.algorithm, Algorithm::Saturnin);
        assert_eq!(metadata.key_size, 32);
        assert_eq!(metadata.nonce_size, 16);
        assert_eq!(metadata.tag_size, 32);
        assert_eq!(metadata.security_level, 1);
        assert_eq!(metadata.name, "Saturnin");
        assert_eq!(metadata.description, "Test algorithm");
    }

    #[test]
    fn test_performance_tier() {
        let metadata = AeadMetadata::new(Algorithm::Saturnin, 32, 16, 32, 1, "Test", "Test");
        assert_eq!(metadata.performance_tier(), PerformanceTier::Performance);

        let metadata = AeadMetadata::new(Algorithm::Saturnin, 32, 16, 32, 3, "Test", "Test");
        assert_eq!(metadata.performance_tier(), PerformanceTier::Balanced);

        let metadata = AeadMetadata::new(Algorithm::Saturnin, 32, 16, 32, 4, "Test", "Test");
        assert_eq!(metadata.performance_tier(), PerformanceTier::UltraSecure);

        let metadata = AeadMetadata::new(Algorithm::Saturnin, 32, 16, 32, 5, "Test", "Test");
        assert_eq!(metadata.performance_tier(), PerformanceTier::Hybrid);
    }

    #[test]
    fn test_security_level_suitability() {
        let metadata = AeadMetadata::new(Algorithm::Saturnin, 32, 16, 32, 3, "Test", "Test");

        assert!(metadata.is_suitable_for_security_level(1));
        assert!(metadata.is_suitable_for_security_level(3));
        assert!(!metadata.is_suitable_for_security_level(4));
        assert!(!metadata.is_suitable_for_security_level(5));
    }

    #[test]
    fn test_size_validation() {
        let metadata = AeadMetadata::new(Algorithm::Saturnin, 32, 16, 32, 1, "Test", "Test");

        assert!(metadata.validate_key_size(32));
        assert!(!metadata.validate_key_size(16));
        assert!(!metadata.validate_key_size(64));

        assert!(metadata.validate_nonce_size(16));
        assert!(!metadata.validate_nonce_size(12));
        assert!(!metadata.validate_nonce_size(24));

        assert!(metadata.validate_tag_size(32));
        assert!(!metadata.validate_tag_size(16));
        assert!(!metadata.validate_tag_size(64));
    }

    #[test]
    fn test_total_overhead() {
        let metadata = AeadMetadata::new(Algorithm::Saturnin, 32, 16, 32, 1, "Test", "Test");

        assert_eq!(metadata.total_overhead(), 48); // 16 + 32
    }

    #[test]
    fn test_get_metadata() {
        let metadata = get_metadata(Algorithm::Saturnin);
        assert!(metadata.is_some());

        if let Some(meta) = metadata {
            assert_eq!(meta.algorithm, Algorithm::Saturnin);
            assert_eq!(meta.name, "Saturnin");
        }

        let metadata = get_metadata(Algorithm::MlKem512);
        assert!(metadata.is_none());
    }
}
