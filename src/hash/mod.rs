//! Hash Functions for libQ
//!
//! This module provides SHA-3 family hash functions.

use crate::error::{Error, Result};

/// Trait for hash functions
pub trait Hash {
    /// Hash data
    fn hash(&self, data: &[u8]) -> Result<Vec<u8>>;

    /// Get the output size in bytes
    fn output_size(&self) -> usize;
}

/// Hash algorithm types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHAKE256
    Shake256,
    /// SHAKE128
    Shake128,
    /// cSHAKE256
    CShake256,
}

impl HashAlgorithm {
    /// Get the output size for this algorithm
    pub fn output_size(&self) -> usize {
        match self {
            HashAlgorithm::Shake256 => 32,
            HashAlgorithm::Shake128 => 16,
            HashAlgorithm::CShake256 => 32,
        }
    }

    /// Validate input data size
    ///
    /// # Arguments
    ///
    /// * `data` - The input data to validate
    ///
    /// # Returns
    ///
    /// `Ok(())` if the data is valid, or an error if not
    pub fn validate_input(&self, data: &[u8]) -> Result<()> {
        // Check for empty input
        if data.is_empty() {
            return Err(Error::InvalidMessageSize { max: 0, actual: 0 });
        }

        // Check for maximum input size (1GB to prevent DoS)
        const MAX_INPUT_SIZE: usize = 1024 * 1024 * 1024; // 1GB
        if data.len() > MAX_INPUT_SIZE {
            return Err(Error::InvalidMessageSize {
                max: MAX_INPUT_SIZE,
                actual: data.len(),
            });
        }

        Ok(())
    }

    /// Create a hash instance for this algorithm
    pub fn create_hash(&self) -> Box<dyn Hash> {
        match self {
            HashAlgorithm::Shake256 => Box::new(Shake256Hash),
            HashAlgorithm::Shake128 => Box::new(Shake128Hash),
            HashAlgorithm::CShake256 => Box::new(CShake256Hash),
        }
    }
}

/// SHAKE256 hash implementation
pub struct Shake256Hash;

impl Hash for Shake256Hash {
    fn hash(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Validate input
        HashAlgorithm::Shake256.validate_input(data)?;

        // TODO: Implement actual SHAKE256
        // For now, return a placeholder
        Ok(vec![0u8; 32])
    }

    fn output_size(&self) -> usize {
        32
    }
}

/// SHAKE128 hash implementation
pub struct Shake128Hash;

impl Hash for Shake128Hash {
    fn hash(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Validate input
        HashAlgorithm::Shake128.validate_input(data)?;

        // TODO: Implement actual SHAKE128
        // For now, return a placeholder
        Ok(vec![0u8; 16])
    }

    fn output_size(&self) -> usize {
        16
    }
}

/// cSHAKE256 hash implementation
pub struct CShake256Hash;

impl Hash for CShake256Hash {
    fn hash(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Validate input
        HashAlgorithm::CShake256.validate_input(data)?;

        // TODO: Implement actual cSHAKE256
        // For now, return a placeholder
        Ok(vec![0u8; 32])
    }

    fn output_size(&self) -> usize {
        32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_algorithm_output_sizes() {
        assert_eq!(HashAlgorithm::Shake256.output_size(), 32);
        assert_eq!(HashAlgorithm::Shake128.output_size(), 16);
        assert_eq!(HashAlgorithm::CShake256.output_size(), 32);
    }

    #[test]
    fn test_input_validation() {
        // Test empty input
        assert!(HashAlgorithm::Shake256.validate_input(&[]).is_err());

        // Test valid input
        let valid_data = vec![1, 2, 3, 4];
        assert!(HashAlgorithm::Shake256.validate_input(&valid_data).is_ok());

        // Test large input (should be ok for reasonable sizes)
        let large_data = vec![0u8; 1024 * 1024]; // 1MB
        assert!(HashAlgorithm::Shake256.validate_input(&large_data).is_ok());
    }

    #[test]
    fn test_hash_creation() {
        let shake256 = HashAlgorithm::Shake256.create_hash();
        assert_eq!(shake256.output_size(), 32);

        let shake128 = HashAlgorithm::Shake128.create_hash();
        assert_eq!(shake128.output_size(), 16);

        let cshake256 = HashAlgorithm::CShake256.create_hash();
        assert_eq!(cshake256.output_size(), 32);
    }

    #[test]
    fn test_hash_operations() {
        let data = vec![1, 2, 3, 4];

        let shake256 = HashAlgorithm::Shake256.create_hash();
        let result = shake256.hash(&data).expect("SHAKE256 hash should succeed");
        assert_eq!(result.len(), 32);

        let shake128 = HashAlgorithm::Shake128.create_hash();
        let result = shake128.hash(&data).expect("SHAKE128 hash should succeed");
        assert_eq!(result.len(), 16);

        let cshake256 = HashAlgorithm::CShake256.create_hash();
        let result = cshake256
            .hash(&data)
            .expect("cSHAKE256 hash should succeed");
        assert_eq!(result.len(), 32);
    }
}
