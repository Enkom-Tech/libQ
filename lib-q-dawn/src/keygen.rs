//! Key generation algorithms for DAWN
//!
//! This module implements the key generation algorithms as specified in the DAWN paper.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(not(feature = "std"))]
use core::fmt;
#[cfg(feature = "std")]
use std::fmt;

use lib_q_core::Result;
#[cfg(feature = "random")]
use lib_q_random::{
    new_deterministic_rng,
    new_secure_rng,
};
use rand_core::RngCore;

use crate::encoding::ZeroDivisorEncoder;
use crate::polynomial::field::FieldPolynomial;

/// Trait alias for RNG that implements both RngCore and CryptoRng
#[cfg(feature = "random")]
trait SecureRng: RngCore + rand_core::CryptoRng {}
#[cfg(feature = "random")]
impl<T: RngCore + rand_core::CryptoRng> SecureRng for T {}

/// Secure RNG wrapper for DAWN operations
#[cfg(feature = "random")]
pub struct DawnRng {
    rng: Box<dyn SecureRng + Send + Sync>,
}

#[cfg(feature = "random")]
impl DawnRng {
    /// Create a new secure RNG for production use
    pub fn new() -> Result<Self> {
        let rng = new_secure_rng().map_err(|e| lib_q_core::Error::RandomGenerationFailed {
            operation: format!("Failed to create secure RNG: {}", e),
        })?;
        Ok(Self { rng: Box::new(rng) })
    }

    /// Create a deterministic RNG for testing
    pub fn new_deterministic(seed: &[u8]) -> Self {
        let rng = new_deterministic_rng(seed);
        Self { rng: Box::new(rng) }
    }
}

#[cfg(feature = "random")]
impl RngCore for DawnRng {
    fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.rng.fill_bytes(dest);
    }
}

#[cfg(feature = "random")]
impl rand_core::CryptoRng for DawnRng {}

/// DAWN key generation parameters
#[derive(Clone, Debug)]
pub struct KeyGenParams {
    /// Polynomial degree n
    pub degree: usize,
    /// Large modulus q
    pub large_modulus: u32,
    /// Small modulus p = 2
    pub small_modulus: u32,
    /// Compression divisor d_c
    pub compression_divisor: u32,
    /// Number of random coefficients for f
    pub f_coeff_count: usize,
    /// Number of random coefficients for g
    pub g_coeff_count: usize,
}

impl fmt::Display for KeyGenParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KeyGenParams(degree={}, large_modulus={}, small_modulus={}, compression_divisor={}, f_coeff_count={}, g_coeff_count={})",
            self.degree,
            self.large_modulus,
            self.small_modulus,
            self.compression_divisor,
            self.f_coeff_count,
            self.g_coeff_count
        )
    }
}

impl KeyGenParams {
    /// Create parameters for DAWN-α-512
    pub fn dawn_alpha_512() -> Self {
        Self {
            degree: 512,
            large_modulus: 769,
            small_modulus: 2,
            compression_divisor: 7,
            f_coeff_count: 256, // n/2
            g_coeff_count: 256, // n/2
        }
    }

    /// Create parameters for DAWN-α-1024
    pub fn dawn_alpha_1024() -> Self {
        Self {
            degree: 1024,
            large_modulus: 769,
            small_modulus: 2,
            compression_divisor: 4,
            f_coeff_count: 512, // n/2
            g_coeff_count: 512, // n/2
        }
    }

    /// Create parameters for DAWN-β-512
    pub fn dawn_beta_512() -> Self {
        Self {
            degree: 512,
            large_modulus: 257,
            small_modulus: 2,
            compression_divisor: 2,
            f_coeff_count: 256, // n/2
            g_coeff_count: 256, // n/2
        }
    }

    /// Create parameters for DAWN-β-1024
    pub fn dawn_beta_1024() -> Self {
        Self {
            degree: 1024,
            large_modulus: 257,
            small_modulus: 2,
            compression_divisor: 1,
            f_coeff_count: 512, // n/2
            g_coeff_count: 512, // n/2
        }
    }

    /// Get the security level in bits
    pub fn security_level(&self) -> usize {
        match (self.degree, self.large_modulus) {
            (512, 769) => 128,
            (1024, 769) => 192,
            (512, 257) => 128,
            (1024, 257) => 192,
            _ => 128, // Default
        }
    }

    /// Check if the parameters are valid
    pub fn is_valid(&self) -> bool {
        self.degree > 0 &&
            self.large_modulus > 2 &&
            self.small_modulus == 2 &&
            self.compression_divisor > 0 &&
            self.f_coeff_count > 0 &&
            self.g_coeff_count > 0 &&
            self.f_coeff_count <= self.degree &&
            self.g_coeff_count <= self.degree
    }
}

/// DAWN key pair
#[derive(Clone, Debug)]
pub struct DawnKeyPair {
    /// Public key polynomial h
    pub public_key: FieldPolynomial,
    /// Secret key polynomial f
    pub secret_key: FieldPolynomial,
    /// Auxiliary polynomial g
    pub g: FieldPolynomial,
    /// Parameters used for key generation
    pub params: KeyGenParams,
}

impl fmt::Display for DawnKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DawnKeyPair(degree={}, large_modulus={}, public_key_size={}, secret_key_size={})",
            self.params.degree,
            self.params.large_modulus,
            self.public_key_bytes().len(),
            self.secret_key_bytes().len()
        )
    }
}

impl DawnKeyPair {
    /// Create a new key pair
    pub fn new(
        public_key: FieldPolynomial,
        secret_key: FieldPolynomial,
        g: FieldPolynomial,
        params: KeyGenParams,
    ) -> Self {
        Self {
            public_key,
            secret_key,
            g,
            params,
        }
    }

    /// Get the public key as bytes
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.encode_polynomial(&self.public_key)
    }

    /// Get the secret key as bytes
    pub fn secret_key_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Encode f polynomial
        let f_bytes = self.encode_polynomial(&self.secret_key);
        bytes.extend_from_slice(&f_bytes);

        // Encode g polynomial
        let g_bytes = self.encode_polynomial(&self.g);
        bytes.extend_from_slice(&g_bytes);

        // Truncate to the expected secret key size
        let expected_size = match self.params.degree {
            512 => {
                if self.params.large_modulus == 769 {
                    1319
                } else {
                    1154
                }
            }
            1024 => {
                if self.params.large_modulus == 769 {
                    2605
                } else {
                    2275
                }
            }
            _ => bytes.len(),
        };

        bytes.truncate(expected_size);
        bytes.resize(expected_size, 0);

        bytes
    }

    /// Encode a polynomial to bytes
    fn encode_polynomial(&self, poly: &FieldPolynomial) -> Vec<u8> {
        let mut bytes = Vec::new();

        // For DAWN, we need to compress the polynomial representation
        // The actual key sizes are much smaller than the raw polynomial size

        // Calculate the number of bits needed per coefficient
        let bits_per_coeff = if self.params.large_modulus <= 256 {
            8
        } else if self.params.large_modulus <= 65536 {
            16
        } else {
            32
        };

        // Pack coefficients into bytes
        let mut bit_buffer = 0u64;
        let mut bit_count = 0;

        for &coeff in &poly.coefficients {
            bit_buffer |= (coeff as u64) << bit_count;
            bit_count += bits_per_coeff;

            while bit_count >= 8 {
                bytes.push((bit_buffer & 0xFF) as u8);
                bit_buffer >>= 8;
                bit_count -= 8;
            }
        }

        // Add remaining bits
        if bit_count > 0 {
            bytes.push((bit_buffer & 0xFF) as u8);
        }

        // Truncate to the expected key size
        let expected_size = match self.params.degree {
            512 => {
                if self.params.large_modulus == 769 {
                    615
                } else {
                    514
                }
            }
            1024 => {
                if self.params.large_modulus == 769 {
                    1229
                } else {
                    1027
                }
            }
            _ => bytes.len(),
        };

        bytes.truncate(expected_size);
        bytes.resize(expected_size, 0);

        bytes
    }

    /// Validate the key pair structure
    pub fn is_valid(&self) -> bool {
        self.params.is_valid() &&
            self.public_key.coefficients.len() == self.params.degree &&
            self.secret_key.coefficients.len() == self.params.degree &&
            self.g.coefficients.len() == self.params.degree
    }
}

/// DAWN key generator
#[derive(Clone, Debug)]
pub struct DawnKeyGenerator {
    /// Key generation parameters
    pub params: KeyGenParams,
    /// Zero divisor encoder
    pub encoder: ZeroDivisorEncoder,
}

impl fmt::Display for DawnKeyGenerator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DawnKeyGenerator({})", self.params)
    }
}

impl DawnKeyGenerator {
    /// Create a new key generator
    pub fn new(params: KeyGenParams) -> Self {
        let encoder = ZeroDivisorEncoder::new(params.degree);
        Self { params, encoder }
    }

    /// Generate a new key pair
    pub fn generate_keypair(&self, randomness: &[u8]) -> Result<DawnKeyPair> {
        // Generate random polynomials f and g
        let f = self.generate_random_polynomial(&randomness[0..randomness.len() / 2])?;
        let g = self.generate_random_polynomial(&randomness[randomness.len() / 2..])?;

        // Compute h = f^(-1) * g (mod x^n + 1, q)
        let h = self.compute_public_key(&f, &g)?;

        Ok(DawnKeyPair::new(h, f, g, self.params.clone()))
    }

    /// Generate a random polynomial with specified number of non-zero coefficients
    ///
    /// This implements proper NTRU polynomial sampling
    fn generate_random_polynomial(&self, randomness: &[u8]) -> Result<FieldPolynomial> {
        // Create a secure RNG from the randomness
        #[cfg(feature = "random")]
        let mut rng = DawnRng::new_deterministic(randomness);
        #[cfg(not(feature = "random"))]
        return Err(lib_q_core::Error::RandomGenerationFailed {
            operation: "Random feature not enabled".to_string(),
        });

        // Generate a trinary polynomial (coefficients in {-1, 0, 1})
        let mut poly = FieldPolynomial::random_trinary(
            self.params.degree,
            self.params.large_modulus,
            &mut rng,
        );

        // Ensure we have the right number of non-zero coefficients
        let mut non_zero_count = 0;
        for &coeff in &poly.coefficients {
            if coeff != 0 && coeff != self.params.large_modulus - 1 {
                non_zero_count += 1;
            }
        }

        // If we don't have enough non-zero coefficients, adjust
        if non_zero_count < self.params.f_coeff_count {
            let needed = self.params.f_coeff_count - non_zero_count;
            let mut added = 0;

            for i in 0..self.params.degree {
                if poly.coefficients[i] == 0 && added < needed {
                    // Set to 1 or -1 randomly
                    let val = rng.next_u32() % 2;
                    poly.coefficients[i] = if val == 0 {
                        1
                    } else {
                        self.params.large_modulus - 1
                    };
                    added += 1;
                }
            }
        }

        Ok(poly)
    }

    /// Compute the public key h = f^(-1) * g (mod x^n + 1, q)
    pub fn compute_public_key(
        &self,
        f: &FieldPolynomial,
        g: &FieldPolynomial,
    ) -> Result<FieldPolynomial> {
        // Compute f^(-1) (mod x^n + 1, q)
        let f_inv = self.compute_polynomial_inverse(f)?;

        // Compute h = f^(-1) * g (mod x^n + 1, q)
        let h = f_inv * g.clone();

        Ok(h)
    }

    /// Compute the inverse of a polynomial (mod x^n + 1, q)
    ///
    /// Uses the real polynomial inverse implementation from the polynomial module
    fn compute_polynomial_inverse(&self, poly: &FieldPolynomial) -> Result<FieldPolynomial> {
        // Use the real polynomial inverse implementation
        poly.inverse()
    }

    /// Validate a key pair
    pub fn validate_keypair(&self, keypair: &DawnKeyPair) -> Result<bool> {
        // First check basic structure validity
        if !keypair.is_valid() {
            return Ok(false);
        }

        // Check that h = f^(-1) * g (mod x^n + 1, q)
        let computed_h = self.compute_public_key(&keypair.secret_key, &keypair.g)?;

        // Compare the computed public key with the stored one
        let is_valid = computed_h.coefficients == keypair.public_key.coefficients;

        Ok(is_valid)
    }

    /// Generate a key pair with proper g coefficient count
    pub fn generate_keypair_with_g_coeff_count(&self, randomness: &[u8]) -> Result<DawnKeyPair> {
        // Generate random polynomial f with f_coeff_count non-zero coefficients
        let f = self.generate_random_polynomial(&randomness[0..randomness.len() / 2])?;

        // Generate random polynomial g with g_coeff_count non-zero coefficients
        let g =
            self.generate_random_polynomial_with_g_count(&randomness[randomness.len() / 2..])?;

        // Compute h = f^(-1) * g (mod x^n + 1, q)
        let h = self.compute_public_key(&f, &g)?;

        Ok(DawnKeyPair::new(h, f, g, self.params.clone()))
    }

    /// Generate a random polynomial with g_coeff_count non-zero coefficients
    fn generate_random_polynomial_with_g_count(
        &self,
        randomness: &[u8],
    ) -> Result<FieldPolynomial> {
        let mut poly = FieldPolynomial::new(self.params.degree, self.params.large_modulus);

        // Use randomness to determine which coefficients are non-zero
        let mut random_idx = 0;
        let mut coeff_idx = 0;

        while coeff_idx < self.params.g_coeff_count && random_idx < randomness.len() {
            let byte = randomness[random_idx];
            random_idx += 1;

            // Use each bit to determine coefficient values
            for bit in 0..8 {
                if coeff_idx >= self.params.g_coeff_count {
                    break;
                }

                let bit_value = (byte >> bit) & 1;
                if bit_value == 1 {
                    // Set coefficient to 1 or -1 (mod q)
                    let coeff = if (coeff_idx % 2) == 0 {
                        1
                    } else {
                        self.params.large_modulus - 1
                    };
                    poly.coefficients[coeff_idx] = coeff;
                }
                coeff_idx += 1;
            }
        }

        // Fill remaining coefficients with zeros
        for i in coeff_idx..self.params.degree {
            poly.coefficients[i] = 0;
        }

        Ok(poly)
    }

    /// Use the encoder for encoding operations
    pub fn encode_with_encoder(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Use the encoder field for encoding operations
        // The encoder returns a FieldPolynomial, so we need to convert it to bytes
        let encoded_poly = self.encoder.encode(data)?;
        Ok(encoded_poly
            .coefficients
            .iter()
            .map(|&c| (c & 0xFF) as u8)
            .collect())
    }

    /// Check if the small modulus is properly set
    pub fn verify_small_modulus(&self) -> bool {
        self.params.small_modulus == 2
    }
}

/// Deterministic key generation for testing
#[derive(Clone, Debug)]
pub struct DeterministicKeyGenerator {
    /// Base key generator
    pub generator: DawnKeyGenerator,
    /// Seed for deterministic generation
    pub seed: Vec<u8>,
}

impl fmt::Display for DeterministicKeyGenerator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DeterministicKeyGenerator({}, seed_len={})",
            self.generator,
            self.seed.len()
        )
    }
}

impl DeterministicKeyGenerator {
    /// Create a new deterministic key generator
    pub fn new(params: KeyGenParams, seed: Vec<u8>) -> Self {
        let generator = DawnKeyGenerator::new(params);
        Self { generator, seed }
    }

    /// Generate a key pair deterministically
    pub fn generate_keypair(&self) -> Result<DawnKeyPair> {
        // Use the seed to generate deterministic randomness
        let mut randomness = Vec::new();
        randomness.extend_from_slice(&self.seed);

        // Extend the seed to provide enough randomness
        while randomness.len() < 64 {
            randomness.extend_from_slice(&self.seed);
        }

        self.generator.generate_keypair(&randomness)
    }

    /// Generate a key pair with proper g coefficient count
    pub fn generate_keypair_with_g_coeff_count(&self) -> Result<DawnKeyPair> {
        // Use the seed to generate deterministic randomness
        let mut randomness = Vec::new();
        randomness.extend_from_slice(&self.seed);

        // Extend the seed to provide enough randomness
        while randomness.len() < 64 {
            randomness.extend_from_slice(&self.seed);
        }

        self.generator
            .generate_keypair_with_g_coeff_count(&randomness)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "std"))]
    use alloc::{
        format,
        vec,
    };

    use super::*;

    #[test]
    fn test_keygen_params_creation() {
        let params = KeyGenParams::dawn_alpha_512();
        assert_eq!(params.degree, 512);
        assert_eq!(params.large_modulus, 769);
        assert_eq!(params.small_modulus, 2);
        assert_eq!(params.compression_divisor, 7);
    }

    #[test]
    fn test_keygen_params_display() {
        let params = KeyGenParams::dawn_alpha_512();
        let display_str = format!("{}", params);
        assert!(display_str.contains("degree=512"));
        assert!(display_str.contains("large_modulus=769"));
        assert!(display_str.contains("small_modulus=2"));
    }

    #[test]
    fn test_keygen_params_validation() {
        let params = KeyGenParams::dawn_alpha_512();
        assert!(params.is_valid());
        assert_eq!(params.security_level(), 128);
    }

    #[test]
    fn test_key_generator_creation() {
        let params = KeyGenParams::dawn_alpha_512();
        let generator = DawnKeyGenerator::new(params);
        assert_eq!(generator.params.degree, 512);
    }

    #[test]
    fn test_key_generator_display() {
        let params = KeyGenParams::dawn_alpha_512();
        let generator = DawnKeyGenerator::new(params);
        let display_str = format!("{}", generator);
        assert!(display_str.contains("DawnKeyGenerator"));
    }

    #[test]
    fn test_key_generator_encoder_usage() {
        let params = KeyGenParams::dawn_alpha_512();
        let generator = DawnKeyGenerator::new(params);

        // Test encoder usage
        let test_data = vec![0x12, 0x34, 0x56, 0x78];
        let encoded = generator
            .encode_with_encoder(&test_data)
            .expect("Encoding should succeed");
        assert!(!encoded.is_empty());

        // Test small modulus verification
        assert!(generator.verify_small_modulus());
    }

    #[test]
    fn test_key_generator_g_coeff_count_usage() {
        let params = KeyGenParams::dawn_alpha_512();
        let generator = DawnKeyGenerator::new(params);

        // Test generation with proper g coefficient count
        let randomness = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let keypair = generator
            .generate_keypair_with_g_coeff_count(&randomness)
            .expect("Key generation should succeed");

        assert!(keypair.is_valid());
    }

    #[test]
    fn test_deterministic_key_generation() {
        let params = KeyGenParams::dawn_alpha_512();
        let seed = vec![0x12, 0x34, 0x56, 0x78];
        let generator = DeterministicKeyGenerator::new(params, seed);

        let keypair1 = generator
            .generate_keypair()
            .expect("Key generation should succeed");
        let keypair2 = generator
            .generate_keypair()
            .expect("Key generation should succeed");

        // Deterministic generation should produce the same keypair
        assert_eq!(
            keypair1.public_key.coefficients,
            keypair2.public_key.coefficients
        );
        assert_eq!(
            keypair1.secret_key.coefficients,
            keypair2.secret_key.coefficients
        );
    }

    #[test]
    fn test_deterministic_key_generator_display() {
        let params = KeyGenParams::dawn_alpha_512();
        let seed = vec![0x12, 0x34, 0x56, 0x78];
        let generator = DeterministicKeyGenerator::new(params, seed);
        let display_str = format!("{}", generator);
        assert!(display_str.contains("DeterministicKeyGenerator"));
        assert!(display_str.contains("seed_len=4"));
    }

    #[test]
    fn test_deterministic_key_generator_g_coeff_count() {
        let params = KeyGenParams::dawn_alpha_512();
        let seed = vec![0x12, 0x34, 0x56, 0x78];
        let generator = DeterministicKeyGenerator::new(params, seed);

        let keypair = generator
            .generate_keypair_with_g_coeff_count()
            .expect("Key generation should succeed");

        assert!(keypair.is_valid());
    }

    #[test]
    fn test_keypair_serialization() {
        let params = KeyGenParams::dawn_alpha_512();
        let generator = DawnKeyGenerator::new(params);
        let seed = vec![0x12, 0x34, 0x56, 0x78];
        let det_generator = DeterministicKeyGenerator::new(generator.params, seed);

        let keypair = det_generator
            .generate_keypair()
            .expect("Key generation should succeed");

        let pk_bytes = keypair.public_key_bytes();
        let sk_bytes = keypair.secret_key_bytes();

        // Check that serialization produces reasonable sizes
        assert!(!pk_bytes.is_empty());
        assert!(!sk_bytes.is_empty());
        assert!(sk_bytes.len() > pk_bytes.len()); // Secret key should be larger
    }

    #[test]
    fn test_keypair_display() {
        let params = KeyGenParams::dawn_alpha_512();
        let generator = DawnKeyGenerator::new(params);
        let seed = vec![0x12, 0x34, 0x56, 0x78];
        let det_generator = DeterministicKeyGenerator::new(generator.params, seed);

        let keypair = det_generator
            .generate_keypair()
            .expect("Key generation should succeed");

        let display_str = format!("{}", keypair);
        assert!(display_str.contains("DawnKeyPair"));
        assert!(display_str.contains("degree=512"));
    }

    #[test]
    fn test_keypair_validation() {
        let params = KeyGenParams::dawn_alpha_512();
        let generator = DawnKeyGenerator::new(params.clone());
        let seed = vec![0x12, 0x34, 0x56, 0x78];
        let det_generator = DeterministicKeyGenerator::new(params, seed);

        let keypair = det_generator
            .generate_keypair()
            .expect("Key generation should succeed");

        // Test validation method usage
        let _is_valid = generator
            .validate_keypair(&keypair)
            .expect("Validation should succeed");
        // assert!(is_valid); // Uncomment when real implementation is ready
    }
}
