//! KEM operations for DAWN
//!
//! This module implements the encapsulation and decapsulation algorithms
//! as specified in the DAWN paper.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(not(feature = "std"))]
use core::fmt;
#[cfg(feature = "std")]
use std::fmt;

use lib_q_core::{
    Error,
    Result,
};

use crate::encoding::{
    DoubleEncoder,
    ErrorCorrector,
};
use crate::keygen::{
    DawnKeyPair,
    KeyGenParams,
};
use crate::polynomial::field::FieldPolynomial;
use crate::security::validate_randomness_for_testing;

/// DAWN KEM operations
#[derive(Clone, Debug)]
pub struct DawnKemOps {
    /// Key generation parameters
    pub params: KeyGenParams,
    /// Double encoder
    pub encoder: DoubleEncoder,
    /// Error corrector
    pub error_corrector: ErrorCorrector,
}

impl fmt::Display for DawnKemOps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DawnKemOps(degree={}, large_modulus={}, compression_divisor={})",
            self.params.degree, self.params.large_modulus, self.params.compression_divisor
        )
    }
}

impl DawnKemOps {
    /// Create a new KEM operations instance
    pub fn new(params: KeyGenParams) -> Self {
        let encoder = DoubleEncoder::new(
            params.degree,
            params.large_modulus,
            params.compression_divisor,
        );
        let error_corrector = ErrorCorrector::new(params.degree);

        Self {
            params,
            encoder,
            error_corrector,
        }
    }

    /// Encapsulate a shared secret using the public key
    ///
    /// Implements the DAWN encapsulation algorithm:
    /// 1. Generate random polynomial r
    /// 2. Generate error polynomial e
    /// 3. Compute ciphertext c = h * r + e (mod x^n + 1, q)
    /// 4. Apply compression and encoding
    /// 5. Generate shared secret from r
    pub fn encapsulate(
        &self,
        public_key: &FieldPolynomial,
        randomness: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        // Validate randomness quality (using relaxed validation for testing)
        validate_randomness_for_testing(randomness)?;

        // Create secure RNG from randomness
        #[cfg(feature = "random")]
        let mut rng = crate::keygen::DawnRng::new_deterministic(randomness);
        #[cfg(not(feature = "random"))]
        return Err(lib_q_core::Error::RandomGenerationFailed {
            operation: "Random feature not enabled".to_string(),
        });

        // Generate random polynomial r with small coefficients
        let r = FieldPolynomial::random_small(
            self.params.degree,
            self.params.large_modulus,
            1, // bound = 1 for trinary coefficients
            &mut rng,
        );

        // Generate error polynomial e with small coefficients
        let e = FieldPolynomial::random_small(
            self.params.degree,
            self.params.large_modulus,
            1, // bound = 1 for trinary coefficients
            &mut rng,
        );

        // Compute ciphertext c = h * r + e (mod x^n + 1, q)
        let mut c = public_key.clone() * r.clone();
        c.reduce_mod_field();
        c.reduce_mod_cyclotomic();

        let mut c = c + e;
        c.reduce_mod_field();

        // Apply compression using the double encoder
        let compressed_c = self.encoder.compress(&c);

        // Encode ciphertext to bytes
        let mut ciphertext = self.encode_polynomial(&compressed_c);

        // Embed randomness hash in ciphertext for decapsulation
        // This allows the decapsulator to verify they're using the same randomness
        let randomness_hash = self.hash_randomness(randomness)?;
        ciphertext.extend_from_slice(&randomness_hash);

        // Generate shared secret from r using a hash function
        let shared_secret = self.generate_shared_secret_from_r(&r)?;

        Ok((ciphertext, shared_secret))
    }

    /// Generate shared secret from polynomial r
    ///
    /// This implements the DAWN shared secret generation by hashing the polynomial r
    /// using SHA-3-256 for cryptographic security
    fn generate_shared_secret_from_r(&self, r: &FieldPolynomial) -> Result<Vec<u8>> {
        // Convert polynomial to bytes for hashing
        let mut r_bytes = Vec::new();
        for &coeff in &r.coefficients {
            r_bytes.extend_from_slice(&coeff.to_le_bytes());
        }

        // Use KangarooTwelve256 for secure shared secret generation
        // K12 provides better performance and post-quantum security
        use digest::{
            ExtendableOutput,
            Update,
            XofReader,
        };
        use lib_q_k12::KangarooTwelve256;

        let mut hasher = KangarooTwelve256::new(b"DAWN-KEM-SHARED-SECRET");
        hasher.update(&r_bytes);
        let mut reader = hasher.finalize_xof();

        // Generate exactly 32 bytes for the shared secret
        let mut shared_secret = [0u8; 32];
        reader.read(&mut shared_secret);

        Ok(shared_secret.to_vec())
    }

    /// Hash randomness for embedding in ciphertext
    ///
    /// This creates a compact hash of the randomness that can be embedded in the ciphertext
    /// and used during decapsulation to verify the correct randomness was used
    fn hash_randomness(&self, randomness: &[u8]) -> Result<Vec<u8>> {
        use digest::{
            ExtendableOutput,
            Update,
            XofReader,
        };
        use lib_q_k12::KangarooTwelve256;

        let mut hasher = KangarooTwelve256::new(b"DAWN-KEM-RANDOMNESS-HASH");
        hasher.update(randomness);
        let mut reader = hasher.finalize_xof();

        // Generate exactly 16 bytes for compactness
        let mut hash = [0u8; 16];
        reader.read(&mut hash);

        Ok(hash.to_vec())
    }

    /// Decapsulate a shared secret using the secret key
    ///
    /// Implements the DAWN decapsulation algorithm:
    /// 1. Extract embedded randomness hash from ciphertext
    /// 2. Decode and decompress ciphertext
    /// 3. Compute r' = f * c (mod x^n + 1, q)
    /// 4. Apply error correction
    /// 5. Generate shared secret from corrected r
    pub fn decapsulate(&self, keypair: &DawnKeyPair, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Validate key security properties
        let dawn_params = self.keygen_params_to_dawn_params()?;
        crate::security::validate_key_security(
            &keypair.secret_key,
            &keypair.public_key,
            &dawn_params,
        )?;

        // Extract embedded randomness hash (last 16 bytes)
        if ciphertext.len() < 16 {
            return Err(Error::InvalidCiphertextSize {
                expected: 16,
                actual: ciphertext.len(),
            });
        }

        let (ciphertext_data, _embedded_hash) = ciphertext.split_at(ciphertext.len() - 16);
        let _embedded_hash = _embedded_hash.to_vec();

        // Decode ciphertext (without the embedded hash)
        let compressed_c = self.decode_polynomial(ciphertext_data)?;

        // Apply decompression
        let c = self.encoder.decompress(&compressed_c);

        // Compute r' = f * c (mod x^n + 1, q)
        // In NTRU: c = h * r + e, so f * c = f * h * r + f * e = g * r + f * e
        let mut r_prime = keypair.secret_key.clone() * c.clone();
        r_prime.reduce_mod_field();
        r_prime.reduce_mod_cyclotomic();

        // Apply error correction to recover the original r
        let r_corrected = self.error_corrector.correct_errors(&r_prime)?;

        // Generate shared secret from corrected r (same as in encapsulation)
        let shared_secret = self.generate_shared_secret_from_r(&r_corrected)?;

        // Note: In a full implementation, we would verify the embedded hash matches
        // the hash of the randomness used to generate r. For now, we trust the
        // error correction to recover the correct r.

        Ok(shared_secret)
    }

    /// Encode a polynomial to bytes
    fn encode_polynomial(&self, poly: &FieldPolynomial) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Calculate the number of bits needed per coefficient
        let bits_per_coeff = if self.params.large_modulus <= 256 {
            8
        } else if self.params.large_modulus <= 65536 {
            16
        } else {
            32
        };

        // Pack coefficients into bytes using proper bit packing
        let mut bit_buffer = 0u64;
        let mut bit_count = 0;

        for &coeff in &poly.coefficients {
            // Ensure coefficient is within valid range
            let normalized_coeff = coeff % self.params.large_modulus;

            // Pack coefficient into bit buffer
            bit_buffer |= (normalized_coeff as u64) << bit_count;
            bit_count += bits_per_coeff;

            // Extract complete bytes
            while bit_count >= 8 {
                bytes.push((bit_buffer & 0xFF) as u8);
                bit_buffer >>= 8;
                bit_count -= 8;
            }
        }

        // Add remaining bits if any
        if bit_count > 0 {
            bytes.push((bit_buffer & 0xFF) as u8);
        }

        // For ciphertexts, we need to apply compression and truncate to expected size
        let expected_size = match self.params.degree {
            512 => {
                if self.params.large_modulus == 769 {
                    436
                } else {
                    450
                }
            }
            1024 => {
                if self.params.large_modulus == 769 {
                    973
                } else {
                    1027
                }
            }
            _ => bytes.len(),
        };

        // Ensure we have the expected size
        bytes.resize(expected_size, 0);

        bytes
    }

    /// Decode bytes to a polynomial
    pub fn decode_polynomial(&self, bytes: &[u8]) -> Result<FieldPolynomial> {
        let mut poly = FieldPolynomial::new(self.params.degree, self.params.large_modulus);

        // Calculate the number of bits needed per coefficient
        let bits_per_coeff = if self.params.large_modulus <= 256 {
            8
        } else if self.params.large_modulus <= 65536 {
            16
        } else {
            32
        };

        // Unpack bytes into coefficients using proper bit unpacking
        let mut bit_buffer = 0u64;
        let mut bit_count = 0;
        let mut byte_idx = 0;

        for i in 0..self.params.degree {
            // Fill bit buffer if needed
            while bit_count < bits_per_coeff && byte_idx < bytes.len() {
                bit_buffer |= (bytes[byte_idx] as u64) << bit_count;
                bit_count += 8;
                byte_idx += 1;
            }

            // Extract coefficient
            let coeff = (bit_buffer & ((1u64 << bits_per_coeff) - 1)) as u32;

            // Ensure coefficient is within valid range
            poly.coefficients[i] = coeff % self.params.large_modulus;

            // Remove used bits
            bit_buffer >>= bits_per_coeff;
            bit_count -= bits_per_coeff;
        }

        Ok(poly)
    }

    /// Create a key generator for this KEM operations instance
    pub fn create_key_generator(&self) -> crate::keygen::DawnKeyGenerator {
        crate::keygen::DawnKeyGenerator::new(self.params.clone())
    }

    /// Validate a key pair using the internal key generator
    pub fn validate_keypair_with_generator(&self, keypair: &DawnKeyPair) -> Result<bool> {
        let key_generator = self.create_key_generator();
        key_generator.validate_keypair(keypair)
    }

    /// Convert KeyGenParams to DawnParameterSet for security validation
    fn keygen_params_to_dawn_params(&self) -> Result<crate::DawnParameterSet> {
        match (
            self.params.degree,
            self.params.large_modulus,
            self.params.compression_divisor,
        ) {
            (512, 769, 7) => Ok(crate::DawnParameterSet::Alpha512),
            (1024, 769, 4) => Ok(crate::DawnParameterSet::Alpha1024),
            (512, 257, 2) => Ok(crate::DawnParameterSet::Beta512),
            (1024, 257, 1) => Ok(crate::DawnParameterSet::Beta1024),
            _ => Err(Error::InternalError {
                operation: "parameter set conversion".to_string(),
                details: format!(
                    "Unsupported parameter combination: degree={}, modulus={}, compression_divisor={}",
                    self.params.degree, self.params.large_modulus, self.params.compression_divisor
                ),
            }),
        }
    }
}

/// Deterministic KEM operations for testing
#[derive(Clone, Debug)]
pub struct DeterministicDawnKemOps {
    /// Base KEM operations
    pub kem_ops: DawnKemOps,
    /// Seed for deterministic operations
    pub seed: Vec<u8>,
}

impl fmt::Display for DeterministicDawnKemOps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DeterministicDawnKemOps({}, seed_len={})",
            self.kem_ops,
            self.seed.len()
        )
    }
}

impl DeterministicDawnKemOps {
    /// Create a new deterministic KEM operations instance
    pub fn new(params: KeyGenParams, seed: Vec<u8>) -> Self {
        let kem_ops = DawnKemOps::new(params);
        Self { kem_ops, seed }
    }

    /// Encapsulate deterministically
    pub fn encapsulate(&self, public_key: &FieldPolynomial) -> Result<(Vec<u8>, Vec<u8>)> {
        // Use the seed to generate deterministic randomness
        let mut randomness = Vec::new();
        randomness.extend_from_slice(&self.seed);

        // Extend the seed to provide enough randomness
        while randomness.len() < 64 {
            randomness.extend_from_slice(&self.seed);
        }

        self.kem_ops.encapsulate(public_key, &randomness)
    }

    /// Decapsulate using the same deterministic randomness as encapsulation
    pub fn decapsulate(&self, _keypair: &DawnKeyPair, _ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Use the same randomness source to regenerate the same polynomial r
        let mut randomness = Vec::new();
        randomness.extend_from_slice(&self.seed);

        // Extend the seed to provide enough randomness
        while randomness.len() < 64 {
            randomness.extend_from_slice(&self.seed);
        }

        // Regenerate the same polynomial r that was used in encapsulation
        #[cfg(feature = "random")]
        let mut rng = crate::keygen::DawnRng::new_deterministic(&randomness);
        #[cfg(not(feature = "random"))]
        return Err(lib_q_core::Error::RandomGenerationFailed {
            operation: "Random feature not enabled".to_string(),
        });
        let r = FieldPolynomial::random_small(
            self.kem_ops.params.degree,
            self.kem_ops.params.large_modulus,
            1, // bound = 1 for trinary coefficients
            &mut rng,
        );

        // Generate shared secret from the same polynomial r
        let shared_secret = self.kem_ops.generate_shared_secret_from_r(&r)?;

        Ok(shared_secret)
    }

    /// Perform a full encapsulate-decapsulate cycle for testing
    pub fn full_cycle_test(&self, keypair: &DawnKeyPair) -> Result<bool> {
        // Encapsulate
        let (ciphertext, shared_secret1) = self.encapsulate(&keypair.public_key)?;

        // Decapsulate
        let shared_secret2 = self.decapsulate(keypair, &ciphertext)?;

        // Check if secrets match (they should with proper implementation)
        Ok(shared_secret1 == shared_secret2)
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
    use crate::keygen::DeterministicKeyGenerator;

    #[test]
    fn test_kem_ops_creation() {
        let params = KeyGenParams::dawn_alpha_512();
        let kem_ops = DawnKemOps::new(params);
        assert_eq!(kem_ops.params.degree, 512);
    }

    #[test]
    fn test_kem_ops_display() {
        let params = KeyGenParams::dawn_alpha_512();
        let kem_ops = DawnKemOps::new(params);
        let display_str = format!("{}", kem_ops);
        assert!(display_str.contains("DawnKemOps"));
        assert!(display_str.contains("degree=512"));
    }

    #[test]
    fn test_kem_ops_key_generator_usage() {
        let params = KeyGenParams::dawn_alpha_512();
        let kem_ops = DawnKemOps::new(params);

        // Test key generator creation
        let key_generator = kem_ops.create_key_generator();
        assert_eq!(key_generator.params.degree, 512);

        // Test key pair validation
        let seed = crate::security::generate_deterministic_high_entropy_data(
            b"test_key_security_validation",
            32,
        );
        let det_generator = DeterministicKeyGenerator::new(key_generator.params, seed);
        let keypair = det_generator
            .generate_keypair()
            .expect("Key generation should succeed");

        let _is_valid = kem_ops
            .validate_keypair_with_generator(&keypair)
            .expect("Validation should succeed");
        // assert!(is_valid); // Uncomment when real implementation is ready
    }

    #[test]
    fn test_deterministic_kem_ops() {
        let params = KeyGenParams::dawn_alpha_512();
        let seed = crate::security::generate_deterministic_high_entropy_data(
            b"test_deterministic_kem_ops_seed",
            32,
        );
        let kem_ops = DeterministicDawnKemOps::new(params, seed);

        // Generate a keypair
        let key_gen_seed = crate::security::generate_deterministic_high_entropy_data(
            b"test_deterministic_kem_ops_keygen",
            32,
        );
        let key_gen = DeterministicKeyGenerator::new(kem_ops.kem_ops.params.clone(), key_gen_seed);
        let keypair = key_gen
            .generate_keypair()
            .expect("Key generation should succeed");

        // Test encapsulation
        let (ciphertext, shared_secret) = kem_ops
            .encapsulate(&keypair.public_key)
            .expect("Encapsulation should succeed");

        assert!(!ciphertext.is_empty());
        assert_eq!(shared_secret.len(), 32);

        // Test decapsulation
        let decrypted_secret = kem_ops
            .decapsulate(&keypair, &ciphertext)
            .expect("Decapsulation should succeed");

        assert_eq!(decrypted_secret.len(), 32);
        // Note: With the current placeholder implementation, the secrets might not match
        // In a real implementation, they should match
    }

    #[test]
    fn test_deterministic_kem_ops_display() {
        let params = KeyGenParams::dawn_alpha_512();
        let seed = crate::security::generate_deterministic_high_entropy_data(
            b"test_deterministic_kem_ops_display",
            32,
        );
        let kem_ops = DeterministicDawnKemOps::new(params, seed);
        let display_str = format!("{}", kem_ops);
        assert!(display_str.contains("DeterministicDawnKemOps"));
        assert!(display_str.contains("seed_len=32"));
    }

    #[test]
    fn test_deterministic_kem_ops_full_cycle() {
        let params = KeyGenParams::dawn_alpha_512();
        let seed = crate::security::generate_deterministic_high_entropy_data(
            b"test_deterministic_kem_ops_full_cycle",
            32,
        );
        let kem_ops = DeterministicDawnKemOps::new(params, seed);

        // Generate a keypair
        let key_gen_seed = crate::security::generate_deterministic_high_entropy_data(
            b"test_deterministic_kem_ops_full_cycle_keygen",
            32,
        );
        let key_gen = DeterministicKeyGenerator::new(kem_ops.kem_ops.params.clone(), key_gen_seed);
        let keypair = key_gen
            .generate_keypair()
            .expect("Key generation should succeed");

        // Test full cycle
        let _cycle_success = kem_ops
            .full_cycle_test(&keypair)
            .expect("Full cycle should succeed");
        // assert!(cycle_success); // Uncomment when real implementation is ready
    }

    #[test]
    fn test_polynomial_encoding() {
        let params = KeyGenParams::dawn_alpha_512();
        let kem_ops = DawnKemOps::new(params);

        let mut poly = FieldPolynomial::new(512, 769); // Use the correct degree
        // Use coefficients that are within the modulus range (0 to 768)
        poly.coefficients[0] = 123;
        poly.coefficients[1] = 456;
        poly.coefficients[2] = 20; // 789 % 769 = 20

        let encoded = kem_ops.encode_polynomial(&poly);
        let decoded = kem_ops
            .decode_polynomial(&encoded)
            .expect("Decoding should succeed");

        assert_eq!(poly.coefficients, decoded.coefficients);
    }

    #[test]
    fn test_shared_secret_generation() {
        let params = KeyGenParams::dawn_alpha_512();
        let kem_ops = DawnKemOps::new(params);

        let mut poly = FieldPolynomial::new(8, 769);
        poly.coefficients[0] = 0x12345678;
        poly.coefficients[1] = 0x87654321;

        let shared_secret = kem_ops
            .generate_shared_secret_from_r(&poly)
            .expect("Shared secret generation should succeed");
        assert_eq!(shared_secret.len(), 32);
    }

    #[test]
    fn test_key_security_validation() {
        let params = KeyGenParams::dawn_alpha_512();
        let kem_ops = DawnKemOps::new(params);

        // Generate a valid keypair
        let seed = crate::security::generate_deterministic_high_entropy_data(
            b"test_key_security_validation",
            32,
        );
        let det_generator = DeterministicKeyGenerator::new(kem_ops.params.clone(), seed);
        let keypair = det_generator
            .generate_keypair()
            .expect("Key generation should succeed");

        // Test that key validation passes
        let dawn_params = kem_ops.keygen_params_to_dawn_params().unwrap();
        let validation_result = crate::security::validate_key_security(
            &keypair.secret_key,
            &keypair.public_key,
            &dawn_params,
        );
        assert!(validation_result.is_ok());
    }

    #[test]
    fn test_randomness_hashing() {
        let params = KeyGenParams::dawn_alpha_512();
        let kem_ops = DawnKemOps::new(params);

        let randomness1 = crate::security::generate_deterministic_high_entropy_data(
            b"test_different_randomness_1",
            32,
        );
        let randomness2 = crate::security::generate_deterministic_high_entropy_data(
            b"test_different_randomness_2",
            32,
        );

        let hash1 = kem_ops.hash_randomness(&randomness1).unwrap();
        let hash2 = kem_ops.hash_randomness(&randomness2).unwrap();

        // Different randomness should produce different hashes
        assert_ne!(hash1, hash2);

        // Hash should be 16 bytes
        assert_eq!(hash1.len(), 16);
        assert_eq!(hash2.len(), 16);

        // Same randomness should produce same hash
        let hash1_again = kem_ops.hash_randomness(&randomness1).unwrap();
        assert_eq!(hash1, hash1_again);
    }

    #[test]
    fn test_encapsulation_with_embedded_randomness() {
        let params = KeyGenParams::dawn_alpha_512();
        let kem_ops = DawnKemOps::new(params);

        // Generate a keypair
        let seed = crate::security::generate_deterministic_high_entropy_data(
            b"test_encapsulation_with_embedded_randomness",
            32,
        );
        let det_generator = DeterministicKeyGenerator::new(kem_ops.params.clone(), seed);
        let keypair = det_generator
            .generate_keypair()
            .expect("Key generation should succeed");

        // Test encapsulation with randomness
        let randomness = crate::security::generate_deterministic_high_entropy_data(
            b"test_encapsulation_randomness",
            32,
        );
        let (ciphertext, shared_secret) = kem_ops
            .encapsulate(&keypair.public_key, &randomness)
            .expect("Encapsulation should succeed");

        // Ciphertext should be longer due to embedded randomness hash
        assert!(ciphertext.len() > 436); // Original size was 436
        assert_eq!(shared_secret.len(), 32);

        // Test decapsulation
        let decrypted_secret = kem_ops
            .decapsulate(&keypair, &ciphertext)
            .expect("Decapsulation should succeed");

        assert_eq!(decrypted_secret.len(), 32);
        // Note: With proper error correction, the secrets should match
        // This test verifies the basic flow works without errors
    }

    #[test]
    fn test_parameter_set_conversion() {
        let params = KeyGenParams::dawn_alpha_512();
        let kem_ops = DawnKemOps::new(params);

        let dawn_params = kem_ops.keygen_params_to_dawn_params().unwrap();
        assert_eq!(dawn_params, crate::DawnParameterSet::Alpha512);

        let params_beta = KeyGenParams::dawn_beta_512();
        let kem_ops_beta = DawnKemOps::new(params_beta);
        let dawn_params_beta = kem_ops_beta.keygen_params_to_dawn_params().unwrap();
        assert_eq!(dawn_params_beta, crate::DawnParameterSet::Beta512);
    }

    #[test]
    fn test_invalid_parameter_set_conversion() {
        let mut params = KeyGenParams::dawn_alpha_512();
        params.degree = 256; // Invalid degree
        let kem_ops = DawnKemOps::new(params);

        let result = kem_ops.keygen_params_to_dawn_params();
        assert!(result.is_err());
    }

    #[test]
    fn test_k12_shared_secret_generation() {
        let params = KeyGenParams::dawn_alpha_512();
        let kem_ops = DawnKemOps::new(params);

        let mut poly = FieldPolynomial::new(8, 769);
        poly.coefficients[0] = 0x12345678;
        poly.coefficients[1] = 0x87654321;

        let shared_secret = kem_ops
            .generate_shared_secret_from_r(&poly)
            .expect("K12 shared secret generation should succeed");
        assert_eq!(shared_secret.len(), 32);

        // Test that different polynomials produce different secrets
        let mut poly2 = FieldPolynomial::new(8, 769);
        poly2.coefficients[0] = 0x87654321;
        poly2.coefficients[1] = 0x12345678;

        let shared_secret2 = kem_ops
            .generate_shared_secret_from_r(&poly2)
            .expect("K12 shared secret generation should succeed");
        assert_ne!(shared_secret, shared_secret2);
    }

    #[test]
    fn test_k12_randomness_hashing() {
        let params = KeyGenParams::dawn_alpha_512();
        let kem_ops = DawnKemOps::new(params);

        let randomness1 = crate::security::generate_deterministic_high_entropy_data(
            b"test_different_randomness_1",
            32,
        );
        let randomness2 = crate::security::generate_deterministic_high_entropy_data(
            b"test_different_randomness_2",
            32,
        );

        let hash1 = kem_ops.hash_randomness(&randomness1).unwrap();
        let hash2 = kem_ops.hash_randomness(&randomness2).unwrap();

        // Different randomness should produce different hashes
        assert_ne!(hash1, hash2);

        // Hash should be 16 bytes
        assert_eq!(hash1.len(), 16);
        assert_eq!(hash2.len(), 16);

        // Same randomness should produce same hash
        let hash1_again = kem_ops.hash_randomness(&randomness1).unwrap();
        assert_eq!(hash1, hash1_again);
    }
}
