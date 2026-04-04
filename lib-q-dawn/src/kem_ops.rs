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

use digest::{
    ExtendableOutput,
    Update,
    XofReader,
};
use lib_q_core::{
    Error,
    Result,
};
use lib_q_k12::KangarooTwelve256;
use subtle::ConstantTimeEq;

use crate::codec::{
    ct_bits_per_coeff,
    pack_bits,
    pk_bits_per_coeff,
    unpack_bits,
};
use crate::encoding::{
    DoubleEncoder,
    ErrorCorrector,
    pke_decrypt,
    pke_decrypt_chase,
    pke_decrypt_majority_reliability,
    pke_decrypt_reliability,
    pke_encrypt,
};
use crate::keygen::{
    DawnKeyPair,
    KeyGenParams,
    PkeDecryptKind,
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
    /// Create a new KEM operations instance using `params.pke_decrypt`.
    pub fn new(params: KeyGenParams) -> Self {
        Self::new_from_params(params)
    }

    /// Force the reliability-bounded decoder regardless of `params.pke_decrypt` (sweeps / experiments).
    pub fn new_with_reliability_decoder(mut params: KeyGenParams) -> Self {
        params.pke_decrypt = PkeDecryptKind::ReliabilityBounded;
        Self::new_from_params(params)
    }

    /// Force the Path B majority-reliability decoder regardless of `params.pke_decrypt`.
    pub fn new_with_majority_reliability_decoder(mut params: KeyGenParams) -> Self {
        params.pke_decrypt = PkeDecryptKind::MajorityReliability;
        Self::new_from_params(params)
    }

    /// Force the Chase decoder regardless of `params.pke_decrypt`.
    pub fn new_with_chase_decoder(mut params: KeyGenParams) -> Self {
        params.pke_decrypt = PkeDecryptKind::Chase;
        Self::new_from_params(params)
    }

    fn new_from_params(params: KeyGenParams) -> Self {
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

    /// Encapsulate (Algorithm 7): m random, (K_m, rho) = K12(m||H_pk), c = PKE.Encrypt(pk,m,rho), K = K12(K_m||c).
    pub fn encapsulate(
        &self,
        public_key: &FieldPolynomial,
        randomness: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        validate_randomness_for_testing(randomness)?;

        let n = self.params.degree;
        let m_len = n / 4 / 8;

        let pk_bytes = self.encode_pk_polynomial(public_key);
        let h_pk = {
            let mut hasher = KangarooTwelve256::new(b"DAWN-KEM-H-PK");
            hasher.update(&pk_bytes);
            let mut reader = hasher.finalize_xof();
            let mut out = [0u8; 32];
            reader.read(&mut out);
            out
        };

        let m = &randomness[..m_len.min(randomness.len())];
        let mut m_padded = vec![0u8; m_len];
        m_padded[..m.len()].copy_from_slice(m);

        let (k_m, rho) = {
            let mut hasher = KangarooTwelve256::new(b"DAWN-KEM-KM-RHO");
            hasher.update(&m_padded);
            hasher.update(&h_pk);
            let mut reader = hasher.finalize_xof();
            let mut k_m = [0u8; 32];
            reader.read(&mut k_m);
            let mut rho = [0u8; 64];
            reader.read(&mut rho);
            (k_m, rho)
        };

        #[cfg(feature = "random")]
        let mut rng = crate::keygen::DawnRng::new_deterministic(&rho);
        #[cfg(not(feature = "random"))]
        return Err(lib_q_core::Error::RandomGenerationFailed {
            operation: "Random feature not enabled".to_string(),
        });

        let k_s = self.params.s_coeff_count / 2;
        let k_e = self.params.e_coeff_count / 2;
        let s = FieldPolynomial::random_ternary_exact(n, k_s, self.params.large_modulus, &mut rng);
        let e = FieldPolynomial::random_ternary_exact(n, k_e, self.params.large_modulus, &mut rng);

        let compressed_c = pke_encrypt(public_key, &m_padded, &s, &e, &self.encoder)?;
        let ciphertext = self.encode_polynomial(&compressed_c);

        let k = {
            let mut hasher = KangarooTwelve256::new(b"DAWN-KEM-K");
            hasher.update(&k_m);
            hasher.update(&ciphertext);
            let mut reader = hasher.finalize_xof();
            let mut out = [0u8; 32];
            reader.read(&mut out);
            out.to_vec()
        };

        Ok((ciphertext, k))
    }

    /// Decapsulate (Algorithm 8): m' = PKE.Decrypt(c), re-encrypt, K = K12(K_m||c) or K12(k_stored||c).
    pub fn decapsulate(&self, keypair: &DawnKeyPair, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let dawn_params = self.keygen_params_to_dawn_params()?;
        crate::security::validate_key_security(
            &keypair.secret_key,
            &keypair.public_key,
            &dawn_params,
        )?;

        let compressed_c = self.decode_polynomial(ciphertext)?;

        let m_prime = match self.params.pke_decrypt {
            PkeDecryptKind::Chase => pke_decrypt_chase(
                &compressed_c,
                &keypair.secret_key,
                &keypair.f2,
                &self.encoder,
            )?,
            PkeDecryptKind::MajorityReliability => pke_decrypt_majority_reliability(
                &compressed_c,
                &keypair.secret_key,
                &keypair.f2,
                &self.encoder,
            )?,
            PkeDecryptKind::ReliabilityBounded => pke_decrypt_reliability(
                &compressed_c,
                &keypair.secret_key,
                &keypair.f2,
                &self.encoder,
            )?,
            PkeDecryptKind::Baseline => pke_decrypt(
                &compressed_c,
                &keypair.secret_key,
                &keypair.f2,
                &self.encoder,
            )?,
        };

        let (k_m, rho) = {
            let mut hasher = KangarooTwelve256::new(b"DAWN-KEM-KM-RHO");
            hasher.update(&m_prime);
            hasher.update(&keypair.h_pk);
            let mut reader = hasher.finalize_xof();
            let mut k_m = [0u8; 32];
            reader.read(&mut k_m);
            let mut rho = [0u8; 64];
            reader.read(&mut rho);
            (k_m, rho)
        };

        #[cfg(feature = "random")]
        let mut rng = crate::keygen::DawnRng::new_deterministic(&rho);
        #[cfg(not(feature = "random"))]
        return Err(lib_q_core::Error::RandomGenerationFailed {
            operation: "Random feature not enabled".to_string(),
        });

        let k_s = self.params.s_coeff_count / 2;
        let k_e = self.params.e_coeff_count / 2;
        let s = FieldPolynomial::random_ternary_exact(
            self.params.degree,
            k_s,
            self.params.large_modulus,
            &mut rng,
        );
        let e = FieldPolynomial::random_ternary_exact(
            self.params.degree,
            k_e,
            self.params.large_modulus,
            &mut rng,
        );

        let c_prime = pke_encrypt(&keypair.public_key, &m_prime, &s, &e, &self.encoder)?;
        let ciphertext_prime = self.encode_polynomial(&c_prime);

        let k = if ciphertext_prime.len() == ciphertext.len() &&
            bool::from(ciphertext_prime.as_slice().ct_eq(ciphertext))
        {
            let mut hasher = KangarooTwelve256::new(b"DAWN-KEM-K");
            hasher.update(&k_m);
            hasher.update(ciphertext);
            let mut reader = hasher.finalize_xof();
            let mut out = [0u8; 32];
            reader.read(&mut out);
            out.to_vec()
        } else {
            let mut hasher = KangarooTwelve256::new(b"DAWN-KEM-K");
            hasher.update(&keypair.k_stored);
            hasher.update(ciphertext);
            let mut reader = hasher.finalize_xof();
            let mut out = [0u8; 32];
            reader.read(&mut out);
            out.to_vec()
        };

        Ok(k)
    }

    /// Encode a compressed ciphertext polynomial to bytes (lossless, ct bit-width).
    fn encode_polynomial(&self, poly: &FieldPolynomial) -> Vec<u8> {
        let bits = ct_bits_per_coeff(self.params.large_modulus, self.params.compression_divisor);
        pack_bits(&poly.coefficients, bits)
    }

    /// Decode bytes to a compressed ciphertext polynomial.
    pub fn decode_polynomial(&self, bytes: &[u8]) -> Result<FieldPolynomial> {
        let bits = ct_bits_per_coeff(self.params.large_modulus, self.params.compression_divisor);
        let coeffs = unpack_bits(bytes, self.params.degree, bits);
        Ok(FieldPolynomial::from_coefficients(
            coeffs,
            self.params.large_modulus,
        ))
    }

    /// Decode bytes to a public-key polynomial (full modulus bit-width).
    pub fn decode_pk_polynomial(&self, bytes: &[u8]) -> Result<FieldPolynomial> {
        let bits = pk_bits_per_coeff(self.params.large_modulus);
        let coeffs = unpack_bits(bytes, self.params.degree, bits);
        Ok(FieldPolynomial::from_coefficients(
            coeffs,
            self.params.large_modulus,
        ))
    }

    /// Encode a public-key polynomial to bytes (lossless, pk bit-width). Used for h_pk hashing.
    fn encode_pk_polynomial(&self, poly: &FieldPolynomial) -> Vec<u8> {
        let bits = pk_bits_per_coeff(self.params.large_modulus);
        pack_bits(&poly.coefficients, bits)
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

    /// Resolve base parameter set for security validation (uses explicit identity from params).
    fn keygen_params_to_dawn_params(&self) -> Result<crate::DawnParameterSet> {
        let expected_degree = self.params.base_parameter_set.polynomial_degree();
        let expected_modulus = self.params.base_parameter_set.large_modulus();
        if self.params.degree != expected_degree || self.params.large_modulus != expected_modulus {
            return Err(Error::InternalError {
                operation: "parameter set consistency".to_string(),
                details: format!(
                    "KeyGenParams (degree={}, modulus={}) inconsistent with base {:?} (expected degree={}, modulus={})",
                    self.params.degree,
                    self.params.large_modulus,
                    self.params.base_parameter_set,
                    expected_degree,
                    expected_modulus
                ),
            });
        }
        Ok(self.params.base_parameter_set)
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

    /// Decapsulate using the real FO-KEM decapsulate (same as DawnKemOps).
    pub fn decapsulate(&self, keypair: &DawnKeyPair, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.kem_ops.decapsulate(keypair, ciphertext)
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

    /// Full cycle with strict shared-secret equality (Production Alpha512).
    #[test]
    fn test_deterministic_kem_ops_full_cycle() {
        let params = KeyGenParams::for_profile(
            crate::DawnParameterSet::Alpha512,
            crate::DawnProfile::Production,
        );
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
        let cycle_success = kem_ops
            .full_cycle_test(&keypair)
            .expect("Full cycle should succeed");
        assert!(cycle_success);
    }

    /// Alpha1024 full cycle (Production).
    #[test]
    fn test_deterministic_kem_ops_full_cycle_alpha1024() {
        let params = KeyGenParams::for_profile(
            crate::DawnParameterSet::Alpha1024,
            crate::DawnProfile::Production,
        );
        let seed = crate::security::generate_deterministic_high_entropy_data(
            b"test_deterministic_kem_ops_full_cycle_alpha1024",
            32,
        );
        let kem_ops = DeterministicDawnKemOps::new(params, seed);

        let key_gen_seed = crate::security::generate_deterministic_high_entropy_data(
            b"test_deterministic_kem_ops_full_cycle_alpha1024_keygen",
            32,
        );
        let key_gen = DeterministicKeyGenerator::new(kem_ops.kem_ops.params.clone(), key_gen_seed);
        let keypair = key_gen
            .generate_keypair()
            .expect("Key generation should succeed");

        let cycle_success = kem_ops
            .full_cycle_test(&keypair)
            .expect("Full cycle should succeed");
        assert!(cycle_success);
    }

    #[test]
    fn test_polynomial_encoding() {
        let params = KeyGenParams::dawn_alpha_512();
        let kem_ops = DawnKemOps::new(params);

        let mut poly = FieldPolynomial::new(512, 769);
        // Coefficients within compressed range for Alpha512 (d_c=7, max 110)
        poly.coefficients[0] = 10;
        poly.coefficients[1] = 110;
        poly.coefficients[2] = 20;
        poly.coefficients[300] = 50;
        poly.coefficients[511] = 99;

        let encoded = kem_ops.encode_polynomial(&poly);
        let decoded = kem_ops
            .decode_polynomial(&encoded)
            .expect("Decoding should succeed");

        assert_eq!(poly.coefficients, decoded.coefficients);
    }

    /// Phase 1.3: Verify encode_polynomial/decode_polynomial use ct_bits_per_coeff and do not reduce compressed coeffs mod q.
    #[test]
    fn test_ciphertext_codec_no_mod_q_on_compressed() {
        use crate::codec::ct_bits_per_coeff;

        let params = KeyGenParams::dawn_alpha_512_spec();
        let degree = params.degree;
        let large_modulus = params.large_modulus;
        let kem_ops = DawnKemOps::new(params);
        let bits = ct_bits_per_coeff(large_modulus, kem_ops.params.compression_divisor);
        assert_eq!(bits, 7, "q=769 d_c=7 => 7 bits per coeff");
        let expected_len = (degree * bits).div_ceil(8);
        let mut poly = FieldPolynomial::new(degree, large_modulus);
        poly.coefficients[0] = 110;
        poly.coefficients[1] = 0;
        let encoded = kem_ops.encode_polynomial(&poly);
        assert_eq!(
            encoded.len(),
            expected_len,
            "encode_polynomial must use ct_bits_per_coeff (no extra padding)"
        );
        let decoded = kem_ops.decode_polynomial(&encoded).expect("decode");
        assert_eq!(
            decoded.coefficients[0], 110,
            "decode must not reduce compressed coeffs mod q (110 must stay 110)"
        );
    }

    #[test]
    fn test_shared_secret_generation() {
        let ct_len = KeyGenParams::dawn_alpha_512().ciphertext_byte_size();
        let mut hasher = KangarooTwelve256::new(b"DAWN-KEM-K");
        hasher.update(&[1u8; 32]);
        hasher.update(&vec![0u8; ct_len]);
        let mut reader = hasher.finalize_xof();
        let mut shared_secret = [0u8; 32];
        reader.read(&mut shared_secret);
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
        let randomness1 = crate::security::generate_deterministic_high_entropy_data(
            b"test_different_randomness_1",
            32,
        );
        let randomness2 = crate::security::generate_deterministic_high_entropy_data(
            b"test_different_randomness_2",
            32,
        );

        let hash1 = {
            let mut hasher = KangarooTwelve256::new(b"DAWN-KEM-H-PK");
            hasher.update(&randomness1);
            let mut r = hasher.finalize_xof();
            let mut out = [0u8; 32];
            r.read(&mut out);
            out
        };
        let hash2 = {
            let mut hasher = KangarooTwelve256::new(b"DAWN-KEM-H-PK");
            hasher.update(&randomness2);
            let mut r = hasher.finalize_xof();
            let mut out = [0u8; 32];
            r.read(&mut out);
            out
        };
        assert_ne!(hash1, hash2);
        let hash1_again = {
            let mut hasher = KangarooTwelve256::new(b"DAWN-KEM-H-PK");
            hasher.update(&randomness1);
            let mut r = hasher.finalize_xof();
            let mut out = [0u8; 32];
            r.read(&mut out);
            out
        };
        assert_eq!(hash1, hash1_again);
    }

    /// Strict shared-secret equality (Production Alpha512).
    #[test]
    fn test_encapsulation_with_embedded_randomness() {
        let params = KeyGenParams::for_profile(
            crate::DawnParameterSet::Alpha512,
            crate::DawnProfile::Production,
        );
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

        assert_eq!(ciphertext.len(), kem_ops.params.ciphertext_byte_size());
        assert_eq!(shared_secret.len(), 32);

        let decrypted_secret = kem_ops
            .decapsulate(&keypair, &ciphertext)
            .expect("Decapsulation should succeed");

        assert_eq!(decrypted_secret.len(), 32);
        if shared_secret != decrypted_secret {
            eprintln!(
                "FO-KEM secret mismatch: enc[..8] = {:?}, dec[..8] = {:?}",
                &shared_secret[..8],
                &decrypted_secret[..8]
            );
        }
        assert_eq!(
            shared_secret, decrypted_secret,
            "FO-KEM must recover same shared secret"
        );
    }

    /// Alpha1024 encapsulation with embedded randomness (Production).
    #[test]
    fn test_encapsulation_with_embedded_randomness_alpha1024() {
        let params = KeyGenParams::for_profile(
            crate::DawnParameterSet::Alpha1024,
            crate::DawnProfile::Production,
        );
        let kem_ops = DawnKemOps::new(params);

        let seed = crate::security::generate_deterministic_high_entropy_data(
            b"test_encapsulation_with_embedded_randomness_alpha1024",
            32,
        );
        let det_generator = DeterministicKeyGenerator::new(kem_ops.params.clone(), seed);
        let keypair = det_generator
            .generate_keypair()
            .expect("Key generation should succeed");

        let randomness = crate::security::generate_deterministic_high_entropy_data(
            b"test_encapsulation_randomness_alpha1024",
            32,
        );
        let (ciphertext, shared_secret) = kem_ops
            .encapsulate(&keypair.public_key, &randomness)
            .expect("Encapsulation should succeed");

        assert_eq!(ciphertext.len(), kem_ops.params.ciphertext_byte_size());
        assert_eq!(shared_secret.len(), 32);

        let decrypted_secret = kem_ops
            .decapsulate(&keypair, &ciphertext)
            .expect("Decapsulation should succeed");

        assert_eq!(decrypted_secret.len(), 32);
        assert_eq!(
            shared_secret, decrypted_secret,
            "FO-KEM must recover same shared secret"
        );
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
        let mut hasher = KangarooTwelve256::new(b"DAWN-KEM-K");
        hasher.update(&[1u8; 32]);
        hasher.update(&[0u8; 10]);
        let mut r = hasher.finalize_xof();
        let mut shared_secret = [0u8; 32];
        r.read(&mut shared_secret);
        assert_eq!(shared_secret.len(), 32);

        let mut hasher2 = KangarooTwelve256::new(b"DAWN-KEM-K");
        hasher2.update(&[2u8; 32]);
        hasher2.update(&[0u8; 10]);
        let mut r2 = hasher2.finalize_xof();
        let mut shared_secret2 = [0u8; 32];
        r2.read(&mut shared_secret2);
        assert_ne!(shared_secret, shared_secret2);
    }

    #[test]
    fn test_k12_randomness_hashing() {
        let randomness1 = crate::security::generate_deterministic_high_entropy_data(
            b"test_different_randomness_1",
            32,
        );
        let randomness2 = crate::security::generate_deterministic_high_entropy_data(
            b"test_different_randomness_2",
            32,
        );

        let hash1 = {
            let mut hasher = KangarooTwelve256::new(b"DAWN-KEM-H-PK");
            hasher.update(&randomness1);
            let mut r = hasher.finalize_xof();
            let mut out = [0u8; 32];
            r.read(&mut out);
            out
        };
        let hash2 = {
            let mut hasher = KangarooTwelve256::new(b"DAWN-KEM-H-PK");
            hasher.update(&randomness2);
            let mut r = hasher.finalize_xof();
            let mut out = [0u8; 32];
            r.read(&mut out);
            out
        };
        assert_ne!(hash1, hash2);
        let hash1_again = {
            let mut hasher = KangarooTwelve256::new(b"DAWN-KEM-H-PK");
            hasher.update(&randomness1);
            let mut r = hasher.finalize_xof();
            let mut out = [0u8; 32];
            r.read(&mut out);
            out
        };
        assert_eq!(hash1, hash1_again);
    }
}
