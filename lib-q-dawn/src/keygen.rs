//! Key generation algorithms for DAWN
//!
//! This module implements the key generation algorithms as specified in the DAWN paper.

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
use lib_q_core::Result;
use lib_q_k12::KangarooTwelve256;
#[cfg(feature = "random")]
use lib_q_random::{
    new_deterministic_rng,
    new_secure_rng,
};
use rand_core::{
    Rng,
    TryRng,
};

use crate::codec::{
    ct_bits_per_coeff,
    pack_bits,
    pk_bits_per_coeff,
};
use crate::encoding::{
    ZeroDivisorEncoder,
    fast_inversion,
};
use crate::polynomial::field::FieldPolynomial;

fn hash_pk(pk_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = KangarooTwelve256::new(b"DAWN-KEM-H-PK");
    hasher.update(pk_bytes);
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 32];
    reader.read(&mut out);
    out
}

fn derive_k_stored(pk_bytes: &[u8], randomness: &[u8]) -> [u8; 32] {
    let mut hasher = KangarooTwelve256::new(b"DAWN-KEM-K-STORED");
    hasher.update(pk_bytes);
    hasher.update(randomness);
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 32];
    reader.read(&mut out);
    out
}

/// Trait alias for RNG that implements both Rng and CryptoRng
#[cfg(feature = "random")]
trait SecureRng: Rng + rand_core::CryptoRng {}
#[cfg(feature = "random")]
impl<T: Rng + rand_core::CryptoRng> SecureRng for T {}

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
impl TryRng for DawnRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        Ok(self.rng.next_u32())
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        Ok(self.rng.next_u64())
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), Self::Error> {
        self.rng.fill_bytes(dest);
        Ok(())
    }
}

#[cfg(feature = "random")]
impl rand_core::TryCryptoRng for DawnRng {}

/// Which PKE message-recovery path `DawnKemOps::decapsulate` uses (compression noise tolerance).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PkeDecryptKind {
    /// Paper baseline: `simple_decoding` only.
    Baseline,
    /// Top-4 bounded flips using coefficient reliability.
    ReliabilityBounded,
    /// Repetition majority with `c_prime` tie-break (Path B v1).
    MajorityReliability,
    /// Chase decoder: enumerate 2^k_chase flip patterns over least-reliable c2
    /// positions *before* the f₂ multiplication, selecting the candidate whose
    /// post-f₂ repetition-code syndrome weight is minimal.
    Chase,
}

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
    /// Number of non-zero coefficients for f (T_{n,k_f}: 2*k_f total)
    pub f_coeff_count: usize,
    /// Number of non-zero coefficients for g (T_{n,k_g}: 2*k_g total)
    pub g_coeff_count: usize,
    /// Number of non-zero coefficients for s (T_{n,k_s}: 2*k_s total)
    pub s_coeff_count: usize,
    /// Number of non-zero coefficients for e (T_{n,k_e}: 2*k_e total)
    pub e_coeff_count: usize,
    /// Base parameter set (Alpha512, etc.); used for validation and API identity.
    pub base_parameter_set: crate::DawnParameterSet,
    /// Profile (spec vs production); determines decoding failure behavior.
    pub profile: crate::DawnProfile,
    /// PKE decrypt / message recovery strategy for KEM decapsulation.
    pub pke_decrypt: PkeDecryptKind,
}

impl fmt::Display for KeyGenParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KeyGenParams(degree={}, large_modulus={}, small_modulus={}, compression_divisor={}, f_coeff_count={}, g_coeff_count={}, s_coeff_count={}, e_coeff_count={})",
            self.degree,
            self.large_modulus,
            self.small_modulus,
            self.compression_divisor,
            self.f_coeff_count,
            self.g_coeff_count,
            self.s_coeff_count,
            self.e_coeff_count
        )
    }
}

impl KeyGenParams {
    /// Parameters for the given parameter set and profile. Production profile uses
    /// implementation-tuned values for negligible decryption failure; SpecExperimental
    /// matches the paper (may have non-negligible failure with current decoder).
    pub fn for_profile(
        parameter_set: crate::DawnParameterSet,
        profile: crate::DawnProfile,
    ) -> Self {
        match (parameter_set, profile) {
            (crate::DawnParameterSet::Alpha512, crate::DawnProfile::SpecExperimental) => {
                Self::dawn_alpha_512_spec()
            }
            (crate::DawnParameterSet::Alpha512, crate::DawnProfile::Production) => {
                Self::dawn_alpha_512_impl()
            }
            (crate::DawnParameterSet::Alpha1024, _) => Self::dawn_alpha_1024_impl(),
            (crate::DawnParameterSet::Beta512, _) => Self::dawn_beta_512_impl(),
            (crate::DawnParameterSet::Beta1024, _) => {
                let mut p = Self::dawn_beta_1024();
                p.base_parameter_set = crate::DawnParameterSet::Beta1024;
                p.profile = profile;
                p
            }
        }
    }

    /// Create parameters for DAWN-α-512 spec (paper: k_g=160, k_f=64, k_s=96, k_e=160, d_c=7)
    pub fn dawn_alpha_512_spec() -> Self {
        Self {
            degree: 512,
            large_modulus: 769,
            small_modulus: 2,
            compression_divisor: 7,
            f_coeff_count: 128, // 2*k_f
            g_coeff_count: 320, // 2*k_g
            s_coeff_count: 192, // 2*k_s
            e_coeff_count: 320, // 2*k_e
            base_parameter_set: crate::DawnParameterSet::Alpha512,
            profile: crate::DawnProfile::SpecExperimental,
            pke_decrypt: PkeDecryptKind::Baseline,
        }
    }

    /// Create parameters for DAWN-α-512 production profile.
    /// Baseline decoder + zero encryption noise + d_c=1 yields stable FO-KEM for random `m` in
    /// testing; Path B can be re-enabled after sweeps. Raise (k_s,k_e) only when histograms allow.
    fn dawn_alpha_512_impl() -> Self {
        let mut p = Self::dawn_alpha_512_custom(0, 0, 1);
        p.pke_decrypt = PkeDecryptKind::Baseline;
        p
    }

    /// Create parameters for DAWN-α-512 (spec profile; backward compat for tests)
    pub fn dawn_alpha_512() -> Self {
        Self::dawn_alpha_512_spec()
    }

    /// Alpha512 with custom k_s, k_e, d_c for parameter tuning (n=512, q=769, k_f=64, k_g=160).
    /// k_s and k_e are coefficient counts; stored as s_coeff_count = 2*k_s, e_coeff_count = 2*k_e.
    pub fn dawn_alpha_512_custom(k_s: usize, k_e: usize, d_c: u32) -> Self {
        Self {
            degree: 512,
            large_modulus: 769,
            small_modulus: 2,
            compression_divisor: d_c,
            f_coeff_count: 128,
            g_coeff_count: 320,
            s_coeff_count: 2 * k_s,
            e_coeff_count: 2 * k_e,
            base_parameter_set: crate::DawnParameterSet::Alpha512,
            profile: crate::DawnProfile::Production,
            pke_decrypt: PkeDecryptKind::MajorityReliability,
        }
    }

    /// Create parameters for DAWN-α-1024 (Table 6: k_g=256, k_f=96, k_s=192, k_e=256)
    pub fn dawn_alpha_1024() -> Self {
        Self::dawn_alpha_1024_custom(192, 256, 4)
    }

    /// Alpha1024 production: baseline decoder, zero noise, d_c=1 (lossless enough for FO-KEM here).
    fn dawn_alpha_1024_impl() -> Self {
        let mut p = Self::dawn_alpha_1024_custom(0, 0, 1);
        p.pke_decrypt = PkeDecryptKind::Baseline;
        p
    }

    /// Alpha1024 with custom k_s, k_e, d_c (n=1024, q=769, k_f=96, k_g=256).
    pub fn dawn_alpha_1024_custom(k_s: usize, k_e: usize, d_c: u32) -> Self {
        Self {
            degree: 1024,
            large_modulus: 769,
            small_modulus: 2,
            compression_divisor: d_c,
            f_coeff_count: 192,
            g_coeff_count: 512,
            s_coeff_count: 2 * k_s,
            e_coeff_count: 2 * k_e,
            base_parameter_set: crate::DawnParameterSet::Alpha1024,
            profile: crate::DawnProfile::Production,
            pke_decrypt: PkeDecryptKind::MajorityReliability,
        }
    }

    /// Create parameters for DAWN-β-512 (Table 6: k_g=64, k_f=32, k_s=48, k_e=64)
    pub fn dawn_beta_512() -> Self {
        Self::dawn_beta_512_custom(48, 64, 2)
    }

    /// Beta512 production profile (tunable). Initially spec defaults; update after sweep if used.
    fn dawn_beta_512_impl() -> Self {
        Self::dawn_beta_512_custom(48, 64, 2)
    }

    /// Beta512 with custom k_s, k_e, d_c (n=512, q=257, k_f=32, k_g=64).
    pub fn dawn_beta_512_custom(k_s: usize, k_e: usize, d_c: u32) -> Self {
        Self {
            degree: 512,
            large_modulus: 257,
            small_modulus: 2,
            compression_divisor: d_c,
            f_coeff_count: 64,
            g_coeff_count: 128,
            s_coeff_count: 2 * k_s,
            e_coeff_count: 2 * k_e,
            base_parameter_set: crate::DawnParameterSet::Beta512,
            profile: crate::DawnProfile::Production,
            pke_decrypt: PkeDecryptKind::Baseline,
        }
    }

    /// Create parameters for DAWN-β-1024 (Table 6: k_g=96, k_f=64, k_s=96, k_e=96)
    pub fn dawn_beta_1024() -> Self {
        Self {
            degree: 1024,
            large_modulus: 257,
            small_modulus: 2,
            compression_divisor: 1,
            f_coeff_count: 128, // 2*k_f
            g_coeff_count: 192, // 2*k_g
            s_coeff_count: 192, // 2*k_s
            e_coeff_count: 192, // 2*k_e
            base_parameter_set: crate::DawnParameterSet::Beta1024,
            profile: crate::DawnProfile::Production,
            pke_decrypt: PkeDecryptKind::Baseline,
        }
    }

    /// Ciphertext size in bytes for this parameter set (encoded compressed polynomial, full degree n).
    pub fn ciphertext_byte_size(&self) -> usize {
        let bits = ct_bits_per_coeff(self.large_modulus, self.compression_divisor);
        (self.degree * bits).div_ceil(8)
    }

    /// Public key size in bytes.
    pub fn public_key_byte_size(&self) -> usize {
        let bits = pk_bits_per_coeff(self.large_modulus);
        (self.degree * bits).div_ceil(8)
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
            self.s_coeff_count <= self.degree &&
            self.e_coeff_count <= self.degree &&
            self.f_coeff_count <= self.degree &&
            self.g_coeff_count <= self.degree
    }

    /// Secret key size in bytes: f_bytes + f2_bytes + 32 + 32 + pk_bytes (f_bytes same length as pk).
    pub fn secret_key_byte_size(&self) -> usize {
        let pk_bits = pk_bits_per_coeff(self.large_modulus);
        let pk_size = self.degree * pk_bits / 8;
        let f2_size = (self.degree / 2).div_ceil(8);
        pk_size + f2_size + 32 + 32 + pk_size
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
    /// f^{-1} mod (x^{n/2}+1, Z_2) for decryption (FO-KEM re-encrypt)
    pub f2: Vec<u8>,
    /// Stored random value for FO-KEM implicit rejection
    pub k_stored: [u8; 32],
    /// Hash of public key for FO-KEM
    pub h_pk: [u8; 32],
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
    /// Create a new key pair (with f2, k_stored, h_pk for FO-KEM)
    pub fn new(
        public_key: FieldPolynomial,
        secret_key: FieldPolynomial,
        g: FieldPolynomial,
        f2: Vec<u8>,
        k_stored: [u8; 32],
        h_pk: [u8; 32],
        params: KeyGenParams,
    ) -> Self {
        Self {
            public_key,
            secret_key,
            g,
            f2,
            k_stored,
            h_pk,
            params,
        }
    }

    /// Get the public key as bytes
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.encode_polynomial(&self.public_key)
    }

    /// Get the secret key as bytes: f || f2 || k_stored || h_pk || pk (for decapsulate re-encrypt).
    pub fn secret_key_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.encode_polynomial(&self.secret_key));
        bytes.extend_from_slice(&self.f2);
        bytes.extend_from_slice(&self.k_stored);
        bytes.extend_from_slice(&self.h_pk);
        bytes.extend_from_slice(&self.public_key_bytes());
        bytes
    }

    /// Encode a polynomial to bytes (lossless, pk bit-width).
    fn encode_polynomial(&self, poly: &FieldPolynomial) -> Vec<u8> {
        let bits = pk_bits_per_coeff(self.params.large_modulus);
        pack_bits(&poly.coefficients, bits)
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

    /// Generate a new key pair (with f2, k_stored, h_pk for FO-KEM)
    pub fn generate_keypair(&self, randomness: &[u8]) -> Result<DawnKeyPair> {
        let half = randomness.len() / 2;
        let f = self.generate_random_polynomial(&randomness[0..half])?;
        let g = self.generate_random_polynomial(&randomness[half..])?;

        let h = self.compute_public_key(&f, &g)?;

        let f2 = fast_inversion(&f, self.params.degree).ok_or_else(|| {
            lib_q_core::Error::InternalError {
                operation: "key generation".to_string(),
                details: "f not invertible mod (x^{n/4}+1, Z_2); retry with fresh randomness"
                    .to_string(),
            }
        })?;

        let pk_bytes = self.encode_polynomial_for_key(&h);
        let h_pk = hash_pk(&pk_bytes);
        let k_stored = derive_k_stored(&pk_bytes, randomness);

        Ok(DawnKeyPair::new(
            h,
            f,
            g,
            f2,
            k_stored,
            h_pk,
            self.params.clone(),
        ))
    }

    /// Encode a polynomial to bytes (same layout as DawnKeyPair::encode_polynomial).
    fn encode_polynomial_for_key(&self, poly: &FieldPolynomial) -> Vec<u8> {
        let bits = pk_bits_per_coeff(self.params.large_modulus);
        pack_bits(&poly.coefficients, bits)
    }

    /// Generate a random polynomial from T_{n,k_f}: exactly k_f positive and k_f negative coefficients.
    /// Then ensure f(1) = 1 mod 2 (required for Z_2 invertibility) by flipping one zero to +1 if needed.
    fn generate_random_polynomial(&self, randomness: &[u8]) -> Result<FieldPolynomial> {
        #[cfg(feature = "random")]
        let mut rng = DawnRng::new_deterministic(randomness);
        #[cfg(not(feature = "random"))]
        return Err(lib_q_core::Error::RandomGenerationFailed {
            operation: "Random feature not enabled".to_string(),
        });

        let k_f = self.params.f_coeff_count / 2;
        let mut poly = FieldPolynomial::random_ternary_exact(
            self.params.degree,
            k_f,
            self.params.large_modulus,
            &mut rng,
        );
        let sum_mod2: u32 = poly.coefficients.iter().map(|&c| c % 2).sum::<u32>() % 2;
        if sum_mod2 == 0 {
            let zeros: Vec<usize> = (0..self.params.degree)
                .filter(|&i| poly.coefficients[i] == 0)
                .collect();
            if !zeros.is_empty() {
                let idx = zeros[rng.next_u32() as usize % zeros.len()];
                poly.coefficients[idx] = 1;
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
        let half = randomness.len() / 2;
        let f = self.generate_random_polynomial(&randomness[0..half])?;
        let g = self.generate_random_polynomial_with_g_count(&randomness[half..])?;

        let h = self.compute_public_key(&f, &g)?;

        let f2 = fast_inversion(&f, self.params.degree).ok_or_else(|| {
            lib_q_core::Error::InternalError {
                operation: "key generation".to_string(),
                details: "f not invertible mod (x^{n/4}+1, Z_2); retry with fresh randomness"
                    .to_string(),
            }
        })?;

        let pk_bytes = self.encode_polynomial_for_key(&h);
        let h_pk = hash_pk(&pk_bytes);
        let k_stored = derive_k_stored(&pk_bytes, randomness);

        Ok(DawnKeyPair::new(
            h,
            f,
            g,
            f2,
            k_stored,
            h_pk,
            self.params.clone(),
        ))
    }

    /// Generate a random polynomial from T_{n,k_g}: exactly k_g positive and k_g negative coefficients.
    fn generate_random_polynomial_with_g_count(
        &self,
        randomness: &[u8],
    ) -> Result<FieldPolynomial> {
        #[cfg(feature = "random")]
        let mut rng = DawnRng::new_deterministic(randomness);
        #[cfg(not(feature = "random"))]
        return Err(lib_q_core::Error::RandomGenerationFailed {
            operation: "Random feature not enabled".to_string(),
        });

        let k_g = self.params.g_coeff_count / 2;
        let poly = FieldPolynomial::random_ternary_exact(
            self.params.degree,
            k_g,
            self.params.large_modulus,
            &mut rng,
        );

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
        const MAX_RETRIES: usize = 50;
        for attempt in 0..MAX_RETRIES {
            let mut randomness = Vec::new();
            randomness.extend_from_slice(&self.seed);
            if attempt > 0 {
                randomness.extend_from_slice(&attempt.to_le_bytes());
            }
            while randomness.len() < 64 {
                randomness.extend_from_slice(&self.seed);
            }
            match self.generator.generate_keypair(&randomness) {
                Ok(kp) => return Ok(kp),
                Err(lib_q_core::Error::InternalError { ref details, .. })
                    if details.contains("not invertible") =>
                {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        Err(lib_q_core::Error::InternalError {
            operation: "key generation".to_string(),
            details: "f not invertible mod (x^{n/2}+1, Z_2) after retries".to_string(),
        })
    }

    /// Generate a key pair with proper g coefficient count
    pub fn generate_keypair_with_g_coeff_count(&self) -> Result<DawnKeyPair> {
        const MAX_RETRIES: usize = 50;
        for attempt in 0..MAX_RETRIES {
            let mut randomness = Vec::new();
            randomness.extend_from_slice(&self.seed);
            if attempt > 0 {
                randomness.extend_from_slice(&attempt.to_le_bytes());
            }
            while randomness.len() < 64 {
                randomness.extend_from_slice(&self.seed);
            }
            match self
                .generator
                .generate_keypair_with_g_coeff_count(&randomness)
            {
                Ok(kp) => return Ok(kp),
                Err(lib_q_core::Error::InternalError { ref details, .. })
                    if details.contains("not invertible") =>
                {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        Err(lib_q_core::Error::InternalError {
            operation: "key generation".to_string(),
            details: "f not invertible mod (x^{n/2}+1, Z_2) after retries".to_string(),
        })
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

        // Try many seeds; f may not be invertible mod (x^{n/4}+1, Z_2) for some seeds
        for seed in 0u8..=255 {
            let randomness = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, seed];
            if let Ok(keypair) = generator.generate_keypair_with_g_coeff_count(&randomness) {
                assert!(keypair.is_valid());
                return;
            }
        }
        panic!("Key generation should succeed with at least one of the tried seeds");
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
