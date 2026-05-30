//! HQC Key Encapsulation Mechanism (KEM) Implementation
//!
//! This module implements the HQC KEM layer as specified in the reference implementation.
//! The KEM layer provides IND-CCA2 security using the PKE layer with additional hash functions.

use core::fmt;

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "zeroize")]
use zeroize::{
    Zeroize,
    ZeroizeOnDrop,
    Zeroizing,
};

use crate::hqc_pke::{
    HqcPke,
    HqcPkeCiphertext,
    HqcPkeError,
    HqcPkePublicKey,
    HqcPkeSecretKey,
};
use crate::internal::shake256::Shake256Xof;
use crate::params_correct::HqcParams;

// Domain separators for hash functions (2025 specification)
// According to HQC 2025 spec Section 3.1, each hash function uses its own domain separator
// Domain bytes match the reference implementation / KAT tooling (Table 1):
// G → 0, H → 1, I → 2 (PKE), J → 3, XOF → 1, PRNG → 0.
const H_DOMAIN_SEPARATOR: u8 = 1; // SHA3-256 for H
const G_DOMAIN_SEPARATOR: u8 = 0; // SHA3-512 for G
const J_DOMAIN_SEPARATOR: u8 = 3; // SHA3-256 for J

/// HQC KEM implementation
pub struct HqcKem<P: HqcParams> {
    pke: HqcPke<P>,
}

impl<P: HqcParams> HqcKem<P> {
    /// Create a new HQC KEM instance
    pub fn new() -> Result<Self, HqcKemError> {
        let pke = HqcPke::new().map_err(HqcKemError::PkeError)?;

        Ok(Self { pke })
    }

    /// Get access to the underlying PKE implementation (for testing/debugging)
    pub fn pke(&self) -> &HqcPke<P> {
        &self.pke
    }

    /// Generate a key pair for HQC KEM using a seed
    ///
    /// Returns (public_key, secret_key) where:
    /// - public_key: ek_pke (same as PKE public key)
    /// - secret_key: (ek_pke, dk_pke, sigma, seed_kem)
    pub fn keygen_with_seed(
        &self,
        seed_kem: &[u8],
    ) -> Result<(HqcKemPublicKey<P>, HqcKemSecretKey<P>), HqcKemError> {
        // NIST/HQC KAT `seed` is `seedKEM` (48 bytes). Derive `(seedPKE, σ)` via XOF domain 1,
        // then run PKE keygen on `seedPKE` (HQC 2025 KEM.Keygen flow).
        if seed_kem.len() < 48 {
            return Err(HqcKemError::InvalidInput);
        }

        let mut seed_kem_array = [0u8; 48];
        seed_kem_array.copy_from_slice(&seed_kem[..48]);

        // NIST `.req`/`.rsp` `seed` is 48 bytes: `seedKEM` (32) || `m` (16) for encaps KAT.
        let mut seed_kem_32 = [0u8; 32];
        seed_kem_32.copy_from_slice(&seed_kem_array[..32]);

        let mut ctx_kem = Shake256Xof::new();
        ctx_kem
            .init_with_domain(&seed_kem_32, 1) // HQC_XOF_DOMAIN = 1
            .map_err(|_| HqcKemError::HashError)?;

        let mut seed_pke = [0u8; 32];
        ctx_kem
            .squeeze(&mut seed_pke)
            .map_err(|_| HqcKemError::HashError)?;

        let mut sigma = [0u8; 16]; // PARAM_SECURITY_BYTES
        ctx_kem
            .squeeze(&mut sigma)
            .map_err(|_| HqcKemError::HashError)?;

        let (ek_pke, dk_pke) = self
            .pke
            .keygen_from_seed_pke(&seed_pke)
            .map_err(HqcKemError::PkeError)?;

        let kem_public_key = HqcKemPublicKey::new(ek_pke.clone());
        let kem_secret_key = HqcKemSecretKey::new(ek_pke, dk_pke, sigma, seed_kem_array);

        Ok((kem_public_key, kem_secret_key))
    }

    /// Generate a key pair for HQC KEM
    ///
    /// Returns (public_key, secret_key) where:
    /// - public_key: ek_pke (same as PKE public key)
    /// - secret_key: (ek_pke, dk_pke, sigma, seed_kem)
    pub fn keygen<R: rand_core::CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> Result<(HqcKemPublicKey<P>, HqcKemSecretKey<P>), HqcKemError> {
        // Sample seed_kem (48 bytes for KAT compatibility)
        let mut seed_kem = [0u8; 48];
        rng.fill_bytes(&mut seed_kem);

        // Use the same approach as keygen_with_seed
        self.keygen_with_seed(&seed_kem)
    }

    /// Encapsulate with caller-supplied `m` and `salt` (NIST KEM KAT / deterministic harness).
    pub fn encapsulate_with_m_salt(
        &self,
        public_key: &HqcKemPublicKey<P>,
        m: &[u8; 16],
        salt: &[u8; 16],
    ) -> Result<(HqcKemCiphertext<P>, HqcKemSharedSecret<P>), HqcKemError> {
        // Compute shared key K and ciphertext c_kem
        let mut hash_ek_kem = [0u8; 32]; // SEED_BYTES
        self.hash_h(&mut hash_ek_kem, public_key.as_bytes())?;

        let mut k_theta = [0u8; 64]; // SHARED_SECRET_BYTES + SEED_BYTES
        self.hash_g(&mut k_theta, &hash_ek_kem, m.as_ref(), salt.as_ref())?;

        let mut theta = [0u8; 32]; // SEED_BYTES
        theta.copy_from_slice(&k_theta[32..]);

        // Encrypt using PKE
        let c_pke = self
            .pke
            .encrypt(
                public_key.pke_public_key(),
                &self.bytes_to_u64_array(m.as_ref()),
                &theta,
            )
            .map_err(HqcKemError::PkeError)?;

        // Create KEM ciphertext
        let kem_ciphertext = HqcKemCiphertext::new(c_pke, *salt);

        // Create shared secret (clear transient stack buffers when zeroize is enabled)
        #[cfg(feature = "zeroize")]
        let kem_shared_secret = {
            let mut shared_secret = Zeroizing::new([0u8; 32]);
            shared_secret.copy_from_slice(&k_theta[..32]);
            HqcKemSharedSecret::new(*shared_secret)
        };
        #[cfg(not(feature = "zeroize"))]
        let kem_shared_secret = {
            let mut shared_secret = [0u8; 32]; // SHARED_SECRET_BYTES
            shared_secret.copy_from_slice(&k_theta[..32]);
            HqcKemSharedSecret::new(shared_secret)
        };

        #[cfg(feature = "zeroize")]
        {
            use zeroize::Zeroize;
            hash_ek_kem.zeroize();
            k_theta.zeroize();
            theta.zeroize();
        }

        Ok((kem_ciphertext, kem_shared_secret))
    }

    /// Encapsulate a shared secret using HQC KEM
    pub fn encapsulate<R: rand_core::CryptoRng + ?Sized>(
        &self,
        public_key: &HqcKemPublicKey<P>,
        rng: &mut R,
    ) -> Result<(HqcKemCiphertext<P>, HqcKemSharedSecret<P>), HqcKemError> {
        let mut m = [0u8; 16];
        rng.fill_bytes(&mut m);
        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);
        let result = self.encapsulate_with_m_salt(public_key, &m, &salt);
        #[cfg(feature = "zeroize")]
        {
            use zeroize::Zeroize;
            m.zeroize();
            salt.zeroize();
        }
        result
    }

    /// Decapsulate a shared secret using HQC KEM
    pub fn decapsulate(
        &self,
        secret_key: &HqcKemSecretKey<P>,
        ciphertext: &HqcKemCiphertext<P>,
    ) -> Result<HqcKemSharedSecret<P>, HqcKemError> {
        // Parse secret key
        let (ek_pke, dk_pke, sigma, _seed_kem) = secret_key.parse();

        // Parse ciphertext
        let (c_pke, salt) = ciphertext.parse();

        // Compute message m_prime
        let mut m_prime = self
            .pke
            .decrypt(&dk_pke, &c_pke)
            .map_err(HqcKemError::PkeError)?;

        // Compute shared key K_prime and ciphertext c_kem_prime
        let mut hash_ek_kem = [0u8; 32]; // SEED_BYTES
        self.hash_h(&mut hash_ek_kem, ek_pke.as_bytes())?;

        let mut k_theta_prime = [0u8; 64]; // SHARED_SECRET_BYTES + SEED_BYTES
        self.hash_g(
            &mut k_theta_prime,
            &hash_ek_kem,
            &self.u64_array_to_message_bytes(&m_prime),
            &salt,
        )?;

        let mut theta_prime = [0u8; 32]; // SEED_BYTES
        theta_prime.copy_from_slice(&k_theta_prime[32..]);

        // Re-encrypt to verify
        let c_pke_prime = self
            .pke
            .encrypt(&ek_pke, &m_prime, &theta_prime)
            .map_err(HqcKemError::PkeError)?;

        // Create re-encrypted KEM ciphertext with same salt
        let c_kem_prime = HqcKemCiphertext::new(c_pke_prime.clone(), salt);

        // Compute rejection key K_bar (following reference implementation order)
        let mut k_bar = [0u8; 32]; // SHARED_SECRET_BYTES
        self.hash_j(&mut k_bar, &hash_ek_kem, &sigma, ciphertext)?;

        // Compare ciphertexts c'KEM with cKEM (following 2025 specification)
        // Compare full ciphertexts: (c'PKE, salt') with (cPKE, salt)
        let c_kem_bytes = ciphertext.as_bytes();
        let c_kem_prime_bytes = c_kem_prime.as_bytes();

        #[cfg(feature = "hardened")]
        let kem_shared_secret = {
            use subtle::ConstantTimeEq;
            let equal = c_kem_bytes.ct_eq(&c_kem_prime_bytes);
            #[cfg(feature = "zeroize")]
            {
                let mut k_prime = Zeroizing::new([0u8; 32]);
                k_prime.copy_from_slice(&k_theta_prime[..32]);
                let out = select_shared_secret_ct(equal, &k_prime, &k_bar);
                HqcKemSharedSecret::new(out)
            }
            #[cfg(not(feature = "zeroize"))]
            {
                let mut k_prime = [0u8; 32];
                k_prime.copy_from_slice(&k_theta_prime[..32]);
                let out = select_shared_secret_ct(equal, &k_prime, &k_bar);
                HqcKemSharedSecret::new(out)
            }
        };

        #[cfg(not(feature = "hardened"))]
        let kem_shared_secret = {
            let mut result = 0u8;
            result |= self.vect_compare(&c_kem_bytes, &c_kem_prime_bytes, c_kem_bytes.len());
            // Constant-time normalisation matching the reference implementation:
            //   result = (uint8_t)(-((int16_t)result) >> 15)
            // Maps 0 → 0x00, any non-zero → 0xFF.
            let neg = (-(result as i16)) as u16;
            result = (neg >> 15) as u8; // 0 or 1
            result = (-(result as i8)) as u8; // 0x00 or 0xFF
            // Invert: 0xFF = ciphertexts match (select k_prime),
            //         0x00 = mismatch (select k_bar).
            result = !result;

            #[cfg(feature = "zeroize")]
            {
                let mut k_prime = Zeroizing::new([0u8; 32]);
                k_prime.copy_from_slice(&k_theta_prime[..32]);
                for i in 0..32 {
                    k_prime[i] = (k_prime[i] & result) ^ (k_bar[i] & !result);
                }
                HqcKemSharedSecret::new(*k_prime)
            }
            #[cfg(not(feature = "zeroize"))]
            {
                let mut k_prime = [0u8; 32]; // SHARED_SECRET_BYTES
                k_prime.copy_from_slice(&k_theta_prime[..32]);
                for i in 0..32 {
                    k_prime[i] = (k_prime[i] & result) ^ (k_bar[i] & !result);
                }
                HqcKemSharedSecret::new(k_prime)
            }
        };

        #[cfg(feature = "zeroize")]
        {
            use zeroize::Zeroize;
            hash_ek_kem.zeroize();
            k_theta_prime.zeroize();
            theta_prime.zeroize();
            k_bar.zeroize();
            m_prime.zeroize();
        }

        Ok(kem_shared_secret)
    }

    // Helper functions

    /// Hash function hash_h (SHA3-256 with domain separation)
    /// H(str) = SHA3-256(str || H_DOMAIN_SEPARATOR)
    fn hash_h(&self, output: &mut [u8], input: &[u8]) -> Result<(), HqcKemError> {
        use lib_q_sha3::{
            Digest,
            Sha3_256,
        };

        let mut hasher = Sha3_256::new();
        hasher.update(input);
        hasher.update([H_DOMAIN_SEPARATOR]);
        let result = hasher.finalize();
        output.copy_from_slice(&result);
        Ok(())
    }

    /// Hash function hash_g (SHA3-512 with domain separation)
    /// G(str) = SHA3-512(str || G_DOMAIN_SEPARATOR)
    /// Computes (K, θ) = G(H(ekKEM)∥m∥salt)
    fn hash_g(
        &self,
        output: &mut [u8],
        hash_ek_kem: &[u8],
        m: &[u8],
        salt: &[u8],
    ) -> Result<(), HqcKemError> {
        use lib_q_sha3::{
            Digest,
            Sha3_512,
        };

        let mut hasher = Sha3_512::new();
        // Concatenate inputs: hash_ek_kem || m || salt
        hasher.update(hash_ek_kem);
        hasher.update(m);
        hasher.update(salt);
        hasher.update([G_DOMAIN_SEPARATOR]);
        let result = hasher.finalize();
        output.copy_from_slice(&result);
        Ok(())
    }

    /// Hash function hash_j (SHA3-256 with domain separation)
    /// J(str) = SHA3-256(str || J_DOMAIN_SEPARATOR)
    /// Computes rejection key K̄ = J(H(ekKEM)∥σ∥cKEM)
    fn hash_j(
        &self,
        output: &mut [u8],
        hash_ek_kem: &[u8],
        sigma: &[u8],
        ciphertext: &HqcKemCiphertext<P>,
    ) -> Result<(), HqcKemError> {
        use lib_q_sha3::{
            Digest,
            Sha3_256,
        };

        // Concatenate inputs: hash_ek_kem || sigma || ciphertext
        let ciphertext_bytes = ciphertext.as_bytes();
        let mut hasher = Sha3_256::new();
        hasher.update(hash_ek_kem);
        hasher.update(sigma);
        hasher.update(ciphertext_bytes);
        hasher.update([J_DOMAIN_SEPARATOR]);
        let result = hasher.finalize();
        output.copy_from_slice(&result);
        Ok(())
    }

    /// Vector comparison (non-hardened decapsulation path).
    #[cfg(not(feature = "hardened"))]
    fn vect_compare(&self, a: &[u8], b: &[u8], len: usize) -> u8 {
        let mut result = 0u8;
        for i in 0..len {
            if i < a.len() && i < b.len() {
                result |= a[i] ^ b[i];
            }
        }
        result
    }

    /// Convert bytes to u64 array (little-endian, 8 bytes per u64)
    /// The result is padded/truncated to exactly K u64 values as expected by PKE
    #[cfg(feature = "alloc")]
    fn bytes_to_u64_array(&self, input: &[u8]) -> Vec<u64> {
        let mut result = vec![0u64; P::K];

        // Convert input bytes to u64 values
        for (i, chunk) in input.chunks(8).enumerate() {
            if i >= P::K {
                break; // Truncate if input is too long
            }
            let mut bytes = [0u8; 8];
            bytes[..chunk.len()].copy_from_slice(chunk);
            result[i] = u64::from_le_bytes(bytes);
        }
        result
    }

    /// Convert u64 array to message bytes (truncated to 16 bytes for hash_g)
    #[cfg(feature = "alloc")]
    fn u64_array_to_message_bytes(&self, input: &[u64]) -> Vec<u8> {
        let mut result = Vec::with_capacity(input.len() * 8);
        for &value in input {
            result.extend_from_slice(&value.to_le_bytes());
        }
        // Truncate to the original message length (PARAM_SECURITY_BYTES = 16)
        result.truncate(16);
        result
    }
}

/// HQC KEM Public Key
#[derive(Debug, Clone, PartialEq)]
pub struct HqcKemPublicKey<P: HqcParams> {
    pke_public_key: HqcPkePublicKey<P>,
}

impl<P: HqcParams> HqcKemPublicKey<P> {
    pub fn new(pke_public_key: HqcPkePublicKey<P>) -> Self {
        Self { pke_public_key }
    }

    pub fn pke_public_key(&self) -> &HqcPkePublicKey<P> {
        &self.pke_public_key
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.pke_public_key.data
    }
}

/// HQC KEM Secret Key
#[derive(Debug, Clone, PartialEq)]
pub struct HqcKemSecretKey<P: HqcParams> {
    ek_pke: HqcPkePublicKey<P>,
    dk_pke: HqcPkeSecretKey<P>,
    sigma: [u8; 16],    // PARAM_SECURITY_BYTES
    seed_kem: [u8; 48], // KAT seed (48 bytes for compatibility)
}

impl<P: HqcParams> HqcKemSecretKey<P> {
    pub fn new(
        ek_pke: HqcPkePublicKey<P>,
        dk_pke: HqcPkeSecretKey<P>,
        sigma: [u8; 16],
        seed_kem: [u8; 48],
    ) -> Self {
        Self {
            ek_pke,
            dk_pke,
            sigma,
            seed_kem,
        }
    }

    pub fn parse(&self) -> (HqcPkePublicKey<P>, HqcPkeSecretKey<P>, [u8; 16], [u8; 48]) {
        (
            self.ek_pke.clone(),
            self.dk_pke.clone(),
            self.sigma,
            self.seed_kem,
        )
    }

    #[cfg(feature = "alloc")]
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(P::SECRET_KEY_BYTES);
        result.extend_from_slice(&self.ek_pke.data);
        result.extend_from_slice(&self.dk_pke.data);
        result.extend_from_slice(&self.sigma);
        result.extend_from_slice(&self.seed_kem);
        result
    }

    /// Serialize to NIST `CRYPTO_SECRETKEYBYTES` layout: `dk_pke` ‖ `sigma` ‖ `ek_pke`.
    #[cfg(feature = "alloc")]
    pub fn to_nist_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(P::NIST_SECRET_KEY_BYTES);
        out.extend_from_slice(&self.dk_pke.data);
        out.extend_from_slice(&self.sigma);
        out.extend_from_slice(&self.ek_pke.data);
        out
    }

    /// Parse NIST `CRYPTO_SECRETKEYBYTES` (`dk_pke` ‖ `sigma` ‖ `ek_pke`).
    ///
    /// `seed_kem` is not part of the NIST wire format; a zero placeholder is stored because
    /// decapsulation only needs `(ek_pke, dk_pke, sigma)`.
    #[cfg(feature = "alloc")]
    pub fn from_nist_bytes(bytes: &[u8]) -> Result<Self, HqcKemError> {
        if bytes.len() != P::NIST_SECRET_KEY_BYTES {
            return Err(HqcKemError::InvalidKey);
        }
        let mut dk = [0u8; 32];
        dk.copy_from_slice(&bytes[..32]);
        let mut sigma = [0u8; 16];
        sigma.copy_from_slice(&bytes[32..48]);
        let ek_bytes = &bytes[48..];
        if ek_bytes.len() != P::PUBLIC_KEY_BYTES {
            return Err(HqcKemError::InvalidKey);
        }
        let ek_pke = HqcPkePublicKey::new(ek_bytes.to_vec());
        let dk_pke = HqcPkeSecretKey::new(dk);
        let seed_kem = [0u8; 48];
        Ok(Self::new(ek_pke, dk_pke, sigma, seed_kem))
    }
}

#[cfg(feature = "hardened")]
fn select_shared_secret_ct(
    equal: subtle::Choice,
    k_prime: &[u8; 32],
    k_bar: &[u8; 32],
) -> [u8; 32] {
    use subtle::ConditionallySelectable;
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::conditional_select(&k_bar[i], &k_prime[i], equal);
    }
    out
}

/// HQC KEM Ciphertext
#[derive(Debug, Clone, PartialEq)]
pub struct HqcKemCiphertext<P: HqcParams> {
    c_pke: HqcPkeCiphertext<P>,
    salt: [u8; 16], // SALT_BYTES
}

impl<P: HqcParams> HqcKemCiphertext<P> {
    pub fn new(c_pke: HqcPkeCiphertext<P>, salt: [u8; 16]) -> Self {
        Self { c_pke, salt }
    }

    pub fn parse(&self) -> (HqcPkeCiphertext<P>, [u8; 16]) {
        (self.c_pke.clone(), self.salt)
    }

    #[cfg(feature = "alloc")]
    pub fn as_bytes(&self) -> Vec<u8> {
        // Ciphertext structure: cKEM = (cPKE, salt)
        // Where cPKE = (u, v) and salt is 16 bytes
        let mut result =
            Vec::with_capacity(P::VEC_N_SIZE_BYTES + P::VEC_N1N2_SIZE_BYTES + P::SALT_BYTES);
        result.extend_from_slice(&self.c_pke.data[..P::VEC_N_SIZE_BYTES + P::VEC_N1N2_SIZE_BYTES]);
        result.extend_from_slice(&self.salt);
        result
    }
}

/// HQC KEM Shared Secret
#[derive(Debug, Clone, PartialEq)]
pub struct HqcKemSharedSecret<P: HqcParams> {
    data: [u8; 32], // SHARED_SECRET_BYTES
    _params: core::marker::PhantomData<P>,
}

impl<P: HqcParams> HqcKemSharedSecret<P> {
    pub fn new(data: [u8; 32]) -> Self {
        Self {
            data,
            _params: core::marker::PhantomData,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(feature = "zeroize")]
impl<P: HqcParams> Zeroize for HqcKemSharedSecret<P> {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<P: HqcParams> ZeroizeOnDrop for HqcKemSharedSecret<P> {}

/// HQC KEM error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HqcKemError {
    PkeError(HqcPkeError),
    HashError,
    InvalidKey,
    InvalidCiphertext,
    DecryptionFailed,
    InvalidInput,
}

impl fmt::Display for HqcKemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HqcKemError::PkeError(e) => write!(f, "PKE error: {}", e),
            HqcKemError::HashError => write!(f, "Hash error"),
            HqcKemError::InvalidKey => write!(f, "Invalid key"),
            HqcKemError::InvalidCiphertext => write!(f, "Invalid ciphertext"),
            HqcKemError::DecryptionFailed => write!(f, "Decryption failed"),
            HqcKemError::InvalidInput => write!(f, "Invalid input"),
        }
    }
}

impl From<HqcPkeError> for HqcKemError {
    fn from(error: HqcPkeError) -> Self {
        HqcKemError::PkeError(error)
    }
}
