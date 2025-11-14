//! HQC Correct Implementation
//!
//! This module provides the correct HQC implementation based on the reference specification.
//! It implements HQC-1, HQC-3, and HQC-5 with proper Reed-Solomon + Reed-Muller concatenated codes.

use core::fmt;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::hqc_kem::{
    HqcKem,
    HqcKemCiphertext,
    HqcKemError,
    HqcKemPublicKey,
    HqcKemSecretKey,
    HqcKemSharedSecret,
};
use crate::params_correct::{
    Hqc1Params,
    Hqc3Params,
    Hqc5Params,
    HqcParams,
};

/// HQC core trait following libQ patterns
pub trait HqcCore<P: HqcParams>: Clone + fmt::Debug + PartialEq {
    /// The public key type for this HQC instance
    type PublicKey: Clone + fmt::Debug + PartialEq;
    /// The secret key type for this HQC instance
    type SecretKey: Clone + fmt::Debug + PartialEq;
    /// The ciphertext type for this HQC instance
    type Ciphertext: Clone + fmt::Debug + PartialEq;
    /// The shared secret type for this HQC instance
    type SharedSecret: Clone + fmt::Debug + PartialEq;

    /// Generate a new (secret key, public key) pair
    fn generate_keypair<R: rand_core::CryptoRng + ?Sized>(
        rng: &mut R,
    ) -> Result<(Self::SecretKey, Self::PublicKey), HqcError>;

    /// Encapsulate a shared secret to the public key
    fn encapsulate<R: rand_core::CryptoRng + ?Sized>(
        public_key: &Self::PublicKey,
        rng: &mut R,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), HqcError>;

    /// Decapsulate the shared secret using the secret key
    fn decapsulate<R: rand_core::CryptoRng + ?Sized>(
        secret_key: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, HqcError>;

    /// Derive public key from secret key
    fn derive_public_key(secret_key: &Self::SecretKey) -> Result<Self::PublicKey, HqcError>;
}

/// HQC-1 implementation
#[derive(Debug, Clone, PartialEq)]
pub struct Hqc1;

impl HqcCore<Hqc1Params> for Hqc1 {
    type PublicKey = Hqc1PublicKey;
    type SecretKey = Hqc1SecretKey;
    type Ciphertext = Hqc1Ciphertext;
    type SharedSecret = Hqc1SharedSecret;

    fn generate_keypair<R: rand_core::CryptoRng + ?Sized>(
        rng: &mut R,
    ) -> Result<(Self::SecretKey, Self::PublicKey), HqcError> {
        let kem = HqcKem::<Hqc1Params>::new().map_err(HqcError::KemError)?;
        let (public_key, secret_key) = kem.keygen(rng).map_err(HqcError::KemError)?;

        Ok((
            Hqc1SecretKey::new(secret_key),
            Hqc1PublicKey::new(public_key),
        ))
    }

    fn encapsulate<R: rand_core::CryptoRng + ?Sized>(
        public_key: &Self::PublicKey,
        rng: &mut R,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), HqcError> {
        let kem = HqcKem::<Hqc1Params>::new().map_err(HqcError::KemError)?;
        let (ciphertext, shared_secret) = kem
            .encapsulate(&public_key.kem_public_key, rng)
            .map_err(HqcError::KemError)?;

        Ok((
            Hqc1Ciphertext::new(ciphertext),
            Hqc1SharedSecret::new(shared_secret),
        ))
    }

    fn decapsulate<R: rand_core::CryptoRng + ?Sized>(
        secret_key: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, HqcError> {
        let kem = HqcKem::<Hqc1Params>::new().map_err(HqcError::KemError)?;
        let shared_secret = kem
            .decapsulate(&secret_key.kem_secret_key, &ciphertext.kem_ciphertext)
            .map_err(HqcError::KemError)?;

        Ok(Hqc1SharedSecret::new(shared_secret))
    }

    fn derive_public_key(secret_key: &Self::SecretKey) -> Result<Self::PublicKey, HqcError> {
        // Extract the public key from the secret key
        let (ek_pke, _dk_pke, _sigma, _seed_kem) = secret_key.kem_secret_key.parse();
        Ok(Hqc1PublicKey::new(HqcKemPublicKey::new(ek_pke)))
    }
}

/// HQC-3 implementation
#[derive(Debug, Clone, PartialEq)]
pub struct Hqc3;

impl HqcCore<Hqc3Params> for Hqc3 {
    type PublicKey = Hqc3PublicKey;
    type SecretKey = Hqc3SecretKey;
    type Ciphertext = Hqc3Ciphertext;
    type SharedSecret = Hqc3SharedSecret;

    fn generate_keypair<R: rand_core::CryptoRng + ?Sized>(
        rng: &mut R,
    ) -> Result<(Self::SecretKey, Self::PublicKey), HqcError> {
        let kem = HqcKem::<Hqc3Params>::new().map_err(HqcError::KemError)?;
        let (public_key, secret_key) = kem.keygen(rng).map_err(HqcError::KemError)?;

        Ok((
            Hqc3SecretKey::new(secret_key),
            Hqc3PublicKey::new(public_key),
        ))
    }

    fn encapsulate<R: rand_core::CryptoRng + ?Sized>(
        public_key: &Self::PublicKey,
        rng: &mut R,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), HqcError> {
        let kem = HqcKem::<Hqc3Params>::new().map_err(HqcError::KemError)?;
        let (ciphertext, shared_secret) = kem
            .encapsulate(&public_key.kem_public_key, rng)
            .map_err(HqcError::KemError)?;

        Ok((
            Hqc3Ciphertext::new(ciphertext),
            Hqc3SharedSecret::new(shared_secret),
        ))
    }

    fn decapsulate<R: rand_core::CryptoRng + ?Sized>(
        secret_key: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, HqcError> {
        let kem = HqcKem::<Hqc3Params>::new().map_err(HqcError::KemError)?;
        let shared_secret = kem
            .decapsulate(&secret_key.kem_secret_key, &ciphertext.kem_ciphertext)
            .map_err(HqcError::KemError)?;

        Ok(Hqc3SharedSecret::new(shared_secret))
    }

    fn derive_public_key(secret_key: &Self::SecretKey) -> Result<Self::PublicKey, HqcError> {
        let (ek_pke, _dk_pke, _sigma, _seed_kem) = secret_key.kem_secret_key.parse();
        Ok(Hqc3PublicKey::new(HqcKemPublicKey::new(ek_pke)))
    }
}

/// HQC-5 implementation
#[derive(Debug, Clone, PartialEq)]
pub struct Hqc5;

impl HqcCore<Hqc5Params> for Hqc5 {
    type PublicKey = Hqc5PublicKey;
    type SecretKey = Hqc5SecretKey;
    type Ciphertext = Hqc5Ciphertext;
    type SharedSecret = Hqc5SharedSecret;

    fn generate_keypair<R: rand_core::CryptoRng + ?Sized>(
        rng: &mut R,
    ) -> Result<(Self::SecretKey, Self::PublicKey), HqcError> {
        let kem = HqcKem::<Hqc5Params>::new().map_err(HqcError::KemError)?;
        let (public_key, secret_key) = kem.keygen(rng).map_err(HqcError::KemError)?;

        Ok((
            Hqc5SecretKey::new(secret_key),
            Hqc5PublicKey::new(public_key),
        ))
    }

    fn encapsulate<R: rand_core::CryptoRng + ?Sized>(
        public_key: &Self::PublicKey,
        rng: &mut R,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), HqcError> {
        let kem = HqcKem::<Hqc5Params>::new().map_err(HqcError::KemError)?;
        let (ciphertext, shared_secret) = kem
            .encapsulate(&public_key.kem_public_key, rng)
            .map_err(HqcError::KemError)?;

        Ok((
            Hqc5Ciphertext::new(ciphertext),
            Hqc5SharedSecret::new(shared_secret),
        ))
    }

    fn decapsulate<R: rand_core::CryptoRng + ?Sized>(
        secret_key: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, HqcError> {
        let kem = HqcKem::<Hqc5Params>::new().map_err(HqcError::KemError)?;
        let shared_secret = kem
            .decapsulate(&secret_key.kem_secret_key, &ciphertext.kem_ciphertext)
            .map_err(HqcError::KemError)?;

        Ok(Hqc5SharedSecret::new(shared_secret))
    }

    fn derive_public_key(secret_key: &Self::SecretKey) -> Result<Self::PublicKey, HqcError> {
        let (ek_pke, _dk_pke, _sigma, _seed_kem) = secret_key.kem_secret_key.parse();
        Ok(Hqc5PublicKey::new(HqcKemPublicKey::new(ek_pke)))
    }
}

// HQC-1 Types
#[derive(Debug, Clone, PartialEq)]
pub struct Hqc1PublicKey {
    kem_public_key: HqcKemPublicKey<Hqc1Params>,
}

impl Hqc1PublicKey {
    pub fn new(kem_public_key: HqcKemPublicKey<Hqc1Params>) -> Self {
        Self { kem_public_key }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.kem_public_key.as_bytes()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Hqc1SecretKey {
    kem_secret_key: HqcKemSecretKey<Hqc1Params>,
}

impl Hqc1SecretKey {
    pub fn new(kem_secret_key: HqcKemSecretKey<Hqc1Params>) -> Self {
        Self { kem_secret_key }
    }

    #[cfg(feature = "alloc")]
    #[cfg(feature = "alloc")]
    pub fn as_bytes(&self) -> Vec<u8> {
        self.kem_secret_key.as_bytes()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Hqc1Ciphertext {
    kem_ciphertext: HqcKemCiphertext<Hqc1Params>,
}

impl Hqc1Ciphertext {
    pub fn new(kem_ciphertext: HqcKemCiphertext<Hqc1Params>) -> Self {
        Self { kem_ciphertext }
    }

    #[cfg(feature = "alloc")]
    pub fn as_bytes(&self) -> Vec<u8> {
        self.kem_ciphertext.as_bytes().to_vec()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Hqc1SharedSecret {
    kem_shared_secret: HqcKemSharedSecret<Hqc1Params>,
}

impl Hqc1SharedSecret {
    pub fn new(kem_shared_secret: HqcKemSharedSecret<Hqc1Params>) -> Self {
        Self { kem_shared_secret }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.kem_shared_secret.as_bytes()
    }
}

// HQC-3 Types
#[derive(Debug, Clone, PartialEq)]
pub struct Hqc3PublicKey {
    kem_public_key: HqcKemPublicKey<Hqc3Params>,
}

impl Hqc3PublicKey {
    pub fn new(kem_public_key: HqcKemPublicKey<Hqc3Params>) -> Self {
        Self { kem_public_key }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.kem_public_key.as_bytes()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Hqc3SecretKey {
    kem_secret_key: HqcKemSecretKey<Hqc3Params>,
}

impl Hqc3SecretKey {
    pub fn new(kem_secret_key: HqcKemSecretKey<Hqc3Params>) -> Self {
        Self { kem_secret_key }
    }

    #[cfg(feature = "alloc")]
    pub fn as_bytes(&self) -> Vec<u8> {
        self.kem_secret_key.as_bytes()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Hqc3Ciphertext {
    kem_ciphertext: HqcKemCiphertext<Hqc3Params>,
}

impl Hqc3Ciphertext {
    pub fn new(kem_ciphertext: HqcKemCiphertext<Hqc3Params>) -> Self {
        Self { kem_ciphertext }
    }

    #[cfg(feature = "alloc")]
    pub fn as_bytes(&self) -> Vec<u8> {
        self.kem_ciphertext.as_bytes().to_vec()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Hqc3SharedSecret {
    kem_shared_secret: HqcKemSharedSecret<Hqc3Params>,
}

impl Hqc3SharedSecret {
    pub fn new(kem_shared_secret: HqcKemSharedSecret<Hqc3Params>) -> Self {
        Self { kem_shared_secret }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.kem_shared_secret.as_bytes()
    }
}

// HQC-5 Types
#[derive(Debug, Clone, PartialEq)]
pub struct Hqc5PublicKey {
    kem_public_key: HqcKemPublicKey<Hqc5Params>,
}

impl Hqc5PublicKey {
    pub fn new(kem_public_key: HqcKemPublicKey<Hqc5Params>) -> Self {
        Self { kem_public_key }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.kem_public_key.as_bytes()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Hqc5SecretKey {
    kem_secret_key: HqcKemSecretKey<Hqc5Params>,
}

impl Hqc5SecretKey {
    pub fn new(kem_secret_key: HqcKemSecretKey<Hqc5Params>) -> Self {
        Self { kem_secret_key }
    }

    #[cfg(feature = "alloc")]
    pub fn as_bytes(&self) -> Vec<u8> {
        self.kem_secret_key.as_bytes()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Hqc5Ciphertext {
    kem_ciphertext: HqcKemCiphertext<Hqc5Params>,
}

impl Hqc5Ciphertext {
    pub fn new(kem_ciphertext: HqcKemCiphertext<Hqc5Params>) -> Self {
        Self { kem_ciphertext }
    }

    #[cfg(feature = "alloc")]
    pub fn as_bytes(&self) -> Vec<u8> {
        self.kem_ciphertext.as_bytes().to_vec()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Hqc5SharedSecret {
    kem_shared_secret: HqcKemSharedSecret<Hqc5Params>,
}

impl Hqc5SharedSecret {
    pub fn new(kem_shared_secret: HqcKemSharedSecret<Hqc5Params>) -> Self {
        Self { kem_shared_secret }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.kem_shared_secret.as_bytes()
    }
}

/// HQC error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HqcError {
    KemError(HqcKemError),
    InvalidParameters,
    InvalidKey,
    InvalidCiphertext,
    DecryptionFailed,
}

impl fmt::Display for HqcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HqcError::KemError(e) => write!(f, "KEM error: {}", e),
            HqcError::InvalidParameters => write!(f, "Invalid parameters"),
            HqcError::InvalidKey => write!(f, "Invalid key"),
            HqcError::InvalidCiphertext => write!(f, "Invalid ciphertext"),
            HqcError::DecryptionFailed => write!(f, "Decryption failed"),
        }
    }
}

impl From<HqcKemError> for HqcError {
    fn from(error: HqcKemError) -> Self {
        HqcError::KemError(error)
    }
}

/*
#[cfg(test)]
mod tests {
    use super::*;
    // Note: Using a simple RNG for testing - in production use proper crypto RNG

    #[test]
    fn test_hqc1_full_cycle() {
        // Simple test RNG - in production use proper crypto RNG
        let mut rng = [42u8; 32];

        // Generate key pair
        let (secret_key, public_key) = Hqc1::generate_keypair(&mut rng).unwrap();

        // Encapsulate
        let (ciphertext, shared_secret) = Hqc1::encapsulate(&public_key, &mut rng).unwrap();

        // Decapsulate
        let decapsulated_secret = Hqc1::decapsulate::<[u8; 32]>(&secret_key, &ciphertext).unwrap();

        // Verify
        assert_eq!(shared_secret.as_bytes(), decapsulated_secret.as_bytes());
    }

    #[test]
    fn test_hqc3_full_cycle() {
        // Simple test RNG - in production use proper crypto RNG
        let mut rng = [42u8; 32];

        // Generate key pair
        let (secret_key, public_key) = Hqc3::generate_keypair(&mut rng).unwrap();

        // Encapsulate
        let (ciphertext, shared_secret) = Hqc3::encapsulate(&public_key, &mut rng).unwrap();

        // Decapsulate
        let decapsulated_secret = Hqc3::decapsulate::<[u8; 32]>(&secret_key, &ciphertext).unwrap();

        // Verify
        assert_eq!(shared_secret.as_bytes(), decapsulated_secret.as_bytes());
    }

    #[test]
    fn test_hqc5_full_cycle() {
        // Simple test RNG - in production use proper crypto RNG
        let mut rng = [42u8; 32];

        // Generate key pair
        let (secret_key, public_key) = Hqc5::generate_keypair(&mut rng).unwrap();

        // Encapsulate
        let (ciphertext, shared_secret) = Hqc5::encapsulate(&public_key, &mut rng).unwrap();

        // Decapsulate
        let decapsulated_secret = Hqc5::decapsulate::<[u8; 32]>(&secret_key, &ciphertext).unwrap();

        // Verify
        assert_eq!(shared_secret.as_bytes(), decapsulated_secret.as_bytes());
    }

    #[test]
    fn test_derive_public_key() {
        // Simple test RNG - in production use proper crypto RNG
        let mut rng = [42u8; 32];

        // Generate key pair
        let (secret_key, original_public_key) = Hqc1::generate_keypair(&mut rng).unwrap();

        // Derive public key from secret key
        let derived_public_key = Hqc1::derive_public_key(&secret_key).unwrap();

        // Verify they match
        assert_eq!(original_public_key.as_bytes(), derived_public_key.as_bytes());
    }

    #[test]
    fn test_key_sizes() {
        // Simple test RNG - in production use proper crypto RNG
        let mut rng = [42u8; 32];

        // Test HQC-1 key sizes
        let (secret_key, public_key) = Hqc1::generate_keypair(&mut rng).unwrap();
        assert_eq!(public_key.as_bytes().len(), Hqc1Params::PUBLIC_KEY_BYTES);
        assert_eq!(secret_key.as_bytes().len(), Hqc1Params::SECRET_KEY_BYTES);

        // Test HQC-3 key sizes
        let (secret_key, public_key) = Hqc3::generate_keypair(&mut rng).unwrap();
        assert_eq!(public_key.as_bytes().len(), Hqc3Params::PUBLIC_KEY_BYTES);
        assert_eq!(secret_key.as_bytes().len(), Hqc3Params::SECRET_KEY_BYTES);

        // Test HQC-5 key sizes
        let (secret_key, public_key) = Hqc5::generate_keypair(&mut rng).unwrap();
        assert_eq!(public_key.as_bytes().len(), Hqc5Params::PUBLIC_KEY_BYTES);
        assert_eq!(secret_key.as_bytes().len(), Hqc5Params::SECRET_KEY_BYTES);
    }
}
*/

// Type aliases for convenience
pub type Hqc128Kem = HqcKem<Hqc1Params>;
pub type Hqc192Kem = HqcKem<Hqc3Params>;
pub type Hqc256Kem = HqcKem<Hqc5Params>;
