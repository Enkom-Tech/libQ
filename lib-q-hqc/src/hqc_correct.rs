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
        self.kem_ciphertext.as_bytes()
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
        self.kem_ciphertext.as_bytes()
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
        self.kem_ciphertext.as_bytes()
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

// NOTE: an earlier version of this test module used a bare `[u8; 32]` as the RNG argument,
// which does not implement `rand_core::CryptoRng` (the bound `HqcCore::generate_keypair`
// requires) -- it never compiled and was commented out wholesale. The tests below are a
// corrected replacement using `lib_q_random::LibQRng` (which gets `CryptoRng` via rand_core's
// blanket impl over `TryCryptoRng`, matching how `provider.rs` drives the same trait). Their
// purpose is unchanged: HQC-3 and HQC-5 (`Hqc192`/`Hqc256`) had no full generate/encapsulate/
// decapsulate cycle exercised directly against `hqc_correct.rs` (HQC-1's cycle and HQC-3's
// `derive_public_key`-only round trip are covered via `provider.rs`'s tests and
// `tests/integration_test.rs`, but not HQC-5's encapsulate/decapsulate).
#[cfg(all(test, feature = "random"))]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::string::ToString;

    use lib_q_random::LibQRng;

    use super::*;

    #[test]
    fn test_hqc1_full_cycle() {
        let mut rng = LibQRng::new_deterministic([1u8; 32]);

        let (secret_key, public_key) = Hqc1::generate_keypair(&mut rng).unwrap();
        let (ciphertext, shared_secret) = Hqc1::encapsulate(&public_key, &mut rng).unwrap();
        let decapsulated_secret = Hqc1::decapsulate::<LibQRng>(&secret_key, &ciphertext).unwrap();

        assert_eq!(shared_secret.as_bytes(), decapsulated_secret.as_bytes());
    }

    #[test]
    fn test_hqc3_full_cycle() {
        let mut rng = LibQRng::new_deterministic([2u8; 32]);

        let (secret_key, public_key) = Hqc3::generate_keypair(&mut rng).unwrap();
        let (ciphertext, shared_secret) = Hqc3::encapsulate(&public_key, &mut rng).unwrap();
        let decapsulated_secret = Hqc3::decapsulate::<LibQRng>(&secret_key, &ciphertext).unwrap();

        assert_eq!(shared_secret.as_bytes(), decapsulated_secret.as_bytes());
    }

    #[test]
    fn test_hqc5_full_cycle() {
        let mut rng = LibQRng::new_deterministic([3u8; 32]);

        let (secret_key, public_key) = Hqc5::generate_keypair(&mut rng).unwrap();
        let (ciphertext, shared_secret) = Hqc5::encapsulate(&public_key, &mut rng).unwrap();
        let decapsulated_secret = Hqc5::decapsulate::<LibQRng>(&secret_key, &ciphertext).unwrap();

        assert_eq!(shared_secret.as_bytes(), decapsulated_secret.as_bytes());
    }

    #[test]
    fn test_derive_public_key_hqc3_and_hqc5() {
        let mut rng3 = LibQRng::new_deterministic([4u8; 32]);
        let (secret_key3, original_pk3) = Hqc3::generate_keypair(&mut rng3).unwrap();
        let derived_pk3 = Hqc3::derive_public_key(&secret_key3).unwrap();
        assert_eq!(original_pk3.as_bytes(), derived_pk3.as_bytes());

        let mut rng5 = LibQRng::new_deterministic([5u8; 32]);
        let (secret_key5, original_pk5) = Hqc5::generate_keypair(&mut rng5).unwrap();
        let derived_pk5 = Hqc5::derive_public_key(&secret_key5).unwrap();
        assert_eq!(original_pk5.as_bytes(), derived_pk5.as_bytes());
    }

    #[test]
    fn test_key_and_ciphertext_sizes_all_variants() {
        let mut rng = LibQRng::new_deterministic([6u8; 32]);

        let (secret_key, public_key) = Hqc1::generate_keypair(&mut rng).unwrap();
        assert_eq!(public_key.as_bytes().len(), Hqc1Params::PUBLIC_KEY_BYTES);
        assert_eq!(secret_key.as_bytes().len(), Hqc1Params::SECRET_KEY_BYTES);
        let (ct, _) = Hqc1::encapsulate(&public_key, &mut rng).unwrap();
        assert_eq!(
            ct.as_bytes().len(),
            Hqc1Params::VEC_N_SIZE_BYTES + Hqc1Params::VEC_N1N2_SIZE_BYTES + 16
        );

        let (secret_key, public_key) = Hqc3::generate_keypair(&mut rng).unwrap();
        assert_eq!(public_key.as_bytes().len(), Hqc3Params::PUBLIC_KEY_BYTES);
        assert_eq!(secret_key.as_bytes().len(), Hqc3Params::SECRET_KEY_BYTES);

        let (secret_key, public_key) = Hqc5::generate_keypair(&mut rng).unwrap();
        assert_eq!(public_key.as_bytes().len(), Hqc5Params::PUBLIC_KEY_BYTES);
        assert_eq!(secret_key.as_bytes().len(), Hqc5Params::SECRET_KEY_BYTES);
    }

    /// Negative path: decapsulating with the WRONG secret key must not return the original
    /// shared secret (implicit rejection), and must not panic.
    #[test]
    fn test_decapsulate_with_wrong_key_does_not_leak_secret() {
        let mut rng = LibQRng::new_deterministic([7u8; 32]);
        let (_correct_sk, public_key) = Hqc3::generate_keypair(&mut rng).unwrap();
        let (wrong_sk, _wrong_pk) = Hqc3::generate_keypair(&mut rng).unwrap();

        let (ciphertext, shared_secret) = Hqc3::encapsulate(&public_key, &mut rng).unwrap();
        let mismatched = Hqc3::decapsulate::<LibQRng>(&wrong_sk, &ciphertext).unwrap();

        assert_ne!(
            shared_secret.as_bytes(),
            mismatched.as_bytes(),
            "decapsulating with an unrelated secret key must not reproduce the shared secret"
        );
    }

    /// This file's local `HqcError` (distinct from `crate::error::HqcError` -- an explicit `pub
    /// use error::HqcError` in `lib.rs` shadows this one for the crate's public glob re-export,
    /// so this type is reachable only as `hqc_correct::HqcError`) has a `Display` impl and a
    /// `From<HqcKemError>` impl that are never invoked anywhere in the crate: every
    /// `HqcCore::generate_keypair`/`encapsulate`/`decapsulate` here uses
    /// `.map_err(HqcError::KemError)` -- the enum variant used directly as a function pointer,
    /// which does NOT go through `impl From<HqcKemError> for HqcError` -- and nothing ever
    /// formats a `hqc_correct::HqcError` (confirmed: `grep -rn "hqc_correct::HqcError\.\|HqcError::from"
    /// lib-q-hqc/src` outside this file finds nothing). Construct-and-check directly.
    #[test]
    fn test_local_hqc_error_display_and_from_hqc_kem_error() {
        use crate::hqc_kem::HqcKemError;

        assert_eq!(
            HqcError::InvalidParameters.to_string(),
            "Invalid parameters"
        );
        assert_eq!(HqcError::InvalidKey.to_string(), "Invalid key");
        assert_eq!(
            HqcError::InvalidCiphertext.to_string(),
            "Invalid ciphertext"
        );
        assert_eq!(HqcError::DecryptionFailed.to_string(), "Decryption failed");

        let wrapped = HqcError::KemError(HqcKemError::InvalidKey);
        assert_eq!(wrapped.to_string(), "KEM error: Invalid key");

        // The `From<HqcKemError>` impl specifically (not the `.map_err(HqcError::KemError)`
        // idiom used everywhere else in this file, which bypasses it).
        let converted: HqcError = HqcKemError::InvalidCiphertext.into();
        assert_eq!(
            converted,
            HqcError::KemError(HqcKemError::InvalidCiphertext)
        );
    }
}

// Type aliases for convenience
pub type Hqc128Kem = HqcKem<Hqc1Params>;
pub type Hqc192Kem = HqcKem<Hqc3Params>;
pub type Hqc256Kem = HqcKem<Hqc5Params>;
