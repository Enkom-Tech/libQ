//! Provider traits for HPKE cryptographic operations

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::error::HpkeError;
use crate::security::CryptoRng;
use crate::types::*;

/// Trait for Key Encapsulation Mechanism (KEM) providers
pub trait KemProvider {
    /// Error type for KEM operations
    type Error: Into<HpkeError>;

    /// Generate a key pair for the given KEM algorithm
    fn generate_keypair(
        &self,
        kem: HpkeKem,
        rng: &mut dyn CryptoRng,
    ) -> Result<(Vec<u8>, Vec<u8>), Self::Error>;

    /// Encapsulate a shared secret using the public key
    fn encapsulate(
        &self,
        kem: HpkeKem,
        public_key: &[u8],
        rng: &mut dyn CryptoRng,
    ) -> Result<(Vec<u8>, Vec<u8>), Self::Error>;

    /// Decapsulate a shared secret using the secret key
    fn decapsulate(
        &self,
        kem: HpkeKem,
        secret_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;

    /// Validate a KEM key
    fn validate_key(&self, kem: HpkeKem, key: &[u8], is_secret: bool) -> Result<(), Self::Error>;

    /// Check if the provider supports the given KEM algorithm
    fn supports_kem(&self, kem: HpkeKem) -> bool;

    /// Authenticated encapsulation for Auth and AuthPSK modes (RFC 9180 Section 5.1.3)
    /// Returns (encapsulated_key, shared_secret)
    fn auth_encapsulate(
        &self,
        kem: HpkeKem,
        sender_sk: &[u8],
        recipient_pk: &[u8],
        rng: &mut dyn CryptoRng,
    ) -> Result<(Vec<u8>, Vec<u8>), Self::Error>;

    /// Authenticated decapsulation for Auth and AuthPSK modes (RFC 9180 Section 5.1.3)
    fn auth_decapsulate(
        &self,
        kem: HpkeKem,
        encapsulated_key: &[u8],
        recipient_sk: &[u8],
        sender_pk: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;
}

/// Trait for Key Derivation Function (KDF) providers
pub trait KdfProvider {
    /// Error type for KDF operations
    type Error: Into<HpkeError>;

    /// Extract a pseudorandom key from input key material
    fn extract(&self, kdf: HpkeKdf, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Expand a pseudorandom key to the desired length
    fn expand(
        &self,
        kdf: HpkeKdf,
        prk: &[u8],
        info: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, Self::Error>;

    /// Check if the provider supports the given KDF algorithm
    fn supports_kdf(&self, kdf: HpkeKdf) -> bool;
}

/// Trait for Authenticated Encryption with Associated Data (AEAD) providers
pub trait AeadProvider {
    /// Error type for AEAD operations
    type Error: Into<HpkeError>;

    /// Encrypt and authenticate plaintext
    fn seal(
        &self,
        aead: HpkeAead,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;

    /// Decrypt and verify ciphertext
    fn open(
        &self,
        aead: HpkeAead,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;

    /// Validate an AEAD key
    fn validate_key(&self, aead: HpkeAead, key: &[u8]) -> Result<(), Self::Error>;

    /// Validate an AEAD nonce
    fn validate_nonce(&self, aead: HpkeAead, nonce: &[u8]) -> Result<(), Self::Error>;

    /// Check if the provider supports the given AEAD algorithm
    fn supports_aead(&self, aead: HpkeAead) -> bool;
}

/// Combined provider trait that implements all cryptographic operations
pub trait HpkeCryptoProvider: KemProvider + KdfProvider + AeadProvider {
    /// Get the name of the provider
    fn name(&self) -> &'static str;

    /// Get the supported algorithms
    fn supported_algorithms(&self) -> SupportedAlgorithms;
}

/// Supported algorithms information
#[derive(Debug, Clone, PartialEq)]
pub struct SupportedAlgorithms {
    /// Supported KEM algorithms
    pub kems: Vec<HpkeKem>,
    /// Supported KDF algorithms
    pub kdfs: Vec<HpkeKdf>,
    /// Supported AEAD algorithms
    pub aeads: Vec<HpkeAead>,
}

impl SupportedAlgorithms {
    /// Create a new supported algorithms structure
    pub fn new(kems: Vec<HpkeKem>, kdfs: Vec<HpkeKdf>, aeads: Vec<HpkeAead>) -> Self {
        Self { kems, kdfs, aeads }
    }

    /// Check if a KEM is supported
    pub fn supports_kem(&self, kem: HpkeKem) -> bool {
        self.kems.contains(&kem)
    }

    /// Check if a KDF is supported
    pub fn supports_kdf(&self, kdf: HpkeKdf) -> bool {
        self.kdfs.contains(&kdf)
    }

    /// Check if an AEAD is supported
    pub fn supports_aead(&self, aead: HpkeAead) -> bool {
        self.aeads.contains(&aead)
    }
}
