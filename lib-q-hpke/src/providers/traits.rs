//! Provider traits for HPKE cryptographic operations

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::error::HpkeError;
use crate::security::CryptoRng;
use crate::types::{
    HpkeAead,
    HpkeCipherSuite,
    HpkeKdf,
    HpkeKem,
    SecretBytes,
};

/// Public KEM material (e.g. ciphertext or public key) paired with zeroized secret bytes
/// (shared secret or secret key), as returned by [`KemProvider`].
pub type KemPublicAndSecretBytes = (Vec<u8>, SecretBytes);

/// Trait for Key Encapsulation Mechanism (KEM) providers
///
/// Shared secrets and secret keys are returned in `zeroize::Zeroizing` buffers so callers
/// clear them on drop. Implementations should move underlying `Vec` material into
/// [`SecretBytes`] (for example via `zeroize::Zeroizing::new`) at the boundary (as
/// [`crate::providers::PostQuantumProvider`] does).
///
/// All methods use [`HpkeError`] so this trait remains **object-safe** and can be used behind
/// [`alloc::sync::Arc`] as a unified HPKE backend (see [`crate::HpkeContext`]).
pub trait KemProvider {
    /// Generate a key pair for the given KEM algorithm.
    ///
    /// Returns `(public_key, secret_key)` with the secret key in [`SecretBytes`].
    fn generate_keypair(
        &self,
        kem: HpkeKem,
        rng: &mut dyn CryptoRng,
    ) -> Result<KemPublicAndSecretBytes, HpkeError>;

    /// Encapsulate a shared secret using the public key.
    ///
    /// Returns `(ciphertext, shared_secret)`; shared secret material is zeroized on drop.
    fn encapsulate(
        &self,
        kem: HpkeKem,
        public_key: &[u8],
        rng: &mut dyn CryptoRng,
    ) -> Result<KemPublicAndSecretBytes, HpkeError>;

    /// Decapsulate a shared secret using the secret key
    fn decapsulate(
        &self,
        kem: HpkeKem,
        secret_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<SecretBytes, HpkeError>;

    /// Validate a KEM key
    fn validate_key(&self, kem: HpkeKem, key: &[u8], is_secret: bool) -> Result<(), HpkeError>;

    /// Derive public key from secret key
    fn derive_public_key(&self, kem: HpkeKem, secret_key: &[u8]) -> Result<Vec<u8>, HpkeError>;

    /// Check if the provider supports the given KEM algorithm
    fn supports_kem(&self, kem: HpkeKem) -> bool;

    /// Authenticated encapsulation for Auth and AuthPSK modes (RFC 9180 Section 5.1.3)
    ///
    /// Returns `(encapsulated_key, shared_secret)` with shared secret in [`SecretBytes`].
    fn auth_encapsulate(
        &self,
        kem: HpkeKem,
        sender_sk: &[u8],
        recipient_pk: &[u8],
        rng: &mut dyn CryptoRng,
    ) -> Result<KemPublicAndSecretBytes, HpkeError>;

    /// Authenticated decapsulation for Auth and AuthPSK modes (RFC 9180 Section 5.1.3)
    fn auth_decapsulate(
        &self,
        kem: HpkeKem,
        encapsulated_key: &[u8],
        recipient_sk: &[u8],
        sender_pk: &[u8],
    ) -> Result<SecretBytes, HpkeError>;
}

/// Trait for Key Derivation Function (KDF) providers
pub trait KdfProvider {
    /// Extract a pseudorandom key from input key material
    fn extract(&self, kdf: HpkeKdf, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, HpkeError>;

    /// Expand a pseudorandom key to the desired length
    fn expand(
        &self,
        kdf: HpkeKdf,
        prk: &[u8],
        info: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, HpkeError>;

    /// Check if the provider supports the given KDF algorithm
    fn supports_kdf(&self, kdf: HpkeKdf) -> bool;
}

/// Trait for Authenticated Encryption with Associated Data (AEAD) providers
///
/// `open` / `seal` remain **Layer A** [`Result`] APIs. Semantic decrypt
/// ([`lib_q_core::AeadDecryptSemantic`]) is not part of this trait; callers that need
/// [`lib_q_core::DecryptSemanticOutcome`] must use a concrete AEAD implementation type
/// (for example [`crate::aead::saturnin::SaturninAeadImpl`] when the `saturnin` feature is enabled).
pub trait AeadProvider {
    /// Encrypt and authenticate plaintext
    fn seal(
        &self,
        aead: HpkeAead,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, HpkeError>;

    /// Decrypt and verify ciphertext
    fn open(
        &self,
        aead: HpkeAead,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, HpkeError>;

    /// Validate an AEAD key
    fn validate_key(&self, aead: HpkeAead, key: &[u8]) -> Result<(), HpkeError>;

    /// Validate an AEAD nonce
    fn validate_nonce(&self, aead: HpkeAead, nonce: &[u8]) -> Result<(), HpkeError>;

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

    /// True when KEM, KDF, and AEAD from `suite` are all listed as supported.
    pub fn supports_cipher_suite(&self, suite: &HpkeCipherSuite) -> bool {
        self.supports_kem(suite.kem) &&
            self.supports_kdf(suite.kdf) &&
            self.supports_aead(suite.aead)
    }
}
