//! HQC KEM implementations for the legacy `Kem` trait and `create_kem()` API.
//!
//! This module delegates all operations to `lib_q_hqc::LibQHqcProvider`. The three
//! types (`Hqc128Impl`, `Hqc192Impl`, `Hqc256Impl`) are algorithm-specific wrappers
//! that forward to the provider with a fixed algorithm.

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::string::ToString;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use lib_q_core::{
    Algorithm,
    Error,
    Kem,
    KemKeypair,
    KemOperations,
    KemPublicKey,
    KemSecretKey,
    Result,
};
use lib_q_hqc::LibQHqcProvider;

fn provider() -> Result<LibQHqcProvider> {
    LibQHqcProvider::new()
}

/// HQC-128 KEM implementation (NIST Level 1). Delegates to `LibQHqcProvider`.
#[derive(Debug, Clone, Default)]
pub struct Hqc128Impl;

impl Hqc128Impl {
    /// Create a new HQC-128 instance.
    pub fn new() -> Self {
        Self
    }
}

impl Kem for Hqc128Impl {
    fn generate_keypair(&self) -> Result<KemKeypair> {
        provider()?.generate_keypair(Algorithm::Hqc128, None)
    }

    fn encapsulate(&self, public_key: &KemPublicKey) -> Result<(Vec<u8>, Vec<u8>)> {
        let (ciphertext, shared_secret) =
            provider()?.encapsulate(Algorithm::Hqc128, public_key, None)?;
        Ok((ciphertext, shared_secret))
    }

    fn decapsulate(&self, secret_key: &KemSecretKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
        provider()?.decapsulate(Algorithm::Hqc128, secret_key, ciphertext)
    }

    fn derive_public_key(&self, secret_key: &KemSecretKey) -> Result<KemPublicKey> {
        provider()?.derive_public_key(Algorithm::Hqc128, secret_key)
    }

    fn auth_encapsulate(
        &self,
        _sender_sk: &KemSecretKey,
        _recipient_pk: &KemPublicKey,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        Err(Error::NotImplemented {
            feature: "HQC authenticated encapsulation - use HPKE AuthEncap instead".to_string(),
        })
    }

    fn auth_decapsulate(
        &self,
        _recipient_sk: &KemSecretKey,
        _ciphertext: &[u8],
        _sender_pk: &KemPublicKey,
    ) -> Result<Vec<u8>> {
        Err(Error::NotImplemented {
            feature: "HQC authenticated decapsulation - use HPKE AuthDecap instead".to_string(),
        })
    }
}

/// HQC-192 KEM implementation (NIST Level 3). Delegates to `LibQHqcProvider`.
#[derive(Debug, Clone, Default)]
pub struct Hqc192Impl;

impl Hqc192Impl {
    /// Create a new HQC-192 instance.
    pub fn new() -> Self {
        Self
    }
}

impl Kem for Hqc192Impl {
    fn generate_keypair(&self) -> Result<KemKeypair> {
        provider()?.generate_keypair(Algorithm::Hqc192, None)
    }

    fn encapsulate(&self, public_key: &KemPublicKey) -> Result<(Vec<u8>, Vec<u8>)> {
        let (ciphertext, shared_secret) =
            provider()?.encapsulate(Algorithm::Hqc192, public_key, None)?;
        Ok((ciphertext, shared_secret))
    }

    fn decapsulate(&self, secret_key: &KemSecretKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
        provider()?.decapsulate(Algorithm::Hqc192, secret_key, ciphertext)
    }

    fn derive_public_key(&self, secret_key: &KemSecretKey) -> Result<KemPublicKey> {
        provider()?.derive_public_key(Algorithm::Hqc192, secret_key)
    }

    fn auth_encapsulate(
        &self,
        _sender_sk: &KemSecretKey,
        _recipient_pk: &KemPublicKey,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        Err(Error::NotImplemented {
            feature: "HQC authenticated encapsulation - use HPKE AuthEncap instead".to_string(),
        })
    }

    fn auth_decapsulate(
        &self,
        _recipient_sk: &KemSecretKey,
        _ciphertext: &[u8],
        _sender_pk: &KemPublicKey,
    ) -> Result<Vec<u8>> {
        Err(Error::NotImplemented {
            feature: "HQC authenticated decapsulation - use HPKE AuthDecap instead".to_string(),
        })
    }
}

/// HQC-256 KEM implementation (NIST Level 5). Delegates to `LibQHqcProvider`.
#[derive(Debug, Clone, Default)]
pub struct Hqc256Impl;

impl Hqc256Impl {
    /// Create a new HQC-256 instance.
    pub fn new() -> Self {
        Self
    }
}

impl Kem for Hqc256Impl {
    fn generate_keypair(&self) -> Result<KemKeypair> {
        provider()?.generate_keypair(Algorithm::Hqc256, None)
    }

    fn encapsulate(&self, public_key: &KemPublicKey) -> Result<(Vec<u8>, Vec<u8>)> {
        let (ciphertext, shared_secret) =
            provider()?.encapsulate(Algorithm::Hqc256, public_key, None)?;
        Ok((ciphertext, shared_secret))
    }

    fn decapsulate(&self, secret_key: &KemSecretKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
        provider()?.decapsulate(Algorithm::Hqc256, secret_key, ciphertext)
    }

    fn derive_public_key(&self, secret_key: &KemSecretKey) -> Result<KemPublicKey> {
        provider()?.derive_public_key(Algorithm::Hqc256, secret_key)
    }

    fn auth_encapsulate(
        &self,
        _sender_sk: &KemSecretKey,
        _recipient_pk: &KemPublicKey,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        Err(Error::NotImplemented {
            feature: "HQC authenticated encapsulation - use HPKE AuthEncap instead".to_string(),
        })
    }

    fn auth_decapsulate(
        &self,
        _recipient_sk: &KemSecretKey,
        _ciphertext: &[u8],
        _sender_pk: &KemPublicKey,
    ) -> Result<Vec<u8>> {
        Err(Error::NotImplemented {
            feature: "HQC authenticated decapsulation - use HPKE AuthDecap instead".to_string(),
        })
    }
}
