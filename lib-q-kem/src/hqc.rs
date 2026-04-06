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

#[cfg(all(test, feature = "hqc", feature = "alloc", feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn test_hqc_impl_constructors_and_roundtrip() {
        let hqc128 = Hqc128Impl::new();
        let kp128 = hqc128.generate_keypair().unwrap();
        let (ct128, ss128_a) = hqc128.encapsulate(&kp128.public_key).unwrap();
        let ss128_b = hqc128.decapsulate(&kp128.secret_key, &ct128).unwrap();
        assert_eq!(ss128_a, ss128_b);
        let derived128 = hqc128.derive_public_key(&kp128.secret_key).unwrap();
        assert_eq!(derived128.data, kp128.public_key.data);

        let hqc192 = Hqc192Impl::new();
        let kp192 = hqc192.generate_keypair().unwrap();
        let (ct192, ss192_a) = hqc192.encapsulate(&kp192.public_key).unwrap();
        let ss192_b = hqc192.decapsulate(&kp192.secret_key, &ct192).unwrap();
        assert_eq!(ss192_a, ss192_b);
        let derived192 = hqc192.derive_public_key(&kp192.secret_key).unwrap();
        assert_eq!(derived192.data, kp192.public_key.data);

        let hqc256 = Hqc256Impl::new();
        let kp256 = hqc256.generate_keypair().unwrap();
        let (ct256, ss256_a) = hqc256.encapsulate(&kp256.public_key).unwrap();
        let ss256_b = hqc256.decapsulate(&kp256.secret_key, &ct256).unwrap();
        assert_eq!(ss256_a, ss256_b);
        let derived256 = hqc256.derive_public_key(&kp256.secret_key).unwrap();
        assert_eq!(derived256.data, kp256.public_key.data);
    }

    #[test]
    fn test_hqc_auth_methods_not_implemented() {
        let hqc128 = Hqc128Impl::new();
        let kp128 = hqc128.generate_keypair().unwrap();
        let auth_enc_128 = hqc128.auth_encapsulate(&kp128.secret_key, &kp128.public_key);
        assert!(matches!(auth_enc_128, Err(Error::NotImplemented { .. })));
        let auth_dec_128 = hqc128.auth_decapsulate(&kp128.secret_key, &[0u8; 8], &kp128.public_key);
        assert!(matches!(auth_dec_128, Err(Error::NotImplemented { .. })));

        let hqc192 = Hqc192Impl::new();
        let kp192 = hqc192.generate_keypair().unwrap();
        let auth_enc_192 = hqc192.auth_encapsulate(&kp192.secret_key, &kp192.public_key);
        assert!(matches!(auth_enc_192, Err(Error::NotImplemented { .. })));
        let auth_dec_192 = hqc192.auth_decapsulate(&kp192.secret_key, &[0u8; 8], &kp192.public_key);
        assert!(matches!(auth_dec_192, Err(Error::NotImplemented { .. })));

        let hqc256 = Hqc256Impl::new();
        let kp256 = hqc256.generate_keypair().unwrap();
        let auth_enc_256 = hqc256.auth_encapsulate(&kp256.secret_key, &kp256.public_key);
        assert!(matches!(auth_enc_256, Err(Error::NotImplemented { .. })));
        let auth_dec_256 = hqc256.auth_decapsulate(&kp256.secret_key, &[0u8; 8], &kp256.public_key);
        assert!(matches!(auth_dec_256, Err(Error::NotImplemented { .. })));
    }
}
