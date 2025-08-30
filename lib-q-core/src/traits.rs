//! Common traits for lib-Q cryptographic operations

#[cfg(feature = "alloc")]
use zeroize::{
    Zeroize,
    ZeroizeOnDrop,
};

use crate::error::Result;

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// Trait for key encapsulation mechanisms
pub trait Kem {
    /// Generate a keypair
    fn generate_keypair(&self) -> Result<KemKeypair>;

    /// Encapsulate a shared secret
    #[cfg(feature = "alloc")]
    fn encapsulate(&self, public_key: &KemPublicKey) -> Result<(Vec<u8>, Vec<u8>)>;
    #[cfg(not(feature = "alloc"))]
    fn encapsulate(&self, public_key: &KemPublicKey) -> Result<(&'static [u8], &'static [u8])>;

    /// Decapsulate a shared secret
    #[cfg(feature = "alloc")]
    fn decapsulate(&self, secret_key: &KemSecretKey, ciphertext: &[u8]) -> Result<Vec<u8>>;
    #[cfg(not(feature = "alloc"))]
    fn decapsulate(&self, secret_key: &KemSecretKey, ciphertext: &[u8]) -> Result<&'static [u8]>;
}

/// Trait for digital signatures
pub trait Signature {
    /// Generate a keypair
    fn generate_keypair(&self) -> Result<SigKeypair>;

    /// Sign a message
    #[cfg(feature = "alloc")]
    fn sign(&self, secret_key: &SigSecretKey, message: &[u8]) -> Result<Vec<u8>>;
    #[cfg(not(feature = "alloc"))]
    fn sign(&self, secret_key: &SigSecretKey, message: &[u8]) -> Result<&'static [u8]>;

    /// Verify a signature
    fn verify(&self, public_key: &SigPublicKey, message: &[u8], signature: &[u8]) -> Result<bool>;
}

/// Trait for hash functions
pub trait Hash {
    /// Hash data
    #[cfg(feature = "alloc")]
    fn hash(&self, data: &[u8]) -> Result<Vec<u8>>;
    #[cfg(not(feature = "alloc"))]
    fn hash(&self, data: &[u8]) -> Result<&'static [u8]>;

    /// Get the output size in bytes
    fn output_size(&self) -> usize;
}

/// Trait for authenticated encryption
pub trait Aead {
    /// Encrypt data
    #[cfg(feature = "alloc")]
    fn encrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>>;
    #[cfg(not(feature = "alloc"))]
    fn encrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<&'static [u8]>;

    /// Decrypt data
    #[cfg(feature = "alloc")]
    fn decrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>>;
    #[cfg(not(feature = "alloc"))]
    fn decrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<&'static [u8]>;
}

// Key types
/// KEM keypair with automatic memory zeroization
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct KemKeypair {
    #[cfg_attr(feature = "wasm", wasm_bindgen(skip))]
    pub public_key: KemPublicKey,
    #[cfg_attr(feature = "wasm", wasm_bindgen(skip))]
    pub secret_key: KemSecretKey,
}

/// KEM public key
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct KemPublicKey {
    #[cfg_attr(feature = "wasm", wasm_bindgen(skip))]
    #[cfg(feature = "alloc")]
    pub data: Vec<u8>,
    #[cfg(not(feature = "alloc"))]
    pub data: &'static [u8],
}

/// KEM secret key with automatic memory zeroization
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct KemSecretKey {
    #[cfg_attr(feature = "wasm", wasm_bindgen(skip))]
    #[cfg(feature = "alloc")]
    pub data: Vec<u8>,
    #[cfg(not(feature = "alloc"))]
    pub data: &'static [u8],
}

#[cfg(feature = "alloc")]
impl Zeroize for KemSecretKey {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

#[cfg(feature = "alloc")]
impl ZeroizeOnDrop for KemSecretKey {}

/// Signature keypair with automatic memory zeroization
pub struct SigKeypair {
    pub public_key: SigPublicKey,
    pub secret_key: SigSecretKey,
}

/// Signature public key
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigPublicKey {
    #[cfg(feature = "alloc")]
    pub data: Vec<u8>,
    #[cfg(not(feature = "alloc"))]
    pub data: &'static [u8],
}

/// Signature secret key with automatic memory zeroization
pub struct SigSecretKey {
    #[cfg(feature = "alloc")]
    pub data: Vec<u8>,
    #[cfg(not(feature = "alloc"))]
    pub data: &'static [u8],
}

#[cfg(feature = "alloc")]
impl Zeroize for SigSecretKey {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

#[cfg(feature = "alloc")]
impl ZeroizeOnDrop for SigSecretKey {}

/// AEAD key
pub struct AeadKey {
    #[cfg(feature = "alloc")]
    pub data: Vec<u8>,
    #[cfg(not(feature = "alloc"))]
    pub data: &'static [u8],
}

#[cfg(feature = "alloc")]
impl Zeroize for AeadKey {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

#[cfg(feature = "alloc")]
impl ZeroizeOnDrop for AeadKey {}

/// Nonce for AEAD operations
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nonce {
    #[cfg(feature = "alloc")]
    pub data: Vec<u8>,
    #[cfg(not(feature = "alloc"))]
    pub data: &'static [u8],
}

// Implementations for key types
impl KemKeypair {
    #[cfg(feature = "alloc")]
    pub fn new(public_key: Vec<u8>, secret_key: Vec<u8>) -> Self {
        Self {
            public_key: KemPublicKey { data: public_key },
            secret_key: KemSecretKey { data: secret_key },
        }
    }

    #[cfg(not(feature = "alloc"))]
    pub fn new(public_key: &'static [u8], secret_key: &'static [u8]) -> Self {
        Self {
            public_key: KemPublicKey { data: public_key },
            secret_key: KemSecretKey { data: secret_key },
        }
    }

    pub fn public_key(&self) -> &KemPublicKey {
        &self.public_key
    }

    pub fn secret_key(&self) -> &KemSecretKey {
        &self.secret_key
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl KemKeypair {
    /// Create a new KEM keypair from bytes for WASM
    #[wasm_bindgen(constructor)]
    pub fn new_wasm(public_key: Vec<u8>, secret_key: Vec<u8>) -> KemKeypair {
        Self::new(public_key, secret_key)
    }

    /// Get the public key as bytes for WASM
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.data.to_vec()
    }

    /// Get the secret key as bytes for WASM
    pub fn secret_key_bytes(&self) -> Vec<u8> {
        self.secret_key.data.to_vec()
    }
}

impl SigKeypair {
    #[cfg(feature = "alloc")]
    pub fn new(public_key: Vec<u8>, secret_key: Vec<u8>) -> Self {
        Self {
            public_key: SigPublicKey { data: public_key },
            secret_key: SigSecretKey { data: secret_key },
        }
    }

    #[cfg(not(feature = "alloc"))]
    pub fn new(public_key: &'static [u8], secret_key: &'static [u8]) -> Self {
        Self {
            public_key: SigPublicKey { data: public_key },
            secret_key: SigSecretKey { data: secret_key },
        }
    }

    pub fn public_key(&self) -> &SigPublicKey {
        &self.public_key
    }

    pub fn secret_key(&self) -> &SigSecretKey {
        &self.secret_key
    }
}

impl KemPublicKey {
    #[cfg(feature = "alloc")]
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    #[cfg(not(feature = "alloc"))]
    pub fn new(data: &'static [u8]) -> Self {
        Self { data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl KemPublicKey {
    /// Create a new KEM public key from bytes for WASM
    #[wasm_bindgen(constructor)]
    pub fn new_from_bytes(data: Vec<u8>) -> KemPublicKey {
        Self::new(data)
    }

    /// Get the key data as bytes for WASM
    pub fn bytes(&self) -> Vec<u8> {
        self.data.to_vec()
    }
}

impl KemSecretKey {
    #[cfg(feature = "alloc")]
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    #[cfg(not(feature = "alloc"))]
    pub fn new(data: &'static [u8]) -> Self {
        Self { data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl KemSecretKey {
    /// Create a new KEM secret key from bytes for WASM
    #[wasm_bindgen(constructor)]
    pub fn new_from_bytes(data: Vec<u8>) -> KemSecretKey {
        Self::new(data)
    }

    /// Get the key data as bytes for WASM
    pub fn bytes(&self) -> Vec<u8> {
        self.data.to_vec()
    }
}

impl SigPublicKey {
    #[cfg(feature = "alloc")]
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    #[cfg(not(feature = "alloc"))]
    pub fn new(data: &'static [u8]) -> Self {
        Self { data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl SigSecretKey {
    #[cfg(feature = "alloc")]
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    #[cfg(not(feature = "alloc"))]
    pub fn new(data: &'static [u8]) -> Self {
        Self { data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl AeadKey {
    #[cfg(feature = "alloc")]
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    #[cfg(not(feature = "alloc"))]
    pub fn new(data: &'static [u8]) -> Self {
        Self { data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl Nonce {
    #[cfg(feature = "alloc")]
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    #[cfg(not(feature = "alloc"))]
    pub fn new(data: &'static [u8]) -> Self {
        Self { data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}
