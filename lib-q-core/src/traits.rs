//! Common traits for lib-Q cryptographic operations

use crate::error::Result;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Trait for key encapsulation mechanisms
pub trait Kem {
    /// Generate a keypair
    fn generate_keypair(&self) -> Result<KemKeypair>;

    /// Encapsulate a shared secret
    fn encapsulate(&self, public_key: &KemPublicKey) -> Result<(Vec<u8>, Vec<u8>)>;

    /// Decapsulate a shared secret
    fn decapsulate(&self, secret_key: &KemSecretKey, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

/// Trait for digital signatures
pub trait Signature {
    /// Generate a keypair
    fn generate_keypair(&self) -> Result<SigKeypair>;

    /// Sign a message
    fn sign(&self, secret_key: &SigSecretKey, message: &[u8]) -> Result<Vec<u8>>;

    /// Verify a signature
    fn verify(&self, public_key: &SigPublicKey, message: &[u8], signature: &[u8]) -> Result<bool>;
}

/// Trait for hash functions
pub trait Hash {
    /// Hash data
    fn hash(&self, data: &[u8]) -> Result<Vec<u8>>;

    /// Get the output size in bytes
    fn output_size(&self) -> usize;
}

/// Trait for authenticated encryption
pub trait Aead {
    /// Encrypt data
    fn encrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>>;

    /// Decrypt data
    fn decrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>>;
}

// Key types
/// KEM keypair with automatic memory zeroization
pub struct KemKeypair {
    pub public_key: KemPublicKey,
    pub secret_key: KemSecretKey,
}

/// KEM public key
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KemPublicKey {
    pub data: Vec<u8>,
}

/// KEM secret key with automatic memory zeroization
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KemSecretKey {
    pub data: Vec<u8>,
}

/// Signature keypair with automatic memory zeroization
pub struct SigKeypair {
    pub public_key: SigPublicKey,
    pub secret_key: SigSecretKey,
}

/// Signature public key
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigPublicKey {
    pub data: Vec<u8>,
}

/// Signature secret key with automatic memory zeroization
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SigSecretKey {
    pub data: Vec<u8>,
}

/// AEAD key
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AeadKey {
    pub data: Vec<u8>,
}

/// Nonce for AEAD operations
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nonce {
    pub data: Vec<u8>,
}

// Implementations for key types
impl KemKeypair {
    pub fn new(public_key: Vec<u8>, secret_key: Vec<u8>) -> Self {
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

impl SigKeypair {
    pub fn new(public_key: Vec<u8>, secret_key: Vec<u8>) -> Self {
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
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl KemSecretKey {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl SigPublicKey {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl SigSecretKey {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl AeadKey {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl Nonce {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}
