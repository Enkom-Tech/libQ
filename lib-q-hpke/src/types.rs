//! HPKE-specific types and algorithms

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// HPKE Modes (RFC 9180 Section 5.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HpkeMode {
    /// Base mode - no authentication
    Base = 0x00,
    /// PSK mode - pre-shared key authentication
    Psk = 0x01,
    /// Auth mode - asymmetric authentication
    Auth = 0x02,
    /// AuthPsk mode - both PSK and asymmetric authentication
    AuthPsk = 0x03,
}

impl HpkeMode {
    /// Convert from u8
    pub fn from_u8(mode: u8) -> Option<Self> {
        match mode {
            0x00 => Some(Self::Base),
            0x01 => Some(Self::Psk),
            0x02 => Some(Self::Auth),
            0x03 => Some(Self::AuthPsk),
            _ => None,
        }
    }

    /// Convert to u8
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// HPKE Key Encapsulation Mechanisms (Post-Quantum Only)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpkeKem {
    /// ML-KEM-512 (Kyber-512)
    MlKem512,
    /// ML-KEM-768 (Kyber-768)
    MlKem768,
    /// ML-KEM-1024 (Kyber-1024)
    MlKem1024,
    // X-Wing KEM (draft) - future feature
    // XWing,
}

impl HpkeKem {
    /// Get algorithm identifier (RFC 9180 Section 7.1)
    pub fn algorithm_id(self) -> u16 {
        match self {
            Self::MlKem512 => 0x0022,
            Self::MlKem768 => 0x0023,
            Self::MlKem1024 => 0x0024,
            // Future: XWing => 0x0025, // draft
        }
    }

    /// Get the length of the KEM shared secret
    pub fn shared_secret_len(self) -> usize {
        match self {
            Self::MlKem512 => 32,
            Self::MlKem768 => 32,
            Self::MlKem1024 => 32,
            // Future: XWing => 32,
        }
    }

    /// Get the length of encapsulated keys
    pub fn enc_len(self) -> usize {
        match self {
            Self::MlKem512 => 768,
            Self::MlKem768 => 1088,
            Self::MlKem1024 => 1568,
            // Future: XWing => 64, // draft
        }
    }
}

/// HPKE Key Derivation Functions (Post-Quantum)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpkeKdf {
    /// HKDF-SHAKE128
    HkdfShake128,
    /// HKDF-SHAKE256
    HkdfShake256,
    /// HKDF-SHA3-256
    HkdfSha3_256,
    /// HKDF-SHA3-512
    HkdfSha3_512,
}

impl HpkeKdf {
    /// Get algorithm identifier (Post-quantum extensions)
    pub fn algorithm_id(self) -> u16 {
        match self {
            Self::HkdfShake128 => 0x0004, // Post-quantum extension
            Self::HkdfShake256 => 0x0005, // Post-quantum extension
            Self::HkdfSha3_256 => 0x0006, // Post-quantum extension
            Self::HkdfSha3_512 => 0x0007, // Post-quantum extension
        }
    }

    /// Get the digest length
    pub fn digest_len(self) -> usize {
        match self {
            Self::HkdfShake128 => 32, // Default output length
            Self::HkdfShake256 => 64, // Default output length
            Self::HkdfSha3_256 => 32,
            Self::HkdfSha3_512 => 64,
        }
    }
}

/// HPKE Authenticated Encryption with Associated Data (Post-Quantum Only)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpkeAead {
    /// Ascon-128
    Ascon128,
    /// Ascon-128a
    Ascon128a,
    // Future AEADs
    // Ascon80pq, // Ascon-80pq
    // Xoodyak,   // Xoodyak
    // Sparkle,   // Sparkle
    /// Export-only (no encryption)
    Export,
}

impl HpkeAead {
    /// Get algorithm identifier (Post-quantum extensions)
    pub fn algorithm_id(self) -> u16 {
        match self {
            Self::Ascon128 => 0x0004,  // Post-quantum extension
            Self::Ascon128a => 0x0005, // Post-quantum extension
            // Future: Ascon80pq => 0x0006,     // Post-quantum extension
            // Future: Xoodyak => 0x0007,       // Post-quantum extension
            // Future: Sparkle => 0x0008,       // Post-quantum extension
            Self::Export => 0xFFFF,
        }
    }

    /// Get the key length
    pub fn key_len(self) -> usize {
        match self {
            Self::Ascon128 => 16,
            Self::Ascon128a => 16,
            // Future: Ascon80pq => 20,         // Ascon-80pq uses 160-bit key
            // Future: Xoodyak => 16,
            // Future: Sparkle => 16,
            Self::Export => 0,
        }
    }

    /// Get the nonce length
    pub fn nonce_len(self) -> usize {
        match self {
            Self::Ascon128 => 16,
            Self::Ascon128a => 16,
            // Future: Ascon80pq => 16,
            // Future: Xoodyak => 16,
            // Future: Sparkle => 16,
            Self::Export => 0,
        }
    }

    /// Get the tag length
    pub fn tag_len(self) -> usize {
        match self {
            Self::Ascon128 => 16,
            Self::Ascon128a => 16,
            // Future: Ascon80pq => 16,
            // Future: Xoodyak => 16,
            // Future: Sparkle => 16,
            Self::Export => 0,
        }
    }
}

/// HPKE cipher suite combining KEM, KDF, and AEAD
#[derive(Debug, Clone)]
pub struct HpkeCipherSuite {
    /// Key Encapsulation Mechanism algorithm
    pub kem: HpkeKem,
    /// Key Derivation Function algorithm
    pub kdf: HpkeKdf,
    /// Authenticated Encryption with Associated Data algorithm
    pub aead: HpkeAead,
}

impl HpkeCipherSuite {
    /// Create a new cipher suite
    pub fn new(kem: HpkeKem, kdf: HpkeKdf, aead: HpkeAead) -> Self {
        Self { kem, kdf, aead }
    }

    /// Get the cipher suite identifier
    pub fn identifier(&self) -> Vec<u8> {
        let mut id = Vec::new();
        id.extend_from_slice(&self.kem.algorithm_id().to_be_bytes());
        id.extend_from_slice(&self.kdf.algorithm_id().to_be_bytes());
        id.extend_from_slice(&self.aead.algorithm_id().to_be_bytes());
        id
    }
}

/// HPKE public key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HpkePublicKey {
    pub(crate) value: Vec<u8>,
}

impl HpkePublicKey {
    /// Create from bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { value: bytes }
    }

    /// Get as byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.value
    }

    /// Convert to owned bytes
    pub fn to_bytes(self) -> Vec<u8> {
        self.value.clone()
    }
}

/// HPKE private key
#[derive(Clone)]
pub struct HpkePrivateKey {
    pub(crate) value: Vec<u8>,
}

impl HpkePrivateKey {
    /// Create from bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { value: bytes }
    }

    /// Get as byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.value
    }
}

impl HpkePrivateKey {
    /// Convert to owned bytes (secure: clones to avoid moving sensitive data)
    pub fn to_bytes(&self) -> Vec<u8> {
        self.value.clone()
    }
}

impl Drop for HpkePrivateKey {
    fn drop(&mut self) {
        // Zeroize the private key when dropped
        self.value.iter_mut().for_each(|b| *b = 0);
    }
}

/// HPKE key pair containing public and private keys
#[derive(Clone)]
pub struct HpkeKeyPair {
    /// Public key for key encapsulation
    pub public_key: HpkePublicKey,
    /// Private key for key decapsulation (sensitive data)
    pub private_key: HpkePrivateKey,
}

impl HpkeKeyPair {
    /// Create from public and private keys
    pub fn from_keys(public_key: HpkePublicKey, private_key: HpkePrivateKey) -> Self {
        Self {
            public_key,
            private_key,
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> &HpkePublicKey {
        &self.public_key
    }

    /// Get the private key
    pub fn private_key(&self) -> &HpkePrivateKey {
        &self.private_key
    }

    /// Split into public and private keys
    pub fn into_keys(self) -> (HpkePublicKey, HpkePrivateKey) {
        (self.public_key, self.private_key)
    }
}

/// Encapsulated key (KEM ciphertext)
pub type EncapsulatedKey = Vec<u8>;

/// Exported key material
pub type ExportedKey = Vec<u8>;

/// HPKE sender context for multi-message encryption
#[derive(Debug)]
pub struct HpkeSenderContext {
    /// Shared secret from KEM
    pub(crate) shared_secret: Vec<u8>,
    /// Secret for key export
    pub(crate) exporter_secret: Vec<u8>,
    /// AEAD encryption key
    pub(crate) key: Vec<u8>,
    /// Base nonce for AEAD
    pub(crate) nonce: Vec<u8>,
    /// Sequence number for nonce derivation
    pub(crate) sequence_number: u32,
}

impl HpkeSenderContext {
    /// Create a new sender context
    pub fn new(
        shared_secret: Vec<u8>,
        exporter_secret: Vec<u8>,
        key: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Self {
        Self {
            shared_secret,
            exporter_secret,
            key,
            nonce,
            sequence_number: 0,
        }
    }
}

/// HPKE receiver context for multi-message decryption
#[derive(Debug)]
pub struct HpkeReceiverContext {
    /// Shared secret from KEM
    pub(crate) shared_secret: Vec<u8>,
    /// Secret for key export
    pub(crate) exporter_secret: Vec<u8>,
    /// AEAD decryption key
    pub(crate) key: Vec<u8>,
    /// Base nonce for AEAD
    pub(crate) nonce: Vec<u8>,
    /// Sequence number for nonce derivation
    pub(crate) sequence_number: u32,
}

impl HpkeReceiverContext {
    /// Create a new receiver context
    pub fn new(
        shared_secret: Vec<u8>,
        exporter_secret: Vec<u8>,
        key: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Self {
        Self {
            shared_secret,
            exporter_secret,
            key,
            nonce,
            sequence_number: 0,
        }
    }
}
