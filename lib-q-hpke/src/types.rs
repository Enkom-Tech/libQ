//! HPKE type definitions and algorithm specifications

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// HPKE modes as defined in RFC 9180 Section 5.1
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

/// Post-quantum key encapsulation mechanisms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpkeKem {
    /// ML-KEM-512
    MlKem512,
    /// ML-KEM-768
    MlKem768,
    /// ML-KEM-1024
    MlKem1024,
}

impl HpkeKem {
    /// Algorithm identifier per RFC 9180 Section 7.1
    pub fn algorithm_id(self) -> u16 {
        match self {
            Self::MlKem512 => 0x0022,
            Self::MlKem768 => 0x0023,
            Self::MlKem1024 => 0x0024,
        }
    }

    /// Shared secret length in bytes
    pub fn shared_secret_len(self) -> usize {
        match self {
            Self::MlKem512 => 32,
            Self::MlKem768 => 32,
            Self::MlKem1024 => 32,
        }
    }

    /// Encapsulated key length in bytes
    pub fn enc_len(self) -> usize {
        match self {
            Self::MlKem512 => 768,
            Self::MlKem768 => 1088,
            Self::MlKem1024 => 1568,
        }
    }

    /// Public key length in bytes
    pub fn public_key_len(self) -> usize {
        match self {
            Self::MlKem512 => 800,
            Self::MlKem768 => 1184,
            Self::MlKem1024 => 1568,
        }
    }

    /// Secret key length in bytes
    pub fn secret_key_len(self) -> usize {
        match self {
            Self::MlKem512 => 1632,
            Self::MlKem768 => 2400,
            Self::MlKem1024 => 3168,
        }
    }
}

/// Post-quantum key derivation functions
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
    /// Algorithm identifier for post-quantum extensions
    pub fn algorithm_id(self) -> u16 {
        match self {
            Self::HkdfShake128 => 0x0004,
            Self::HkdfShake256 => 0x0005,
            Self::HkdfSha3_256 => 0x0006,
            Self::HkdfSha3_512 => 0x0007,
        }
    }

    /// Digest output length in bytes
    pub fn digest_len(self) -> usize {
        match self {
            Self::HkdfShake128 => 32,
            Self::HkdfShake256 => 64,
            Self::HkdfSha3_256 => 32,
            Self::HkdfSha3_512 => 64,
        }
    }

    /// Extract output length in bytes
    pub fn extract_len(self) -> usize {
        match self {
            Self::HkdfShake128 => 16,
            Self::HkdfShake256 => 32,
            Self::HkdfSha3_256 => 32,
            Self::HkdfSha3_512 => 64,
        }
    }
}

/// Post-quantum authenticated encryption with associated data
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpkeAead {
    /// Saturnin-256
    Saturnin256,
    /// SHAKE256-based construction
    Shake256,
    /// Keccak-f[1600] duplex-sponge AEAD (lib-q; non-standard mode, 32-byte tag)
    DuplexSpongeAead,
    /// Export-only mode
    Export,
}

impl HpkeAead {
    /// Algorithm identifier for post-quantum extensions
    pub fn algorithm_id(self) -> u16 {
        match self {
            Self::Saturnin256 => 0x0004,
            Self::Shake256 => 0x0005,
            Self::DuplexSpongeAead => 0x0006,
            Self::Export => 0xFFFF,
        }
    }

    /// Key length in bytes
    pub fn key_len(self) -> usize {
        match self {
            Self::Saturnin256 => 32,
            Self::Shake256 => 32,
            Self::DuplexSpongeAead => 32,
            Self::Export => 0,
        }
    }

    /// Nonce length in bytes
    pub fn nonce_len(self) -> usize {
        match self {
            Self::Saturnin256 => 16,
            Self::Shake256 => 16,
            Self::DuplexSpongeAead => 16,
            Self::Export => 0,
        }
    }

    /// Authentication tag length in bytes
    pub fn tag_len(self) -> usize {
        match self {
            Self::Saturnin256 => 16,
            Self::Shake256 => 16,
            Self::DuplexSpongeAead => 32,
            Self::Export => 0,
        }
    }
}

/// HPKE cipher suite specification
#[derive(Debug, Clone)]
pub struct HpkeCipherSuite {
    /// Key encapsulation mechanism
    pub kem: HpkeKem,
    /// Key derivation function
    pub kdf: HpkeKdf,
    /// Authenticated encryption algorithm
    pub aead: HpkeAead,
}

impl HpkeCipherSuite {
    /// Create a new cipher suite
    pub fn new(kem: HpkeKem, kdf: HpkeKdf, aead: HpkeAead) -> Self {
        Self { kem, kdf, aead }
    }

    /// Cipher suite identifier as byte vector
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
    /// Convert to owned bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.value.clone()
    }
}

impl Drop for HpkePrivateKey {
    fn drop(&mut self) {
        self.value.iter_mut().for_each(|b| *b = 0);
    }
}

/// HPKE key pair
#[derive(Clone)]
pub struct HpkeKeyPair {
    /// Public key
    pub public_key: HpkePublicKey,
    /// Private key
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

/// Encapsulated key
pub type EncapsulatedKey = Vec<u8>;

/// Exported key material
pub type ExportedKey = Vec<u8>;

/// HPKE context state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpkeContextState {
    /// Context is active and can be used for encryption/decryption
    Active,
    /// Context has reached maximum sequence number and needs rekeying
    NeedsRekey,
    /// Context has been closed and cannot be used
    Closed,
}

/// HPKE sender context (no_std version)
///
/// This is the core context structure that can be used in no_std environments.
/// The std version in lib.rs wraps this structure with additional functionality.
#[derive(Debug)]
pub struct HpkeSenderContext {
    /// Shared secret from KEM
    pub shared_secret: Vec<u8>,
    /// Exporter secret
    pub exporter_secret: Vec<u8>,
    /// AEAD encryption key
    pub key: Vec<u8>,
    /// Base nonce
    pub nonce: Vec<u8>,
    /// AEAD algorithm from the negotiated cipher suite
    pub aead: HpkeAead,
    /// Encapsulated key to be sent to receiver
    pub encapsulated_key: Vec<u8>,
    /// Sequence number
    pub sequence_number: u32,
    /// Maximum sequence number before context must be rekeyed
    pub max_sequence_number: u32,
    /// Context state
    pub state: HpkeContextState,
}

impl HpkeSenderContext {
    /// Create a new sender context
    pub fn new(
        shared_secret: Vec<u8>,
        exporter_secret: Vec<u8>,
        key: Vec<u8>,
        nonce: Vec<u8>,
        encapsulated_key: Vec<u8>,
        aead: HpkeAead,
    ) -> Self {
        Self {
            shared_secret,
            exporter_secret,
            key,
            nonce,
            aead,
            encapsulated_key,
            sequence_number: 0,
            max_sequence_number: u32::MAX - 1, // Leave room for overflow check
            state: HpkeContextState::Active,
        }
    }

    /// Check if the context can be used for encryption
    pub fn can_encrypt(&self) -> bool {
        self.state == HpkeContextState::Active && self.sequence_number < self.max_sequence_number
    }

    /// Increment sequence number with overflow protection
    pub fn increment_sequence(&mut self) -> Result<(), crate::error::HpkeError> {
        if self.sequence_number >= self.max_sequence_number {
            self.state = HpkeContextState::NeedsRekey;
            return Err(crate::error::HpkeError::CryptoError(
                "Sequence number overflow: context needs rekeying".into(),
            ));
        }
        self.sequence_number = self.sequence_number.wrapping_add(1);
        Ok(())
    }

    /// Close the context
    pub fn close(&mut self) {
        self.state = HpkeContextState::Closed;
    }

    /// Get the encapsulated key to send to the receiver
    pub fn encapsulated_key(&self) -> &[u8] {
        &self.encapsulated_key
    }
}

/// HPKE receiver context (no_std version)
///
/// This is the core context structure that can be used in no_std environments.
/// The std version in lib.rs wraps this structure with additional functionality.
#[derive(Debug)]
pub struct HpkeReceiverContext {
    /// Shared secret from KEM
    pub shared_secret: Vec<u8>,
    /// Exporter secret
    pub exporter_secret: Vec<u8>,
    /// AEAD decryption key
    pub key: Vec<u8>,
    /// Base nonce
    pub nonce: Vec<u8>,
    /// AEAD algorithm from the negotiated cipher suite
    pub aead: HpkeAead,
    /// Sequence number
    pub sequence_number: u32,
    /// Maximum sequence number before context must be rekeyed
    pub max_sequence_number: u32,
    /// Context state
    pub state: HpkeContextState,
}

impl HpkeReceiverContext {
    /// Create a new receiver context
    pub fn new(
        shared_secret: Vec<u8>,
        exporter_secret: Vec<u8>,
        key: Vec<u8>,
        nonce: Vec<u8>,
        aead: HpkeAead,
    ) -> Self {
        Self {
            shared_secret,
            exporter_secret,
            key,
            nonce,
            aead,
            sequence_number: 0,
            max_sequence_number: u32::MAX - 1, // Leave room for overflow check
            state: HpkeContextState::Active,
        }
    }

    /// Check if the context can be used for decryption
    pub fn can_decrypt(&self) -> bool {
        self.state == HpkeContextState::Active && self.sequence_number < self.max_sequence_number
    }

    /// Increment sequence number with overflow protection
    pub fn increment_sequence(&mut self) -> Result<(), crate::error::HpkeError> {
        if self.sequence_number >= self.max_sequence_number {
            self.state = HpkeContextState::NeedsRekey;
            return Err(crate::error::HpkeError::CryptoError(
                "Sequence number overflow: context needs rekeying".into(),
            ));
        }
        self.sequence_number = self.sequence_number.wrapping_add(1);
        Ok(())
    }

    /// Close the context
    pub fn close(&mut self) {
        self.state = HpkeContextState::Closed;
    }
}
