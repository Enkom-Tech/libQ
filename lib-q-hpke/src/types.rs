//! HPKE type definitions and algorithm specifications

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::fmt;

use zeroize::Zeroizing;

/// Sensitive byte buffer that is cleared on drop (KEM IKM, AEAD keys, exporter secret, etc.).
pub type SecretBytes = Zeroizing<Vec<u8>>;

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

/// How the PSK-related HPKE modes encode the encapsulated key on the wire.
///
/// This applies only to [`HpkeMode::Psk`] and [`HpkeMode::AuthPsk`]. Base and Auth modes always
/// use RFC 9180 layout regardless of this setting.
///
/// # Defaults and interoperability
///
/// The default is [`Self::Rfc9180`]: the encapsulated key matches RFC 9180 (KEM ciphertext only,
/// plus the sender-auth encapsulation in AuthPSK). Use this for interoperability with other
/// RFC 9180 implementations.
///
/// [`Self::LibQCommitmentSuffix`] is a libQ extension: it appends a KDF commitment so the receiver
/// can reject a wrong `(psk, psk_id)` or a mismatched primary KEM ciphertext before decapsulation
/// and key schedule. Both peers must select it explicitly; it is not RFC 9180–conformant on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HpkePskWireFormat {
    /// RFC 9180: no PSK commitment suffix on the encapsulated key.
    #[default]
    Rfc9180,
    /// libQ: append `labeled_extract(..., "psk_commitment", psk ‖ psk_id ‖ enc_kem)` after the
    /// KEM output (and after the auth encapsulation in AuthPSK), where `enc_kem` is the primary
    /// KEM ciphertext only (session-bound; not the sender-auth encapsulation).
    LibQCommitmentSuffix,
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

    /// Authentication tag length in bytes.
    ///
    /// For [`HpkeAead::Saturnin256`], this is **32** bytes, matching `lib-q-saturnin`
    /// `SaturninAead::tag_size` (full CTR-cascade AEAD).
    pub fn tag_len(self) -> usize {
        match self {
            Self::Saturnin256 => 32,
            Self::Shake256 => 16,
            Self::DuplexSpongeAead => 32,
            Self::Export => 0,
        }
    }
}

/// HPKE cipher suite specification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
pub struct HpkeSenderContext {
    /// Shared secret from KEM
    pub shared_secret: SecretBytes,
    /// Exporter secret
    pub exporter_secret: SecretBytes,
    /// AEAD encryption key
    pub key: SecretBytes,
    /// Base nonce
    pub nonce: SecretBytes,
    /// Cipher suite (KEM, KDF, AEAD) used for this session (RFC 9180 `suite_id` / export)
    pub cipher_suite: HpkeCipherSuite,
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

impl fmt::Debug for HpkeSenderContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HpkeSenderContext")
            .field("shared_secret", &"<redacted>")
            .field("exporter_secret", &"<redacted>")
            .field("key", &"<redacted>")
            .field("nonce", &"<redacted>")
            .field("cipher_suite", &self.cipher_suite)
            .field("aead", &self.aead)
            .field("encapsulated_key_len", &self.encapsulated_key.len())
            .field("sequence_number", &self.sequence_number)
            .field("max_sequence_number", &self.max_sequence_number)
            .field("state", &self.state)
            .finish()
    }
}

impl HpkeSenderContext {
    /// Create a new sender context
    pub fn new(
        shared_secret: SecretBytes,
        exporter_secret: SecretBytes,
        key: SecretBytes,
        nonce: SecretBytes,
        encapsulated_key: Vec<u8>,
        cipher_suite: HpkeCipherSuite,
        aead: HpkeAead,
    ) -> Self {
        Self {
            shared_secret,
            exporter_secret,
            key,
            nonce,
            cipher_suite,
            aead,
            encapsulated_key,
            sequence_number: 0,
            max_sequence_number: u32::MAX - 1, // Leave room for overflow check
            state: HpkeContextState::Active,
        }
    }

    /// Check if the context can be used for encryption
    pub fn can_encrypt(&self) -> bool {
        self.aead != HpkeAead::Export &&
            self.state == HpkeContextState::Active &&
            self.sequence_number < self.max_sequence_number
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
pub struct HpkeReceiverContext {
    /// Shared secret from KEM
    pub shared_secret: SecretBytes,
    /// Exporter secret
    pub exporter_secret: SecretBytes,
    /// AEAD decryption key
    pub key: SecretBytes,
    /// Base nonce
    pub nonce: SecretBytes,
    /// Cipher suite (KEM, KDF, AEAD) used for this session (RFC 9180 `suite_id` / export)
    pub cipher_suite: HpkeCipherSuite,
    /// AEAD algorithm from the negotiated cipher suite
    pub aead: HpkeAead,
    /// Sequence number
    pub sequence_number: u32,
    /// Maximum sequence number before context must be rekeyed
    pub max_sequence_number: u32,
    /// Context state
    pub state: HpkeContextState,
}

impl fmt::Debug for HpkeReceiverContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HpkeReceiverContext")
            .field("shared_secret", &"<redacted>")
            .field("exporter_secret", &"<redacted>")
            .field("key", &"<redacted>")
            .field("nonce", &"<redacted>")
            .field("cipher_suite", &self.cipher_suite)
            .field("aead", &self.aead)
            .field("sequence_number", &self.sequence_number)
            .field("max_sequence_number", &self.max_sequence_number)
            .field("state", &self.state)
            .finish()
    }
}

impl HpkeReceiverContext {
    /// Create a new receiver context
    pub fn new(
        shared_secret: SecretBytes,
        exporter_secret: SecretBytes,
        key: SecretBytes,
        nonce: SecretBytes,
        cipher_suite: HpkeCipherSuite,
        aead: HpkeAead,
    ) -> Self {
        Self {
            shared_secret,
            exporter_secret,
            key,
            nonce,
            cipher_suite,
            aead,
            sequence_number: 0,
            max_sequence_number: u32::MAX - 1, // Leave room for overflow check
            state: HpkeContextState::Active,
        }
    }

    /// Check if the context can be used for decryption
    pub fn can_decrypt(&self) -> bool {
        self.aead != HpkeAead::Export &&
            self.state == HpkeContextState::Active &&
            self.sequence_number < self.max_sequence_number
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

#[cfg(test)]
mod tests {
    use alloc::vec;

    use zeroize::Zeroizing;

    use super::*;
    use crate::error::HpkeError;

    #[test]
    fn hpke_psk_wire_format_default_is_rfc9180() {
        assert_eq!(HpkePskWireFormat::default(), HpkePskWireFormat::Rfc9180);
    }

    #[test]
    fn hpke_mode_roundtrip_and_invalid() {
        assert_eq!(HpkeMode::from_u8(0x00), Some(HpkeMode::Base));
        assert_eq!(HpkeMode::from_u8(0x01), Some(HpkeMode::Psk));
        assert_eq!(HpkeMode::from_u8(0x02), Some(HpkeMode::Auth));
        assert_eq!(HpkeMode::from_u8(0x03), Some(HpkeMode::AuthPsk));
        assert_eq!(HpkeMode::from_u8(0xFF), None);

        assert_eq!(HpkeMode::Base.as_u8(), 0x00);
        assert_eq!(HpkeMode::Psk.as_u8(), 0x01);
        assert_eq!(HpkeMode::Auth.as_u8(), 0x02);
        assert_eq!(HpkeMode::AuthPsk.as_u8(), 0x03);
    }

    #[test]
    fn kem_lengths_and_ids() {
        assert_eq!(HpkeKem::MlKem512.algorithm_id(), 0x0022);
        assert_eq!(HpkeKem::MlKem768.algorithm_id(), 0x0023);
        assert_eq!(HpkeKem::MlKem1024.algorithm_id(), 0x0024);

        assert_eq!(HpkeKem::MlKem512.shared_secret_len(), 32);
        assert_eq!(HpkeKem::MlKem768.shared_secret_len(), 32);
        assert_eq!(HpkeKem::MlKem1024.shared_secret_len(), 32);

        assert_eq!(HpkeKem::MlKem512.enc_len(), 768);
        assert_eq!(HpkeKem::MlKem768.enc_len(), 1088);
        assert_eq!(HpkeKem::MlKem1024.enc_len(), 1568);

        assert_eq!(HpkeKem::MlKem512.public_key_len(), 800);
        assert_eq!(HpkeKem::MlKem768.public_key_len(), 1184);
        assert_eq!(HpkeKem::MlKem1024.public_key_len(), 1568);

        assert_eq!(HpkeKem::MlKem512.secret_key_len(), 1632);
        assert_eq!(HpkeKem::MlKem768.secret_key_len(), 2400);
        assert_eq!(HpkeKem::MlKem1024.secret_key_len(), 3168);
    }

    #[test]
    fn kdf_lengths_and_ids() {
        assert_eq!(HpkeKdf::HkdfShake128.algorithm_id(), 0x0004);
        assert_eq!(HpkeKdf::HkdfShake256.algorithm_id(), 0x0005);
        assert_eq!(HpkeKdf::HkdfSha3_256.algorithm_id(), 0x0006);
        assert_eq!(HpkeKdf::HkdfSha3_512.algorithm_id(), 0x0007);

        assert_eq!(HpkeKdf::HkdfShake128.digest_len(), 32);
        assert_eq!(HpkeKdf::HkdfShake256.digest_len(), 64);
        assert_eq!(HpkeKdf::HkdfSha3_256.digest_len(), 32);
        assert_eq!(HpkeKdf::HkdfSha3_512.digest_len(), 64);

        assert_eq!(HpkeKdf::HkdfShake128.extract_len(), 16);
        assert_eq!(HpkeKdf::HkdfShake256.extract_len(), 32);
        assert_eq!(HpkeKdf::HkdfSha3_256.extract_len(), 32);
        assert_eq!(HpkeKdf::HkdfSha3_512.extract_len(), 64);
    }

    #[test]
    fn aead_lengths_and_ids() {
        assert_eq!(HpkeAead::Saturnin256.algorithm_id(), 0x0004);
        assert_eq!(HpkeAead::Shake256.algorithm_id(), 0x0005);
        assert_eq!(HpkeAead::DuplexSpongeAead.algorithm_id(), 0x0006);
        assert_eq!(HpkeAead::Export.algorithm_id(), 0xFFFF);

        assert_eq!(HpkeAead::Saturnin256.key_len(), 32);
        assert_eq!(HpkeAead::Shake256.key_len(), 32);
        assert_eq!(HpkeAead::DuplexSpongeAead.key_len(), 32);
        assert_eq!(HpkeAead::Export.key_len(), 0);

        assert_eq!(HpkeAead::Saturnin256.nonce_len(), 16);
        assert_eq!(HpkeAead::Shake256.nonce_len(), 16);
        assert_eq!(HpkeAead::DuplexSpongeAead.nonce_len(), 16);
        assert_eq!(HpkeAead::Export.nonce_len(), 0);

        assert_eq!(HpkeAead::Saturnin256.tag_len(), 32);
        assert_eq!(HpkeAead::Shake256.tag_len(), 16);
        assert_eq!(HpkeAead::DuplexSpongeAead.tag_len(), 32);
        assert_eq!(HpkeAead::Export.tag_len(), 0);
    }

    #[test]
    fn export_only_context_disallows_payload_ops() {
        let export_suite =
            HpkeCipherSuite::new(HpkeKem::MlKem512, HpkeKdf::HkdfShake256, HpkeAead::Export);
        let sender = HpkeSenderContext::new(
            Zeroizing::new(vec![1u8; 32]),
            Zeroizing::new(vec![2u8; 32]),
            Zeroizing::new(vec![]),
            Zeroizing::new(vec![]),
            vec![5u8; 768],
            export_suite,
            HpkeAead::Export,
        );
        assert!(!sender.can_encrypt());

        let receiver = HpkeReceiverContext::new(
            Zeroizing::new(vec![1u8; 32]),
            Zeroizing::new(vec![2u8; 32]),
            Zeroizing::new(vec![]),
            Zeroizing::new(vec![]),
            export_suite,
            HpkeAead::Export,
        );
        assert!(!receiver.can_decrypt());
    }

    #[test]
    fn cipher_suite_identifier_order() {
        let suite =
            HpkeCipherSuite::new(HpkeKem::MlKem768, HpkeKdf::HkdfSha3_512, HpkeAead::Export);
        let id = suite.identifier();
        assert_eq!(id, vec![0x00, 0x23, 0x00, 0x07, 0xFF, 0xFF]);
    }

    #[test]
    fn key_types_and_keypair_helpers() {
        let public = HpkePublicKey::from_bytes(vec![1, 2, 3]);
        assert_eq!(public.as_bytes(), &[1, 2, 3]);
        assert_eq!(public.clone().to_bytes(), vec![1, 2, 3]);

        let private = HpkePrivateKey::from_bytes(vec![4, 5, 6]);
        assert_eq!(private.as_bytes(), &[4, 5, 6]);
        assert_eq!(private.to_bytes(), vec![4, 5, 6]);

        let keypair = HpkeKeyPair::from_keys(public.clone(), private.clone());
        assert_eq!(keypair.public_key().as_bytes(), public.as_bytes());
        assert_eq!(keypair.private_key().as_bytes(), private.as_bytes());

        let (pub2, priv2) = keypair.into_keys();
        assert_eq!(pub2.as_bytes(), public.as_bytes());
        assert_eq!(priv2.as_bytes(), private.as_bytes());
    }

    #[test]
    fn sender_context_state_transitions() {
        let suite = HpkeCipherSuite::new(
            HpkeKem::MlKem512,
            HpkeKdf::HkdfShake256,
            HpkeAead::Saturnin256,
        );
        let mut sender = HpkeSenderContext::new(
            Zeroizing::new(vec![1; 32]),
            Zeroizing::new(vec![2; 32]),
            Zeroizing::new(vec![3; 32]),
            Zeroizing::new(vec![4; 16]),
            vec![5; 768],
            suite,
            HpkeAead::Saturnin256,
        );

        assert!(sender.can_encrypt());
        assert_eq!(sender.encapsulated_key(), &[5; 768]);
        assert!(sender.increment_sequence().is_ok());
        assert_eq!(sender.sequence_number, 1);

        sender.max_sequence_number = 1;
        let overflow = sender.increment_sequence();
        assert!(matches!(overflow, Err(HpkeError::CryptoError(_))));
        assert_eq!(sender.state, HpkeContextState::NeedsRekey);
        assert!(!sender.can_encrypt());

        sender.close();
        assert_eq!(sender.state, HpkeContextState::Closed);
        assert!(!sender.can_encrypt());
    }

    #[test]
    fn receiver_context_state_transitions() {
        let suite =
            HpkeCipherSuite::new(HpkeKem::MlKem512, HpkeKdf::HkdfShake256, HpkeAead::Shake256);
        let mut receiver = HpkeReceiverContext::new(
            Zeroizing::new(vec![1; 32]),
            Zeroizing::new(vec![2; 32]),
            Zeroizing::new(vec![3; 32]),
            Zeroizing::new(vec![4; 16]),
            suite,
            HpkeAead::Shake256,
        );

        assert!(receiver.can_decrypt());
        assert!(receiver.increment_sequence().is_ok());
        assert_eq!(receiver.sequence_number, 1);

        receiver.max_sequence_number = 1;
        let overflow = receiver.increment_sequence();
        assert!(matches!(overflow, Err(HpkeError::CryptoError(_))));
        assert_eq!(receiver.state, HpkeContextState::NeedsRekey);
        assert!(!receiver.can_decrypt());

        receiver.close();
        assert_eq!(receiver.state, HpkeContextState::Closed);
        assert!(!receiver.can_decrypt());
    }
}
