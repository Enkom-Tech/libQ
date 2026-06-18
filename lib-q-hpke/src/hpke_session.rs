//! HPKE sender/receiver session state (post-setup).
//!
//! Lives in its own module so it can hold an [`alloc::sync::Arc`] to [`crate::providers::traits::HpkeCryptoProvider`]
//! without a `types` ↔ `providers` dependency cycle.

#[cfg(feature = "alloc")]
use alloc::sync::Arc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::fmt;

use crate::providers::traits::HpkeCryptoProvider;
use crate::types::{
    HpkeAead,
    HpkeCipherSuite,
    HpkeContextState,
    SecretBytes,
};

/// HPKE sender context (no_std + alloc).
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
    /// Cryptographic backend for multi-message seal and export
    pub(crate) hpke_crypto: Arc<dyn HpkeCryptoProvider + Send + Sync>,
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
            .field("hpke_crypto", &self.hpke_crypto.name())
            .finish()
    }
}

impl HpkeSenderContext {
    /// Create a new sender context with the HPKE crypto backend used for `seal` / `export`.
    #[allow(clippy::too_many_arguments)] // One-shot setup: mirrors HPKE key schedule / encapsulation outputs.
    pub fn new(
        shared_secret: SecretBytes,
        exporter_secret: SecretBytes,
        key: SecretBytes,
        nonce: SecretBytes,
        encapsulated_key: Vec<u8>,
        cipher_suite: HpkeCipherSuite,
        aead: HpkeAead,
        hpke_crypto: Arc<dyn HpkeCryptoProvider + Send + Sync>,
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
            max_sequence_number: u32::MAX - 1,
            state: HpkeContextState::Active,
            hpke_crypto,
        }
    }

    /// HPKE crypto provider used for this session.
    pub fn hpke_crypto(&self) -> &(dyn HpkeCryptoProvider + Send + Sync) {
        self.hpke_crypto.as_ref()
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

/// HPKE receiver context (no_std + alloc).
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
    /// Cryptographic backend for multi-message open and export
    pub(crate) hpke_crypto: Arc<dyn HpkeCryptoProvider + Send + Sync>,
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
            .field("hpke_crypto", &self.hpke_crypto.name())
            .finish()
    }
}

impl HpkeReceiverContext {
    /// Create a new receiver context with the HPKE crypto backend used for `open` / `export`.
    pub fn new(
        shared_secret: SecretBytes,
        exporter_secret: SecretBytes,
        key: SecretBytes,
        nonce: SecretBytes,
        cipher_suite: HpkeCipherSuite,
        aead: HpkeAead,
        hpke_crypto: Arc<dyn HpkeCryptoProvider + Send + Sync>,
    ) -> Self {
        Self {
            shared_secret,
            exporter_secret,
            key,
            nonce,
            cipher_suite,
            aead,
            sequence_number: 0,
            max_sequence_number: u32::MAX - 1,
            state: HpkeContextState::Active,
            hpke_crypto,
        }
    }

    /// HPKE crypto provider used for this session.
    pub fn hpke_crypto(&self) -> &(dyn HpkeCryptoProvider + Send + Sync) {
        self.hpke_crypto.as_ref()
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
    use alloc::sync::Arc;
    use alloc::vec;

    use zeroize::Zeroizing;

    use super::{
        HpkeReceiverContext,
        HpkeSenderContext,
    };
    use crate::error::HpkeError;
    use crate::providers::post_quantum::PostQuantumProvider;
    use crate::providers::traits::HpkeCryptoProvider;
    use crate::types::{
        HpkeAead,
        HpkeCipherSuite,
        HpkeContextState,
        HpkeKdf,
        HpkeKem,
    };

    #[test]
    fn export_only_context_disallows_payload_ops() {
        let export_suite =
            HpkeCipherSuite::new(HpkeKem::MlKem512, HpkeKdf::HkdfShake256, HpkeAead::Export);
        let hpke_crypto: Arc<dyn HpkeCryptoProvider + Send + Sync> =
            Arc::new(PostQuantumProvider::new());
        let sender = HpkeSenderContext::new(
            Zeroizing::new(vec![1u8; 32]),
            Zeroizing::new(vec![2u8; 32]),
            Zeroizing::new(vec![]),
            Zeroizing::new(vec![]),
            vec![5u8; 768],
            export_suite,
            HpkeAead::Export,
            hpke_crypto.clone(),
        );
        assert!(!sender.can_encrypt());

        let receiver = HpkeReceiverContext::new(
            Zeroizing::new(vec![1u8; 32]),
            Zeroizing::new(vec![2u8; 32]),
            Zeroizing::new(vec![]),
            Zeroizing::new(vec![]),
            export_suite,
            HpkeAead::Export,
            hpke_crypto,
        );
        assert!(!receiver.can_decrypt());
    }

    #[test]
    fn sender_context_state_transitions() {
        let suite = HpkeCipherSuite::new(
            HpkeKem::MlKem512,
            HpkeKdf::HkdfShake256,
            HpkeAead::Saturnin256,
        );
        let hpke_crypto: Arc<dyn HpkeCryptoProvider + Send + Sync> =
            Arc::new(PostQuantumProvider::new());
        let mut sender = HpkeSenderContext::new(
            Zeroizing::new(vec![1; 32]),
            Zeroizing::new(vec![2; 32]),
            Zeroizing::new(vec![3; 32]),
            Zeroizing::new(vec![4; 16]),
            vec![5; 768],
            suite,
            HpkeAead::Saturnin256,
            hpke_crypto,
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
        let hpke_crypto: Arc<dyn HpkeCryptoProvider + Send + Sync> =
            Arc::new(PostQuantumProvider::new());
        let mut receiver = HpkeReceiverContext::new(
            Zeroizing::new(vec![1; 32]),
            Zeroizing::new(vec![2; 32]),
            Zeroizing::new(vec![3; 32]),
            Zeroizing::new(vec![4; 16]),
            suite,
            HpkeAead::Shake256,
            hpke_crypto,
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
