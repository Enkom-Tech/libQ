//! # lib-Q HPKE - Hybrid Public Key Encryption
//!
//! RFC 9180–aligned HPKE for lib-q using **post-quantum-only** primitives (ML-KEM for `HpkeKem::*`
//! in the default internal provider path; Saturnin / SHAKE256 / optional duplex-sponge AEAD; SHAKE
//! / SHA3 HKDF backends). There is no classical KEM in this stack.
//!
//! ## Features
//!
//! - **RFC 9180–aligned** modes, key schedule, and labeled KDF; default PSK / AuthPSK encapsulated-key
//!   wire format is RFC 9180; optional [`HpkePskWireFormat::LibQCommitmentSuffix`]
//!   when both peers call [`HpkeContext::set_psk_wire_format`]
//! - **Post-quantum algorithms**: ML-KEM, Saturnin, SHAKE/SHA3; optional **duplex-sponge AEAD** via
//!   Cargo feature `duplex-sponge-aead` (umbrella `lib-q` crate: `hpke-duplex-aead`)
//! - **Provider integration**: [`HpkeContext`] holds a `lib_q_core::KemContext`
//!   from [`HpkeContext::with_provider`] (`Box<dyn CryptoProvider>`);
//!   HPKE protocol steps use [`PostQuantumProvider`]
//!   implementing [`crate::providers::KemProvider`], [`crate::providers::KdfProvider`],
//!   and [`crate::providers::AeadProvider`] (see also [`crate::providers::HpkeCryptoProvider`])
//! - **Comprehensive tests** (RFC 9180 suites, modes, integration)
//! - **Security helpers** (validation, constant-time utilities, secure buffers)
//! - **No-std** with `alloc` (required by this crate)
//!
//! ## Supported algorithms
//!
//! ### Key encapsulation (KEM)
//! - **ML-KEM-512**, **ML-KEM-768**, **ML-KEM-1024** — wire sizes per [`HpkeKem`]
//!
//! ### Key derivation (KDF)
//! - **HKDF-SHAKE128**, **HKDF-SHAKE256**, **HKDF-SHA3-256**, **HKDF-SHA3-512** — lengths per [`HpkeKdf`]
//!
//! ### Authenticated encryption (AEAD)
//! - **Saturnin-256** — 32-byte key, 16-byte nonce, 32-byte tag
//! - **SHAKE256** AEAD — per [`HpkeAead::tag_len`]
//! - **Duplex-sponge** (feature `duplex-sponge-aead`) — 32-byte tag via `lib-q-aead`
//! - **Export-only** — exporter secret usage without message AEAD
//!
//! ## Quick start
//!
//! ```rust
//! use lib_q_hpke::HpkeContext;
//!
//! // Default `KemContext` inside (no custom CryptoProvider).
//! let hpke_ctx = HpkeContext::new();
//!
//! // For ML-KEM key generation and `seal`/`open`, supply a `CryptoProvider` (e.g. `libq::LibQCryptoProvider`)
//! // via `HpkeContext::with_provider` and use `lib_q_core::KemContext` with the same provider for keypairs.
//! ```
//!
//! ## Architecture
//!
//! - **[`HpkeContext`]**: cipher suite ([`HpkeCipherSuite`]),
//!   PSK wire policy ([`HpkePskWireFormat`]), single-shot and multi-shot APIs
//! - **[`HpkeSenderContext`] / [`HpkeReceiverContext`]**:
//!   multi-message encrypt/decrypt and export
//! - **`hpke_core`**: RFC 9180 schedule, setup, seal/open
//! - **[`PostQuantumProvider`]**: ML-KEM via `lib-q-kem`,
//!   HKDF via `lib-q-hash`, AEAD via `lib-q-aead`
//!
//! Public `HpkeContext` methods return `lib_q_core::Result`; see `From<HpkeError>` for `lib_q_core::Error`
//! in this crate’s `error` module. More detail: `docs/API_REFERENCE.md` in the crate tree and
//! `docs/hpke-architecture.md` at the workspace root.
//!
//! ## Security considerations
//!
//! - Post-quantum primitives for the stated HPKE path; validate keys and suite agreement between peers
//! - Authenticated encryption for application payloads (except export-only suite)
//! - Constant-time helpers and zeroization where implemented; see `security` module and `docs/SECURITY_CONSIDERATIONS.md`
//!
//! ## Performance
//!
//! Throughput and latency depend on suite, platform, and features. Profile under your target configuration.
//!
//! ## Testing
//!
//! Run `cargo test -p lib-q-hpke` (with the feature set you ship). Compliance and mode coverage live under
//! `tests/` (e.g. `rfc9180_compliance_tests`, PSK/Auth/AuthPSK suites).

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code, unused_must_use, unstable_features)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    missing_docs,
    unused_import_braces,
    unused_qualifications
)]

#[cfg(not(feature = "alloc"))]
compile_error!(
    "lib-q-hpke requires the 'alloc' feature to be enabled. This crate cannot function without alloc support."
);

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::{
    boxed::Box,
    sync::Arc,
    vec::Vec,
};

pub use error::*;
// Re-export HPKE types that users need
pub use types::*;

// Internal modules
pub mod error;
pub mod hpke_core;
pub mod hpke_session;
pub mod interop;
pub mod kdf;
pub mod providers;
pub mod types;

// New modular architecture
pub mod aead;
pub mod benchmarking;
pub mod kem;
pub mod protocol;
pub mod security;

pub use hpke_session::{
    HpkeReceiverContext,
    HpkeSenderContext,
};

#[cfg(feature = "wasm")]
mod wasm;

// Security tests module
#[cfg(test)]
mod security_tests;

// Imports used in conditionally compiled code
#[allow(unused_imports)]
use lib_q_core::{
    KemContext,
    KemPublicKey,
    KemSecretKey,
    Result,
};
#[allow(unused_imports)]
use providers::{
    post_quantum::PostQuantumProvider,
    traits::HpkeCryptoProvider,
};

use crate::security::{
    CryptoRng,
    EntropyCryptoRng,
};

/// HPKE Context that integrates with lib-q's provider pattern
///
/// The `HpkeContext` is the main interface for HPKE operations. It provides
/// both single-shot encryption/decryption and context-based operations for
/// encrypting multiple messages with the same key material.
///
/// Cryptography for encapsulation, KDF, and AEAD uses [`HpkeCryptoProvider`] (default:
/// [`PostQuantumProvider`]). [`HpkeContext::with_provider`] configures only the inner
/// [`KemContext`] for ML-KEM key validation and key-generation checks; use
/// [`HpkeContext::with_hpke_crypto`] to replace the HPKE crypto backend.
///
/// Randomness for setup and single-shot `seal` uses [`crate::security::EntropyCryptoRng`] by default
/// (OS-backed entropy via `lib-q-random`). Override with [`HpkeContext::set_rng`] for tests.
pub struct HpkeContext {
    kem_ctx: KemContext,
    cipher_suite: HpkeCipherSuite,
    /// PSK / AuthPSK encapsulated-key wire format (ignored for Base and Auth).
    psk_wire_format: HpkePskWireFormat,
    hpke_crypto: Arc<dyn HpkeCryptoProvider + Send + Sync>,
    rng: Box<dyn CryptoRng + Send>,
}

/// Create a KEM context for internal use
fn create_kem_context() -> KemContext {
    // Create a basic KEM context - this would normally be passed from the main library
    KemContext::new()
}

impl HpkeContext {
    /// Create a new HPKE context with default [`PostQuantumProvider`] and OS-backed RNG.
    pub fn new() -> Self {
        let hpke_crypto: Arc<dyn HpkeCryptoProvider + Send + Sync> =
            Arc::new(PostQuantumProvider::new());
        Self {
            kem_ctx: create_kem_context(),
            cipher_suite: HpkeCipherSuite::new(
                HpkeKem::MlKem512,
                HpkeKdf::HkdfShake256,
                HpkeAead::Saturnin256,
            ),
            psk_wire_format: HpkePskWireFormat::default(),
            hpke_crypto,
            rng: Box::new(EntropyCryptoRng),
        }
    }

    /// Build an HPKE context with a custom [`HpkeCryptoProvider`] (for example tests or an alternate PQ backend).
    pub fn with_hpke_crypto(hpke_crypto: Arc<dyn HpkeCryptoProvider + Send + Sync>) -> Self {
        Self {
            kem_ctx: create_kem_context(),
            cipher_suite: HpkeCipherSuite::new(
                HpkeKem::MlKem512,
                HpkeKdf::HkdfShake256,
                HpkeAead::Saturnin256,
            ),
            psk_wire_format: HpkePskWireFormat::default(),
            hpke_crypto,
            rng: Box::new(EntropyCryptoRng),
        }
    }

    /// Configure the inner [`KemContext`] with a [`lib_q_core::CryptoProvider`] for key validation and ML-KEM keygen.
    ///
    /// HPKE encapsulation/KDF/AEAD still use [`Self::hpke_crypto`] (default [`PostQuantumProvider`]).
    pub fn with_provider(provider: Box<dyn lib_q_core::CryptoProvider>) -> Self {
        let hpke_crypto: Arc<dyn HpkeCryptoProvider + Send + Sync> =
            Arc::new(PostQuantumProvider::new());
        Self {
            kem_ctx: KemContext::with_provider(provider),
            cipher_suite: HpkeCipherSuite::new(
                HpkeKem::MlKem512,
                HpkeKdf::HkdfShake256,
                HpkeAead::Saturnin256,
            ),
            psk_wire_format: HpkePskWireFormat::default(),
            hpke_crypto,
            rng: Box::new(EntropyCryptoRng),
        }
    }

    /// Full wiring: custom [`KemContext`] provider and custom HPKE crypto backend.
    pub fn with_kem_and_hpke_crypto(
        kem_provider: Box<dyn lib_q_core::CryptoProvider>,
        hpke_crypto: Arc<dyn HpkeCryptoProvider + Send + Sync>,
    ) -> Self {
        Self {
            kem_ctx: KemContext::with_provider(kem_provider),
            cipher_suite: HpkeCipherSuite::new(
                HpkeKem::MlKem512,
                HpkeKdf::HkdfShake256,
                HpkeAead::Saturnin256,
            ),
            psk_wire_format: HpkePskWireFormat::default(),
            hpke_crypto,
            rng: Box::new(EntropyCryptoRng),
        }
    }

    /// Replace the HPKE crypto backend (multi-shot `seal`/`open` on derived contexts use the snapshot from setup).
    pub fn set_hpke_crypto(&mut self, hpke_crypto: Arc<dyn HpkeCryptoProvider + Send + Sync>) {
        self.hpke_crypto = hpke_crypto;
    }

    /// Active HPKE crypto provider reference.
    pub fn hpke_crypto(&self) -> &(dyn HpkeCryptoProvider + Send + Sync) {
        self.hpke_crypto.as_ref()
    }

    /// Replace the RNG used for encapsulation and single-shot `seal` (tests may use [`crate::security::prng::SimpleRng`]).
    pub fn set_rng(&mut self, rng: Box<dyn CryptoRng + Send>) {
        self.rng = rng;
    }
}

impl Default for HpkeContext {
    fn default() -> Self {
        Self::new()
    }
}

impl HpkeContext {
    /// Active cipher suite (KEM, KDF, AEAD) used for subsequent HPKE operations.
    pub fn cipher_suite(&self) -> &HpkeCipherSuite {
        &self.cipher_suite
    }

    /// Set the cipher suite before `setup_sender` / `seal` / `open`.
    pub fn set_cipher_suite(&mut self, cipher_suite: HpkeCipherSuite) {
        self.cipher_suite = cipher_suite;
    }

    /// PSK-mode encapsulated key wire format used for subsequent PSK / AuthPSK operations.
    #[must_use]
    pub fn psk_wire_format(&self) -> HpkePskWireFormat {
        self.psk_wire_format
    }

    /// Set how PSK and AuthPSK modes encode the encapsulated key on the wire.
    ///
    /// **Default:** [`HpkePskWireFormat::Rfc9180`] (RFC 9180 on-the-wire layout for PSK / AuthPSK).
    ///
    /// **libQ extension:** set [`HpkePskWireFormat::LibQCommitmentSuffix`] when both peers support
    /// it to get early rejection of PSK / KEM mismatch before decapsulation. This is not RFC 9180
    /// wire format; do not use it when interoperating with a strict RFC 9180 implementation.
    pub fn set_psk_wire_format(&mut self, format: HpkePskWireFormat) {
        self.psk_wire_format = format;
    }

    /// Setup sender with recipient's public key
    pub fn setup_sender(
        &mut self,
        recipient_pk: &KemPublicKey,
        info: &[u8],
    ) -> Result<HpkeSenderContext> {
        hpke_core::setup_sender(
            &mut self.kem_ctx,
            recipient_pk,
            info,
            &self.cipher_suite,
            self.hpke_crypto.as_ref(),
            self.rng.as_mut(),
            self.hpke_crypto.clone(),
        )
        .map_err(|e| e.into())
    }

    /// Setup receiver with encapsulated key and private key
    pub fn setup_receiver(
        &mut self,
        encapsulated_key: &[u8],
        recipient_sk: &KemSecretKey,
        info: &[u8],
    ) -> Result<HpkeReceiverContext> {
        hpke_core::setup_receiver(
            &mut self.kem_ctx,
            encapsulated_key,
            recipient_sk,
            info,
            &self.cipher_suite,
            self.hpke_crypto.as_ref(),
            self.hpke_crypto.clone(),
        )
        .map_err(|e| e.into())
    }

    /// Setup sender with PSK mode.
    ///
    /// Uses [`HpkeContext::psk_wire_format`]. With the default ([`HpkePskWireFormat::Rfc9180`]),
    /// [`HpkeSenderContext::encapsulated_key`] is exactly the KEM ciphertext (RFC 9180). With
    /// [`HpkePskWireFormat::LibQCommitmentSuffix`], the same ciphertext is followed by a PSK
    /// commitment (`hpke_core::psk_commitment_len` bytes); set via [`Self::set_psk_wire_format`].
    pub fn setup_sender_psk(
        &mut self,
        recipient_pk: &KemPublicKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<HpkeSenderContext> {
        hpke_core::setup_sender_with_mode(
            &mut self.kem_ctx,
            recipient_pk,
            info,
            &self.cipher_suite,
            self.hpke_crypto.as_ref(),
            self.rng.as_mut(),
            HpkeMode::Psk,
            Some(psk),
            Some(psk_id),
            None,
            None,
            self.psk_wire_format,
            self.hpke_crypto.clone(),
        )
        .map_err(|e| e.into())
    }

    /// Setup sender with Auth mode
    pub fn setup_sender_auth(
        &mut self,
        recipient_pk: &KemPublicKey,
        info: &[u8],
        sender_sk: &KemSecretKey,
        sender_pk: &KemPublicKey,
    ) -> Result<HpkeSenderContext> {
        hpke_core::setup_sender_with_mode(
            &mut self.kem_ctx,
            recipient_pk,
            info,
            &self.cipher_suite,
            self.hpke_crypto.as_ref(),
            self.rng.as_mut(),
            HpkeMode::Auth,
            None,
            None,
            Some(sender_sk),
            Some(sender_pk),
            self.psk_wire_format,
            self.hpke_crypto.clone(),
        )
        .map_err(|e| e.into())
    }

    /// Setup sender with AuthPSK mode.
    ///
    /// Wire layout follows [`HpkeContext::psk_wire_format`]: either RFC 9180 (KEM ‖ auth) or the
    /// same with a libQ PSK commitment suffix when using [`HpkePskWireFormat::LibQCommitmentSuffix`].
    pub fn setup_sender_auth_psk(
        &mut self,
        recipient_pk: &KemPublicKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        sender_sk: &KemSecretKey,
        sender_pk: &KemPublicKey,
    ) -> Result<HpkeSenderContext> {
        hpke_core::setup_sender_with_mode(
            &mut self.kem_ctx,
            recipient_pk,
            info,
            &self.cipher_suite,
            self.hpke_crypto.as_ref(),
            self.rng.as_mut(),
            HpkeMode::AuthPsk,
            Some(psk),
            Some(psk_id),
            Some(sender_sk),
            Some(sender_pk),
            self.psk_wire_format,
            self.hpke_crypto.clone(),
        )
        .map_err(|e| e.into())
    }

    /// Setup receiver with PSK mode.
    ///
    /// `encapsulated_key` must match the sender's [`HpkeContext::psk_wire_format`]. With the
    /// default [`HpkePskWireFormat::Rfc9180`], agreement is implicit (typically AEAD failure on
    /// mismatch). With [`HpkePskWireFormat::LibQCommitmentSuffix`], a wrong PSK, PSK ID, or primary
    /// KEM ciphertext relative to the commitment fails with [`HpkeError::InconsistentPsk`] before
    /// key schedule.
    pub fn setup_receiver_psk(
        &mut self,
        encapsulated_key: &[u8],
        recipient_sk: &KemSecretKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<HpkeReceiverContext> {
        hpke_core::setup_receiver_with_mode(
            &mut self.kem_ctx,
            encapsulated_key,
            recipient_sk,
            info,
            &self.cipher_suite,
            self.hpke_crypto.as_ref(),
            HpkeMode::Psk,
            Some(psk),
            Some(psk_id),
            None,
            self.psk_wire_format,
            self.hpke_crypto.clone(),
        )
        .map_err(|e| e.into())
    }

    /// Setup receiver with Auth mode
    pub fn setup_receiver_auth(
        &mut self,
        encapsulated_key: &[u8],
        recipient_sk: &KemSecretKey,
        info: &[u8],
        sender_pk: &KemPublicKey,
    ) -> Result<HpkeReceiverContext> {
        hpke_core::setup_receiver_with_mode(
            &mut self.kem_ctx,
            encapsulated_key,
            recipient_sk,
            info,
            &self.cipher_suite,
            self.hpke_crypto.as_ref(),
            HpkeMode::Auth,
            None,
            None,
            Some(sender_pk),
            self.psk_wire_format,
            self.hpke_crypto.clone(),
        )
        .map_err(|e| e.into())
    }

    /// Setup receiver with AuthPSK mode.
    ///
    /// `encapsulated_key` layout must match [`HpkeContext::psk_wire_format`] on both peers.
    pub fn setup_receiver_auth_psk(
        &mut self,
        encapsulated_key: &[u8],
        recipient_sk: &KemSecretKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        sender_pk: &KemPublicKey,
    ) -> Result<HpkeReceiverContext> {
        hpke_core::setup_receiver_with_mode(
            &mut self.kem_ctx,
            encapsulated_key,
            recipient_sk,
            info,
            &self.cipher_suite,
            self.hpke_crypto.as_ref(),
            HpkeMode::AuthPsk,
            Some(psk),
            Some(psk_id),
            Some(sender_pk),
            self.psk_wire_format,
            self.hpke_crypto.clone(),
        )
        .map_err(|e| e.into())
    }

    /// Single-shot encryption (seal)
    pub fn seal(
        &mut self,
        recipient_pk: &KemPublicKey,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        hpke_core::seal(
            &mut self.kem_ctx,
            recipient_pk,
            info,
            aad,
            plaintext,
            &self.cipher_suite,
            self.hpke_crypto.as_ref(),
            self.rng.as_mut(),
        )
        .map_err(|e| e.into())
    }

    /// Single-shot decryption (open)
    pub fn open(
        &mut self,
        encapsulated_key: &[u8],
        recipient_sk: &KemSecretKey,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        hpke_core::open(
            &mut self.kem_ctx,
            encapsulated_key,
            recipient_sk,
            info,
            aad,
            ciphertext,
            &self.cipher_suite,
            self.hpke_crypto.as_ref(),
            self.hpke_crypto.clone(),
        )
        .map_err(|e| e.into())
    }
}

/// Context for HPKE sender operations
impl HpkeSenderContext {
    /// Encrypt a message
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        // Check if context can be used for encryption
        if !self.can_encrypt() {
            if self.sequence_number >= self.max_sequence_number {
                self.state = HpkeContextState::NeedsRekey;
            }
            return Err(lib_q_core::Error::InternalError {
                operation: "Context validation".into(),
                details: "Context cannot be used for encryption".into(),
            });
        }

        let ciphertext = hpke_core::seal_message(
            self.aead,
            self.key.as_slice(),
            self.nonce.as_slice(),
            self.sequence_number,
            aad,
            plaintext,
            self.hpke_crypto.as_ref(),
        )
        .map_err(lib_q_core::Error::from)?;

        // Increment sequence number with overflow protection
        self.increment_sequence().map_err(lib_q_core::Error::from)?;

        Ok(ciphertext)
    }

    /// Export key material
    pub fn export(&self, exporter_context: &[u8], length: usize) -> Result<Vec<u8>> {
        hpke_core::export(
            self.exporter_secret.as_slice(),
            exporter_context,
            length,
            &self.cipher_suite,
            self.hpke_crypto.as_ref(),
        )
        .map_err(|e| e.into())
    }
}

/// Context for HPKE receiver operations
impl HpkeReceiverContext {
    /// Decrypt a message
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Check if context can be used for decryption
        if !self.can_decrypt() {
            return Err(lib_q_core::Error::InternalError {
                operation: "Context validation".into(),
                details: "Context cannot be used for decryption".into(),
            });
        }

        let plaintext = hpke_core::open_message(
            self.aead,
            self.key.as_slice(),
            self.nonce.as_slice(),
            self.sequence_number,
            aad,
            ciphertext,
            self.hpke_crypto.as_ref(),
        )
        .map_err(lib_q_core::Error::from)?;

        // Increment sequence number with overflow protection
        self.increment_sequence().map_err(lib_q_core::Error::from)?;

        Ok(plaintext)
    }

    /// Export key material
    pub fn export(&self, exporter_context: &[u8], length: usize) -> Result<Vec<u8>> {
        hpke_core::export(
            self.exporter_secret.as_slice(),
            exporter_context,
            length,
            &self.cipher_suite,
            self.hpke_crypto.as_ref(),
        )
        .map_err(|e| e.into())
    }
}

/// Create a new HPKE context with default configuration
pub fn create_hpke_context() -> HpkeContext {
    HpkeContext::new()
}

/// Convenience function to create HPKE context with specific provider
pub fn create_hpke_context_with_provider(
    provider: Box<dyn lib_q_core::CryptoProvider>,
) -> HpkeContext {
    HpkeContext::with_provider(provider)
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::sync::Arc;
    use alloc::vec;

    use super::*;

    fn dummy_ml_kem_512_keys() -> (KemPublicKey, KemSecretKey) {
        (
            KemPublicKey::new(vec![1u8; HpkeKem::MlKem512.public_key_len()]),
            KemSecretKey::new(vec![2u8; HpkeKem::MlKem512.secret_key_len()]),
        )
    }

    #[test]
    fn context_constructors_and_cipher_suite_accessors() {
        let mut ctx = HpkeContext::new();
        assert_eq!(ctx.cipher_suite().kem, HpkeKem::MlKem512);
        assert_eq!(ctx.cipher_suite().kdf, HpkeKdf::HkdfShake256);
        assert_eq!(ctx.cipher_suite().aead, HpkeAead::Saturnin256);

        let suite =
            HpkeCipherSuite::new(HpkeKem::MlKem768, HpkeKdf::HkdfSha3_256, HpkeAead::Shake256);
        ctx.set_cipher_suite(suite);
        assert_eq!(ctx.cipher_suite().kem, suite.kem);
        assert_eq!(ctx.cipher_suite().kdf, suite.kdf);
        assert_eq!(ctx.cipher_suite().aead, suite.aead);

        let _default_ctx = HpkeContext::default();
        let _created_ctx = create_hpke_context();
    }

    #[test]
    fn hpke_setup_and_single_shot_paths_are_exercised() {
        let (recipient_pk, recipient_sk) = dummy_ml_kem_512_keys();
        let (sender_pk, sender_sk) = dummy_ml_kem_512_keys();

        let mut ctx = HpkeContext::new();
        let info = b"test-info";
        let psk = b"test-psk";
        let psk_id = b"test-psk-id";
        let aad = b"aad";
        let plaintext = b"plaintext";
        let fake_enc = vec![0u8; HpkeKem::MlKem512.enc_len()];

        let _ = ctx.setup_sender(&recipient_pk, info);
        let _ = ctx.setup_receiver(&fake_enc, &recipient_sk, info);

        let _ = ctx.setup_sender_psk(&recipient_pk, info, psk, psk_id);
        let _ = ctx.setup_receiver_psk(&fake_enc, &recipient_sk, info, psk, psk_id);

        let _ = ctx.setup_sender_auth(&recipient_pk, info, &sender_sk, &sender_pk);
        let _ = ctx.setup_receiver_auth(&fake_enc, &recipient_sk, info, &sender_pk);

        let _ = ctx.setup_sender_auth_psk(&recipient_pk, info, psk, psk_id, &sender_sk, &sender_pk);
        let _ =
            ctx.setup_receiver_auth_psk(&fake_enc, &recipient_sk, info, psk, psk_id, &sender_pk);

        let _ = ctx.seal(&recipient_pk, info, aad, plaintext);
        let _ = ctx.open(&fake_enc, &recipient_sk, info, aad, b"ciphertext");
    }

    #[test]
    fn sender_and_receiver_context_guards_are_exercised() {
        let hpke_crypto: Arc<dyn HpkeCryptoProvider + Send + Sync> =
            Arc::new(PostQuantumProvider::new());
        let mut sender = HpkeSenderContext::new(
            vec![3u8; 32].into(),
            vec![4u8; 32].into(),
            vec![5u8; 32].into(),
            vec![6u8; 16].into(),
            vec![7u8; HpkeKem::MlKem512.enc_len()],
            HpkeCipherSuite::new(
                HpkeKem::MlKem512,
                HpkeKdf::HkdfShake256,
                HpkeAead::Saturnin256,
            ),
            HpkeAead::Saturnin256,
            hpke_crypto.clone(),
        );
        sender.state = HpkeContextState::Closed;
        let sender_err = sender.seal(b"aad", b"msg").unwrap_err().to_string();
        assert!(sender_err.contains("Context cannot be used for encryption"));

        let mut receiver = HpkeReceiverContext::new(
            vec![8u8; 32].into(),
            vec![9u8; 32].into(),
            vec![10u8; 32].into(),
            vec![11u8; 16].into(),
            HpkeCipherSuite::new(
                HpkeKem::MlKem512,
                HpkeKdf::HkdfShake256,
                HpkeAead::Saturnin256,
            ),
            HpkeAead::Saturnin256,
            hpke_crypto,
        );
        receiver.state = HpkeContextState::Closed;
        let receiver_err = receiver.open(b"aad", b"ct").unwrap_err().to_string();
        assert!(receiver_err.contains("Context cannot be used for decryption"));
    }
}
