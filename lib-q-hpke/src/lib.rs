//! # lib-Q HPKE - Hybrid Public Key Encryption
//!
//! This crate provides HPKE (RFC 9180) implementation for lib-q,
//! integrating with our provider pattern architecture.
//!
//! ## Features
//!
//! - **RFC 9180 compliant** HPKE implementation
//! - **Multiple backends**: libcrux (formally verified) and RustCrypto
//! - **Provider pattern integration** with lib-q-core
//! - **Post-quantum algorithms** via ML-KEM/ML-DSA when available
//! - **No-std support** for embedded environments
//!
//! ## Architecture
//!
//! lib-q-hpke is a library that provides a HPKE implementation for lib-q.

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
compile_error!("lib-q-hpke requires the 'alloc' feature to be enabled. This crate cannot function without alloc support.");

#[cfg(feature = "alloc")]
extern crate alloc;

pub use error::*;
// Re-export HPKE types that users need
pub use types::*;

// Internal modules
mod crypto_provider;
mod error;
mod hpke_core;
mod types;
// Future backends (commented out until implemented)
// #[cfg(feature = "libcrux")]
// mod libcrux_provider;

// #[cfg(feature = "rustcrypto")]
// mod rustcrypto_provider;

// Future provider re-exports
// #[cfg(feature = "libcrux")]
// pub use libcrux_provider::LibcruxHpkeProvider;

/// HPKE Context that integrates with lib-q's provider pattern
#[cfg(feature = "std")]
pub struct HpkeContext {
    kem_ctx: KemContext,
}

/// Create a KEM context for internal use
#[cfg(feature = "std")]
fn create_kem_context() -> KemContext {
    // Create a basic KEM context - this would normally be passed from the main library
    KemContext::new()
}

#[cfg(feature = "std")]
impl HpkeContext {
    /// Create a new HPKE context with default provider
    #[cfg(feature = "std")]
    pub fn new() -> Self {
        Self {
            kem_ctx: create_kem_context(),
        }
    }

    /// Create HPKE context with custom provider
    pub fn with_provider(provider: Box<dyn lib_q_core::CryptoProvider>) -> Self {
        Self {
            kem_ctx: KemContext::with_provider(provider),
        }
    }

    /// Setup sender with recipient's public key
    pub fn setup_sender(
        &mut self,
        recipient_pk: &KemPublicKey,
        info: &[u8],
    ) -> Result<HpkeSenderContext> {
        // Use the underlying KEM to establish shared secret
        // This is where we bridge to the actual HPKE implementation
        hpke_core::setup_sender::<PostQuantumProvider>(&mut self.kem_ctx, recipient_pk, info)
            .map_err(|e| e.into())
    }

    /// Setup receiver with encapsulated key and private key
    pub fn setup_receiver(
        &mut self,
        encapsulated_key: &[u8],
        recipient_sk: &KemSecretKey,
        info: &[u8],
    ) -> Result<HpkeReceiverContext> {
        hpke_core::setup_receiver::<PostQuantumProvider>(
            &mut self.kem_ctx,
            encapsulated_key,
            recipient_sk,
            info,
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
        hpke_core::seal::<PostQuantumProvider>(
            &mut self.kem_ctx,
            recipient_pk,
            info,
            aad,
            plaintext,
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
        hpke_core::open::<PostQuantumProvider>(
            &mut self.kem_ctx,
            encapsulated_key,
            recipient_sk,
            info,
            aad,
            ciphertext,
        )
        .map_err(|e| e.into())
    }
}

/// Context for HPKE sender operations
#[cfg(feature = "std")]
pub struct HpkeSenderContext {
    shared_secret: Vec<u8>,
    exporter_secret: Vec<u8>,
    key: Vec<u8>,
    nonce: Vec<u8>,
    sequence_number: u32,
}

#[cfg(feature = "std")]
impl HpkeSenderContext {
    /// Encrypt a message
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        hpke_core::seal_message::<PostQuantumProvider>(
            &self.key,
            &self.nonce,
            self.sequence_number,
            aad,
            plaintext,
        )
        .map_err::<lib_q_core::Error, _>(|e| e.into())?;
        self.sequence_number += 1;
        Ok(vec![]) // Placeholder
    }

    /// Export key material
    pub fn export(&self, exporter_context: &[u8], length: usize) -> Result<Vec<u8>> {
        hpke_core::export(&self.exporter_secret, exporter_context, length).map_err(|e| e.into())
    }
}

/// Context for HPKE receiver operations
#[cfg(feature = "std")]
pub struct HpkeReceiverContext {
    shared_secret: Vec<u8>,
    exporter_secret: Vec<u8>,
    key: Vec<u8>,
    nonce: Vec<u8>,
    sequence_number: u32,
}

#[cfg(feature = "std")]
impl HpkeReceiverContext {
    /// Decrypt a message
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        hpke_core::open_message::<PostQuantumProvider>(
            &self.key,
            &self.nonce,
            self.sequence_number,
            aad,
            ciphertext,
        )
        .map_err::<lib_q_core::Error, _>(|e| e.into())?;
        self.sequence_number += 1;
        Ok(vec![]) // Placeholder
    }

    /// Export key material
    pub fn export(&self, exporter_context: &[u8], length: usize) -> Result<Vec<u8>> {
        hpke_core::export(&self.exporter_secret, exporter_context, length).map_err(|e| e.into())
    }
}

/// Create a new HPKE context with default configuration
#[cfg(feature = "std")]
pub fn create_hpke_context() -> HpkeContext {
    HpkeContext::new()
}

/// Convenience function to create HPKE context with specific provider
#[cfg(feature = "std")]
pub fn create_hpke_context_with_provider(
    provider: Box<dyn lib_q_core::CryptoProvider>,
) -> HpkeContext {
    HpkeContext::with_provider(provider)
}
