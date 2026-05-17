//! AEAD trait definitions for HPKE.
//!
//! Implementations of [`Aead`] delegate to concrete algorithms (for example Saturnin via
//! `lib-q-saturnin`). **Cryptographic** cost during `open` should follow the underlying AEAD’s
//! contract (full symmetric decrypt before branching on authentication where applicable). The
//! HPKE `open` still returns [`Result`]: success versus authentication failure remains a
//! control-flow discriminant unless callers add outer timing mediation. For Saturnin,
//! [`crate::aead::saturnin::SaturninAeadImpl::decrypt_semantic`] exposes Layer B
//! ([`lib_q_core::DecryptSemanticOutcome`]); see workspace ADR `docs/adr/003-aead-decrypt-layers.md`.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::error::HpkeError;

/// Trait for AEAD implementations used inside HPKE.
///
/// `seal` / `open` map algorithm errors to [`HpkeError`]. Authentication failure is surfaced
/// as `Err` after the underlying AEAD has applied its own verification discipline; see
/// `lib-q-core`’s [`Aead`](lib_q_core::Aead) trait documentation for the cross-crate contract on
/// verification timing versus the `Result` API boundary.
pub trait Aead {
    /// Encrypt and authenticate plaintext
    fn seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, HpkeError>;

    /// Decrypt and verify ciphertext
    fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, HpkeError>;
}
