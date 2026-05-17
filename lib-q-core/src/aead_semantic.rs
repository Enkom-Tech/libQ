//! Layer B semantic outcomes for AEAD decryption.
//!
//! See workspace ADR `docs/adr/003-aead-decrypt-layers.md` for Layer A/B/C definitions and
//! threat-model boundaries. This module is gated on the **`alloc`** feature.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use zeroize::Zeroizing;

use crate::Result;
use crate::traits::{
    Aead,
    AeadKey,
    Nonce,
};

/// Semantic result of an AEAD decrypt after parseable inputs were accepted.
///
/// This type is a closed `enum`: downstream crates cannot add variants. Use exhaustive
/// `match` (or `if let`) to branch; do not reduce verification to a secret-derived `bool`
/// without an explicit, reviewed threat model.
///
/// # Examples
///
/// ```rust
/// use lib_q_core::{
///     AeadDecryptSemantic,
///     DecryptSemanticOutcome,
///     AeadKey,
///     Nonce,
/// };
/// # fn demo<T: AeadDecryptSemantic>(aead: &T, key: &AeadKey, nonce: &Nonce, ct: &[u8]) -> lib_q_core::Result<()> {
/// match aead.decrypt_semantic(key, nonce, ct, None)? {
///     DecryptSemanticOutcome::Success(pt) => {
///         let _ = pt.len();
///     }
///     DecryptSemanticOutcome::AuthenticationFailed => {}
/// }
/// # Ok(())
/// # }
/// ```
#[derive(PartialEq, Eq)]
pub enum DecryptSemanticOutcome {
    /// Verified plaintext; buffer is zeroized on drop.
    Success(Zeroizing<Vec<u8>>),
    /// Integrity failure after the algorithm’s decrypt/verify schedule. No plaintext.
    AuthenticationFailed,
}

impl fmt::Debug for DecryptSemanticOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success(_) => f.write_str("Success(<redacted>)"),
            Self::AuthenticationFailed => f.write_str("AuthenticationFailed"),
        }
    }
}

/// AEAD implementations that expose a semantic decrypt API (Layer B).
///
/// Implementors must also implement [`Aead`]. Operational errors (invalid sizes, keys,
/// nonces, configuration) are returned as [`Err`]. Only post-decrypt authentication
/// failure is reported as [`DecryptSemanticOutcome::AuthenticationFailed`] inside [`Ok`].
///
/// This trait is separate from [`Aead`] so `dyn AeadOperations` and other object-safe
/// surfaces can remain `Result`-only ([`crate::api::AeadOperations`]) without forcing every
/// backend to expose semantic decrypt.
pub trait AeadDecryptSemantic: Aead {
    /// Decrypt and classify the outcome without overloading `Result` for auth failure.
    fn decrypt_semantic(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<DecryptSemanticOutcome>;
}
