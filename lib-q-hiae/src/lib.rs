//! # lib-Q HiAE (provisional)
//!
//! HiAE (draft-pham-cfrg-hiae-06): an AES-round AEAD with a 2048-bit state, fast on
//! both ARM and x86 at large message sizes. 256-bit key, 128-bit nonce, 128-bit tag.
//!
//! **Provisional.** HiAE is an individual Internet-Draft, and its security model
//! excludes repeated forgery attempts: published attacks that use decryption
//! queries recover the key with about 2^128 data (IACR ePrint 2025/1180). Do not
//! deploy it where an adversary can submit many forgeries under one key, which
//! includes any network data plane. See `SECURITY.md`. For a negotiated AES-round
//! AEAD use `lib-q-aegis` (AEGIS-256, RFC 10032).
//!
//! The AES round comes from `lib-q-intrinsics` (`aes_round`): hardware AES selected
//! at runtime, otherwise a portable constant-time bitsliced round.
//!
//! ```rust
//! use lib_q_hiae::Hiae;
//!
//! let key = [0x42u8; 32];
//! let nonce = [0x24u8; 16];
//! let mut buf = *b"payload";
//! let tag =
//!     Hiae::encrypt_in_place_detached(&key, &nonce, b"ad", &mut buf).unwrap();
//! Hiae::decrypt_in_place_detached(&key, &nonce, b"ad", &mut buf, &tag)
//!     .unwrap();
//! assert_eq!(&buf, b"payload");
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod dispatch;
mod hiae;
mod wrapper;

pub use hiae::{
    KEY_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
};
pub use lib_q_core::{
    Aead,
    AeadKey,
    Error,
    Nonce,
    Result,
};
// Re-export the lib-Q AEAD surface so downstream code can `use lib_q_hiae::Aead`.
#[cfg(feature = "alloc")]
pub use lib_q_core::{
    AeadDecryptSemantic,
    DecryptSemanticOutcome,
};
pub use lib_q_intrinsics::aes_round::hardware_aes_available;

/// Maximum plaintext and associated-data length in bytes (`2^61 - 1`).
pub const MAX_INPUT_LEN: u64 = (1u64 << 61) - 1;

wrapper::define_aead! {
    /// HiAE (draft-pham-cfrg-hiae-06). **Provisional**: individual Internet-Draft,
    /// and its security model excludes repeated forgery attempts. See `SECURITY.md`.
    Hiae,
    name: "HiAE",
    key: hiae::KEY_SIZE,
    nonce: hiae::NONCE_SIZE,
    tag: hiae::TAG_SIZE,
    seal: hiae::seal_dispatch,
    open: hiae::open_dispatch,
}

/// Internal hooks for cross-backend equivalence tests. Not a stable API.
#[doc(hidden)]
pub mod _internals {
    /// Whether a hardware backend is compiled in for this target.
    pub const fn simd_feature_wired() -> bool {
        lib_q_intrinsics::aes_round::hardware_backend_compiled()
    }

    /// Seal on the portable backend.
    pub fn hiae_seal_soft(key: &[u8; 32], nonce: &[u8; 16], ad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        crate::hiae::seal_soft(key, nonce, ad, buf)
    }

    /// Open on the portable backend.
    pub fn hiae_open_soft(key: &[u8; 32], nonce: &[u8; 16], ad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        crate::hiae::open_soft(key, nonce, ad, buf)
    }

    /// Seal on the dispatched backend.
    pub fn hiae_seal_dispatch(
        key: &[u8; 32],
        nonce: &[u8; 16],
        ad: &[u8],
        buf: &mut [u8],
    ) -> [u8; 16] {
        crate::hiae::seal_dispatch(key, nonce, ad, buf)
    }

    /// Open on the dispatched backend.
    pub fn hiae_open_dispatch(
        key: &[u8; 32],
        nonce: &[u8; 16],
        ad: &[u8],
        buf: &mut [u8],
    ) -> [u8; 16] {
        crate::hiae::open_dispatch(key, nonce, ad, buf)
    }
}
