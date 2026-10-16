//! # lib-Q AEGIS-256
//!
//! AEGIS-256 (RFC 10032, Section 4): a high-throughput AEAD built on the AES round,
//! for protocols that negotiate it only when both peers have AES hardware (x86
//! AES-NI, ARMv8 AES). It complements, and does not replace, lib-Q's AES-free
//! default AEAD (Saturnin).
//!
//! | Type | Key | Nonce | Tag |
//! |------|-----|-------|-----|
//! | [`Aegis256`] | 32 | 32 | 32 |
//! | [`Aegis256Tag128`] | 32 | 32 | 16 |
//!
//! The 256-bit tag keeps forgery resistance above the 128-bit level even against
//! differential forgery attacks (RFC 10032, Section 9.3).
//!
//! ## Backends
//!
//! The AES round comes from `lib-q-intrinsics` (`aes_round`): a hardware round
//! selected at runtime when the `simd` features are on (the default) and the CPU
//! supports it, otherwise a portable **constant-time** bitsliced round. All
//! backends are bit-for-bit equivalent. [`hardware_aes_available`] reports which
//! one runs.
//!
//! ## APIs
//!
//! Each type implements [`lib_q_core::Aead`] and [`lib_q_core::AeadDecryptSemantic`]
//! (with `alloc`; ciphertext is `ct || tag`) and has allocation-free in-place
//! functions with a detached tag:
//!
//! ```rust
//! use lib_q_aegis::Aegis256;
//!
//! let key = [0x42u8; 32];
//! let nonce = [0x24u8; 32];
//! let mut buf = *b"datagram payload";
//! let tag =
//!     Aegis256::encrypt_in_place_detached(&key, &nonce, b"header", &mut buf)
//!         .unwrap();
//! Aegis256::decrypt_in_place_detached(
//!     &key, &nonce, b"header", &mut buf, &tag,
//! )
//! .unwrap();
//! assert_eq!(&buf, b"datagram payload");
//! ```
//!
//! Nonces MUST be unique per key. AEGIS-256 is not nonce-misuse resistant.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod aegis256;
mod dispatch;
mod wrapper;

pub use aegis256::{
    KEY_SIZE,
    NONCE_SIZE,
};
pub use lib_q_core::{
    Aead,
    AeadKey,
    Error,
    Nonce,
    Result,
};
// Re-export the lib-Q AEAD surface so downstream code can `use lib_q_aegis::Aead`.
#[cfg(feature = "alloc")]
pub use lib_q_core::{
    AeadDecryptSemantic,
    DecryptSemanticOutcome,
};
pub use lib_q_intrinsics::aes_round::hardware_aes_available;

/// Maximum plaintext and associated-data length in bytes (`2^61 - 1`).
pub const MAX_INPUT_LEN: u64 = (1u64 << 61) - 1;

wrapper::define_aead! {
    /// AEGIS-256 with a 256-bit tag (RFC 10032, Section 4). lib-Q's default AEGIS profile.
    Aegis256,
    name: "AEGIS-256",
    key: aegis256::KEY_SIZE,
    nonce: aegis256::NONCE_SIZE,
    tag: 32,
    seal: aegis256::seal_dispatch::<32>,
    open: aegis256::open_dispatch::<32>,
}

wrapper::define_aead! {
    /// AEGIS-256 with a 128-bit tag (RFC 10032, Section 4), for protocols that fix
    /// the 128-bit tag on the wire. Prefer [`Aegis256`] for new designs.
    Aegis256Tag128,
    name: "AEGIS-256 (128-bit tag)",
    key: aegis256::KEY_SIZE,
    nonce: aegis256::NONCE_SIZE,
    tag: 16,
    seal: aegis256::seal_dispatch::<16>,
    open: aegis256::open_dispatch::<16>,
}

/// Internal hooks for cross-backend equivalence tests. Not a stable API.
#[doc(hidden)]
pub mod _internals {
    /// Whether a hardware backend is compiled in for this target.
    pub const fn simd_feature_wired() -> bool {
        lib_q_intrinsics::aes_round::hardware_backend_compiled()
    }

    /// Seal on the portable backend; returns the `T`-byte tag (16 or 32).
    pub fn aegis256_seal_soft<const T: usize>(
        key: &[u8; 32],
        nonce: &[u8; 32],
        ad: &[u8],
        buf: &mut [u8],
    ) -> [u8; T] {
        crate::aegis256::seal_soft::<T>(key, nonce, ad, buf)
    }

    /// Open on the portable backend; returns the expected tag.
    pub fn aegis256_open_soft<const T: usize>(
        key: &[u8; 32],
        nonce: &[u8; 32],
        ad: &[u8],
        buf: &mut [u8],
    ) -> [u8; T] {
        crate::aegis256::open_soft::<T>(key, nonce, ad, buf)
    }

    /// Seal on the dispatched backend.
    pub fn aegis256_seal_dispatch<const T: usize>(
        key: &[u8; 32],
        nonce: &[u8; 32],
        ad: &[u8],
        buf: &mut [u8],
    ) -> [u8; T] {
        crate::aegis256::seal_dispatch::<T>(key, nonce, ad, buf)
    }

    /// Open on the dispatched backend.
    pub fn aegis256_open_dispatch<const T: usize>(
        key: &[u8; 32],
        nonce: &[u8; 32],
        ad: &[u8],
        buf: &mut [u8],
    ) -> [u8; T] {
        crate::aegis256::open_dispatch::<T>(key, nonce, ad, buf)
    }
}
