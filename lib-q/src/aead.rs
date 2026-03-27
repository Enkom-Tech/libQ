//! AEAD backed by `lib-q-aead` (SHAKE256-AEAD and feature-gated algorithms).
//!
//! Use [`context`] to obtain a configured [`AeadContext`].

#[cfg(feature = "alloc")]
pub use lib_q_core::{
    AeadContext,
    AeadKey,
    Algorithm,
    Nonce,
};

/// Returns an `AeadContext` wired to `lib-q-aead`.
#[cfg(feature = "alloc")]
pub fn context() -> AeadContext {
    AeadContext::with_aead_operations(Box::new(
        lib_q_aead::LibQAeadProvider::new()
            .expect("lib-q-aead LibQAeadProvider / SecurityValidator initialization"),
    ))
}
