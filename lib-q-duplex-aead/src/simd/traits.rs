//! SIMD dispatch trait for duplex AEAD (portable path; AVX2 delegates here).

use crate::params::{
    KEY_BYTES,
    NONCE_BYTES,
};

/// Encrypt/decrypt entry points for optional SIMD backends.
pub trait DuplexAeadOps {
    fn encrypt(
        key: &[u8; KEY_BYTES],
        nonce: &[u8; NONCE_BYTES],
        ad: &[u8],
        pt: &[u8],
        out: &mut [u8],
    ) -> Result<(), ()>;

    fn decrypt(
        key: &[u8; KEY_BYTES],
        nonce: &[u8; NONCE_BYTES],
        ad: &[u8],
        ct_in: &[u8],
        out: &mut [u8],
    ) -> Result<(), ()>;
}
