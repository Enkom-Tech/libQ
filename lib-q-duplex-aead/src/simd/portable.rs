//! Portable duplex AEAD (scalar Keccak-f[1600]).

use crate::crypto::{
    decrypt as core_decrypt,
    encrypt as core_encrypt,
};
use crate::params::{
    KEY_BYTES,
    NONCE_BYTES,
};
use crate::simd::traits::DuplexAeadOps;

/// Portable implementation marker (zero-sized).
pub struct Portable;

impl DuplexAeadOps for Portable {
    fn encrypt(
        key: &[u8; KEY_BYTES],
        nonce: &[u8; NONCE_BYTES],
        ad: &[u8],
        pt: &[u8],
        out: &mut [u8],
    ) -> Result<(), crate::crypto::DuplexCryptoError> {
        core_encrypt(key, nonce, ad, pt, out)
    }

    fn decrypt(
        key: &[u8; KEY_BYTES],
        nonce: &[u8; NONCE_BYTES],
        ad: &[u8],
        ct_in: &[u8],
        out: &mut [u8],
    ) -> Result<(), crate::crypto::DuplexCryptoError> {
        core_decrypt(key, nonce, ad, ct_in, out)
    }
}
