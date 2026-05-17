//! AVX2 build: single-session duplex remains scalar; delegates to portable.

#[cfg(all(target_arch = "x86_64", feature = "simd-avx2"))]
use crate::params::{
    KEY_BYTES,
    NONCE_BYTES,
};
#[cfg(all(target_arch = "x86_64", feature = "simd-avx2"))]
use crate::simd::{
    portable::Portable,
    traits::DuplexAeadOps,
};

/// AVX2 marker; duplex sequential mode uses the same scalar state machine as portable.
#[cfg(all(target_arch = "x86_64", feature = "simd-avx2"))]
pub struct Avx2;

#[cfg(all(target_arch = "x86_64", feature = "simd-avx2"))]
impl DuplexAeadOps for Avx2 {
    fn encrypt(
        key: &[u8; KEY_BYTES],
        nonce: &[u8; NONCE_BYTES],
        ad: &[u8],
        pt: &[u8],
        out: &mut [u8],
    ) -> Result<(), crate::crypto::DuplexCryptoError> {
        <Portable as DuplexAeadOps>::encrypt(key, nonce, ad, pt, out)
    }

    fn decrypt(
        key: &[u8; KEY_BYTES],
        nonce: &[u8; NONCE_BYTES],
        ad: &[u8],
        ct_in: &[u8],
        out: &mut [u8],
    ) -> Result<(), crate::crypto::DuplexCryptoError> {
        <Portable as DuplexAeadOps>::decrypt(key, nonce, ad, ct_in, out)
    }
}
