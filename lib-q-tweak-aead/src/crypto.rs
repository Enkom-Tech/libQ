//! Tweakable CTR AEAD encrypt/decrypt.

use core::fmt;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::params::{
    KEY_BYTES,
    NONCE_BYTES,
    PLEN,
    TAG_BYTES,
};
use crate::simd::portable::Portable;
use crate::simd::traits::TweakAeadStreamOps;
use crate::sponge::{
    absorb_all,
    first_32_from_state,
};

/// Encrypt/decrypt failed: buffer too small, length overflow, or (decrypt) authentication failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TweakCryptoError;

impl fmt::Debug for TweakCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TweakCryptoError")
    }
}

/// Encrypt: `out` is `pt.len() + TAG_BYTES`.
pub fn encrypt(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    ad: &[u8],
    pt: &[u8],
    out: &mut [u8],
) -> Result<(), TweakCryptoError> {
    let total = pt.len().checked_add(TAG_BYTES).ok_or(TweakCryptoError)?;
    if out.len() < total {
        return Err(TweakCryptoError);
    }
    let ct = &mut out[..pt.len()];
    xor_body(key, nonce, pt, ct);
    let tag = compute_tag(key, nonce, ad, ct);
    out[pt.len()..pt.len() + TAG_BYTES].copy_from_slice(&tag);
    Ok(())
}

fn xor_body(key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES], pt: &[u8], ct: &mut [u8]) {
    #[cfg(all(target_arch = "x86_64", feature = "simd-avx2"))]
    {
        if crate::simd::runtime::has_avx2() {
            unsafe {
                crate::simd::avx2::xor_keystream_avx2(key, nonce, pt, ct);
            }
            return;
        }
    }
    <Portable as TweakAeadStreamOps>::xor_keystream(key, nonce, pt, ct);
}

/// Decrypt `ct_in` (includes tag) in constant time.
///
/// On success, writes plaintext to `out[..body_len]`. On authentication failure, zeroes
/// `out[..body_len]` and returns `Err`. Decryption always executes regardless of tag validity.
pub fn decrypt(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    ad: &[u8],
    ct_in: &[u8],
    out: &mut [u8],
) -> Result<(), TweakCryptoError> {
    if ct_in.len() < TAG_BYTES {
        return Err(TweakCryptoError);
    }
    let body_len = ct_in.len() - TAG_BYTES;
    if out.len() < body_len {
        return Err(TweakCryptoError);
    }
    let ct_body = &ct_in[..body_len];
    let tag_recv = &ct_in[body_len..body_len + TAG_BYTES];

    let tag_calc = compute_tag(key, nonce, ad, ct_body);
    let tag_recv_arr: [u8; TAG_BYTES] = tag_recv.try_into().map_err(|_| TweakCryptoError)?;
    let tag_ok = tag_calc.ct_eq(&tag_recv_arr).unwrap_u8() == 1;

    // Always perform decryption so execution time is independent of tag validity.
    xor_body(key, nonce, ct_body, &mut out[..body_len]);

    if tag_ok {
        Ok(())
    } else {
        out[..body_len].zeroize();
        Err(TweakCryptoError)
    }
}

fn compute_tag(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    ad: &[u8],
    ct: &[u8],
) -> [u8; TAG_BYTES] {
    let mut v = Vec::with_capacity(KEY_BYTES + 1 + NONCE_BYTES + 8 + ad.len() + 8 + ct.len());
    v.extend_from_slice(key.as_slice());
    v.push(0x03);
    v.extend_from_slice(nonce.as_slice());
    v.extend_from_slice(&(ad.len() as u64).to_le_bytes());
    v.extend_from_slice(ad);
    v.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    v.extend_from_slice(ct);
    let mut s = [0u64; PLEN];
    absorb_all(&mut s, &v);
    first_32_from_state(&s)
}

#[cfg(test)]
mod kat_tests {
    use super::encrypt;

    #[test]
    fn kat_encrypt_libq_empty_ad() {
        let key = [0u8; 32];
        let nonce = [0u8; 16];
        let ad = b"";
        let pt = b"libQ";
        let mut out = [0u8; 4 + 32];
        encrypt(&key, &nonce, ad, pt, &mut out).unwrap();
        assert_eq!(
            out.as_slice(),
            hex::decode("4b77faf686b79b9f0cb22a26a3d2f10882b40b801c15c8801bd8eb7c01d2f13b5e13661a")
                .unwrap()
                .as_slice()
        );
    }
}
