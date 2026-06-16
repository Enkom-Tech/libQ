//! # lib-q-sah — Stream-AEAD-H (S-A-H)
//!
//! S-A-H is the high-throughput, **nonce-sensitive** AEAD for capable GIP nodes.
//! It is KEM-agnostic: it consumes an AEAD key produced by the active suite KDF
//! from the negotiated shared secret and context.
//!
//! ## Variants
//! - **S-A-H-256** (this crate, [`Sah256`]): 256-bit key, 128-bit nonce,
//!   128-bit tag. 8x64-bit state, 256-bit data blocks, ARX + 8-bit S-box +
//!   linear-permutation rounds.
//! - S-A-H-512 (512-bit key, 256-bit tag): future work.
//!
//! ## Nonce model — read before use
//! S-A-H is **not** misuse-resistant. Nonce uniqueness per `(key, direction)`
//! MUST be enforced at integration boundaries (a per-key/direction monotone
//! record counter, with rekey before counter exhaustion). Reusing a nonce under
//! one key leaks the XOR of plaintexts and degrades integrity. For contexts that
//! cannot guarantee uniqueness, use Romulus-M1 instead. See `SECURITY.md`.
//!
//! ## Status
//! Spec version `0.3.0` is **DRAFT**: the round constants and rotations are
//! provisional placeholders carrying no security claim, pending the
//! research-track freeze gates. (The S-box is settled as the AES S-box, computed
//! constant-time; init/final anchors are 12 rounds.) Do not deploy.

#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "alloc")]
extern crate alloc;

mod aead;
mod error;
mod params;
mod round;
mod sbox;

pub use error::SahError;
pub use params::{KEY_LEN, NONCE_LEN, SPEC_VERSION, TAG_LEN};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A 256-bit S-A-H key. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Sah256Key([u8; KEY_LEN]);

impl Sah256Key {
    /// Wrap a 32-byte key.
    pub fn new(bytes: [u8; KEY_LEN]) -> Self {
        Sah256Key(bytes)
    }

    /// Wrap a key from a slice; errors if the slice is not exactly 32 bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, SahError> {
        let arr: [u8; KEY_LEN] = bytes.try_into().map_err(|_| SahError::InvalidLength)?;
        Ok(Sah256Key(arr))
    }
}

impl From<[u8; KEY_LEN]> for Sah256Key {
    fn from(bytes: [u8; KEY_LEN]) -> Self {
        Sah256Key(bytes)
    }
}

/// A 128-bit S-A-H nonce. Must be unique per `(key, direction)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sah256Nonce([u8; NONCE_LEN]);

impl Sah256Nonce {
    pub fn new(bytes: [u8; NONCE_LEN]) -> Self {
        Sah256Nonce(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, SahError> {
        let arr: [u8; NONCE_LEN] = bytes.try_into().map_err(|_| SahError::InvalidLength)?;
        Ok(Sah256Nonce(arr))
    }
}

impl From<[u8; NONCE_LEN]> for Sah256Nonce {
    fn from(bytes: [u8; NONCE_LEN]) -> Self {
        Sah256Nonce(bytes)
    }
}

/// Stream-AEAD-H-256.
pub struct Sah256;

impl Sah256 {
    /// Detached seal. Encrypts `pt` into `ct` (which must be the same length)
    /// and returns the 16-byte tag. `InvalidLength` if `ct.len() != pt.len()`
    /// or an input exceeds the maximum supported length.
    pub fn seal_detached(
        key: &Sah256Key,
        nonce: &Sah256Nonce,
        aad: &[u8],
        pt: &[u8],
        ct: &mut [u8],
    ) -> Result<[u8; TAG_LEN], SahError> {
        if ct.len() != pt.len() {
            return Err(SahError::InvalidLength);
        }
        if pt.len() as u64 > params::MAX_LEN || aad.len() as u64 > params::MAX_LEN {
            return Err(SahError::InvalidLength);
        }
        Ok(aead::seal_detached(&key.0, &nonce.0, aad, pt, ct))
    }

    /// Detached open. Decrypts `ct` into `pt` (same length) and verifies `tag`
    /// in constant time. On authentication failure, `pt` is zeroized and
    /// `AuthenticationFailed` is returned.
    pub fn open_detached(
        key: &Sah256Key,
        nonce: &Sah256Nonce,
        aad: &[u8],
        ct: &[u8],
        tag: &[u8; TAG_LEN],
        pt: &mut [u8],
    ) -> Result<(), SahError> {
        if pt.len() != ct.len() {
            return Err(SahError::InvalidLength);
        }
        if ct.len() as u64 > params::MAX_LEN || aad.len() as u64 > params::MAX_LEN {
            return Err(SahError::InvalidLength);
        }
        let expected = aead::open_detached_recompute(&key.0, &nonce.0, aad, ct, pt);
        let ok: bool = expected.ct_eq(tag).into();
        if ok {
            Ok(())
        } else {
            pt.zeroize();
            Err(SahError::AuthenticationFailed)
        }
    }

    /// Combined seal: returns `ciphertext || tag`.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn seal(
        key: &Sah256Key,
        nonce: &Sah256Nonce,
        aad: &[u8],
        pt: &[u8],
    ) -> Result<Vec<u8>, SahError> {
        let mut out = alloc::vec![0u8; pt.len() + TAG_LEN];
        let (ct, tag_slot) = out.split_at_mut(pt.len());
        let tag = Self::seal_detached(key, nonce, aad, pt, ct)?;
        tag_slot.copy_from_slice(&tag);
        Ok(out)
    }

    /// Combined open: input is `ciphertext || tag`. Returns the plaintext, or
    /// `AuthenticationFailed` (which also covers input shorter than the tag).
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn open(
        key: &Sah256Key,
        nonce: &Sah256Nonce,
        aad: &[u8],
        ct_and_tag: &[u8],
    ) -> Result<Vec<u8>, SahError> {
        if ct_and_tag.len() < TAG_LEN {
            return Err(SahError::AuthenticationFailed);
        }
        let (ct, tag) = ct_and_tag.split_at(ct_and_tag.len() - TAG_LEN);
        let tag: &[u8; TAG_LEN] = tag.try_into().map_err(|_| SahError::AuthenticationFailed)?;
        let mut pt = alloc::vec![0u8; ct.len()];
        Self::open_detached(key, nonce, aad, ct, tag, &mut pt)?;
        Ok(pt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Sah256Key {
        let mut k = [0u8; KEY_LEN];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(1);
        }
        Sah256Key::new(k)
    }

    fn nonce() -> Sah256Nonce {
        let mut n = [0u8; NONCE_LEN];
        for (i, b) in n.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(13).wrapping_add(3);
        }
        Sah256Nonce::new(n)
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn roundtrip_combined() {
        let (k, n) = (key(), nonce());
        for len in [0usize, 1, 16, 31, 32, 33, 64, 200] {
            let pt = alloc::vec![0xABu8; len];
            let sealed = Sah256::seal(&k, &n, b"hdr", &pt).unwrap();
            let opened = Sah256::open(&k, &n, b"hdr", &sealed).unwrap();
            assert_eq!(opened, pt);
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn open_rejects_short_input() {
        let (k, n) = (key(), nonce());
        assert_eq!(
            Sah256::open(&k, &n, b"", &[0u8; 4]),
            Err(SahError::AuthenticationFailed)
        );
    }
}
