//! TurboSHAKE duplex AEAD (GIP `aead_id = 17`).
//!
//! A keyed duplex (SpongeWrap pattern) over **Keccak-p\[1600, 12\]**, the permutation TurboSHAKE
//! and KangarooTwelve use, called through the same [`lib_q_keccak::p1600`] entry point as
//! `lib-q-sha3`'s TurboSHAKE and `lib-q-k12`. Rate 136 bytes, capacity 512 bits, 32-byte key,
//! 16-byte nonce, 32-byte tag. Nonce-respecting: a (key, nonce) pair **MUST NOT** be used twice.
//!
//! Normative definition: the `aead_id = 17` TurboSHAKE duplex specification, v0. Every
//! duplex call absorbs at most 134 bytes, then a domain byte `D` (`0x41`..`0x45`), and `0x80`
//! in the last rate byte, exactly the TurboSHAKE padding; so the initialization call leaves the
//! state TurboSHAKE256(`label ‖ key ‖ nonce`, `D = 0x41`) would leave.
//!
//! The mode is custom (not a published standard) and has had no independent cryptanalysis yet.
//! Do not deploy it until a cryptographer has reviewed the construction.

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::crypto::DuplexCryptoError;

/// Keccak-p rounds (TurboSHAKE / KangarooTwelve).
pub const ROUNDS: usize = 12;
/// Sponge rate in bytes.
pub const RATE: usize = 136;
/// Data bytes per duplex call (the rate less the domain byte and the final `0x80`).
pub const BLOCK: usize = 134;
/// Key size.
pub const KEY_BYTES: usize = 32;
/// Nonce size.
pub const NONCE_BYTES: usize = 16;
/// Tag size.
pub const TAG_BYTES: usize = 32;
/// Initialization label, absorbed before the key.
pub const LABEL: &[u8; 15] = b"gip.aead.tsd.v1";

const D_INIT: u8 = 0x41;
const D_AD: u8 = 0x42;
const D_AD_LAST: u8 = 0x43;
const D_MSG: u8 = 0x44;
const D_MSG_LAST: u8 = 0x45;

const _: () = assert!(LABEL.len() + KEY_BYTES + NONCE_BYTES <= BLOCK);

/// The 200-byte state as 25 little-endian lanes.
struct State([u64; 25]);

impl Drop for State {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl State {
    fn new() -> Self {
        Self([0u64; 25])
    }

    #[inline]
    fn byte(&self, i: usize) -> u8 {
        (self.0[i / 8] >> (8 * (i % 8))) as u8
    }

    #[inline]
    fn xor_byte(&mut self, i: usize, b: u8) {
        self.0[i / 8] ^= u64::from(b) << (8 * (i % 8));
    }

    /// One duplex call: XOR `x ‖ D ‖ 0* ‖ 0x80` into the rate, then Keccak-p\[1600, 12\].
    fn duplex(&mut self, x: &[u8], d: u8) {
        debug_assert!(x.len() <= BLOCK);
        debug_assert!((0x01..=0x7F).contains(&d));
        for (i, &b) in x.iter().enumerate() {
            self.xor_byte(i, b);
        }
        self.xor_byte(x.len(), d);
        self.xor_byte(RATE - 1, 0x80);
        lib_q_keccak::p1600(&mut self.0, ROUNDS);
    }

    fn tag(&self) -> [u8; TAG_BYTES] {
        let mut t = [0u8; TAG_BYTES];
        for (i, o) in t.iter_mut().enumerate() {
            *o = self.byte(i);
        }
        t
    }
}

/// Block count of a field: an empty field is one empty block.
#[inline]
fn block_count(len: usize) -> usize {
    if len == 0 { 1 } else { len.div_ceil(BLOCK) }
}

fn start(key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES], ad: &[u8]) -> State {
    let mut s = State::new();
    let mut init = [0u8; LABEL.len() + KEY_BYTES + NONCE_BYTES];
    init[..LABEL.len()].copy_from_slice(LABEL);
    init[LABEL.len()..LABEL.len() + KEY_BYTES].copy_from_slice(key);
    init[LABEL.len() + KEY_BYTES..].copy_from_slice(nonce);
    s.duplex(&init, D_INIT);
    init.zeroize();

    let n = block_count(ad.len());
    for i in 0..n {
        let a = &ad[(i * BLOCK).min(ad.len())..((i + 1) * BLOCK).min(ad.len())];
        s.duplex(a, if i + 1 == n { D_AD_LAST } else { D_AD });
    }
    s
}

/// Seal: writes `pt.len() + TAG_BYTES` bytes (ciphertext ‖ tag) into `out`.
pub fn encrypt(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    ad: &[u8],
    pt: &[u8],
    out: &mut [u8],
) -> Result<(), DuplexCryptoError> {
    let total = pt.len().checked_add(TAG_BYTES).ok_or(DuplexCryptoError)?;
    if out.len() < total {
        return Err(DuplexCryptoError);
    }
    let mut s = start(key, nonce, ad);
    let n = block_count(pt.len());
    for i in 0..n {
        let lo = (i * BLOCK).min(pt.len());
        let hi = ((i + 1) * BLOCK).min(pt.len());
        for j in lo..hi {
            out[j] = pt[j] ^ s.byte(j - lo);
        }
        s.duplex(&pt[lo..hi], if i + 1 == n { D_MSG_LAST } else { D_MSG });
    }
    out[pt.len()..total].copy_from_slice(&s.tag());
    Ok(())
}

/// Open `ct` (ciphertext ‖ tag). On success writes the plaintext to `out[..ct.len() - TAG_BYTES]`.
/// On a bad tag zeroes that range and returns `Err`. The walk over the body always runs to the
/// end; the tag compare is constant time.
pub fn decrypt(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    ad: &[u8],
    ct: &[u8],
    out: &mut [u8],
) -> Result<(), DuplexCryptoError> {
    if ct.len() < TAG_BYTES {
        return Err(DuplexCryptoError);
    }
    let body_len = ct.len() - TAG_BYTES;
    if out.len() < body_len {
        return Err(DuplexCryptoError);
    }
    let mut s = start(key, nonce, ad);
    let n = block_count(body_len);
    for i in 0..n {
        let lo = (i * BLOCK).min(body_len);
        let hi = ((i + 1) * BLOCK).min(body_len);
        for j in lo..hi {
            out[j] = ct[j] ^ s.byte(j - lo);
        }
        s.duplex(&out[lo..hi], if i + 1 == n { D_MSG_LAST } else { D_MSG });
    }
    let mut calc = s.tag();
    let ok = calc.ct_eq(&ct[body_len..]).unwrap_u8() == 1;
    calc.zeroize();
    if ok {
        Ok(())
    } else {
        out[..body_len].zeroize();
        Err(DuplexCryptoError)
    }
}

/// First `out.len()` (at most 136) state bytes after the initialization call alone. Exposed for
/// the cross-check against TurboSHAKE256 (`D = 0x41`); not an API for applications.
#[doc(hidden)]
pub fn init_state_prefix(key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES], out: &mut [u8]) {
    let mut s = State::new();
    let mut init = [0u8; LABEL.len() + KEY_BYTES + NONCE_BYTES];
    init[..LABEL.len()].copy_from_slice(LABEL);
    init[LABEL.len()..LABEL.len() + KEY_BYTES].copy_from_slice(key);
    init[LABEL.len() + KEY_BYTES..].copy_from_slice(nonce);
    s.duplex(&init, D_INIT);
    init.zeroize();
    for (i, o) in out.iter_mut().take(RATE).enumerate() {
        *o = s.byte(i);
    }
}

#[cfg(feature = "alloc")]
mod aead_impl {
    extern crate alloc;
    use alloc::string::ToString;
    use alloc::vec::Vec;

    use lib_q_core::{Aead, AeadKey, Error, Nonce, Result};
    use zeroize::Zeroizing;

    use super::{
        KEY_BYTES, NONCE_BYTES, TAG_BYTES, decrypt as tsd_decrypt, encrypt as tsd_encrypt,
    };

    /// TurboSHAKE duplex AEAD (`aead_id = 17`) behind the `lib_q_core::Aead` trait.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct TurboShakeDuplexAead;

    fn arrays(
        key: &AeadKey,
        nonce: &Nonce,
    ) -> Result<(Zeroizing<[u8; KEY_BYTES]>, [u8; NONCE_BYTES])> {
        let kb = key.as_bytes();
        let nb = nonce.as_bytes();
        let k: [u8; KEY_BYTES] = kb.try_into().map_err(|_| Error::InvalidKeySize {
            expected: KEY_BYTES,
            actual: kb.len(),
        })?;
        let n: [u8; NONCE_BYTES] = nb.try_into().map_err(|_| Error::InvalidNonceSize {
            expected: NONCE_BYTES,
            actual: nb.len(),
        })?;
        Ok((Zeroizing::new(k), n))
    }

    impl Aead for TurboShakeDuplexAead {
        fn encrypt(
            &self,
            key: &AeadKey,
            nonce: &Nonce,
            plaintext: &[u8],
            associated_data: Option<&[u8]>,
        ) -> Result<Vec<u8>> {
            let (k, n) = arrays(key, nonce)?;
            let mut out = alloc::vec![0u8; plaintext.len() + TAG_BYTES];
            tsd_encrypt(&k, &n, associated_data.unwrap_or(&[]), plaintext, &mut out).map_err(
                |_| Error::InvalidMessageSize {
                    max: usize::MAX,
                    actual: plaintext.len(),
                },
            )?;
            Ok(out)
        }

        fn decrypt(
            &self,
            key: &AeadKey,
            nonce: &Nonce,
            ciphertext: &[u8],
            associated_data: Option<&[u8]>,
        ) -> Result<Vec<u8>> {
            let (k, n) = arrays(key, nonce)?;
            if ciphertext.len() < TAG_BYTES {
                return Err(Error::aead_ciphertext_shorter_than_tag(
                    TAG_BYTES,
                    ciphertext.len(),
                ));
            }
            let mut pt = alloc::vec![0u8; ciphertext.len() - TAG_BYTES];
            tsd_decrypt(&k, &n, associated_data.unwrap_or(&[]), ciphertext, &mut pt).map_err(
                |_| Error::VerificationFailed {
                    operation: "AEAD tag verification".to_string(),
                },
            )?;
            Ok(pt)
        }
    }
}

#[cfg(feature = "alloc")]
pub use aead_impl::TurboShakeDuplexAead;

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::vec::Vec;

    use super::*;

    fn seal(k: &[u8; 32], n: &[u8; 16], ad: &[u8], pt: &[u8]) -> Vec<u8> {
        let mut out = alloc::vec![0u8; pt.len() + TAG_BYTES];
        encrypt(k, n, ad, pt, &mut out).unwrap();
        out
    }

    #[test]
    fn round_trip_across_block_boundaries() {
        let k = [7u8; 32];
        let n = [9u8; 16];
        for len in [0usize, 1, 133, 134, 135, 267, 268, 269, 1000] {
            for adl in [0usize, 1, 134, 135] {
                let pt: Vec<u8> = (0..len).map(|i| i as u8).collect();
                let ad: Vec<u8> = (0..adl).map(|i| (i * 3) as u8).collect();
                let ct = seal(&k, &n, &ad, &pt);
                let mut back = alloc::vec![0u8; len];
                decrypt(&k, &n, &ad, &ct, &mut back).unwrap();
                assert_eq!(back, pt);
            }
        }
    }

    #[test]
    fn any_bit_flip_fails_and_zeroes_output() {
        let k = [1u8; 32];
        let n = [2u8; 16];
        let ct = seal(&k, &n, b"ad", b"attack at dawn, attack at dawn");
        for i in 0..ct.len() {
            let mut bad = ct.clone();
            bad[i] ^= 0x01;
            let mut out = alloc::vec![0xAAu8; ct.len() - TAG_BYTES];
            assert!(decrypt(&k, &n, b"ad", &bad, &mut out).is_err());
            assert!(out.iter().all(|&b| b == 0));
        }
        let mut out = alloc::vec![0u8; ct.len() - TAG_BYTES];
        assert!(decrypt(&k, &n, b"ae", &ct, &mut out).is_err());
        let mut n2 = n;
        n2[15] ^= 1;
        assert!(decrypt(&k, &n2, b"ad", &ct, &mut out).is_err());
    }

    #[test]
    fn empty_ad_differs_from_one_zero_byte_ad() {
        let k = [3u8; 32];
        let n = [4u8; 16];
        assert_ne!(seal(&k, &n, b"", b"x"), seal(&k, &n, &[0u8], b"x"));
        // AD and message are domain separated: moving a byte between them changes the output.
        assert_ne!(seal(&k, &n, b"ab", b"")[..], seal(&k, &n, b"a", b"b")[1..]);
    }
}
