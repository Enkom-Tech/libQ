//! Tweakable CTR AEAD encrypt/decrypt.

use core::fmt;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
use lib_q_core::DecryptSemanticOutcome;
use subtle::ConstantTimeEq;
use zeroize::{
    Zeroize,
    Zeroizing,
};

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

/// Shared tweak decrypt: writes plaintext into `out[..body_len]` and returns whether the tag
/// was valid. XOR decrypt always runs regardless of tag validity.
pub(crate) fn decrypt_core(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    ad: &[u8],
    ct_in: &[u8],
    out: &mut [u8],
) -> Result<bool, TweakCryptoError> {
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

    xor_body(key, nonce, ct_body, &mut out[..body_len]);

    Ok(tag_ok)
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
    let tag_ok = decrypt_core(key, nonce, ad, ct_in, out)?;
    let body_len = ct_in.len() - TAG_BYTES;
    if tag_ok {
        Ok(())
    } else {
        out[..body_len].zeroize();
        Err(TweakCryptoError)
    }
}

/// Layer B semantic decrypt: single shared [`decrypt_core`].
#[cfg(feature = "alloc")]
pub(crate) fn decrypt_semantic_outcome(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    ad: &[u8],
    ct_in: &[u8],
) -> Result<DecryptSemanticOutcome, TweakCryptoError> {
    if ct_in.len() < TAG_BYTES {
        return Err(TweakCryptoError);
    }
    let body_len = ct_in.len() - TAG_BYTES;
    let mut pt = vec![0u8; body_len];
    let tag_ok = decrypt_core(key, nonce, ad, ct_in, &mut pt)?;
    if tag_ok {
        Ok(DecryptSemanticOutcome::Success(Zeroizing::new(pt)))
    } else {
        pt.zeroize();
        Ok(DecryptSemanticOutcome::AuthenticationFailed)
    }
}

fn compute_tag(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    ad: &[u8],
    ct: &[u8],
) -> [u8; TAG_BYTES] {
    let mut v = Zeroizing::new(Vec::with_capacity(
        KEY_BYTES + 1 + NONCE_BYTES + 8 + ad.len() + 8 + ct.len(),
    ));
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
    use crate::params::{
        KEY_BYTES,
        NONCE_BYTES,
        TAG_BYTES,
    };

    #[test]
    fn kat_encrypt_libq_empty_ad() {
        let key = [0u8; 32];
        let nonce = [0u8; 16];
        let ad = b"";
        let pt = b"libQ";
        // Deliberately DIRTY (see `kat_encrypt_multi_block_293`): `encrypt` must assign into the
        // caller's buffer, not XOR into whatever it already held. A zeroed buffer cannot tell the
        // two apart, since 0 is the XOR identity.
        let mut out = [0xAAu8; 4 + 32];
        encrypt(&key, &nonce, ad, pt, &mut out).unwrap();
        assert_eq!(
            out.as_slice(),
            hex::decode("4b77faf686b79b9f0cb22a26a3d2f10882b40b801c15c8801bd8eb7c01d2f13b5e13661a")
                .unwrap()
                .as_slice()
        );
    }

    /// Multi-block KAT: 293 bytes = 9 full 32-byte blocks + a 5-byte remainder.
    ///
    /// This length is chosen to drive **every** loop of the AVX2 keystream in one shot:
    /// two iterations of the 4-way batched loop (blocks 0..4 and 4..8), one iteration of the
    /// single-block tail loop (block 8), and the sub-block remainder (block 9). The pre-existing
    /// `kat_encrypt_libq_empty_ad` vector is 4 bytes, so it only ever reached the remainder path
    /// — it cannot detect a batched-loop defect.
    ///
    /// Why a KAT and not only `tests/simd_equivalence.rs`: this test is **branch-independent**.
    /// `xor_body` picks AVX2 vs portable at runtime, and the differential test can only run when
    /// the host CPU actually has AVX2 (it returns early otherwise). This one pins fixed bytes
    /// whichever branch runs, so a build that takes the AVX2 branch must produce exactly the
    /// portable answer or fail here. Regenerate with
    /// `cargo run -p lib-q-tweak-aead --example dump_tweak_kat` (no `simd-avx2`, so the expected
    /// bytes stay an independent oracle rather than a recording of the AVX2 path).
    #[test]
    fn kat_encrypt_multi_block_293() {
        let mut key = [0u8; KEY_BYTES];
        for (i, k) in key.iter_mut().enumerate() {
            *k = i as u8;
        }
        // A known-answer test pins fixed inputs to fixed outputs; a fresh nonce would make the
        // expected bytes below unverifiable, which is the whole point of a KAT. This value never
        // leaves the test module and is not reachable from any production path.
        // codeql[rust/hard-coded-cryptographic-value]
        let mut nonce = [0u8; NONCE_BYTES];
        for (i, n) in nonce.iter_mut().enumerate() {
            *n = 0x10 + i as u8;
        }
        let ad = b"lib-q tweak-aead KAT";
        let mut pt = [0u8; 293];
        for (i, p) in pt.iter_mut().enumerate() {
            *p = i as u8;
        }

        // Deliberately DIRTY, not zeroed. `encrypt` is `pub` and writes into a caller-supplied
        // `out`; a caller reusing one buffer across messages is the obvious way to avoid
        // reallocating. A zeroed buffer cannot distinguish `ct[i] = pt[i] ^ ks[i]` from
        // `ct[i] ^= pt[i] ^ ks[i]` (0 is the XOR identity), and every output buffer in this
        // suite used to be zeroed: changing both AVX2 write sites to `^=` left all 12 tests
        // green. Prefilling here pins assignment semantics on whichever branch `xor_body` takes,
        // so it holds on AVX2-less runners too. The expected bytes are unchanged — that is the
        // point.
        let mut out = [0xAAu8; 293 + TAG_BYTES];
        encrypt(&key, &nonce, ad, &pt, &mut out).unwrap();

        let expected = hex::decode(concat!(
            "394feaffac29c1b3eb0b999fd7915ebae93b036d675a4829cac0c823eabf8b0cd35eaf556d6f60a7",
            "b81a1d87d5cac535d9338ae11bffac70912a498436240736c865f2c75f7277b3278eb2fba75c0920",
            "dd07dbd0ca8f9605f8630447de31b33ccd9970d50ed8497ae9de95753ef3a5a03c75300a178859b1",
            "3da26b8a0c1e60046fd0275b8c6b4c1711978cfeee6a54b3c893eb8546f9dcadbd061257d27337dc",
            "e57145a13903fa215fae05118c49ed9ead64e404adbdcee09be5cf9749fbda26493e58cdf04acc2b",
            "f42bfae1e8f27a6e6d70ffbc553108687a00469f36b9d9de48d5ce5aaa24b8999e953b134b8b380a",
            "2ae1fb58bc9612471967abe0e1798c7dcf5beb371c0e570e156e23ac52532a6eb5a0ff0045467082",
            "c9000e6e71fd3bafe22deb597f5cb1345ef0fb0301b6f65f43ee1138064c57033a7e79826ad7831b",
            "c4980fd1ce",
        ))
        .unwrap();
        assert_eq!(out.len(), expected.len());
        assert_eq!(
            out.as_slice(),
            expected.as_slice(),
            "multi-block ciphertext+tag mismatch; first differing byte at index {:?}",
            out.iter().zip(expected.iter()).position(|(a, b)| a != b)
        );
    }
}
