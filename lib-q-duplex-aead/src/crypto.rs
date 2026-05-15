//! Duplex AEAD encrypt/decrypt over byte slices.

use core::fmt;

use lib_q_keccak::f1600;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use lib_q_core::DecryptSemanticOutcome;
#[cfg(feature = "alloc")]
use zeroize::Zeroizing;

use crate::params::{
    KEY_BYTES,
    NONCE_BYTES,
    PLEN,
    RATE_BYTES,
    TAG_BYTES,
};
use crate::state::{
    absorb_all,
    duplex_decrypt_chunk,
    duplex_encrypt_chunk,
    init_key_nonce,
    rate_to_bytes,
    set_rate_from_bytes,
    tag_from_state,
};

fn absorb_padding_only(state: &mut [u64; PLEN]) {
    let mut rate = [0u8; RATE_BYTES];
    rate_to_bytes(state, &mut rate);
    rate[0] ^= 0x01;
    rate[RATE_BYTES - 1] ^= 0x80;
    set_rate_from_bytes(state, &rate);
    f1600(state);
}

fn advance_decrypt_state_without_output(state: &mut [u64; PLEN], ct: &[u8]) {
    debug_assert!(ct.len() <= RATE_BYTES);
    let mut rate = [0u8; RATE_BYTES];
    rate_to_bytes(state, &mut rate);

    if ct.len() == RATE_BYTES {
        let mut c_full = [0u8; RATE_BYTES];
        c_full.copy_from_slice(ct);
        set_rate_from_bytes(state, &c_full);
        f1600(state);
        absorb_padding_only(state);
        return;
    }

    let mut c_full = rate;
    c_full[..ct.len()].copy_from_slice(ct);
    c_full[ct.len()] ^= 0x01;
    c_full[RATE_BYTES - 1] ^= 0x80;
    set_rate_from_bytes(state, &c_full);
    f1600(state);
}

/// Encrypt/decrypt failed: buffer too small, length overflow, or (decrypt) authentication failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DuplexCryptoError;

impl fmt::Debug for DuplexCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DuplexCryptoError")
    }
}

/// Shared duplex decrypt: writes plaintext into `out[..body_len]` and returns whether the tag
/// was valid. Both auth and decrypt passes always run (timing discipline).
///
/// Returns `Err` if `ct_in` is shorter than `TAG_BYTES` or `out` is shorter than the body length.
pub(crate) fn decrypt_core(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    ad: &[u8],
    ct_in: &[u8],
    out: &mut [u8],
) -> Result<bool, DuplexCryptoError> {
    if ct_in.len() < TAG_BYTES {
        return Err(DuplexCryptoError);
    }
    let body_len = ct_in.len() - TAG_BYTES;
    if out.len() < body_len {
        return Err(DuplexCryptoError);
    }
    let ct_body = &ct_in[..body_len];
    let tag_recv = &ct_in[body_len..body_len + TAG_BYTES];

    let mut state = [0u64; PLEN];
    init_key_nonce(&mut state, key, nonce);
    absorb_all(&mut state, ad);

    let mut off = 0usize;
    while off + RATE_BYTES <= body_len {
        advance_decrypt_state_without_output(&mut state, &ct_body[off..off + RATE_BYTES]);
        off += RATE_BYTES;
    }
    if off < body_len {
        advance_decrypt_state_without_output(&mut state, &ct_body[off..]);
    }

    let tag_calc = tag_from_state(&state);
    let tag_recv_arr: [u8; TAG_BYTES] = tag_recv.try_into().map_err(|_| DuplexCryptoError)?;
    let tag_ok = tag_calc.ct_eq(&tag_recv_arr).unwrap_u8() == 1;

    init_key_nonce(&mut state, key, nonce);
    absorb_all(&mut state, ad);
    let pt = &mut out[..body_len];
    let mut off = 0usize;
    while off + RATE_BYTES <= body_len {
        duplex_decrypt_chunk(
            &mut state,
            &ct_body[off..off + RATE_BYTES],
            &mut pt[off..off + RATE_BYTES],
        );
        off += RATE_BYTES;
    }
    if off < body_len {
        duplex_decrypt_chunk(&mut state, &ct_body[off..], &mut pt[off..]);
    }

    state.zeroize();

    Ok(tag_ok)
}

/// Encrypt: `ciphertext` is `pt.len() + TAG_BYTES`; `ct` must hold at least that.
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
    let mut state = [0u64; PLEN];
    init_key_nonce(&mut state, key, nonce);
    absorb_all(&mut state, ad);

    let ct = &mut out[..pt.len()];
    let mut off = 0usize;
    while off + RATE_BYTES <= pt.len() {
        duplex_encrypt_chunk(
            &mut state,
            &pt[off..off + RATE_BYTES],
            &mut ct[off..off + RATE_BYTES],
        );
        off += RATE_BYTES;
    }
    if off < pt.len() {
        duplex_encrypt_chunk(&mut state, &pt[off..], &mut ct[off..]);
    }

    let tag = tag_from_state(&state);
    out[pt.len()..pt.len() + TAG_BYTES].copy_from_slice(&tag);
    state.zeroize();
    Ok(())
}

/// Decrypt `ct_in` (ciphertext including tag) in constant time.
///
/// On success, plaintext is written to `out` (length `ct_in.len() - TAG_BYTES`).
/// On authentication failure, zeroes `out[..body_len]` and returns `Err`.
/// Both authentication and decryption passes always execute regardless of tag validity.
pub fn decrypt(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    ad: &[u8],
    ct_in: &[u8],
    out: &mut [u8],
) -> Result<(), DuplexCryptoError> {
    if ct_in.len() < TAG_BYTES {
        return Err(DuplexCryptoError);
    }
    let body_len = ct_in.len() - TAG_BYTES;
    let tag_ok = decrypt_core(key, nonce, ad, ct_in, out)?;
    if tag_ok {
        Ok(())
    } else {
        out[..body_len].zeroize();
        Err(DuplexCryptoError)
    }
}

/// Layer B semantic decrypt: single shared [`decrypt_core`] (no duplicate sponge passes).
#[cfg(feature = "alloc")]
pub(crate) fn decrypt_semantic_outcome(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    ad: &[u8],
    ct_in: &[u8],
) -> Result<DecryptSemanticOutcome, DuplexCryptoError> {
    if ct_in.len() < TAG_BYTES {
        return Err(DuplexCryptoError);
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
