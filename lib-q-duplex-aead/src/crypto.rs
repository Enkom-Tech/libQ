//! Duplex AEAD encrypt/decrypt over byte slices.

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

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
    tag_from_state,
};

/// Encrypt: `ciphertext` is `pt.len() + TAG_BYTES`; `ct` must hold at least that.
pub fn encrypt(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    ad: &[u8],
    pt: &[u8],
    out: &mut [u8],
) -> Result<(), ()> {
    let total = pt.len().checked_add(TAG_BYTES).ok_or(())?;
    if out.len() < total {
        return Err(());
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

/// Decrypt: `ct_in` is ciphertext including tag. On success, plaintext written to `out` (length `ct_in.len() - TAG_BYTES`).
pub fn decrypt(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    ad: &[u8],
    ct_in: &[u8],
    out: &mut [u8],
) -> Result<(), ()> {
    if ct_in.len() < TAG_BYTES {
        return Err(());
    }
    let body_len = ct_in.len() - TAG_BYTES;
    if out.len() < body_len {
        return Err(());
    }
    let ct_body = &ct_in[..body_len];
    let tag_recv = &ct_in[body_len..body_len + TAG_BYTES];

    let mut state = [0u64; PLEN];
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

    let tag_calc = tag_from_state(&state);
    let tag_recv_arr: [u8; TAG_BYTES] = tag_recv.try_into().map_err(|_| ())?;
    if tag_calc.ct_eq(&tag_recv_arr).unwrap_u8() != 1 {
        pt.fill(0);
        state.zeroize();
        return Err(());
    }
    state.zeroize();
    Ok(())
}
