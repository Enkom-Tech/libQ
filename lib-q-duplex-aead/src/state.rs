//! Keccak duplex sponge state for AEAD.

use lib_q_keccak::f1600;

use crate::params::{
    KEY_BYTES,
    NONCE_BYTES,
    PLEN,
    RATE_BYTES,
    TAG_BYTES,
};

/// XOR `data` into the first `data.len()` bytes of the sponge rate (little-endian lanes).
pub fn xor_into_rate(state: &mut [u64; PLEN], data: &[u8]) {
    debug_assert!(data.len() <= RATE_BYTES);
    let mut chunks = data.chunks_exact(8);
    for (s, chunk) in state.iter_mut().zip(&mut chunks) {
        *s ^= u64::from_le_bytes(chunk.try_into().unwrap());
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        let mut buf = [0u8; 8];
        buf[..rem.len()].copy_from_slice(rem);
        let n = data.len() / 8;
        state[n] ^= u64::from_le_bytes(buf);
    }
}

/// Read the rate (first `RATE_BYTES`) from `state` into `out`.
pub fn rate_to_bytes(state: &[u64; PLEN], out: &mut [u8; RATE_BYTES]) {
    for i in 0..17 {
        out[i * 8..(i + 1) * 8].copy_from_slice(&state[i].to_le_bytes());
    }
}

/// Replace the rate portion of `state` with `new_rate` (capacity lanes unchanged).
pub fn set_rate_from_bytes(state: &mut [u64; PLEN], new_rate: &[u8; RATE_BYTES]) {
    for i in 0..17 {
        state[i] = u64::from_le_bytes(new_rate[i * 8..(i + 1) * 8].try_into().unwrap());
    }
}

/// Absorb `data` with Keccak multi-rate padding (0x01 after payload, 0x80 at last rate byte).
pub fn absorb_all(state: &mut [u64; PLEN], data: &[u8]) {
    let mut i = 0usize;
    while i + RATE_BYTES <= data.len() {
        xor_into_rate(state, &data[i..i + RATE_BYTES]);
        f1600(state);
        i += RATE_BYTES;
    }
    let rest = data.len() - i;
    let mut block = [0u8; RATE_BYTES];
    if rest > 0 {
        block[..rest].copy_from_slice(&data[i..]);
    }
    block[rest] ^= 0x01;
    block[RATE_BYTES - 1] ^= 0x80;
    xor_into_rate(state, &block);
    f1600(state);
}

/// Initialize duplex from key and nonce (single padded rate block).
pub fn init_key_nonce(state: &mut [u64; PLEN], key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES]) {
    *state = [0u64; PLEN];
    let mut block = [0u8; RATE_BYTES];
    block[..KEY_BYTES].copy_from_slice(key.as_slice());
    block[KEY_BYTES..KEY_BYTES + NONCE_BYTES].copy_from_slice(nonce.as_slice());
    block[KEY_BYTES + NONCE_BYTES] ^= 0x01;
    block[RATE_BYTES - 1] ^= 0x80;
    xor_into_rate(state, &block);
    f1600(state);
}

fn absorb_padding_only(state: &mut [u64; PLEN]) {
    let mut pad = [0u8; RATE_BYTES];
    pad[0] ^= 0x01;
    pad[RATE_BYTES - 1] ^= 0x80;
    xor_into_rate(state, &pad);
    f1600(state);
}

/// Duplex encryption step: writes `ct` (same length as `pt`).
pub fn duplex_encrypt_chunk(state: &mut [u64; PLEN], pt: &[u8], ct: &mut [u8]) {
    debug_assert_eq!(pt.len(), ct.len());
    debug_assert!(pt.len() <= RATE_BYTES);
    let mut r = [0u8; RATE_BYTES];
    rate_to_bytes(state, &mut r);

    if pt.len() == RATE_BYTES {
        let mut c_full = [0u8; RATE_BYTES];
        for i in 0..RATE_BYTES {
            c_full[i] = r[i] ^ pt[i];
        }
        ct.copy_from_slice(&c_full);
        set_rate_from_bytes(state, &c_full);
        f1600(state);
        absorb_padding_only(state);
        return;
    }

    let mut padded = [0u8; RATE_BYTES];
    padded[..pt.len()].copy_from_slice(pt);
    padded[pt.len()] ^= 0x01;
    padded[RATE_BYTES - 1] ^= 0x80;

    let mut c_full = [0u8; RATE_BYTES];
    for i in 0..RATE_BYTES {
        c_full[i] = r[i] ^ padded[i];
    }
    ct.copy_from_slice(&c_full[..pt.len()]);
    set_rate_from_bytes(state, &c_full);
    f1600(state);
}

/// Duplex decryption step: recovers plaintext and advances state like encrypt.
pub fn duplex_decrypt_chunk(state: &mut [u64; PLEN], ct: &[u8], pt: &mut [u8]) {
    debug_assert_eq!(ct.len(), pt.len());
    debug_assert!(ct.len() <= RATE_BYTES);
    let mut r = [0u8; RATE_BYTES];
    rate_to_bytes(state, &mut r);

    if ct.len() == RATE_BYTES {
        for i in 0..RATE_BYTES {
            pt[i] = r[i] ^ ct[i];
        }
        let mut c_full = [0u8; RATE_BYTES];
        c_full.copy_from_slice(ct);
        set_rate_from_bytes(state, &c_full);
        f1600(state);
        absorb_padding_only(state);
        return;
    }

    for i in 0..ct.len() {
        pt[i] = r[i] ^ ct[i];
    }
    let mut padded = [0u8; RATE_BYTES];
    padded[..ct.len()].copy_from_slice(pt);
    padded[ct.len()] ^= 0x01;
    padded[RATE_BYTES - 1] ^= 0x80;
    let mut c_full = [0u8; RATE_BYTES];
    for i in 0..RATE_BYTES {
        c_full[i] = r[i] ^ padded[i];
    }
    set_rate_from_bytes(state, &c_full);
    f1600(state);
}

/// Extract tag from the first 32 bytes of the rate (4 lanes).
pub fn tag_from_state(state: &[u64; PLEN]) -> [u8; TAG_BYTES] {
    let mut t = [0u8; TAG_BYTES];
    for i in 0..4 {
        t[i * 8..(i + 1) * 8].copy_from_slice(&state[i].to_le_bytes());
    }
    t
}
