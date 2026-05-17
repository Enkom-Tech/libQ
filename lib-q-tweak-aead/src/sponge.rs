//! Keccak sponge helpers (rate XOR + f1600).

use lib_q_keccak::f1600;

use crate::params::{
    PLEN,
    RATE_BYTES,
};

/// XOR `data` into the rate (first `data.len()` bytes, LE lanes).
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

/// Absorb `data` with Keccak padding (0x01 then 0x80 at end of rate).
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
    if rest == RATE_BYTES {
        let mut pad = [0u8; RATE_BYTES];
        pad[0] ^= 0x01;
        pad[RATE_BYTES - 1] ^= 0x80;
        xor_into_rate(state, &pad);
        f1600(state);
    }
}

/// First 32 bytes of state (4 lanes, LE).
pub fn first_32_from_state(state: &[u64; PLEN]) -> [u8; crate::params::TAG_BYTES] {
    let mut t = [0u8; crate::params::TAG_BYTES];
    for i in 0..4 {
        t[i * 8..(i + 1) * 8].copy_from_slice(&state[i].to_le_bytes());
    }
    t
}
