//! Per-block keystream from sponge (key, nonce, counter).

use lib_q_keccak::f1600;

use crate::params::{
    BLOCK_BYTES,
    KEY_BYTES,
    NONCE_BYTES,
    PLEN,
    RATE_BYTES,
};
use crate::sponge::{
    first_32_from_state,
    xor_into_rate,
};

/// One block of keystream for 256-bit counter `block_index`.
pub fn keystream_block(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    block_index: u64,
) -> [u8; BLOCK_BYTES] {
    let mut s = [0u64; PLEN];
    let mut buf = [0u8; RATE_BYTES];
    buf[..KEY_BYTES].copy_from_slice(key.as_slice());
    buf[KEY_BYTES] = 0x01;
    buf[KEY_BYTES + 1..KEY_BYTES + 1 + NONCE_BYTES].copy_from_slice(nonce.as_slice());
    buf[KEY_BYTES + 1 + NONCE_BYTES..KEY_BYTES + 1 + NONCE_BYTES + 8]
        .copy_from_slice(&block_index.to_le_bytes());
    buf[KEY_BYTES + 1 + NONCE_BYTES + 8] = 0x02;
    buf[RATE_BYTES - 1] = 0x80;
    xor_into_rate(&mut s, &buf);
    f1600(&mut s);
    first_32_from_state(&s)
}

/// Prepare state up to (excluding) f1600 for `block_index` (for batched permutation).
pub fn setup_state_pre_f1600(
    state: &mut [u64; PLEN],
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    block_index: u64,
) {
    *state = [0u64; PLEN];
    let mut buf = [0u8; RATE_BYTES];
    buf[..KEY_BYTES].copy_from_slice(key.as_slice());
    buf[KEY_BYTES] = 0x01;
    buf[KEY_BYTES + 1..KEY_BYTES + 1 + NONCE_BYTES].copy_from_slice(nonce.as_slice());
    buf[KEY_BYTES + 1 + NONCE_BYTES..KEY_BYTES + 1 + NONCE_BYTES + 8]
        .copy_from_slice(&block_index.to_le_bytes());
    buf[KEY_BYTES + 1 + NONCE_BYTES + 8] = 0x02;
    buf[RATE_BYTES - 1] = 0x80;
    xor_into_rate(state, &buf);
}
