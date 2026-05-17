//! Sizes for tweakable CTR AEAD (32-byte blocks, Keccak-f\[1600\] rate 136).

/// Sponge rate in bytes.
pub const RATE_BYTES: usize = 136;
pub const PLEN: usize = 25;
/// Plaintext/ciphertext block (keystream block).
pub const BLOCK_BYTES: usize = 32;
pub const KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 16;
pub const TAG_BYTES: usize = 32;
