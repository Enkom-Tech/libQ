//! Parameter sizes for duplex-sponge AEAD (Keccak-f[1600], rate 136 bytes).

/// Sponge rate in bytes (17 × 64-bit lanes).
pub const RATE_BYTES: usize = 136;
/// Keccak-f[1600] state lane count.
pub const PLEN: usize = 25;
/// User key size (256 bits).
pub const KEY_BYTES: usize = 32;
/// Nonce size (128 bits).
pub const NONCE_BYTES: usize = 16;
/// Authentication tag size (256 bits).
pub const TAG_BYTES: usize = 32;
