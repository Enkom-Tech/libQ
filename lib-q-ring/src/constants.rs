//! ML-DSA field and ring geometry (FIPS 204).

/// Modulus `q` for ML-DSA (ML-KEM uses a different field).
pub const FIELD_MODULUS: i32 = 8_380_417;

/// Polynomial degree `n = 256`.
pub const COEFFICIENTS_IN_RING_ELEMENT: usize = 256;

/// `R^(-1) mod 2^32` where `R = 2^32 mod q` (Montgomery).
pub const INVERSE_OF_MODULUS_MOD_MONTGOMERY_R: u64 = 58_728_449;

pub const MONTGOMERY_SHIFT: u8 = 32;

/// Post-inverse NTT scaling: `(M^2) / 256 mod q` with `M = 2^32 mod q`.
pub const INVERSE_NTT_MONTGOMERY_FINISH: i32 = 41_978;

/// SHAKE256 block size used by ML-DSA streaming XOF (rate 136 bytes).
pub const SHAKE256_BLOCK_SIZE: usize = 136;

/// SHAKE128 rate (168 bytes).
pub const SHAKE128_BLOCK_SIZE: usize = 168;

/// Five SHAKE128 blocks (ML-DSA matrix sampling prefetch).
pub const SHAKE128_FIVE_BLOCKS_SIZE: usize = SHAKE128_BLOCK_SIZE * 5;

/// `ρ` length for ExpandA (FIPS 204).
pub const SEED_FOR_A_SIZE: usize = 32;
