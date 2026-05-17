//! ML-DSA parameter markers (FIPS 204) as associated constants.

/// Shared geometry and bounds for \(R_q\) instantiations used with ML-DSA.
pub trait RingParams {
    /// Polynomial degree `n`.
    const N: usize;
    /// Modulus `q`.
    const Q: i32;
    /// Matrix rows `k`.
    const ROWS_IN_A: usize;
    /// Matrix columns `l`.
    const COLUMNS_IN_A: usize;
    /// Hamming weight `τ` of the challenge polynomial.
    const TAU: usize;
    /// `γ₁ = 2^{γ₁_exp}`.
    const GAMMA1_EXPONENT: usize;
    /// `γ₂ = ⌊(q-1)/88⌋` (ML-DSA-44) or `⌊(q-1)/32⌋` (65/87).
    const GAMMA2: i32;
    /// `η` (centered binomial / uniform width parameter as an integer bound).
    const ETA: i32;
    /// `β = τ · η`.
    const BETA: i32;
}

/// ML-DSA-44 (`ML-DSA-44`).
pub enum MlDsa44Params {}

impl RingParams for MlDsa44Params {
    const N: usize = 256;
    const Q: i32 = crate::constants::FIELD_MODULUS;
    const ROWS_IN_A: usize = 4;
    const COLUMNS_IN_A: usize = 4;
    const TAU: usize = 39;
    const GAMMA1_EXPONENT: usize = 17;
    const GAMMA2: i32 = (Self::Q - 1) / 88;
    const ETA: i32 = 2;
    const BETA: i32 = (Self::TAU as i32) * Self::ETA;
}

/// ML-DSA-65 (`ML-DSA-65`).
pub enum MlDsa65Params {}

impl RingParams for MlDsa65Params {
    const N: usize = 256;
    const Q: i32 = crate::constants::FIELD_MODULUS;
    const ROWS_IN_A: usize = 6;
    const COLUMNS_IN_A: usize = 5;
    const TAU: usize = 49;
    const GAMMA1_EXPONENT: usize = 19;
    const GAMMA2: i32 = (Self::Q - 1) / 32;
    const ETA: i32 = 4;
    const BETA: i32 = (Self::TAU as i32) * Self::ETA;
}

/// ML-DSA-87 (`ML-DSA-87`).
pub enum MlDsa87Params {}

impl RingParams for MlDsa87Params {
    const N: usize = 256;
    const Q: i32 = crate::constants::FIELD_MODULUS;
    const ROWS_IN_A: usize = 8;
    const COLUMNS_IN_A: usize = 7;
    const TAU: usize = 60;
    const GAMMA1_EXPONENT: usize = 19;
    const GAMMA2: i32 = (Self::Q - 1) / 32;
    const ETA: i32 = 2;
    const BETA: i32 = (Self::TAU as i32) * Self::ETA;
}
