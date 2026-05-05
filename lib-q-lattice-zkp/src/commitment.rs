//! Ajtai commitment `com = A · (r || m)`.

use alloc::vec::Vec;

use lib_q_ring::{
    ModuleMatrix,
    ModuleVec,
    Poly,
};
use zeroize::{
    Zeroize,
    ZeroizeOnDrop,
};

use crate::params::AjtaiParameters;

/// CRS seed `ρ` and dimensions.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AjtaiCommitmentKey {
    /// ExpandA seed (32 bytes).
    pub seed: [u8; 32],
    pub params: AjtaiParameters,
}

/// Commitment image `A · witness` in the time domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AjtaiCommitment {
    /// `k` ring elements (rows of `A`).
    pub value: ModuleVec,
}

/// Secret opening `(m || r)` split for API clarity.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AjtaiOpening {
    /// Message block (`k` polynomials).
    pub message: ModuleVec,
    /// Randomness block (`l` polynomials).
    pub randomness: ModuleVec,
}

impl AjtaiOpening {
    /// Concatenate `(r || m)` as in the plan (`randomness` then `message`).
    fn witness_polys(&self) -> Vec<Poly> {
        let mut v = Vec::with_capacity(self.randomness.0.len() + self.message.0.len());
        v.extend_from_slice(&self.randomness.0);
        v.extend_from_slice(&self.message.0);
        v
    }
}

/// Compute `com = A · (r || m)`.
#[must_use]
pub fn commit(key: &AjtaiCommitmentKey, opening: &AjtaiOpening) -> AjtaiCommitment {
    let p = &key.params;
    let matrix = ModuleMatrix::expand_from_seed(&key.seed, p.module_rank, p.witness_len());
    let witness = ModuleVec(opening.witness_polys());
    let value = matrix.mul_vec(&witness);
    AjtaiCommitment { value }
}
