//! Public parameters.

use zeroize::Zeroize;

/// Geometry for an Ajtai-style commitment `com = A · (r || m)`.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Zeroize)]
pub struct AjtaiParameters {
    /// Rows of `A` (module rank `k`).
    pub module_rank: usize,
    /// Number of randomness polynomials `l` (witness tail length).
    pub randomness_dimension: usize,
}

impl AjtaiParameters {
    #[must_use]
    pub const fn new(module_rank: usize, randomness_dimension: usize) -> Self {
        Self {
            module_rank,
            randomness_dimension,
        }
    }

    /// Witness column dimension `k + l`.
    #[must_use]
    pub const fn witness_len(&self) -> usize {
        self.module_rank + self.randomness_dimension
    }
}
