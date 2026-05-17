//! Transcript footprint model (ML-DSA-65 pilot constants).

/// Rough byte accounting for batched presentations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AmortisationBudget {
    /// Variable cost per attribute (opening slack + hashes).
    pub bytes_per_attribute: usize,
    /// Fixed overhead (CRS handles, single batch hash).
    pub overhead_bytes: usize,
}

impl AmortisationBudget {
    /// ML-DSA-65-oriented placeholder (`τ=49`, 32-byte seeds, one SHAKE256 block per challenge).
    #[must_use]
    pub const fn mldsa65_pilot() -> Self {
        Self {
            bytes_per_attribute: 49 * 256 * 4 / 8 + 32,
            overhead_bytes: 128,
        }
    }

    #[must_use]
    pub const fn new(bytes_per_attribute: usize, overhead_bytes: usize) -> Self {
        Self {
            bytes_per_attribute,
            overhead_bytes,
        }
    }

    #[must_use]
    pub fn estimate_presentation_bytes(&self, attribute_count: usize) -> usize {
        self.overhead_bytes
            .saturating_add(self.bytes_per_attribute.saturating_mul(attribute_count))
    }
}
