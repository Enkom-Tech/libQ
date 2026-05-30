//! Transcript footprint model aligned with `lattice_zkp_wire_v0` encoded sizes.

use lib_q_ring::encoding::simple_bit_pack_len;

use crate::profile::{
    LatticeZkpProfileV0,
    RQ_COEFF_PACK_BITS,
};

/// Rough byte accounting for batched presentations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AmortisationBudget {
    /// Variable cost per attribute (opening slack + hashes).
    pub bytes_per_attribute: usize,
    /// Fixed overhead (batch transcript hash and aggregation handles).
    pub overhead_bytes: usize,
}

impl AmortisationBudget {
    /// Measured from `encode_opening_proof_v0` under [`LatticeZkpProfileV0::selective_disclosure_v0`].
    #[must_use]
    pub fn selective_disclosure_v0_measured() -> Self {
        let profile = LatticeZkpProfileV0::selective_disclosure_v0();
        Self {
            bytes_per_attribute: measured_opening_wire_body_bytes(&profile),
            overhead_bytes: 128,
        }
    }

    /// ML-DSA-65-oriented placeholder retained for backwards-compatible tests; prefer
    /// [`Self::selective_disclosure_v0_measured`] for presentation wire budgeting.
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

    /// Estimate amortised aggregate wire size (transcript + scalars + aggregated polys).
    #[must_use]
    pub fn estimate_amortised_wire_bytes(
        &self,
        attribute_count: usize,
        transcript_len: usize,
    ) -> usize {
        let profile = LatticeZkpProfileV0::selective_disclosure_v0();
        let opening = measured_opening_wire_body_bytes(&profile);
        transcript_len
            .saturating_add(6)
            .saturating_add(attribute_count.saturating_mul(4))
            .saturating_add(opening.saturating_mul(2))
            .saturating_add(crate::wire::WIRE_ENVELOPE_HEADER_LEN)
    }
}

/// Opening proof payload bytes (no envelope) for a frozen profile.
#[must_use]
pub fn measured_opening_wire_body_bytes(profile: &LatticeZkpProfileV0) -> usize {
    let rq_len = simple_bit_pack_len(usize::from(RQ_COEFF_PACK_BITS));
    let z_len = simple_bit_pack_len(usize::from(profile.z_pack_bits));
    2 + profile.mask_poly_count().saturating_mul(rq_len) +
        2 +
        profile.witness_poly_count().saturating_mul(z_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measured_budget_is_below_legacy_pilot_upper_bound() {
        let measured = AmortisationBudget::selective_disclosure_v0_measured();
        let pilot = AmortisationBudget::mldsa65_pilot();
        assert!(
            measured.bytes_per_attribute <= pilot.bytes_per_attribute,
            "measured {} should not exceed legacy pilot {}",
            measured.bytes_per_attribute,
            pilot.bytes_per_attribute
        );
    }

    #[test]
    fn three_attribute_presentation_within_wire_budget() {
        let b = AmortisationBudget::selective_disclosure_v0_measured();
        let est = b.estimate_presentation_bytes(3);
        assert!(
            est <= crate::profile::WIRE_BUDGET_PRESENTATION_BYTES,
            "3-attribute estimate {est} exceeds budget"
        );
    }
}
