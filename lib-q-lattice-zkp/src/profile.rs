//! Frozen wire parameter profiles (`LatticeZkpProfileV0`).
//!
//! Each profile fixes ring geometry, Fiat–Shamir challenge sparsity, response bounds, and
//! Merkle depth caps for a specific on-wire proof bundle. Security reduces to **Module-SIS**
//! (binding) and **Module-LWE** (hiding) over `R_q = Z_q[X]/(X^256+1)` with `q` from ML-DSA.
//! Fiat–Shamir proofs use a committed-first-message transform analyzed in the **QROM**
//! (see workspace [`SECURITY.md`](../../SECURITY.md)).

use lib_q_ring::constants::{
    COEFFICIENTS_IN_RING_ELEMENT,
    FIELD_MODULUS,
};

use crate::params::AjtaiParameters;

/// Frozen `||z||_inf` abort bound for all v0 profiles.
///
/// Soundness fix (#5): the legacy bound was `20_000_000`, larger than `2q` (`q = 8_380_417`,
/// `q/2 = 4_190_208`), so the verifier's norm check never rejected anything and Module-SIS
/// *binding* of the Ajtai commitment was not enforced. The bound must be **well below `q/2`** for
/// shortness — and hence binding — to hold.
///
/// Honest provers sample the mask `y` with coefficients in `[-Y_MASK_BOUND, Y_MASK_BOUND]`
/// (`1_000_000`) and short opening witnesses in `[-OPENING_WITNESS_BOUND, OPENING_WITNESS_BOUND]`
/// (`1_024`); see [`crate::sigma::opening`]. With a sparse ternary challenge of Hamming weight
/// `τ = 39`, the honest response is bounded by
/// `||z||_inf ≤ Y_MASK_BOUND + τ·OPENING_WITNESS_BOUND = 1_000_000 + 39·1_024 = 1_039_936`,
/// and at most `≈ 1_079_872` for aggregated (user+blind) openings. We set the frozen bound to
/// `1_500_000`, which leaves a comfortable completeness margin while staying at roughly `0.36·(q/2)`
/// — safely short for Module-SIS binding.
pub const V0_Z_INF_BOUND: i32 = 1_500_000;

/// Wire format major version carried in every `lattice_zkp_wire_v0` envelope.
pub const LATTICE_ZKP_WIRE_VERSION_V0: u8 = 0;

/// Private-membership (PVTN) proof wire budget.
pub const WIRE_BUDGET_PVTN_MEMBERSHIP_BYTES: usize = 4_096;

/// Presentation / anonymous token spend wire budget (125 KiB).
pub const WIRE_BUDGET_PRESENTATION_BYTES: usize = 125 * 1024;

/// Presentation proof hard cap (160 KiB).
pub const WIRE_BUDGET_PRESENTATION_HARD_CAP_BYTES: usize = 160 * 1024;

/// Profile id: PVTN private membership (compact geometry, depth-capped Merkle).
pub const PROFILE_ID_PVTN_MEMBERSHIP_V0: u8 = 1;

/// Profile id: anonymous token spend / rate-limit token.
pub const PROFILE_ID_TOKEN_SPEND_V0: u8 = 2;

/// Profile id: selective-disclosure / multi-attribute presentation openings.
pub const PROFILE_ID_SELECTIVE_DISCLOSURE_V0: u8 = 3;

/// Bits per `R_q` coefficient on the wire (`ceil(log2 q)` for ML-DSA modulus).
pub const RQ_COEFF_PACK_BITS: u8 = 23;

/// Frozen public parameters for a lattice-ZKP wire profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LatticeZkpProfileV0 {
    /// Stable profile identifier on the wire.
    pub profile_id: u8,
    /// Human-readable label for docs and manifests.
    pub label: &'static str,
    /// Ajtai module geometry (`k`, `l`).
    pub ajtai: AjtaiParameters,
    /// Ring degree `n` (fixed at 256 for wire v0).
    pub ring_degree: usize,
    /// Modulus `q` (ML-DSA field).
    pub modulus: i32,
    /// Sparse challenge Hamming weight `tau` (FIPS 204 ternary ball).
    pub tau: usize,
    /// Infinity-norm abort bound `||z||_inf`.
    pub z_inf_bound: i32,
    /// Prover rejection-sampling attempt budget.
    pub max_prove_attempts: usize,
    /// Maximum Merkle authentication path depth on the wire.
    pub merkle_depth_cap: u8,
    /// Bit width for biased packing of bounded `z` coefficients.
    pub z_pack_bits: u8,
    /// Maximum encoded bytes for proofs under this profile.
    pub max_wire_bytes: usize,
}

impl LatticeZkpProfileV0 {
    /// Bit width for packing signed responses in `[-z_inf_bound, z_inf_bound]`.
    #[must_use]
    pub const fn z_pack_bits_for_bound(z_inf_bound: i32) -> u8 {
        let range = (z_inf_bound as u32).saturating_mul(2).saturating_add(1);
        let mut bits = 0u8;
        let mut v = range;
        while v > 0 {
            bits = bits.saturating_add(1);
            v >>= 1;
        }
        if bits == 0 { 1 } else { bits }
    }

    /// PVTN private membership: `k=1`, `l=1`, depth cap 16, wire cap 4096 B.
    #[must_use]
    pub const fn pvtn_membership_v0() -> Self {
        let z_inf_bound = V0_Z_INF_BOUND;
        Self {
            profile_id: PROFILE_ID_PVTN_MEMBERSHIP_V0,
            label: "lib-q-lattice-zkp/pvtn-membership/v0",
            ajtai: AjtaiParameters::new(1, 1),
            ring_degree: COEFFICIENTS_IN_RING_ELEMENT,
            modulus: FIELD_MODULUS,
            tau: 39,
            z_inf_bound,
            max_prove_attempts: 512,
            merkle_depth_cap: 16,
            z_pack_bits: Self::z_pack_bits_for_bound(z_inf_bound),
            max_wire_bytes: WIRE_BUDGET_PVTN_MEMBERSHIP_BYTES,
        }
    }

    /// Anonymous token spend: `k=2`, `l=1` (header in message poly), 125 KiB cap.
    #[must_use]
    pub const fn token_spend_v0() -> Self {
        let z_inf_bound = V0_Z_INF_BOUND;
        Self {
            profile_id: PROFILE_ID_TOKEN_SPEND_V0,
            label: "lib-q-lattice-zkp/token-spend/v0",
            ajtai: AjtaiParameters::new(2, 1),
            ring_degree: COEFFICIENTS_IN_RING_ELEMENT,
            modulus: FIELD_MODULUS,
            tau: 39,
            z_inf_bound,
            max_prove_attempts: 512,
            merkle_depth_cap: 0,
            z_pack_bits: Self::z_pack_bits_for_bound(z_inf_bound),
            max_wire_bytes: WIRE_BUDGET_PRESENTATION_BYTES,
        }
    }

    /// Selective-disclosure opening / amortised presentation attributes.
    #[must_use]
    pub const fn selective_disclosure_v0() -> Self {
        let z_inf_bound = V0_Z_INF_BOUND;
        Self {
            profile_id: PROFILE_ID_SELECTIVE_DISCLOSURE_V0,
            label: "lib-q-lattice-zkp/selective-disclosure/v0",
            ajtai: AjtaiParameters::new(2, 1),
            ring_degree: COEFFICIENTS_IN_RING_ELEMENT,
            modulus: FIELD_MODULUS,
            tau: 39,
            z_inf_bound,
            max_prove_attempts: 512,
            merkle_depth_cap: 0,
            z_pack_bits: Self::z_pack_bits_for_bound(z_inf_bound),
            max_wire_bytes: WIRE_BUDGET_PRESENTATION_BYTES,
        }
    }

    /// Resolve a profile id to the frozen v0 parameters.
    #[must_use]
    pub fn from_profile_id(id: u8) -> Option<Self> {
        match id {
            PROFILE_ID_PVTN_MEMBERSHIP_V0 => Some(Self::pvtn_membership_v0()),
            PROFILE_ID_TOKEN_SPEND_V0 => Some(Self::token_spend_v0()),
            PROFILE_ID_SELECTIVE_DISCLOSURE_V0 => Some(Self::selective_disclosure_v0()),
            _ => None,
        }
    }

    /// Expected `w` mask vector length (`k`).
    #[must_use]
    pub const fn mask_poly_count(&self) -> usize {
        self.ajtai.module_rank
    }

    /// Expected `z` response vector length (`k + l`).
    #[must_use]
    pub const fn witness_poly_count(&self) -> usize {
        self.ajtai.witness_len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_ids_are_distinct_and_roundtrip() {
        for id in [
            PROFILE_ID_PVTN_MEMBERSHIP_V0,
            PROFILE_ID_TOKEN_SPEND_V0,
            PROFILE_ID_SELECTIVE_DISCLOSURE_V0,
        ] {
            let p = LatticeZkpProfileV0::from_profile_id(id).expect("known id");
            assert_eq!(p.profile_id, id);
        }
        assert!(LatticeZkpProfileV0::from_profile_id(0xFF).is_none());
    }

    #[test]
    fn pvtn_geometry_is_smaller_than_token_spend() {
        let pvtn = LatticeZkpProfileV0::pvtn_membership_v0();
        let token = LatticeZkpProfileV0::token_spend_v0();
        assert!(pvtn.ajtai.witness_len() < token.ajtai.witness_len());
        assert_eq!(pvtn.max_wire_bytes, WIRE_BUDGET_PVTN_MEMBERSHIP_BYTES);
    }
}
