//! Fiat–Shamir sigma protocols over module-SIS/Ajtai commitments.

pub mod amortise;
pub mod hierarchical;
pub mod linear;
pub mod norm;
pub mod opening;
pub mod uniqueness;

pub use amortise::{
    AmortisedProof,
    BatchPresentationState,
    aggregate_proofs,
    amortise,
    verify_aggregate,
};
pub use hierarchical::{
    HierarchicalAuthProof,
    MerklePath,
    PVTN_CLEARANCE_MARGIN_NORM_BETA,
    PrivateMembershipProof,
    encode_pvtn_leaf,
    hierarchical_opening_ctx,
    leaf_clearance_level,
    leaf_hash,
    node_hash,
    private_membership_opening_ctx,
    prove_level_membership,
    prove_private_membership,
    verify_hierarchical_membership,
    verify_level_membership,
    verify_merkle_path,
    verify_private_membership,
};
pub use linear::{
    LinearRelationProof,
    prove_linear,
    verify_linear,
};
pub use norm::{
    CrtPackedNormProof,
    prove_inf_norm,
    verify_inf_norm,
    verify_inf_norm_proof,
};
pub use opening::{
    DualRingOpeningProof,
    OpeningProof,
    prove_dual_ring_opening,
    prove_opening,
    verify_dual_ring_opening,
    verify_opening,
};
pub use uniqueness::{
    NullifierOpeningProof,
    WitnessNullifierOpeningProof,
    opening_ctx_with_nullifier,
    opening_ctx_with_witness_nullifier,
    prove_nullifier_opening,
    prove_witness_nullifier_opening,
    registry_nullifier,
    uniqueness_amortisation_label,
    verify_nullifier_opening,
    verify_witness_nullifier_opening,
    witness_nullifier,
    witness_uniqueness_amortisation_label,
    witness_wire,
};
