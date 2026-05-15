//! Deterministic workloads for TVLA/timing harnesses over privacy-protocol code paths.
//!
//! Call these inside `sample_wall_times` / dudect-style drivers; this module does not
//! assert statistical leakage bounds. Each helper exercises a single constant-time-critical
//! path with caller-prepared inputs so timing samples can be attributed to the inner
//! call rather than to setup work.

use lib_q_lattice_zkp::{
    AjtaiCommitment,
    AjtaiCommitmentKey,
    AjtaiOpening,
    BlindIssuance,
    BlindSignature,
    OpeningProof,
    PrivateMembershipProof,
    UnblindedBlindSignature,
    UnblindedIssuance,
    VerifyError,
    registry_nullifier,
    verify_private_membership,
    witness_nullifier,
};
use lib_q_ring_sig::{
    DualRingLbSignature,
    federation_digest,
    verify_dualring_lb,
    verify_federation_opening,
};

/// Registry nullifier derivation (SHAKE256 over commitment wire || realm).
#[must_use]
pub fn touch_nullifier(com: &AjtaiCommitment, realm: &[u8]) -> [u8; 32] {
    registry_nullifier(com, realm)
}

/// Federation ring digest (SHAKE256 over ordered commitments).
#[must_use]
pub fn touch_federation_digest(ring: &[AjtaiCommitment]) -> [u8; 32] {
    federation_digest(ring)
}

/// Blind issuance bundle verification (Fiat-Shamir hot path).
///
/// Drives the verifier-side transcript recomputation and opening checks; the prover-side
/// rejection sampling lives in `BlindIssuance::request` / `issuer_sign` and is **not**
/// constant-time-critical.
pub fn touch_blind_verify(
    key: &AjtaiCommitmentKey,
    bundle: &UnblindedIssuance,
    base_ctx: &[u8],
    tau: usize,
    z_inf_bound: i32,
) -> Result<(), VerifyError> {
    BlindIssuance::verify(key, bundle, base_ctx, tau, z_inf_bound)
}

/// Federation opening verification at a fixed signer index.
///
/// `sign_federation_message` itself uses rejection sampling and is unsuitable for
/// TVLA screening; the verifier path here is the constant-time target.
#[allow(clippy::too_many_arguments)]
pub fn touch_federation_verify(
    key: &AjtaiCommitmentKey,
    ring: &[AjtaiCommitment],
    signer_index: usize,
    msg: &[u8],
    proof: &OpeningProof,
    tau: usize,
    z_inf_bound: i32,
) -> Result<(), VerifyError> {
    verify_federation_opening(key, ring, signer_index, msg, proof, tau, z_inf_bound)
}

/// DualRing-LB pilot: aggregated opening verification (CCS 2021 Alg. 3 on Ajtai relation).
#[allow(clippy::too_many_arguments)]
pub fn touch_dualring_lb_verify(
    key: &AjtaiCommitmentKey,
    ring: &[AjtaiCommitment],
    msg: &[u8],
    sig: &DualRingLbSignature,
    tau: usize,
    z_inf_bound: i32,
) -> Result<(), VerifyError> {
    verify_dualring_lb(key, ring, msg, sig, tau, z_inf_bound)
}

/// Witness-derived nullifier (secret-dependent wire hash).
#[must_use]
pub fn touch_witness_nullifier(opening: &AjtaiOpening, realm: &[u8]) -> [u8; 32] {
    witness_nullifier(opening, realm)
}

/// Pilot blind-signature bundle verification ([`BlindSignature::verify_blind_signature`]).
pub fn touch_blind_signature_verify(
    key: &AjtaiCommitmentKey,
    bundle: &UnblindedBlindSignature,
    base_ctx: &[u8],
    tau: usize,
    z_inf_bound: i32,
) -> Result<(), VerifyError> {
    bundle.verify_blind_signature(key, base_ctx, tau, z_inf_bound)
}

/// Private Merkle membership pilot verifier.
#[allow(clippy::too_many_arguments)]
pub fn touch_private_membership(
    key: &AjtaiCommitmentKey,
    proof: &PrivateMembershipProof,
    tree_root: &[u8; 32],
    min_clearance: u32,
    opening_base_ctx: &[u8],
    tau: usize,
    z_inf_bound: i32,
) -> Result<(), VerifyError> {
    verify_private_membership(
        key,
        proof,
        tree_root,
        min_clearance,
        opening_base_ctx,
        tau,
        z_inf_bound,
    )
}
