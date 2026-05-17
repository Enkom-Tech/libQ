//! Verification for federation opening proofs.

use lib_q_lattice_zkp::{
    AjtaiCommitment,
    AjtaiCommitmentKey,
    OpeningProof,
    VerifyError,
    verify_opening,
};

use crate::sign::federation_signing_context;

/// Verify an opening proof for a known signer index.
pub fn verify_federation_opening(
    crs: &AjtaiCommitmentKey,
    ring: &[AjtaiCommitment],
    signer_index: usize,
    message: &[u8],
    proof: &OpeningProof,
    tau: usize,
    z_inf_bound: i32,
) -> Result<(), VerifyError> {
    let com = ring.get(signer_index).ok_or(VerifyError::InvalidFormat)?;
    let ctx = federation_signing_context(ring, message);
    verify_opening(crs, com, proof, &ctx, tau, z_inf_bound)
}

/// Try every ring position until one verifies (not constant-time; reveals signer to verifier).
pub fn verify_federation_opening_scan(
    crs: &AjtaiCommitmentKey,
    ring: &[AjtaiCommitment],
    message: &[u8],
    proof: &OpeningProof,
    tau: usize,
    z_inf_bound: i32,
) -> Result<usize, VerifyError> {
    for i in 0..ring.len() {
        if verify_federation_opening(crs, ring, i, message, proof, tau, z_inf_bound).is_ok() {
            return Ok(i);
        }
    }
    Err(VerifyError::Rejected)
}
