//! Bind attribute openings to ring signatures (DualRing-LB transcript by default).

use alloc::vec::Vec;

use lib_q_lattice_zkp::serialize::write_module_vec;
use lib_q_lattice_zkp::{
    AjtaiCommitment,
    AjtaiCommitmentKey,
    OpeningProof,
    VerifyError,
    leaf_hash,
    verify_opening,
};

use crate::dualring_lb::{
    DualRingLbSignature,
    dualring_lb_signing_context,
    verify_dualring_lb,
};
use crate::sign::federation_signing_context;
#[cfg(feature = "federation-opening")]
use crate::verify::verify_federation_opening_scan;

/// 32-byte message digest for federation signing, derived from the attribute commitment.
#[must_use]
pub fn attribute_message_digest(com: &AjtaiCommitment) -> [u8; 32] {
    leaf_hash(&write_module_vec(&com.value.0))
}

/// Holder presentation: attribute opening + DualRing-LB-style ring signature over
/// [`attribute_message_digest`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialPresentation {
    pub attribute_commitment: AjtaiCommitment,
    pub attribute_opening_proof: OpeningProof,
    pub ring_signature: DualRingLbSignature,
}

/// Verify attribute proof and ring signature for some member of `ring`.
pub fn verify_credential_presentation(
    crs: &AjtaiCommitmentKey,
    ring: &[AjtaiCommitment],
    pres: &CredentialPresentation,
    attribute_fs_ctx: &[u8],
    tau: usize,
    z_inf_bound: i32,
) -> Result<(), VerifyError> {
    verify_opening(
        crs,
        &pres.attribute_commitment,
        &pres.attribute_opening_proof,
        attribute_fs_ctx,
        tau,
        z_inf_bound,
    )?;
    let msg = attribute_message_digest(&pres.attribute_commitment);
    verify_dualring_lb(crs, ring, &msg, &pres.ring_signature, tau, z_inf_bound)
}

/// Legacy scan-based verifier (linear cost; reveals signer index to a timing observer).
///
/// Enabled with the `federation-opening` Cargo feature for backward compatibility with
/// deployments that still issue bare [`OpeningProof`] values under
/// [`crate::sign::federation_signing_context`].
#[cfg(feature = "federation-opening")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialPresentationFederationOpening {
    pub attribute_commitment: AjtaiCommitment,
    pub attribute_opening_proof: OpeningProof,
    pub federation_proof: OpeningProof,
}

/// Verify a legacy federation presentation using [`verify_federation_opening_scan`].
#[cfg(feature = "federation-opening")]
pub fn verify_credential_presentation_federation_opening(
    crs: &AjtaiCommitmentKey,
    ring: &[AjtaiCommitment],
    pres: &CredentialPresentationFederationOpening,
    attribute_fs_ctx: &[u8],
    tau: usize,
    z_inf_bound: i32,
) -> Result<(), VerifyError> {
    verify_opening(
        crs,
        &pres.attribute_commitment,
        &pres.attribute_opening_proof,
        attribute_fs_ctx,
        tau,
        z_inf_bound,
    )?;
    let msg = attribute_message_digest(&pres.attribute_commitment);
    verify_federation_opening_scan(crs, ring, &msg, &pres.federation_proof, tau, z_inf_bound)
        .map(|_| ())
}

/// Build the federation FS context explicitly (for tests comparing to [`federation_signing_context`]).
#[must_use]
pub fn federation_context_for_attributes(
    ring: &[AjtaiCommitment],
    attribute_com: &AjtaiCommitment,
) -> Vec<u8> {
    let msg = attribute_message_digest(attribute_com);
    federation_signing_context(ring, &msg)
}

/// DualRing-LB transcript bytes for attribute-bound signing.
#[must_use]
pub fn dualring_context_for_attributes(
    ring: &[AjtaiCommitment],
    attribute_com: &AjtaiCommitment,
) -> Vec<u8> {
    let msg = attribute_message_digest(attribute_com);
    dualring_lb_signing_context(ring, &msg)
}
