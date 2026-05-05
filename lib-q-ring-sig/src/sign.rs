//! Federation signing: Fiat–Shamir opening proof with ring digest + message binding.

use alloc::vec::Vec;

use lib_q_lattice_zkp::error::ProofError;
use lib_q_lattice_zkp::{
    AjtaiCommitment,
    AjtaiCommitmentKey,
    AjtaiOpening,
    OpeningProof,
    prove_opening,
};
use rand_core::{
    CryptoRng,
    Rng,
};

use crate::ring::federation_digest;

/// Build the Fiat–Shamir context for [`sign_federation_message`].
#[must_use]
pub fn federation_signing_context(ring: &[AjtaiCommitment], message: &[u8]) -> Vec<u8> {
    let d = federation_digest(ring);
    let mut v = Vec::with_capacity(64 + message.len());
    v.extend_from_slice(b"lib-q-ring-sig/sign-v1");
    v.extend_from_slice(&d);
    v.push(0);
    v.extend_from_slice(message);
    v
}

/// Produce an opening proof for `member_com` binding `message` and the full `ring` digest.
#[allow(clippy::too_many_arguments)]
pub fn sign_federation_message<R: Rng + CryptoRng>(
    rng: &mut R,
    crs: &AjtaiCommitmentKey,
    member_opening: &AjtaiOpening,
    member_com: &AjtaiCommitment,
    ring: &[AjtaiCommitment],
    message: &[u8],
    tau: usize,
    z_inf_bound: i32,
    max_attempts: usize,
) -> Result<OpeningProof, ProofError> {
    let ctx = federation_signing_context(ring, message);
    prove_opening(
        rng,
        crs,
        member_opening,
        member_com,
        &ctx,
        tau,
        z_inf_bound,
        max_attempts,
    )
}
