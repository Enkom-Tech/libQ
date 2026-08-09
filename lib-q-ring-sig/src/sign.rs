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
///
/// The message is length-prefixed (a little-endian `u64` count immediately before the bytes) so
/// this context is self-delimiting even when a caller appends further fields after it — see
/// card t_f0d676d1 / finding F25, which found that an *unprefixed* trailing message let
/// [`crate::dualring_lb::dualring_lb_signing_context`] (which used to be built by appending bytes
/// directly after this function's output) be made byte-identical to a *different*
/// `(ring, message)` framing by choosing a message that swallows the appended suffix. The length
/// prefix here is defense-in-depth for this function; the primary fix is that
/// `dualring_lb_signing_context` no longer uses this function's raw output as a byte prefix (it
/// hashes it first).
#[must_use]
pub fn federation_signing_context(ring: &[AjtaiCommitment], message: &[u8]) -> Vec<u8> {
    let d = federation_digest(ring);
    let mut v = Vec::with_capacity(64 + message.len());
    v.extend_from_slice(b"lib-q-ring-sig/sign-v1");
    v.extend_from_slice(&d);
    v.push(0);
    v.extend_from_slice(&(message.len() as u64).to_le_bytes());
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
