//! **Pilot transcript only — this is not a ring signature.**
//!
//! This module wires [`lib_q_prf`] Legendre and Gold PRFs into a Fiat–Shamir challenge over a
//! ring digest. Verification is defined only for a **known signer index**, and the verifier
//! model requires the ordered list to carry **raw PRF secret key encodings** for every member
//! ([`PilotPrfTranscriptMemberSecrets256`]). Anyone who obtains that list can evaluate the PRFs
//! and forge transcripts for any index.
//!
//! The canonical wire format and batch verification live in [`crate::dualring_prf`]; this module
//! keeps the historical `pilot_prf_transcript_*` names as type aliases and thin wrappers.
//! [`PilotPrfBatchItem256`] matches [`crate::dualring_prf::DualringPrfBatchItem256`].
//!
//! # Threat model
//!
//! - There is **no** signer anonymity toward parties who see the member list.
//! - There is **no** unforgeability toward parties who see the member list (keys are in the list).
//!
//! Use this surface only behind the `pilot-insecure-prf-transcript` feature for laboratory
//! wiring tests. Production ring-style authentication must use a construction that exposes only
//! true public material (for example the opening-based federation path elsewhere in this crate).

use lib_q_prf::{
    GoldKey256,
    LegendreKey256,
};
use rand_core::{
    CryptoRng,
    Rng,
};

pub type PilotPrfTranscriptError = crate::dualring_prf::DualringPrfError;
pub type PilotPrfTranscriptMemberSecrets256 = crate::dualring_prf::DualringPrfMemberSecrets256;
pub type PilotPrfTranscriptSignature256 = crate::dualring_prf::DualringPrfSignature256;
/// One batch entry: same layout as [`crate::dualring_prf::DualringPrfBatchItem256`].
pub type PilotPrfBatchItem256 = crate::dualring_prf::DualringPrfBatchItem256;

/// Domain-separated digest of the ordered member list (like [`crate::ring::federation_digest`]).
#[inline]
#[must_use]
pub fn pilot_prf_transcript_ring_digest(
    members: &[PilotPrfTranscriptMemberSecrets256],
) -> [u8; 32] {
    crate::dualring_prf::dualring_prf_ring_digest(members)
}

/// Sign using the pilot 256-bit safe-prime parameters bundled in [`lib_q_prf`].
#[inline]
#[must_use = "signature may be invalid if the Result is not checked"]
pub fn pilot_prf_transcript_sign_u256<R: Rng + CryptoRng>(
    rng: &mut R,
    ring: &[PilotPrfTranscriptMemberSecrets256],
    signer_index: usize,
    leg_key: &LegendreKey256,
    gold_key: &GoldKey256,
    message: &[u8],
) -> Result<PilotPrfTranscriptSignature256, PilotPrfTranscriptError> {
    crate::dualring_prf::dualring_prf_sign_u256(rng, ring, signer_index, leg_key, gold_key, message)
}

/// Verify for a known signer index (pilot profile).
#[inline]
#[must_use = "verification outcome must be checked"]
pub fn pilot_prf_transcript_verify_u256(
    ring: &[PilotPrfTranscriptMemberSecrets256],
    signer_index: usize,
    message: &[u8],
    sig: &PilotPrfTranscriptSignature256,
) -> Result<(), PilotPrfTranscriptError> {
    crate::dualring_prf::dualring_prf_verify_u256(ring, signer_index, message, sig)
}

/// Batch verification: independent messages per signature, shared ring.
///
/// Delegates to [`crate::dualring_prf::verify_dualring_prf_batch_u256`].
#[inline]
#[must_use = "batch verification outcome must be checked"]
pub fn pilot_prf_transcript_verify_batch_u256(
    ring: &[PilotPrfTranscriptMemberSecrets256],
    items: &[PilotPrfBatchItem256],
) -> Result<(), PilotPrfTranscriptError> {
    crate::dualring_prf::verify_dualring_prf_batch_u256(ring, items)
}
