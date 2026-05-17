//! DualRing-style PRF transcript over a ring digest (Legendre + Gold at one field point).
//!
//! # Role in this crate
//!
//! This module is the **canonical** implementation of the `lib-q-ring-sig/dualring-prf-v1` wire
//! labels and transcript layout. [`crate::pilot_insecure_prf_transcript`] keeps historical
//! `pilot_prf_transcript_*` names as type aliases and thin wrappers over the same code paths, so
//! digest values and signatures remain interoperable with earlier pilot vectors.
//!
//! # Security (laboratory profile)
//!
//! Verification assumes a **known signer index** and, in the shipped profile, an ordered member
//! list that carries **raw PRF secret key encodings** so the verifier can recompute PRF outputs.
//! This is **not** a ring signature and does **not** provide unforgeability or signer anonymity
//! toward parties who see that list. Enable only behind the `pilot-insecure-prf-transcript` Cargo
//! feature and read [`crate::pilot_insecure_prf_transcript`] for the full threat model.
//!
//! Single-item verification is **not** written to be constant-time across all rejection reasons
//! (different paths can perform different amounts of work). Batch verification
//! ([`verify_dualring_prf_batch_u256`]) is written so the **batch loop** never short-circuits on the
//! first failing index: each entry is processed, outcomes are folded with [`subtle::Choice`], and
//! the function returns one aggregate [`Result`]. That removes a **batch-position** timing signal
//! from stopping early; it does not by itself equalize per-item wall time across distinct failure
//! modes inside [`dualring_prf_verify_u256`].
//!
//! Challenge bytes are mapped to \(\mathbb{F}_p\) with [`crypto_bigint::U256::rem_vartime`]; that
//! step is transcript wiring, not a shared-secret comparison primitive.

use crypto_bigint::{
    CtEq,
    U256,
};
use lib_q_prf::{
    GoldKey256,
    GoldPrfParams256,
    LegendreKey256,
    LegendrePrfParams256,
    PrfError,
    gold_prf_u256,
    legendre_prf_u256,
    u256_from_le_bytes,
};
use lib_q_sha3::{
    ExtendableOutput,
    Update,
    XofReader,
};
use rand_core::{
    CryptoRng,
    Rng,
};
use subtle::Choice;

/// Errors for the DualRing PRF transcript layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DualringPrfError {
    /// Underlying PRF error (e.g. Legendre undefined point).
    Prf(PrfError),
    /// Format / indexing error.
    InvalidInput,
    /// Challenge or tag mismatch.
    Rejected,
}

impl From<PrfError> for DualringPrfError {
    fn from(e: PrfError) -> Self {
        DualringPrfError::Prf(e)
    }
}

/// Ordered ring entry: **secret** Legendre and Gold PRF key material (little-endian encodings).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DualringPrfMemberSecrets256 {
    /// Little-endian encoding of the Legendre PRF secret `K mod p`.
    pub legendre_key_le: [u8; 32],
    /// Little-endian encoding of the Gold PRF secret `k mod p`.
    pub gold_key_le: [u8; 32],
}

/// Signature blob: commitment–challenge–response tags at a single field point `x(challenge)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DualringPrfSignature256 {
    /// Random commitment absorbed into Fiat–Shamir.
    pub commitment: [u8; 32],
    /// Fiat–Shamir challenge digest.
    pub challenge: [u8; 32],
    /// Legendre PRF output in `{-1,0,1}`.
    pub legendre_out: i8,
    /// Gold PRF output (little-endian canonical residue).
    pub gold_out: [u8; 32],
}

/// One batch verification entry: message bytes, signer index into `ring`, and transcript blob.
///
/// All entries in a batch share the same `ring` slice passed to [`verify_dualring_prf_batch_u256`].
pub type DualringPrfBatchItem256 = (Vec<u8>, usize, DualringPrfSignature256);

// Stable domain labels for wire/interoperability with earlier pilot vectors.
const FS_LABEL: &[u8] = b"lib-q-ring-sig/dualring-prf-v1";
const RING_LABEL: &[u8] = b"lib-q-ring-sig/dualring-prf-ring-v1";

/// Domain-separated digest of the ordered member list (like [`crate::ring::federation_digest`]).
#[must_use]
pub fn dualring_prf_ring_digest(members: &[DualringPrfMemberSecrets256]) -> [u8; 32] {
    let mut h = lib_q_sha3::Shake256::default();
    h.update(RING_LABEL);
    h.update(&(members.len() as u64).to_le_bytes());
    for m in members {
        h.update(&m.legendre_key_le);
        h.update(&m.gold_key_le);
    }
    let mut out = [0u8; 32];
    let mut r = h.finalize_xof();
    XofReader::read(&mut r, &mut out);
    out
}

fn fs_challenge(ring_digest: &[u8; 32], message: &[u8], commitment: &[u8; 32]) -> [u8; 32] {
    let mut h = lib_q_sha3::Shake256::default();
    h.update(FS_LABEL);
    h.update(ring_digest);
    h.update(&(message.len() as u64).to_le_bytes());
    h.update(message);
    h.update(commitment);
    let mut out = [0u8; 32];
    let mut r = h.finalize_xof();
    XofReader::read(&mut r, &mut out);
    out
}

fn challenge_to_field_x(challenge: &[u8; 32], leg_params: &LegendrePrfParams256) -> U256 {
    let x = U256::from_le_slice(challenge.as_slice());
    x.rem_vartime(&leg_params.p)
}

/// Sign using the pilot 256-bit safe-prime parameters bundled in [`lib_q_prf`].
#[must_use = "signature may be invalid if the Result is not checked"]
#[allow(clippy::too_many_lines)]
pub fn dualring_prf_sign_u256<R: Rng + CryptoRng>(
    rng: &mut R,
    ring: &[DualringPrfMemberSecrets256],
    signer_index: usize,
    leg_key: &LegendreKey256,
    gold_key: &GoldKey256,
    message: &[u8],
) -> Result<DualringPrfSignature256, DualringPrfError> {
    let member = ring
        .get(signer_index)
        .ok_or(DualringPrfError::InvalidInput)?;
    let leg_params = LegendrePrfParams256::pilot();
    let gold_params = GoldPrfParams256::pilot();

    let pk_leg =
        LegendreKey256::from_uint(u256_from_le_bytes(&member.legendre_key_le), &leg_params)
            .map_err(|_| DualringPrfError::InvalidInput)?;
    let pk_gold = GoldKey256::from_uint(u256_from_le_bytes(&member.gold_key_le), &gold_params)
        .map_err(|_| DualringPrfError::InvalidInput)?;

    if !bool::from(leg_key.as_uint().ct_eq(pk_leg.as_uint())) ||
        !bool::from(gold_key.as_uint().ct_eq(pk_gold.as_uint()))
    {
        return Err(DualringPrfError::InvalidInput);
    }

    let mut commitment = [0u8; 32];
    rng.fill_bytes(&mut commitment);

    let ring_digest = dualring_prf_ring_digest(ring);
    let challenge = fs_challenge(&ring_digest, message, &commitment);
    let x = challenge_to_field_x(&challenge, &leg_params);

    let legendre_out = legendre_prf_u256(leg_key, &x, &leg_params)?;
    let gold_out = gold_prf_u256(gold_key, &x, &gold_params)?;

    Ok(DualringPrfSignature256 {
        commitment,
        challenge,
        legendre_out,
        gold_out,
    })
}

/// Verify for a known signer index (pilot safe-prime profile in [`lib_q_prf`]).
#[must_use = "verification outcome must be checked"]
pub fn dualring_prf_verify_u256(
    ring: &[DualringPrfMemberSecrets256],
    signer_index: usize,
    message: &[u8],
    sig: &DualringPrfSignature256,
) -> Result<(), DualringPrfError> {
    let member = ring
        .get(signer_index)
        .ok_or(DualringPrfError::InvalidInput)?;
    let leg_params = LegendrePrfParams256::pilot();
    let gold_params = GoldPrfParams256::pilot();

    let leg_k = LegendreKey256::from_uint(u256_from_le_bytes(&member.legendre_key_le), &leg_params)
        .map_err(|_| DualringPrfError::InvalidInput)?;
    let gold_k = GoldKey256::from_uint(u256_from_le_bytes(&member.gold_key_le), &gold_params)
        .map_err(|_| DualringPrfError::InvalidInput)?;

    let ring_digest = dualring_prf_ring_digest(ring);
    let expected_chal = fs_challenge(&ring_digest, message, &sig.commitment);
    if expected_chal != sig.challenge {
        return Err(DualringPrfError::Rejected);
    }

    let x = challenge_to_field_x(&sig.challenge, &leg_params);

    let leg = legendre_prf_u256(&leg_k, &x, &leg_params)?;
    let gld = gold_prf_u256(&gold_k, &x, &gold_params)?;

    if leg != sig.legendre_out || gld != sig.gold_out {
        return Err(DualringPrfError::Rejected);
    }
    Ok(())
}

/// Batch verification: independent messages per signature, shared ring.
///
/// Every item is verified (no short-circuit on the first failure). An empty `items` slice verifies
/// successfully (vacuous truth). The aggregate result is success only if all items succeed;
/// otherwise this returns [`DualringPrfError::Rejected`],
/// avoiding a timing signal correlated with which batch index failed first. Per-item failures
/// that would surface as [`DualringPrfError::Prf`] or [`DualringPrfError::InvalidInput`]
/// in single-item verify are folded into that aggregate [`Rejected`] outcome.
#[must_use = "batch verification outcome must be checked"]
pub fn verify_dualring_prf_batch_u256(
    ring: &[DualringPrfMemberSecrets256],
    items: &[DualringPrfBatchItem256],
) -> Result<(), DualringPrfError> {
    let mut all_ok = Choice::from(1u8);
    for (msg, idx, sig) in items {
        let item_ok = match dualring_prf_verify_u256(ring, *idx, msg, sig) {
            Ok(()) => Choice::from(1u8),
            Err(_) => Choice::from(0u8),
        };
        all_ok &= item_ok;
    }
    if bool::from(all_ok) {
        Ok(())
    } else {
        Err(DualringPrfError::Rejected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_digest_order_sensitive() {
        let a = DualringPrfMemberSecrets256 {
            legendre_key_le: [1u8; 32],
            gold_key_le: [2u8; 32],
        };
        let b = DualringPrfMemberSecrets256 {
            legendre_key_le: [3u8; 32],
            gold_key_le: [4u8; 32],
        };
        assert_ne!(
            dualring_prf_ring_digest(&[a.clone(), b.clone()]),
            dualring_prf_ring_digest(&[b, a]),
        );
    }

    #[test]
    fn ring_digest_len_encoded() {
        let m = DualringPrfMemberSecrets256 {
            legendre_key_le: [0u8; 32],
            gold_key_le: [0u8; 32],
        };
        assert_ne!(
            dualring_prf_ring_digest(core::slice::from_ref(&m)),
            dualring_prf_ring_digest(&[m.clone(), m]),
        );
    }
}
