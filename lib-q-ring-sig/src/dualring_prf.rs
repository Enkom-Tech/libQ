//! DualRing-PRF **pilot** transcript: Fiat–Shamir binding of Legendre and Gold PRF outputs to a ring digest.
//!
//! This module is **not** a complete anonymous ring signature in the sense of Beullens et al.; it
//! wires [`lib_q_prf`] primitives into a domain-separated challenge and a **signer-index-known**
//! verification path (analogous to [`verify::verify_federation_opening`]). Hiding the signer index
//! requires the full dual-ring lattice construction; that integration is tracked in [`DESIGN.md`].
//!
//! # Pilot security warning
//!
//! [`DualRingPrfMemberPublic256`] embeds raw field key material so verifiers can recompute PRF
//! outputs. This **does not** provide confidentiality of keys and is intended for interoperability
//! testing only.

use alloc::vec::Vec;

use crypto_bigint::{
    CtEq,
    NonZero,
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

/// Errors for the pilot DualRing-PRF transcript layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DualRingPrfError {
    /// Underlying PRF error (e.g. Legendre undefined point).
    Prf(PrfError),
    /// Format / indexing error.
    InvalidInput,
    /// Challenge or tag mismatch.
    Rejected,
}

impl From<PrfError> for DualRingPrfError {
    fn from(e: PrfError) -> Self {
        DualRingPrfError::Prf(e)
    }
}

/// Public ring entry: **pilot** encoding of PRF keys (see module docs).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DualRingPrfMemberPublic256 {
    /// Little-endian encoding of `K mod p` (Legendre PRF key).
    pub legendre_key_le: [u8; 32],
    /// Little-endian encoding of `k mod p` (Gold PRF key).
    pub gold_key_le: [u8; 32],
}

/// Pilot signature blob: commitment–challenge–response tags at a single field point `x(challenge)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DualRingPrfSignature256 {
    /// Random commitment absorbed into Fiat–Shamir.
    pub commitment: [u8; 32],
    /// Fiat–Shamir challenge digest.
    pub challenge: [u8; 32],
    /// Legendre PRF output in `{-1,0,1}`.
    pub legendre_out: i8,
    /// Gold PRF output (little-endian canonical residue).
    pub gold_out: [u8; 32],
}

const FS_LABEL: &[u8] = b"lib-q-ring-sig/dualring-prf-v1";
const RING_LABEL: &[u8] = b"lib-q-ring-sig/dualring-prf-ring-v1";

/// Domain-separated digest of the ordered public ring (like [`crate::ring::federation_digest`]).
#[must_use]
pub fn dualring_prf_ring_digest(members: &[DualRingPrfMemberPublic256]) -> [u8; 32] {
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
    let nz = NonZero::new(leg_params.p)
        .into_option()
        .expect("pilot modulus");
    x.rem_vartime(&nz)
}

/// Sign using the pilot 256-bit safe-prime parameters bundled in [`lib_q_prf`].
#[allow(clippy::too_many_lines)]
pub fn sign_dualring_prf_u256<R: Rng + CryptoRng>(
    rng: &mut R,
    ring: &[DualRingPrfMemberPublic256],
    signer_index: usize,
    leg_key: &LegendreKey256,
    gold_key: &GoldKey256,
    message: &[u8],
) -> Result<DualRingPrfSignature256, DualRingPrfError> {
    let member = ring
        .get(signer_index)
        .ok_or(DualRingPrfError::InvalidInput)?;
    let leg_params = LegendrePrfParams256::pilot();
    let gold_params = GoldPrfParams256::pilot();

    let pk_leg =
        LegendreKey256::from_uint(u256_from_le_bytes(&member.legendre_key_le), &leg_params)
            .map_err(|_| DualRingPrfError::InvalidInput)?;
    let pk_gold = GoldKey256::from_uint(u256_from_le_bytes(&member.gold_key_le), &gold_params)
        .map_err(|_| DualRingPrfError::InvalidInput)?;

    if !bool::from(leg_key.k.ct_eq(&pk_leg.k)) || !bool::from(gold_key.k.ct_eq(&pk_gold.k)) {
        return Err(DualRingPrfError::InvalidInput);
    }

    let mut commitment = [0u8; 32];
    rng.fill_bytes(&mut commitment);

    let ring_digest = dualring_prf_ring_digest(ring);
    let challenge = fs_challenge(&ring_digest, message, &commitment);
    let x = challenge_to_field_x(&challenge, &leg_params);

    let legendre_out = legendre_prf_u256(leg_key, &x, &leg_params)?;
    let gold_out = gold_prf_u256(gold_key, &x, &gold_params)?;

    Ok(DualRingPrfSignature256 {
        commitment,
        challenge,
        legendre_out,
        gold_out,
    })
}

/// Verify for a known signer index (pilot profile).
pub fn verify_dualring_prf_u256(
    ring: &[DualRingPrfMemberPublic256],
    signer_index: usize,
    message: &[u8],
    sig: &DualRingPrfSignature256,
) -> Result<(), DualRingPrfError> {
    let member = ring
        .get(signer_index)
        .ok_or(DualRingPrfError::InvalidInput)?;
    let leg_params = LegendrePrfParams256::pilot();
    let gold_params = GoldPrfParams256::pilot();

    let leg_k = LegendreKey256::from_uint(u256_from_le_bytes(&member.legendre_key_le), &leg_params)
        .map_err(|_| DualRingPrfError::InvalidInput)?;
    let gold_k = GoldKey256::from_uint(u256_from_le_bytes(&member.gold_key_le), &gold_params)
        .map_err(|_| DualRingPrfError::InvalidInput)?;

    let ring_digest = dualring_prf_ring_digest(ring);
    let expected_chal = fs_challenge(&ring_digest, message, &sig.commitment);
    if expected_chal != sig.challenge {
        return Err(DualRingPrfError::Rejected);
    }

    let x = challenge_to_field_x(&sig.challenge, &leg_params);

    let leg = legendre_prf_u256(&leg_k, &x, &leg_params)?;
    let gld = gold_prf_u256(&gold_k, &x, &gold_params)?;

    if leg != sig.legendre_out || gld != sig.gold_out {
        return Err(DualRingPrfError::Rejected);
    }
    Ok(())
}

/// Batch verification: independent messages per signature, shared ring.
pub fn verify_dualring_prf_batch_u256(
    ring: &[DualRingPrfMemberPublic256],
    items: &[(Vec<u8>, usize, DualRingPrfSignature256)],
) -> Result<(), DualRingPrfError> {
    for (msg, idx, sig) in items {
        verify_dualring_prf_u256(ring, *idx, msg, sig)?;
    }
    Ok(())
}
