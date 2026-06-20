//! `lib-q-threshold-raccoon` — a PROVISIONAL post-quantum **lattice threshold signature** whose
//! signing key is exactly the output of `lib-q-dkg`'s dealerless DKG.
//!
//! The group key is a BDLOP commitment `T = commit(s; r)` to a **short** secret `s` (the DKG's
//! reconstructed group secret); a signature is a Fiat–Shamir proof of knowledge of the short opening
//! `(s, r)` (see [`signer`]). Unforgeability reduces to BDLOP binding + Module-LWE.
//!
//! This crate is **co-designed** with `lib-q-dkg`: a [`SecretShare`] here is byte-identical to a
//! `lib_q_dkg::SigningShare`, and [`keygen_shares`] (a centralized trusted-dealer reference) produces
//! the same share format as `lib_q_dkg::dkg_run_honest`. So the DKG is a drop-in dealerless keygen
//! for this signer — closing the field-mismatch gap with the GF(256) `lib-q-threshold-sig`. The
//! production target replaces that GF(256) placeholder for PQ root/recovery keys.
//!
//! **Scope (research-grade):** the threshold *combine* ([`combine_opening`]) is a caller-side
//! Lagrange sum; a fully threshold-native distributed signing round (Threshold-Raccoon: additive
//! sharing + clearing factor) is the documented next phase. See `LIBQ_API.md` §7.

#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

use lib_q_dkg::lattice::bdlop::{
    self,
    Commitment,
    KAPPA,
    MU,
};
use lib_q_dkg::lattice::ring::{
    RQ_BYTES,
    Rq,
    ring_add,
    rq_from_le_bytes,
    rq_to_le_bytes,
    sample_secret_poly,
    sample_uniform_poly,
    scalar_mul,
};
use rand_core::{
    CryptoRng,
    Rng,
};
use zeroize::Zeroizing;

pub mod error;
pub mod profile;
pub mod signer;
pub mod threshold;
pub mod wire;

pub use error::RaccoonError;
pub use profile::{
    PROFILE_ID_V1,
    PROFILE_MAX_PARTIES_V1,
    ThresholdRaccoonProfileV1,
    setup,
};
pub use signer::{
    MAX_SIGNATURES_PER_KEY,
    Signature,
    sign as sign_raw,
    verify as verify_raw,
};
pub use wire::{
    WIRE_BUDGET_SIGNATURE_BYTES,
    WIRE_VERSION_V1,
    decode_signature,
    encode_signature,
};

#[cfg(feature = "wasm")]
pub mod wasm;

/// Gaussian width for the secret key (matches `lib-q-dkg`'s `SECRET_KEY_WIDTH`).
pub const SECRET_KEY_WIDTH: f64 = 8.0;

/// Per-party verification key (the public BDLOP commitment to the party's share, serialized).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShareVerifier {
    /// Party index `1..=n`.
    pub index: u8,
    /// Serialized commitment image (`MU` `t0` elements followed by `t1`).
    pub verifying_key: Vec<u8>,
}

/// The threshold public key: group key (commitment to the secret) + per-party verification keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThresholdRaccoonPublicKey {
    /// Reconstruction threshold `t`.
    pub threshold: u8,
    /// Serialized group commitment `T = commit(s; r)`.
    pub group_key: Vec<u8>,
    /// Per-party verification keys.
    pub share_verifiers: Vec<ShareVerifier>,
}

/// A signing share — byte-identical to `lib_q_dkg::SigningShare` (`share_bytes = value ‖ rand`).
#[derive(Clone)]
pub struct SecretShare {
    /// Party index `1..=n`.
    pub index: u8,
    /// Reconstruction threshold `t`.
    pub threshold: u8,
    /// Canonical encoding of `value ‖ rand` (`1 + KAPPA` `R_q` elements).
    pub share_bytes: Zeroizing<Vec<u8>>,
}

/// Output of [`keygen_shares`]: shape mirrors `lib_q_dkg::KeygenSharesOutput`.
#[derive(Clone)]
pub struct KeygenSharesOutput {
    /// The threshold public key.
    pub public_key: ThresholdRaccoonPublicKey,
    /// One signing share per party.
    pub secret_shares: Vec<SecretShare>,
}

/// Centralized trusted-dealer keygen (reference path; `lib_q_dkg::dkg_run_honest` is the dealerless
/// equivalent producing the same share format).
pub fn keygen_shares<R: CryptoRng + Rng>(
    profile: &ThresholdRaccoonProfileV1,
    threshold: u8,
    parties: u8,
    rng: &mut R,
) -> Result<KeygenSharesOutput, RaccoonError> {
    if profile.id != PROFILE_ID_V1 || profile.max_parties != PROFILE_MAX_PARTIES_V1 {
        return Err(RaccoonError::InvalidProfile);
    }
    if parties == 0 || parties > PROFILE_MAX_PARTIES_V1 {
        return Err(RaccoonError::InvalidShareCount);
    }
    if threshold == 0 || threshold > parties {
        return Err(RaccoonError::InvalidThreshold);
    }
    let key = bdlop::key();
    let t = usize::from(threshold);

    // Sharing polynomial: short secret constant term, uniform blinding, ternary commit randomness.
    let mut coeffs = Vec::with_capacity(t);
    let mut rho = Vec::with_capacity(t);
    let mut commitments = Vec::with_capacity(t);
    for i in 0..t {
        let a = if i == 0 {
            // Constant-time CDT sampler at the fixed secret width (lib_q_dkg::lattice::gaussian).
            sample_secret_poly(rng)
        } else {
            sample_uniform_poly(rng)
        };
        let r = bdlop::sample_randomness(rng);
        commitments.push(bdlop::commit(key, &a, &r));
        coeffs.push(a);
        rho.push(r);
    }

    let mut secret_shares = Vec::with_capacity(usize::from(parties));
    for j in 1..=parties {
        let (value, rand) = eval_poly(&coeffs, &rho, j);
        secret_shares.push(SecretShare {
            index: j,
            threshold,
            share_bytes: Zeroizing::new(encode_value_rand(&value, &rand)),
        });
    }

    let share_verifiers = (1..=parties)
        .map(|j| ShareVerifier {
            index: j,
            verifying_key: encode_commitment(&bdlop::eval_commitments(&commitments, j)),
        })
        .collect();

    Ok(KeygenSharesOutput {
        public_key: ThresholdRaccoonPublicKey {
            threshold,
            group_key: encode_commitment(&commitments[0]),
            share_verifiers,
        },
        secret_shares,
    })
}

/// Recover the short signing opening `(s, r)` from a threshold subset of shares (Lagrange at zero).
///
/// The provided `shares` define the reconstruction subset (`≥ threshold` distinct indices).
pub fn combine_opening(shares: &[SecretShare]) -> Result<(Rq, [Rq; KAPPA]), RaccoonError> {
    let first = shares.first().ok_or(RaccoonError::InvalidSignerSet)?;
    let threshold = first.threshold;
    if shares.len() < usize::from(threshold) {
        return Err(RaccoonError::InvalidSignerSet);
    }
    let subset: Vec<u8> = shares.iter().map(|s| s.index).collect();
    let mut s = Rq::zero();
    let mut r: Vec<Rq> = (0..KAPPA).map(|_| Rq::zero()).collect();
    for sh in shares {
        let lam = lib_q_dkg::lagrange_coeff_at_zero(&subset, sh.index)
            .map_err(|_| RaccoonError::InvalidSignerSet)?;
        let (value, rand) = decode_value_rand(&sh.share_bytes)?;
        s = ring_add(&s, &scalar_mul(&value, lam));
        for (acc, ri) in r.iter_mut().zip(rand.iter()) {
            *acc = ring_add(acc, &scalar_mul(ri, lam));
        }
    }
    Ok((s, core::array::from_fn(|k| r[k].clone())))
}

/// Decode the group commitment `T` from the public key.
pub fn group_commitment(pk: &ThresholdRaccoonPublicKey) -> Result<Commitment, RaccoonError> {
    decode_commitment(&pk.group_key)
}

/// Sign `msg` under `pk` with a recovered opening `(s, r)` (see [`combine_opening`]).
pub fn sign<R: CryptoRng + Rng>(
    rng: &mut R,
    pk: &ThresholdRaccoonPublicKey,
    opening: &(Rq, [Rq; KAPPA]),
    msg: &[u8],
) -> Result<Signature, RaccoonError> {
    let t = group_commitment(pk)?;
    signer::sign(rng, &t, &opening.0, &opening.1, msg).ok_or(RaccoonError::SignExhausted)
}

/// Verify a signature under `pk`.
#[must_use]
pub fn verify(pk: &ThresholdRaccoonPublicKey, msg: &[u8], sig: &Signature) -> bool {
    match group_commitment(pk) {
        Ok(t) => signer::verify(&t, msg, sig),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Encoding helpers (shared format with lib-q-dkg)
// ---------------------------------------------------------------------------

fn eval_poly(coeffs: &[Rq], rho: &[[Rq; KAPPA]], j: u8) -> (Rq, Vec<Rq>) {
    let mut value = Rq::zero();
    let mut rand: Vec<Rq> = (0..KAPPA).map(|_| Rq::zero()).collect();
    for (i, a) in coeffs.iter().enumerate() {
        let p = bdlop::pow_mod_q(j, i);
        value = ring_add(&value, &scalar_mul(a, p));
        for (acc, ri) in rand.iter_mut().zip(rho[i].iter()) {
            *acc = ring_add(acc, &scalar_mul(ri, p));
        }
    }
    (value, rand)
}

/// Serialize a commitment: `MU` `t0` elements followed by `t1`.
pub(crate) fn encode_commitment(c: &Commitment) -> Vec<u8> {
    let mut out = Vec::with_capacity((MU + 1) * RQ_BYTES);
    for p in &c.t0 {
        out.extend_from_slice(&rq_to_le_bytes(p));
    }
    out.extend_from_slice(&rq_to_le_bytes(&c.t1));
    out
}

fn decode_commitment(bytes: &[u8]) -> Result<Commitment, RaccoonError> {
    if bytes.len() != (MU + 1) * RQ_BYTES {
        return Err(RaccoonError::Encoding);
    }
    let mut t0 = Vec::with_capacity(MU);
    for i in 0..MU {
        t0.push(
            rq_from_le_bytes(&bytes[i * RQ_BYTES..(i + 1) * RQ_BYTES])
                .ok_or(RaccoonError::Encoding)?,
        );
    }
    let t1 = rq_from_le_bytes(&bytes[MU * RQ_BYTES..(MU + 1) * RQ_BYTES])
        .ok_or(RaccoonError::Encoding)?;
    Ok(Commitment { t0, t1 })
}

fn encode_value_rand(value: &Rq, rand: &[Rq]) -> Vec<u8> {
    let mut out = rq_to_le_bytes(value);
    for r in rand {
        out.extend_from_slice(&rq_to_le_bytes(r));
    }
    out
}

pub(crate) fn decode_value_rand(bytes: &[u8]) -> Result<(Rq, Vec<Rq>), RaccoonError> {
    if bytes.len() != RQ_BYTES * (1 + KAPPA) {
        return Err(RaccoonError::Encoding);
    }
    let value = rq_from_le_bytes(&bytes[..RQ_BYTES]).ok_or(RaccoonError::Encoding)?;
    let mut rand = Vec::with_capacity(KAPPA);
    for k in 0..KAPPA {
        let start = RQ_BYTES * (1 + k);
        rand.push(rq_from_le_bytes(&bytes[start..start + RQ_BYTES]).ok_or(RaccoonError::Encoding)?);
    }
    Ok((value, rand))
}
