//! `lib-q-threshold-kem-lattice` — a PROVISIONAL post-quantum **lattice threshold KEM** whose
//! decapsulation key is exactly the output of `lib-q-dkg`'s dealerless DKG.
//!
//! The group key is the `t0 = B0·r` half of a BDLOP commitment `T = commit(s; r)` to a **short**
//! secret (the DKG's reconstructed group key). Since `t0 = B0·r` is a dual-Regev / GPV public key
//! whose short decryption key is `r`, and `lib-q-dkg` already `t`-of-`n` Shamir-shares `r` (each
//! `SigningShare`'s `rand` component, with `Σ_{j∈S} λ_j·rand(j) = r`), decapsulation
//! `w = v − ⟨r, p⟩` is a **linear** function of the shares. Each holder contributes
//! `λ_j·⟨rand(j), p⟩`; the contributions sum to `⟨r, p⟩` with **no key reconstruction**.
//!
//! This crate is **co-designed** with `lib-q-dkg`, exactly as `lib-q-threshold-raccoon` is for
//! signatures: a [`SecretShare`] here is byte-identical to a `lib_q_dkg::SigningShare`, and
//! [`keygen_shares`] (a centralized trusted-dealer reference) produces the same share format as
//! `lib_q_dkg::dkg_run_honest`. So the DKG is a **drop-in dealerless keygen** for this KEM —
//! [`public_key_from_dkg`] extracts the KEM public key from a `lib_q_dkg::VerificationKeySet`.
//!
//! **Scope (research-grade).** Chosen-ciphertext hardening is layered (see `SECURITY_ANALYSIS.md`):
//! an **explicit-rejection Fujisaki–Okamoto check** (FO⊥ — [`combine`] re-encrypts the decoded
//! message with integer-only, platform-exact derandomized sampling and rejects any mismatch),
//! **uniform noise flooding** on every masked partial ([`threshold::partial_decap_masked`]), and an
//! **enforceable per-key decapsulation budget** ([`threshold::DecapBudget`] /
//! [`threshold::partial_decap_masked_budgeted`]). Both Module-LWE instances (decapsulation key and
//! ciphertext) are lattice-estimator-gated. The remaining deployment boundary: a `t-1`-corrupt
//! insider who submits a *malformed* ciphertext learns a flooded linear probe of the honest share
//! before the FO check can reject at [`combine`]. Note a ciphertext *well-formedness* proof does
//! **not** close this (a small spike `f = δ·unit_k` passes any norm bound); the minimal sufficient
//! statement is a proof of *correct encryption* (knowledge of `μ`). The deployable, sound closure is
//! an **authenticated encapsulator** plus the enforceable budget + DKG key rotation. See
//! `THRESHOLD_SECURITY.md` (full treatment) and `LIBQ_API.md` §7 for the RED-zone review surface.

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;

use lib_q_dkg::lattice::bdlop::{
    self,
    KAPPA,
    MU,
};
use lib_q_dkg::lattice::ring::{
    RQ_BYTES,
    Rq,
    ring_add,
    rq_from_le_bytes,
    rq_write_le_bytes,
    sample_secret_poly,
    sample_uniform_poly,
    scalar_mul,
};
use rand_core::{
    CryptoRng,
    Rng,
};
use zeroize::{
    Zeroize,
    Zeroizing,
};

pub mod error;
pub mod kem;
pub mod profile;
pub mod threshold;
/// WASM bindings (`@lib-q/threshold-kem-lattice`), gated behind the `wasm` feature.
#[cfg(feature = "wasm")]
pub mod wasm;

pub use error::ThresholdKemError;
pub use kem::{
    Ciphertext,
    ENC_ERROR_BOUND,
    FLOOD_BOUND,
    MALFORMED_PROBE_SAFE_DECAPS,
    MESSAGE_BITS,
    RECOMMENDED_DECAP_BUDGET,
};
pub use profile::{
    PARAMETER_SET_CANONICAL_BLOB_V1,
    PROFILE_ID_V1,
    PROFILE_MAX_PARTIES_V1,
    ThresholdKemLatticeProfileV1,
    WIRE_VERSION_V1,
    setup,
};
pub use threshold::DecapBudget;

/// The group public key: reconstruction threshold + the serialized `t0 = B0·r` (`MU` ring elements).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThresholdKemLatticePublicKey {
    /// Reconstruction threshold `t`.
    pub threshold: u8,
    /// Serialized `t0` (`MU · RQ_BYTES` bytes).
    pub t0_bytes: Vec<u8>,
}

impl ThresholdKemLatticePublicKey {
    /// Decode `t0` into `MU` ring elements.
    pub fn t0(&self) -> Result<Vec<Rq>, ThresholdKemError> {
        if self.t0_bytes.len() != MU * RQ_BYTES {
            return Err(ThresholdKemError::EncodingPublicKey);
        }
        let mut t0 = Vec::with_capacity(MU);
        for i in 0..MU {
            t0.push(
                rq_from_le_bytes(&self.t0_bytes[i * RQ_BYTES..(i + 1) * RQ_BYTES])
                    .ok_or(ThresholdKemError::EncodingPublicKey)?,
            );
        }
        Ok(t0)
    }
}

/// A decapsulation share — byte-identical to `lib_q_dkg::SigningShare` (`share_bytes = value ‖ rand`,
/// `1 + KAPPA` ring elements). Only the `rand` half is used by the KEM.
#[derive(Clone)]
pub struct SecretShare {
    /// Party index `1..=n`.
    pub index: u8,
    /// Reconstruction threshold `t`.
    pub threshold: u8,
    /// Canonical encoding of `value ‖ rand`.
    pub share_bytes: Zeroizing<Vec<u8>>,
}

/// One party's contribution to a threshold decapsulation.
///
/// `value` is `λ_i·⟨rand(i), p⟩` (reference path) or `λ_i·⟨rand(i), p⟩ + m_i` (distributed masked
/// path, [`threshold::partial_decap_masked`]). Either way [`combine`] just **sums** the `value`s to
/// obtain `⟨r, p⟩`, so the two paths share one combiner.
#[derive(Clone, Eq, PartialEq)]
pub struct PartialDecap {
    /// Party index.
    pub index: u8,
    /// This party's pre-weighted (and possibly masked) contribution.
    pub value: Rq,
}

// Manual Debug: on the unmasked path `value` is a linear image of the secret share, so a derived
// Debug would leak share material into logs. Print only the non-secret `index`; redact `value`.
impl core::fmt::Debug for PartialDecap {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PartialDecap")
            .field("index", &self.index)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl PartialDecap {
    /// Serialized length in bytes: `1` (party index) + `RQ_BYTES` (the `value` ring element).
    pub const BYTES: usize = 1 + RQ_BYTES;

    /// Canonical little-endian serialization `index ‖ rq_le(value)` — for carrying a masked partial
    /// over the wire to a distributed combiner. The masked `value` is uniform over `R_q`, so the bytes
    /// reveal nothing about the emitting party's share.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::BYTES);
        out.push(self.index);
        rq_write_le_bytes(&self.value, &mut out);
        out
    }

    /// Parse from exactly [`PartialDecap::BYTES`] bytes; rejects a wrong length or non-canonical
    /// coefficient ([`ThresholdKemError::EncodingPartial`]).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ThresholdKemError> {
        if bytes.len() != Self::BYTES {
            return Err(ThresholdKemError::EncodingPartial);
        }
        let value = rq_from_le_bytes(&bytes[1..]).ok_or(ThresholdKemError::EncodingPartial)?;
        Ok(PartialDecap {
            index: bytes[0],
            value,
        })
    }
}

/// Output of [`keygen_shares`]: shape mirrors `lib_q_dkg::KeygenSharesOutput`.
#[derive(Clone)]
pub struct KeygenSharesOutput {
    /// The group public key.
    pub public_key: ThresholdKemLatticePublicKey,
    /// One decapsulation share per party.
    pub secret_shares: Vec<SecretShare>,
}

/// Centralized trusted-dealer keygen (reference path; `lib_q_dkg::dkg_run_honest` is the dealerless
/// equivalent producing the same share format — see [`public_key_from_dkg`] / [`share_from_dkg`]).
pub fn keygen_shares<R: CryptoRng + Rng>(
    profile: &ThresholdKemLatticeProfileV1,
    threshold: u8,
    parties: u8,
    rng: &mut R,
) -> Result<KeygenSharesOutput, ThresholdKemError> {
    if profile.id != PROFILE_ID_V1 || profile.max_parties != PROFILE_MAX_PARTIES_V1 {
        return Err(ThresholdKemError::InvalidProfile);
    }
    if parties == 0 || parties > PROFILE_MAX_PARTIES_V1 {
        return Err(ThresholdKemError::InvalidShareCount);
    }
    if threshold == 0 || threshold > parties {
        return Err(ThresholdKemError::InvalidThreshold);
    }
    let key = bdlop::key();
    let t = usize::from(threshold);

    // Sharing polynomial: short secret constant term, uniform blinding, ternary commit randomness —
    // identical to `lib_q_dkg`'s honest run and `lib-q-threshold-raccoon`'s reference keygen.
    let mut coeffs = Vec::with_capacity(t);
    let mut rho = Vec::with_capacity(t);
    let mut commitments = Vec::with_capacity(t);
    for i in 0..t {
        let a = if i == 0 {
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
        let (mut value, mut rand) = eval_poly(&coeffs, &rho, j);
        secret_shares.push(SecretShare {
            index: j,
            threshold,
            share_bytes: Zeroizing::new(encode_value_rand(&value, &rand)),
        });
        value.zeroize();
        rand.zeroize();
    }

    // The dealer's sharing polynomial (secret constant term!) and commitment randomness are no
    // longer needed once the shares are encoded — clear them before returning.
    coeffs.zeroize();
    rho.zeroize();

    // The KEM public key is `t0 = B0·r` — the `t0` half of the constant-term commitment.
    let t0_bytes = encode_t0(&commitments[0].t0);

    Ok(KeygenSharesOutput {
        public_key: ThresholdKemLatticePublicKey {
            threshold,
            t0_bytes,
        },
        secret_shares,
    })
}

/// Extract the KEM public key from a `lib_q_dkg::VerificationKeySet` (dealerless keygen path). The
/// DKG group key is `commit(s; r)` encoded as `MU` `t0` elements followed by `t1`; the KEM uses the
/// `t0` prefix.
pub fn public_key_from_dkg(
    vk: &lib_q_dkg::VerificationKeySet,
) -> Result<ThresholdKemLatticePublicKey, ThresholdKemError> {
    if vk.group_key.len() != (MU + 1) * RQ_BYTES {
        return Err(ThresholdKemError::EncodingPublicKey);
    }
    Ok(ThresholdKemLatticePublicKey {
        threshold: vk.threshold,
        t0_bytes: vk.group_key[..MU * RQ_BYTES].to_vec(),
    })
}

/// Adapt a `lib_q_dkg::SigningShare` into a KEM [`SecretShare`] (byte-identical; a re-wrap).
#[must_use]
pub fn share_from_dkg(share: &lib_q_dkg::SigningShare) -> SecretShare {
    SecretShare {
        index: share.index,
        threshold: share.threshold,
        share_bytes: Zeroizing::new(share.share_bytes.as_slice().to_vec()),
    }
}

/// Encapsulate to the group public key: `(shared_secret, ciphertext)`.
pub fn encapsulate<R: CryptoRng + Rng>(
    pk: &ThresholdKemLatticePublicKey,
    rng: &mut R,
) -> Result<([u8; 32], Ciphertext), ThresholdKemError> {
    let t0 = pk.t0()?;
    let (ss, ct) = kem::encapsulate(&t0, rng);
    Ok((ss, ct))
}

/// Validate a share/subset pair before any secret is touched: the subset must hold at least
/// `share.threshold` **distinct, nonzero** party indices and contain the share's own (nonzero)
/// index. Nonzero matters because index `0` is the Shamir evaluation point of the secret itself —
/// `λ_0 = 1` would weight a hand-built share as a direct claim on `f(0)`. Sub-threshold subsets
/// are rejected here (they can only interpolate garbage), and a too-small subset also shrinks the
/// honest Lagrange weights' denominator structure the flooding analysis assumes.
pub(crate) fn validate_share_subset(
    share: &SecretShare,
    subset: &[u8],
) -> Result<(), ThresholdKemError> {
    if share.index == 0 ||
        subset.len() < usize::from(share.threshold) ||
        !subset.contains(&share.index)
    {
        return Err(ThresholdKemError::InvalidSubset);
    }
    // Upper bound: the noise budget is sized for at most PROFILE_MAX_PARTIES_V1 contributions.
    if subset.len() > usize::from(PROFILE_MAX_PARTIES_V1) {
        return Err(ThresholdKemError::InvalidShareCount);
    }
    let mut seen = [false; 256];
    for &j in subset {
        if j == 0 || seen[usize::from(j)] {
            return Err(ThresholdKemError::InvalidSubset);
        }
        seen[usize::from(j)] = true;
    }
    Ok(())
}

/// Reference (un-flooded) partial decapsulation by party `index` over the decapping `subset`:
/// `λ_index·⟨rand(index), p⟩`. Individually **not** private (leaks a linear image of the share) —
/// use [`threshold::partial_decap_masked`] for the privacy-preserving distributed path.
///
/// Rejects structurally malformed ciphertexts, zero/duplicate/missing subset indices, and
/// sub-threshold subsets before touching the share.
pub fn partial_decap(
    share: &SecretShare,
    subset: &[u8],
    ct: &Ciphertext,
) -> Result<PartialDecap, ThresholdKemError> {
    validate_share_subset(share, subset)?;
    if !ct.is_well_formed() {
        return Err(ThresholdKemError::EncodingCiphertext);
    }
    let rand = decode_rand(&share.share_bytes)?;
    let lambda = lib_q_dkg::lagrange_coeff_at_zero(subset, share.index)
        .map_err(|_| ThresholdKemError::InvalidSubset)?;
    let mut rp = kem::ring_inner(&rand, &ct.p); // ⟨rand(index), p⟩
    let value = scalar_mul(&rp, lambda);
    rp.zeroize();
    Ok(PartialDecap {
        index: share.index,
        value,
    })
}

/// Sum a threshold of partial decapsulations into the shared secret, then enforce the **FO⊥
/// validity check** (re-encrypt the decoded message and reject any mismatch — see
/// [`kem::finish_decap`]). Rejects duplicate indices and sub-threshold partial sets (fewer than
/// `pk.threshold` points can only interpolate garbage — callers get [`ThresholdKemError::InvalidSubset`]
/// instead of a misleading FO rejection). Shared by the reference and distributed-masked paths
/// (the `value`s are always pre-weighted; flooding and zero-share masks are absorbed into the
/// decode margin / cancel, respectively).
pub fn combine(
    pk: &ThresholdKemLatticePublicKey,
    partials: &[PartialDecap],
    ct: &Ciphertext,
) -> Result<[u8; 32], ThresholdKemError> {
    if partials.is_empty() || partials.len() < usize::from(pk.threshold) {
        return Err(ThresholdKemError::InvalidSubset);
    }
    // Upper bound: the noise budget is sized for at most PROFILE_MAX_PARTIES_V1 contributions.
    if partials.len() > usize::from(PROFILE_MAX_PARTIES_V1) {
        return Err(ThresholdKemError::InvalidShareCount);
    }
    let mut seen = [false; 256];
    let mut rp = Rq::zero();
    for p in partials {
        if seen[usize::from(p.index)] {
            return Err(ThresholdKemError::DuplicateIndex { index: p.index });
        }
        seen[usize::from(p.index)] = true;
        rp = ring_add(&rp, &p.value);
    }
    let t0 = pk.t0()?;
    // `rp = Σ p.value` is an exact linear image of the secret share ("not private"); wipe it on
    // every return path (Rq: Zeroize) after finish_decap consumes it.
    let result = kem::finish_decap(&t0, ct, &rp);
    rp.zeroize();
    result
}

/// Convenience: full reference decapsulation from a subset of shares (trusted combiner).
pub fn decapsulate_reference(
    pk: &ThresholdKemLatticePublicKey,
    shares: &[SecretShare],
    ct: &Ciphertext,
) -> Result<[u8; 32], ThresholdKemError> {
    let subset: Vec<u8> = shares.iter().map(|s| s.index).collect();
    let partials: Vec<PartialDecap> = shares
        .iter()
        .map(|s| partial_decap(s, &subset, ct))
        .collect::<Result<_, _>>()?;
    combine(pk, &partials, ct)
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

fn encode_t0(t0: &[Rq]) -> Vec<u8> {
    let mut out = Vec::with_capacity(MU * RQ_BYTES);
    for p in t0 {
        rq_write_le_bytes(p, &mut out);
    }
    out
}

/// Encode `value ‖ rand`. Fully pre-allocated so the secret bytes are written once — no
/// reallocation ever copies them to a second, un-zeroized heap block.
fn encode_value_rand(value: &Rq, rand: &[Rq]) -> Vec<u8> {
    let mut out = Vec::with_capacity((1 + rand.len()) * RQ_BYTES);
    rq_write_le_bytes(value, &mut out);
    for r in rand {
        rq_write_le_bytes(r, &mut out);
    }
    out
}

/// Decode just the `rand` half (`KAPPA` ring elements) of a `value ‖ rand` share. The result is
/// the caller's decapsulation-key share — returned [`Zeroizing`] so it is cleared on drop.
pub(crate) fn decode_rand(bytes: &[u8]) -> Result<Zeroizing<Vec<Rq>>, ThresholdKemError> {
    if bytes.len() != RQ_BYTES * (1 + KAPPA) {
        return Err(ThresholdKemError::EncodingShare);
    }
    let mut rand = Zeroizing::new(Vec::with_capacity(KAPPA));
    for k in 0..KAPPA {
        let start = RQ_BYTES * (1 + k);
        rand.push(
            rq_from_le_bytes(&bytes[start..start + RQ_BYTES])
                .ok_or(ThresholdKemError::EncodingShare)?,
        );
    }
    Ok(rand)
}
