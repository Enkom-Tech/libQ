//! Homomorphic blinding for issuer-keyed Ajtai commitments (wire v0 blind issuance).
//!
//! [`BlindIssuance`] wires user blinding, issuer Fiat–Shamir attestation, and verifier checks.
//! See [`BLIND_ISSUANCE.md`](../BLIND_ISSUANCE.md) for the issuer-keyed model and wire layout.

extern crate alloc;

use alloc::vec::Vec;

use lib_q_ring::ModuleVec;
use lib_q_sha3::{
    ExtendableOutput,
    Update,
    XofReader,
};
use subtle::ConstantTimeEq;
use rand_core::{
    CryptoRng,
    Rng,
};
use zeroize::{
    Zeroize,
    ZeroizeOnDrop,
};

use crate::commitment::{
    AjtaiCommitment,
    AjtaiCommitmentKey,
    AjtaiOpening,
    commit,
};
use crate::error::{
    ProofError,
    VerifyError,
};
use crate::params::AjtaiParameters;
use crate::profile::LatticeZkpProfileV0;
use crate::serialize::write_module_vec;
use crate::sigma::opening::{
    OpeningProof,
    prove_opening,
    sample_random_opening,
    verify_opening,
};

/// Fiat–Shamir label binding the issuer attestation to the blinded commitment bytes.
pub const BLIND_ISSUER_FS_LABEL: &[u8] = b"blind-issuer-v1";

/// Domain-separated digest of `message` for blind-signature transcript binding.
#[must_use]
pub fn blind_message_digest(message: &[u8]) -> [u8; 32] {
    let mut h = lib_q_sha3::Shake256::default();
    h.update(b"lattice-zkp/blind-msg/v1");
    h.update(&(message.len() as u64).to_le_bytes());
    h.update(message);
    let mut out = [0u8; 32];
    let mut r = h.finalize_xof();
    XofReader::read(&mut r, &mut out);
    out
}

/// Domain-separated digest of a blinded commitment image for wire kind `0x08`.
#[must_use]
pub fn blinded_commitment_digest(com: &AjtaiCommitment) -> [u8; 32] {
    let wire = write_module_vec(&com.value.0);
    let mut h = lib_q_sha3::Shake256::default();
    h.update(b"lattice-zkp/blinded-com/v0");
    h.update(&wire);
    let mut out = [0u8; 32];
    let mut r = h.finalize_xof();
    XofReader::read(&mut r, &mut out);
    out
}

/// Domain tag for issuer-keyed commitment parameter digests on wire kind `0x08`.
pub const ISSUER_PARAMS_DIGEST_DOMAIN: &[u8] = b"lattice-zkp/issuer-params/v0";

/// Issuer-specific Ajtai matrix parameters (wire v0; replaces shared-CRS blind pilot).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerCommitmentParams {
    /// Seed expanding issuer-specific matrix `A_issuer`.
    pub issuer_matrix_seed: [u8; 32],
    pub params: AjtaiParameters,
    /// Profile id bound into [`Self::issuer_params_digest`].
    pub profile_id: u8,
}

impl IssuerCommitmentParams {
    /// Build issuer params from a wire profile and issuer matrix seed.
    #[must_use]
    pub fn from_profile(profile: &LatticeZkpProfileV0, issuer_matrix_seed: [u8; 32]) -> Self {
        Self {
            issuer_matrix_seed,
            params: profile.ajtai.clone(),
            profile_id: profile.profile_id,
        }
    }

    /// Expand `A_issuer` commitment key.
    #[must_use]
    pub fn commitment_key(&self) -> AjtaiCommitmentKey {
        AjtaiCommitmentKey {
            seed: self.issuer_matrix_seed,
            params: self.params.clone(),
        }
    }

    /// `SHAKE256(domain ‖ issuer_matrix_seed ‖ profile_id)` carried on wire kind `0x08`.
    #[must_use]
    pub fn issuer_params_digest(&self) -> [u8; 32] {
        let mut h = lib_q_sha3::Shake256::default();
        h.update(ISSUER_PARAMS_DIGEST_DOMAIN);
        h.update(&self.issuer_matrix_seed);
        h.update(&[self.profile_id]);
        let mut out = [0u8; 32];
        let mut r = h.finalize_xof();
        XofReader::read(&mut r, &mut out);
        out
    }
}

/// Issuer signing key: secret opening and public commitment under issuer-keyed `A_issuer`.
#[derive(Clone)]
pub struct BlindIssuerKeypair {
    /// Issuer matrix parameters (wire-bound via digest).
    pub issuer_params: IssuerCommitmentParams,
    /// Secret opening witness under `issuer_params.commitment_key()`.
    pub secret_opening: AjtaiOpening,
    /// Public commitment `commit(A_issuer, secret_opening)`.
    pub public_commitment: AjtaiCommitment,
}

impl Zeroize for BlindIssuerKeypair {
    fn zeroize(&mut self) {
        self.secret_opening.zeroize();
    }
}

impl Drop for BlindIssuerKeypair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl core::fmt::Debug for BlindIssuerKeypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlindIssuerKeypair")
            .field("public_commitment", &self.public_commitment)
            .field("secret_opening", &"<redacted>")
            .finish()
    }
}

impl BlindIssuerKeypair {
    /// Derive `(sk, pk)` from uniformly sampled opening under issuer-keyed matrix.
    #[must_use]
    pub fn sample_issuer_keyed<R: Rng + CryptoRng>(
        rng: &mut R,
        issuer_params: &IssuerCommitmentParams,
    ) -> Self {
        let key = issuer_params.commitment_key();
        let secret_opening = sample_random_opening(rng, &key);
        let public_commitment = commit(&key, &secret_opening);
        Self {
            issuer_params: issuer_params.clone(),
            secret_opening,
            public_commitment,
        }
    }

    /// Issuer commitment key for blind issuance operations.
    #[must_use]
    pub fn commitment_key(&self) -> AjtaiCommitmentKey {
        self.issuer_params.commitment_key()
    }

    /// Wire bytes for the public commitment image (absorbed into Fiat–Shamir contexts).
    #[must_use]
    pub fn public_commitment_wire(&self) -> Vec<u8> {
        write_module_vec(&self.public_commitment.value.0)
    }
}

/// Final bundle after [`BlindIssuance::finalize_message`]: blinded token + issuer attestation + message digest.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct UnblindedBlindSignature {
    /// Inner blind issuance bundle.
    pub issuance: UnblindedIssuance,
    /// [`blind_message_digest`] of the signed application message.
    #[zeroize(skip)]
    pub message_digest: [u8; 32],
}

/// Trait for verifying blind-signature–style bundles that bind an application message.
///
/// Naming aligns with blind-signature literature: [`BlindSignature::verify_signature`] is the
/// public verifier entry point; [`BlindIssuance::issuer_sign_message`] / [`BlindIssuance::finalize_message`]
/// implement the issuer-side **blind sign** and user-side **unblind** steps under
/// [`IssuerCommitmentParams`].
pub trait BlindSignature {
    /// Verify commitment consistency, issuer attestation, and message digest binding.
    ///
    /// `genuine_issuer_com` pins the authentic issuer public commitment.
    fn verify_blind_signature(
        &self,
        issuer_params: &IssuerCommitmentParams,
        genuine_issuer_com: &AjtaiCommitment,
        base_ctx: &[u8],
        tau: usize,
        z_inf_bound: i32,
    ) -> Result<(), VerifyError>;

    /// Synonym for [`Self::verify_blind_signature`] (Phase 7 plan surface: `verify_signature`).
    fn verify_signature(
        &self,
        issuer_params: &IssuerCommitmentParams,
        genuine_issuer_com: &AjtaiCommitment,
        base_ctx: &[u8],
        tau: usize,
        z_inf_bound: i32,
    ) -> Result<(), VerifyError> {
        self.verify_blind_signature(issuer_params, genuine_issuer_com, base_ctx, tau, z_inf_bound)
    }
}

impl BlindSignature for UnblindedBlindSignature {
    fn verify_blind_signature(
        &self,
        issuer_params: &IssuerCommitmentParams,
        genuine_issuer_com: &AjtaiCommitment,
        base_ctx: &[u8],
        tau: usize,
        z_inf_bound: i32,
    ) -> Result<(), VerifyError> {
        BlindIssuance::verify_message(
            issuer_params,
            genuine_issuer_com,
            &self.issuance,
            base_ctx,
            &self.message_digest,
            tau,
            z_inf_bound,
        )
    }
}

/// User-side blind openings (scrubbed on drop unless consumed by [`BlindIssuance::finalize`]).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct BlindOpeningSecrets {
    user_opening: AjtaiOpening,
    blind_opening: AjtaiOpening,
}

/// User-side state after [`BlindIssuance::request`].
///
/// Dropping without finalizing scrubs [`BlindOpeningSecrets`] automatically.
#[must_use = "consume via BlindIssuance::finalize or drop to scrub blind/user openings"]
#[derive(Clone)]
pub struct BlindUserState {
    /// Blinded token commitment `Com(user + blind)`.
    pub com_blinded: AjtaiCommitment,
    secrets: BlindOpeningSecrets,
}

impl BlindUserState {
    /// User credential opening before blinding.
    #[must_use]
    pub fn user_opening(&self) -> &AjtaiOpening {
        &self.secrets.user_opening
    }

    /// Uniform blinding opening sampled in [`BlindIssuance::request`].
    #[must_use]
    pub fn blind_opening(&self) -> &AjtaiOpening {
        &self.secrets.blind_opening
    }
}

impl core::fmt::Debug for BlindUserState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlindUserState")
            .field("com_blinded", &self.com_blinded)
            .field("user_opening", &"<redacted>")
            .field("blind_opening", &"<redacted>")
            .finish()
    }
}

/// Message sent to the issuer (blinded commitment only).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlindRequest {
    pub com_blinded: AjtaiCommitment,
}

/// Issuer attestation: opening proof over a separate issuer commitment whose transcript
/// binds the blinded commitment bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlindResponse {
    pub issuer_com: AjtaiCommitment,
    pub issuer_proof: OpeningProof,
}

/// Final bundle after [`BlindIssuance::finalize`].
///
/// Cloning duplicates the secret [`token_opening`]; prefer references when possible.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct UnblindedIssuance {
    #[zeroize(skip)]
    pub com_blinded: AjtaiCommitment,
    /// Opening for `com_blinded` (= user + blind).
    pub token_opening: AjtaiOpening,
    #[zeroize(skip)]
    pub issuer_com: AjtaiCommitment,
    #[zeroize(skip)]
    pub issuer_proof: OpeningProof,
}

impl core::fmt::Debug for UnblindedIssuance {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UnblindedIssuance")
            .field("com_blinded", &self.com_blinded)
            .field("token_opening", &"<redacted>")
            .field("issuer_com", &self.issuer_com)
            .field("issuer_proof", &self.issuer_proof)
            .finish()
    }
}

/// Constant-time authentication of the bundle's issuer commitment against the genuine one.
///
/// Soundness fix: blind-signature verification previously trusted whatever
/// [`UnblindedIssuance::issuer_com`] the bundle carried, so any party holding *some* valid
/// issuer keypair could produce a bundle that verifies — the genuine issuer was never
/// authenticated. The verifier must pin the genuine issuer public commitment and compare it
/// against the bundle's `issuer_com` in constant time before trusting the attestation.
fn authenticate_issuer_commitment(
    bundle_issuer_com: &AjtaiCommitment,
    genuine_issuer_com: &AjtaiCommitment,
) -> Result<(), VerifyError> {
    let bundle_wire = write_module_vec(&bundle_issuer_com.value.0);
    let genuine_wire = write_module_vec(&genuine_issuer_com.value.0);
    // Length check (public metadata) before the constant-time byte comparison.
    if bundle_wire.len() != genuine_wire.len() {
        return Err(VerifyError::Rejected);
    }
    if bool::from(bundle_wire.ct_eq(&genuine_wire)) {
        Ok(())
    } else {
        Err(VerifyError::Rejected)
    }
}

/// Issuer-keyed blind issuance orchestration (homomorphic Ajtai blinding; not Chaum blind RSA).
pub struct BlindIssuance;

impl BlindIssuance {
    /// User samples blinding, returns the blinded commitment for the issuer.
    pub fn request<R: Rng + CryptoRng>(
        rng: &mut R,
        issuer_params: &IssuerCommitmentParams,
        user_opening: AjtaiOpening,
    ) -> Result<(BlindRequest, BlindUserState), ProofError> {
        let key = issuer_params.commitment_key();
        let blind_opening = sample_random_opening(rng, &key);
        let com_blinded = blinded_commitment(&key, &user_opening, &blind_opening)
            .ok_or(ProofError::InvalidParameters)?;
        let req = BlindRequest {
            com_blinded: com_blinded.clone(),
        };
        let st = BlindUserState {
            com_blinded,
            secrets: BlindOpeningSecrets {
                user_opening,
                blind_opening,
            },
        };
        Ok((req, st))
    }

    /// Issuer produces a Schnorr-style opening proof whose FS context includes the
    /// serialized blinded commitment, issuer public image, and [`blind_message_digest`].
    #[allow(clippy::too_many_arguments)] // Fiat–Shamir sigma API: explicit public inputs
    pub fn issuer_sign_message<R: Rng + CryptoRng>(
        rng: &mut R,
        issuer: &BlindIssuerKeypair,
        blind_req: &BlindRequest,
        message: &[u8],
        base_ctx: &[u8],
        tau: usize,
        z_inf_bound: i32,
        max_attempts: usize,
    ) -> Result<(BlindResponse, [u8; 32]), ProofError> {
        let key = issuer.commitment_key();
        let digest = blind_message_digest(message);
        let issuer_com = issuer.public_commitment.clone();
        let blind_wire = write_module_vec(&blind_req.com_blinded.value.0);
        let issuer_wire = issuer.public_commitment_wire();
        let extra = issuance_blind_message_extra(&blind_wire, &issuer_wire, &digest);
        let ctx = issuance_transcript_ctx(base_ctx, BLIND_ISSUER_FS_LABEL, &extra);
        let issuer_proof = prove_opening(
            rng,
            &key,
            &issuer.secret_opening,
            &issuer_com,
            &ctx,
            tau,
            z_inf_bound,
            max_attempts,
        )?;
        Ok((
            BlindResponse {
                issuer_com,
                issuer_proof,
            },
            digest,
        ))
    }

    /// Issuer produces a Schnorr-style opening proof whose FS context includes the
    /// serialized blinded commitment.
    #[allow(clippy::too_many_arguments)] // Fiat–Shamir sigma API: explicit public inputs
    pub fn issuer_sign<R: Rng + CryptoRng>(
        rng: &mut R,
        issuer_params: &IssuerCommitmentParams,
        blind_req: &BlindRequest,
        issuer_opening: &AjtaiOpening,
        base_ctx: &[u8],
        tau: usize,
        z_inf_bound: i32,
        max_attempts: usize,
    ) -> Result<BlindResponse, ProofError> {
        let key = issuer_params.commitment_key();
        let issuer_com = commit(&key, issuer_opening);
        let blind_wire = write_module_vec(&blind_req.com_blinded.value.0);
        let extra = blind_wire;
        let ctx = issuance_transcript_ctx(base_ctx, BLIND_ISSUER_FS_LABEL, &extra);
        let issuer_proof = prove_opening(
            rng,
            &key,
            issuer_opening,
            &issuer_com,
            &ctx,
            tau,
            z_inf_bound,
            max_attempts,
        )?;
        Ok(BlindResponse {
            issuer_com,
            issuer_proof,
        })
    }

    /// User aggregates openings; issuer response is carried unchanged.
    pub fn finalize(
        user: BlindUserState,
        resp: BlindResponse,
    ) -> Result<UnblindedIssuance, ProofError> {
        let BlindUserState {
            com_blinded,
            secrets,
        } = user;
        let token_opening = aggregate_opening(&secrets.user_opening, &secrets.blind_opening)
            .ok_or(ProofError::InvalidParameters)?;
        Ok(UnblindedIssuance {
            com_blinded,
            token_opening,
            issuer_com: resp.issuer_com,
            issuer_proof: resp.issuer_proof,
        })
    }

    /// [`BlindIssuance::finalize`] plus carried [`blind_message_digest`] for [`BlindSignature`] verification.
    ///
    /// **Unblinding:** the issuer’s attestation [`BlindResponse::issuer_proof`] is unchanged,
    /// while the aggregated [`UnblindedIssuance::token_opening`] is the sum of the user and
    /// blinding openings—blinding randomness is folded into the token witness and not carried
    /// separately on the wire after this step.
    pub fn finalize_message(
        user: BlindUserState,
        resp: BlindResponse,
        message_digest: [u8; 32],
    ) -> Result<UnblindedBlindSignature, ProofError> {
        let issuance = Self::finalize(user, resp)?;
        Ok(UnblindedBlindSignature {
            issuance,
            message_digest,
        })
    }

    /// Plan-aligned alias for [`BlindIssuance::finalize_message`]: user-side **unblind** of the
    /// blinded issuance into a presentable bundle plus message digest binding.
    pub fn unblind_message(
        user: BlindUserState,
        resp: BlindResponse,
        message_digest: [u8; 32],
    ) -> Result<UnblindedBlindSignature, ProofError> {
        Self::finalize_message(user, resp, message_digest)
    }

    /// Verify token opening matches `com_blinded` and issuer attestation.
    ///
    /// `genuine_issuer_com` is the issuer's authentic public commitment; the bundle's
    /// `issuer_com` is authenticated against it in constant time so an attacker cannot
    /// substitute their own valid issuer keypair.
    pub fn verify(
        issuer_params: &IssuerCommitmentParams,
        genuine_issuer_com: &AjtaiCommitment,
        bundle: &UnblindedIssuance,
        base_ctx: &[u8],
        tau: usize,
        z_inf_bound: i32,
    ) -> Result<(), VerifyError> {
        authenticate_issuer_commitment(&bundle.issuer_com, genuine_issuer_com)?;
        let key = issuer_params.commitment_key();
        let expect = commit(&key, &bundle.token_opening);
        if expect != bundle.com_blinded {
            return Err(VerifyError::Rejected);
        }
        let blind_wire = write_module_vec(&bundle.com_blinded.value.0);
        let ctx = issuance_transcript_ctx(base_ctx, BLIND_ISSUER_FS_LABEL, &blind_wire);
        verify_opening(
            &key,
            &bundle.issuer_com,
            &bundle.issuer_proof,
            &ctx,
            tau,
            z_inf_bound,
        )
    }

    /// Verify [`UnblindedBlindSignature`]: token opening, issuer attestation, and message digest.
    ///
    /// `genuine_issuer_com` is the issuer's authentic public commitment; the bundle's
    /// `issuer_com` is authenticated against it in constant time so an attacker cannot
    /// substitute their own valid issuer keypair.
    pub fn verify_message(
        issuer_params: &IssuerCommitmentParams,
        genuine_issuer_com: &AjtaiCommitment,
        bundle: &UnblindedIssuance,
        base_ctx: &[u8],
        message_digest: &[u8; 32],
        tau: usize,
        z_inf_bound: i32,
    ) -> Result<(), VerifyError> {
        authenticate_issuer_commitment(&bundle.issuer_com, genuine_issuer_com)?;
        let key = issuer_params.commitment_key();
        let expect = commit(&key, &bundle.token_opening);
        if expect != bundle.com_blinded {
            return Err(VerifyError::Rejected);
        }
        let blind_wire = write_module_vec(&bundle.com_blinded.value.0);
        let issuer_wire = write_module_vec(&bundle.issuer_com.value.0);
        let extra = issuance_blind_message_extra(&blind_wire, &issuer_wire, message_digest);
        let ctx = issuance_transcript_ctx(base_ctx, BLIND_ISSUER_FS_LABEL, &extra);
        verify_opening(
            &key,
            &bundle.issuer_com,
            &bundle.issuer_proof,
            &ctx,
            tau,
            z_inf_bound,
        )
    }
}

/// Concatenate blinded commitment wire, issuer public wire, and message digest for FS absorption.
#[must_use]
pub fn issuance_blind_message_extra(
    blinded_com_wire: &[u8],
    issuer_pub_wire: &[u8],
    message_digest: &[u8; 32],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(
        blinded_com_wire.len() + issuer_pub_wire.len() + message_digest.len() + 3,
    );
    v.extend_from_slice(blinded_com_wire);
    v.push(0);
    v.extend_from_slice(issuer_pub_wire);
    v.push(0);
    v.extend_from_slice(message_digest.as_slice());
    v
}

/// Add two module vectors (polynomial-wise, with coefficient reduction).
pub fn add_module_vec(a: &ModuleVec, b: &ModuleVec) -> Option<ModuleVec> {
    if a.0.len() != b.0.len() {
        return None;
    }
    let mut out = Vec::with_capacity(a.0.len());
    for (x, y) in a.0.iter().zip(b.0.iter()) {
        let mut p = x.clone();
        p.add_assign(y);
        out.push(p);
    }
    Some(ModuleVec(out))
}

/// Sum two openings by summing message and randomness blocks separately.
pub fn aggregate_opening(a: &AjtaiOpening, b: &AjtaiOpening) -> Option<AjtaiOpening> {
    if a.message.0.len() != b.message.0.len() || a.randomness.0.len() != b.randomness.0.len() {
        return None;
    }
    let message = add_module_vec(&a.message, &b.message)?;
    let randomness = add_module_vec(&a.randomness, &b.randomness)?;
    Some(AjtaiOpening {
        message,
        randomness,
    })
}

/// Compute `com_user + com_blind` as commitment to `aggregate_opening(user, blind)`.
pub fn blinded_commitment(
    key: &AjtaiCommitmentKey,
    user: &AjtaiOpening,
    blind: &AjtaiOpening,
) -> Option<AjtaiCommitment> {
    let o = aggregate_opening(user, blind)?;
    Some(commit(key, &o))
}

/// Concatenate domain separators for Fiat–Shamir transcripts (`ctx || label || extra`).
pub fn issuance_transcript_ctx(base_ctx: &[u8], label: &[u8], extra: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(base_ctx.len() + label.len() + extra.len() + 2);
    v.extend_from_slice(base_ctx);
    v.push(0);
    v.extend_from_slice(label);
    v.push(0);
    v.extend_from_slice(extra);
    v
}

#[cfg(test)]
mod tests {
    use lib_q_random::new_deterministic_rng;
    use lib_q_ring::Poly;

    use super::*;
    use crate::params::AjtaiParameters;
    use crate::serialize::write_module_vec;
    use crate::sigma::opening::sample_random_opening;

    #[inline]
    fn test_issuer_params(seed: u8) -> IssuerCommitmentParams {
        let mut issuer_matrix_seed = [0u8; 32];
        issuer_matrix_seed[0] = seed;
        IssuerCommitmentParams {
            issuer_matrix_seed,
            params: AjtaiParameters::new(2, 1),
            profile_id: LatticeZkpProfileV0::token_spend_v0().profile_id,
        }
    }

    #[test]
    fn homomorphic_blind_matches_sum_commitment() {
        let params = AjtaiParameters::new(2, 1);
        let key = AjtaiCommitmentKey {
            seed: [0xABu8; 32],
            params,
        };
        let mut mu = alloc::vec![Poly::zero(), Poly::zero()];
        mu[0].coeffs[0] = 5;
        let mut ru = alloc::vec![Poly::zero()];
        ru[0].coeffs[0] = 3;
        let user = AjtaiOpening {
            message: ModuleVec(mu),
            randomness: ModuleVec(ru),
        };

        let mb = alloc::vec![Poly::zero(), Poly::zero()];
        let mut rb = alloc::vec![Poly::zero()];
        rb[0].coeffs[0] = 11;
        let blind = AjtaiOpening {
            message: ModuleVec(mb),
            randomness: ModuleVec(rb),
        };

        let c_user = commit(&key, &user);
        let c_blind = commit(&key, &blind);
        let c_sum = add_module_vec(&c_user.value, &c_blind.value).expect("add com");
        let c_blinded = blinded_commitment(&key, &user, &blind).expect("blind");
        assert_eq!(c_blinded.value.0.len(), c_sum.0.len());
        for (a, b) in c_blinded.value.0.iter().zip(c_sum.0.iter()) {
            assert_eq!(a.coeffs, b.coeffs);
        }
    }

    #[test]
    fn blind_issuance_attestation_roundtrip() {
        let issuer_params = test_issuer_params(0xCD);
        let key = issuer_params.commitment_key();
        let mut mu = alloc::vec![Poly::zero(), Poly::zero()];
        mu[0].coeffs[0] = 9;
        let user = AjtaiOpening {
            message: ModuleVec(mu),
            randomness: ModuleVec(alloc::vec![Poly::zero()]),
        };
        let mut rng = new_deterministic_rng([
            0xB1, 0x0C, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0,
        ]);
        let (req, user_st) =
            BlindIssuance::request(&mut rng, &issuer_params, user).expect("request");
        let issuer_opening = sample_random_opening(&mut rng, &key);
        let resp = BlindIssuance::issuer_sign(
            &mut rng,
            &issuer_params,
            &req,
            &issuer_opening,
            b"realm",
            39,
            20_000_000,
            512,
        )
        .expect("issuer");
        let genuine_issuer_com = commit(&key, &issuer_opening);
        let bundle = BlindIssuance::finalize(user_st, resp).expect("finalize");
        BlindIssuance::verify(
            &issuer_params,
            &genuine_issuer_com,
            &bundle,
            b"realm",
            39,
            20_000_000,
        )
        .expect("verify");
    }

    #[test]
    fn blind_signature_message_roundtrip_and_wrong_message_fails() {
        let issuer_params = test_issuer_params(0xE1);
        let mut mu = alloc::vec![Poly::zero(), Poly::zero()];
        mu[0].coeffs[0] = 2;
        let user = AjtaiOpening {
            message: ModuleVec(mu),
            randomness: ModuleVec(alloc::vec![Poly::zero()]),
        };
        let mut rng = new_deterministic_rng([
            0x51, 0xAE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0,
        ]);
        let (req, user_st) =
            BlindIssuance::request(&mut rng, &issuer_params, user).expect("request");
        let issuer = BlindIssuerKeypair::sample_issuer_keyed(&mut rng, &issuer_params);
        let genuine_issuer_com = issuer.public_commitment.clone();
        let (resp, digest) = BlindIssuance::issuer_sign_message(
            &mut rng,
            &issuer,
            &req,
            b"app-policy-42",
            b"realm-ms",
            39,
            20_000_000,
            512,
        )
        .expect("issuer msg");
        let bundle =
            BlindIssuance::finalize_message(user_st, resp, digest).expect("finalize message");
        bundle
            .verify_signature(&issuer_params, &genuine_issuer_com, b"realm-ms", 39, 20_000_000)
            .expect("BlindSignature::verify_signature alias");

        let mut bad = bundle.clone();
        bad.message_digest[0] ^= 0xFF;
        assert!(
            BlindIssuance::verify_message(
                &issuer_params,
                &genuine_issuer_com,
                &bad.issuance,
                b"realm-ms",
                &bad.message_digest,
                39,
                20_000_000,
            )
            .is_err()
        );
    }

    #[test]
    fn blind_signature_wrong_issuer_commitment_rejected() {
        let issuer_params = test_issuer_params(0xA7);
        let mut mu = alloc::vec![Poly::zero(), Poly::zero()];
        mu[0].coeffs[0] = 3;
        let user = AjtaiOpening {
            message: ModuleVec(mu),
            randomness: ModuleVec(alloc::vec![Poly::zero()]),
        };
        let mut rng = new_deterministic_rng([
            0xBA, 0xD0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0,
        ]);
        let (req, user_st) =
            BlindIssuance::request(&mut rng, &issuer_params, user).expect("request");
        let issuer = BlindIssuerKeypair::sample_issuer_keyed(&mut rng, &issuer_params);
        let other = BlindIssuerKeypair::sample_issuer_keyed(&mut rng, &issuer_params);
        let genuine_issuer_com = issuer.public_commitment.clone();
        let (mut resp, digest) = BlindIssuance::issuer_sign_message(
            &mut rng, &issuer, &req, b"policy", b"ctx", 39, 20_000_000, 512,
        )
        .expect("issuer msg");
        resp.issuer_com = other.public_commitment.clone();
        let bundle = BlindIssuance::finalize_message(user_st, resp, digest).expect("finalize");
        assert!(
            bundle
                .verify_blind_signature(&issuer_params, &genuine_issuer_com, b"ctx", 39, 20_000_000)
                .is_err(),
            "replacing issuer commitment must break attestation verification"
        );
    }

    #[test]
    fn blind_signature_same_message_unlinkable_across_sessions() {
        let issuer_params = test_issuer_params(0xB2);
        let mut mu = alloc::vec![Poly::zero(), Poly::zero()];
        mu[0].coeffs[0] = 1;
        let user = AjtaiOpening {
            message: ModuleVec(mu.clone()),
            randomness: ModuleVec(alloc::vec![Poly::zero()]),
        };
        let mut issuer_rng = new_deterministic_rng([
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]);
        let issuer = BlindIssuerKeypair::sample_issuer_keyed(&mut issuer_rng, &issuer_params);

        let mut r1 = new_deterministic_rng([
            0x11, 0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0,
        ]);
        let (req1, st1) =
            BlindIssuance::request(&mut r1, &issuer_params, user.clone()).expect("r1");
        let (resp1, d1) = BlindIssuance::issuer_sign_message(
            &mut r1,
            &issuer,
            &req1,
            b"same-msg",
            b"ctx-u",
            39,
            20_000_000,
            512,
        )
        .expect("i1");
        let b1 = BlindIssuance::finalize_message(st1, resp1, d1).expect("f1");

        let mut r2 = new_deterministic_rng([
            0x22, 0x22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0,
        ]);
        let (req2, st2) = BlindIssuance::request(&mut r2, &issuer_params, user).expect("r2");
        let (resp2, d2) = BlindIssuance::issuer_sign_message(
            &mut r2,
            &issuer,
            &req2,
            b"same-msg",
            b"ctx-u",
            39,
            20_000_000,
            512,
        )
        .expect("i2");
        let b2 = BlindIssuance::finalize_message(st2, resp2, d2).expect("f2");

        assert_eq!(b1.message_digest, b2.message_digest);
        assert_ne!(
            write_module_vec(&b1.issuance.com_blinded.value.0),
            write_module_vec(&b2.issuance.com_blinded.value.0),
            "independent blinding must change the blinded commitment bytes"
        );
    }

    #[test]
    fn issuer_params_digest_rejects_wrong_profile() {
        let profile = LatticeZkpProfileV0::token_spend_v0();
        let mut seed = [0u8; 32];
        seed[0] = 0x42;
        let params = IssuerCommitmentParams::from_profile(&profile, seed);
        let mut wrong = params.clone();
        wrong.profile_id = profile.profile_id.wrapping_add(1);
        assert_ne!(params.issuer_params_digest(), wrong.issuer_params_digest());
    }
}
