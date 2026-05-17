//! Homomorphic blinding helpers for Ajtai commitments used in prototype blind-issuance flows.
//!
//! [`BlindIssuance`] wires user blinding, issuer Fiat–Shamir attestation, and verifier checks.
//! See [`BLIND_ISSUANCE.md`](../BLIND_ISSUANCE.md) for the CRS model and limitations.

extern crate alloc;

use alloc::vec::Vec;

use lib_q_ring::ModuleVec;
use lib_q_sha3::{
    ExtendableOutput,
    Update,
    XofReader,
};
use rand_core::{
    CryptoRng,
    Rng,
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

/// Pilot issuer key material: an [`AjtaiOpening`] witness and its commitment image under the CRS.
///
/// Production blind signatures over Module-SIS require a trapdoor or issuer-keyed matrix family
/// (see [`BLIND_ISSUANCE.md`](../BLIND_ISSUANCE.md)); this type models a **pilot** signing key as a
/// standard Ajtai opening under the shared CRS.
#[derive(Clone)]
pub struct BlindIssuerKeypair {
    /// Secret opening witness.
    pub secret_opening: AjtaiOpening,
    /// Public commitment `commit(crs, secret_opening)`.
    pub public_commitment: AjtaiCommitment,
}

impl BlindIssuerKeypair {
    /// Derive `(sk, pk)` from a uniformly sampled opening.
    #[must_use]
    pub fn sample<R: Rng + CryptoRng>(rng: &mut R, crs: &AjtaiCommitmentKey) -> Self {
        let secret_opening = sample_random_opening(rng, crs);
        let public_commitment = commit(crs, &secret_opening);
        Self {
            secret_opening,
            public_commitment,
        }
    }

    /// Wire bytes for the public commitment image (absorbed into Fiat–Shamir contexts).
    #[must_use]
    pub fn public_commitment_wire(&self) -> Vec<u8> {
        write_module_vec(&self.public_commitment.value.0)
    }
}

/// Final bundle after [`BlindIssuance::finalize_message`]: blinded token + issuer attestation + message digest.
#[derive(Clone)]
pub struct UnblindedBlindSignature {
    /// Inner blind issuance bundle.
    pub issuance: UnblindedIssuance,
    /// [`blind_message_digest`] of the signed application message.
    pub message_digest: [u8; 32],
}

/// Trait for verifying blind-signature–style bundles that bind an application message.
///
/// Naming aligns with blind-signature literature: [`BlindSignature::verify_signature`] is the
/// public verifier entry point; [`BlindIssuance::issuer_sign_message`] / [`BlindIssuance::finalize_message`]
/// implement the issuer-side **blind sign** and user-side **unblind** steps for the pilot CRS model.
pub trait BlindSignature {
    /// Verify commitment consistency, issuer attestation, and message digest binding.
    fn verify_blind_signature(
        &self,
        key: &AjtaiCommitmentKey,
        base_ctx: &[u8],
        tau: usize,
        z_inf_bound: i32,
    ) -> Result<(), VerifyError>;

    /// Synonym for [`Self::verify_blind_signature`] (Phase 7 plan surface: `verify_signature`).
    fn verify_signature(
        &self,
        key: &AjtaiCommitmentKey,
        base_ctx: &[u8],
        tau: usize,
        z_inf_bound: i32,
    ) -> Result<(), VerifyError> {
        self.verify_blind_signature(key, base_ctx, tau, z_inf_bound)
    }
}

impl BlindSignature for UnblindedBlindSignature {
    fn verify_blind_signature(
        &self,
        key: &AjtaiCommitmentKey,
        base_ctx: &[u8],
        tau: usize,
        z_inf_bound: i32,
    ) -> Result<(), VerifyError> {
        BlindIssuance::verify_message(
            key,
            &self.issuance,
            base_ctx,
            &self.message_digest,
            tau,
            z_inf_bound,
        )
    }
}

/// User-side state after [`BlindIssuance::request`].
#[derive(Clone)]
pub struct BlindUserState {
    /// Blinded token commitment `Com(user + blind)`.
    pub com_blinded: AjtaiCommitment,
    pub user_opening: AjtaiOpening,
    pub blind_opening: AjtaiOpening,
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
#[derive(Clone)]
pub struct UnblindedIssuance {
    pub com_blinded: AjtaiCommitment,
    /// Opening for `com_blinded` (= user + blind).
    pub token_opening: AjtaiOpening,
    pub issuer_com: AjtaiCommitment,
    pub issuer_proof: OpeningProof,
}

/// CRS-style blind issuance orchestration (see design note: not Chaum blind RSA).
pub struct BlindIssuance;

impl BlindIssuance {
    /// User samples blinding, returns the blinded commitment for the issuer.
    pub fn request<R: Rng + CryptoRng>(
        rng: &mut R,
        key: &AjtaiCommitmentKey,
        user_opening: AjtaiOpening,
    ) -> Result<(BlindRequest, BlindUserState), ProofError> {
        let blind_opening = sample_random_opening(rng, key);
        let com_blinded = blinded_commitment(key, &user_opening, &blind_opening)
            .ok_or(ProofError::InvalidParameters)?;
        let req = BlindRequest {
            com_blinded: com_blinded.clone(),
        };
        let st = BlindUserState {
            com_blinded,
            user_opening,
            blind_opening,
        };
        Ok((req, st))
    }

    /// Issuer produces a Schnorr-style opening proof whose FS context includes the
    /// serialized blinded commitment, issuer public image, and [`blind_message_digest`].
    #[allow(clippy::too_many_arguments)] // Fiat–Shamir sigma API: explicit public inputs
    pub fn issuer_sign_message<R: Rng + CryptoRng>(
        rng: &mut R,
        key: &AjtaiCommitmentKey,
        blind_req: &BlindRequest,
        issuer: &BlindIssuerKeypair,
        message: &[u8],
        base_ctx: &[u8],
        tau: usize,
        z_inf_bound: i32,
        max_attempts: usize,
    ) -> Result<(BlindResponse, [u8; 32]), ProofError> {
        let digest = blind_message_digest(message);
        let issuer_com = issuer.public_commitment.clone();
        let blind_wire = write_module_vec(&blind_req.com_blinded.value.0);
        let issuer_wire = issuer.public_commitment_wire();
        let extra = issuance_blind_message_extra(&blind_wire, &issuer_wire, &digest);
        let ctx = issuance_transcript_ctx(base_ctx, BLIND_ISSUER_FS_LABEL, &extra);
        let issuer_proof = prove_opening(
            rng,
            key,
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
        key: &AjtaiCommitmentKey,
        blind_req: &BlindRequest,
        issuer_opening: &AjtaiOpening,
        base_ctx: &[u8],
        tau: usize,
        z_inf_bound: i32,
        max_attempts: usize,
    ) -> Result<BlindResponse, ProofError> {
        let issuer_com = commit(key, issuer_opening);
        let blind_wire = write_module_vec(&blind_req.com_blinded.value.0);
        let extra = blind_wire;
        let ctx = issuance_transcript_ctx(base_ctx, BLIND_ISSUER_FS_LABEL, &extra);
        let issuer_proof = prove_opening(
            rng,
            key,
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
        let token_opening = aggregate_opening(&user.user_opening, &user.blind_opening)
            .ok_or(ProofError::InvalidParameters)?;
        Ok(UnblindedIssuance {
            com_blinded: user.com_blinded,
            token_opening,
            issuer_com: resp.issuer_com,
            issuer_proof: resp.issuer_proof,
        })
    }

    /// [`BlindIssuance::finalize`] plus carried [`blind_message_digest`] for [`BlindSignature`] verification.
    ///
    /// **Unblinding (pilot CRS model):** the issuer’s attestation [`BlindResponse::issuer_proof`]
    /// is unchanged, while the aggregated [`UnblindedIssuance::token_opening`] is the sum of the
    /// user and blinding openings—so the separate blinding randomness is **not** carried as an
    /// independent component on the wire after this step (it is folded into the token witness).
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
    pub fn verify(
        key: &AjtaiCommitmentKey,
        bundle: &UnblindedIssuance,
        base_ctx: &[u8],
        tau: usize,
        z_inf_bound: i32,
    ) -> Result<(), VerifyError> {
        let expect = commit(key, &bundle.token_opening);
        if expect != bundle.com_blinded {
            return Err(VerifyError::Rejected);
        }
        let blind_wire = write_module_vec(&bundle.com_blinded.value.0);
        let ctx = issuance_transcript_ctx(base_ctx, BLIND_ISSUER_FS_LABEL, &blind_wire);
        verify_opening(
            key,
            &bundle.issuer_com,
            &bundle.issuer_proof,
            &ctx,
            tau,
            z_inf_bound,
        )
    }

    /// Verify [`UnblindedBlindSignature`]: token opening, issuer attestation, and message digest.
    pub fn verify_message(
        key: &AjtaiCommitmentKey,
        bundle: &UnblindedIssuance,
        base_ctx: &[u8],
        message_digest: &[u8; 32],
        tau: usize,
        z_inf_bound: i32,
    ) -> Result<(), VerifyError> {
        let expect = commit(key, &bundle.token_opening);
        if expect != bundle.com_blinded {
            return Err(VerifyError::Rejected);
        }
        let blind_wire = write_module_vec(&bundle.com_blinded.value.0);
        let issuer_wire = write_module_vec(&bundle.issuer_com.value.0);
        let extra = issuance_blind_message_extra(&blind_wire, &issuer_wire, message_digest);
        let ctx = issuance_transcript_ctx(base_ctx, BLIND_ISSUER_FS_LABEL, &extra);
        verify_opening(
            key,
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
    use lib_q_ring::Poly;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    use super::*;
    use crate::params::AjtaiParameters;
    use crate::serialize::write_module_vec;
    use crate::sigma::opening::sample_random_opening;

    #[inline]
    fn test_seed32(tag: u64) -> [u8; 32] {
        let mut seed = [0u8; 32];
        seed[0..8].copy_from_slice(&tag.to_le_bytes());
        seed
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
        let params = AjtaiParameters::new(2, 1);
        let key = AjtaiCommitmentKey {
            seed: [0xCDu8; 32],
            params,
        };
        let mut mu = alloc::vec![Poly::zero(), Poly::zero()];
        mu[0].coeffs[0] = 9;
        let user = AjtaiOpening {
            message: ModuleVec(mu),
            randomness: ModuleVec(alloc::vec![Poly::zero()]),
        };
        let mut rng = ChaCha8Rng::from_seed(test_seed32(0xB10C_u64));
        let (req, user_st) = BlindIssuance::request(&mut rng, &key, user).expect("request");
        let issuer_opening = sample_random_opening(&mut rng, &key);
        let resp = BlindIssuance::issuer_sign(
            &mut rng,
            &key,
            &req,
            &issuer_opening,
            b"realm",
            39,
            20_000_000,
            512,
        )
        .expect("issuer");
        let bundle = BlindIssuance::finalize(user_st, resp).expect("finalize");
        BlindIssuance::verify(&key, &bundle, b"realm", 39, 20_000_000).expect("verify");
    }

    #[test]
    fn blind_signature_message_roundtrip_and_wrong_message_fails() {
        let params = AjtaiParameters::new(2, 1);
        let key = AjtaiCommitmentKey {
            seed: [0xE1u8; 32],
            params,
        };
        let mut mu = alloc::vec![Poly::zero(), Poly::zero()];
        mu[0].coeffs[0] = 2;
        let user = AjtaiOpening {
            message: ModuleVec(mu),
            randomness: ModuleVec(alloc::vec![Poly::zero()]),
        };
        let mut rng = ChaCha8Rng::from_seed(test_seed32(0x51AE_u64));
        let (req, user_st) = BlindIssuance::request(&mut rng, &key, user).expect("request");
        let issuer = BlindIssuerKeypair::sample(&mut rng, &key);
        let (resp, digest) = BlindIssuance::issuer_sign_message(
            &mut rng,
            &key,
            &req,
            &issuer,
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
            .verify_signature(&key, b"realm-ms", 39, 20_000_000)
            .expect("BlindSignature::verify_signature alias");

        let mut bad = bundle.clone();
        bad.message_digest[0] ^= 0xFF;
        assert!(
            BlindIssuance::verify_message(
                &key,
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
        let params = AjtaiParameters::new(2, 1);
        let key = AjtaiCommitmentKey {
            seed: [0xA7u8; 32],
            params,
        };
        let mut mu = alloc::vec![Poly::zero(), Poly::zero()];
        mu[0].coeffs[0] = 3;
        let user = AjtaiOpening {
            message: ModuleVec(mu),
            randomness: ModuleVec(alloc::vec![Poly::zero()]),
        };
        let mut rng = ChaCha8Rng::from_seed(test_seed32(0xBAD_u64));
        let (req, user_st) = BlindIssuance::request(&mut rng, &key, user).expect("request");
        let issuer = BlindIssuerKeypair::sample(&mut rng, &key);
        let other = BlindIssuerKeypair::sample(&mut rng, &key);
        let (mut resp, digest) = BlindIssuance::issuer_sign_message(
            &mut rng, &key, &req, &issuer, b"policy", b"ctx", 39, 20_000_000, 512,
        )
        .expect("issuer msg");
        resp.issuer_com = other.public_commitment;
        let bundle = BlindIssuance::finalize_message(user_st, resp, digest).expect("finalize");
        assert!(
            bundle
                .verify_blind_signature(&key, b"ctx", 39, 20_000_000)
                .is_err(),
            "replacing issuer commitment must break attestation verification"
        );
    }

    #[test]
    fn blind_signature_same_message_unlinkable_across_sessions() {
        let params = AjtaiParameters::new(2, 1);
        let key = AjtaiCommitmentKey {
            seed: [0xB2u8; 32],
            params,
        };
        let mut mu = alloc::vec![Poly::zero(), Poly::zero()];
        mu[0].coeffs[0] = 1;
        let user = AjtaiOpening {
            message: ModuleVec(mu.clone()),
            randomness: ModuleVec(alloc::vec![Poly::zero()]),
        };
        let mut issuer_rng = ChaCha8Rng::from_seed(test_seed32(1));
        let issuer = BlindIssuerKeypair::sample(&mut issuer_rng, &key);

        let mut r1 = ChaCha8Rng::from_seed(test_seed32(0x111_u64));
        let (req1, st1) = BlindIssuance::request(&mut r1, &key, user.clone()).expect("r1");
        let (resp1, d1) = BlindIssuance::issuer_sign_message(
            &mut r1,
            &key,
            &req1,
            &issuer,
            b"same-msg",
            b"ctx-u",
            39,
            20_000_000,
            512,
        )
        .expect("i1");
        let b1 = BlindIssuance::finalize_message(st1, resp1, d1).expect("f1");

        let mut r2 = ChaCha8Rng::from_seed(test_seed32(0x222_u64));
        let (req2, st2) = BlindIssuance::request(&mut r2, &key, user).expect("r2");
        let (resp2, d2) = BlindIssuance::issuer_sign_message(
            &mut r2,
            &key,
            &req2,
            &issuer,
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
}
