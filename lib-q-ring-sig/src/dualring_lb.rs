//! DualRing-LB ring signatures over the shared Ajtai CRS.
//!
//! This module wires the DualRing construction from Beullens et al. (CCS 2021, ePrint 2021/1213,
//! Algorithm 3) into the opening identification scheme from [`lib_q_lattice_zkp`]: one response `z`
//! and challenges `c_1, …, c_n` with `Σ_i c_i = H(ctx ‖ R)` and
//! `R = A·y − Σ_{i≠j} c_i · Com_i` for signer index `j`. Verification is a **single** aggregated check
//! ([`lib_q_lattice_zkp::verify_dual_ring_opening`]); work and control flow do not depend on which
//! ring member signed.
//!
//! The Fiat–Shamir context extends the federation digest with per-index domain labels (same
//! absorption as before) so the ring and message bind into `ctx`.
//!
//! **Parameter note:** The paper’s Section 7 uses a coefficient-wise mod-3 challenge group; this
//! integration keeps the ML-DSA–compatible sparse ball from [`lib_q_ring::sample_in_ball`] for the
//! hashed aggregate `c = H(ctx ‖ R)` only. Decoy challenges `c_i` (for `i ≠ j`) are independent ball
//! samples; the adjusted `c_j` lies in `R_q` but is not required to be sparse.

use alloc::vec::Vec;

pub use lib_q_lattice_zkp::DualRingOpeningProof;
use lib_q_lattice_zkp::{
    AjtaiCommitment,
    AjtaiCommitmentKey,
    AjtaiOpening,
    ProofError,
    VerifyError,
    prove_dual_ring_opening,
    verify_dual_ring_opening,
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

use crate::ring::federation_digest;
use crate::sign::federation_signing_context;

const DUALRING_LB_CTX_TAG: &[u8] = b"lib-q-ring-sig/dualring-lb-v1";

/// Pilot “dual challenge ring” material: per-member SHAKE256 digests bound to the federation digest.
///
/// The signing context [`dualring_lb_signing_context`] absorbs these labels so the Fiat–Shamir
/// transcript binds each ring slot; see [`DualRingLbChallengeState`] for inspection and tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DualRingLbChallengeState {
    /// `federation_digest(ring)`.
    pub federation_digest: [u8; 32],
    /// One 32-byte label per ring slot (same order as `ring`).
    pub per_member_challenge_digest: Vec<[u8; 32]>,
}

/// Build the per-index challenge labels used inside [`dualring_lb_signing_context`].
#[must_use]
pub fn dualring_lb_challenge_state(
    ring: &[AjtaiCommitment],
    message: &[u8],
) -> DualRingLbChallengeState {
    let federation_digest = federation_digest(ring);
    let mut per_member_challenge_digest = Vec::with_capacity(ring.len());
    for i in 0..ring.len() {
        let mut h = lib_q_sha3::Shake256::default();
        h.update(b"lib-q-ring-sig/dualring-lb-challenge");
        h.update(&federation_digest);
        h.update(&(i as u64).to_le_bytes());
        h.update(&(message.len() as u64).to_le_bytes());
        h.update(message);
        let mut s = [0u8; 32];
        let mut r = h.finalize_xof();
        XofReader::read(&mut r, &mut s);
        per_member_challenge_digest.push(s);
    }
    DualRingLbChallengeState {
        federation_digest,
        per_member_challenge_digest,
    }
}

/// Serialized DualRing-LB opening: additive challenge ring + response `z`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DualRingLbSignature {
    /// Inner DualRing opening proof (`c_1, …, c_n`, `z`).
    pub proof: DualRingOpeningProof,
}

impl From<DualRingOpeningProof> for DualRingLbSignature {
    fn from(proof: DualRingOpeningProof) -> Self {
        Self { proof }
    }
}

impl From<DualRingLbSignature> for DualRingOpeningProof {
    fn from(sig: DualRingLbSignature) -> Self {
        sig.proof
    }
}

/// Fiat–Shamir context: federation context plus per-index domain-separated digests.
#[must_use]
pub fn dualring_lb_signing_context(ring: &[AjtaiCommitment], message: &[u8]) -> Vec<u8> {
    let st = dualring_lb_challenge_state(ring, message);
    let mut v = federation_signing_context(ring, message);
    v.push(2);
    v.extend_from_slice(DUALRING_LB_CTX_TAG);
    for s in &st.per_member_challenge_digest {
        v.extend_from_slice(s);
    }
    v
}

/// Sign with the DualRing-LB transcript (aggregated verification).
#[allow(clippy::too_many_arguments)]
pub fn sign_dualring_lb<R: Rng + CryptoRng>(
    rng: &mut R,
    crs: &AjtaiCommitmentKey,
    member_opening: &AjtaiOpening,
    member_com: &AjtaiCommitment,
    ring: &[AjtaiCommitment],
    message: &[u8],
    tau: usize,
    z_inf_bound: i32,
    max_attempts: usize,
) -> Result<DualRingLbSignature, ProofError> {
    let signer_idx = ring
        .iter()
        .position(|c| c == member_com)
        .ok_or(ProofError::InvalidParameters)?;
    let ctx = dualring_lb_signing_context(ring, message);
    let proof = prove_dual_ring_opening(
        rng,
        crs,
        member_opening,
        ring,
        signer_idx,
        &ctx,
        tau,
        z_inf_bound,
        max_attempts,
    )?;
    Ok(DualRingLbSignature { proof })
}

/// Verify a DualRing-LB signature using the aggregated DualRing equation (CCS 2021, Algorithm 3).
#[allow(clippy::too_many_arguments)]
pub fn verify_dualring_lb(
    crs: &AjtaiCommitmentKey,
    ring: &[AjtaiCommitment],
    message: &[u8],
    sig: &DualRingLbSignature,
    tau: usize,
    z_inf_bound: i32,
) -> Result<(), VerifyError> {
    let ctx = dualring_lb_signing_context(ring, message);
    verify_dual_ring_opening(crs, ring, &sig.proof, &ctx, tau, z_inf_bound)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use lib_q_lattice_zkp::{
        AjtaiCommitmentKey,
        AjtaiOpening,
        AjtaiParameters,
    };
    use lib_q_random::new_deterministic_rng;
    use lib_q_ring::{
        ModuleVec,
        Poly,
    };

    use super::*;

    #[inline]
    fn test_deterministic_seed32(tag: u64) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[0..8].copy_from_slice(&tag.to_le_bytes());
        s
    }

    fn pilot_crs() -> AjtaiCommitmentKey {
        AjtaiCommitmentKey {
            seed: [0x5Du8; 32],
            params: AjtaiParameters::new(2, 1),
        }
    }

    #[test]
    fn dualring_lb_challenge_state_matches_signing_context_absorption() {
        let key = pilot_crs();
        let o0 = AjtaiOpening {
            message: ModuleVec(vec![Poly::zero(), Poly::zero()]),
            randomness: ModuleVec(vec![Poly::zero()]),
        };
        let c0 = lib_q_lattice_zkp::commit(&key, &o0);
        let msg = b"ctx-bind";
        let st = dualring_lb_challenge_state(core::slice::from_ref(&c0), msg);
        assert_eq!(st.per_member_challenge_digest.len(), 1);
        let full = dualring_lb_signing_context(core::slice::from_ref(&c0), msg);
        assert!(
            full.windows(32)
                .any(|w| w == st.per_member_challenge_digest[0]),
            "signing context must contain the per-member digest"
        );
    }

    #[test]
    fn dualring_lb_ring_of_one_matches_opening_proof() {
        let key = pilot_crs();
        let tau = 39;
        let z = 20_000_000;
        let max = 512;
        let o = AjtaiOpening {
            message: ModuleVec(vec![Poly::zero(), Poly::zero()]),
            randomness: ModuleVec(vec![Poly::zero()]),
        };
        let com = lib_q_lattice_zkp::commit(&key, &o);
        let ring = [com.clone()];
        let msg = b"singleton";
        let mut rng = new_deterministic_rng(test_deterministic_seed32(0x51A1_u64));
        let sig =
            sign_dualring_lb(&mut rng, &key, &o, &com, &ring, msg, tau, z, max).expect("sign");
        verify_dualring_lb(&key, &ring, msg, &sig, tau, z).expect("verify ring of 1");
    }

    #[test]
    fn dualring_lb_wrong_message_rejected() {
        let key = pilot_crs();
        let tau = 39;
        let z = 20_000_000;
        let max = 512;
        let mut o = AjtaiOpening {
            message: ModuleVec(vec![Poly::zero(), Poly::zero()]),
            randomness: ModuleVec(vec![Poly::zero()]),
        };
        o.randomness.0[0].coeffs[0] = 1;
        let com = lib_q_lattice_zkp::commit(&key, &o);
        let ring = [com.clone()];
        let msg = b"signed-once";
        let mut rng = new_deterministic_rng(test_deterministic_seed32(0xC0FFEE_u64));
        let sig =
            sign_dualring_lb(&mut rng, &key, &o, &com, &ring, msg, tau, z, max).expect("sign");
        verify_dualring_lb(&key, &ring, msg, &sig, tau, z).expect("verify");
        assert!(
            verify_dualring_lb(&key, &ring, b"other-msg", &sig, tau, z).is_err(),
            "verify must reject wrong message when commitment is non-zero"
        );
    }

    #[test]
    fn dualring_lb_wrong_ring_member_rejected() {
        let key = pilot_crs();
        let tau = 39;
        let z = 20_000_000;
        let max = 512;
        let o_a = AjtaiOpening {
            message: ModuleVec(vec![Poly::zero(), Poly::zero()]),
            randomness: ModuleVec(vec![Poly::zero()]),
        };
        let mut o_b = AjtaiOpening {
            message: ModuleVec(vec![Poly::zero(), Poly::zero()]),
            randomness: ModuleVec(vec![Poly::zero()]),
        };
        o_b.message.0[0].coeffs[0] = 3;
        let com_a = lib_q_lattice_zkp::commit(&key, &o_a);
        let com_b = lib_q_lattice_zkp::commit(&key, &o_b);
        let ring = [com_a.clone(), com_b.clone()];
        let msg = b"fed-dual";
        let mut rng = new_deterministic_rng(test_deterministic_seed32(0xD06_u64));
        let sig = sign_dualring_lb(&mut rng, &key, &o_b, &com_b, &ring, msg, tau, z, max)
            .expect("sign b");
        let wrong_ring = [com_a.clone(), com_a];
        assert!(
            verify_dualring_lb(&key, &wrong_ring, msg, &sig, tau, z).is_err(),
            "proof for member B must not verify as member A"
        );
    }
}
