//! DualRing-LB–style ring signatures over the shared Ajtai CRS.
//!
//! This module implements a **pilot** integration on top of the existing Schnorr-style opening
//! proofs from [`lib_q_lattice_zkp`]: the Fiat–Shamir transcript is extended with per-index domain
//! labels so the verifier runs a **full-ring** check without short-circuiting on the first success
//! (mitigating a timing channel that reveals the signer index to a local observer).
//!
//! The transcript shape follows the DualRing idea of absorbing the whole ring into the hash
//! before deriving the sparse challenge; a full Beullens–Yuen *et al.* (ePrint 2021/1213)
//! `Algorithm 6` key schedule is **not** wired here—the public keys remain Ajtai commitment images
//! under the CRS from [`crate::keygen::MemberIssuerKey`].
//!
//! Cryptographic anonymity against a malicious verifier still requires the paper’s aggregated
//! verification equation; until that lands, treat this path as **hardened federation openings**
//! with a DualRing-oriented transcript.

use alloc::vec::Vec;

use lib_q_lattice_zkp::{
    AjtaiCommitment,
    AjtaiCommitmentKey,
    AjtaiOpening,
    OpeningProof,
    ProofError,
    VerifyError,
    prove_opening,
    verify_opening,
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
use subtle::{
    Choice,
    ConstantTimeEq,
};

use crate::ring::federation_digest;
use crate::sign::federation_signing_context;

const DUALRING_LB_CTX_TAG: &[u8] = b"lib-q-ring-sig/dualring-lb-v1";

/// Pilot “dual challenge ring” material: per-member SHAKE256 digests bound to the federation digest.
///
/// A full DualRing-LB construction (Beullens et al., CCS 2021) requires a **linked** challenge ring
/// with a sum closure in the signing algebra; this type exposes only the **independent** per-index
/// labels that [`dualring_lb_signing_context`] absorbs. Use it for transcript inspection, tests, and
/// future aggregation work.
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

/// Serialized opening proof with a DualRing-LB-oriented Fiat–Shamir transcript.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DualRingLbSignature {
    /// Inner opening proof `(w, z)`.
    pub opening_proof: OpeningProof,
}

impl From<OpeningProof> for DualRingLbSignature {
    fn from(opening_proof: OpeningProof) -> Self {
        Self { opening_proof }
    }
}

impl From<DualRingLbSignature> for OpeningProof {
    fn from(sig: DualRingLbSignature) -> Self {
        sig.opening_proof
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

/// Sign with the DualRing-LB transcript (same witness relation as federation openings).
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
    let ctx = dualring_lb_signing_context(ring, message);
    let opening_proof = prove_opening(
        rng,
        crs,
        member_opening,
        member_com,
        &ctx,
        tau,
        z_inf_bound,
        max_attempts,
    )?;
    Ok(DualRingLbSignature { opening_proof })
}

/// Verify a DualRing-LB signature without short-circuiting on the signer index.
///
/// Every ring position is checked; the aggregate result is combined with [`Choice`] so the control
/// flow does not return early on success. This is **not** the CCS 2021 paper’s single linked
/// verification equation (that remains future work); it is a constant-time **OR** over per-member
/// [`verify_opening`] checks so local timing does not reveal which index matched first.
pub fn verify_dualring_lb(
    crs: &AjtaiCommitmentKey,
    ring: &[AjtaiCommitment],
    message: &[u8],
    sig: &DualRingLbSignature,
    tau: usize,
    z_inf_bound: i32,
) -> Result<(), VerifyError> {
    let ctx = dualring_lb_signing_context(ring, message);
    let mut any_ok = Choice::from(0u8);
    for com in ring {
        let ok = verify_opening(crs, com, &sig.opening_proof, &ctx, tau, z_inf_bound).is_ok();
        any_ok |= Choice::from(ok as u8);
    }
    if bool::from(any_ok.ct_eq(&Choice::from(1u8))) {
        Ok(())
    } else {
        Err(VerifyError::Rejected)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use core::convert::Infallible;

    use lib_q_lattice_zkp::{
        AjtaiCommitmentKey,
        AjtaiOpening,
        AjtaiParameters,
    };
    use lib_q_ring::{
        ModuleVec,
        Poly,
    };
    use rand_core::{
        TryCryptoRng,
        TryRng,
    };

    use super::*;

    #[derive(Debug)]
    struct TestRng(u64);

    impl TryRng for TestRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            Ok((self.0 >> 32) as u32)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(((self.try_next_u32()? as u64) << 32) | u64::from(self.try_next_u32()?))
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            let mut i = 0usize;
            while i < dst.len() {
                let v = self.try_next_u32()?.to_le_bytes();
                let take = (dst.len() - i).min(4);
                dst[i..i + take].copy_from_slice(&v[..take]);
                i += take;
            }
            Ok(())
        }
    }

    impl TryCryptoRng for TestRng {}

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
        let mut rng = TestRng(0x51A1_u64);
        let sig =
            sign_dualring_lb(&mut rng, &key, &o, &com, &ring, msg, tau, z, max).expect("sign");
        verify_dualring_lb(&key, &ring, msg, &sig, tau, z).expect("verify ring of 1");
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
        let mut rng = TestRng(0xD06_u64);
        let sig = sign_dualring_lb(&mut rng, &key, &o_b, &com_b, &ring, msg, tau, z, max)
            .expect("sign b");
        let wrong_ring = [com_a.clone(), com_a];
        assert!(
            verify_dualring_lb(&key, &wrong_ring, msg, &sig, tau, z).is_err(),
            "proof for member B must not verify as member A"
        );
    }
}
