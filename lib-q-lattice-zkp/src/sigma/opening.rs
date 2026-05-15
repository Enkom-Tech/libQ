//! Schnorr-style opening proof for `com = A·wit` with sparse ternary challenge.

use alloc::vec::Vec;

use lib_q_ring::{
    ModuleMatrix,
    ModuleVec,
    Poly,
};
use rand_core::{
    CryptoRng,
    Rng,
};

use crate::commitment::{
    AjtaiCommitment,
    AjtaiCommitmentKey,
    AjtaiOpening,
};
use crate::error::{
    ProofError,
    VerifyError,
};
use crate::serialize::write_module_vec;
use crate::util::{
    module_add,
    module_infinity_norm,
    module_ring_mul_challenge,
    module_sub,
    polys_ct_eq,
};

/// Mask `w = A·y` and response `z = y + c·wit`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpeningProof {
    /// `A · y`.
    pub w: ModuleVec,
    /// `y + c · wit` (per witness slot).
    pub z: ModuleVec,
}

pub(crate) fn witness_vec(opening: &AjtaiOpening) -> Vec<Poly> {
    let mut v = Vec::with_capacity(opening.randomness.0.len() + opening.message.0.len());
    v.extend_from_slice(&opening.randomness.0);
    v.extend_from_slice(&opening.message.0);
    v
}

fn fs_sparse_challenge(ctx: &[u8], first_message: &[Poly], tau: usize) -> Poly {
    let mut h = lib_q_sha3::Shake256::default();
    lib_q_sha3::Update::update(&mut h, ctx);
    lib_q_sha3::Update::update(&mut h, &write_module_vec(first_message));
    let mut reader = lib_q_sha3::ExtendableOutput::finalize_xof(h);
    let mut xof_seed = [0u8; 32];
    lib_q_sha3::XofReader::read(&mut reader, &mut xof_seed);
    lib_q_ring::sample_in_ball(&xof_seed, tau)
}

fn sum_challenge_polys(ch: &[Poly]) -> Poly {
    let mut acc = Poly::zero();
    for p in ch {
        acc.add_assign(p);
    }
    acc
}

pub(crate) fn sample_uniform_poly<R: Rng + CryptoRng>(rng: &mut R) -> Poly {
    let mut coeffs = [0i32; 256];
    for c in &mut coeffs {
        *c = lib_q_ring::sample_uniform_field_coefficient(rng);
    }
    Poly::from_coeffs(coeffs)
}

/// Sample a uniformly random opening with dimensions from `key.params`.
#[must_use]
pub fn sample_random_opening<R: Rng + CryptoRng>(
    rng: &mut R,
    key: &AjtaiCommitmentKey,
) -> AjtaiOpening {
    let p = &key.params;
    let message: Vec<Poly> = (0..p.module_rank)
        .map(|_| sample_uniform_poly(rng))
        .collect();
    let randomness: Vec<Poly> = (0..p.randomness_dimension)
        .map(|_| sample_uniform_poly(rng))
        .collect();
    AjtaiOpening {
        message: ModuleVec(message),
        randomness: ModuleVec(randomness),
    }
}

/// Prove knowledge of `wit` with aborts (`max_attempts`).
#[allow(clippy::too_many_arguments)] // Fiat–Shamir sigma API: explicit public inputs
pub fn prove_opening<R: Rng + CryptoRng>(
    rng: &mut R,
    key: &AjtaiCommitmentKey,
    opening: &AjtaiOpening,
    com: &AjtaiCommitment,
    ctx: &[u8],
    tau: usize,
    z_inf_bound: i32,
    max_attempts: usize,
) -> Result<OpeningProof, ProofError> {
    let p = &key.params;
    if opening.message.0.len() != p.module_rank ||
        opening.randomness.0.len() != p.randomness_dimension ||
        com.value.0.len() != p.module_rank
    {
        return Err(ProofError::InvalidParameters);
    }
    let wit = witness_vec(opening);
    let matrix = ModuleMatrix::expand_from_seed(&key.seed, p.module_rank, p.witness_len());

    let expected_com = matrix.mul_vec(&ModuleVec(wit.clone()));
    if expected_com.0.len() != com.value.0.len() ||
        !bool::from(polys_ct_eq(&expected_com.0, &com.value.0))
    {
        return Err(ProofError::InvalidParameters);
    }

    for _ in 0..max_attempts {
        let y: Vec<Poly> = (0..wit.len()).map(|_| sample_uniform_poly(rng)).collect();
        let w = matrix.mul_vec(&ModuleVec(y.clone()));

        let c = fs_sparse_challenge(ctx, &w.0, tau);

        let mut z = Vec::with_capacity(wit.len());
        for (yi, wi) in y.iter().zip(wit.iter()) {
            let mut t = yi.clone();
            let cw = crate::util::ring_mul(&c, wi);
            t.add_assign(&cw);
            z.push(t);
        }

        if module_infinity_norm(&z) <= z_inf_bound {
            let proof = OpeningProof { w, z: ModuleVec(z) };
            // If the bound holds but the Schnorr check fails, keep sampling (same outer attempt
            // budget). This matches the intended "abort until a verifying transcript" semantics.
            if verify_opening(key, com, &proof, ctx, tau, z_inf_bound).is_ok() {
                return Ok(proof);
            }
        }
    }
    Err(ProofError::RejectionLimit)
}

/// Verify opening proof (public).
#[allow(clippy::too_many_arguments)]
pub fn verify_opening(
    key: &AjtaiCommitmentKey,
    com: &AjtaiCommitment,
    proof: &OpeningProof,
    ctx: &[u8],
    tau: usize,
    z_inf_bound: i32,
) -> Result<(), VerifyError> {
    let p = &key.params;
    if proof.w.0.len() != p.module_rank ||
        proof.z.0.len() != p.witness_len() ||
        com.value.0.len() != p.module_rank
    {
        return Err(VerifyError::InvalidFormat);
    }
    if module_infinity_norm(&proof.z.0) > z_inf_bound {
        return Err(VerifyError::Rejected);
    }

    let c = fs_sparse_challenge(ctx, &proof.w.0, tau);

    let matrix = ModuleMatrix::expand_from_seed(&key.seed, p.module_rank, p.witness_len());
    let lhs = matrix.mul_vec(&proof.z);
    let scaled_com = ModuleVec(module_ring_mul_challenge(&c, &com.value.0));
    let rhs = module_add(&proof.w.0, &scaled_com.0)?;

    if lhs.0.len() != rhs.len() || !bool::from(polys_ct_eq(&lhs.0, &rhs)) {
        return Err(VerifyError::Rejected);
    }
    Ok(())
}

/// DualRing opening (CCS 2021, Algorithm 3): additive challenge ring over `R_q` with one response `z`.
///
/// The Fiat–Shamir challenge is `c = H(ctx ‖ R)` with combined first message
/// `R = A·y − Σ_{i≠j} c_i · Com_i`. Challenges satisfy `Σ_i c_i = c` in `R_q` (coefficient-wise mod `q`);
/// only the hashed aggregate `c` is required to lie in the sparse ball from [`lib_q_ring::sample_in_ball`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DualRingOpeningProof {
    /// `c_1, …, c_n` (same order as `ring` in [`prove_dual_ring_opening`] / [`verify_dual_ring_opening`]).
    pub challenges: Vec<Poly>,
    /// `z = y + c_j · wit` for the signer slot `j`.
    pub z: ModuleVec,
}

/// Prove knowledge of an opening for `ring[signer_idx]` using the DualRing transcript in `ctx`.
#[allow(clippy::too_many_arguments)]
pub fn prove_dual_ring_opening<R: Rng + CryptoRng>(
    rng: &mut R,
    key: &AjtaiCommitmentKey,
    opening: &AjtaiOpening,
    ring: &[AjtaiCommitment],
    signer_idx: usize,
    ctx: &[u8],
    tau: usize,
    z_inf_bound: i32,
    max_attempts: usize,
) -> Result<DualRingOpeningProof, ProofError> {
    let p = &key.params;
    if ring.is_empty() || signer_idx >= ring.len() {
        return Err(ProofError::InvalidParameters);
    }
    if opening.message.0.len() != p.module_rank ||
        opening.randomness.0.len() != p.randomness_dimension ||
        ring[signer_idx].value.0.len() != p.module_rank
    {
        return Err(ProofError::InvalidParameters);
    }
    for com in ring {
        if com.value.0.len() != p.module_rank {
            return Err(ProofError::InvalidParameters);
        }
    }

    let wit = witness_vec(opening);
    let matrix = ModuleMatrix::expand_from_seed(&key.seed, p.module_rank, p.witness_len());
    let expected_com = matrix.mul_vec(&ModuleVec(wit.clone()));
    if expected_com.0.len() != ring[signer_idx].value.0.len() ||
        !bool::from(polys_ct_eq(&expected_com.0, &ring[signer_idx].value.0))
    {
        return Err(ProofError::InvalidParameters);
    }

    let n = ring.len();
    for _ in 0..max_attempts {
        let y: Vec<Poly> = (0..wit.len()).map(|_| sample_uniform_poly(rng)).collect();
        let ay = matrix.mul_vec(&ModuleVec(y.clone()));

        let mut challenges = alloc::vec![Poly::zero(); n];
        for (i, ch) in challenges.iter_mut().enumerate() {
            if i == signer_idx {
                continue;
            }
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            *ch = lib_q_ring::sample_in_ball(&seed, tau);
        }

        let mut r_combined = ay.0.clone();
        for (i, (com, ch_i)) in ring.iter().zip(challenges.iter()).enumerate() {
            if i == signer_idx {
                continue;
            }
            let scaled = module_ring_mul_challenge(ch_i, &com.value.0);
            r_combined =
                module_sub(&r_combined, &scaled).map_err(|_| ProofError::InvalidParameters)?;
        }

        let c_fs = fs_sparse_challenge(ctx, &r_combined, tau);

        let mut sum_others = Poly::zero();
        for (i, ch) in challenges.iter().enumerate() {
            if i == signer_idx {
                continue;
            }
            sum_others.add_assign(ch);
        }
        let mut cj = c_fs;
        cj.sub_assign(&sum_others);
        challenges[signer_idx] = cj;

        let mut z = Vec::with_capacity(wit.len());
        for (yi, wi) in y.iter().zip(wit.iter()) {
            let mut t = yi.clone();
            let cw = crate::util::ring_mul(&challenges[signer_idx], wi);
            t.add_assign(&cw);
            z.push(t);
        }

        if module_infinity_norm(&z) <= z_inf_bound {
            let proof = DualRingOpeningProof {
                challenges,
                z: ModuleVec(z),
            };
            if verify_dual_ring_opening(key, ring, &proof, ctx, tau, z_inf_bound).is_ok() {
                return Ok(proof);
            }
        }
    }
    Err(ProofError::RejectionLimit)
}

/// Verify a [`DualRingOpeningProof`] with one aggregated linear equation (no per-member short-circuit).
#[allow(clippy::too_many_arguments)]
pub fn verify_dual_ring_opening(
    key: &AjtaiCommitmentKey,
    ring: &[AjtaiCommitment],
    proof: &DualRingOpeningProof,
    ctx: &[u8],
    tau: usize,
    z_inf_bound: i32,
) -> Result<(), VerifyError> {
    let p = &key.params;
    if ring.is_empty() || proof.challenges.len() != ring.len() {
        return Err(VerifyError::InvalidFormat);
    }
    if proof.z.0.len() != p.witness_len() {
        return Err(VerifyError::InvalidFormat);
    }
    for com in ring {
        if com.value.0.len() != p.module_rank {
            return Err(VerifyError::InvalidFormat);
        }
    }
    if module_infinity_norm(&proof.z.0) > z_inf_bound {
        return Err(VerifyError::Rejected);
    }

    let matrix = ModuleMatrix::expand_from_seed(&key.seed, p.module_rank, p.witness_len());
    let lhs = matrix.mul_vec(&proof.z);

    let mut scaled_sum = alloc::vec![Poly::zero(); p.module_rank];
    for (com, ci) in ring.iter().zip(proof.challenges.iter()) {
        let part = module_ring_mul_challenge(ci, &com.value.0);
        for (acc, pp) in scaled_sum.iter_mut().zip(part.iter()) {
            acc.add_assign(pp);
        }
    }

    let r_rec = module_sub(&lhs.0, &scaled_sum)?;
    let c_fs = fs_sparse_challenge(ctx, &r_rec, tau);
    let c_sum = sum_challenge_polys(&proof.challenges);

    if !bool::from(polys_ct_eq(
        core::slice::from_ref(&c_sum),
        core::slice::from_ref(&c_fs),
    )) {
        return Err(VerifyError::Rejected);
    }
    Ok(())
}

#[cfg(test)]
mod dual_ring_opening_tests {
    use alloc::vec;

    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    use super::*;

    #[test]
    fn dual_ring_opening_singleton_roundtrip() {
        let key = AjtaiCommitmentKey {
            seed: [0x5Du8; 32],
            params: crate::params::AjtaiParameters::new(2, 1),
        };
        let tau = 39;
        let z_bound = 20_000_000;
        let max = 512;
        let o = AjtaiOpening {
            message: ModuleVec(vec![Poly::zero(), Poly::zero()]),
            randomness: ModuleVec(vec![Poly::zero()]),
        };
        let com = crate::commitment::commit(&key, &o);
        let ring = [com.clone()];
        let mut rng = ChaCha8Rng::from_seed([7u8; 32]);
        let ctx = b"dual-ring-ctx";
        let proof = prove_dual_ring_opening(&mut rng, &key, &o, &ring, 0, ctx, tau, z_bound, max)
            .expect("prove");
        verify_dual_ring_opening(&key, &ring, &proof, ctx, tau, z_bound).expect("verify");
    }

    #[test]
    fn dual_ring_opening_rejects_wrong_ctx() {
        let key = AjtaiCommitmentKey {
            seed: [0x5Du8; 32],
            params: crate::params::AjtaiParameters::new(2, 1),
        };
        let tau = 39;
        let z_bound = 20_000_000;
        let max = 512;
        let o = AjtaiOpening {
            message: ModuleVec(vec![Poly::zero(), Poly::zero()]),
            randomness: ModuleVec(vec![Poly::zero()]),
        };
        let com = crate::commitment::commit(&key, &o);
        let ring = [com];
        let mut rng = ChaCha8Rng::from_seed([9u8; 32]);
        let proof =
            prove_dual_ring_opening(&mut rng, &key, &o, &ring, 0, b"ctx-a", tau, z_bound, max)
                .expect("prove");
        assert!(verify_dual_ring_opening(&key, &ring, &proof, b"ctx-b", tau, z_bound).is_err());
    }

    #[test]
    fn dual_ring_opening_two_member_roundtrip() {
        let key = AjtaiCommitmentKey {
            seed: [0x3Cu8; 32],
            params: crate::params::AjtaiParameters::new(2, 1),
        };
        let tau = 39;
        let z_bound = 20_000_000;
        let max = 1024;
        let o0 = AjtaiOpening {
            message: ModuleVec(vec![Poly::zero(), Poly::zero()]),
            randomness: ModuleVec(vec![Poly::zero()]),
        };
        let mut m = vec![Poly::zero(), Poly::zero()];
        m[0].coeffs[0] = 5;
        let o1 = AjtaiOpening {
            message: ModuleVec(m),
            randomness: ModuleVec(vec![Poly::zero()]),
        };
        let c0 = crate::commitment::commit(&key, &o0);
        let c1 = crate::commitment::commit(&key, &o1);
        let ring = [c0, c1];
        let mut rng = ChaCha8Rng::from_seed([2u8; 32]);
        let ctx = b"two-slot";
        let proof = prove_dual_ring_opening(&mut rng, &key, &o1, &ring, 1, ctx, tau, z_bound, max)
            .expect("prove slot 1");
        verify_dual_ring_opening(&key, &ring, &proof, ctx, tau, z_bound).expect("verify");
    }
}
