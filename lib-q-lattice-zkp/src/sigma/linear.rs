//! Linear relation `L·wit = t` layered on the opening protocol.

use lib_q_ring::{
    ModuleMatrix,
    ModuleVec,
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
use crate::sigma::opening::{
    self,
    OpeningProof,
};
use crate::util::{
    module_add,
    module_infinity_norm,
    module_ring_mul_challenge,
    polys_ct_eq,
};

/// Opening proof plus `u = L·y`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinearRelationProof {
    /// Base opening data.
    pub opening: OpeningProof,
    /// `L · y`.
    pub u: ModuleVec,
}

/// Prove `L·wit = t` for public `L`, `t` (time domain).
#[allow(clippy::too_many_arguments)]
pub fn prove_linear<R: Rng + CryptoRng>(
    rng: &mut R,
    key: &AjtaiCommitmentKey,
    opening: &AjtaiOpening,
    com: &AjtaiCommitment,
    l: &ModuleMatrix,
    t: &ModuleVec,
    ctx: &[u8],
    tau: usize,
    z_inf_bound: i32,
    max_attempts: usize,
) -> Result<LinearRelationProof, ProofError> {
    if l.cols != key.params.witness_len() || l.rows != t.0.len() {
        return Err(ProofError::InvalidParameters);
    }
    let l_times_wit = l.mul_vec(&ModuleVec(opening::witness_vec(opening)));
    if l_times_wit.0.len() != t.0.len() || !bool::from(polys_ct_eq(&l_times_wit.0, &t.0)) {
        return Err(ProofError::InvalidParameters);
    }

    let wit = opening::witness_vec(opening);
    let matrix =
        ModuleMatrix::expand_from_seed(&key.seed, key.params.module_rank, key.params.witness_len());

    for _ in 0..max_attempts {
        let y: alloc::vec::Vec<_> = (0..wit.len())
            .map(|_| opening::sample_uniform_poly(rng))
            .collect();
        let w = matrix.mul_vec(&ModuleVec(y.clone()));
        let u = l.mul_vec(&ModuleVec(y.clone()));

        let mut h = lib_q_sha3::Shake256::default();
        lib_q_sha3::Update::update(&mut h, ctx);
        lib_q_sha3::Update::update(&mut h, &write_module_vec(&w.0));
        let mut reader = lib_q_sha3::ExtendableOutput::finalize_xof(h);
        let mut xof_seed = [0u8; 32];
        lib_q_sha3::XofReader::read(&mut reader, &mut xof_seed);
        let c = lib_q_ring::sample_in_ball(&xof_seed, tau);

        let mut z = alloc::vec::Vec::with_capacity(wit.len());
        for (yi, wi) in y.iter().zip(wit.iter()) {
            let mut tp = yi.clone();
            tp.add_assign(&crate::util::ring_mul(&c, wi));
            z.push(tp);
        }

        if module_infinity_norm(&z) <= z_inf_bound {
            let proof = LinearRelationProof {
                opening: OpeningProof { w, z: ModuleVec(z) },
                u,
            };
            // Keep sampling unless the full linear verification equation accepts this transcript.
            if verify_linear(key, com, &proof, l, t, ctx, tau, z_inf_bound).is_ok() {
                return Ok(proof);
            }
        }
    }
    Err(ProofError::RejectionLimit)
}

/// Verify linear relation (includes opening verification).
#[allow(clippy::too_many_arguments)]
pub fn verify_linear(
    key: &AjtaiCommitmentKey,
    com: &AjtaiCommitment,
    proof: &LinearRelationProof,
    l: &ModuleMatrix,
    t: &ModuleVec,
    ctx: &[u8],
    tau: usize,
    z_inf_bound: i32,
) -> Result<(), VerifyError> {
    opening::verify_opening(key, com, &proof.opening, ctx, tau, z_inf_bound)?;
    if proof.u.0.len() != l.rows || l.cols != key.params.witness_len() {
        return Err(VerifyError::InvalidFormat);
    }

    let mut h = lib_q_sha3::Shake256::default();
    lib_q_sha3::Update::update(&mut h, ctx);
    lib_q_sha3::Update::update(&mut h, &write_module_vec(&proof.opening.w.0));
    let mut reader = lib_q_sha3::ExtendableOutput::finalize_xof(h);
    let mut xof_seed = [0u8; 32];
    lib_q_sha3::XofReader::read(&mut reader, &mut xof_seed);
    let c = lib_q_ring::sample_in_ball(&xof_seed, tau);

    let lhs = l.mul_vec(&proof.opening.z);
    let rhs = module_add(&proof.u.0, &module_ring_mul_challenge(&c, &t.0))?;
    if lhs.0.len() != rhs.len() || !bool::from(polys_ct_eq(&lhs.0, &rhs)) {
        return Err(VerifyError::Rejected);
    }
    Ok(())
}
