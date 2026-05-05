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

pub(crate) fn sample_uniform_poly<R: Rng + CryptoRng>(rng: &mut R) -> Poly {
    let q = lib_q_ring::constants::FIELD_MODULUS as u32;
    let mut coeffs = [0i32; 256];
    for c in &mut coeffs {
        *c = (rng.next_u32() % q) as i32;
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

        let mut h = lib_q_sha3::Shake256::default();
        lib_q_sha3::Update::update(&mut h, ctx);
        lib_q_sha3::Update::update(&mut h, &write_module_vec(&w.0));
        let mut reader = lib_q_sha3::ExtendableOutput::finalize_xof(h);
        let mut xof_seed = [0u8; 32];
        lib_q_sha3::XofReader::read(&mut reader, &mut xof_seed);
        let c = lib_q_ring::sample_in_ball(&xof_seed, tau);

        let mut z = Vec::with_capacity(wit.len());
        for (yi, wi) in y.iter().zip(wit.iter()) {
            let mut t = yi.clone();
            let cw = crate::util::ring_mul(&c, wi);
            t.add_assign(&cw);
            z.push(t);
        }

        if module_infinity_norm(&z) <= z_inf_bound {
            return Ok(OpeningProof { w, z: ModuleVec(z) });
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

    let mut h = lib_q_sha3::Shake256::default();
    lib_q_sha3::Update::update(&mut h, ctx);
    lib_q_sha3::Update::update(&mut h, &write_module_vec(&proof.w.0));
    let mut reader = lib_q_sha3::ExtendableOutput::finalize_xof(h);
    let mut xof_seed = [0u8; 32];
    lib_q_sha3::XofReader::read(&mut reader, &mut xof_seed);
    let c = lib_q_ring::sample_in_ball(&xof_seed, tau);

    let matrix = ModuleMatrix::expand_from_seed(&key.seed, p.module_rank, p.witness_len());
    let lhs = matrix.mul_vec(&proof.z);
    let scaled_com = ModuleVec(module_ring_mul_challenge(&c, &com.value.0));
    let rhs = module_add(&proof.w.0, &scaled_com.0)?;

    if lhs.0.len() != rhs.len() || !bool::from(polys_ct_eq(&lhs.0, &rhs)) {
        return Err(VerifyError::Rejected);
    }
    Ok(())
}
