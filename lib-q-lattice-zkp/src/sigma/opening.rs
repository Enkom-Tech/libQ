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
#[cfg(not(feature = "hardened"))]
use crate::sigma::secrets::accumulate_response_z;
#[cfg(feature = "hardened")]
use crate::sigma::secrets::{
    MaskedWitness,
    accumulate_response_z_masked,
};
use crate::sigma::secrets::{
    SecretMaskVec,
    SecretWitnessVec,
    scrub_rejected_dual_ring_parts,
    scrub_rejected_opening_parts,
    zeroize_module_vec,
    zeroize_polys,
};
#[cfg(not(feature = "hardened"))]
use crate::util::module_infinity_norm;
use crate::util::{
    module_add,
    module_norm_within_bound,
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

/// Map each coefficient into `[0, q)` so wire packing and Fiat–Shamir hashing agree.
#[cfg(not(feature = "hardened"))]
pub(crate) fn normalize_polys_mod_q_for_fs(polys: &mut [Poly]) {
    normalize_polys_mod_q(polys);
}

#[cfg(not(feature = "hardened"))]
fn normalize_polys_mod_q(polys: &mut [Poly]) {
    let q = lib_q_ring::constants::FIELD_MODULUS as i64;
    for p in polys {
        for c in &mut p.coeffs {
            let mut v = *c as i64 % q;
            if v < 0 {
                v += q;
            }
            *c = v as i32;
        }
    }
}

/// Domain tag for committed-first-message Fiat–Shamir (QROM-hardened transcript).
pub const QROM_FS_W_DIGEST_DOMAIN: &[u8] = b"lattice-zkp/qrom-fs/w-digest/v0";

/// `SHAKE256(domain ‖ canonical_module_bytes(w))` before challenge derivation.
#[must_use]
pub fn fs_w_digest(first_message: &[Poly]) -> [u8; 32] {
    let mut h = lib_q_sha3::Shake256::default();
    lib_q_sha3::Update::update(&mut h, QROM_FS_W_DIGEST_DOMAIN);
    lib_q_sha3::Update::update(&mut h, &write_module_vec(first_message));
    let mut out = [0u8; 32];
    let mut reader = lib_q_sha3::ExtendableOutput::finalize_xof(h);
    lib_q_sha3::XofReader::read(&mut reader, &mut out);
    out
}

/// Domain separator binding the opening *statement* into the Fiat–Shamir transcript.
pub const OPENING_STATEMENT_FS_DOMAIN: &[u8] = b"lattice-zkp/sigma-opening/statement/v0";

/// Build the statement-bound Fiat–Shamir context for [`prove_opening`] / [`verify_opening`].
///
/// Defense-in-depth (#6): absorb the public statement — commitment-key seed, commitment image
/// `com`, sparse-challenge weight `tau`, and the norm bound `z_inf_bound` — into the context so the
/// challenge is bound to the exact instance and cannot be transplanted across keys/params/bounds
/// (cross-parameter binding). The identical encoding is used on both prover and verifier sides.
pub(crate) fn opening_statement_ctx(
    key: &AjtaiCommitmentKey,
    com: &AjtaiCommitment,
    ctx: &[u8],
    tau: usize,
    z_inf_bound: i32,
) -> Vec<u8> {
    let com_wire = write_module_vec(&com.value.0);
    let mut out = Vec::with_capacity(
        ctx.len() + OPENING_STATEMENT_FS_DOMAIN.len() + key.seed.len() + com_wire.len() + 8 + 4,
    );
    out.extend_from_slice(ctx);
    out.extend_from_slice(OPENING_STATEMENT_FS_DOMAIN);
    out.extend_from_slice(&key.seed);
    out.extend_from_slice(&(tau as u64).to_le_bytes());
    out.extend_from_slice(&z_inf_bound.to_le_bytes());
    out.extend_from_slice(&com_wire);
    out
}

pub(crate) fn fs_sparse_challenge(ctx: &[u8], first_message: &[Poly], tau: usize) -> Poly {
    let w_digest = fs_w_digest(first_message);
    let mut h = lib_q_sha3::Shake256::default();
    lib_q_sha3::Update::update(&mut h, ctx);
    lib_q_sha3::Update::update(&mut h, &w_digest);
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

// --- Bounded sampling for Module-SIS shortness (soundness fix #5) ---
//
// `q = FIELD_MODULUS = 8_380_417`, so `q/2 = 4_190_208`. Module-SIS *binding* of the Ajtai
// commitment is only meaningful when both the witness and the proof response `z` are SHORT
// (well below `q/2`). The legacy `z_inf_bound = 20_000_000 > 2q` made the verifier's norm check
// a no-op, so shortness was never enforced and binding did not hold.
//
// We sample the mask `y` and the opening witness from small symmetric ranges and size the
// response bound accordingly:
//
//   z = y + c · wit,   with a sparse ternary challenge `c` of Hamming weight τ (= 39 for v0).
//   ||c·wit||_inf ≤ τ · ||wit||_inf,   so ||z||_inf ≤ ||y||_inf + τ · ||wit||_inf.
//
// With `Y_MASK_BOUND` and `OPENING_WITNESS_BOUND` below, the honest response is *deterministically*
// bounded by `Y_MASK_BOUND + τ·OPENING_WITNESS_BOUND`, which is comfortably below `q/2`. See
// `crate::profile` for the resulting `z_inf_bound` value and reasoning.

/// Symmetric infinity-norm bound for the Fiat–Shamir mask `y` (coefficients in `[-B, B]`).
pub(crate) const Y_MASK_BOUND: i32 = 1_000_000;

/// Symmetric infinity-norm bound for sampled opening witnesses (coefficients in `[-B, B]`).
pub(crate) const OPENING_WITNESS_BOUND: i32 = 1_024;

/// Sample a polynomial with coefficients uniform in `[-bound, bound]` (centered, short).
fn sample_bounded_poly<R: Rng + CryptoRng>(rng: &mut R, bound: i32) -> Poly {
    debug_assert!(bound >= 0);
    // `2*bound + 1` distinct values; rejection-free modular reduction is unbiased only if we
    // reject the few high words, so reuse the unbiased rejection sampler over the range size.
    let range = (bound as u32).wrapping_mul(2).wrapping_add(1);
    let q = lib_q_ring::constants::FIELD_MODULUS;
    let mut coeffs = [0i32; 256];
    for c in &mut coeffs {
        let v = lib_q_ring::sample_uniform_coeff_mod_q(rng, range) - bound;
        // Store as a canonical representative in [0, q) so wire packing / FS hashing agree.
        *c = v.rem_euclid(q);
    }
    Poly::from_coeffs(coeffs)
}

/// Sample the short Fiat–Shamir mask `y` (coefficients uniform in `[-Y_MASK_BOUND, Y_MASK_BOUND]`).
///
/// Previously this drew a *full-field-uniform* polynomial, which forced `||z||_inf ≈ q/2` and made
/// any sub-`q/2` norm bound reject honest proofs. Bounding `y` is what lets the verifier enforce a
/// short `z` (and therefore Module-SIS binding) while preserving honest completeness.
pub(crate) fn sample_uniform_poly<R: Rng + CryptoRng>(rng: &mut R) -> Poly {
    sample_bounded_poly(rng, Y_MASK_BOUND)
}

/// Sample a short random opening (witness coefficients in `[-OPENING_WITNESS_BOUND, +bound]`).
///
/// Short witnesses are required for Module-SIS binding to hold; full-field-uniform openings make
/// the commitment non-binding.
#[must_use]
pub fn sample_random_opening<R: Rng + CryptoRng>(
    rng: &mut R,
    key: &AjtaiCommitmentKey,
) -> AjtaiOpening {
    let p = &key.params;
    let message: Vec<Poly> = (0..p.module_rank)
        .map(|_| sample_bounded_poly(rng, OPENING_WITNESS_BOUND))
        .collect();
    let randomness: Vec<Poly> = (0..p.randomness_dimension)
        .map(|_| sample_bounded_poly(rng, OPENING_WITNESS_BOUND))
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
    let wit_vec = witness_vec(opening);
    let matrix = ModuleMatrix::expand_from_seed(&key.seed, p.module_rank, p.witness_len());

    let expected_com = matrix.mul_vec_polys(&wit_vec);
    if expected_com.0.len() != com.value.0.len() ||
        !bool::from(polys_ct_eq(&expected_com.0, &com.value.0))
    {
        return Err(ProofError::InvalidParameters);
    }

    // Bind the public statement into the FS challenge (#6); same encoding as `verify_opening`.
    let stmt_ctx = opening_statement_ctx(key, com, ctx, tau, z_inf_bound);

    #[cfg(not(feature = "hardened"))]
    let wit = SecretWitnessVec::new(wit_vec);
    #[cfg(feature = "hardened")]
    let masked_wit = MaskedWitness::split(SecretWitnessVec::new(wit_vec), rng, &key.seed, ctx);

    #[cfg(feature = "hardened")]
    let mut candidate_w = ModuleVec((0..p.module_rank).map(|_| Poly::zero()).collect());
    #[cfg(feature = "hardened")]
    let mut candidate_z = ModuleVec((0..p.witness_len()).map(|_| Poly::zero()).collect());
    #[cfg(feature = "hardened")]
    let mut have_success = subtle::Choice::from(0u8);

    for _ in 0..max_attempts {
        let y = SecretMaskVec::new(
            (0..p.witness_len())
                .map(|_| sample_uniform_poly(rng))
                .collect::<Vec<_>>(),
        );
        let mut w = matrix.mul_vec_polys(y.as_slice());
        #[cfg(feature = "hardened")]
        for p in &mut w.0 {
            p.normalize_mod_q_assign();
        }
        #[cfg(not(feature = "hardened"))]
        normalize_polys_mod_q(&mut w.0);

        let c = fs_sparse_challenge(&stmt_ctx, &w.0, tau);

        #[cfg(not(feature = "hardened"))]
        let z = accumulate_response_z(&y, &c, &wit);
        #[cfg(feature = "hardened")]
        let z = accumulate_response_z_masked(&y, &c, &masked_wit);

        #[cfg(not(feature = "hardened"))]
        {
            if module_infinity_norm(z.as_slice()) > z_inf_bound {
                zeroize_module_vec(&mut w);
                continue;
            }

            let mut proof = OpeningProof {
                w,
                z: ModuleVec(z.into_public()),
            };
            if verify_opening(key, com, &proof, ctx, tau, z_inf_bound).is_ok() {
                return Ok(proof);
            }
            scrub_rejected_opening_parts(&mut proof.w, &mut proof.z.0);
        }

        #[cfg(feature = "hardened")]
        {
            let within = crate::hardened::response_within_bound(z.as_slice(), z_inf_bound);
            let mut proof = OpeningProof {
                w,
                z: ModuleVec(z.into_public()),
            };
            let verify_ok = verify_opening(key, com, &proof, ctx, tau, z_inf_bound).is_ok();
            let accept = crate::hardened::accept_transcript(within, verify_ok);
            let take = crate::hardened::first_accept_take(accept, have_success);
            crate::hardened::ct_select_polys(&mut candidate_w.0, &proof.w.0, take);
            crate::hardened::ct_select_polys(&mut candidate_z.0, &proof.z.0, take);
            have_success = crate::hardened::fold_accept_seen(have_success, accept);
            scrub_rejected_opening_parts(&mut proof.w, &mut proof.z.0);
        }
    }

    #[cfg(feature = "hardened")]
    return {
        if bool::from(have_success) {
            Ok(OpeningProof {
                w: candidate_w,
                z: candidate_z,
            })
        } else {
            scrub_rejected_opening_parts(&mut candidate_w, &mut candidate_z.0);
            Err(ProofError::RejectionLimit)
        }
    };

    #[cfg(not(feature = "hardened"))]
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
    if !bool::from(module_norm_within_bound(&proof.z.0, z_inf_bound)) {
        return Err(VerifyError::Rejected);
    }

    // Bind the public statement into the FS challenge (#6); same encoding as `prove_opening`.
    let stmt_ctx = opening_statement_ctx(key, com, ctx, tau, z_inf_bound);
    let c = fs_sparse_challenge(&stmt_ctx, &proof.w.0, tau);

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

    let wit_vec = witness_vec(opening);
    let matrix = ModuleMatrix::expand_from_seed(&key.seed, p.module_rank, p.witness_len());
    let expected_com = matrix.mul_vec_polys(&wit_vec);
    if expected_com.0.len() != ring[signer_idx].value.0.len() ||
        !bool::from(polys_ct_eq(&expected_com.0, &ring[signer_idx].value.0))
    {
        return Err(ProofError::InvalidParameters);
    }

    #[cfg(not(feature = "hardened"))]
    let wit = SecretWitnessVec::new(wit_vec);
    #[cfg(feature = "hardened")]
    let masked_wit = MaskedWitness::split(SecretWitnessVec::new(wit_vec), rng, &key.seed, ctx);

    let n = ring.len();
    #[cfg(feature = "hardened")]
    let mut candidate_challenges = alloc::vec![Poly::zero(); n];
    #[cfg(feature = "hardened")]
    let mut candidate_z = ModuleVec((0..p.witness_len()).map(|_| Poly::zero()).collect());
    #[cfg(feature = "hardened")]
    let mut have_success = subtle::Choice::from(0u8);

    for _ in 0..max_attempts {
        let y = SecretMaskVec::new(
            (0..p.witness_len())
                .map(|_| sample_uniform_poly(rng))
                .collect::<Vec<_>>(),
        );
        let mut ay = matrix.mul_vec_polys(y.as_slice());

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
        zeroize_polys(&mut r_combined);

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

        #[cfg(not(feature = "hardened"))]
        let z = accumulate_response_z(&y, &challenges[signer_idx], &wit);
        #[cfg(feature = "hardened")]
        let z = accumulate_response_z_masked(&y, &challenges[signer_idx], &masked_wit);

        #[cfg(not(feature = "hardened"))]
        {
            if module_infinity_norm(z.as_slice()) > z_inf_bound {
                zeroize_polys(&mut challenges);
                zeroize_module_vec(&mut ay);
                continue;
            }

            let mut proof = DualRingOpeningProof {
                challenges,
                z: ModuleVec(z.into_public()),
            };
            if verify_dual_ring_opening(key, ring, &proof, ctx, tau, z_inf_bound).is_ok() {
                return Ok(proof);
            }
            scrub_rejected_dual_ring_parts(&mut proof.z, &mut proof.challenges);
            zeroize_module_vec(&mut ay);
        }

        #[cfg(feature = "hardened")]
        {
            let within = crate::hardened::response_within_bound(z.as_slice(), z_inf_bound);
            let mut proof = DualRingOpeningProof {
                challenges,
                z: ModuleVec(z.into_public()),
            };
            let verify_ok =
                verify_dual_ring_opening(key, ring, &proof, ctx, tau, z_inf_bound).is_ok();
            let accept = crate::hardened::accept_transcript(within, verify_ok);
            let take = crate::hardened::first_accept_take(accept, have_success);
            crate::hardened::ct_select_polys(&mut candidate_challenges, &proof.challenges, take);
            crate::hardened::ct_select_polys(&mut candidate_z.0, &proof.z.0, take);
            have_success = crate::hardened::fold_accept_seen(have_success, accept);
            scrub_rejected_dual_ring_parts(&mut proof.z, &mut proof.challenges);
            zeroize_module_vec(&mut ay);
        }
    }

    #[cfg(feature = "hardened")]
    return {
        if bool::from(have_success) {
            Ok(DualRingOpeningProof {
                challenges: candidate_challenges,
                z: candidate_z,
            })
        } else {
            scrub_rejected_dual_ring_parts(&mut candidate_z, &mut candidate_challenges);
            Err(ProofError::RejectionLimit)
        }
    };

    #[cfg(not(feature = "hardened"))]
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
    if !bool::from(module_norm_within_bound(&proof.z.0, z_inf_bound)) {
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

    use lib_q_random::new_deterministic_rng;

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
        let mut rng = new_deterministic_rng([7u8; 32]);
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
        let mut rng = new_deterministic_rng([9u8; 32]);
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
        let mut rng = new_deterministic_rng([2u8; 32]);
        let ctx = b"two-slot";
        let proof = prove_dual_ring_opening(&mut rng, &key, &o1, &ring, 1, ctx, tau, z_bound, max)
            .expect("prove slot 1");
        verify_dual_ring_opening(&key, &ring, &proof, ctx, tau, z_bound).expect("verify");
    }
}
