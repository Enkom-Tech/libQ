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
    scrub_rejected_opening_parts,
    zeroize_module_vec,
};
#[cfg(not(feature = "hardened"))]
use crate::util::module_infinity_norm;
use crate::util::{
    module_add,
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

/// Domain separator binding `u = L·y` into the linear-relation Fiat–Shamir transcript.
const LINEAR_U_FS_DOMAIN: &[u8] = b"lattice-zkp/sigma-linear/u/v0";

/// Build the Fiat–Shamir context that binds `u` into the challenge.
///
/// Soundness fix: the base opening challenge is `c = H(ctx ‖ w)`, which omits `u`.
/// Without binding `u`, a malicious prover can set `u := L·z − c·t` for any false `t`
/// and pass `L·z = u + c·t`. We fold the canonical byte encoding of `u` into the
/// context so the challenge becomes `c = H(ctx ‖ u ‖ w)`. The same canonical encoding
/// ([`write_module_vec`]) is used on both prover and verifier sides.
fn linear_fs_ctx(ctx: &[u8], u: &ModuleVec) -> alloc::vec::Vec<u8> {
    let u_wire = write_module_vec(&u.0);
    let mut out =
        alloc::vec::Vec::with_capacity(ctx.len() + LINEAR_U_FS_DOMAIN.len() + u_wire.len());
    out.extend_from_slice(ctx);
    out.extend_from_slice(LINEAR_U_FS_DOMAIN);
    out.extend_from_slice(&u_wire);
    out
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
    let wit_vec = opening::witness_vec(opening);
    let l_times_wit = l.mul_vec_polys(&wit_vec);
    if l_times_wit.0.len() != t.0.len() || !bool::from(polys_ct_eq(&l_times_wit.0, &t.0)) {
        return Err(ProofError::InvalidParameters);
    }

    #[cfg(not(feature = "hardened"))]
    let wit = SecretWitnessVec::new(wit_vec);
    #[cfg(feature = "hardened")]
    let masked_wit = MaskedWitness::split(SecretWitnessVec::new(wit_vec), rng, &key.seed, ctx);

    let matrix =
        ModuleMatrix::expand_from_seed(&key.seed, key.params.module_rank, key.params.witness_len());

    #[cfg(feature = "hardened")]
    let mut candidate_opening_w = ModuleVec(
        (0..key.params.module_rank)
            .map(|_| lib_q_ring::Poly::zero())
            .collect(),
    );
    #[cfg(feature = "hardened")]
    let mut candidate_opening_z = ModuleVec(
        (0..key.params.witness_len())
            .map(|_| lib_q_ring::Poly::zero())
            .collect(),
    );
    #[cfg(feature = "hardened")]
    let mut candidate_u = ModuleVec((0..l.rows).map(|_| lib_q_ring::Poly::zero()).collect());
    #[cfg(feature = "hardened")]
    let mut have_success = subtle::Choice::from(0u8);

    for _ in 0..max_attempts {
        let y = SecretMaskVec::new(
            (0..key.params.witness_len())
                .map(|_| opening::sample_uniform_poly(rng))
                .collect::<alloc::vec::Vec<_>>(),
        );
        #[cfg_attr(feature = "hardened", allow(unused_mut))]
        let mut w = matrix.mul_vec_polys(y.as_slice());
        #[cfg_attr(feature = "hardened", allow(unused_mut))]
        let mut u = l.mul_vec_polys(y.as_slice());
        #[cfg(not(feature = "hardened"))]
        {
            opening::normalize_polys_mod_q_for_fs(&mut w.0);
            opening::normalize_polys_mod_q_for_fs(&mut u.0);
        }
        #[cfg(feature = "hardened")]
        for p in &mut w.0 {
            p.normalize_mod_q_assign();
        }
        #[cfg(feature = "hardened")]
        for p in &mut u.0 {
            p.normalize_mod_q_assign();
        }

        // Bind `u` into the Fiat–Shamir challenge: c = H(ctx ‖ u ‖ w), then bind the opening
        // statement (key/com/tau/bound) exactly as `opening::verify_opening` does so the shared
        // challenge `c` matches the inner opening check on the verifier side.
        let linear_ctx = linear_fs_ctx(ctx, &u);
        let stmt_ctx = opening::opening_statement_ctx(key, com, &linear_ctx, tau, z_inf_bound);
        let c = opening::fs_sparse_challenge(&stmt_ctx, &w.0, tau);

        #[cfg(not(feature = "hardened"))]
        let z = accumulate_response_z(&y, &c, &wit);
        #[cfg(feature = "hardened")]
        let z = accumulate_response_z_masked(&y, &c, &masked_wit);

        #[cfg(not(feature = "hardened"))]
        {
            if module_infinity_norm(z.as_slice()) > z_inf_bound {
                zeroize_module_vec(&mut w);
                zeroize_module_vec(&mut u);
                continue;
            }

            let mut proof = LinearRelationProof {
                opening: OpeningProof {
                    w,
                    z: ModuleVec(z.into_public()),
                },
                u,
            };
            if verify_linear(key, com, &proof, l, t, ctx, tau, z_inf_bound).is_ok() {
                return Ok(proof);
            }
            scrub_rejected_opening_parts(&mut proof.opening.w, &mut proof.opening.z.0);
            zeroize_module_vec(&mut proof.u);
        }

        #[cfg(feature = "hardened")]
        {
            let within = crate::hardened::response_within_bound(z.as_slice(), z_inf_bound);
            let mut proof = LinearRelationProof {
                opening: OpeningProof {
                    w,
                    z: ModuleVec(z.into_public()),
                },
                u,
            };
            let verify_ok = verify_linear(key, com, &proof, l, t, ctx, tau, z_inf_bound).is_ok();
            let accept = crate::hardened::accept_transcript(within, verify_ok);
            let take = crate::hardened::first_accept_take(accept, have_success);
            crate::hardened::ct_select_polys(&mut candidate_opening_w.0, &proof.opening.w.0, take);
            crate::hardened::ct_select_polys(&mut candidate_opening_z.0, &proof.opening.z.0, take);
            crate::hardened::ct_select_polys(&mut candidate_u.0, &proof.u.0, take);
            have_success = crate::hardened::fold_accept_seen(have_success, accept);
            scrub_rejected_opening_parts(&mut proof.opening.w, &mut proof.opening.z.0);
            zeroize_module_vec(&mut proof.u);
        }
    }

    #[cfg(feature = "hardened")]
    return {
        if bool::from(have_success) {
            Ok(LinearRelationProof {
                opening: OpeningProof {
                    w: candidate_opening_w,
                    z: candidate_opening_z,
                },
                u: candidate_u,
            })
        } else {
            scrub_rejected_opening_parts(&mut candidate_opening_w, &mut candidate_opening_z.0);
            zeroize_module_vec(&mut candidate_u);
            Err(ProofError::RejectionLimit)
        }
    };

    #[cfg(not(feature = "hardened"))]
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
    if proof.u.0.len() != l.rows || l.cols != key.params.witness_len() {
        return Err(VerifyError::InvalidFormat);
    }

    // Bind `u` into the Fiat–Shamir challenge so the shared `c` covers `u` as well:
    // c = H(ctx ‖ u ‖ w). The opening sub-proof and the linear check use the same `c`,
    // so both must use this augmented context (matches the prover in `prove_linear`).
    let linear_ctx = linear_fs_ctx(ctx, &proof.u);
    opening::verify_opening(key, com, &proof.opening, &linear_ctx, tau, z_inf_bound)?;

    // Reconstruct the same statement-bound challenge `c` that the opening sub-proof used
    // (matches `prove_linear` and `opening::verify_opening`).
    let stmt_ctx = opening::opening_statement_ctx(key, com, &linear_ctx, tau, z_inf_bound);
    let c = opening::fs_sparse_challenge(&stmt_ctx, &proof.opening.w.0, tau);

    let lhs = l.mul_vec(&proof.opening.z);
    let rhs = module_add(&proof.u.0, &module_ring_mul_challenge(&c, &t.0))?;
    if lhs.0.len() != rhs.len() || !bool::from(polys_ct_eq(&lhs.0, &rhs)) {
        return Err(VerifyError::Rejected);
    }
    Ok(())
}
