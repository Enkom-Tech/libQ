//! Norm / range checks (public-side).

use alloc::vec::Vec;

use lib_q_ring::Poly;

use crate::util::module_infinity_norm;

/// Compact public proof artifact for per-slot infinity bounds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrtPackedNormProof {
    /// Per-slot infinity norm witnesses (`||slot_i||_inf`).
    pub slot_bounds: Vec<i32>,
    /// Claimed global bound β for all slots.
    pub beta: i32,
    /// Maximum slot norm (cached to avoid recomputation by verifiers).
    pub max_norm: i32,
}

/// Build a compact bound proof from per-slot vectors.
#[must_use]
pub fn prove_inf_norm(slots: &[Vec<Poly>], beta: i32) -> CrtPackedNormProof {
    let mut slot_bounds = Vec::with_capacity(slots.len());
    let mut max_norm = 0i32;
    for slot in slots {
        let n = module_infinity_norm(slot);
        slot_bounds.push(n);
        if n > max_norm {
            max_norm = n;
        }
    }
    CrtPackedNormProof {
        slot_bounds,
        beta,
        max_norm,
    }
}

/// Public check `‖v‖_∞ ≤ β` for one vector.
#[must_use]
pub fn verify_inf_norm(v: &[Poly], beta: i32) -> bool {
    module_infinity_norm(v) <= beta
}

/// Verify packed slot bounds against a caller-provided `beta`.
#[must_use]
pub fn verify_inf_norm_proof(proof: &CrtPackedNormProof, beta: i32) -> bool {
    if proof.beta != beta || proof.max_norm > beta {
        return false;
    }
    if proof.max_norm < 0 {
        return false;
    }
    let mut computed_max = 0i32;
    for &slot in &proof.slot_bounds {
        if slot < 0 || slot > beta {
            return false;
        }
        if slot > computed_max {
            computed_max = slot;
        }
    }
    computed_max == proof.max_norm
}
