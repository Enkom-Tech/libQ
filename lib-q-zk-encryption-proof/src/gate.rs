//! The **malformed-ciphertext partial-decap gate** (task #33) — the composition point at which a
//! caller-supplied encryption-proof verification is enforced *before* a share is read.
//!
//! ## The threat
//! A threshold partial-decapsulation is a share-linear function of the ciphertext, so a malicious
//! insider who submits a *malformed* ciphertext (a `(p, v)` that is structurally well-formed but whose
//! `(e, f, g)` are NOT the Fiat–Shamir–Ω FO expansion of any message) can steer the leaked value to
//! probe the secret share. `partial_decap_masked` already rejects *structurally* invalid ciphertexts,
//! but not this class. The intended fix is to require, alongside the ciphertext, a zero-knowledge
//! **proof of correct encryption** and to partial-decapsulate ONLY when it verifies.
//!
//! ## What this gate does — and does NOT — guarantee
//! The gate enforces **exactly what the caller-supplied `proof_verifies` closure checks, and nothing
//! more**. It is a mechanism, not a proof: its soundness is entirely inherited from that closure.
//!
//! The **only sound** closure is one that verifies a proof of knowledge of a message `μ` such that
//! `(e, f, g) = XOF(pk ‖ μ)` (the deterministic FO expansion) **AND** that `e` is ternary and `f, g`
//! are bounded — i.e. the full **sponge + sampler + byte-provenance joins** layer that binds the
//! witness to the ciphertext's public key and message. Only such a closure actually rejects a
//! malformed ciphertext.
//!
//! ## `# WARNING` — do NOT gate on the relation layer alone
//! [`crate::prove::verify_relation_layer`] (paired with [`crate::prove::prove_relation_layer`]) proves
//! **ONLY** the R3 linear relations (`p = B0ᵀe + f`, `v = ⟨t0,e⟩ + g + encode(μ)`) with `(e, f, g)`
//! as **free, prover-chosen** values. There is no sponge AIR, no ternary/bounded sampler AIR, and no
//! join binding `(e, f, g)` to `XOF(pk ‖ μ)` or to any range in that path. A malformed ciphertext
//! (e.g. the `f = δ·unitₖ` spike) therefore produces a **fully-verifying** relation-layer proof.
//!
//! **Using `verify_relation_layer` alone as the production `proof_verifies` yields a gate that admits
//! malformed ciphertexts — it blocks nothing of the insider-probe class.** The full byte-provenance
//! binding is validated only as a `#[cfg(test)]` toy-parameter vertical slice in [`crate::compose`];
//! composing it into a production-parameter batch (sharing the fold instances) is an **open task** and
//! is NOT yet wired. Until it is, this gate must not be relied on as a malformed-ciphertext closure.
//!
//! ## Why the gate lives here (not in `tkem`)
//! `lib-q-zk-encryption-proof` already depends on `lib-q-threshold-kem-lattice`; putting the gate in
//! `tkem` would require `tkem → this crate`, a dependency **cycle**. So the gate is the composition
//! point: it lives in the proof crate, which can both verify the proof and call the KEM's
//! `partial_decap_masked`.
//!
//! ## The verification is a caller-supplied closure
//! The batch `verify_batch<SC, A>` is bounded by a `lib-q-plonky-batch-stark`-internal folder type that
//! the crate does not re-export, so a config-generic gate cannot name the bound. Instead the gate takes
//! a `proof_verifies: FnOnce() -> bool` that the caller wires to `verify_batch` over the ciphertext's
//! encryption proof at its chosen config (rebuilt from public inputs via
//! [`crate::prove::verify_relation_layer`], which recomputes ζ and the public coefficients — never
//! trusting the prover). The gate **calls it before touching the share** and returns
//! [`EncProofError::ProofRejected`] on failure, so a caller structurally cannot decapsulate an
//! unverified ciphertext.

use lib_q_threshold_kem_lattice::kem::Ciphertext;
use lib_q_threshold_kem_lattice::threshold::{
    ZeroShareSeeds,
    partial_decap_masked,
};
use lib_q_threshold_kem_lattice::{
    PartialDecap,
    SecretShare,
};
use rand_core::{
    CryptoRng,
    Rng,
};

use crate::error::EncProofError;

/// Partial-decapsulate `ct` under `share` for `subset` **only if** its encryption proof verifies.
///
/// `proof_verifies` must run the encryption-proof verification (`verify_batch` over the ciphertext's
/// proof, rebuilt from public inputs) and return whether it accepted. On `false` the gate refuses with
/// [`EncProofError::ProofRejected`] **before** the share is read; otherwise it forwards to
/// [`partial_decap_masked`] (wrapping any KEM error in [`EncProofError::Decap`]).
///
/// # Security
/// The gate's guarantee is **only** as strong as `proof_verifies`; it enforces that closure and
/// nothing more (see the module docs). A sound closure MUST verify knowledge of `μ` with
/// `(e, f, g) = XOF(pk ‖ μ)` and `e` ternary / `f, g` bounded — the sponge + sampler + joins layer.
///
/// **Do NOT** pass [`crate::prove::verify_relation_layer`] alone as `proof_verifies`: it checks only
/// the R3 linear relations over free `(e, f, g)`, so a malformed ciphertext passes it and the gate
/// would admit it. That full binding is not yet wired into a production-parameter proof.
pub fn gated_partial_decap_masked<R, V>(
    proof_verifies: V,
    share: &SecretShare,
    subset: &[u8],
    ct: &Ciphertext,
    seeds: &ZeroShareSeeds,
    rng: &mut R,
) -> Result<PartialDecap, EncProofError>
where
    R: CryptoRng + Rng,
    V: FnOnce() -> bool,
{
    // Gate FIRST: the proof must verify before the share is touched.
    if !proof_verifies() {
        return Err(EncProofError::ProofRejected);
    }
    partial_decap_masked(share, subset, ct, seeds, rng).map_err(EncProofError::Decap)
}

#[cfg(test)]
mod tests {
    use lib_q_dkg::lattice::bdlop::MU;
    use lib_q_dkg::lattice::ring::{
        N,
        Rq,
    };
    use lib_q_random::new_deterministic_rng;
    use lib_q_threshold_kem_lattice::kem::encapsulate_derand;
    use zeroize::Zeroizing;

    use super::*;

    /// **The gate's security property (task #33):** a ciphertext whose encryption proof does NOT verify
    /// is refused with [`EncProofError::ProofRejected`] **before the share is read** — the
    /// malformed-ciphertext insider probe never reaches the secret (the `if !proof_verifies()` return is
    /// structurally before `partial_decap_masked`). A *verified* proof (`|| true`) forwards past the
    /// gate into `partial_decap_masked` (here it then errors on the placeholder share — hence NOT
    /// `ProofRejected`; a full success needs a real DKG share, covered by the KEM's own tests). The
    /// production closure runs `verify_batch` over the ciphertext's encryption proof
    /// (`crate::prove::verify_relation_layer` ⇒ this gate).
    #[test]
    fn gate_refuses_unverified_ciphertext() {
        let t0: Vec<Rq> = (0..MU)
            .map(|r| {
                let mut c = [0i64; N];
                for (i, ci) in c.iter_mut().enumerate() {
                    *ci = (i as i64 + r as i64) % lib_q_dkg::lattice::ring::Q;
                }
                Rq::from_coeffs(c)
            })
            .collect();
        let ct = encapsulate_derand(&t0, &[0x11u8; 32]);
        let share = SecretShare {
            index: 1,
            threshold: 1,
            share_bytes: Zeroizing::new(vec![0u8; 1]),
        };
        let seeds = ZeroShareSeeds::from_pairwise(Vec::new()).expect("empty seed set is canonical");

        // Reject path: the gate refuses before touching the share.
        let mut rng = new_deterministic_rng([0u8; 32]);
        let refused =
            gated_partial_decap_masked(|| false, &share, &[1u8, 2, 3], &ct, &seeds, &mut rng);
        assert!(
            matches!(refused, Err(EncProofError::ProofRejected)),
            "an unverified ciphertext must be refused before the share is read"
        );

        // Accept path: the gate forwards past verification into partial_decap_masked (which then errors
        // on the placeholder share) — so NOT ProofRejected, proving the gate did not block a verified ct.
        let mut rng2 = new_deterministic_rng([1u8; 32]);
        let forwarded =
            gated_partial_decap_masked(|| true, &share, &[1u8, 2, 3], &ct, &seeds, &mut rng2);
        assert!(
            !matches!(forwarded, Err(EncProofError::ProofRejected)),
            "a verified proof must forward past the gate to partial_decap_masked"
        );
    }
}
