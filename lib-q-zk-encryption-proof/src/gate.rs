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
//! ## `# WARNING` — the gate is only as strong as the closure
//! A relation-layer-only entry point (`crate::prove::verify_relation_layer`) used to exist and was
//! documented here as unsafe to gate on: it proved **ONLY** the R3 linear relations with `(e, f, g)`
//! free and prover-chosen, so a malformed ciphertext (e.g. the `f = δ·unitₖ` spike) produced a
//! fully-verifying proof. It has since been **removed** rather than kept with a warning.
//!
//! The rule it existed to state still holds: a closure that does not include the sponge + sampler +
//! byte-provenance joins does not reject malformed ciphertexts, and a gate built on one blocks nothing
//! of the insider-probe class.
//!
//! ## The sound closure — [`crate::encryption_proof`] (COMPLETE)
//! [`crate::encryption_proof::assemble_full_provenance_prover`] / `..._verifier` compose the sponge +
//! squeeze-byte + ternary sampler (`e`) + two bounded samplers (`f`, `g`) byte-provenance joins into
//! the SAME `prove_batch` as EVERY R3a `p_k` equation AND the R3b `v` equation, over `m` independent
//! Fiat–Shamir challenges, at **production** FRI params. A `proof_verifies` closure that runs that
//! composed `verify_batch` (rebuilding the verifier from `(t0, ct)` — never prover claims) is a
//! **complete** malformed-ciphertext closure: the whole witness `(e, f, g)` is pinned to the genuine
//! `XOF(pk ‖ μ)` expansion with `e` ternary and `f, g` bounded, so NO component is left free for an
//! insider to spike. In particular the classic `f = δ·unitₖ` R3a spike is rejected
//! (`encryption_proof::tests::spike_tampered_f_witness_rejected`), as is a tampered `e`
//! (`..::spike_tampered_e_witness_rejected`); the gate wiring is exercised end-to-end by
//! `..::gate_uses_composed_byte_provenance_closure`.
//!
//! The lighter [`crate::encryption_proof::assemble_e_provenance_prover`] (binds `e` + R3b) and
//! [`crate::encryption_proof::assemble_r3a_f_provenance_prover`] (binds `e` + `f` for selected R3a
//! columns) remain as cheaper per-component entry points and as the spike-test harnesses.
//!
//! The closure is also **zero-knowledge** when run under the hiding-FRI config (blinds `μ`; task #32,
//! demonstrated by `encryption_proof::tests::e_provenance_zero_knowledge_round_trip`).
//!
//! **Remaining (RED — not soundness of THIS proof):** constant-time samplers on the KEM's FO
//! re-encryption path (H1, a `kem.rs` wire concern), reproducing the key-instance estimator in-tree
//! (H3), and external cryptographer sign-off on the cross-AIR composition.
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
//! [`crate::encryption_proof::assemble_full_provenance_verifier`], which recomputes the challenges and
//! every public coefficient — never trusting the prover). The gate **calls it before touching the
//! share** and returns
//! [`EncProofError::ProofRejected`] on failure, so a caller structurally cannot decapsulate an
//! unverified ciphertext.

use lib_q_threshold_kem_lattice::auth_encap::{
    AuthKey,
    AuthenticatedCiphertext,
};
use lib_q_threshold_kem_lattice::kem::Ciphertext;
use lib_q_threshold_kem_lattice::threshold::{
    DecapBudget,
    ZeroShareSeeds,
    partial_decap_masked,
    partial_decap_masked_budgeted,
};
use lib_q_threshold_kem_lattice::{
    PartialDecap,
    SecretShare,
    ThresholdKemError,
    ThresholdKemLatticePublicKey,
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
/// **Do NOT** pass a relation-layer-only verifier as `proof_verifies`: checking the R3 relations over
/// free `(e, f, g)` lets a malformed ciphertext through and the gate would admit it. Use the COMPLETE
/// composed byte-provenance closure from
/// [`crate::encryption_proof::assemble_full_provenance_verifier`] (binds `e`, all `f`, and `g` across
/// all R3a + R3b at production params over `m` challenges — see module docs).
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

/// [`gated_partial_decap_masked`] composed with closure C (the per-key [`DecapBudget`]): the budget
/// is checked **before** `proof_verifies` runs, and `proof_verifies` is checked **before**
/// [`partial_decap_masked_budgeted`] is invoked. Order, in full:
/// 1. `budget.remaining() == 0` → [`EncProofError::Decap`]`(`[`ThresholdKemError::BudgetExhausted`]`)`,
///    without running `proof_verifies` at all — an exhausted budget must not pay for even one more
///    (expensive) proof verification.
/// 2. `!proof_verifies()` → [`EncProofError::ProofRejected`], and the budget is **not** charged — a
///    rejected proof must not consume an honest party's remaining budget.
/// 3. Otherwise forwards to [`partial_decap_masked_budgeted`], which charges the budget itself only
///    on a successfully emitted partial.
///
/// # Security
/// Same closure-shape warning as [`gated_partial_decap_masked`]: this is only as sound as
/// `proof_verifies` (see the module docs). Composing with the budget does not change that — a bad
/// closure still admits a malformed ciphertext, just at most `budget.remaining()` times.
///
/// # A DoS trade-off, stated plainly
/// Not charging the budget on a rejected proof (step 2) is required so a rejected probe cannot burn
/// an honest party's key-rotation budget. But it also means a rejected proof costs the caller a full
/// STARK verification for **free** from the budget's point of view: an attacker who can force many
/// rejected-proof calls trades what would have been a key-exhaustion DoS (bounded by `budget.cap()`)
/// for a compute DoS (bounded only by however many `proof_verifies` calls the deployment tolerates).
/// That is not this gate's concern to fix — verification-request rate limiting is a transport/caller
/// responsibility — but a deployment relying on this budget as its *only* DoS defense should know the
/// budget does not bound rejected-proof traffic.
#[allow(clippy::too_many_arguments)]
pub fn gated_partial_decap_masked_budgeted<R, V>(
    proof_verifies: V,
    share: &SecretShare,
    subset: &[u8],
    ct: &Ciphertext,
    seeds: &ZeroShareSeeds,
    rng: &mut R,
    budget: &mut DecapBudget,
) -> Result<PartialDecap, EncProofError>
where
    R: CryptoRng + Rng,
    V: FnOnce() -> bool,
{
    // Budget FIRST: an exhausted budget must short-circuit before the (expensive) verifier closure
    // ever runs.
    if budget.remaining() == 0 {
        return Err(EncProofError::Decap(ThresholdKemError::BudgetExhausted));
    }
    // Then the proof: rejected proofs must not charge the budget, so this check happens strictly
    // before any call that could charge it.
    if !proof_verifies() {
        return Err(EncProofError::ProofRejected);
    }
    partial_decap_masked_budgeted(share, subset, ct, seeds, rng, budget)
        .map_err(EncProofError::Decap)
}

/// [`gated_partial_decap_masked_budgeted`] composed further with closure B (the authenticator):
/// verifies `act`'s tag under `(pk, auth_key)` and only then proceeds to the budget/proof-gated
/// partial decapsulation. This composes closures **A + B + C** — the encryption proof (A), the
/// origin authenticator (B), and the leakage budget (C) — none of which by itself is a substitute
/// for the others (see [`gated_partial_decap_masked`] and the `threshold` module docs).
///
/// Order, in full:
/// 1. `verify_authenticator(pk, auth_key, act)` — an unauthenticated ciphertext is refused with
///    [`EncProofError::Decap`]`(`[`ThresholdKemError::AuthenticationFailed`]`)` before the budget or
///    the proof closure are touched at all.
/// 2. Forwards to [`gated_partial_decap_masked_budgeted`] on `act.ct` — budget check, then
///    `proof_verifies`, then the KEM's own budgeted partial-decap.
///
/// # Security
/// **A's guarantee is still only as strong as the caller-supplied `proof_verifies` closure** — layering
/// the authenticator (B) does not strengthen or substitute for A; it only additionally requires the
/// caller to hold `auth_key`. See [`gated_partial_decap_masked`]'s `# WARNING` and the `auth_encap`
/// module docs for B's own assumption (a shared symmetric key, not per-identity accountability).
#[allow(clippy::too_many_arguments)]
pub fn gated_partial_decap_authenticated_budgeted<R, V>(
    proof_verifies: V,
    share: &SecretShare,
    subset: &[u8],
    pk: &ThresholdKemLatticePublicKey,
    auth_key: &AuthKey,
    act: &AuthenticatedCiphertext,
    seeds: &ZeroShareSeeds,
    rng: &mut R,
    budget: &mut DecapBudget,
) -> Result<PartialDecap, EncProofError>
where
    R: CryptoRng + Rng,
    V: FnOnce() -> bool,
{
    use lib_q_threshold_kem_lattice::auth_encap::verify_authenticator;

    // This repeats the authenticator check from `partial_decap_authenticated_budgeted` rather than
    // delegating to it, deliberately: delegating would put the STARK verification (A) BEFORE the
    // MAC check (B), letting an unauthenticated caller force a full proof verification. Checking
    // the cheap MAC first is what keeps the rejected-proof compute cost documented above behind the
    // authenticator. The cost of not delegating is drift — if the KEM's authenticated entry point
    // ever gains a check beyond `verify_authenticator`, this path must gain it too.
    if verify_authenticator(pk, auth_key, act).unwrap_u8() != 1 {
        return Err(EncProofError::Decap(
            ThresholdKemError::AuthenticationFailed,
        ));
    }
    gated_partial_decap_masked_budgeted(proof_verifies, share, subset, &act.ct, seeds, rng, budget)
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
    /// sound production closure runs `verify_batch` over the composed byte-provenance proof
    /// (`crate::encryption_proof::assemble_e_provenance_verifier` ⇒ this gate) — exercised end-to-end in
    /// `encryption_proof::tests::gate_uses_composed_byte_provenance_closure`.
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

    fn fixture_t0() -> Vec<Rq> {
        (0..MU)
            .map(|r| {
                let mut c = [0i64; N];
                for (i, ci) in c.iter_mut().enumerate() {
                    *ci = (i as i64 + r as i64) % lib_q_dkg::lattice::ring::Q;
                }
                Rq::from_coeffs(c)
            })
            .collect()
    }

    fn fixture_share() -> SecretShare {
        SecretShare {
            index: 1,
            threshold: 1,
            share_bytes: Zeroizing::new(vec![0u8; 1]),
        }
    }

    /// A `SecretShare` whose bytes actually decode (unlike `fixture_share`'s 1-byte placeholder) —
    /// an all-zero `rand` vector of the correct `RQ_BYTES * (1 + KAPPA)` length, which parses as
    /// canonical zero coefficients and lets `partial_decap_masked` run to completion (charging the
    /// budget). Used only by the behavioral-red charge-order probe.
    fn decodable_zero_share() -> SecretShare {
        let len = lib_q_dkg::lattice::ring::RQ_BYTES * (1 + lib_q_dkg::lattice::bdlop::KAPPA);
        SecretShare {
            index: 1,
            threshold: 1,
            share_bytes: Zeroizing::new(vec![0u8; len]),
        }
    }

    fn fixture_pk(t0: &[Rq]) -> ThresholdKemLatticePublicKey {
        let mut t0_bytes = Vec::new();
        for p in t0 {
            lib_q_dkg::lattice::ring::rq_write_le_bytes(p, &mut t0_bytes);
        }
        ThresholdKemLatticePublicKey {
            threshold: 1,
            t0_bytes,
        }
    }

    /// **Content-carrying assertion 1:** a rejected proof leaves the budget uncharged. Modeled on
    /// `gate_refuses_unverified_ciphertext`. Behavioral-red verified (see progress log): temporarily
    /// swapping the check order (charge-then-check) makes `budget.used() == 0` fail with a real
    /// `assertion failed` line, not a compile error.
    #[test]
    fn budgeted_gate_rejected_proof_does_not_charge_budget() {
        let t0 = fixture_t0();
        let ct = encapsulate_derand(&t0, &[0x11u8; 32]);
        let share = decodable_zero_share();
        let mut rng = new_deterministic_rng([2u8; 32]);
        let seeds = ZeroShareSeeds::setup(3, &mut rng);
        let mut budget = DecapBudget::new(5);

        let refused = gated_partial_decap_masked_budgeted(
            || false,
            &share,
            &[1u8, 2, 3],
            &ct,
            &seeds,
            &mut rng,
            &mut budget,
        );
        assert!(
            matches!(refused, Err(EncProofError::ProofRejected)),
            "a rejected proof must be refused with ProofRejected"
        );
        assert_eq!(
            budget.used(),
            0,
            "a rejected proof must NOT charge the budget"
        );
    }

    /// **Content-carrying assertion 2:** an exhausted budget short-circuits BEFORE the verifier
    /// closure runs. Uses a `Cell<bool>` flag to observe whether `proof_verifies` was ever invoked.
    /// Behavioral-red verified (see progress log): temporarily swapping the check order (verify-then-
    /// budget) makes the "closure must not run" assertion fail with a real `assertion failed` line.
    #[test]
    fn budgeted_gate_exhausted_budget_short_circuits_before_verifier_runs() {
        let t0 = fixture_t0();
        let ct = encapsulate_derand(&t0, &[0x11u8; 32]);
        let share = fixture_share();
        let seeds = ZeroShareSeeds::from_pairwise(Vec::new()).expect("empty seed set is canonical");
        let mut rng = new_deterministic_rng([3u8; 32]);
        let mut budget = DecapBudget::new(0);

        let closure_ran = core::cell::Cell::new(false);
        let result = gated_partial_decap_masked_budgeted(
            || {
                closure_ran.set(true);
                true
            },
            &share,
            &[1u8, 2, 3],
            &ct,
            &seeds,
            &mut rng,
            &mut budget,
        );
        assert!(
            matches!(
                result,
                Err(EncProofError::Decap(ThresholdKemError::BudgetExhausted))
            ),
            "an exhausted budget must be refused with Decap(BudgetExhausted)"
        );
        assert!(
            !closure_ran.get(),
            "the verifier closure must NOT run once the budget is exhausted"
        );
    }

    /// Verified proof + available budget forwards into the KEM path (NOT ProofRejected / NOT
    /// BudgetExhausted) — it then errors on the placeholder share, same acceptance pattern as
    /// `gate_refuses_unverified_ciphertext`'s forwarded case.
    #[test]
    fn budgeted_gate_verified_proof_with_budget_forwards_past_the_gate() {
        let t0 = fixture_t0();
        let ct = encapsulate_derand(&t0, &[0x11u8; 32]);
        let share = fixture_share();
        let seeds = ZeroShareSeeds::from_pairwise(Vec::new()).expect("empty seed set is canonical");
        let mut rng = new_deterministic_rng([4u8; 32]);
        let mut budget = DecapBudget::new(5);

        let forwarded = gated_partial_decap_masked_budgeted(
            || true,
            &share,
            &[1u8, 2, 3],
            &ct,
            &seeds,
            &mut rng,
            &mut budget,
        );
        assert!(
            !matches!(forwarded, Err(EncProofError::ProofRejected)),
            "a verified proof must not be refused as ProofRejected"
        );
        assert!(
            !matches!(
                forwarded,
                Err(EncProofError::Decap(ThresholdKemError::BudgetExhausted))
            ),
            "an available budget must not be reported as exhausted"
        );
    }

    /// Authenticated variant: a bad tag is refused with `Decap(AuthenticationFailed)`, before the
    /// budget or proof closure are touched, and the budget is left uncharged.
    #[test]
    fn authenticated_gate_bad_tag_is_rejected_before_budget_or_proof() {
        use lib_q_threshold_kem_lattice::auth_encap::authenticated_encapsulate;

        let t0 = fixture_t0();
        let pk = fixture_pk(&t0);
        let auth_key = AuthKey::from_bytes([0x55u8; 32]);
        let mut rng = new_deterministic_rng([5u8; 32]);
        let (_ss, mut act) = authenticated_encapsulate(&pk, &auth_key, &mut rng)
            .expect("authenticated_encapsulate over a well-formed fixture pk");
        // Forge the tag.
        act.tag = [0u8; lib_q_threshold_kem_lattice::AUTH_TAG_BYTES];

        let share = fixture_share();
        let seeds = ZeroShareSeeds::from_pairwise(Vec::new()).expect("empty seed set is canonical");
        let mut budget = DecapBudget::new(5);
        let closure_ran = core::cell::Cell::new(false);

        let result = gated_partial_decap_authenticated_budgeted(
            || {
                closure_ran.set(true);
                true
            },
            &share,
            &[1u8, 2, 3],
            &pk,
            &auth_key,
            &act,
            &seeds,
            &mut rng,
            &mut budget,
        );
        assert!(
            matches!(
                result,
                Err(EncProofError::Decap(
                    ThresholdKemError::AuthenticationFailed
                ))
            ),
            "a forged tag must be refused with Decap(AuthenticationFailed)"
        );
        assert_eq!(
            budget.used(),
            0,
            "a rejected authenticator must not charge the budget"
        );
        assert!(
            !closure_ran.get(),
            "the proof-verification closure must not run when the authenticator fails first"
        );
    }

    /// Authenticated variant, good tag: forwards past the authenticator check (and the budget/proof
    /// gate) into the KEM's own authenticated-budgeted path.
    #[test]
    fn authenticated_gate_good_tag_forwards_past_the_gate() {
        use lib_q_threshold_kem_lattice::auth_encap::authenticated_encapsulate;

        let t0 = fixture_t0();
        let pk = fixture_pk(&t0);
        let auth_key = AuthKey::from_bytes([0x66u8; 32]);
        let mut rng = new_deterministic_rng([6u8; 32]);
        let (_ss, act) = authenticated_encapsulate(&pk, &auth_key, &mut rng)
            .expect("authenticated_encapsulate over a well-formed fixture pk");

        let share = fixture_share();
        let seeds = ZeroShareSeeds::from_pairwise(Vec::new()).expect("empty seed set is canonical");
        let mut budget = DecapBudget::new(5);

        let result = gated_partial_decap_authenticated_budgeted(
            || true,
            &share,
            &[1u8, 2, 3],
            &pk,
            &auth_key,
            &act,
            &seeds,
            &mut rng,
            &mut budget,
        );
        assert!(
            !matches!(
                result,
                Err(EncProofError::Decap(
                    ThresholdKemError::AuthenticationFailed
                ))
            ),
            "a valid tag must not be reported as an authentication failure"
        );
    }
}
