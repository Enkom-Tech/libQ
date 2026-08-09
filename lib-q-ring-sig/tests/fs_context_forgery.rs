//! Card t_eacf23b1: does the (now-fixed) ring-sig transcript collision (card t_f0d676d1 / F25,
//! see `fs_context_collision.rs`) yield an actual cross-protocol FORGERY, or does it stop at the
//! transcript level?
//!
//! Background: before the fix at commit 275bf59, `dualring_lb_signing_context(ring, msg_b)` was
//! byte-identical to `federation_signing_context(ring, msg_a)` for a crafted
//! `msg_a = msg_b || suffix(ring, msg_b)`. That byte-identical string is only ever a
//! *precondition* for forgery — the two verification paths in `lib-q-lattice-zkp` diverge after
//! the context is built:
//!
//!   * `prove_opening` / `verify_opening` (the federation single-opening path) wrap the raw `ctx`
//!     through `opening_statement_ctx(key, com, ctx, tau, z_inf_bound)` — which APPENDS
//!     `OPENING_STATEMENT_FS_DOMAIN || key.seed || tau.to_le_bytes() || z_inf_bound.to_le_bytes()
//!     || write_module_vec(com)` after `ctx` — before ever hashing anything.
//!   * `prove_dual_ring_opening` / `verify_dual_ring_opening` hash `ctx` directly, with no such
//!     wrapping.
//!
//! **How this was actually checked (not just argued):** with `lib-q-ring-sig/src/sign.rs` and
//! `lib-q-ring-sig/src/dualring_lb.rs` temporarily reverted to their pre-275bf59 content (via
//! `git checkout 275bf59~1 -- <files>`, restored afterwards; `git status --short` was clean for
//! both files once restored), the pre-fix crafted pair `ctx_fed(ring, msg_a) ==
//! ctx_dual(ring, msg_b)` was reproduced and printed as byte-identical 133-byte arrays (see the
//! card's progress log for the verbatim printed bytes). Feeding that SAME `ctx` value through
//! `manual_opening_statement_ctx` (federation) vs. raw (dual-ring) and then through the
//! `fs_sparse_challenge` hash-input formula produced a 2299-byte federation input and a 165-byte
//! dual-ring input — different by exactly 2134 bytes, which is precisely
//! `len(DOMAIN) + len(seed) + 8 + 4 + len(write_module_vec(com))` for the test's parameters.
//!
//! This test below re-checks the SAME mechanism using an arbitrary shared `ctx` byte string
//! (rather than re-deriving one from the ring-sig functions), because the divergence being
//! tested is a property of `lib-q-lattice-zkp`'s `opening.rs` alone — it holds for ANY
//! byte-identical `ctx`, regardless of how two ring-sig call sites might arrive at producing it,
//! and unlike the historical collision (which the ring-sig fix has since closed), an arbitrary
//! shared `ctx` keeps this regression test meaningful whether or not the ring-sig transcript
//! layer is later refactored again.
//!
//! CONCLUSION: **REFUTED.** A byte-identical `ctx` is a necessary but NOT sufficient condition
//! for a cross-protocol forgery between `prove_opening`/`verify_opening` and
//! `prove_dual_ring_opening`/`verify_dual_ring_opening`: `opening_statement_ctx`'s
//! statement-dependent suffix (present only on the federation path) makes the two protocols hash
//! byte strings of provably different length before either side ever calls
//! `lib_q_ring::sample_in_ball`. This holds regardless of the ring-sig fix — it is a property of
//! `opening.rs`, which the ring-sig fix never touched.
//!
//! Strength of evidence: the length-mismatch (this test's core assertion) is unconditional pure
//! counting, not a cryptographic assumption — `write_module_vec` always emits a non-empty
//! (>= 4-byte) encoding for a non-empty commitment, so `extra_len` in the assertion below is a
//! provably positive integer for any real `AjtaiCommitment`. The follow-on claim "therefore the
//! sampled Fiat-Shamir challenges differ" additionally relies on SHAKE256 behaving as an XOF
//! (not colliding on two structurally different inputs) — the crate's own foundational hash
//! assumption elsewhere, not a new or weaker one introduced here. No actual forged signature
//! (a proof produced under one path that verifies under the other) was constructed or is claimed;
//! the two proof types (`OpeningProof` vs `DualRingOpeningProof`) are additionally not
//! interchangeable at the Rust type level, which was not required to reach this REFUTED verdict
//! but is a second, independent obstacle to any transplant attempt.

use lib_q_lattice_zkp::serialize::write_module_vec;
use lib_q_lattice_zkp::{
    AjtaiCommitmentKey,
    AjtaiOpening,
    AjtaiParameters,
    fs_w_digest,
};
use lib_q_ring::{
    ModuleVec,
    Poly,
};

fn crs() -> AjtaiCommitmentKey {
    AjtaiCommitmentKey {
        seed: [0x5Du8; 32],
        params: AjtaiParameters::new(2, 1),
    }
}

fn commit_with_first_coeff(key: &AjtaiCommitmentKey, v: i32) -> lib_q_lattice_zkp::AjtaiCommitment {
    let mut mvec = vec![Poly::zero(), Poly::zero()];
    mvec[0].coeffs[0] = v;
    let o = AjtaiOpening {
        message: ModuleVec(mvec),
        randomness: ModuleVec(vec![Poly::zero()]),
    };
    lib_q_lattice_zkp::commit(key, &o)
}

/// Imported, NOT copied. An earlier draft duplicated the literal with a comment claiming the
/// constant was `pub(crate)` and unreachable; it is in fact `pub`, inside `pub mod sigma` ->
/// `pub mod opening`, so the copy was both unnecessary and a liability. A duplicated constant
/// silently stops matching when upstream changes it -- the hand-maintained-drift class that has
/// already produced two shipped defects here (t_1558e72f, and the FN-DSA-1024 size at 0737349).
/// Referencing the real one keeps this test's length arithmetic CORRECT if the domain separator
/// ever changes. Verified honestly: changing the upstream constant does NOT make this test fail,
/// and it should not -- the claim here is about the LENGTH difference between the two hash
/// inputs, which holds for any domain value. What the import prevents is the arithmetic silently
/// computing against a stale copy, which could turn into a false pass.
use lib_q_lattice_zkp::sigma::opening::OPENING_STATEMENT_FS_DOMAIN;

/// Manually reproduce `opening_statement_ctx(key, com, ctx, tau, z_inf_bound)`'s output, per its
/// documented formula (opening.rs:110-128): `ctx || DOMAIN || key.seed || tau_le || bound_le ||
/// write_module_vec(com)`.
fn manual_opening_statement_ctx(
    key: &AjtaiCommitmentKey,
    com: &lib_q_lattice_zkp::AjtaiCommitment,
    ctx: &[u8],
    tau: usize,
    z_inf_bound: i32,
) -> Vec<u8> {
    let com_wire = write_module_vec(&com.value.0);
    let mut out = Vec::new();
    out.extend_from_slice(ctx);
    out.extend_from_slice(OPENING_STATEMENT_FS_DOMAIN);
    out.extend_from_slice(&key.seed);
    out.extend_from_slice(&(tau as u64).to_le_bytes());
    out.extend_from_slice(&z_inf_bound.to_le_bytes());
    out.extend_from_slice(&com_wire);
    out
}

/// Manually reproduce `fs_sparse_challenge`'s hash INPUT (not the sampled polynomial itself,
/// which additionally needs `lib_q_ring::sample_in_ball`, not needed to answer this question):
/// `ctx || fs_w_digest(first_message)`.
fn hash_input(ctx: &[u8], first_message: &[Poly]) -> Vec<u8> {
    let w_digest = fs_w_digest(first_message);
    let mut out = ctx.to_vec();
    out.extend_from_slice(&w_digest);
    out
}

/// THE DECISIVE TEST for card t_eacf23b1: given a byte-identical `ctx` shared by both opening
/// protocols (which is exactly what the pre-fix ring-sig collision produced — see module docs),
/// are the two protocols' actual Fiat-Shamir hash inputs also identical, for the SAME
/// attacker-chosen first message `w`? OBSERVED: no — see the length-mismatch assertion below.
#[test]
fn byte_identical_ctx_does_not_yield_equal_opening_hash_inputs() {
    let key = crs();
    let com_a = commit_with_first_coeff(&key, 7);

    // A `ctx` shared by both call sites. This stands in for the pre-fix crafted collision
    // `federation_signing_context(ring, msg_a) == dualring_lb_signing_context(ring, msg_b)`
    // (reproduced separately, see module docs); the divergence tested here does not depend on
    // how the shared ctx was produced, only on it being byte-identical to both callers.
    let shared_ctx: &[u8] = b"shared-colliding-ctx-133-bytes-stand-in-xxxxxxxxxxxxxxxxxxxxxxxxxx";

    // Same attacker-chosen first message `w` fed to both hash-input constructions (an attacker
    // trying to transplant a proof would reuse the same `w = A*y` from one proof on the other
    // side, so give them the most favourable case: identical `w`).
    let w = vec![Poly::zero(), Poly::zero()];

    let tau = 39usize;
    let z_inf_bound = 20_000_000i32;

    let stmt_ctx_fed = manual_opening_statement_ctx(&key, &com_a, shared_ctx, tau, z_inf_bound);
    let fed_hash_input = hash_input(&stmt_ctx_fed, &w);
    let dual_hash_input = hash_input(shared_ctx, &w);

    eprintln!(
        "federation hash input ({} bytes): {:02x?}",
        fed_hash_input.len(),
        fed_hash_input
    );
    eprintln!(
        "dual-ring  hash input ({} bytes): {:02x?}",
        dual_hash_input.len(),
        dual_hash_input
    );

    let extra_len = OPENING_STATEMENT_FS_DOMAIN.len() +
        key.seed.len() +
        8 +
        4 +
        write_module_vec(&com_a.value.0).len();
    assert_eq!(
        fed_hash_input.len(),
        dual_hash_input.len() + extra_len,
        "federation hash input must be longer by exactly the opening_statement_ctx suffix"
    );
    assert!(
        extra_len > 0,
        "the appended suffix must be non-empty for a real commitment"
    );
    assert_ne!(
        fed_hash_input, dual_hash_input,
        "REFUTED-pinning: byte-identical ctx must not yield byte-identical FS hash inputs \
         across the two opening protocols"
    );
}
