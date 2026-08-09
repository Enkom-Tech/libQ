//! F25 (card t_f0d676d1): the transcript-collision hypothesis for the ring-sig Fiat-Shamir
//! contexts.
//!
//! `lens-api-soundness.md` F25 hypothesized that `federation_signing_context` and
//! `dualring_lb_signing_context` are unlength-prefixed concatenations ending in the
//! attacker-chosen message, and that "the base and DualRing-LB contexts can be made byte-equal
//! by choosing a message."
//!
//! **What was found (before the fix landed in this same change):** `dualring_lb_signing_context`
//! built its output by appending a public, attacker-computable suffix directly after
//! `federation_signing_context`'s raw bytes:
//! `dualring_ctx(ring, msg) == federation_signing_context(ring, msg) || suffix(ring, msg)`.
//! Because `suffix` is fully computable without any secret, an attacker could pick
//! `msg_a = msg_b || suffix(ring, msg_b)` so that
//! `federation_signing_context(ring, msg_a) == dualring_lb_signing_context(ring, msg_b)`
//! **as byte strings**, for two genuinely different `(ring, msg_a)` / `(ring, msg_b)` framings.
//! This was CONFIRMED at the byte level (see git history of this file / the card for the
//! before-fix demonstration) — it is a real cross-protocol transcript collision in the context
//! *construction*, not merely a hypothesis.
//!
//! **Fix applied:** `dualring_lb_signing_context` now hashes the base context to a fixed 32-byte
//! digest before appending its own suffix, so it is no longer a byte-extension of
//! `federation_signing_context`'s output. This test pins that: the two constructions must not be
//! related by any message-chosen prefix/suffix relationship any more.
//!
//! What never held (and is also pinned here) is the classic same-function ring-boundary-shift
//! collision "ring=[A,B],msg=M vs ring=[A],msg=serialize(B)||M": `federation_digest` hashes the
//! ring into a fixed 32-byte digest at a fixed offset, so two rings with a different member count
//! can never produce the same digest bytes there without a SHAKE256 collision.
//!
//! **Not (yet) demonstrated in either direction:** an actual signature valid under one
//! construction verifying under the other. The single-opening path (`prove_opening`/
//! `verify_opening`, used by `federation_signing_context`) additionally wraps its context via
//! `lib_q_lattice_zkp::sigma::opening::opening_statement_ctx` (appends a domain tag, the CRS
//! seed, `tau`, `z_inf_bound`, and the commitment wire bytes) before hashing, while the DualRing
//! path (`prove_dual_ring_opening`/`verify_dual_ring_opening`) hashes its `ctx` argument directly
//! with no such wrapping. So even a byte-identical `ctx` string fed to both does not by itself
//! give byte-identical Fiat–Shamir challenges end-to-end; a full cross-protocol forgery was not
//! attempted here (would require also colliding through `opening_statement_ctx`, which lives in
//! `lib-q-lattice-zkp`, outside this crate's edit scope for card t_f0d676d1).

use lib_q_lattice_zkp::{
    AjtaiCommitmentKey,
    AjtaiOpening,
    AjtaiParameters,
};
use lib_q_ring::{
    ModuleVec,
    Poly,
};
use lib_q_ring_sig::{
    dualring_lb_signing_context,
    federation_signing_context,
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

/// REGRESSION for the fix: `dualring_lb_signing_context` must not be a byte-extension (prefix or
/// suffix) of `federation_signing_context`'s output for any message. This is exactly what made
/// the pre-fix cross-protocol collision constructible: the suffix that
/// `dualring_lb_signing_context` appended was fully attacker-computable from public inputs, so
/// folding it into a longer message made the two constructions byte-identical.
#[test]
fn dualring_lb_ctx_is_not_a_byte_extension_of_base_ctx() {
    let key = crs();
    let com_a = commit_with_first_coeff(&key, 7);
    let ring = [com_a];

    let msg_b: &[u8] = b"the-real-message";
    let dualring_ctx = dualring_lb_signing_context(&ring, msg_b);
    let base_ctx_b = federation_signing_context(&ring, msg_b);

    assert!(
        !dualring_ctx.starts_with(&base_ctx_b),
        "dualring context must no longer literally start with the base context bytes"
    );

    // The pre-fix exploit: attacker picks msg_a = msg_b || <the old raw suffix>. Reconstruct the
    // old (vulnerable) suffix shape and confirm it can no longer be folded into a message to
    // reproduce dualring_ctx via federation_signing_context.
    let mut old_style_suffix = vec![2u8];
    old_style_suffix.extend_from_slice(b"lib-q-ring-sig/dualring-lb-v1");
    // One 32-byte per-member label, as the pre-fix construction appended directly.
    let st = lib_q_ring_sig::dualring_lb_challenge_state(&ring, msg_b);
    for d in &st.per_member_challenge_digest {
        old_style_suffix.extend_from_slice(d);
    }
    let mut msg_a = msg_b.to_vec();
    msg_a.extend_from_slice(&old_style_suffix);
    let base_ctx_a = federation_signing_context(&ring, &msg_a);

    assert_ne!(
        base_ctx_a, dualring_ctx,
        "the old cross-protocol byte collision must no longer reproduce after the fix"
    );
}

/// REFUTED (same-function case, holds both before and after the fix): the classic
/// ring-boundary-shift attack `ring=[A,B], msg=M` vs `ring=[A], msg=serialize(B)||M` does NOT
/// collide for either `federation_signing_context` or `dualring_lb_signing_context`, because the
/// ring is absorbed as a length-prefixed hash digest (fixed 32 bytes at a fixed offset), not a
/// raw concatenation of member encodings that the message directly continues.
#[test]
fn ring_boundary_shift_does_not_collide_same_function() {
    let key = crs();
    let com_a = commit_with_first_coeff(&key, 1);
    let com_b = commit_with_first_coeff(&key, 2);

    let msg_m: &[u8] = b"tail-message";

    // ring = [A, B], message = M
    let ring_ab = [com_a.clone(), com_b.clone()];
    let ctx_ab_m = federation_signing_context(&ring_ab, msg_m);
    let dctx_ab_m = dualring_lb_signing_context(&ring_ab, msg_m);

    // ring = [A], message = serialize(B) || M  (the naive "shifted boundary" attempt)
    let com_b_wire = lib_q_lattice_zkp::serialize::write_module_vec(&com_b.value.0);
    let mut msg_shifted = com_b_wire.clone();
    msg_shifted.extend_from_slice(msg_m);
    let ring_a = [com_a];
    let ctx_a_shifted = federation_signing_context(&ring_a, &msg_shifted);
    let dctx_a_shifted = dualring_lb_signing_context(&ring_a, &msg_shifted);

    eprintln!("ctx([A,B], M)              = {:02x?}", ctx_ab_m);
    eprintln!("ctx([A], serialize(B)||M)  = {:02x?}", ctx_a_shifted);
    assert_ne!(
        ctx_ab_m, ctx_a_shifted,
        "federation_signing_context must not be shiftable across the ring/message boundary"
    );
    assert_ne!(
        dctx_ab_m, dctx_a_shifted,
        "dualring_lb_signing_context must not be shiftable across the ring/message boundary"
    );
}

/// Sanity: the fix must not break normal binding — different messages (same ring) still produce
/// different dualring contexts, and different rings (same message) still produce different ones.
#[test]
fn dualring_lb_ctx_still_binds_ring_and_message() {
    let key = crs();
    let com_a = commit_with_first_coeff(&key, 11);
    let com_b = commit_with_first_coeff(&key, 12);
    let ring = [com_a.clone()];
    let ring2 = [com_a, com_b];

    let ctx1 = dualring_lb_signing_context(&ring, b"msg-one");
    let ctx2 = dualring_lb_signing_context(&ring, b"msg-two");
    assert_ne!(
        ctx1, ctx2,
        "different messages must yield different contexts"
    );

    let ctx3 = dualring_lb_signing_context(&ring2, b"msg-one");
    assert_ne!(ctx1, ctx3, "different rings must yield different contexts");
}
