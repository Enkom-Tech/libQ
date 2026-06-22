//! Integration tests for the public unlinkable membership API
//! (`lib_q_zkp::membership`, libQ `libq.zkfri.membership.v0`).
//!
//! Exercises the prove/verify contract, the nullifier properties (determinism, context
//! unlinkability, double-use linkability), verifier negatives, input validation / DoS limits,
//! and the wire serialization — all through the crate's public surface, as an external
//! consumer would. Uses [`fast_proof_config`] so the real STARK prover stays fast.
//!
//! RED: the membership tier is gated behind the ADR-113 freeze review (Poseidon-256 round
//! counts unverified for GF(p²)); these tests pin behaviour, not a soundness sign-off.

use lib_q_stark_field::extension::Complex;
use lib_q_stark_mersenne31::Mersenne31;
use lib_q_zkp::air::{
    CTX_ELEMS,
    SECRET_T_ELEMS,
    WideDigest,
    membership_leaf,
    membership_nullifier,
};
use lib_q_zkp::membership::{
    CTX_BYTES,
    MAX_DEPTH,
    MembershipWitness,
    PUBLIC_STATEMENT_BYTES,
    WIDE_DIGEST_BYTES,
    prove_unlinkable_membership_with_config,
    public_statement_bytes,
    statement_domain,
    verify_unlinkable_membership_with_config,
    wide_digest_from_bytes,
    wide_digest_to_bytes,
};
use lib_q_zkp::merkle::WidePoseidonMerkleTree;
use lib_q_zkp::stark::fast_proof_config;

type Fe = Complex<Mersenne31>;

fn fe(x: u32) -> Fe {
    Complex::<Mersenne31>::from(Mersenne31::new(x))
}
fn secret(seed: u32) -> [Fe; SECRET_T_ELEMS] {
    core::array::from_fn(|i| fe(seed * 7 + i as u32 + 1))
}
fn ctx_of(seed: u32) -> [Fe; CTX_ELEMS] {
    core::array::from_fn(|i| fe(seed * 13 + i as u32 + 100))
}

fn build(n: u32) -> (WidePoseidonMerkleTree, Vec<[Fe; SECRET_T_ELEMS]>) {
    let secrets: Vec<_> = (0..n).map(secret).collect();
    let leaves: Vec<WideDigest> = secrets.iter().map(membership_leaf).collect();
    let tree = WidePoseidonMerkleTree::from_leaf_digests(&leaves).expect("tree");
    (tree, secrets)
}

fn witness(
    tree: &WidePoseidonMerkleTree,
    secrets: &[[Fe; SECRET_T_ELEMS]],
    index: usize,
    ctx_seed: u32,
) -> MembershipWitness {
    let (path_bits, siblings) = tree.path(index).expect("path");
    MembershipWitness {
        t: secrets[index],
        ctx: ctx_of(ctx_seed),
        path_bits,
        siblings,
    }
}

#[test]
fn round_trip_every_member() {
    // 6 members → depth 3 (padded to height 4 internally).
    let (tree, secrets) = build(6);
    let cfg = fast_proof_config();
    for index in 0..6usize {
        let w = witness(&tree, &secrets, index, index as u32);
        let (nullifier, proof) =
            prove_unlinkable_membership_with_config(&w, cfg.clone()).expect("prove");
        assert!(
            verify_unlinkable_membership_with_config(
                &proof,
                &tree.root(),
                &w.ctx,
                &nullifier,
                cfg.clone()
            )
            .expect("verify"),
            "member {index} must verify against the canonical root"
        );
    }
}

#[test]
fn round_trip_power_of_two_depth() {
    // 16 members → depth 4 (already a power of two ⇒ no padding).
    let (tree, secrets) = build(16);
    assert_eq!(tree.depth(), 4);
    let cfg = fast_proof_config();
    let w = witness(&tree, &secrets, 13, 1);
    let (nullifier, proof) =
        prove_unlinkable_membership_with_config(&w, cfg.clone()).expect("prove");
    assert!(
        verify_unlinkable_membership_with_config(&proof, &tree.root(), &w.ctx, &nullifier, cfg)
            .expect("verify")
    );
}

#[test]
fn nullifier_determinism_and_unlinkability() {
    let (tree, secrets) = build(8);
    let cfg = fast_proof_config();

    // Same member + same ctx ⇒ identical nullifier (double-use is detectable).
    let w1 = witness(&tree, &secrets, 2, 5);
    let (n1, _p1) = prove_unlinkable_membership_with_config(&w1, cfg.clone()).expect("prove");
    let (n1b, _p1b) = prove_unlinkable_membership_with_config(&w1, cfg.clone()).expect("prove");
    assert_eq!(
        n1, n1b,
        "same (t, ctx) ⇒ same nullifier (linkable double-use)"
    );
    assert_eq!(n1, membership_nullifier(&secrets[2], &ctx_of(5)));

    // Same member, different ctx ⇒ unlinkable nullifier.
    let w2 = witness(&tree, &secrets, 2, 6);
    let (n2, _p2) = prove_unlinkable_membership_with_config(&w2, cfg.clone()).expect("prove");
    assert_ne!(n1, n2, "different ctx ⇒ unlinkable nullifier");

    // Different member, same ctx ⇒ different nullifier.
    let w3 = witness(&tree, &secrets, 3, 5);
    let (n3, _p3) = prove_unlinkable_membership_with_config(&w3, cfg).expect("prove");
    assert_ne!(n1, n3, "distinct members ⇒ distinct nullifiers");
}

#[test]
fn verify_rejects_wrong_public_inputs() {
    let (tree, secrets) = build(8);
    let cfg = fast_proof_config();
    let w = witness(&tree, &secrets, 1, 9);
    let (nullifier, proof) =
        prove_unlinkable_membership_with_config(&w, cfg.clone()).expect("prove");

    // Wrong root.
    assert!(
        !verify_unlinkable_membership_with_config(
            &proof,
            &membership_leaf(&secret(4242)),
            &w.ctx,
            &nullifier,
            cfg.clone()
        )
        .unwrap()
    );
    // Wrong ctx.
    assert!(
        !verify_unlinkable_membership_with_config(
            &proof,
            &tree.root(),
            &ctx_of(99),
            &nullifier,
            cfg.clone()
        )
        .unwrap()
    );
    // Wrong nullifier.
    let mut bad_n = nullifier;
    bad_n[2] += fe(1);
    assert!(
        !verify_unlinkable_membership_with_config(&proof, &tree.root(), &w.ctx, &bad_n, cfg)
            .unwrap()
    );
}

#[test]
fn non_member_secret_does_not_verify_against_tree_root() {
    // A non-member presents a real member's authentication path with their own secret. The
    // prover folds a DIFFERENT root, so verification against the canonical tree root fails.
    let (tree, secrets) = build(8);
    let cfg = fast_proof_config();
    let real = witness(&tree, &secrets, 4, 2);

    let forged = MembershipWitness {
        t: secret(123_456), // not in the tree
        ctx: ctx_of(2),
        path_bits: real.path_bits.clone(),
        siblings: real.siblings.clone(),
    };
    let (nullifier, proof) =
        prove_unlinkable_membership_with_config(&forged, cfg.clone()).expect("prove");
    assert!(
        !verify_unlinkable_membership_with_config(
            &proof,
            &tree.root(),
            &forged.ctx,
            &nullifier,
            cfg
        )
        .unwrap(),
        "non-member must not verify against the canonical tree root"
    );
}

#[test]
fn input_validation_and_dos_limits() {
    let cfg = fast_proof_config();
    let zero_sib: WideDigest = [fe(0); 5];

    // Depth 0 (empty path) is rejected.
    let empty = MembershipWitness {
        t: secret(1),
        ctx: ctx_of(1),
        path_bits: vec![],
        siblings: vec![],
    };
    assert!(prove_unlinkable_membership_with_config(&empty, cfg.clone()).is_err());

    // Depth > MAX_DEPTH is rejected (fast: validated before proving).
    let too_deep = MembershipWitness {
        t: secret(1),
        ctx: ctx_of(1),
        path_bits: vec![false; MAX_DEPTH + 1],
        siblings: vec![zero_sib; MAX_DEPTH + 1],
    };
    assert!(prove_unlinkable_membership_with_config(&too_deep, cfg.clone()).is_err());

    // path_bits / siblings length mismatch is rejected.
    let mismatch = MembershipWitness {
        t: secret(1),
        ctx: ctx_of(1),
        path_bits: vec![false, true, false],
        siblings: vec![zero_sib, zero_sib],
    };
    assert!(prove_unlinkable_membership_with_config(&mismatch, cfg).is_err());
}

#[test]
fn serialization_round_trips() {
    let (tree, secrets) = build(8);
    let w_ctx = ctx_of(7);
    let nullifier = membership_nullifier(&secrets[3], &w_ctx);

    // Wide digest round-trip.
    let root = tree.root();
    let root_bytes = wide_digest_to_bytes(&root);
    assert_eq!(root_bytes.len(), WIDE_DIGEST_BYTES);
    assert_eq!(wide_digest_from_bytes(&root_bytes).unwrap(), root);

    // Public-statement encoding `root ‖ ctx ‖ N`.
    let stmt = public_statement_bytes(&root, &w_ctx, &nullifier);
    assert_eq!(stmt.len(), PUBLIC_STATEMENT_BYTES);
    assert_eq!(
        wide_digest_from_bytes(&stmt[..WIDE_DIGEST_BYTES]).unwrap(),
        root
    );
    assert_eq!(
        wide_digest_from_bytes(&stmt[WIDE_DIGEST_BYTES + CTX_BYTES..]).unwrap(),
        nullifier
    );

    // Too-short buffers are rejected, not truncated.
    assert!(wide_digest_from_bytes(&root_bytes[..WIDE_DIGEST_BYTES - 1]).is_err());
}

#[test]
fn rejects_mismatched_declared_depth() {
    // Freeze-gate O5: the declared tree_depth is authenticated against the proof's actual STARK
    // trace height; relabelling it (so next_pow2(depth) != height) must be rejected.
    use lib_q_zkp::ProofMetadata;
    let (tree, secrets) = build(6); // 6 members → depth 3 → padded height 4
    let cfg = fast_proof_config();
    let w = witness(&tree, &secrets, 2, 1);
    let (nullifier, mut proof) =
        prove_unlinkable_membership_with_config(&w, cfg.clone()).expect("prove");

    // Honest proof verifies.
    assert!(
        verify_unlinkable_membership_with_config(
            &proof,
            &tree.root(),
            &w.ctx,
            &nullifier,
            cfg.clone()
        )
        .unwrap()
    );

    // Relabel declared depth to 5: next_pow2(5) == 8 != trace height 4 → guard rejects.
    proof.metadata = ProofMetadata::UnlinkableMembership {
        tree_depth: 5,
        digest_width: 5,
        zk: false,
    };
    assert!(
        !verify_unlinkable_membership_with_config(&proof, &tree.root(), &w.ctx, &nullifier, cfg)
            .unwrap(),
        "depth-confusion guard must reject a relabelled tree_depth"
    );
}

#[test]
fn statement_domain_is_pinned() {
    assert_eq!(statement_domain(), "libq.zkfri.membership.v0");
}
