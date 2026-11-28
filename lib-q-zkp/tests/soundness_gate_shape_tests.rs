//! Ties the PROVEN soundness gate (`soundness_gate`) to the real prover and verifier: the number of
//! openings the PCS batches (`l`), the LDE domain a trace of a given height produces, and the trace
//! heights each verifier accepts are MEASURED here from production-config proofs, so the constants
//! in `soundness_gate` cannot drift from the code they price.

#![cfg(feature = "zkp")]

mod soundness_gate;

use lib_q_stark_baby_bear::BabyBear;
use lib_q_stark_field::TwoAdicField;
use lib_q_stark_field::extension::Complex;
use lib_q_stark_mersenne31::Mersenne31;
use lib_q_zkp::air::unlinkable_membership_baby_bear::{
    CTX_ELEMS as BB_CTX_ELEMS, SECRET_T_ELEMS as BB_SECRET_T_ELEMS, membership_leaf_bb,
};
use lib_q_zkp::air::wide_merkle_path_baby_bear::WideDigestBb;
use lib_q_zkp::air::{CTX_ELEMS, SECRET_T_ELEMS, WideDigest, membership_leaf};
use lib_q_zkp::membership::{
    MAX_DEPTH, MembershipWitness, prove_unlinkable_membership, prove_unlinkable_membership_zk,
};
use lib_q_zkp::merkle::WidePoseidonMerkleTree;
use lib_q_zkp::merkle_baby_bear::{WidePoseidonMerkleTreeBb, wide_node_hash_bb};
use lib_q_zkp::stark::{MembershipConfig, MembershipZkConfig};
use lib_q_zkp::stark_baby_bear::{
    default_config_bb, default_zk_config_bb, prove_membership_bb, prove_membership_bb_zk,
    verify_membership_bb,
};
use soundness_gate::{
    ARM_A_LDE_TWO_ADICITY, ARM_A_MAX_TRACE_ROWS, ARM_B_LDE_TWO_ADICITY, ProvenArm,
    arm_a_membership, arm_a_membership_zk, arm_b_membership, arm_b_membership_zk,
};

/// Tree depth the shape is measured at. `l` depends on the AIR width, not on the depth; the LDE
/// height rule is checked here and extrapolated to the verifier's limit by `lde_domain_log2`.
const DEPTH: usize = 8;

/// Every value the STARK opens; each is one (column, point) pair of the alpha-batched reduction.
fn stark_openings<C>(o: &lib_q_stark::OpenedValues<C>) -> usize {
    o.trace_local.len()
        + o.trace_next.len()
        + o.preprocessed_local.iter().map(Vec::len).sum::<usize>()
        + o.preprocessed_next.iter().map(Vec::len).sum::<usize>()
        + o.quotient_chunks.iter().map(Vec::len).sum::<usize>()
        + o.random.iter().map(Vec::len).sum::<usize>()
}

/// Openings of the random polynomials the hiding PCS adds; they are batched with the rest.
fn hiding_openings<C>(o: &lib_q_stark_commit::OpenedValues<C>) -> usize {
    o.iter().flatten().flatten().map(Vec::len).sum()
}

/// log2 of the largest committed LDE height, from the number of FRI folding rounds (the FRI
/// verifier's own relation; `log_final_poly_len` is 0 in every membership config).
fn lde_log2(fold_rounds: usize, arm: &ProvenArm) -> usize {
    fold_rounds + arm.log_blowup
}

fn expected_lde_log2(arm: &ProvenArm) -> usize {
    DEPTH.ilog2() as usize + usize::from(arm.zk) + arm.log_blowup
}

/// The gate prices FRI on ONE batched word (BCGM Lemma 9.3 + BCIKS20 Thm 8.3, no `beta^2` roll-in),
/// which holds only if every committed matrix sits at the global max LDE height. A Merkle opening
/// has one sibling per level of its commitment's tallest matrix, so every input opening of every
/// query must be `lde_log2` long. (Within one commitment the quotient chunks are equal-sized by
/// construction: `lib-q-stark/src/verifier.rs`, `split_domains`.)
fn assert_single_lde_height(path_lens: impl Iterator<Item = usize>, lde_log2: usize) {
    let mut seen = 0;
    for len in path_lens {
        assert_eq!(
            len, lde_log2,
            "an input commitment is shorter than the max LDE height"
        );
        seen += 1;
    }
    assert!(seen > 0, "no input openings measured");
}

fn arm_a_witness() -> MembershipWitness {
    let fe = |x: u32| Complex::<Mersenne31>::from(Mersenne31::new(x));
    let secrets: Vec<[Complex<Mersenne31>; SECRET_T_ELEMS]> = (0..1u32 << DEPTH)
        .map(|s| core::array::from_fn(|i| fe(s * 7 + i as u32 + 1)))
        .collect();
    let leaves: Vec<WideDigest> = secrets.iter().map(membership_leaf).collect();
    let tree = WidePoseidonMerkleTree::from_leaf_digests(&leaves).expect("tree");
    let (path_bits, siblings) = tree.path(3).expect("path");
    MembershipWitness {
        t: secrets[3],
        ctx: core::array::from_fn::<_, CTX_ELEMS, _>(|i| fe(100 + i as u32)),
        path_bits,
        siblings,
    }
}

struct ArmBWitness {
    t: [BabyBear; BB_SECRET_T_ELEMS],
    ctx: [BabyBear; BB_CTX_ELEMS],
    bits: Vec<bool>,
    sibs: Vec<WideDigestBb>,
    root: WideDigestBb,
}

fn arm_b_secret() -> [BabyBear; BB_SECRET_T_ELEMS] {
    core::array::from_fn(|i| BabyBear::new(31 * i as u32 + 5))
}

fn arm_b_witness() -> ArmBWitness {
    let mut secrets: Vec<[BabyBear; BB_SECRET_T_ELEMS]> = (0..1u32 << DEPTH)
        .map(|s| core::array::from_fn(|i| BabyBear::new(s * 7 + i as u32 + 1)))
        .collect();
    secrets[3] = arm_b_secret();
    let leaves: Vec<WideDigestBb> = secrets.iter().map(membership_leaf_bb).collect();
    let tree = WidePoseidonMerkleTreeBb::from_leaf_digests(&leaves).expect("tree");
    let (bits, sibs) = tree.path(3).expect("path");
    ArmBWitness {
        t: secrets[3],
        ctx: core::array::from_fn(|i| BabyBear::new(100 + i as u32)),
        bits,
        sibs,
        root: tree.root(),
    }
}

/// An Arm B path of any depth, built by folding the leaf with arbitrary siblings (no `2^depth`
/// tree), in the tree's own orientation: bit set means the running node is the right child.
fn arm_b_synthetic_witness(depth: usize) -> ArmBWitness {
    let t = arm_b_secret();
    let mut running = membership_leaf_bb(&t);
    let (mut bits, mut sibs) = (Vec::new(), Vec::new());
    for level in 0..depth {
        let sib: WideDigestBb =
            core::array::from_fn(|i| BabyBear::new(1_000 + 17 * level as u32 + i as u32));
        let dir = level % 3 == 1;
        running = if dir {
            wide_node_hash_bb(&sib, &running)
        } else {
            wide_node_hash_bb(&running, &sib)
        };
        bits.push(dir);
        sibs.push(sib);
    }
    ArmBWitness {
        t,
        ctx: core::array::from_fn(|i| BabyBear::new(100 + i as u32)),
        bits,
        sibs,
        root: running,
    }
}

#[test]
fn arm_a_transparent_shape_matches_the_gate() {
    let arm = arm_a_membership();
    let (_, zkp) = prove_unlinkable_membership(&arm_a_witness()).expect("prove");
    let proof = zkp.to_stark_proof::<MembershipConfig>().expect("decode");
    assert_eq!(stark_openings(&proof.opened_values), arm.batched_openings);
    let rounds = proof.opening_proof.commit_phase_commits.len();
    assert_eq!(lde_log2(rounds, &arm), expected_lde_log2(&arm));
    assert_single_lde_height(
        proof
            .opening_proof
            .query_proofs
            .iter()
            .flat_map(|q| q.input_proof.iter().map(|b| b.opening_proof.len())),
        lde_log2(rounds, &arm),
    );
}

#[test]
fn arm_a_zk_shape_matches_the_gate() {
    let arm = arm_a_membership_zk();
    let (_, zkp) =
        prove_unlinkable_membership_zk(&arm_a_witness(), [1; 32], [2; 32]).expect("prove");
    let proof = zkp.to_stark_proof::<MembershipZkConfig>().expect("decode");
    let (hiding, fri) = &proof.opening_proof;
    assert_eq!(
        stark_openings(&proof.opened_values) + hiding_openings(hiding),
        arm.batched_openings
    );
    assert_eq!(
        lde_log2(fri.commit_phase_commits.len(), &arm),
        expected_lde_log2(&arm)
    );
    assert_single_lde_height(
        fri.query_proofs
            .iter()
            .flat_map(|q| q.input_proof.iter().map(|b| b.opening_proof.1.len())),
        lde_log2(fri.commit_phase_commits.len(), &arm),
    );
}

#[test]
fn arm_b_transparent_shape_matches_the_gate() {
    let arm = arm_b_membership();
    let w = arm_b_witness();
    let (_, proof) = prove_membership_bb(
        &default_config_bb(),
        &w.t,
        &w.ctx,
        &w.bits,
        &w.sibs,
        &w.root,
    )
    .expect("prove");
    assert_eq!(stark_openings(&proof.opened_values), arm.batched_openings);
    let rounds = proof.opening_proof.commit_phase_commits.len();
    assert_eq!(lde_log2(rounds, &arm), expected_lde_log2(&arm));
    assert_single_lde_height(
        proof
            .opening_proof
            .query_proofs
            .iter()
            .flat_map(|q| q.input_proof.iter().map(|b| b.opening_proof.len())),
        lde_log2(rounds, &arm),
    );
}

#[test]
fn arm_b_zk_shape_matches_the_gate() {
    let arm = arm_b_membership_zk();
    let w = arm_b_witness();
    let config = default_zk_config_bb([1; 32], [2; 32]);
    let (_, proof) =
        prove_membership_bb_zk(&config, &w.t, &w.ctx, &w.bits, &w.sibs, &w.root).expect("prove");
    let (hiding, fri) = &proof.opening_proof;
    assert_eq!(
        stark_openings(&proof.opened_values) + hiding_openings(hiding),
        arm.batched_openings
    );
    assert_eq!(
        lde_log2(fri.commit_phase_commits.len(), &arm),
        expected_lde_log2(&arm)
    );
    assert_single_lde_height(
        fri.query_proofs
            .iter()
            .flat_map(|q| q.input_proof.iter().map(|b| b.opening_proof.1.len())),
        lde_log2(fri.commit_phase_commits.len(), &arm),
    );
}

/// The gate's trace-height limits are the code's: Arm A's is `MAX_DEPTH` (a power of two, so the
/// padded height never exceeds it) and the two-adicity limits are the fields' own.
#[test]
fn trace_height_limits_match_the_code() {
    assert_eq!(ARM_A_MAX_TRACE_ROWS, MAX_DEPTH);
    assert!(MAX_DEPTH.is_power_of_two());
    assert_eq!(
        ARM_A_LDE_TWO_ADICITY,
        <Complex<Mersenne31> as TwoAdicField>::TWO_ADICITY
    );
    assert_eq!(
        ARM_B_LDE_TWO_ADICITY,
        <BabyBear as TwoAdicField>::TWO_ADICITY
    );
}

/// Why Arm B is priced at the two-adicity limit and not at `MAX_DEPTH`: its verifier accepts a
/// proof whose trace is taller than `MAX_DEPTH` rows.
#[test]
fn arm_b_verifier_accepts_a_trace_taller_than_max_depth() {
    let depth = 2 * MAX_DEPTH;
    let w = arm_b_synthetic_witness(depth);
    let config = default_config_bb();
    let (nullifier, proof) =
        prove_membership_bb(&config, &w.t, &w.ctx, &w.bits, &w.sibs, &w.root).expect("prove");
    assert_eq!(1usize << proof.degree_bits, depth);
    assert!(verify_membership_bb(
        &config, &proof, &w.root, &w.ctx, &nullifier
    ));
}
