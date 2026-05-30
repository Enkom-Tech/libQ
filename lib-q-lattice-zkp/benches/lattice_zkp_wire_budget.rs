//! Record encoded wire sizes and prove/verify timings for wire-budget evidence.

use criterion::{
    Criterion,
    criterion_group,
    criterion_main,
};
use lib_q_lattice_zkp::{
    AjtaiCommitmentKey,
    AjtaiOpening,
    LatticeZkpProfileV0,
    MerklePath,
    WIRE_BUDGET_PVTN_MEMBERSHIP_BYTES,
    commit,
    decode_opening_proof_v0,
    encode_opening_proof_v0,
    encode_private_membership_proof_v0,
    encode_pvtn_leaf,
    leaf_hash,
    node_hash,
    prove_opening,
    prove_private_membership,
    verify_opening,
    verify_private_membership,
    wire_byte_len,
};
use lib_q_random::new_deterministic_rng;
use lib_q_ring::{
    ModuleVec,
    Poly,
};

const SEED: [u8; 32] = [0x47u8; 32];

fn bench_group(c: &mut Criterion) {
    let pvtn_profile = LatticeZkpProfileV0::pvtn_membership_v0();
    let token_profile = LatticeZkpProfileV0::token_spend_v0();

    c.bench_function("pvtn_membership_wire_bytes", |b| {
        b.iter(|| {
            let key = AjtaiCommitmentKey {
                seed: SEED,
                params: pvtn_profile.ajtai.clone(),
            };
            let opening = AjtaiOpening {
                message: ModuleVec(vec![Poly::zero()]),
                randomness: ModuleVec(vec![Poly::zero()]),
            };
            let com = commit(&key, &opening);
            let role = [0x5Au8; 16];
            let parent = [0u8; 32];
            let leaf_payload = encode_pvtn_leaf(8, &role, &parent);
            let l0 = leaf_hash(b"bench-0");
            let l1 = leaf_hash(&leaf_payload);
            let root = node_hash(&l0, &l1);
            let path = MerklePath {
                path_index: 1,
                siblings: vec![l0],
            };
            let mut rng = new_deterministic_rng(SEED);
            let proof = prove_private_membership(
                &mut rng,
                &key,
                &opening,
                &com,
                leaf_payload,
                path,
                &root,
                3,
                b"bench-pvtn",
                pvtn_profile.tau,
                pvtn_profile.z_inf_bound,
                pvtn_profile.max_prove_attempts,
            )
            .expect("prove");
            let wire = encode_private_membership_proof_v0(&pvtn_profile, &proof, &root, 3)
                .expect("encode");
            verify_private_membership(
                &key,
                &proof,
                &root,
                3,
                b"bench-pvtn",
                pvtn_profile.tau,
                pvtn_profile.z_inf_bound,
            )
            .expect("verify");
            assert!(wire_byte_len(&wire) <= WIRE_BUDGET_PVTN_MEMBERSHIP_BYTES);
            wire
        });
    });

    c.bench_function("opening_prove_verify", |b| {
        b.iter(|| {
            let key = AjtaiCommitmentKey {
                seed: SEED,
                params: token_profile.ajtai.clone(),
            };
            let opening = AjtaiOpening {
                message: ModuleVec(vec![Poly::zero(), Poly::zero()]),
                randomness: ModuleVec(vec![Poly::zero()]),
            };
            let com = commit(&key, &opening);
            let mut rng = new_deterministic_rng(SEED);
            let proof = prove_opening(
                &mut rng,
                &key,
                &opening,
                &com,
                b"bench-open",
                token_profile.tau,
                token_profile.z_inf_bound,
                token_profile.max_prove_attempts,
            )
            .expect("prove");
            verify_opening(
                &key,
                &com,
                &proof,
                b"bench-open",
                token_profile.tau,
                token_profile.z_inf_bound,
            )
            .expect("verify");
            let wire = encode_opening_proof_v0(&token_profile, &proof).expect("encode");
            let _ = decode_opening_proof_v0(&wire).expect("decode");
        });
    });
}

criterion_group!(benches, bench_group);
criterion_main!(benches);
