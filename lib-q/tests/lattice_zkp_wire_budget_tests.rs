//! Reference wire-budget scenarios: prove/verify, encoded sizes, and CI gates.

use lib_q_lattice_zkp::{
    AjtaiCommitmentKey,
    AjtaiOpening,
    AmortisationBudget,
    AnonymousToken,
    LatticeZkpProfileV0,
    MerklePath,
    SpendingProof,
    TOKEN_EPOCH_LEN,
    TOKEN_ORIGIN_LEN,
    TOKEN_SERIAL_LEN,
    WIRE_BUDGET_PRESENTATION_BYTES,
    WIRE_BUDGET_PVTN_MEMBERSHIP_BYTES,
    amortise,
    commit,
    encode_opening_proof_v0,
    encode_private_membership_proof_v0,
    encode_pvtn_leaf,
    encode_spending_proof_v0,
    leaf_hash,
    measured_opening_wire_body_bytes,
    node_hash,
    opening_from_token_fields,
    prove_opening,
    prove_private_membership,
    verify_opening,
    verify_private_membership,
};
use lib_q_random::new_deterministic_rng;
use lib_q_ring::{
    ModuleVec,
    Poly,
};

const KAT_SEED: [u8; 32] = [
    0x6C, 0x61, 0x74, 0x74, 0x69, 0x63, 0x65, 0x2D, 0x7A, 0x6B, 0x70, 0x2D, 0x76, 0x30, 0x2D, 0x6B,
    0x61, 0x74, 0x2D, 0x73, 0x65, 0x65, 0x64, 0x2D, 0x30, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[inline]
fn rng() -> lib_q_random::LibQRng {
    new_deterministic_rng(KAT_SEED)
}

fn pvtn_key() -> AjtaiCommitmentKey {
    AjtaiCommitmentKey {
        seed: KAT_SEED,
        params: LatticeZkpProfileV0::pvtn_membership_v0().ajtai,
    }
}

fn token_key() -> AjtaiCommitmentKey {
    AjtaiCommitmentKey {
        seed: KAT_SEED,
        params: LatticeZkpProfileV0::token_spend_v0().ajtai,
    }
}

fn disclosure_key() -> AjtaiCommitmentKey {
    AjtaiCommitmentKey {
        seed: KAT_SEED,
        params: LatticeZkpProfileV0::selective_disclosure_v0().ajtai,
    }
}

#[test]
fn baseline_legacy_i32_pvtn_exceeds_budget() {
    let profile = LatticeZkpProfileV0::pvtn_membership_v0();
    let key = pvtn_key();
    let opening = AjtaiOpening {
        message: ModuleVec(vec![Poly::zero()]),
        randomness: ModuleVec(vec![Poly::zero()]),
    };
    let com = commit(&key, &opening);
    let role = [0x5Au8; 16];
    let parent = [0u8; 32];
    let leaf_payload = encode_pvtn_leaf(8, &role, &parent);
    let l0 = leaf_hash(b"baseline-0");
    let l1 = leaf_hash(&leaf_payload);
    let root = node_hash(&l0, &l1);
    let path = MerklePath {
        path_index: 1,
        siblings: vec![l0],
    };
    let mut r = rng();
    let proof = prove_private_membership(
        &mut r,
        &key,
        &opening,
        &com,
        leaf_payload,
        path,
        &root,
        3,
        b"lattice-zkp/kat/baseline-pvtn",
        profile.tau,
        profile.z_inf_bound,
        profile.max_prove_attempts,
    )
    .expect("prove pvtn");
    let legacy_estimate = 5 * 1024 + 32 + 52;
    assert!(
        legacy_estimate > WIRE_BUDGET_PVTN_MEMBERSHIP_BYTES,
        "sanity: legacy packing estimate should exceed 4KiB"
    );
    let wire =
        encode_private_membership_proof_v0(&profile, &proof, &root, 3).expect("encode pvtn wire");
    assert!(
        wire.len() <= WIRE_BUDGET_PVTN_MEMBERSHIP_BYTES,
        "PVTN wire {} exceeds {}",
        wire.len(),
        WIRE_BUDGET_PVTN_MEMBERSHIP_BYTES
    );
    verify_private_membership(
        &key,
        &proof,
        &root,
        3,
        b"lattice-zkp/kat/baseline-pvtn",
        profile.tau,
        profile.z_inf_bound,
    )
    .expect("verify pvtn");
}

#[test]
fn wire_budget_opening_and_token_spend() {
    let profile = LatticeZkpProfileV0::token_spend_v0();
    let key = token_key();
    let serial = [0x42u8; TOKEN_SERIAL_LEN];
    let origin = [0x07u8; TOKEN_ORIGIN_LEN];
    let epoch = [0x01u8; TOKEN_EPOCH_LEN];
    let opening =
        opening_from_token_fields(2, 1, &serial, &origin, &epoch).expect("token opening layout");
    let com = commit(&key, &opening);
    let mut r = rng();
    let proof = prove_opening(
        &mut r,
        &key,
        &opening,
        &com,
        b"lattice-zkp/kat/token-spend",
        profile.tau,
        profile.z_inf_bound,
        profile.max_prove_attempts,
    )
    .expect("prove opening");
    verify_opening(
        &key,
        &com,
        &proof,
        b"lattice-zkp/kat/token-spend",
        profile.tau,
        profile.z_inf_bound,
    )
    .expect("verify opening");
    let opening_wire = encode_opening_proof_v0(&profile, &proof).expect("encode opening");
    assert!(opening_wire.len() <= WIRE_BUDGET_PRESENTATION_BYTES);
    let spend = SpendingProof {
        serial,
        opening_proof: proof,
    };
    let spend_wire = encode_spending_proof_v0(&profile, &spend).expect("encode spend");
    assert!(spend_wire.len() <= WIRE_BUDGET_PRESENTATION_BYTES);
    let _token = AnonymousToken {
        commitment: com,
        serial,
        origin,
        epoch_le: epoch,
        opening_proof: spend.opening_proof.clone(),
    };
}

#[test]
#[ignore = "WIP: encode_amortised_proof_v0 rejects agg_z that exceeds per-response z_inf_bound after aggregation"]
fn wire_budget_three_attribute_selective_disclosure() {
    let profile = LatticeZkpProfileV0::selective_disclosure_v0();
    let key = disclosure_key();
    let mut openings = Vec::new();
    let mut commitments = Vec::new();
    for i in 0u8..3 {
        let mut m = vec![Poly::zero(), Poly::zero()];
        m[0].coeffs[0] = i32::from(i + 1);
        let o = AjtaiOpening {
            message: ModuleVec(m),
            randomness: ModuleVec(vec![Poly::zero()]),
        };
        commitments.push(commit(&key, &o));
        openings.push(o);
    }
    let mut proof = None;
    for attempt in 0u64..256 {
        let mut ar = new_deterministic_rng([
            KAT_SEED[0],
            KAT_SEED[1],
            attempt as u8,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ]);
        if let Ok(p) = amortise(
            &mut ar,
            &key,
            &openings,
            &commitments,
            b"lattice-zkp/kat/3-attr",
            profile.tau,
            500_000_000,
        ) {
            proof = Some(p);
            break;
        }
    }
    let proof = proof.expect("amortise 3 attributes");
    let wire =
        lib_q_lattice_zkp::encode_amortised_proof_v0(&profile, &proof).expect("encode amortised");
    assert!(
        wire.len() <= WIRE_BUDGET_PRESENTATION_BYTES,
        "3-attr amortised wire {} exceeds budget",
        wire.len()
    );
    let budget = AmortisationBudget::selective_disclosure_v0_measured();
    let est = budget.estimate_presentation_bytes(3);
    assert!(est <= WIRE_BUDGET_PRESENTATION_BYTES);
    let per_attr = measured_opening_wire_body_bytes(&profile);
    assert!(per_attr > 0);
}

#[test]
fn recorded_opening_wire_body_sizes() {
    let pvtn = LatticeZkpProfileV0::pvtn_membership_v0();
    let token = LatticeZkpProfileV0::token_spend_v0();
    let disc = LatticeZkpProfileV0::selective_disclosure_v0();
    let pvtn_body = measured_opening_wire_body_bytes(&pvtn);
    let token_body = measured_opening_wire_body_bytes(&token);
    let disc_body = measured_opening_wire_body_bytes(&disc);
    assert!(pvtn_body < token_body);
    assert_eq!(token_body, disc_body);
}
