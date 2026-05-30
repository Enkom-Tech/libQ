//! Exportable KAT vectors for cross-crate interoperability tests.

use lib_q_lattice_zkp::{
    AjtaiCommitmentKey,
    AjtaiOpening,
    LatticeZkpProfileV0,
    MerklePath,
    SpendingProof,
    TOKEN_EPOCH_LEN,
    TOKEN_ORIGIN_LEN,
    TOKEN_SERIAL_LEN,
    commit,
    decode_opening_proof_v0,
    decode_private_membership_proof_v0,
    decode_spending_proof_v0,
    encode_opening_proof_v0,
    encode_private_membership_proof_v0,
    encode_pvtn_leaf,
    encode_spending_proof_v0,
    leaf_hash,
    node_hash,
    opening_from_token_fields,
    prove_opening,
    prove_private_membership,
    verify_opening,
    verify_private_membership,
};
use lib_q_random::{
    LibQRng,
    new_deterministic_rng,
};
use lib_q_ring::{
    ModuleVec,
    Poly,
};

const KAT_SEED: [u8; 32] = [
    0x6C, 0x61, 0x74, 0x74, 0x69, 0x63, 0x65, 0x2D, 0x7A, 0x6B, 0x70, 0x2D, 0x76, 0x30, 0x2D, 0x6B,
    0x61, 0x74, 0x2D, 0x73, 0x65, 0x65, 0x64, 0x2D, 0x30, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

fn kat_rng() -> LibQRng {
    new_deterministic_rng(KAT_SEED)
}

fn build_opening_wire() -> Vec<u8> {
    let profile = LatticeZkpProfileV0::token_spend_v0();
    let key = AjtaiCommitmentKey {
        seed: KAT_SEED,
        params: profile.ajtai.clone(),
    };
    let serial = [0x11u8; TOKEN_SERIAL_LEN];
    let origin = [0x22u8; TOKEN_ORIGIN_LEN];
    let epoch = [0x33u8; TOKEN_EPOCH_LEN];
    let opening =
        opening_from_token_fields(2, 1, &serial, &origin, &epoch).expect("token opening layout");
    let com = commit(&key, &opening);
    let proof = prove_opening(
        &mut kat_rng(),
        &key,
        &opening,
        &com,
        b"lattice-zkp/kat/token-spend",
        profile.tau,
        profile.z_inf_bound,
        profile.max_prove_attempts,
    )
    .expect("prove opening kat");
    verify_opening(
        &key,
        &com,
        &proof,
        b"lattice-zkp/kat/token-spend",
        profile.tau,
        profile.z_inf_bound,
    )
    .expect("verify opening kat");
    encode_opening_proof_v0(&profile, &proof).expect("encode opening kat")
}

fn build_pvtn_wire() -> (Vec<u8>, AjtaiCommitmentKey, [u8; 32]) {
    let profile = LatticeZkpProfileV0::pvtn_membership_v0();
    let key = AjtaiCommitmentKey {
        seed: KAT_SEED,
        params: profile.ajtai.clone(),
    };
    let opening = AjtaiOpening {
        message: ModuleVec(vec![Poly::zero()]),
        randomness: ModuleVec(vec![Poly::zero()]),
    };
    let com = commit(&key, &opening);
    let role = [0x5Au8; 16];
    let parent = [0u8; 32];
    let leaf_payload = encode_pvtn_leaf(8, &role, &parent);
    let l0 = leaf_hash(b"kat-leaf-0");
    let l1 = leaf_hash(&leaf_payload);
    let root = node_hash(&l0, &l1);
    let path = MerklePath {
        path_index: 1,
        siblings: vec![l0],
    };
    let proof = prove_private_membership(
        &mut kat_rng(),
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
    .expect("prove pvtn kat");
    verify_private_membership(
        &key,
        &proof,
        &root,
        3,
        b"lattice-zkp/kat/baseline-pvtn",
        profile.tau,
        profile.z_inf_bound,
    )
    .expect("verify pvtn kat");
    let wire =
        encode_private_membership_proof_v0(&profile, &proof, &root, 3).expect("encode pvtn kat");
    (wire, key, root)
}

fn build_spending_wire() -> Vec<u8> {
    let profile = LatticeZkpProfileV0::token_spend_v0();
    let key = AjtaiCommitmentKey {
        seed: KAT_SEED,
        params: profile.ajtai.clone(),
    };
    let serial = [0x44u8; TOKEN_SERIAL_LEN];
    let origin = [0x55u8; TOKEN_ORIGIN_LEN];
    let epoch = [0x66u8; TOKEN_EPOCH_LEN];
    let opening =
        opening_from_token_fields(2, 1, &serial, &origin, &epoch).expect("token opening layout");
    let com = commit(&key, &opening);
    let proof = prove_opening(
        &mut kat_rng(),
        &key,
        &opening,
        &com,
        b"lattice-zkp/kat/token-spend",
        profile.tau,
        profile.z_inf_bound,
        profile.max_prove_attempts,
    )
    .expect("prove spend kat");
    let spend = SpendingProof {
        serial,
        opening_proof: proof,
    };
    encode_spending_proof_v0(&profile, &spend).expect("encode spending kat")
}

#[test]
fn kat_opening_token_spend_v0_roundtrip() {
    let wire = build_opening_wire();
    let (proof, profile) = decode_opening_proof_v0(&wire).expect("decode opening kat");
    assert_eq!(
        profile.profile_id,
        LatticeZkpProfileV0::token_spend_v0().profile_id
    );
    assert_eq!(proof.w.0.len(), profile.mask_poly_count());
    assert_eq!(proof.z.0.len(), profile.witness_poly_count());
}

#[test]
fn kat_pvtn_membership_v0_roundtrip() {
    let (wire, key, root) = build_pvtn_wire();
    let com = commit(
        &key,
        &AjtaiOpening {
            message: ModuleVec(vec![Poly::zero()]),
            randomness: ModuleVec(vec![Poly::zero()]),
        },
    );
    let proof = decode_private_membership_proof_v0(&wire, 3, &root, com).expect("decode pvtn kat");
    verify_private_membership(
        &key,
        &proof,
        &root,
        3,
        b"lattice-zkp/kat/baseline-pvtn",
        LatticeZkpProfileV0::pvtn_membership_v0().tau,
        LatticeZkpProfileV0::pvtn_membership_v0().z_inf_bound,
    )
    .expect("verify decoded pvtn kat");
}

#[test]
fn kat_spending_v0_roundtrip() {
    let wire = build_spending_wire();
    let (spend, profile) = decode_spending_proof_v0(&wire).expect("decode spending kat");
    assert_eq!(
        profile.profile_id,
        LatticeZkpProfileV0::token_spend_v0().profile_id
    );
    assert_eq!(spend.serial, [0x44u8; TOKEN_SERIAL_LEN]);
}

#[test]
#[ignore = "run to print/write hex fixtures for tests/vectors/"]
fn kat_regenerate_vectors() {
    use std::fs;
    use std::path::PathBuf;

    let opening = build_opening_wire();
    let (pvtn, _, _) = build_pvtn_wire();
    let spending = build_spending_wire();

    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    fs::write(
        dir.join("opening_token_spend_v0.hex"),
        hex::encode(&opening),
    )
    .expect("write opening");
    fs::write(dir.join("pvtn_membership_v0.hex"), hex::encode(&pvtn)).expect("write pvtn");
    fs::write(dir.join("token_spend_v0.hex"), hex::encode(&spending)).expect("write spending");

    println!("opening_bytes={}", opening.len());
    println!("pvtn_bytes={}", pvtn.len());
    println!("spending_bytes={}", spending.len());
}

fn load_hex_fixture(name: &str) -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(name);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    hex::decode(text.trim()).expect("hex decode fixture")
}

#[test]
fn kat_manifest_hex_fixtures_verify() {
    let opening = load_hex_fixture("opening_token_spend_v0.hex");
    let pvtn = load_hex_fixture("pvtn_membership_v0.hex");
    let spending = load_hex_fixture("token_spend_v0.hex");

    assert!(opening.len() <= lib_q_lattice_zkp::WIRE_BUDGET_PRESENTATION_BYTES);
    assert!(pvtn.len() <= lib_q_lattice_zkp::WIRE_BUDGET_PVTN_MEMBERSHIP_BYTES);
    assert!(spending.len() <= lib_q_lattice_zkp::WIRE_BUDGET_PRESENTATION_BYTES);

    decode_opening_proof_v0(&opening).expect("fixture opening");
    let (pvtn_proof, key, root) = {
        let profile = LatticeZkpProfileV0::pvtn_membership_v0();
        let key = AjtaiCommitmentKey {
            seed: KAT_SEED,
            params: profile.ajtai.clone(),
        };
        let com = commit(
            &key,
            &AjtaiOpening {
                message: ModuleVec(vec![Poly::zero()]),
                randomness: ModuleVec(vec![Poly::zero()]),
            },
        );
        let role = [0x5Au8; 16];
        let parent = [0u8; 32];
        let leaf_payload = encode_pvtn_leaf(8, &role, &parent);
        let l0 = leaf_hash(b"kat-leaf-0");
        let l1 = leaf_hash(&leaf_payload);
        let root = node_hash(&l0, &l1);
        let proof = decode_private_membership_proof_v0(&pvtn, 3, &root, com).expect("fixture pvtn");
        verify_private_membership(
            &key,
            &proof,
            &root,
            3,
            b"lattice-zkp/kat/baseline-pvtn",
            profile.tau,
            profile.z_inf_bound,
        )
        .expect("verify fixture pvtn");
        (proof, key, root)
    };
    let _ = (pvtn_proof, key, root);
    decode_spending_proof_v0(&spending).expect("fixture spending");
}
