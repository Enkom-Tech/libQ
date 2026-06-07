//! Recovery policy hybrid STARK integration tests and KAT export.

#![cfg(feature = "zkp")]

use lib_q_zkp::air::RecoveryPolicyKey;
use lib_q_zkp::air::recovery_policy_hybrid::{
    RecoveryPolicyHybridInput,
    RecoveryPolicyHybridPublicInputs,
    hybrid_policy_commitment,
};
use lib_q_zkp::ip::{
    prove_recovery_policy_hybrid,
    verify_recovery_policy_hybrid_envelope,
};
use lib_q_zkp::wire::decode_recovery_zk_proof_v1;

fn kat_hybrid_input(seed: u64) -> RecoveryPolicyHybridInput {
    let zk_keys = vec![
        RecoveryPolicyKey {
            key_id: 1,
            weight: 2,
            raw_vk_bytes: vec![0xA0 | ((seed >> 8) as u8); 64],
        },
        RecoveryPolicyKey {
            key_id: 2,
            weight: 2,
            raw_vk_bytes: vec![0xB0 | (seed as u8); 64],
        },
    ];
    let commit = hybrid_policy_commitment(5, &zk_keys).unwrap();
    let public = RecoveryPolicyHybridPublicInputs {
        policy_commitment: commit,
        threshold: 5,
        zk_key_count: 2,
        time_lock_min: 0,
        time_lock_max: 86_400,
        freshness_epoch: 1_700_000_000 + seed,
        crypto_suite_id: 1,
        cleartext_key_count: 1,
        cleartext_weight_sum: 1,
    };
    RecoveryPolicyHybridInput {
        public,
        zk_keys,
        policy_time_lock: 3600,
    }
}

#[test]
fn recovery_policy_hybrid_prove_verify_roundtrip() {
    let input = kat_hybrid_input(42);
    let (_proof, envelope) = prove_recovery_policy_hybrid(&input).unwrap();
    assert!(verify_recovery_policy_hybrid_envelope(&envelope).is_ok());
}

#[test]
fn recovery_policy_hybrid_rejects_below_threshold() {
    let mut input = kat_hybrid_input(7);
    input.public.threshold = 100;
    assert!(prove_recovery_policy_hybrid(&input).is_err());
}

#[test]
#[ignore = "Regenerate KAT: cargo test -p lib-q-zkp kat_regenerate_recovery_policy_hybrid_vectors -- --ignored --release"]
fn kat_regenerate_recovery_policy_hybrid_vectors() {
    use std::fs;
    use std::path::PathBuf;

    let input = kat_hybrid_input(0xDEAD_BEEF);
    let (_proof, envelope) = prove_recovery_policy_hybrid(&input).unwrap();
    let decoded = decode_recovery_zk_proof_v1(&envelope).unwrap();

    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/recovery-policy-v1");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("minimal_hybrid_2zk_1clear.proof.hex"),
        hex::encode(&envelope),
    )
    .unwrap();

    let manifest = serde_json::json!({
        "schema": "recovery-zkp-kat-v1",
        "regenerate": "cargo test -p lib-q-zkp kat_regenerate_recovery_policy_hybrid_vectors -- --ignored --release",
        "vectors": [{
            "id": "minimal_hybrid_2zk_1clear",
            "air_id": 2,
            "expect_verify": true,
            "proof_file": "minimal_hybrid_2zk_1clear.proof.hex",
            "public_inputs_hex": hex::encode(decoded.public_inputs.encode()),
        }]
    });
    fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
}
