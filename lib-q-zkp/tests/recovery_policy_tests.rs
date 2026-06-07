//! Recovery policy STARK integration tests and KAT export.

#![cfg(feature = "zkp")]

use lib_q_zkp::air::{
    RecoveryPolicyInput,
    RecoveryPolicyKey,
    RecoveryPolicyPublicInputs,
    policy_commitment,
};
use lib_q_zkp::ip::{
    prove_recovery_policy,
    verify_recovery_policy_envelope,
};
use lib_q_zkp::wire::decode_recovery_zk_proof_v0;

fn kat_input(seed: u64) -> RecoveryPolicyInput {
    let keys = vec![
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
    let commit = policy_commitment(3, &keys).unwrap();
    let public = RecoveryPolicyPublicInputs {
        policy_commitment: commit,
        threshold: 3,
        key_count: 2,
        time_lock_min: 0,
        time_lock_max: 86_400,
        freshness_epoch: 1_700_000_000 + seed,
        crypto_suite_id: 1,
    };
    RecoveryPolicyInput {
        public,
        keys,
        policy_time_lock: 3600,
    }
}

#[test]
fn recovery_policy_prove_verify_roundtrip() {
    let input = kat_input(42);
    let (_proof, envelope) = prove_recovery_policy(&input).unwrap();
    assert!(verify_recovery_policy_envelope(&envelope).is_ok());
}

#[test]
fn recovery_policy_rejects_corrupted_envelope() {
    let input = kat_input(7);
    let (_proof, mut envelope) = prove_recovery_policy(&input).unwrap();
    if let Some(b) = envelope.last_mut() {
        *b ^= 0xFF;
    }
    assert!(verify_recovery_policy_envelope(&envelope).is_err());
}

#[test]
fn recovery_policy_rejects_oversize_envelope() {
    let huge = vec![0u8; lib_q_zkp::wire::RECOVERY_ZK_MAX_ENVELOPE + 1];
    assert!(decode_recovery_zk_proof_v0(&huge).is_err());
}

#[test]
fn recovery_policy_prove_fails_below_threshold() {
    let mut input = kat_input(99);
    input.public.threshold = 100;
    assert!(prove_recovery_policy(&input).is_err());
}

#[test]
fn recovery_policy_prove_fails_duplicate_key_ids() {
    let mut input = kat_input(11);
    input.keys[1].key_id = input.keys[0].key_id;
    assert!(prove_recovery_policy(&input).is_err());
}

#[test]
fn recovery_policy_rejects_wrong_air_id_in_envelope() {
    let input = kat_input(3);
    let (_proof, mut envelope) = prove_recovery_policy(&input).unwrap();
    // wire_version(0) + air_id byte at offset 1
    envelope[1] = 0xFF;
    assert!(verify_recovery_policy_envelope(&envelope).is_err());
}

#[test]
fn recovery_policy_rejects_excessive_key_count() {
    use lib_q_zkp::air::{
        RecoveryPolicyAir,
        RecoveryPolicyPublicInputs,
        policy_commitment,
    };

    let keys: Vec<_> = (0..33)
        .map(|i| RecoveryPolicyKey {
            key_id: (i + 1) as u32,
            weight: 1,
            raw_vk_bytes: vec![0xC0 | (i as u8); 64],
        })
        .collect();
    let commit = policy_commitment(33, &keys).unwrap();
    let public = RecoveryPolicyPublicInputs {
        policy_commitment: commit,
        threshold: 33,
        key_count: 33,
        time_lock_min: 0,
        time_lock_max: 86_400,
        freshness_epoch: 1_700_000_000,
        crypto_suite_id: 1,
    };
    assert!(RecoveryPolicyAir::new(public).is_err());
}

#[test]
#[ignore = "Regenerate KAT hex fixtures: cargo test -p lib-q-zkp kat_regenerate_recovery_policy_vectors -- --ignored --release"]
fn kat_regenerate_recovery_policy_vectors() {
    use std::fs;
    use std::path::PathBuf;

    let input = kat_input(0xDEAD_BEEF);
    let (_proof, envelope) = prove_recovery_policy(&input).unwrap();
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("recovery-policy-v0");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("minimal_2_keys.proof.hex"), hex::encode(&envelope)).unwrap();
    let manifest = serde_json::json!({
        "schema": "recovery-zkp-kat-v0",
        "description": "Fixed-seed recovery policy STARK vectors",
        "regenerate": "cargo test -p lib-q-zkp kat_regenerate_recovery_policy_vectors -- --ignored --release",
        "vectors": [{
            "id": "minimal_2_keys",
            "air_id": 1,
            "expect_verify": true,
            "proof_file": "minimal_2_keys.proof.hex",
            "public_inputs_hex": hex::encode(input.public.encode()),
        }]
    });
    fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
}

#[test]
#[ignore = "Measure proof sizes: cargo test -p lib-q-zkp recovery_policy_budget_sizes -- --ignored --release"]
fn recovery_policy_budget_sizes() {
    use lib_q_zkp::air::{
        RecoveryPolicyPublicInputs,
        policy_commitment,
    };

    fn prove_size(key_count: usize, threshold: u32) -> usize {
        let mut keys = Vec::with_capacity(key_count);
        for i in 0..key_count {
            keys.push(RecoveryPolicyKey {
                key_id: (i + 1) as u32,
                weight: 2,
                raw_vk_bytes: vec![0xA0 | (i as u8); 64],
            });
        }
        let commit = policy_commitment(threshold, &keys).unwrap();
        let public = RecoveryPolicyPublicInputs {
            policy_commitment: commit,
            threshold,
            key_count: key_count as u32,
            time_lock_min: 0,
            time_lock_max: 86_400,
            freshness_epoch: 1_700_000_000,
            crypto_suite_id: 1,
        };
        let input = RecoveryPolicyInput {
            public,
            keys,
            policy_time_lock: 3600,
        };
        let (_p, envelope) = prove_recovery_policy(&input).unwrap();
        envelope.len()
    }

    let s2 = prove_size(2, 3);
    let s5 = prove_size(5, 3);
    let s32 = prove_size(32, 16);
    eprintln!("budget 2-key envelope: {s2} bytes");
    eprintln!("budget 5-key envelope: {s5} bytes");
    eprintln!("budget 32-key envelope: {s32} bytes");
    assert!(s2 <= 512 * 1024);
    assert!(s5 <= 512 * 1024);
    assert!(s32 <= 512 * 1024);
}
