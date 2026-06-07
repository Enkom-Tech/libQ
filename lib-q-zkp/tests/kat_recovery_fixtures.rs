//! Manifest + hex fixture verification (no-drift gate for recovery KATs).

#![cfg(feature = "zkp")]

use std::path::{
    Path,
    PathBuf,
};

use lib_q_zkp::air::RECOVERY_POLICY_AIR_ID;
use lib_q_zkp::air::recovery_policy_hybrid::RECOVERY_POLICY_HYBRID_AIR_ID;
use lib_q_zkp::ip::{
    verify_recovery_policy_envelope,
    verify_recovery_policy_hybrid_envelope,
};
use lib_q_zkp::wire::{
    decode_recovery_zk_proof_v0,
    decode_recovery_zk_proof_v1,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct KatManifest {
    vectors: Vec<KatVector>,
}

#[derive(Debug, Deserialize)]
struct KatVector {
    id: String,
    air_id: u8,
    expect_verify: bool,
    proof_file: String,
    public_inputs_hex: String,
}

fn kat_dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(name)
}

fn load_manifest(dir: &Path) -> KatManifest {
    let raw = std::fs::read_to_string(dir.join("manifest.json"))
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.join("manifest.json").display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("parse manifest in {}: {e}", dir.display()))
}

fn verify_v0_dir(dir: &Path) {
    let manifest = load_manifest(dir);
    for v in &manifest.vectors {
        assert_eq!(v.air_id, RECOVERY_POLICY_AIR_ID, "{} air_id", v.id);
        let hex_path = dir.join(&v.proof_file);
        let hex = std::fs::read_to_string(&hex_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", hex_path.display()));
        let envelope = hex::decode(hex.trim()).unwrap_or_else(|e| panic!("{} hex: {e}", v.id));
        let decoded = decode_recovery_zk_proof_v0(&envelope)
            .unwrap_or_else(|_| panic!("{} decode failed", v.id));
        let got_public = hex::encode(decoded.public_inputs.encode());
        assert_eq!(
            got_public.to_lowercase(),
            v.public_inputs_hex.to_lowercase(),
            "{} public_inputs mismatch",
            v.id
        );
        let verify_ok = verify_recovery_policy_envelope(&envelope).is_ok();
        assert_eq!(
            verify_ok, v.expect_verify,
            "{} expect_verify={} verify={verify_ok}",
            v.id, v.expect_verify
        );
    }
}

fn verify_v1_dir(dir: &Path) {
    let manifest = load_manifest(dir);
    for v in &manifest.vectors {
        assert_eq!(v.air_id, RECOVERY_POLICY_HYBRID_AIR_ID, "{} air_id", v.id);
        let hex_path = dir.join(&v.proof_file);
        let hex = std::fs::read_to_string(&hex_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", hex_path.display()));
        let envelope = hex::decode(hex.trim()).unwrap_or_else(|e| panic!("{} hex: {e}", v.id));
        let decoded = decode_recovery_zk_proof_v1(&envelope)
            .unwrap_or_else(|_| panic!("{} decode failed", v.id));
        let got_public = hex::encode(decoded.public_inputs.encode());
        assert_eq!(
            got_public.to_lowercase(),
            v.public_inputs_hex.to_lowercase(),
            "{} public_inputs mismatch",
            v.id
        );
        let verify_ok = verify_recovery_policy_hybrid_envelope(&envelope).is_ok();
        assert_eq!(
            verify_ok, v.expect_verify,
            "{} expect_verify={} verify={verify_ok}",
            v.id, v.expect_verify
        );
    }
}

#[test]
fn kat_recovery_policy_v0_manifest_fixtures_verify() {
    verify_v0_dir(&kat_dir("recovery-policy-v0"));
}

#[test]
fn kat_recovery_policy_v1_manifest_fixtures_verify() {
    verify_v1_dir(&kat_dir("recovery-policy-v1"));
}
