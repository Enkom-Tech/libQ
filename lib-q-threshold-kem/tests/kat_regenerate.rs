mod common;

use lib_q_threshold_kem::encap;

#[test]
#[ignore = "regenerates tests/vectors/threshold-kem-v1.json"]
fn kat_regenerate_vectors() {
    use std::fs;
    use std::path::Path;

    let (profile, keygen) = common::deterministic_keygen(0x55);
    let mut rng = common::deterministic_rng(0x56);
    let enc = encap(&profile, &keygen.public_key, &mut rng).expect("encap");

    let doc = serde_json::json!({
        "format": "threshold-kem-kat-v1",
        "spec_version": "v1",
        "parameter_set_digest": hex::encode(profile.parameter_set_digest),
        "ciphertext_hex": hex::encode(&enc.ciphertext),
        "ciphertext_bytes": enc.ciphertext.len(),
        "threshold": common::THRESHOLD,
        "parties": common::PARTIES,
        "shared_secret_hex": hex::encode(enc.shared_secret),
    });
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    fs::create_dir_all(&dir).expect("mkdir vectors");
    fs::write(
        dir.join("threshold-kem-v1.json"),
        serde_json::to_string_pretty(&doc).expect("json"),
    )
    .expect("write kat");

    let manifest = serde_json::json!({
        "schema": "threshold-kem-kat-v1",
        "regenerate": "cargo test -p lib-q-threshold-kem kat_regenerate_vectors -- --ignored",
        "ciphertext_bytes": enc.ciphertext.len(),
        "budget_bytes": lib_q_threshold_kem::WIRE_BUDGET_TKEM_CIPHERTEXT_BYTES,
        "parameter_set_digest": hex::encode(profile.parameter_set_digest),
    });
    fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).expect("json"),
    )
    .expect("write manifest");
}
