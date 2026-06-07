//! Exportable KAT regeneration for double-kem-kat-v1.

mod common;

use std::fs;
use std::path::Path;

use lib_q_double_kem::{
    BASELINE_DOUBLE_ML_KEM_768_CIPHERTEXT_BYTES,
    DOUBLE_KEM_KAT_SCHEMA,
    MaulProfileV1,
    WIRE_BUDGET_MAUL_ENCAP_BYTES,
    double_encap,
};
use serde_json::json;

#[test]
#[ignore = "regenerates tests/vectors/double-kem-v1.json"]
fn kat_regenerate_vectors() {
    let profile = MaulProfileV1;
    let (_, ek_a, _, ek_b) = common::kat_keys();
    let mut rng = common::kat_rng();

    let vectors: Vec<_> = (0..4)
        .map(|idx| {
            let (wire, ss) = double_encap(profile, &ek_a, &ek_b, &mut rng).expect("encap");
            json!({
                "name": format!("case-{idx}"),
                "wire_hex": hex::encode(wire.to_bytes()),
                "shared_secret_hex": hex::encode(ss),
            })
        })
        .collect();

    let saved = BASELINE_DOUBLE_ML_KEM_768_CIPHERTEXT_BYTES - WIRE_BUDGET_MAUL_ENCAP_BYTES;
    let savings_percent =
        (saved as f64) * 100.0 / (BASELINE_DOUBLE_ML_KEM_768_CIPHERTEXT_BYTES as f64);
    assert!(savings_percent >= 40.0);

    let doc = json!({
        "format": DOUBLE_KEM_KAT_SCHEMA,
        "spec_version": "v1",
        "profile": "maul-v1",
        "wire_bytes": WIRE_BUDGET_MAUL_ENCAP_BYTES,
        "baseline_bytes": BASELINE_DOUBLE_ML_KEM_768_CIPHERTEXT_BYTES,
        "savings_percent": savings_percent,
        "cases": vectors,
    });

    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    fs::create_dir_all(&dir).expect("create vectors dir");
    fs::write(
        dir.join("double-kem-v1.json"),
        serde_json::to_string_pretty(&doc).expect("serialize vectors"),
    )
    .expect("write vectors");

    let manifest = json!({
        "schema": DOUBLE_KEM_KAT_SCHEMA,
        "regenerate": "cargo test -p lib-q-double-kem kat_regenerate_vectors -- --ignored",
        "wire_bytes": WIRE_BUDGET_MAUL_ENCAP_BYTES,
        "baseline_bytes": BASELINE_DOUBLE_ML_KEM_768_CIPHERTEXT_BYTES,
        "min_savings_percent": 40.0
    });

    fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).expect("serialize manifest"),
    )
    .expect("write manifest");
}
