//! Deterministic KAT vector replay.

mod common;

use std::fs;
use std::path::Path;

use lib_q_double_kem::{
    BASELINE_DOUBLE_ML_KEM_768_CIPHERTEXT_BYTES,
    DOUBLE_KEM_KAT_SCHEMA,
    MaulEncapWire,
    MaulProfileV1,
    WIRE_BUDGET_MAUL_ENCAP_BYTES,
    double_decap,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct KatCase {
    name: String,
    wire_hex: String,
    shared_secret_hex: String,
}

#[derive(Debug, Deserialize)]
struct KatDoc {
    format: String,
    wire_bytes: usize,
    baseline_bytes: usize,
    savings_percent: f64,
    cases: Vec<KatCase>,
}

#[test]
fn kat_vectors_verify() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/double-kem-v1.json");
    let bytes = fs::read(path).expect("read KAT vectors");
    let doc: KatDoc = serde_json::from_slice(&bytes).expect("parse KAT vectors");

    assert_eq!(doc.format, DOUBLE_KEM_KAT_SCHEMA);
    assert_eq!(doc.wire_bytes, WIRE_BUDGET_MAUL_ENCAP_BYTES);
    assert_eq!(
        doc.baseline_bytes,
        BASELINE_DOUBLE_ML_KEM_768_CIPHERTEXT_BYTES
    );
    assert!(doc.savings_percent >= 40.0);

    let profile = MaulProfileV1;
    let (dk_a, _, dk_b, _) = common::kat_keys();
    for case in doc.cases {
        let wire_raw = hex::decode(case.wire_hex).expect("decode wire");
        let expected = hex::decode(case.shared_secret_hex).expect("decode shared secret");
        let wire = MaulEncapWire::from_bytes(&wire_raw).expect("wire decode");
        let ss = double_decap(profile, &wire, &dk_a, &dk_b).expect("decap");
        assert_eq!(
            ss.as_slice(),
            expected.as_slice(),
            "case {} failed",
            case.name
        );
    }
}
