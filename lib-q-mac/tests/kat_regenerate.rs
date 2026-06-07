//! Exportable KAT regeneration for qcw-mac-kat-v1.

mod common;

use std::fs;
use std::path::Path;

use common::{
    kat_key,
    kat_positive_cases,
};
use lib_q_mac::{
    QCW_MAC_KAT_SCHEMA,
    QcwMac,
};
use serde_json::json;

#[test]
#[ignore = "regenerates tests/vectors/qcw-mac-v1.json"]
fn kat_regenerate_vectors() {
    let positive: Vec<_> = kat_positive_cases()
        .into_iter()
        .map(|(name, msg, ad, tag)| {
            json!({
                "name": name,
                "msg_hex": hex::encode(msg),
                "ad_hex": hex::encode(ad),
                "tag_hex": hex::encode(tag),
            })
        })
        .collect();

    let cases = kat_positive_cases();
    let (_, msg, ad, tag) = &cases[0];
    let mut tampered = tag.clone();
    tampered[0] ^= 0x01;
    let negative = [json!({
        "name": "tamper_reject",
        "msg_hex": hex::encode(msg),
        "ad_hex": hex::encode(ad),
        "tag_hex": hex::encode(tampered),
        "expected": { "verified": false },
    })];

    let doc = json!({
        "format": QCW_MAC_KAT_SCHEMA,
        "spec_version": "v1",
        "positive_cases": positive,
        "negative_cases": negative,
    });

    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    fs::create_dir_all(&dir).expect("create vectors dir");
    fs::write(
        dir.join("qcw-mac-v1.json"),
        serde_json::to_string_pretty(&doc).expect("serialize"),
    )
    .expect("write qcw-mac-v1.json");

    let manifest = json!({
        "schema": QCW_MAC_KAT_SCHEMA,
        "regenerate": "cargo test -p lib-q-mac kat_regenerate_vectors -- --ignored",
        "key_hex": hex::encode(kat_key().as_bytes()),
    });
    fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).expect("serialize manifest"),
    )
    .expect("write manifest");

    for case in &negative {
        let msg = hex::decode(case["msg_hex"].as_str().unwrap()).unwrap();
        let ad = hex::decode(case["ad_hex"].as_str().unwrap()).unwrap();
        let tag = hex::decode(case["tag_hex"].as_str().unwrap()).unwrap();
        assert!(!QcwMac::verify(&kat_key(), &msg, &ad, &tag));
    }
}
