#![cfg(feature = "fhe")]

use lib_q_fhe::{
    EvalOp,
    decrypt,
    encrypt,
    eval,
    fhe_keygen,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct DemoManifest {
    name: String,
    profile: String,
    note: String,
}

#[test]
fn toy_demo_encrypt_eval_decrypt_roundtrip() {
    let sk = fhe_keygen(7, 4, 257);
    let plaintext = [3, 9, 11, 0];
    let ct = encrypt(&sk, &plaintext, 19);

    let evaluated = eval(&ct, EvalOp::AddConstant(5));
    let recovered = decrypt(&sk, &evaluated);

    assert_eq!(recovered, vec![8, 14, 16, 5]);
}

#[test]
fn demo_vector_manifest_is_present() {
    let content = include_str!("vectors/manifest.json");
    let manifest: DemoManifest = serde_json::from_str(content).expect("manifest json");
    assert_eq!(manifest.profile, "demo-only");
    assert_eq!(manifest.name, "lib-q-fhe toy vectors");
    assert!(!manifest.note.is_empty());
}
