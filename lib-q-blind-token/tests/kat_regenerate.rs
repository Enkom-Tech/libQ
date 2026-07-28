//! Regenerates `tests/vectors/blind-token-v2.json` + `manifest.json` (run with `--ignored`).

mod common;

use common::{
    EPOCH,
    ISSUER_KEY_ID,
    det_rng,
    issue,
};
use lib_q_blind_token::{
    WIRE_BUDGET_BLIND_TOKEN_BYTES,
    redeem,
    verify,
};

#[test]
#[ignore = "regenerates tests/vectors/blind-token-v2.json"]
fn kat_regenerate_vectors() {
    use std::fs;
    use std::path::Path;

    let nonce = b"kat-regenerate-nonce";
    let (issuer_pub, _priv, cred) = issue(0x66);
    let mut rng = det_rng(0x67);
    let token = redeem(&mut rng, &issuer_pub, &cred, nonce).expect("redeem");
    assert!(verify(&issuer_pub, nonce, &token), "kat token must verify");

    let doc = serde_json::json!({
        "format": "blind-token-kat-v2",
        "spec_version": "v2",
        "scheme": "gpv-mp-trapdoor + zk-proof-of-possession (unlinkable)",
        "issuer_key_id": ISSUER_KEY_ID,
        "epoch": EPOCH,
        "nonce_hex": hex::encode(nonce),
        "token_bytes": token.len(),
        "token_hex": hex::encode(&token),
    });
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    fs::create_dir_all(&dir).expect("mkdir vectors");
    fs::write(
        dir.join("blind-token-v2.json"),
        serde_json::to_string_pretty(&doc).expect("json"),
    )
    .expect("write kat");

    let manifest = serde_json::json!({
        "schema": "blind-token-kat-v2",
        "regenerate": "cargo test -p lib-q-blind-token kat_regenerate_vectors -- --ignored",
        "note": "token is a re-randomized ZK proof; bytes vary per redemption (RNG-seeded here)",
        "token_bytes": token.len(),
        "budget_bytes": WIRE_BUDGET_BLIND_TOKEN_BYTES,
    });
    fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).expect("json"),
    )
    .expect("write manifest");
}
