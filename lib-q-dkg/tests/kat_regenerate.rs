//! Regenerates `tests/vectors/dkg-v1.json` + `manifest.json` (run with `--ignored`).

mod common;

use common::{
    PARTIES,
    THRESHOLD,
    det_rng,
};
use lib_q_dkg::{
    WIRE_BUDGET_DKG_ROUND1_BYTES,
    dkg_round1_commit,
    dkg_run_honest,
    encode_round1_commitments,
    setup,
    signing_share_commitment,
};

#[test]
#[ignore = "regenerates tests/vectors/dkg-v1.json"]
fn kat_regenerate_vectors() {
    use std::fs;
    use std::path::Path;

    let profile = setup();

    // Deterministic round-1 broadcast size for the proof-size table.
    let mut rng = det_rng(0x66);
    let (_poly, comms) =
        dkg_round1_commit(&profile, PARTIES, THRESHOLD, 1, &mut rng).expect("round1");
    let round1_wire = encode_round1_commitments(&comms).expect("encode");

    // Deterministic honest keygen output.
    let mut rng = det_rng(0x66);
    let kg = dkg_run_honest(&profile, PARTIES, THRESHOLD, &mut rng).expect("dkg");
    let verifiers: Vec<_> = kg
        .public_key
        .share_verifiers
        .iter()
        .map(|v| {
            serde_json::json!({
                "index": v.index,
                "verifying_key_hex": hex::encode(&v.verifying_key),
            })
        })
        .collect();
    let share_commitments: Vec<_> = kg
        .secret_shares
        .iter()
        .map(|s| hex::encode(signing_share_commitment(s).expect("commit")))
        .collect();

    let doc = serde_json::json!({
        "format": "dkg-kat-v1",
        "spec_version": "v1",
        "threshold": THRESHOLD,
        "parties": PARTIES,
        "round1_wire_bytes": round1_wire.len(),
        "group_key_hex": hex::encode(&kg.public_key.group_key),
        "share_verifiers": verifiers,
        "share_commitments_hex": share_commitments,
    });

    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    fs::create_dir_all(&dir).expect("mkdir vectors");
    fs::write(
        dir.join("dkg-v1.json"),
        serde_json::to_string_pretty(&doc).expect("json"),
    )
    .expect("write kat");

    let manifest = serde_json::json!({
        "schema": "dkg-kat-v1",
        "regenerate": "cargo test -p lib-q-dkg kat_regenerate_vectors -- --ignored",
        "round1_wire_bytes": round1_wire.len(),
        "round1_budget_bytes": WIRE_BUDGET_DKG_ROUND1_BYTES,
    });
    fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).expect("json"),
    )
    .expect("write manifest");
}
