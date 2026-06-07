mod common;

use lib_q_threshold_sig::aggregate;

#[test]
#[ignore = "regenerates tests/vectors/threshold-sig-pop-v1.json"]
fn kat_regenerate_vectors() {
    use std::fs;
    use std::path::Path;

    let (profile, keygen) = common::deterministic_keygen(0x66);
    let message = b"kat-regenerate-message";
    let signers = common::select_signers(&keygen.secret_shares);
    let mut rng = common::deterministic_rng(0x67);
    let states = common::build_round_states(&profile, &signers, message, &mut rng);
    let commitments = states
        .iter()
        .map(|s| s.commitment.clone())
        .collect::<Vec<_>>();
    let partials = common::build_partials(
        &profile,
        &keygen.public_key,
        &signers,
        &states,
        &commitments,
        message,
    );
    let aggregate_out = aggregate(
        &profile,
        &keygen.public_key,
        message,
        &commitments,
        &partials,
    )
    .expect("aggregate");

    let doc = serde_json::json!({
        "format": "threshold-sig-kat-v1",
        "spec_version": "v1",
        "wire_hex": hex::encode(&aggregate_out.wire),
        "wire_bytes": aggregate_out.wire.len(),
        "message_hex": hex::encode(message),
        "threshold": common::THRESHOLD,
        "parties": common::PARTIES,
    });
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    fs::create_dir_all(&dir).expect("mkdir vectors");
    fs::write(
        dir.join("threshold-sig-pop-v1.json"),
        serde_json::to_string_pretty(&doc).expect("json"),
    )
    .expect("write kat");

    let manifest = serde_json::json!({
        "schema": "threshold-sig-kat-v1",
        "regenerate": "cargo test -p lib-q-threshold-sig kat_regenerate_vectors -- --ignored",
        "wire_bytes": aggregate_out.wire.len(),
        "budget_bytes": lib_q_threshold_sig::PROFILE_ENVELOPE_BUDGET_BYTES,
    });
    fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).expect("json"),
    )
    .expect("write manifest");
}
