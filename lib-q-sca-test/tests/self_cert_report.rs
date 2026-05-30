//! Self-certification battery runner.
//!
//! Fast smoke (`self_cert_smoke`) validates the battery and evidence-package plumbing
//! on every `cargo test` run. The ignored `self_cert_full_report` runs the
//! default-sized battery and writes a dated evidence package under
//! `target/sca-self-cert/<unix-ts>/` for archival:
//!
//! ```bash
//! cargo test -p lib-q-sca-test --features lattice-zkp-hardened \
//!     --test self_cert_report self_cert_full_report -- --ignored --nocapture
//! ```

use std::path::PathBuf;

use lib_q_sca_test::self_cert::{
    BatteryConfig,
    run_timing_battery,
    write_evidence_package,
};

#[test]
fn self_cert_smoke() {
    let report = run_timing_battery(BatteryConfig::smoke());
    let json = report.to_json();
    assert!(json.contains("\"schema\":\"libq.sca.self-cert.v1\""));
    // Default features bring in at least the ML-KEM and ML-DSA targets.
    #[cfg(any(
        feature = "mlkem",
        feature = "mldsa",
        feature = "lattice-zkp-hardened",
        feature = "hqc-hardened"
    ))]
    assert!(!report.reports.is_empty());
}

#[test]
#[ignore = "slow: default battery runs 10k timings per class per hardened target"]
fn self_cert_full_report() {
    let report = run_timing_battery(BatteryConfig::default());

    let timestamp = report.environment.timestamp_unix;
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.push("..");
    dir.push("target");
    dir.push("sca-self-cert");
    dir.push(timestamp.to_string());

    let (json_path, md_path) =
        write_evidence_package(&dir, &report).expect("write self-cert evidence package");

    eprintln!("self-cert JSON:     {}", json_path.display());
    eprintln!("self-cert Markdown: {}", md_path.display());
    eprintln!("{}", report.to_markdown());

    // Wall-clock timing under test harness scheduling is noisy; this runner records
    // evidence and must not fail the build on a single noisy verdict. Gating on the
    // verdict belongs to instrumented runs per docs/sca-self-certification.md.
    assert!(!report.reports.is_empty(), "battery produced no reports");
}
