//! Integration tests for the `security-validator` binary (raises tarpaulin line coverage on `src/bin`).

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_security-validator"))
}

#[test]
fn usage_without_args_exits_with_error() {
    let out = bin().output().expect("spawn security-validator");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("Usage:") || combined.contains("usage"),
        "expected usage hint, got stdout={stdout:?} stderr={stderr:?}"
    );
}

#[test]
fn unknown_command_exits_with_error() {
    let out = bin().args(["not-a-real-command"]).output().expect("spawn");
    assert!(!out.status.success());
}

#[test]
fn validate_nist_succeeds() {
    let out = bin().args(["validate-nist"]).output().expect("spawn");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn validate_timing_succeeds() {
    let out = bin().args(["validate-timing"]).output().expect("spawn");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn validate_memory_succeeds() {
    let out = bin().args(["validate-memory"]).output().expect("spawn");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn validate_classical_succeeds() {
    let out = bin().args(["validate-classical"]).output().expect("spawn");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn validate_sha3_succeeds() {
    let out = bin().args(["validate-sha3"]).output().expect("spawn");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn validate_all_succeeds() {
    let out = bin().args(["validate-all"]).output().expect("spawn");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}
