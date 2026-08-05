//! Integration tests for the `security-validator` binary (raises tarpaulin line coverage on
//! `src/bin`). These spawn the real compiled binary, which scans the real libQ workspace — they
//! are exercising the actual CI gate, not a synthetic fixture.

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

// These five subcommands each now run only their named, real check(s) (previously every
// subcommand ran all eight identical stubs). They pass today against the real workspace:
// sha2/aes are NIST-mandated allowlisted deps, no external sha3/tiny-keccak dependency exists,
// every AEAD/MAC crate uses a constant-time comparison, and every key-material crate uses
// `zeroize`.

#[test]
fn validate_nist_succeeds() {
    let out = bin().args(["validate-nist"]).output().expect("spawn");
    assert!(
        out.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn validate_timing_succeeds() {
    let out = bin().args(["validate-timing"]).output().expect("spawn");
    assert!(
        out.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn validate_memory_succeeds() {
    let out = bin().args(["validate-memory"]).output().expect("spawn");
    assert!(
        out.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn validate_classical_succeeds() {
    let out = bin().args(["validate-classical"]).output().expect("spawn");
    assert!(
        out.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn validate_sha3_succeeds() {
    let out = bin().args(["validate-sha3"]).output().expect("spawn");
    assert!(
        out.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn validate_all_fails_on_a_real_cross_crate_finding() {
    // validate-all additionally runs unsafe_code_usage, error_handling, input_validation and
    // random_generation. input_validation currently, genuinely fails: lib-q-hpke's
    // `HpkePublicKey`/`HpkePrivateKey::from_bytes` (lib-q-hpke/src/types.rs:275,298) are
    // infallible constructors over an unchecked `Vec<u8>`. That is a real, out-of-scope
    // finding for this lane (see out-of-scope.md), not a defect in this checker — this test
    // intentionally asserts non-zero so this gate can never again silently paper over that
    // kind of finding with an unearned "All security checks passed!". No CI workflow currently
    // invokes `validate-all` (see pr.yml/security.yml), so this does not turn any existing CI
    // job red.
    let out = bin().args(["validate-all"]).output().expect("spawn");
    assert!(
        !out.status.success(),
        "expected validate-all to report the real, tracked lib-q-hpke finding; stdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("input_validation"),
        "expected the failing check to be named in the report, got: {stdout}"
    );
}
