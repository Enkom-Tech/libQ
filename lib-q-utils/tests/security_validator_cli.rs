//! Integration tests for the `security-validator` binary (raises tarpaulin line coverage on
//! `src/bin`). These spawn the real compiled binary. The tests that pass no `[source-dir]`
//! argument scan the real libQ workspace — they exercise the actual CI gate, not a synthetic
//! fixture. The failure-path tests at the bottom of this file deliberately do use a synthetic
//! `[source-dir]` fixture, because a planted violation is the only way to watch the compiled
//! binary fail without depending on the ambient state of an unrelated crate.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_security-validator"))
}

/// A throwaway single-crate directory under `std::env::temp_dir()`, removed on drop, used to
/// hand the compiled binary a deliberately violating `[source-dir]` override (see
/// `security-validator`'s `run_command`) so the failure path can be exercised end-to-end through
/// the real CLI, not just the in-process fixtures in `security_validation.rs`'s own unit tests.
struct TempCrateDir {
    path: PathBuf,
}

impl TempCrateDir {
    fn new(name: &str, cargo_toml: &str, lib_rs: &str) -> Self {
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("lib-q-utils-secval-cli-test-{pid}-{name}"));
        let src = path.join("src");
        fs::create_dir_all(&src).expect("create temp crate src dir");
        fs::write(path.join("Cargo.toml"), cargo_toml).expect("write Cargo.toml");
        fs::write(src.join("lib.rs"), lib_rs).expect("write lib.rs");
        Self { path }
    }

    /// An empty directory: no `Cargo.toml`, no `src/`, nothing — for testing the "scanned 0
    /// files" guard.
    fn empty(name: &str) -> Self {
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("lib-q-utils-secval-cli-test-{pid}-{name}"));
        fs::create_dir_all(&path).expect("create temp empty dir");
        Self { path }
    }

    fn path_string(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }
}

impl Drop for TempCrateDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
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
fn validate_all_succeeds_now_that_the_hpke_finding_is_fixed() {
    // validate-all additionally runs unsafe_code_usage, error_handling, input_validation and
    // random_generation. input_validation used to genuinely fail here: lib-q-hpke's
    // `HpkePublicKey`/`HpkePrivateKey::from_bytes` were infallible constructors over an
    // unchecked `Vec<u8>`. Those types were dead API (zero consumers outside their own unit
    // test workspace-wide; every real entry point takes `lib_q_core::KemPublicKey`, which is
    // validated at each call site) and have been deleted (card t_f3ea6b2a). This test now
    // asserts validate-all reports a clean pass so this gate cannot silently regress back to
    // an unearned "All security checks passed!" if the finding class returns.
    let out = bin().args(["validate-all"]).output().expect("spawn");
    assert!(
        out.status.success(),
        "expected validate-all to pass now that the tracked lib-q-hpke finding is fixed; stdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---- failure-path tests: the compiled binary must actually be able to fail -----------------
//
// The tests above only ever observe a clean tree. None of them prove the checks can trip at
// all — a validator that always exits 0 would pass every test above too (this is exactly the
// t_4d2dc427 defect: "8/8 stub checks" that could never fail). These tests plant a real,
// self-contained violation in a throwaway directory (independent of the ambient state of any
// other crate in this workspace) and assert the compiled binary itself reports it.

#[test]
fn validate_classical_fails_on_a_planted_denylisted_dependency() {
    let crate_dir = TempCrateDir::new(
        "classical-bad",
        "[package]\nname = \"lib-q-fake\"\n[dependencies]\nmd5 = \"0.7\"\n",
        "pub fn f() {}\n",
    );
    let out = bin()
        .args(["validate-classical", &crate_dir.path_string()])
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !out.status.success(),
        "expected a planted `md5` dependency to fail validate-classical; stdout={stdout}"
    );
    assert!(
        stdout.contains("classical_crypto_detection") && stdout.contains("md5"),
        "expected the report to name both the failing check and the offending dependency, got: \
         {stdout}"
    );
}

#[test]
fn validate_classical_passes_once_the_planted_dependency_is_removed() {
    // Same fixture machinery as the failing test above, but with a clean manifest — proves the
    // override mechanism itself isn't just hard-coded to fail.
    let crate_dir = TempCrateDir::new(
        "classical-ok",
        "[package]\nname = \"lib-q-fake-ok\"\n[dependencies]\n",
        "pub fn f() {}\n",
    );
    let out = bin()
        .args(["validate-classical", &crate_dir.path_string()])
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "expected a clean manifest to pass validate-classical; stdout={stdout}\nstderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    // A green report produced under `[source-dir]` must never be mistakable for a workspace
    // certification: the whole t_4d2dc427 defect was a tool printing "All security checks
    // passed!" without having read the thing it claimed to certify.
    assert!(
        stdout.contains("does NOT certify the libQ workspace"),
        "a green override run must announce that it did not certify the libQ workspace, got: \
         {stdout}"
    );
}

#[test]
fn validate_sha3_fails_on_a_planted_external_sha3_dependency() {
    let crate_dir = TempCrateDir::new(
        "sha3-bad",
        "[package]\nname = \"lib-q-fake\"\n[dependencies]\nsha3 = \"0.10\"\n",
        "pub fn f() {}\n",
    );
    let out = bin()
        .args(["validate-sha3", &crate_dir.path_string()])
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !out.status.success(),
        "expected a planted external `sha3` dependency to fail validate-sha3; stdout={stdout}"
    );
    assert!(
        stdout.contains("sha3_compliance"),
        "expected the failing check to be named in the report, got: {stdout}"
    );
}

#[test]
fn validate_all_fails_on_an_empty_source_override() {
    // No Cargo.toml, no .rs files at all: every check must hard-fail with its
    // "scanned 0 ... — cannot certify a workspace that was never read" guard, not silently pass.
    let empty_dir = TempCrateDir::empty("empty");
    let out = bin()
        .args(["validate-all", &empty_dir.path_string()])
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !out.status.success(),
        "expected an empty override directory to fail every check rather than pass vacuously; \
         stdout={stdout}"
    );
    assert!(
        stdout.contains("cannot certify a workspace that was never read"),
        "expected the zero-files guard diagnostic, got: {stdout}"
    );
}
