//! Synthetic acceptance tests: engineered clean / leaky / broken C fixtures must receive the
//! expected verdicts, and the failure-handling rules of the spec must hold.
//!
//! Environment in which these were written: gcc and objdump present; valgrind and clang absent.
//! Tests that need a real valgrind skip themselves when it is missing. Tests that use the shell
//! "fake valgrind" below exercise the output parsing and aggregation only - they are NOT a
//! memcheck run and say so in their names.

use std::path::{Path, PathBuf};

use ct_kat::config::Config;
use ct_kat::verdict::{Status, Verdict};
use ct_kat::{Options, Report, rundir, screen};

fn have(tool: &str) -> bool {
    std::process::Command::new(tool)
        .arg("--version")
        .output()
        .is_ok()
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn yaml(extra_layers: &str, target: &str, file: &str, func: &str, triage: &str) -> String {
    format!(
        r#"
compilers: [gcc]
opt_levels: ["-O0", "-O2", "-Os"]
timeout_secs: 60
layers: {{ {extra_layers} }}
dudect: {{ measurements: 20000, t_threshold: 10.0 }}
targets:
  - name: {target}
    sources: ["{}"]
    function: {func}
    args:
      - {{ kind: secret, len: 16 }}
      - {{ kind: public, len: 16 }}
      - {{ kind: out, len: 16 }}
{triage}
"#,
        fixtures().join(file).display()
    )
}

const FAKE_CLEAN: &str =
    "#!/bin/sh\n# FAKE valgrind: runs the program, reports nothing.\nshift 2\nexec \"$@\"\n";
const FAKE_BRANCH: &str = "#!/bin/sh\n# FAKE valgrind: always claims a secret-dependent branch.\necho '==1== Conditional jump or move depends on uninitialised value(s)' >&2\nexit 99\n";
const FAKE_SEGV: &str = "#!/bin/sh\nkill -SEGV $$\n";

fn fake(dir: &Path, name: &str, body: &str) -> String {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join(name);
    std::fs::write(&p, body).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p.display().to_string()
}

/// Fake valgrind plus a no-op `valgrind/memcheck.h` stub so the harness compiles its taint mode.
/// PLUMBING ONLY: nothing is tainted and nothing is checked by Memcheck.
fn stubbed(body: &str) -> (PathBuf, String) {
    let tmp = std::env::temp_dir().join(format!("ctkat-fake-{}", rundir::new_id()));
    std::fs::create_dir_all(tmp.join("valgrind")).unwrap();
    std::fs::write(
        tmp.join("valgrind/memcheck.h"),
        "#define VALGRIND_MAKE_MEM_UNDEFINED(p,n) ((void)(p),(void)(n))\n#define VALGRIND_MAKE_MEM_DEFINED(p,n) ((void)(p),(void)(n))\n",
    )
    .unwrap();
    std::fs::create_dir_all(tmp.join("bin")).unwrap();
    let vg = fake(&tmp.join("bin"), "valgrind", body);
    (tmp, vg)
}

fn with_stub(y: String, tmp: &Path) -> String {
    y.replacen(
        "    function:",
        &format!("    include_dirs: [\"{}\"]\n    function:", tmp.display()),
        1,
    )
}

fn run(yaml: &str, valgrind: &str) -> Report {
    let cfg = Config::parse(yaml).expect("config");
    let cfg = Config {
        base_dir: fixtures(),
        ..cfg
    };
    let base = std::env::temp_dir().join(format!("ct-kat-test-{}", rundir::new_id()));
    let rd = rundir::RunDir::create(&base, false).unwrap();
    let opts = Options {
        valgrind: valgrind.into(),
        detail_cap: 4000,
        only: None,
    };
    let r = screen(&cfg, &rd.path, &rd.id, true, &opts);
    drop(rd);
    let _ = std::fs::remove_dir_all(&base);
    r
}

fn layer<'a>(r: &'a Report, name: &str) -> &'a ct_kat::verdict::LayerResult {
    r.targets[0]
        .layers
        .iter()
        .find(|l| l.layer == name)
        .unwrap()
}

const NO_VG: &str = "/nonexistent/valgrind";

#[test]
fn missing_valgrind_never_reads_as_robust() {
    if !have("gcc") {
        return eprintln!("skip: gcc missing");
    }
    let r = run(&yaml("", "clean", "clean.c", "ct_clean", ""), NO_VG);
    assert_eq!(layer(&r, "memcheck").status, Status::Error);
    assert_eq!(
        layer(&r, "memcheck").error_kind.as_deref(),
        Some("tool-missing")
    );
    assert_eq!(layer(&r, "asm_scan").status, Status::Pass);
    assert_eq!(layer(&r, "ct_matrix").status, Layer_ERR_OR_PASS(&r));
    assert_eq!(r.targets[0].verdict, Verdict::NeedsAnalysis);
    assert!(!r.gate_pass);
}

#[allow(non_snake_case)]
fn Layer_ERR_OR_PASS(r: &Report) -> Status {
    // Without valgrind the matrix cannot run its memcheck cells, so it must be an Error too.
    assert_eq!(
        layer(r, "ct_matrix").error_kind.as_deref(),
        Some("tool-missing")
    );
    Status::Error
}

#[test]
fn clean_fixture_with_fake_valgrind_pipeline_is_robust() {
    if !have("gcc") {
        return eprintln!("skip: gcc missing");
    }
    let (tmp, vg) = stubbed(FAKE_CLEAN);
    let r = run(
        &with_stub(yaml("", "clean", "clean.c", "ct_clean", ""), &tmp),
        &vg,
    );
    assert_eq!(
        r.targets[0].verdict,
        Verdict::Robust,
        "{:#?}",
        r.targets[0].layers
    );
    assert!(r.gate_pass);
    let _ = std::fs::remove_dir_all(tmp);
}

#[test]
fn real_valgrind_clean_fixture_is_robust() {
    if !have("gcc") || !have("valgrind") {
        return eprintln!("skip: needs gcc and valgrind");
    }
    let r = run(&yaml("", "clean", "clean.c", "ct_clean", ""), "valgrind");
    assert_eq!(
        r.targets[0].verdict,
        Verdict::Robust,
        "{:#?}",
        r.targets[0].layers
    );
}

#[test]
fn leaky_division_is_flagged_by_asm_scan() {
    if !have("gcc") {
        return eprintln!("skip: gcc missing");
    }
    let r = run(
        &yaml("memcheck: false", "div", "leaky_div.c", "ct_leaky_div", ""),
        NO_VG,
    );
    let a = layer(&r, "asm_scan");
    assert_eq!(a.status, Status::Fail, "{a:?}");
    assert_eq!(a.classes, ["varlat"]);
    assert!(!r.gate_pass);
}

#[test]
fn leaky_division_verdict_is_varlat_when_other_layers_settle() {
    if !have("gcc") {
        return eprintln!("skip: gcc missing");
    }
    let (tmp, vg) = stubbed(FAKE_CLEAN);
    let r = run(
        &with_stub(yaml("", "div", "leaky_div.c", "ct_leaky_div", ""), &tmp),
        &vg,
    );
    assert_eq!(
        r.targets[0].verdict,
        Verdict::VarlatSecretRisk,
        "{:#?}",
        r.targets[0].layers
    );
    let _ = std::fs::remove_dir_all(tmp);
}

#[test]
fn memcheck_branch_finding_with_fake_valgrind_parsing_only() {
    if !have("gcc") {
        return eprintln!("skip: gcc missing");
    }
    let (tmp, vg) = stubbed(FAKE_BRANCH);
    let r = run(
        &with_stub(
            yaml(
                "ct_matrix: false",
                "b",
                "leaky_branch.c",
                "ct_leaky_branch",
                "",
            ),
            &tmp,
        ),
        &vg,
    );
    assert_eq!(layer(&r, "memcheck").classes, ["secret-branch"]);
    assert_eq!(r.targets[0].verdict, Verdict::SecretBranchRisk);
    let _ = std::fs::remove_dir_all(tmp);
}

#[test]
fn target_crash_under_valgrind_is_error_not_finding() {
    if !have("gcc") {
        return eprintln!("skip: gcc missing");
    }
    let (tmp, vg) = stubbed(FAKE_SEGV);
    let r = run(
        &with_stub(
            yaml(
                "ct_matrix: false, asm_scan: false",
                "c",
                "clean.c",
                "ct_clean",
                "",
            ),
            &tmp,
        ),
        &vg,
    );
    let m = layer(&r, "memcheck");
    assert_eq!(
        (m.status, m.error_kind.as_deref()),
        (Status::Error, Some("target-crash"))
    );
    assert_eq!(r.targets[0].verdict, Verdict::NeedsAnalysis);
    let _ = std::fs::remove_dir_all(tmp);
}

#[test]
fn dudect_detects_secret_dependent_loop_and_passes_clean() {
    if !have("gcc") {
        return eprintln!("skip: gcc missing");
    }
    let layers = "memcheck: false, ct_matrix: false, asm_scan: false, dudect: true";
    let leaky = run(
        &yaml(layers, "b", "leaky_branch.c", "ct_leaky_branch", ""),
        NO_VG,
    );
    let d = layer(&leaky, "dudect");
    assert_eq!(d.status, Status::Fail, "{d:?}");
    assert_eq!(d.classes, ["timing"]);
    let clean = run(&yaml(layers, "c", "clean.c", "ct_clean", ""), NO_VG);
    assert_eq!(
        layer(&clean, "dudect").status,
        Status::Pass,
        "{:?}",
        layer(&clean, "dudect")
    );
}

#[test]
fn crashing_target_is_invalid_target() {
    if !have("gcc") {
        return eprintln!("skip: gcc missing");
    }
    let r = run(&yaml("", "x", "crash.c", "ct_crash", ""), NO_VG);
    assert_eq!(r.targets[0].verdict, Verdict::InvalidTarget);
    assert_eq!(layer(&r, "memcheck").status, Status::NotRun);
}

#[test]
fn wrong_expected_kat_is_invalid_target_and_right_one_passes() {
    if !have("gcc") {
        return eprintln!("skip: gcc missing");
    }
    let bad = yaml(
        "memcheck: false, ct_matrix: false, asm_scan: false",
        "k",
        "clean.c",
        "ct_clean",
        "",
    )
    .replace(
        "function: ct_clean",
        "function: ct_clean\n    expected_out_hex: \"00\"",
    );
    let r = run(&bad, NO_VG);
    assert_eq!(r.targets[0].verdict, Verdict::InvalidTarget);
    assert!(layer(&r, "build_kat").detail.contains("KAT mismatch"));
    // learn the real output, then feed it back as the expected KAT
    let ok = run(
        &yaml(
            "memcheck: false, ct_matrix: false, asm_scan: false",
            "k",
            "clean.c",
            "ct_clean",
            "",
        ),
        NO_VG,
    );
    assert_eq!(layer(&ok, "build_kat").status, Status::Pass);
    assert!(layer(&ok, "build_kat").detail.contains("NOT checked"));
}

#[test]
fn compile_failure_is_invalid_target_and_missing_compiler_is_tool_missing() {
    if !have("gcc") {
        return eprintln!("skip: gcc missing");
    }
    let tmp = std::env::temp_dir().join(format!("ctkat-bad-{}", rundir::new_id()));
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::write(tmp.join("bad.c"), "this is not C").unwrap();
    let y = yaml("", "bad", "clean.c", "ct_clean", "").replace(
        &fixtures().join("clean.c").display().to_string(),
        &tmp.join("bad.c").display().to_string(),
    );
    assert_eq!(run(&y, NO_VG).targets[0].verdict, Verdict::InvalidTarget);
    let y = yaml("", "n", "clean.c", "ct_clean", "")
        .replace("compilers: [gcc]", "compilers: [no-such-cc-ctkat]");
    let r = run(&y, NO_VG);
    assert_eq!(
        layer(&r, "build_kat").error_kind.as_deref(),
        Some("tool-missing")
    );
    assert_eq!(r.targets[0].verdict, Verdict::NeedsAnalysis);
    let _ = std::fs::remove_dir_all(tmp);
}

#[test]
fn triage_with_justification_gives_accepted_variable_time() {
    if !have("gcc") {
        return eprintln!("skip: gcc missing");
    }
    let (tmp, vg) = stubbed(FAKE_CLEAN);
    let triage = "    triage:\n      asm_scan: \"divisor is public: spec-permitted variable time\"";
    let r = run(
        &with_stub(yaml("", "div", "leaky_div.c", "ct_leaky_div", triage), &tmp),
        &vg,
    );
    assert_eq!(
        r.targets[0].verdict,
        Verdict::AcceptedVariableTime,
        "{:#?}",
        r.targets[0].layers
    );
    assert!(r.gate_pass);
    let _ = std::fs::remove_dir_all(tmp);
}

#[test]
fn config_errors_are_reported_not_panicked() {
    assert!(Config::load(Path::new("/nonexistent/ct-kat.yaml")).is_err());
    assert!(matches!(
        Config::parse("targets: [ {"),
        Err(ct_kat::config::ConfigError::Syntax(_))
    ));
    assert!(
        Config::parse(&yaml("", "t", "clean.c", "ct_clean", "").replace("-Os", "-Obogus")).is_err()
    );
    assert!(
        Config::parse(&yaml(
            "",
            "t",
            "clean.c",
            "ct_clean",
            "    triage:\n      asm_scan: \"  \""
        ))
        .is_err()
    );
    assert!(
        Config::parse(&yaml(
            "",
            "t",
            "clean.c",
            "ct_clean",
            "    triage:\n      nonsense: why"
        ))
        .is_err()
    );
    // a source path that does not exist
    let dir = std::env::temp_dir();
    let p = dir.join(format!("ctkat-cfg-{}.yaml", rundir::new_id()));
    std::fs::write(
        &p,
        yaml("", "t", "clean.c", "ct_clean", "").replace("clean.c", "nope.c"),
    )
    .unwrap();
    assert!(matches!(
        Config::load(&p),
        Err(ct_kat::config::ConfigError::MissingPath(_))
    ));
    let _ = std::fs::remove_file(p);
}

#[test]
fn run_directories_are_unique_gc_reaps_only_dead_old_ones() {
    let base = std::env::temp_dir().join(format!("ctkat-rd-{}", rundir::new_id()));
    let a = rundir::RunDir::create(&base, false).unwrap();
    let b = rundir::RunDir::create(&base, false).unwrap();
    assert_ne!(a.path, b.path);
    // a fresh directory (even with a dead pid) is inside the grace period
    let stale = base.join("run-deadbeef00000000");
    std::fs::create_dir_all(&stale).unwrap();
    std::fs::write(stale.join("pid"), "999999999").unwrap();
    assert!(rundir::gc(&base).is_empty());
    assert!(stale.exists() && a.path.exists());
    drop((a, b));
    let _ = std::fs::remove_dir_all(base);
}

#[test]
fn json_and_text_agree_on_verdict_and_gate() {
    if !have("gcc") {
        return eprintln!("skip: gcc missing");
    }
    let r = run(
        &yaml(
            "memcheck: false, ct_matrix: false",
            "clean",
            "clean.c",
            "ct_clean",
            "",
        ),
        NO_VG,
    );
    let json: serde_json::Value = serde_json::from_str(&ct_kat::to_json(&r)).unwrap();
    let text = ct_kat::to_text(&r, false, false);
    assert_eq!(json["targets"][0]["verdict"], r.targets[0].verdict.as_str());
    assert!(text.contains(&format!("verdict {}", r.targets[0].verdict.as_str())));
    assert!(text.contains(if r.gate_pass {
        "gate: PASS"
    } else {
        "gate: BLOCKED"
    }));
    assert!(!text.contains('\x1b'), "no ANSI escapes when color is off");
}
