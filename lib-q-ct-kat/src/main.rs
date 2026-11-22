//! `cargo ct-kat` entry point. Exit codes: 0 gate passed, 1 gate blocked, 2 usage/config/IO error.

// A CLI reads its environment by design (same scoped allow as lib-q/build.rs).
#![allow(clippy::disallowed_methods)]

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use ct_kat::config::Config;
use ct_kat::{Options, rundir};

const USAGE: &str = "\
cargo ct-kat [run] -c <config.yaml> [--ci | --interactive] [--report <path>] [--keep] [--verbose]
             [--only <target>] [--target-dir <dir>]
cargo ct-kat gc [--target-dir <dir>]      remove run directories left by interrupted runs

Environment: CT_KAT_VALGRIND overrides the valgrind binary; CI=1 selects --ci.
Exit codes: 0 gate passed, 1 gate blocked (any verdict except robust / accepted-variable-time), 2 usage or I/O error.";

#[derive(Default)]
struct Args {
    gc: bool,
    config: Option<PathBuf>,
    ci: bool,
    interactive: bool,
    report: Option<PathBuf>,
    keep: bool,
    verbose: bool,
    only: Option<String>,
    target_dir: Option<PathBuf>,
}

fn parse(mut it: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut a = Args::default();
    let mut rest: Vec<String> = it.by_ref().collect();
    // `cargo ct-kat ...` invokes `cargo-ct-kat ct-kat ...`.
    if rest.first().is_some_and(|s| s == "ct-kat") {
        rest.remove(0);
    }
    let mut it = rest.into_iter().peekable();
    match it.peek().map(String::as_str) {
        Some("gc") => {
            a.gc = true;
            it.next();
        }
        Some("run") => {
            it.next();
        }
        _ => {}
    }
    while let Some(s) = it.next() {
        let mut val = |name: &str| it.next().ok_or(format!("{name} needs a value"));
        match s.as_str() {
            "-c" | "--config" => a.config = Some(val("--config")?.into()),
            "--ci" => a.ci = true,
            "--interactive" => a.interactive = true,
            "--report" => a.report = Some(val("--report")?.into()),
            "--keep" => a.keep = true,
            "-v" | "--verbose" => a.verbose = true,
            "--only" => a.only = Some(val("--only")?),
            "--target-dir" => a.target_dir = Some(val("--target-dir")?.into()),
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    if a.ci && a.interactive {
        return Err("--ci and --interactive are mutually exclusive".into());
    }
    Ok(a)
}

fn die(msg: &str) -> ExitCode {
    eprintln!("cargo-ct-kat: {msg}");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let a = match parse(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(m) => {
            if !m.is_empty() {
                eprintln!("cargo-ct-kat: {m}");
            }
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let base = rundir::base_dir(a.target_dir.as_deref());
    if a.gc {
        let removed = rundir::gc(&base);
        println!(
            "removed {} stale run directories under {}",
            removed.len(),
            base.display()
        );
        return ExitCode::SUCCESS;
    }
    let Some(cfg_path) = a.config.as_ref() else {
        return die("missing --config <file>");
    };
    let cfg = match Config::load(cfg_path) {
        Ok(c) => c,
        Err(e) => return die(&e.to_string()),
    };
    if let Some(o) = &a.only
        && !cfg.targets.iter().any(|t| &t.name == o)
    {
        return die(&format!("--only: no target named {o:?}"));
    }
    let stdout_tty = std::io::stdout().is_terminal();
    let ci = a.ci || (!a.interactive && (std::env::var_os("CI").is_some() || !stdout_tty));

    let _ = rundir::gc(&base); // reap directories of interrupted earlier runs
    let run = match rundir::RunDir::create(&base, a.keep) {
        Ok(r) => r,
        Err(e) => {
            return die(&format!(
                "cannot create run directory under {}: {e}",
                base.display()
            ));
        }
    };
    let opts = Options {
        valgrind: std::env::var("CT_KAT_VALGRIND").unwrap_or_else(|_| "valgrind".into()),
        detail_cap: if ci && !a.verbose { 2_000 } else { 8_000 },
        only: a.only.clone(),
    };
    let report = ct_kat::screen(&cfg, &run.path, &run.id, ci, &opts);

    let json = ct_kat::to_json(&report);
    let report_path = a
        .report
        .clone()
        .unwrap_or_else(|| base.join(format!("report-{}.json", run.id)));
    if let Err(e) = std::fs::write(&report_path, &json) {
        return die(&format!(
            "cannot write report {}: {e}",
            report_path.display()
        ));
    }
    if ci {
        println!("{json}");
        eprintln!("report: {}", report_path.display());
    } else {
        let color = stdout_tty && std::env::var_os("NO_COLOR").is_none();
        print!("{}", ct_kat::to_text(&report, color, a.verbose));
        println!("report: {}", report_path.display());
    }
    if a.keep {
        eprintln!("kept run directory: {}", run.path.display());
    }
    if report.gate_pass {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
