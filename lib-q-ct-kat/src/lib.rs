//! CT-KAT style screening of constant-time risks in C implementations.
//!
//! Layers: build + KAT validation, Valgrind/Memcheck taint, a compiler x optimization matrix,
//! an assembly scan for division instructions, and an optional dudect-style timing test, folded
//! into one verdict by a default-deny policy (see [`verdict`]). A PASS is a screening result,
//! never a proof of constant-time behaviour.
#![forbid(unsafe_code)]

pub mod config;
pub mod exec;
pub mod harness;
pub mod layers;
pub mod rundir;
pub mod stats;
pub mod verdict;

use std::fmt::Write as _;
use std::path::Path;
use std::time::Duration;

use config::{Config, Target};
use layers::Ctx;
use serde::Serialize;
use verdict::{LayerResult, Status, Verdict};

#[derive(Debug, Serialize)]
pub struct TargetReport {
    pub target: String,
    pub function: String,
    pub verdict: Verdict,
    pub gate_pass: bool,
    pub layers: Vec<LayerResult>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub tool: &'static str,
    pub run_id: String,
    pub mode: &'static str,
    pub gate_pass: bool,
    pub note: &'static str,
    pub targets: Vec<TargetReport>,
}

pub const NOTE: &str =
    "A passing verdict is a screening result, not proof of constant-time behaviour.";

pub struct Options {
    pub valgrind: String,
    pub detail_cap: usize,
    pub only: Option<String>,
}

pub fn screen_target(cfg: &Config, t: &Target, dir: &Path, opts: &Options) -> TargetReport {
    let tdir = dir.join(&t.name);
    let mut layers_out: Vec<LayerResult> = vec![];
    let finish = |mut ls: Vec<LayerResult>| {
        let v = verdict::aggregate(&mut ls, &t.triage);
        for l in &mut ls {
            l.detail = layers::clip(&l.detail, opts.detail_cap);
        }
        TargetReport {
            target: t.name.clone(),
            function: t.function.clone(),
            verdict: v,
            gate_pass: v.passes_gate(),
            layers: ls,
        }
    };
    if let Err(e) = std::fs::create_dir_all(&tdir)
        .and_then(|()| std::fs::write(tdir.join("harness.c"), harness::generate(t)))
    {
        layers_out.push(LayerResult::error(
            "build_kat",
            "tool-error",
            format!("cannot write harness: {e}"),
        ));
        return finish(layers_out);
    }
    let ctx = Ctx {
        cfg,
        target: t,
        dir: tdir,
        timeout: Duration::from_secs(cfg.timeout_secs),
        valgrind: opts.valgrind.clone(),
    };
    let (bk, base) = layers::build_kat(&ctx);
    layers_out.push(bk);
    let need = "build/KAT did not produce a baseline binary";
    let run = |on: bool, name: &str, f: &dyn Fn(&layers::Baseline) -> LayerResult| match (on, &base)
    {
        (false, _) => LayerResult::disabled(name),
        (true, None) => LayerResult::not_run(name, need),
        (true, Some(b)) => f(b),
    };
    layers_out.push(run(cfg.layers.memcheck, "memcheck", &|b| {
        layers::memcheck(&ctx, b)
    }));
    layers_out.push(run(cfg.layers.ct_matrix, "ct_matrix", &|b| {
        layers::ct_matrix(&ctx, b)
    }));
    // asm-scan compiles sources on its own; it does not need the baseline binary.
    layers_out.push(if cfg.layers.asm_scan {
        layers::asm_scan(&ctx)
    } else {
        LayerResult::disabled("asm_scan")
    });
    layers_out.push(run(cfg.layers.dudect, "dudect", &|b| {
        layers::dudect(&ctx, b)
    }));
    finish(layers_out)
}

pub fn screen(cfg: &Config, dir: &Path, run_id: &str, ci: bool, opts: &Options) -> Report {
    let targets: Vec<TargetReport> = cfg
        .targets
        .iter()
        .filter(|t| opts.only.as_ref().is_none_or(|o| *o == t.name))
        .map(|t| screen_target(cfg, t, dir, opts))
        .collect();
    Report {
        tool: "cargo-ct-kat",
        run_id: run_id.into(),
        mode: if ci { "ci" } else { "interactive" },
        gate_pass: !targets.is_empty() && targets.iter().all(|t| t.gate_pass),
        note: NOTE,
        targets,
    }
}

pub fn to_json(r: &Report) -> String {
    serde_json::to_string_pretty(r).expect("report serializes")
}

/// Human-readable rendering of the same `Report` the JSON comes from (so the two cannot differ).
pub fn to_text(r: &Report, color: bool, verbose: bool) -> String {
    let c = |code: &str, s: &str| {
        if color {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    };
    let mut o = String::new();
    for t in &r.targets {
        let vc = if t.gate_pass { "32" } else { "31" };
        let _ = writeln!(
            o,
            "{} ({}): verdict {}",
            t.target,
            t.function,
            c(vc, t.verdict.as_str())
        );
        for l in &t.layers {
            let st = format!("{:?}", l.status).to_lowercase();
            let sc = match l.status {
                Status::Pass => "32",
                Status::Fail => "31",
                Status::Error => "33",
                _ => "2",
            };
            let extra = l
                .error_kind
                .as_deref()
                .map(|k| format!(" [{k}]"))
                .unwrap_or_default();
            let acc = if l.accepted.is_some() {
                " (accepted by triage)"
            } else {
                ""
            };
            let _ = writeln!(o, "  {:<10} {}{extra}{acc}", l.layer, c(sc, &st));
            if verbose || matches!(l.status, Status::Fail | Status::Error) {
                let d = if verbose {
                    l.detail.clone()
                } else {
                    layers::clip(&l.detail, 300)
                };
                if !d.is_empty() {
                    let _ = writeln!(o, "             {d}");
                }
            }
        }
    }
    let _ = writeln!(o, "gate: {}", if r.gate_pass { "PASS" } else { "BLOCKED" });
    let _ = writeln!(o, "{}", r.note);
    o
}
