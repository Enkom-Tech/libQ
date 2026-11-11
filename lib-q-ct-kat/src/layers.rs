//! The analysis layers. Each returns a `LayerResult`; none of them ever turns "could not run"
//! into a pass.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config::{Config, Target};
use crate::exec::{self, CmdResult, Outcome};
use crate::stats;
use crate::verdict::LayerResult;

const CAP: usize = 256 * 1024;
const TIME_CAP: usize = 64 * 1024 * 1024;

pub struct Ctx<'a> {
    pub cfg: &'a Config,
    pub target: &'a Target,
    pub dir: PathBuf,
    pub timeout: Duration,
    pub valgrind: String,
}

pub struct Baseline {
    pub bin: PathBuf,
    pub kat_hex: String,
}

pub fn clip(s: &str, n: usize) -> String {
    let s = s.trim();
    if s.len() <= n {
        return s.to_string();
    }
    let mut end = n;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}... [truncated, {} bytes total]", &s[..end], s.len())
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

enum Build {
    NoCompiler,
    Failed(String),
}

fn include_args(ctx: &Ctx) -> Vec<String> {
    ctx.target
        .include_dirs
        .iter()
        .map(|d| format!("-I{}", ctx.cfg.resolve(d).display()))
        .collect()
}

fn sources(ctx: &Ctx) -> Vec<String> {
    ctx.target
        .sources
        .iter()
        .map(|p| ctx.cfg.resolve(p).display().to_string())
        .collect()
}

fn build_cell(ctx: &Ctx, cc: &str, opt: &str) -> Result<PathBuf, Build> {
    let bin = ctx.dir.join(format!("{}-{}", sanitize(cc), sanitize(opt)));
    let mut args: Vec<String> = vec![
        "-g".into(),
        opt.into(),
        "-std=gnu11".into(),
        "-o".into(),
        bin.display().to_string(),
    ];
    args.extend(include_args(ctx));
    args.push(ctx.dir.join("harness.c").display().to_string());
    args.extend(sources(ctx));
    args.extend(ctx.target.link_args.iter().map(|a| {
        // A link argument naming a file relative to the config (e.g. a static library) is made absolute.
        let p = ctx.cfg.base_dir.join(a);
        if !a.starts_with('-') && p.exists() {
            p.display().to_string()
        } else {
            a.clone()
        }
    }));
    let r = exec::run(cc, &args, Some(&ctx.dir), ctx.timeout, CAP);
    match r.outcome {
        Outcome::NotFound => Err(Build::NoCompiler),
        Outcome::Exited(0) => Ok(bin),
        Outcome::TimedOut => Err(Build::Failed(format!("{cc} {opt}: compile timed out"))),
        _ => Err(Build::Failed(format!(
            "{cc} {opt}: {}",
            clip(&r.stderr_text(), 1500)
        ))),
    }
}

fn parse_out(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .find_map(|l| l.strip_prefix("OUT "))
        .map(|s| s.trim().to_string())
}

enum Kat {
    Ok(String),
    /// (error-kind or "invalid", detail); "invalid" means the target itself is wrong.
    Bad(&'static str, String),
}

fn run_kat(ctx: &Ctx, bin: &Path) -> Kat {
    let mut outs = vec![];
    for _ in 0..2 {
        let r = exec::run(
            &bin.display().to_string(),
            &["kat".into()],
            Some(&ctx.dir),
            ctx.timeout,
            CAP,
        );
        match r.outcome {
            Outcome::Exited(0) => match parse_out(&r.stdout_text()) {
                Some(o) => outs.push(o),
                None => return Kat::Bad("invalid", "harness printed no OUT line".into()),
            },
            Outcome::Signaled(s) => {
                return Kat::Bad(
                    "invalid",
                    format!("target crashed with signal {s} on well-formed input"),
                );
            }
            Outcome::Exited(c) => return Kat::Bad("invalid", format!("harness exited {c}")),
            Outcome::TimedOut => return Kat::Bad("timeout", "KAT run timed out".into()),
            Outcome::NotFound | Outcome::SpawnError(_) => {
                return Kat::Bad("tool-error", format!("cannot run harness: {:?}", r.outcome));
            }
        }
    }
    if outs[0] != outs[1] {
        return Kat::Bad(
            "invalid",
            "nondeterministic output across two identical runs".into(),
        );
    }
    Kat::Ok(outs.remove(0))
}

/// Build + KAT. Returns the baseline cell for later layers when it succeeded.
pub fn build_kat(ctx: &Ctx) -> (LayerResult, Option<Baseline>) {
    const L: &str = "build_kat";
    let opt = &ctx.cfg.opt_levels[0];
    let mut missing = vec![];
    for cc in &ctx.cfg.compilers {
        match build_cell(ctx, cc, opt) {
            Err(Build::NoCompiler) => missing.push(cc.clone()),
            Err(Build::Failed(m)) => {
                return (
                    LayerResult::fail(L, vec![], format!("build failed: {m}")),
                    None,
                );
            }
            Ok(bin) => {
                return match run_kat(ctx, &bin) {
                    Kat::Bad("invalid", m) => (LayerResult::fail(L, vec![], m), None),
                    Kat::Bad(kind, m) => (LayerResult::error(L, kind, m), None),
                    Kat::Ok(hex) => {
                        if let Some(exp) = &ctx.target.expected_out_hex {
                            if !exp.eq_ignore_ascii_case(&hex) {
                                return (
                                    LayerResult::fail(
                                        L,
                                        vec![],
                                        format!(
                                            "KAT mismatch: expected {}, got {}",
                                            clip(exp, 80),
                                            clip(&hex, 80)
                                        ),
                                    ),
                                    None,
                                );
                            }
                            (
                                LayerResult::pass(L, format!("built with {cc} {opt}; KAT matches")),
                                Some(Baseline { bin, kat_hex: hex }),
                            )
                        } else {
                            (
                                LayerResult::pass(
                                    L,
                                    format!(
                                        "built with {cc} {opt}; deterministic, but no expected_out_hex so the functional KAT was NOT checked"
                                    ),
                                ),
                                Some(Baseline { bin, kat_hex: hex }),
                            )
                        }
                    }
                };
            }
        }
    }
    (
        LayerResult::error(
            L,
            "tool-missing",
            format!("none of the compilers {missing:?} is on PATH"),
        ),
        None,
    )
}

/// Result of one Valgrind taint run.
#[derive(Debug, PartialEq, Eq)]
pub enum Mem {
    Clean,
    Findings(Vec<String>, String),
    Err(&'static str, String),
}

/// Pure classification of a finished Valgrind run, kept separate so it is testable without
/// Valgrind installed.
pub fn classify_valgrind(r: &CmdResult) -> Mem {
    match &r.outcome {
        Outcome::NotFound => Mem::Err("tool-missing", "valgrind not found".into()),
        Outcome::TimedOut => Mem::Err("timeout", "valgrind run timed out".into()),
        Outcome::Signaled(s) => Mem::Err("target-crash", format!("terminated by signal {s}")),
        Outcome::SpawnError(e) => Mem::Err("tool-error", e.clone()),
        Outcome::Exited(0) => Mem::Clean,
        Outcome::Exited(77) => Mem::Err(
            "unsupported",
            "harness built without <valgrind/memcheck.h>; secrets were not tainted".into(),
        ),
        Outcome::Exited(99) => {
            let e = r.stderr_text();
            let mut classes = vec![];
            if e.contains("Conditional jump or move depends on uninitialised value") {
                classes.push("secret-branch".to_string());
            }
            if e.contains("Use of uninitialised value") {
                classes.push("secret-index".to_string());
            }
            if classes.is_empty() {
                classes.push("uninit-other".into());
            }
            Mem::Findings(classes, clip(&e, 1500))
        }
        Outcome::Exited(c) => Mem::Err(
            "tool-error",
            format!("exit code {c}: {}", clip(&r.stderr_text(), 400)),
        ),
    }
}

fn memcheck_run(ctx: &Ctx, bin: &Path) -> Mem {
    let args = vec![
        "-q".into(),
        "--error-exitcode=99".into(),
        bin.display().to_string(),
        "taint".into(),
    ];
    // Valgrind is slow: allow it more time than a plain run.
    classify_valgrind(&exec::run(
        &ctx.valgrind,
        &args,
        Some(&ctx.dir),
        ctx.timeout * 4,
        CAP,
    ))
}

pub fn memcheck(ctx: &Ctx, base: &Baseline) -> LayerResult {
    const L: &str = "memcheck";
    match memcheck_run(ctx, &base.bin) {
        Mem::Clean => LayerResult::pass(L, "no uninitialised-value use derived from secret inputs"),
        Mem::Findings(c, d) => LayerResult::fail(L, c, d),
        Mem::Err(k, d) => LayerResult::error(L, k, d),
    }
}

pub fn ct_matrix(ctx: &Ctx, base: &Baseline) -> LayerResult {
    const L: &str = "ct_matrix";
    let mut sigs: Vec<(String, String)> = vec![];
    let mut missing = vec![];
    let mut errors = vec![];
    for cc in &ctx.cfg.compilers {
        for opt in &ctx.cfg.opt_levels {
            let cell = format!("{cc} {opt}");
            let bin = match build_cell(ctx, cc, opt) {
                Ok(b) => b,
                Err(Build::NoCompiler) => {
                    if !missing.contains(cc) {
                        missing.push(cc.clone());
                    }
                    break;
                }
                Err(Build::Failed(m)) => {
                    sigs.push((cell, format!("build failed: {}", clip(&m, 120))));
                    continue;
                }
            };
            let kat = match run_kat(ctx, &bin) {
                Kat::Ok(h) => {
                    if h == base.kat_hex {
                        "kat-same".to_string()
                    } else {
                        "kat-DIFFERENT".to_string()
                    }
                }
                Kat::Bad(k, m) => {
                    errors.push(format!("{cell}: KAT {k}: {}", clip(&m, 120)));
                    continue;
                }
            };
            let mem = match memcheck_run(ctx, &bin) {
                Mem::Clean => "clean".to_string(),
                Mem::Findings(mut c, _) => {
                    c.sort();
                    c.join("+")
                }
                Mem::Err(k, d) => {
                    errors.push(format!("{cell}: memcheck {k}: {}", clip(&d, 120)));
                    continue;
                }
            };
            sigs.push((cell, format!("{kat}/{mem}")));
        }
    }
    if !missing.is_empty() || !errors.is_empty() {
        let kind = if errors.iter().any(|e| e.contains("tool-missing")) || !missing.is_empty() {
            "tool-missing"
        } else {
            "tool-error"
        };
        return LayerResult::error(
            L,
            kind,
            format!(
                "incomplete matrix; missing compilers {missing:?}; {} cell errors: {}; completed cells: {}",
                errors.len(),
                clip(&errors.join(" | "), 600),
                sigs.len()
            ),
        );
    }
    let first = &sigs[0].1;
    let divergent: Vec<String> = sigs
        .iter()
        .filter(|(_, s)| s != first)
        .map(|(c, s)| format!("{c} => {s}"))
        .collect();
    if divergent.is_empty() {
        LayerResult::pass(L, format!("{} cells agree ({first})", sigs.len()))
    } else {
        LayerResult::fail(
            L,
            vec!["build-sensitive".into()],
            format!(
                "baseline {} => {first}; differing: {}",
                sigs[0].0,
                clip(&divergent.join("; "), 900)
            ),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86,
    Aarch64,
    Arm,
    Riscv,
}

pub fn arch_from_triple(t: &str) -> Option<Arch> {
    let a = t.split('-').next()?;
    match a {
        "x86_64" | "amd64" | "i386" | "i486" | "i586" | "i686" => Some(Arch::X86),
        "aarch64" | "arm64" | "aarch64_be" => Some(Arch::Aarch64),
        _ if a.starts_with("riscv") => Some(Arch::Riscv),
        _ if a.starts_with("arm") || a.starts_with("thumb") => Some(Arch::Arm),
        _ => None,
    }
}

fn is_div_mnemonic(arch: Arch, m: &str) -> bool {
    match arch {
        Arch::X86 => {
            let base = m.strip_prefix('v').unwrap_or(m);
            matches!(
                base,
                "div"
                    | "divb"
                    | "divw"
                    | "divl"
                    | "divq"
                    | "idiv"
                    | "idivb"
                    | "idivw"
                    | "idivl"
                    | "idivq"
            ) || base.starts_with("divs")
                || base.starts_with("divp")
                || matches!(
                    m,
                    "fdiv"
                        | "fdivp"
                        | "fdivr"
                        | "fdivrp"
                        | "fidiv"
                        | "fidivr"
                        | "fidivl"
                        | "fidivs"
                )
        }
        Arch::Aarch64 => matches!(m, "udiv" | "sdiv" | "fdiv"),
        Arch::Arm => matches!(m, "udiv" | "sdiv") || m.starts_with("vdiv"),
        Arch::Riscv => matches!(
            m,
            "div"
                | "divu"
                | "divw"
                | "divuw"
                | "rem"
                | "remu"
                | "remw"
                | "remuw"
                | "fdiv.s"
                | "fdiv.d"
        ),
    }
}

fn is_div_helper(sym: &str) -> bool {
    let s = sym.split('@').next().unwrap_or(sym);
    s.starts_with("__aeabi_idiv")
        || s.starts_with("__aeabi_uidiv")
        || s.starts_with("__aeabi_ldivmod")
        || s.starts_with("__aeabi_uldivmod")
        || matches!(
            s,
            "__divdi3"
                | "__udivdi3"
                | "__moddi3"
                | "__umoddi3"
                | "__divti3"
                | "__udivti3"
                | "__modti3"
                | "__umodti3"
        )
}

/// Division instructions (and runtime division helper calls) in compiler-emitted assembly,
/// as `function: instruction` strings. This is an over-approximation: it does not know which
/// divisors are secret, so every hit is a candidate for manual triage.
pub fn scan_asm(text: &str, arch: Arch) -> Vec<String> {
    let mut hits = vec![];
    let mut func = String::from("?");
    for raw in text.lines() {
        let line = raw.split(['#', '@']).next().unwrap_or("");
        let line = line.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(label) = line.strip_suffix(':') {
            if !label.starts_with(".L") && !label.starts_with('.') {
                func = label.to_string();
            }
            continue;
        }
        if line.starts_with('.') {
            continue;
        }
        let mut toks = line.split_whitespace();
        let m = toks.next().unwrap_or("");
        let operand = toks.next().unwrap_or("");
        if is_div_mnemonic(arch, m) {
            hits.push(format!("{func}: {m}"));
        } else if matches!(m, "call" | "callq" | "bl" | "b" | "jmp" | "tail" | "jal")
            && is_div_helper(operand)
        {
            hits.push(format!("{func}: {m} {operand}"));
        }
    }
    hits
}

pub fn asm_scan(ctx: &Ctx) -> LayerResult {
    const L: &str = "asm_scan";
    let mut findings: Vec<String> = vec![];
    let mut scanned = 0usize;
    let mut missing = vec![];
    for cc in &ctx.cfg.compilers {
        let m = exec::run(cc, &["-dumpmachine".into()], None, ctx.timeout, 4096);
        if m.outcome == Outcome::NotFound {
            missing.push(cc.clone());
            continue;
        }
        let triple = m.stdout_text();
        let Some(arch) = arch_from_triple(triple.trim()) else {
            return LayerResult::error(
                L,
                "unsupported",
                format!("{cc}: unsupported target architecture {:?}", triple.trim()),
            );
        };
        for opt in &ctx.cfg.opt_levels {
            for (i, src) in sources(ctx).iter().enumerate() {
                let out = ctx
                    .dir
                    .join(format!("{}-{}-{i}.s", sanitize(cc), sanitize(opt)));
                let mut args: Vec<String> = vec![
                    "-S".into(),
                    opt.clone(),
                    "-std=gnu11".into(),
                    "-fno-asynchronous-unwind-tables".into(),
                    "-o".into(),
                    out.display().to_string(),
                ];
                args.extend(include_args(ctx));
                args.push(src.clone());
                let r = exec::run(cc, &args, Some(&ctx.dir), ctx.timeout, CAP);
                if !r.ok() {
                    return LayerResult::error(
                        L,
                        if r.outcome == Outcome::TimedOut {
                            "timeout"
                        } else {
                            "tool-error"
                        },
                        format!("{cc} {opt} -S {src}: {}", clip(&r.stderr_text(), 400)),
                    );
                }
                let Ok(text) = std::fs::read_to_string(&out) else {
                    return LayerResult::error(
                        L,
                        "tool-error",
                        format!("no assembly produced for {src}"),
                    );
                };
                scanned += 1;
                for h in scan_asm(&text, arch) {
                    let f = format!(
                        "{cc} {opt} {}: {h}",
                        Path::new(src)
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                    );
                    if !findings.contains(&f) {
                        findings.push(f);
                    }
                }
            }
        }
    }
    if !missing.is_empty() {
        return LayerResult::error(
            L,
            "tool-missing",
            format!("compilers not on PATH: {missing:?}"),
        );
    }
    if findings.is_empty() {
        LayerResult::pass(
            L,
            format!("{scanned} assembly files: no division instructions or helper calls"),
        )
    } else {
        findings.truncate(50);
        LayerResult::fail(
            L,
            vec!["varlat".into()],
            format!(
                "division candidates (divisor secrecy not determined): {}",
                clip(&findings.join("; "), 1500)
            ),
        )
    }
}

pub fn parse_timing(text: &str) -> (Vec<f64>, Vec<f64>) {
    let (mut a, mut b) = (vec![], vec![]);
    for l in text.lines() {
        let mut it = l.split_whitespace();
        if let (Some(c), Some(t)) = (it.next(), it.next())
            && let Ok(t) = t.parse::<f64>()
        {
            match c {
                "0" => a.push(t),
                "1" => b.push(t),
                _ => {}
            }
        }
    }
    (a, b)
}

pub fn dudect(ctx: &Ctx, base: &Baseline) -> LayerResult {
    const L: &str = "dudect";
    let n = ctx.cfg.dudect.measurements;
    let r = exec::run(
        &base.bin.display().to_string(),
        &["time".into(), n.to_string()],
        Some(&ctx.dir),
        ctx.timeout * 4,
        TIME_CAP,
    );
    match r.outcome {
        Outcome::Exited(0) => {}
        Outcome::TimedOut => return LayerResult::error(L, "timeout", "timing run timed out"),
        Outcome::Signaled(s) => {
            return LayerResult::error(L, "target-crash", format!("signal {s}"));
        }
        ref o => return LayerResult::error(L, "tool-error", format!("{o:?}")),
    }
    if r.truncated {
        return LayerResult::error(L, "tool-error", "timing output exceeded the capture cap");
    }
    let (a, b) = parse_timing(&r.stdout_text());
    match stats::max_cropped_t(&a, &b) {
        None => LayerResult::error(
            L,
            "no-data",
            format!("too few samples per class ({} / {})", a.len(), b.len()),
        ),
        Some((t, crop)) => {
            let thr = ctx.cfg.dudect.t_threshold;
            let d = format!(
                "max|t| = {t:.2} at crop {crop} over {} + {} samples (threshold {thr}); wall-clock, noisy hosts can give false positives",
                a.len(),
                b.len()
            );
            if t > thr {
                LayerResult::fail(L, vec!["timing".into()], d)
            } else {
                LayerResult::pass(L, d)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn res(o: Outcome, stderr: &str) -> CmdResult {
        CmdResult {
            outcome: o,
            stdout: vec![],
            stderr: stderr.as_bytes().to_vec(),
            truncated: false,
        }
    }

    #[test]
    fn valgrind_classification() {
        assert_eq!(classify_valgrind(&res(Outcome::Exited(0), "")), Mem::Clean);
        assert!(matches!(
            classify_valgrind(&res(Outcome::NotFound, "")),
            Mem::Err("tool-missing", _)
        ));
        assert!(matches!(
            classify_valgrind(&res(Outcome::Signaled(11), "")),
            Mem::Err("target-crash", _)
        ));
        assert!(matches!(
            classify_valgrind(&res(Outcome::TimedOut, "")),
            Mem::Err("timeout", _)
        ));
        assert!(matches!(
            classify_valgrind(&res(Outcome::Exited(77), "")),
            Mem::Err("unsupported", _)
        ));
        assert!(matches!(
            classify_valgrind(&res(Outcome::Exited(3), "x")),
            Mem::Err("tool-error", _)
        ));
        let m = classify_valgrind(&res(
            Outcome::Exited(99),
            "==1== Conditional jump or move depends on uninitialised value(s)",
        ));
        assert!(matches!(m, Mem::Findings(ref c, _) if c == &["secret-branch"]));
        let m = classify_valgrind(&res(
            Outcome::Exited(99),
            "==1== Use of uninitialised value of size 8",
        ));
        assert!(matches!(m, Mem::Findings(ref c, _) if c == &["secret-index"]));
        let m = classify_valgrind(&res(
            Outcome::Exited(99),
            "==1== Syscall param write(buf) points to uninitialised byte(s)",
        ));
        assert!(matches!(m, Mem::Findings(ref c, _) if c == &["uninit-other"]));
    }

    #[test]
    fn asm_scan_per_architecture() {
        let x86 = "f:\n\tmovl %edi,%eax\n\tcltd\n\tidivl %esi\n\tret\n.L2:\n\tdivsd %xmm1,%xmm0\n\tcall __udivdi3@PLT\n";
        let h = scan_asm(x86, Arch::X86);
        assert_eq!(h.len(), 3, "{h:?}");
        assert!(h[0].starts_with("f: idivl"));
        assert!(
            scan_asm(
                "g:\n\tudiv w0, w0, w1\n\tfdiv d0,d0,d1\n\tmul w0,w0,w1\n",
                Arch::Aarch64
            )
            .len()
                == 2
        );
        assert!(
            scan_asm(
                "h:\n\tbl __aeabi_idiv\n\tsdiv r0,r0,r1 @ c\n\tadd r0,r0,r1\n",
                Arch::Arm
            )
            .len()
                == 2
        );
        assert!(
            scan_asm(
                "k:\n\tremu a0,a0,a1\n\tdivw a0,a0,a1\n\taddi a0,a0,1\n",
                Arch::Riscv
            )
            .len()
                == 2
        );
        // comments and directives are not instructions
        assert!(scan_asm("\t.ident \"div\"\nf:\n\tmovl $1,%eax # idiv\n", Arch::X86).is_empty());
    }

    #[test]
    fn arch_detection() {
        assert_eq!(arch_from_triple("x86_64-linux-gnu"), Some(Arch::X86));
        assert_eq!(
            arch_from_triple("aarch64-unknown-linux-gnu"),
            Some(Arch::Aarch64)
        );
        assert_eq!(
            arch_from_triple("armv7-unknown-linux-gnueabihf"),
            Some(Arch::Arm)
        );
        assert_eq!(arch_from_triple("riscv64-linux-gnu"), Some(Arch::Riscv));
        assert_eq!(arch_from_triple("sparc-sun-solaris"), None);
    }

    #[test]
    fn timing_parse() {
        let (a, b) = parse_timing("0 10\n1 20\n1 21\nbogus\n0 x\n");
        assert_eq!((a.len(), b.len()), (1, 2));
    }

    #[test]
    fn clip_is_utf8_safe() {
        assert!(clip(&"é".repeat(100), 51).contains("truncated"));
    }
}
