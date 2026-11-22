//! `phone-bench`: one harness for both credential tracks (credential-track research note,
//! section 7, steps L5 and S3).
//!
//! Every workload runs in its own child process (`worker`) so peak RSS is per workload, not the
//! running maximum of the whole run. The parent (`run`) wraps the results with host metadata and
//! writes one JSON document. Pass/fail thresholds are applied afterwards by
//! `scripts/phone-bench-compare.py`, which reads the JSON from all three hosts.
//!
//! Single-threaded by design: the `parallel` features of the STARK crates are off, matching the
//! note's "thread count" field (recorded as 1).

mod workloads;

use std::fmt::Write as _;
use std::process::Command;

use workloads::ALL;

fn usage() -> ! {
    eprintln!(
        "usage:\n  phone-bench list\n  phone-bench run --class <desktop-x86|desktop-aarch64|phone> \
         [--workload NAME]... [--iters N=11] [--depth D=20] [--label TEXT] [--out FILE]\n  \
         phone-bench worker NAME ITERS DEPTH   (internal)"
    );
    std::process::exit(2)
}

fn median(v: &mut [u128]) -> u128 {
    v.sort_unstable();
    v[v.len() / 2]
}

fn json_str(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            c if (c as u32) < 0x20 => {
                let _ = write!(o, "\\u{:04x}", c as u32);
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// Peak resident set of THIS process in KiB, or `None` if the platform gives no way to read it.
fn peak_rss_kib() -> Option<u64> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // VmHWM is per address space, so it is not inherited across exec the way
        // getrusage(RUSAGE_SELF).ru_maxrss can be.
        let s = std::fs::read_to_string("/proc/self/status").ok()?;
        let line = s.lines().find(|l| l.starts_with("VmHWM:"))?;
        line.split_whitespace().nth(1)?.parse().ok()
    }
    #[cfg(target_os = "macos")]
    {
        // `nix` is a safe wrapper over getrusage(2); `max_rss` is the process's resident-set
        // high-water mark. macOS reports bytes, Linux KiB.
        let usage =
            nix::sys::resource::getrusage(nix::sys::resource::UsageWho::RUSAGE_SELF).ok()?;
        Some(usage.max_rss() as u64 / 1024)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    {
        None
    }
}

/// Child entry point: run one workload, print one JSON object on stdout.
fn worker(name: &str, iters: usize, depth: usize) -> i32 {
    let Some(w) = ALL.iter().find(|w| w.name == name) else {
        eprintln!("unknown workload {name}");
        return 2;
    };
    match (w.run)(iters, depth) {
        Ok(mut m) => {
            let list = |v: &[u128]| {
                v.iter()
                    .map(|n| format!("{:.3}", *n as f64 / 1e6))
                    .collect::<Vec<_>>()
                    .join(",")
            };
            let p_list = list(&m.prove_ns);
            let v_list = list(&m.verify_ns);
            let p_med = median(&mut m.prove_ns) as f64 / 1e6;
            let v_med = median(&mut m.verify_ns) as f64 / 1e6;
            let rss = peak_rss_kib().map_or("null".to_string(), |k| k.to_string());
            println!(
                "{{\"ok\":true,\"prove_ms_median\":{p_med:.3},\"verify_ms_median\":{v_med:.3},\
                 \"prove_ms_all\":[{p_list}],\"verify_ms_all\":[{v_list}],\
                 \"wire_bytes\":{},\"peak_rss_kib\":{rss}}}",
                m.wire_bytes
            );
            0
        }
        Err(e) => {
            println!("{{\"ok\":false,\"error\":{}}}", json_str(&e));
            1
        }
    }
}

fn cpu_model() -> String {
    if let Ok(s) = std::fs::read_to_string("/proc/cpuinfo") {
        for key in ["model name", "Hardware", "Model", "CPU part"] {
            if let Some((_, v)) = s
                .lines()
                .find(|l| l.starts_with(key))
                .and_then(|l| l.split_once(':'))
            {
                return v.trim().to_string();
            }
        }
    }
    Command::new("sysctl")
        .args(["-n", "machdep.cpu.brand_string"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

fn cpu_flags() -> String {
    let s = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    s.lines()
        .find(|l| l.starts_with("flags") || l.starts_with("Features"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim().to_string())
        .unwrap_or_default()
}

fn run(args: &[String]) -> i32 {
    let (mut class, mut label, mut out) = (None, String::new(), None);
    let (mut iters, mut depth) = (11usize, 20usize);
    let mut selected: Vec<String> = vec![];
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().cloned().unwrap_or_else(|| usage());
        match a.as_str() {
            "--class" => class = Some(val()),
            "--label" => label = val(),
            "--out" => out = Some(val()),
            "--iters" => iters = val().parse().unwrap_or_else(|_| usage()),
            "--depth" => depth = val().parse().unwrap_or_else(|_| usage()),
            "--workload" => selected.push(val()),
            _ => usage(),
        }
    }
    let class = class.unwrap_or_else(|| usage());
    if !["desktop-x86", "desktop-aarch64", "phone"].contains(&class.as_str()) {
        eprintln!("--class must be desktop-x86, desktop-aarch64 or phone");
        return 2;
    }
    if iters == 0 || !(1..=64).contains(&depth) {
        eprintln!("--iters must be >= 1 and --depth in 1..=64");
        return 2;
    }
    let exe = std::env::current_exe().expect("current_exe");
    let mut results = vec![];
    let mut failed = false;
    for w in ALL {
        if !selected.is_empty() && !selected.iter().any(|s| s == w.name) {
            continue;
        }
        eprintln!("running {} (iters={iters}, depth={depth})", w.name);
        let o = Command::new(&exe)
            .args(["worker", w.name, &iters.to_string(), &depth.to_string()])
            .output();
        let body = match o {
            Ok(o) if !o.stdout.is_empty() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            Ok(o) => format!(
                "{{\"ok\":false,\"error\":{}}}",
                json_str(&format!(
                    "worker exited {:?}: {}",
                    o.status.code(),
                    String::from_utf8_lossy(&o.stderr)
                ))
            ),
            Err(e) => format!("{{\"ok\":false,\"error\":{}}}", json_str(&e.to_string())),
        };
        if !body.contains("\"ok\":true") {
            failed = true;
        }
        results.push(format!(
            "{{\"workload\":{},\"track\":{},\"standin\":{},\"result\":{body}}}",
            json_str(w.name),
            json_str(w.track.as_str()),
            w.standin
        ));
    }
    if results.is_empty() {
        eprintln!("no workload matched");
        return 2;
    }
    let doc = format!(
        "{{\"schema\":1,\"commit\":{},\"host\":{{\"class\":{},\"label\":{},\"os\":{},\"arch\":{},\
         \"cpu\":{},\"cpu_flags\":{},\"threads\":1}},\"iters\":{iters},\"depth\":{depth},\
         \"statistic\":\"median\",\"results\":[{}]}}\n",
        json_str(env!("PHONE_BENCH_COMMIT")),
        json_str(&class),
        json_str(&label),
        json_str(std::env::consts::OS),
        json_str(std::env::consts::ARCH),
        json_str(&cpu_model()),
        json_str(&cpu_flags()),
        results.join(",")
    );
    match out {
        Some(p) => {
            if let Err(e) = std::fs::write(&p, &doc) {
                eprintln!("write {p}: {e}");
                return 1;
            }
            eprintln!("wrote {p}");
        }
        None => print!("{doc}"),
    }
    i32::from(failed)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("list") => {
            for w in ALL {
                println!(
                    "{}\t{}\tstandin={}\t{}",
                    w.name,
                    w.track.as_str(),
                    w.standin,
                    w.desc
                );
            }
            0
        }
        Some("run") => run(&args[1..]),
        Some("worker") if args.len() == 4 => worker(
            &args[1],
            args[2].parse().unwrap_or_else(|_| usage()),
            args[3].parse().unwrap_or_else(|_| usage()),
        ),
        _ => usage(),
    };
    std::process::exit(code);
}
