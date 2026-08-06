//! Statistical timing check for `FnDsa512::sign` (Welch t-test on wall-clock means).
//!
//! WHAT THIS IS
//! ------------
//! Two axes, each measured by interleaving `sign()` calls from two input classes (interleaving
//! cancels thermal/scheduler drift the same way `lib-q-hqc/tests/reed_solomon_constant_time.rs`
//! does) and running a Welch t-test on the resulting per-call wall-clock samples:
//!
//!   * message class -- one keypair, two fixed 64-byte messages (`msg_a`/`msg_b`, the same byte
//!     patterns the old smoke test used).
//!   * key class -- two keypairs, one fixed message. Falcon's Gaussian sampler is designed to be
//!     key-independent; this is the axis a real secret-dependent regression (e.g. a
//!     data-dependent rejection-sampling loop or lattice-point selection) would most plausibly
//!     show up on.
//!
//! WHAT THIS IS NOT
//! ----------------
//! This detects mean wall-clock timing differences between input classes at microsecond
//! resolution, over n=1000 samples per class, on whatever machine runs it. It does NOT provide:
//!   * cycle-accurate or single-trace evidence (wall-clock `Instant`, not a cycle counter or
//!     power trace);
//!   * microarchitectural evidence (cache-timing, port contention, branch-predictor state);
//!   * proof of constant-time-ness -- passing here means "no timing effect this test's power
//!     could resolve was observed today," not "this code is constant-time."
//!
//! Rejection-sampling variance inside Falcon's Gaussian sampler is expected and legitimate; the
//! Welch t-test compares MEANS across many samples, which is why that variance does not by
//! itself fail this check (a real secret-dependent leak still shifts the mean; pure per-call
//! jitter around a stable mean does not).
//!
//! AVX2: exercised whenever the runner has it (GitHub's ubuntu runners do); the `no_avx2` CI job
//! does not run this harness -- accepted, not covered by this wave.
//!
//! Card t_9d1766f3: the previous "constant-time" CI gate was a single sign per class compared
//! against a 500ms wall-clock bound (still present, relabeled, in
//! `tests/security_tests.rs::test_signing_latency_smoke` -- a livelock tripwire, not a
//! statistical check). This file is the real statistical replacement; see also
//! `lib-q-sca-test/src/lib.rs::welch_t_statistic`, whose formula is ported inline below (this
//! crate has no dependency on `lib-q-sca-test`).
//!
//! TIMING TESTS ARE MEANINGLESS IN DEBUG BUILDS. `cargo test` alone builds in debug, where bounds
//! checks and unoptimized codegen dominate the wall-clock signal. Both tests below are
//! `#[ignore]`d under `debug_assertions` (a compile-time check, so it applies regardless of how
//! the test binary is invoked). Run for real with:
//!
//!   cargo test -p lib-q-fn-dsa --profile release-ci --test constant_time -- --nocapture
//!
//! (`release-ci` inherits `release` -- see the profile's own comment in the workspace
//! `Cargo.toml` -- so `debug_assertions` is off and the tests actually execute.)

use std::io::Write as _;

use lib_q_fn_dsa::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
type MeasureResult = std::result::Result<(f64, f64, f64), Box<dyn std::error::Error>>;

/// Samples per input class. `FnDsa512::sign` is sub-millisecond in a release build, so 1000
/// iterations per class (2000 total per test) completes in a few seconds while giving the Welch
/// t-test enough power to resolve a real mean shift against typical CI-runner noise.
const ITERS: usize = 1000;

/// Pinned Welch |t| gate, same convention as `lib-q-hqc/tests/reed_solomon_constant_time.rs`:
/// chosen above the observed no-leak noise floor and far below the signal a real timing leak of
/// this kind would produce. See `security_tests.rs::welch_t_detects_synthetic_shift` for the
/// permanent proof this statistic can actually fail (a threshold this high is meaningless without
/// that separate proof).
///
/// MEASURED SENSITIVITY -- what a pass here does and does not rule out. Calibrated by injecting a
/// known busy-wait of N ns into the class-A timed region of `measure_key_class` and rerunning
/// (`--profile release-ci --test-threads=1`, one Windows dev box, `sign()` median ~265us,
/// OBSERVED 2026-08):
///
///   injected shift | resulting |t| | verdict at T=15
///   ---------------+---------------+----------------
///   0 (no leak)    | 0.74 .. 1.69  | pass  <- noise floor across all runs in this sweep
///   8us  (~3%)     | 4.86          | PASS -- NOT DETECTED
///   30us (~11%)    | 15.55         | fail (marginal -- this is the detection floor)
///   100us (~38%)   | 50.60         | fail
///   500us (~190%)  | 173.81        | fail
///
/// So this gate resolves a mean shift of roughly 10% of `sign()`'s runtime and nothing finer: it
/// catches a gross secret-dependent branch or an extra rejection-sampling round, and it does NOT
/// catch a few-microsecond (let alone a cache-line- or cycle-level) leak. Do not cite a pass here
/// as constant-time evidence beyond that resolution. Lowering the threshold toward the dudect
/// convention (4.5) would buy roughly 3x more resolution against this box's 1.69 noise floor, but
/// was NOT done: the noise floor on shared GitHub runners has not been measured here, and a
/// flaky timing gate gets muted, which is how the previous one ended up meaningless.
const T_THRESHOLD: f64 = 15.0;

/// Ported from `lib-q-sca-test/src/lib.rs::welch_t_statistic` (this crate has no dependency on
/// `lib-q-sca-test`, so the ~15-line formula is inlined rather than imported).
fn welch_t(a: &[f64], b: &[f64]) -> Option<f64> {
    let na = a.len() as f64;
    let nb = b.len() as f64;
    if na < 2.0 || nb < 2.0 {
        return None;
    }
    let mean_a = a.iter().sum::<f64>() / na;
    let mean_b = b.iter().sum::<f64>() / nb;
    let var_a = a.iter().map(|x| (x - mean_a).powi(2)).sum::<f64>() / (na - 1.0);
    let var_b = b.iter().map(|x| (x - mean_b).powi(2)).sum::<f64>() / (nb - 1.0);
    let se = (var_a / na + var_b / nb).sqrt();
    if se == 0.0 {
        return None;
    }
    Some((mean_a - mean_b) / se)
}

fn median(xs: &mut [f64]) -> f64 {
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = xs.len();
    if n.is_multiple_of(2) {
        (xs[n / 2 - 1] + xs[n / 2]) / 2.0
    } else {
        xs[n / 2]
    }
}

/// `cargo clippy` in this crate's CI denies `print_stdout`/`print_stderr` (i.e. the
/// `println!`/`eprintln!` macros), so diagnostics are written directly via `io::Write` instead --
/// that is not a macro call and is unaffected by either lint. Errors from writing to stderr are
/// deliberately ignored: this is best-effort diagnostic output, not the test outcome.
fn report(label: &str, t: f64, median_a: f64, median_b: f64) {
    let _ = writeln!(
        std::io::stderr(),
        "{label} sign() timing: n={ITERS} welch_t={t:.2} median_a={:.3}us median_b={:.3}us",
        median_a * 1e6,
        median_b * 1e6,
    );
}

/// Interleaves `sign(msg_a)` / `sign(msg_b)` under one keypair. Returns `(welch_t, median_a,
/// median_b)` in seconds.
fn measure_message_class(fn_dsa: &FnDsa512, sk: &SigSecretKey, iters: usize) -> MeasureResult {
    let msg_a = [0x4Au8; 64];
    let msg_b = [0xB3u8; 64];

    let mut samples_a = Vec::with_capacity(iters);
    let mut samples_b = Vec::with_capacity(iters);

    for _ in 0..iters {
        let start = std::time::Instant::now();
        let _sig_a = fn_dsa.sign(sk, &msg_a)?;
        samples_a.push(start.elapsed().as_secs_f64());

        let start = std::time::Instant::now();
        let _sig_b = fn_dsa.sign(sk, &msg_b)?;
        samples_b.push(start.elapsed().as_secs_f64());
    }

    let mut combined = samples_a.clone();
    combined.extend(samples_b.clone());
    let t = welch_t(&combined[..iters], &combined[iters..]).unwrap_or(0.0);
    Ok((t, median(&mut samples_a), median(&mut samples_b)))
}

/// Interleaves `sign(msg)` under two different keypairs. Returns `(welch_t, median_a,
/// median_b)` in seconds.
fn measure_key_class(
    fn_dsa: &FnDsa512,
    sk_a: &SigSecretKey,
    sk_b: &SigSecretKey,
    iters: usize,
) -> MeasureResult {
    let msg = [0x7Eu8; 64];

    let mut samples_a = Vec::with_capacity(iters);
    let mut samples_b = Vec::with_capacity(iters);

    for _ in 0..iters {
        let start = std::time::Instant::now();
        let _sig_a = fn_dsa.sign(sk_a, &msg)?;
        samples_a.push(start.elapsed().as_secs_f64());

        let start = std::time::Instant::now();
        let _sig_b = fn_dsa.sign(sk_b, &msg)?;
        samples_b.push(start.elapsed().as_secs_f64());
    }

    let mut combined = samples_a.clone();
    combined.extend(samples_b.clone());
    let t = welch_t(&combined[..iters], &combined[iters..]).unwrap_or(0.0);
    Ok((t, median(&mut samples_a), median(&mut samples_b)))
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "timing measurements are meaningless in debug builds; rerun with \
              `cargo test -p lib-q-fn-dsa --profile release-ci --test constant_time -- --nocapture`"
)]
fn constant_time_sign_message_class() -> TestResult {
    let fn_dsa = FnDsa512::new();
    let keypair = fn_dsa.generate_keypair()?;

    let (t, median_a, median_b) = measure_message_class(&fn_dsa, &keypair.secret_key, ITERS)?;
    report("message-class", t, median_a, median_b);

    assert!(
        t.abs() < T_THRESHOLD,
        "message-class sign() timing leak: |t|={:.2} exceeds threshold {:.2} \
         (n={ITERS}, median_a={:.3}us, median_b={:.3}us)",
        t.abs(),
        T_THRESHOLD,
        median_a * 1e6,
        median_b * 1e6,
    );
    Ok(())
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "timing measurements are meaningless in debug builds; rerun with \
              `cargo test -p lib-q-fn-dsa --profile release-ci --test constant_time -- --nocapture`"
)]
fn constant_time_sign_key_class() -> TestResult {
    let fn_dsa = FnDsa512::new();
    let keypair_a = fn_dsa.generate_keypair()?;
    let keypair_b = fn_dsa.generate_keypair()?;

    let (t, median_a, median_b) =
        measure_key_class(&fn_dsa, &keypair_a.secret_key, &keypair_b.secret_key, ITERS)?;
    report("key-class", t, median_a, median_b);

    assert!(
        t.abs() < T_THRESHOLD,
        "key-class sign() timing leak: |t|={:.2} exceeds threshold {:.2} \
         (n={ITERS}, median_a={:.3}us, median_b={:.3}us)",
        t.abs(),
        T_THRESHOLD,
        median_a * 1e6,
        median_b * 1e6,
    );
    Ok(())
}
