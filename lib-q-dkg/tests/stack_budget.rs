//! Stack-budget regression: the BDLOP/DKG ceremony must run on a **normal** thread stack.
//!
//! Background. `Rq` is `[i64; N=1024]` ≈ 8 KiB held inline, so an inline `[Rq; KAPPA=9]` block is a
//! ~72 KiB stack temporary. Earlier code built those blocks (`combined` in `bdlop::phi` /
//! `recompute_w`) on the stack *live across* the deep `b0_apply → ring_mul → ntt` call chain, which
//! could overflow the OS-default thread stack (1 MiB on Windows). Downstream ceremony runners worked
//! around it by spawning `run_ceremony()` on a dedicated `std::thread` with a **64 MiB** stack — a
//! band-aid in the caller for a working-set-placement bug in this crate.
//!
//! The fix moves the BDLOP working set off the stack (heap-backed `Vec<Rq>` accumulators). These
//! tests pin that fix: they drive the real Round-1 commit + share-evaluation (prover) + share
//! verification — the exact path that overflowed — inside a thread whose stack is a small fraction of
//! the retired 64 MiB band-aid, and assert it completes without a stack overflow.
//!
//! NOTE on platform semantics: a guard-page stack overflow *aborts the whole process* (Windows
//! `STATUS_STACK_OVERFLOW`); it cannot be caught by `JoinHandle::join`. So "ran within budget B" is
//! observed as "the test binary did not abort". The fixed regression budgets below are chosen with
//! headroom in the (pessimistic) unoptimized `cargo test` profile; release frames are far smaller.
//!
//! The peak frame is essentially independent of `(n, t)`: the only large stack temporaries are the
//! `KAPPA`-sized BDLOP blocks, not the `t`-length polynomial (which lives on the heap). So a modest
//! committee exercises the same worst-case frame depth as a full one.

// `common` also defines `PARTIES`/`THRESHOLD` used by sibling test binaries; only `det_rng` is
// needed here (this path deliberately exercises its own committee size), so silence the per-binary
// dead-code lint for the unused fixtures.
#[allow(dead_code)]
mod common;

use common::det_rng;
use lib_q_dkg::{
    dkg_eval_share,
    dkg_round1_commit,
    dkg_verify_share,
    setup,
};

/// One full prover+verifier pass through the BDLOP-heavy ceremony path. Returns `true` iff the
/// binding share verifies — i.e. the deep `prove_share`/`recompute_w` chain ran to completion.
fn run_ceremony_once() -> bool {
    let profile = setup();
    let parties: u8 = 7;
    let threshold: u8 = 5;
    let dealer: u8 = 1;
    let recipient: u8 = 4;

    let mut rng = det_rng(0xA5);
    let (poly, commitments) = dkg_round1_commit(&profile, parties, threshold, dealer, &mut rng)
        .expect("round-1 commit must succeed");
    let share = dkg_eval_share(&poly, recipient, &mut rng).expect("share evaluation must succeed");
    dkg_verify_share(&commitments, dealer, recipient, &share)
}

/// Run `run_ceremony_once` on a thread with `stack_bytes` of stack and require it to finish and
/// verify. A stack overflow aborts the process (so the test fails by abnormal exit); any other panic
/// is surfaced via `join`.
fn assert_runs_within(stack_bytes: usize, label: &str) {
    let handle = std::thread::Builder::new()
        .name(format!("dkg-stack-budget-{label}"))
        .stack_size(stack_bytes)
        .spawn(run_ceremony_once)
        .expect("thread spawn");
    let verified = handle
        .join()
        .unwrap_or_else(|_| panic!("DKG ceremony panicked on the {label} stack budget"));
    assert!(verified, "share failed to verify on the {label} stack budget");
}

/// Primary regression guard: the ceremony runs on the **OS-default 1 MiB stack** (the size the
/// dedicated 64 MiB thread existed to avoid). Passing here means the band-aid is retired — a normal
/// thread suffices.
///
/// Measured floor (unoptimized `cargo test` profile, this machine): overflow at 640 KiB, success at
/// 768 KiB, so the 1 MiB budget carries ≈1.4× headroom in the pessimistic debug build; release frames
/// are smaller still. Before the heap-backed-working-set fix this path overflowed a 1 MiB stack.
#[test]
fn ceremony_runs_on_one_mib_stack() {
    assert_runs_within(1024 * 1024, "1MiB");
}

/// Manual probe (ignored by default): budget comes from `DKG_STACK_KIB` (default 2048 KiB). Use to
/// re-measure the peak across debug/release, e.g.
/// `DKG_STACK_KIB=768 cargo test -p lib-q-dkg --test stack_budget -- --ignored probe`.
#[test]
#[ignore = "manual stack-floor probe; set DKG_STACK_KIB"]
#[allow(clippy::disallowed_methods)] // env read is intentional for this manual probe harness only
fn probe_configurable_stack() {
    let kib: usize = std::env::var("DKG_STACK_KIB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2048);
    assert_runs_within(kib * 1024, &format!("{kib}KiB-probe"));
}
