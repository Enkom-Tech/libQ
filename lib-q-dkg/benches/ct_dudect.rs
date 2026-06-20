//! Constant-time **measurement** (dudect) for the two secret-dependent components named in
//! `lib-q-threshold-raccoon/SECURITY_ANALYSIS.md` §8. This complements the construction-level review
//! and the equivalence unit-tests with a statistical timing-leakage test (Welch/dudect t-statistic).
//!
//! Run (quiet, core-pinned host recommended):
//! ```text
//!   taskset -c 3 cargo bench -p lib-q-dkg --bench ct_dudect -- --filter secret_sampler
//!   taskset -c 3 cargo bench -p lib-q-dkg --bench ct_dudect -- --filter ring_reduce
//! ```
//! dudect reports `max t = …`; the leakage rule of thumb is `|t| < 10` (no leakage detected) —
//! a CT routine should keep `|t|` bounded as sample count grows, a leaky one diverges.
//!
//! Two classes per test (the dudect Left/Right design):
//! * **Left**  = a *fixed* seed ⇒ the routine walks one deterministic value/path every run.
//! * **Right** = a *random* seed ⇒ values vary across the routine's full output range.
//!
//! If timing depended on the secret value (data-dependent branch, early-out, table index, …) the
//! Right class would diverge from Left. Constant-time ⇒ the two distributions stay indistinguishable.

use dudect_bencher::rand::{
    Rng,
    RngExt,
};
use dudect_bencher::{
    BenchRng,
    Class,
    CtRunner,
    ctbench_main,
};
use lib_q_dkg::lattice::gaussian::sample_secret_coeff_ct;
use lib_q_dkg::lattice::ring::{
    Rq,
    ring_mul,
    sample_in_ball,
    sample_secret_poly,
};
use lib_q_random::new_deterministic_rng;

/// How many primitive ops to fold into one timed sample (amplifies a per-op signal above the
/// measurement-noise floor without changing the leakage verdict).
const FOLD: usize = 256;
/// Number of timed samples per run.
const SAMPLES: usize = 100_000;

fn rand_seed(rng: &mut BenchRng) -> [u8; 32] {
    let mut s = [0u8; 32];
    rng.fill_bytes(&mut s);
    s
}

/// Component 1: the constant-time CDT secret base sampler (`sample_secret_coeff_ct`).
/// Left  = fixed seed (same coefficient sequence each run);
/// Right = random seed (coefficients span the CDT's full magnitude range).
fn bench_secret_sampler(runner: &mut CtRunner, rng: &mut BenchRng) {
    const FIXED: [u8; 32] = [0x42; 32];
    let mut classes = Vec::with_capacity(SAMPLES);
    let mut seeds = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        if rng.random::<bool>() {
            classes.push(Class::Left);
            seeds.push(FIXED);
        } else {
            classes.push(Class::Right);
            seeds.push(rand_seed(rng));
        }
    }
    for (seed, class) in seeds.into_iter().zip(classes) {
        // `run_one` takes a `Fn` closure, so use a RefCell for the sampler's interior RNG mutation.
        let cell = core::cell::RefCell::new(new_deterministic_rng(seed));
        runner.run_one(class, || {
            let mut r = cell.borrow_mut();
            let mut acc = 0i64;
            for _ in 0..FOLD {
                acc = acc.wrapping_add(sample_secret_coeff_ct(&mut *r));
            }
            acc
        });
    }
}

/// Component 2: the branchless ring reduction (`mont_reduce`/`modadd`/`modsub`) exercised through
/// `ring_mul(challenge, secret)` — the secret·challenge products the signer computes.
/// Left  = fixed secret polynomial; Right = random secret polynomial (challenge fixed for both).
fn bench_ring_reduce(runner: &mut CtRunner, rng: &mut BenchRng) {
    let challenge: Rq = sample_in_ball(&[0x11; 32], 22);
    const FIXED: [u8; 32] = [0x42; 32];
    let mut classes = Vec::with_capacity(SAMPLES);
    let mut secrets: Vec<Rq> = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let seed = if rng.random::<bool>() {
            classes.push(Class::Left);
            FIXED
        } else {
            classes.push(Class::Right);
            rand_seed(rng)
        };
        let mut r = new_deterministic_rng(seed);
        secrets.push(sample_secret_poly(&mut r));
    }
    for (secret, class) in secrets.into_iter().zip(classes) {
        runner.run_one(class, || ring_mul(&challenge, &secret));
    }
}

ctbench_main!(bench_secret_sampler, bench_ring_reduce);
