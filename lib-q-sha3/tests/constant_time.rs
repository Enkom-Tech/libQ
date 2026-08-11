//! Constant-time tests for SHA3 family algorithms
//!
//! These tests verify that SHA3 operations are constant-time to prevent
//! timing-based side-channel attacks.

mod common;

use std::sync::{
    Mutex,
    MutexGuard,
};
use std::time::{
    Duration,
    Instant,
};

use common::duration_min_max_nanos;
use digest::Digest;
use lib_q_sha3::{
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
};

#[cfg(not(tarpaulin))]
const TIMING_ITERATIONS: usize = 10_000;
#[cfg(tarpaulin)]
const TIMING_ITERATIONS: usize = 500;

#[cfg(not(tarpaulin))]
const TIMING_RUNS: usize = 9;
#[cfg(tarpaulin)]
const TIMING_RUNS: usize = 5;

#[cfg(not(tarpaulin))]
const TIMING_WARMUP: usize = 1_000;
#[cfg(tarpaulin)]
const TIMING_WARMUP: usize = 100;

#[cfg(not(tarpaulin))]
const TIMING_ATTEMPTS: usize = 3;
#[cfg(tarpaulin)]
const TIMING_ATTEMPTS: usize = 1;
const MAX_SPREAD_PERCENT: u128 = 80; // Max allowed spread over min, e.g. 80% => 1.8x ratio.

fn build_fixed_length_inputs(len: usize) -> Vec<Vec<u8>> {
    vec![
        vec![0u8; len],
        vec![0xFFu8; len],
        vec![0xA5u8; len],
        (0..len).map(|i| (i % 251) as u8).collect::<Vec<_>>(),
        (0..len)
            .map(|i| ((i.wrapping_mul(73) + 19) % 256) as u8)
            .collect::<Vec<_>>(),
    ]
}

fn trimmed_mean_duration<F>(op: F) -> Duration
where
    F: FnMut(),
{
    trimmed_mean_duration_with(TIMING_WARMUP, TIMING_ITERATIONS, op)
}

/// `trimmed_mean_duration` with an explicit measurement budget.
///
/// Callers whose operation is far more expensive than a single short hash need many fewer
/// iterations to average out noise; see `test_hash_algorithm_timing_relationships`.
fn trimmed_mean_duration_with<F>(warmup: usize, iterations: usize, mut op: F) -> Duration
where
    F: FnMut(),
{
    for _ in 0..warmup {
        op();
    }

    let mut run_times = Vec::with_capacity(TIMING_RUNS);
    for _ in 0..TIMING_RUNS {
        let start = Instant::now();
        for _ in 0..iterations {
            op();
        }
        run_times.push(start.elapsed());
    }

    run_times.sort_unstable();
    let trimmed = &run_times[1..run_times.len() - 1];
    trimmed.iter().copied().sum::<Duration>() / trimmed.len() as u32
}

fn timing_spread_is_within_limit(timings: &[Duration]) -> bool {
    let Some((min_ns, max_ns)) = duration_min_max_nanos(timings) else {
        return true;
    };

    // `max <= min * (1 + MAX_SPREAD_PERCENT/100)`.
    let rhs = min_ns * (100 + MAX_SPREAD_PERCENT);
    let lhs = max_ns * 100;
    lhs <= rhs
}

fn assert_timing_spread_with_retries<F>(label: &str, mut collect_timings: F)
where
    F: FnMut() -> Vec<Duration>,
{
    let mut last_failure: Option<(u128, u128, Vec<u128>)> = None;

    for attempt in 1..=TIMING_ATTEMPTS {
        let timings = collect_timings();
        let Some((min_ns, max_ns)) = duration_min_max_nanos(&timings) else {
            panic!("{label}: collect_timings returned no durations");
        };
        let timing_ns = timings
            .iter()
            .map(|duration| duration.as_nanos())
            .collect::<Vec<_>>();
        let ratio = max_ns as f64 / min_ns as f64;

        eprintln!(
            "{} timing attempt {}/{}: timings={:?} min={}ns max={}ns ratio={:.3}",
            label, attempt, TIMING_ATTEMPTS, timing_ns, min_ns, max_ns, ratio
        );

        if timing_spread_is_within_limit(&timings) {
            return;
        }

        last_failure = Some((min_ns, max_ns, timing_ns));
    }

    match last_failure {
        Some((min_ns, max_ns, timing_ns)) => panic!(
            "{} timing spread too high after {} attempts: timings={:?} min={}ns max={}ns allowed_ratio<=1.{}",
            label, TIMING_ATTEMPTS, timing_ns, min_ns, max_ns, MAX_SPREAD_PERCENT
        ),
        None => panic!(
            "{label} timing spread too high after {TIMING_ATTEMPTS} attempts (no timing samples recorded)"
        ),
    }
}

/// Serializes the three timing tests in this binary against each other.
///
/// libtest runs a test binary's tests on several threads at once, so without this the two
/// spread tests -- which each hash tens of thousands of times -- are still running while
/// `test_hash_algorithm_timing_relationships` takes its measurements. That test's own doc
/// records what this does to it: SHA3-384 measured 1.667x SHA3-256 against a 1.290x block-count
/// prediction, i.e. the measurement moved further than the quantity being measured. It was then
/// hardened twice (interleaving the variants, then min-of-45-rounds) and it STILL failed a
/// scheduled run on 2026-08-11 at `RELATION_TOLERANCE = 0.25`.
///
/// Interleaving and min-of-N make the estimator robust to load; they cannot remove load that is
/// present for every round. This removes it. Taking the lock is cheap next to what these tests
/// already spend, and it changes no threshold -- widening the tolerance instead would have made
/// the test pass by making it measure less.
static TIMING_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Acquire [`TIMING_TEST_LOCK`], ignoring poisoning.
///
/// A panicking test poisons the mutex. Poisoning here carries no data-integrity meaning -- the
/// guarded state is `()` -- so recovering keeps one assertion failure from cascading into two
/// unrelated `PoisonError` failures that would obscure it.
fn timing_lock() -> MutexGuard<'static, ()> {
    TIMING_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Test that SHA3-224 operations have similar timing for equal-length inputs.
#[test]
fn test_sha3_224_constant_time() {
    let _serialized = timing_lock();
    let test_inputs = build_fixed_length_inputs(128);
    assert_timing_spread_with_retries("SHA3-224", || {
        let mut timings = Vec::new();
        for input in &test_inputs {
            let timing = trimmed_mean_duration(|| {
                let mut hasher = Sha3_224::new();
                hasher.update(input);
                let _result = hasher.finalize();
                std::hint::black_box(_result);
            });
            timings.push(timing);
        }
        timings
    });
}

/// Test that SHA3-256 operations have similar timing for equal-length inputs.
#[test]
fn test_sha3_256_constant_time() {
    let _serialized = timing_lock();
    let test_inputs = build_fixed_length_inputs(128);
    assert_timing_spread_with_retries("SHA3-256", || {
        let mut timings = Vec::new();
        for input in &test_inputs {
            let timing = trimmed_mean_duration(|| {
                let mut hasher = Sha3_256::new();
                hasher.update(input);
                let _result = hasher.finalize();
                std::hint::black_box(_result);
            });
            timings.push(timing);
        }
        timings
    });
}

/// Sponge rates in bytes (FIPS 202 §6.1: `rate = 200 - 2 * digest_len`). These match the
/// `SpongeHasherCore<Rate, _, _>` parameters in `lib-q-sha3/src/lib.rs`.
const RATE_SHA3_224: usize = 144;
const RATE_SHA3_256: usize = 136;
const RATE_SHA3_384: usize = 104;
const RATE_SHA3_512: usize = 72;

/// Input length for [`test_hash_algorithm_timing_relationships`]. Must be several blocks wide
/// at every rate above, so the measurement is dominated by permutations and not by fixed
/// per-call overhead.
const RELATION_INPUT_LEN: usize = 4096;

/// Iterations inside one timed window in [`measure_variants`]: far smaller than
/// `TIMING_ITERATIONS` because each hash there is 29-57 permutations rather than one.
///
/// Deliberately small. See [`RELATION_ROUNDS`] — the product of the two is the measurement
/// budget, and how it is split between them decides whether the minimum estimator works.
#[cfg(not(tarpaulin))]
const RELATION_ITERATIONS: usize = 20;
#[cfg(tarpaulin)]
const RELATION_ITERATIONS: usize = 5;
#[cfg(not(tarpaulin))]
const RELATION_WARMUP: usize = 20;
#[cfg(tarpaulin)]
const RELATION_WARMUP: usize = 2;

/// Rounds of the interleaved measurement in [`measure_variants`].
///
/// # Why many short rounds and not a few long ones
///
/// `measure_variants` reports each variant's *fastest* round, which is only a good estimate of
/// the underlying operation if at least one round ran without interference. The chance a given
/// round is clean falls as its window widens, so a wide window spends the whole budget on
/// samples that are all polluted — and it does so unevenly, because the four windows are not
/// the same width. SHA3-512 absorbs the most blocks, so its window is the widest and it is the
/// likeliest of the four to never see a clean round; a ratio taken against SHA3-256 then reads
/// as a violated relationship when nothing about SHA-3 changed.
///
/// That is the observed failure, not a hypothetical one. At 100 iterations x 9 rounds, CI run
/// 31262247680 measured SHA3-512 at 107183ns per absorbed block while 224/256/384 sat at
/// 87430/82658/84717 — a 512-only inflation of ~30%, which pushed the 512:256 ratio to 2.384
/// against a block-count prediction of 1.839 and a +-25% band topping out at 2.298.
///
/// The budget per variant is unchanged (`ITERATIONS * ROUNDS` = 900 hashes, as before); it is
/// only split differently. That narrows the widest window from ~6.5ms to ~1.3ms and raises the
/// number of chances at a clean one from 9 to 45.
#[cfg(not(tarpaulin))]
const RELATION_ROUNDS: usize = 45;
#[cfg(tarpaulin)]
const RELATION_ROUNDS: usize = 6;

/// Allowed deviation from the block-count ratio, absorbing per-call overhead and CI noise.
///
/// Sized to stay meaningful rather than to make the test pass: a variant wired to the wrong
/// rate lands at ratio 1.000, which is outside every band this tolerance produces below.
const RELATION_TOLERANCE: f64 = 0.25;

/// Number of blocks absorbed for a `len`-byte message at sponge rate `rate`.
///
/// `pad10*1` appends at least one byte, so a message that is an exact multiple of the rate
/// still starts one further block — hence `+ 1` unconditionally rather than a `div_ceil`.
const fn absorbed_blocks(len: usize, rate: usize) -> usize {
    len / rate + 1
}

/// Assert that `label`'s time relative to SHA3-256 tracks their ratio of absorbed blocks.
fn assert_ratio_tracks_blocks(
    label: &str,
    time: Duration,
    blocks: usize,
    reference_time: Duration,
    reference_blocks: usize,
) {
    let expected = blocks as f64 / reference_blocks as f64;
    let observed = time.as_nanos() as f64 / reference_time.as_nanos() as f64;
    let low = expected * (1.0 - RELATION_TOLERANCE);
    let high = expected * (1.0 + RELATION_TOLERANCE);

    assert!(
        observed >= low && observed <= high,
        "{label} vs SHA3-256: {} bound violated. Expected a time ratio near {expected:.3} \
         ({blocks} absorbed blocks vs {reference_blocks}); tolerance ±{:.0}% gives \
         [{low:.3}, {high:.3}]; measured {observed:.3}.",
        if observed < low { "lower" } else { "upper" },
        RELATION_TOLERANCE * 100.0,
    );
}

/// Time `iterations` calls of `op` as a single span.
fn time_iterations<F>(iterations: usize, mut op: F) -> Duration
where
    F: FnMut(),
{
    let start = Instant::now();
    for _ in 0..iterations {
        op();
    }
    start.elapsed()
}

/// Measure all four SHA3 variants over `input`, returned in the order `[224, 256, 384, 512]`.
///
/// # Why the variants are interleaved, and why the minimum round wins
///
/// The other two tests in this binary each hash tens of thousands of times, and libtest runs
/// them on other threads concurrently with this one. A variant measured while they are still
/// running is therefore timed under a heavier load than one measured after they finish, so
/// timing the four variants once each, one after another, compares them under *different*
/// conditions. That is not hypothetical: measured that way on a loaded machine, SHA3-384 came
/// out at 1.667x SHA3-256, where its block count predicts 1.290x — the measurement moved far
/// more than the quantity being measured.
///
/// Each round therefore times all four variants back to back, so a load spike landing inside a
/// round hits all four roughly equally, and each variant's reported time is its fastest round.
/// The minimum is the right estimator rather than a mean or a trimmed mean: contention,
/// scheduling and frequency scaling can only ever make a sample slower than the underlying
/// operation, never faster, so the fastest round is the least polluted one.
fn measure_variants(input: &[u8]) -> [Duration; 4] {
    for _ in 0..RELATION_WARMUP {
        std::hint::black_box(Sha3_224::digest(std::hint::black_box(input)));
        std::hint::black_box(Sha3_256::digest(std::hint::black_box(input)));
        std::hint::black_box(Sha3_384::digest(std::hint::black_box(input)));
        std::hint::black_box(Sha3_512::digest(std::hint::black_box(input)));
    }

    let mut best = [Duration::MAX; 4];
    for _ in 0..RELATION_ROUNDS {
        let round = [
            time_iterations(RELATION_ITERATIONS, || {
                std::hint::black_box(Sha3_224::digest(std::hint::black_box(input)));
            }),
            time_iterations(RELATION_ITERATIONS, || {
                std::hint::black_box(Sha3_256::digest(std::hint::black_box(input)));
            }),
            time_iterations(RELATION_ITERATIONS, || {
                std::hint::black_box(Sha3_384::digest(std::hint::black_box(input)));
            }),
            time_iterations(RELATION_ITERATIONS, || {
                std::hint::black_box(Sha3_512::digest(std::hint::black_box(input)));
            }),
        ];
        for (slot, sample) in best.iter_mut().zip(round) {
            *slot = (*slot).min(sample);
        }
    }

    best
}

/// Test that the SHA3 variants' timings track their sponge rates.
///
/// # Why this measures a multi-block input
///
/// This test used to hash the 30-byte string `b"test input for timing analysis"`, which is
/// shorter than every rate above, so **all four variants performed exactly one
/// Keccak-f\[1600\]**. With the permutation count identical, the measured ratio was decided
/// entirely by fixed per-call overhead — a property of the build and the machine, not of
/// SHA-3. Identical, correct code measured `SHA3-512 / SHA3-256` at 0.96 on a Windows debug
/// build and at 0.494 and 0.496 on two ubuntu CI jobs of the same commit (CI run
/// 31229311589), and the latter tripped the old `ratio > 0.5` lower bound. A bound that
/// correct code fails on one platform and passes on another is not measuring correctness.
/// That 30-byte input was also a compile-time constant re-hashed in a loop, making the whole
/// computation loop-invariant and so eligible to be hoisted out of the timed region.
///
/// Both are fixed here: the input is built at runtime and passed through `black_box` on every
/// iteration, and it spans many blocks so that permutation count dominates. That count is
/// fixed by FIPS 202 — a variant with rate `r` absorbs [`absorbed_blocks`] of them, and each
/// variant's digest is squeezed from the first output block, so no variant permutes again to
/// squeeze. The expected time ratio between two variants is therefore their block-count
/// ratio, which is a property of SHA-3 itself and holds on any machine.
#[test]
fn test_hash_algorithm_timing_relationships() {
    let _serialized = timing_lock();
    // Built at runtime, and fed through `black_box` at every call below, so that the hash
    // cannot be treated as loop-invariant and lifted out of the measurement loop.
    let test_input: Vec<u8> = (0..RELATION_INPUT_LEN).map(|i| (i % 251) as u8).collect();

    let [sha3_224_time, sha3_256_time, sha3_384_time, sha3_512_time] =
        measure_variants(&test_input);

    let blocks_224 = absorbed_blocks(RELATION_INPUT_LEN, RATE_SHA3_224);
    let blocks_256 = absorbed_blocks(RELATION_INPUT_LEN, RATE_SHA3_256);
    let blocks_384 = absorbed_blocks(RELATION_INPUT_LEN, RATE_SHA3_384);
    let blocks_512 = absorbed_blocks(RELATION_INPUT_LEN, RATE_SHA3_512);

    eprintln!(
        "timing relationships over {RELATION_INPUT_LEN} bytes: 224={}ns/{blocks_224}blk \
         256={}ns/{blocks_256}blk 384={}ns/{blocks_384}blk 512={}ns/{blocks_512}blk",
        sha3_224_time.as_nanos(),
        sha3_256_time.as_nanos(),
        sha3_384_time.as_nanos(),
        sha3_512_time.as_nanos()
    );

    // SHA3-512 has the smallest rate (72 bytes), so it absorbs the most blocks and must be the
    // slowest of the four on a multi-block message — the reverse of the single-block case.
    assert_ratio_tracks_blocks(
        "SHA3-512",
        sha3_512_time,
        blocks_512,
        sha3_256_time,
        blocks_256,
    );
    assert_ratio_tracks_blocks(
        "SHA3-384",
        sha3_384_time,
        blocks_384,
        sha3_256_time,
        blocks_256,
    );
    assert_ratio_tracks_blocks(
        "SHA3-224",
        sha3_224_time,
        blocks_224,
        sha3_256_time,
        blocks_256,
    );
}
