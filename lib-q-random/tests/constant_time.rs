//! Constant-time tests for lib-q-random's own seed-expansion path.
//!
//! Most of the heavy cryptographic primitives this crate wires together (KT128 in
//! lib-q-k12, Saturnin in lib-q-saturnin) already carry their own dedicated
//! constant-time suites in their respective crates. What lives directly in THIS
//! crate is [`Kt128Expander`]: the buffer/counter bookkeeping that turns a 32-byte
//! seed -- which callers use as a deterministic-RNG seed or a ZK hiding salt, i.e.
//! potentially secret material -- into an output byte stream (see
//! `kt128_rng.rs`, `saturnin_det.rs`'s `DOMAIN_LIBQ_DET_SATURNIN` nonce derivation,
//! and every `Kt128Expander::from_seed_32` call site).
//!
//! That bookkeeping is plain `copy_from_slice`/index arithmetic with no
//! seed-dependent branch, so there is nothing implementation-specific to defeat --
//! but "nothing to defeat" is exactly the property a timing test should be able to
//! observe from the outside, on the crate's actual public API, rather than assumed
//! from reading the source. This is a coarse wall-clock smoke test (see
//! `lib-q-k12/tests/constant_time.rs` for the same caveat spelled out in full): a
//! pass here is not a side-channel proof, only a check that the property has not
//! regressed to something *visibly* data-dependent (e.g. a future`Vec`-growth path
//! keyed off seed content, or a debug/logging branch on seed bytes).

use std::time::{
    Duration,
    Instant,
};

use lib_q_random::{
    DOMAIN_LIBQ_DET_RNG,
    Kt128Expander,
};

const ITERATIONS: usize = 2_000;

/// How many times each measurement is repeated before a timing is accepted (see
/// `lib-q-k12/tests/constant_time.rs::min_time` for the rationale: the minimum over
/// repeated samples is the maximum-likelihood estimate of true cost on a noisy
/// shared CI runner, so taking it makes the assertion stricter, not looser).
const REPS: usize = 7;

fn min_time(iterations: usize, mut op: impl FnMut()) -> Duration {
    let mut best = Duration::MAX;
    for _ in 0..REPS {
        let start = Instant::now();
        for _ in 0..iterations {
            op();
        }
        let elapsed = start.elapsed();
        if elapsed < best {
            best = elapsed;
        }
    }
    best
}

/// Fixed-length seeds, differing only in content, must expand in indistinguishable time.
#[test]
fn test_seed_expansion_constant_time() {
    let seeds: [[u8; 32]; 4] = [
        [0x00; 32],
        [0xFF; 32],
        core::array::from_fn(|i| (i as u8).wrapping_mul(251)),
        core::array::from_fn(|i| ((i as u32).wrapping_mul(73).wrapping_add(19) % 256) as u8),
    ];

    // Warm up.
    for _ in 0..500 {
        let mut expander = Kt128Expander::from_seed_32(DOMAIN_LIBQ_DET_RNG, seeds[0]);
        let mut out = [0u8; 64];
        expander.fill_bytes(&mut out);
        std::hint::black_box(out);
    }

    let mut times = Vec::with_capacity(seeds.len());
    for seed in &seeds {
        times.push(min_time(ITERATIONS, || {
            let mut expander = Kt128Expander::from_seed_32(DOMAIN_LIBQ_DET_RNG, *seed);
            let mut out = [0u8; 64];
            expander.fill_bytes(&mut out);
            std::hint::black_box(out);
        }));
    }

    let avg_time = times.iter().sum::<Duration>() / times.len() as u32;
    let tolerance = avg_time * 60 / 100; // 60% band: same rationale as lib-q-k12's tests.

    for (i, time) in times.iter().enumerate() {
        let diff = (*time).abs_diff(avg_time);
        assert!(
            diff <= tolerance,
            "seed {} expansion timing {}ns differs too much from average {}ns (diff {}ns, tolerance {}ns)",
            i,
            time.as_nanos(),
            avg_time.as_nanos(),
            diff.as_nanos(),
            tolerance.as_nanos()
        );
    }
}

/// Same property once `fill_bytes` is asked for more than the 32-byte internal buffer, forcing
/// at least one `refill()` (the counter-chained XOF step) -- content must still not leak.
#[test]
fn test_seed_expansion_with_refill_constant_time() {
    let seeds: [[u8; 32]; 3] = [
        [0x11; 32],
        [0x22; 32],
        core::array::from_fn(|i| (i as u8) ^ 0x5A),
    ];

    // 96 bytes > the 32-byte buffer, so this always exercises at least one refill().
    const OUT_LEN: usize = 96;

    // Warm up.
    for _ in 0..300 {
        let mut expander = Kt128Expander::from_seed_32(DOMAIN_LIBQ_DET_RNG, seeds[0]);
        let mut out = [0u8; OUT_LEN];
        expander.fill_bytes(&mut out);
        std::hint::black_box(out);
    }

    let mut times = Vec::with_capacity(seeds.len());
    for seed in &seeds {
        times.push(min_time(ITERATIONS, || {
            let mut expander = Kt128Expander::from_seed_32(DOMAIN_LIBQ_DET_RNG, *seed);
            let mut out = [0u8; OUT_LEN];
            expander.fill_bytes(&mut out);
            std::hint::black_box(out);
        }));
    }

    let avg_time = times.iter().sum::<Duration>() / times.len() as u32;
    let tolerance = avg_time * 60 / 100;

    for (i, time) in times.iter().enumerate() {
        let diff = (*time).abs_diff(avg_time);
        assert!(
            diff <= tolerance,
            "seed {} refill-path timing {}ns differs too much from average {}ns (diff {}ns, tolerance {}ns)",
            i,
            time.as_nanos(),
            avg_time.as_nanos(),
            diff.as_nanos(),
            tolerance.as_nanos()
        );
    }
}
