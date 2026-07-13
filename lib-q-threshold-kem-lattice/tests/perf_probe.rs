//! One-shot performance probe (`#[ignore]`d — run on demand, not in CI):
//! `cargo test -p lib-q-threshold-kem-lattice --release --test perf_probe -- --ignored --nocapture`
//!
//! Reports wall time for encapsulation / reference decapsulation / masked partial, plus an
//! apples-to-apples comparison of the NTT-domain inner product against the pre-audit
//! per-term-`ring_mul` formulation it replaced (2026-07 hardening pass).

use std::time::Instant;

use lib_q_dkg::lattice::ring::{
    Rq,
    ring_add,
    ring_mul,
};
use lib_q_random::new_deterministic_rng;
use lib_q_threshold_kem_lattice::threshold::{
    ZeroShareSeeds,
    partial_decap_masked,
};
use lib_q_threshold_kem_lattice::{
    decapsulate_reference,
    encapsulate,
    kem,
    keygen_shares,
    setup,
};

const THRESHOLD: u8 = 3;
const PARTIES: u8 = 5;
const ITERS: u32 = 20;

/// The pre-audit inner product: one full `ring_mul` (2 fwd + 1 inv NTT) per term.
fn ring_inner_naive(a: &[Rq], b: &[Rq]) -> Rq {
    let mut acc = Rq::zero();
    for (ai, bi) in a.iter().zip(b.iter()) {
        acc = ring_add(&acc, &ring_mul(ai, bi));
    }
    acc
}

#[test]
#[ignore = "perf probe: run with --ignored --nocapture"]
fn perf_probe() {
    let profile = setup();
    let mut rng = new_deterministic_rng([0xB7u8; 32]);
    let keygen = keygen_shares(&profile, THRESHOLD, PARTIES, &mut rng).expect("keygen");
    let (_ss, ct) = encapsulate(&keygen.public_key, &mut rng).expect("encap");
    let shares = &keygen.secret_shares[..usize::from(THRESHOLD)];
    let subset: Vec<u8> = shares.iter().map(|s| s.index).collect();
    let seeds = ZeroShareSeeds::setup(PARTIES, &mut rng);
    let t0 = keygen.public_key.t0().expect("t0");

    let t = Instant::now();
    for _ in 0..ITERS {
        let _ = encapsulate(&keygen.public_key, &mut rng).expect("encap");
    }
    println!(
        "encapsulate:            {:>8.1} µs",
        t.elapsed().as_secs_f64() * 1e6 / f64::from(ITERS)
    );

    let t = Instant::now();
    for _ in 0..ITERS {
        let _ = decapsulate_reference(&keygen.public_key, shares, &ct).expect("decap");
    }
    println!(
        "decapsulate_reference:  {:>8.1} µs",
        t.elapsed().as_secs_f64() * 1e6 / f64::from(ITERS)
    );

    let t = Instant::now();
    for _ in 0..ITERS {
        let _ = partial_decap_masked(&shares[0], &subset, &ct, &seeds, &mut rng).expect("partial");
    }
    println!(
        "partial_decap_masked:   {:>8.1} µs",
        t.elapsed().as_secs_f64() * 1e6 / f64::from(ITERS)
    );

    // Inner-product core, old vs new formulation on identical inputs (KAPPA = 9 terms, as in
    // ⟨rand, p⟩). Results must be identical; only the transform count differs.
    assert_eq!(
        ring_inner_naive(&t0, &t0[..]),
        kem::ring_inner(&t0, &t0[..])
    );
    let t = Instant::now();
    for _ in 0..ITERS {
        let _ = ring_inner_naive(&ct.p, &ct.p);
    }
    let naive = t.elapsed().as_secs_f64() * 1e6 / f64::from(ITERS);
    let t = Instant::now();
    for _ in 0..ITERS {
        let _ = kem::ring_inner(&ct.p, &ct.p);
    }
    let ntt_domain = t.elapsed().as_secs_f64() * 1e6 / f64::from(ITERS);
    println!("ring_inner (9 terms):   {naive:>8.1} µs naive per-term ring_mul");
    println!(
        "ring_inner (9 terms):   {ntt_domain:>8.1} µs NTT-domain accumulation ({:.2}x)",
        naive / ntt_domain
    );
}
