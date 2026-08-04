#![cfg(not(target_arch = "wasm32"))]
//! Dudect-style timing harness for `ReedSolomon::encode` (all HQC parameter sets).
//!
//! Gated off `wasm32` entirely: this file depends on `lib-q-sca-test`, which is a
//! `[target.'cfg(not(target_arch = "wasm32"))'.dev-dependencies]` dependency (it does not exist
//! on wasm32), and wall-clock timing measurement is meaningless in a wasm host anyway.
//!
//! Companion to `reed_solomon_constant_time.rs`, which covers `decode`. This one targets
//! `encode`'s LFSR loop (`lib-q-hqc/src/reed_solomon.rs`'s `ReedSolomon::encode`), which computes
//! `gate_value = message[k - 1 - i] ^ codeword[n1 - k - 1]` — directly derived from the message
//! byte being encoded — and then calls `self.gf_multiply(gate_value, poly_coef)` for every
//! generator-polynomial coefficient.
//!
//! `encode` sits on HQC's decapsulation re-encryption path: `Hqc::decapsulate` recovers a
//! candidate plaintext `m'` from the ciphertext and re-encrypts it (`pke.encrypt` ->
//! `concatenated_code.code_encode` -> `reed_solomon.encode`) to implicit-reject malformed
//! ciphertexts. So a secret-dependent timing leak in `encode` leaks bits of `m'` to anyone who can
//! submit chosen ciphertexts and time decapsulation — the same leak class `decode`'s early-return
//! fix already closed on the other side of the FO transform.
//!
//! Before this test existed, `gf_multiply` had `if a == 0 || b == 0 { return 0 }` ahead of two
//! table loads (`gf_log[a]`, `gf_log[b]`) and a third (`gf_exp[log_a + log_b]`) — a data-dependent
//! branch (plus secret-indexed loads) exercised once per generator-polynomial coefficient per
//! message byte. This harness compares `encode` timing over an all-zero-byte message (`gate_value`
//! is `0` on essentially every LFSR step, so the fast-return branch is taken almost every call)
//! against a message with no zero bytes at all (every `gf_multiply` call falls through to the
//! table-lookup path) — the encode-side analogue of the zero/nonzero-syndrome split `decode`'s
//! harness uses.
//!
//! TIMING TESTS ARE MEANINGLESS IN DEBUG BUILDS — see `reed_solomon_constant_time.rs`'s module
//! doc for why; the same `#[ignore]`-under-`debug_assertions` gating is used here. Run for real
//! with:
//!
//!   cargo test --release -p lib-q-hqc --test reed_solomon_encode_constant_time -- --nocapture

use lib_q_hqc::params_correct::{
    Hqc1Params,
    Hqc3Params,
    Hqc5Params,
    HqcParams,
};
use lib_q_hqc::reed_solomon::ReedSolomon;
use lib_q_sca_test::dudect::timing_t_statistic;

/// Samples per input class, per parameter set. See `reed_solomon_constant_time.rs` for the
/// rationale behind this magnitude.
const ITERS: usize = 8000;

/// Pinned Welch |t| gate — same threshold and rationale as `reed_solomon_constant_time.rs`.
const T_THRESHOLD: f64 = 15.0;

fn median(xs: &mut [f64]) -> f64 {
    xs.sort_by(|a, b| a.partial_cmp(b).expect("timings are finite"));
    let n = xs.len();
    if n.is_multiple_of(2) {
        (xs[n / 2 - 1] + xs[n / 2]) / 2.0
    } else {
        xs[n / 2]
    }
}

/// Times `ReedSolomon::<P>::encode` over two message classes: all-zero bytes (drives
/// `gate_value` to `0` on almost every LFSR step) and all-`0xFF` bytes (drives `gate_value`
/// nonzero on almost every step, since `codeword[n1-k-1]` starts at `0` and `0xFF ^ 0 = 0xFF`).
/// Returns `(welch_t, median_zero_secs, median_nonzero_secs)`.
fn measure<P: HqcParams>(iters: usize) -> (f64, f64, f64) {
    let rs = ReedSolomon::<P>::new().expect("ReedSolomon::new");
    let k = P::K;
    let n1 = P::N1;

    let zero_message = vec![0u8; k];
    let nonzero_message = vec![0xFFu8; k];
    let mut codeword = vec![0u8; n1];

    let mut zero_samples = Vec::with_capacity(iters);
    let mut nonzero_samples = Vec::with_capacity(iters);

    for _ in 0..iters {
        let start = std::time::Instant::now();
        rs.encode(&zero_message, &mut codeword)
            .expect("encode zero_message");
        zero_samples.push(start.elapsed().as_secs_f64());

        let start = std::time::Instant::now();
        rs.encode(&nonzero_message, &mut codeword)
            .expect("encode nonzero_message");
        nonzero_samples.push(start.elapsed().as_secs_f64());
    }

    // `timing_t_statistic` splits its input in half via `split_at(len / 2)`, so the sample
    // layout contract is: first `iters` samples are class A, next `iters` are class B — see
    // `reed_solomon_constant_time.rs` for the same note.
    let mut samples = zero_samples.clone();
    samples.extend(nonzero_samples.clone());
    let t = timing_t_statistic(&samples).expect("2*ITERS samples is well above the len<4 floor");

    let median_zero = median(&mut zero_samples);
    let median_nonzero = median(&mut nonzero_samples);

    (t, median_zero, median_nonzero)
}

macro_rules! constant_time_test {
    ($name:ident, $params:ty, $label:literal) => {
        #[test]
        #[cfg_attr(
            debug_assertions,
            ignore = "timing measurements are meaningless in debug builds; rerun with \
                      `cargo test --release -p lib-q-hqc --test reed_solomon_encode_constant_time`"
        )]
        fn $name() {
            let (t, median_zero, median_nonzero) = measure::<$params>(ITERS);
            eprintln!(
                "{} ReedSolomon::encode timing: n={} welch_t={:.2} \
                 median_zero_message={:.3}us median_nonzero_message={:.3}us",
                $label,
                ITERS,
                t,
                median_zero * 1e6,
                median_nonzero * 1e6
            );
            assert!(
                t.abs() < T_THRESHOLD,
                "{} Reed-Solomon encode timing leak: |t|={:.2} exceeds threshold {:.2} \
                 (n={}, median_zero_message={:.3}us, median_nonzero_message={:.3}us) -- \
                 encode()'s LFSR (gf_multiply) takes a data-dependent path on message bytes, \
                 which are secret plaintext on HQC's decapsulation re-encryption path",
                $label,
                t.abs(),
                T_THRESHOLD,
                ITERS,
                median_zero * 1e6,
                median_nonzero * 1e6
            );
        }
    };
}

constant_time_test!(reed_solomon_encode_constant_time_hqc1, Hqc1Params, "HQC-1");
constant_time_test!(reed_solomon_encode_constant_time_hqc3, Hqc3Params, "HQC-3");
constant_time_test!(reed_solomon_encode_constant_time_hqc5, Hqc5Params, "HQC-5");
