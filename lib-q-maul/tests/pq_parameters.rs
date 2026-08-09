//! EVIDENCE 2 — the concrete parameter choice, and where its post-quantum number comes from.
//!
//! The operator's bar (card t_5bc0f630, 2026-08-09) is: "verify the concrete parameter choice
//! gives >= 128-bit POST-QUANTUM security, not classical, and record the estimator basis". Not
//! "it is PQ because lattices are PQ".
//!
//! # The basis, in full
//!
//! 1. **The problem.** Maul's security rests on MLWE and **Hint-MLWE** (ePrint 2025/1755 §5.2,
//!    Theorem 5). Hint-MLWE, not plain MLWE: when an adversary holds one side's secret, the other
//!    side's scalar leaks a known noisy linear relation about the shared randomness (§1.2 p6,
//!    §5.5 p21). Estimating this as if it were plain MLWE would overstate the security, which is
//!    why the operative column below is the hint-adjusted one.
//!
//! 2. **The blocksize.** Table 6 (§5.5, p21) reports BKZ blocksizes from the leaky-LWE estimator
//!    of Ducas et al. [18] (<https://github.com/lducas/leaky-LWE-Estimator>), run with the
//!    approximate hint `z = H(s,e) + y`, `H = (e_L^T, -s_L^T)`, `y = f_L`. Three columns:
//!    * `PrimalLWE_sigma1` — plain MLWE at the same width. An **upper** bound.
//!    * `PrimalLWE_SigmaHints` — residual security **with** the hint. **This is the operative one.**
//!    * `PrimalLWE_(sigma1/sqrt2)` — the paper's own conservative **lower** bound.
//!
//! 3. **Blocksize to bits.** §5.4: "assessed via the core-SVP cost model [1] ... applying the
//!    complexity of the best known sieving algorithms -- both classical and quantum [6,14] -- to
//!    this block size, deliberately omitting polynomial factors". The standard core-SVP exponents
//!    are `0.292*beta` classical (Becker-Ducas-Gama-Laarhoven) and `0.265*beta` quantum
//!    (Laarhoven) — the same pair every NIST PQC lattice submission, ML-KEM included, quotes.
//!
//! 4. **Direction of the error.** §5.4 also says the omitted BKZ polynomial factors "typically
//!    account for around 30 bits of security", so these figures UNDERSTATE the real cost. The
//!    numbers below are therefore conservative, and this file asserts the conservative one.
//!
//! # What is NOT established here
//!
//! These are the paper's own estimates, re-derived arithmetically. This crate did **not** re-run
//! the leaky-LWE estimator, and §5.5 is explicit that "potential security loss arising from the
//! reduction from MLWE to Hint-MLWE is not formally captured", that Maul's distributions "fall
//! below" the smoothing threshold Theorem 4 needs, and that "some degree of security degradation
//! may be expected" — a conjecture, backed by their empirical attack, not a proof. That gap is
//! one of the items in this crate's `SECURITY.md` sign-off list.

use lib_q_maul::params::{
    ALL,
    MAUL512,
    MAUL768,
    MAUL1024,
};

#[test]
fn table_5_parameters_are_transcribed_exactly() {
    // A wrong q or k here would silently change every number in this file.
    let expected = [
        // (name, k, q, eta, du, dv, nu_bits, nist_category)
        ("Maul512", 2usize, 7681i32, 4u32, 10u32, 4u32, 384usize, 1u8),
        ("Maul768", 3, 7681, 4, 11, 6, 512, 3),
        ("Maul1024", 4, 9473, 4, 12, 5, 640, 5),
    ];
    for (p, e) in ALL.iter().zip(expected.iter()) {
        assert_eq!(
            (
                p.name,
                p.k,
                p.q,
                p.eta,
                p.du,
                p.dv,
                p.nu_bits,
                p.nist_category
            ),
            *e
        );
    }
}

#[test]
fn table_6_blocksizes_are_transcribed_exactly() {
    let expected = [
        ("Maul512", 353u32, 338u32),
        ("Maul768", 589, 560),
        ("Maul1024", 811, 772),
    ];
    for (p, e) in ALL.iter().zip(expected.iter()) {
        assert_eq!((p.name, p.bikz_hints, p.bikz_lower_bound), *e);
    }
}

#[test]
fn core_svp_conversion_is_the_documented_one() {
    // 0.265*beta quantum, 0.292*beta classical, applied to the HINT-ADJUSTED blocksize.
    for p in ALL {
        assert_eq!(
            p.quantum_core_svp_bits(),
            p.bikz_hints * 265 / 1000,
            "{}: quantum exponent is not 0.265",
            p.name
        );
        assert_eq!(
            p.classical_core_svp_bits(),
            p.bikz_hints * 292 / 1000,
            "{}: classical exponent is not 0.292",
            p.name
        );
        // The quantum figure must be the SMALLER of the two -- if it ever came out larger, the
        // crate would be quoting the classical number as if it were the post-quantum one, which
        // is the exact mistake the operator asked to rule out.
        assert!(
            p.quantum_core_svp_bits() < p.classical_core_svp_bits(),
            "{}: the quantum figure is not below the classical one",
            p.name
        );
    }
}

#[test]
fn the_recommended_parameter_set_clears_128_bit_post_quantum_security() {
    // THE CLAIM. Maul768, quantum core-SVP, on the hint-adjusted blocksize.
    assert_eq!(MAUL768.bikz_hints, 589);
    assert_eq!(MAUL768.quantum_core_svp_bits(), 156);
    assert!(
        MAUL768.quantum_core_svp_bits() >= 128,
        "Maul768 quantum core-SVP is {} bits",
        MAUL768.quantum_core_svp_bits()
    );
    assert!(MAUL768.meets_128_bit_quantum_core_svp());

    // It clears it even on the paper's OWN conservative lower bound, which is the number to hold
    // the claim to: 560 bikz -> 148 bits.
    assert_eq!(MAUL768.quantum_core_svp_bits_lower_bound(), 148);
    assert!(
        MAUL768.quantum_core_svp_bits_lower_bound() >= 128,
        "Maul768 fails 128-bit PQ on the paper's own lower bound"
    );

    // Maul1024 likewise, with margin.
    assert_eq!(MAUL1024.quantum_core_svp_bits(), 214);
    assert_eq!(MAUL1024.quantum_core_svp_bits_lower_bound(), 204);
    assert!(MAUL1024.meets_128_bit_quantum_core_svp());
}

#[test]
fn maul512_does_not_clear_128_bit_post_quantum_and_says_so() {
    // Honest finding, not a footnote. Maul512 is NIST category 1 in the paper's framing, but its
    // direct quantum core-SVP figure is 93 bits. This is the same well-known property ML-KEM-512
    // has (~107 bits) and is not a defect in the paper -- but it does mean Maul512 cannot be used
    // to satisfy a literal ">= 128-bit post-quantum" requirement, and the crate must not let a
    // caller believe otherwise.
    assert_eq!(MAUL512.quantum_core_svp_bits(), 93);
    assert_eq!(MAUL512.quantum_core_svp_bits_lower_bound(), 89);
    assert!(
        !MAUL512.meets_128_bit_quantum_core_svp(),
        "Maul512 is being reported as 128-bit PQ; it is {} bits",
        MAUL512.quantum_core_svp_bits()
    );
    // And it is the ONLY set in that position -- if a future edit made another set fall below,
    // this count changes and the test fails.
    let below = ALL
        .iter()
        .filter(|p| !p.meets_128_bit_quantum_core_svp())
        .count();
    assert_eq!(
        below, 1,
        "exactly one parameter set should be below 128-bit PQ"
    );
}

#[test]
fn the_full_security_table_is_pinned() {
    // (name, bikz_hints, quantum, quantum lower bound, classical)
    let expected = [
        ("Maul512", 353u32, 93u32, 89u32, 103u32),
        ("Maul768", 589, 156, 148, 171),
        ("Maul1024", 811, 214, 204, 236),
    ];
    for (p, e) in ALL.iter().zip(expected.iter()) {
        assert_eq!(
            (
                p.name,
                p.bikz_hints,
                p.quantum_core_svp_bits(),
                p.quantum_core_svp_bits_lower_bound(),
                p.classical_core_svp_bits(),
            ),
            *e,
            "security table drifted for {}",
            p.name
        );
    }
}

#[test]
fn sizes_are_pinned_against_table_5_and_against_ml_kem() {
    // Table 5 |ct|, reproduced from (k, n, du, dv) rather than restated.
    let expected_ct = [896usize, 1440, 1856];
    // Two parallel ML-KEM ciphertexts at the matching NIST level (Table 2 "ML-KEM" column).
    let two_ml_kem = [1536usize, 2176, 3136];
    // One ML-KEM ciphertext at the matching level.
    let one_ml_kem = [768usize, 1088, 1568];

    for (i, p) in ALL.iter().enumerate() {
        assert_eq!(p.ciphertext_size(), expected_ct[i], "{} |ct|", p.name);
        assert!(
            p.ciphertext_size() < two_ml_kem[i],
            "{} is not smaller than two parallel ML-KEMs",
            p.name
        );
        assert!(
            p.ciphertext_size() > one_ml_kem[i],
            "{} claims to beat a single ML-KEM; it does not",
            p.name
        );
    }
}

#[test]
fn public_key_sizes_are_reported_as_encoded_not_as_the_paper_s_bound() {
    // Table 5's |pk| (826 / 1240 / 1691) is n*k*log2(q)/8 with the A-seed excluded -- an
    // information-theoretic bound. Asserting our encoder hits it would be asserting a falsehood.
    // Pin what the encoder ACTUALLY emits, and pin that it exceeds the paper's bound (it must:
    // byte alignment plus a 32-byte seed can only add).
    let encoded = [864usize, 1280, 1824];
    let paper_bound = [826usize, 1240, 1691];
    for (i, p) in ALL.iter().enumerate() {
        assert_eq!(p.public_key_size(), encoded[i], "{} encoded |pk|", p.name);
        assert!(
            p.public_key_size() > paper_bound[i],
            "{} encoded |pk| is below the information-theoretic bound, which is impossible",
            p.name
        );
    }
}

#[test]
fn the_noise_distribution_matches_the_variance_the_parameters_assume() {
    // D_64 is instantiated as a sum of uniforms with variance 4095 (sigma = 63.9922). Table 5
    // specifies D_64. If this drifted, every bikz figure above would be about a different scheme.
    assert_eq!(lib_q_maul::sample::D_VARIANCE, 4095);
    let sigma_times_100 = 6399u32; // sqrt(4095) = 63.9922
    assert_eq!(
        (f64::from(lib_q_maul::sample::D_VARIANCE).sqrt() * 100.0) as u32,
        sigma_times_100
    );
}
