//! Security parameter tests: enforce minimum query counts, blowup, and proof-of-work
//! for production configs; ensure test params are obviously insecure.

#![cfg(feature = "zkp")]

use lib_q_stark_commit::ExtensionMmcs;
use lib_q_stark_field::extension::Complex;
use lib_q_stark_fri::{FriParameters, create_test_fri_params};
use lib_q_stark_merkle::MerkleTreeMmcs;
use lib_q_stark_mersenne31::Mersenne31;
use lib_q_stark_shake256::Shake256Hash;
use lib_q_stark_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use lib_q_zkp::stark::default_fri_params_for_tests;

mod soundness_gate;
use soundness_gate::{
    ARM_B_LDE_TWO_ADICITY, M31_BITS, ProvenArm, arm_a_membership, arm_a_membership_zk,
    arm_b_membership, arm_b_membership_zk, arm_b_superseded_gf_q5, bciks_commit_phase_bits,
    bciks_field_term_bits, deep_term_bits, fri_phase_bits, lde_domain_log2, min_soundness_bits,
    min_soundness_bits_provable, query_phase_bits,
};

/// `default_config` (the SHARED Arm A config used by recursion / auth / credential) uses the value
/// field `Complex<Mersenne31>` (~62 bits) as its FRI challenge field, which HARD-CAPS its
/// Fiat–Shamir/DEEP soundness near 62 bits regardless of query count. This test documents that
/// honestly — it is NOT a 128-bit config and must not be presented as one. (Membership uses the
/// separate degree-3-challenge-field config; see below.)
#[test]
fn test_default_config_is_challenge_field_bound_below_128() {
    let (log_blowup, num_queries, pow_bits) = default_fri_params_for_tests();
    let challenge_field_bits = 2.0 * M31_BITS; // Complex<Mersenne31> = GF(p^2)
    let bits = min_soundness_bits(challenge_field_bits, log_blowup, num_queries, pow_bits);
    assert!(
        bits < 128.0,
        "default_config is challenge-field-bound; expected < 128-bit, got {bits}"
    );
    assert!(
        bits >= 50.0,
        "default_config soundness sanity floor (~62-bit field minus DEEP), got {bits}"
    );
}

/// The Arm A **membership** config raises the FRI challenge field to the degree-3 extension over
/// `Complex<Mersenne31>` = `GF(p^6)` (~186 bits) with FRI `log_blowup 3 / q 96 / PoW 20`, so the
/// FS/DEEP term is no longer the binder and the proof-system soundness reaches the 128-bit hash
/// floor (classical AND post-quantum, mainstream/deployed QROM model). Mirrors the Arm B
/// `fri_soundness.py` accounting.
#[test]
fn min_soundness_bits_provable_arm_a_membership_clears_128_classical_and_pq() {
    let challenge_field_bits = 6.0 * M31_BITS; // BinomialExtensionField<Complex<Mersenne31>, 3> = GF(p^6)
    let bits = min_soundness_bits(challenge_field_bits, 3, 96, 20);
    assert!(
        bits >= 128.0,
        "membership_config must reach >= 128-bit, got {bits}"
    );
    // PQ (mainstream model): IOP soundness preserved in QROM; SHAKE256/256 = NIST Cat-2 128-bit
    // collision; only the PoW grinding is Grover-halved. The binding term is the hash at 128, so the
    // PQ level equals the classical here.
    assert!(
        bits >= 128.0,
        "membership_config must reach >= 128-bit post-quantum, got {bits}"
    );
    // The load-bearing check the SoK (eprint 2026/1367) motivates: the config must clear 128-bit on
    // the PROVEN Johnson query bound too, not only the conjectured/capacity one. This is what keeps
    // the claimed level intact after the late-2025 disproof of the up-to-capacity conjectures.
    let bits_provable = min_soundness_bits_provable(&arm_a_membership());
    assert!(
        bits_provable >= 128.0,
        "membership_config must reach >= 128-bit on the PROVEN Johnson bound, got {bits_provable}"
    );
}

/// Arm B (BabyBear, Poseidon2) membership config: FRI challenge field is the degree-8 extension
/// `BinomialExtensionField<BabyBear, 8>` = `GF(q^8)` (~247 bits) with FRI `log_blowup 4 / q 96 /
/// PoW 20`. It must clear 128-bit on the PROVEN Johnson bound as well as the conjectured one. The
/// earlier GF(q^5) field (~154 bits) left the BCIKS proximity-gap field term near 119 bits
/// (see `tools/fri_soundness.py`), which is why Arm B moved to GF(q^8).
#[test]
fn min_soundness_bits_provable_arm_b_membership_clears_128() {
    let arm = arm_b_membership(); // BinomialExtensionField<BabyBear, 8> = GF(q^8)
    let conjectured = min_soundness_bits(arm.challenge_field_bits, 4, 96, 20);
    assert!(
        conjectured >= 128.0,
        "Arm B must reach >= 128-bit (conjectured), got {conjectured}"
    );
    let proven = min_soundness_bits_provable(&arm);
    assert!(
        proven >= 128.0,
        "Arm B must reach >= 128-bit on the PROVEN Johnson bound, got {proven}"
    );
}

/// Positive control: the PROVEN gate must be able to reject a config that clears conjectured-128 but
/// not proven-128. The superseded Arm B field `GF(q^5)` (~154.5 bits) with the same FRI parameters
/// passes the conjectured gate (128, hash-bound) yet falls below 128 on the BCIKS-aware proven gate.
#[test]
fn min_soundness_bits_provable_rejects_superseded_gf_q5_positive_control() {
    let arm = arm_b_superseded_gf_q5(); // GF(q^5): the field Arm B used before this change
    let conjectured = min_soundness_bits(arm.challenge_field_bits, 4, 96, 20);
    let proven = min_soundness_bits_provable(&arm);
    assert!(
        conjectured >= 128.0,
        "control precondition: GF(q^5) clears the conjectured-only gate, got {conjectured}"
    );
    assert!(
        proven < 128.0,
        "the proven gate must reject GF(q^5) (BCIKS field term), got {proven}"
    );
}

/// The hiding (ZK) configs commit the trace at twice its degree and open more columns, so they are
/// priced separately; they must clear the same PROVEN floor as the transparent configs.
#[test]
fn min_soundness_bits_provable_zk_membership_arms_clear_128() {
    for (name, arm) in [
        ("Arm A zk", arm_a_membership_zk()),
        ("Arm B zk", arm_b_membership_zk()),
    ] {
        let proven = min_soundness_bits_provable(&arm);
        assert!(
            proven >= 128.0,
            "{name} must reach >= 128-bit on the PROVEN bound, got {proven}"
        );
    }
}

// ---- BCIKS20 deltas (the tightening follow-up to the BCIKS20 review). Papers: Ben-Sasson, Carmon,
// Ishai, Kopparty, Saraf, "Proximity Gaps for Reed-Solomon Codes", ePrint 2020/654, version of
// July 3, 2021 (BCIKS20); Bordage, Chiesa, Guan, Manzur, "All Polynomial Generators Preserve
// Distance with Mutual Correlated Agreement", ePrint 2025/2051, version of May 19, 2026 (BCGM). Each
// test below pins one equation of a paper against the gate's arithmetic. The expected values are
// written out here from the papers on purpose, independently of `soundness_gate`. ----

/// BCIKS20 parameter `m` (Thm 5.1 / 6.2 / 7.2 / Lemma 8.2 all require `m >= 3`).
const M: f64 = 3.0;

fn assert_close(got: f64, want: f64, what: &str) {
    assert!(
        (got - want).abs() < 1e-9,
        "{what}: gate gives {got}, paper gives {want}"
    );
}

/// A synthetic arm with the LDE domain fixed at `2^(log2(rows) + log_blowup)` and `l` batched
/// openings, used to isolate one delta at a time.
fn synthetic(field: f64, log_blowup: usize, rows: usize, l: usize) -> ProvenArm {
    ProvenArm {
        challenge_field_bits: field,
        log_blowup,
        num_queries: 96,
        pow_bits: 20,
        zk: false,
        max_trace_rows: Some(rows),
        lde_two_adicity: ARM_B_LDE_TWO_ADICITY,
        batched_openings: l,
        max_constraint_degree: 7,
    }
}

/// Delta 2. BCIKS20 Lemma 8.2 eq (8.5), first term: `(m+1/2)^7 |D|^2 / (2 rho^(3/2) |F|)`.
/// The constant is 2, not the 3 of Thm 5.1 eq (5.3): Lemma 8.2 is the FRI statement, and its first
/// term covers every folding round, not one line. Old gate: 3 (0.585 bits too generous).
#[test]
fn delta2_lemma_8_2_first_term_has_constant_2() {
    let arm = synthetic(200.0, 4, 32, 1);
    let (n, rho) = (512.0_f64, 1.0_f64 / 16.0);
    let want = 200.0 - ((M + 0.5).powi(7) * n * n / (2.0 * rho.powf(1.5))).log2();
    assert_close(bciks_field_term_bits(&arm), want, "Lemma 8.2 first term");
}

/// Delta 3. The PCS combines all `l` opened (column, point) pairs with powers of ONE alpha
/// (`lib-q-stark-fri/src/two_adic_pcs.rs`): `w = sum_j alpha^j (p_j(X) - y_j)/(X - z_j)`, i.e. the
/// univariate powers generator `(1, x, ..., x^d)` with `d = l - 1`, not the independent `x_1..x_t`
/// of BCIKS20 eq (8.3). Every committed matrix sits at one LDE height, so FRI then runs on the single
/// word `w` (no roll-in). The batching step is priced by BCGM Lemma 9.3 / Def 9.1, MCA for
/// RS[F, D, k] up to `gamma = 1 - (1 + 1/2m) sqrt(rho)`:
/// `eps_MCA = (m+1/2)^7 d n^2 / (3 rho^(3/2) |F|)`, and the FRI on `w` by BCIKS20 Thm 8.3 as stated
/// (Lemma 8.2 does not depend on `l`). Previous round: factor `l` on Lemma 8.2's first term (our own
/// composition, no theorem behind it).
#[test]
fn delta3_powers_of_alpha_batching_is_priced_by_bcgm_lemma_9_3() {
    let (n, rho, rounds) = (512.0_f64, 1.0_f64 / 16.0, 5.0_f64);
    // Lemma 8.2 is a statement about FRI on one word: no `l` in it.
    let one = bciks_field_term_bits(&synthetic(200.0, 4, 32, 1));
    let many = bciks_field_term_bits(&synthetic(200.0, 4, 32, 1024));
    assert_close(one, many, "Lemma 8.2 first term does not depend on l");
    // eps_FRI = eps_MCA(BCGM, d = l - 1) + eps_C(BCIKS20 Lemma 8.2) + query term (Thm 8.3).
    let arm = synthetic(200.0, 4, 32, 1024);
    let d = 1023.0;
    let mca = (M + 0.5).powi(7) * d * n * n / (3.0 * rho.powf(1.5));
    let lemma = (M + 0.5).powi(7) * n * n / (2.0 * rho.powf(1.5))
        + (2.0 * M + 1.0) * (n + 1.0) * (2.0 * rounds) / rho.sqrt();
    let query = 96.0 * -(rho.sqrt() * (1.0 + 1.0 / (2.0 * M))).log2() + 20.0;
    let want = -((mca + lemma) / 2.0_f64.powf(200.0) + 2.0_f64.powf(-query)).log2();
    assert_close(
        fri_phase_bits(&arm),
        want,
        "BCGM batching + BCIKS20 Thm 8.3",
    );
}

/// Delta 4. BCIKS20 Thm 8.3: `eps_FRI = eps_C + (sqrt(rho) (1 + 1/(2m)))^s`. The query term uses
/// the SAME `m` as the field term. Old gate: `m -> infinity` (`log_blowup/2` bits per query) while
/// the field term used `m = 3`. At `m = 3` each query costs `-log2(sqrt(rho) * 7/6)` bits.
#[test]
fn delta4_query_phase_uses_the_same_m_as_the_field_term() {
    for arm in [arm_a_membership(), arm_b_membership()] {
        let rho = 0.5_f64.powi(arm.log_blowup as i32);
        let per_query = -(rho.sqrt() * (1.0 + 1.0 / (2.0 * M))).log2();
        let want = arm.num_queries as f64 * per_query + arm.pow_bits as f64;
        assert_close(query_phase_bits(&arm), want, "Thm 8.3 query term");
    }
}

/// Delta 5. `n = |D^(0)|` in every BCIKS term is the LDE domain size, and for soundness it must be
/// the LARGEST one the verifier accepts. Arm A: both verifiers pin `degree_bits` to the padded
/// declared depth, at most `MAX_DEPTH` (64) rows, doubled under the hiding PCS. Arm B:
/// `verify_membership_bb` binds no depth, so only the FRI verifier's two-adicity check bounds it
/// (`2^27` for BabyBear). Old gate: 32 rows for both arms (`n = 256` / `512`).
#[test]
fn delta5_lde_domain_is_the_largest_the_verifier_accepts() {
    let depth_log2 = lib_q_zkp::membership::MAX_DEPTH.ilog2() as usize;
    for (name, arm, want) in [
        ("Arm A", arm_a_membership(), depth_log2 + 3),
        ("Arm A zk", arm_a_membership_zk(), depth_log2 + 1 + 3),
        ("Arm B", arm_b_membership(), ARM_B_LDE_TWO_ADICITY),
        ("Arm B zk", arm_b_membership_zk(), ARM_B_LDE_TWO_ADICITY),
    ] {
        let got = lde_domain_log2(&arm);
        assert_eq!(
            got, want,
            "{name}: gate prices n = 2^{got}, verifier accepts 2^{want}"
        );
    }
}

/// Consequence of delta 5 (DEEP is not a BCIKS term): the DEEP / ALI Schwartz–Zippel error,
/// `max_constraint_degree * n / |F|`, grows with the same domain, so it is priced there too (the
/// form `tools/fri_soundness.py` already used). Old proven gate: a fixed 11 bits, which stops being
/// conservative once `n` is what the Arm B verifier accepts (`log2(7 * 2^27)` = 29.8 bits).
#[test]
fn delta5_deep_term_is_priced_at_the_same_domain() {
    let arm = arm_b_membership();
    let want = arm.challenge_field_bits - (7.0 * 2.0_f64.powi(27)).log2();
    assert_close(deep_term_bits(&arm), want, "DEEP term at n = 2^27");
}

/// Delta 6. BCIKS20 Lemma 8.2 eq (8.5) has a second term,
/// `(2m+1)(|D|+1) sum_i l^(i) / (sqrt(rho) |F|)`, with `l^(i) = |D^(i)|/|D^(i+1)|` (2 per round for
/// binary folding). Old gate: term omitted. Previous round: the batching `l` was also added to the
/// sum; with the batching priced by BCGM (delta 3) the sum is Lemma 8.2's own. It is numerically tiny
/// at production sizes, so it is checked on a small domain where it shows.
#[test]
fn delta6_lemma_8_2_second_term_is_included() {
    let arm = synthetic(64.0, 1, 2, 1); // n = 4, rho = 1/2, one folding round
    let (n, rho) = (4.0_f64, 0.5_f64);
    let rounds = 1.0;
    let first = (M + 0.5).powi(7) * n * n / (2.0 * rho.powf(1.5));
    let second = (2.0 * M + 1.0) * (n + 1.0) * (2.0 * rounds) / rho.sqrt();
    let want = 64.0 - (first + second).log2();
    assert_close(bciks_commit_phase_bits(&arm), want, "Lemma 8.2 both terms");
    // Second term: 7 * 5 * 2 / sqrt(1/2) ~ 99 against a first term of ~1.46e5, so ~1e-3 bits.
    assert!(bciks_commit_phase_bits(&arm) < bciks_field_term_bits(&arm) - 5e-4);
}

/// The Rust gate and `tools/fri_soundness.py` must agree. These are the Thm 8.3 `eps_FRI` bits that
/// `python fri_soundness.py` prints for each config (its `fri_proven`, to 4 decimals).
#[test]
fn proven_fri_bits_match_tools_fri_soundness_py() {
    for (name, arm, eps_fri_bits) in [
        ("Arm A", arm_a_membership(), 137.3303),
        ("Arm A zk", arm_a_membership_zk(), 135.3528),
        ("Arm B", arm_b_membership(), 164.4630),
        ("Arm B zk", arm_b_membership_zk(), 164.4013),
        ("GF(q^5) control", arm_b_superseded_gf_q5(), 71.7424),
    ] {
        let got = fri_phase_bits(&arm);
        assert!(
            (got - eps_fri_bits).abs() < 5e-4,
            "{name}: gate {got}, fri_soundness.py {eps_fri_bits}"
        );
    }
}

#[test]
fn test_default_config_num_queries_minimum() {
    let (_log_blowup, num_queries, _pow_bits) = default_fri_params_for_tests();
    assert!(
        num_queries >= 80,
        "default_config num_queries must be >= 80, got {}",
        num_queries
    );
}

#[test]
fn test_default_config_proof_of_work_bits_minimum() {
    let (_log_blowup, _num_queries, pow_bits) = default_fri_params_for_tests();
    assert!(
        pow_bits >= 16,
        "default_config proof_of_work_bits must be >= 16, got {}",
        pow_bits
    );
}

#[test]
fn test_default_config_log_blowup_minimum() {
    let (log_blowup, _num_queries, _pow_bits) = default_fri_params_for_tests();
    assert!(
        log_blowup >= 1,
        "default_config log_blowup must be >= 1, got {}",
        log_blowup
    );
}

#[test]
fn test_test_fri_params_are_obviously_insecure() {
    type Val = Complex<Mersenne31>;
    type MyHash = SerializingHasher<Shake256Hash>;
    type MyCompress = CompressionFunctionFromHasher<Shake256Hash, 2, 32>;
    type ValMmcs =
        MerkleTreeMmcs<<Val as lib_q_stark_field::Field>::Packing, u8, MyHash, MyCompress, 32>;
    type ChallengeMmcs = ExtensionMmcs<Val, Val, ValMmcs>;

    let shake256 = Shake256Hash {};
    let hash = MyHash::new(shake256);
    let compress = MyCompress::new(shake256);
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs);

    let p = create_test_fri_params(challenge_mmcs, 2);
    let soundness = p.log_blowup * p.num_queries + p.proof_of_work_bits;
    assert!(
        soundness < 20,
        "test FRI params must be obviously insecure (soundness < 20), got {}",
        soundness
    );
}

#[test]
fn test_zero_queries_is_rejected() {
    type Val = Complex<Mersenne31>;
    type MyHash = SerializingHasher<Shake256Hash>;
    type MyCompress = CompressionFunctionFromHasher<Shake256Hash, 2, 32>;
    type ValMmcs =
        MerkleTreeMmcs<<Val as lib_q_stark_field::Field>::Packing, u8, MyHash, MyCompress, 32>;
    type ChallengeMmcs = ExtensionMmcs<Val, Val, ValMmcs>;

    let shake256 = Shake256Hash {};
    let hash = MyHash::new(shake256);
    let compress = MyCompress::new(shake256);
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs);

    let params = FriParameters {
        log_blowup: 2,
        log_final_poly_len: 0,
        num_queries: 0,
        proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };
    let result = params.validate();
    assert!(
        result.is_err(),
        "FriParameters with num_queries=0 must be rejected"
    );
}
