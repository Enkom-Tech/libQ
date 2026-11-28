//! Pure soundness arithmetic for the membership-STARK gate (`security_parameter_tests.rs`).
//!
//! No prover, no I/O: every function maps a parameter set to bits of security. Mirrors
//! `tools/fri_soundness.py`.

// Each test crate that includes this module uses a different subset of it.
#![allow(dead_code)]

// HONEST proof-system soundness = min over ALL terms, not just the FRI query phase:
//   - challenge field (Fiat–Shamir / DEEP): cannot exceed |F_challenge|, minus a small
//     Schwartz–Zippel degree·domain term (~11 bits);
//   - FRI query phase (conjectured / deployed regime): log_blowup·num_queries + PoW;
//   - hash commitment: SHAKE256/256 → 128-bit collision (NIST Cat-2).
// The earlier tests omitted the challenge-field term and so FALSELY certified `default_config`
// (whose challenge field is the ~62-bit value field `Complex<Mersenne31>`) at ≥200/≥100 bits.
pub const M31_BITS: f64 = 31.0;
/// Fixed DEEP allowance of the CONJECTURED gate. The proven gate prices the DEEP term per arm at the
/// verifier-accepted domain instead ([`deep_term_bits`]).
pub const DEEP_TERM_BITS: f64 = 11.0;
pub const HASH_COLLISION_BITS: f64 = 128.0; // SHAKE256/256

/// The parameters of one membership config that the PROVEN gate prices.
#[derive(Clone, Copy, Debug)]
pub struct ProvenArm {
    /// log2 |F_challenge|.
    pub challenge_field_bits: f64,
    /// FRI `log_blowup` (rate `rho = 2^-log_blowup`).
    pub log_blowup: usize,
    /// FRI `num_queries`.
    pub num_queries: usize,
    /// FRI `proof_of_work_bits`.
    pub pow_bits: usize,
    /// `true` under the hiding PCS, which commits the trace at twice its degree.
    pub zk: bool,
    /// Largest trace height the VERIFIER accepts, or `None` when the verifier does not bound it
    /// (then only [`Self::lde_two_adicity`] does).
    pub max_trace_rows: Option<usize>,
    /// Two-adicity of the FRI value field: the FRI verifier rejects any LDE domain larger than
    /// `2^lde_two_adicity`.
    pub lde_two_adicity: usize,
    /// `l`: the number of (column, opening point) pairs the PCS combines with powers of ONE alpha
    /// (the powers generator of degree `l - 1`). Measured from a real proof in
    /// `soundness_gate_shape_tests.rs`.
    pub batched_openings: usize,
    /// Maximum AIR constraint degree.
    pub max_constraint_degree: usize,
}

/// BabyBear prime `q`, the Arm B base field.
pub const BABY_BEAR_MODULUS: f64 = 2_013_265_921.0;

/// Largest trace height the Arm A verifiers accept: `lib_q_zkp::membership::MAX_DEPTH`, one row
/// per tree level. Both Arm A verifiers pin `degree_bits` to the padded declared depth.
pub const ARM_A_MAX_TRACE_ROWS: usize = 64;
/// Two-adicity of `Complex<Mersenne31>`, the Arm A FRI value field.
pub const ARM_A_LDE_TWO_ADICITY: usize = 32;
/// Two-adicity of BabyBear, the Arm B FRI value field.
pub const ARM_B_LDE_TWO_ADICITY: usize = 27;

/// Arm A membership config (`membership_config`): challenge field
/// `BinomialExtensionField<Complex<Mersenne31>, 3>` = `GF(p^6)`, FRI `log_blowup 3 / q 96 / PoW 20`.
pub fn arm_a_membership() -> ProvenArm {
    ProvenArm {
        challenge_field_bits: 6.0 * M31_BITS,
        log_blowup: 3,
        num_queries: 96,
        pow_bits: 20,
        zk: false,
        max_trace_rows: Some(ARM_A_MAX_TRACE_ROWS),
        lde_two_adicity: ARM_A_LDE_TWO_ADICITY,
        batched_openings: 34_316,
        max_constraint_degree: 5,
    }
}

/// Arm A hiding config (`prove_unlinkable_membership_zk`): same field and FRI parameters
/// (`ZK_LOG_BLOWUP 3 / ZK_NUM_QUERIES 96 / ZK_POW_BITS 20`) under the hiding PCS.
pub fn arm_a_membership_zk() -> ProvenArm {
    ProvenArm {
        zk: true,
        batched_openings: 34_431,
        ..arm_a_membership()
    }
}

/// Arm B membership config (`default_config_bb`): challenge field
/// `BinomialExtensionField<BabyBear, 8>` = `GF(q^8)`, FRI `log_blowup 4 / q 96 / PoW 20`.
/// `verify_membership_bb` does not bind `degree_bits` to a depth, so the trace height is bounded
/// only by the FRI verifier's two-adicity check.
pub fn arm_b_membership() -> ProvenArm {
    ProvenArm {
        challenge_field_bits: 8.0 * BABY_BEAR_MODULUS.log2(),
        log_blowup: 4,
        num_queries: 96,
        pow_bits: 20,
        zk: false,
        max_trace_rows: None,
        lde_two_adicity: ARM_B_LDE_TWO_ADICITY,
        batched_openings: 3_386,
        max_constraint_degree: 7,
    }
}

/// Arm B hiding config (`default_zk_config_bb`): same field and FRI parameters.
pub fn arm_b_membership_zk() -> ProvenArm {
    ProvenArm {
        zk: true,
        batched_openings: 3_534,
        ..arm_b_membership()
    }
}

/// The superseded Arm B field `GF(q^5)` with the same FRI parameters: the positive control the
/// PROVEN gate must reject.
pub fn arm_b_superseded_gf_q5() -> ProvenArm {
    ProvenArm {
        challenge_field_bits: 5.0 * BABY_BEAR_MODULUS.log2(),
        ..arm_b_membership()
    }
}

pub fn min_soundness_bits(
    challenge_field_bits: f64,
    log_blowup: usize,
    num_queries: usize,
    pow_bits: usize,
) -> f64 {
    let field = challenge_field_bits - DEEP_TERM_BITS;
    let query_conjectured = (log_blowup * num_queries + pow_bits) as f64;
    field.min(query_conjectured).min(HASH_COLLISION_BITS)
}

// PROVEN soundness: the FRI part priced by BCIKS20 ("Proximity Gaps for Reed-Solomon Codes",
// ePrint 2020/654, version of July 3, 2021) and BCGM (Bordage, Chiesa, Guan, Manzur, "All Polynomial
// Generators Preserve Distance with Mutual Correlated Agreement", ePrint 2025/2051, version of May
// 19, 2026), theorems in the Johnson list-decoding regime. Unlike the conjectured/capacity number
// above it is unaffected by the late-2025 disproof of the up-to-capacity soundness conjectures (SoK,
// eprint 2026/1367). Production configs must clear 128-bit on THIS bound, not only the conjectured
// one.
//
// The PCS combines the `l` opened (column, point) quotients `u_j` into ONE word
// `w = sum_j alpha^j u_j` (powers generator, degree `d = l - 1`; every committed matrix has one LDE
// height, so there is no roll-in) and runs FRI on `w`. With `theta = sqrt(rho) (1 + 1/(2m))`:
//   - BCGM Lemma 9.3 (Def 9.1): unless the `u_j` have correlated agreement of density >= theta,
//     `w` has agreement >= theta with probability at most `eps_MCA` over alpha;
//   - BCIKS20 Thm 8.3 on the single word `w` (t = 0): if `w` has agreement < theta, FRI accepts
//     with probability at most `eps_C + theta^s`, `eps_C` from Lemma 8.2 eq (8.5).
// So `eps_FRI = eps_MCA + eps_C + theta^s` (a union bound over alpha), ONE m = 3 throughout, priced at
// the largest LDE domain the verifier accepts.
pub fn min_soundness_bits_provable(arm: &ProvenArm) -> f64 {
    deep_term_bits(arm)
        .min(fri_phase_bits(arm))
        .min(HASH_COLLISION_BITS)
}

/// BCIKS20 / BCGM parameter `m`. BCIKS20 Thm 5.1, 6.2, 7.2, Lemma 8.2 and BCGM Lemma 9.3 all need
/// `m >= 3`; the gate uses 3 for the field terms AND the query term (BCIKS20 Thm 8.3).
pub const BCIKS_M: f64 = 3.0;

/// log2 of the LDE domain size `n = |D^(0)|` the gate prices: the LARGEST domain the verifier
/// accepts. A verifier that caps the trace height at `rows` accepts `rows * (1 + zk) *
/// 2^log_blowup`; without a cap, only the FRI verifier's two-adicity check bounds it.
pub fn lde_domain_log2(arm: &ProvenArm) -> usize {
    match arm.max_trace_rows {
        Some(rows) => {
            let capped =
                rows.next_power_of_two().ilog2() as usize + usize::from(arm.zk) + arm.log_blowup;
            capped.min(arm.lde_two_adicity)
        }
        None => arm.lde_two_adicity,
    }
}

fn domain_size(arm: &ProvenArm) -> f64 {
    2.0_f64.powi(lde_domain_log2(arm) as i32)
}

fn rate(arm: &ProvenArm) -> f64 {
    0.5_f64.powi(arm.log_blowup as i32)
}

/// Fiat–Shamir / DEEP Schwartz–Zippel term, `|F| / (max_constraint_degree * n)`, priced at the same
/// domain as the BCIKS terms.
pub fn deep_term_bits(arm: &ProvenArm) -> f64 {
    arm.challenge_field_bits - (arm.max_constraint_degree as f64 * domain_size(arm)).log2()
}

/// First term of BCIKS20 Lemma 8.2 eq (8.5), `(m+1/2)^7 |D|^2 / (2 rho^(3/2) |F|)`, in bits. The
/// constant 2 is Lemma 8.2's (it covers every folding round). Lemma 8.2 is FRI on one word: the
/// batching is priced separately ([`mca_batching_bits`]).
pub fn bciks_field_term_bits(arm: &ProvenArm) -> f64 {
    arm.challenge_field_bits - bciks_first_term_log2_numerator(arm)
}

fn bciks_first_term_log2_numerator(arm: &ProvenArm) -> f64 {
    let n = domain_size(arm);
    ((BCIKS_M + 0.5).powi(7) * n * n / (2.0 * rate(arm).powf(1.5))).log2()
}

/// `eps_C` of BCIKS20 Lemma 8.2 eq (8.5), both terms, in bits. Second term:
/// `(2m+1)(|D|+1) sum_i l^(i) / (sqrt(rho) |F|)` with `l^(i) = 2` for each binary folding round
/// (at most `log2(n) - log_blowup` of them, `log_final_poly_len = 0`).
pub fn bciks_commit_phase_bits(arm: &ProvenArm) -> f64 {
    let n = domain_size(arm);
    let rounds = lde_domain_log2(arm).saturating_sub(arm.log_blowup) as f64;
    let first = 2.0_f64.powf(bciks_first_term_log2_numerator(arm));
    let second = (2.0 * BCIKS_M + 1.0) * (n + 1.0) * (2.0 * rounds) / rate(arm).sqrt();
    arm.challenge_field_bits - (first + second).log2()
}

/// MCA error of the powers-of-alpha batching, BCGM Lemma 9.3 / Def 9.1 for RS[F, D, k] with the
/// powers generator `(1, x, ..., x^d)`, `d = l - 1`, valid up to `gamma = 1 - (1 + 1/2m) sqrt(rho)`:
/// `(m+1/2)^7 d n^2 / (3 rho^(3/2) |F|)`, in bits. `l = 1` is no batching: infinite bits.
pub fn mca_batching_bits(arm: &ProvenArm) -> f64 {
    let d = arm.batched_openings.saturating_sub(1) as f64;
    if d == 0.0 {
        return f64::INFINITY;
    }
    let n = domain_size(arm);
    arm.challenge_field_bits
        - ((BCIKS_M + 0.5).powi(7) * d * n * n / (3.0 * rate(arm).powf(1.5))).log2()
}

/// Everything that depends on the verifier's field challenges (batching alpha and folding betas):
/// `eps_MCA + eps_C`, in bits.
pub fn commit_phase_bits(arm: &ProvenArm) -> f64 {
    -(2.0_f64.powf(-mca_batching_bits(arm)) + 2.0_f64.powf(-bciks_commit_phase_bits(arm))).log2()
}

/// Query term of BCIKS20 Thm 8.3, `(sqrt(rho) (1 + 1/(2m)))^s`, plus grinding, in bits.
pub fn query_phase_bits(arm: &ProvenArm) -> f64 {
    let per_query = -(rate(arm).sqrt() * (1.0 + 1.0 / (2.0 * BCIKS_M))).log2();
    arm.num_queries as f64 * per_query + arm.pow_bits as f64
}

/// `eps_FRI = eps_MCA + eps_C + eps_query` (BCGM Lemma 9.3 + BCIKS20 Thm 8.3), in bits.
pub fn fri_phase_bits(arm: &ProvenArm) -> f64 {
    let eps = 2.0_f64.powf(-commit_phase_bits(arm)) + 2.0_f64.powf(-query_phase_bits(arm));
    -eps.log2()
}
