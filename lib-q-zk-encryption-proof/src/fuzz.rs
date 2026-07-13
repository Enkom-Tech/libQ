//! Under-constraint fuzzer for the three arithmetic AIRs in `zq.rs`.
//!
//! Each test:
//! 1. Builds N valid instances and asserts the constraint oracle accepts them (completeness).
//! 2. Runs a mutation census (M random single-cell flips per instance) and asserts no survivor
//!    makes it through (zero under-constraint holes found).
//!
//! A deliberate canary AIR with one unconstrained column verifies the harness actually works.

use lib_q_stark::{
    DebugConstraintBuilder,
    check_constraints,
};
use lib_q_stark_air::{
    Air,
    AirBuilder,
    BaseAir,
    WindowAccess,
};
use lib_q_stark_field::{
    BasedVectorSpace,
    Field,
    PrimeCharacteristicRing,
};
use lib_q_stark_matrix::Matrix;
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_mersenne31::Mersenne31;
use lib_q_zkp::stark::ConfigVal;

use crate::sponge_air::{
    ShakeSpongeAir,
    encap_preimage,
    generate_sponge_air_trace,
    sponge_public_values,
};
use crate::zq::{
    EncodeMuFoldAir,
    HornerFoldAir,
    ModReduceAir,
    Q,
    RelationCheckAir,
    encode_mu_public_values,
    generate_encode_mu_trace,
    generate_horner_trace,
    generate_modreduce_trace,
    generate_relation_trace,
    horner_public_values,
};

// ---------------------------------------------------------------------------
// Deterministic PRNG (SplitMix64) — no external rand crate
// ---------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

// ---------------------------------------------------------------------------
// Field element constructor — matches the private `cv` helper in zq.rs exactly
// ---------------------------------------------------------------------------

fn cv_real(x: u64) -> ConfigVal {
    ConfigVal::from_basis_coefficients_fn(|i| {
        if i == 0 {
            Mersenne31::new((x % ((1u64 << 31) - 1)) as u32)
        } else {
            Mersenne31::ZERO
        }
    })
}

// ---------------------------------------------------------------------------
// Constraint oracle: wraps check_constraints in catch_unwind for bool result
// ---------------------------------------------------------------------------

fn accepts<A>(air: &A, trace: &RowMajorMatrix<ConfigVal>, pubs: &[ConfigVal]) -> bool
where
    A: for<'a> Air<DebugConstraintBuilder<'a, ConfigVal>> + std::panic::RefUnwindSafe,
{
    // Silence the panic hook so caught constraint panics don't flood stderr.
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let res = std::panic::catch_unwind(|| check_constraints(air, trace, pubs));
    std::panic::set_hook(prev);
    res.is_ok()
}

// ---------------------------------------------------------------------------
// Census: single-cell mutation sweep for a given (air, trace, pubs)
// ---------------------------------------------------------------------------

/// (row, col, old_value_raw_as_debug_string, new_raw)
type Survivor = (usize, usize, ConfigVal, ConfigVal);

fn census<A>(
    air: &A,
    trace: &RowMajorMatrix<ConfigVal>,
    pubs: &[ConfigVal],
    rng: &mut Rng,
    m: usize,
) -> Vec<Survivor>
where
    A: for<'a> Air<DebugConstraintBuilder<'a, ConfigVal>> + std::panic::RefUnwindSafe,
{
    let mut survivors: Vec<Survivor> = Vec::new();
    let width = Matrix::width(trace);
    let height = trace.height();

    for _ in 0..m {
        let row = rng.below(height as u64) as usize;
        let col = rng.below(width as u64) as usize;
        let idx = row * width + col;

        let old = trace.values[idx];

        // Mutate to a random M31 real-part element (imag = 0).
        let new_raw = rng.next_u64() % ((1u64 << 31) - 1);
        let new = cv_real(new_raw);

        if new == old {
            continue;
        }

        let mut t = trace.clone();
        t.values[idx] = new;

        if accepts(air, &t, pubs) {
            survivors.push((row, col, old, new));
        }
    }
    survivors
}

// ---------------------------------------------------------------------------
// Canary AIR: col 0 pinned to 1; col 1 completely unconstrained (intentional hole)
// ---------------------------------------------------------------------------

struct CanaryAir;

impl<F: Field> BaseAir<F> for CanaryAir {
    fn width(&self) -> usize {
        2
    }
}

impl<AB: AirBuilder> Air<AB> for CanaryAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let cur = main.current_slice();
        builder.assert_eq(cur[0], AB::Expr::ONE);
        // col 1 is deliberately left unconstrained
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const N: usize = 40; // instances per AIR
const M: usize = 300; // mutations per instance

#[test]
fn fuzz_modreduce_air() {
    let mut rng = Rng::new(0xDEAD_BEEF_1234_5678);
    let air = ModReduceAir;

    for inst in 0..N {
        // Build a random spread of u128 values: small, near q, and large (< 2^90).
        let seed = rng.next_u64();
        let mut inst_rng = Rng::new(seed ^ (inst as u64 * 0x9E3779B97F4A7C15));

        let count = (inst_rng.below(8) as usize) + 2; // 2..9 values
        let mut values: Vec<u128> = Vec::with_capacity(count);
        for _ in 0..count {
            let kind = inst_rng.below(4);
            let v: u128 = match kind {
                0 => inst_rng.next_u64() as u128 % Q as u128, // < q
                1 => {
                    // near q
                    let delta = inst_rng.below(100) as u128;
                    (Q as u128).saturating_add(delta)
                }
                2 => {
                    // large, up to ~2^90
                    let hi = inst_rng.next_u64() as u128 % (1u128 << 27);
                    let lo = inst_rng.next_u64() as u128;
                    (hi << 63) | lo
                }
                _ => inst_rng.next_u64() as u128, // random u64 range
            };
            // cap at 2^96 - 1 (the AIR's input domain)
            values.push(v & ((1u128 << 96) - 1));
        }

        let trace = generate_modreduce_trace(&values)
            .unwrap_or_else(|e| panic!("ModReduceAir inst {inst}: trace gen failed: {e:?}"));

        // Completeness: valid trace must be accepted.
        assert!(
            accepts(&air, &trace, &[]),
            "ModReduceAir inst {inst}: valid trace rejected (completeness failure). values={values:?}"
        );

        // Census.
        let mut census_rng = Rng::new(seed ^ 0xCAFE_BABE);
        let survivors = census(&air, &trace, &[], &mut census_rng, M);

        assert!(
            survivors.is_empty(),
            "ModReduceAir POTENTIAL SOUNDNESS FINDING at inst {inst}:\n\
             values={values:?}\n\
             First survivors (row, col): {:?}",
            survivors
                .iter()
                .take(5)
                .map(|(r, c, _, _)| (*r, *c))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn fuzz_horner_fold_air() {
    let mut rng = Rng::new(0xFEED_FACE_DEAD_C0DE);
    let air = HornerFoldAir;

    for inst in 0..N {
        let seed = rng.next_u64();
        let mut inst_rng = Rng::new(seed ^ (inst as u64 * 0x517CC1B727220A95));

        // coeffs: length 4..12, each < q
        let len = (inst_rng.below(9) as usize) + 4; // 4..12
        let coeffs: Vec<u64> = (0..len).map(|_| inst_rng.next_u64() % Q).collect();
        let zeta = inst_rng.next_u64() % Q;

        let (trace, _e) = generate_horner_trace(&coeffs, zeta)
            .unwrap_or_else(|e| panic!("HornerFoldAir inst {inst}: trace gen failed: {e:?}"));
        let pubs = horner_public_values(zeta);

        // Completeness.
        assert!(
            accepts(&air, &trace, &pubs),
            "HornerFoldAir inst {inst}: valid trace rejected. coeffs={coeffs:?} zeta={zeta}"
        );

        // Census.
        let mut census_rng = Rng::new(seed ^ 0x1234_5678_9ABC_DEF0);
        let survivors = census(&air, &trace, &pubs, &mut census_rng, M);

        assert!(
            survivors.is_empty(),
            "HornerFoldAir POTENTIAL SOUNDNESS FINDING at inst {inst}:\n\
             coeffs={coeffs:?} zeta={zeta}\n\
             First survivors (row, col): {:?}",
            survivors
                .iter()
                .take(5)
                .map(|(r, c, _, _)| (*r, *c))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn fuzz_relation_check_air() {
    let mut rng = Rng::new(0xC0DE_C0FF_EE00_1337);

    for inst in 0..N {
        let seed = rng.next_u64();
        let mut inst_rng = Rng::new(seed ^ (inst as u64 * 0xA0761D6478BD642F));

        // L in 3..8
        let l = (inst_rng.below(6) as usize) + 3; // 3..8

        let a: Vec<u64> = (0..l).map(|_| inst_rng.next_u64() % Q).collect();
        let w: Vec<u64> = (0..l).map(|_| inst_rng.next_u64() % Q).collect();

        // Set c so the relation holds: c = (q - (Σ a_j·w_j mod q)) mod q
        let q128 = u128::from(Q);
        let sum: u128 = a
            .iter()
            .zip(w.iter())
            .map(|(&ai, &wi)| u128::from(ai) * u128::from(wi))
            .sum();
        let c = ((q128 - (sum % q128)) % q128) as u64;

        let air = RelationCheckAir { num_terms: l };

        let (trace, pubs) = generate_relation_trace(&a, &w, c)
            .unwrap_or_else(|e| panic!("RelationCheckAir inst {inst}: trace gen failed: {e:?}"));

        // Completeness.
        assert!(
            accepts(&air, &trace, &pubs),
            "RelationCheckAir inst {inst}: valid trace rejected. L={l} a={a:?} w={w:?} c={c}"
        );

        // Census.
        let mut census_rng = Rng::new(seed ^ 0xABCD_EF01_2345_6789);
        let survivors = census(&air, &trace, &pubs, &mut census_rng, M);

        assert!(
            survivors.is_empty(),
            "RelationCheckAir POTENTIAL SOUNDNESS FINDING at inst {inst}:\n\
             L={l} a={a:?} w={w:?} c={c}\n\
             First survivors (row, col): {:?}",
            survivors
                .iter()
                .take(5)
                .map(|(r, c_col, _, _)| (*r, *c_col))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn fuzz_encode_mu_fold_air() {
    // The encode(μ) fold is a 256-row trace (394 cols); use a lighter budget than the tiny AIRs.
    const EM_N: usize = 16; // instances
    const EM_M: usize = 200; // mutations per instance
    let mut rng = Rng::new(0x0EA7_C0DE_F00D_1234);
    let air = EncodeMuFoldAir;

    for inst in 0..EM_N {
        let seed = rng.next_u64();
        let mut inst_rng = Rng::new(seed ^ (inst as u64 * 0x2545_F491_4F6C_DD1D));

        // Random 32-byte message and random ζ < q.
        let mut mu = [0u8; 32];
        for b in mu.iter_mut() {
            *b = (inst_rng.next_u64() & 0xFF) as u8;
        }
        let zeta = inst_rng.next_u64() % Q;

        let (trace, _e) = generate_encode_mu_trace(&mu, zeta)
            .unwrap_or_else(|e| panic!("EncodeMuFoldAir inst {inst}: trace gen failed: {e:?}"));
        let pubs = encode_mu_public_values(zeta);

        // Completeness.
        assert!(
            accepts(&air, &trace, &pubs),
            "EncodeMuFoldAir inst {inst}: valid trace rejected. mu={mu:?} zeta={zeta}"
        );

        // Census.
        let mut census_rng = Rng::new(seed ^ 0x5DEE_CE66_1234_ABCD);
        let survivors = census(&air, &trace, &pubs, &mut census_rng, EM_M);

        assert!(
            survivors.is_empty(),
            "EncodeMuFoldAir POTENTIAL SOUNDNESS FINDING at inst {inst}:\n\
             zeta={zeta}\n\
             First survivors (row, col): {:?}",
            survivors
                .iter()
                .take(5)
                .map(|(r, c, _, _)| (*r, *c))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn fuzz_shake_sponge_air() {
    // The sponge AIR wraps the 2633-col Keccak trace, so use a small trace (2 permutations, 48 rows)
    // and a light budget. Unlike the dense arithmetic AIRs, the Keccak `export` column (index 24) is
    // a FREE boolean on final-step rows (KeccakAir's LogUp hook; unused by ShakeSpongeAir), so a
    // surviving mutation there is EXPECTED and benign — the assertion allowlists exactly that cell.
    const KECCAK_EXPORT_COL: usize = 24;
    const KECCAK_ROUNDS: usize = 24;
    const SP_N: usize = 5; // instances
    const SP_M: usize = 60; // mutations per instance

    let mut rng = Rng::new(0x5A17_C0DE_BEEF_0F0F);
    let air = ShakeSpongeAir::default();

    for inst in 0..SP_N {
        let seed = rng.next_u64();
        let mut inst_rng = Rng::new(seed ^ (inst as u64 * 0xD1B5_4A32_D192_ED03));

        // Real encap preimage `DOM_FO_SEED ‖ pk_digest ‖ μ` (random pk_digest + μ; the label is the
        // pinned constant), 2 permutations. The pk_digest public values must be passed or the AIR's
        // public-value read panics on every check.
        let mut pk = [0u8; 32];
        let mut mu = [0u8; 32];
        for b in pk.iter_mut() {
            *b = (inst_rng.next_u64() & 0xFF) as u8;
        }
        for b in mu.iter_mut() {
            *b = (inst_rng.next_u64() & 0xFF) as u8;
        }
        let input = encap_preimage(&pk, &mu);
        let pubs = sponge_public_values(&pk);
        let trace = generate_sponge_air_trace(&input, 200); // 1 absorb + 2 squeeze - 1 = 2 perms

        // Completeness.
        assert!(
            accepts(&air, &trace, &pubs),
            "ShakeSpongeAir inst {inst}: valid sponge trace rejected"
        );

        // Census — survivors must be confined to the benign `export` cell on final-step rows.
        let mut census_rng = Rng::new(seed ^ 0x9E37_79B9_7F4A_7C15);
        let survivors = census(&air, &trace, &pubs, &mut census_rng, SP_M);

        let bad: Vec<_> = survivors
            .iter()
            .filter(|(r, c, _, _)| {
                !(*c == KECCAK_EXPORT_COL && *r % KECCAK_ROUNDS == KECCAK_ROUNDS - 1)
            })
            .map(|(r, c, _, _)| (*r, *c))
            .collect();
        assert!(
            bad.is_empty(),
            "ShakeSpongeAir POTENTIAL SOUNDNESS FINDING at inst {inst}: survivors outside the benign \
             export cell (row, col): {bad:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Negative control: canary AIR with one unconstrained column
// ---------------------------------------------------------------------------

#[test]
fn fuzz_canary_unconstrained_column() {
    let air = CanaryAir;
    // Build a height-4 trace: col0 = 1 (valid), col1 = arbitrary constant 42.
    let height = 4usize;
    let width = 2usize;
    let mut values: Vec<ConfigVal> = Vec::with_capacity(height * width);
    for _ in 0..height {
        values.push(ConfigVal::ONE); // col 0 = 1
        values.push(cv_real(42)); // col 1 = 42 (unconstrained)
    }
    let trace = RowMajorMatrix::new(values, width);

    // The valid trace must be accepted.
    assert!(
        accepts(&air, &trace, &[]),
        "CanaryAir: valid trace rejected — harness is broken"
    );

    // Run census with a generous budget so we're sure to find survivors in col 1.
    let mut rng = Rng::new(0x0101_CAFE_F00D_BABE);
    let survivors = census(&air, &trace, &[], &mut rng, 600);

    // The harness MUST find survivors (proves it is working).
    assert!(
        !survivors.is_empty(),
        "CanaryAir: census found NO survivors — the harness is broken and cannot detect \
         under-constrained columns"
    );

    // All survivors must be in col 1 (the unconstrained one).
    // Col 0 is pinned to 1; any mutation there changes it away from 1 and breaks assert_eq.
    for &(row, col, ref _old, ref _new) in &survivors {
        assert_eq!(
            col, 1,
            "CanaryAir: survivor found in col {col} (row {row}), expected only col 1. \
             This means col 0 is not being enforced correctly."
        );
    }
}
