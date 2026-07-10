//! Property-based **constraint-fuzzing** scaffold for the `unlinkable_membership` AIR.
//!
//! The idea: evaluate the AIR's constraints on a CONCRETE trace window without ever running
//! the prover / FRI. A [`RecordingBuilder`] implements the real [`AirBuilder`] trait with
//! `Expr == Var == F` (a field element), and every `assert_zero` residual is *recorded* rather
//! than asserted. Checking a trace then reduces to "are all recorded residuals zero on every
//! row" — cheap enough to sweep thousands of mutated traces.
//!
//! This mirrors the crate-internal `DebugConstraintBuilder` (see
//! `lib-q-stark/src/check_constraints.rs`), but instead of panicking on the first nonzero
//! residual it collects them, so we can *quantify* sensitivity: how many constraints does a
//! given mutation actually trip?
//!
//! Two properties are exercised:
//!
//! 1. **Completeness** ([`honest_trace_all_residuals_zero`]): an honest membership trace
//!    (built by the crate's own `generate_membership_trace`) makes every recorded residual
//!    zero on every row. This is the must-pass green test.
//!
//! 2. **Under-constraint / sensitivity** ([`statement_changing_mutation_trips_a_constraint`]):
//!    mutating the public statement (root / ctx / N) — which is what the proof is supposed to
//!    bind — must cause at least one recorded residual to become nonzero on some row. If ALL
//!    residuals stayed zero while the statement changed, that would be an under-constraint bug
//!    (the AIR fails to bind the public input); the test asserts this never happens.
//!
//! ## Honest limits
//!
//! This is **sampling-based testing, not a proof**. Passing says nothing about O1 round-count
//! security, nothing about the Poseidon-256 GF(p²) round counts (which are RED / unverified —
//! see the AIR header), and nothing about soundness against a *witness-side* forgery that we
//! did not happen to sample. It only checks that the constraint system, as evaluated on the
//! traces we generate, (a) accepts honest traces and (b) is not blind to changes in the public
//! statement. It reuses the crate's real honest-trace builder, so the completeness arm is
//! meaningful; the sensitivity arm samples a deterministic pseudo-random schedule of statement
//! mutations.
//!
//! ## Dependency choice
//!
//! `proptest` is NOT a dev-dependency of `lib-q-zkp`, so — per the scaffold brief — we do NOT
//! add a new external dependency. Instead we drive the sweep with a small deterministic
//! xorshift64 PRNG seeded from a fixed constant. Zero new deps, fully reproducible.

#![cfg(feature = "zkp")]

use lib_q_poseidon::PoseidonField;
use lib_q_stark_air::{
    Air,
    AirBuilder,
    RowWindow,
};
use lib_q_stark_field::PrimeCharacteristicRing;
use lib_q_stark_matrix::Matrix;
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_zkp::air::unlinkable_membership::{
    MEMBERSHIP_ROW_WIDTH,
    UnlinkableMembershipAir,
    generate_membership_trace,
    membership_leaf,
    membership_nullifier,
    membership_public_values,
    SECRET_T_ELEMS,
    CTX_ELEMS,
};
use lib_q_zkp::air::wide_hash::WideDigest;
use lib_q_zkp::merkle::WidePoseidonMerkleTree;

/// The concrete field the membership AIR is instantiated over: GF(p²) over Mersenne-31.
type F = PoseidonField;

// --- Public-value layout, mirrored from the (private) constants in
//     `lib-q-zkp/src/air/unlinkable_membership.rs`:
//         `[ root(5) ‖ ctx(2) ‖ N(5) ]`
//     These are asserted by that module's `layout_constants_are_consistent` test, so pinning
//     them here is safe; if the layout ever changes, this file will fail loudly. ---
const PUB_ROOT_START: usize = 0;
const PUB_CTX_START: usize = 5;
const PUB_NULL_START: usize = 7;

// =====================================================================================
// RecordingBuilder — a concrete AirBuilder that records residuals instead of asserting.
// =====================================================================================

/// A concrete [`AirBuilder`] that evaluates constraints on a two-row trace window and *records*
/// each `assert_zero` residual (the field value that is supposed to be zero) instead of
/// panicking. `Expr == Var == F`, so every constraint collapses to a field element the moment
/// it is asserted — exactly like the crate-internal `DebugConstraintBuilder`, but collecting.
struct RecordingBuilder<'a> {
    main: RowWindow<'a, F>,
    preprocessed: RowWindow<'a, F>,
    public_values: &'a [F],
    is_first_row: F,
    is_last_row: F,
    is_transition: F,
    /// Every residual passed to `assert_zero` on this row.
    residuals: Vec<F>,
}

impl<'a> AirBuilder for RecordingBuilder<'a> {
    type F = F;
    type Expr = F;
    type Var = F;
    type PreprocessedWindow = RowWindow<'a, F>;
    type MainWindow = RowWindow<'a, F>;
    type PublicVar = F;

    fn main(&self) -> Self::MainWindow {
        self.main
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.preprocessed
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }

    fn is_first_row(&self) -> Self::Expr {
        self.is_first_row
    }

    fn is_last_row(&self) -> Self::Expr {
        self.is_last_row
    }

    /// # Panics
    /// Panics if `size != 2` (the membership AIR only uses a 2-row window).
    fn is_transition_window(&self, size: usize) -> Self::Expr {
        assert_eq!(size, 2, "RecordingBuilder only supports a window size of 2");
        self.is_transition
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.residuals.push(x.into());
    }
}

/// Result of recording every constraint residual across a whole trace.
struct Recording {
    /// `(row_index, residual)` for every residual that was NONZERO.
    nonzero: Vec<(usize, F)>,
    /// Total number of residuals recorded (across all rows).
    total: usize,
}

impl Recording {
    fn is_all_zero(&self) -> bool {
        self.nonzero.is_empty()
    }
}

/// Evaluate `air` over every row of `trace` (current + next with wraparound, matching
/// `check_constraints`) and record all constraint residuals.
fn record_constraints(
    air: &UnlinkableMembershipAir,
    trace: &RowMajorMatrix<F>,
    public_values: &[F],
) -> Recording {
    let height = trace.height();
    let mut nonzero = Vec::new();
    let mut total = 0usize;

    for row_index in 0..height {
        let row_index_next = (row_index + 1) % height;
        let local = trace.row_slice(row_index).expect("row in range");
        let next = trace.row_slice(row_index_next).expect("row in range");
        let main = RowWindow::from_two_rows(&*local, &*next);
        let empty: [F; 0] = [];
        let preprocessed = RowWindow::from_two_rows(&empty, &empty);

        let mut builder = RecordingBuilder {
            main,
            preprocessed,
            public_values,
            is_first_row: F::from_bool(row_index == 0),
            is_last_row: F::from_bool(row_index == height - 1),
            is_transition: F::from_bool(row_index != height - 1),
            residuals: Vec::new(),
        };
        air.eval(&mut builder);

        total += builder.residuals.len();
        for r in builder.residuals {
            if r != F::ZERO {
                nonzero.push((row_index, r));
            }
        }
    }

    Recording { nonzero, total }
}

// =====================================================================================
// Honest-trace fixtures (reuse the crate's real trace builder + Merkle tree).
// =====================================================================================

fn fe(x: u32) -> F {
    F::from(lib_q_stark_mersenne31::Mersenne31::new(x))
}

fn secret(seed: u32) -> [F; SECRET_T_ELEMS] {
    core::array::from_fn(|i| fe(seed.wrapping_mul(7).wrapping_add(i as u32 + 1)))
}

fn ctx_of(seed: u32) -> [F; CTX_ELEMS] {
    core::array::from_fn(|i| fe(seed.wrapping_mul(13).wrapping_add(i as u32 + 100)))
}

/// A depth-4 (16-leaf) membership tree over secrets `0..16`, plus the secrets.
fn build_tree() -> (WidePoseidonMerkleTree, Vec<[F; SECRET_T_ELEMS]>) {
    let secrets: Vec<_> = (0..16u32).map(secret).collect();
    let leaves: Vec<WideDigest> = secrets.iter().map(membership_leaf).collect();
    let tree = WidePoseidonMerkleTree::from_leaf_digests(&leaves).expect("tree");
    (tree, secrets)
}

/// Build an honest (trace, public_values) pair for member `index`.
fn honest_case(
    tree: &WidePoseidonMerkleTree,
    secrets: &[[F; SECRET_T_ELEMS]],
    index: usize,
) -> (RowMajorMatrix<F>, Vec<F>) {
    let t = secrets[index];
    let ctx = ctx_of(index as u32);
    let (path_bits, siblings) = tree.path(index).expect("path");
    let trace = generate_membership_trace::<F>(&t, &ctx, &path_bits, &siblings);
    let n = membership_nullifier(&t, &ctx);
    let pubs = membership_public_values::<F>(&tree.root(), &ctx, &n);
    (trace, pubs)
}

// =====================================================================================
// Deterministic xorshift64 PRNG (no external deps).
// =====================================================================================

struct XorShift64(u64);

impl XorShift64 {
    fn new(seed: u64) -> Self {
        // Avoid the all-zero fixed point.
        XorShift64(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }

    /// A random nonzero field element (so a mutation actually perturbs the target cell).
    fn nonzero_fe(&mut self) -> F {
        loop {
            // Mersenne31 is < 2^31; mask to stay in range and land on a valid element.
            let v = (self.next_u64() & 0x7fff_ffff) as u32 % ((1u32 << 31) - 1);
            let f = fe(v);
            if f != F::ZERO {
                return f;
            }
        }
    }
}

// =====================================================================================
// Property 1 — Completeness.
// =====================================================================================

/// An honest membership trace makes every recorded constraint residual zero on every row.
///
/// This is the must-pass green test. It also sanity-checks that the AIR actually emitted a
/// non-trivial number of constraints (so a builder that silently records nothing can't pass).
#[test]
fn honest_trace_all_residuals_zero() {
    let (tree, secrets) = build_tree();
    assert_eq!(tree.depth(), 4);
    let air = UnlinkableMembershipAir;

    for index in [0usize, 5, 11, 15] {
        let (trace, pubs) = honest_case(&tree, &secrets, index);
        assert_eq!(trace.width(), MEMBERSHIP_ROW_WIDTH);
        let rec = record_constraints(&air, &trace, &pubs);
        assert!(
            rec.total > 100,
            "index {index}: AIR emitted only {} residuals — recorder likely mis-wired",
            rec.total
        );
        assert!(
            rec.is_all_zero(),
            "index {index}: honest trace has {} nonzero residual(s), first: row {} value {:?}",
            rec.nonzero.len(),
            rec.nonzero[0].0,
            rec.nonzero[0].1,
        );
    }
}

// =====================================================================================
// Property 2 — Under-constraint / sensitivity.
// =====================================================================================

/// Mutating the public statement (root / ctx / N) must trip at least one constraint.
///
/// We sweep a deterministic pseudo-random schedule of single-slot public-value mutations. For
/// each: the honest trace is left intact but one public-statement element is perturbed by a
/// nonzero field element (so root / ctx / N genuinely changes). Because the AIR binds all three
/// on row 0 / the last row, at least one recorded residual MUST become nonzero. If any sampled
/// mutation left every residual zero, that is a genuine under-constraint finding and this test
/// fails loudly (do NOT suppress — it means the AIR fails to bind that public slot).
#[test]
fn statement_changing_mutation_trips_a_constraint() {
    let (tree, secrets) = build_tree();
    let air = UnlinkableMembershipAir;

    // The public slots that are load-bearing (the entire statement `[root ‖ ctx ‖ N]`).
    let statement_slots: Vec<usize> = (PUB_ROOT_START..PUB_NULL_START + 5).collect();
    debug_assert_eq!(statement_slots.len(), 12);
    debug_assert!(statement_slots.contains(&PUB_CTX_START));

    let mut rng = XorShift64::new(0x5eed_1234_c0ff_ee01);
    let members = [0usize, 3, 7, 9, 11, 15];

    // Each case re-evaluates the whole (~8600-col, 1428-elem-per-sponge-block) trace, so a debug
    // build is heavy. `CASES` is deliberately modest — enough to hit every one of the 12
    // statement slots across several members many times over. Bump it (or run `--release`) for a
    // deeper sweep; see the `deep_statement_sweep` ignored test below.
    const CASES: usize = 256;

    let mut cases = 0usize;
    let mut missed: Vec<(usize, usize)> = Vec::new(); // (member, slot) that failed to trip

    for _ in 0..CASES {
        let index = members[rng.below(members.len())];
        let (trace, pubs) = honest_case(&tree, &secrets, index);

        // Perturb exactly one statement slot by a nonzero delta.
        let slot = statement_slots[rng.below(statement_slots.len())];
        let mut mutated = pubs.clone();
        let delta = rng.nonzero_fe();
        let before = mutated[slot];
        mutated[slot] = before + delta;
        // Guard: the statement genuinely changed.
        assert_ne!(mutated[slot], before, "mutation must change the statement slot");

        let rec = record_constraints(&air, &trace, &mutated);
        if rec.is_all_zero() {
            missed.push((index, slot));
        }
        cases += 1;
    }

    assert_eq!(cases, CASES);
    assert!(
        missed.is_empty(),
        "UNDER-CONSTRAINT FINDING: {} statement mutation(s) left ALL residuals zero. \
         Sample (member,pub_slot): {:?}. The AIR does not bind these public slots.",
        missed.len(),
        &missed[..missed.len().min(8)],
    );
}

/// Deeper, slower version of the statement sweep. `#[ignore]` by default because in a debug
/// build each case re-evaluates the full trace; run explicitly (ideally `--release`) with
/// `cargo test -p lib-q-zkp --features zkp --test constraint_fuzz_membership -- --ignored`.
#[test]
#[ignore = "slow: full-trace re-eval per case; run explicitly, ideally in --release"]
fn deep_statement_sweep() {
    let (tree, secrets) = build_tree();
    let air = UnlinkableMembershipAir;
    let statement_slots: Vec<usize> = (PUB_ROOT_START..PUB_NULL_START + 5).collect();
    let members = [0usize, 3, 7, 9, 11, 15];
    let mut rng = XorShift64::new(0x5eed_1234_c0ff_ee01);
    let mut missed: Vec<(usize, usize)> = Vec::new();

    for _ in 0..4000 {
        let index = members[rng.below(members.len())];
        let (trace, pubs) = honest_case(&tree, &secrets, index);
        let slot = statement_slots[rng.below(statement_slots.len())];
        let mut mutated = pubs.clone();
        mutated[slot] = mutated[slot] + rng.nonzero_fe();
        if record_constraints(&air, &trace, &mutated).is_all_zero() {
            missed.push((index, slot));
        }
    }
    assert!(
        missed.is_empty(),
        "UNDER-CONSTRAINT FINDING (deep sweep): {} mutation(s) left all residuals zero: {:?}",
        missed.len(),
        &missed[..missed.len().min(8)],
    );
}

/// Companion sanity check: a single-cell mutation to a load-bearing WITNESS cell that changes
/// the recomputed statement (here, the row-0 secret `t`, which drives both leaf L and
/// nullifier N) must also trip a constraint. This exercises the trace side rather than the
/// public side. `t` starts at the (documented) leaf region column; mutating it breaks the
/// `running == H(t)` leaf binding and the nullifier binding.
#[test]
fn tampered_secret_trips_a_constraint() {
    let (tree, secrets) = build_tree();
    let air = UnlinkableMembershipAir;

    // T_START == LEAF_REGION_START == 8579 (see the AIR's `layout_constants_are_consistent`).
    const T_START: usize = 8579;

    let mut rng = XorShift64::new(0xabcd_0001_0002_0003);
    for index in [0usize, 4, 11, 15] {
        let (mut trace, pubs) = honest_case(&tree, &secrets, index);
        let col = T_START + rng.below(SECRET_T_ELEMS);
        let idx = 0 * MEMBERSHIP_ROW_WIDTH + col; // row 0
        let delta = rng.nonzero_fe();
        trace.values[idx] += delta;

        let rec = record_constraints(&air, &trace, &pubs);
        assert!(
            !rec.is_all_zero(),
            "index {index}: tampering row-0 secret cell {col} left all residuals zero \
             (under-constraint: t is not bound)",
        );
    }
}
