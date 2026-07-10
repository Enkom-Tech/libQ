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
//!
//! ## Two arms
//!
//! The membership statement has two AIR instantiations. The [`RecordingBuilder`] is generic over
//! the field, so a single recorder drives both:
//!
//! * **Arm A** (`unlinkable_membership`, GF(p²) / Poseidon-256): the original, slower arm. Its
//!   heavier sweeps stay behind `#[ignore]` (see [`deep_statement_sweep`]).
//! * **Arm B** (`unlinkable_membership_baby_bear`, BabyBear / Poseidon2): the recommended, much
//!   faster instantiation. Its tests run by DEFAULT with a healthy case count.
//!
//! ## Cross-member forgery probe
//!
//! Single-cell mutation only catches *unbound* inputs. The sharper soundness probe (for both arms)
//! builds TWO fully-honest traces for distinct members A and B — so every sponge intermediate is
//! correctly computed in each — and then evaluates member B's genuine trace against member A's
//! PUBLIC statement. Because both traces are internally consistent, all sponge-round constraints
//! hold by construction; the ONLY constraints that can catch the swap are the *binding* ones
//! (running==root on the last row, ctx==public, N==public). A nonzero residual there is exactly
//! what soundness requires; if a pairing left ALL residuals zero, that would be a real
//! cross-member forgery / under-constraint finding, surfaced loudly. This isolates *binding* from
//! *sponge correctness*, which single-cell tampering cannot.

#![cfg(feature = "zkp")]

use lib_q_poseidon::PoseidonField;
use lib_q_stark_air::{
    Air,
    AirBuilder,
    BaseAir,
    RowWindow,
};
// --- Arm B (BabyBear / Poseidon2) analogues. ---
use lib_q_stark_baby_bear::BabyBear;
use lib_q_stark_field::{
    Field,
    PrimeCharacteristicRing,
};
use lib_q_stark_matrix::Matrix;
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_zkp::air::unlinkable_membership::{
    CTX_ELEMS,
    MEMBERSHIP_ROW_WIDTH,
    SECRET_T_ELEMS,
    UnlinkableMembershipAir,
    generate_membership_trace,
    membership_leaf,
    membership_nullifier,
    membership_public_values,
};
use lib_q_zkp::air::unlinkable_membership_baby_bear::{
    CTX_ELEMS as CTX_ELEMS_BB,
    MEMBERSHIP_ROW_WIDTH as MEMBERSHIP_ROW_WIDTH_BB,
    SECRET_T_ELEMS as SECRET_T_ELEMS_BB,
    UnlinkableMembershipBbAir,
    generate_membership_trace_bb,
    membership_leaf_bb,
    membership_nullifier_bb,
    membership_public_values_bb,
};
use lib_q_zkp::air::wide_hash::WideDigest;
use lib_q_zkp::air::wide_merkle_path_baby_bear::WideDigestBb;
use lib_q_zkp::merkle::WidePoseidonMerkleTree;
use lib_q_zkp::merkle_baby_bear::WidePoseidonMerkleTreeBb;

/// The concrete field the Arm A membership AIR is instantiated over: GF(p²) over Mersenne-31.
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
/// panicking. `Expr == Var == K`, so every constraint collapses to a field element the moment
/// it is asserted — exactly like the crate-internal `DebugConstraintBuilder`, but collecting.
///
/// Generic over the field `K` so ONE recorder drives both arms: Arm A over GF(p²)
/// ([`PoseidonField`]) and Arm B over [`BabyBear`]. Every `when_*`/`assert_*` helper on
/// [`AirBuilder`] is a default method that funnels into `assert_zero`, so this minimal impl
/// captures every constraint either AIR emits.
struct RecordingBuilder<'a, K: Field> {
    main: RowWindow<'a, K>,
    preprocessed: RowWindow<'a, K>,
    public_values: &'a [K],
    is_first_row: K,
    is_last_row: K,
    is_transition: K,
    /// Every residual passed to `assert_zero` on this row.
    residuals: Vec<K>,
}

impl<'a, K: Field> AirBuilder for RecordingBuilder<'a, K> {
    type F = K;
    type Expr = K;
    type Var = K;
    type PreprocessedWindow = RowWindow<'a, K>;
    type MainWindow = RowWindow<'a, K>;
    type PublicVar = K;

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

/// Result of recording every constraint residual across a whole trace. Generic over the field so
/// it serves both arms.
struct Recording<K: Field> {
    /// `(row_index, residual)` for every residual that was NONZERO.
    nonzero: Vec<(usize, K)>,
    /// Total number of residuals recorded (across all rows).
    total: usize,
}

impl<K: Field> Recording<K> {
    fn is_all_zero(&self) -> bool {
        self.nonzero.is_empty()
    }
}

/// Evaluate `air` over every row of `trace` (current + next with wraparound, matching
/// `check_constraints`) and record all constraint residuals. Generic over the field `K` and the
/// AIR, so it drives both the Arm A ([`UnlinkableMembershipAir`]) and Arm B
/// ([`UnlinkableMembershipBbAir`]) AIRs.
fn record_constraints<K, A>(air: &A, trace: &RowMajorMatrix<K>, public_values: &[K]) -> Recording<K>
where
    K: Field,
    A: for<'a> Air<RecordingBuilder<'a, K>> + BaseAir<K>,
{
    let height = trace.height();
    let mut nonzero = Vec::new();
    let mut total = 0usize;

    for row_index in 0..height {
        let row_index_next = (row_index + 1) % height;
        let local = trace.row_slice(row_index).expect("row in range");
        let next = trace.row_slice(row_index_next).expect("row in range");
        let main = RowWindow::from_two_rows(&local, &next);
        let empty: [K; 0] = [];
        let preprocessed = RowWindow::from_two_rows(&empty, &empty);

        let mut builder = RecordingBuilder {
            main,
            preprocessed,
            public_values,
            is_first_row: K::from_bool(row_index == 0),
            is_last_row: K::from_bool(row_index == height - 1),
            is_transition: K::from_bool(row_index != height - 1),
            residuals: Vec::new(),
        };
        air.eval(&mut builder);

        total += builder.residuals.len();
        for r in builder.residuals {
            if r != K::ZERO {
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

    /// A random nonzero Arm A field element (so a mutation actually perturbs the target cell).
    fn nonzero_fe(&mut self) -> F {
        loop {
            // Mersenne31 is < 2^31; mask to stay in range and land on a valid element.
            let v = (self.next_u64() & 0x7FFF_FFFF) as u32 % ((1u32 << 31) - 1);
            let f = fe(v);
            if f != F::ZERO {
                return f;
            }
        }
    }

    /// A random nonzero Arm B (BabyBear) field element.
    fn nonzero_fe_bb(&mut self) -> BabyBear {
        // BabyBear prime p = 2^31 - 2^27 + 1 = 2_013_265_921.
        const P: u32 = 2_013_265_921;
        loop {
            let v = (self.next_u64() & 0x7FFF_FFFF) as u32 % P;
            let f = BabyBear::new(v);
            if f != BabyBear::ZERO {
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
///
/// `#[ignore]` in CI: even at 256 cases this re-evaluates the full GF(p²) trace per case (~100s
/// in debug). The equivalent Arm B sweep (`statement_changing_mutation_trips_a_constraint_bb`) is
/// ~500x faster and runs by default, giving the same coverage on the recommended arm; run this one
/// explicitly with `-- --ignored` when auditing Arm A.
#[test]
#[ignore = "slow: full GF(p²) trace re-eval per case (~100s debug); Arm B sweep covers CI"]
fn statement_changing_mutation_trips_a_constraint() {
    let (tree, secrets) = build_tree();
    let air = UnlinkableMembershipAir;

    // The public slots that are load-bearing (the entire statement `[root ‖ ctx ‖ N]`).
    let statement_slots: Vec<usize> = (PUB_ROOT_START..PUB_NULL_START + 5).collect();
    debug_assert_eq!(statement_slots.len(), 12);
    debug_assert!(statement_slots.contains(&PUB_CTX_START));

    let mut rng = XorShift64::new(0x5EED_1234_C0FF_EE01);
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
        assert_ne!(
            mutated[slot], before,
            "mutation must change the statement slot"
        );

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
    let mut rng = XorShift64::new(0x5EED_1234_C0FF_EE01);
    let mut missed: Vec<(usize, usize)> = Vec::new();

    for _ in 0..4000 {
        let index = members[rng.below(members.len())];
        let (trace, pubs) = honest_case(&tree, &secrets, index);
        let slot = statement_slots[rng.below(statement_slots.len())];
        let mut mutated = pubs.clone();
        mutated[slot] += rng.nonzero_fe();
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

    let mut rng = XorShift64::new(0xABCD_0001_0002_0003);
    for index in [0usize, 4, 11, 15] {
        let (mut trace, pubs) = honest_case(&tree, &secrets, index);
        let col = T_START + rng.below(SECRET_T_ELEMS);
        let idx = col; // row 0: offset is 0 * MEMBERSHIP_ROW_WIDTH
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

// =====================================================================================
// Cross-member forgery probe (Arm A). The meaningful soundness probe: bind member B's
// genuine trace to member A's public statement. See the module header.
// =====================================================================================

/// Try to pass member B's fully-honest trace against member A's public statement. Both traces are
/// internally consistent, so every sponge-round constraint holds; only the *binding* constraints
/// (running==root, ctx==pub, N==pub) can catch the swap. A nonzero residual there is required. If
/// ANY pairing leaves all residuals zero, that is a genuine cross-member forgery finding.
#[test]
fn cross_member_forgery_arm_a() {
    let (tree, secrets) = build_tree();
    let air = UnlinkableMembershipAir;

    // A handful of distinct member pairs, each direction.
    let pairs = [(0usize, 1usize), (3, 7), (11, 15), (5, 9)];
    let mut forgeries: Vec<(usize, usize)> = Vec::new();

    for (a, b) in pairs {
        for (owner, other) in [(a, b), (b, a)] {
            // `other`'s honest trace, `owner`'s public statement.
            let (trace_other, _pubs_other) = honest_case(&tree, &secrets, other);
            let (_trace_owner, pubs_owner) = honest_case(&tree, &secrets, owner);
            let rec = record_constraints(&air, &trace_other, &pubs_owner);
            if rec.is_all_zero() {
                forgeries.push((other, owner));
            }
        }
    }

    assert!(
        forgeries.is_empty(),
        "CROSS-MEMBER FORGERY FINDING (Arm A): member B's honest trace satisfied member A's \
         public statement with ZERO residuals for (trace_member, statement_member): {forgeries:?}. \
         The binding constraints fail to tie the witness to the public statement.",
    );
}

// =====================================================================================
// Arm B (BabyBear / Poseidon2) — the recommended, fast instantiation. Runs by DEFAULT.
// =====================================================================================
//
// Public-value layout for Arm B, mirrored from `unlinkable_membership_baby_bear.rs`:
//     `[ root(9) ‖ ctx(4) ‖ N(9) ]`  (WIDE_DIGEST_ELEMS = 9, CTX_ELEMS_BB = 4).
// Pinned here; the AIR module's own `row_width_and_publics` test guards the widths, so a layout
// change surfaces loudly.
const PUB_ROOT_START_BB: usize = 0;
const PUB_CTX_START_BB: usize = 9;
const PUB_NULL_START_BB: usize = 13;
const MEMBERSHIP_NUM_PUBLIC_BB: usize = 22;

fn fe_bb(x: u32) -> BabyBear {
    BabyBear::new(x)
}

fn secret_bb(seed: u32) -> [BabyBear; SECRET_T_ELEMS_BB] {
    core::array::from_fn(|i| fe_bb(seed.wrapping_mul(7).wrapping_add(i as u32 + 1)))
}

fn ctx_of_bb(seed: u32) -> [BabyBear; CTX_ELEMS_BB] {
    core::array::from_fn(|i| fe_bb(seed.wrapping_mul(13).wrapping_add(i as u32 + 100)))
}

/// A depth-4 (16-leaf) BabyBear membership tree over secrets `0..16`, plus the secrets.
fn build_tree_bb() -> (WidePoseidonMerkleTreeBb, Vec<[BabyBear; SECRET_T_ELEMS_BB]>) {
    let secrets: Vec<_> = (0..16u32).map(secret_bb).collect();
    let leaves: Vec<WideDigestBb> = secrets.iter().map(membership_leaf_bb).collect();
    let tree = WidePoseidonMerkleTreeBb::from_leaf_digests(&leaves).expect("tree");
    (tree, secrets)
}

/// Build an honest (trace, public_values) pair for Arm B member `index`.
fn honest_case_bb(
    tree: &WidePoseidonMerkleTreeBb,
    secrets: &[[BabyBear; SECRET_T_ELEMS_BB]],
    index: usize,
) -> (RowMajorMatrix<BabyBear>, Vec<BabyBear>) {
    let t = secrets[index];
    let ctx = ctx_of_bb(index as u32);
    let (path_bits, siblings) = tree.path(index).expect("path");
    let trace = generate_membership_trace_bb(&t, &ctx, &path_bits, &siblings);
    let n = membership_nullifier_bb(&t, &ctx);
    let pubs = membership_public_values_bb(&tree.root(), &ctx, &n);
    (trace, pubs)
}

/// **Completeness (Arm B).** An honest BabyBear membership trace makes every recorded residual
/// zero on every row. Also sanity-checks a non-trivial residual count.
#[test]
fn honest_trace_all_residuals_zero_bb() {
    let (tree, secrets) = build_tree_bb();
    assert_eq!(tree.depth(), 4);
    let air = UnlinkableMembershipBbAir;

    for index in [0usize, 5, 11, 15] {
        let (trace, pubs) = honest_case_bb(&tree, &secrets, index);
        assert_eq!(trace.width(), MEMBERSHIP_ROW_WIDTH_BB);
        assert_eq!(pubs.len(), MEMBERSHIP_NUM_PUBLIC_BB);
        let rec = record_constraints(&air, &trace, &pubs);
        assert!(
            rec.total > 100,
            "index {index}: Arm B AIR emitted only {} residuals — recorder likely mis-wired",
            rec.total
        );
        assert!(
            rec.is_all_zero(),
            "index {index}: honest Arm B trace has {} nonzero residual(s), first: row {} value {:?}",
            rec.nonzero.len(),
            rec.nonzero[0].0,
            rec.nonzero[0].1,
        );
    }
}

/// **Under-constraint / sensitivity (Arm B).** Perturbing any single statement slot
/// (`[root ‖ ctx ‖ N]`) must trip at least one constraint. Arm B is fast, so we run a healthy,
/// un-`#[ignore]`d sweep. Any mutation that leaves all residuals zero is a genuine finding.
#[test]
fn statement_changing_mutation_trips_a_constraint_bb() {
    let (tree, secrets) = build_tree_bb();
    let air = UnlinkableMembershipBbAir;

    let statement_slots: Vec<usize> = (PUB_ROOT_START_BB..PUB_NULL_START_BB + 9).collect();
    debug_assert_eq!(statement_slots.len(), 22);
    debug_assert!(statement_slots.contains(&PUB_CTX_START_BB));

    let mut rng = XorShift64::new(0x5EED_1234_C0FF_EE02);
    let members = [0usize, 3, 7, 9, 11, 15];

    // Arm B is fast (small BabyBear field, no GF(p²) extension); a 4-row trace re-eval is cheap,
    // so a healthy case count runs by default.
    const CASES: usize = 1500;

    let mut missed: Vec<(usize, usize)> = Vec::new();
    for _ in 0..CASES {
        let index = members[rng.below(members.len())];
        let (trace, pubs) = honest_case_bb(&tree, &secrets, index);
        let slot = statement_slots[rng.below(statement_slots.len())];
        let mut mutated = pubs.clone();
        let before = mutated[slot];
        mutated[slot] = before + rng.nonzero_fe_bb();
        assert_ne!(
            mutated[slot], before,
            "mutation must change the statement slot"
        );

        if record_constraints(&air, &trace, &mutated).is_all_zero() {
            missed.push((index, slot));
        }
    }

    assert!(
        missed.is_empty(),
        "UNDER-CONSTRAINT FINDING (Arm B): {} statement mutation(s) left ALL residuals zero. \
         Sample (member,pub_slot): {:?}. The AIR does not bind these public slots.",
        missed.len(),
        &missed[..missed.len().min(8)],
    );
}

/// **Witness-tamper sensitivity (Arm B).** Corrupting the row-0 secret `t` (which drives both the
/// leaf and the nullifier) must trip a constraint.
#[test]
fn tampered_secret_trips_a_constraint_bb() {
    let (tree, secrets) = build_tree_bb();
    let air = UnlinkableMembershipBbAir;

    // T_START for Arm B == LEAF_REGION_START == 844 (see the AIR's column-layout constants).
    const T_START_BB: usize = 844;

    let mut rng = XorShift64::new(0xABCD_0001_0002_0004);
    for index in [0usize, 4, 11, 15] {
        let (mut trace, pubs) = honest_case_bb(&tree, &secrets, index);
        let col = T_START_BB + rng.below(SECRET_T_ELEMS_BB);
        let idx = col; // row 0
        trace.values[idx] += rng.nonzero_fe_bb();

        let rec = record_constraints(&air, &trace, &pubs);
        assert!(
            !rec.is_all_zero(),
            "index {index}: tampering row-0 secret cell {col} left all residuals zero \
             (under-constraint: t is not bound)",
        );
    }
}

/// **Cross-member forgery probe (Arm B).** Same construction as [`cross_member_forgery_arm_a`]:
/// bind member B's fully-honest trace to member A's public statement across several pairs and both
/// directions; every pairing MUST trip a binding constraint. Runs by default (Arm B is fast).
#[test]
fn cross_member_forgery_bb() {
    let (tree, secrets) = build_tree_bb();
    let air = UnlinkableMembershipBbAir;

    let pairs = [(0usize, 1usize), (3, 7), (11, 15), (5, 9), (2, 14)];
    let mut forgeries: Vec<(usize, usize)> = Vec::new();

    for (a, b) in pairs {
        for (owner, other) in [(a, b), (b, a)] {
            let (trace_other, _pubs_other) = honest_case_bb(&tree, &secrets, other);
            let (_trace_owner, pubs_owner) = honest_case_bb(&tree, &secrets, owner);
            let rec = record_constraints(&air, &trace_other, &pubs_owner);
            if rec.is_all_zero() {
                forgeries.push((other, owner));
            }
        }
    }

    assert!(
        forgeries.is_empty(),
        "CROSS-MEMBER FORGERY FINDING (Arm B): member B's honest trace satisfied member A's \
         public statement with ZERO residuals for (trace_member, statement_member): {forgeries:?}. \
         The binding constraints fail to tie the witness to the public statement.",
    );
}
