use alloc::vec;
use alloc::vec::Vec;

use itertools::Itertools;
use lib_q_stark_air::Air;
use lib_q_stark_challenger::{
    CanObserve,
    FieldChallenger,
};
use lib_q_stark_commit::{
    LagrangeSelectors,
    Pcs,
    PolynomialSpace,
};
use lib_q_stark_field::{
    BasedVectorSpace,
    PackedValue,
    PrimeCharacteristicRing,
};
use lib_q_stark_matrix::Matrix;
use lib_q_stark_matrix::dense::RowMajorMatrix;
#[cfg(feature = "parallel")]
use lib_q_stark_rayon::prelude::*;
use lib_q_stark_util::log2_strict_usize;
use tracing::{
    debug_span,
    info_span,
    instrument,
};

use crate::{
    Commitments,
    Domain,
    OpenedValues,
    PackedChallenge,
    PackedVal,
    PreprocessedProverData,
    Proof,
    ProverConstraintFolder,
    StarkGenericConfig,
    SymbolicAirBuilder,
    Val,
    get_log_num_quotient_chunks,
    get_symbolic_constraints,
};

/// Maximum trace height (2^30) to prevent memory exhaustion attacks.
/// This limits trace size to approximately 1 billion rows.
pub const MAX_TRACE_HEIGHT: usize = 1 << 30;

/// Panics if `height` exceeds [`MAX_TRACE_HEIGHT`]. Used for DoS protection and testability.
#[inline]
pub fn assert_trace_height_within_limit(height: usize) {
    if height > MAX_TRACE_HEIGHT {
        panic!(
            "Trace height {} exceeds maximum allowed {} (prevents memory exhaustion)",
            height, MAX_TRACE_HEIGHT
        );
    }
}

/// Maximum trace width to prevent memory exhaustion attacks.
/// This limits the number of columns in a trace.
const MAX_TRACE_WIDTH: usize = 1 << 20; // ~1 million columns

/// Maximum number of public values to prevent DoS attacks.
const MAX_PUBLIC_VALUES: usize = 1 << 20; // ~1 million public values

/// Generate a STARK proof for the given trace and AIR.
///
/// # Security Considerations
///
/// ## Memory Safety
/// The `trace` parameter contains secret witness data that must be protected.
/// - The trace matrix will be zeroized on drop if it contains field elements that implement `Zeroize`
/// - For additional protection, wrap the trace in `SecretWitness` before calling this function
/// - Intermediate values created during proof generation are automatically zeroized when dropped
///
/// ## Constant-Time Operations
/// All field operations should use constant-time implementations when processing secret values.
/// Use `constant_time` module functions for secret comparisons.
///
/// # Arguments
/// * `config` - STARK configuration including PCS and challenger
/// * `air` - Algebraic Intermediate Representation defining the constraints
/// * `trace` - Witness trace matrix (contains secret data - will be zeroized on drop)
/// * `public_values` - Public values known to both prover and verifier
/// * `preprocessed` - Optional preprocessed trace data
///
/// # Returns
/// A STARK proof that can be verified without revealing the witness trace.
#[cfg(debug_assertions)]
#[instrument(skip_all)]
pub fn prove_with_preprocessed<SC, A>(
    config: &SC,
    air: &A,
    trace: RowMajorMatrix<Val<SC>>,
    public_values: &[Val<SC>],
    preprocessed: Option<&PreprocessedProverData<SC>>,
) -> Proof<SC>
where
    SC: StarkGenericConfig,
    A: Air<SymbolicAirBuilder<Val<SC>>> + for<'a> Air<ProverConstraintFolder<'a, SC>>,
    A: for<'a> Air<crate::check_constraints::DebugConstraintBuilder<'a, Val<SC>>>,
{
    crate::check_constraints::check_constraints(air, &trace, public_values);
    prove_with_preprocessed_impl(config, air, trace, public_values, preprocessed)
}

#[cfg(not(debug_assertions))]
#[instrument(skip_all)]
pub fn prove_with_preprocessed<SC, A>(
    config: &SC,
    air: &A,
    trace: RowMajorMatrix<Val<SC>>,
    public_values: &[Val<SC>],
    preprocessed: Option<&PreprocessedProverData<SC>>,
) -> Proof<SC>
where
    SC: StarkGenericConfig,
    A: Air<SymbolicAirBuilder<Val<SC>>> + for<'a> Air<ProverConstraintFolder<'a, SC>>,
{
    prove_with_preprocessed_impl(config, air, trace, public_values, preprocessed)
}

fn prove_with_preprocessed_impl<SC, A>(
    config: &SC,
    air: &A,
    trace: RowMajorMatrix<Val<SC>>,
    public_values: &[Val<SC>],
    preprocessed: Option<&PreprocessedProverData<SC>>,
) -> Proof<SC>
where
    SC: StarkGenericConfig,
    A: Air<SymbolicAirBuilder<Val<SC>>> + for<'a> Air<ProverConstraintFolder<'a, SC>>,
{
    // Input validation to prevent DoS and invalid states
    let degree = trace.height();
    let width = trace.width();

    // Validate trace dimensions
    if degree == 0 {
        panic!("Trace height must be greater than 0");
    }
    if !degree.is_power_of_two() {
        panic!("Trace height must be a power of 2, got {}", degree);
    }
    assert_trace_height_within_limit(degree);
    if width == 0 {
        panic!("Trace width must be greater than 0");
    }
    if width > MAX_TRACE_WIDTH {
        panic!(
            "Trace width {} exceeds maximum allowed {} (prevents memory exhaustion)",
            width, MAX_TRACE_WIDTH
        );
    }
    if public_values.len() > MAX_PUBLIC_VALUES {
        panic!(
            "Number of public values {} exceeds maximum allowed {} (prevents DoS)",
            public_values.len(),
            MAX_PUBLIC_VALUES
        );
    }

    // Validate trace data consistency
    let expected_len = degree * width;
    if trace.values.len() != expected_len {
        panic!(
            "Trace data length {} does not match expected {} (height {} * width {})",
            trace.values.len(),
            expected_len,
            degree,
            width
        );
    }

    // Compute the height `N = 2^n` and `log_2(height)`, `n`, of the trace.
    let log_degree = log2_strict_usize(degree);
    let log_ext_degree = log_degree + config.is_zk();

    // Get preprocessed width for symbolic constraint evaluation.
    //
    // - If reusable preprocessed prover data is provided, trust its width and degree_bits
    //   (and enforce consistency).
    // - Otherwise, if the AIR defines preprocessed columns, we treat it as an error:
    //   callers must use `setup_preprocessed` and pass the resulting data in.
    let preprocessed_width = preprocessed.map_or_else(
        || {
            if let Some(preprocessed_trace) = air.preprocessed_trace() {
                let width = preprocessed_trace.width();
                if width > 0 {
                    panic!(
                        "AIR defines preprocessed columns (width = {}), \
                         but no PreprocessedProverData was provided. \
                         Call `setup_preprocessed` and pass it to `prove_with_preprocessed`.",
                        width
                    );
                }
            }
            0
        },
        |pp| {
            // Preprocessed columns are currently only supported in non-ZK mode.
            assert_eq!(
                config.is_zk(),
                0,
                "preprocessed columns are not supported in zk mode"
            );
            assert_eq!(
                pp.degree_bits, log_ext_degree,
                "PreprocessedProverData degree_bits does not match trace degree_bits"
            );
            pp.width
        },
    );

    // Compute the constraint polynomials as vectors of symbolic expressions.
    let symbolic_constraints =
        get_symbolic_constraints(air, preprocessed_width, public_values.len());

    // Count the number of constraints that we have.
    let constraint_count = symbolic_constraints.len();

    // Each constraint polynomial looks like `C_j(X_1, ..., X_w, Y_1, ..., Y_w, Z_1, ..., Z_j)`.
    // When evaluated on a given row, the X_i's will be the `i`'th element of the that row, the
    // Y_i's will be the `i`'th element of the next row and the Z_i's will be evaluations of
    // selector polynomials on the given row index.
    //
    // When we convert to working with polynomials, the `X_i`'s and `Y_i`'s will be replaced by the
    // degree `N - 1` polynomials `T_i(x)` and `T_i(hx)` respectively. The selector polynomials are
    //  a little more complicated however.
    //
    // In our our case, the selector polynomials are `S_1(x) = is_first_row`, `S_2(x) = is_last_row`
    // and `S_3(x) = is_transition`. Both `S_1(x)` and `S_2(x)` are polynomials of degree `N - 1`
    // as they must be non zero only at a single location in the initial domain. However, `is_transition`
    // is a polynomial of degree `1` as it simply need to be `0` on the last row.
    //
    // The constraint degree (`deg(C)`) is the linear factor of `N` in the constraint polynomial. In other
    // words, it is roughly the total degree of `C` however, we treat `Z_3` as a constant term which does
    // not contribute to the degree.
    //
    // E.g. `C_j = Z_1 * (X_1^3 - X_2 * X_3 * X_4)` would have degree `4`.
    //      `C_j = Z_3 * (X_1^3 - X_2 * X_3 * X_4)` would have degree `3`.
    //
    // The point of all this is that, defining:
    //          C(x) = C(T_1(x), ..., T_w(x), T_1(hx), ... T_w(hx), S_1(x), S_2(x), S_3(x))
    // We get the constraint bound:
    //          deg(C(x)) <= deg(C) * (N - 1) + 1
    // The `+1` is due to the `is_transition` selector which is not accounted for in `deg(C)`. Note
    // that S_i^2 should never appear in a constraint as it should just be replaced by `S_i`.
    //
    // For now in comments we assume that `deg(C) = 3` meaning `deg(C(x)) <= 3N - 2`

    // From the degree of the constraint polynomial, compute the number
    // of quotient polynomials we will split Q(x) into. This is chosen to
    // always be a power of 2.
    let log_num_quotient_chunks = get_log_num_quotient_chunks::<Val<SC>, A>(
        air,
        preprocessed_width,
        public_values.len(),
        config.is_zk(),
    );

    let num_quotient_chunks = 1 << (log_num_quotient_chunks + config.is_zk());

    let trace_to_commit = trace.clone();
    let degree_for_domains = degree;
    let log_ext_degree_commit = log_ext_degree;

    // Initialize the PCS and the Challenger.
    let pcs = config.pcs();
    let mut challenger = config.initialise_challenger();

    // Get the subgroup `H` of size `N`. We treat each column `T_i` of
    // the trace as an evaluation vector of polynomials `T_i(x)` over `H`.
    // (In the Circle STARK case `H` is instead a standard position twin coset of size `N`)
    let trace_domain = pcs.natural_domain_for_degree(degree_for_domains);

    // When ZK is enabled, we need to use an extended domain of size `2N` as we will
    // add random values to the trace.
    let ext_trace_domain = pcs.natural_domain_for_degree(degree_for_domains * (config.is_zk() + 1));

    // Let `g` denote a generator of the multiplicative group of `F` and `H'` the unique
    // subgroup of `F` of size `N << (pcs.config.log_blowup + config.is_zk())`.
    // If `zk` is enabled, we double the trace length by adding random values.
    //
    // For each trace column `T_i`, we compute the evaluation vector of `T_i(x)` over `H'`. This
    // new extended trace `ET` is hashed into a Merkle tree with its rows bit-reversed.
    //      trace_commit contains the root of the tree
    //      trace_data contains the entire tree.
    //          - trace_data.leaves is the matrix containing `ET`.
    let (trace_commit, trace_data) = info_span!("commit to trace data")
        .in_scope(|| pcs.commit([(ext_trace_domain, trace_to_commit)]));

    // Preprocessed commitment and prover data (if any).
    let (preprocessed_commit, preprocessed_data_ref) = preprocessed
        .map(|pp| (pp.commitment.clone(), &pp.prover_data))
        .unzip();

    // Observe the instance (must match verifier: use from_usize for transcript consistency).
    challenger.observe(Val::<SC>::from_usize(log_ext_degree_commit));
    challenger.observe(Val::<SC>::from_usize(log2_strict_usize(degree_for_domains)));
    challenger.observe(Val::<SC>::from_usize(preprocessed_width));
    challenger.observe(Val::<SC>::from_usize(A::width(air)));

    // Observe the Merkle root of the trace commitment.
    challenger.observe(trace_commit.clone());
    if preprocessed_width > 0 {
        challenger.observe(preprocessed_commit.as_ref().unwrap().clone());
    }

    // Observe the public input values.
    challenger.observe_slice(public_values);

    // Get the first Fiat Shamir challenge which will be used to combine all constraint polynomials
    // into a single polynomial.
    //
    // Soundness Error:
    // If a prover is malicious, we can find a row `i` such that some of the constraints
    // C_0, ..., C_n are non 0 on this row. The malicious prover "wins" if the random challenge
    // alpha is such that:
    // (1): C_0(i) + alpha * C_1(i) + ... + alpha^n * C_n(i) = 0
    // This is a polynomial of degree n, so it has at most n roots. Thus the probability of this
    // occurring for a given trace and set of constraints is n/|EF|.
    //
    // Currently, we do not observe data about the constraint polynomials directly. In particular
    // a prover could take a trace and fiddle around with the AIR it claims to satisfy without
    // changing this sample alpha.
    //
    // In particular this means that a malicious prover could create a custom AIR for a given trace
    // such that equation (1) holds. However, such AIRs would need to be very specific and
    // so such tampering should be obvious to spot. The verifier needs to check the AIR anyway to
    // confirm that satisfying it indeed proves what the prover claims. Hence this should not be
    // a soundness issue.
    let alpha: SC::Challenge = challenger.sample_algebra_element();

    // A domain large enough to uniquely identify the quotient polynomial.
    // This domain must be contained in the domain over which `trace_data` is defined.
    let quotient_domain =
        ext_trace_domain.create_disjoint_domain(1 << (log_ext_degree + log_num_quotient_chunks));

    // Return the subset of the extended trace `ET` corresponding to the rows giving evaluations
    // over the quotient domain.
    //
    // Precondition: the quotient domain must be contained in the extended trace domain. Concretely,
    // the trace domain is gH' and the quotient domain is gK for some subgroup K contained in H';
    // get_evaluations_on_domain relies on this so that requested evaluations exist in trace_data.
    let trace_on_quotient_domain = pcs.get_evaluations_on_domain(&trace_data, 0, quotient_domain);
    let preprocessed_on_quotient_domain =
        preprocessed_data_ref.map(|data| pcs.get_evaluations_on_domain(data, 0, quotient_domain));

    // Compute the quotient polynomial `Q(x)` by evaluating
    //          `C(T_1(x), ..., T_w(x), T_1(hx), ..., T_w(hx), selectors(x)) / Z_H(x)`
    // at every point in the quotient domain. The degree of `Q(x)` is `<= deg(C(x)) - N = 2N - 2` in the case
    // where `deg(C) = 3`. (See the discussion above constraint_degree for more details.)
    let quotient_input = QuotientInput {
        trace_domain,
        quotient_domain,
        trace_on_quotient_domain: &trace_on_quotient_domain,
        preprocessed_on_quotient_domain: preprocessed_on_quotient_domain.as_ref(),
    };
    let quotient_values =
        quotient_values(air, public_values, &quotient_input, alpha, constraint_count);

    // Due to `alpha`, evaluations of `Q` all lie in the extension field `E`.
    // We flatten this into a matrix of `F` values by treating `E` as an `F`
    // vector space and so separating each element of `E` into `e + 1 = [E: F]` elements of `F`.
    //
    // This is valid to do because our domain lies in the base field `F`. Hence we can split
    // `Q(x)` into `e + 1` polynomials `Q_0(x), ... , Q_e(x)` each contained in `F`.
    // such that `Q(x) = [Q_0(x), ... ,Q_e(x)]` holds for all `x` in `F`.
    let quotient_flat = RowMajorMatrix::new_col(quotient_values).flatten_to_base();

    // Currently each polynomial `Q_i(x)` is of degree `<= 2(N - 1)` and
    // we have it's evaluations over a the coset `gK of size `2N`. Let `k` be the chosen
    // generator of `K` which satisfies `k^2 = h`.
    //
    // We can split this coset into the sub-cosets `gH` and `gkH` each of size `N`.
    // Define:  L_g(x)    = (x^N - (gk)^N)/(g^N - (gk)^N) = (x^N + g^N)/2g^N
    //          L_{gk}(x) = (x^N - g^N)/(g^N - (gk)^N)    = -(x^N - g^N)/2g^N.
    // Then `L_g` is equal to `1` on `gH` and `0` on `gkH` and `L_{gk}` is equal to `1` on `gkH` and `0` on `gH`.
    //
    // Thus we can decompose `Q_i(x) = L_{g}(x)q_{i0}(x) + L_{gk}(x)q_{i1}(x)` (Or an randomized version of this in the zk case)
    // where `q_{i0}(x)` and `q_{i1}(x)` are polynomials of degree `<= N - 1`.
    // Moreover the evaluations of `q_{i0}(x), q_{i1}(x)` on `gH` and `gkH` respectively are
    // exactly the evaluations of `Q_i(x)` on `gH` and `gkH`.
    // For each polynomial `q_{ij}`, compute the evaluation vector of `q_{ij}(x)` over `gH'`. We bit
    // reverse the rows and hash the resulting matrix into a merkle tree.
    //      quotient_commit contains the root of the tree
    //      quotient_data contains the entire tree.
    //          - quotient_data.leaves is a pair of matrices containing the `q_i0(x)` and `q_i1(x)`.
    let (quotient_commit, quotient_data) = info_span!("commit to quotient poly chunks")
        .in_scope(|| pcs.commit_quotient(quotient_domain, quotient_flat, num_quotient_chunks));
    challenger.observe(quotient_commit.clone());

    // If zk is enabled, we generate random extension field values of the size of the randomized trace. If `n` is the degree of the initial trace,
    // then the randomized trace has degree `2n`. To randomize the FRI batch polynomial, we then need an extension field random polynomial of degree `2n -1`.
    // So we can generate a random polynomial  of degree `2n`, and provide it to `open` as is.
    // Then the method will add `(R(X) - R(z)) / (X - z)` (which is of the desired degree `2n - 1`), to the batch of polynomials.
    // Since we need a random polynomial defined over the extension field, and the `commit` method is over the base field,
    // we actually need to commit to `SC::CHallenge::D` base field random polynomials.
    // This is similar to what is done for the quotient polynomials.
    // This yields statistical ZK only. For perfect ZK, add a config flag (e.g. PerfectZk) and commit to
    // an extension-field random polynomial by generating R in extension-field form before committing.
    let (opt_r_commit, opt_r_data) = if SC::Pcs::ZK {
        let (r_commit, r_data) = pcs
            .get_opt_randomization_poly_commitment(ext_trace_domain)
            .expect("ZK is enabled, so we should have randomization commitments");
        (Some(r_commit), Some(r_data))
    } else {
        (None, None)
    };

    // Combine our commitments to the trace and quotient polynomials into a single object which
    // will be passed to the verifier.
    let commitments = Commitments {
        trace: trace_commit,
        quotient_chunks: quotient_commit,
        random: opt_r_commit.clone(),
    };

    if let Some(r_commit) = opt_r_commit {
        challenger.observe(r_commit);
    }

    // Get an out-of-domain point to open our values at.
    //
    // Soundness Error:
    // This sample will be used to check the equality: `C(X) = ZH(X)Q(X)`. If a prover is malicious
    // and this equality is false, the probability that it is true at the point `zeta` will be
    // deg(C(X))/|EF| = dN/|EF| where `N` is the trace length and our constraints have degree `d`.
    //
    // Completeness Error:
    // If zeta happens to lie in the domain `gK`, then when opening at zeta we will run into division
    // by zero errors. This doesn't lead to a soundness issue as the verifier will just reject in those
    // cases but it is a completeness issue and contributes a completeness error of |gK| = 2N/|EF|.
    let zeta: SC::Challenge = challenger.sample_algebra_element();
    let zeta_next = trace_domain
        .next_point(zeta)
        .expect("domain should support next_point operation");

    let is_random = opt_r_data.is_some();
    let (opened_values, opening_proof) = info_span!("open").in_scope(|| {
        let round0 = opt_r_data.as_ref().map(|r_data| (r_data, vec![vec![zeta]]));
        let round1 = (&trace_data, vec![vec![zeta, zeta_next]]);
        let round2 = (&quotient_data, vec![vec![zeta]; num_quotient_chunks]); // open every chunk at zeta
        let round3 = preprocessed_data_ref.map(|data| (data, vec![vec![zeta, zeta_next]]));

        let rounds = round0
            .into_iter()
            .chain([round1, round2])
            .chain(round3)
            .collect();

        pcs.open(rounds, &mut challenger)
    });
    let trace_idx = SC::Pcs::TRACE_IDX;
    let quotient_idx = SC::Pcs::QUOTIENT_IDX;
    let trace_local = opened_values[trace_idx][0][0].clone();
    let trace_next = opened_values[trace_idx][0][1].clone();
    let quotient_chunks = opened_values[quotient_idx]
        .iter()
        .map(|v| v[0].clone())
        .collect_vec();
    let random = if is_random {
        Some(opened_values[0][0][0].clone())
    } else {
        None
    };
    let (preprocessed_local, preprocessed_next) = if preprocessed_width > 0 {
        (
            Some(opened_values[SC::Pcs::PREPROCESSED_TRACE_IDX][0][0].clone()),
            Some(opened_values[SC::Pcs::PREPROCESSED_TRACE_IDX][0][1].clone()),
        )
    } else {
        (None, None)
    };
    let opened_values = OpenedValues {
        trace_local,
        trace_next,
        preprocessed_local,
        preprocessed_next,
        quotient_chunks,
        random,
    };
    Proof {
        commitments,
        opened_values,
        opening_proof,
        degree_bits: log_ext_degree_commit,
    }
}

#[cfg(debug_assertions)]
#[instrument(skip_all)]
pub fn prove<SC, A>(
    config: &SC,
    air: &A,
    trace: RowMajorMatrix<Val<SC>>,
    public_values: &[Val<SC>],
) -> Proof<SC>
where
    SC: StarkGenericConfig,
    A: Air<SymbolicAirBuilder<Val<SC>>> + for<'a> Air<ProverConstraintFolder<'a, SC>>,
    A: for<'a> Air<crate::check_constraints::DebugConstraintBuilder<'a, Val<SC>>>,
{
    prove_with_preprocessed::<SC, A>(config, air, trace, public_values, None)
}

#[cfg(not(debug_assertions))]
#[instrument(skip_all)]
pub fn prove<SC, A>(
    config: &SC,
    air: &A,
    trace: RowMajorMatrix<Val<SC>>,
    public_values: &[Val<SC>],
) -> Proof<SC>
where
    SC: StarkGenericConfig,
    A: Air<SymbolicAirBuilder<Val<SC>>> + for<'a> Air<ProverConstraintFolder<'a, SC>>,
{
    prove_with_preprocessed::<SC, A>(config, air, trace, public_values, None)
}

/// Input for quotient polynomial evaluation (trace/quotient domains and matrices).
pub struct QuotientInput<'a, SC: StarkGenericConfig, Mat> {
    pub trace_domain: Domain<SC>,
    pub quotient_domain: Domain<SC>,
    pub trace_on_quotient_domain: &'a Mat,
    pub preprocessed_on_quotient_domain: Option<&'a Mat>,
}

/// Context for a single chunk of quotient evaluation (selectors, alpha powers, etc.).
struct QuotientChunkCtx<'a, SC: StarkGenericConfig, Mat> {
    quotient_size: usize,
    next_step: usize,
    width: usize,
    sels: &'a LagrangeSelectors<Vec<Val<SC>>>,
    trace_on_quotient_domain: &'a Mat,
    preprocessed_on_quotient_domain: Option<&'a Mat>,
    public_values: &'a [Val<SC>],
    alpha_powers: &'a [SC::Challenge],
    decomposed_alpha_powers: &'a [Vec<Val<SC>>],
}

#[instrument(skip_all)]
pub fn quotient_values<SC, A, Mat>(
    air: &A,
    public_values: &[Val<SC>],
    input: &QuotientInput<SC, Mat>,
    alpha: SC::Challenge,
    constraint_count: usize,
) -> Vec<SC::Challenge>
where
    SC: StarkGenericConfig,
    A: for<'a> Air<ProverConstraintFolder<'a, SC>>,
    Mat: Matrix<Val<SC>> + Sync,
{
    let quotient_size = input.quotient_domain.size();
    let width = input.trace_on_quotient_domain.width();
    let mut sels = debug_span!("Compute Selectors")
        .in_scope(|| input.trace_domain.selectors_on_coset(input.quotient_domain));

    let qdb = log2_strict_usize(input.quotient_domain.size()) -
        log2_strict_usize(input.trace_domain.size());
    let next_step = 1 << qdb;

    // We take PackedVal::<SC>::WIDTH worth of values at a time from a quotient_size slice, so we need to
    // pad with default values in the case where quotient_size is smaller than PackedVal::<SC>::WIDTH.
    for _ in quotient_size..PackedVal::<SC>::WIDTH {
        sels.is_first_row.push(Val::<SC>::default());
        sels.is_last_row.push(Val::<SC>::default());
        sels.is_transition.push(Val::<SC>::default());
        sels.inv_vanishing.push(Val::<SC>::default());
    }

    let mut alpha_powers = alpha.powers().collect_n(constraint_count);
    alpha_powers.reverse();
    // alpha powers looks like Vec<EF> ~ Vec<[F; D]>
    // It's useful to also have access to the transpose of this of form [Vec<F>; D].
    let decomposed_alpha_powers: Vec<_> = (0..SC::Challenge::DIMENSION)
        .map(|i| {
            alpha_powers
                .iter()
                .map(|x| x.as_basis_coefficients_slice()[i])
                .collect()
        })
        .collect();

    let ctx = QuotientChunkCtx {
        quotient_size,
        next_step,
        width,
        sels: &sels,
        trace_on_quotient_domain: input.trace_on_quotient_domain,
        preprocessed_on_quotient_domain: input.preprocessed_on_quotient_domain,
        public_values,
        alpha_powers: &alpha_powers,
        decomposed_alpha_powers: &decomposed_alpha_powers,
    };

    #[cfg(feature = "parallel")]
    let iter = (0..quotient_size)
        .into_par_iter()
        .step_by(PackedVal::<SC>::WIDTH)
        .flat_map_iter(|i_start| quotient_values_chunk(air, i_start, &ctx));

    #[cfg(not(feature = "parallel"))]
    let iter = (0..quotient_size)
        .step_by(PackedVal::<SC>::WIDTH)
        .flat_map(|i_start| quotient_values_chunk(air, i_start, &ctx));

    iter.collect()
}

fn quotient_values_chunk<'b, A, SC, Mat>(
    air: &'b A,
    i_start: usize,
    ctx: &'b QuotientChunkCtx<SC, Mat>,
) -> impl Iterator<Item = SC::Challenge> + 'b
where
    A: for<'a> Air<ProverConstraintFolder<'a, SC>>,
    SC: StarkGenericConfig,
    Mat: Matrix<Val<SC>>,
{
    let i_range = i_start..i_start + PackedVal::<SC>::WIDTH;

    let is_first_row = *PackedVal::<SC>::from_slice(&ctx.sels.is_first_row[i_range.clone()]);
    let is_last_row = *PackedVal::<SC>::from_slice(&ctx.sels.is_last_row[i_range.clone()]);
    let is_transition = *PackedVal::<SC>::from_slice(&ctx.sels.is_transition[i_range.clone()]);
    let inv_vanishing = *PackedVal::<SC>::from_slice(&ctx.sels.inv_vanishing[i_range]);

    let main = RowMajorMatrix::new(
        ctx.trace_on_quotient_domain
            .vertically_packed_row_pair(i_start, ctx.next_step),
        ctx.width,
    );

    let preprocessed = ctx.preprocessed_on_quotient_domain.map(|preprocessed| {
        let preprocessed_width = preprocessed.width();
        RowMajorMatrix::new(
            preprocessed.vertically_packed_row_pair(i_start, ctx.next_step),
            preprocessed_width,
        )
    });

    let accumulator = PackedChallenge::<SC>::ZERO;
    let mut folder = ProverConstraintFolder {
        main: main.as_view(),
        preprocessed: preprocessed.as_ref().map(|m| m.as_view()),
        public_values: ctx.public_values,
        is_first_row,
        is_last_row,
        is_transition,
        alpha_powers: ctx.alpha_powers,
        decomposed_alpha_powers: ctx.decomposed_alpha_powers,
        accumulator,
        constraint_index: 0,
    };
    air.eval(&mut folder);

    // quotient(x) = constraints(x) / Z_H(x)
    let quotient = folder.accumulator * inv_vanishing;

    // "Transpose" D packed base coefficients into WIDTH scalar extension coefficients.
    (0..core::cmp::min(ctx.quotient_size, PackedVal::<SC>::WIDTH)).map(move |idx_in_packing| {
        SC::Challenge::from_basis_coefficients_fn(|coeff_idx| {
            quotient.as_basis_coefficients_slice()[coeff_idx].as_slice()[idx_in_packing]
        })
    })
}
