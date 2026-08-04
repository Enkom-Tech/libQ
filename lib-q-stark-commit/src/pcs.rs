//! Traits for polynomial commitment schemes.

use alloc::vec::Vec;
use core::fmt::Debug;

use lib_q_stark_field::ExtensionField;
use lib_q_stark_matrix::Matrix;
use lib_q_stark_matrix::dense::RowMajorMatrix;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::PolynomialSpace;

pub type Val<D> = <D as PolynomialSpace>::Val;

/// A polynomial commitment scheme, for committing to batches of polynomials defined by their evaluations
/// over some domain.
///
/// In general this does not have to be a hiding commitment scheme but it might be for some implementations.
// TODO: Should we have a super-trait for weakly-binding PCSs, like FRI outside unique decoding radius?
pub trait Pcs<Challenge, Challenger>
where
    Challenge: ExtensionField<Val<Self::Domain>>,
{
    /// The class of evaluation domains that this commitment scheme works over.
    type Domain: PolynomialSpace;

    /// The commitment that's sent to the verifier.
    type Commitment: Clone + Serialize + DeserializeOwned;

    /// Data that the prover stores for committed polynomials, to help the prover with opening.
    type ProverData;

    /// Type of the output of `get_evaluations_on_domain`.
    type EvaluationsOnDomain<'a>: Matrix<Val<Self::Domain>> + 'a;

    /// The opening argument.
    type Proof: Clone + Serialize + DeserializeOwned;

    /// The type of a proof verification error.
    type Error: Debug;

    /// Set to true to activate randomization and achieve zero-knowledge.
    const ZK: bool;

    /// Index of the trace commitment in the computed opened values.
    const TRACE_IDX: usize = Self::ZK as usize;

    /// Index of the quotient commitments in the computed opened values.
    const QUOTIENT_IDX: usize = Self::TRACE_IDX + 1;

    /// Index of the preprocessed trace commitment in the computed opened values.
    const PREPROCESSED_TRACE_IDX: usize = Self::QUOTIENT_IDX + 1; // Note: not always present

    /// This should return a domain such that `Domain::next_point` returns `Some`.
    ///
    /// # Panics
    /// Implementations backed by a two-adic domain (the only kind in this workspace today) will
    /// panic if `degree` is not a power of two, or exceeds the field's two-adicity. Callers that
    /// process untrusted/adversarial `degree` values (e.g. a proof verifier) MUST validate `degree`
    /// themselves before calling this, or use [`try_natural_domain_for_degree`](Self::try_natural_domain_for_degree) instead.
    fn natural_domain_for_degree(&self, degree: usize) -> Self::Domain;

    /// Fallible sibling of [`natural_domain_for_degree`](Self::natural_domain_for_degree), for
    /// callers (such as proof verifiers) that must reject an out-of-range `degree` instead of
    /// panicking. Returns `None` exactly under the conditions documented on
    /// `natural_domain_for_degree`'s `# Panics` section.
    ///
    /// The default implementation simply delegates to the infallible method, so it is only
    /// non-panicking for implementations that override it; `TwoAdicFriPcs` and `HidingFriPcs`
    /// (the only implementations in this workspace, in `lib-q-stark-fri`) both override it with a
    /// genuinely non-panicking check.
    fn try_natural_domain_for_degree(&self, degree: usize) -> Option<Self::Domain> {
        Some(self.natural_domain_for_degree(degree))
    }

    /// Given a collection of evaluation matrices, produce a binding commitment to
    /// the polynomials defined by those evaluations. If `zk` is enabled, the evaluations are
    /// first randomized as explained in Section 3 of <https://eprint.iacr.org/2024/1037.pdf>.
    ///
    /// Returns both the commitment which should be sent to the verifier
    /// and the prover data which can be used to produce opening proofs.
    #[allow(clippy::type_complexity)]
    fn commit(
        &self,
        evaluations: impl IntoIterator<Item = (Self::Domain, RowMajorMatrix<Val<Self::Domain>>)>,
    ) -> (Self::Commitment, Self::ProverData);

    /// Commit to the quotient polynomial. We first decompose the quotient polynomial into
    /// `num_chunks` many smaller polynomials each of degree `degree / num_chunks`.
    /// This can have minor performance benefits, but is not strictly necessary in the non `zk` case.
    /// When `zk` is enabled, this commitment will additionally include some randomization process
    /// to hide the inputs.
    ///
    /// ### Arguments
    /// - `quotient_domain` the domain of the quotient polynomial.
    /// - `quotient_evaluations` the evaluations of the quotient polynomial over the domain. This should be in
    ///   standard (not bit-reversed) order.
    /// - `num_chunks` the number of smaller polynomials to decompose the quotient polynomial into.
    #[allow(clippy::type_complexity)]
    fn commit_quotient(
        &self,
        quotient_domain: Self::Domain,
        quotient_evaluations: RowMajorMatrix<Val<Self::Domain>>,
        num_chunks: usize,
    ) -> (Self::Commitment, Self::ProverData) {
        let quotient_sub_evaluations =
            quotient_domain.split_evals(num_chunks, quotient_evaluations);
        let quotient_sub_domains = quotient_domain.split_domains(num_chunks);
        let ldes = self.get_quotient_ldes(
            quotient_sub_domains
                .into_iter()
                .zip(quotient_sub_evaluations),
            num_chunks,
        );
        self.commit_ldes(ldes)
    }

    /// When committing to quotient polynomials in batch-STARK, it is simpler to first compute
    /// the LDE evaluations before batch-committing. When `zk` is enabled, this may add randomization.
    fn get_quotient_ldes(
        &self,
        evaluations: impl IntoIterator<Item = (Self::Domain, RowMajorMatrix<Val<Self::Domain>>)>,
        num_chunks: usize,
    ) -> Vec<RowMajorMatrix<Val<Self::Domain>>>;

    /// Commits to a collection of LDE evaluation matrices.
    fn commit_ldes(
        &self,
        ldes: Vec<RowMajorMatrix<Val<Self::Domain>>>,
    ) -> (Self::Commitment, Self::ProverData);

    /// Same as `commit`; used when the committed data is preprocessing (e.g. fixed trace).
    fn commit_preprocessing(
        &self,
        evaluations: impl IntoIterator<Item = (Self::Domain, RowMajorMatrix<Val<Self::Domain>>)>,
    ) -> (Self::Commitment, Self::ProverData) {
        self.commit(evaluations)
    }

    /// Given prover data corresponding to a commitment to a collection of evaluation matrices,
    /// return the evaluations of those matrices on the given domain.
    ///
    /// This is essentially a no-op when called with a `domain` which is a subset of the evaluation domain
    /// on which the evaluation matrices are defined.
    fn get_evaluations_on_domain<'a>(
        &self,
        prover_data: &'a Self::ProverData,
        idx: usize,
        domain: Self::Domain,
    ) -> Self::EvaluationsOnDomain<'a>;

    /// Like `get_evaluations_on_domain` but without applying ZK randomization (e.g. for quotient domain).
    fn get_evaluations_on_domain_no_random<'a>(
        &self,
        prover_data: &'a Self::ProverData,
        idx: usize,
        domain: Self::Domain,
    ) -> Self::EvaluationsOnDomain<'a> {
        self.get_evaluations_on_domain(prover_data, idx, domain)
    }

    /// Open a collection of polynomial commitments at a set of points. Produce the values at those points along with a proof
    /// of correctness.
    ///
    /// Arguments:
    /// - `commitment_data_with_opening_points`: A vector whose elements are a pair:
    ///     - `data`: The prover data corresponding to a multi-matrix commitment.
    ///     - `opening_points`: A vector containing, for each matrix committed to, a vector of opening points.
    /// - `fiat_shamir_challenger`: The challenger that will be used to generate the proof.
    ///
    /// Unwrapping the arguments further, each `data` contains a vector of the committed matrices (`matrices = Vec<M>`).
    /// If the length of `matrices` is not equal to the length of `opening_points` the function will error. Otherwise, for
    /// each index `i`, the matrix `M = matrices[i]` will be opened at the points `opening_points[i]`.
    ///
    /// This means that each column of `M` will be interpreted as the evaluation vector of some polynomial
    /// and we will compute the value of all of those polynomials at `opening_points[i]`.
    ///
    /// The domains on which the evaluation vectors are defined is not part of the arguments here
    /// but should be public information known to both the prover and verifier.
    fn open(
        &self,
        // For each multi-matrix commitment,
        commitment_data_with_opening_points: Vec<(
            // The matrices and auxiliary prover data
            &Self::ProverData,
            // for each matrix,
            Vec<
                // the points to open
                Vec<Challenge>,
            >,
        )>,
        fiat_shamir_challenger: &mut Challenger,
    ) -> (OpenedValues<Challenge>, Self::Proof);

    /// Like `open` but allows the implementation to treat some rounds as preprocessing (e.g. for ZK).
    #[allow(clippy::type_complexity)]
    fn open_with_preprocessing(
        &self,
        rounds: Vec<(&Self::ProverData, Vec<Vec<Challenge>>)>,
        challenger: &mut Challenger,
        _is_preprocessing: bool,
    ) -> (OpenedValues<Challenge>, Self::Proof) {
        self.open(rounds, challenger)
    }

    /// Verify that a collection of opened values is correct.
    ///
    /// Arguments:
    /// - `commitments_with_opening_points`: A vector whose elements are a pair:
    ///     - `commitment`: A multi matrix commitment.
    ///     - `opening_points`: A vector containing, for each matrix committed to, a vector of opening points and claimed evaluations.
    /// - `proof`: A claimed proof of correctness for the opened values.
    /// - `fiat_shamir_challenger`: The challenger that will be used to generate the proof.
    #[allow(clippy::type_complexity)]
    fn verify(
        &self,
        // For each commitment:
        commitments_with_opening_points: Vec<(
            // The commitment
            Self::Commitment,
            // for each matrix in the commitment:
            Vec<(
                // its domain,
                Self::Domain,
                // A vector of (point, claimed_evaluation) pairs
                Vec<(
                    // the point the matrix was opened at,
                    Challenge,
                    // the claimed evaluations at that point
                    Vec<Challenge>,
                )>,
            )>,
        )>,
        // The opening proof for all claimed evaluations.
        proof: &Self::Proof,
        fiat_shamir_challenger: &mut Challenger,
    ) -> Result<(), Self::Error>;

    fn get_opt_randomization_poly_commitment(
        &self,
        _domains: impl IntoIterator<Item = Self::Domain>,
    ) -> Option<(Self::Commitment, Self::ProverData)> {
        None
    }
}

pub type OpenedValues<F> = Vec<OpenedValuesForRound<F>>;
pub type OpenedValuesForRound<F> = Vec<OpenedValuesForMatrix<F>>;
pub type OpenedValuesForMatrix<F> = Vec<OpenedValuesForPoint<F>>;
pub type OpenedValuesForPoint<F> = Vec<F>;

#[cfg(test)]
mod tests {
    use alloc::vec;
    use core::marker::PhantomData;

    use lib_q_stark_baby_bear::BabyBear;
    use lib_q_stark_challenger::{
        CanSample,
        Shake128Challenger32,
    };
    use lib_q_stark_dft::{
        NaiveDft,
        TwoAdicSubgroupDft,
    };
    use lib_q_stark_field::coset::TwoAdicMultiplicativeCoset;
    use lib_q_stark_field::{
        PrimeCharacteristicRing,
        TwoAdicField,
    };
    use lib_q_stark_shake128::Shake128Hash;

    use super::*;
    use crate::testing::{
        TrivialPcs,
        eval_coeffs_at_pt,
    };

    type F = BabyBear;
    type Challenge = F;
    type Challenger = Shake128Challenger32<F>;

    fn pcs(log_n: usize) -> TrivialPcs<F, NaiveDft> {
        TrivialPcs {
            dft: NaiveDft,
            log_n,
            _phantom: PhantomData,
        }
    }

    fn challenger() -> Challenger {
        Challenger::from_hasher(Vec::new(), Shake128Hash)
    }

    /// Coefficients (one polynomial per column, low-degree-first down each column) for two
    /// distinct small polynomials over an 8-element domain.
    fn coeffs() -> RowMajorMatrix<F> {
        RowMajorMatrix::new(
            [1u32, 10, 2, 0, 3, 0, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0]
                .into_iter()
                .map(F::new)
                .collect(),
            2,
        )
    }

    /// `TrivialPcs::commit` is documented as "only commit on larger domain than natural": it takes
    /// evaluations over a domain and recovers coefficients via an inverse DFT weighted by the
    /// domain's shift. On the *natural* domain (shift = `ONE`, so the weighting is a no-op), this
    /// must exactly invert the forward DFT used to build the evaluations in the first place.
    #[test]
    fn commit_recovers_the_original_coefficients_on_the_natural_domain() {
        let p = pcs(3);
        let domain =
            <TrivialPcs<F, NaiveDft> as Pcs<Challenge, Challenger>>::natural_domain_for_degree(
                &p, 8,
            );
        let original = coeffs();
        let evals = NaiveDft.dft_batch(original.clone());

        let (_commitment, prover_data) =
            Pcs::<Challenge, Challenger>::commit(&p, [(domain, evals)]);
        assert_eq!(prover_data[0], original);
    }

    /// End-to-end `commit` -> `open` -> `verify` round trip: the value produced by `open` for an
    /// arbitrary (off-domain) evaluation point must be the true evaluation of the committed
    /// polynomial there, and `verify` must accept that (correct) claim.
    #[test]
    fn open_and_verify_accept_an_honest_evaluation_claim() {
        let p = pcs(3);
        let domain =
            <TrivialPcs<F, NaiveDft> as Pcs<Challenge, Challenger>>::natural_domain_for_degree(
                &p, 8,
            );
        let original = coeffs();
        let evals = NaiveDft.dft_batch(original.clone());
        let (commitment, prover_data) = Pcs::<Challenge, Challenger>::commit(&p, [(domain, evals)]);

        let z = F::new(12345);
        let expected = eval_coeffs_at_pt(&original, z);

        let (opened, proof) = Pcs::<Challenge, Challenger>::open(
            &p,
            vec![(&prover_data, vec![vec![z]])],
            &mut challenger(),
        );
        assert_eq!(opened[0][0][0], expected);

        Pcs::<Challenge, Challenger>::verify(
            &p,
            vec![(
                commitment,
                vec![(domain, vec![(z, opened[0][0][0].clone())])],
            )],
            &proof,
            &mut challenger(),
        )
        .expect("verify must accept the value `open` itself produced for an honest commitment");
    }

    /// Negative control for the round trip above: assert a claimed evaluation known to be wrong
    /// and confirm `verify` does NOT accept it. `TrivialPcs` is a testing-only PCS that signals a
    /// bad claim by panicking (`assert_eq!` internally, documented on `Pcs::verify`'s impl), so the
    /// failure mode here is a panic rather than an `Err`.
    #[test]
    #[should_panic]
    fn verify_rejects_a_tampered_evaluation_claim() {
        let p = pcs(3);
        let domain =
            <TrivialPcs<F, NaiveDft> as Pcs<Challenge, Challenger>>::natural_domain_for_degree(
                &p, 8,
            );
        let original = coeffs();
        let evals = NaiveDft.dft_batch(original.clone());
        let (commitment, prover_data) = Pcs::<Challenge, Challenger>::commit(&p, [(domain, evals)]);

        let z = F::new(12345);
        let (_opened, proof) = Pcs::<Challenge, Challenger>::open(
            &p,
            vec![(&prover_data, vec![vec![z]])],
            &mut challenger(),
        );

        let tampered_value = eval_coeffs_at_pt(&original, z)
            .into_iter()
            .map(|v| v + F::ONE)
            .collect();

        Pcs::<Challenge, Challenger>::verify(
            &p,
            vec![(commitment, vec![(domain, vec![(z, tampered_value)])])],
            &proof,
            &mut challenger(),
        )
        .ok();
    }

    // ---- Coverage of `Pcs`'s DEFAULT method bodies ----
    //
    // `TrivialPcs` (the only `Pcs` impl in this crate) overrides every required method plus
    // `commit_quotient`, but deliberately leaves `try_natural_domain_for_degree`,
    // `commit_preprocessing`, `open_with_preprocessing` and `get_opt_randomization_poly_commitment`
    // on the trait's own default bodies (see `testing.rs`'s `impl Pcs for TrivialPcs`: those four
    // methods are simply absent). So calling them through `TrivialPcs` exercises the DEFAULT body
    // defined right here in `pcs.rs`, not an override elsewhere -- closing exactly the gap the
    // 0/20-covered `pcs.rs` report pointed at.

    /// `try_natural_domain_for_degree`'s default just wraps `natural_domain_for_degree` in `Some`.
    #[test]
    fn try_natural_domain_for_degree_default_wraps_the_infallible_version() {
        let p = pcs(3);
        let degree = 8;
        let direct =
            <TrivialPcs<F, NaiveDft> as Pcs<Challenge, Challenger>>::natural_domain_for_degree(
                &p, degree,
            );
        let via_default = Pcs::<Challenge, Challenger>::try_natural_domain_for_degree(&p, degree);
        // `TwoAdicMultiplicativeCoset` does not implement `PartialEq`; compare the two
        // domain-identifying fields instead (shift and size uniquely determine a coset).
        let via_default = via_default.expect("default must wrap in `Some`");
        assert_eq!(via_default.shift(), direct.shift());
        assert_eq!(via_default.log_size(), direct.log_size());
    }

    /// `commit_preprocessing`'s default is a pure passthrough to `commit`: same input must produce
    /// the identical (commitment, prover_data) pair.
    #[test]
    fn commit_preprocessing_default_delegates_to_commit() {
        let p = pcs(3);
        let domain =
            <TrivialPcs<F, NaiveDft> as Pcs<Challenge, Challenger>>::natural_domain_for_degree(
                &p, 8,
            );
        let evals = NaiveDft.dft_batch(coeffs());

        let (direct_commitment, direct_prover_data) =
            Pcs::<Challenge, Challenger>::commit(&p, [(domain, evals.clone())]);
        let (default_commitment, default_prover_data) =
            Pcs::<Challenge, Challenger>::commit_preprocessing(&p, [(domain, evals)]);

        assert_eq!(default_commitment, direct_commitment);
        assert_eq!(default_prover_data, direct_prover_data);
    }

    /// Negative control for the delegation test above: prove the two calls are not being compared
    /// via some vacuously-equal placeholder by feeding `commit` a genuinely different polynomial
    /// and confirming the two commitments then differ.
    #[test]
    fn commit_preprocessing_negative_control_distinct_input_gives_distinct_commitment() {
        let p = pcs(3);
        let domain =
            <TrivialPcs<F, NaiveDft> as Pcs<Challenge, Challenger>>::natural_domain_for_degree(
                &p, 8,
            );
        let evals_a = NaiveDft.dft_batch(coeffs());
        let mut other = coeffs();
        // Perturb one coefficient so the two polynomials are genuinely different.
        other.values[0] += F::ONE;
        let evals_b = NaiveDft.dft_batch(other);

        let (commitment_a, _) =
            Pcs::<Challenge, Challenger>::commit_preprocessing(&p, [(domain, evals_a)]);
        let (commitment_b, _) =
            Pcs::<Challenge, Challenger>::commit_preprocessing(&p, [(domain, evals_b)]);
        assert_ne!(commitment_a, commitment_b);
    }

    /// `open_with_preprocessing`'s default ignores the `is_preprocessing` flag entirely and
    /// delegates straight to `open`; check both flag values produce `open`'s own result.
    #[test]
    fn open_with_preprocessing_default_delegates_to_open_regardless_of_flag() {
        let p = pcs(3);
        let domain =
            <TrivialPcs<F, NaiveDft> as Pcs<Challenge, Challenger>>::natural_domain_for_degree(
                &p, 8,
            );
        let evals = NaiveDft.dft_batch(coeffs());
        let (_commitment, prover_data) =
            Pcs::<Challenge, Challenger>::commit(&p, [(domain, evals)]);
        let z = F::new(999);

        let (direct_opened, _) = Pcs::<Challenge, Challenger>::open(
            &p,
            vec![(&prover_data, vec![vec![z]])],
            &mut challenger(),
        );
        for flag in [false, true] {
            let (via_default, _) = Pcs::<Challenge, Challenger>::open_with_preprocessing(
                &p,
                vec![(&prover_data, vec![vec![z]])],
                &mut challenger(),
                flag,
            );
            assert_eq!(via_default, direct_opened);
        }
    }

    /// `get_evaluations_on_domain_no_random`'s default is a pure passthrough to
    /// `get_evaluations_on_domain`: same inputs must produce identical evaluations.
    #[test]
    fn get_evaluations_on_domain_no_random_default_delegates() {
        let p = pcs(3);
        let domain =
            <TrivialPcs<F, NaiveDft> as Pcs<Challenge, Challenger>>::natural_domain_for_degree(
                &p, 8,
            );
        let evals = NaiveDft.dft_batch(coeffs());
        let (_commitment, prover_data) =
            Pcs::<Challenge, Challenger>::commit(&p, [(domain, evals)]);

        let direct =
            Pcs::<Challenge, Challenger>::get_evaluations_on_domain(&p, &prover_data, 0, domain);
        let via_default = Pcs::<Challenge, Challenger>::get_evaluations_on_domain_no_random(
            &p,
            &prover_data,
            0,
            domain,
        );
        assert_eq!(via_default, direct);
    }

    /// `get_opt_randomization_poly_commitment`'s default always returns `None`; nothing about a
    /// non-hiding PCS like `TrivialPcs` should make it produce a randomization commitment.
    #[test]
    fn get_opt_randomization_poly_commitment_default_is_none() {
        let p = pcs(3);
        let domain =
            <TrivialPcs<F, NaiveDft> as Pcs<Challenge, Challenger>>::natural_domain_for_degree(
                &p, 8,
            );
        assert!(
            Pcs::<Challenge, Challenger>::get_opt_randomization_poly_commitment(&p, [domain])
                .is_none()
        );
    }

    /// Minimal wrapper around `TrivialPcs` that supplies real (if non-LDE) bodies for
    /// `get_quotient_ldes`/`commit_ldes` -- `TrivialPcs`'s own versions are `unimplemented!()` --
    /// and, crucially, does NOT re-override `commit_quotient`. That leaves `commit_quotient` on
    /// the trait's own default body in `pcs.rs`, so calling it here runs that default end-to-end
    /// instead of `TrivialPcs`'s override (see `testing.rs`, which DOES override `commit_quotient`).
    struct QuotientDefaultPcs<Val: TwoAdicField, Dft: TwoAdicSubgroupDft<Val>>(
        TrivialPcs<Val, Dft>,
    );

    impl<Val, Dft, Challenge, Challenger> Pcs<Challenge, Challenger> for QuotientDefaultPcs<Val, Dft>
    where
        Val: TwoAdicField,
        Challenge: ExtensionField<Val>,
        Challenger: CanSample<Challenge>,
        Dft: TwoAdicSubgroupDft<Val>,
        Vec<Vec<Val>>: Serialize + DeserializeOwned,
    {
        type Domain = TwoAdicMultiplicativeCoset<Val>;
        type Commitment = Vec<Vec<Val>>;
        type ProverData = Vec<RowMajorMatrix<Val>>;
        type EvaluationsOnDomain<'a> = Dft::Evaluations;
        type Proof = ();
        type Error = ();
        const ZK: bool = false;

        fn natural_domain_for_degree(&self, degree: usize) -> Self::Domain {
            Pcs::<Challenge, Challenger>::natural_domain_for_degree(&self.0, degree)
        }

        fn commit(
            &self,
            evaluations: impl IntoIterator<Item = (Self::Domain, RowMajorMatrix<Val>)>,
        ) -> (Self::Commitment, Self::ProverData) {
            Pcs::<Challenge, Challenger>::commit(&self.0, evaluations)
        }

        // Deliberately NOT overriding `commit_quotient`: that is the point of this type.

        fn get_quotient_ldes(
            &self,
            evaluations: impl IntoIterator<Item = (Self::Domain, RowMajorMatrix<Val>)>,
            _num_chunks: usize,
        ) -> Vec<RowMajorMatrix<Val>> {
            // Identity passthrough: this type exists only to observe `commit_quotient`'s default
            // plumbing, not to compute an actual low-degree extension.
            evaluations
                .into_iter()
                .map(|(_domain, evals)| evals)
                .collect()
        }

        fn commit_ldes(
            &self,
            ldes: Vec<RowMajorMatrix<Val>>,
        ) -> (Self::Commitment, Self::ProverData) {
            (ldes.iter().map(|m| m.values.clone()).collect(), ldes)
        }

        fn get_evaluations_on_domain<'a>(
            &self,
            prover_data: &'a Self::ProverData,
            idx: usize,
            domain: Self::Domain,
        ) -> Self::EvaluationsOnDomain<'a> {
            Pcs::<Challenge, Challenger>::get_evaluations_on_domain(
                &self.0,
                prover_data,
                idx,
                domain,
            )
        }

        fn open(
            &self,
            rounds: Vec<(&Self::ProverData, Vec<Vec<Challenge>>)>,
            challenger: &mut Challenger,
        ) -> (OpenedValues<Challenge>, Self::Proof) {
            Pcs::<Challenge, Challenger>::open(&self.0, rounds, challenger)
        }

        #[allow(clippy::type_complexity)]
        fn verify(
            &self,
            rounds: Vec<(
                Self::Commitment,
                Vec<(Self::Domain, Vec<(Challenge, Vec<Challenge>)>)>,
            )>,
            proof: &Self::Proof,
            challenger: &mut Challenger,
        ) -> Result<(), Self::Error> {
            Pcs::<Challenge, Challenger>::verify(&self.0, rounds, proof, challenger)
        }
    }

    /// `commit_quotient`'s default: split the quotient domain/evaluations into `num_chunks`
    /// pieces, hand them to `get_quotient_ldes`, then commit the result via `commit_ldes`. Check
    /// the whole default end-to-end against an independently-assembled expectation built from the
    /// same `PolynomialSpace::split_evals` call the default itself must be using.
    #[test]
    fn commit_quotient_default_splits_then_delegates_to_get_quotient_ldes_and_commit_ldes() {
        let p = QuotientDefaultPcs(pcs(2));
        let quotient_domain =
            <QuotientDefaultPcs<F, NaiveDft> as Pcs<Challenge, Challenger>>::natural_domain_for_degree(
                &p, 8,
            );
        let evals = NaiveDft.dft_batch(coeffs());
        let num_chunks = 2;

        let (commitment, prover_data) = Pcs::<Challenge, Challenger>::commit_quotient(
            &p,
            quotient_domain,
            evals.clone(),
            num_chunks,
        );

        // Independently reconstruct what the default *should* produce: `get_quotient_ldes` here is
        // an identity passthrough of the split evaluation chunks, and `commit_ldes` copies each
        // chunk's raw values as the commitment -- so the expected prover data is exactly
        // `split_evals`'s own output, in order.
        let expected_ldes = PolynomialSpace::split_evals(&quotient_domain, num_chunks, evals);
        let expected_commitment: Vec<Vec<F>> =
            expected_ldes.iter().map(|m| m.values.clone()).collect();

        assert_eq!(prover_data, expected_ldes);
        assert_eq!(commitment, expected_commitment);
    }

    /// Negative control for the `commit_quotient` default test: corrupting `num_chunks` (splitting
    /// into a different number of pieces than the default actually used) must produce a different
    /// prover-data shape/content, proving the equality check above is not vacuous.
    #[test]
    fn commit_quotient_negative_control_wrong_num_chunks_disagrees() {
        let p = QuotientDefaultPcs(pcs(2));
        let quotient_domain =
            <QuotientDefaultPcs<F, NaiveDft> as Pcs<Challenge, Challenger>>::natural_domain_for_degree(
                &p, 8,
            );
        let evals = NaiveDft.dft_batch(coeffs());

        let (_commitment, prover_data) =
            Pcs::<Challenge, Challenger>::commit_quotient(&p, quotient_domain, evals.clone(), 2);
        // Split into 4 chunks instead of the 2 actually used above: different shape entirely.
        let wrong_split = PolynomialSpace::split_evals(&quotient_domain, 4, evals);
        assert_ne!(prover_data.len(), wrong_split.len());
    }
}
