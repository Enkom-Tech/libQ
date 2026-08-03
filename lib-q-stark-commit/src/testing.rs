//! A mock, non-hiding polynomial commitment scheme for use in downstream crates' own tests.
//!
//! Ported from upstream Plonky3's `p3-commit::testing`, with the crate names swapped for their
//! libQ equivalents (`p3_field` -> `lib_q_stark_field`, `p3_matrix` -> `lib_q_stark_matrix`,
//! `p3_dft` -> `lib_q_stark_dft`, `p3_challenger` -> `lib_q_stark_challenger`,
//! `p3_util::zip_eq` -> `lib_q_stark_util::zip_eq`). The logic is otherwise unchanged: see
//! `reference/Plonky3-main/commit/src/testing.rs`.

use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use lib_q_stark_challenger::CanSample;
use lib_q_stark_dft::TwoAdicSubgroupDft;
use lib_q_stark_field::coset::TwoAdicMultiplicativeCoset;
use lib_q_stark_field::{
    ExtensionField,
    Field,
    TwoAdicField,
};
use lib_q_stark_matrix::Matrix;
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_util::log2_strict_usize;
use lib_q_stark_util::zip_eq::zip_eq;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::{
    OpenedValues,
    Pcs,
    PolynomialSpace,
};

/// A trivial PCS: its commitment is simply the coefficients of each poly.
///
/// This is **not** a real (binding, let alone hiding) commitment scheme — the "commitment" is the
/// plaintext coefficients of every committed polynomial, so it carries no soundness whatsoever.
/// It exists purely so that code written against the [`Pcs`] trait can be exercised in tests
/// without pulling in a full FRI setup.
#[derive(Clone, Debug)]
pub struct TrivialPcs<Val: TwoAdicField, Dft: TwoAdicSubgroupDft<Val>> {
    /// The DFT implementation used to interpolate committed evaluations into coefficients.
    pub dft: Dft,
    /// The degree bound: `commit` requires every domain to have size `>= 1 << log_n`.
    pub log_n: usize,
    pub _phantom: PhantomData<Val>,
}

/// Evaluate a matrix of polynomial coefficients (one polynomial per column, coefficients in
/// standard low-to-high order along the rows) at a point `x`, via Horner's method.
pub fn eval_coeffs_at_pt<F: Field, EF: ExtensionField<F>>(
    coeffs: &RowMajorMatrix<F>,
    x: EF,
) -> Vec<EF> {
    let mut acc = vec![EF::ZERO; coeffs.width()];
    for r in (0..coeffs.height()).rev() {
        let row = coeffs.row_slice(r).unwrap();
        for (acc_c, row_c) in acc.iter_mut().zip(row.iter()) {
            *acc_c *= x;
            *acc_c += *row_c;
        }
    }
    acc
}

impl<Val, Dft, Challenge, Challenger> Pcs<Challenge, Challenger> for TrivialPcs<Val, Dft>
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
        // This panics if (and only if) `degree` is not a power of 2 or `degree`
        // > `1 << Val::TWO_ADICITY`.
        TwoAdicMultiplicativeCoset::new(Val::ONE, log2_strict_usize(degree)).unwrap()
    }

    fn commit(
        &self,
        evaluations: impl IntoIterator<Item = (Self::Domain, RowMajorMatrix<Val>)>,
    ) -> (Self::Commitment, Self::ProverData) {
        let coeffs: Vec<_> = evaluations
            .into_iter()
            .map(|(domain, evals)| {
                let log_domain_size = log2_strict_usize(domain.size());
                // for now, only commit on larger domain than natural
                assert!(log_domain_size >= self.log_n);
                assert_eq!(domain.size(), evals.height());
                // coset_idft_batch
                let mut coeffs = self.dft.idft_batch(evals);
                coeffs
                    .rows_mut()
                    .zip(domain.shift_inverse().powers())
                    .for_each(|(row, weight)| {
                        row.iter_mut().for_each(|coeff| {
                            *coeff *= weight;
                        });
                    });
                coeffs
            })
            .collect();
        (
            coeffs.clone().into_iter().map(|m| m.values).collect(),
            coeffs,
        )
    }

    fn commit_quotient(
        &self,
        quotient_domain: Self::Domain,
        quotient_evaluations: RowMajorMatrix<crate::Val<Self::Domain>>,
        num_chunks: usize,
    ) -> (Self::Commitment, Self::ProverData) {
        let quotient_sub_evaluations =
            quotient_domain.split_evals(num_chunks, quotient_evaluations);
        let quotient_sub_domains = quotient_domain.split_domains(num_chunks);

        Pcs::<Challenge, Challenger>::commit(
            self,
            quotient_sub_domains
                .into_iter()
                .zip(quotient_sub_evaluations),
        )
    }

    fn get_quotient_ldes(
        &self,
        _evaluations: impl IntoIterator<Item = (Self::Domain, RowMajorMatrix<Val>)>,
        _num_chunks: usize,
    ) -> Vec<RowMajorMatrix<crate::Val<Self::Domain>>> {
        unimplemented!("This PCS does not support computing of LDEs");
    }

    fn commit_ldes(&self, _ldes: Vec<RowMajorMatrix<Val>>) -> (Self::Commitment, Self::ProverData) {
        unimplemented!("This PCS does not support computing of LDEs");
    }

    fn get_evaluations_on_domain<'a>(
        &self,
        prover_data: &'a Self::ProverData,
        idx: usize,
        domain: Self::Domain,
    ) -> Self::EvaluationsOnDomain<'a> {
        let mut coeffs = prover_data[idx].clone();
        assert!(domain.log_size() >= self.log_n);
        coeffs.values.resize(
            coeffs.values.len() << (domain.log_size() - self.log_n),
            Val::ZERO,
        );
        self.dft.coset_dft_batch(coeffs, domain.shift())
    }

    fn open(
        &self,
        // For each round,
        rounds: Vec<(
            &Self::ProverData,
            // for each matrix,
            Vec<
                // points to open
                Vec<Challenge>,
            >,
        )>,
        _challenger: &mut Challenger,
    ) -> (OpenedValues<Challenge>, Self::Proof) {
        (
            rounds
                .into_iter()
                .map(|(coeffs_for_round, points_for_round)| {
                    // ensure that each matrix corresponds to a set of opening points
                    debug_assert_eq!(coeffs_for_round.len(), points_for_round.len());
                    coeffs_for_round
                        .iter()
                        .zip(points_for_round)
                        .map(|(coeffs_for_mat, points_for_mat)| {
                            points_for_mat
                                .into_iter()
                                .map(|pt| eval_coeffs_at_pt(coeffs_for_mat, pt))
                                .collect()
                        })
                        .collect()
                })
                .collect(),
            (),
        )
    }

    // This is a testing function, so we allow panics for convenience.
    #[allow(clippy::panic_in_result_fn)]
    fn verify(
        &self,
        // For each round:
        rounds: Vec<(
            Self::Commitment,
            // for each matrix:
            Vec<(
                // its domain,
                Self::Domain,
                // for each point:
                Vec<(
                    Challenge,
                    // values at this point
                    Vec<Challenge>,
                )>,
            )>,
        )>,
        _proof: &Self::Proof,
        _challenger: &mut Challenger,
    ) -> Result<(), Self::Error> {
        for (comm, round_opening) in rounds {
            for (coeff_vec, (domain, points_and_values)) in zip_eq(comm, round_opening, ())? {
                let width = coeff_vec.len() / domain.size();
                assert_eq!(width * domain.size(), coeff_vec.len());
                let coeffs = RowMajorMatrix::new(coeff_vec, width);
                for (pt, values) in points_and_values {
                    assert_eq!(eval_coeffs_at_pt(&coeffs, pt), values);
                }
            }
        }
        Ok(())
    }
}
