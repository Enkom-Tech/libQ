use alloc::vec::Vec;

use lib_q_stark_air::{
    AirBuilder,
    ExtensionBuilder,
    RowWindow,
};
use lib_q_stark_field::{
    Algebra,
    BasedVectorSpace,
    PackedField,
    PrimeCharacteristicRing,
};
use lib_q_stark_matrix::dense::RowMajorMatrixView;
use lib_q_stark_matrix::stack::ViewPair;

use crate::{
    PackedChallenge,
    PackedVal,
    StarkGenericConfig,
    Val,
};

const CONSTRAINT_BATCH: usize = 8;

#[inline]
fn batched_ext_linear_combination<PE, EF>(coeffs: &[EF], values: &[PE]) -> PE
where
    EF: lib_q_stark_field::Field,
    PE: PrimeCharacteristicRing + Algebra<EF> + Copy,
{
    debug_assert_eq!(coeffs.len(), values.len());
    let len = coeffs.len();
    let mut acc = PE::ZERO;
    let mut start = 0;
    while start + CONSTRAINT_BATCH <= len {
        let batch: [PE; CONSTRAINT_BATCH] =
            core::array::from_fn(|i| values[start + i] * coeffs[start + i]);
        acc += PE::sum_array::<CONSTRAINT_BATCH>(&batch);
        start += CONSTRAINT_BATCH;
    }
    for (&coeff, &val) in coeffs[start..].iter().zip(&values[start..]) {
        acc += val * coeff;
    }
    acc
}

#[inline]
fn batched_base_linear_combination<P: PackedField>(coeffs: &[P::Scalar], values: &[P]) -> P {
    debug_assert_eq!(coeffs.len(), values.len());
    let len = coeffs.len();
    let mut acc = P::ZERO;
    let mut start = 0;
    while start + CONSTRAINT_BATCH <= len {
        acc += P::packed_linear_combination::<CONSTRAINT_BATCH>(
            &coeffs[start..start + CONSTRAINT_BATCH],
            &values[start..start + CONSTRAINT_BATCH],
        );
        start += CONSTRAINT_BATCH;
    }
    for (&coeff, &val) in coeffs[start..].iter().zip(&values[start..]) {
        acc += val * coeff;
    }
    acc
}

/// Packed constraint folder for SIMD-optimized prover evaluation.
///
/// Collects constraints during `air.eval()` into separate base/ext vectors, then
/// combines them in [`Self::finalize_constraints`] using decomposed alpha powers.
#[derive(Debug)]
pub struct ProverConstraintFolder<'a, SC: StarkGenericConfig> {
    pub main: RowMajorMatrixView<'a, PackedVal<SC>>,
    pub preprocessed: RowMajorMatrixView<'a, PackedVal<SC>>,
    pub preprocessed_window: RowWindow<'a, PackedVal<SC>>,
    pub public_values: &'a [Val<SC>],
    pub is_first_row: PackedVal<SC>,
    pub is_last_row: PackedVal<SC>,
    pub is_transition: PackedVal<SC>,
    pub base_alpha_powers: &'a [Vec<Val<SC>>],
    pub ext_alpha_powers: &'a [SC::Challenge],
    pub base_constraints: Vec<PackedVal<SC>>,
    pub ext_constraints: Vec<PackedChallenge<SC>>,
    pub constraint_index: usize,
    pub constraint_count: usize,
}

/// Handles constraint verification for the verifier in a STARK system.
#[derive(Debug)]
pub struct VerifierConstraintFolder<'a, SC: StarkGenericConfig> {
    pub main: ViewPair<'a, SC::Challenge>,
    pub preprocessed: ViewPair<'a, SC::Challenge>,
    pub preprocessed_window: RowWindow<'a, SC::Challenge>,
    pub public_values: &'a [Val<SC>],
    pub is_first_row: SC::Challenge,
    pub is_last_row: SC::Challenge,
    pub is_transition: SC::Challenge,
    pub alpha: SC::Challenge,
    pub accumulator: SC::Challenge,
}

impl<SC: StarkGenericConfig> ProverConstraintFolder<'_, SC> {
    /// Combine all collected constraints with their pre-computed alpha powers.
    ///
    /// Base constraints use `batched_base_linear_combination` per basis dimension,
    /// decomposing the extension-field multiply into D base-field SIMD dot products.
    /// Extension constraints use `batched_ext_linear_combination` with scalar EF
    /// coefficients.
    #[inline]
    pub fn finalize_constraints(&self) -> PackedChallenge<SC> {
        debug_assert_eq!(self.constraint_index, self.constraint_count);
        let base = &self.base_constraints;
        let base_powers = self.base_alpha_powers;
        let acc = PackedChallenge::<SC>::from_basis_coefficients_fn(|d| {
            batched_base_linear_combination(&base_powers[d], base)
        });
        acc + batched_ext_linear_combination(self.ext_alpha_powers, &self.ext_constraints)
    }
}

impl<'a, SC: StarkGenericConfig> AirBuilder for ProverConstraintFolder<'a, SC> {
    type F = Val<SC>;
    type Expr = PackedVal<SC>;
    type Var = PackedVal<SC>;
    type PreprocessedWindow = RowWindow<'a, PackedVal<SC>>;
    type MainWindow = RowWindow<'a, PackedVal<SC>>;
    type PublicVar = Val<SC>;

    #[inline]
    fn main(&self) -> Self::MainWindow {
        RowWindow::from_view(&self.main)
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.preprocessed_window
    }

    #[inline]
    fn is_first_row(&self) -> Self::Expr {
        self.is_first_row
    }

    #[inline]
    fn is_last_row(&self) -> Self::Expr {
        self.is_last_row
    }

    #[inline]
    fn is_transition_window(&self, size: usize) -> Self::Expr {
        assert!(size <= 2, "only two-row windows are supported, got {size}");
        self.is_transition
    }

    #[inline]
    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.base_constraints.push(x.into());
        self.constraint_index += 1;
    }

    #[inline]
    fn assert_zeros<const N: usize, I: Into<Self::Expr>>(&mut self, array: [I; N]) {
        let expr_array = array.map(Into::into);
        self.base_constraints.extend(expr_array);
        self.constraint_index += N;
    }

    #[inline]
    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }
}

impl<SC: StarkGenericConfig> ExtensionBuilder for ProverConstraintFolder<'_, SC> {
    type EF = SC::Challenge;
    type ExprEF = PackedChallenge<SC>;
    type VarEF = PackedChallenge<SC>;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        self.ext_constraints.push(x.into());
        self.constraint_index += 1;
    }
}

impl<'a, SC: StarkGenericConfig> AirBuilder for VerifierConstraintFolder<'a, SC> {
    type F = Val<SC>;
    type Expr = SC::Challenge;
    type Var = SC::Challenge;
    type PreprocessedWindow = RowWindow<'a, SC::Challenge>;
    type MainWindow = RowWindow<'a, SC::Challenge>;
    type PublicVar = Val<SC>;

    fn main(&self) -> Self::MainWindow {
        RowWindow::from_two_rows(self.main.top.values, self.main.bottom.values)
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.preprocessed_window
    }

    fn is_first_row(&self) -> Self::Expr {
        self.is_first_row
    }

    fn is_last_row(&self) -> Self::Expr {
        self.is_last_row
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        assert!(size <= 2, "only two-row windows are supported, got {size}");
        self.is_transition
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.accumulator *= self.alpha;
        self.accumulator += x.into();
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }
}
