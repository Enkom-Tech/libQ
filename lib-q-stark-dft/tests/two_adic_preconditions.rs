//! Radix-2 DFT must reject subgroup orders above the field's two-adicity.

use lib_q_stark_dft::{
    Radix2DFTSmallBatch,
    Radix2Dit,
    TwoAdicSubgroupDft,
};
use lib_q_stark_field::PrimeCharacteristicRing;
use lib_q_stark_field::extension::Complex;
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_mersenne31::{
    Mersenne31,
    Mersenne31Dft,
};

type F = Mersenne31;
type C = Complex<Mersenne31>;

fn m31_matrix(height: usize) -> RowMajorMatrix<F> {
    RowMajorMatrix::new(vec![F::ZERO; height], 1)
}

#[test]
#[should_panic(expected = "TWO_ADICITY")]
fn radix2_dit_rejects_oversized_mersenne31_subgroup() {
    Radix2Dit::<F>::default().dft_batch(m31_matrix(4));
}

#[test]
#[should_panic(expected = "TWO_ADICITY")]
fn radix2_small_batch_rejects_oversized_mersenne31_subgroup() {
    Radix2DFTSmallBatch::<F>::default().dft_batch(m31_matrix(4));
}

/// Same subgroup order as CI failure: `fft/.../ncols=256/16384` on raw `Mersenne31`.
#[test]
#[should_panic(expected = "TWO_ADICITY")]
fn radix2_small_batch_rejects_ci_failure_size() {
    Radix2DFTSmallBatch::<F>::default().dft_batch(m31_matrix(16_384));
}

#[test]
fn complex_mersenne31_accepts_stark_scale_fft() {
    let n = 1 << 13;
    let mat = RowMajorMatrix::new(vec![C::ZERO; n], 1);
    let _ = Radix2Dit::<C>::default().dft_batch(mat);
}

/// Supported path for real `Mersenne31` inputs at STARK scale (height 16384).
#[test]
fn m31_dft_accepts_ci_failure_input_height() {
    let mat = m31_matrix(16_384);
    let _ = Mersenne31Dft::dft_batch::<Radix2Dit<C>>(&mat);
}
