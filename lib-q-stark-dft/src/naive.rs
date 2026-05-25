use alloc::vec;

use lib_q_stark_field::{
    TwoAdicField,
    assert_two_adic_fft_height,
};
use lib_q_stark_matrix::Matrix;
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_util::log2_strict_usize;

use crate::TwoAdicSubgroupDft;

#[derive(Default, Clone, Debug)]
pub struct NaiveDft;

impl<F: TwoAdicField> TwoAdicSubgroupDft<F> for NaiveDft {
    type Evaluations = RowMajorMatrix<F>;
    fn dft_batch(&self, mat: RowMajorMatrix<F>) -> RowMajorMatrix<F> {
        assert_two_adic_fft_height::<F>(mat.height());
        let w = mat.width();
        let h = mat.height();
        let log_h = log2_strict_usize(h);
        let g = F::two_adic_generator(log_h);

        let mut res = RowMajorMatrix::new(vec![F::ZERO; w * h], w);
        for (res_r, point) in g.powers().take(h).enumerate() {
            for (src_r, point_power) in point.powers().take(h).enumerate() {
                for c in 0..w {
                    res.values[res_r * w + c] += point_power * mat.values[src_r * w + c];
                }
            }
        }

        res
    }
}

#[cfg(any())]
mod tests {
    use alloc::vec;

    use lib_q_stark_field::PrimeCharacteristicRing;
    use lib_q_stark_matrix::dense::RowMajorMatrix;
    use lib_q_stark_mersenne31::Mersenne31;

    // Goldilocks field not integrated
    // use p3_goldilocks::Goldilocks;
    use crate::{
        NaiveDft,
        TwoAdicSubgroupDft,
    };

    #[test]
    fn basic() {
        type F = Mersenne31;

        // A few polynomials:
        // 5 + 4x
        // 2 + 3x
        // 0
        let mat = RowMajorMatrix::new(
            vec![
                F::from_u8(5),
                F::from_u8(2),
                F::ZERO,
                F::from_u8(4),
                F::from_u8(3),
                F::ZERO,
            ],
            3,
        );

        let dft = NaiveDft.dft_batch(mat);
        // Expected evaluations on {1, -1}:
        // 9, 1
        // 5, -1
        // 0, 0
        assert_eq!(
            dft,
            RowMajorMatrix::new(
                vec![
                    F::from_u8(9),
                    F::from_u8(5),
                    F::ZERO,
                    F::ONE,
                    F::NEG_ONE,
                    F::ZERO,
                ],
                3,
            )
        );
    }

    // Goldilocks tests commented out - field not integrated
    // #[test]
    // fn dft_idft_consistency() {
    //     type F = Goldilocks;
    //     let mut rng = SmallRng::seed_from_u64(1);
    //     let original = RowMajorMatrix::<F>::rand(&mut rng, 8, 3);
    //     let dft = NaiveDft.dft_batch(original.clone());
    //     let idft = NaiveDft.idft_batch(dft);
    //     assert_eq!(original, idft);
    // }
    //
    // #[test]
    // fn coset_dft_idft_consistency() {
    //     type F = Goldilocks;
    //     let generator = F::GENERATOR;
    //     let mut rng = SmallRng::seed_from_u64(1);
    //     let original = RowMajorMatrix::<F>::rand(&mut rng, 8, 3);
    //     let dft = NaiveDft.coset_dft_batch(original.clone(), generator);
    //     let idft = NaiveDft.coset_idft_batch(dft, generator);
    //     assert_eq!(original, idft);
    // }
}
