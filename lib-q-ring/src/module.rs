//! Module operations: matrix–vector product in the NTT domain (ML-DSA style).

use alloc::vec::Vec;

use crate::field::reduce_poly_simd;
use crate::poly::{
    NttPoly,
    Poly,
};

/// Column vector of ring elements (time domain).
#[derive(Clone, Debug, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct ModuleVec(pub Vec<Poly>);

/// Public matrix `A` stored row-major as NTT polynomials `Â_{i,j}`.
pub struct ModuleMatrix {
    /// Number of rows `k`.
    pub rows: usize,
    /// Number of columns `l`.
    pub cols: usize,
    /// Row-major `k · l` entries.
    pub entries_ntt: Vec<NttPoly>,
}

impl ModuleMatrix {
    /// Expand `A` from seed `ρ` with [`crate::expand_a_from_seed`].
    #[must_use]
    pub fn expand_from_seed(seed: &[u8; 32], rows: usize, cols: usize) -> Self {
        Self {
            rows,
            cols,
            entries_ntt: crate::expand_a_from_seed(seed, rows, cols),
        }
    }

    /// `y_i = InvNTT( Σ_j Â_{i,j} ∘ v̂_j )` — same pattern as ML-DSA `compute_matrix_x_mask`.
    #[must_use]
    pub fn mul_vec_ntt(&self, v_ntt: &[NttPoly]) -> ModuleVec {
        assert_eq!(v_ntt.len(), self.cols);
        assert_eq!(self.entries_ntt.len(), self.rows * self.cols);
        let mut out = Vec::with_capacity(self.rows);
        for i in 0..self.rows {
            let mut acc = NttPoly::zero();
            for (j, v_cell) in v_ntt.iter().enumerate() {
                let mut prod = v_cell.clone();
                prod.pointwise_mul_assign(&self.entries_ntt[i * self.cols + j]);
                acc.add_assign(&prod);
            }
            reduce_poly_simd(acc.as_simd_mut());
            out.push(acc.to_poly());
        }
        ModuleVec(out)
    }

    /// [`mul_vec_ntt`] with automatic `NTT` on each input [`Poly`].
    #[must_use]
    pub fn mul_vec(&self, v: &ModuleVec) -> ModuleVec {
        let v_ntt: Vec<NttPoly> = v.0.iter().map(Poly::to_ntt).collect();
        self.mul_vec_ntt(&v_ntt)
    }
}
