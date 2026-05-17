//! Debug utilities for SIMD implementation verification

#[cfg(all(test, feature = "simd-avx2", target_arch = "x86_64"))]
pub mod debug {
    use lib_q_hqc::simd::{
        Avx2,
        PolynomialOps,
        Portable,
    };

    /// Compare AVX2 vs Portable element-wise with detailed mismatch reporting
    pub fn verify_sparse_dense_mul(sparse: &[u8], dense: &[u8], weight: u32) -> Result<(), String> {
        let mut avx2_out = vec![0u8; dense.len()];
        let mut portable_out = vec![0u8; dense.len()];

        let n_bits = dense.len() * 8;
        Avx2::sparse_dense_mul(&mut avx2_out, sparse, dense, weight, n_bits);
        Portable::sparse_dense_mul(&mut portable_out, sparse, dense, weight, n_bits);

        for (i, (&a, &p)) in avx2_out.iter().zip(portable_out.iter()).enumerate() {
            if a != p {
                return Err(format!(
                    "Mismatch at byte {}: AVX2={:#04x}, Portable={:#04x}",
                    i, a, p
                ));
            }
        }
        Ok(())
    }

    /// Test shift_xor at various distances
    pub fn verify_shift_xor(source: &[u64], distance: usize) -> Result<(), String> {
        let mut avx2_dest = vec![0u64; source.len() * 2];
        let mut portable_dest = vec![0u64; source.len() * 2];

        Avx2::shift_xor(&mut avx2_dest, source, distance);
        Portable::shift_xor(&mut portable_dest, source, distance);

        for (i, (&a, &p)) in avx2_dest.iter().zip(portable_dest.iter()).enumerate() {
            if a != p {
                return Err(format!(
                    "Mismatch at u64[{}]: AVX2={:#018x}, Portable={:#018x}",
                    i, a, p
                ));
            }
        }
        Ok(())
    }
}
