//! LaZer's uniform sampling of coefficients, polynomials and polynomial matrices.
//!
//! Reference: LaZer `src/urandom.c` (`_urandom_i64`, the `log2mod < 60` branch of `_urandom`)
//! and `src/polymat.c` (`polymat_urandom`) at commit `10eafeca4cd53ff4fc54193dce904dbd0026fefd`.
//!
//! Only the `log2mod < 60` branch is ported. LaZer takes a different code path
//! (`_urandom_bnd`, multi-limb) for wider moduli, and that path is NOT reproduced here; the
//! functions below refuse such moduli rather than silently producing different output.

use alloc::vec::Vec;

use super::rng::LazerRng;

/// Ring degree of every LaZer ring used by the anonymous-credential demo.
pub const LAZER_DEG: usize = 64;

/// One polynomial of `Z[X]/(X^64 + 1)`, coefficient `k` at index `k`, values in `[0, modulus)`.
pub type LazerPoly = [i64; LAZER_DEG];

/// A row-major `rows x cols` matrix of [`LazerPoly`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LazerPolyMat {
    pub rows: usize,
    pub cols: usize,
    pub elems: Vec<LazerPoly>,
}

impl LazerPolyMat {
    pub fn get(&self, row: usize, col: usize) -> &LazerPoly {
        &self.elems[row * self.cols + col]
    }
}

/// Why a LaZer sampling request was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LazerSampleError {
    /// `log2mod` is outside `1..60` or `modulus` is outside `[2^(log2mod-1), 2^log2mod)`; LaZer
    /// asserts the same bounds (`ASSERT_ERR`) and uses another code path at `log2mod >= 60`.
    UnsupportedModulus,
    /// `rows * cols` does not fit LaZer's 32-bit element-index domain word.
    MatrixTooLarge,
}

/// `log2mod` as LaZer's Python wrapper computes it: `(mod - 1).bit_length()`.
pub fn log2mod_of(modulus: i64) -> u32 {
    64 - ((modulus - 1) as u64).leading_zeros()
}

fn check_modulus(modulus: i64, log2mod: u32) -> Result<(), LazerSampleError> {
    if !(1..60).contains(&log2mod)
        || modulus < (1i64 << (log2mod - 1))
        || modulus >= (1i64 << log2mod)
    {
        return Err(LazerSampleError::UnsupportedModulus);
    }
    Ok(())
}

/// `_urandom_i64(vec, nelems, mod, log2mod, seed, dom)`: fill `out` with values uniform in
/// `[0, modulus)` by rejection sampling.
///
/// Each round squeezes `ceil(log2mod * l / 8)` fresh bytes for the `l` values still missing,
/// reads `l` candidates of `log2mod` bits each, least-significant bit first, and keeps the
/// candidates below `modulus` in order. The bytes left over from a round are discarded.
pub fn urandom_i64(
    out: &mut [i64],
    modulus: i64,
    log2mod: u32,
    seed: &[u8; 32],
    dom: u64,
) -> Result<(), LazerSampleError> {
    check_modulus(modulus, log2mod)?;
    let bits = log2mod as usize;
    let mut rng = LazerRng::new(seed, dom);
    let mut filled = 0;
    let mut buf = Vec::new();
    while filled < out.len() {
        let missing = out.len() - filled;
        buf.clear();
        buf.resize((bits * missing).div_ceil(8), 0);
        rng.fill(&mut buf);
        for i in 0..missing {
            let candidate = read_bits_lsb_first(&buf, i * bits, bits);
            if candidate < modulus {
                out[filled] = candidate;
                filled += 1;
            }
        }
    }
    Ok(())
}

fn read_bits_lsb_first(buf: &[u8], first_bit: usize, nbits: usize) -> i64 {
    let mut v = 0i64;
    for j in 0..nbits {
        let pos = first_bit + j;
        let bit = (buf[pos >> 3] >> (pos & 7)) & 1;
        v |= i64::from(bit) << j;
    }
    v
}

/// `polymat_urandom(r, mod, log2mod, seed, dom)` for a `rows x cols` matrix over the degree-64
/// ring. Element `(i, j)` is sampled with the 64-bit domain `(dom << 32) | (i * cols + j)`,
/// which is LaZer's `union dom { uint32_t d32[2]; uint64_t d64; }` with `d32[0] = i * ncols + j`
/// and `d32[1] = dom`, read on a little-endian host.
pub fn polymat_urandom(
    rows: usize,
    cols: usize,
    modulus: i64,
    log2mod: u32,
    seed: &[u8; 32],
    dom: u32,
) -> Result<LazerPolyMat, LazerSampleError> {
    check_modulus(modulus, log2mod)?;
    let n = rows
        .checked_mul(cols)
        .filter(|n| u32::try_from(*n).is_ok())
        .ok_or(LazerSampleError::MatrixTooLarge)?;
    let mut elems = Vec::with_capacity(n);
    for idx in 0..n {
        let mut p = [0i64; LAZER_DEG];
        let elem_dom = (u64::from(dom) << 32) | idx as u64;
        urandom_i64(&mut p, modulus, log2mod, seed, elem_dom)?;
        elems.push(p);
    }
    Ok(LazerPolyMat { rows, cols, elems })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log2mod_matches_python_bit_length() {
        assert_eq!(log2mod_of(12289), 14);
        assert_eq!(log2mod_of(2), 1);
        assert_eq!(log2mod_of(4097), 13);
        assert_eq!(log2mod_of(4096), 12);
    }

    #[test]
    fn refuses_moduli_lazer_samples_elsewhere() {
        let seed = [0u8; 32];
        let mut out = [0i64; 4];
        assert_eq!(
            urandom_i64(&mut out, 1i64 << 60, 61, &seed, 0),
            Err(LazerSampleError::UnsupportedModulus)
        );
        assert_eq!(
            urandom_i64(&mut out, 12289, 13, &seed, 0),
            Err(LazerSampleError::UnsupportedModulus)
        );
    }

    #[test]
    fn samples_lie_in_range() {
        let m = polymat_urandom(2, 3, 12289, 14, &[9u8; 32], 4).expect("valid modulus");
        assert!(m.elems.iter().flatten().all(|c| (0..12289).contains(c)));
    }
}
